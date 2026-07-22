# test_phase22_remote_bounded_file_read.py
# Regression tests for Phase 22: the live remote bounded-file-read path through the Kali tool service — RemoteToolBackend.read_bounded_file, ToolBackendCommandReadStrategy integration, policy gating, and full-objective verification without a cat allowlist entry.
"""Phase 22 tests: live remote bounded-file-read through the Kali tool service.

Covers the full flow:

    UserFlagExecutor
        -> BoundedCommandCapabilityAdapter.read_bounded_file(path)
        -> ToolBackendCommandReadStrategy
        -> RemoteToolBackend.read_bounded_file(target, path, ...)
        -> POST /v1/bounded-file-read
        -> apex_tool_service (real, in-process via httpx.ASGITransport)
        -> fixed ["cat", "--", path] argv
        -> bounded output
        -> verify_user_flag()
        -> EngagementOutcome.user_flag_verified

The "remote service" in every test here is the REAL apex_tool_service
FastAPI app mounted in-process via httpx.ASGITransport (no Docker, no real
socket, no HTB, no internet access) — the same contract-integration
pattern already established in test_remote_backend.py. No test uses a
real flag or a real HTB target.
"""
from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, EvidenceBundle, Goal, Node, SubgraphView, TaskSpec

from apex_host.config import ApexConfig
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.graph_ids import access_capability_id, endpoint_id, host_id, service_id
from apex_host.orchestration.outcome import EngagementOutcome, exit_code_for, is_success_outcome
from apex_host.parsers.capability_parser import CapabilityParser
from apex_host.planners.access_capabilities import access_capabilities_from_subgraph
from apex_host.policy import PolicyAdvisor, load_policy
from apex_host.policy.rules import check_bounded_user_flag_verification
from apex_host.runtime_registry import BoundedCommandCapabilityAdapter, ToolBackendCommandReadStrategy
from apex_host.tools.backend import BoundedFileReadBackend
from apex_host.tools.remote_backend import RemoteToolBackend
from apex_host.tools.registry import ToolRegistry
from apex_host.types import AccessCapabilityType
from apex_tool_service.app import create_app
from apex_tool_service.settings import ServiceSettings

_TARGET = "10.129.1.5"
_ANCHOR = host_id(_TARGET)
_FLAG_VALUE = "b2e7f4c19a3d0865"  # a plausible, well-formed synthetic token — never a real HTB flag
_SERVICE_TOKEN = "test-only-service-token"


def _non_comment_code(source: str) -> str:
    stripped = re.sub(r'("""|\'\'\')(?:.|\n)*?\1', "", source)
    return "\n".join(line for line in stripped.splitlines() if not line.strip().startswith("#"))


def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(), episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(), vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(), config=cfg,
    )


async def _seed_node(api: MemoryAPI, node_id: str, node_type: str, props: dict[str, Any] | None = None) -> None:
    ts = now()
    await api.upsert_node(Node(
        id=node_id, type=node_type, props=props or {}, confidence=0.9,
        source="test-seed", first_seen=ts, last_seen=ts,
    ))


async def _seed_edge(api: MemoryAPI, from_id: str, to_id: str, edge_type: str = "has_capability") -> None:
    ts = now()
    await api.upsert_edge(Edge(
        id=f"edge:{edge_type}:{from_id}:{to_id}", from_id=from_id, to_id=to_id, type=edge_type,
        props={}, confidence=0.9, source="test-seed", first_seen=ts, last_seen=ts,
    ))


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _goal(target: str, phase: str = "objective") -> Goal:
    return Goal(id="goal-1", description="verify objective", phase=phase, anchor_node=host_id(target))


async def _subgraph(api: MemoryAPI, target: str) -> SubgraphView:
    return await api.get_subgraph(host_id(target), depth=10)


async def _seed_validated_command_capability(
    api: MemoryAPI, target: str, *, principal: str = "application",
    capability_type: AccessCapabilityType = AccessCapabilityType.remote_command,
    confidence: float = 0.7, runtime_available: bool = True,
) -> str:
    h_id = host_id(target)
    await _seed_node(api, h_id, "host", {"ip": target})
    parsed = CapabilityParser().derive_command_capability(
        target=target, capability_type=capability_type, principal=principal,
        source_task_id="", validation_method="operator_attestation", confidence=confidence,
    )
    await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
    cap_id = access_capability_id(target, capability_type.value, principal)
    if runtime_available:
        ts = now()
        await api.upsert_node(Node(
            id=cap_id, type="access_capability", props={"runtime_available": True},
            confidence=0.5, source="test-seed", first_seen=ts, last_seen=ts,
        ))
    return cap_id


def _make_initial_state(target: str, run_id: str = "run-22") -> dict[str, Any]:
    return {
        "run_id": run_id, "target": target, "phase": "recon",
        "goal": f"Begin engagement against {target}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "", "privilege_state": "", "privilege_summary": {},
        "opportunity_ids": [], "attempted_opportunities": [],
        "enumeration_complete": False, "web_session_state": {},
        "workflow_summary": {}, "learning_summary": {}, "task_latency_log": [],
        "objective_status": "", "objective_summary": {}, "direct_file_read_log": [],
        "bounded_command_log": [],
    }


async def _seed_command_ready_engagement(api: MemoryAPI, target: str) -> None:
    h_id = host_id(target)
    svc_id = service_id(target, "80", "tcp")
    ep_id = endpoint_id(f"http://{target}/index.html")
    await _seed_node(api, h_id, "host", {"ip": target})
    await _seed_node(api, svc_id, "service", {"port": "80", "proto": "tcp", "service": "http", "state": "open"})
    await _seed_node(api, ep_id, "endpoint", {"url": f"http://{target}/index.html"})
    await _seed_edge(api, h_id, svc_id, edge_type="exposes")
    await _seed_edge(api, h_id, ep_id, edge_type="exposes")
    await _seed_validated_command_capability(api, target, principal="application")


def _real_service_settings(**overrides: Any) -> ServiceSettings:
    base: dict[str, Any] = {
        "token": _SERVICE_TOKEN,
        "authorized_cidrs": ("10.129.0.0/16",),
        "allowed_flag_basenames": ("user.txt",),
    }
    base.update(overrides)
    return ServiceSettings(**base)


def _remote_config(**overrides: Any) -> ApexConfig:
    base: dict[str, Any] = dict(
        target=_TARGET, dry_run=False, max_turns=5,
        tool_backend="remote", tool_service_url="http://kali-service",
        tool_service_token=_SERVICE_TOKEN,
        bounded_command_operator_attested=True,
        bounded_command_capability_type="remote_command",
        bounded_command_principal="application",
    )
    base.update(overrides)
    return ApexConfig(**base)


def _install_real_remote_service(monkeypatch: pytest.MonkeyPatch, settings: ServiceSettings) -> None:
    """Monkeypatch every ``httpx.AsyncClient()`` construction inside
    ``apex_host.tools.remote_backend`` to return a client transparently
    wired (via ``httpx.ASGITransport``) to a REAL, in-process
    ``apex_tool_service`` FastAPI app built from *settings* — no Docker, no
    real socket, no HTB. Mirrors ``test_remote_backend.py``'s own
    "contract-integration" pattern, applied here so that code paths which
    construct ``RemoteToolBackend`` via ``select_runtime_backend(config)``
    (never injecting a client directly) still exercise the real service.
    """
    import apex_host.tools.remote_backend as rb_mod

    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    real_async_client = httpx.AsyncClient

    def _patched(*args: object, **kwargs: object) -> httpx.AsyncClient:
        return real_async_client(transport=transport, base_url="http://kali-service")

    monkeypatch.setattr(rb_mod.httpx, "AsyncClient", _patched)


# ---------------------------------------------------------------------------
# 7. Remote backend
# ---------------------------------------------------------------------------

class TestRemoteBackend:
    async def test_dedicated_route_used(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_real_service_settings())
        transport = httpx.ASGITransport(app=app)
        client = httpx.AsyncClient(transport=transport, base_url="http://kali-service")
        try:
            config = _remote_config()
            backend = RemoteToolBackend(config, client=client)
            result = await backend.read_bounded_file(_TARGET, str(flag_file), timeout_seconds=5.0, max_output_bytes=4096)
            assert result.connected is True
            assert result.output == _FLAG_VALUE
        finally:
            await client.aclose()

    async def test_structured_body_only_no_command_fields(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={
                "ok": True, "output": _FLAG_VALUE, "error_code": None, "sanitized_error": None,
                "return_code": 0, "bytes_received": 16, "oversized": False, "timed_out": False,
                "duration_ms": 1.0, "method": "bounded_file_read",
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="http://kali-service")
        config = _remote_config()
        backend = RemoteToolBackend(config, client=client)
        await backend.read_bounded_file(_TARGET, str(flag_file), timeout_seconds=5.0, max_output_bytes=4096)
        assert set(captured["body"].keys()) == {"target", "path", "timeout_seconds", "max_output_bytes"}
        assert captured["body"]["target"] == _TARGET
        assert captured["body"]["path"] == str(flag_file)
        await client.aclose()

    async def test_service_token_sent_safely(self) -> None:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["auth"] = request.headers.get("Authorization", "")
            return httpx.Response(200, json={
                "ok": False, "output": "", "error_code": "file_not_found", "sanitized_error": "x",
                "return_code": 1, "bytes_received": 0, "oversized": False, "timed_out": False,
                "duration_ms": 1.0, "method": "bounded_file_read",
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="http://kali-service")
        config = _remote_config(tool_service_token="sekrit-token")
        backend = RemoteToolBackend(config, client=client)
        await backend.read_bounded_file(_TARGET, "/home/app/user.txt", timeout_seconds=5.0, max_output_bytes=4096)
        assert captured["auth"] == "Bearer sekrit-token"
        await client.aclose()

    async def test_malformed_response_rejected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"unexpected": "shape"})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="http://kali-service")
        config = _remote_config()
        backend = RemoteToolBackend(config, client=client)
        result = await backend.read_bounded_file(_TARGET, "/home/app/user.txt", timeout_seconds=5.0, max_output_bytes=4096)
        assert result.connected is False
        assert result.error is not None and "missing required field" in result.error
        await client.aclose()

    async def test_backend_timeout_mapped(self) -> None:
        class _RaisingTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ReadTimeout("simulated read timeout", request=request)

        client = httpx.AsyncClient(transport=_RaisingTransport(), base_url="http://kali-service")
        config = _remote_config()
        backend = RemoteToolBackend(config, client=client)
        result = await backend.read_bounded_file(_TARGET, "/home/app/user.txt", timeout_seconds=5.0, max_output_bytes=4096)
        assert result.connected is False
        assert result.timed_out is True
        await client.aclose()

    async def test_output_not_logged(self, caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
        import logging
        caplog.set_level(logging.DEBUG)
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_real_service_settings())
        transport = httpx.ASGITransport(app=app)
        client = httpx.AsyncClient(transport=transport, base_url="http://kali-service")
        config = _remote_config()
        backend = RemoteToolBackend(config, client=client)
        await backend.read_bounded_file(_TARGET, str(flag_file), timeout_seconds=5.0, max_output_bytes=4096)
        assert _FLAG_VALUE not in caplog.text
        await client.aclose()

    async def test_bounded_read_result_populated_correctly(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_real_service_settings())
        transport = httpx.ASGITransport(app=app)
        client = httpx.AsyncClient(transport=transport, base_url="http://kali-service")
        config = _remote_config()
        backend = RemoteToolBackend(config, client=client)
        result = await backend.read_bounded_file(_TARGET, str(flag_file), timeout_seconds=5.0, max_output_bytes=4096)
        assert result.connected is True
        assert result.output == _FLAG_VALUE
        assert result.error is None
        assert result.return_code == 0
        assert result.bytes_received == len(_FLAG_VALUE)
        assert result.truncated is False
        assert result.timed_out is False
        await client.aclose()

    async def test_dry_run_never_touches_network(self) -> None:
        called = {"count": 0}

        class _CountingTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                called["count"] += 1
                return httpx.Response(200, json={})

        client = httpx.AsyncClient(transport=_CountingTransport(), base_url="http://kali-service")
        config = _remote_config(dry_run=True)
        backend = RemoteToolBackend(config, client=client)
        result = await backend.read_bounded_file(_TARGET, "/home/app/user.txt", timeout_seconds=5.0, max_output_bytes=4096)
        assert called["count"] == 0
        assert result.connected is True  # synthetic dry-run result, never verifiable as a flag
        await client.aclose()


# ---------------------------------------------------------------------------
# 8. Strategy integration
# ---------------------------------------------------------------------------

class TestStrategyIntegration:
    async def test_strategy_uses_bounded_method_when_backend_supports_it(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_real_service_settings())
        transport = httpx.ASGITransport(app=app)
        client = httpx.AsyncClient(transport=transport, base_url="http://kali-service")
        config = _remote_config()
        backend = RemoteToolBackend(config, client=client)
        assert isinstance(backend, BoundedFileReadBackend)
        strategy = ToolBackendCommandReadStrategy(backend=backend, target=_TARGET)
        result = await strategy.read_file(str(flag_file), timeout_seconds=5.0, max_output_bytes=4096)
        assert result.connected is True
        assert result.output == _FLAG_VALUE
        await client.aclose()

    async def test_generic_run_tool_method_not_called_on_remote_backend(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_real_service_settings())
        transport = httpx.ASGITransport(app=app)
        client = httpx.AsyncClient(transport=transport, base_url="http://kali-service")
        config = _remote_config()
        backend = RemoteToolBackend(config, client=client)

        async def _fail_execute(*args: object, **kwargs: object) -> object:
            raise AssertionError("RemoteToolBackend.execute() must never be called from the bounded-read strategy")

        monkeypatch.setattr(backend, "execute", _fail_execute)
        strategy = ToolBackendCommandReadStrategy(backend=backend, target=_TARGET)
        result = await strategy.read_file(str(flag_file), timeout_seconds=5.0, max_output_bytes=4096)
        assert result.connected is True
        await client.aclose()

    def test_no_command_construction_in_strategy_for_remote_path(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod.ToolBackendCommandReadStrategy.read_file))
        # The preferred branch calls backend.read_bounded_file(...) and
        # never constructs "cat"/"--" itself.
        assert '"cat"' not in code
        assert "_FIXED_TOOL" not in code

    async def test_same_adapter_contract_preserved(self, tmp_path: Path) -> None:
        """BoundedCommandCapabilityAdapter's public contract
        (read_bounded_file(path) -> BoundedReadResult) is unchanged
        regardless of which strategy/backend services it."""
        from apex_host.runtime_registry import BoundedCommandReadPrimitive

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_real_service_settings())
        transport = httpx.ASGITransport(app=app)
        client = httpx.AsyncClient(transport=transport, base_url="http://kali-service")
        config = _remote_config()
        backend = RemoteToolBackend(config, client=client)
        strategy = ToolBackendCommandReadStrategy(backend=backend, target=_TARGET)
        primitive = BoundedCommandReadPrimitive(
            capability_id="cap-1", strategy=strategy, allowed_filenames=frozenset({"user.txt"}),
        )
        adapter = BoundedCommandCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file(str(flag_file))
        assert result.connected is True
        assert result.output == _FLAG_VALUE
        await client.aclose()


# ---------------------------------------------------------------------------
# 9. Policy
# ---------------------------------------------------------------------------

class TestPolicy:
    async def test_blocked_objective_never_calls_backend(self) -> None:
        from apex_host.execution.dispatcher import TaskDispatcher
        from apex_host.execution.registry import TaskRegistry

        config = _remote_config(target=_TARGET)
        advisor = PolicyAdvisor(load_policy(config), config)

        class _SpyExecutor:
            calls = 0

            async def run(self, task: Any, evidence: Any) -> Any:
                type(self).calls += 1
                raise AssertionError("executor/backend must never be reached for a blocked task")

        dispatcher = TaskDispatcher(
            advisor=advisor, task_registry=TaskRegistry(), config=config,
            run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type]
            user_flag_executor=_SpyExecutor(),  # type: ignore[arg-type]
        )
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": "8.8.8.8",  # off-scope
                "candidate_path": "/home/application/user.txt",
                "capability_id": "cmd-cap", "capability_type": "remote_command",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        ctx = ExecutionContext(
            run_id="r1", phase="objective", turn_number=0, evidence_version=None,
            subgraph=None, evidence=_empty_evidence(), dry_run=False,  # type: ignore[arg-type]
        )
        result = await dispatcher.dispatch(task, ctx)
        assert result.disposition is ExecutionDisposition.BLOCKED_POLICY
        assert _SpyExecutor.calls == 0

    async def test_blocked_request_never_reaches_subprocess_on_service(self) -> None:
        """A policy-blocked (unauthorized target) request to the SERVICE
        itself never reaches subprocess creation — proven independently at
        the service layer, mirroring apex_tool_service's own test suite."""
        import asyncio as _asyncio

        from tests.apex_tool_service._support import auth_headers, client_for

        calls = {"count": 0}
        orig = _asyncio.create_subprocess_exec

        async def _spy(*args: object, **kwargs: object):
            calls["count"] += 1
            return await orig(*args, **kwargs)

        import apex_tool_service.executor as executor_mod
        real_create = executor_mod.asyncio.create_subprocess_exec
        executor_mod.asyncio.create_subprocess_exec = _spy  # type: ignore[assignment]
        try:
            app = create_app(_real_service_settings())
            async with client_for(app) as client:
                r = await client.post(
                    "/v1/bounded-file-read",
                    json={"target": "8.8.8.8", "path": "/home/app/user.txt"},
                    headers=auth_headers(_SERVICE_TOKEN),
                )
            assert r.status_code == 400
            assert calls["count"] == 0
        finally:
            executor_mod.asyncio.create_subprocess_exec = real_create  # type: ignore[assignment]

    async def test_dry_run_never_calls_subprocess(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        async def _fail(*args: object, **kwargs: object) -> object:
            raise AssertionError("create_subprocess_exec must never be called when dry_run=True")

        import apex_tool_service.executor as executor_mod
        real_create = executor_mod.asyncio.create_subprocess_exec
        executor_mod.asyncio.create_subprocess_exec = _fail  # type: ignore[assignment]
        try:
            from tests.apex_tool_service._support import auth_headers, client_for
            app = create_app(_real_service_settings())
            async with client_for(app) as client:
                r = await client.post(
                    "/v1/bounded-file-read",
                    json={"target": _TARGET, "path": str(flag_file), "dry_run": True},
                    headers=auth_headers(_SERVICE_TOKEN),
                )
            assert r.status_code == 200
            assert r.json()["ok"] is False
        finally:
            executor_mod.asyncio.create_subprocess_exec = real_create  # type: ignore[assignment]

    async def test_target_mismatch_rejected_at_host_layer(self) -> None:
        config = _remote_config(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t2", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": "8.8.8.8",
                "candidate_path": "/home/application/user.txt",
                "capability_id": "cmd-cap", "capability_type": "remote_command",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is None  # falls through; check_target_in_scope already blocks it in ALL_RULES

    async def test_target_mismatch_rejected_at_service_layer(self) -> None:
        from tests.apex_tool_service._support import auth_headers, client_for

        app = create_app(_real_service_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": "8.8.8.8", "path": "/home/app/user.txt"},
                headers=auth_headers(_SERVICE_TOKEN),
            )
        assert r.status_code == 400
        assert "authorized CIDR" in str(r.json())


# ---------------------------------------------------------------------------
# 10. Full objective integration (positive)
# ---------------------------------------------------------------------------

class TestFullObjectiveIntegration:
    async def test_full_graph_verified_success_via_remote_bounded_read_no_ssh_no_dfr(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        settings = _real_service_settings()
        _install_real_remote_service(monkeypatch, settings)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = _remote_config(
            user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] == EngagementOutcome.user_flag_verified.value
        assert is_success_outcome(EngagementOutcome(final_state["outcome"])) is True
        assert final_state["completed"] is True
        assert exit_code_for(EngagementOutcome(final_state["outcome"])) == 0

        subgraph = await _subgraph(api, _TARGET)
        assert not any(n.type == "access_state" for n in subgraph.nodes), "no SSH access_state anywhere"
        assert not any(
            n.type == "access_capability" and str(n.props.get("capability_type", "")) in ("arbitrary_file_read", "api_file_read")
            for n in subgraph.nodes
        ), "no direct-file-read capability anywhere"
        assert any(n.type == "objective_evidence" for n in subgraph.nodes)

    async def test_command_capability_registered_with_runtime_available(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        settings = _real_service_settings()
        _install_real_remote_service(monkeypatch, settings)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = _remote_config(
            user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        await graph.ainvoke(_make_initial_state(_TARGET))

        subgraph = await _subgraph(api, _TARGET)
        caps = access_capabilities_from_subgraph(subgraph)
        remote_caps = [c for c in caps if c.capability_type is AccessCapabilityType.remote_command]
        assert len(remote_caps) == 1
        assert remote_caps[0].runtime_available is True

    async def test_raw_flag_absent_everywhere_downstream(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        settings = _real_service_settings()
        _install_real_remote_service(monkeypatch, settings)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = _remote_config(
            user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        subgraph = await _subgraph(api, _TARGET)

        # EKG
        ekg_serialized = json.dumps([n.props for n in subgraph.nodes], default=str)
        assert _FLAG_VALUE not in ekg_serialized

        # Episodes (via final_state's own log accumulators)
        assert _FLAG_VALUE not in json.dumps(final_state, default=str)

        # Report (text + JSON)
        report = build_report(final_state, subgraph, config)
        text = format_text(report)
        assert _FLAG_VALUE not in text
        assert "Capability used" in text and "Remote Command" in text
        data = to_json_dict(report)
        assert _FLAG_VALUE not in json.dumps(data)
        assert data["objective"]["benchmark_success"] is True


# ---------------------------------------------------------------------------
# 11. Negative full objective
# ---------------------------------------------------------------------------

class TestNegativeFullObjective:
    async def test_service_unavailable_never_becomes_verified_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        import apex_host.tools.remote_backend as rb_mod

        class _RefusingTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ConnectError("connection refused (simulated)", request=request)

        real_async_client = httpx.AsyncClient

        def _patched(*args: object, **kwargs: object) -> httpx.AsyncClient:
            return real_async_client(transport=_RefusingTransport(), base_url="http://kali-service")

        monkeypatch.setattr(rb_mod.httpx, "AsyncClient", _patched)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = _remote_config(max_turns=3)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value
        assert exit_code_for(EngagementOutcome(final_state["outcome"])) != 0

    async def test_unauthorized_request_never_becomes_verified_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        settings = _real_service_settings()
        _install_real_remote_service(monkeypatch, settings)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        # Wrong service token -> every request is unauthorized (401).
        config = _remote_config(tool_service_token="wrong-token-entirely", max_turns=3)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

    async def test_invalid_candidate_never_becomes_verified_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        settings = _real_service_settings(allowed_flag_basenames=("root.txt",))  # "user.txt" not approved
        _install_real_remote_service(monkeypatch, settings)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = _remote_config(max_turns=3)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

    async def test_file_not_found_never_becomes_verified_success(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from apex_host.graph import build_apex_graph

        settings = _real_service_settings()
        _install_real_remote_service(monkeypatch, settings)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        # tmp_path exists but no user.txt file is ever created inside it.
        config = _remote_config(
            max_turns=3, user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

    async def test_permission_denied_never_becomes_verified_success(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        import os
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        os.chmod(flag_file, 0)
        try:
            settings = _real_service_settings()
            _install_real_remote_service(monkeypatch, settings)

            api = _make_api()
            await _seed_command_ready_engagement(api, _TARGET)
            config = _remote_config(
                max_turns=3, user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
            )
            registry = ToolRegistry.from_config(config)
            graph = build_apex_graph(api, registry, config)
            final_state = await graph.ainvoke(_make_initial_state(_TARGET))
            assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value
        finally:
            os.chmod(flag_file, 0o600)

    async def test_oversized_output_never_becomes_verified_success(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from apex_host.graph import build_apex_graph

        big_file = tmp_path / "user.txt"
        big_file.write_text("x" * 10000)
        settings = _real_service_settings(bounded_read_max_bytes=100)
        _install_real_remote_service(monkeypatch, settings)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = _remote_config(
            max_turns=3, user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
            bounded_command_max_output_bytes=4096,
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

    async def test_malformed_response_never_becomes_verified_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph
        import apex_host.tools.remote_backend as rb_mod

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"nonsense": True})

        real_async_client = httpx.AsyncClient

        def _patched(*args: object, **kwargs: object) -> httpx.AsyncClient:
            return real_async_client(transport=httpx.MockTransport(handler), base_url="http://kali-service")

        monkeypatch.setattr(rb_mod.httpx, "AsyncClient", _patched)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = _remote_config(max_turns=3)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value
        assert exit_code_for(EngagementOutcome(final_state["outcome"])) != 0


# ---------------------------------------------------------------------------
# 12. Architecture scans
# ---------------------------------------------------------------------------

_HTB_MACHINE_NAMES: tuple[str, ...] = (
    "meow", "fawn", "dancing", "redeemer", "explosion", "preignition",
    "mongod", "synced", "appointment", "sequel", "crocodile", "responder",
    "three", "ignition", "vaccine", "lame", "blue",
)


class TestArchitectureScans:
    def test_memfabric_unchanged_by_this_phase(self) -> None:
        memfabric_dir = Path("memfabric")
        forbidden_terms = (
            "bounded-file-read", "BoundedFileReadBackend", "ReadBoundedFileRequest",
            "apex_tool_service", "RemoteToolBackend",
        )
        for py_file in memfabric_dir.rglob("*.py"):
            code = _non_comment_code(py_file.read_text())
            for term in forbidden_terms:
                assert term not in code, f"{py_file} references {term!r}"

    def test_memfabric_has_no_new_apex_host_or_apex_tool_service_imports(self) -> None:
        memfabric_dir = Path("memfabric")
        for py_file in memfabric_dir.rglob("*.py"):
            code = py_file.read_text()
            assert "import apex_host" not in code
            assert "import apex_tool_service" not in code

    def test_no_machine_specific_names_in_new_code(self) -> None:
        for rel_path in (
            "apex_tool_service/executor.py",
            "apex_tool_service/validation.py",
            "apex_tool_service/models.py",
            "apex_tool_service/settings.py",
            "apex_host/tools/remote_backend.py",
        ):
            code = _non_comment_code(Path(rel_path).read_text())
            for name in _HTB_MACHINE_NAMES:
                pattern = re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE)
                assert not pattern.search(code), f"{rel_path} contains machine-name-like token {name!r}"

    def test_no_hardcoded_flag_values(self) -> None:
        for rel_path in (
            "apex_tool_service/executor.py", "apex_tool_service/app.py",
            "apex_host/tools/remote_backend.py",
        ):
            code = _non_comment_code(Path(rel_path).read_text())
            assert "HTB{" not in code
            assert "flag{" not in code.lower()

    def test_no_shell_true(self) -> None:
        for rel_path in ("apex_tool_service/executor.py", "apex_host/tools/remote_backend.py"):
            assert "shell=True" not in Path(rel_path).read_text()

    def test_no_bin_sh_c_or_bash_c(self) -> None:
        for rel_path in ("apex_tool_service/executor.py", "apex_host/tools/remote_backend.py"):
            code = Path(rel_path).read_text()
            assert "/bin/sh" not in code
            assert "bash -c" not in code

    def test_no_generic_cat_allowance_added(self) -> None:
        from apex_tool_service.allowlist import ALLOWED_TOOLS
        assert "cat" not in ALLOWED_TOOLS

    def test_no_arbitrary_command_fields_anywhere(self) -> None:
        from apex_tool_service.models import ReadBoundedFileRequest
        fields = set(ReadBoundedFileRequest.model_fields.keys())
        for forbidden in ("command", "argv", "executable", "shell"):
            assert forbidden not in fields

    def test_no_raw_output_logging_in_remote_backend(self) -> None:
        code = _non_comment_code(Path("apex_host/tools/remote_backend.py").read_text())
        assert "logger.info(response" not in code
        assert "logger.debug(response" not in code

    def test_dry_run_default_true(self) -> None:
        config = ApexConfig(target=_TARGET)
        assert config.dry_run is True

    def test_user_flag_executor_transport_independent(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "RemoteToolBackend" not in code
        assert "apex_tool_service" not in code

    def test_objective_planner_transport_independent(self) -> None:
        import apex_host.planners.objective_planner as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "RemoteToolBackend" not in code
        assert "apex_tool_service" not in code

    def test_objective_parser_transport_independent(self) -> None:
        import apex_host.parsers.objective_parser as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "RemoteToolBackend" not in code
        assert "apex_tool_service" not in code

    def test_verified_flag_remains_only_benchmark_success(self) -> None:
        from apex_host.orchestration.outcome import is_success_outcome, EngagementOutcome
        for outcome in EngagementOutcome:
            expected = outcome is EngagementOutcome.user_flag_verified
            assert is_success_outcome(outcome) == expected
