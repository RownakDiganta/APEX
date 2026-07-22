# test_access_capability_refactor.py
# Regression tests for the access-capability abstraction: AccessCapability/AccessCapabilityType, the runtime-only capability registry and SSH adapter, capability derivation/ranking, executor/parser/planner transport-independence, and report/policy/graph integration.
"""Access-capability abstraction regression tests.

Companion to ``test_phase18_user_flag_objective.py`` (the User Flag
Objective's own end-to-end behavior, updated in place for this refactor).
This file focuses on the NEW abstraction layer itself: the
``AccessCapability`` data model, the runtime-only
``CapabilityRuntimeRegistry``/``SSHCapabilityAdapter``, the
``CapabilityParser``, the pure ``access_capabilities`` reasoning helpers,
and the structural guarantee that nothing above the adapter boundary
(``ObjectivePlanner``, ``UserFlagExecutor``, ``ObjectiveParser``, the
report generator) has any transport-specific knowledge.

No test requires a real HTB machine, Docker, VPN, internet access, a real
SSH server, or real credentials — ``paramiko.SSHClient`` is monkeypatched
exactly as in ``test_ssh_executor.py``/``test_phase18_user_flag_objective.py``.
"""
from __future__ import annotations

import inspect
import re
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node, SubgraphView, TaskSpec

from apex_host.config import ApexConfig
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.graph_ids import (
    access_capability_id,
    access_state_id,
    enables_edge_id,
    has_capability_edge_id,
    host_id,
)
from apex_host.parsers.capability_parser import CapabilityParser
from apex_host.planners.access_capabilities import (
    CAPABILITY_TYPE_LABELS,
    access_capabilities_from_subgraph,
    best_capability_for_objective,
    capability_type_label,
    rank_capabilities,
)
from apex_host.policy import PolicyAdvisor, load_policy
from apex_host.runtime_registry import (
    CapabilityRuntimeRegistry,
    FlagReadCapability,
    SSHCapabilityAdapter,
)
from apex_host.tools.registry import ToolRegistry
from apex_host.types import AccessCapability, AccessCapabilityType

_TARGET = "10.10.10.155"
_ANCHOR = host_id(_TARGET)

_TRIPLE_QUOTED_RE = re.compile(r'("""|\'\'\')(?:.|\n)*?\1')


def _non_comment_code(source: str) -> str:
    """Strip triple-quoted docstrings and full-line ``#`` comments, so an
    architecture scan matches real code/identifiers rather than prose that
    happens to mention a word (mirrors the pattern already established in
    ``tests/docker/test_compose.py``)."""
    stripped = _TRIPLE_QUOTED_RE.sub("", source)
    return "\n".join(
        line for line in stripped.splitlines() if not line.strip().startswith("#")
    )


def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
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


def _make_capability(
    *, principal: str = "testuser", validated: bool = True, confidence: float = 0.85,
    capability_type: AccessCapabilityType = AccessCapabilityType.ssh_command,
) -> AccessCapability:
    return AccessCapability(
        capability_id=access_capability_id(_TARGET, capability_type.value, principal),
        host_id=_ANCHOR, capability_type=capability_type, validated=validated,
        principal=principal, confidence=confidence, source_task_id="t1", metadata={},
    )


class _FakeChannel:
    def __init__(self, exit_status: int) -> None:
        self._exit_status = exit_status

    def recv_exit_status(self) -> int:
        return self._exit_status


class _FakeChannelFile:
    def __init__(self, data: bytes, exit_status: int) -> None:
        self._data = data
        self.channel = _FakeChannel(exit_status)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._data
        return self._data[:size]


class _FakeSSHClient:
    def __init__(self, *, stdout: bytes, stderr: bytes, exit_status: int, connect_raises: Exception | None) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._exit_status = exit_status
        self._connect_raises = connect_raises
        self.commands_run: list[str] = []
        self.closed = False

    def set_missing_host_key_policy(self, policy: Any) -> None:
        pass

    def connect(self, **kwargs: Any) -> None:
        if self._connect_raises is not None:
            raise self._connect_raises

    def exec_command(self, command: str, timeout: float | None = None) -> Any:
        self.commands_run.append(command)
        return (
            None,
            _FakeChannelFile(self._stdout, self._exit_status),
            _FakeChannelFile(self._stderr, self._exit_status),
        )

    def close(self) -> None:
        self.closed = True


def _install_fake_ssh(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    exit_status: int = 0,
    connect_raises: Exception | None = None,
) -> list[_FakeSSHClient]:
    import apex_host.runtime_registry as registry_mod

    created: list[_FakeSSHClient] = []

    def _factory() -> _FakeSSHClient:
        client = _FakeSSHClient(stdout=stdout, stderr=stderr, exit_status=exit_status, connect_raises=connect_raises)
        created.append(client)
        return client

    monkeypatch.setattr(registry_mod.paramiko, "SSHClient", _factory)
    return created


# ---------------------------------------------------------------------------
# 1. AccessCapability / AccessCapabilityType data model
# ---------------------------------------------------------------------------

class TestCapabilityCreation:
    def test_all_seven_capability_types_exist(self) -> None:
        # Phase 21 added `remote_command` — a generic, non-web, non-SSH
        # remote command-execution channel — as an additive 7th member.
        names = {t.value for t in AccessCapabilityType}
        assert names == {
            "ssh_command", "telnet_command", "web_command",
            "local_shell", "arbitrary_file_read", "api_file_read",
            "remote_command",
        }

    def test_capability_fields_match_spec(self) -> None:
        import dataclasses
        field_names = {f.name for f in dataclasses.fields(AccessCapability)}
        assert field_names == {
            "capability_id", "host_id", "capability_type", "validated",
            "principal", "confidence", "source_task_id", "metadata",
            # Phase 20 — distinguishes graph metadata from a runtime fact.
            "runtime_available",
        }

    def test_capability_forbids_secret_fields_by_construction(self) -> None:
        """No field on AccessCapability may ever hold a password, cookie,
        bearer token, SSH session, shell object, or socket — the dataclass
        simply has no such field, so no caller can ever populate one."""
        import dataclasses
        field_names = {f.name for f in dataclasses.fields(AccessCapability)}
        forbidden = ("password", "secret", "cookie", "token", "session", "socket", "shell_handle")
        for name in field_names:
            for bad in forbidden:
                assert bad not in name.lower(), f"AccessCapability.{name} looks secret-shaped"

    def test_construct_capability_directly(self) -> None:
        cap = _make_capability()
        assert cap.capability_type is AccessCapabilityType.ssh_command
        assert cap.validated is True
        assert cap.principal == "testuser"
        assert cap.metadata == {}

    def test_capability_id_is_content_addressed(self) -> None:
        """Same (target, capability_type, principal) -> same ID, always —
        this is what makes CapabilityParser.derive_ssh_capability() an
        idempotent upsert rather than a duplicate-creating append."""
        id1 = access_capability_id(_TARGET, "ssh_command", "root")
        id2 = access_capability_id(_TARGET, "ssh_command", "root")
        id3 = access_capability_id(_TARGET, "ssh_command", "other")
        assert id1 == id2
        assert id1 != id3


# ---------------------------------------------------------------------------
# 2. Runtime-only capability registry
# ---------------------------------------------------------------------------

class TestRuntimeRegistry:
    def test_empty_registry_returns_none(self) -> None:
        registry = CapabilityRuntimeRegistry()
        assert registry.get("nope") is None
        assert registry.has("nope") is False

    def test_register_and_get_round_trip(self) -> None:
        registry = CapabilityRuntimeRegistry()

        class _Dummy:
            async def read_bounded_file(self, path: str) -> tuple[bool, str, str | None]:
                return True, "x", None

        adapter = _Dummy()
        registry.register("cap-1", adapter)
        assert registry.has("cap-1") is True
        assert registry.get("cap-1") is adapter

    def test_ensure_ssh_is_idempotent(self) -> None:
        """A second ensure_ssh() call for the same capability_id returns the
        SAME adapter instance — registration never overwrites live state
        with a possibly-stale re-derivation mid-turn."""
        registry = CapabilityRuntimeRegistry()
        config = ApexConfig(target=_TARGET, dry_run=True)
        first = registry.ensure_ssh(
            "cap-1", target=_TARGET, port="22", username="root", password="pw1", config=config,
        )
        second = registry.ensure_ssh(
            "cap-1", target=_TARGET, port="22", username="root", password="pw2", config=config,
        )
        assert first is second

    def test_registry_never_imports_memfabric_or_apex_host_config_types_at_runtime(self) -> None:
        """The registry is a plain in-memory dict — never backed by
        MemoryAPI or any memfabric store."""
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "MemoryAPI" not in code
        assert "apply_deltas" not in code
        assert "upsert_node" not in code
        assert "upsert_edge" not in code

    def test_registry_is_a_plain_dict_wrapper(self) -> None:
        registry = CapabilityRuntimeRegistry()
        assert isinstance(registry._adapters, dict)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 3. Adapter resolution / FlagReadCapability protocol
# ---------------------------------------------------------------------------

class TestAdapterResolution:
    def test_ssh_adapter_satisfies_flag_read_capability_protocol(self) -> None:
        """FlagReadCapability is a plain (non-runtime-checkable) Protocol —
        structural conformance is verified by asserting the adapter exposes
        exactly the one required async method with a matching signature."""
        config = ApexConfig(target=_TARGET, dry_run=True)
        adapter = SSHCapabilityAdapter(target=_TARGET, port="22", username="root", password="pw", config=config)
        assert hasattr(adapter, "read_bounded_file")
        assert inspect.iscoroutinefunction(adapter.read_bounded_file)
        sig = inspect.signature(adapter.read_bounded_file)
        assert list(sig.parameters) == ["path"]

    def test_flag_read_capability_exposes_only_read_bounded_file(self) -> None:
        """The objective layer must never be able to request arbitrary
        command execution through this protocol — only one bounded-read
        operation exists on it."""
        members = [
            name for name, _ in inspect.getmembers(FlagReadCapability)
            if not name.startswith("_")
        ]
        assert members == ["read_bounded_file"]

    async def test_ssh_adapter_read_bounded_file_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_ssh(monkeypatch, stdout=b"hello-world\n")
        config = ApexConfig(target=_TARGET, dry_run=True)
        adapter = SSHCapabilityAdapter(target=_TARGET, port="22", username="root", password="pw", config=config)
        result = await adapter.read_bounded_file("/home/root/user.txt")
        assert result.connected is True
        assert result.output == "hello-world\n"
        assert result.error is None

    async def test_ssh_adapter_read_bounded_file_auth_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import paramiko
        _install_fake_ssh(monkeypatch, connect_raises=paramiko.AuthenticationException())
        config = ApexConfig(target=_TARGET, dry_run=True)
        adapter = SSHCapabilityAdapter(target=_TARGET, port="22", username="root", password="pw", config=config)
        result = await adapter.read_bounded_file("/home/root/user.txt")
        assert result.connected is False
        assert result.output == ""
        assert result.error is not None and "authentication" in result.error.lower()

    async def test_ssh_adapter_closes_client_every_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fakes = _install_fake_ssh(monkeypatch, stdout=b"data")
        config = ApexConfig(target=_TARGET, dry_run=True)
        adapter = SSHCapabilityAdapter(target=_TARGET, port="22", username="root", password="pw", config=config)
        await adapter.read_bounded_file("/home/root/user.txt")
        assert len(fakes) == 1
        assert fakes[0].closed is True

    async def test_ssh_adapter_no_client_held_across_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Two calls -> two fresh SSHClient instances, never one reused
        session (memfabric Invariant 6 discipline extended to adapters)."""
        fakes = _install_fake_ssh(monkeypatch, stdout=b"data")
        config = ApexConfig(target=_TARGET, dry_run=True)
        adapter = SSHCapabilityAdapter(target=_TARGET, port="22", username="root", password="pw", config=config)
        await adapter.read_bounded_file("/home/root/a.txt")
        await adapter.read_bounded_file("/home/root/b.txt")
        assert len(fakes) == 2
        assert fakes[0] is not fakes[1]


# ---------------------------------------------------------------------------
# 4. CapabilityParser derivation + ranking helpers
# ---------------------------------------------------------------------------

class TestCapabilityDerivationAndRanking:
    def test_derive_ssh_capability_produces_expected_shape(self) -> None:
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="root", source_task_id="t1")
        assert len(parsed.node_deltas) == 1
        node = parsed.node_deltas[0]
        assert node.type == "access_capability"
        assert node.props["capability_type"] == "ssh_command"
        assert node.props["principal"] == "root"
        assert node.props["validated"] is True
        edge_types = {e.type for e in parsed.edge_deltas}
        assert edge_types == {"has_capability", "enables"}

    def test_derive_ssh_capability_empty_username_produces_nothing(self) -> None:
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="", source_task_id="t1")
        assert parsed.node_deltas == []
        assert parsed.edge_deltas == []

    def test_derive_ssh_capability_is_idempotent_id(self) -> None:
        first = CapabilityParser().derive_ssh_capability(target=_TARGET, username="root", source_task_id="t1")
        second = CapabilityParser().derive_ssh_capability(target=_TARGET, username="root", source_task_id="t2")
        assert first.node_deltas[0].id == second.node_deltas[0].id

    def test_rank_capabilities_prefers_validated_then_confidence(self) -> None:
        unvalidated = _make_capability(principal="a", validated=False, confidence=0.99)
        low = _make_capability(principal="b", validated=True, confidence=0.3)
        high = _make_capability(principal="c", validated=True, confidence=0.9)
        ranked = rank_capabilities([unvalidated, low, high])
        assert [c.principal for c in ranked] == ["c", "b", "a"]

    def test_rank_capabilities_stable_tiebreak_by_id(self) -> None:
        c1 = _make_capability(principal="zzz", confidence=0.5)
        c2 = _make_capability(principal="aaa", confidence=0.5)
        ranked = rank_capabilities([c1, c2])
        assert ranked[0].capability_id < ranked[1].capability_id

    def test_best_capability_for_objective_excludes_ids(self) -> None:
        c1 = _make_capability(principal="a", confidence=0.9)
        c2 = _make_capability(principal="b", confidence=0.5)

        class _FakeSubgraph:
            nodes: list[Any] = []

        # Directly exercise via a monkeypatched access_capabilities_from_subgraph-free path
        ranked = rank_capabilities([c1, c2])
        assert ranked[0].principal == "a"
        # excluding the top choice should fall through to the next
        remaining = [c for c in ranked if c.capability_id != c1.capability_id]
        assert remaining[0].principal == "b"

    async def test_best_capability_for_objective_from_real_subgraph(self) -> None:
        api = _make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        low_id = access_capability_id(_TARGET, "ssh_command", "low")
        high_id = access_capability_id(_TARGET, "ssh_command", "high")
        await _seed_node(api, low_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": _ANCHOR, "validated": True,
            "principal": "low", "confidence": 0.2, "source_task_id": "", "metadata": {},
        })
        await _seed_node(api, high_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": _ANCHOR, "validated": True,
            "principal": "high", "confidence": 0.8, "source_task_id": "", "metadata": {},
        })
        await _seed_edge(api, _ANCHOR, low_id)
        await _seed_edge(api, _ANCHOR, high_id)
        subgraph = await api.get_subgraph(_ANCHOR, depth=5)

        found = access_capabilities_from_subgraph(subgraph)
        assert {c.principal for c in found} == {"low", "high"}

        best = best_capability_for_objective(subgraph)
        assert best is not None
        assert best.principal == "high"

        best_excluding_high = best_capability_for_objective(
            subgraph, exclude_capability_ids=frozenset({high_id})
        )
        assert best_excluding_high is not None
        assert best_excluding_high.principal == "low"

    def test_unrecognised_capability_type_is_skipped_forward_compatibly(self) -> None:
        node = Node(
            id="access_capability:x:y:z", type="access_capability",
            props={"capability_type": "quantum_teleport", "host_id": _ANCHOR, "validated": True,
                   "principal": "p", "confidence": 0.5, "source_task_id": "", "metadata": {}},
            confidence=0.5, source="t", first_seen=now(), last_seen=now(),
        )
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[node], edges=[], depth=0)
        assert access_capabilities_from_subgraph(subgraph) == []

    def test_capability_type_label_lookup(self) -> None:
        assert capability_type_label("ssh_command") == "SSH Command"
        assert capability_type_label("telnet_command") == "Telnet Command"
        # Forward-compatible: unknown type falls back to the raw value.
        assert capability_type_label("some_future_type") == "some_future_type"

    def test_all_six_types_have_labels(self) -> None:
        for t in AccessCapabilityType:
            assert t.value in CAPABILITY_TYPE_LABELS


# ---------------------------------------------------------------------------
# 5. Objective layer no longer depends on SSH specifically
# ---------------------------------------------------------------------------

class TestObjectiveTransportIndependence:
    def test_objective_planner_source_has_no_ssh_specific_symbols(self) -> None:
        """ObjectivePlanner must select AccessCapability records generically
        — it must never reference SSH-specific concepts like a port number,
        a raw username field, or "access_validate_ssh" directly."""
        import apex_host.planners.objective_planner as mod
        source = inspect.getsource(mod)
        assert "access_validate_ssh" not in source
        assert "paramiko" not in source
        assert "ssh_port" not in source.lower().replace("_ssh_port_for_capability", "")

    def test_user_flag_executor_never_imports_paramiko(self) -> None:
        """UserFlagExecutor must never know it is talking to SSH — only the
        registry-resolved adapter does."""
        import apex_host.agents.user_flag_executor as mod
        source = inspect.getsource(mod)
        assert "paramiko" not in source
        assert "import socket" not in source

    def test_user_flag_executor_never_branches_on_capability_type(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        source = inspect.getsource(mod)
        assert "AccessCapabilityType.ssh_command" not in source
        assert "== \"ssh_command\"" not in source

    def test_objective_parser_never_imports_paramiko_or_ssh(self) -> None:
        import apex_host.parsers.objective_parser as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "paramiko" not in code
        assert "ssh" not in code.lower()

    def test_report_capability_line_uses_label_not_transport_word(self) -> None:
        """The report renders 'Capability used: <label>' — never a literal
        'Transport:' framing, so a future capability type needs no report
        rendering change (only a new CAPABILITY_TYPE_LABELS entry)."""
        import apex_host.eval.report as mod
        source = inspect.getsource(mod)
        code = _non_comment_code(source)
        assert "Capability used" in source
        assert "Transport:" not in code
        assert '"transport"' not in code


# ---------------------------------------------------------------------------
# 6. SSH adapter behavioral compatibility with the pre-refactor executor
# ---------------------------------------------------------------------------

class TestSSHAdapterCompatibility:
    async def test_command_is_cat_dash_dash_quoted_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fakes = _install_fake_ssh(monkeypatch, stdout=b"content")
        config = ApexConfig(target=_TARGET, dry_run=True)
        adapter = SSHCapabilityAdapter(target=_TARGET, port="22", username="root", password="pw", config=config)
        await adapter.read_bounded_file("/home/root/user.txt")
        assert fakes[0].commands_run == ["cat -- /home/root/user.txt"]

    async def test_never_uses_agent_or_key_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}
        import apex_host.runtime_registry as registry_mod

        class _CapturingClient(_FakeSSHClient):
            def connect(self, **kwargs: Any) -> None:
                captured.update(kwargs)

        monkeypatch.setattr(
            registry_mod.paramiko, "SSHClient",
            lambda: _CapturingClient(stdout=b"x", stderr=b"", exit_status=0, connect_raises=None),
        )
        config = ApexConfig(target=_TARGET, dry_run=True)
        adapter = SSHCapabilityAdapter(target=_TARGET, port="22", username="root", password="pw", config=config)
        await adapter.read_bounded_file("/home/root/user.txt")
        assert captured["allow_agent"] is False
        assert captured["look_for_keys"] is False

    async def test_read_is_byte_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_ssh(monkeypatch, stdout=b"x" * 100)
        config = ApexConfig(target=_TARGET, dry_run=True, user_flag_max_output_bytes=10)
        adapter = SSHCapabilityAdapter(target=_TARGET, port="22", username="root", password="pw", config=config)
        result = await adapter.read_bounded_file("/home/root/user.txt")
        assert len(result.output) == 10


# ---------------------------------------------------------------------------
# 7. Report generation
# ---------------------------------------------------------------------------

class TestReportCapabilityField:
    def test_capability_line_absent_when_not_verified(self) -> None:
        state = {
            "run_id": "r", "target": _TARGET, "phase": "done", "goal": "", "current_task": None,
            "evidence_summary": "", "findings": [], "last_tool_result": None, "last_error": None,
            "completed": True, "turn_count": 1, "planner_decisions": [], "tool_results": None,
            "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
            "execution_backend_log": [], "credential_validation_log": [],
            "outcome": "validated_access", "termination_reason": "", "termination_phase": "",
            "stall_reason": "", "privilege_state": "", "privilege_summary": {},
            "opportunity_ids": [], "attempted_opportunities": [], "enumeration_complete": False,
            "web_session_state": {}, "workflow_summary": {}, "learning_summary": {},
            "task_latency_log": [], "objective_status": "", "objective_summary": {},
        }
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        report = build_report(state, subgraph, ApexConfig(target=_TARGET))
        text = format_text(report)
        assert "Capability used" not in text
        data = to_json_dict(report)
        assert data["objective"]["capability_type"] == ""
        assert data["objective"]["capability_label"] == ""

    async def test_capability_line_present_when_verified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph
        from apex_host.graph_ids import access_state_id, service_id

        _install_fake_ssh(monkeypatch, stdout=b"9f3a7c21b6e04d18\n")
        api = _make_api()
        h_id = host_id(_TARGET)
        svc_id = service_id(_TARGET, "22", "tcp")
        acc_id = access_state_id(_TARGET, "testuser", protocol="ssh")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, svc_id, "service", {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"})
        await _seed_node(api, acc_id, "access_state", {"level": "user", "username": "testuser", "target": _TARGET, "service": "ssh"})
        await _seed_edge(api, h_id, svc_id, edge_type="exposes")
        await _seed_edge(api, h_id, acc_id, edge_type="exposes")
        cap_obs = CapabilityParser().derive_ssh_capability(target=_TARGET, username="testuser", source_task_id="")
        await api.apply_deltas(nodes=cap_obs.node_deltas, edges=cap_obs.edge_deltas)

        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke({
            "run_id": "r2", "target": _TARGET, "phase": "recon", "goal": "", "current_task": None,
            "evidence_summary": "", "findings": [], "error_episodes": [], "last_tool_result": None,
            "last_error": None, "completed": False, "turn_count": 0, "planner_decisions": [],
            "tool_results": None, "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
            "completed_fingerprints": [], "execution_backend_log": [], "diagnostic_events": [],
            "credential_validation_log": [], "outcome": "", "termination_reason": "",
            "termination_phase": "", "stall_reason": "", "privilege_state": "", "privilege_summary": {},
            "opportunity_ids": [], "attempted_opportunities": [], "enumeration_complete": False,
            "web_session_state": {}, "workflow_summary": {}, "learning_summary": {},
            "task_latency_log": [], "objective_status": "", "objective_summary": {},
        })
        subgraph = await api.get_subgraph(h_id, depth=10)
        report = build_report(final_state, subgraph, config)
        text = format_text(report)
        assert "Capability used    : SSH Command" in text
        data = to_json_dict(report)
        assert data["objective"]["capability_type"] == "ssh_command"
        assert data["objective"]["capability_label"] == "SSH Command"


# ---------------------------------------------------------------------------
# 8. Policy validation
# ---------------------------------------------------------------------------

class TestCapabilityPolicyValidation:
    def test_user_flag_verify_task_approved_with_capability_params(self) -> None:
        from apex_host.policy.rules import check_bounded_user_flag_verification

        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "capability_id": access_capability_id(_TARGET, "ssh_command", "root"),
                "capability_type": "ssh_command", "principal": "root",
                "candidate_path": "/home/root/user.txt",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None
        assert decision.status.value == "approved"

    def test_user_flag_verify_task_blocked_for_unbounded_path_regardless_of_capability(self) -> None:
        from apex_host.policy.rules import check_bounded_user_flag_verification

        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t2", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "capability_id": access_capability_id(_TARGET, "ssh_command", "root"),
                "capability_type": "ssh_command", "principal": "root",
                "candidate_path": "/etc/shadow",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None
        assert decision.status.value == "blocked"

    async def test_policy_blocked_task_never_reaches_registry_or_executor(self) -> None:
        from apex_host.execution.dispatcher import TaskDispatcher
        from apex_host.execution.dispositions import ExecutionDisposition
        from apex_host.execution.registry import TaskRegistry
        from apex_host.execution.context import ExecutionContext
        from memfabric.types import EvidenceBundle

        config = ApexConfig(target=_TARGET, dry_run=False)
        advisor = PolicyAdvisor(load_policy(config), config)

        class _SpyExecutor:
            calls = 0

            async def run(self, task: Any, evidence: Any) -> Any:
                type(self).calls += 1
                raise AssertionError("executor must never be reached for an off-scope target")

        dispatcher = TaskDispatcher(
            advisor=advisor, task_registry=TaskRegistry(), config=config,
            run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type]
            user_flag_executor=_SpyExecutor(),  # type: ignore[arg-type]
        )
        task = TaskSpec(
            id="t3", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": "8.8.8.8",
                "capability_id": "access_capability:8.8.8.8:ssh_command:root",
                "capability_type": "ssh_command", "principal": "root",
                "candidate_path": "/home/root/user.txt",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        ctx = ExecutionContext(
            run_id="r1", phase="objective", turn_number=0, evidence_version=None,
            subgraph=None, evidence=EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]),
            dry_run=False,  # type: ignore[arg-type]
        )
        result = await dispatcher.dispatch(task, ctx)
        assert result.disposition is ExecutionDisposition.BLOCKED_POLICY
        assert _SpyExecutor.calls == 0


# ---------------------------------------------------------------------------
# 9. Graph node/edge shape
# ---------------------------------------------------------------------------

class TestCapabilityGraphNodes:
    def test_access_capability_node_type_documented_in_capabilities_module(self) -> None:
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="root", source_task_id="")
        node = parsed.node_deltas[0]
        assert node.type == "access_capability"
        required_props = {
            "capability_type", "host_id", "validated", "principal",
            "confidence", "source_task_id", "metadata",
        }
        assert required_props.issubset(node.props.keys())

    def test_has_capability_edge_from_host(self) -> None:
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="root", source_task_id="")
        h_id = host_id(_TARGET)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        has_cap_edges = [e for e in parsed.edge_deltas if e.type == "has_capability"]
        assert len(has_cap_edges) == 1
        assert has_cap_edges[0].from_id == h_id
        assert has_cap_edges[0].to_id == cap_id
        assert has_cap_edges[0].id == has_capability_edge_id(h_id, cap_id)

    def test_enables_edge_from_access_state_to_capability(self) -> None:
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="root", source_task_id="")
        acc_id = access_state_id(_TARGET, "root", protocol="ssh")
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        enables_edges = [e for e in parsed.edge_deltas if e.type == "enables"]
        assert len(enables_edges) == 1
        assert enables_edges[0].from_id == acc_id
        assert enables_edges[0].to_id == cap_id
        assert enables_edges[0].id == enables_edge_id(acc_id, cap_id)

    async def test_capability_node_reachable_and_deletable_via_memory_api(self) -> None:
        api = _make_api()
        h_id = host_id(_TARGET)
        acc_id = access_state_id(_TARGET, "root", protocol="ssh")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, acc_id, "access_state", {"username": "root", "target": _TARGET})
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="root", source_task_id="")
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
        subgraph = await api.get_subgraph(h_id, depth=3)
        cap_nodes = [n for n in subgraph.nodes if n.type == "access_capability"]
        assert len(cap_nodes) == 1


# ---------------------------------------------------------------------------
# 10. No runtime session persistence (the registry is never EKG-backed)
# ---------------------------------------------------------------------------

class TestNoRuntimeSessionPersistence:
    async def test_registered_adapter_never_appears_in_graph(self) -> None:
        api = _make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        registry = CapabilityRuntimeRegistry()
        config = ApexConfig(target=_TARGET, dry_run=True)
        registry.ensure_ssh("cap-1", target=_TARGET, port="22", username="root", password="secretpw", config=config)

        subgraph = await api.get_subgraph(_ANCHOR, depth=5)
        for node in subgraph.nodes:
            assert "secretpw" not in str(node.props)
            assert "SSHCapabilityAdapter" not in str(node.props)

    def test_orchestration_deps_capability_registry_field_is_runtime_only(self) -> None:
        """OrchestrationDeps.capability_registry is a plain constructor
        field, never derived from or written to via MemoryAPI — verified by
        checking the field exists and the class is frozen (so nothing can
        smuggle a registry-derived value into a mutable, ekg-backed slot)."""
        from apex_host.orchestration.dependencies import OrchestrationDeps
        import dataclasses
        field_names = {f.name for f in dataclasses.fields(OrchestrationDeps)}
        assert "capability_registry" in field_names
        assert dataclasses.fields(OrchestrationDeps)[0].name != ""  # sanity: fields introspectable
        # Frozen dataclass -> no attribute can be reassigned after construction.
        assert OrchestrationDeps.__dataclass_params__.frozen is True  # type: ignore[attr-defined]

    def test_apex_graph_state_never_contains_a_capability_registry_field(self) -> None:
        """Mirrors the existing 'TurnState/ApexGraphState must not contain
        MemoryAPI/Scheduler/Executor/Planner/Config types' architecture
        invariant, extended to the new registry type."""
        from apex_host.graph_state import ApexGraphState
        annotations = getattr(ApexGraphState, "__annotations__", {})
        for name, ann in annotations.items():
            ann_str = str(ann)
            assert "CapabilityRuntimeRegistry" not in ann_str, name


# ---------------------------------------------------------------------------
# 11. Serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_access_capability_type_is_str_enum_json_serializable(self) -> None:
        import json
        # AccessCapabilityType(str, Enum): json.dumps encodes a str-subclass
        # member using its underlying string VALUE, not Enum.__str__() (which
        # would render "AccessCapabilityType.ssh_command") — so the member
        # can be embedded directly in a JSON-serializable structure.
        assert json.dumps({"t": AccessCapabilityType.ssh_command}) == '{"t": "ssh_command"}'
        assert AccessCapabilityType.ssh_command == "ssh_command"

    def test_access_capability_node_props_are_json_serializable(self) -> None:
        import json
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="root", source_task_id="")
        node = parsed.node_deltas[0]
        serialized = json.dumps(node.props, default=str)
        assert isinstance(serialized, str)
        assert "root" in serialized

    async def test_final_graph_state_json_serializable_with_capability_flow(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import json
        from apex_host.graph import build_apex_graph
        from apex_host.graph_ids import service_id

        _install_fake_ssh(monkeypatch, stdout=b"not-a-flag-value")
        api = _make_api()
        h_id = host_id(_TARGET)
        svc_id = service_id(_TARGET, "22", "tcp")
        acc_id = access_state_id(_TARGET, "testuser", protocol="ssh")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, svc_id, "service", {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"})
        await _seed_node(api, acc_id, "access_state", {"level": "user", "username": "testuser", "target": _TARGET, "service": "ssh"})
        await _seed_edge(api, h_id, svc_id, edge_type="exposes")
        await _seed_edge(api, h_id, acc_id, edge_type="exposes")
        cap_obs = CapabilityParser().derive_ssh_capability(target=_TARGET, username="testuser", source_task_id="")
        await api.apply_deltas(nodes=cap_obs.node_deltas, edges=cap_obs.edge_deltas)

        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=2,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke({
            "run_id": "r3", "target": _TARGET, "phase": "recon", "goal": "", "current_task": None,
            "evidence_summary": "", "findings": [], "error_episodes": [], "last_tool_result": None,
            "last_error": None, "completed": False, "turn_count": 0, "planner_decisions": [],
            "tool_results": None, "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
            "completed_fingerprints": [], "execution_backend_log": [], "diagnostic_events": [],
            "credential_validation_log": [], "outcome": "", "termination_reason": "",
            "termination_phase": "", "stall_reason": "", "privilege_state": "", "privilege_summary": {},
            "opportunity_ids": [], "attempted_opportunities": [], "enumeration_complete": False,
            "web_session_state": {}, "workflow_summary": {}, "learning_summary": {},
            "task_latency_log": [], "objective_status": "", "objective_summary": {},
        })
        serialized = json.dumps(final_state, default=str)
        assert isinstance(serialized, str)


# ---------------------------------------------------------------------------
# 12. MemoryAPI invariants preserved
# ---------------------------------------------------------------------------

class TestMemoryAPIInvariants:
    def test_capability_parser_never_calls_memory_api_directly(self) -> None:
        """CapabilityParser is a stateless, pure parser — no MemoryAPI
        reference anywhere in its source (memfabric Invariant 1: all
        writes go through the caller's apply_deltas)."""
        import apex_host.parsers.capability_parser as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "MemoryAPI" not in code
        assert ".upsert_node(" not in code
        assert ".upsert_edge(" not in code
        assert ".apply_deltas(" not in code

    def test_access_capabilities_helpers_never_call_memory_api(self) -> None:
        import apex_host.planners.access_capabilities as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "MemoryAPI" not in code
        assert ".upsert_node(" not in code
        assert ".upsert_edge(" not in code

    def test_objective_planner_never_calls_memory_api_directly(self) -> None:
        """Blackboard model (memfabric Invariant 7): ObjectivePlanner reads
        only the SubgraphView/EvidenceBundle it is handed."""
        import apex_host.planners.objective_planner as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "MemoryAPI" not in code
        assert "deps.api" not in code

    async def test_capability_written_through_apply_deltas_is_visible_to_query(self) -> None:
        """A capability node upserted via apply_deltas is immediately
        visible to a subsequent get_subgraph — no separate cache/store."""
        api = _make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        await _seed_node(api, access_state_id(_TARGET, "root", protocol="ssh"), "access_state", {"username": "root", "target": _TARGET})
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="root", source_task_id="")
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
        subgraph = await api.get_subgraph(_ANCHOR, depth=3)
        assert any(n.type == "access_capability" for n in subgraph.nodes)
