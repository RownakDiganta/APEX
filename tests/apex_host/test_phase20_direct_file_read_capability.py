# test_phase20_direct_file_read_capability.py
# Regression tests for Phase 20: the generic, bounded, policy-gated direct-file-read access capability — capability model, derivation, runtime registry, adapter security, planner/executor/parser transport-independence, policy, EKG, and full-graph verification without SSH.
"""Phase 20 regression tests: direct file-read access capability.

Covers the full flow:

    validated application file-read primitive
        -> AccessCapability(type=arbitrary_file_read | api_file_read)
        -> CapabilityRuntimeRegistry
        -> DirectFileReadCapabilityAdapter.read_bounded_file(path)
        -> verify_user_flag()
        -> objective evidence
        -> user_flag_verified

No test performs a real HTTP request — ``httpx.AsyncClient`` is always
exercised against ``httpx.MockTransport`` (monkeypatched into
``DirectFileReadCapabilityAdapter.__init__``, mirroring
``test_phase18_user_flag_objective.py``'s ``_install_fake_ssh`` pattern for
Paramiko). No test requires a real HTB machine, Docker, VPN, or internet
access. This phase is not a specific exploit or a named-machine solver —
every fixture uses a synthetic target and a synthetic, well-formed
(never real) flag-shaped token.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import re
from pathlib import Path
from typing import Any, Callable

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
from memfabric.types import AbandonSignal, Edge, EvidenceBundle, Goal, Node, SubgraphView, TaskSpec

from apex_host.config import ApexConfig
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.graph_ids import (
    access_capability_id,
    access_state_id,
    endpoint_id,
    host_id,
    service_id,
)
from apex_host.orchestration.capability_seed import seed_direct_file_read_capability
from apex_host.orchestration.outcome import EngagementOutcome, exit_code_for, is_success_outcome
from apex_host.parsers.capability_parser import CapabilityParser
from apex_host.planners.access_capabilities import (
    access_capabilities_from_subgraph,
    capability_type_label,
)
from apex_host.planners.objective_planner import ObjectivePlanner, _ObjectiveDeterministic
from apex_host.policy import PolicyAdvisor, load_policy
from apex_host.policy.rules import check_bounded_user_flag_verification
from apex_host.runtime_registry import (
    BoundedReadResult,
    CapabilityRuntimeRegistry,
    DirectFileReadCapabilityAdapter,
    DirectFileReadPrimitive,
)
from apex_host.tools.registry import ToolRegistry
from apex_host.types import AccessCapability, AccessCapabilityType
from apex_host.verification.user_flag import verify_user_flag

_TARGET = "10.10.10.190"
_ANCHOR = host_id(_TARGET)
_ORIGIN = f"http://{_TARGET}:80"
_TEMPLATE = "/download.php?file={path}"
_FLAG_VALUE = "b2e7f4c19a3d0865"  # a plausible, well-formed synthetic token — never a real HTB flag

_TRIPLE_QUOTED_RE = re.compile(r'("""|\'\'\')(?:.|\n)*?\1')


def _non_comment_code(source: str) -> str:
    """Strip triple-quoted docstrings and full-line ``#`` comments — mirrors
    ``test_access_capability_refactor.py``'s identical helper, so an
    architecture scan matches real code/identifiers, not prose."""
    stripped = _TRIPLE_QUOTED_RE.sub("", source)
    return "\n".join(line for line in stripped.splitlines() if not line.strip().startswith("#"))


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


def _make_primitive(
    *, capability_id: str = "cap-1", max_response_bytes: int = 4096,
    allow_redirects: bool = False, allowed_filenames: frozenset[str] = frozenset({"user.txt"}),
    method: str = "GET", headers: dict[str, str] | None = None,
) -> DirectFileReadPrimitive:
    return DirectFileReadPrimitive(
        capability_id=capability_id, target_origin=_ORIGIN, endpoint_template=_TEMPLATE,
        method=method, headers=headers or {}, timeout_seconds=5.0,
        max_response_bytes=max_response_bytes, allow_redirects=allow_redirects,
        allowed_filenames=allowed_filenames,
    )


def _mock_handler(body: str, *, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body)
    return handler


def _install_fake_http(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> None:
    """Patch ``DirectFileReadCapabilityAdapter`` to always use an
    ``httpx.MockTransport`` — no real network I/O ever occurs. Mirrors
    ``test_phase18_user_flag_objective.py``'s ``_install_fake_ssh`` pattern."""
    import apex_host.runtime_registry as registry_mod

    transport = httpx.MockTransport(handler)
    orig_init = registry_mod.DirectFileReadCapabilityAdapter.__init__

    def patched_init(self: Any, primitive: Any, *, transport_: httpx.AsyncBaseTransport = transport) -> None:
        orig_init(self, primitive, transport=transport_)

    monkeypatch.setattr(registry_mod.DirectFileReadCapabilityAdapter, "__init__", patched_init)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _goal(target: str, phase: str = "objective") -> Goal:
    return Goal(id="goal-1", description="verify objective", phase=phase, anchor_node=host_id(target))


async def _subgraph(api: MemoryAPI, target: str) -> SubgraphView:
    return await api.get_subgraph(host_id(target), depth=10)


async def _seed_validated_dfr_capability(
    api: MemoryAPI, target: str, *, principal: str = "application",
    capability_type: AccessCapabilityType = AccessCapabilityType.arbitrary_file_read,
    confidence: float = 0.7, runtime_available: bool = True,
) -> str:
    """Seed host + a validated, runtime-available direct-file-read
    capability — the precondition ObjectivePlanner requires. Uses the real
    ``CapabilityParser.derive_direct_file_read_capability()`` to build the
    node/edges, then marks it runtime-available (simulating what
    ``dispatch_node.py``'s registration step would do) at a confidence
    below MemoryAPI's conflict_confidence_floor, mirroring the production
    fix for the exact same collision documented in
    ``apex_host/orchestration/dispatch_node.py``."""
    h_id = host_id(target)
    await _seed_node(api, h_id, "host", {"ip": target})
    parsed = CapabilityParser().derive_direct_file_read_capability(
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


# ---------------------------------------------------------------------------
# 1. Capability model
# ---------------------------------------------------------------------------

class TestCapabilityModel:
    def test_arbitrary_file_read_type_exists(self) -> None:
        assert AccessCapabilityType.arbitrary_file_read.value == "arbitrary_file_read"

    def test_api_file_read_type_exists(self) -> None:
        assert AccessCapabilityType.api_file_read.value == "api_file_read"

    def test_no_exploit_specific_capability_types_exist(self) -> None:
        names = {t.value for t in AccessCapabilityType}
        forbidden = {"alert_xss", "lfi_exploit", "shoppy_read", "twomillion_download"}
        assert not (names & forbidden)

    def test_capability_serializes_to_json(self) -> None:
        cap = AccessCapability(
            capability_id=access_capability_id(_TARGET, "arbitrary_file_read", "application"),
            host_id=_ANCHOR, capability_type=AccessCapabilityType.arbitrary_file_read,
            validated=True, principal="application", confidence=0.7, source_task_id="",
            metadata={"validation_method": "operator_attestation"},
        )
        payload = {
            "capability_id": cap.capability_id, "capability_type": str(cap.capability_type.value),
            "validated": cap.validated, "principal": cap.principal, "confidence": cap.confidence,
            "metadata": cap.metadata, "runtime_available": cap.runtime_available,
        }
        serialized = json.dumps(payload)
        assert isinstance(serialized, str)
        assert "application" in serialized

    def test_labels_are_direct_file_read_and_api_file_read(self) -> None:
        """The task's own report examples say 'Capability used: Direct File
        Read' and 'Capability used: API File Read' — never
        'Arbitrary File Read'."""
        assert capability_type_label(AccessCapabilityType.arbitrary_file_read.value) == "Direct File Read"
        assert capability_type_label(AccessCapabilityType.api_file_read.value) == "API File Read"

    def test_graph_ids_are_content_addressed_and_distinct_per_type(self) -> None:
        afr_id = access_capability_id(_TARGET, "arbitrary_file_read", "application")
        api_id = access_capability_id(_TARGET, "api_file_read", "application")
        assert afr_id != api_id
        assert afr_id == access_capability_id(_TARGET, "arbitrary_file_read", "application")

    def test_sanitized_metadata_shape(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="operator_attestation",
            confidence=0.7, requires_auth=True, max_response_bytes=4096, request_shape_id="shape-1",
        )
        node = parsed.node_deltas[0]
        metadata = node.props["metadata"]
        assert set(metadata.keys()) == {"validation_method", "requires_auth", "max_response_bytes", "request_shape_id"}
        forbidden_terms = ("cookie", "password", "token", "header", "body")
        serialized = json.dumps(metadata).lower()
        for term in forbidden_terms:
            assert term not in serialized


# ---------------------------------------------------------------------------
# 2. Capability derivation
# ---------------------------------------------------------------------------

class TestCapabilityDerivation:
    def test_valid_structured_evidence_derives_capability(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="canary_file_match",
            confidence=0.8,
        )
        assert len(parsed.node_deltas) == 1
        assert parsed.node_deltas[0].type == "access_capability"

    def test_unrecognised_validation_method_does_not_derive(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="a_payload_was_attempted",
            confidence=0.9,
        )
        assert parsed.node_deltas == []
        assert parsed.edge_deltas == []

    def test_http_200_alone_is_insufficient(self) -> None:
        """'http_200' (or any status-code-only signal) is not in the
        accepted validation-method set — an HTTP 200 alone is never
        positive evidence of a file read."""
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="http_200",
            confidence=0.9,
        )
        assert parsed.node_deltas == []

    def test_llm_assertion_alone_is_insufficient(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="llm_claimed_vulnerable",
            confidence=0.95,
        )
        assert parsed.node_deltas == []

    def test_low_confidence_recognised_method_still_rejected(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="canary_file_match",
            confidence=0.1,
        )
        assert parsed.node_deltas == []

    def test_empty_principal_does_not_derive(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        assert parsed.node_deltas == []

    def test_wrong_capability_type_does_not_derive(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
            principal="application", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        assert parsed.node_deltas == []

    def test_duplicate_derivation_is_idempotent(self) -> None:
        first = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="t1", validation_method="operator_attestation", confidence=0.9,
        )
        second = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="t2", validation_method="operator_attestation", confidence=0.9,
        )
        assert first.node_deltas[0].id == second.node_deltas[0].id

    def test_host_has_capability_relationship_is_correct(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        h_id = host_id(_TARGET)
        cap_id = access_capability_id(_TARGET, "arbitrary_file_read", "application")
        has_cap_edges = [e for e in parsed.edge_deltas if e.type == "has_capability"]
        assert len(has_cap_edges) == 1
        assert has_cap_edges[0].from_id == h_id
        assert has_cap_edges[0].to_id == cap_id

    def test_source_evidence_relationship_is_correct_when_supplied(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="operator_attestation",
            confidence=0.9, source_node_id="endpoint:some-evidence-node",
        )
        cap_id = access_capability_id(_TARGET, "arbitrary_file_read", "application")
        enables_edges = [e for e in parsed.edge_deltas if e.type == "enables"]
        assert len(enables_edges) == 1
        assert enables_edges[0].from_id == "endpoint:some-evidence-node"
        assert enables_edges[0].to_id == cap_id

    def test_no_source_evidence_edge_when_not_supplied(self) -> None:
        parsed = CapabilityParser().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        assert all(e.type != "enables" for e in parsed.edge_deltas)

    def test_api_file_read_and_arbitrary_file_read_share_one_adapter_class(self) -> None:
        """Behaviorally identical at runtime — both resolve to
        DirectFileReadCapabilityAdapter, never a distinct class per type."""
        p1 = _make_primitive(capability_id="a")
        p2 = _make_primitive(capability_id="b")
        adapter1 = DirectFileReadCapabilityAdapter(p1)
        adapter2 = DirectFileReadCapabilityAdapter(p2)
        assert type(adapter1) is type(adapter2) is DirectFileReadCapabilityAdapter


# ---------------------------------------------------------------------------
# 3. Runtime registry
# ---------------------------------------------------------------------------

class TestRuntimeRegistry:
    def test_ensure_direct_file_read_registers_adapter(self) -> None:
        registry = CapabilityRuntimeRegistry()
        primitive = _make_primitive()
        adapter = registry.ensure_direct_file_read("cap-1", primitive=primitive)
        assert registry.has("cap-1") is True
        assert registry.get("cap-1") is adapter

    def test_ensure_direct_file_read_is_idempotent(self) -> None:
        registry = CapabilityRuntimeRegistry()
        first = registry.ensure_direct_file_read("cap-1", primitive=_make_primitive())
        second = registry.ensure_direct_file_read("cap-1", primitive=_make_primitive())
        assert first is second

    def test_unregistered_capability_resolves_to_none(self) -> None:
        registry = CapabilityRuntimeRegistry()
        assert registry.get("never-registered") is None

    def test_replacing_via_register_overwrites(self) -> None:
        registry = CapabilityRuntimeRegistry()

        class _DummyA:
            async def read_bounded_file(self, path: str) -> BoundedReadResult:
                return BoundedReadResult(connected=True, output="a", error=None)

        class _DummyB:
            async def read_bounded_file(self, path: str) -> BoundedReadResult:
                return BoundedReadResult(connected=True, output="b", error=None)

        registry.register("cap-1", _DummyA())
        registry.register("cap-1", _DummyB())
        assert isinstance(registry.get("cap-1"), _DummyB)

    def test_registry_is_a_plain_in_process_dict(self) -> None:
        registry = CapabilityRuntimeRegistry()
        assert isinstance(registry._adapters, dict)  # type: ignore[attr-defined]

    def test_registry_never_appears_in_apex_graph_state_annotations(self) -> None:
        from apex_host.graph_state import ApexGraphState
        annotations = getattr(ApexGraphState, "__annotations__", {})
        for name, ann in annotations.items():
            assert "CapabilityRuntimeRegistry" not in str(ann), name

    def test_orchestration_deps_capability_registry_is_frozen(self) -> None:
        from apex_host.orchestration.dependencies import OrchestrationDeps
        assert OrchestrationDeps.__dataclass_params__.frozen is True  # type: ignore[attr-defined]

    async def test_missing_runtime_material_leaves_capability_unavailable(self) -> None:
        """A validated capability with NO operator-supplied primitive
        configuration must not be considered executable — registration
        fails gracefully, runtime_available stays False."""
        from apex_host.orchestration.dispatch_node import _register_capability_adapter

        api = _make_api()
        cap_id = await _seed_validated_dfr_capability(api, _TARGET, runtime_available=False)
        subgraph = await _subgraph(api, _TARGET)
        capability = next(c for c in access_capabilities_from_subgraph(subgraph) if c.capability_id == cap_id)

        config = ApexConfig(target=_TARGET, dry_run=True)  # no direct_file_read_* fields set
        registry = CapabilityRuntimeRegistry()
        deps = _fake_deps(api, config, registry)
        registered = _register_capability_adapter(deps, subgraph, _TARGET, capability)
        assert registered is False
        assert registry.has(cap_id) is False


def _fake_deps(api: MemoryAPI, config: ApexConfig, registry: CapabilityRuntimeRegistry) -> Any:
    """Minimal stand-in exposing only the attributes
    ``_register_capability_adapter`` reads (``api``/``config``/
    ``capability_registry``) — avoids constructing a full
    ``OrchestrationDeps`` (which needs a dispatcher/planners/etc. this test
    never uses)."""
    class _Deps:
        pass

    d = _Deps()
    d.api = api  # type: ignore[attr-defined]
    d.config = config  # type: ignore[attr-defined]
    d.capability_registry = registry  # type: ignore[attr-defined]
    return d


# ---------------------------------------------------------------------------
# 4. Adapter behavior
# ---------------------------------------------------------------------------

class TestAdapterBehavior:
    async def test_bounded_candidate_substitution(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, text=_FLAG_VALUE)

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive())
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.connected is True
        assert "file=%2Fhome%2Fapplication%2Fuser.txt" in captured["url"] or "/home/application/user.txt" in captured["url"]

    async def test_fixed_authorized_origin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, text=_FLAG_VALUE)

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive())
        await adapter.read_bounded_file("/home/application/user.txt")
        # httpx omits the default HTTP port (80) when serializing a URL, so
        # compare structurally rather than by exact string prefix.
        from urllib.parse import urlsplit
        parsed = urlsplit(captured["url"])
        expected = urlsplit(_ORIGIN)
        assert parsed.hostname == expected.hostname
        assert parsed.scheme == expected.scheme

    async def test_fixed_request_method(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            return httpx.Response(200, text=_FLAG_VALUE)

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(method="POST"))
        await adapter.read_bounded_file("/home/application/user.txt")
        assert captured["method"] == "POST"

    async def test_fixed_request_headers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["cookie"] = request.headers.get("Cookie", "")
            return httpx.Response(200, text=_FLAG_VALUE)

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(headers={"Cookie": "session=abc123"}))
        await adapter.read_bounded_file("/home/application/user.txt")
        assert captured["cookie"] == "session=abc123"

    async def test_maximum_bytes_enforced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_http(monkeypatch, _mock_handler("x" * 10000))
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(max_response_bytes=100))
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.truncated is True
        assert result.output == ""
        assert result.error is not None and "exceeds" in result.error

    async def test_timeout_enforced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("simulated timeout")

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive())
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.connected is False
        assert result.error is not None and "timed out" in result.error

    async def test_errors_are_sanitized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Error strings never contain a header value, cookie, or full URL
        with query parameters."""
        _install_fake_http(monkeypatch, _mock_handler("nope", status=500))
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(headers={"Cookie": "supersecretvalue"}))
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.error is not None
        assert "supersecretvalue" not in result.error
        assert "?" not in result.error

    def test_no_arbitrary_url_control(self) -> None:
        """read_bounded_file's ONLY parameter is the bounded path."""
        sig = inspect.signature(DirectFileReadCapabilityAdapter.read_bounded_file)
        assert list(sig.parameters) == ["self", "path"]

    def test_no_arbitrary_headers_control(self) -> None:
        """Headers are fixed at primitive-construction time; the read call
        itself cannot supply headers."""
        sig = inspect.signature(DirectFileReadCapabilityAdapter.read_bounded_file)
        assert "headers" not in sig.parameters

    def test_no_arbitrary_body_control(self) -> None:
        sig = inspect.signature(DirectFileReadCapabilityAdapter.read_bounded_file)
        assert "body" not in sig.parameters and "data" not in sig.parameters

    def test_no_generic_command_execution(self) -> None:
        """The adapter exposes no method beyond read_bounded_file — no
        exec/run/shell/command method exists on the class."""
        members = [name for name, _ in inspect.getmembers(DirectFileReadCapabilityAdapter) if not name.startswith("_")]
        assert members == ["read_bounded_file"]


# ---------------------------------------------------------------------------
# 5. Origin and redirect security
# ---------------------------------------------------------------------------

class TestOriginAndRedirectSecurity:
    async def test_external_redirect_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://evil.example.com/steal"})

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(allow_redirects=True))
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.output == ""
        assert result.error is not None and "outside the authorized origin" in result.error

    async def test_scheme_change_in_redirect_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": f"https://{_TARGET}:80/download.php?file=x"})

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(allow_redirects=True))
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.error is not None and "outside the authorized origin" in result.error

    async def test_host_change_in_redirect_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://10.10.10.191:80/download.php?file=x"})

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(allow_redirects=True))
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.error is not None and "outside the authorized origin" in result.error

    async def test_port_change_in_redirect_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": f"http://{_TARGET}:8080/download.php?file=x"})

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(allow_redirects=True))
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.error is not None and "outside the authorized origin" in result.error

    def test_userinfo_in_origin_rejected(self) -> None:
        with pytest.raises(ValueError, match="userinfo"):
            DirectFileReadPrimitive(
                capability_id="x", target_origin="http://user:pass@10.10.10.190:80",
                endpoint_template=_TEMPLATE,
            )

    def test_unsupported_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="scheme"):
            DirectFileReadPrimitive(capability_id="x", target_origin="ftp://10.10.10.190", endpoint_template=_TEMPLATE)

    async def test_redirect_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": f"{_ORIGIN}/other"})

        _install_fake_http(monkeypatch, handler)
        primitive = _make_primitive()
        assert primitive.allow_redirects is False
        adapter = DirectFileReadCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.error is not None and "disabled" in result.error

    async def test_authorized_same_origin_redirect_followed_when_explicitly_enabled(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "file=" in str(request.url) and "redirected" not in str(request.url):
                return httpx.Response(302, headers={"Location": f"{_ORIGIN}/download.php?file=redirected"})
            return httpx.Response(200, text=_FLAG_VALUE)

        _install_fake_http(monkeypatch, handler)
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(allow_redirects=True))
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.connected is True
        assert result.output == _FLAG_VALUE
        assert result.error is None


# ---------------------------------------------------------------------------
# 6. Candidate-path security
# ---------------------------------------------------------------------------

class TestCandidatePathSecurity:
    async def test_valid_candidate_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))
        adapter = DirectFileReadCapabilityAdapter(_make_primitive())
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.connected is True

    async def test_traversal_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))
        adapter = DirectFileReadCapabilityAdapter(_make_primitive())
        result = await adapter.read_bounded_file("/home/../etc/user.txt")
        assert result.connected is False
        assert "bounded-path validation" in (result.error or "")

    async def test_relative_path_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))
        adapter = DirectFileReadCapabilityAdapter(_make_primitive())
        result = await adapter.read_bounded_file("home/application/user.txt")
        assert result.connected is False

    async def test_unapproved_basename_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))
        adapter = DirectFileReadCapabilityAdapter(_make_primitive(allowed_filenames=frozenset({"user.txt"})))
        result = await adapter.read_bounded_file("/home/application/root.txt")
        assert result.connected is False

    async def test_wildcard_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))
        adapter = DirectFileReadCapabilityAdapter(_make_primitive())
        result = await adapter.read_bounded_file("/home/application/*.txt")
        assert result.connected is False

    async def test_oversized_path_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))
        adapter = DirectFileReadCapabilityAdapter(_make_primitive())
        long_path = "/" + ("a" * 300) + "/user.txt"
        result = await adapter.read_bounded_file(long_path)
        assert result.connected is False

    async def test_one_candidate_per_task(self) -> None:
        """ObjectivePlanner's TaskSpec carries exactly one candidate_path —
        never a list, never multiple tasks per turn."""
        api = _make_api()
        await _seed_validated_dfr_capability(api, _TARGET)
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0].params["candidate_path"], str)


# ---------------------------------------------------------------------------
# 7. UserFlagExecutor transport independence
# ---------------------------------------------------------------------------

class TestUserFlagExecutorIndependence:
    async def test_same_executor_works_with_ssh_adapter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.runtime_registry as registry_mod

        class _FakeSSHClient:
            def set_missing_host_key_policy(self, policy: Any) -> None:
                pass

            def connect(self, **kwargs: Any) -> None:
                pass

            def exec_command(self, command: str, timeout: float | None = None) -> Any:
                class _F:
                    def __init__(self, data: bytes) -> None:
                        self._data = data
                        self.channel = type("C", (), {"recv_exit_status": lambda self: 0})()

                    def read(self, n: int = -1) -> bytes:
                        return self._data

                return None, _F(f"{_FLAG_VALUE}\n".encode()), _F(b"")

            def close(self) -> None:
                pass

        monkeypatch.setattr(registry_mod.paramiko, "SSHClient", lambda: _FakeSSHClient())

        from apex_host.agents.user_flag_executor import UserFlagExecutor

        registry = CapabilityRuntimeRegistry()
        registry.ensure_ssh(
            "ssh-cap", target=_TARGET, port="22", username="root", password="pw",
            config=ApexConfig(target=_TARGET),
        )
        config = ApexConfig(target=_TARGET, dry_run=False)
        executor = UserFlagExecutor(config, registry)
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET, "capability_id": "ssh-cap",
                "capability_type": "ssh_command", "principal": "root",
                "candidate_path": "/home/root/user.txt", "objective_type": "user_flag",
                "attempted_paths": [], "is_last_candidate": False,
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        result = await executor.run(task, _empty_evidence())
        assert result.episode.data["verified"] is True

    async def test_same_executor_works_with_direct_file_read_adapter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))
        from apex_host.agents.user_flag_executor import UserFlagExecutor

        registry = CapabilityRuntimeRegistry()
        registry.ensure_direct_file_read("dfr-cap", primitive=_make_primitive(capability_id="dfr-cap"))
        config = ApexConfig(target=_TARGET, dry_run=False)
        executor = UserFlagExecutor(config, registry)
        task = TaskSpec(
            id="t2", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET, "capability_id": "dfr-cap",
                "capability_type": "arbitrary_file_read", "principal": "application",
                "candidate_path": "/home/application/user.txt", "objective_type": "user_flag",
                "attempted_paths": [], "is_last_candidate": False,
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        result = await executor.run(task, _empty_evidence())
        assert result.episode.data["verified"] is True

    def test_executor_has_no_ssh_imports(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "paramiko" not in code

    def test_executor_has_no_http_imports(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "httpx" not in code
        assert "import requests" not in code

    def test_executor_has_no_capability_type_branching(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "AccessCapabilityType" not in code
        assert "ssh_command" not in code
        assert "arbitrary_file_read" not in code
        assert "api_file_read" not in code

    def test_executor_has_no_credential_handling(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "password" not in code.lower()

    def test_executor_has_no_url_construction(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "urlsplit" not in code and "urljoin" not in code and "f\"http" not in code

    async def test_executor_does_not_return_raw_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))
        from apex_host.agents.user_flag_executor import UserFlagExecutor

        registry = CapabilityRuntimeRegistry()
        registry.ensure_direct_file_read("dfr-cap", primitive=_make_primitive(capability_id="dfr-cap"))
        config = ApexConfig(target=_TARGET, dry_run=False)
        executor = UserFlagExecutor(config, registry)
        task = TaskSpec(
            id="t3", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET, "capability_id": "dfr-cap",
                "capability_type": "arbitrary_file_read", "principal": "application",
                "candidate_path": "/home/application/user.txt", "objective_type": "user_flag",
                "attempted_paths": [], "is_last_candidate": False,
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        result = await executor.run(task, _empty_evidence())
        serialized = json.dumps(result.episode.data, default=str)
        assert _FLAG_VALUE not in serialized

    async def test_executor_does_not_log_raw_output(self, monkeypatch: pytest.MonkeyPatch, caplog: Any) -> None:
        import logging
        caplog.set_level(logging.DEBUG, logger="apex_host.agents.user_flag_executor")
        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))

        from apex_host.agents.user_flag_executor import UserFlagExecutor

        registry = CapabilityRuntimeRegistry()
        registry.ensure_direct_file_read("dfr-cap", primitive=_make_primitive(capability_id="dfr-cap"))
        config = ApexConfig(target=_TARGET, dry_run=False)
        executor = UserFlagExecutor(config, registry)
        task = TaskSpec(
            id="t4", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET, "capability_id": "dfr-cap",
                "capability_type": "arbitrary_file_read", "principal": "application",
                "candidate_path": "/home/application/user.txt", "objective_type": "user_flag",
                "attempted_paths": [], "is_last_candidate": False,
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        await executor.run(task, _empty_evidence())
        assert _FLAG_VALUE not in caplog.text

    def test_objective_planner_has_no_ssh_or_http_imports(self) -> None:
        import apex_host.planners.objective_planner as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "paramiko" not in code
        assert "httpx" not in code

    def test_objective_planner_has_no_capability_type_branching(self) -> None:
        import apex_host.planners.objective_planner as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "ssh_command" not in code
        assert "arbitrary_file_read" not in code
        assert "api_file_read" not in code

    def test_objective_parser_has_no_ssh_or_http_imports(self) -> None:
        import apex_host.parsers.objective_parser as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "paramiko" not in code
        assert "httpx" not in code
        assert "ssh_command" not in code
        assert "arbitrary_file_read" not in code


# ---------------------------------------------------------------------------
# 8. Verifier integration
# ---------------------------------------------------------------------------

class TestVerifierIntegration:
    def test_dfr_output_verified_by_the_one_authoritative_verifier(self) -> None:
        result = verify_user_flag(_FLAG_VALUE)
        assert result.verified is True
        assert not hasattr(result, "raw") and not hasattr(result, "value")

    def test_bounded_read_result_output_flows_through_verify_user_flag_unmodified(self) -> None:
        read_result = BoundedReadResult(connected=True, output=_FLAG_VALUE, error=None, status_code=200)
        result = verify_user_flag(read_result.output, raw_error=read_result.error or "")
        assert result.verified is True

    def test_error_marker_in_body_rejected_via_same_verifier(self) -> None:
        read_result = BoundedReadResult(connected=True, output="No such file or directory", error=None, status_code=200)
        result = verify_user_flag(read_result.output)
        assert result.verified is False

    def test_oversized_dfr_response_never_verified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The adapter itself already rejects oversized bodies (category 4);
        this proves the SAME guarantee holds even if a caller fed a
        would-be-oversized body straight to the verifier — defense in
        depth, matching every other authoritative-verifier caller."""
        result = verify_user_flag("x" * 10000, max_output_bytes=4096)
        assert result.verified is False

    def test_verifier_result_has_no_plaintext_field(self) -> None:
        result = verify_user_flag(_FLAG_VALUE)
        field_names = {f.name for f in __import__("dataclasses").fields(result)}
        assert field_names == {"verified", "reason", "digest", "redacted", "length", "method"}
        serialized = json.dumps({"verified": result.verified, "reason": result.reason, "digest": result.digest, "redacted": result.redacted})
        assert _FLAG_VALUE not in serialized

    def test_digest_is_sha256_of_candidate(self) -> None:
        result = verify_user_flag(_FLAG_VALUE)
        assert result.digest == hashlib.sha256(_FLAG_VALUE.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 9. Policy
# ---------------------------------------------------------------------------

class TestPolicy:
    def test_approves_bounded_dfr_candidate_against_target(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "candidate_path": "/home/application/user.txt",
                "capability_id": "dfr-cap", "capability_type": "arbitrary_file_read",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None and decision.status.value == "approved"

    def test_blocks_unbounded_dfr_candidate_path(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t2", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "candidate_path": "/etc/shadow",
                "capability_id": "dfr-cap", "capability_type": "arbitrary_file_read",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None and decision.status.value == "blocked"

    async def test_dispatcher_blocks_off_scope_dfr_target_before_adapter_reached(self) -> None:
        from apex_host.execution.dispatcher import TaskDispatcher
        from apex_host.execution.registry import TaskRegistry

        config = ApexConfig(target=_TARGET, dry_run=False)
        advisor = PolicyAdvisor(load_policy(config), config)

        class _SpyExecutor:
            calls = 0

            async def run(self, task: Any, evidence: Any) -> Any:
                type(self).calls += 1
                raise AssertionError("adapter/executor must never be reached for an off-scope target")

        dispatcher = TaskDispatcher(
            advisor=advisor, task_registry=TaskRegistry(), config=config,
            run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type]
            user_flag_executor=_SpyExecutor(),  # type: ignore[arg-type]
        )
        task = TaskSpec(
            id="t3", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": "8.8.8.8",  # off-scope
                "candidate_path": "/home/application/user.txt",
                "capability_id": "dfr-cap", "capability_type": "arbitrary_file_read",
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

    def test_policy_never_receives_request_shape_fields(self) -> None:
        """The rule inspects only target/candidate_path — headers, origin,
        method, and cookies never need to reach it (the request shape is
        never task-controlled at all)."""
        code = _non_comment_code(inspect.getsource(check_bounded_user_flag_verification))
        for forbidden in ("headers", "cookie", "origin", "endpoint_template"):
            assert forbidden not in code


# ---------------------------------------------------------------------------
# 10. Planner
# ---------------------------------------------------------------------------

class TestPlanner:
    async def test_planner_selects_available_dfr_capability_with_no_ssh_present(self) -> None:
        api = _make_api()
        await _seed_validated_dfr_capability(api, _TARGET)
        subgraph = await _subgraph(api, _TARGET)
        planner = ObjectivePlanner(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await planner.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list) and len(result) == 1
        assert result[0].params["capability_type"] == "arbitrary_file_read"

    async def test_planner_never_selects_capability_without_runtime_adapter(self) -> None:
        api = _make_api()
        await _seed_validated_dfr_capability(api, _TARGET, runtime_available=False)
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, AbandonSignal)

    async def test_planner_prefers_higher_confidence_between_two_available_capabilities(self) -> None:
        api = _make_api()
        await _seed_validated_dfr_capability(
            api, _TARGET, principal="app_low", confidence=0.6,
        )
        high_id = await _seed_validated_dfr_capability(
            api, _TARGET, principal="app_high", confidence=0.9,
        )
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["capability_id"] == high_id

    async def test_failed_ssh_attempt_does_not_block_dfr_retry_on_same_path(self) -> None:
        """The exact Phase 20 retry-scoping requirement: a failed SSH
        attempt on a candidate path must not prevent trying the SAME path
        through a newly available direct-file-read capability."""
        api = _make_api()
        ssh_cap_id = access_capability_id(_TARGET, "ssh_command", "application")
        h_id = host_id(_TARGET)
        acc_id = access_state_id(_TARGET, "application", protocol="ssh")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, acc_id, "access_state", {"level": "user", "username": "application", "target": _TARGET, "service": "ssh"})
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="application", source_task_id="")
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
        ts = now()
        await api.upsert_node(Node(id=ssh_cap_id, type="access_capability", props={"runtime_available": True}, confidence=0.5, source="t", first_seen=ts, last_seen=ts))
        dfr_cap_id = await _seed_validated_dfr_capability(api, _TARGET, principal="application")
        from apex_host.graph_ids import objective_id
        obj_id = objective_id(_TARGET, "user_flag")
        await _seed_node(api, obj_id, "objective", {
            "objective_type": "user_flag", "status": "in_progress", "target": _TARGET,
            "attempted_paths": ["/home/application/user.txt"],
            "attempted_capability_paths": [[ssh_cap_id, "/home/application/user.txt"]],
        })
        await _seed_edge(api, h_id, obj_id, edge_type="indicates")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list), "DFR retry of the SSH-attempted path must still be offered"
        assert result[0].params["capability_id"] == dfr_cap_id
        assert result[0].params["candidate_path"] == "/home/application/user.txt"

    async def test_true_global_exhaustion_required_for_failed_status(self) -> None:
        api = _make_api()
        dfr_cap_id = await _seed_validated_dfr_capability(api, _TARGET, principal="application")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        prospective = {(dfr_cap_id, "/home/application/user.txt")}
        assert core._is_globally_exhausted(subgraph, prospective) is True

    def test_no_exploit_or_transport_specific_planning_branches(self) -> None:
        import apex_host.planners.objective_planner as mod
        code = _non_comment_code(inspect.getsource(mod))
        for forbidden in ("lfi", "xss", "sql", "traversal_payload"):
            assert forbidden not in code.lower()


# ---------------------------------------------------------------------------
# 11. EKG and persistence
# ---------------------------------------------------------------------------

class TestEKGAndPersistence:
    async def test_capability_seed_derives_from_operator_attested_config(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True,
            direct_file_read_operator_attested=True,
            direct_file_read_origin=_ORIGIN,
            direct_file_read_endpoint_template=_TEMPLATE,
            direct_file_read_principal="application",
        )
        seeded = await seed_direct_file_read_capability(api, config)
        assert seeded is True
        subgraph = await _subgraph(api, _TARGET)
        caps = access_capabilities_from_subgraph(subgraph)
        assert len(caps) == 1
        assert caps[0].capability_type is AccessCapabilityType.arbitrary_file_read

    async def test_capability_seed_is_idempotent(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True,
            direct_file_read_operator_attested=True,
            direct_file_read_origin=_ORIGIN,
            direct_file_read_endpoint_template=_TEMPLATE,
            direct_file_read_principal="application",
        )
        first = await seed_direct_file_read_capability(api, config)
        second = await seed_direct_file_read_capability(api, config)
        assert first is True
        assert second is False

    async def test_capability_seed_rejects_origin_mismatched_target(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True,
            direct_file_read_operator_attested=True,
            direct_file_read_origin="http://10.10.10.191:80",  # different host
            direct_file_read_endpoint_template=_TEMPLATE,
            direct_file_read_principal="application",
        )
        seeded = await seed_direct_file_read_capability(api, config)
        assert seeded is False
        subgraph = await _subgraph(api, _TARGET)
        assert access_capabilities_from_subgraph(subgraph) == []

    async def test_capability_seed_disabled_by_default(self) -> None:
        api = _make_api()
        config = ApexConfig(target=_TARGET, dry_run=True)
        seeded = await seed_direct_file_read_capability(api, config)
        assert seeded is False

    async def test_no_secrets_persisted_in_capability_node(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True,
            direct_file_read_operator_attested=True,
            direct_file_read_origin=_ORIGIN,
            direct_file_read_endpoint_template=_TEMPLATE,
            direct_file_read_principal="application",
            direct_file_read_headers={"Cookie": "session=verysecretvalue"},
        )
        await seed_direct_file_read_capability(api, config)
        subgraph = await _subgraph(api, _TARGET)
        serialized = json.dumps([n.props for n in subgraph.nodes])
        assert "verysecretvalue" not in serialized

    async def test_runtime_registry_never_persisted_to_ekg(self) -> None:
        """CapabilityRuntimeRegistry itself is never written as node/edge
        data — only the boolean runtime_available fact is."""
        api = _make_api()
        cap_id = await _seed_validated_dfr_capability(api, _TARGET)
        subgraph = await _subgraph(api, _TARGET)
        node = next(n for n in subgraph.nodes if n.id == cap_id)
        serialized = json.dumps(node.props, default=str)
        assert "DirectFileReadCapabilityAdapter" not in serialized
        assert "httpx" not in serialized

    async def test_host_has_capability_edge_exists_in_persisted_graph(self) -> None:
        api = _make_api()
        cap_id = await _seed_validated_dfr_capability(api, _TARGET)
        subgraph = await _subgraph(api, _TARGET)
        has_cap = [e for e in subgraph.edges if e.type == "has_capability" and e.to_id == cap_id]
        assert len(has_cap) == 1
        assert has_cap[0].from_id == _ANCHOR


# ---------------------------------------------------------------------------
# 12. Full graph — synthetic verified success via direct file read, no SSH
# ---------------------------------------------------------------------------

def _make_initial_state(target: str, run_id: str = "run-20") -> dict[str, Any]:
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
    }


async def _seed_dfr_ready_engagement(api: MemoryAPI, target: str) -> None:
    """Seed the recon/web-phase EKG state a real engagement would already
    have produced (host + an http service + an endpoint) plus a validated,
    runtime-available direct-file-read capability — no SSH/access_state
    node anywhere, proving the objective phase is reachable through the
    direct-file-read capability alone."""
    h_id = host_id(target)
    svc_id = service_id(target, "80", "tcp")
    ep_id = endpoint_id(f"http://{target}/download.php")
    await _seed_node(api, h_id, "host", {"ip": target})
    await _seed_node(api, svc_id, "service", {"port": "80", "proto": "tcp", "service": "http", "state": "open"})
    await _seed_node(api, ep_id, "endpoint", {"url": f"http://{target}/download.php"})
    await _seed_edge(api, h_id, svc_id, edge_type="exposes")
    await _seed_edge(api, h_id, ep_id, edge_type="exposes")
    await _seed_validated_dfr_capability(api, target, principal="application")


class TestFullGraphPositive:
    async def test_full_graph_verified_success_via_direct_file_read_no_ssh(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from apex_host.graph import build_apex_graph

        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))

        api = _make_api()
        await _seed_dfr_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5,
            direct_file_read_origin=_ORIGIN, direct_file_read_endpoint_template=_TEMPLATE,
            direct_file_read_principal="application",
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] == EngagementOutcome.user_flag_verified.value
        assert is_success_outcome(EngagementOutcome(final_state["outcome"])) is True
        assert final_state["completed"] is True
        assert exit_code_for(EngagementOutcome(final_state["outcome"])) == 0

        subgraph = await _subgraph(api, _TARGET)
        assert not any(n.type == "access_state" for n in subgraph.nodes), "no SSH access_state anywhere in this run"
        assert any(n.type == "objective_evidence" for n in subgraph.nodes)

    async def test_full_graph_report_shows_direct_file_read_capability_label(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from apex_host.graph import build_apex_graph

        _install_fake_http(monkeypatch, _mock_handler(_FLAG_VALUE))

        api = _make_api()
        await _seed_dfr_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5,
            direct_file_read_origin=_ORIGIN, direct_file_read_endpoint_template=_TEMPLATE,
            direct_file_read_principal="application",
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        subgraph = await _subgraph(api, _TARGET)

        report = build_report(final_state, subgraph, config)
        text = format_text(report)
        assert "Capability used" in text and "Direct File Read" in text
        assert "Benchmark success  : Yes" in text
        assert _FLAG_VALUE not in text

        data = to_json_dict(report)
        assert data["objective"]["benchmark_success"] is True
        assert _FLAG_VALUE not in json.dumps(data)

    async def test_full_graph_dry_run_never_verifies_via_dfr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        called = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            called["count"] += 1
            return httpx.Response(200, text=_FLAG_VALUE)

        _install_fake_http(monkeypatch, handler)

        api = _make_api()
        await _seed_dfr_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=5,
            direct_file_read_origin=_ORIGIN, direct_file_read_endpoint_template=_TEMPLATE,
            direct_file_read_principal="application",
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value
        assert called["count"] == 0, "dry-run must never issue a real (mocked) HTTP request"


# ---------------------------------------------------------------------------
# 13. Negative full graph
# ---------------------------------------------------------------------------

class TestFullGraphNegative:
    async def test_oversized_response_never_becomes_verified_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        _install_fake_http(monkeypatch, _mock_handler("x" * 10000))

        api = _make_api()
        await _seed_dfr_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=3,
            direct_file_read_origin=_ORIGIN, direct_file_read_endpoint_template=_TEMPLATE,
            direct_file_read_principal="application", direct_file_read_max_response_bytes=100,
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

    async def test_cross_origin_redirect_never_becomes_verified_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://evil.example.com/steal"})

        _install_fake_http(monkeypatch, handler)

        api = _make_api()
        await _seed_dfr_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=3,
            direct_file_read_origin=_ORIGIN, direct_file_read_endpoint_template=_TEMPLATE,
            direct_file_read_principal="application", direct_file_read_allow_redirects=True,
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

    async def test_missing_runtime_material_never_becomes_verified_success(self) -> None:
        """A validated capability exists but no direct_file_read_origin/
        endpoint_template is configured — registration fails, and access
        alone (or an unregistered capability) is never mistaken for
        success."""
        from apex_host.graph import build_apex_graph

        api = _make_api()
        await _seed_dfr_ready_engagement(api, _TARGET)
        config = ApexConfig(target=_TARGET, dry_run=False, max_turns=3)  # no direct_file_read_* configured
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value
        assert final_state["completed"] is True

    async def test_capability_metadata_alone_is_never_success(self) -> None:
        """A validated-but-NOT-runtime-available capability (metadata
        exists; no adapter) must never be reported as success, and the
        engagement must terminate rather than loop forever trying to use
        it."""
        from apex_host.graph import build_apex_graph

        api = _make_api()
        h_id = host_id(_TARGET)
        svc_id = service_id(_TARGET, "80", "tcp")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, svc_id, "service", {"port": "80", "proto": "tcp", "service": "http", "state": "open"})
        await _seed_edge(api, h_id, svc_id, edge_type="exposes")
        await _seed_validated_dfr_capability(api, _TARGET, principal="application", runtime_available=False)
        config = ApexConfig(target=_TARGET, dry_run=False, max_turns=3)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value
        assert final_state["completed"] is True


# ---------------------------------------------------------------------------
# 14. Architecture scans
# ---------------------------------------------------------------------------

_PHASE20_NEW_FILES: tuple[str, ...] = (
    "apex_host/orchestration/capability_seed.py",
)

_HTB_MACHINE_NAMES: tuple[str, ...] = (
    "meow", "fawn", "dancing", "redeemer", "explosion", "preignition",
    "mongod", "synced", "appointment", "sequel", "crocodile", "responder",
    "three", "ignition", "vaccine", "cap", "lame", "blue",
)


class TestArchitectureScans:
    def test_no_generic_url_or_ssrf_executor_introduced(self) -> None:
        """The adapter must not expose a generic 'fetch this URL' method —
        only the one bounded, path-substituting read_bounded_file()."""
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "def fetch(" not in code
        assert "def request(" not in code
        assert "def get_url(" not in code

    def test_no_shell_true_anywhere_in_new_code(self) -> None:
        import apex_host.runtime_registry as mod
        import apex_host.orchestration.capability_seed as seed_mod
        for module in (mod, seed_mod):
            code = _non_comment_code(inspect.getsource(module))
            assert "shell=True" not in code
            assert "subprocess" not in code
            assert "os.system" not in code

    def test_no_unrestricted_filesystem_search_in_new_code(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        for forbidden in ("glob.glob", "os.walk", "Path(\"/\").rglob", "find /", "**/*"):
            assert forbidden not in code

    def test_no_hardcoded_flag_values_in_new_code(self) -> None:
        for path in (
            Path("apex_host/runtime_registry.py"),
            Path("apex_host/orchestration/capability_seed.py"),
            Path("apex_host/parsers/capability_parser.py"),
            Path("apex_host/planners/objective_planner.py"),
        ):
            code = _non_comment_code(path.read_text())
            assert "HTB{" not in code
            assert "flag{" not in code.lower()

    def test_no_machine_specific_names_in_phase20_files(self) -> None:
        for rel_path in _PHASE20_NEW_FILES:
            source = Path(rel_path).read_text()
            code = _non_comment_code(source)
            for name in _HTB_MACHINE_NAMES:
                pattern = re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE)
                assert not pattern.search(code), f"{rel_path} contains machine-name-like token {name!r}"

    def test_memfabric_has_no_direct_file_read_references(self) -> None:
        memfabric_dir = Path("memfabric")
        forbidden_terms = ("direct_file_read", "arbitrary_file_read", "DirectFileReadCapabilityAdapter", "BoundedReadResult")
        for py_file in memfabric_dir.rglob("*.py"):
            code = _non_comment_code(py_file.read_text())
            for term in forbidden_terms:
                assert term not in code, f"{py_file} references {term!r} — memfabric must remain domain-agnostic"

    def test_memfabric_has_no_new_apex_host_imports(self) -> None:
        memfabric_dir = Path("memfabric")
        for py_file in memfabric_dir.rglob("*.py"):
            code = py_file.read_text()
            assert "import apex_host" not in code
            assert "from apex_host" not in code

    def test_user_flag_executor_has_no_transport_branching(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "isinstance(adapter" not in code
        assert "DirectFileReadCapabilityAdapter" not in code
        assert "SSHCapabilityAdapter" not in code

    def test_objective_parser_has_no_transport_branching(self) -> None:
        import apex_host.parsers.objective_parser as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "DirectFileReadCapabilityAdapter" not in code
        assert "SSHCapabilityAdapter" not in code

    def test_adapter_module_has_no_generic_command_string_construction(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "os.system" not in code
        assert "eval(" not in code
        assert "exec(" not in code
