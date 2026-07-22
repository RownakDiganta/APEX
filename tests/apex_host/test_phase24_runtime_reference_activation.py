# test_phase24_runtime_reference_activation.py
# Regression tests for Phase 24: RuntimeReference/RuntimeReferenceStore/RuntimeReferenceResolver, CapabilityRuntimeRegistry safe-replacement semantics, typed organic evidence emission, the shared repair-node result-processing helper, invalidation hooks, and persistence/replay guarantees.
"""Phase 24 regression tests: the runtime half of structured automatic
capability derivation.

Covers the full flow the module docstrings describe:

    register_capability_adapter() -> CapabilityRuntimeRegistry.generation_for()
        -> RuntimeReferenceStore.mint() -> RuntimeReference
        -> RuntimeReferenceResolver.resolve() -> adapter
        -> (a connection-level failure) -> unregister()/invalidate_for_capability()
        -> next turn's registration mints a NEW generation

No test performs a real network operation, requires Docker/VPN/internet,
or targets a real HTB machine. Every fixture uses a synthetic target and a
synthetic, well-formed (never real) flag-shaped token, mirroring
``tests/apex_host/test_phase23_capability_discovery.py``'s own discipline.
"""
from __future__ import annotations

import dataclasses
import inspect
import json
import re
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node, SubgraphView

from apex_host.capabilities.discovery import CapabilityDiscoveryContext, run_capability_discovery
from apex_host.capabilities.emission import (
    DirectFileReadValidationResult,
    LocalCommandValidationResult,
    RemoteCommandValidationResult,
    WebCommandValidationResult,
    evidence_from_direct_file_read_validation,
    evidence_from_local_command_validation,
    evidence_from_remote_command_validation,
    evidence_from_ssh_validation,
    evidence_from_web_command_validation,
)
from apex_host.capabilities.evidence import CapabilityEvidence, CapabilityEvidenceType
from apex_host.capabilities.runtime_references import (
    RuntimeReference,
    RuntimeReferenceError,
    RuntimeReferenceResolver,
    RuntimeReferenceStore,
)
from apex_host.config import ApexConfig
from apex_host.graph_ids import access_capability_id, access_state_id, host_id
from apex_host.orchestration.dependencies import OrchestrationDeps
from apex_host.orchestration.dispatch_node import make_objective_node
from apex_host.orchestration.parsing_node import (
    apply_parsed_observation,
    parse_result_and_collect_evidence,
    run_pending_capability_discovery,
    ssh_capability_evidence_for_result,
)
from apex_host.orchestration.repair_node import make_repair_node
from apex_host.planners.access_capabilities import access_capabilities_from_subgraph
from apex_host.planners.objective import objective_reopening_eligible
from apex_host.runtime import ApexRuntime
from apex_host.runtime_registry import CapabilityRuntimeRegistry
from apex_host.types import AccessCapability, AccessCapabilityType, CredentialValidationResult

_TARGET = "10.10.10.224"
_ANCHOR = host_id(_TARGET)
_FLAG_VALUE = "9e21a6c0f4d8b357"  # synthetic, well-formed — never a real flag

_TRIPLE_QUOTED_RE = re.compile(r'("""|\'\'\')(?:.|\n)*?\1')


def _non_comment_code(source: str) -> str:
    stripped = _TRIPLE_QUOTED_RE.sub("", source)
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


async def _subgraph(api: MemoryAPI, target: str) -> SubgraphView:
    return await api.get_subgraph(host_id(target), depth=5)


async def _seed_ssh_prereqs(api: MemoryAPI, *, principal: str = "root", target: str = _TARGET) -> None:
    h_id = host_id(target)
    await _seed_node(api, h_id, "host", {"ip": target})
    await _seed_node(api, access_state_id(target, principal, protocol="ssh"), "access_state", {
        "level": "user", "username": principal, "target": target, "service": "ssh",
    })


def _ssh_evidence(
    *, principal: str = "root", confidence: float = 0.85, evidence_id: str = "", target: str = _TARGET,
) -> CapabilityEvidence:
    return CapabilityEvidence(
        evidence_id=evidence_id or new_id(),
        evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
        capability_family=AccessCapabilityType.ssh_command,
        target_host_id=host_id(target), source_task_id="task-1", principal=principal,
        validation_method="deterministic_benign_command", confidence=confidence, timestamp=now(),
    )


def _context(
    api: MemoryAPI, subgraph: SubgraphView, *, config: ApexConfig | None = None,
    registry: CapabilityRuntimeRegistry | None = None,
    runtime_reference_store: RuntimeReferenceStore | None = None,
    attempt_runtime_registration: bool = True,
) -> CapabilityDiscoveryContext:
    return CapabilityDiscoveryContext(
        api=api, config=config or ApexConfig(target=_TARGET, dry_run=True),
        capability_registry=registry or CapabilityRuntimeRegistry(),
        subgraph=subgraph, target=_TARGET, now_iso=now(),
        attempt_runtime_registration=attempt_runtime_registration,
        runtime_reference_store=runtime_reference_store,
    )


def _make_initial_state(target: str, run_id: str = "run-24") -> dict[str, Any]:
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
        "bounded_command_log": [], "capability_discovery_log": [],
    }


def _build_deps(
    api: MemoryAPI, config: ApexConfig, *,
    capability_registry: CapabilityRuntimeRegistry | None = None,
    runtime_reference_store: RuntimeReferenceStore | None = None,
) -> OrchestrationDeps:
    from apex_host.execution.dispatcher import TaskDispatcher
    from apex_host.execution.registry import TaskRegistry
    from apex_host.orchestration.dependencies import build_planners
    from apex_host.orchestration.stall import StallTracker
    from apex_host.planners.global_planner import GlobalPlanner
    from apex_host.planning.repair import RepairEngine
    from apex_host.policy import PolicyAdvisor, load_policy
    from apex_host.tools.registry import ToolRegistry

    registry = ToolRegistry.from_config(config)
    dispatcher = TaskDispatcher(
        advisor=PolicyAdvisor(load_policy(config), config), task_registry=TaskRegistry(), config=config,
        run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type]
    )
    capability_registry = capability_registry if capability_registry is not None else CapabilityRuntimeRegistry()
    runtime_reference_store = runtime_reference_store if runtime_reference_store is not None else RuntimeReferenceStore()
    return OrchestrationDeps(
        api=api, dispatcher=dispatcher, global_planner=GlobalPlanner(max_turns=config.max_turns),
        phase_planners=build_planners(config, registry),
        repair_engine=RepairEngine(model_router=None, allowed_tools=config.allowed_tools, dry_run=config.dry_run),
        config=config, anchor_id=host_id(config.target), stall_tracker=StallTracker(),
        capability_registry=capability_registry,
        runtime_reference_store=runtime_reference_store,
        runtime_reference_resolver=RuntimeReferenceResolver(runtime_reference_store, capability_registry),
    )


# ---------------------------------------------------------------------------
# 1. RuntimeReference model
# ---------------------------------------------------------------------------

class TestRuntimeReferenceModel:
    def test_is_frozen(self) -> None:
        ref = RuntimeReference(
            reference_id="abc", capability_id="cap-1", target=_TARGET,
            capability_type=AccessCapabilityType.ssh_command, generation=1,
        )
        with pytest.raises(Exception):  # noqa: PT011 - dataclasses.FrozenInstanceError
            ref.revoked = True  # type: ignore[misc]

    def test_never_expires_with_no_expires_at(self) -> None:
        ref = RuntimeReference(
            reference_id="abc", capability_id="cap-1", target=_TARGET,
            capability_type=AccessCapabilityType.ssh_command, generation=1,
        )
        assert ref.is_expired(now()) is False

    def test_is_expired_when_now_past_expires_at(self) -> None:
        ref = RuntimeReference(
            reference_id="abc", capability_id="cap-1", target=_TARGET,
            capability_type=AccessCapabilityType.ssh_command, generation=1,
            expires_at="2000-01-01T00:00:00+00:00",
        )
        assert ref.is_expired(now()) is True

    def test_not_expired_before_expires_at(self) -> None:
        ref = RuntimeReference(
            reference_id="abc", capability_id="cap-1", target=_TARGET,
            capability_type=AccessCapabilityType.ssh_command, generation=1,
            expires_at="2999-01-01T00:00:00+00:00",
        )
        assert ref.is_expired(now()) is False

    def test_to_dict_never_exposes_full_reference_id(self) -> None:
        ref = RuntimeReference(
            reference_id="a-very-long-opaque-reference-id-value", capability_id="cap-1",
            target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1,
        )
        d = ref.to_dict()
        assert d["reference_digest"] == ref.reference_id[:8]
        assert "a-very-long-opaque-reference-id-value" not in json.dumps(d)

    def test_repr_never_exposes_full_reference_id(self) -> None:
        ref = RuntimeReference(
            reference_id="a-very-long-opaque-reference-id-value", capability_id="cap-1",
            target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1,
        )
        assert "a-very-long-opaque-reference-id-value" not in repr(ref)
        assert "cap-1" in repr(ref)

    def test_to_dict_reports_generation_and_revocation(self) -> None:
        ref = RuntimeReference(
            reference_id="abc", capability_id="cap-1", target=_TARGET,
            capability_type=AccessCapabilityType.ssh_command, generation=3,
            revoked=True, revocation_reason="shutdown",
        )
        d = ref.to_dict()
        assert d["generation"] == 3
        assert d["revoked"] is True
        assert d["revocation_reason"] == "shutdown"

    def test_default_authorization_scope_and_expiry_are_empty(self) -> None:
        ref = RuntimeReference(
            reference_id="abc", capability_id="cap-1", target=_TARGET,
            capability_type=AccessCapabilityType.ssh_command, generation=1,
        )
        assert ref.authorization_scope_id == ""
        assert ref.expires_at == ""
        assert ref.revoked is False


# ---------------------------------------------------------------------------
# 2. RuntimeReferenceError vocabulary
# ---------------------------------------------------------------------------

class TestRuntimeReferenceErrorVocabulary:
    def test_exactly_thirteen_members(self) -> None:
        assert len(list(RuntimeReferenceError)) == 13

    @pytest.mark.parametrize("member", [
        "not_found", "revoked", "expired", "target_mismatch", "type_mismatch",
        "generation_mismatch", "scope_mismatch", "adapter_unavailable",
        "capability_unregistered", "backend_disconnected", "authorization_revoked",
        "session_invalid", "internal_error",
    ])
    def test_member_exists(self, member: str) -> None:
        assert RuntimeReferenceError(member).value == member

    def test_is_str_enum(self) -> None:
        assert RuntimeReferenceError.revoked == "revoked"


# ---------------------------------------------------------------------------
# 3. RuntimeReferenceStore.mint
# ---------------------------------------------------------------------------

class TestRuntimeReferenceStoreMint:
    def test_mint_returns_reference_with_matching_fields(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(
            capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
            generation=1,
        )
        assert ref.capability_id == "cap-1"
        assert ref.target == _TARGET
        assert ref.capability_type is AccessCapabilityType.ssh_command
        assert ref.generation == 1
        assert ref.revoked is False

    def test_mint_produces_opaque_non_sequential_id(self) -> None:
        store = RuntimeReferenceStore()
        ref1 = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        ref2 = store.mint(capability_id="cap-2", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        assert ref1.reference_id != ref2.reference_id
        assert len(ref1.reference_id) >= 32

    def test_mint_id_is_not_a_python_object_id(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        assert str(id(ref)) != ref.reference_id
        assert not ref.reference_id.isdigit()

    def test_mint_with_ttl_sets_expires_at(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(
            capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
            generation=1, ttl_seconds=3600.0,
        )
        assert ref.expires_at != ""
        assert ref.is_expired(now()) is False

    def test_mint_without_ttl_never_expires(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        assert ref.expires_at == ""

    def test_mint_records_authorization_scope(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(
            capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
            generation=1, authorization_scope_id="scope-a",
        )
        assert ref.authorization_scope_id == "scope-a"

    def test_second_mint_for_same_capability_supersedes_first(self) -> None:
        store = RuntimeReferenceStore()
        ref1 = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        ref2 = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=2)
        assert store.get(ref1.reference_id).revoked is True
        assert store.get(ref1.reference_id).revocation_reason == "superseded_by_new_generation"
        assert store.get(ref2.reference_id).revoked is False
        assert store.current_reference_for("cap-1").reference_id == ref2.reference_id


# ---------------------------------------------------------------------------
# 4. RuntimeReferenceStore lookups
# ---------------------------------------------------------------------------

class TestRuntimeReferenceStoreLookups:
    def test_get_unknown_id_returns_none(self) -> None:
        store = RuntimeReferenceStore()
        assert store.get("nonexistent") is None

    def test_current_reference_for_unknown_capability_returns_none(self) -> None:
        store = RuntimeReferenceStore()
        assert store.current_reference_for("nonexistent-cap") is None

    def test_current_reference_for_returns_latest(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        assert store.current_reference_for("cap-1").reference_id == ref.reference_id

    def test_get_returns_the_exact_minted_reference(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        assert store.get(ref.reference_id) == ref


# ---------------------------------------------------------------------------
# 5. Explicit invalidation
# ---------------------------------------------------------------------------

class TestExplicitInvalidation:
    def test_invalidate_revokes_reference(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        assert store.invalidate(ref.reference_id, reason="authorization_revoked") is True
        assert store.get(ref.reference_id).revoked is True
        assert store.get(ref.reference_id).revocation_reason == "authorization_revoked"

    def test_invalidate_unknown_id_returns_false(self) -> None:
        store = RuntimeReferenceStore()
        assert store.invalidate("nonexistent") is False

    def test_invalidate_is_idempotent(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        assert store.invalidate(ref.reference_id) is True
        assert store.invalidate(ref.reference_id) is True
        assert store.get(ref.reference_id).revoked is True

    def test_invalidate_default_reason_is_authorization_revoked(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        store.invalidate(ref.reference_id)
        assert store.get(ref.reference_id).revocation_reason == RuntimeReferenceError.authorization_revoked.value


# ---------------------------------------------------------------------------
# 6. invalidate_for_capability
# ---------------------------------------------------------------------------

class TestInvalidateForCapability:
    def test_revokes_current_reference(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        assert store.invalidate_for_capability("cap-1", reason="session_invalid") is True
        assert store.get(ref.reference_id).revoked is True
        assert store.get(ref.reference_id).revocation_reason == "session_invalid"

    def test_unknown_capability_returns_false(self) -> None:
        store = RuntimeReferenceStore()
        assert store.invalidate_for_capability("nonexistent-cap") is False

    def test_does_not_affect_other_capabilities(self) -> None:
        store = RuntimeReferenceStore()
        ref_a = store.mint(capability_id="cap-a", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        ref_b = store.mint(capability_id="cap-b", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        store.invalidate_for_capability("cap-a")
        assert store.get(ref_a.reference_id).revoked is True
        assert store.get(ref_b.reference_id).revoked is False


# ---------------------------------------------------------------------------
# 7. invalidate_for_target (authorization/target-change trigger)
# ---------------------------------------------------------------------------

class TestInvalidateForTarget:
    def test_revokes_every_reference_for_target(self) -> None:
        store = RuntimeReferenceStore()
        ref_a = store.mint(capability_id="cap-a", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        ref_b = store.mint(capability_id="cap-b", target=_TARGET, capability_type=AccessCapabilityType.local_shell, generation=1)
        count = store.invalidate_for_target(_TARGET, reason="target_changed")
        assert count == 2
        assert store.get(ref_a.reference_id).revoked is True
        assert store.get(ref_b.reference_id).revoked is True

    def test_does_not_revoke_a_different_target(self) -> None:
        store = RuntimeReferenceStore()
        ref_a = store.mint(capability_id="cap-a", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        ref_b = store.mint(capability_id="cap-b", target="10.10.10.9", capability_type=AccessCapabilityType.ssh_command, generation=1)
        count = store.invalidate_for_target(_TARGET)
        assert count == 1
        assert store.get(ref_a.reference_id).revoked is True
        assert store.get(ref_b.reference_id).revoked is False

    def test_no_references_for_target_returns_zero(self) -> None:
        store = RuntimeReferenceStore()
        assert store.invalidate_for_target("no-such-target") == 0

    def test_already_revoked_reference_not_double_counted(self) -> None:
        store = RuntimeReferenceStore()
        ref = store.mint(capability_id="cap-a", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        store.invalidate(ref.reference_id)
        assert store.invalidate_for_target(_TARGET) == 0


# ---------------------------------------------------------------------------
# 8. invalidate_all (process-shutdown trigger)
# ---------------------------------------------------------------------------

class TestInvalidateAll:
    def test_revokes_every_reference(self) -> None:
        store = RuntimeReferenceStore()
        ref_a = store.mint(capability_id="cap-a", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        ref_b = store.mint(capability_id="cap-b", target="10.10.10.9", capability_type=AccessCapabilityType.local_shell, generation=1)
        count = store.invalidate_all(reason="shutdown")
        assert count == 2
        assert store.get(ref_a.reference_id).revoked is True
        assert store.get(ref_b.reference_id).revoked is True
        assert store.get(ref_a.reference_id).revocation_reason == "shutdown"

    def test_empty_store_returns_zero(self) -> None:
        store = RuntimeReferenceStore()
        assert store.invalidate_all() == 0

    def test_idempotent_second_call_returns_zero(self) -> None:
        store = RuntimeReferenceStore()
        store.mint(capability_id="cap-a", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        store.invalidate_all()
        assert store.invalidate_all() == 0


# ---------------------------------------------------------------------------
# 9. RuntimeReferenceResolver
# ---------------------------------------------------------------------------

class TestRuntimeReferenceResolver:
    def _setup(self) -> tuple[RuntimeReferenceStore, CapabilityRuntimeRegistry, RuntimeReferenceResolver]:
        store = RuntimeReferenceStore()
        registry = CapabilityRuntimeRegistry()
        return store, registry, RuntimeReferenceResolver(store, registry)

    def test_resolve_success(self) -> None:
        store, registry, resolver = self._setup()
        adapter = object()
        registry.register("cap-1", adapter)  # type: ignore[arg-type]
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        resolved, error = resolver.resolve(ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert error is None
        assert resolved is adapter

    def test_empty_reference_id_is_not_found(self) -> None:
        _store, _registry, resolver = self._setup()
        resolved, error = resolver.resolve("", target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert resolved is None
        assert error is RuntimeReferenceError.not_found

    def test_unknown_reference_id_is_not_found(self) -> None:
        _store, _registry, resolver = self._setup()
        resolved, error = resolver.resolve("nonexistent", target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert resolved is None
        assert error is RuntimeReferenceError.not_found

    def test_revoked_reference_rejected(self) -> None:
        store, registry, resolver = self._setup()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        store.invalidate(ref.reference_id)
        resolved, error = resolver.resolve(ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert resolved is None
        assert error is RuntimeReferenceError.revoked

    def test_expired_reference_rejected(self) -> None:
        store, registry, resolver = self._setup()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        ref = store.mint(
            capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
            generation=1, ttl_seconds=1.0,
        )
        resolved, error = resolver.resolve(
            ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
            now_iso="2999-01-01T00:00:00+00:00",
        )
        assert resolved is None
        assert error is RuntimeReferenceError.expired

    def test_target_mismatch_never_falls_back_to_global_adapter(self) -> None:
        store, registry, resolver = self._setup()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        resolved, error = resolver.resolve(
            ref.reference_id, target="10.10.10.99", capability_type=AccessCapabilityType.ssh_command,
        )
        assert resolved is None
        assert error is RuntimeReferenceError.target_mismatch

    def test_type_mismatch_rejected(self) -> None:
        store, registry, resolver = self._setup()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        resolved, error = resolver.resolve(
            ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.local_shell,
        )
        assert resolved is None
        assert error is RuntimeReferenceError.type_mismatch

    def test_generation_mismatch_rejected_when_expected_generation_supplied(self) -> None:
        store, registry, resolver = self._setup()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        resolved, error = resolver.resolve(
            ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
            expected_generation=2,
        )
        assert resolved is None
        assert error is RuntimeReferenceError.generation_mismatch

    def test_generation_match_succeeds(self) -> None:
        store, registry, resolver = self._setup()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        resolved, error = resolver.resolve(
            ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
            expected_generation=1,
        )
        assert error is None
        assert resolved is not None

    def test_capability_unregistered_when_registry_has_no_adapter(self) -> None:
        store, _registry, resolver = self._setup()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        resolved, error = resolver.resolve(ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert resolved is None
        assert error is RuntimeReferenceError.capability_unregistered

    def test_capability_unregistered_after_unregister(self) -> None:
        store, registry, resolver = self._setup()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        registry.unregister("cap-1")
        resolved, error = resolver.resolve(ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert resolved is None
        assert error is RuntimeReferenceError.capability_unregistered

    def test_check_order_existence_before_revocation(self) -> None:
        """A reference that doesn't exist reports not_found even though the
        target/type also wouldn't match anything — proves check ordering,
        not just individual checks in isolation."""
        _store, _registry, resolver = self._setup()
        resolved, error = resolver.resolve(
            "nonexistent", target="wrong-target", capability_type=AccessCapabilityType.web_command,
        )
        assert error is RuntimeReferenceError.not_found

    def test_never_reconstructs_adapter_from_reference_fields_alone(self) -> None:
        """The resolver must always re-fetch from the live registry — a
        RuntimeReference carries no adapter-shaped field it could return
        instead."""
        store, registry, resolver = self._setup()
        ref = store.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        assert not hasattr(ref, "adapter")
        # Registering AFTER minting still resolves correctly — proves the
        # adapter is fetched live at resolve() time, not cached at mint() time.
        registry.register("cap-1", "the-adapter")  # type: ignore[arg-type]
        resolved, error = resolver.resolve(ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert error is None
        assert resolved == "the-adapter"


# ---------------------------------------------------------------------------
# 10. CapabilityRuntimeRegistry safe-replacement semantics
# ---------------------------------------------------------------------------

class TestCapabilityRuntimeRegistrySafeReplacement:
    def test_generation_zero_when_never_registered(self) -> None:
        registry = CapabilityRuntimeRegistry()
        assert registry.generation_for("cap-1") == 0

    def test_ensure_ssh_first_call_sets_generation_one(self) -> None:
        registry = CapabilityRuntimeRegistry()
        config = ApexConfig(target=_TARGET, dry_run=True)
        registry.ensure_ssh("cap-1", target=_TARGET, port="22", username="root", password="pw", config=config)
        assert registry.generation_for("cap-1") == 1

    def test_ensure_ssh_idempotent_second_call_does_not_bump_generation(self) -> None:
        registry = CapabilityRuntimeRegistry()
        config = ApexConfig(target=_TARGET, dry_run=True)
        first = registry.ensure_ssh("cap-1", target=_TARGET, port="22", username="root", password="pw", config=config)
        second = registry.ensure_ssh("cap-1", target=_TARGET, port="22", username="root", password="different", config=config)
        assert first is second
        assert registry.generation_for("cap-1") == 1

    def test_register_first_call_generation_one(self) -> None:
        registry = CapabilityRuntimeRegistry()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        assert registry.generation_for("cap-1") == 1

    def test_replace_bumps_generation(self) -> None:
        registry = CapabilityRuntimeRegistry()
        adapter1 = object()
        adapter2 = object()
        gen1 = registry.replace("cap-1", adapter1)  # type: ignore[arg-type]
        gen2 = registry.replace("cap-1", adapter2)  # type: ignore[arg-type]
        assert gen1 == 1
        assert gen2 == 2
        assert registry.get("cap-1") is adapter2

    def test_replace_installs_newer_adapter_unconditionally(self) -> None:
        registry = CapabilityRuntimeRegistry()
        adapter1, adapter2 = object(), object()
        registry.register("cap-1", adapter1)  # type: ignore[arg-type]
        registry.replace("cap-1", adapter2)  # type: ignore[arg-type]
        assert registry.get("cap-1") is adapter2

    def test_unregister_removes_adapter(self) -> None:
        registry = CapabilityRuntimeRegistry()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        assert registry.unregister("cap-1") is True
        assert registry.has("cap-1") is False
        assert registry.get("cap-1") is None

    def test_unregister_absent_capability_returns_false(self) -> None:
        registry = CapabilityRuntimeRegistry()
        assert registry.unregister("nonexistent") is False

    def test_unregister_does_not_reset_generation(self) -> None:
        registry = CapabilityRuntimeRegistry()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        registry.unregister("cap-1")
        assert registry.generation_for("cap-1") == 1

    def test_reregister_after_unregister_is_a_new_generation(self) -> None:
        registry = CapabilityRuntimeRegistry()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        registry.unregister("cap-1")
        registry.replace("cap-1", object())  # type: ignore[arg-type]
        assert registry.generation_for("cap-1") == 2

    def test_ensure_direct_file_read_first_call_sets_generation_one(self) -> None:
        from apex_host.runtime_registry import DirectFileReadPrimitive

        registry = CapabilityRuntimeRegistry()
        primitive = DirectFileReadPrimitive(
            capability_id="cap-1", target_origin=f"http://{_TARGET}", endpoint_template="/f?p={path}",
        )
        registry.ensure_direct_file_read("cap-1", primitive=primitive)
        assert registry.generation_for("cap-1") == 1

    def test_generations_are_independent_per_capability(self) -> None:
        registry = CapabilityRuntimeRegistry()
        registry.register("cap-a", object())  # type: ignore[arg-type]
        registry.replace("cap-a", object())  # type: ignore[arg-type]
        registry.register("cap-b", object())  # type: ignore[arg-type]
        assert registry.generation_for("cap-a") == 2
        assert registry.generation_for("cap-b") == 1


# ---------------------------------------------------------------------------
# 11. Typed SSH evidence emission
# ---------------------------------------------------------------------------

class TestTypedSSHEmission:
    def _result(self, **overrides: Any) -> CredentialValidationResult:
        base = dict(
            protocol="ssh", target=_TARGET, port="22", username="root", success=True,
            authenticated=True, operation="id", response_summary="uid=0(root)",
            error_category="success", error_detail="", duration_seconds=0.1,
            timed_out=False, executor="ssh",
        )
        base.update(overrides)
        return CredentialValidationResult(**base)

    def test_success_produces_evidence(self) -> None:
        ev = evidence_from_ssh_validation(self._result(), task_id="t-1", target=_TARGET)
        assert ev is not None
        assert ev.evidence_type is CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND
        assert ev.capability_family is AccessCapabilityType.ssh_command
        assert ev.principal == "root"
        assert ev.target_host_id == f"host:{_TARGET}"

    def test_non_ssh_protocol_rejected(self) -> None:
        ev = evidence_from_ssh_validation(self._result(protocol="ftp"), task_id="t-1", target=_TARGET)
        assert ev is None

    def test_failed_login_rejected(self) -> None:
        ev = evidence_from_ssh_validation(self._result(success=False), task_id="t-1", target=_TARGET)
        assert ev is None

    def test_missing_username_rejected(self) -> None:
        ev = evidence_from_ssh_validation(self._result(username=""), task_id="t-1", target=_TARGET)
        assert ev is None

    def test_dry_run_flag_passed_through(self) -> None:
        ev = evidence_from_ssh_validation(self._result(), task_id="t-1", target=_TARGET, is_dry_run=True)
        assert ev is not None
        assert ev.is_dry_run is True

    def test_confidence_matches_capability_parser_constant(self) -> None:
        from apex_host.parsers.capability_parser import _SSH_CAPABILITY_CONFIDENCE

        ev = evidence_from_ssh_validation(self._result(), task_id="t-1", target=_TARGET)
        assert ev is not None
        assert ev.confidence == _SSH_CAPABILITY_CONFIDENCE


# ---------------------------------------------------------------------------
# 12. Typed DFR/local/remote/web stub emission (no live call site — see
#     apex_host.capabilities.emission module docstring)
# ---------------------------------------------------------------------------

class TestTypedStubEmission:
    def test_dfr_accepted_with_valid_method(self) -> None:
        result = DirectFileReadValidationResult(
            target=_TARGET, principal="application", validation_method="path_dependent_content", confidence=0.8,
        )
        ev = evidence_from_direct_file_read_validation(result)
        assert ev is not None
        assert ev.evidence_type is CapabilityEvidenceType.DIRECT_FILE_READ_VALIDATED

    def test_dfr_rejects_unaccepted_method(self) -> None:
        result = DirectFileReadValidationResult(
            target=_TARGET, principal="application", validation_method="http_200", confidence=0.9,
        )
        assert evidence_from_direct_file_read_validation(result) is None

    def test_dfr_rejects_low_confidence(self) -> None:
        result = DirectFileReadValidationResult(
            target=_TARGET, principal="application", validation_method="path_dependent_content", confidence=0.1,
        )
        assert evidence_from_direct_file_read_validation(result) is None

    def test_dfr_rejects_missing_principal(self) -> None:
        result = DirectFileReadValidationResult(
            target=_TARGET, principal="", validation_method="path_dependent_content", confidence=0.9,
        )
        assert evidence_from_direct_file_read_validation(result) is None

    def test_local_command_accepted(self) -> None:
        result = LocalCommandValidationResult(
            target=_TARGET, principal="app", validation_method="deterministic_benign_command", confidence=0.8,
        )
        ev = evidence_from_local_command_validation(result)
        assert ev is not None
        assert ev.capability_family is AccessCapabilityType.local_shell

    def test_local_command_rejects_bad_method(self) -> None:
        result = LocalCommandValidationResult(
            target=_TARGET, principal="app", validation_method="llm_claim", confidence=0.9,
        )
        assert evidence_from_local_command_validation(result) is None

    def test_remote_command_accepted(self) -> None:
        result = RemoteCommandValidationResult(
            target=_TARGET, principal="app", validation_method="backend_confirmed_session", confidence=0.8,
        )
        ev = evidence_from_remote_command_validation(result)
        assert ev is not None
        assert ev.capability_family is AccessCapabilityType.remote_command

    def test_remote_command_rejects_low_confidence(self) -> None:
        result = RemoteCommandValidationResult(
            target=_TARGET, principal="app", validation_method="backend_confirmed_session", confidence=0.2,
        )
        assert evidence_from_remote_command_validation(result) is None

    def test_web_command_accepted_but_marked_runtime_unavailable_by_provider(self) -> None:
        from apex_host.capabilities.providers import WebCommandCapabilityProvider

        result = WebCommandValidationResult(
            target=_TARGET, principal="app", validation_method="operator_attestation", confidence=0.8,
        )
        ev = evidence_from_web_command_validation(result)
        assert ev is not None
        provider = WebCommandCapabilityProvider()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ctx = _context(_make_api(), subgraph)
        decision = provider.evaluate(ev, ctx)
        from apex_host.capabilities.decisions import CapabilityDerivationStatus
        assert decision.status is CapabilityDerivationStatus.runtime_unavailable

    def test_web_command_rejects_missing_principal(self) -> None:
        result = WebCommandValidationResult(
            target=_TARGET, principal="", validation_method="operator_attestation", confidence=0.8,
        )
        assert evidence_from_web_command_validation(result) is None

    def test_all_four_stub_dataclasses_are_frozen(self) -> None:
        for cls, kwargs in [
            (DirectFileReadValidationResult, dict(target=_TARGET, principal="a", validation_method="m", confidence=0.7)),
            (LocalCommandValidationResult, dict(target=_TARGET, principal="a", validation_method="m", confidence=0.7)),
            (RemoteCommandValidationResult, dict(target=_TARGET, principal="a", validation_method="m", confidence=0.7)),
            (WebCommandValidationResult, dict(target=_TARGET, principal="a", validation_method="m", confidence=0.7)),
        ]:
            instance = cls(**kwargs)
            with pytest.raises(Exception):  # noqa: PT011
                instance.principal = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 13. parsing_node SSH-evidence dict-wrapper parity with the typed emitter
# ---------------------------------------------------------------------------

class TestSSHEvidenceDictWrapperParity:
    def test_wrapper_delegates_and_matches_typed_emitter(self) -> None:
        tool_result = {
            "tool": "ssh_access", "success": True, "username": "root", "task_id": "t-9",
            "authenticated": True, "operation": "id", "port": "22",
        }
        ev_from_wrapper = ssh_capability_evidence_for_result(tool_result, target=_TARGET)
        assert ev_from_wrapper is not None
        assert ev_from_wrapper.evidence_type is CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND
        assert ev_from_wrapper.principal == "root"
        assert ev_from_wrapper.source_task_id == "t-9"

    def test_wrapper_rejects_non_ssh_tool(self) -> None:
        assert ssh_capability_evidence_for_result({"tool": "ftp_access", "success": True, "username": "root"}, target=_TARGET) is None

    def test_wrapper_rejects_failed_login(self) -> None:
        assert ssh_capability_evidence_for_result({"tool": "ssh_access", "success": False, "username": "root"}, target=_TARGET) is None

    def test_wrapper_rejects_missing_username(self) -> None:
        assert ssh_capability_evidence_for_result({"tool": "ssh_access", "success": True, "username": ""}, target=_TARGET) is None

    def test_wrapper_propagates_dry_run_flag(self) -> None:
        ev = ssh_capability_evidence_for_result(
            {"tool": "ssh_access", "success": True, "username": "root", "dry_run": True}, target=_TARGET,
        )
        assert ev is not None
        assert ev.is_dry_run is True


# ---------------------------------------------------------------------------
# 14. Shared result-processing helper (parse_observation & repair_node parity)
# ---------------------------------------------------------------------------

class TestSharedResultProcessingHelper:
    def test_parse_result_and_collect_evidence_returns_parsed_source_and_evidence(self) -> None:
        state = _make_initial_state(_TARGET)
        tool_result = {
            "tool": "ssh_access", "success": True, "username": "root", "task_id": "t-1",
            "target": _TARGET, "parser": "access", "port": "22",
        }
        parsed, source, evidence = parse_result_and_collect_evidence(tool_result, state, target=_TARGET)
        assert source == "ssh_access"
        assert evidence is not None
        assert evidence.principal == "root"

    def test_no_evidence_for_non_ssh_result(self) -> None:
        state = _make_initial_state(_TARGET)
        tool_result = {"tool": "nmap", "stdout": "", "parser": "nmap", "target": _TARGET}
        _parsed, _source, evidence = parse_result_and_collect_evidence(tool_result, state, target=_TARGET)
        assert evidence is None

    @pytest.mark.asyncio
    async def test_apply_parsed_observation_writes_through_memory_api(self) -> None:
        from memfabric.types import ParsedObservation

        api = _make_api()
        deps = _build_deps(api, ApexConfig(target=_TARGET, dry_run=True))
        h_id = host_id(_TARGET)
        node = Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=now(), last_seen=now())
        await apply_parsed_observation(deps, ParsedObservation(node_deltas=[node]))
        subgraph = await _subgraph(api, _TARGET)
        assert any(n.id == h_id for n in subgraph.nodes)

    @pytest.mark.asyncio
    async def test_run_pending_capability_discovery_empty_list_is_noop(self) -> None:
        api = _make_api()
        deps = _build_deps(api, ApexConfig(target=_TARGET, dry_run=True))
        result = await run_pending_capability_discovery(deps, [])
        assert result == {}

    @pytest.mark.asyncio
    async def test_run_pending_capability_discovery_disabled_is_noop(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        config = ApexConfig(target=_TARGET, dry_run=True, capability_discovery_enabled=False)
        deps = _build_deps(api, config)
        result = await run_pending_capability_discovery(deps, [_ssh_evidence()])
        assert result == {}

    @pytest.mark.asyncio
    async def test_run_pending_capability_discovery_produces_log(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        deps = _build_deps(api, ApexConfig(target=_TARGET, dry_run=True))
        result = await run_pending_capability_discovery(deps, [_ssh_evidence()])
        assert "capability_discovery_log" in result
        assert result["capability_discovery_log"][0]["capabilities_derived"] == 1

    @pytest.mark.asyncio
    async def test_run_pending_capability_discovery_degrades_gracefully_on_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        deps = _build_deps(api, ApexConfig(target=_TARGET, dry_run=True))

        async def _raise(*a: Any, **k: Any) -> Any:
            raise RuntimeError("boom")

        monkeypatch.setattr(deps.api, "get_subgraph", _raise)
        result = await run_pending_capability_discovery(deps, [_ssh_evidence()])
        assert result == {}


# ---------------------------------------------------------------------------
# 15. repair_node emits capability evidence for a repaired ssh_access success
# ---------------------------------------------------------------------------

class TestRepairNodeCapabilityEvidence:
    @pytest.mark.asyncio
    async def test_repaired_ssh_success_derives_capability(self) -> None:
        from apex_host.execution.dispositions import ExecutionDisposition
        from apex_host.planning.repair import RepairRequest
        from memfabric.types import TaskSpec

        api = _make_api()
        await _seed_ssh_prereqs(api)
        # AccessParser.parse_structured also derives a `tested` edge from the
        # SSH service node — a real engagement turn always has one (from
        # NmapParser) by the time a credential task runs; seed it here too.
        h_id = host_id(_TARGET)
        svc_id = f"service:{_TARGET}:22/tcp"
        await _seed_node(api, svc_id, "service", {"port": "22", "proto": "tcp", "service": "ssh"})
        await _seed_edge(api, h_id, svc_id, edge_type="exposes")
        config = ApexConfig(target=_TARGET, dry_run=True, username_candidates=["root"], password_candidates=["pw"])
        deps = _build_deps(api, config)

        class _StubDispatchResult:
            def __init__(self) -> None:
                self.disposition = ExecutionDisposition.EXECUTED_SUCCESS
                self.tool_result_dict = {
                    "tool": "ssh_access", "success": True, "username": "root", "task_id": "t-1",
                    "target": _TARGET, "parser": "access", "port": "22", "returncode": 0,
                }
                self.audit_metadata: dict[str, Any] = {}

        class _StubRepairEngine:
            async def repair(self, **kwargs: Any) -> Any:
                return RepairRequest(
                    original_task_id="t-1",
                    repaired_task=TaskSpec(
                        id="t-1", goal_id="g", executor_domain="credential",
                        params={"tool": "ssh_access", "target": _TARGET}, subgraph_anchor=_ANCHOR, phase="credential",
                    ),
                    repair_attempt=0, failure_reason="transient", phase="credential", target=_TARGET,
                )

        class _StubDispatcher:
            async def dispatch(self, *a: Any, **k: Any) -> Any:
                return _StubDispatchResult()

        object.__setattr__(deps, "repair_engine", _StubRepairEngine())
        object.__setattr__(deps, "dispatcher", _StubDispatcher())

        node = make_repair_node(deps)
        state = _make_initial_state(_TARGET)
        state["phase"] = "credential"
        state["last_tool_result"] = {"tool": "ssh_access", "error": "transient", "task_id": "t-1"}
        state["current_task"] = {"params": {"tool": "ssh_access", "target": _TARGET}, "executor_domain": "credential"}

        result = await node(state)
        assert "capability_discovery_log" in result
        assert result["capability_discovery_log"][0]["capabilities_derived"] == 1

        subgraph = await _subgraph(api, _TARGET)
        caps = access_capabilities_from_subgraph(subgraph)
        assert any(c.capability_type is AccessCapabilityType.ssh_command for c in caps)


# ---------------------------------------------------------------------------
# 16. dispatch_node runtime-reference minting on registration
# ---------------------------------------------------------------------------

class TestObjectiveNodeRuntimeReferenceMinting:
    @pytest.mark.asyncio
    async def test_registration_mints_reference_when_live(self) -> None:
        api = _make_api()
        h_id = host_id(_TARGET)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, cap_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": h_id, "validated": True,
            "principal": "root", "confidence": 0.85, "runtime_available": False, "metadata": {},
        })
        await _seed_edge(api, h_id, cap_id)

        config = ApexConfig(target=_TARGET, dry_run=False, username_candidates=["root"], password_candidates=["pw"])
        deps = _build_deps(api, config)
        node = make_objective_node(deps)
        state = _make_initial_state(_TARGET)
        state["phase"] = "objective"
        await node(state)

        assert deps.capability_registry.has(cap_id)
        ref = deps.runtime_reference_store.current_reference_for(cap_id)
        assert ref is not None
        assert ref.generation == deps.capability_registry.generation_for(cap_id)

    @pytest.mark.asyncio
    async def test_dry_run_never_mints_a_reference(self) -> None:
        api = _make_api()
        h_id = host_id(_TARGET)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, cap_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": h_id, "validated": True,
            "principal": "root", "confidence": 0.85, "runtime_available": False, "metadata": {},
        })
        await _seed_edge(api, h_id, cap_id)

        config = ApexConfig(target=_TARGET, dry_run=True, username_candidates=["root"], password_candidates=["pw"])
        deps = _build_deps(api, config)
        node = make_objective_node(deps)
        state = _make_initial_state(_TARGET)
        state["phase"] = "objective"
        await node(state)

        # Registration still succeeds in dry-run (adapters may be
        # constructed; only the RUNTIME REFERENCE store must stay empty).
        assert deps.runtime_reference_store.current_reference_for(cap_id) is None

    @pytest.mark.asyncio
    async def test_already_registered_capability_still_gets_a_reference(self) -> None:
        """A capability whose adapter was already registered BEFORE this
        turn (deps.capability_registry.has() short-circuits the
        registration branch) must still get a reference via the
        `continue`-path call to _ensure_runtime_reference."""
        api = _make_api()
        h_id = host_id(_TARGET)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, cap_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": h_id, "validated": True,
            "principal": "root", "confidence": 0.85, "runtime_available": True, "metadata": {},
        })
        await _seed_edge(api, h_id, cap_id)

        config = ApexConfig(target=_TARGET, dry_run=False, username_candidates=["root"], password_candidates=["pw"])
        deps = _build_deps(api, config)
        deps.capability_registry.register(cap_id, object())  # type: ignore[arg-type]
        node = make_objective_node(deps)
        state = _make_initial_state(_TARGET)
        state["phase"] = "objective"
        await node(state)
        assert deps.runtime_reference_store.current_reference_for(cap_id) is not None


# ---------------------------------------------------------------------------
# 17. dispatch_node invalidation on connection failure
# ---------------------------------------------------------------------------

class TestObjectiveNodeInvalidationOnConnectionFailure:
    @pytest.mark.asyncio
    async def test_connected_false_unregisters_and_invalidates(self) -> None:
        from apex_host.orchestration.dispatch_node import _invalidate_on_connection_failure

        registry = CapabilityRuntimeRegistry()
        store = RuntimeReferenceStore()
        cap_id = "cap-1"
        registry.register(cap_id, object())  # type: ignore[arg-type]
        store.mint(capability_id=cap_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        deps = _build_deps(_make_api(), ApexConfig(target=_TARGET, dry_run=False), capability_registry=registry, runtime_reference_store=store)

        _invalidate_on_connection_failure(deps, {"tool": "user_flag_verify", "capability_id": cap_id, "connected": False})

        assert registry.has(cap_id) is False
        ref = store.current_reference_for(cap_id)
        assert ref.revoked is True
        assert ref.revocation_reason == RuntimeReferenceError.session_invalid.value

    @pytest.mark.asyncio
    async def test_connected_true_does_not_invalidate(self) -> None:
        from apex_host.orchestration.dispatch_node import _invalidate_on_connection_failure

        registry = CapabilityRuntimeRegistry()
        cap_id = "cap-1"
        registry.register(cap_id, object())  # type: ignore[arg-type]
        deps = _build_deps(_make_api(), ApexConfig(target=_TARGET, dry_run=False), capability_registry=registry)

        _invalidate_on_connection_failure(deps, {"tool": "user_flag_verify", "capability_id": cap_id, "connected": True})
        assert registry.has(cap_id) is True

    @pytest.mark.asyncio
    async def test_non_user_flag_verify_tool_ignored(self) -> None:
        from apex_host.orchestration.dispatch_node import _invalidate_on_connection_failure

        registry = CapabilityRuntimeRegistry()
        cap_id = "cap-1"
        registry.register(cap_id, object())  # type: ignore[arg-type]
        deps = _build_deps(_make_api(), ApexConfig(target=_TARGET, dry_run=False), capability_registry=registry)

        _invalidate_on_connection_failure(deps, {"tool": "nmap", "capability_id": cap_id, "connected": False})
        assert registry.has(cap_id) is True

    @pytest.mark.asyncio
    async def test_none_tool_result_is_noop(self) -> None:
        from apex_host.orchestration.dispatch_node import _invalidate_on_connection_failure

        deps = _build_deps(_make_api(), ApexConfig(target=_TARGET, dry_run=False))
        _invalidate_on_connection_failure(deps, None)  # must not raise

    @pytest.mark.asyncio
    async def test_missing_capability_id_is_noop(self) -> None:
        from apex_host.orchestration.dispatch_node import _invalidate_on_connection_failure

        deps = _build_deps(_make_api(), ApexConfig(target=_TARGET, dry_run=False))
        _invalidate_on_connection_failure(deps, {"tool": "user_flag_verify", "connected": False})  # must not raise

    @pytest.mark.asyncio
    async def test_reregistration_after_invalidation_bumps_generation(self) -> None:
        registry = CapabilityRuntimeRegistry()
        store = RuntimeReferenceStore()
        cap_id = "cap-1"
        registry.register(cap_id, object())  # type: ignore[arg-type]
        first_ref = store.mint(capability_id=cap_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)

        from apex_host.orchestration.dispatch_node import _invalidate_on_connection_failure
        deps = _build_deps(_make_api(), ApexConfig(target=_TARGET, dry_run=False), capability_registry=registry, runtime_reference_store=store)
        _invalidate_on_connection_failure(deps, {"tool": "user_flag_verify", "capability_id": cap_id, "connected": False})

        # Simulate the NEXT turn's registration loop re-registering fresh.
        new_gen = registry.replace(cap_id, object())  # type: ignore[arg-type]
        assert new_gen == 2
        new_ref = store.mint(capability_id=cap_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=new_gen)
        assert new_ref.generation == 2
        assert store.get(first_ref.reference_id).revoked is True


# ---------------------------------------------------------------------------
# 18. discovery.py runtime_reference_store wiring
# ---------------------------------------------------------------------------

class TestDiscoveryEngineRuntimeReferenceWiring:
    @pytest.mark.asyncio
    async def test_none_store_is_backward_compatible(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        ctx = _context(api, subgraph, runtime_reference_store=None)
        result = await run_capability_discovery([_ssh_evidence()], context=ctx)
        assert result.capabilities_derived == 1

    @pytest.mark.asyncio
    async def test_supplied_store_mints_reference_on_registration(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        config = ApexConfig(target=_TARGET, dry_run=False, username_candidates=["root"], password_candidates=["pw"])
        registry = CapabilityRuntimeRegistry()
        store = RuntimeReferenceStore()
        ctx = _context(api, subgraph, config=config, registry=registry, runtime_reference_store=store)
        result = await run_capability_discovery([_ssh_evidence()], context=ctx)
        assert result.adapters_registered == 1
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        assert store.current_reference_for(cap_id) is not None

    @pytest.mark.asyncio
    async def test_dry_run_config_never_mints_via_discovery(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        config = ApexConfig(target=_TARGET, dry_run=True, username_candidates=["root"], password_candidates=["pw"])
        registry = CapabilityRuntimeRegistry()
        store = RuntimeReferenceStore()
        ctx = _context(api, subgraph, config=config, registry=registry, runtime_reference_store=store)
        await run_capability_discovery([_ssh_evidence()], context=ctx)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        assert store.current_reference_for(cap_id) is None

    @pytest.mark.asyncio
    async def test_no_registration_attempted_never_mints(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        config = ApexConfig(target=_TARGET, dry_run=False, username_candidates=["root"], password_candidates=["pw"])
        store = RuntimeReferenceStore()
        ctx = _context(api, subgraph, config=config, runtime_reference_store=store, attempt_runtime_registration=False)
        await run_capability_discovery([_ssh_evidence()], context=ctx)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        assert store.current_reference_for(cap_id) is None


# ---------------------------------------------------------------------------
# 19. builder.py / OrchestrationDeps wiring
# ---------------------------------------------------------------------------

class TestBuilderWiring:
    def test_orchestration_deps_requires_runtime_reference_fields(self) -> None:
        fields = {f.name for f in dataclasses.fields(OrchestrationDeps)}
        assert "runtime_reference_store" in fields
        assert "runtime_reference_resolver" in fields

    def test_build_apex_graph_accepts_capability_registry_kwarg(self) -> None:
        from apex_host.graph import build_apex_graph

        sig = inspect.signature(build_apex_graph)
        assert "capability_registry" in sig.parameters
        assert "runtime_reference_store" in sig.parameters

    @pytest.mark.asyncio
    async def test_build_apex_graph_uses_supplied_registry_and_store(self) -> None:
        from apex_host.graph import build_apex_graph
        from apex_host.tools.registry import ToolRegistry

        api = _make_api()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        capability_registry = CapabilityRuntimeRegistry()
        runtime_reference_store = RuntimeReferenceStore()
        graph = build_apex_graph(
            api, registry, config,
            capability_registry=capability_registry, runtime_reference_store=runtime_reference_store,
        )
        assert graph is not None  # constructs without error; deep internals not introspectable post-compile

    def test_default_construction_still_works_with_no_kwargs(self) -> None:
        from apex_host.graph import build_apex_graph
        from apex_host.tools.registry import ToolRegistry

        api = _make_api()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        assert graph is not None


# ---------------------------------------------------------------------------
# 20. ApexRuntime.aclose() invalidation
# ---------------------------------------------------------------------------

class TestApexRuntimeAcloseInvalidation:
    @pytest.mark.asyncio
    async def test_aclose_before_run_does_not_raise(self) -> None:
        api = _make_api()
        config = ApexConfig(target=_TARGET, dry_run=True)
        from apex_host.tools.registry import ToolRegistry
        from memfabric.config import Config as MemConfig

        runtime = ApexRuntime(api=api, config=config, memfabric_config=MemConfig(), registry=ToolRegistry.from_config(config))
        await runtime.aclose()  # must not raise even though _runtime_reference_store is None

    @pytest.mark.asyncio
    async def test_aclose_invalidates_references_after_run(self) -> None:
        api = _make_api()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=2)
        from apex_host.tools.registry import ToolRegistry
        from memfabric.config import Config as MemConfig

        runtime = ApexRuntime(api=api, config=config, memfabric_config=MemConfig(), registry=ToolRegistry.from_config(config))
        await runtime.run()
        assert runtime._runtime_reference_store is not None
        # Manually mint one to prove aclose() reaches the real store instance.
        runtime._runtime_reference_store.mint(
            capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1,
        )
        await runtime.aclose()
        ref = runtime._runtime_reference_store.current_reference_for("cap-1")
        assert ref.revoked is True
        assert ref.revocation_reason == "shutdown"

    @pytest.mark.asyncio
    async def test_aclose_idempotent(self) -> None:
        api = _make_api()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=1)
        from apex_host.tools.registry import ToolRegistry
        from memfabric.config import Config as MemConfig

        runtime = ApexRuntime(api=api, config=config, memfabric_config=MemConfig(), registry=ToolRegistry.from_config(config))
        await runtime.run()
        await runtime.aclose()
        await runtime.aclose()  # second call must not raise


# ---------------------------------------------------------------------------
# 21. Objective-reopening with runtime-activation transitions
# ---------------------------------------------------------------------------

class TestObjectiveReopeningRuntimeTransitions:
    @pytest.mark.asyncio
    async def test_registered_capability_makes_reopening_eligible(self) -> None:
        api = _make_api()
        h_id = host_id(_TARGET)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, cap_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": h_id, "validated": True,
            "principal": "root", "confidence": 0.85, "runtime_available": True, "metadata": {},
        })
        await _seed_edge(api, h_id, cap_id)
        await _seed_node(api, f"objective:{_TARGET}:user_flag", "objective", {
            "objective_type": "user_flag", "status": "failed", "target": _TARGET,
            "attempted_paths": [], "attempted_capability_paths": [],
        })
        await _seed_edge(api, h_id, f"objective:{_TARGET}:user_flag", edge_type="indicates")

        subgraph = await _subgraph(api, _TARGET)
        assert objective_reopening_eligible(subgraph, _TARGET, "user_flag") is True

    @pytest.mark.asyncio
    async def test_unregistered_runtime_unavailable_capability_not_eligible(self) -> None:
        """A capability whose runtime adapter was invalidated
        (runtime_available flipped back to False) must NOT make the
        objective eligible for reopening — reopening requires a genuinely
        ACTIVE capability, not merely a validated one."""
        api = _make_api()
        h_id = host_id(_TARGET)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, cap_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": h_id, "validated": True,
            "principal": "root", "confidence": 0.85, "runtime_available": False, "metadata": {},
        })
        await _seed_edge(api, h_id, cap_id)
        await _seed_node(api, f"objective:{_TARGET}:user_flag", "objective", {
            "objective_type": "user_flag", "status": "failed", "target": _TARGET,
            "attempted_paths": [], "attempted_capability_paths": [],
        })
        await _seed_edge(api, h_id, f"objective:{_TARGET}:user_flag", edge_type="indicates")

        subgraph = await _subgraph(api, _TARGET)
        assert objective_reopening_eligible(subgraph, _TARGET, "user_flag") is False

    @pytest.mark.asyncio
    async def test_already_attempted_capability_id_not_eligible_again(self) -> None:
        api = _make_api()
        h_id = host_id(_TARGET)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, cap_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": h_id, "validated": True,
            "principal": "root", "confidence": 0.85, "runtime_available": True, "metadata": {},
        })
        await _seed_edge(api, h_id, cap_id)
        await _seed_node(api, f"objective:{_TARGET}:user_flag", "objective", {
            "objective_type": "user_flag", "status": "failed", "target": _TARGET,
            "attempted_paths": ["/home/root/user.txt"],
            "attempted_capability_paths": [[cap_id, "/home/root/user.txt"]],
        })
        await _seed_edge(api, h_id, f"objective:{_TARGET}:user_flag", edge_type="indicates")

        subgraph = await _subgraph(api, _TARGET)
        assert objective_reopening_eligible(subgraph, _TARGET, "user_flag") is False

    @pytest.mark.asyncio
    async def test_reregistration_after_invalidation_reopens_eligibility(self) -> None:
        """The full transition: a capability was attempted (exhausted) via
        one capability_id, that capability was invalidated and replaced by
        a NEW capability_id (e.g. a different principal/transport becomes
        available) — the new, never-attempted capability makes the
        objective eligible again."""
        api = _make_api()
        h_id = host_id(_TARGET)
        old_cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        new_cap_id = access_capability_id(_TARGET, "local_shell", "app")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, old_cap_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": h_id, "validated": True,
            "principal": "root", "confidence": 0.85, "runtime_available": False, "metadata": {},
        })
        await _seed_node(api, new_cap_id, "access_capability", {
            "capability_type": "local_shell", "host_id": h_id, "validated": True,
            "principal": "app", "confidence": 0.8, "runtime_available": True, "metadata": {},
        })
        await _seed_edge(api, h_id, old_cap_id)
        await _seed_edge(api, h_id, new_cap_id)
        await _seed_node(api, f"objective:{_TARGET}:user_flag", "objective", {
            "objective_type": "user_flag", "status": "failed", "target": _TARGET,
            "attempted_paths": ["/home/root/user.txt"],
            "attempted_capability_paths": [[old_cap_id, "/home/root/user.txt"]],
        })
        await _seed_edge(api, h_id, f"objective:{_TARGET}:user_flag", edge_type="indicates")

        subgraph = await _subgraph(api, _TARGET)
        assert objective_reopening_eligible(subgraph, _TARGET, "user_flag") is True


# ---------------------------------------------------------------------------
# 22. Persistence and replay guarantees
# ---------------------------------------------------------------------------

class TestPersistenceAndReplay:
    def test_apex_graph_state_never_contains_runtime_reference_types(self) -> None:
        import typing

        from apex_host.graph_state import ApexGraphState

        hints = typing.get_type_hints(ApexGraphState, include_extras=True)
        forbidden_names = {"RuntimeReference", "RuntimeReferenceStore", "RuntimeReferenceResolver", "CapabilityRuntimeRegistry"}
        for _field_name, field_type in hints.items():
            type_str = str(field_type)
            for forbidden in forbidden_names:
                assert forbidden not in type_str

    def test_orchestration_deps_never_serialized_into_state(self) -> None:
        source = inspect.getsource(__import__("apex_host.orchestration.dispatch_node", fromlist=["x"]))
        # Runtime reference/registry objects are only ever read from deps.*,
        # never assigned into a returned state dict value.
        assert "state[\"runtime_reference_store\"]" not in source
        assert "state[\"capability_registry\"]" not in source

    def test_fresh_store_never_resolves_reference_from_a_different_instance(self) -> None:
        store_a = RuntimeReferenceStore()
        store_b = RuntimeReferenceStore()
        registry = CapabilityRuntimeRegistry()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        ref = store_a.mint(capability_id="cap-1", target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1)
        resolver_b = RuntimeReferenceResolver(store_b, registry)
        resolved, error = resolver_b.resolve(ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert resolved is None
        assert error is RuntimeReferenceError.not_found

    def test_fresh_registry_after_restart_has_no_adapters(self) -> None:
        """Simulates a process restart: a brand-new CapabilityRuntimeRegistry
        has no adapters even though the EKG (not modeled here) might still
        say runtime_available=True from before the restart."""
        registry = CapabilityRuntimeRegistry()
        assert registry.has("any-capability-id") is False
        assert registry.generation_for("any-capability-id") == 0

    def test_capability_registry_not_in_orchestration_deps_forbidden_scan(self) -> None:
        """Architecture scan mirroring test_phase10_orchestration.py's own
        DEPS-07 pattern: OrchestrationDeps itself (the container) is never
        a field inside ApexGraphState."""
        import typing

        from apex_host.graph_state import ApexGraphState

        hints = typing.get_type_hints(ApexGraphState)
        for _field_name, field_type in hints.items():
            assert "OrchestrationDeps" not in str(field_type)


# ---------------------------------------------------------------------------
# 23. Dry-run guarantees
# ---------------------------------------------------------------------------

class TestDryRunGuarantees:
    @pytest.mark.asyncio
    async def test_full_dry_run_engagement_never_populates_runtime_reference_store(self) -> None:
        from apex_host.graph import build_apex_graph
        from apex_host.tools.registry import ToolRegistry

        api = _make_api()
        h_id = host_id(_TARGET)
        svc_id = f"service:{_TARGET}:22/tcp"
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, svc_id, "service", {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"})
        await _seed_edge(api, h_id, svc_id, edge_type="exposes")

        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=6,
            username_candidates=["root"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        capability_registry = CapabilityRuntimeRegistry()
        runtime_reference_store = RuntimeReferenceStore()
        graph = build_apex_graph(
            api, registry, config,
            capability_registry=capability_registry, runtime_reference_store=runtime_reference_store,
        )
        await graph.ainvoke(_make_initial_state(_TARGET))
        # Regardless of what was derived/registered, no RuntimeReference may
        # ever have been minted while dry_run=True.
        assert runtime_reference_store._references == {}  # noqa: SLF001 - white-box invariant check

    def test_ensure_runtime_reference_helper_noop_under_dry_run(self) -> None:
        from apex_host.orchestration.dispatch_node import _ensure_runtime_reference

        registry = CapabilityRuntimeRegistry()
        store = RuntimeReferenceStore()
        registry.register("cap-1", object())  # type: ignore[arg-type]
        deps = _build_deps(_make_api(), ApexConfig(target=_TARGET, dry_run=True), capability_registry=registry, runtime_reference_store=store)
        cap = AccessCapability(
            capability_id="cap-1", host_id=host_id(_TARGET), capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.85, source_task_id="t-1",
        )
        _ensure_runtime_reference(deps, cap, _TARGET)
        assert store.current_reference_for("cap-1") is None


# ---------------------------------------------------------------------------
# 24. Configuration
# ---------------------------------------------------------------------------

class TestConfiguration:
    def test_default_ttl_is_zero(self) -> None:
        config = ApexConfig(target=_TARGET)
        assert config.capability_runtime_reference_ttl_seconds == 0.0

    def test_ttl_configurable(self) -> None:
        config = ApexConfig(target=_TARGET, capability_runtime_reference_ttl_seconds=3600.0)
        assert config.capability_runtime_reference_ttl_seconds == 3600.0

    def test_present_in_safe_dict(self) -> None:
        config = ApexConfig(target=_TARGET)
        assert "capability_runtime_reference_ttl_seconds" in config.to_safe_dict()

    def test_from_cli_args_default(self) -> None:
        import argparse

        args = argparse.Namespace(target=_TARGET, dry_run=True)
        config = ApexConfig.from_cli_args(args)
        assert config.capability_runtime_reference_ttl_seconds == 0.0

    def test_from_cli_args_explicit(self) -> None:
        import argparse

        args = argparse.Namespace(target=_TARGET, dry_run=True, capability_runtime_reference_ttl_seconds=120.0)
        config = ApexConfig.from_cli_args(args)
        assert config.capability_runtime_reference_ttl_seconds == 120.0


# ---------------------------------------------------------------------------
# 25. Architecture scans
# ---------------------------------------------------------------------------

class TestArchitectureScans:
    def test_runtime_references_module_never_imports_apex_host_orchestration(self) -> None:
        """Checked against actual import statements only — the module's own
        docstring legitimately MENTIONS apex_host.orchestration.* modules as
        prose (describing who calls this module), which is not an import."""
        source = inspect.getsource(__import__("apex_host.capabilities.runtime_references", fromlist=["x"]))
        import_lines = [
            line.strip() for line in source.splitlines()
            if line.strip().startswith("import ") or line.strip().startswith("from ")
        ]
        assert not any("apex_host.orchestration" in line for line in import_lines)

    def test_runtime_references_module_has_no_network_or_subprocess_calls(self) -> None:
        source = _non_comment_code(
            inspect.getsource(__import__("apex_host.capabilities.runtime_references", fromlist=["x"]))
        )
        for forbidden in ("subprocess", "create_subprocess", "httpx.", "socket.socket", "paramiko."):
            assert forbidden not in source

    def test_emission_module_never_calls_memory_api_or_dispatcher(self) -> None:
        source = _non_comment_code(inspect.getsource(__import__("apex_host.capabilities.emission", fromlist=["x"])))
        for forbidden in ("apply_deltas", "MemoryAPI(", "dispatcher.dispatch", "CapabilityRuntimeRegistry("):
            assert forbidden not in source

    def test_emission_module_functions_take_typed_dataclasses_not_dict(self) -> None:
        import apex_host.capabilities.emission as emission_mod

        for name in (
            "evidence_from_direct_file_read_validation", "evidence_from_local_command_validation",
            "evidence_from_remote_command_validation", "evidence_from_web_command_validation",
        ):
            fn = getattr(emission_mod, name)
            sig = inspect.signature(fn)
            first_param = next(iter(sig.parameters.values()))
            assert first_param.annotation != "dict[str, Any]"
            assert first_param.annotation is not dict


# ---------------------------------------------------------------------------
# 26. Full synthetic end-to-end flow: register -> mint -> resolve ->
#     connection failure -> invalidate -> re-register -> new generation
# ---------------------------------------------------------------------------

class TestFullSyntheticRuntimeReferenceFlow:
    @pytest.mark.asyncio
    async def test_end_to_end_generation_lifecycle(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        config = ApexConfig(target=_TARGET, dry_run=False, username_candidates=["root"], password_candidates=["pw"])
        registry = CapabilityRuntimeRegistry()
        store = RuntimeReferenceStore()
        resolver = RuntimeReferenceResolver(store, registry)
        cap_id = access_capability_id(_TARGET, "ssh_command", "root")

        # Turn 1: organic SSH evidence -> discovery -> registration -> mint.
        ctx = _context(api, subgraph, config=config, registry=registry, runtime_reference_store=store)
        result = await run_capability_discovery([_ssh_evidence()], context=ctx)
        assert result.capabilities_derived == 1
        assert result.adapters_registered == 1
        ref1 = store.current_reference_for(cap_id)
        assert ref1 is not None
        assert ref1.generation == 1

        # Resolve succeeds this turn.
        adapter, error = resolver.resolve(ref1.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert error is None
        assert adapter is not None

        # A connection-level failure is observed -> invalidate.
        registry.unregister(cap_id)
        store.invalidate_for_capability(cap_id, reason=RuntimeReferenceError.session_invalid.value)
        adapter2, error2 = resolver.resolve(ref1.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert adapter2 is None
        assert error2 is RuntimeReferenceError.revoked

        # Next turn: re-registration produces a NEW generation and a NEW
        # reference, never reusing the revoked one.
        subgraph2 = await _subgraph(api, _TARGET)
        ctx2 = _context(api, subgraph2, config=config, registry=registry, runtime_reference_store=store)
        result2 = await run_capability_discovery([_ssh_evidence(evidence_id=new_id())], context=ctx2)
        assert result2.adapters_registered == 1
        ref2 = store.current_reference_for(cap_id)
        assert ref2 is not None
        assert ref2.reference_id != ref1.reference_id
        assert ref2.generation == 2
        assert ref2.revoked is False

        adapter3, error3 = resolver.resolve(ref2.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
        assert error3 is None
        assert adapter3 is not None
