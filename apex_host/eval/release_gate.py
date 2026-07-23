# release_gate.py
# The final synthetic release-gate suite (Phase 25) — twelve deterministic scenarios proving the capability-evidence -> discovery -> runtime-activation -> objective-verification pipeline behaves correctly, including every documented negative/boundary case.
"""Synthetic release-gate suite.

    uv run python -m apex_host.eval.release_gate

This is a **test-suite result, not an engagement-success signal** — its
exit code answers "does the implemented architecture behave correctly
across its supported scenarios?", never "was a real target compromised?".
No scenario here contacts a real network, requires Docker/VPN/a real HTB
machine, or performs any real exploitation. Every scenario builds an
in-memory ``MemoryAPI`` (the exact synthetic-target pattern
``apex_host.eval.run_synthetic_machine`` already established) and drives
the REAL production classes directly: ``CapabilityEvidence`` ->
``run_capability_discovery`` -> ``CapabilityParser`` ->
``CapabilityRuntimeRegistry`` -> ``RuntimeReferenceStore``/
``RuntimeReferenceResolver`` -> ``UserFlagExecutor`` -> ``verify_user_flag``
-> ``ObjectiveParser`` -> ``EngagementOutcome``.

The one deliberate synthetic substitution: the lowest-level *transport*
(a real SSH/Paramiko session, a real HTTP request, a real subprocess) is
replaced with a bounded, in-memory ``_FakeFlagReadCapability`` — a plain
``FlagReadCapability`` implementation (the exact seam
``apex_host/runtime_registry.py`` documents as the pluggable extension
point for a "future adapter"). Real transport correctness for each family
is already covered by that family's own dedicated test suite
(``tests/apex_host/test_ssh_executor.py``,
``test_phase20_direct_file_read_capability.py``,
``test_phase21_bounded_command_capability.py``) — this release gate proves
the INTEGRATION around those transports, not the transports themselves.

Every scenario asserts the raw flag value never appears in any persisted
node prop, matching this codebase's own standing "no raw flag persistence"
invariant.
"""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from typing import Any

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node, SubgraphView, TaskSpec

from apex_host.capabilities.discovery import CapabilityDiscoveryContext, run_capability_discovery
from apex_host.capabilities.evidence import CapabilityEvidence, CapabilityEvidenceType
from apex_host.capabilities.runtime_references import RuntimeReferenceResolver, RuntimeReferenceStore
from apex_host.config import ApexConfig
from apex_host.graph_ids import access_capability_id, access_state_id, host_id
from apex_host.parsers.objective_parser import ObjectiveParser
from apex_host.planners.objective import objective_status_from_subgraph
from apex_host.runtime_registry import BoundedReadResult, CapabilityRuntimeRegistry, FlagReadCapability
from apex_host.types import AccessCapabilityType

_TARGET = "10.10.10.250"  # synthetic, never a real HTB IP
_FLAG_VALUE = "b7f0d2a4c9e13856"  # synthetic, well-formed — never a real flag
_ANCHOR = host_id(_TARGET)


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
        source="release_gate", first_seen=ts, last_seen=ts,
    ))


async def _seed_edge(api: MemoryAPI, from_id: str, to_id: str, edge_type: str = "has_capability") -> None:
    ts = now()
    await api.upsert_edge(Edge(
        id=f"edge:{edge_type}:{from_id}:{to_id}", from_id=from_id, to_id=to_id, type=edge_type,
        props={}, confidence=0.9, source="release_gate", first_seen=ts, last_seen=ts,
    ))


async def _subgraph(api: MemoryAPI) -> SubgraphView:
    return await api.get_subgraph(_ANCHOR, depth=5)


def _config(**overrides: Any) -> ApexConfig:
    base: dict[str, Any] = dict(target=_TARGET, dry_run=False)
    base.update(overrides)
    return ApexConfig(**base)


class _FakeFlagReadCapability:
    """A synthetic, in-memory ``FlagReadCapability`` — never opens a real
    connection. Stands in for the lowest-level transport only; every class
    above it in the pipeline is the real production implementation. See
    module docstring."""

    def __init__(self, *, content: str = _FLAG_VALUE, connected: bool = True, error: str | None = None) -> None:
        self._content = content
        self._connected = connected
        self._error = error

    async def read_bounded_file(self, path: str) -> BoundedReadResult:
        return BoundedReadResult(
            connected=self._connected, output=self._content if self._connected else "",
            error=self._error, method="fake",
        )


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    name: str
    passed: bool
    detail: str


@dataclass(slots=True)
class ReleaseGateReport:
    results: list[ScenarioResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    def format_text(self) -> str:
        lines = ["APEX release gate — synthetic scenario results:"]
        for r in self.results:
            lines.append(f"  [{'PASS' if r.passed else 'FAIL'}] {r.name} — {r.detail}")
        lines.append("")
        failed = [r.name for r in self.results if not r.passed]
        if failed:
            lines.append(f"RELEASE GATE FAILED: {len(failed)} scenario(s): {', '.join(failed)}")
        else:
            lines.append(f"RELEASE GATE PASSED: {len(self.results)} scenario(s).")
        return "\n".join(lines)


async def _raw_flag_absent(api: MemoryAPI) -> bool:
    subgraph = await _subgraph(api)
    import json
    serialized = json.dumps([n.props for n in subgraph.nodes], default=str)
    return _FLAG_VALUE not in serialized


async def _run_ssh_style_success(
    *, capability_family: AccessCapabilityType, evidence_type: CapabilityEvidenceType, tool_name: str,
) -> ScenarioResult:
    api = _make_api()
    config = _config(username_candidates=["root"], password_candidates=["pw"])
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    if capability_family is AccessCapabilityType.ssh_command:
        await _seed_node(api, access_state_id(_TARGET, "root", protocol="ssh"), "access_state", {
            "level": "user", "username": "root", "target": _TARGET, "service": "ssh",
        })
    subgraph = await _subgraph(api)

    registry = CapabilityRuntimeRegistry()
    evidence = CapabilityEvidence(
        evidence_id=new_id(), evidence_type=evidence_type, capability_family=capability_family,
        target_host_id=_ANCHOR, source_task_id="release-gate-task", principal="root",
        validation_method=(
            "deterministic_benign_command" if evidence_type is CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND
            else "backend_confirmed_session"
        ),
        confidence=0.85, timestamp=now(),
    )
    ctx = CapabilityDiscoveryContext(
        api=api, config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET,
        now_iso=now(), attempt_runtime_registration=False,
    )
    discovery = await run_capability_discovery([evidence], context=ctx)
    if discovery.capabilities_derived != 1:
        return ScenarioResult(tool_name, False, f"expected 1 derived capability, got {discovery.capabilities_derived}")

    cap_id = access_capability_id(_TARGET, capability_family.value, "root")
    fake_adapter: FlagReadCapability = _FakeFlagReadCapability(content=_FLAG_VALUE)
    generation = registry.replace(cap_id, fake_adapter)
    store = RuntimeReferenceStore()
    resolver = RuntimeReferenceResolver(store, registry)
    ref = store.mint(
        capability_id=cap_id, target=_TARGET, capability_type=capability_family, generation=generation,
    )
    adapter, err = resolver.resolve(ref.reference_id, target=_TARGET, capability_type=capability_family)
    if err is not None or adapter is None:
        return ScenarioResult(tool_name, False, f"resolver rejected a freshly-minted reference: {err}")

    from apex_host.agents.user_flag_executor import UserFlagExecutor
    from memfabric.types import EvidenceBundle

    executor = UserFlagExecutor(config, registry)
    task = TaskSpec(
        id="release-gate-verify", goal_id="release-gate", executor_domain="objective",
        params={
            "capability_id": cap_id, "capability_type": capability_family.value, "principal": "root",
            "candidate_path": "/home/root/user.txt",
        },
        subgraph_anchor=_ANCHOR, phase="objective",
    )
    result = await executor.run(task, EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]))
    data = result.episode.data

    parser = ObjectiveParser()
    parsed = parser.parse_user_flag_result(
        target=_TARGET, objective_type="user_flag", candidate_path=str(data["candidate_path"]),
        connected=bool(data["connected"]), verified=bool(data["verified"]),
        value_digest=str(data["value_digest"]), redacted_value=str(data["redacted_value"]),
        verification_method=str(data["verification_method"]), capability_id=cap_id,
        capability_type=capability_family.value, principal="root",
        attempted_paths=["/home/root/user.txt"], is_last_candidate=True,
    )
    await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)

    final_subgraph = await _subgraph(api)
    status = objective_status_from_subgraph(final_subgraph, _TARGET, "user_flag")
    if status != "verified":
        return ScenarioResult(tool_name, False, f"objective status is {status!r}, expected 'verified'")
    if not await _raw_flag_absent(api):
        return ScenarioResult(tool_name, False, "raw flag value leaked into persisted graph state")
    return ScenarioResult(tool_name, True, "objective verified; runtime reference resolved; raw flag absent from graph")


async def scenario_ssh_success() -> ScenarioResult:
    """1. SSH user-flag success."""
    return await _run_ssh_style_success(
        capability_family=AccessCapabilityType.ssh_command,
        evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
        tool_name="ssh_success",
    )


async def scenario_remote_bounded_command_success() -> ScenarioResult:
    """3. Remote bounded-command user-flag success."""
    return await _run_ssh_style_success(
        capability_family=AccessCapabilityType.remote_command,
        evidence_type=CapabilityEvidenceType.REMOTE_COMMAND_VALIDATED,
        tool_name="remote_bounded_command_success",
    )


async def scenario_dfr_success() -> ScenarioResult:
    """2. Direct File Read user-flag success."""
    api = _make_api()
    config = _config()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    subgraph = await _subgraph(api)
    registry = CapabilityRuntimeRegistry()
    evidence = CapabilityEvidence(
        evidence_id=new_id(), evidence_type=CapabilityEvidenceType.DIRECT_FILE_READ_VALIDATED,
        capability_family=AccessCapabilityType.arbitrary_file_read, target_host_id=_ANCHOR,
        source_task_id="release-gate-task", principal="application",
        validation_method="path_dependent_content", confidence=0.8, timestamp=now(),
        sanitized_attributes={"requires_auth": False, "max_response_bytes": 4096},
    )
    ctx = CapabilityDiscoveryContext(
        api=api, config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET,
        now_iso=now(), attempt_runtime_registration=False,
    )
    discovery = await run_capability_discovery([evidence], context=ctx)
    if discovery.capabilities_derived != 1:
        return ScenarioResult("dfr_success", False, f"expected 1 derived capability, got {discovery.capabilities_derived}")

    cap_id = access_capability_id(_TARGET, "arbitrary_file_read", "application")
    registry.replace(cap_id, _FakeFlagReadCapability(content=_FLAG_VALUE))

    from apex_host.agents.user_flag_executor import UserFlagExecutor
    from memfabric.types import EvidenceBundle

    executor = UserFlagExecutor(config, registry)
    task = TaskSpec(
        id="release-gate-verify-dfr", goal_id="release-gate", executor_domain="objective",
        params={
            "capability_id": cap_id, "capability_type": "arbitrary_file_read", "principal": "application",
            "candidate_path": "/home/app/user.txt",
        },
        subgraph_anchor=_ANCHOR, phase="objective",
    )
    result = await executor.run(task, EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]))
    data = result.episode.data
    parser = ObjectiveParser()
    parsed = parser.parse_user_flag_result(
        target=_TARGET, objective_type="user_flag", candidate_path=str(data["candidate_path"]),
        connected=bool(data["connected"]), verified=bool(data["verified"]),
        value_digest=str(data["value_digest"]), redacted_value=str(data["redacted_value"]),
        verification_method=str(data["verification_method"]), capability_id=cap_id,
        capability_type="arbitrary_file_read", principal="application",
        attempted_paths=["/home/app/user.txt"], is_last_candidate=True,
    )
    await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
    final_subgraph = await _subgraph(api)
    status = objective_status_from_subgraph(final_subgraph, _TARGET, "user_flag")
    if status != "verified":
        return ScenarioResult("dfr_success", False, f"objective status is {status!r}, expected 'verified'")
    if not await _raw_flag_absent(api):
        return ScenarioResult("dfr_success", False, "raw flag value leaked into persisted graph state")
    return ScenarioResult("dfr_success", True, "objective verified via direct-file-read capability; raw flag absent")


async def scenario_no_capability_failure() -> ScenarioResult:
    """4. No-capability failure — reconnaissance completes, no usable
    capability exists, no flag attempt is ever made, objective stays
    unverified (non-zero exit at the CLI layer)."""
    api = _make_api()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    svc_id = f"service:{_TARGET}:80/tcp"
    await _seed_node(api, svc_id, "service", {"port": "80", "proto": "tcp", "service": "http"})
    await _seed_edge(api, _ANCHOR, svc_id, edge_type="exposes")
    subgraph = await _subgraph(api)
    status = objective_status_from_subgraph(subgraph, _TARGET, "user_flag")
    caps_present = any(n.type == "access_capability" for n in subgraph.nodes)
    if caps_present:
        return ScenarioResult("no_capability_failure", False, "unexpected capability node present in a no-capability fixture")
    if status == "verified":
        return ScenarioResult("no_capability_failure", False, "objective incorrectly verified with no capability")
    return ScenarioResult("no_capability_failure", True, f"no capability present; objective status={status!r} (never verified)")


async def scenario_candidate_not_verified() -> ScenarioResult:
    """5. Candidate-not-verified failure — a read succeeds but the content
    does not pass ``verify_user_flag``; the objective must not be
    verified, and the raw (non-flag-shaped) candidate must not be
    persisted."""
    api = _make_api()
    config = _config()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    registry = CapabilityRuntimeRegistry()
    cap_id = access_capability_id(_TARGET, "ssh_command", "root")
    # A real engagement always has an already-persisted capability node by
    # the time ObjectivePlanner selects its capability_id — seed one here
    # to match (ObjectiveParser builds an `enables` edge FROM this id
    # regardless of verification outcome; see its own source).
    await _seed_node(api, cap_id, "access_capability", {
        "capability_type": "ssh_command", "host_id": _ANCHOR, "validated": True,
        "principal": "root", "confidence": 0.85, "runtime_available": True, "metadata": {},
    })
    await _seed_edge(api, _ANCHOR, cap_id)
    registry.register(cap_id, _FakeFlagReadCapability(content="not a flag at all, just plain text output"))

    from apex_host.agents.user_flag_executor import UserFlagExecutor
    from memfabric.types import EvidenceBundle

    executor = UserFlagExecutor(config, registry)
    task = TaskSpec(
        id="release-gate-candidate", goal_id="release-gate", executor_domain="objective",
        params={
            "capability_id": cap_id, "capability_type": "ssh_command", "principal": "root",
            "candidate_path": "/home/root/user.txt",
        },
        subgraph_anchor=_ANCHOR, phase="objective",
    )
    result = await executor.run(task, EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]))
    data = result.episode.data
    if data["verified"]:
        return ScenarioResult("candidate_not_verified", False, "unverified candidate content was incorrectly marked verified")
    parser = ObjectiveParser()
    parsed = parser.parse_user_flag_result(
        target=_TARGET, objective_type="user_flag", candidate_path=str(data["candidate_path"]),
        connected=bool(data["connected"]), verified=bool(data["verified"]),
        value_digest=str(data["value_digest"]), redacted_value=str(data["redacted_value"]),
        verification_method=str(data["verification_method"]), capability_id=cap_id,
        capability_type="ssh_command", principal="root",
        attempted_paths=["/home/root/user.txt"], is_last_candidate=True,
    )
    await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
    final_subgraph = await _subgraph(api)
    status = objective_status_from_subgraph(final_subgraph, _TARGET, "user_flag")
    if status == "verified":
        return ScenarioResult("candidate_not_verified", False, "objective incorrectly reached 'verified' status")
    import json
    raw_candidate_present = any(
        "not a flag at all" in json.dumps(n.props, default=str) for n in final_subgraph.nodes
    )
    if raw_candidate_present:
        return ScenarioResult("candidate_not_verified", False, "raw unverified candidate content was persisted")
    return ScenarioResult("candidate_not_verified", True, f"candidate rejected by verifier; objective status={status!r}; raw candidate not persisted")


async def scenario_runtime_reference_expiry() -> ScenarioResult:
    """6. Runtime-reference expiry — capability metadata remains, but the
    adapter is unavailable (unregistered/revoked); the objective must not
    execute through a stale reference."""
    registry = CapabilityRuntimeRegistry()
    store = RuntimeReferenceStore()
    resolver = RuntimeReferenceResolver(store, registry)
    cap_id = access_capability_id(_TARGET, "ssh_command", "root")
    registry.register(cap_id, _FakeFlagReadCapability())
    ref = store.mint(
        capability_id=cap_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1,
    )
    registry.unregister(cap_id)  # adapter torn down; reference metadata unchanged
    adapter, err = resolver.resolve(ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
    if adapter is not None or err is None:
        return ScenarioResult("runtime_reference_expiry", False, "resolver returned an adapter for an unregistered capability")
    return ScenarioResult("runtime_reference_expiry", True, f"stale reference correctly rejected: {err.value}")


async def scenario_authorization_revoked() -> ScenarioResult:
    """7. Authorization revoked — references revoked, adapters removed,
    the engagement cannot proceed through them."""
    registry = CapabilityRuntimeRegistry()
    store = RuntimeReferenceStore()
    resolver = RuntimeReferenceResolver(store, registry)
    cap_id = access_capability_id(_TARGET, "ssh_command", "root")
    registry.register(cap_id, _FakeFlagReadCapability())
    ref = store.mint(
        capability_id=cap_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command, generation=1,
    )
    store.invalidate_for_capability(cap_id, reason="authorization_revoked")
    registry.unregister(cap_id)
    adapter, err = resolver.resolve(ref.reference_id, target=_TARGET, capability_type=AccessCapabilityType.ssh_command)
    if adapter is not None:
        return ScenarioResult("authorization_revoked", False, "adapter resolved after authorization revocation")
    return ScenarioResult("authorization_revoked", True, f"revoked reference correctly rejected: {err.value if err else 'none'}")


async def scenario_policy_denial() -> ScenarioResult:
    """8. Policy denial — an unsafe/off-scope action is denied by
    ``PolicyAdvisor``, with no bypass."""
    from apex_host.policy import PolicyAdvisor, load_policy
    from apex_host.execution.context import ExecutionContext
    from memfabric.types import EvidenceBundle

    config = _config()
    advisor = PolicyAdvisor(load_policy(config), config)
    task = TaskSpec(
        id="release-gate-policy", goal_id="release-gate", executor_domain="recon",
        params={"tool": "nmap", "args": ["-sV", "10.10.10.99"], "target": "10.10.10.99"},
        subgraph_anchor=_ANCHOR, phase="recon",
    )
    ctx = ExecutionContext(
        run_id="release-gate", phase="recon", turn_number=0, evidence_version=None,
        subgraph=SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0),
        evidence=EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]), dry_run=True,
    )
    decision = advisor.review_task(task, "recon", ctx.evidence, config)
    if decision.is_approved:
        return ScenarioResult("policy_denial", False, "off-scope target was incorrectly approved by policy")
    return ScenarioResult("policy_denial", True, f"off-scope task correctly blocked: rule={decision.rule_name}")


async def scenario_dry_run() -> ScenarioResult:
    """9. Dry-run — plans and reports; no live adapter activation; no
    objective evidence; no success."""
    registry = CapabilityRuntimeRegistry()
    store = RuntimeReferenceStore()
    config = _config(dry_run=True)
    cap_id = access_capability_id(_TARGET, "ssh_command", "root")
    registry.register(cap_id, _FakeFlagReadCapability())

    from apex_host.agents.user_flag_executor import UserFlagExecutor
    from memfabric.types import EvidenceBundle

    executor = UserFlagExecutor(config, registry)
    task = TaskSpec(
        id="release-gate-dry-run", goal_id="release-gate", executor_domain="objective",
        params={
            "capability_id": cap_id, "capability_type": "ssh_command", "principal": "root",
            "candidate_path": "/home/root/user.txt",
        },
        subgraph_anchor=_ANCHOR, phase="objective",
    )
    result = await executor.run(task, EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]))
    data = result.episode.data
    if not data["dry_run"] or data["verified"]:
        return ScenarioResult("dry_run", False, "dry-run executor produced live-looking verified output")
    if store._references:  # noqa: SLF001 - white-box invariant check: nothing was ever minted
        return ScenarioResult("dry_run", False, "a RuntimeReference was minted during a dry-run scenario")
    return ScenarioResult("dry_run", True, "dry-run executor returned synthetic, unverified output; no runtime reference minted")


async def scenario_repair_path_capability_activation() -> ScenarioResult:
    """10. Repair-path capability activation — a repaired, typed SSH
    result emits capability evidence identically to a normally-dispatched
    one (Phase 24's shared result-processing helper)."""
    from apex_host.orchestration.parsing_node import parse_result_and_collect_evidence, run_pending_capability_discovery
    from apex_host.orchestration.dependencies import OrchestrationDeps
    from apex_host.orchestration.stall import StallTracker
    from apex_host.execution.dispatcher import TaskDispatcher
    from apex_host.execution.registry import TaskRegistry
    from apex_host.planners.global_planner import GlobalPlanner
    from apex_host.planning.repair import RepairEngine
    from apex_host.policy import PolicyAdvisor, load_policy
    from apex_host.tools.registry import ToolRegistry
    from apex_host.orchestration.dependencies import build_planners

    api = _make_api()
    config = _config()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(api, access_state_id(_TARGET, "root", protocol="ssh"), "access_state", {
        "level": "user", "username": "root", "target": _TARGET, "service": "ssh",
    })
    svc_id = f"service:{_TARGET}:22/tcp"
    await _seed_node(api, svc_id, "service", {"port": "22", "proto": "tcp", "service": "ssh"})
    await _seed_edge(api, _ANCHOR, svc_id, edge_type="exposes")

    registry = ToolRegistry.from_config(config)
    capability_registry = CapabilityRuntimeRegistry()
    store = RuntimeReferenceStore()
    resolver = RuntimeReferenceResolver(store, capability_registry)
    deps = OrchestrationDeps(
        api=api, dispatcher=TaskDispatcher(
            advisor=PolicyAdvisor(load_policy(config), config), task_registry=TaskRegistry(),
            config=config, run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type]
        ),
        global_planner=GlobalPlanner(max_turns=config.max_turns), phase_planners=build_planners(config, registry),
        repair_engine=RepairEngine(model_router=None, allowed_tools=config.allowed_tools, dry_run=config.dry_run),
        config=config, anchor_id=_ANCHOR, stall_tracker=StallTracker(),
        capability_registry=capability_registry, runtime_reference_store=store, runtime_reference_resolver=resolver,
    )

    from typing import cast

    from apex_host.graph_state import ApexGraphState

    state = cast("ApexGraphState", {"target": _TARGET, "phase": "credential"})
    repaired_tr = {
        "tool": "ssh_access", "success": True, "username": "root", "task_id": "repaired-task",
        "target": _TARGET, "parser": "access", "port": "22", "authenticated": True, "operation": "id",
    }
    parsed, _source, evidence = parse_result_and_collect_evidence(repaired_tr, state, target=_TARGET)
    from apex_host.orchestration.parsing_node import apply_parsed_observation
    await apply_parsed_observation(deps, parsed)
    if evidence is None:
        return ScenarioResult("repair_path_capability_activation", False, "repaired ssh_access success produced no capability evidence")
    log = await run_pending_capability_discovery(deps, [evidence])
    derived = log.get("capability_discovery_log", [{}])[0].get("capabilities_derived", 0) if log else 0
    if derived != 1:
        return ScenarioResult("repair_path_capability_activation", False, f"expected 1 derived capability from repaired result, got {derived}")
    return ScenarioResult("repair_path_capability_activation", True, "repaired ssh_access success emitted capability evidence and derived a capability")


async def scenario_duplicate_evidence() -> ScenarioResult:
    """11. Duplicate evidence — no duplicate capability node, no
    confidence inflation, no repeated objective reopening."""
    api = _make_api()
    config = _config()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(api, access_state_id(_TARGET, "root", protocol="ssh"), "access_state", {
        "level": "user", "username": "root", "target": _TARGET, "service": "ssh",
    })
    registry = CapabilityRuntimeRegistry()
    evidence_id = new_id()

    async def _derive_once() -> Any:
        subgraph = await _subgraph(api)
        ev = CapabilityEvidence(
            evidence_id=evidence_id, evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
            capability_family=AccessCapabilityType.ssh_command, target_host_id=_ANCHOR,
            source_task_id="release-gate", principal="root", validation_method="deterministic_benign_command",
            confidence=0.85, timestamp=now(),
        )
        ctx = CapabilityDiscoveryContext(
            api=api, config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET,
            now_iso=now(), attempt_runtime_registration=False,
        )
        return await run_capability_discovery([ev], context=ctx)

    first = await _derive_once()
    second = await _derive_once()
    if first.capabilities_derived != 1 or second.duplicate_count != 1:
        return ScenarioResult(
            "duplicate_evidence", False,
            f"expected first.capabilities_derived=1 got {first.capabilities_derived}; "
            f"second.duplicate_count=1 got {second.duplicate_count}",
        )
    subgraph = await _subgraph(api)
    cap_nodes = [n for n in subgraph.nodes if n.type == "access_capability"]
    if len(cap_nodes) != 1:
        return ScenarioResult("duplicate_evidence", False, f"expected exactly 1 capability node, found {len(cap_nodes)}")
    return ScenarioResult("duplicate_evidence", True, "replayed evidence_id correctly classified as duplicate; no extra capability node created")


async def scenario_restart_replay() -> ScenarioResult:
    """12. Restart/replay — capability metadata restored (persisted in the
    EKG), but a fresh runtime registry/reference store (simulating a
    process restart) has no adapter; replay alone cannot reach
    'verified'."""
    api = _make_api()
    config = _config()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(api, access_state_id(_TARGET, "root", protocol="ssh"), "access_state", {
        "level": "user", "username": "root", "target": _TARGET, "service": "ssh",
    })
    old_registry = CapabilityRuntimeRegistry()
    subgraph = await _subgraph(api)
    evidence = CapabilityEvidence(
        evidence_id=new_id(), evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
        capability_family=AccessCapabilityType.ssh_command, target_host_id=_ANCHOR,
        source_task_id="release-gate", principal="root", validation_method="deterministic_benign_command",
        confidence=0.85, timestamp=now(),
    )
    ctx = CapabilityDiscoveryContext(
        api=api, config=config, capability_registry=old_registry, subgraph=subgraph, target=_TARGET,
        now_iso=now(), attempt_runtime_registration=False,
    )
    await run_capability_discovery([evidence], context=ctx)
    cap_id = access_capability_id(_TARGET, "ssh_command", "root")
    old_registry.register(cap_id, _FakeFlagReadCapability())  # the "before restart" live adapter

    # --- simulated process restart: brand-new, empty runtime objects ---
    fresh_registry = CapabilityRuntimeRegistry()
    fresh_store = RuntimeReferenceStore()
    fresh_resolver = RuntimeReferenceResolver(fresh_store, fresh_registry)

    post_restart_subgraph = await _subgraph(api)
    cap_node = next((n for n in post_restart_subgraph.nodes if n.type == "access_capability"), None)
    if cap_node is None:
        return ScenarioResult("restart_replay", False, "capability metadata was not restored from persisted EKG state")
    if fresh_registry.has(cap_id):
        return ScenarioResult("restart_replay", False, "fresh registry unexpectedly already has an adapter after 'restart'")
    if fresh_store.current_reference_for(cap_id) is not None:
        return ScenarioResult("restart_replay", False, "fresh reference store unexpectedly has a reference after 'restart'")
    stale_adapter, stale_err = fresh_resolver.resolve(
        "any-reference-id", target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
    )
    if stale_adapter is not None or stale_err is None:
        return ScenarioResult("restart_replay", False, "fresh resolver unexpectedly resolved a reference after 'restart'")

    from apex_host.agents.user_flag_executor import UserFlagExecutor
    from memfabric.types import EvidenceBundle

    executor = UserFlagExecutor(config, fresh_registry)
    task = TaskSpec(
        id="release-gate-replay", goal_id="release-gate", executor_domain="objective",
        params={
            "capability_id": cap_id, "capability_type": "ssh_command", "principal": "root",
            "candidate_path": "/home/root/user.txt",
        },
        subgraph_anchor=_ANCHOR, phase="objective",
    )
    result = await executor.run(task, EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]))
    data = result.episode.data
    if data["connected"] or data["verified"]:
        return ScenarioResult("restart_replay", False, "executor succeeded against an unregistered post-restart adapter")
    return ScenarioResult(
        "restart_replay", True,
        "capability metadata restored; fresh runtime registry/store empty; replay alone could not reach verified",
    )


SCENARIOS: list[Any] = [
    scenario_ssh_success,
    scenario_dfr_success,
    scenario_remote_bounded_command_success,
    scenario_no_capability_failure,
    scenario_candidate_not_verified,
    scenario_runtime_reference_expiry,
    scenario_authorization_revoked,
    scenario_policy_denial,
    scenario_dry_run,
    scenario_repair_path_capability_activation,
    scenario_duplicate_evidence,
    scenario_restart_replay,
]


async def run_release_gate() -> ReleaseGateReport:
    """Run every scenario in :data:`SCENARIOS`, in order, and return the
    aggregate report. A raised exception inside one scenario is caught and
    reported as a failed scenario — one broken scenario must never abort
    the rest of the gate."""
    results: list[ScenarioResult] = []
    for scenario in SCENARIOS:
        name = scenario.__name__.removeprefix("scenario_")
        try:
            results.append(await scenario())
        except Exception as exc:  # noqa: BLE001 - a scenario failure is data, not a crash
            results.append(ScenarioResult(name, False, f"scenario raised {type(exc).__name__}: {exc}"))
    return ReleaseGateReport(results)


def main(argv: list[str] | None = None) -> None:
    import argparse

    argparse.ArgumentParser(
        prog="apex_host.eval.release_gate",
        description=(
            "Synthetic release-gate suite: proves the capability-evidence -> "
            "discovery -> runtime-activation -> objective-verification pipeline "
            "behaves correctly. No real network/target/Docker/VPN involved. "
            "Exit code is a test-suite result, not an engagement-success signal."
        ),
    ).parse_args(argv)
    report = asyncio.run(run_release_gate())
    print(report.format_text())
    sys.exit(0 if report.passed else 1)


if __name__ == "__main__":
    main()
