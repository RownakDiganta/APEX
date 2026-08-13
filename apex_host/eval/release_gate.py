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


async def _seed_node(
    api: MemoryAPI, node_id: str, node_type: str, props: dict[str, Any] | None = None,
    *, source: str = "release_gate",
) -> None:
    ts = now()
    await api.upsert_node(Node(
        id=node_id, type=node_type, props=props or {}, confidence=0.9,
        source=source, first_seen=ts, last_seen=ts,
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
    elif capability_family is AccessCapabilityType.ftp_file_read:  # §28.17
        await _seed_node(api, access_state_id(_TARGET, "root", protocol="ftp"), "access_state", {
            "level": "user", "username": "root", "target": _TARGET, "service": "ftp",
        })
    subgraph = await _subgraph(api)

    registry = CapabilityRuntimeRegistry()
    evidence = CapabilityEvidence(
        evidence_id=new_id(), evidence_type=evidence_type, capability_family=capability_family,
        target_host_id=_ANCHOR, source_task_id="release-gate-task", principal="root",
        validation_method=(
            "deterministic_benign_command" if evidence_type in (
                CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
                CapabilityEvidenceType.FTP_FILE_READ_VALIDATED,  # §28.17
            )
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


async def scenario_ftp_flag_read() -> ScenarioResult:
    """§28.17 — a validated FTP access_state derives an ftp_file_read
    access_capability the ObjectivePlanner acts on, the flag is read, and the
    objective is user_flag_verified (raw flag never persisted). Drives the REAL
    derivation → discovery → objective → verify path (with the release gate's own
    synthetic-transport substitution). Fails against the old code, which had no
    FTP capability provider/derivation, so `capabilities_derived` would be 0."""
    return await _run_ssh_style_success(
        capability_family=AccessCapabilityType.ftp_file_read,
        evidence_type=CapabilityEvidenceType.FTP_FILE_READ_VALIDATED,
        tool_name="ftp_flag_read",
    )


async def scenario_ftp_root_flag_path() -> ScenarioResult:
    """§28.18 — the user flag lives at the FTP root ("/flag.txt"), NOT at
    "/home/<user>/user.txt" (Fawn's anonymous-FTP layout). Drive the REAL
    ``ObjectivePlanner`` turn loop against a path-sensitive fake FTP adapter that
    RETRs the flag ONLY for "/flag.txt" (every other path returns a connected,
    empty "no such file" read, exactly like a real RETR miss). Proves the default
    candidate set now reaches the FTP root. FAILS against the pre-§28.18 candidate
    generation, which only ever produced "/home/<user>/user.txt" and could not
    even construct "/flag.txt" (a "/" root collapsed to "" and was skipped)."""
    name = "ftp_root_flag_path"
    from apex_host.agents.user_flag_executor import UserFlagExecutor
    from apex_host.planners.objective_planner import ObjectivePlanner
    from apex_host.tools.registry import ToolRegistry
    from memfabric.types import AbandonSignal, EvidenceBundle, Goal

    api = _make_api()
    config = _config(username_candidates=["anonymous"], password_candidates=["anonymous"])
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(
        api, access_state_id(_TARGET, "anonymous", protocol="ftp"), "access_state",
        {"level": "user", "username": "anonymous", "target": _TARGET, "service": "ftp"},
    )
    cap_id = access_capability_id(_TARGET, AccessCapabilityType.ftp_file_read.value, "anonymous")
    # A real engagement has an already-persisted, runtime-available capability
    # node by the time ObjectivePlanner selects it (dispatch_node flips
    # runtime_available True after registration) — seed that end state.
    await _seed_node(api, cap_id, "access_capability", {
        "capability_type": "ftp_file_read", "host_id": _ANCHOR, "validated": True,
        "principal": "anonymous", "confidence": 0.85, "runtime_available": True, "metadata": {},
    })
    await _seed_edge(api, _ANCHOR, cap_id)

    class _RootOnlyFtp:
        """Flag only at the FTP root; every other path is a connected miss."""

        async def read_bounded_file(self, path: str) -> BoundedReadResult:
            if path == "/flag.txt":
                return BoundedReadResult(
                    connected=True, output=_FLAG_VALUE + "\n", error=None, method="ftp_read",
                )
            return BoundedReadResult(
                connected=True, output="", error="ftp retr failed: no such file", method="ftp_read",
            )

    registry = CapabilityRuntimeRegistry()
    registry.register(cap_id, _RootOnlyFtp())

    planner = ObjectivePlanner(_TARGET, ToolRegistry.from_config(config), config=config)
    executor = UserFlagExecutor(config, registry)
    parser = ObjectiveParser()
    goal = Goal(id="g", description="user-flag objective", phase="objective", anchor_node=_ANCHOR)
    eb = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])

    verified_path = ""
    for _ in range(8):  # bounded — one capability yields at most 6 candidates
        sub = await _subgraph(api)
        if objective_status_from_subgraph(sub, _TARGET, "user_flag") == "verified":
            break
        plan = await planner.plan(goal, sub, eb)
        if isinstance(plan, AbandonSignal) or not plan:
            break
        task = plan[0]
        res = await executor.run(task, eb)
        d = res.episode.data
        parsed = parser.parse_user_flag_result(
            target=_TARGET, objective_type="user_flag", candidate_path=str(d["candidate_path"]),
            connected=bool(d["connected"]), verified=bool(d["verified"]),
            value_digest=str(d["value_digest"]), redacted_value=str(d["redacted_value"]),
            verification_method=str(d["verification_method"]), capability_id=cap_id,
            capability_type="ftp_file_read", principal="anonymous",
            attempted_paths=list(task.params.get("attempted_paths", [])),
            attempted_capability_paths=list(task.params.get("attempted_capability_paths", [])),
            is_last_candidate=bool(task.params.get("is_last_candidate", False)),
        )
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
        if bool(d["verified"]):
            verified_path = str(d["candidate_path"])
            break

    final = await _subgraph(api)
    status = objective_status_from_subgraph(final, _TARGET, "user_flag")
    if status != "verified":
        return ScenarioResult(
            name, False, f"objective not verified (status={status!r}) — FTP-root /flag.txt not reached",
        )
    if verified_path != "/flag.txt":
        return ScenarioResult(name, False, f"verified via {verified_path!r}, expected the FTP root /flag.txt")
    if not await _raw_flag_absent(api):
        return ScenarioResult(name, False, "raw flag value leaked into the graph")
    return ScenarioResult(
        name, True, "flag at FTP root /flag.txt reached across candidate turns, read, and verified; raw absent",
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


class _ReconWebFakeBackend:
    """A synthetic ``ToolBackend`` for the recon->web regression scenario.

    Returns realistic-but-fake nmap (ports 22 + 80 open) and curl (HTTP 200
    homepage / robots.txt) output — never a real subprocess or network call.
    Records every (tool, args) call so the scenario can assert the demonstrated
    regressions are absent (privileged nmap, repeated failing scans, credential
    tasks without credentials)."""

    name = "fake-recon-web"

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    async def execute(
        self, tool: str, arguments: list[str], *,
        timeout_seconds: float | None = None, stdin: str | None = None,
    ) -> Any:
        from apex_host.types import ToolCommand, ToolResult

        self.calls.append((tool, list(arguments)))
        cmd = ToolCommand(tool=tool, args=list(arguments), timeout_seconds=int(timeout_seconds or 30))
        stdout = ""
        if tool == "nmap":
            stdout = (
                f"Nmap scan report for {_TARGET}\n"
                "Host is up (0.015s latency).\n"
                "PORT   STATE SERVICE VERSION\n"
                "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu\n"
                "80/tcp open  http    Apache httpd 2.4.41\n"
            )
        elif tool == "curl":
            joined = " ".join(arguments)
            if "-I" in arguments:
                stdout = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n"
            elif "robots.txt" in joined:
                stdout = "User-agent: *\nDisallow: /admin\n"
            else:
                stdout = (
                    "<!doctype html><html><head><title>Home</title></head>"
                    "<body><a href=\"/robots.txt\">robots</a></body></html>"
                )
        return ToolResult(
            command=cmd, stdout=stdout, stderr="", returncode=0,
            duration_seconds=0.001, dry_run=True, backend="fake-recon-web", error=None,
        )


async def scenario_recon_web_engagement_regression() -> ScenarioResult:
    """13. End-to-end recon->web regression (the demonstrated failed run).

    One authorized host; ports 22 + 80 discovered; an UNPRIVILEGED remote
    backend; HTTP homepage + robots.txt probed via URL targets; no credentials
    configured. Drives the REAL compiled graph with fake tools + a
    FakeModelRouter (deterministic) + a bounded LLM budget. Fails the gate if
    ANY demonstrated regression reappears:

    - a privileged nmap scan (``-sS`` / no ``-sT``) on the unprivileged backend;
    - a repeated unchanged fundamental nmap failure;
    - an authorized same-host HTTP URL rejected by policy;
    - a credential task scheduled without a credential hypothesis;
    - a fabricated success / forced phase completion;
    - inconsistent planner-call accounting;
    - a report schema regression;
    - a non-idempotent runtime shutdown.
    """
    from apex_host.config import ApexConfig
    from apex_host.eval.report import build_report, to_json_dict
    from apex_host.graph_state import ApexGraphState
    from apex_host.llm.router import FakeModelRouter
    from apex_host.orchestration.builder import build_apex_graph
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.tools.registry import ToolRegistry

    api = _make_api()
    config = ApexConfig(
        target=_TARGET, dry_run=True, max_turns=8, tool_backend="remote",
        allowed_tools=["nmap", "curl", "nc"], use_llm=False,
        max_llm_calls_per_run=20, max_llm_calls_per_phase=4,
    )
    backend = _ReconWebFakeBackend()
    budget = LLMBudgetTracker(max_per_run=20, max_per_phase=4)
    registry = ToolRegistry.from_config(config)
    graph = build_apex_graph(
        api, registry, config,
        model_router=FakeModelRouter(), budget_tracker=budget, tool_backend=backend,
    )

    initial: ApexGraphState = {
        "run_id": "release-gate-recon-web", "target": _TARGET, "phase": "recon",
        "goal": f"Begin engagement against {_TARGET}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [], "repair_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "", "privilege_state": "", "privilege_summary": {},
        "opportunity_ids": [], "attempted_opportunities": [],
        "enumeration_complete": False, "web_session_state": {},
        "workflow_summary": {}, "phase_selection": {}, "learning_summary": {},
        "task_latency_log": [], "objective_status": "", "objective_summary": {},
        "direct_file_read_log": [], "bounded_command_log": [],
        "capability_discovery_log": [], "execution_diagnostics": [],
    }
    final_state: ApexGraphState = await graph.ainvoke(initial)

    problems: list[str] = []

    # --- nmap: never privileged on an unprivileged backend, never repeated raw-socket failure ---
    nmap_calls = [args for (tool, args) in backend.calls if tool == "nmap"]
    for args in nmap_calls:
        if "-sS" in args or "-sT" not in args:
            problems.append(f"privileged/non-connect nmap on unprivileged backend: {args}")
    if len(nmap_calls) > 2:
        problems.append(f"nmap re-executed {len(nmap_calls)} times (repeated unchanged scan)")
    if any(str(d.get("disposition")) == "raw_socket_terminal" for d in final_state.get("duplicate_actions") or []):
        problems.append("a raw-socket terminal failure occurred against the fake backend")

    # --- policy: authorized same-host HTTP URLs must not be rejected ---
    for pd in final_state.get("policy_decisions") or []:
        tgt = str(pd.get("target", ""))
        if str(pd.get("status")) == "blocked" and tgt.startswith("http") and _TARGET in tgt:
            problems.append(f"authorized same-host HTTP URL rejected by policy: {tgt}")

    # --- credential phase must not run without a credential hypothesis (no creds) ---
    cred_tools = {"telnet_access", "ssh_access", "ftp_access"}
    if any(tool in cred_tools for (tool, _a) in backend.calls):
        problems.append("a credential-validation task ran with no credentials configured")
    if final_state.get("credential_validation_log"):
        problems.append("credential validation attempted without a credential hypothesis")

    # --- progress beyond initial web acquisition: web evidence was created ---
    subgraph = await api.get_subgraph(_ANCHOR, depth=5)
    node_types = {n.type for n in subgraph.nodes}
    if "service" not in node_types:
        problems.append("recon produced no service node (ports 22/80 not discovered)")
    if "endpoint" not in node_types:
        problems.append("web acquisition produced no endpoint node (no web evidence)")

    # --- no fabricated success / forced phase completion ---
    report = build_report(final_state, subgraph, config, llm_budget=budget.to_dict())
    if report.success or report.outcome == "user_flag_verified":
        problems.append("engagement fabricated success without a verified user flag")
    if not final_state.get("completed"):
        problems.append("engagement did not terminate with a truthful decision")

    # --- planner-call accounting is internally consistent ---
    u = budget.to_dict()
    if u["fallbacks"] != sum(u["fallback_reasons"].values()):
        problems.append("inconsistent fallback accounting (fallbacks != sum of reasons)")
    if u["calls_attempted"] > u["max_calls_per_run"]:
        problems.append("LLM calls exceeded the configured per-run budget")

    # --- report schema is intact ---
    js = to_json_dict(report)
    if not report.report_schema_version:
        problems.append("report schema_version missing")
    for key in ("engagement_outcome", "bounded_repair", "llm_usage"):
        if key not in js:
            problems.append(f"report JSON missing '{key}' block")
    if "fallback_reasons" not in js.get("llm_usage", {}):
        problems.append("report llm_usage missing fallback_reasons breakdown")

    # --- runtime shutdown is idempotent (no missing/duplicate shutdown) ---
    from apex_host.runtime import ApexRuntime
    rt = ApexRuntime(api=api, config=config, memfabric_config=Config(), registry=registry)
    await rt.aclose()
    await rt.aclose()  # second call must not raise

    if problems:
        return ScenarioResult("recon_web_engagement_regression", False, "; ".join(problems))
    return ScenarioResult(
        "recon_web_engagement_regression", True,
        f"recon->web progressed cleanly: {len(nmap_calls)} -sT nmap scan(s), "
        f"web evidence created, no premature credential, no fabricated success, "
        f"budget {u['calls_attempted']}/{u['max_calls_per_run']} consistent",
    )


class _UnprivilegedNmapBackend:
    """A synthetic ``ToolBackend`` that faithfully models the restricted Kali
    tool-service container: nmap runs as uid 0 but WITHOUT ``CAP_NET_RAW``, so
    any nmap invocation lacking ``--unprivileged`` fails with the demonstrated
    ``Couldn't open a raw socket. Error: (1) Operation not permitted`` (rc=1);
    an invocation carrying ``--unprivileged`` completes a connect scan and
    returns open ports. Never a real subprocess or network call."""

    name = "fake-unprivileged-nmap"

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []
        self.raw_socket_failures = 0

    async def execute(
        self, tool: str, arguments: list[str], *,
        timeout_seconds: float | None = None, stdin: str | None = None,
    ) -> Any:
        from apex_host.types import ToolCommand, ToolResult

        self.calls.append((tool, list(arguments)))
        cmd = ToolCommand(tool=tool, args=list(arguments), timeout_seconds=int(timeout_seconds or 30))
        if tool == "nmap" and "--unprivileged" not in arguments:
            # Exactly what the real container does for a raw-socket scan mode
            # attempted by root without NET_RAW.
            self.raw_socket_failures += 1
            return ToolResult(
                command=cmd, stdout="",
                stderr="Couldn't open a raw socket. Error: (1) Operation not permitted QUITTING!",
                returncode=1, duration_seconds=0.001, dry_run=True,
                backend=self.name, error=None,
            )
        stdout = ""
        if tool == "nmap":
            stdout = (
                f"Nmap scan report for {_TARGET}\n"
                "Host is up.\n"
                "PORT   STATE SERVICE VERSION\n"
                "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu\n"
            )
        return ToolResult(
            command=cmd, stdout=stdout, stderr="", returncode=0,
            duration_seconds=0.001, dry_run=True, backend=self.name, error=None,
        )


async def scenario_unprivileged_backend_completes_connect_scan() -> ScenarioResult:
    """14. An unprivileged backend COMPLETES a connect scan (does not dead-end).

    Models the restricted Kali container (uid 0, no CAP_NET_RAW). Drives the
    REAL compiled graph. The single authoritative nmap path must inject
    ``--unprivileged -Pn -sT`` so the FIRST scan succeeds and a service node is
    produced — instead of the demonstrated failure where every scan hit
    ``Couldn't open a raw socket`` and recon dead-ended. Fails the gate if:

    - any nmap invocation reached the backend WITHOUT ``--unprivileged``
      (i.e. the backend ever saw a raw-socket EPERM);
    - a ``raw_socket_terminal`` disposition was recorded;
    - recon produced no ``service`` node.
    """
    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState
    from apex_host.llm.router import FakeModelRouter
    from apex_host.orchestration.builder import build_apex_graph
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.tools.registry import ToolRegistry

    api = _make_api()
    config = ApexConfig(
        target=_TARGET, dry_run=True, max_turns=5, tool_backend="remote",
        allowed_tools=["nmap", "nc"], use_llm=False,
        max_llm_calls_per_run=10, max_llm_calls_per_phase=3,
    )
    backend = _UnprivilegedNmapBackend()
    budget = LLMBudgetTracker(max_per_run=10, max_per_phase=3)
    registry = ToolRegistry.from_config(config)
    graph = build_apex_graph(
        api, registry, config,
        model_router=FakeModelRouter(), budget_tracker=budget, tool_backend=backend,
    )
    initial: ApexGraphState = {
        "run_id": "release-gate-unpriv-nmap", "target": _TARGET, "phase": "recon",
        "goal": f"Begin engagement against {_TARGET}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [], "repair_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "", "privilege_state": "", "privilege_summary": {},
        "opportunity_ids": [], "attempted_opportunities": [],
        "enumeration_complete": False, "web_session_state": {},
        "workflow_summary": {}, "phase_selection": {}, "learning_summary": {},
        "task_latency_log": [], "objective_status": "", "objective_summary": {},
        "direct_file_read_log": [], "bounded_command_log": [],
        "capability_discovery_log": [], "execution_diagnostics": [],
    }
    final_state: ApexGraphState = await graph.ainvoke(initial)

    problems: list[str] = []
    nmap_calls = [args for (tool, args) in backend.calls if tool == "nmap"]
    if not nmap_calls:
        problems.append("no nmap scan ever reached the backend")
    for args in nmap_calls:
        if "--unprivileged" not in args or "-Pn" not in args or "-sT" not in args:
            problems.append(f"nmap reached the unprivileged backend without --unprivileged -Pn -sT: {args}")
    if backend.raw_socket_failures:
        problems.append(f"backend saw {backend.raw_socket_failures} raw-socket EPERM failure(s)")
    if any(str(d.get("disposition")) == "raw_socket_terminal" for d in final_state.get("duplicate_actions") or []):
        problems.append("recon dead-ended on a raw_socket_terminal disposition")

    subgraph = await api.get_subgraph(_ANCHOR, depth=5)
    if "service" not in {n.type for n in subgraph.nodes}:
        problems.append("connect scan produced no service node (recon dead-ended)")

    if problems:
        return ScenarioResult("unprivileged_backend_completes_connect_scan", False, "; ".join(problems))
    return ScenarioResult(
        "unprivileged_backend_completes_connect_scan", True,
        f"unprivileged backend completed a connect scan: {len(nmap_calls)} "
        f"--unprivileged -Pn -sT scan(s), 0 raw-socket failures, service node created",
    )


async def scenario_curl_only_web_discovery() -> ScenarioResult:
    """15. A live HTTP endpoint proven by curl (zero nmap services) counts.

    Reproduces the demonstrated gap: `curl http://target/` succeeded with a real
    nginx response and an endpoint node was created, yet the engagement died in
    recon "no services discovered" with web_evidence_complete=false. Drives the
    REAL CommandParser + MemoryAPI (Invariant 1: deltas only) + GlobalPlanner.
    Fails the gate if the successful fetch does not produce a service node, if
    the fetched endpoint is not counted as web content, or if recon still
    terminates "no services discovered" with a service present.
    """
    from memfabric.types import RawObservation

    from apex_host.parsers.command_parser import CommandParser
    from apex_host.planners.global_planner import GlobalPlanner
    from apex_host.planners.phase_gates import web_evidence_status
    from apex_host.types import ApexPhase

    api = _make_api()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})

    # A real nginx 301 HTML body (what `curl http://target/` returns).
    body = (
        "<html><head><title>301 Moved Permanently</title></head><body>"
        "<center><h1>301 Moved Permanently</h1></center><hr><center>nginx</center>"
        "</body></html>"
    )
    parsed = CommandParser().parse_curl_body(
        RawObservation(raw=body, metadata={"source": "curl_body", "target": f"http://{_TARGET}/"})
    )
    # All writes go through MemoryAPI (never the store directly).
    await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)

    subgraph = await api.get_subgraph(_ANCHOR, depth=5)
    node_types = {n.type for n in subgraph.nodes}

    problems: list[str] = []
    if "service" not in node_types:
        problems.append("successful curl fetch produced no service node")
    if not any(n.type == "endpoint" and n.props.get("fetched") is True for n in subgraph.nodes):
        problems.append("fetched endpoint not marked fetched")
    # Only recorded on a real HTTP response — never fabricated.
    svc = next((n for n in subgraph.nodes if n.type == "service"), None)
    if svc is not None and svc.props.get("service") != "http":
        problems.append(f"service node is not http: {svc.props.get('service')!r}")

    if not web_evidence_status(subgraph).complete:
        problems.append("fetched HTTP endpoint not counted as web content")

    # Recon budget exhausted with the curl-proven service must NOT die
    # "no services discovered"; it advances toward web.
    gp = GlobalPlanner(max_turns=20, phase_budgets={"recon": 1})
    gp.record_turn(ApexPhase.recon)
    phase = gp.decide_phase(
        node_types_seen=node_types, turn_count=2, current_phase=ApexPhase.recon.value,
        has_web_capability=True, has_credential_hypothesis=False, web_evidence_complete=False,
    )
    if phase == ApexPhase.done:
        problems.append("recon still terminated 'no services discovered' with a curl service present")

    if problems:
        return ScenarioResult("curl_only_web_discovery", False, "; ".join(problems))
    return ScenarioResult(
        "curl_only_web_discovery", True,
        "curl fetch recorded a service + fetched endpoint; counted as web content; "
        f"recon advanced to {phase.value} instead of dead-ending",
    )


async def scenario_vhost_redirect_web_discovery() -> ScenarioResult:
    """16. A name-based vhost discovered from a 301 unblocks web discovery.

    Reproduces the demonstrated gap: recon finds :80, but `curl http://ip/`
    returns an empty 301 pointing at a NEW vhost the container cannot resolve,
    so the web agent was blind. Drives the REAL CommandParser + MemoryAPI
    (Invariant 1) + WebPlanner + PolicyAdvisor. Fails the gate if the redirect
    does not yield a vhost node, if the web planner does not re-fetch with a
    `--resolve` Host-aware curl, if policy blocks that pinned fetch, or if the
    vhost fetch does not discover the real app's content. The vhost is
    DISCOVERED from the redirect — never hardcoded.
    """
    from memfabric.types import EvidenceBundle, Goal, RawObservation

    from apex_host.config import ApexConfig
    from apex_host.parsers.command_parser import CommandParser
    from apex_host.planners.phase_gates import web_evidence_status
    from apex_host.planners.web_planner import WebPlanner
    from apex_host.policy import PolicyAdvisor
    from apex_host.policy.policy_loader import load_policy
    from apex_host.tools.registry import ToolRegistry

    _VHOST = "app.example.htb"  # a value that only appears in the fake redirect
    api = _make_api()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(api, f"service:{_TARGET}:80/tcp", "service",
                     {"port": "80", "proto": "tcp", "state": "open", "service": "http"})
    await _seed_edge(api, _ANCHOR, f"service:{_TARGET}:80/tcp", "exposes")

    parser = CommandParser()
    problems: list[str] = []

    # 1. `curl -s -I` the bare IP → a 301 pointing at the vhost. Route it through
    #    the REAL parser router (parse_single_result), NOT parser.parse directly,
    #    AND with parser="banner" — the exact mislabel a live LLM plan produced
    #    (§28.11). Faithfulness is the whole point: the previous version hand-fed
    #    parser.parse(source="curl"), forcing the header path, so it passed while
    #    the live engagement (which mislabeled the HEAD curl as parser="banner")
    #    routed to BannerParser and produced NO vhost node. This step now fails
    #    the gate if that routing regresses.
    from typing import cast

    from apex_host.graph_state import ApexGraphState
    from apex_host.orchestration.parsing_node import parse_single_result

    ip_301 = (
        f"HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\n"
        f"Location: http://{_VHOST}/\r\nContent-Length: 162\r\n"
    )
    p1, _p1_src = parse_single_result(
        {
            "tool": "curl", "parser": "banner",  # the live mislabel
            "args": ["-s", "-I", f"http://{_TARGET}"],
            "target": f"http://{_TARGET}", "stdout": ip_301,
        },
        cast("ApexGraphState", {"target": _TARGET}),  # only state["target"] is read
    )
    await api.apply_deltas(nodes=p1.node_deltas, edges=p1.edge_deltas)
    subgraph = await api.get_subgraph(_ANCHOR, depth=5)
    vhost_nodes = [n for n in subgraph.nodes if n.type == "vhost"]
    if not vhost_nodes:
        problems.append("301 redirect to a new host produced no vhost node")
    elif vhost_nodes[0].props.get("hostname") != _VHOST:
        problems.append(f"vhost hostname wrong: {vhost_nodes[0].props.get('hostname')!r}")
    # The redirect stub + vhost node must NOT complete the web phase — the
    # real content is behind the vhost, so a follow-up fetch is required (§28.8).
    if web_evidence_status(subgraph).complete:
        problems.append("redirect-stub endpoint / bare vhost wrongly marked web complete")

    # 2. The web planner MUST re-fetch with a --resolve -L Host-aware curl — and
    # it must do so even with the LLM enabled (the LLM re-emits a bare-IP curl
    # that only returns the known stub; the deterministic vhost override wins).
    config = ApexConfig(target=_TARGET, dry_run=True, allowed_tools=["curl"])
    goal = Goal(id="rg-vhost", description="web", phase="web", anchor_node=_ANCHOR)
    empty = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])

    class _BareIPLLM:  # a valid LLM plan that ignores the vhost (what the live LLM did)
        def invoke(self, messages: Any) -> Any:
            import json as _json

            class _R:
                content = _json.dumps({
                    "reasoning": "probe the ip", "confidence": 0.9,
                    "selected_tasks": [{
                        "tool": "curl", "args": ["-s", "-I", f"http://{_TARGET}"],
                        "parser": "command", "executor_domain": "web",
                        "target": f"http://{_TARGET}", "rationale": "head probe",
                    }],
                    "rejected_tasks": [], "stop_reason": None, "next_phase": None,
                })
            return _R()

    class _Router:
        def planner_llm(self) -> Any: return _BareIPLLM()
        def executor_llm(self) -> Any: return None
        def parser_llm(self) -> Any: return None
        def reflector_llm(self) -> Any: return None

    planner = WebPlanner(_TARGET, ToolRegistry.from_config(config), model_router=_Router(), allowed_tools=["curl"])
    tasks = await planner.plan(goal, subgraph, empty)
    if not isinstance(tasks, list) or not tasks:
        problems.append("web planner produced no vhost re-fetch task")
        return ScenarioResult("vhost_redirect_web_discovery", False, "; ".join(problems))
    head = next((t for t in tasks if t.params.get("parser") == "command"), None)
    if head is None:
        problems.append("web planner produced no HEAD probe task")
    else:
        args = head.params["args"]
        if "--resolve" not in args or _VHOST not in " ".join(args):
            problems.append(f"web planner did not issue a --resolve vhost curl (LLM bare-IP won): {args}")
        if "-L" not in args:
            problems.append("vhost fetch does not follow redirects (-L) to load the real homepage")
        if f"http://{_TARGET}" in args:
            problems.append("web planner re-emitted the bare-IP stub fetch")

    # 3. Policy authorizes the pinned vhost fetch (never blocks it).
    advisor = PolicyAdvisor(load_policy(config), config)
    empty_ev = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    if head is not None:
        decision = advisor.review_task(head, "web", empty_ev, config)
        if not decision.is_approved:
            problems.append(f"policy blocked the pinned vhost fetch: {decision.rule_name}")

    # 4. The vhost fetch discovers the real app's content (a form login page).
    # host_ip pins the endpoints to the authorized host node (as parsing_node
    # does in production) so the deltas apply without a dangling edge.
    vhost_body = (
        f"<!DOCTYPE html><html><head><title>{_VHOST} — Login</title></head>"
        "<body><form action=\"/login\"><input name=\"user\"></form>"
        "<a href=\"/dashboard\">Dashboard</a></body></html>"
    )
    p2 = parser.parse_curl_body(
        RawObservation(
            raw=vhost_body,
            metadata={"source": "curl_body", "target": f"http://{_VHOST}", "host_ip": _TARGET},
        )
    )
    await api.apply_deltas(nodes=p2.node_deltas, edges=p2.edge_deltas)
    subgraph2 = await api.get_subgraph(_ANCHOR, depth=6)
    vhost_endpoints = [
        n for n in subgraph2.nodes
        if n.type == "endpoint" and _VHOST in str(n.props.get("url", ""))
    ]
    if not vhost_endpoints:
        problems.append("vhost fetch discovered no endpoint under the vhost URL")
    # AFTER the vhost homepage is fetched the web phase has moved off the stub —
    # it is either complete OR still PRODUCTIVE (a linked page like /dashboard
    # remains to fetch, §28.24) — never stuck with no content (WEB_EVIDENCE_NONE).
    from apex_host.planners.phase_gates import WEB_EVIDENCE_NONE
    if web_evidence_status(subgraph2).reason == WEB_EVIDENCE_NONE:
        problems.append("web phase stuck with no content after fetching the vhost app content")

    if problems:
        return ScenarioResult("vhost_redirect_web_discovery", False, "; ".join(problems))
    return ScenarioResult(
        "vhost_redirect_web_discovery", True,
        f"301 revealed vhost {_VHOST}; stub did NOT complete web; the selected next web "
        f"action was the --resolve -L vhost fetch (LLM bare-IP overridden); the vhost "
        f"fetch discovered real content — {len(vhost_endpoints)} vhost endpoint(s)",
    )


async def scenario_web_incomplete_not_goal_completed() -> ScenarioResult:
    """17. A web phase that discovered nothing must NOT report goal_completed.

    Reproduces the demonstrated bug: the web phase ran, found 0 forms / 0
    opportunities, no credentials were configured, turns/LLM budget remained —
    and the engagement declared outcome="goal_completed" ("organic completion").
    Drives the REAL compiled graph (dry-run, FakeModelRouter — no LLM calls) with
    a web service + a fetched-but-empty endpoint seeded. Fails the gate if the
    engagement reports goal_completed, reports success, or exits 0 without a
    verified user flag.
    """
    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState
    from apex_host.llm.router import FakeModelRouter
    from apex_host.orchestration.builder import build_apex_graph
    from apex_host.orchestration.outcome import EngagementOutcome, exit_code_for
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.tools.registry import ToolRegistry

    api = _make_api()

    async def _seed(node_id: str, node_type: str, props: dict[str, Any]) -> None:
        await _seed_node(api, node_id, node_type, props)

    await _seed(_ANCHOR, "host", {"ip": _TARGET})
    await _seed(f"service:{_TARGET}:80/tcp", "service",
                {"port": "80", "proto": "tcp", "state": "open", "service": "http"})
    await _seed(f"endpoint:http://{_TARGET}", "endpoint",
                {"url": f"http://{_TARGET}", "status": "301", "fetched": True})
    await _seed_edge(api, _ANCHOR, f"service:{_TARGET}:80/tcp", "exposes")
    await _seed_edge(api, _ANCHOR, f"endpoint:http://{_TARGET}", "exposes")

    config = ApexConfig(
        target=_TARGET, dry_run=True, max_turns=6, tool_backend="dry-run",
        allowed_tools=["nmap", "curl", "nc"], use_llm=False,
        max_llm_calls_per_run=10, max_llm_calls_per_phase=3,
    )
    budget = LLMBudgetTracker(max_per_run=10, max_per_phase=3)
    registry = ToolRegistry.from_config(config)
    graph = build_apex_graph(
        api, registry, config, model_router=FakeModelRouter(), budget_tracker=budget,
    )
    initial: ApexGraphState = {
        "run_id": "release-gate-web-incomplete", "target": _TARGET, "phase": "web",
        "goal": f"Web discovery against {_TARGET}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [], "repair_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "", "privilege_state": "", "privilege_summary": {},
        "opportunity_ids": [], "attempted_opportunities": [],
        "enumeration_complete": False, "web_session_state": {},
        "workflow_summary": {}, "phase_selection": {}, "learning_summary": {},
        "task_latency_log": [], "objective_status": "", "objective_summary": {},
        "direct_file_read_log": [], "bounded_command_log": [],
        "capability_discovery_log": [], "execution_diagnostics": [],
    }
    final_state: ApexGraphState = await graph.ainvoke(initial)

    problems: list[str] = []
    outcome = str(final_state.get("outcome") or "")
    if outcome == EngagementOutcome.goal_completed.value:
        problems.append("web phase with no evidence reported goal_completed")
    if outcome == EngagementOutcome.user_flag_verified.value:
        problems.append("fabricated success without a verified user flag")
    if not final_state.get("completed"):
        problems.append("engagement did not terminate")
    if outcome:
        if exit_code_for(EngagementOutcome(outcome)) == 0:
            problems.append(f"non-success outcome {outcome!r} mapped to exit code 0")
    else:
        problems.append("no terminal outcome recorded")

    if problems:
        return ScenarioResult("web_incomplete_not_goal_completed", False, "; ".join(problems))
    return ScenarioResult(
        "web_incomplete_not_goal_completed", True,
        f"web phase with no evidence terminated honestly as {outcome!r} "
        "(never goal_completed, never success)",
    )


class _TimeoutThenEscalateNmapBackend:
    """A synthetic ``ToolBackend`` modelling the demonstrated regression: the
    broad ``--top-ports`` discovery scan exits 0 but times out with 0 open
    ports, while the escalated targeted ``-p <common> -sV`` scan completes and
    finds a port. Never a real subprocess."""

    name = "fake-timeout-escalate"

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    async def execute(
        self, tool: str, arguments: list[str], *,
        timeout_seconds: float | None = None, stdin: str | None = None,
    ) -> Any:
        from apex_host.types import ToolCommand, ToolResult

        self.calls.append((tool, list(arguments)))
        cmd = ToolCommand(tool=tool, args=list(arguments), timeout_seconds=int(timeout_seconds or 30))
        if tool == "nmap" and "--top-ports" in arguments and "-sV" not in arguments:
            # Broad discovery scan → times out, 0 ports (rc 0).
            return ToolResult(
                command=cmd,
                stdout=f"Nmap scan report for {_TARGET}\nSkipping host {_TARGET} due to host timeout\n",
                stderr="", returncode=0, duration_seconds=80.0, dry_run=True,
                backend=self.name, error=None,
            )
        stdout = ""
        if tool == "nmap":  # the escalated -p <common> -sV scan → finds a port
            stdout = (
                f"Nmap scan report for {_TARGET}\n"
                "PORT   STATE SERVICE VERSION\n"
                "22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu\n"
            )
        return ToolResult(
            command=cmd, stdout=stdout, stderr="", returncode=0,
            duration_seconds=0.014, dry_run=True, backend=self.name, error=None,
        )


async def scenario_incomplete_scan_escalates_not_stall() -> ScenarioResult:
    """18. A timed-out discovery scan escalates instead of dedup-stalling.

    Reproduces the demonstrated regression: the top-ports discovery scan hit its
    host-timeout and returned 0 ports but was classified executed_success, so the
    planner re-proposed the identical scan 3x → duplicate_task_stall. Drives the
    REAL compiled graph. Fails the gate if: any nmap scan is classified a bare
    success despite the host-timeout marker; recon terminates
    duplicate_task_stall; the escalated targeted -p <common> -sV scan never runs;
    or recon produces no service node.
    """
    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState
    from apex_host.llm.router import FakeModelRouter
    from apex_host.orchestration.builder import build_apex_graph
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.tools.registry import ToolRegistry

    api = _make_api()
    config = ApexConfig(
        target=_TARGET, dry_run=True, max_turns=8, tool_backend="remote",
        allowed_tools=["nmap", "nc"], use_llm=False,
        max_llm_calls_per_run=10, max_llm_calls_per_phase=3,
    )
    backend = _TimeoutThenEscalateNmapBackend()
    budget = LLMBudgetTracker(max_per_run=10, max_per_phase=3)
    registry = ToolRegistry.from_config(config)
    graph = build_apex_graph(
        api, registry, config, model_router=FakeModelRouter(),
        budget_tracker=budget, tool_backend=backend,
    )
    initial: ApexGraphState = {
        "run_id": "release-gate-incomplete-scan", "target": _TARGET, "phase": "recon",
        "goal": f"Begin engagement against {_TARGET}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [], "repair_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "", "privilege_state": "", "privilege_summary": {},
        "opportunity_ids": [], "attempted_opportunities": [],
        "enumeration_complete": False, "web_session_state": {},
        "workflow_summary": {}, "phase_selection": {}, "learning_summary": {},
        "task_latency_log": [], "objective_status": "", "objective_summary": {},
        "direct_file_read_log": [], "bounded_command_log": [],
        "capability_discovery_log": [], "execution_diagnostics": [],
    }
    final_state: ApexGraphState = await graph.ainvoke(initial)

    problems: list[str] = []
    # The escalated targeted -p <common> -sV scan must have run.
    nmap_calls = [args for (tool, args) in backend.calls if tool == "nmap"]
    if not any("-sV" in args and "-p" in args for args in nmap_calls):
        problems.append(f"escalated -p <common> -sV scan never ran: {nmap_calls}")
    if str(final_state.get("outcome") or "") == "duplicate_task_stall":
        problems.append("recon terminated in duplicate_task_stall instead of escalating")

    subgraph = await api.get_subgraph(_ANCHOR, depth=5)
    if "service" not in {n.type for n in subgraph.nodes}:
        problems.append("escalated scan produced no service node (recon did not recover)")

    if problems:
        return ScenarioResult("incomplete_scan_escalates_not_stall", False, "; ".join(problems))
    return ScenarioResult(
        "incomplete_scan_escalates_not_stall", True,
        "timed-out discovery scan escalated to a targeted -p <common> -sV scan that found a "
        "service — recon recovered instead of dedup-stalling",
    )


async def scenario_web_content_enumeration() -> ScenarioResult:
    """19. A discovered vhost enables bounded content enumeration whose hits
    become actionable endpoint nodes.

    Reproduces the demonstrated gap: the web phase can fetch the real vhost but
    cannot DISCOVER paths it wasn't handed (loaded the homepage, stalled with no
    /api). Drives the REAL WebPlanner + PolicyAdvisor + safety.check_command +
    parse_single_result (the router) + MemoryAPI (Invariant 1). Fails the gate if
    the enumeration is unbounded, off-scope, unsafe, or if a ffuf hit does not
    become an EKG endpoint node under the authorized host. DISCOVERY ONLY.
    """
    from typing import cast

    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState
    from apex_host.orchestration.parsing_node import parse_single_result
    from apex_host.planners.web_planner import _WebDeterministic
    from apex_host.policy import PolicyAdvisor
    from apex_host.policy.policy_loader import load_policy
    from apex_host.tools.registry import ToolRegistry
    from apex_host.tools.safety import check_command
    from apex_host.types import ToolCommand
    from memfabric.types import EvidenceBundle, Goal

    _VHOST = "app.example.htb"
    problems: list[str] = []
    api = _make_api()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(api, f"service:{_TARGET}:80/tcp", "service",
                     {"port": "80", "proto": "tcp", "state": "open", "service": "http"})
    await _seed_edge(api, _ANCHOR, f"service:{_TARGET}:80/tcp", "exposes")
    await _seed_node(api, f"vhost:{_TARGET}:{_VHOST}", "vhost",
                     {"hostname": _VHOST, "ip": _TARGET})
    # host --exposes--> vhost so the vhost is reachable in the host-anchored
    # subgraph traversal (as CommandParser records it, §28.8).
    await _seed_edge(api, _ANCHOR, f"vhost:{_TARGET}:{_VHOST}", "exposes")

    # Wordlist fuzzing requires explicit operator approval (§19) on top of scope.
    config = ApexConfig(
        target=_TARGET, dry_run=True, allowed_tools=["curl", "ffuf"],
        web_wordlist_path="/seclists/common.txt", allow_password_lists=True,
        web_enum_threads=15, web_enum_max_seconds=30,
    )
    subgraph = await api.get_subgraph(_ANCHOR, depth=4)
    goal = Goal(id="rg-enum", description="web", phase="web", anchor_node=_ANCHOR)
    empty = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])

    planner = _WebDeterministic(
        _TARGET, ToolRegistry.from_config(config),
        web_wordlist_path=config.web_wordlist_path,
        web_enum_threads=config.web_enum_threads,
        web_enum_max_seconds=config.web_enum_max_seconds,
    )
    tasks = await planner.plan(goal, subgraph, empty)
    enum = [t for t in tasks if isinstance(tasks, list)
            and t.params["tool"] in ("ffuf", "gobuster")] if isinstance(tasks, list) else []
    if len(enum) != 1:
        problems.append(f"expected exactly one bounded enumeration task, got {len(enum)}")
        return ScenarioResult("web_content_enumeration", False, "; ".join(problems))
    task = enum[0]
    args = task.params["args"]
    # Bounded on BOTH axes + wordlist + vhost Host header + authorized IP target.
    if "-t" not in args or "15" not in args:
        problems.append(f"enumeration missing concurrency cap: {args}")
    if "-maxtime" not in args or "30" not in args:
        problems.append(f"enumeration missing hard time cap: {args}")
    if "/seclists/common.txt" not in args:
        problems.append("enumeration wordlist not present in command")
    if "-H" not in args or f"Host: {_VHOST}" not in args:
        problems.append("enumeration does not carry the vhost Host header")
    if task.params["target"] != f"http://{_TARGET}":
        problems.append(f"enumeration target is not the authorized IP: {task.params['target']}")

    # PolicyAdvisor approves the authorized-IP enumeration (wordlists allowed).
    advisor = PolicyAdvisor(load_policy(config), config)
    decision = advisor.review_task(task, "web", empty, config)
    if not decision.is_approved:
        problems.append(f"policy blocked the bounded enumeration: {decision.rule_name}")

    # safety.py passes the emitted command (no shell metacharacters).
    try:
        check_command(ToolCommand(tool="ffuf", args=args), config)
    except ValueError as exc:  # pragma: no cover - defensive
        problems.append(f"safety.py rejected the enumeration command: {exc}")

    # A ffuf hit routed through parse_single_result becomes an /api endpoint
    # node under the authorized host (no dangling edge → no rollback).
    ffuf_out = ("api                     [Status: 200, Size: 12]\n"
                "admin                   [Status: 403, Size: 0]")
    obs, _src = parse_single_result(
        {"tool": "ffuf", "parser": "ffuf", "args": args,
         "target": task.params["target"], "stdout": ffuf_out},
        cast("ApexGraphState", {"target": _TARGET}),
    )
    await api.apply_deltas(nodes=obs.node_deltas, edges=obs.edge_deltas)
    subgraph2 = await api.get_subgraph(_ANCHOR, depth=5)
    api_eps = [
        n for n in subgraph2.nodes
        if n.type == "endpoint" and n.props.get("path") == "api"
    ]
    if not api_eps:
        problems.append("discovered /api endpoint did not become an EKG node")
    elif api_eps[0].source != "ffuf":
        problems.append(f"endpoint provenance wrong: {api_eps[0].source!r}")

    # Once per phase: with a ffuf endpoint present, no new enumeration is emitted.
    tasks2 = await planner.plan(goal, subgraph2, empty)
    if isinstance(tasks2, list) and any(
        t.params["tool"] in ("ffuf", "gobuster") for t in tasks2
    ):
        problems.append("enumeration re-ran after a prior hit (not once-per-phase)")

    if problems:
        return ScenarioResult("web_content_enumeration", False, "; ".join(problems))
    return ScenarioResult(
        "web_content_enumeration", True,
        f"vhost {_VHOST} → one bounded ffuf (-t 15, --maxtime 30, -H Host, IP target); "
        "policy-approved; safety-passed; /api hit became an EKG endpoint node; "
        "enumeration is once-per-phase",
    )


async def scenario_web_endpoint_fetch_loop() -> ScenarioResult:
    """20. Discovered (enumerated) endpoints get FETCHED, closing the web loop.

    Reproduces the demonstrated stall: enumeration records /api endpoint nodes,
    but the web planner re-fetched only the homepage and stalled. Drives the REAL
    WebPlanner + PolicyAdvisor + safety + parse_single_result (router) + MemoryAPI
    (Invariant 1). Fails the gate if the planner IGNORES the discovered endpoint
    (no --resolve fetch), if the phase completes with a high-signal endpoint
    unfetched, or if the fetched result does not clear the pending set.
    DISCOVERY ONLY — fetch and record.
    """
    from typing import cast

    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState
    from apex_host.orchestration.parsing_node import parse_single_result
    from apex_host.planners.phase_gates import web_evidence_status
    from apex_host.planners.web_opportunities import pending_enumerated_endpoints
    from apex_host.planners.web_planner import _WebDeterministic
    from apex_host.policy import PolicyAdvisor
    from apex_host.policy.policy_loader import load_policy
    from apex_host.tools.registry import ToolRegistry
    from apex_host.tools.safety import check_command
    from apex_host.types import ToolCommand
    from memfabric.types import EvidenceBundle, Goal

    _VHOST = "app.example.htb"
    problems: list[str] = []
    api = _make_api()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(api, f"service:{_TARGET}:80/tcp", "service",
                     {"port": "80", "proto": "tcp", "state": "open", "service": "http"})
    await _seed_edge(api, _ANCHOR, f"service:{_TARGET}:80/tcp", "exposes")
    await _seed_node(api, f"vhost:{_TARGET}:{_VHOST}", "vhost",
                     {"hostname": _VHOST, "ip": _TARGET})
    await _seed_edge(api, _ANCHOR, f"vhost:{_TARGET}:{_VHOST}", "exposes")
    # The vhost homepage was already fetched.
    home_url = f"http://{_VHOST}"
    await _seed_node(api, f"endpoint:{home_url}", "endpoint",
                     {"url": home_url, "status": "200", "fetched": True})
    await _seed_edge(api, _ANCHOR, f"endpoint:{home_url}", "exposes")
    # Enumeration discovered /api (source=ffuf, IP-scoped, not yet fetched) and a
    # low-signal 404.
    api_url = f"http://{_TARGET}/api"
    await _seed_node(api, f"endpoint:{api_url}", "endpoint",
                     {"url": api_url, "path": "api", "status": "200"}, source="ffuf")
    await _seed_edge(api, _ANCHOR, f"endpoint:{api_url}", "exposes")
    gone_url = f"http://{_TARGET}/gone"
    await _seed_node(api, f"endpoint:{gone_url}", "endpoint",
                     {"url": gone_url, "path": "gone", "status": "404"}, source="ffuf")
    await _seed_edge(api, _ANCHOR, f"endpoint:{gone_url}", "exposes")

    config = ApexConfig(target=_TARGET, dry_run=True, allowed_tools=["curl"])
    subgraph = await api.get_subgraph(_ANCHOR, depth=5)
    goal = Goal(id="rg-fetch", description="web", phase="web", anchor_node=_ANCHOR)
    empty = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])

    # The gate must NOT be complete — /api is a discovered, unfetched, high-signal
    # endpoint (a productive fetch remains).
    if web_evidence_status(subgraph).complete:
        problems.append("web marked complete while /api was still unfetched")

    planner = _WebDeterministic(_TARGET, ToolRegistry.from_config(config))
    tasks = await planner.plan(goal, subgraph, empty)
    if not isinstance(tasks, list):
        return ScenarioResult("web_endpoint_fetch_loop", False, "planner abandoned")
    api_fetches = [t for t in tasks if t.params.get("target") == f"http://{_VHOST}/api"]
    if not api_fetches:
        problems.append("planner IGNORED the discovered /api endpoint (no fetch emitted)")
        return ScenarioResult("web_endpoint_fetch_loop", False, "; ".join(problems))
    head = next((t for t in api_fetches if t.params.get("parser") == "command"), None)
    if head is None:
        problems.append("no HEAD fetch of the discovered endpoint")
        return ScenarioResult("web_endpoint_fetch_loop", False, "; ".join(problems))
    args = head.params["args"]
    if "--resolve" not in args or f"{_VHOST}:80:{_TARGET}" not in args:
        problems.append(f"discovered-endpoint fetch is not --resolve-pinned: {args}")
    if "-L" not in args:
        problems.append("discovered-endpoint fetch does not follow redirects (-L)")
    if any(t.params.get("target") == f"http://{_TARGET}/api" for t in tasks):
        problems.append("planner emitted a bare-IP fetch of /api instead of the vhost")
    if any(t.params.get("target", "").endswith("/gone") for t in tasks):
        problems.append("planner fetched a low-signal 404 endpoint")

    # Policy + safety on the emitted fetch.
    advisor = PolicyAdvisor(load_policy(config), config)
    if not advisor.review_task(head, "web", empty, config).is_approved:
        problems.append("policy blocked the --resolve-pinned discovered-endpoint fetch")
    try:
        check_command(ToolCommand(tool="curl", args=args), config)
    except ValueError as exc:  # pragma: no cover - defensive
        problems.append(f"safety.py rejected the fetch: {exc}")

    # Route the HEAD /api result through the real router → apply deltas → /api is
    # now fetched → pending cleared → gate completes.
    header = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\n"
    obs, _src = parse_single_result(
        {"tool": "curl", "parser": "command", "args": args,
         "target": head.params["target"], "stdout": header},
        cast("ApexGraphState", {"target": _TARGET}),
    )
    await api.apply_deltas(nodes=obs.node_deltas, edges=obs.edge_deltas)
    subgraph2 = await api.get_subgraph(_ANCHOR, depth=6)
    if pending_enumerated_endpoints(subgraph2):
        problems.append("/api still pending after it was fetched (loop would not terminate)")
    if not web_evidence_status(subgraph2).complete:
        problems.append("web did not complete after discovered endpoints were fetched")

    if problems:
        return ScenarioResult("web_endpoint_fetch_loop", False, "; ".join(problems))
    return ScenarioResult(
        "web_endpoint_fetch_loop", True,
        f"discovered /api fetched via --resolve -L http://{_VHOST}/api (not bare-IP, "
        "not homepage); 404 skipped; policy-approved; safety-passed; the fetched "
        "result cleared the pending set and the web phase then completed",
    )


async def scenario_web_api_surface_discovery() -> ScenarioResult:
    """§28.22 — bounded API-surface DISCOVERY. With the homepage known, the web
    phase enumerates an API surface it was NOT linked to: an /api/v1 endpoint
    becomes an EKG node, is GET-fetched via the Host-aware --resolve path, and its
    JSON structure is recorded (top-level keys only, never values). A discovered
    GraphQL endpoint is introspected read-only into an api_schema node. Drives the
    REAL WebPlanner + PolicyAdvisor + safety.check_command + parse_single_result
    (router) + MemoryAPI (Invariant 1). Fails against pre-§28.22 code (no API
    discovery). DISCOVERY ONLY — read/map, never forge a request."""
    import json as _json
    from typing import cast
    from urllib.parse import urlsplit

    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState
    from apex_host.orchestration.parsing_node import parse_single_result
    from apex_host.planners.web_planner import _GRAPHQL_INTROSPECTION_BODY, _WebDeterministic
    from apex_host.policy import PolicyAdvisor
    from apex_host.policy.policy_loader import load_policy
    from apex_host.tools.registry import ToolRegistry
    from apex_host.tools.safety import check_command
    from apex_host.types import ToolCommand
    from memfabric.types import EvidenceBundle, Goal

    name = "web_api_surface_discovery"
    _VHOST = "app.example.htb"
    problems: list[str] = []
    api = _make_api()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(api, f"service:{_TARGET}:80/tcp", "service",
                     {"port": "80", "proto": "tcp", "state": "open", "service": "http"})
    await _seed_edge(api, _ANCHOR, f"service:{_TARGET}:80/tcp", "exposes")
    await _seed_node(api, f"vhost:{_TARGET}:{_VHOST}", "vhost", {"hostname": _VHOST, "ip": _TARGET})
    await _seed_edge(api, _ANCHOR, f"vhost:{_TARGET}:{_VHOST}", "exposes")
    home = f"http://{_VHOST}"
    await _seed_node(api, f"endpoint:{home}", "endpoint", {"url": home, "status": "200", "fetched": True})
    await _seed_edge(api, _ANCHOR, f"endpoint:{home}", "exposes")

    config = ApexConfig(
        target=_TARGET, dry_run=True, allowed_tools=["curl", "ffuf"],
        web_api_wordlist_path="/seclists/api.txt", allow_password_lists=True,
        web_enum_threads=10, web_enum_max_seconds=20)
    goal = Goal(id="rg-api", description="web", phase="web", anchor_node=_ANCHOR)
    empty = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    planner = _WebDeterministic(
        _TARGET, ToolRegistry.from_config(config),
        web_api_wordlist_path=config.web_api_wordlist_path,
        web_enum_threads=config.web_enum_threads, web_enum_max_seconds=config.web_enum_max_seconds)
    advisor = PolicyAdvisor(load_policy(config), config)

    # Turn 1 — fixed API/GraphQL root probes + the bounded API-wordlist scan.
    sub1 = await api.get_subgraph(_ANCHOR, depth=5)
    tasks1 = await planner.plan(goal, sub1, empty)
    if not isinstance(tasks1, list):
        return ScenarioResult(name, False, "planner abandoned turn 1")
    api_scan = [t for t in tasks1 if t.params.get("parser") == "ffuf_api"]
    if len(api_scan) != 1:
        return ScenarioResult(name, False, f"expected one bounded API scan, got {len(api_scan)}")
    a = api_scan[0].params["args"]
    if "-t" not in a or "-maxtime" not in a or "/seclists/api.txt" not in a:
        problems.append(f"API scan not bounded/wordlisted: {a}")
    if "-H" not in a or f"Host: {_VHOST}" not in a:
        problems.append("API scan missing vhost Host header")
    if api_scan[0].params["target"] != f"http://{_TARGET}":
        problems.append(f"API scan target not the authorized IP: {api_scan[0].params['target']}")
    if not advisor.review_task(api_scan[0], "web", empty, config).is_approved:
        problems.append("policy blocked the bounded API scan")
    try:
        check_command(ToolCommand(tool="ffuf", args=a), config)
    except ValueError as exc:
        problems.append(f"safety.py rejected the API scan: {exc}")
    probe_paths = {urlsplit(t.params["target"]).path for t in tasks1 if t.params.get("parser") == "command"}
    if "/api/v1" not in probe_paths or "/graphql" not in probe_paths:
        problems.append(f"fixed API/GraphQL root probes missing: {sorted(probe_paths)}")

    # §28.23 — the fixed /api/v1 root probe GETs the body through the vhost
    # --resolve -L path (NOT the bare-IP 301 stub / HEAD). Fails against the
    # pre-§28.23 code, whose probes hit the IP and were then gated off.
    api_v1_get = next((t for t in tasks1 if t.params.get("parser") == "curl_body"
                       and t.params["target"] == f"http://{_VHOST}/api/v1"), None)
    if api_v1_get is None:
        problems.append("no vhost /api/v1 GET body probe emitted (§28.23)")
    else:
        ga = api_v1_get.params["args"]
        if "--resolve" not in ga or f"{_VHOST}:80:{_TARGET}" not in ga or "-L" not in ga:
            problems.append(f"/api/v1 probe not --resolve -L pinned to the vhost: {ga}")
        else:
            # A real JSON body over the vhost maps its structure (keys only).
            jobs, _ = parse_single_result(
                {"tool": "curl", "parser": "curl_body", "args": ga, "target": api_v1_get.params["target"],
                 "stdout": '{"routes": ["/api/v1/user", "/api/v1/auth"], "secret": "do-not-store"}'},
                cast("ApexGraphState", {"target": _TARGET}))
            await api.apply_deltas(nodes=jobs.node_deltas, edges=jobs.edge_deltas)
            subj = await api.get_subgraph(_ANCHOR, depth=6)
            v1 = [n for n in subj.nodes if n.type == "endpoint"
                  and str(n.props.get("url", "")).rstrip("/").endswith("/api/v1")]
            if not any(n.props.get("content_kind") == "json" and "json_keys" in n.props for n in v1):
                problems.append("vhost /api/v1 JSON structure not recorded (§28.23)")
            if "do-not-store" in _json.dumps([n.props for n in subj.nodes], default=str):
                problems.append("a JSON VALUE leaked into the graph")

    # An API-wordlist hit routes through the REAL router into an endpoint node.
    obs, _ = parse_single_result(
        {"tool": "ffuf", "parser": "ffuf_api", "args": a, "target": api_scan[0].params["target"],
         "stdout": "api/v1/users            [Status: 200, Size: 40]"},
        cast("ApexGraphState", {"target": _TARGET}))
    await api.apply_deltas(nodes=obs.node_deltas, edges=obs.edge_deltas)
    sub2 = await api.get_subgraph(_ANCHOR, depth=6)
    api_ep = [n for n in sub2.nodes if n.type == "endpoint"
              and str(n.props.get("url", "")).endswith("/api/v1/users")]
    if not api_ep:
        return ScenarioResult(name, False, "discovered /api/v1/users did not become an EKG node")
    if api_ep[0].source != "ffuf_api":
        problems.append(f"API endpoint provenance wrong: {api_ep[0].source!r}")

    # Turn 2 — the discovered API endpoint is GET-fetched (--resolve).
    tasks2 = await planner.plan(goal, sub2, empty)
    if not isinstance(tasks2, list):
        return ScenarioResult(name, False, "planner abandoned turn 2")
    body = next((t for t in tasks2
                 if t.params.get("target") == f"http://{_VHOST}/api/v1/users"
                 and t.params.get("parser") == "curl_body"), None)
    if body is None:
        return ScenarioResult(name, False, "planner did not GET-fetch the discovered API endpoint")
    if "--resolve" not in body.params["args"]:
        problems.append("API endpoint fetch is not --resolve-pinned")

    # The JSON structure is recorded (keys only, never values).
    obs2, _ = parse_single_result(
        {"tool": "curl", "parser": "curl_body", "args": body.params["args"],
         "target": body.params["target"],
         "stdout": '{"users": [{"id": 1, "username": "supersecret"}], "count": 1}'},
        cast("ApexGraphState", {"target": _TARGET}))
    await api.apply_deltas(nodes=obs2.node_deltas, edges=obs2.edge_deltas)
    sub3 = await api.get_subgraph(_ANCHOR, depth=6)
    fetched_api = [n for n in sub3.nodes if n.type == "endpoint"
                   and str(n.props.get("url", "")).endswith("/api/v1/users")]
    if not any(n.props.get("content_kind") == "json" and "json_keys" in n.props for n in fetched_api):
        problems.append("API endpoint JSON structure (keys) was not recorded")
    if "supersecret" in _json.dumps([n.props for n in sub3.nodes], default=str):
        problems.append("a JSON VALUE leaked into the graph (structure-only violated)")

    # GraphQL — a discovered graphql endpoint is introspected read-only.
    gql = f"http://{_VHOST}/graphql"
    await _seed_node(api, f"endpoint:{gql}", "endpoint", {"url": gql, "status": "400", "fetched": True})
    await _seed_edge(api, _ANCHOR, f"endpoint:{gql}", "exposes")
    sub4 = await api.get_subgraph(_ANCHOR, depth=6)
    tasks3 = await planner.plan(goal, sub4, empty)
    gql_task = [t for t in tasks3 if t.params.get("parser") == "graphql"] if isinstance(tasks3, list) else []
    if not gql_task:
        problems.append("no read-only GraphQL introspection emitted for a discovered graphql endpoint")
    else:
        if _GRAPHQL_INTROSPECTION_BODY not in gql_task[0].params["args"]:
            problems.append("introspection did not use the fixed read-only query body")
        obs3, _ = parse_single_result(
            {"tool": "curl", "parser": "graphql", "args": gql_task[0].params["args"],
             "target": gql_task[0].params["target"],
             "stdout": '{"data":{"__schema":{"queryType":{"name":"Query"},'
                       '"types":[{"name":"User","fields":[{"name":"id"}]}]}}}'},
            cast("ApexGraphState", {"target": _TARGET}))
        await api.apply_deltas(nodes=obs3.node_deltas, edges=obs3.edge_deltas)
        sub5 = await api.get_subgraph(_ANCHOR, depth=7)
        if not any(n.type == "api_schema" for n in sub5.nodes):
            problems.append("GraphQL introspection did not record an api_schema node")

    if problems:
        return ScenarioResult(name, False, "; ".join(problems))
    return ScenarioResult(
        name, True,
        "bounded API-wordlist scan (-t, --maxtime, -H Host, IP target, policy+safety OK) + fixed "
        "/api/v1 & /graphql root probes → /api/v1/users endpoint → --resolve GET → JSON structure "
        "recorded (keys only, no values); GraphQL endpoint → read-only introspection → api_schema node",
    )


async def scenario_web_js_api_discovery() -> ScenarioResult:
    """§28.24 — linked-JS → API discovery. Homepage → discovers /invite → fetches
    /invite → its <script src> JS asset → fetches the JS → STATICALLY extracts a
    /api/v1/... reference (never executing the JS) → GET-fetches and JSON-maps it.
    Drives the REAL WebPlanner + PolicyAdvisor + safety.check_command +
    parse_single_result (router) + MemoryAPI (Invariant 1). Fails against
    pre-§28.24 code (JS never fetched/parsed). DISCOVERY ONLY — read/map."""
    import json as _json
    from typing import cast

    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState
    from apex_host.orchestration.parsing_node import parse_single_result
    from apex_host.planners.web_planner import _WebDeterministic
    from apex_host.policy import PolicyAdvisor
    from apex_host.policy.policy_loader import load_policy
    from apex_host.tools.registry import ToolRegistry
    from apex_host.tools.safety import check_command
    from apex_host.types import ToolCommand
    from memfabric.types import EvidenceBundle, Goal

    name = "web_js_api_discovery"
    _VHOST = "app.example.htb"
    problems: list[str] = []
    api = _make_api()
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(api, f"service:{_TARGET}:80/tcp", "service",
                     {"port": "80", "proto": "tcp", "state": "open", "service": "http"})
    await _seed_edge(api, _ANCHOR, f"service:{_TARGET}:80/tcp", "exposes")
    await _seed_node(api, f"vhost:{_TARGET}:{_VHOST}", "vhost", {"hostname": _VHOST, "ip": _TARGET})
    await _seed_edge(api, _ANCHOR, f"vhost:{_TARGET}:{_VHOST}", "exposes")
    home = f"http://{_VHOST}"
    await _seed_node(api, f"endpoint:{home}", "endpoint", {"url": home, "status": "200", "fetched": True})
    await _seed_edge(api, _ANCHOR, f"endpoint:{home}", "exposes")
    # The homepage linked /invite (a relative-link page, not yet fetched).
    inv = f"http://{_VHOST}/invite"
    await _seed_node(api, f"endpoint:{inv}", "endpoint", {"url": inv, "path": "/invite"}, source="curl_body")
    await _seed_edge(api, _ANCHOR, f"endpoint:{inv}", "exposes")

    config = ApexConfig(target=_TARGET, dry_run=True, allowed_tools=["curl"])
    goal = Goal(id="rg-js", description="web", phase="web", anchor_node=_ANCHOR)
    empty = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    planner = _WebDeterministic(_TARGET, ToolRegistry.from_config(config))
    advisor = PolicyAdvisor(load_policy(config), config)
    st = cast("ApexGraphState", {"target": _TARGET})

    async def _run(parser: str, target: str, stdout: str) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": parser, "args": ["-s", target], "target": target, "stdout": stdout}, st)
        await api.apply_deltas(nodes=obs.node_deltas, edges=obs.edge_deltas)

    # Turn 1 — the planner fetches the discovered /invite page (--resolve GET).
    sub1 = await api.get_subgraph(_ANCHOR, depth=6)
    tasks1 = await planner.plan(goal, sub1, empty)
    inv_body = next((t for t in tasks1 if isinstance(tasks1, list)
                     and t.params.get("parser") == "curl_body"
                     and t.params["target"] == f"http://{_VHOST}/invite"), None) if isinstance(tasks1, list) else None
    if inv_body is None:
        return ScenarioResult(name, False, "planner did not fetch the discovered /invite page")
    if "--resolve" not in inv_body.params["args"]:
        problems.append("/invite fetch not --resolve pinned")
    # /invite's HTML links its JS.
    await _run("curl_body", inv_body.params["target"],
               f'<!DOCTYPE html><html><head><title>{_VHOST}</title>'
               '<script src="/js/inviteapi.min.js"></script></head><body>invite</body></html>')
    sub2 = await api.get_subgraph(_ANCHOR, depth=6)
    js_assets = [n for n in sub2.nodes if n.type == "endpoint" and n.props.get("js_asset") is True]
    if not js_assets:
        return ScenarioResult(name, False, "/invite's <script src> did not become a JS asset node")
    # §28.25 — the root-absolute src on /invite must resolve to the HOST ROOT,
    # not the page directory (the pre-fix bug produced /invite/js/inviteapi.min.js
    # which 404s and yields no API extraction).
    js_urls = {str(n.props.get("url", "")) for n in js_assets}
    if f"http://{_VHOST}/js/inviteapi.min.js" not in js_urls:
        return ScenarioResult(
            name, False,
            f"JS asset URL not resolved to host root (got {sorted(js_urls)}, "
            f"expected http://{_VHOST}/js/inviteapi.min.js)")

    # Turn 2 — the planner fetches the JS asset (parser "js").
    tasks2 = await planner.plan(goal, sub2, empty)
    js_fetch = next((t for t in tasks2 if isinstance(tasks2, list)
                     and t.params.get("parser") == "js"), None) if isinstance(tasks2, list) else None
    if js_fetch is None:
        return ScenarioResult(name, False, "planner did not fetch the discovered JS asset")
    ja = js_fetch.params["args"]
    if "--resolve" not in ja or "-L" not in ja:
        problems.append("JS fetch not --resolve -L pinned")
    if not advisor.review_task(js_fetch, "web", empty, config).is_approved:
        problems.append("policy blocked the JS fetch")
    try:
        check_command(ToolCommand(tool="curl", args=ja), config)
    except ValueError as exc:
        problems.append(f"safety.py rejected the JS fetch: {exc}")
    # The JS statically references an API endpoint (never executed).
    await _run("js", js_fetch.params["target"],
               'fetch("/api/v1/invite/how/to/generate").then(r=>r.json());'
               'const ext="https://evil.com/api/steal";')  # cross-origin must be ignored
    sub3 = await api.get_subgraph(_ANCHOR, depth=7)
    api_eps = [n for n in sub3.nodes if n.type == "endpoint"
               and str(n.props.get("url", "")).endswith("/api/v1/invite/how/to/generate")]
    if not api_eps:
        return ScenarioResult(name, False, "JS-referenced /api/v1/... was not extracted as an endpoint")
    if api_eps[0].source != "js_analysis":
        problems.append(f"JS-discovered endpoint provenance wrong: {api_eps[0].source!r}")
    if any("steal" in str(n.props) or "evil.com" in str(n.props) for n in sub3.nodes):
        problems.append("a cross-origin API URL was extracted (scope violated)")

    # Turn 3 — the JS-discovered API endpoint is GET-fetched and JSON-mapped.
    tasks3 = await planner.plan(goal, sub3, empty)
    api_get = next((t for t in tasks3 if isinstance(tasks3, list)
                    and t.params.get("parser") == "curl_body"
                    and str(t.params.get("target", "")).endswith("/api/v1/invite/how/to/generate")),
                   None) if isinstance(tasks3, list) else None
    if api_get is None:
        return ScenarioResult(name, False, "planner did not GET the JS-discovered API endpoint")
    await _run("curl_body", api_get.params["target"],
               '{"code": "0", "data": {"code": "SEKRETCODE"}}')  # value must NOT be stored
    sub4 = await api.get_subgraph(_ANCHOR, depth=7)
    mapped = [n for n in sub4.nodes if n.type == "endpoint"
              and str(n.props.get("url", "")).endswith("/api/v1/invite/how/to/generate")]
    if not any(n.props.get("content_kind") == "json" and "json_keys" in n.props for n in mapped):
        problems.append("JS-discovered API endpoint's JSON structure was not recorded")
    if "SEKRETCODE" in _json.dumps([n.props for n in sub4.nodes], default=str):
        problems.append("a JSON VALUE leaked into the graph (structure-only violated)")

    if problems:
        return ScenarioResult(name, False, "; ".join(problems))
    return ScenarioResult(
        name, True,
        "homepage → /invite fetched (--resolve) → <script src> JS asset → JS GET-fetched + STATICALLY "
        "parsed (never executed) → /api/v1/invite/... extracted (cross-origin ignored) → --resolve GET "
        "→ JSON structure recorded (keys only, no values); policy+safety OK",
    )


class _ReconFtpFakeBackend:
    """A synthetic ``ToolBackend`` that makes recon DISCOVER an FTP service (so
    the engagement is still in current_phase="recon" when the credential gate
    fires — the exact Fawn state, unlike a pre-seeded service which global_plan
    would advance past before termination). nmap returns port 21/ftp only; no
    web surface. Never a real subprocess or network call."""

    name = "fake-recon-ftp"

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    async def execute(
        self, tool: str, arguments: list[str], *,
        timeout_seconds: float | None = None, stdin: str | None = None,
    ) -> Any:
        from apex_host.types import ToolCommand, ToolResult

        self.calls.append((tool, list(arguments)))
        cmd = ToolCommand(tool=tool, args=list(arguments), timeout_seconds=int(timeout_seconds or 30))
        stdout = ""
        if tool == "nmap":
            stdout = (
                f"Nmap scan report for {_TARGET}\n"
                "Host is up (0.015s latency).\n"
                "PORT   STATE SERVICE VERSION\n"
                "21/tcp open  ftp     vsftpd 3.0.3\n"
            )
        return ToolResult(
            command=cmd, stdout=stdout, stderr="", returncode=0,
            duration_seconds=0.001, dry_run=True, backend="fake-recon-ftp", error=None,
        )


async def scenario_recon_service_no_credentials_honest_outcome() -> ScenarioResult:
    """21. Recon DISCOVERS a service but no credential hypothesis → honest outcome.

    The demonstrated Fawn/FTP bug through the REAL compiled graph: recon
    discovers an FTP service (no web surface, no credentials), so the credential
    phase is gated and the engagement stops while still in the recon phase —
    with NO budget hit. Uses a fake nmap backend so the service is DISCOVERED
    during the recon turn (a pre-seeded service would let global_plan advance
    past recon before termination, missing the buggy branch). Fails the gate if
    the stop is mislabeled ``phase_budget_exhausted``, if the reason falsely
    claims "no services discovered", if it is reported as a success, or if a
    real turn cap was reached. Label + reason correctness only.
    """
    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState
    from apex_host.llm.router import FakeModelRouter
    from apex_host.orchestration.builder import build_apex_graph
    from apex_host.orchestration.outcome import EngagementOutcome, exit_code_for
    from apex_host.tools.registry import ToolRegistry

    api = _make_api()  # NO seeded service — recon discovers it
    config = ApexConfig(target=_TARGET, dry_run=True, max_turns=20, tool_backend="remote",
                        allowed_tools=["nmap", "nc"], use_llm=False)  # NO username/password
    backend = _ReconFtpFakeBackend()
    registry = ToolRegistry.from_config(config)
    graph = build_apex_graph(api, registry, config,
                             model_router=FakeModelRouter(), tool_backend=backend)

    initial: ApexGraphState = {
        "run_id": "release-gate-fawn", "target": _TARGET, "phase": "recon",
        "goal": f"Begin engagement against {_TARGET}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [], "repair_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "", "privilege_state": "", "privilege_summary": {},
        "opportunity_ids": [], "attempted_opportunities": [],
        "enumeration_complete": False, "web_session_state": {},
        "workflow_summary": {}, "phase_selection": {}, "learning_summary": {},
        "task_latency_log": [], "objective_status": "", "objective_summary": {},
        "direct_file_read_log": [], "bounded_command_log": [],
        "capability_discovery_log": [], "execution_diagnostics": [],
    }
    final_state: ApexGraphState = await graph.ainvoke(initial)

    problems: list[str] = []
    outcome = str(final_state.get("outcome", ""))
    reason = str(final_state.get("termination_reason", ""))
    turns = int(final_state.get("turn_count", 0))
    # A service must actually have been discovered (else this isn't the tested case).
    sub = await api.get_subgraph(_ANCHOR, depth=4)
    if not any(n.type == "service" for n in sub.nodes):
        problems.append("recon did not discover the FTP service — scenario setup broken")
    if outcome == EngagementOutcome.phase_budget_exhausted.value:
        problems.append("no-actionable stop mislabeled phase_budget_exhausted (no budget was hit)")
    if outcome != EngagementOutcome.no_actionable_task.value:
        problems.append(f"expected no_actionable_task, got {outcome!r}")
    if outcome and exit_code_for(EngagementOutcome(outcome)) == 0:
        problems.append(f"non-success stop reported exit 0: {outcome!r}")
    if "no services discovered" in reason:
        problems.append("reason falsely claims 'no services discovered' when an FTP service exists")
    if turns >= 20:
        problems.append(f"a real turn cap was reached ({turns}/20) — this was not the tested no-budget stop")

    if problems:
        return ScenarioResult("recon_service_no_credentials_honest_outcome", False, "; ".join(problems))
    return ScenarioResult(
        "recon_service_no_credentials_honest_outcome", True,
        f"recon discovered FTP, no credential hypothesis → honest {outcome} at turn {turns}/20 "
        "(never phase_budget_exhausted, never success, reason does not deny the discovered service)",
    )


class _FawnLiveSock:
    def settimeout(self, value: float) -> None: ...
    def sendall(self, data: bytes) -> None: ...


class _FawnFtpFake:
    """Faithful ftplib.FTP double: after a FAILED connect ``sock`` stays None and
    ``quit()`` sends QUIT via ``self.sock.sendall`` (as ftplib.putline does), so
    the pre-§28.15 unguarded finally quit() would raise the live
    ``AttributeError: 'NoneType' ... 'sendall'``. No network I/O."""

    def __init__(self, *, connect_ok: bool) -> None:
        self.encoding = "utf-8"
        self.sock: _FawnLiveSock | None = None
        self._connect_ok = connect_ok

    def connect(self, host: str = "", port: int = 0, timeout: float = -1,
                source_address: object = None) -> str:
        if not self._connect_ok:
            self.sock = None
            raise OSError(113, "No route to host")  # EHOSTUNREACH, the live case
        self.sock = _FawnLiveSock()
        return "220 (vsFTPd 3.0.3)"

    def set_pasv(self, value: bool) -> None: ...
    def login(self, user: str = "", passwd: str = "", acct: str = "") -> str:
        return "230 Login successful."
    def pwd(self) -> str:
        return '"/" is the current directory'
    def voidcmd(self, cmd: str) -> str:
        return "200 NOOP ok."
    def quit(self) -> str:
        self.sock.sendall(b"QUIT\r\n")  # type: ignore[union-attr]
        return "221 Goodbye."
    def close(self) -> None:
        self.sock = None


async def scenario_ftp_anonymous_access() -> ScenarioResult:
    """21. FTP credential validation: a failed connect yields a clean classified
    error (never the NoneType 'sendall' crash), and a successful anonymous login
    is a validated access.

    Reproduces the demonstrated Fawn/vsftpd bug through the REAL FTPExecutor
    (ftplib patched with a faithful in-process double — no network). Fails the
    gate if a connect failure crashes/masks as backend_error, if it is not
    classified connection_failed, if the password leaks into the episode, or if a
    successful anonymous login is not reported as a validated access.
    """
    import ftplib as _ftplib

    from apex_host.agents.ftp_executor import FTPExecutor
    from apex_host.config import ApexConfig
    from apex_host.types import CredentialErrorCategory
    from memfabric.types import EvidenceBundle, TaskSpec

    problems: list[str] = []
    config = ApexConfig(
        target=_TARGET, dry_run=False, allowed_tools=["nmap"],
        ftp_connect_timeout_seconds=1.0, ftp_login_timeout_seconds=1.0,
        ftp_command_timeout_seconds=1.0,
    )
    ev = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    _SECRET = "probe-not-a-real-secret@x"  # the anonymous password sent in

    def _task() -> TaskSpec:
        return TaskSpec(
            id="rg-ftp", goal_id="g", executor_domain="credential",
            params={"tool": "ftp_access", "target": _TARGET, "port": "21",
                    "username": "anonymous", "password": _SECRET, "parser": "access"},
            subgraph_anchor=_ANCHOR, phase="credential",
        )

    original = _ftplib.FTP  # ftp_executor calls ftplib.FTP() on this same module
    try:
        # 1. Connect FAILURE (EHOSTUNREACH) → clean classified error, NEVER crash.
        setattr(_ftplib, "FTP", lambda *a, **k: _FawnFtpFake(connect_ok=False))
        try:
            r1 = await FTPExecutor(config).run(_task(), ev)
        except Exception as exc:  # noqa: BLE001 — the whole point is: it must NOT raise
            return ScenarioResult(
                "ftp_anonymous_access", False,
                f"FTP connect failure crashed the executor ({type(exc).__name__}: {exc})",
            )
        if r1.episode.data.get("success") is not False:
            problems.append("connect failure not reported as a failure")
        if r1.episode.data.get("error_category") != CredentialErrorCategory.connection_failed.value:
            problems.append(f"connect failure misclassified: {r1.episode.data.get('error_category')!r}")
        if "sendall" in str(r1.episode.data):
            problems.append("the NoneType 'sendall' crash leaked into the result")

        # 2. Successful anonymous login → validated access; password never stored.
        setattr(_ftplib, "FTP", lambda *a, **k: _FawnFtpFake(connect_ok=True))
        r2 = await FTPExecutor(config).run(_task(), ev)
        if not (r2.episode.data.get("success") is True and r2.episode.data.get("authenticated") is True):
            problems.append("successful anonymous FTP login not reported as validated access")
        if _SECRET in str(r2.episode.data):
            problems.append("the FTP password leaked into the episode data")
    finally:
        setattr(_ftplib, "FTP", original)

    if problems:
        return ScenarioResult("ftp_anonymous_access", False, "; ".join(problems))
    return ScenarioResult(
        "ftp_anonymous_access", True,
        "FTP connect failure → clean connection_failed (no NoneType 'sendall' crash); "
        "successful anonymous login → validated access; password never stored",
    )


async def scenario_ftp_validation_via_tool_service() -> ScenarioResult:
    """22. FTP credential validation runs on the target-reachable tool-service
    (Kali/VPN) side, not in-process in apex (§28.16).

    apex has no route to a VPN-only HTB target, so in-process ftplib validation
    always times out — only kali can reach it. Drives the REAL FTPExecutor with
    ``tool_backend="remote"`` against the REAL in-process tool-service app (its
    server-side ftplib mocked for a successful anonymous login). Fails the gate
    if validation ran in-process (the old routing), if the tool-service path did
    not produce a validated access, or if the password leaked into the episode.
    """
    import ftplib as _ftplib

    import httpx

    import apex_host.agents.ftp_executor as ftp_mod
    from apex_host.agents.ftp_executor import FTPExecutor
    from apex_host.config import ApexConfig
    from apex_host.types import CredentialErrorCategory, CredentialValidationResult
    from apex_tool_service.app import create_app
    from apex_tool_service.settings import ServiceSettings
    from memfabric.types import EvidenceBundle, TaskSpec

    _TOKEN = "rg-ftp-token"
    _SECRET = "probe-not-a-real-secret@x"
    task = TaskSpec(
        id="rg-ftp-remote", goal_id="g", executor_domain="credential",
        params={"tool": "ftp_access", "target": _TARGET, "port": "21",
                "username": "anonymous", "password": _SECRET, "parser": "access"},
        subgraph_anchor=_ANCHOR, phase="credential",
    )
    ev = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    config = ApexConfig(
        target=_TARGET, dry_run=False, tool_backend="remote",
        tool_service_url="http://svc", tool_service_token=_TOKEN,
        ftp_connect_timeout_seconds=1.0, ftp_login_timeout_seconds=1.0,
        ftp_command_timeout_seconds=1.0,
    )
    # Tool-service (kali side), authorized for the synthetic target's /24, with a
    # successful server-side ftplib login (reusing the §28.15 faithful double).
    app = create_app(ServiceSettings(token=_TOKEN, authorized_cidrs=("10.10.10.0/24",)))
    transport = httpx.ASGITransport(app=app)
    _real_client = httpx.AsyncClient  # bind before patching to avoid recursion

    in_process_ran = {"v": False}

    def _spy_in_process(*a: object, **k: object) -> CredentialValidationResult:
        # If FTPExecutor ran the in-process path (the OLD routing), record it and
        # return a failure — apex has no route to a VPN-only target.
        in_process_ran["v"] = True
        return CredentialValidationResult(
            protocol="ftp", target=_TARGET, port="21", username="anonymous",
            success=False, authenticated=False, operation="PWD", response_summary="",
            error_category=CredentialErrorCategory.connect_timeout.value,
            error_detail="in-process (apex) has no VPN route", duration_seconds=0.0,
            timed_out=True, executor="ftp",
        )

    orig_ftp = _ftplib.FTP
    orig_attempt = ftp_mod._attempt_ftp_sync
    orig_async_client = httpx.AsyncClient  # RemoteToolBackend uses this same module singleton
    problems: list[str] = []
    try:
        setattr(_ftplib, "FTP", lambda *a, **k: _FawnFtpFake(connect_ok=True))  # server-side success
        setattr(ftp_mod, "_attempt_ftp_sync", _spy_in_process)
        setattr(httpx, "AsyncClient", lambda *a, **k: _real_client(transport=transport))
        result = await FTPExecutor(config).run(task, ev)
    finally:
        setattr(_ftplib, "FTP", orig_ftp)
        setattr(ftp_mod, "_attempt_ftp_sync", orig_attempt)
        setattr(httpx, "AsyncClient", orig_async_client)

    if in_process_ran["v"]:
        problems.append("FTP validation ran in-process (apex) instead of the target-reachable tool-service")
    data = result.episode.data
    if data.get("success") is not True or data.get("authenticated") is not True:
        problems.append(f"tool-service FTP validation did not produce a validated access: {data.get('error_category')!r}")
    if _SECRET in str(data):
        problems.append("the FTP password leaked into the episode data")

    if problems:
        return ScenarioResult("ftp_validation_via_tool_service", False, "; ".join(problems))
    return ScenarioResult(
        "ftp_validation_via_tool_service", True,
        "FTPExecutor routed validation to the tool-service (Kali/VPN side) — never in-process; "
        "successful anonymous login → validated access; password never stored",
    )


class _FlagRetrFtp:
    """Server-side ftplib.FTP double for the tool-service, faithful to a vsftpd
    anonymous chroot (§28.20): the flag exists as the BARE basename ``flag.txt``
    in the root landing dir. It is served ONLY via ``CWD /`` + ``RETR flag.txt``
    — a CWD to any non-root dir 550s (chroot), and an absolute-path
    ``RETR /flag.txt`` 550s. No network I/O."""

    def __init__(self) -> None:
        self.encoding = "utf-8"
        self.sock: _FawnLiveSock | None = _FawnLiveSock()
        self.cwd_path = "/"

    def connect(self, host: str = "", port: int = 0, timeout: float = -1,
                source_address: object = None) -> str:
        self.sock = _FawnLiveSock()
        return "220 (vsFTPd 3.0.3)"

    def set_pasv(self, value: bool) -> None: ...
    def login(self, user: str = "", passwd: str = "", acct: str = "") -> str:
        return "230 Login successful."

    def cwd(self, dirname: str) -> str:
        import ftplib as _ftplib
        if (dirname or "/").rstrip("/") in ("", "/"):
            self.cwd_path = "/"
            return "250 Directory changed to /"
        raise _ftplib.error_perm("550 Failed to change directory.")

    def retrbinary(self, cmd: str, cb: Any, blocksize: int = 8192) -> str:
        import ftplib as _ftplib
        name = cmd.split("RETR ", 1)[1].strip() if cmd.startswith("RETR ") else ""
        # The flag resolves only as the bare basename "flag.txt" at the root.
        if name == "flag.txt" and self.cwd_path == "/":
            cb((_FLAG_VALUE + "\n").encode())
            return "226 Transfer complete."
        if "/" in name or self.cwd_path != "/":
            raise _ftplib.error_perm("550 Failed to open file.")
        return "226 Transfer complete."  # allowlisted basename, but a miss (empty)

    def quit(self) -> str:
        self.sock.sendall(b"QUIT\r\n")  # type: ignore[union-attr]
        return "221 Goodbye."

    def close(self) -> None:
        self.sock = None


async def scenario_ftp_flag_read_via_tool_service() -> ScenarioResult:
    """§28.19 — a legitimate FTP-root ``/flag.txt`` read is accepted by the
    tool-service's OWN basename allowlist and verifies, driving the REAL objective
    turn loop (ObjectivePlanner → UserFlagExecutor → verify_user_flag →
    ObjectiveParser) through the REAL in-process tool-service ``/v1/ftp-read``
    endpoint (server-side ftplib mocked to RETR the flag only for ``/flag.txt``;
    the client HTTP transport pointed at the ASGI app). The objective node is built
    entirely by the parser across candidate turns (no pre-seed), reaching
    ``/flag.txt`` (the FTP-root name §28.18 added).

    FAILS against the pre-§28.19 server allowlist (``user.txt`` only), which
    400-rejects ``flag.txt`` before the RETR — so the ``/flag.txt`` read never
    completes and the objective never verifies (exactly the demonstrated live
    failure)."""
    name = "ftp_flag_read_via_tool_service"
    import ftplib as _ftplib

    import httpx

    from apex_host.agents.user_flag_executor import UserFlagExecutor
    from apex_host.planners.objective_planner import ObjectivePlanner
    from apex_host.runtime_registry import CapabilityRuntimeRegistry, FtpFileReadCapabilityAdapter
    from apex_host.tools.registry import ToolRegistry
    from apex_tool_service.app import create_app
    from apex_tool_service.settings import ServiceSettings
    from memfabric.types import AbandonSignal, EvidenceBundle, Goal

    _TOKEN = "rg-ftpread-token"
    _SECRET = "anon-not-a-real-secret@x"
    api = _make_api()
    config = _config(
        username_candidates=["anonymous"], password_candidates=["anonymous"],
        dry_run=False, tool_backend="remote", tool_service_url="http://svc", tool_service_token=_TOKEN,
        ftp_connect_timeout_seconds=1.0, ftp_login_timeout_seconds=1.0, ftp_command_timeout_seconds=1.0,
    )
    await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
    await _seed_node(
        api, access_state_id(_TARGET, "anonymous", protocol="ftp"), "access_state",
        {"level": "user", "username": "anonymous", "target": _TARGET, "service": "ftp"},
    )
    cap_id = access_capability_id(_TARGET, AccessCapabilityType.ftp_file_read.value, "anonymous")
    await _seed_node(api, cap_id, "access_capability", {
        "capability_type": "ftp_file_read", "host_id": _ANCHOR, "validated": True,
        "principal": "anonymous", "confidence": 0.85, "runtime_available": True, "metadata": {},
    })
    await _seed_edge(api, _ANCHOR, cap_id)

    # Real tool-service (kali side) with DEFAULT settings (§28.19: flag.txt now in
    # allowed_flag_basenames), authorized for the synthetic target's /24.
    registry = CapabilityRuntimeRegistry()
    registry.register(cap_id, FtpFileReadCapabilityAdapter(
        target=_TARGET, port="21", username="anonymous", password=_SECRET, config=config,
    ))
    app = create_app(ServiceSettings(token=_TOKEN, authorized_cidrs=("10.10.10.0/24",)))
    transport = httpx.ASGITransport(app=app)
    _real_client = httpx.AsyncClient
    orig_ftp = _ftplib.FTP
    orig_async_client = httpx.AsyncClient

    planner = ObjectivePlanner(_TARGET, ToolRegistry.from_config(config), config=config)
    executor = UserFlagExecutor(config, registry)
    parser = ObjectiveParser()
    goal = Goal(id="g", description="user-flag objective", phase="objective", anchor_node=_ANCHOR)
    eb = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    verified_path = ""
    last_secret_seen = False
    try:
        setattr(_ftplib, "FTP", lambda *a, **k: _FlagRetrFtp())
        setattr(httpx, "AsyncClient", lambda *a, **k: _real_client(transport=transport))
        for _ in range(8):  # bounded — at most 4 candidates for one capability
            sub = await _subgraph(api)
            if objective_status_from_subgraph(sub, _TARGET, "user_flag") == "verified":
                break
            plan = await planner.plan(goal, sub, eb)
            if isinstance(plan, AbandonSignal) or not plan:
                break
            task = plan[0]
            res = await executor.run(task, eb)
            d = res.episode.data
            last_secret_seen = last_secret_seen or (_SECRET in str(d))
            parsed = parser.parse_user_flag_result(
                target=_TARGET, objective_type="user_flag", candidate_path=str(d["candidate_path"]),
                connected=bool(d["connected"]), verified=bool(d["verified"]),
                value_digest=str(d["value_digest"]), redacted_value=str(d["redacted_value"]),
                verification_method=str(d["verification_method"]), capability_id=cap_id,
                capability_type="ftp_file_read", principal="anonymous",
                attempted_paths=list(task.params.get("attempted_paths", [])),
                attempted_capability_paths=list(task.params.get("attempted_capability_paths", [])),
                is_last_candidate=bool(task.params.get("is_last_candidate", False)),
            )
            await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
            if bool(d["verified"]):
                verified_path = str(d["candidate_path"])
                break
    finally:
        setattr(_ftplib, "FTP", orig_ftp)
        setattr(httpx, "AsyncClient", orig_async_client)

    final = await _subgraph(api)
    status = objective_status_from_subgraph(final, _TARGET, "user_flag")
    if status != "verified":
        return ScenarioResult(
            name, False,
            f"objective not verified (status={status!r}) — /flag.txt rejected by the server allowlist",
        )
    if verified_path != "/flag.txt":
        return ScenarioResult(name, False, f"verified via {verified_path!r}, expected the FTP root /flag.txt")
    if not await _raw_flag_absent(api):
        return ScenarioResult(name, False, "raw flag value leaked into the graph")
    if last_secret_seen:
        return ScenarioResult(name, False, "the FTP password leaked into an executor result")
    return ScenarioResult(
        name, True,
        "/flag.txt accepted by the tool-service basename allowlist, RETR'd, and verified "
        "via the real objective loop through /v1/ftp-read; raw flag absent; password never stored",
    )


SCENARIOS: list[Any] = [
    scenario_ssh_success,
    scenario_ftp_flag_read,
    scenario_ftp_root_flag_path,
    scenario_ftp_flag_read_via_tool_service,
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
    scenario_recon_web_engagement_regression,
    scenario_unprivileged_backend_completes_connect_scan,
    scenario_curl_only_web_discovery,
    scenario_vhost_redirect_web_discovery,
    scenario_web_incomplete_not_goal_completed,
    scenario_incomplete_scan_escalates_not_stall,
    scenario_web_content_enumeration,
    scenario_web_endpoint_fetch_loop,
    scenario_web_api_surface_discovery,
    scenario_web_js_api_discovery,
    scenario_recon_service_no_credentials_honest_outcome,
    scenario_ftp_anonymous_access,
    scenario_ftp_validation_via_tool_service,
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
