# dispatch_node.py
# Agent-node factories for all five APEX phases: shared _dispatch_tasks helper eliminates duplication.
"""Dispatch node factories for the APEX orchestration layer.

Provides one factory per phase agent node (recon, web, priv_esc, execute,
browser) plus the shared ``_dispatch_tasks`` helper that eliminates the
duplication that previously existed between ``_run_tasks`` and
``execute_agent`` in ``graph.py``.

Key invariants:
- All gate checks (policy, conflict, duplicate) run inside ``TaskDispatcher``.
- ``execute_agent`` (credential phase) uses ``single_task=True`` so at most
  one task runs per turn (§12.12 safety invariant).
- ``browser_agent`` synthesises its own ``TaskSpec`` rather than calling a
  planner — the URL is derived from state, not from a planner output.
- ``asyncio.gather`` uses ``return_exceptions=True`` (F09) so one failing
  coroutine does not cancel concurrent tasks.
- Phase 12C: an exception raised directly by ``planner.plan()`` (as opposed
  to a normal ``AbandonSignal``) is caught here and converted into an
  ``EngagementOutcome.planner_failure`` upstream-preset outcome — see
  ``apex_host.orchestration.outcome`` module docstring, precedence level 2
  — rather than propagating out of the node closure and crashing
  ``graph.ainvoke()``.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from memfabric.ids import now
from memfabric.types import AbandonSignal, Goal, Node, TaskSpec

from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.models import task_info
from apex_host.orchestration.outcome import EngagementOutcome
from apex_host.planners.access_capabilities import access_capabilities_from_subgraph
from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planners.objective import objective_state_fields
from apex_host.planners.priv_esc_opportunities import privilege_state_fields
from apex_host.planners.web_opportunities import web_session_state_fields
from apex_host.types import AccessCapabilityType, ApexPhase

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps
    from apex_host.types import AccessCapability
    from memfabric.coordination.protocols import Planner
    from memfabric.types import SubgraphView

logger = logging.getLogger(__name__)


def _dup_entry(
    task: TaskSpec, fingerprint: str, phase: str, config_target: str
) -> dict[str, Any]:
    return {
        "fingerprint": fingerprint,
        "tool": str(task.params.get("tool", "")),
        "target": str(task.params.get("target", config_target)),
        "phase": phase,
        "disposition": "skip_task",
        "reason": f"task matched completed fingerprint={fingerprint}",
        "meaningful_state_change": False,
    }


async def _dispatch_tasks(
    deps: "OrchestrationDeps",
    state: "ApexGraphState",
    planner: "Planner",
    *,
    single_task: bool = False,
) -> dict[str, Any]:
    """Plan + dispatch tasks for a phase, returning state-dict updates.

    Args:
        deps: Orchestration services (API, dispatcher, config …).
        state: Current LangGraph state snapshot.
        planner: The domain planner for this phase.
        single_task: When True, only the first task is executed and a
            SKIPPED_DUPLICATE causes an early return with null tool_result
            (credential-phase safety invariant §12.12).
    """
    anchor = deps.anchor_id
    goal = Goal(
        id=state["run_id"],
        description=state["goal"],
        phase=state["phase"],
        anchor_node=anchor,
    )
    try:
        subgraph = await deps.api.get_subgraph(anchor, depth=2)
        evidence = await deps.api.query(text=goal.description, subgraph_anchor=anchor)
    except Exception as exc:
        logger.error("MemoryAPI read failed in phase %s: %s", state["phase"], exc)
        return {
            "current_task": None, "last_tool_result": None, "tool_results": None,
            "last_error": f"memory failure: {exc}", "planner_decisions": [],
            "outcome": EngagementOutcome.memory_failure.value,
            "termination_reason": f"{type(exc).__name__}: {exc}",
            "termination_phase": state["phase"],
        }

    try:
        plan_result = await planner.plan(goal, subgraph, evidence)
    except Exception as exc:
        logger.error("planner raised in phase %s: %s", state["phase"], exc)
        return {
            "current_task": None, "last_tool_result": None, "tool_results": None,
            "last_error": f"planner failure: {exc}", "planner_decisions": [],
            "outcome": EngagementOutcome.planner_failure.value,
            "termination_reason": f"{type(exc).__name__}: {exc}",
            "termination_phase": state["phase"],
        }

    from apex_host.planning.models import PlanDecision as _PD

    decision: _PD | None = getattr(planner, "last_decision", None)
    decision_list: list[dict[str, Any]] = [decision.to_dict()] if decision is not None else []

    if isinstance(plan_result, AbandonSignal):
        logger.info("phase %s abandoned: %s", state["phase"], plan_result.reason)
        return {
            "current_task": None, "last_tool_result": None, "tool_results": None,
            "last_error": plan_result.reason, "planner_decisions": decision_list,
        }

    tasks: list[TaskSpec] = list(plan_result) if plan_result else []
    if not tasks:
        return {
            "current_task": None, "last_tool_result": None, "tool_results": None,
            "last_error": "planner returned no tasks", "planner_decisions": decision_list,
        }

    if single_task:
        tasks = tasks[:1]

    concurrency_cap = max(1, min(deps.config.max_concurrency, len(tasks)))
    sem = asyncio.Semaphore(concurrency_cap)

    async def _run_one(
        task: TaskSpec,
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        async with sem:
            ctx = ExecutionContext(
                run_id=state["run_id"], phase=state["phase"],
                turn_number=state["turn_count"], evidence_version=None,
                subgraph=subgraph, evidence=evidence, dry_run=deps.config.dry_run,
            )
            dr = await deps.dispatcher.dispatch(task, ctx)
            pd_entry = dict(dr.audit_metadata.get("policy_decision") or {})
            dup_list: list[dict[str, Any]] = []
            if dr.disposition is ExecutionDisposition.SKIPPED_DUPLICATE:
                dup_list = [_dup_entry(task, dr.fingerprint, state["phase"], deps.config.target)]
            return dr.tool_result_dict, pd_entry, dup_list

    raw = list(await asyncio.gather(*[_run_one(t) for t in tasks], return_exceptions=True))
    pairs: list[tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]] = []
    for i, item in enumerate(raw):
        if isinstance(item, BaseException):
            t = tasks[i]
            err: dict[str, Any] = {
                "task_id": t.id, "tool": str(t.params.get("tool", "")),
                "args": [str(a) for a in t.params.get("args", [])],
                "target": str(t.params.get("target", deps.config.target)),
                "parser": str(t.params.get("parser", "command")),
                "stdout": "", "stderr": str(item), "returncode": 1,
                "dry_run": deps.config.dry_run, "error": str(item), "phase": state["phase"],
            }
            logger.warning("_run_one raised for task %s: %s", t.id, item)
            pairs.append((err, {}, []))
        else:
            pairs.append(item)

    results = [p[0] for p in pairs]
    pd_list_all = [p[1] for p in pairs]
    dup_all = [e for p in pairs for e in p[2]]
    first_result = results[0] if results else None
    first_task = tasks[0] if tasks else None

    # Single-task duplicate early return (credential-phase §12.12 safety invariant)
    if single_task and dup_all and first_result is not None:
        return {
            "current_task": task_info(first_task), "last_tool_result": None,
            "tool_results": None, "last_error": None,
            "planner_decisions": decision_list, "policy_decisions": pd_list_all,
            "duplicate_actions": dup_all,
        }

    rdict: dict[str, Any] = {
        "current_task": task_info(first_task),
        "last_tool_result": first_result,
        "tool_results": results,
        "last_error": first_result.get("error") if first_result else None,
        "planner_decisions": decision_list,
        "policy_decisions": pd_list_all,
    }
    if dup_all:
        rdict["duplicate_actions"] = dup_all
    return rdict


def make_recon_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``recon_agent`` node bound to the recon planner."""
    async def recon_agent(state: "ApexGraphState") -> dict[str, Any]:
        return await _dispatch_tasks(deps, state, deps.phase_planners[ApexPhase.recon.value])
    return recon_agent


def make_web_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``web_agent`` node bound to the web planner."""
    async def web_agent(state: "ApexGraphState") -> dict[str, Any]:
        return await _dispatch_tasks(deps, state, deps.phase_planners[ApexPhase.web.value])
    return web_agent


def make_priv_esc_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``priv_esc_agent`` node bound to the priv_esc planner.

    Phase 13: after dispatching, refreshes the ``privilege_state``/
    ``privilege_summary``/``opportunity_ids``/``attempted_opportunities``/
    ``enumeration_complete`` state fields from a fresh EKG read — mirrors
    the read-after-write "peek" pattern ``continuation_node.py`` already
    uses, scoped only to this node so other phase agents are unaffected. A
    failed refresh degrades gracefully (state fields simply keep their
    previous value this turn) rather than failing the whole turn.
    """
    async def priv_esc_agent(state: "ApexGraphState") -> dict[str, Any]:
        result = await _dispatch_tasks(deps, state, deps.phase_planners[ApexPhase.priv_esc.value])
        try:
            subgraph = await deps.api.get_subgraph(deps.anchor_id, depth=2)
            result.update(privilege_state_fields(subgraph, target=state["target"]))
        except Exception as exc:
            logger.debug("priv_esc_agent: privilege-state summary refresh failed: %s", exc)
        return result
    return priv_esc_agent


def _ssh_port_for_capability(subgraph: "SubgraphView") -> str:
    """Lowest-port ``access_validate_ssh`` capability's port, or the SSH
    default. Mirrors the pre-refactor ``objective_planner._ssh_port``
    helper — relocated here since resolving a runtime connection detail
    for a capability adapter is an orchestration-layer concern, never a
    planner concern (memfabric Invariant 7)."""
    caps = [c for c in capabilities_from_subgraph(subgraph) if c.name == "access_validate_ssh"]
    if not caps:
        return "22"
    return sorted(caps, key=lambda c: int(c.port) if c.port.isdigit() else 22)[0].port or "22"


def _register_capability_adapter(
    deps: "OrchestrationDeps", subgraph: "SubgraphView", target: str, cap: "AccessCapability"
) -> bool:
    """Register a runtime adapter for one validated ``AccessCapability`` so
    ``UserFlagExecutor`` can resolve ``capability_id -> adapter`` this turn.
    Returns ``True`` iff an adapter was successfully constructed and
    registered — the caller uses this to keep the EKG node's
    ``runtime_available`` prop accurate (see ``make_objective_node``).

    Orchestration-layer-only concern: planners stay pure over subgraph/
    evidence data (memfabric Invariant 7); executors only ever *look up* an
    already-registered adapter (see ``apex_host/runtime_registry.py``).
    SSH, direct-file-read (``arbitrary_file_read``/``api_file_read``), and
    bounded command execution (``local_shell``/``remote_command``/
    ``web_command``, Phase 21) have real adapters — an unrecognised
    ``capability_type`` is silently skipped (forward-compatible: a future
    capability type simply has no adapter registered, and stays
    ``runtime_available=False``, until its own registration branch is added
    here). ``web_command`` deliberately shares
    ``_register_direct_file_read_adapter`` (and therefore
    ``ApexConfig.direct_file_read_*`` configuration) with
    ``arbitrary_file_read``/``api_file_read`` — the underlying mechanism (a
    fixed HTTP request shape) is identical; only the capability_type label
    differs, recording whether the operator classifies the primitive as
    "serves a file directly" or "executes a command whose response happens
    to contain the read output."
    """
    if cap.capability_type is AccessCapabilityType.ssh_command:
        return _register_ssh_adapter(deps, subgraph, target, cap)
    if cap.capability_type in (
        AccessCapabilityType.arbitrary_file_read,
        AccessCapabilityType.api_file_read,
        AccessCapabilityType.web_command,
    ):
        return _register_direct_file_read_adapter(deps, target, cap)
    if cap.capability_type in (AccessCapabilityType.local_shell, AccessCapabilityType.remote_command):
        return _register_bounded_command_adapter(deps, target, cap)
    return False


def _register_ssh_adapter(
    deps: "OrchestrationDeps", subgraph: "SubgraphView", target: str, cap: "AccessCapability"
) -> bool:
    usernames = list(getattr(deps.config, "username_candidates", None) or [])
    passwords = list(getattr(deps.config, "password_candidates", None) or [])
    # Mirrors CredentialPlanner's own one-credential-pair-per-engagement
    # invariant: only the first configured pair is ever validated, so only
    # a capability whose principal matches it can be provisioned here.
    if not usernames or not passwords or cap.principal != usernames[0]:
        return False
    deps.capability_registry.ensure_ssh(
        cap.capability_id,
        target=target,
        port=_ssh_port_for_capability(subgraph),
        username=cap.principal,
        password=passwords[0],
        config=deps.config,
    )
    return True


def _register_direct_file_read_adapter(
    deps: "OrchestrationDeps", target: str, cap: "AccessCapability"
) -> bool:
    """Construct (from operator-supplied ``ApexConfig`` fields only — never
    from the capability node's own EKG metadata, which carries no secret)
    and register a ``DirectFileReadCapabilityAdapter``. Performs NO network
    I/O — constructing the adapter/primitive is always safe.

    Mirrors ``_register_ssh_adapter``'s principal-matching discipline: only
    a capability whose principal matches the operator's configured
    ``direct_file_read_principal`` can be provisioned here.
    """
    from apex_host.runtime_registry import DirectFileReadPrimitive

    config = deps.config
    if not config.direct_file_read_origin or not config.direct_file_read_endpoint_template:
        return False
    if cap.principal != config.direct_file_read_principal:
        return False
    allowed_filenames = frozenset(getattr(config, "user_flag_candidate_filenames", None) or [])
    try:
        primitive = DirectFileReadPrimitive(
            capability_id=cap.capability_id,
            target_origin=config.direct_file_read_origin,
            endpoint_template=config.direct_file_read_endpoint_template,
            method=config.direct_file_read_method,
            headers=dict(config.direct_file_read_headers),
            timeout_seconds=config.direct_file_read_timeout_seconds,
            max_response_bytes=config.direct_file_read_max_response_bytes,
            allow_redirects=config.direct_file_read_allow_redirects,
            allowed_filenames=allowed_filenames,
        )
    except ValueError as exc:
        logger.warning("direct-file-read primitive construction rejected: %s", exc)
        return False
    deps.capability_registry.ensure_direct_file_read(cap.capability_id, primitive=primitive)
    return True


def _register_bounded_command_adapter(
    deps: "OrchestrationDeps", target: str, cap: "AccessCapability"
) -> bool:
    """Construct and register a ``BoundedCommandCapabilityAdapter`` for a
    validated ``local_shell``/``remote_command`` capability (Phase 21).

    Mirrors ``_register_direct_file_read_adapter``'s principal-matching
    discipline: only a capability whose principal matches the operator's
    configured ``bounded_command_principal`` can be provisioned here. The
    one reference strategy (``ToolBackendCommandReadStrategy``) is
    constructed from ``apex_host.tools.backend.select_runtime_backend`` —
    the SAME centralized, dry-run-aware backend selector every other
    command-execution path in this codebase uses — so this registration
    step performs no execution itself (constructing a ``ToolBackend`` and a
    strategy wrapper is always safe) and inherits the same dry-run
    guarantee as every other tool invocation.
    """
    from apex_host.runtime_registry import BoundedCommandReadPrimitive, ToolBackendCommandReadStrategy
    from apex_host.tools.backend import select_runtime_backend

    config = deps.config
    if not config.bounded_command_operator_attested:
        return False
    if cap.principal != config.bounded_command_principal:
        return False
    allowed_filenames = frozenset(getattr(config, "user_flag_candidate_filenames", None) or [])
    try:
        backend = select_runtime_backend(config)
        strategy = ToolBackendCommandReadStrategy(backend=backend)
        primitive = BoundedCommandReadPrimitive(
            capability_id=cap.capability_id,
            strategy=strategy,
            allowed_filenames=allowed_filenames,
            timeout_seconds=config.bounded_command_timeout_seconds,
            max_output_bytes=config.bounded_command_max_output_bytes,
        )
    except ValueError as exc:
        logger.warning("bounded-command primitive construction rejected: %s", exc)
        return False
    deps.capability_registry.ensure_bounded_command(cap.capability_id, primitive=primitive)
    return True


def make_objective_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``objective_agent`` node bound to the objective planner.

    Phase 18: uses ``single_task=True`` to enforce the one-bounded-
    verification-task-per-turn invariant, mirroring the credential phase's
    own safety pacing for sensitive session-based operations.

    Access-capability refactor: immediately before dispatching, registers a
    runtime adapter (``deps.capability_registry``) for every validated
    ``AccessCapability`` the live EKG currently has, so
    ``UserFlagExecutor`` can resolve whichever ``capability_id``
    ``ObjectivePlanner`` selects to a real adapter this turn — this is the
    ONE place live connection parameters (e.g. an SSH password, a
    direct-file-read primitive's headers) are ever paired with a
    ``capability_id``; neither the planner nor the executor itself ever
    sees them together. After dispatching, refreshes the
    ``objective_status``/``objective_summary`` state fields from a fresh
    EKG read — mirrors the read-after-write "peek" pattern
    ``make_priv_esc_node``/``make_browser_node`` already use (Phase 13/14),
    scoped only to this node so other phase agents are unaffected. A failed
    refresh (registration or state-summary) degrades gracefully.

    Phase 20 — registration outcome (success or failure) is written back
    onto the capability's EKG node as ``runtime_available`` (a plain
    per-field upsert, memfabric Invariant 3), so the distinction between
    "a validated capability exists" (metadata) and "a runtime adapter is
    currently registered for it" (a runtime fact) stays visible in the
    graph — see ``AccessCapability.runtime_available``'s docstring. Only
    written when it actually changes, to avoid a needless upsert every
    turn once a capability's availability has stabilised.
    """
    async def objective_agent(state: "ApexGraphState") -> dict[str, Any]:
        try:
            pre_subgraph = await deps.api.get_subgraph(deps.anchor_id, depth=2)
            for cap in access_capabilities_from_subgraph(pre_subgraph):
                if not cap.validated or deps.capability_registry.has(cap.capability_id):
                    continue
                registered = _register_capability_adapter(deps, pre_subgraph, state["target"], cap)
                if registered != cap.runtime_available:
                    timestamp = now()
                    await deps.api.upsert_node(Node(
                        id=cap.capability_id, type="access_capability",
                        props={"runtime_available": registered},
                        # Deliberately BELOW MemoryAPI's conflict_confidence_floor
                        # (default 0.8): `runtime_available` is a runtime STATUS
                        # flag re-derived fresh every turn, not an epistemic claim
                        # two credible sources might genuinely disagree about — a
                        # capability's own `confidence` (often >= 0.8) would make
                        # this flip-flopping True/False update collide with the
                        # ORIGINAL derivation's high-confidence write and spuriously
                        # open a Conflict record every time availability changes.
                        # Plain last-writer-wins (by logical_version) is exactly
                        # the semantics wanted here.
                        confidence=0.5, source="dispatch_node",
                        first_seen=timestamp, last_seen=timestamp,
                    ))
        except Exception as exc:
            logger.debug("objective_agent: capability registration failed: %s", exc)

        result = await _dispatch_tasks(
            deps, state, deps.phase_planners[ApexPhase.objective.value], single_task=True
        )
        try:
            subgraph = await deps.api.get_subgraph(deps.anchor_id, depth=2)
            result.update(objective_state_fields(subgraph, state["target"], deps.config.objective_type))
        except Exception as exc:
            logger.debug("objective_agent: objective-state summary refresh failed: %s", exc)
        return result
    return objective_agent


def make_execute_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``execute_agent`` (credential-phase) node.

    Uses ``single_task=True`` to enforce the one-task-per-turn invariant
    from §12.12 (no brute force, no credential stuffing).
    """
    async def execute_agent(state: "ApexGraphState") -> dict[str, Any]:
        return await _dispatch_tasks(
            deps, state, deps.phase_planners[ApexPhase.credential.value], single_task=True
        )
    return execute_agent


def make_browser_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``browser_agent`` node bound to the browser planner.

    Phase 14: ``browser_agent`` now goes through ``_dispatch_tasks`` like
    every other phase agent, calling ``BrowserPlanner`` (registered under
    the ``"browser"`` key in ``deps.phase_planners`` — see
    ``apex_host.orchestration.dependencies.build_planners``) instead of
    synthesising a hardcoded ``TaskSpec`` for ``state["target"]`` on every
    turn. ``single_task=True`` preserves the pre-Phase-14 "exactly one
    browse action per turn" behavior. After dispatching, refreshes the
    ``web_session_state`` field from a fresh EKG read — mirrors the
    read-after-write "peek" pattern ``make_priv_esc_node`` already uses
    (Phase 13), scoped only to this node so other phase agents are
    unaffected. A failed refresh degrades gracefully.
    """
    async def browser_agent(state: "ApexGraphState") -> dict[str, Any]:
        result = await _dispatch_tasks(
            deps, state, deps.phase_planners["browser"], single_task=True
        )
        try:
            subgraph = await deps.api.get_subgraph(deps.anchor_id, depth=2)
            result.update(web_session_state_fields(subgraph, target=state["target"]))
        except Exception as exc:
            logger.debug("browser_agent: web-session-state summary refresh failed: %s", exc)
        return result

    return browser_agent
