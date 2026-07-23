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

from apex_host.capabilities.runtime_references import RuntimeReferenceError
from apex_host.capabilities.runtime_resolution import register_capability_adapter
from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.graph_state import ApexGraphState
from apex_host.llm.errors import PERMANENT_LLM_ERROR_CATEGORIES
from apex_host.orchestration.models import task_info
from apex_host.orchestration.outcome import EngagementOutcome
from apex_host.planners.access_capabilities import access_capabilities_from_subgraph
from apex_host.planners.objective import objective_state_fields
from apex_host.planners.priv_esc_opportunities import privilege_state_fields
from apex_host.planners.web_opportunities import web_session_state_fields
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps
    from memfabric.coordination.protocols import Planner

logger = logging.getLogger(__name__)

# Plain-string projection of PERMANENT_LLM_ERROR_CATEGORIES for comparison
# against PlanDecision.llm_error_category (typed str, not LLMErrorCategory
# — see apex_host/planning/models.py) without a per-call enum round-trip.
_PERMANENT_LLM_ERROR_CATEGORY_VALUES: frozenset[str] = frozenset(
    c.value for c in PERMANENT_LLM_ERROR_CATEGORIES
)


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

    # Phase 1 (post-live-test debugging) — explicit fail-fast policy for a
    # CONFIRMED PERMANENT LLM provider misconfiguration. Only fires when
    # the operator explicitly opted in via ApexConfig.llm_required=True
    # (default False — existing silent-fallback behavior is otherwise
    # completely unchanged). "Confirmed permanent" means the SAME category
    # PlanningEngine already checked against LLMBudgetTracker
    # .permanent_provider_error_category before even attempting this call
    # (apex_host.llm.errors.PERMANENT_LLM_ERROR_CATEGORIES) — a transient
    # failure (timeout/rate-limit/network) never sets this category and so
    # never reaches this branch.
    if (
        getattr(deps.config, "llm_required", False)
        and decision is not None
        and decision.llm_error_category in _PERMANENT_LLM_ERROR_CATEGORY_VALUES
    ):
        logger.error(
            "phase %s: LLM required (llm_required=True) but provider unavailable "
            "(category=%s) — terminating engagement",
            state["phase"], decision.llm_error_category,
        )
        return {
            "current_task": None, "last_tool_result": None, "tool_results": None,
            "last_error": f"LLM required but provider unavailable: {decision.llm_error_category}",
            "planner_decisions": decision_list,
            "outcome": EngagementOutcome.llm_unavailable.value,
            "termination_reason": (
                f"llm_required=True; confirmed permanent provider failure: "
                f"{decision.llm_error_category}"
            ),
            "termination_phase": state["phase"],
        }

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


def _ensure_runtime_reference(deps: "OrchestrationDeps", cap: Any, target: str) -> None:
    """Mint a fresh :class:`~apex_host.capabilities.runtime_references.RuntimeReference`
    for *cap* when the registry's current generation for it is not already
    backed by a live, non-revoked reference (Phase 24).

    Dry-run guarantee: when ``config.dry_run`` is ``True``, this function
    never calls ``store.mint()`` — no ``RuntimeReference`` object of any
    kind is ever created in dry-run mode, mirroring
    ``DryRunToolBackend``'s own unconditional-safety discipline. This is
    additive bookkeeping only; it never affects whether registration
    itself succeeded (``register_capability_adapter``'s own return value,
    written back as ``runtime_available``, is unaffected by whether a
    reference was minted).
    """
    if deps.config.dry_run:
        return
    generation = deps.capability_registry.generation_for(cap.capability_id)
    if generation < 1:
        return
    current = deps.runtime_reference_store.current_reference_for(cap.capability_id)
    if current is not None and not current.revoked and current.generation == generation:
        return
    deps.runtime_reference_store.mint(
        capability_id=cap.capability_id,
        target=target,
        capability_type=cap.capability_type,
        generation=generation,
        authorization_scope_id=deps.config.target,
        ttl_seconds=float(getattr(deps.config, "capability_runtime_reference_ttl_seconds", 0.0) or 0.0),
    )


def _invalidate_on_connection_failure(deps: "OrchestrationDeps", tool_result: dict[str, Any] | None) -> None:
    """Runtime invalidation trigger: a ``user_flag_verify`` result whose
    ``connected`` field is ``False`` means the underlying access mechanism
    (an SSH session, a bounded command strategy, ...) failed at the
    connection/authentication/backend layer — a runtime-context-
    invalidating failure, distinct from a merely-informative read failure
    (e.g. "no such file", which still means ``connected=True``; see
    ``BoundedReadResult.connected``'s own docstring). On this signal, the
    stale adapter/reference is torn down so the NEXT objective turn's
    registration loop attempts a fresh registration rather than silently
    reusing a dead adapter forever (Phase 24 — the ``ensure_*`` methods on
    ``CapabilityRuntimeRegistry`` are otherwise idempotent-forever)."""
    if not tool_result or tool_result.get("tool") != "user_flag_verify":
        return
    if tool_result.get("connected", True):
        return
    capability_id = str(tool_result.get("capability_id") or "")
    if not capability_id:
        return
    deps.capability_registry.unregister(capability_id)
    deps.runtime_reference_store.invalidate_for_capability(
        capability_id, reason=RuntimeReferenceError.session_invalid.value,
    )


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

    Phase 24: every successful registration also mints (or reuses) a
    :class:`~apex_host.capabilities.runtime_references.RuntimeReference`
    tied to the registry's own generation counter for that capability —
    see ``_ensure_runtime_reference``. After dispatching, a
    ``user_flag_verify`` result reporting ``connected=False`` (a
    connection/session-level failure, not a mere "file not found") tears
    down the stale adapter/reference so the next turn registers fresh —
    see ``_invalidate_on_connection_failure``.
    """
    async def objective_agent(state: "ApexGraphState") -> dict[str, Any]:
        try:
            pre_subgraph = await deps.api.get_subgraph(deps.anchor_id, depth=2)
            for cap in access_capabilities_from_subgraph(pre_subgraph):
                if not cap.validated:
                    continue
                if deps.capability_registry.has(cap.capability_id):
                    _ensure_runtime_reference(deps, cap, state["target"])
                    continue
                registered = register_capability_adapter(
                    config=deps.config, capability_registry=deps.capability_registry,
                    subgraph=pre_subgraph, target=state["target"], cap=cap,
                )
                if registered:
                    _ensure_runtime_reference(deps, cap, state["target"])
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
            _invalidate_on_connection_failure(deps, result.get("last_tool_result"))
        except Exception as exc:
            logger.debug("objective_agent: runtime invalidation check failed: %s", exc)
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
