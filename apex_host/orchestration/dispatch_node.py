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

from memfabric.types import AbandonSignal, Goal, TaskSpec

from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.models import task_info
from apex_host.orchestration.outcome import EngagementOutcome
from apex_host.planners.priv_esc_opportunities import privilege_state_fields
from apex_host.planners.web_opportunities import web_session_state_fields
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps
    from memfabric.coordination.protocols import Planner

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
