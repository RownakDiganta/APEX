# repair_node.py
# Factory for the repair_agent LangGraph node: LLM-backed task correction after failures.
"""Repair node factory for the APEX orchestration layer.

``make_repair_node`` returns the ``repair_agent`` async LangGraph node that
calls ``RepairEngine`` to produce a corrected ``TaskSpec`` when a task fails
with ``script_error`` or ``fixable`` outcome.  On success it parses and
writes the repaired observation through ``MemoryAPI`` (same path as normal
``parse_observation`` + ``write_memory``).

Safety invariants preserved:
- ``fundamental`` outcomes are never repaired (route_after_write sends them
  directly to ``reflect_or_continue``).
- Policy-blocked and conflict-blocked repaired tasks are not executed.
- ``RepairEngine`` returns ``None`` when ``dry_run=True`` (no real repair in
  dry-run mode) or when ``ModelRouter.planner_llm()`` returns None (deterministic
  fallback / fake router).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from memfabric.types import Episode, TaskSpec

from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.completion import outcome_for
from apex_host.orchestration.parsing_node import (
    apply_parsed_observation,
    parse_result_and_collect_evidence,
    run_pending_capability_discovery,
)

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps

logger = logging.getLogger(__name__)


def make_repair_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``repair_agent`` async node bound to *deps*."""

    async def repair_agent(state: "ApexGraphState") -> dict[str, Any]:
        tool_result = state.get("last_tool_result")
        if not tool_result:
            return {"repair_count": int(state.get("repair_count") or 0) + 1}

        failed_task_params = (state.get("current_task") or {}).get("params", {})
        error = str(tool_result.get("error") or state.get("last_error") or "non-zero returncode")

        failed_task = TaskSpec(
            id=str(tool_result.get("task_id", "unknown")),
            goal_id=state["run_id"],
            executor_domain=str((state.get("current_task") or {}).get("executor_domain", "recon")),
            params=dict(failed_task_params),
            subgraph_anchor=deps.anchor_id,
            phase=state["phase"],
        )
        anchor = deps.anchor_id
        subgraph = await deps.api.get_subgraph(anchor, depth=2)
        evidence = await deps.api.query(text=state["goal"], subgraph_anchor=anchor)

        repair_result = await deps.repair_engine.repair(
            failed_task=failed_task, error=error, phase=state["phase"],
            evidence=evidence, subgraph=subgraph,
            repair_attempt=int(state.get("repair_count") or 0),
        )
        new_repair_count = int(state.get("repair_count") or 0) + 1

        if repair_result is None:
            logger.debug("repair_agent: no repair available for phase=%s", state["phase"])
            return {"repair_count": new_repair_count}

        repaired_task: TaskSpec = repair_result.repaired_task
        r_tool = str(repaired_task.params.get("tool", ""))
        r_target = str(repaired_task.params.get("target", deps.config.target))

        repair_ctx = ExecutionContext(
            run_id=state["run_id"], phase=state["phase"], turn_number=state["turn_count"],
            evidence_version=None, subgraph=subgraph, evidence=evidence,
            dry_run=deps.config.dry_run, is_repair=True,
            repair_attempt=int(state.get("repair_count") or 0),
        )
        repair_dr = await deps.dispatcher.dispatch(repaired_task, repair_ctx)
        r_pd = dict(repair_dr.audit_metadata.get("policy_decision") or {})

        if repair_dr.disposition in (
            ExecutionDisposition.BLOCKED_POLICY,
            ExecutionDisposition.BLOCKED_CONFLICT,
            ExecutionDisposition.SKIPPED_DUPLICATE,
        ):
            return {
                "repair_count": new_repair_count,
                "policy_decisions": [r_pd] if r_pd else [],
            }

        repaired_tr: dict[str, Any] = dict(repair_dr.tool_result_dict)
        repaired_tr["repaired"] = True
        r_error = repaired_tr.get("error")

        # Phase 24: shared with parse_observation's own per-result body
        # (apex_host.orchestration.parsing_node) so a repaired ssh_access
        # success emits capability evidence identically to a
        # normally-dispatched one — see that module's docstring.
        parsed, _source, capability_evidence = parse_result_and_collect_evidence(
            repaired_tr, state, target=deps.config.target,
        )
        await apply_parsed_observation(deps, parsed)
        r_outcome = outcome_for(int(repaired_tr.get("returncode", 0) or 0), r_error)
        repair_episode = Episode(
            agent=f"apex.{state['phase']}.repair",
            action=f"repair/{r_tool} {r_target}".strip(),
            outcome=r_outcome, data=repaired_tr,
            task_id=repaired_task.id, phase=state["phase"],
        )
        await deps.api.apply_deltas(episodes=[repair_episode])

        result: dict[str, Any] = {
            "repair_count": new_repair_count, "last_tool_result": repaired_tr,
            "last_error": r_error, "policy_decisions": [r_pd] if r_pd else [],
        }
        result.update(
            await run_pending_capability_discovery(
                deps, [capability_evidence] if capability_evidence is not None else [],
            )
        )
        return result

    return repair_agent
