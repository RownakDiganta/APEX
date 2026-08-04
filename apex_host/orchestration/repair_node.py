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

from memfabric.ids import new_id
from memfabric.types import Episode, TaskSpec

from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.execution.registry import TaskStatus
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.completion import outcome_for
from apex_host.orchestration.parsing_node import (
    apply_parsed_observation,
    parse_result_and_collect_evidence,
    run_pending_capability_discovery,
)
from apex_host.planning.fingerprint import task_fingerprint
from apex_host.tools.backend import backend_capability_mode

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps

logger = logging.getLogger(__name__)


def _action_fingerprint(task: TaskSpec, phase: str, capability_mode: str) -> str:
    """Compute the SAME canonical action fingerprint
    ``TaskDispatcher.dispatch()`` computes for *task* — used here, before
    dispatch, to detect whether a repaired task is a materially different
    action from the one that just failed (Phase 2, post-live-test
    debugging)."""
    return task_fingerprint(
        phase,
        str(task.params.get("tool", "")),
        [str(a) for a in task.params.get("args", [])],
        str(task.params.get("target", "")),
        parser=str(task.params.get("parser", "command")),
        executor_domain=task.executor_domain,
        capability_mode=capability_mode,
    )


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
        new_repair_count = int(state.get("repair_count") or 0) + 1
        capability_mode = backend_capability_mode(deps.config)

        # ── Deterministic, bounded raw-socket repair (runs BEFORE the LLM
        # repair path). A classified nmap ``raw_socket_permission_denied``
        # failure is rewritten ONCE to the equivalent unprivileged ``-sT``
        # scan; a failure that ALREADY used ``-sT`` (or was a UDP scan) is
        # terminal rather than looping. See
        # apex_host.tools.nmap_command.plan_raw_socket_repair.
        failed_tool = str(failed_task_params.get("tool", ""))
        error_category = str(tool_result.get("error_category") or "")
        repaired_task: TaskSpec
        repair_kind = "llm"
        if failed_tool == "nmap" and error_category == "raw_socket_permission_denied":
            from apex_host.tools.nmap_command import plan_raw_socket_repair

            # Decide on the command that ACTUALLY executed (the normalized args
            # recorded on the tool result — which already include any injected
            # --unprivileged/-Pn), falling back to the planner args. This makes
            # the terminal-vs-rewrite decision honest: a scan that already ran
            # with --unprivileged -Pn -sT and still failed is terminal.
            executed_args = tool_result.get("args")
            failed_args = [
                str(a) for a in (executed_args if executed_args else failed_task_params.get("args", []))
            ]
            rs_target = str(failed_task_params.get("target", deps.config.target))
            plan = plan_raw_socket_repair(failed_args, rs_target)
            if plan.terminal:
                terminal_fp = _action_fingerprint(failed_task, state["phase"], capability_mode)
                await deps.dispatcher.task_registry.update_status(
                    terminal_fp, TaskStatus.FAILED_TERMINAL,
                )
                logger.info("repair_agent: nmap raw-socket failure is terminal — %s", plan.reason)
                return {
                    "repair_count": new_repair_count,
                    "duplicate_actions": [{
                        "fingerprint": terminal_fp, "tool": "nmap", "target": rs_target,
                        "phase": state["phase"], "disposition": "raw_socket_terminal",
                        "reason": plan.reason,
                        "meaningful_state_change": False,
                        "repair_changed_action": False,
                    }],
                    "repair_log": [{
                        "kind": "raw_socket_to_tcp_connect", "tool": "nmap",
                        "target": rs_target, "phase": state["phase"],
                        "outcome": "terminal", "changed_action": False,
                        "reason": plan.reason,
                    }],
                }
            repaired_task = TaskSpec(
                id=new_id(), goal_id=state["run_id"],
                executor_domain=failed_task.executor_domain,
                params={**dict(failed_task_params), "args": list(plan.repaired_args or [])},
                subgraph_anchor=deps.anchor_id, phase=state["phase"],
            )
            repair_kind = "raw_socket_to_tcp_connect"
        else:
            repair_result = await deps.repair_engine.repair(
                failed_task=failed_task, error=error, phase=state["phase"],
                evidence=evidence, subgraph=subgraph,
                repair_attempt=int(state.get("repair_count") or 0),
            )
            if repair_result is None:
                logger.debug("repair_agent: no repair available for phase=%s", state["phase"])
                return {
                    "repair_count": new_repair_count,
                    "repair_log": [{
                        "kind": "llm", "tool": failed_tool,
                        "target": str(failed_task_params.get("target", deps.config.target)),
                        "phase": state["phase"], "outcome": "no_repair",
                        "changed_action": False,
                        "reason": "no repair available (dry-run, fake router, or engine declined)",
                    }],
                }
            repaired_task = repair_result.repaired_task

        r_tool = str(repaired_task.params.get("tool", ""))
        r_target = str(repaired_task.params.get("target", deps.config.target))

        # Phase 2 (post-live-test debugging): if the repaired task is the
        # EXACT SAME canonical action as the one that just failed (same
        # tool, normalized args, target, phase, parser, executor_domain,
        # backend capability mode — see
        # apex_host.planning.fingerprint.task_fingerprint), classify it as
        # repair_no_change and reject it BEFORE dispatch — it must not
        # consume another execution turn, and must not silently re-run
        # the identical failing command. Recorded in duplicate_actions
        # (never as an execution episode) so the report shows exactly why
        # no new action was taken.
        original_fp = _action_fingerprint(failed_task, state["phase"], capability_mode)
        repaired_fp = _action_fingerprint(repaired_task, state["phase"], capability_mode)

        if repaired_fp == original_fp:
            logger.info(
                "repair_agent: repair produced no change (fingerprint=%s phase=%s) — "
                "rejecting before dispatch",
                repaired_fp, state["phase"],
            )
            no_change_entry = {
                "fingerprint": repaired_fp,
                "tool": r_tool,
                "target": r_target,
                "phase": state["phase"],
                "disposition": "repair_no_change",
                "reason": "repair produced the same normalized action as the original failure",
                "meaningful_state_change": False,
                "repair_changed_action": False,
            }
            return {
                "repair_count": new_repair_count,
                "duplicate_actions": [no_change_entry],
                "repair_log": [{
                    "kind": repair_kind, "tool": r_tool, "target": r_target,
                    "phase": state["phase"], "outcome": "no_change",
                    "changed_action": False,
                    "reason": "repair produced the same normalized action as the original failure",
                }],
            }

        # Repair produced a materially different action — mark the
        # ORIGINAL fingerprint as superseded (audit-distinguishable from
        # an unresolved terminal failure; still suppresses future blind
        # resubmission of the SAME original action) before dispatching
        # the repaired one.
        await deps.dispatcher.task_registry.update_status(original_fp, TaskStatus.SUPERSEDED)

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
                "repair_log": [{
                    "kind": repair_kind, "tool": r_tool, "target": r_target,
                    "phase": state["phase"], "outcome": "failed",
                    "changed_action": True,
                    "reason": f"repaired action not executed ({repair_dr.disposition.value})",
                }],
            }

        repaired_tr: dict[str, Any] = dict(repair_dr.tool_result_dict)
        repaired_tr["repaired"] = True
        repaired_tr["repair_kind"] = repair_kind
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
            "repair_log": [{
                "kind": repair_kind, "tool": r_tool, "target": r_target,
                "phase": state["phase"],
                "outcome": "succeeded" if not r_error else "failed",
                "changed_action": True,
                "reason": (
                    "repaired action executed successfully" if not r_error
                    else f"repaired action executed but failed: {r_error}"
                ),
            }],
        }
        result.update(
            await run_pending_capability_discovery(
                deps, [capability_evidence] if capability_evidence is not None else [],
            )
        )
        return result

    return repair_agent
