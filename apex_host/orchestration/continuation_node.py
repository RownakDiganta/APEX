# continuation_node.py
# Factory for the reflect_or_continue LangGraph node: canonical termination evaluation, stall detection, and dynamic replanning.
"""Continuation node factory for the APEX orchestration layer.

``make_continuation_node`` returns the ``reflect_or_continue`` async
LangGraph node — the single place every graph-internal termination reason
is decided (Phase 12C; success redefined in Phase 18). After each turn it:

1. Peeks at the live EKG (bounded, best-effort — a failed peek degrades
   gracefully rather than crashing the turn).
2. Applies the outcome precedence documented in
   ``apex_host.orchestration.outcome`` (module docstring): the configured
   objective being verified first, unconditionally (Phase 18 — NOT a bare
   ``access_state``, which is an intermediate milestone only); then any
   upstream-preset outcome (``state["outcome"]`` already set by
   ``dispatch_node``/``parsing_node``/``memory_node`` this turn); then
   stall detection; then phase-budget/max-turns exhaustion.
3. On termination, writes the single canonical terminal ``Episode``
   (``apex_host.orchestration.terminal_episode``) and threads
   ``outcome``/``termination_reason``/``termination_phase``/``stall_reason``
   into state.
4. Otherwise, peeks at the next phase (without charging GlobalPlanner's
   budget — ``global_plan`` charges it at the start of the next turn).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.outcome import (
    EngagementOutcome,
    TerminationDecision,
    evaluate_termination,
)
from apex_host.orchestration.terminal_episode import terminal_state_fields, write_terminal_episode
from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planners.objective import objective_status_from_subgraph
from apex_host.planners.workflow_orchestration import (
    build_workflow_graph_deltas,
    derive_sessions_from_subgraph,
    derive_workflows_from_subgraph,
    workflow_summary_fields,
)
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from memfabric.types import SubgraphView

    from apex_host.orchestration.dependencies import OrchestrationDeps

logger = logging.getLogger(__name__)


def _state_fingerprint(phase: str, node_types_seen: set[str]) -> str:
    """A short, deterministic signature of "where the engagement currently
    is" — unchanged across turns signals no graph progress is being made.
    Used only by the stall detector; never persisted, never exposed."""
    return phase + "|" + ",".join(sorted(node_types_seen))


def make_continuation_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``reflect_or_continue`` async node bound to *deps*."""

    async def reflect_or_continue(state: "ApexGraphState") -> dict[str, Any]:
        turn_count = state["turn_count"] + 1
        current_phase = state["phase"]

        subgraph: "SubgraphView | None" = None
        node_types_seen: set[str] = set()
        try:
            subgraph = await deps.api.get_subgraph(deps.anchor_id, depth=2)
            node_types_seen = {n.type for n in subgraph.nodes}
        except Exception as exc:
            # Graceful degradation for a single transient EKG-read failure —
            # matches memfabric's own "graceful degradation" philosophy
            # (CLAUDE.md §2). A *persistent* failure surfaces indirectly via
            # the stall detector's stagnant-state-fingerprint signal below
            # (an empty node_types_seen never changes turn over turn), which
            # eventually produces a duplicate_task_stall termination rather
            # than spinning silently until max_turns.
            logger.warning("reflect_or_continue: EKG peek failed: %s", exc)

        # Phase 15: reify GlobalPlanner's existing dependency ordering into
        # explicit, persisted workflow/session/recommendation EKG data,
        # reusing the SAME subgraph snapshot above (no extra read). A failed
        # sync degrades gracefully — it never affects termination decisions,
        # and the final report re-derives independently from the complete
        # final EKG regardless of whether this per-turn sync ever ran (see
        # docs/workflow-orchestration.md).
        workflow_fields: dict[str, Any] = {}
        if subgraph is not None:
            try:
                workflows = derive_workflows_from_subgraph(state["target"], subgraph)
                sessions = derive_sessions_from_subgraph(state["target"], subgraph)
                wf_nodes, wf_edges = build_workflow_graph_deltas(state["target"], workflows, sessions)
                if wf_nodes:
                    await deps.api.apply_deltas(nodes=wf_nodes, edges=wf_edges)
                workflow_fields = workflow_summary_fields(state["target"], subgraph)
            except Exception as exc:
                logger.debug("reflect_or_continue: workflow sync failed: %s", exc)

        # Phase 18: a validated access_state is an intermediate milestone
        # only — success requires the configured objective (default
        # "user_flag") to be VERIFIED. See apex_host.orchestration.outcome
        # module docstring "Success invariant".
        objective_status = "pending"
        if subgraph is not None:
            objective_status = objective_status_from_subgraph(
                subgraph, state["target"], deps.config.objective_type
            )
        objective_verified = objective_status == "verified"

        # --- Outcome precedence level 1: objective verification always wins. ---
        if objective_verified:
            decision = TerminationDecision(
                terminate=True, outcome=EngagementOutcome.user_flag_verified, success=True,
                reason="configured objective verified — evidence recorded in the EKG",
                phase=current_phase, turn=turn_count,
            )
        else:
            # --- Precedence level 2: an upstream node already decided. ---
            upstream_outcome = state.get("outcome")
            if upstream_outcome:
                decision = TerminationDecision(
                    terminate=True, outcome=EngagementOutcome(upstream_outcome), success=False,
                    reason=state.get("termination_reason") or "",
                    phase=state.get("termination_phase") or current_phase,
                    turn=turn_count,
                )
            else:
                # --- Precedence levels 3-5: stall / phase-budget / max-turns. ---
                # Default: unchanged from current_phase when the peek below
                # doesn't run or doesn't resolve — evaluate_termination()'s
                # own turn_count>=max_turns fallback still fires correctly
                # in that case (it does not depend on next_phase_value).
                next_phase_value = current_phase
                if turn_count < deps.config.max_turns:
                    try:
                        peek_caps = capabilities_from_subgraph(subgraph) if subgraph else []
                        has_web_peek = any(c.name == "web_probe" for c in peek_caps)
                        # F08: pass current_phase so budget force-advance fires
                        # correctly during the inter-turn peek (without
                        # charging the budget counter).
                        next_phase = deps.global_planner.decide_phase(
                            node_types_seen=node_types_seen,
                            turn_count=turn_count,
                            has_web_capability=has_web_peek,
                            current_phase=state.get("phase"),
                            objective_status=objective_status,
                        )
                        next_phase_value = next_phase.value
                    except Exception as exc:
                        logger.debug("reflect_or_continue: dynamic replan peek failed (%s)", exc)

                planner_fingerprint = f"{current_phase}:{state.get('last_error') or ''}"
                state_fp = _state_fingerprint(current_phase, node_types_seen)
                stall = deps.stall_tracker.record_turn(
                    had_action=state.get("current_task") is not None,
                    duplicate_actions=list(state.get("duplicate_actions") or []),
                    policy_decisions=list(state.get("policy_decisions") or []),
                    planner_fingerprint=planner_fingerprint,
                    state_fingerprint=state_fp,
                )

                decision = evaluate_termination(
                    max_turns=deps.config.max_turns, turn_count=turn_count,
                    objective_verified=False, next_phase=next_phase_value,
                    current_phase=current_phase, stall=stall,
                )
                if not decision.terminate:
                    return {
                        "turn_count": turn_count, "completed": False,
                        "phase": next_phase_value, "repair_count": 0,
                        **workflow_fields,
                    }

        # --- Terminating this turn: write the one canonical episode. ---
        logger.info(
            "engagement terminating: outcome=%s phase=%s turn=%d reason=%s",
            decision.outcome.value if decision.outcome else "?",
            decision.phase, decision.turn, decision.reason,
        )
        await write_terminal_episode(deps.api, decision, run_id=state["run_id"])

        result: dict[str, Any] = {
            "turn_count": turn_count, "completed": True,
            "phase": ApexPhase.done.value, "repair_count": 0,
        }
        result.update(workflow_fields)
        result.update(terminal_state_fields(decision))
        return result

    return reflect_or_continue
