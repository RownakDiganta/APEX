# diagnostics_node.py
# Factory for the unknown_phase_agent LangGraph node: handles unroutable ApexPhase values without a silent END.
"""Diagnostic termination node for the APEX orchestration layer.

``make_unknown_phase_node`` returns the ``unknown_phase_agent`` async node.
It is reached only via ``routing.route_after_global_plan`` when the current
turn's phase is not ``web``, not in ``routing.PHASE_NODE``, and not
``ApexPhase.done`` — i.e. a genuinely unroutable phase value (for example a
not-yet-dispatchable ``ApexPhase`` member such as ``exploit``/``lateral``, or
any other unexpected string).

Before Phase 12A (R1, Bug E), an unroutable phase fell straight through to
LangGraph's ``END`` with no episode, no error message, and no trace of why
the engagement stopped — indistinguishable from a normal successful
completion. This node makes that failure mode explicit instead, using the
same canonical outcome model and terminal-episode writer every other
termination reason uses (Phase 12C — ``apex_host.orchestration.outcome``/
``terminal_episode``): it writes the one terminal ``Episode`` describing
exactly which phase was unroutable and at what turn, threads
``outcome=unknown_phase``/``termination_reason``/``termination_phase`` into
state (plus the pre-existing ``diagnostic_events`` field, checkpoint-visible
without querying the episodic store), and marks the engagement
``completed`` so the graph terminates cleanly on the very next edge
(``sg.add_edge(UNKNOWN_PHASE_NODE, END)`` in ``builder.py`` — this node
never visits ``reflect_or_continue``, so it can never produce a second
terminal episode for the same engagement).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.outcome import EngagementOutcome, TerminationDecision
from apex_host.orchestration.terminal_episode import terminal_state_fields, write_terminal_episode
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps


def make_unknown_phase_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``unknown_phase_agent`` async node bound to *deps*."""

    async def unknown_phase_agent(state: "ApexGraphState") -> dict[str, Any]:
        phase = state["phase"]
        turn_count = state["turn_count"]
        reason = (
            f"GlobalPlanner produced unroutable phase {phase!r} at turn "
            f"{turn_count} — no dispatch node is registered for it "
            "(routing.PHASE_NODE has no entry and it is not 'web' or 'done'). "
            "Terminating the engagement cleanly instead of silently reaching END."
        )
        decision = TerminationDecision(
            terminate=True, outcome=EngagementOutcome.unknown_phase, success=False,
            reason=reason, phase=phase, turn=turn_count,
        )
        await write_terminal_episode(deps.api, decision, run_id=state["run_id"])

        event: dict[str, Any] = {"phase": phase, "turn_count": turn_count, "reason": reason}
        result: dict[str, Any] = {
            "completed": True,
            "phase": ApexPhase.done.value,
            "last_error": reason,
            "diagnostic_events": [event],
        }
        result.update(terminal_state_fields(decision))
        return result

    return unknown_phase_agent
