# diagnostics_node.py
# Factory for the unknown_phase_agent LangGraph node: handles unroutable ApexPhase values without a silent END.
"""Diagnostic termination node for the APEX orchestration layer.

``make_unknown_phase_node`` returns the ``unknown_phase_agent`` async node.
It is reached only via ``routing.route_after_global_plan`` when the current
turn's phase is not ``web``, not in ``routing.PHASE_NODE``, and not
``ApexPhase.done`` — i.e. a genuinely unroutable phase value (for example a
not-yet-dispatchable ``ApexPhase`` member such as ``exploit``/``lateral``, or
any other unexpected string).

Before this fix (Phase 12A / R1, Bug E), an unroutable phase fell straight
through to LangGraph's ``END`` with no episode, no error message, and no
trace of why the engagement stopped — indistinguishable from a normal
successful completion. This node makes that failure mode explicit instead:
it appends a diagnostic ``Episode`` describing exactly which phase was
unroutable and at what turn, records the same information in
``ApexGraphState.diagnostic_events`` (checkpoint-visible without querying
the episodic store), sets ``last_error``, and marks the engagement
``completed`` so the graph terminates cleanly on the very next edge.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memfabric.types import Episode, Outcome

from apex_host.graph_state import ApexGraphState
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps


def make_unknown_phase_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``unknown_phase_agent`` async node bound to *deps*."""

    async def unknown_phase_agent(state: "ApexGraphState") -> dict[str, Any]:
        phase = state["phase"]
        reason = (
            f"GlobalPlanner produced unroutable phase {phase!r} at turn "
            f"{state['turn_count']} — no dispatch node is registered for it "
            "(routing.PHASE_NODE has no entry and it is not 'web' or 'done'). "
            "Terminating the engagement cleanly instead of silently reaching END."
        )
        event: dict[str, Any] = {
            "phase": phase,
            "turn_count": state["turn_count"],
            "reason": reason,
        }

        episode = Episode(
            agent="apex.orchestration",
            action="unknown_phase_diagnostic",
            outcome=Outcome.fundamental,
            data=event,
            task_id=None,
            phase=phase,
        )
        await deps.api.apply_deltas(episodes=[episode])

        return {
            "completed": True,
            "phase": ApexPhase.done.value,
            "last_error": reason,
            "diagnostic_events": [event],
        }

    return unknown_phase_agent
