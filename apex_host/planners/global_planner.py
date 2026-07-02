# global_planner.py
# Rule-based global phase router that decides which ApexPhase the engagement should enter next based on observed EKG node types and the turn budget.
"""Rule-based phase router for the top-level APEX engagement.

Unlike the other planners in this package, GlobalPlanner does not implement
memfabric.coordination.protocols.Planner (it doesn't emit TaskSpecs) — it
decides which ApexPhase the engagement should be in next, based on which
node types have been observed so far and the turn budget. apex_host/graph.py
calls it directly from the ``global_plan`` node.
"""
from __future__ import annotations

from apex_host.types import ApexPhase

_PHASE_GOALS: dict[ApexPhase, str] = {
    ApexPhase.recon: "Perform reconnaissance on {target}",
    ApexPhase.web: "Enumerate web endpoints on {target}",
    ApexPhase.credential: "Probe authentication flows on {target}",
    ApexPhase.priv_esc: "Enumerate privilege-escalation surface on {target}",
    ApexPhase.exploit: "Investigate exploitation surface on {target}",
    ApexPhase.lateral: "Investigate lateral-movement surface on {target}",
    ApexPhase.done: "Engagement on {target} complete",
}


class GlobalPlanner:
    """Deterministic phase router. LLM seam: swap ``decide_phase`` for an
    LLM-backed implementation later without touching graph.py."""

    def __init__(self, max_turns: int) -> None:
        self._max_turns = max_turns

    def decide_phase(self, *, node_types_seen: set[str], turn_count: int) -> ApexPhase:
        if turn_count >= self._max_turns:
            return ApexPhase.done
        if "host" not in node_types_seen:
            return ApexPhase.recon
        if "endpoint" not in node_types_seen:
            return ApexPhase.web
        if "auth_flow" not in node_types_seen:
            return ApexPhase.credential
        if "service" in node_types_seen:
            return ApexPhase.priv_esc
        return ApexPhase.done

    def goal_for_phase(self, phase: ApexPhase, target: str) -> str:
        return _PHASE_GOALS[phase].format(target=target)
