# metrics.py
# Simple, dependency-free metrics summariser that computes engagement coverage counts from a completed ApexGraphState.
"""Simple, dependency-free metrics over an ApexGraphState's findings/turns."""
from __future__ import annotations

from dataclasses import dataclass

from apex_host.graph_state import ApexGraphState


@dataclass(slots=True)
class EngagementMetrics:
    turns_used: int
    findings_count: int
    reached_phase: str
    completed: bool


def summarize(state: ApexGraphState) -> EngagementMetrics:
    # Phase 12C: `state["phase"]` is always "done" once an engagement
    # terminates (the canonical outcome model — see
    # apex_host.orchestration.outcome) — `termination_phase` records the
    # phase the engagement was actually in when it stopped, which is what
    # "reached_phase" has always meant here. Falls back to `phase` for a
    # state that never terminated (termination_phase still "").
    return EngagementMetrics(
        turns_used=state["turn_count"],
        findings_count=len(state["findings"]),
        reached_phase=state.get("termination_phase") or state["phase"],
        completed=state["completed"],
    )
