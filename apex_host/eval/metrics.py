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
    return EngagementMetrics(
        turns_used=state["turn_count"],
        findings_count=len(state["findings"]),
        reached_phase=state["phase"],
        completed=state["completed"],
    )
