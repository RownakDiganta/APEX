# terminal_episode.py
# Builds and writes the single canonical terminal Episode that marks how and why an engagement ended.
"""The one canonical terminal-episode writer (Phase 12C).

Exactly one terminal ``Episode`` is written per engagement, marking the
final ``TerminationDecision`` — never one of the ordinary per-tool-result
episodes ``apex_host/orchestration/memory_node.py`` writes every turn.
Both call sites that can end an engagement (``continuation_node.py`` for
every graph-internal outcome, and ``diagnostics_node.py`` for the
``unknown_phase`` special case) share this exact function so the episode
shape — and the "exactly one, never duplicated" guarantee — has a single
implementation, not two.

Writes go through ``MemoryAPI.apply_deltas`` (the same transactional path
every other episode write in this codebase uses — memfabric Invariant 1
and the "graph merge must be transactional" invariant, CLAUDE.md §"Graph
merge must be transactional").
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memfabric.types import Episode, Outcome

from apex_host.orchestration.outcome import TerminationDecision, is_success_outcome

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI


def build_terminal_episode(decision: TerminationDecision, *, run_id: str) -> Episode:
    """Build (but do not write) the terminal Episode for *decision*.

    Exposed separately from ``write_terminal_episode`` so tests can assert
    on the episode's shape without needing a live ``MemoryAPI``.
    """
    assert decision.outcome is not None  # only ever called when decision.terminate is True
    return Episode(
        agent="apex.orchestration",
        action="engagement_terminated",
        outcome=Outcome.success if is_success_outcome(decision.outcome) else Outcome.fundamental,
        data={
            "outcome": decision.outcome.value,
            "success": decision.success,
            "reason": decision.reason,
            "phase": decision.phase,
            "turn": decision.turn,
            "run_id": run_id,
        },
        task_id=None,
        phase=decision.phase,
    )


async def write_terminal_episode(
    api: "MemoryAPI", decision: TerminationDecision, *, run_id: str
) -> None:
    """Write the single terminal episode for *decision* via ``apply_deltas``.

    Callers are responsible for calling this at most once per engagement —
    both current call sites (``continuation_node.py``'s ``reflect_or_continue``
    and ``diagnostics_node.py``'s ``unknown_phase_agent``) are structurally
    mutually exclusive terminal nodes (see each module's own docstring), so
    "exactly one terminal episode" holds by construction, not by a runtime
    guard here.
    """
    episode = build_terminal_episode(decision, run_id=run_id)
    await api.apply_deltas(episodes=[episode])


def terminal_state_fields(decision: TerminationDecision) -> dict[str, Any]:
    """The ``ApexGraphState`` partial-update dict for a terminating turn.

    Shared by both call sites so the exact field shape
    (``outcome``/``termination_reason``/``termination_phase``/``stall_reason``)
    is defined in exactly one place.
    """
    assert decision.outcome is not None
    from apex_host.orchestration.outcome import EngagementOutcome

    fields: dict[str, Any] = {
        "outcome": decision.outcome.value,
        "termination_reason": decision.reason,
        "termination_phase": decision.phase,
        "stall_reason": "",
    }
    if decision.outcome in (
        EngagementOutcome.duplicate_task_stall,
        EngagementOutcome.no_actionable_task,
        EngagementOutcome.policy_blocked,
    ):
        fields["stall_reason"] = decision.reason
    return fields
