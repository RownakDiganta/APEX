# completion.py
# Pure functions for task-outcome classification and engagement-completion logic.
"""Pure completion and outcome helpers for the APEX orchestration layer.

These functions contain no I/O and no state mutations — they are safe to
call from routing functions and can be unit-tested in isolation.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memfabric.types import Outcome

if TYPE_CHECKING:
    from apex_host.graph_state import ApexGraphState


def outcome_for(returncode: int, error: str | None) -> Outcome:
    """Map a tool returncode + error string to a memfabric Outcome enum value."""
    if error:
        return Outcome.fixable if "timed out" in error else Outcome.fundamental
    if returncode != 0:
        return Outcome.script_error
    return Outcome.success


def is_repairable(
    tool_result: dict[str, Any],
    repair_count: int,
    max_repair: int,
) -> bool:
    """Return True when a tool_result warrants a repair attempt.

    Blocked-by-policy, conflict-blocked, browser, and skipped-duplicate
    results are never repairable.  Only ``script_error`` and ``fixable``
    outcomes within the repair budget are eligible.
    """
    if tool_result.get("kind") == "browser":
        return False
    if tool_result.get("conflict_blocked") or tool_result.get("skipped_duplicate"):
        return False
    if tool_result.get("policy_blocked"):
        return False
    o = outcome_for(
        int(tool_result.get("returncode", 0) or 0),
        tool_result.get("error"),
    )
    return o in (Outcome.script_error, Outcome.fixable) and repair_count < max_repair


def should_complete(state: "ApexGraphState", max_turns: int) -> bool:
    """Return True when the engagement should stop after this turn."""
    return bool(state["completed"]) or state["turn_count"] + 1 >= max_turns
