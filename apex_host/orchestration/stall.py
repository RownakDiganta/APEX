# stall.py
# Bounded stall detector: tracks consecutive no-progress turns and produces a StallDecision once a threshold is crossed.
"""Bounded stall detection for the APEX orchestration layer (Phase 12C).

``StallTracker`` accumulates a small set of streak counters — one per stall
category — across the turns of a single engagement, and resets them the
moment genuine progress is observed. It never allows the engagement to loop
forever: once any streak reaches ``threshold`` consecutive turns, it reports
a ``StallDecision`` that ``apex_host.orchestration.outcome.evaluate_termination()``
turns into a terminal outcome.

Persistence scope (documented limitation): like ``GlobalPlanner``'s own
per-phase budget counters (``_spent``), a ``StallTracker`` instance lives in
``OrchestrationDeps`` — constructed fresh per engagement, not persisted in
``ApexGraphState`` and therefore not restored across a checkpoint resume.
This mirrors the existing, accepted precedent for ``GlobalPlanner`` rather
than introducing a new, inconsistent persistence model.
"""
from __future__ import annotations

from dataclasses import dataclass

from apex_host.orchestration.outcome import EngagementOutcome


@dataclass(slots=True)
class StallDecision:
    """One call's stall-detection result."""

    stalled: bool
    outcome: EngagementOutcome | None
    reason: str


class StallTracker:
    """Bounded, resettable stall detector — see module docstring.

    ``threshold`` is the number of *consecutive* qualifying turns required
    before a stall is reported (default 3 — matches the phase budget
    ceilings' order of magnitude in ``GlobalPlanner``, generous enough not
    to fire on a single transient hiccup, bounded enough to never spin
    forever).
    """

    def __init__(self, threshold: int = 3) -> None:
        self._threshold = max(1, threshold)
        self._prev_duplicate_count = 0
        self._prev_policy_count = 0
        self._last_state_fingerprint: str | None = None
        self._last_planner_fingerprint: str | None = None
        self._duplicate_streak = 0
        self._no_action_streak = 0
        self._policy_block_streak = 0
        self._stagnant_streak = 0

    def reset(self) -> None:
        """Clear every streak counter (used by tests and, defensively, on
        any turn that shows unambiguous forward progress)."""
        self._duplicate_streak = 0
        self._no_action_streak = 0
        self._policy_block_streak = 0
        self._stagnant_streak = 0

    def record_turn(
        self,
        *,
        had_action: bool,
        duplicate_actions: list[dict[str, object]],
        policy_decisions: list[dict[str, object]],
        planner_fingerprint: str | None,
        state_fingerprint: str,
    ) -> StallDecision:
        """Update streaks from one turn's signals and return a decision.

        Args:
            had_action: True when a real task was dispatched this turn
                (``state.get("current_task") is not None``).
            duplicate_actions: The full, accumulated
                ``state["duplicate_actions"]`` list (``operator.add``
                across turns) — this method tracks its own previous length
                internally to isolate what *this* turn contributed.
            policy_decisions: The full, accumulated
                ``state["policy_decisions"]`` list, same delta treatment.
            planner_fingerprint: A short string identifying "what the
                planner/phase is currently doing" (e.g.
                ``f"{phase}:{last_error}"``) — unchanged across turns
                signals the engagement is repeating itself.
            state_fingerprint: A short string identifying the EKG/phase
                shape this turn — unchanged across turns signals no graph
                progress is being made.
        """
        new_duplicates = duplicate_actions[self._prev_duplicate_count:]
        self._prev_duplicate_count = len(duplicate_actions)
        was_duplicate = bool(new_duplicates)

        new_policy = policy_decisions[self._prev_policy_count:]
        self._prev_policy_count = len(policy_decisions)
        was_policy_blocked = any(d.get("status") == "blocked" for d in new_policy)

        if was_duplicate:
            self._duplicate_streak += 1
        else:
            self._duplicate_streak = 0

        if not had_action and not was_policy_blocked:
            self._no_action_streak += 1
        else:
            self._no_action_streak = 0

        if was_policy_blocked:
            self._policy_block_streak += 1
        else:
            self._policy_block_streak = 0

        repeated_state = state_fingerprint == self._last_state_fingerprint
        repeated_planner = (
            planner_fingerprint is not None
            and planner_fingerprint == self._last_planner_fingerprint
        )
        if repeated_state or repeated_planner:
            self._stagnant_streak += 1
        else:
            self._stagnant_streak = 0
        self._last_state_fingerprint = state_fingerprint
        self._last_planner_fingerprint = planner_fingerprint

        # Progress resets every streak — a genuine new (non-duplicate,
        # non-policy-blocked) action this turn means the engagement is not
        # stuck, regardless of what the other counters currently read.
        progress = had_action and not was_duplicate and not was_policy_blocked
        if progress:
            self.reset()

        if self._duplicate_streak >= self._threshold:
            return StallDecision(
                True, EngagementOutcome.duplicate_task_stall,
                f"{self._duplicate_streak} consecutive turns produced only duplicate tasks",
            )
        if self._policy_block_streak >= self._threshold:
            return StallDecision(
                True, EngagementOutcome.policy_blocked,
                f"{self._policy_block_streak} consecutive turns were blocked by policy",
            )
        if self._no_action_streak >= self._threshold:
            return StallDecision(
                True, EngagementOutcome.no_actionable_task,
                f"{self._no_action_streak} consecutive turns produced no actionable task",
            )
        if self._stagnant_streak >= self._threshold:
            return StallDecision(
                True, EngagementOutcome.duplicate_task_stall,
                f"{self._stagnant_streak} consecutive turns with no planner/state change",
            )
        return StallDecision(False, None, "")
