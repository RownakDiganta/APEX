# budget.py
# LLMBudgetTracker: tracks LLM call counts, enforces per-run and per-phase call limits, and detects repeated context.
"""LLM call budget tracking for the APEX planning layer.

``LLMBudgetTracker`` is a plain Python object (not stored in graph state)
that enforces two configurable limits on real LLM calls:

1. **Global budget** — at most ``max_per_run`` calls across the entire run.
2. **Per-phase budget** — at most ``max_per_phase`` calls for any single phase.

When either limit is exhausted, ``PlanningEngine`` falls back to the
deterministic planner automatically rather than calling the LLM.

Repeated-context detection
--------------------------
When ``stop_on_repeated_plan=True`` (the default), the tracker also detects
when the subgraph+evidence context has not changed since the last LLM call
for a given phase.  If the context is identical, skipping the LLM is safe
(it would produce the same plan) and saves one API call.  The context hash
is a lightweight structural fingerprint: ``len(nodes):len(edges):len(evidence)``.

Metrics
-------
``to_dict()`` returns a JSON-serialisable metrics summary included in the
run report's ``llm_usage`` section.  Per-call details are stored in
``call_metrics`` (one dict per attempted call).

Design rules
------------
- No I/O, no LLM calls, no MemoryAPI access.
- Created in ``ApexRuntime.run()``; shared via closures into each
  ``PlanningEngine`` — never stored in ``ApexGraphState`` (memfabric
  Invariant 1 and 7).
- ``FakeModelRouter`` returns ``None`` for all roles, so the engine falls
  back to deterministic before the budget is ever consulted.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class LLMBudgetTracker:
    """Shared call-budget and metrics tracker for all ``PlanningEngine`` instances.

    Parameters
    ----------
    max_per_run:
        Maximum number of real LLM calls allowed for the entire run.
    max_per_phase:
        Maximum calls allowed for any single phase value.
    stop_on_repeated_plan:
        When ``True``, skip the LLM call if the subgraph+evidence context
        is unchanged since the last call for the same phase.
    enabled:
        When ``False``, ``can_call()`` always returns ``(True, "")``.
        Useful for testing the budget-absent code path.
    """

    def __init__(
        self,
        max_per_run: int = 5,
        max_per_phase: int = 2,
        stop_on_repeated_plan: bool = True,
        *,
        enabled: bool = True,
    ) -> None:
        self.max_per_run = max_per_run
        self.max_per_phase = max_per_phase
        self.stop_on_repeated_plan = stop_on_repeated_plan
        self.enabled = enabled

        # Aggregate counters
        self.calls_attempted: int = 0
        self.calls_succeeded: int = 0
        self.calls_failed: int = 0
        self.fallbacks: int = 0
        self.retries: int = 0
        self.total_elapsed_seconds: float = 0.0

        # Per-phase call counts
        self._phase_counts: dict[str, int] = {}

        # Last context hash per phase: phase → context_hash string.
        # Used to detect unchanged context (repeated plan skip).
        self._last_context: dict[str, str] = {}

        # Repeated-plan counters per phase (how many times we skipped because
        # context was unchanged)
        self._repeated_counts: dict[str, int] = {}

        # Per-call detail log (one entry per attempted call)
        self.call_metrics: list[dict[str, Any]] = []

        # Stop-reason (set when the run-level budget is exhausted)
        self.stop_reason: str = ""

    # ------------------------------------------------------------------ #
    # Budget enforcement
    # ------------------------------------------------------------------ #

    def can_call(self, phase: str) -> tuple[bool, str]:
        """Return ``(allowed, reason_if_blocked)``.

        ``reason_if_blocked`` is an empty string when allowed.
        """
        if not self.enabled:
            return True, ""

        if self.calls_attempted >= self.max_per_run:
            reason = (
                f"global LLM budget exhausted "
                f"({self.calls_attempted}/{self.max_per_run} calls used)"
            )
            if not self.stop_reason:
                self.stop_reason = reason
            return False, reason

        phase_count = self._phase_counts.get(phase, 0)
        if phase_count >= self.max_per_phase:
            reason = (
                f"per-phase LLM budget exhausted for phase={phase!r} "
                f"({phase_count}/{self.max_per_phase} calls used)"
            )
            return False, reason

        return True, ""

    def is_context_repeated(self, phase: str, context_hash: str) -> bool:
        """Return ``True`` if context hash is unchanged since last call for *phase*.

        Only fires when ``stop_on_repeated_plan=True`` and a prior context
        exists for the phase.
        """
        if not self.stop_on_repeated_plan or not self.enabled:
            return False
        last = self._last_context.get(phase)
        if last is None:
            return False
        return last == context_hash

    # ------------------------------------------------------------------ #
    # Recording
    # ------------------------------------------------------------------ #

    def record_call_start(self, phase: str) -> None:
        """Increment both global and per-phase call counters.

        Must be called exactly once at the point the engine decides to
        attempt an LLM call (after budget checks pass).
        """
        self.calls_attempted += 1
        self._phase_counts[phase] = self._phase_counts.get(phase, 0) + 1

    def record_success(
        self,
        phase: str,
        elapsed: float,
        task_count: int,
        context_hash: str,
        model: str = "",
    ) -> None:
        """Record a successful LLM call and update the stored context hash."""
        self.calls_succeeded += 1
        self.total_elapsed_seconds += elapsed
        self._last_context[phase] = context_hash
        call_num = self.calls_attempted
        self.call_metrics.append({
            "call_number": call_num,
            "phase": phase,
            "model": model,
            "elapsed_seconds": round(elapsed, 3),
            "success": True,
            "task_count": task_count,
            "error_category": "",
            "http_status": None,
        })
        logger.info(
            "LLM call %d/%d phase=%s model=%s elapsed=%.1fs result=success tasks=%d",
            call_num, self.max_per_run, phase, model or "?", elapsed, task_count,
        )

    def record_failure(
        self,
        phase: str,
        elapsed: float,
        error_category: str,
        http_status: int | None,
        model: str = "",
    ) -> None:
        """Record a failed LLM call (the engine used the fallback planner)."""
        self.calls_failed += 1
        self.fallbacks += 1
        self.total_elapsed_seconds += elapsed
        call_num = self.calls_attempted
        self.call_metrics.append({
            "call_number": call_num,
            "phase": phase,
            "model": model,
            "elapsed_seconds": round(elapsed, 3),
            "success": False,
            "task_count": 0,
            "error_category": error_category,
            "http_status": http_status,
        })
        status_str = f" status={http_status}" if http_status else ""
        logger.info(
            "LLM call %d/%d phase=%s model=%s elapsed=%.1fs result=failed%s fallback=true",
            call_num, self.max_per_run, phase, model or "?", elapsed, status_str,
        )

    def record_retry(self) -> None:
        """Increment the retry counter."""
        self.retries += 1

    def record_repeated_skip(self, phase: str) -> int:
        """Record that a plan was skipped due to repeated context.

        Returns the new repeated count for that phase.
        """
        count = self._repeated_counts.get(phase, 0) + 1
        self._repeated_counts[phase] = count
        logger.info(
            "planning_engine: context unchanged since last plan for phase=%s "
            "(skipped LLM call — repeated_count=%d)",
            phase, count,
        )
        return count

    def record_fallback_only(self) -> None:
        """Record that the deterministic path was used without any LLM attempt."""
        self.fallbacks += 1

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def budget_remaining(self) -> int:
        """Remaining global call budget."""
        return max(0, self.max_per_run - self.calls_attempted)

    # ------------------------------------------------------------------ #
    # Serialisation
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable metrics summary for the run report."""
        return {
            "enabled": self.enabled,
            "max_calls_per_run": self.max_per_run,
            "max_calls_per_phase": self.max_per_phase,
            "stop_on_repeated_plan": self.stop_on_repeated_plan,
            "calls_attempted": self.calls_attempted,
            "calls_succeeded": self.calls_succeeded,
            "calls_failed": self.calls_failed,
            "fallbacks": self.fallbacks,
            "retries": self.retries,
            "total_elapsed_seconds": round(self.total_elapsed_seconds, 3),
            "budget_remaining": self.budget_remaining,
            "stop_reason": self.stop_reason,
            "phase_counts": dict(self._phase_counts),
            "repeated_skips": dict(self._repeated_counts),
        }
