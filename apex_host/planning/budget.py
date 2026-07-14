# budget.py
# LLMBudgetTracker: atomic reservation-based LLM call budget with per-run, per-phase, and purpose limits.
"""LLM call budget tracking for the APEX planning layer.

``LLMBudgetTracker`` enforces call limits with **atomic reservations** so two
concurrent planning or repair coroutines can never jointly overspend a shared
budget.

Limits enforced:
1. **Global budget** — at most ``max_per_run`` calls per engagement run.
2. **Per-phase budget** — at most ``max_per_phase`` calls per phase value.

Atomic reservation model (replaces TOCTOU-prone check-then-act)
----------------------------------------------------------------
``budget.reserve(purpose, phase)`` acquires an asyncio.Lock, checks all
limits, atomically claims one call slot, and returns a ``BudgetReservation``
object.  The slot is held until the caller calls one of:

  - ``reservation.commit(actual_input_tokens, actual_output_tokens)``
    — records a successful invocation; slot remains consumed.
  - ``reservation.fail(known_usage)``
    — records a failed invocation; slot remains consumed.
  - ``reservation.release()``
    — returns the slot (pre-call block; provider was never invoked);
      decrements ``calls_attempted`` so the budget remains available.

Backward-compatible legacy interface
--------------------------------------
``can_call(phase)`` and ``record_call_start(phase)`` are still available for
code paths that do not use the reservation API.  They are safe to use
sequentially but have no atomicity guarantee against concurrent callers.
Use ``reserve()`` for all concurrent paths.

Checkpoint / resume
-------------------
``to_dict()`` and ``from_dict(d)`` serialize and deserialize tracker state.
No live objects (locks, reservations) are serialised.  Active reservations
are silently dropped on resume — callers must re-attempt any incomplete call.

Design rules
------------
- No I/O, no LLM calls, no MemoryAPI access.
- Created once in ``ApexRuntime.run()``; shared via closure into all
  ``PlanningEngine`` and ``RepairEngine`` instances — never stored in
  ``ApexGraphState``.
"""
from __future__ import annotations

import asyncio
import logging
import weakref
from dataclasses import dataclass, field
from typing import Any

from memfabric.ids import new_id

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# BudgetReservation — result of an atomic reserve() call
# ---------------------------------------------------------------------------


@dataclass
class BudgetReservation:
    """One atomically-claimed call slot.

    Lifecycle: ``open`` → ``committed`` | ``failed`` | ``released``.
    Exactly one of ``commit()``, ``fail()``, or ``release()`` must be called.
    Calling more than one raises ``RuntimeError``.
    """

    reservation_id: str
    purpose: str
    phase: str
    # Back-reference to the tracker; weakref so we don't create a cycle.
    _tracker_ref: "weakref.ref[LLMBudgetTracker]"

    committed: bool = field(default=False, init=False)
    failed: bool = field(default=False, init=False)
    released: bool = field(default=False, init=False)

    @property
    def is_settled(self) -> bool:
        return self.committed or self.failed or self.released

    def _require_open(self) -> None:
        if self.is_settled:
            raise RuntimeError(
                f"BudgetReservation {self.reservation_id} already settled "
                f"(committed={self.committed} failed={self.failed} released={self.released})"
            )

    async def commit(
        self,
        actual_input_tokens: int = 0,
        actual_output_tokens: int = 0,
    ) -> None:
        """Record a successful provider invocation.  Slot remains consumed."""
        self._require_open()
        self.committed = True
        tracker = self._tracker_ref()
        if tracker is None:
            return
        tracker._on_commit(self, actual_input_tokens, actual_output_tokens)

    async def fail(self, known_usage: int = 0) -> None:
        """Record a failed provider invocation.  Slot remains consumed."""
        self._require_open()
        self.failed = True
        tracker = self._tracker_ref()
        if tracker is None:
            return
        tracker._on_fail(self, known_usage)

    async def release(self) -> None:
        """Return the slot — provider was NOT invoked (pre-call block).

        Decrements ``calls_attempted`` so the freed slot is available for
        the next caller.
        """
        self._require_open()
        self.released = True
        tracker = self._tracker_ref()
        if tracker is None:
            return
        tracker._on_release(self)


# ---------------------------------------------------------------------------
# LLMBudgetTracker
# ---------------------------------------------------------------------------


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
        When ``False``, ``can_call()`` always returns ``(True, "")`` and
        ``reserve()`` always succeeds.  Useful for testing.
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

        # Last context hash per phase
        self._last_context: dict[str, str] = {}

        # Repeated-plan counters per phase
        self._repeated_counts: dict[str, int] = {}

        # Per-call detail log
        self.call_metrics: list[dict[str, Any]] = []

        # Stop-reason (set when the run-level budget is exhausted)
        self.stop_reason: str = ""

        # Atomic reservation lock — all reserve/release operations acquire this.
        self._lock: asyncio.Lock = asyncio.Lock()

        # Active reservation IDs (for leak detection in tests)
        self._active_reservations: set[str] = set()

    # ------------------------------------------------------------------ #
    # Atomic reservation API
    # ------------------------------------------------------------------ #

    async def reserve(
        self,
        purpose: str,
        phase: str,
    ) -> tuple[bool, str, BudgetReservation | None]:
        """Atomically claim one call slot.

        Acquires the internal lock, verifies all limits, increments counters,
        and returns ``(True, "", reservation)`` on success or
        ``(False, reason, None)`` when the budget is exhausted.

        The caller MUST eventually call ``reservation.commit()``,
        ``reservation.fail()``, or ``reservation.release()`` to settle the
        reservation; ``release()`` returns the slot if the provider was never
        invoked.
        """
        async with self._lock:
            if not self.enabled:
                res_id = new_id()
                reservation = BudgetReservation(
                    reservation_id=res_id,
                    purpose=purpose,
                    phase=phase,
                    _tracker_ref=weakref.ref(self),
                )
                # Not tracked — enabled=False means unlimited.
                return True, "", reservation

            if self.calls_attempted >= self.max_per_run:
                reason = (
                    f"global LLM budget exhausted "
                    f"({self.calls_attempted}/{self.max_per_run} calls used)"
                )
                if not self.stop_reason:
                    self.stop_reason = reason
                return False, reason, None

            phase_count = self._phase_counts.get(phase, 0)
            if phase_count >= self.max_per_phase:
                reason = (
                    f"per-phase LLM budget exhausted for phase={phase!r} "
                    f"({phase_count}/{self.max_per_phase} calls used)"
                )
                return False, reason, None

            # All checks passed — reserve atomically.
            self.calls_attempted += 1
            self._phase_counts[phase] = phase_count + 1

            res_id = new_id()
            self._active_reservations.add(res_id)
            reservation = BudgetReservation(
                reservation_id=res_id,
                purpose=purpose,
                phase=phase,
                _tracker_ref=weakref.ref(self),
            )
            return True, "", reservation

    # -- Reservation lifecycle callbacks (called by BudgetReservation) ---- #

    def _on_commit(
        self,
        reservation: BudgetReservation,
        actual_input_tokens: int,
        actual_output_tokens: int,
    ) -> None:
        self._active_reservations.discard(reservation.reservation_id)
        self.calls_succeeded += 1
        self.call_metrics.append({
            "reservation_id": reservation.reservation_id,
            "phase": reservation.phase,
            "purpose": reservation.purpose,
            "success": True,
            "actual_input_tokens": actual_input_tokens,
            "actual_output_tokens": actual_output_tokens,
            "error_category": "",
        })

    def _on_fail(self, reservation: BudgetReservation, known_usage: int) -> None:
        self._active_reservations.discard(reservation.reservation_id)
        self.calls_failed += 1
        self.call_metrics.append({
            "reservation_id": reservation.reservation_id,
            "phase": reservation.phase,
            "purpose": reservation.purpose,
            "success": False,
            "actual_input_tokens": known_usage,
            "actual_output_tokens": 0,
            "error_category": "provider_failure",
        })

    def _on_release(self, reservation: BudgetReservation) -> None:
        self._active_reservations.discard(reservation.reservation_id)
        # Return the slot so the next caller can use it.
        self.calls_attempted = max(0, self.calls_attempted - 1)
        phase = reservation.phase
        if phase in self._phase_counts:
            self._phase_counts[phase] = max(0, self._phase_counts[phase] - 1)

    # ------------------------------------------------------------------ #
    # Legacy API (backward compatible, not atomic against concurrent callers)
    # ------------------------------------------------------------------ #

    def can_call(self, phase: str) -> tuple[bool, str]:
        """Return ``(allowed, reason_if_blocked)`` — synchronous, non-atomic."""
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
        """Return ``True`` if context hash is unchanged since last call for *phase*."""
        if not self.stop_on_repeated_plan or not self.enabled:
            return False
        last = self._last_context.get(phase)
        if last is None:
            return False
        return last == context_hash

    def record_call_start(self, phase: str) -> None:
        """Increment both global and per-phase call counters (legacy API)."""
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
        """Record a failed LLM call."""
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
        """Record that a plan was skipped due to repeated context."""
        count = self._repeated_counts.get(phase, 0) + 1
        self._repeated_counts[phase] = count
        logger.info(
            "planning_engine: context unchanged since last plan for phase=%s "
            "(skipped LLM call — repeated_count=%d)",
            phase, count,
        )
        return count

    def record_context(self, phase: str, context_hash: str) -> None:
        """Update the stored context hash for repeated-context detection.

        Called by ``PlanningEngine._plan_via_gateway`` after a successful
        gateway invocation so that subsequent calls for the same phase can
        detect unchanged contexts without making an LLM call.
        """
        self._last_context[phase] = context_hash

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

    @property
    def active_reservation_count(self) -> int:
        """Number of reservations that have not yet been settled."""
        return len(self._active_reservations)

    # ------------------------------------------------------------------ #
    # Serialisation (checkpoint / resume)
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

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "LLMBudgetTracker":
        """Reconstruct a tracker from a ``to_dict()`` snapshot.

        Active reservations are NOT restored — callers must re-attempt any
        incomplete call after resume.  The lock is fresh; all counters are
        restored exactly.
        """
        tracker = cls(
            max_per_run=int(d.get("max_calls_per_run", 5)),
            max_per_phase=int(d.get("max_calls_per_phase", 2)),
            stop_on_repeated_plan=bool(d.get("stop_on_repeated_plan", True)),
            enabled=bool(d.get("enabled", True)),
        )
        tracker.calls_attempted = int(d.get("calls_attempted", 0))
        tracker.calls_succeeded = int(d.get("calls_succeeded", 0))
        tracker.calls_failed = int(d.get("calls_failed", 0))
        tracker.fallbacks = int(d.get("fallbacks", 0))
        tracker.retries = int(d.get("retries", 0))
        tracker.total_elapsed_seconds = float(d.get("total_elapsed_seconds", 0.0))
        tracker.stop_reason = str(d.get("stop_reason", ""))
        tracker._phase_counts = dict(d.get("phase_counts", {}))
        tracker._repeated_counts = dict(d.get("repeated_skips", {}))
        return tracker
