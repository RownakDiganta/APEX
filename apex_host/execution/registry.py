# registry.py
# TaskRegistry: atomic task deduplication registry with asyncio.Lock for concurrent safety.
"""Atomic task deduplication registry for the APEX dispatcher.

``TaskRegistry`` maintains a set of task records keyed by fingerprint.  The
``reserve()`` coroutine acquires an asyncio lock before the
check-and-register operation, ensuring that concurrent duplicate submissions
cannot both register as "first" even under cooperative multitasking.

Persistence:

    ``TaskRegistry.snapshot()`` returns a JSON-serialisable dict suitable for
    inclusion in ``ApexGraphState.completed_fingerprints`` (a new append-only
    field).  ``TaskRegistry.restore_from_snapshot()`` reconstructs the in-memory
    state from that dict so that resumed engagements do not re-execute completed
    tasks.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    """Lifecycle state of a registered task — the canonical action-outcome
    taxonomy (Phase 2, post-live-test debugging).

    ``PENDING``/``EXECUTING`` together represent "currently reserved / in
    flight" (a reservation has been made but the executor has not yet
    returned a terminal result). ``TIMED_OUT`` and ``FAILED_RETRYABLE``
    are both non-suppressing (retry-eligible) but distinct: ``TIMED_OUT``
    specifically means the executor's own timeout fired (as opposed to a
    non-timeout transient failure such as "connection refused", which is
    still recorded as ``FAILED_RETRYABLE``). ``SUPERSEDED`` means a
    RepairEngine-produced, materially-different action addressed this
    fingerprint's failure — the original fingerprint stays suppressed
    (its own broken action must never be blindly resubmitted) but is
    audit-distinguishable from an unresolved terminal failure. See
    ``apex_host.execution.dispatcher.TaskDispatcher.dispatch`` (status
    assignment) and ``apex_host.orchestration.repair_node`` (SUPERSEDED
    marking) for where each value is actually produced.
    """

    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED_RETRYABLE = "failed_retryable"
    FAILED_TERMINAL = "failed_terminal"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"
    POLICY_BLOCKED = "policy_blocked"
    CANCELLED = "cancelled"
    SKIPPED_DUPLICATE = "skipped_duplicate"
    SUPERSEDED = "superseded"

    @property
    def suppresses_new_submission(self) -> bool:
        """True when a new task with the same fingerprint should be suppressed."""
        return self in (
            TaskStatus.PENDING,
            TaskStatus.EXECUTING,
            TaskStatus.COMPLETED,
            TaskStatus.FAILED_TERMINAL,
            TaskStatus.SUPERSEDED,
        )


@dataclass
class TaskRecord:
    """A single task entry in the registry."""

    fingerprint: str
    task_id: str
    run_id: str
    phase: str
    evidence_version: str | None
    status: TaskStatus
    retry_count: int = 0
    disposition: str = ""
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "phase": self.phase,
            "evidence_version": self.evidence_version,
            "status": self.status.value,
            "retry_count": self.retry_count,
            "disposition": self.disposition,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TaskRecord":
        return cls(
            fingerprint=str(d.get("fingerprint", "")),
            task_id=str(d.get("task_id", "")),
            run_id=str(d.get("run_id", "")),
            phase=str(d.get("phase", "")),
            evidence_version=d.get("evidence_version"),
            status=TaskStatus(d.get("status", TaskStatus.COMPLETED.value)),
            retry_count=int(d.get("retry_count", 0)),
            disposition=str(d.get("disposition", "")),
            timestamp=str(d.get("timestamp", "")),
            metadata=dict(d.get("metadata", {})),
        )


class TaskRegistry:
    """Atomic duplicate registry for the APEX engagement run.

    ``reserve()`` is the primary entry point — it atomically checks and
    registers a fingerprint under ``asyncio.Lock`` so concurrent coroutines
    cannot both slip through the duplicate gate.

    ``update_status()`` updates the status of a previously registered task.

    ``snapshot()`` / ``restore_from_snapshot()`` provide checkpoint persistence
    so that resumed engagements skip already-completed tasks.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._records: dict[str, TaskRecord] = {}
        # Phase 2 (post-live-test debugging) — cumulative, 1-based attempt
        # count per fingerprint, incremented on every SUCCESSFUL reserve()
        # (whether the first-ever attempt or a legitimate resubmission
        # after a FAILED_RETRYABLE/TIMED_OUT status). Never decremented —
        # this is a lifetime counter for the fingerprint's action
        # identity, used by TaskDispatcher to bound how many times a
        # transiently-failing action may be resubmitted before it is
        # forced to FAILED_TERMINAL regardless of the per-attempt retry
        # classification (ApexConfig.max_fingerprint_retries).
        self._attempt_counts: dict[str, int] = {}

    async def reserve(
        self,
        *,
        fingerprint: str,
        task_id: str,
        run_id: str,
        phase: str,
        evidence_version: str | None = None,
        timestamp: str = "",
    ) -> tuple[bool, TaskRecord | None]:
        """Atomically check-and-reserve a fingerprint.

        Returns ``(True, new_record)`` when the reservation succeeds (no prior
        record suppresses this task).  Returns ``(False, existing_record)`` when
        a suppressing record already exists.

        The caller must call ``update_status(fingerprint, COMPLETED / FAILED_*
        / CANCELLED)`` when the task finishes so that later calls can make
        correct suppression decisions.
        """
        async with self._lock:
            existing = self._records.get(fingerprint)
            if existing is not None and existing.status.suppresses_new_submission:
                logger.debug(
                    "registry: duplicate fingerprint=%s status=%s task_id=%s",
                    fingerprint, existing.status.value, existing.task_id,
                )
                return False, existing

            self._attempt_counts[fingerprint] = self._attempt_counts.get(fingerprint, 0) + 1
            record = TaskRecord(
                fingerprint=fingerprint,
                task_id=task_id,
                run_id=run_id,
                phase=phase,
                evidence_version=evidence_version,
                status=TaskStatus.PENDING,
                timestamp=timestamp,
            )
            self._records[fingerprint] = record
            logger.debug(
                "registry: reserved fingerprint=%s task_id=%s attempt=%d",
                fingerprint, task_id, self._attempt_counts[fingerprint],
            )
            return True, record

    def attempt_count(self, fingerprint: str) -> int:
        """Total number of times *fingerprint* has ever been successfully
        reserved (1-based; 0 if never reserved). Never reset by eviction —
        this is a lifetime counter for the run, used to bound resubmission
        of a transiently-failing action (see ``ApexConfig
        .max_fingerprint_retries``)."""
        return self._attempt_counts.get(fingerprint, 0)

    async def update_status(
        self,
        fingerprint: str,
        status: TaskStatus,
        *,
        disposition: str = "",
        retry_count: int = 0,
    ) -> None:
        """Update the status of a registered task."""
        async with self._lock:
            record = self._records.get(fingerprint)
            if record is None:
                logger.warning(
                    "registry: update_status called for unknown fingerprint=%s", fingerprint
                )
                return
            record.status = status
            if disposition:
                record.disposition = disposition
            record.retry_count = retry_count

    def get(self, fingerprint: str) -> TaskRecord | None:
        """Non-locking read — safe for asyncio single-threaded reads."""
        return self._records.get(fingerprint)

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a JSON-serialisable list of all records for checkpoint persistence."""
        return [r.to_dict() for r in self._records.values()]

    def restore_from_snapshot(self, records: list[dict[str, Any]]) -> None:
        """Restore registry state from a checkpoint snapshot.

        Only ``COMPLETED`` and ``FAILED_TERMINAL`` records are restored —
        ``PENDING`` / ``EXECUTING`` records from the prior run are treated as
        lost (the engagement was interrupted mid-execution) and the task is
        permitted to run again.
        """
        for d in records:
            record = TaskRecord.from_dict(d)
            if record.status in (TaskStatus.COMPLETED, TaskStatus.FAILED_TERMINAL):
                self._records[record.fingerprint] = record
                logger.debug(
                    "registry: restored fingerprint=%s status=%s",
                    record.fingerprint, record.status.value,
                )

    @property
    def size(self) -> int:
        return len(self._records)
