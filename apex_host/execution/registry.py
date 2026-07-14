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
    """Lifecycle state of a registered task."""

    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED_RETRYABLE = "failed_retryable"
    FAILED_TERMINAL = "failed_terminal"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    SKIPPED_DUPLICATE = "skipped_duplicate"

    @property
    def suppresses_new_submission(self) -> bool:
        """True when a new task with the same fingerprint should be suppressed."""
        return self in (
            TaskStatus.PENDING,
            TaskStatus.EXECUTING,
            TaskStatus.COMPLETED,
            TaskStatus.FAILED_TERMINAL,
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
                "registry: reserved fingerprint=%s task_id=%s",
                fingerprint, task_id,
            )
            return True, record

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
