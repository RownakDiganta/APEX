# errors.py
# Typed execution error taxonomy for the APEX dispatcher.
"""Typed execution error records for the APEX task dispatcher.

These are typed **result records**, not Python exceptions.  Expected control-
flow outcomes (policy denial, conflict block, duplicate skip) produce typed
records; unexpected infrastructure failures (asyncio timeout, parser crash)
use ``ExecutionError`` with the appropriate category.

Each category documents:
  - ``retryable``: whether the dispatcher may schedule a retry
  - ``repairable``: whether a RepairRequest may be generated
  - ``counts_as_execution``: whether an attempt budget unit is consumed
  - ``updates_skill``: whether the skill execution counter changes
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ErrorCategory(str, Enum):
    """Taxonomy of execution error categories."""

    # Task rejected before any resource is allocated.
    POLICY_DENIED = "policy_denied"
    CONFLICT_BLOCKED = "conflict_blocked"
    DUPLICATE_TASK = "duplicate_task"
    INVALID_TASK = "invalid_task"
    TOOL_NOT_FOUND = "tool_not_found"

    # Executor ran; failure in the executor output.
    EXECUTION_TIMEOUT = "execution_timeout"
    EXECUTION_CANCELLED = "execution_cancelled"
    AUTHENTICATION_FAILURE = "authentication_failure"
    PARSER_FAILURE = "parser_failure"
    EXTERNAL_EXECUTION_ERROR = "external_execution_error"

    # Lifecycle / bookkeeping failures.
    RETRY_EXHAUSTED = "retry_exhausted"
    TRANSACTION_INTEGRITY = "transaction_integrity"

    # Classification helpers -------------------------------------------

    @property
    def retryable(self) -> bool:
        return self in (
            ErrorCategory.EXECUTION_TIMEOUT,
            ErrorCategory.EXTERNAL_EXECUTION_ERROR,
        )

    @property
    def repairable(self) -> bool:
        return self in (
            ErrorCategory.EXTERNAL_EXECUTION_ERROR,
            ErrorCategory.PARSER_FAILURE,
        )

    @property
    def counts_as_execution(self) -> bool:
        """True when an attempt budget unit should be consumed."""
        return self not in (
            ErrorCategory.POLICY_DENIED,
            ErrorCategory.CONFLICT_BLOCKED,
            ErrorCategory.DUPLICATE_TASK,
            ErrorCategory.INVALID_TASK,
        )

    @property
    def updates_skill(self) -> bool:
        """True when the skill execution counter should be incremented."""
        return self.counts_as_execution


@dataclass(slots=True)
class ExecutionError:
    """A typed record of an execution error.

    Use ``policy_decision`` / ``conflict_block_reason`` / ``duplicate_fingerprint``
    for the corresponding structured data; ``message`` is human-readable only.
    """

    category: ErrorCategory
    message: str
    task_id: str = ""
    policy_decision: object = None        # PolicyDecision when category=POLICY_DENIED
    conflict_block_reason: str = ""       # when category=CONFLICT_BLOCKED
    duplicate_fingerprint: str = ""       # when category=DUPLICATE_TASK
    raw_output: str = ""                  # redacted executor stdout/stderr
    metadata: dict[str, object] = field(default_factory=dict)

    # Convenience forwarders to the category
    @property
    def retryable(self) -> bool:
        return self.category.retryable

    @property
    def repairable(self) -> bool:
        return self.category.repairable

    @property
    def counts_as_execution(self) -> bool:
        return self.category.counts_as_execution

    @property
    def updates_skill(self) -> bool:
        return self.category.updates_skill
