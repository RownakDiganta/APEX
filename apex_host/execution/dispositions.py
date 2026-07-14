# dispositions.py
# ExecutionDisposition enum, RetryDecision, and classify_retry pure function.
"""Typed execution dispositions for the APEX task dispatcher.

``ExecutionDisposition`` describes the final outcome of a single dispatch
attempt with enough fidelity to drive retry, repair, skill-lifecycle, and
audit decisions.  It is separate from ``memfabric.types.Outcome`` so that
control-flow dispositions (blocked, skipped, invalid) are not conflated with
executor success/failure results.

``classify_retry`` is a pure function that produces a ``RetryDecision`` given
a disposition and optional error string.  Graph nodes call this exactly once;
no retry decisions are scattered across agent node closures.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ExecutionDisposition(str, Enum):
    """Final outcome classification for one dispatcher invocation."""

    # Executor was called and produced a clean result.
    EXECUTED_SUCCESS = "executed_success"
    # Executor ran; the operation completed but produced a valid negative (e.g.
    # auth rejected, 404 response, no open ports). Not an error; not a failure.
    EXECUTED_VALID_NEGATIVE = "executed_valid_negative"
    # Executor ran but produced a non-zero exit code or error string.
    EXECUTED_FAILURE = "executed_failure"
    # PolicyAdvisor denied the task before execution.
    BLOCKED_POLICY = "blocked_policy"
    # An open conflict dependency blocked the task before execution.
    BLOCKED_CONFLICT = "blocked_conflict"
    # Task fingerprint matched a recent completed/pending task — skipped.
    SKIPPED_DUPLICATE = "skipped_duplicate"
    # Task schema validation failed (unknown tool, bad args, out-of-scope target).
    INVALID_TASK = "invalid_task"
    # Task was cancelled (asyncio.CancelledError propagated).
    CANCELLED = "cancelled"
    # Executor timed out.
    TIMED_OUT = "timed_out"
    # Tool binary not found in PATH.
    TOOL_UNAVAILABLE = "tool_unavailable"
    # Parser raised an exception while processing the executor output.
    PARSER_FAILED = "parser_failed"
    # All retry attempts exhausted without success.
    RETRY_EXHAUSTED = "retry_exhausted"

    # ----------------------------------------------------------------
    # Derived properties — do not use raw comparisons in caller code.
    # ----------------------------------------------------------------

    @property
    def counts_as_execution(self) -> bool:
        """True when the executor was actually invoked (budget consumed)."""
        return self in (
            ExecutionDisposition.EXECUTED_SUCCESS,
            ExecutionDisposition.EXECUTED_VALID_NEGATIVE,
            ExecutionDisposition.EXECUTED_FAILURE,
            ExecutionDisposition.TIMED_OUT,
            ExecutionDisposition.PARSER_FAILED,
            ExecutionDisposition.RETRY_EXHAUSTED,
        )

    @property
    def updates_skill(self) -> bool:
        """True when a skill execution counter should be incremented."""
        return self.counts_as_execution

    @property
    def is_success(self) -> bool:
        return self in (
            ExecutionDisposition.EXECUTED_SUCCESS,
            ExecutionDisposition.EXECUTED_VALID_NEGATIVE,
        )

    @property
    def is_blocked(self) -> bool:
        return self in (
            ExecutionDisposition.BLOCKED_POLICY,
            ExecutionDisposition.BLOCKED_CONFLICT,
        )

    @property
    def is_skipped(self) -> bool:
        return self is ExecutionDisposition.SKIPPED_DUPLICATE

    @property
    def is_retryable(self) -> bool:
        """Dispositions that MAY permit a retry (caller still enforces budget)."""
        return self in (
            ExecutionDisposition.EXECUTED_FAILURE,
            ExecutionDisposition.TIMED_OUT,
        )

    @property
    def is_repairable(self) -> bool:
        """Dispositions that MAY permit a repair attempt via RepairEngine."""
        return self in (
            ExecutionDisposition.EXECUTED_FAILURE,
            ExecutionDisposition.PARSER_FAILED,
        )

    @property
    def never_retry(self) -> bool:
        """Dispositions that MUST NOT be retried automatically."""
        return self in (
            ExecutionDisposition.BLOCKED_POLICY,
            ExecutionDisposition.BLOCKED_CONFLICT,
            ExecutionDisposition.SKIPPED_DUPLICATE,
            ExecutionDisposition.INVALID_TASK,
            ExecutionDisposition.CANCELLED,
            ExecutionDisposition.TOOL_UNAVAILABLE,
            ExecutionDisposition.RETRY_EXHAUSTED,
            ExecutionDisposition.EXECUTED_SUCCESS,
            ExecutionDisposition.EXECUTED_VALID_NEGATIVE,
        )

    @property
    def never_repair(self) -> bool:
        """Dispositions that MUST NOT enter automatic repair."""
        return self in (
            ExecutionDisposition.BLOCKED_POLICY,
            ExecutionDisposition.BLOCKED_CONFLICT,
            ExecutionDisposition.SKIPPED_DUPLICATE,
            ExecutionDisposition.INVALID_TASK,
            ExecutionDisposition.CANCELLED,
            ExecutionDisposition.TOOL_UNAVAILABLE,
            ExecutionDisposition.RETRY_EXHAUSTED,
            ExecutionDisposition.EXECUTED_VALID_NEGATIVE,
        )


@dataclass(slots=True)
class RetryDecision:
    """Result of ``classify_retry`` — tells callers what to do next."""

    may_retry: bool
    may_repair: bool
    reason: str


_RETRYABLE_ERRORS = (
    "timed out",
    "timeout",
    "connection refused",
    "network unreachable",
    "temporarily unavailable",
)

_FIXABLE_ERRORS = (
    "command not found",
    "no such file",
    "permission denied",
    "syntax error",
    "invalid option",
    "unrecognized option",
)


def classify_retry(
    disposition: ExecutionDisposition,
    error: str | None = None,
) -> RetryDecision:
    """Pure function: given a disposition + optional error string, decide retry/repair.

    This is the single retry-decision point.  No graph node, planner, executor,
    or repair component may make retry/repair decisions independently.

    Retry matrix
    ------------
    BLOCKED_POLICY     → no retry, no repair (policy denial must be resolved externally)
    BLOCKED_CONFLICT   → no retry, no repair (conflict must be resolved in EKG)
    SKIPPED_DUPLICATE  → no retry, no repair
    INVALID_TASK       → no retry, no repair
    CANCELLED          → no retry, no repair (caller controls re-submission)
    TOOL_UNAVAILABLE   → no retry, no repair (environment must change)
    RETRY_EXHAUSTED    → no retry, no repair
    EXECUTED_SUCCESS   → no retry, no repair (already succeeded)
    EXECUTED_VALID_NEGATIVE → no retry, no repair (valid outcome)
    TIMED_OUT          → may retry (transient timeout)
    EXECUTED_FAILURE   → may retry/repair depending on error string
    PARSER_FAILED      → may repair (bad output format)
    """
    if disposition.never_retry and not disposition.is_repairable:
        return RetryDecision(may_retry=False, may_repair=False, reason=disposition.value)

    if disposition is ExecutionDisposition.TIMED_OUT:
        return RetryDecision(may_retry=True, may_repair=False, reason="timeout — transient")

    if disposition is ExecutionDisposition.PARSER_FAILED:
        return RetryDecision(may_retry=False, may_repair=True, reason="parser failure")

    if disposition is ExecutionDisposition.EXECUTED_FAILURE:
        err = (error or "").lower()
        # Tool-not-found, auth failure → no repair, no retry
        if "not found in path" in err:
            return RetryDecision(may_retry=False, may_repair=False, reason="tool unavailable")
        if "login incorrect" in err or "authentication failed" in err or "login failed" in err:
            return RetryDecision(
                may_retry=False, may_repair=False,
                reason="authentication failure — no new credentials",
            )
        # Transient network → retry only
        for transient in _RETRYABLE_ERRORS:
            if transient in err:
                return RetryDecision(may_retry=True, may_repair=False, reason=f"transient: {transient}")
        # Fixable format error → repair eligible
        for fixable in _FIXABLE_ERRORS:
            if fixable in err:
                return RetryDecision(may_retry=False, may_repair=True, reason=f"fixable: {fixable}")
        # Generic failure → repair eligible (RepairEngine decides if it can help)
        return RetryDecision(may_retry=False, may_repair=True, reason="script_error — repair eligible")

    # Everything else: no action
    return RetryDecision(may_retry=False, may_repair=False, reason=disposition.value)
