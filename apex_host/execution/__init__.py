# __init__.py
# Public re-exports for the apex_host.execution package.
from __future__ import annotations

from apex_host.execution.context import DispatchResult, ExecutionContext
from apex_host.execution.dispositions import (
    ExecutionDisposition,
    RetryDecision,
    classify_retry,
)
from apex_host.execution.errors import ErrorCategory, ExecutionError
from apex_host.execution.registry import TaskRecord, TaskRegistry, TaskStatus

__all__ = [
    "DispatchResult",
    "ErrorCategory",
    "ExecutionContext",
    "ExecutionDisposition",
    "ExecutionError",
    "RetryDecision",
    "TaskRecord",
    "TaskRegistry",
    "TaskStatus",
    "classify_retry",
]
