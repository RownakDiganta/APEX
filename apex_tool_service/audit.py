# audit.py
# Structured execution audit logging — correlation IDs, bounded argument previews, and an explicit set of things that are never logged.
"""Structured audit logging for apex_tool_service.

Uses the stdlib ``logging`` package (this repository has no pre-existing
structured-logging framework to match — ``apex_host`` itself uses
module-level ``logging.getLogger(__name__)`` loggers throughout, e.g.
``apex_host/tools/runner.py``, so this follows the same convention).

**Never logged, anywhere in this module:** the bearer token (success or
failure path), the full ``stdin`` payload, environment variables, or the
configured ``ServiceSettings.token``.

**Argument logging decision (documented per this phase's task brief):**
arguments are logged as a *bounded preview* — each argument individually
truncated to ``_PREVIEW_ARG_CHARS`` characters, and the joined preview
further truncated to ``_PREVIEW_TOTAL_CHARS``, not logged in full. This
bounds log volume for large argument lists (e.g. a long wordlist path
repeated across many arguments) and reduces incidental exposure if a
validation gap ever let something sensitive-looking through. The
trade-off is less complete audit detail than full argument logging — an
operator needing the complete argument list should correlate the
``correlation_id`` against the *caller's* own audit trail (in APEX's case,
the EKG/episodic log, which already redacts credentials via
``apex_host.security.redaction``), not reconstruct it from this service's
logs alone.
"""
from __future__ import annotations

import logging
import time
import uuid

from apex_tool_service.models import ExecuteResponse

logger = logging.getLogger("apex_tool_service.audit")

_PREVIEW_ARG_CHARS = 40
_PREVIEW_TOTAL_CHARS = 200


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def preview_arguments(arguments: list[str]) -> str:
    """Bounded, non-sensitive preview of an argument list for logging only."""
    parts = [a if len(a) <= _PREVIEW_ARG_CHARS else a[:_PREVIEW_ARG_CHARS] + "…" for a in arguments]
    joined = " ".join(parts)
    if len(joined) > _PREVIEW_TOTAL_CHARS:
        joined = joined[:_PREVIEW_TOTAL_CHARS] + "…"
    return joined


def log_request_accepted(correlation_id: str, tool: str, argument_count: int, timeout_seconds: float) -> float:
    """Log that a request passed auth+validation and is about to execute. Returns a start timestamp."""
    logger.info(
        "execution_accepted id=%s tool=%s arg_count=%d timeout_seconds=%.1f",
        correlation_id, tool, argument_count, timeout_seconds,
    )
    return time.monotonic()


def log_execution_result(correlation_id: str, tool: str, arguments: list[str], result: ExecuteResponse) -> None:
    logger.info(
        "execution_complete id=%s tool=%s returncode=%s duration_seconds=%.3f "
        "timed_out=%s stdout_bytes=%d stderr_bytes=%d error=%s args=%s",
        correlation_id, tool, result.returncode, result.duration_seconds,
        result.timed_out, len(result.stdout.encode("utf-8", errors="replace")),
        len(result.stderr.encode("utf-8", errors="replace")),
        result.error or "", preview_arguments(arguments),
    )


def log_validation_rejected(correlation_id: str, detail: str) -> None:
    logger.info("execution_rejected id=%s reason=%s", correlation_id, detail)


def log_auth_failure(correlation_id: str, status: str) -> None:
    """Log an authentication failure. NEVER pass the Authorization header value here."""
    logger.warning("auth_failure id=%s status=%s", correlation_id, status)
