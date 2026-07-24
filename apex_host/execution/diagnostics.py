# diagnostics.py
# Builds bounded, redacted per-execution diagnostic records from an existing dispatcher tool-result dict (Phase 3).
"""Bounded, redacted execution-diagnostic records (Phase 3, post-live-test
debugging track).

``build_execution_diagnostic()`` is the single place a dispatcher
``tool_result`` dict (the ubiquitous ``tr`` shape already used throughout
``apex_host`` — see ``apex_host.execution.dispatcher.TaskDispatcher``) is
turned into a bounded, redacted, report-facing diagnostic record. This
does NOT introduce a new, competing execution-result model — it is a pure
projection function over the existing ``tr`` dict shape, reusing fields
``TaskDispatcher.dispatch()`` already populates (``fingerprint``,
``retry_index``, ``start_timestamp``, ``end_timestamp``,
``classifier_reason``, ``final_disposition`` — see that module's step 6)
plus the classification from
``apex_host.execution.error_classifier.classify_execution_diagnostic``.

Size limits and redaction (non-negotiable — never weakened):
- ``stdout``/``stderr`` are capped at :data:`STDOUT_SAMPLE_LIMIT` /
  :data:`STDERR_SAMPLE_LIMIT` characters with a deterministic truncation
  flag — never the complete raw output.
- Every sample and every argument token is passed through
  ``apex_host.security.redaction.redact_secret_patterns`` (pattern-based —
  catches an API-key/bearer-token/AWS-key/private-key shape even when the
  specific secret VALUE is not known in advance) and, when the caller
  supplies configured credential values (``passwords``), through
  ``redact_session_text`` as well (substring-based — catches an EXACT
  configured password/username value verbatim).
- No field on the returned dict ever carries a cookie, session token, or
  raw payload body beyond the bounded, redacted samples above.
"""
from __future__ import annotations

from typing import Any

from apex_host.execution.error_classifier import classify_execution_diagnostic
from apex_host.security.redaction import redact_secret_patterns, redact_session_text

#: Bounded sample size for stdout/stderr — matches the pre-existing DEBUG-log
#: truncation convention already used elsewhere in this codebase
#: (apex_host.execution.dispatcher's own step-6 DEBUG log).
STDOUT_SAMPLE_LIMIT = 500
STDERR_SAMPLE_LIMIT = 500
#: Bounded per-token cap for argument samples — defensive against a single
#: pathologically long argument value dominating the record.
ARG_TOKEN_LIMIT = 200


def _bounded_redacted(text: str, limit: int, *, passwords: list[str] | None) -> tuple[str, bool]:
    """Redact then truncate *text*, returning ``(sample, was_truncated)``.
    Redaction always runs BEFORE truncation so a secret straddling the
    truncation boundary is never partially exposed."""
    scrubbed = redact_secret_patterns(text or "")
    if passwords:
        scrubbed = redact_session_text(scrubbed, passwords=passwords)
    if len(scrubbed) > limit:
        return scrubbed[:limit], True
    return scrubbed, False


def build_execution_diagnostic(
    tr: dict[str, Any],
    *,
    phase: str,
    passwords: list[str] | None = None,
) -> dict[str, Any]:
    """Return one bounded, redacted execution-diagnostic record for *tr*.

    Called once per actual tool execution (never for a
    ``skipped_duplicate``/``repair_no_change`` non-execution — callers
    are expected to filter those out first, matching the same discipline
    already established for episode creation in
    ``apex_host.orchestration.memory_node``).

    Fields (see module docstring for the size/redaction guarantees):
    ``execution_id``, ``task_id``, ``fingerprint``, ``phase``, ``agent``,
    ``tool``, ``args`` (redacted), ``target``, ``backend``,
    ``start_timestamp``, ``end_timestamp``, ``duration_seconds``,
    ``returncode``, ``timed_out``, ``stdout_sample``, ``stderr_sample``,
    ``stdout_truncated``, ``stderr_truncated``, ``diagnostic_category``
    (the unified, apex_host-level classification —
    ``apex_host.execution.error_classifier.classify_execution_diagnostic``),
    ``tool_error_category`` (a tool-specific classifier's own label, e.g.
    nmap's ``raw_socket_permission_denied``, when present — kept
    alongside, never overwritten by, the unified category),
    ``classifier_reason`` (``apex_host.execution.dispositions
    .classify_retry``'s own reason string), ``policy_decision_ref``,
    ``retry_index``, ``final_disposition``.
    """
    task_id = str(tr.get("task_id", ""))
    retry_index = int(tr.get("retry_index", 0) or 0)
    tool = str(tr.get("tool", tr.get("kind", "unknown")))

    stdout_sample, stdout_truncated = _bounded_redacted(
        str(tr.get("stdout", "")), STDOUT_SAMPLE_LIMIT, passwords=passwords
    )
    stderr_sample, stderr_truncated = _bounded_redacted(
        str(tr.get("stderr", "")), STDERR_SAMPLE_LIMIT, passwords=passwords
    )
    args = [
        redact_secret_patterns(str(a))[:ARG_TOKEN_LIMIT]
        for a in (tr.get("args") or [])
    ]
    if passwords:
        args = [redact_session_text(a, passwords=passwords) for a in args]

    return {
        "execution_id": f"{task_id}:{retry_index}" if task_id else "",
        "task_id": task_id,
        "fingerprint": str(tr.get("fingerprint", "")),
        "phase": phase,
        "agent": str(tr.get("agent", f"apex.{phase}")),
        "tool": tool,
        "args": args,
        "target": str(tr.get("target", "")),
        "backend": str(tr.get("backend", "")),
        "start_timestamp": str(tr.get("start_timestamp", "")),
        "end_timestamp": str(tr.get("end_timestamp", "")),
        "duration_seconds": float(tr.get("duration_seconds", 0.0) or 0.0),
        "returncode": tr.get("returncode"),
        "timed_out": bool(tr.get("timed_out", False)),
        "stdout_sample": stdout_sample,
        "stderr_sample": stderr_sample,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "diagnostic_category": classify_execution_diagnostic(tr),
        "tool_error_category": str(tr.get("error_category", "")),
        "classifier_reason": str(tr.get("classifier_reason", "")),
        "policy_decision_ref": str(tr.get("policy_rule", "")) or None,
        "retry_index": retry_index,
        "final_disposition": str(tr.get("final_disposition", "")),
    }
