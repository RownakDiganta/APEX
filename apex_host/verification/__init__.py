# __init__.py
# Package marker for apex_host.verification — the single authoritative home for objective/flag verification logic.
"""Verification helpers for APEX engagement objectives.

``apex_host.verification.user_flag`` is the ONE authoritative place flag
verification and bounded-path validation logic lives — see that module's
docstring and docs/user-flag-objective.md. Parsers, planners, executors,
and reports must import from here rather than re-implementing any of this
logic locally (CLAUDE.md's "one authoritative X" convention, matching
``apex_host.security.redaction`` for secret handling).
"""
from __future__ import annotations

from apex_host.verification.user_flag import (
    DEFAULT_FLAG_FORMAT_REGEX,
    FlagVerificationResult,
    is_bounded_candidate_path,
    verify_user_flag,
)

__all__ = [
    "DEFAULT_FLAG_FORMAT_REGEX",
    "FlagVerificationResult",
    "is_bounded_candidate_path",
    "verify_user_flag",
]
