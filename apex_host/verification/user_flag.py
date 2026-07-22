# user_flag.py
# The one authoritative user-flag verifier and bounded-candidate-path validator for the objective/verification model (Phase 18).
"""Authoritative user-flag verification (Phase 18).

This module is the SOLE place flag-verification and bounded-path-validation
logic lives. Nothing else in ``apex_host`` may re-implement flag-detection
heuristics — the executor (``apex_host/agents/user_flag_executor.py``), the
policy rule (``apex_host/policy/rules.py::check_bounded_user_flag_verification``),
and the parser (``apex_host/parsers/objective_parser.py``) all call
``verify_user_flag``/``is_bounded_candidate_path`` from here rather than
scattering their own copies (CLAUDE.md's "one authoritative X" convention —
mirrors ``apex_host.security.redaction`` for secret handling).

Design constraints (see docs/user-flag-objective.md for the full rationale):

- Conservative by construction: a suspicious, multiline, malformed, empty,
  oversized, or ambiguous candidate is never accepted as verified. False
  negatives (rejecting a real flag because it doesn't match the configured
  format) are considered safe; false positives (accepting garbage as a
  verified flag) are not.
- No exact expected flag value is ever required or accepted as
  configuration — ``format_regex`` only constrains *shape*
  (charset/length), never a specific known value (CLAUDE.md §13.8/§13.9 —
  no machine-specific logic anywhere in this codebase).
- The returned ``FlagVerificationResult`` deliberately has NO plaintext
  field. The raw candidate value exists only as a local variable inside
  this function and is discarded the moment the digest/redacted form are
  computed — it can never flow further downstream (a report, an episode,
  an experience record) because there is no field to carry it.
- This module never writes to any store — it is a pure function, consistent
  with "the verifier ... never independently write[s] memory" (memfabric
  Invariant 7: planners/pure-helpers never touch MemoryAPI directly).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

#: Generic, conservative default flag-format regex: a single bounded token
#: (8-128 chars) drawn from a safe charset (alnum, underscore, hyphen, and
#: brace characters — covers common "TAG{...}"-style and bare hex/UUID-style
#: benchmark flag shapes) with no internal whitespace. Deliberately NOT
#: tuned to any specific machine's actual flag value — CLAUDE.md §13.8/§13.9.
DEFAULT_FLAG_FORMAT_REGEX: str = r"^[A-Za-z0-9_\-{}]{8,128}$"

#: Read-command error markers — presence of any of these anywhere in the
#: raw stdout/stderr means the "read" did not actually retrieve file
#: content, regardless of what the executor's own returncode/error
#: classification concluded. Matching is case-insensitive.
_ERROR_MARKERS: tuple[str, ...] = (
    "no such file or directory",
    "permission denied",
    "is a directory",
    "not a directory",
    "cannot open",
    "operation not permitted",
)

#: Bounded absolute-path syntax: leading "/", then a conservative charset,
#: bounded total length. Defense-in-depth on top of the caller's own
#: candidate-generation bounds (apex_host/planners/objective_planner.py) —
#: this validator is also called independently by the policy layer
#: (apex_host/policy/rules.py) and the executor
#: (apex_host/agents/user_flag_executor.py), so it must reject on its own,
#: never relying on the caller having already validated.
_PATH_CHAR_RE = re.compile(r"^/[A-Za-z0-9_./\-]{1,254}$")


@dataclass(slots=True)
class FlagVerificationResult:
    """Structured, secret-free verification evidence.

    No field here can ever hold the plaintext candidate value — only a
    SHA-256 digest and a short redacted display string survive past
    ``verify_user_flag()``. See module docstring.
    """

    verified: bool
    reason: str
    digest: str
    redacted: str
    length: int
    method: str


def _redact(value: str) -> str:
    """Short prefix/suffix redaction — fully masked for very short values."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _contains_error_marker(text: str) -> str | None:
    low = text.lower()
    for marker in _ERROR_MARKERS:
        if marker in low:
            return marker
    return None


def verify_user_flag(
    raw_output: str,
    *,
    raw_error: str = "",
    format_regex: str | None = None,
    max_output_bytes: int = 4096,
) -> FlagVerificationResult:
    """Verify whether *raw_output* is a plausible, well-formed flag value.

    Rejection rules (checked in order; the first match wins):

    1. ``raw_error`` (the executor's own error string, if any) contains a
       known command-error marker (not found / permission denied /
       directory) -> rejected, never even inspects ``raw_output``.
    2. ``raw_output`` exceeds ``max_output_bytes`` -> rejected (oversized).
    3. ``raw_output`` itself contains a command-error marker (defense in
       depth in case the executor's error classification missed it) ->
       rejected.
    4. Normalized (only harmless leading/trailing whitespace stripped)
       value is empty -> rejected.
    5. Contains a newline/carriage return -> rejected (multiline output is
       not a plausible single flag token).
    6. Contains any other internal whitespace -> rejected.
    7. Does not fully match ``format_regex`` (or
       :data:`DEFAULT_FLAG_FORMAT_REGEX` when not supplied, or when
       ``format_regex`` itself fails to compile) -> rejected.

    On success, returns a digest+redacted-display result. The raw value is
    never returned or logged.
    """
    if raw_error:
        marker = _contains_error_marker(raw_error)
        if marker is not None:
            return FlagVerificationResult(False, f"command error: {marker}", "", "", 0, "format_regex")

    text = raw_output or ""
    if len(text.encode("utf-8", errors="replace")) > max(0, max_output_bytes):
        return FlagVerificationResult(False, "output exceeds the maximum bounded size", "", "", len(text), "format_regex")

    marker = _contains_error_marker(text)
    if marker is not None:
        return FlagVerificationResult(False, f"command error marker present in output: {marker}", "", "", 0, "format_regex")

    normalized = text.strip()
    if not normalized:
        return FlagVerificationResult(False, "empty output", "", "", 0, "format_regex")
    if "\n" in normalized or "\r" in normalized:
        return FlagVerificationResult(
            False, "multiline output is not a plausible single flag token", "", "", len(normalized), "format_regex"
        )
    if any(ch.isspace() for ch in normalized):
        return FlagVerificationResult(
            False, "output contains internal whitespace", "", "", len(normalized), "format_regex"
        )

    pattern = format_regex or DEFAULT_FLAG_FORMAT_REGEX
    try:
        compiled = re.compile(pattern)
    except re.error:
        compiled = re.compile(DEFAULT_FLAG_FORMAT_REGEX)
    if compiled.fullmatch(normalized) is None:
        return FlagVerificationResult(
            False, "output does not match the configured flag format", "", "", len(normalized), "format_regex"
        )

    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    redacted = _redact(normalized)
    return FlagVerificationResult(True, "verified", digest, redacted, len(normalized), "format_regex")


def is_bounded_candidate_path(path: str, *, allowed_filenames: frozenset[str]) -> bool:
    """True only for a bounded, safe, absolute candidate read path.

    Structurally prevents unrestricted filesystem search: the path must be
    absolute, drawn from a conservative charset, contain no ``..``
    traversal segment, and its basename must be one of the operator's own
    configured ``allowed_filenames`` (``ApexConfig.user_flag_candidate_filenames``).
    Called independently by the policy layer and the executor — never
    trust a caller to have already validated.
    """
    if not path or _PATH_CHAR_RE.match(path) is None:
        return False
    if ".." in path.split("/"):
        return False
    basename = path.rsplit("/", 1)[-1]
    return bool(basename) and basename in allowed_filenames
