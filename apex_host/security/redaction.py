# redaction.py
# Central recursive redaction module — sole source of secret-scrubbing logic for apex_host.
"""Central redaction utilities for apex_host.

This is the SOLE location for secret-scrubbing logic.  No inline
``secret_hint = "[redacted]"`` assignments or ``str.replace`` calls
targeting credentials may appear anywhere else in apex_host parsers or
executors — they must all delegate here (P8-S06).

Public API
----------
redact_session_text(text, *, passwords)
    Replaces each password that appears in *text* with ``[redacted]``.
    Does NOT skip short passwords — any non-empty password is redacted.
    Returns *text* unchanged when *passwords* is empty.

redact_value(value, *, passwords)
    Recursively redacts passwords from a string, list, or dict value.

redact_dict(d, *, passwords)
    Convenience wrapper for ``redact_value`` that accepts a dict and
    always returns a dict.

Constants
---------
REDACTED_PLACEHOLDER : str
    The literal replacement string used for all redactions.

SESSION_REDACTED_PLACEHOLDER : str
    Replacement for entire live Telnet session transcripts (P8-S03).
"""
from __future__ import annotations

from typing import Any

REDACTED_PLACEHOLDER: str = "[redacted]"
SESSION_REDACTED_PLACEHOLDER: str = "[session_redacted]"


def redact_session_text(text: str, *, passwords: list[str]) -> str:
    """Replace each password occurrence in *text* with REDACTED_PLACEHOLDER.

    - Passwords are replaced as-is (case-sensitive substring match).
    - Empty strings in *passwords* are skipped (replacing "" would corrupt text).
    - Returns *text* unchanged when *passwords* is empty.

    This function is safe to call on any string including login session
    transcripts, `id` command output, or banner text.
    """
    if not passwords:
        return text
    result = text
    for pwd in passwords:
        if pwd:  # never replace empty string
            result = result.replace(pwd, REDACTED_PLACEHOLDER)
    return result


def redact_value(value: Any, *, passwords: list[str]) -> Any:
    """Recursively redact *passwords* from *value*.

    - str  → substring-replaced string (see redact_session_text)
    - list → new list with each element recursively redacted
    - dict → new dict with each value recursively redacted (keys untouched)
    - other (int, float, bool, None, …) → returned unchanged

    Returns a new object; the original *value* is never mutated.
    """
    if isinstance(value, str):
        return redact_session_text(value, passwords=passwords)
    if isinstance(value, list):
        return [redact_value(item, passwords=passwords) for item in value]
    if isinstance(value, dict):
        return {k: redact_value(v, passwords=passwords) for k, v in value.items()}
    return value


def redact_dict(d: dict[str, Any], *, passwords: list[str]) -> dict[str, Any]:
    """Convenience wrapper: redact passwords from every value in *d*.

    Returns a **new** dict; *d* is not mutated.
    """
    return {k: redact_value(v, passwords=passwords) for k, v in d.items()}
