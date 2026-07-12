# llm_guard.py
# LLMPolicyGuard: pre/post LLM call content policy — redaction, scope, and output safety checks.
"""LLM-level policy guard for APEX planning calls.

``LLMPolicyGuard`` enforces three lightweight safety layers around every LLM
call in ``PlanningEngine`` and ``RepairEngine``:

1. **Sanitize** — removes configured passwords and known secret patterns from
   prompt messages before they reach the LLM.
2. **Check prompt** — rejects prompts that still contain credential material or
   reference out-of-scope targets in actionable GOAL/TARGET lines.
3. **Check output** — rejects LLM responses that suggest persistence/backdoor
   mechanisms, brute-force tools, private data exfiltration, or actions against
   out-of-scope targets.

On any block, the caller (``PlanningEngine`` / ``RepairEngine``) falls back to
the deterministic planner rather than raising.

No I/O, no LLM calls, no MemoryAPI access — pure synchronous text analysis.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_GOAL_LINE_PATTERN = re.compile(r"^(?:GOAL|TARGET):\s*(.+)$", re.MULTILINE)
_TARGET_FIELD_PATTERN = re.compile(r'"target"\s*:\s*"([^"]*)"')
_ARGS_ARRAY_PATTERN = re.compile(r'"args"\s*:\s*(\[[^\]]*\])')

# Secret patterns for redaction.  Each entry: (compiled_pattern, replacement).
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (
        re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
]

# Patterns that block LLM output.  Each entry: (label, compiled_pattern).
_PERSISTENCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("crontab_edit", re.compile(r"\bcrontab\s+-[eil]\b")),
    ("cron_dir", re.compile(r"/etc/cron(?:d|tab|\.d|\.daily|\.weekly|\.monthly)")),
    ("authorized_keys", re.compile(r"authorized_keys")),
    ("shell_rc", re.compile(r"\.bash(?:rc|_profile|_login)\b")),
    ("systemctl_enable", re.compile(r"\bsystemctl\s+enable\b")),
    ("netcat_backdoor", re.compile(r"\bnc\b.*-[el]\b|\bnetcat\b.*-[el]\b")),
]

_BRUTE_FORCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("hydra", re.compile(r"\bhydra\b", re.IGNORECASE)),
    ("medusa", re.compile(r"\bmedusa\b", re.IGNORECASE)),
    ("patator", re.compile(r"\bpatator\b", re.IGNORECASE)),
    ("hashcat", re.compile(r"\bhashcat\b", re.IGNORECASE)),
    (
        "john_wordlist",
        re.compile(r"\bjohn\b\s+.*--wordlist|\bjohn\b\s+.*\.txt", re.IGNORECASE),
    ),
]

_EXFILTRATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("shadow_file", re.compile(r"/etc/shadow")),
    ("b64_pipe_etc", re.compile(r"\bbase64\b.{0,40}</etc/", re.IGNORECASE)),
]

# Minimum length for a password/username to be eligible for redaction.
# Prevents accidental redaction of single-character or empty strings.
_MIN_SECRET_LEN = 4


class LLMPolicyGuard:
    """Pre/post LLM policy checker for ``PlanningEngine`` and ``RepairEngine``.

    Parameters
    ----------
    config:
        The ``ApexConfig`` for the current engagement.  Supplies
        ``password_candidates``, ``username_candidates``, and ``target``
        (the scope boundary).

    Typical usage::

        guard = LLMPolicyGuard(config)

        # Before LLM call:
        messages, n = guard.sanitize_messages(messages)
        blocked, reason = guard.check_prompt(messages)
        if blocked:
            return fallback_result()

        # Call LLM here, get raw text.

        # After LLM call:
        blocked, reason = guard.check_output(raw)
        if blocked:
            return fallback_result()

        # Proceed to Validator.
    """

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize_messages(
        self, messages: list[dict[str, str]]
    ) -> tuple[list[dict[str, str]], int]:
        """Redact secret material from prompt messages before LLM invocation.

        Replaces every occurrence of a configured password and every match of
        a known API-key / token / private-key pattern with a
        ``[REDACTED_*]`` placeholder.

        Returns
        -------
        (sanitized_messages, redaction_count)
            ``redaction_count`` is the total number of substitutions made
            across all messages.
        """
        total_count = 0
        sanitized: list[dict[str, str]] = []
        for msg in messages:
            content = msg.get("content", "")
            new_content, n = self._redact_content(content)
            total_count += n
            sanitized.append({**msg, "content": new_content})
        return sanitized, total_count

    def check_prompt(
        self, messages: list[dict[str, str]]
    ) -> tuple[bool, str]:
        """Pre-LLM prompt safety gate.

        Returns ``(True, reason)`` to block; ``(False, "")`` to proceed.

        Blocks when:
        - A configured password survives in message content (defense-in-depth
          after ``sanitize_messages``).
        - A private-key header appears in message content.
        - A GOAL: or TARGET: line references an IP address outside
          ``config.target``.
        """
        for msg in messages:
            content = msg.get("content", "")
            blocked, reason = self._check_for_residual_secrets(content)
            if blocked:
                logger.warning("llm_guard.check_prompt blocked: %s", reason)
                return True, reason
            blocked, reason = self._check_goal_scope(content)
            if blocked:
                logger.warning("llm_guard.check_prompt blocked: %s", reason)
                return True, reason
        return False, ""

    def check_output(self, raw_text: str) -> tuple[bool, str]:
        """Post-LLM output safety gate.

        Returns ``(True, reason)`` to block and fall back; ``(False, "")`` to
        proceed to the ``Validator``.

        Blocks when the raw LLM output contains:
        - Persistence / backdoor patterns (crontab, authorized_keys, …).
        - Brute-force tool names (hydra, medusa, …).
        - Private data exfiltration indicators (/etc/shadow, …).
        - Out-of-scope target IPs in JSON ``"target"`` or ``"args"`` fields.
        """
        # Persistence / backdoor
        for label, pattern in _PERSISTENCE_PATTERNS:
            if pattern.search(raw_text):
                reason = f"output suggests persistence: {label}"
                logger.warning("llm_guard.check_output blocked: %s", reason)
                return True, reason

        # Brute force
        for label, pattern in _BRUTE_FORCE_PATTERNS:
            if pattern.search(raw_text):
                reason = f"output suggests brute force: {label}"
                logger.warning("llm_guard.check_output blocked: %s", reason)
                return True, reason

        # Exfiltration
        for label, pattern in _EXFILTRATION_PATTERNS:
            if pattern.search(raw_text):
                reason = f"output suggests data exfiltration: {label}"
                logger.warning("llm_guard.check_output blocked: %s", reason)
                return True, reason

        # Out-of-scope target in JSON "target" fields
        if self._config.target:
            for m in _TARGET_FIELD_PATTERN.finditer(raw_text):
                val = m.group(1)
                for ip_m in _IP_PATTERN.finditer(val):
                    ip = ip_m.group(1)
                    if ip != self._config.target:
                        reason = f"output references out-of-scope target: {ip}"
                        logger.warning("llm_guard.check_output blocked: %s", reason)
                        return True, reason

        # Out-of-scope IP in JSON "args" arrays
        if self._config.target:
            for m in _ARGS_ARRAY_PATTERN.finditer(raw_text):
                args_text = m.group(1)
                for ip_m in _IP_PATTERN.finditer(args_text):
                    ip = ip_m.group(1)
                    if ip != self._config.target:
                        reason = f"output uses out-of-scope IP in args: {ip}"
                        logger.warning("llm_guard.check_output blocked: %s", reason)
                        return True, reason

        return False, ""

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _redact_content(self, text: str) -> tuple[str, int]:
        """Redact passwords, usernames, and secret patterns in one text string."""
        count = 0

        for pwd in self._config.password_candidates:
            if len(pwd) >= _MIN_SECRET_LEN and pwd in text:
                text = text.replace(pwd, "[REDACTED_PASSWORD]")
                count += 1

        for uname in self._config.username_candidates:
            if len(uname) >= _MIN_SECRET_LEN and uname in text:
                text = text.replace(uname, "[REDACTED_USERNAME]")
                count += 1

        for pattern, label in _SECRET_PATTERNS:
            new_text, n = pattern.subn(label, text)
            count += n
            text = new_text

        return text, count

    def _check_for_residual_secrets(self, text: str) -> tuple[bool, str]:
        """Return (True, reason) if surviving credential material is found."""
        for pwd in self._config.password_candidates:
            if len(pwd) >= _MIN_SECRET_LEN and pwd in text:
                return True, "prompt contains unsanitized credential material"
        if "-----BEGIN" in text and "PRIVATE KEY" in text:
            return True, "prompt contains private key material"
        return False, ""

    def _check_goal_scope(self, text: str) -> tuple[bool, str]:
        """Return (True, reason) if a GOAL/TARGET line references an out-of-scope IP."""
        if not self._config.target:
            return False, ""
        for match in _GOAL_LINE_PATTERN.finditer(text):
            line = match.group(1)
            for ip_match in _IP_PATTERN.finditer(line):
                ip = ip_match.group(1)
                if ip != self._config.target:
                    return True, f"prompt goal references out-of-scope IP: {ip}"
        return False, ""
