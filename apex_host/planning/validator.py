# validator.py
# Validates raw LLM planner output: JSON parse, Pydantic model check, tool allowlist, safety gates; returns None on any failure.
"""Validator for raw LLM planner output.

``Validator.validate()`` is the safety choke-point between LLM text and
live TaskSpec objects.  It returns ``None`` on any failure — the
``PlanningEngine`` treats ``None`` as "fall back to the deterministic
planner" rather than crashing or silently executing an unsafe command.

Rejection criteria (any one triggers ``None`` return):
1. Malformed JSON — cannot be parsed.
2. Schema mismatch — does not match ``PlannerOutput`` Pydantic model.
3. Unsupported tool — ``task.tool`` not in ``allowed_tools``.
4. Unsafe/destructive tool — ``task.tool`` in the unconditional blocklist.
5. Shell metacharacter — any token in ``task.args`` contains ``;``, ``&&``,
   ``||``, ``|``, ``>``, ``>>``, ``<``, ``$(``, or `` ` ``.
6. Unknown executor_domain — not one of the registered domains.
"""
from __future__ import annotations

import json
import logging
import re

from pydantic import ValidationError

from apex_host.planning.models import PlannerOutput

logger = logging.getLogger(__name__)

# Mirrors apex_host/tools/safety.py constants — kept here so the validator
# is self-contained and testable without a full ApexConfig.
_DESTRUCTIVE_COMMANDS: frozenset[str] = frozenset(
    {"rm", "mkfs", "dd", "shutdown", "reboot", "halt", "poweroff", "fdisk", "format", "mkswap"}
)
_SHELL_OPERATORS: tuple[str, ...] = (";", "&&", "||", "|", ">>", ">", "<", "$(", "`")
_KNOWN_DOMAINS: frozenset[str] = frozenset(
    {"recon", "web", "credential", "priv_esc", "execute", "browser"}
)

# Regex to strip markdown code fences (```json ... ```)
_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```", re.IGNORECASE)


def _extract_json(raw: str) -> str:
    """Return the JSON body from raw LLM output.

    Handles two common LLM formats:
    - Bare JSON object.
    - JSON wrapped in a ```json ... ``` code fence.
    """
    stripped = raw.strip()
    # Try to extract from code fence first
    m = _CODE_FENCE_RE.search(stripped)
    if m:
        return m.group(1).strip()
    # Fall back to the raw string (may already be plain JSON)
    return stripped


class Validator:
    """Validates raw LLM text against the ``PlannerOutput`` schema and safety rules.

    Parameters
    ----------
    min_confidence:
        If the model's self-reported confidence falls below this threshold
        the output is still accepted (confidence is informational, not a
        gate) — but the engine logs a warning.
    """

    def __init__(self, min_confidence: float = 0.0) -> None:
        self._min_confidence = min_confidence

    def validate(
        self,
        raw: str,
        allowed_tools: list[str],
        allowed_actions: list[str] | None = None,
    ) -> PlannerOutput | None:
        """Parse and validate *raw* LLM text.

        Parameters
        ----------
        raw:
            The raw string returned by the LLM.
        allowed_tools:
            List of tool names permitted in the current engagement
            (from ``ApexConfig.allowed_tools``).
        allowed_actions:
            Optional explicit whitelist of executor_domain values.  When
            ``None`` the built-in ``_KNOWN_DOMAINS`` set is used.

        Returns
        -------
        PlannerOutput | None
            A valid, safe ``PlannerOutput`` if all checks pass; ``None``
            otherwise (caller should fall back to the deterministic planner).
        """
        if not raw or not raw.strip():
            logger.warning("validator: empty LLM response")
            return None

        # 1. JSON extraction
        json_str = _extract_json(raw)
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            logger.warning("validator: malformed JSON — %s", exc)
            return None

        # 2. Schema validation
        try:
            output = PlannerOutput.model_validate(data)
        except ValidationError as exc:
            logger.warning("validator: schema mismatch — %s", exc)
            return None

        # 3. Per-task safety gates
        domains = frozenset(allowed_actions) if allowed_actions else _KNOWN_DOMAINS
        for task in output.selected_tasks:
            # Destructive-command blocklist (unconditional)
            if task.tool in _DESTRUCTIVE_COMMANDS:
                logger.warning(
                    "validator: destructive tool %r rejected (unconditional blocklist)",
                    task.tool,
                )
                return None

            # Allowlist check
            if task.tool not in allowed_tools:
                logger.warning(
                    "validator: unsupported tool %r (not in allowed_tools %s)",
                    task.tool,
                    allowed_tools,
                )
                return None

            # Executor domain check
            if task.executor_domain not in domains:
                logger.warning(
                    "validator: unknown executor_domain %r (known: %s)",
                    task.executor_domain,
                    sorted(domains),
                )
                return None

            # Shell metacharacter check in args
            for token in task.args:
                for op in _SHELL_OPERATORS:
                    if op in token:
                        logger.warning(
                            "validator: shell operator %r in arg token %r",
                            op,
                            token,
                        )
                        return None

        # 4. Low-confidence advisory (not a hard reject)
        if output.confidence < self._min_confidence:
            logger.info(
                "validator: low confidence %.2f (threshold %.2f) — accepting but flagging",
                output.confidence,
                self._min_confidence,
            )

        return output
