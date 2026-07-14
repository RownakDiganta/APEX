# consolidate.py
# Episodic-to-skill generalisation: turns concrete episode chains into templated Skills by replacing configurable identifier patterns with typed slot references.
"""Episodic→skill generalization (Section 7 — consolidate).

``generalize(chain, ...)`` turns a concrete episode chain into a templated Skill
with typed slots.  The mechanism is generic: it replaces concrete string values
that match a configurable set of identifier patterns with slot references
(``<SLOT_n>``).

**No domain-specific patterns are hardcoded here.**  The host application
supplies a list of raw regex strings via ``Config.slot_patterns``; these are
compiled at call time and used only for that invocation.  The substrate ships
with an empty default — only UUID v4 strings are replaced by the single
built-in pattern, since UUIDs are universally opaque identifiers in any domain.
"""
from __future__ import annotations

import re
from typing import Any

from memfabric.ids import new_id, now
from memfabric.types import Episode, Skill

# Built-in pattern: UUID v4 — universally opaque in any domain.
# This is the ONLY pattern shipped in the substrate.  All domain-specific
# patterns (IPv4, port numbers, CVE IDs, etc.) must be supplied by the host
# application through Config.slot_patterns.
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def _build_pattern(extra_patterns: list[str]) -> re.Pattern[str]:
    """Compile a combined pattern from the built-in UUID pattern plus any
    caller-supplied raw regex strings.

    Extra patterns are joined with ``|`` into a single compiled regex so slot
    replacement requires only one pass over each string.  An empty
    *extra_patterns* list returns the UUID-only pattern.
    """
    parts = [_UUID_RE.pattern]
    for raw in extra_patterns:
        parts.append(raw)
    return re.compile(r"\b(?:" + "|".join(parts) + r")\b")


def _slot_replace(value: str, slots: dict[str, str], pattern: re.Pattern[str]) -> str:
    """Replace identifier matches in *value* with slot references.

    Accumulates the concrete→slot mapping into *slots* so the template
    inverse map can be reconstructed later.
    """
    def replacer(m: re.Match[str]) -> str:
        concrete = m.group(0)
        if concrete not in slots:
            slots[concrete] = f"<SLOT_{len(slots)}>"
        return slots[concrete]
    return pattern.sub(replacer, value)


def _template_data(
    data: dict[str, Any],
    slots: dict[str, str],
    pattern: re.Pattern[str],
) -> dict[str, Any]:
    """Recursively replace identifier matches in a data dict."""
    result: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            result[k] = _slot_replace(v, slots, pattern)
        elif isinstance(v, dict):
            result[k] = _template_data(v, slots, pattern)
        elif isinstance(v, list):
            result[k] = [
                _slot_replace(str(item), slots, pattern)
                if isinstance(item, str) else item
                for item in v
            ]
        else:
            result[k] = v
    return result


def generalize(
    chain: list[Episode],
    confidence: float = 0.5,
    slot_patterns: list[str] | None = None,
) -> Skill:
    """Turn a concrete success episode chain into a templated Skill.

    Parameters
    ----------
    chain:
        Ordered list of Episode objects forming one completed sub-chain.
    confidence:
        Starting confidence for the new skill (from ``config.skill_prior``).
    slot_patterns:
        List of raw regex strings identifying concrete values to replace with
        slot references.  Supplied by the host application via
        ``Config.slot_patterns``.  Defaults to ``[]`` (UUID-only).
    """
    pattern = _build_pattern(slot_patterns or [])
    slots: dict[str, str] = {}  # concrete → <SLOT_n>

    steps: list[dict[str, Any]] = []
    for ep in chain:
        step: dict[str, Any] = {
            "action": _slot_replace(ep.action, slots, pattern),
            "data": _template_data(ep.data, slots, pattern),
        }
        steps.append(step)

    name = f"skill_{chain[0].action}" if chain else "skill_unknown"
    description = f"Generalised from {len(chain)}-step chain: " + " → ".join(
        ep.action for ep in chain
    )

    preconditions: dict[str, Any] = {}
    if chain:
        first_data = chain[0].data
        preconditions = {
            k: type(v).__name__
            for k, v in first_data.items()
            if not isinstance(v, (dict, list))
        }

    return Skill(
        id=new_id(),
        timestamp=now(),
        name=name,
        description=description,
        template={"steps": steps, "slots": {v: k for k, v in slots.items()}},
        preconditions=preconditions,
        source_episodes=[ep.id for ep in chain if ep.id],
        confidence=confidence,
        evidence_count=1,
    )
