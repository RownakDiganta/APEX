# consolidate.py
# Episodic-to-skill generalisation logic that turns concrete success episode chains into templated Skills by replacing domain-specific identifiers with typed slot references.
"""Episodic→skill generalization (Section 7 — consolidate).

``generalize(chain)`` turns a concrete episode chain into a templated Skill
with typed slots.  The mechanism is generic: it replaces concrete string values
that look like domain-specific identifiers with slot references (``<SLOT_n>``).

No domain knowledge is encoded here.  The host app supplies episodes; the
reflector generalises whatever structure those episodes contain.
"""
from __future__ import annotations

import re
from typing import Any

from memfabric.ids import new_id, now
from memfabric.types import Episode, Outcome, Skill

# Matches values that look like specific identifiers: IPs, port numbers, hashes,
# URLs, UUIDs, etc.  These are replaced with slot references.
_IDENTIFIER_RE = re.compile(
    r"\b(?:"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"      # IPv4
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # UUID
    r"|\d{4,6}"                                   # port / numeric ID
    r")\b"
)


def _slot_replace(value: str, slots: dict[str, str]) -> str:
    """Replace identifiers in *value* with slot references, accumulating into *slots*."""
    def replacer(m: re.Match[str]) -> str:
        concrete = m.group(0)
        if concrete not in slots:
            slots[concrete] = f"<SLOT_{len(slots)}>"
        return slots[concrete]
    return _IDENTIFIER_RE.sub(replacer, value)


def _template_data(
    data: dict[str, Any], slots: dict[str, str]
) -> dict[str, Any]:
    """Recursively replace identifiers in a data dict with slot references."""
    result: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            result[k] = _slot_replace(v, slots)
        elif isinstance(v, dict):
            result[k] = _template_data(v, slots)
        elif isinstance(v, list):
            result[k] = [
                _slot_replace(str(item), slots) if isinstance(item, str) else item
                for item in v
            ]
        else:
            result[k] = v
    return result


def generalize(chain: list[Episode], confidence: float = 0.5) -> Skill:
    """Turn a concrete success episode chain into a templated Skill.

    Parameters
    ----------
    chain:
        Ordered list of Episode objects forming one completed sub-chain.
    confidence:
        Starting confidence for the new skill (from config.skill_prior).
    """
    slots: dict[str, str] = {}   # concrete → <SLOT_n>

    # Build a template from each episode's action + data
    steps: list[dict[str, Any]] = []
    for ep in chain:
        step: dict[str, Any] = {
            "action": _slot_replace(ep.action, slots),
            "data": _template_data(ep.data, slots),
        }
        steps.append(step)

    # Derive a name and description from the first episode's action
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
