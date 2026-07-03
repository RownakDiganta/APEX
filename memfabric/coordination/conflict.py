# conflict.py
# EKG conflict detection and resolution policy — lifecycle management for Conflict records.
"""EKG conflict detection and resolution policy.

This module provides helpers used by ``MemoryAPI.upsert_node`` and by
orchestrators that need to inspect or resolve open conflicts.  The actual
Conflict records are stored inside ``MemoryAPI._conflicts``.

Lifecycle statuses (see ``ConflictStatus``):
  open        — detected, blocks dependents
  resolved    — winner chosen; dependents may proceed
  superseded  — a later write made both claims moot
  quarantined — Reflector marked the field as untrusted

Default resolution policy (applied by ``resolve_by_policy``):
  1. Higher confidence claim wins.
  2. Tie: higher ``logical_version`` wins.
  3. Still tied: conflict remains ``open``.

Unresolved (open) conflicts MUST block any downstream component that
depends on the contested field.  ``dependents_blocked()`` encodes this rule
and must be consulted before any logic that reads the contested value.
"""
from __future__ import annotations

import logging
from typing import Any

from memfabric.ids import new_id, now
from memfabric.types import Conflict, ConflictStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def make_conflict(
    node_id: str,
    field_name: str,
    claim_a: dict[str, Any],
    claim_b: dict[str, Any],
) -> Conflict:
    """Create a new ``open`` Conflict record from two competing claims."""
    ts = now()
    c = Conflict(
        id=new_id(),
        node_id=node_id,
        field_name=field_name,
        claim_a=dict(claim_a),
        claim_b=dict(claim_b),
        timestamp=ts,
        status=ConflictStatus.open,
        resolved=False,
    )
    c.history.append({
        "event": "created",
        "timestamp": ts,
        "detail": f"high-confidence contradiction on field '{field_name}'",
    })
    return c


# ---------------------------------------------------------------------------
# Default resolution policy
# ---------------------------------------------------------------------------

def resolve_by_policy(conflict: Conflict) -> bool:
    """Apply the default resolution policy in-place.

    Policy:
    1. Higher ``confidence`` claim wins.
    2. Tie → higher ``logical_version`` claim wins.
    3. Still tied → conflict remains ``open`` (returns ``False``).

    Returns ``True`` if the conflict was resolved, ``False`` if it remains open.

    The conflict record is mutated:
    - ``status`` → ``ConflictStatus.resolved`` (or stays ``open``).
    - ``winning_value`` set to the winning claim's value.
    - ``resolution`` set to a human-readable description.
    - ``resolved`` set to ``True`` (legacy field).
    - An entry appended to ``history``.
    """
    if conflict.status != ConflictStatus.open:
        # Already settled — nothing to do.
        return conflict.status == ConflictStatus.resolved

    conf_a = float(conflict.claim_a.get("confidence", 0.0))
    conf_b = float(conflict.claim_b.get("confidence", 0.0))
    lv_a = int(conflict.claim_a.get("logical_version", 0))
    lv_b = int(conflict.claim_b.get("logical_version", 0))

    if conf_a > conf_b:
        winner = "claim_a"
        winning_value = conflict.claim_a.get("value")
        reason = f"claim_a has higher confidence ({conf_a} > {conf_b})"
    elif conf_b > conf_a:
        winner = "claim_b"
        winning_value = conflict.claim_b.get("value")
        reason = f"claim_b has higher confidence ({conf_b} > {conf_a})"
    elif lv_a > lv_b:
        winner = "claim_a"
        winning_value = conflict.claim_a.get("value")
        reason = f"claim_a has higher logical_version ({lv_a} > {lv_b})"
    elif lv_b > lv_a:
        winner = "claim_b"
        winning_value = conflict.claim_b.get("value")
        reason = f"claim_b has higher logical_version ({lv_b} > {lv_a})"
    else:
        # Cannot resolve — remain open.
        ts = now()
        conflict.history.append({
            "event": "resolve_attempted",
            "timestamp": ts,
            "detail": f"tie on confidence ({conf_a}) and logical_version ({lv_a}); remains open",
        })
        logger.info(
            "conflict unresolved (tied) node=%s field=%s id=%s",
            conflict.node_id, conflict.field_name, conflict.id,
        )
        return False

    resolution = f"{winner} wins — {reason} (value={winning_value!r})"
    ts = now()
    conflict.status = ConflictStatus.resolved
    conflict.resolved = True
    conflict.winning_value = winning_value
    conflict.resolution = resolution
    conflict.history.append({
        "event": "resolved",
        "timestamp": ts,
        "detail": resolution,
    })
    logger.info(
        "conflict resolved node=%s field=%s → %s id=%s",
        conflict.node_id, conflict.field_name, resolution, conflict.id,
    )
    return True


def mark_superseded(conflict: Conflict, reason: str = "") -> None:
    """Mark a conflict superseded (a later write made both claims moot).

    Superseded conflicts do NOT block dependents.
    """
    if conflict.status in (ConflictStatus.resolved, ConflictStatus.superseded):
        return
    ts = now()
    conflict.status = ConflictStatus.superseded
    conflict.resolved = True   # superseded also unblocks
    conflict.resolution = reason or "superseded by a later authoritative write"
    conflict.history.append({
        "event": "superseded",
        "timestamp": ts,
        "detail": conflict.resolution,
    })
    logger.info(
        "conflict superseded node=%s field=%s id=%s",
        conflict.node_id, conflict.field_name, conflict.id,
    )


def mark_quarantined(conflict: Conflict, reason: str = "") -> None:
    """Mark a conflict quarantined — field is considered untrusted.

    Quarantined conflicts also unblock dependents (they must treat the field
    as absent, not as ambiguous).
    """
    ts = now()
    conflict.status = ConflictStatus.quarantined
    conflict.resolved = True   # quarantined unblocks (field treated as absent)
    conflict.resolution = reason or "quarantined by Reflector — field is untrusted"
    conflict.history.append({
        "event": "quarantined",
        "timestamp": ts,
        "detail": conflict.resolution,
    })
    logger.warning(
        "conflict quarantined node=%s field=%s id=%s",
        conflict.node_id, conflict.field_name, conflict.id,
    )


# ---------------------------------------------------------------------------
# Dependent-blocking predicate
# ---------------------------------------------------------------------------

def dependents_blocked(conflict: Conflict) -> bool:
    """Return True if dependents MUST be blocked by this conflict.

    Only ``open`` conflicts block dependents.  ``resolved``, ``superseded``,
    and ``quarantined`` conflicts do not block — the ambiguity has been
    settled (or the field has been removed from trusted state).
    """
    return conflict.status == ConflictStatus.open
