"""EKG conflict detection and resolution policy.

This module provides helpers used by MemoryAPI.upsert_node.  The actual
Conflict records are stored inside MemoryAPI._conflicts.

Resolution policy (default):
1. Higher-confidence claim wins.
2. Ties broken by recency (later timestamp wins).
3. Unresolved conflicts block any component that depends on the contested field.
"""
from __future__ import annotations

import logging
from typing import Any

from memfabric.ids import new_id, now
from memfabric.types import Conflict

logger = logging.getLogger(__name__)


def make_conflict(
    node_id: str,
    field_name: str,
    claim_a: dict[str, Any],
    claim_b: dict[str, Any],
) -> Conflict:
    """Create a new Conflict record from two competing claims."""
    return Conflict(
        id=new_id(),
        node_id=node_id,
        field_name=field_name,
        claim_a=dict(claim_a),
        claim_b=dict(claim_b),
        timestamp=now(),
    )


def resolve_by_policy(conflict: Conflict) -> str:
    """Apply the default resolution policy and return the winning value.

    Policy:
    - Higher confidence wins.
    - Ties resolved by recency (later ``timestamp`` in the claim wins).
    - Returns a string describing the resolution, suitable for
      ``Conflict.resolution``.
    """
    conf_a = float(conflict.claim_a.get("confidence", 0.0))
    conf_b = float(conflict.claim_b.get("confidence", 0.0))

    if conf_a > conf_b:
        winner = "claim_a"
        winning_value = conflict.claim_a.get("value")
    elif conf_b > conf_a:
        winner = "claim_b"
        winning_value = conflict.claim_b.get("value")
    else:
        # Tie-break by timestamp (lexicographic ISO-8601 comparison)
        ts_a = str(conflict.claim_a.get("timestamp", ""))
        ts_b = str(conflict.claim_b.get("timestamp", ""))
        if ts_b >= ts_a:
            winner = "claim_b"
            winning_value = conflict.claim_b.get("value")
        else:
            winner = "claim_a"
            winning_value = conflict.claim_a.get("value")

    resolution = f"{winner} wins (value={winning_value!r})"
    logger.info(
        "conflict resolved node=%s field=%s → %s",
        conflict.node_id, conflict.field_name, resolution,
    )
    return resolution


def dependents_blocked(conflict: Conflict) -> bool:
    """Return True if dependents should be blocked by this unresolved conflict."""
    return not conflict.resolved
