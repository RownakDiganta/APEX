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
  quarantined — Reflector marked the field as untrusted; treat as absent

Default resolution policy (applied by ``resolve_by_policy`` / ``choose_conflict_winner``):
  1. Higher confidence claim wins.
  2. Tie: higher ``logical_version`` wins.
  3. Still tied: conflict remains ``open``.

Unresolved (open) conflicts MUST block any downstream component that
depends on the contested field.  ``dependents_blocked()`` encodes this rule.

``choose_conflict_winner`` is a **pure function** — it never mutates the
Conflict record.  ``_apply_conflict_resolution_locked`` in ``MemoryAPI``
uses it to calculate the winner before performing any writes, so that the
conflict is never marked resolved before graph and index persistence succeeds.

``check_conflict_dependencies`` is a pure function that returns only the
subset of ``blocked_fields`` that a task actually depends on.  The central
execution guard uses this so that an unrelated conflict on node B cannot
block a task that only reads node A.
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from memfabric.ids import new_id, now
from memfabric.types import Conflict, ConflictStatus

if TYPE_CHECKING:
    from memfabric.types import BlockedClaim, ClaimDependency

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pure result of winner selection
# ---------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class ResolutionDecision:
    """The output of ``choose_conflict_winner`` — no side effects, no mutation.

    ``winner`` is one of ``"claim_a"``, ``"claim_b"``, or ``"tie"``.
    When ``winner == "tie"``, ``winning_value`` is ``None`` and the caller
    must leave the conflict open.

    ``method`` records which tiebreaker was applied:
      ``"confidence"``       — higher confidence claim won.
      ``"logical_version"``  — confidence was tied; higher logical_version won.
      ``"tie"``              — both confidence and logical_version are equal.
    """
    winner: str
    winning_value: object | None
    reason: str
    method: str


# ---------------------------------------------------------------------------
# Pure winner selection (no mutation)
# ---------------------------------------------------------------------------

def choose_conflict_winner(conflict: Conflict) -> ResolutionDecision | None:
    """Select the winning claim without mutating the Conflict record.

    Returns ``None`` when the conflict is not ``open`` (already settled in
    any terminal state) — the caller should treat this as "nothing to do".

    Returns a ``ResolutionDecision`` with ``winner="tie"`` when both
    confidence and logical_version are equal; the caller is responsible for
    recording a non-terminal tie-attempt history entry and returning
    ``False`` (the conflict stays open).

    This function is intentionally side-effect-free.  All mutations — history
    appends, status transitions, winning_value assignment — must happen in the
    caller after all persistence steps succeed.
    """
    if conflict.status != ConflictStatus.open:
        return None

    conf_a = float(conflict.claim_a.get("confidence", 0.0))
    conf_b = float(conflict.claim_b.get("confidence", 0.0))
    lv_a = int(conflict.claim_a.get("logical_version", 0))
    lv_b = int(conflict.claim_b.get("logical_version", 0))

    if conf_a > conf_b:
        return ResolutionDecision(
            winner="claim_a",
            winning_value=conflict.claim_a.get("value"),
            reason=f"claim_a has higher confidence ({conf_a} > {conf_b})",
            method="confidence",
        )
    if conf_b > conf_a:
        return ResolutionDecision(
            winner="claim_b",
            winning_value=conflict.claim_b.get("value"),
            reason=f"claim_b has higher confidence ({conf_b} > {conf_a})",
            method="confidence",
        )
    if lv_a > lv_b:
        return ResolutionDecision(
            winner="claim_a",
            winning_value=conflict.claim_a.get("value"),
            reason=f"claim_a has higher logical_version ({lv_a} > {lv_b})",
            method="logical_version",
        )
    if lv_b > lv_a:
        return ResolutionDecision(
            winner="claim_b",
            winning_value=conflict.claim_b.get("value"),
            reason=f"claim_b has higher logical_version ({lv_b} > {lv_a})",
            method="logical_version",
        )
    return ResolutionDecision(
        winner="tie",
        winning_value=None,
        reason=f"tie on confidence ({conf_a}) and logical_version ({lv_a})",
        method="tie",
    )


# ---------------------------------------------------------------------------
# Dependency-specific conflict guard (pure)
# ---------------------------------------------------------------------------

def check_conflict_dependencies(
    claim_deps: "tuple[ClaimDependency, ...] | list[ClaimDependency]",
    blocked_fields: "list[BlockedClaim]",
) -> "list[BlockedClaim]":
    """Return the subset of ``blocked_fields`` that the task actually depends on.

    Pure function — no I/O, no mutation.  Used by the central execution guard
    in ``apex_host/graph.py`` so that a task is blocked only when at least one
    of its declared ``ClaimDependency`` values overlaps with an open
    ``BlockedClaim`` in the evidence bundle.

    An unrelated open conflict on node B cannot block a task whose
    ``claim_dependencies`` reference only node A.

    ``claim_deps`` is the ``TaskSpec.claim_dependencies`` tuple.
    ``blocked_fields`` is ``EvidenceBundle.blocked_fields``.

    Returns an empty list when there is no overlap (task may proceed).
    """
    open_index: dict[tuple[str, str], BlockedClaim] = {
        (bc.node_id, bc.field_name): bc for bc in blocked_fields
    }
    blocking: list[BlockedClaim] = []
    for dep in claim_deps:
        key = (dep.node_id, dep.field_name)
        if key in open_index:
            blocking.append(open_index[key])
    return blocking


# ---------------------------------------------------------------------------
# Mutating lifecycle helpers (called only by MemoryAPI after persistence)
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
        claim_a=copy.deepcopy(claim_a),
        claim_b=copy.deepcopy(claim_b),
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


def resolve_by_policy(conflict: Conflict) -> bool:
    """Apply the default resolution policy in-place.

    Uses ``choose_conflict_winner`` for the pure decision, then mutates the
    conflict record (status, winning_value, resolution, history, resolved).

    Returns ``True`` if resolved, ``False`` if the conflict remains open
    (tied confidence and logical_version, or already non-open).

    NOTE: In the atomic resolution path (``MemoryAPI._apply_conflict_resolution_locked``),
    mutations to the conflict record happen AFTER graph and index writes
    succeed.  This function is retained for callers that perform non-atomic
    updates (e.g., explicit orchestrator overrides that don't need a graph
    write, or legacy test fixtures).
    """
    if conflict.status != ConflictStatus.open:
        return conflict.status == ConflictStatus.resolved

    decision = choose_conflict_winner(conflict)
    if decision is None:
        return False

    if decision.winner == "tie":
        ts = now()
        conflict.history.append({
            "event": "resolve_attempted",
            "timestamp": ts,
            "detail": decision.reason + "; remains open",
        })
        logger.info(
            "conflict unresolved (tied) node=%s field=%s id=%s",
            conflict.node_id, conflict.field_name, conflict.id,
        )
        return False

    resolution = f"{decision.winner} wins — {decision.reason} (value={decision.winning_value!r})"
    ts = now()
    conflict.status = ConflictStatus.resolved
    conflict.resolved = True
    conflict.winning_value = decision.winning_value
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
    conflict.resolved = True
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
    """Mark a conflict quarantined — field is considered untrusted / absent.

    Quarantined conflicts also unblock dependents in the "contested" sense
    (they are not open), but the quarantined field must be treated as
    **absent**, not as a trusted value.  Planners and capability extractors
    must not use a quarantined field to derive capabilities.

    The ``MemoryAPI`` exposes quarantined fields through
    ``SubgraphView.quarantined_fields`` so that ``capabilities_from_subgraph``
    and planners can apply the correct "absent" treatment without needing to
    inspect the conflict registry directly.
    """
    ts = now()
    conflict.status = ConflictStatus.quarantined
    conflict.resolved = True
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
