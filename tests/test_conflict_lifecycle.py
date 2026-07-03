# test_conflict_lifecycle.py
# Tests for Conflict lifecycle statuses, default resolution policy, and dependent-blocking behaviour.
"""Tests for the Conflict lifecycle (open → resolved / superseded / quarantined).

Invariants under test (CLAUDE.md conflict lifecycle section):
- Contradictory high-confidence writes create an OPEN conflict.
- Default policy: higher confidence wins; tie broken by logical_version; still
  tied → remains open.
- Resolved / superseded / quarantined conflicts do NOT block dependents.
- Open conflicts DO block dependents.
- Every status transition is recorded in Conflict.history (provenance).
- Conflict records are never deleted — audit trail is preserved.
"""
from __future__ import annotations

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.coordination.conflict import (
    dependents_blocked,
    make_conflict,
    mark_quarantined,
    mark_superseded,
    resolve_by_policy,
)
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Conflict, ConflictStatus, Node


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_api(conflict_floor: float = 0.8) -> MemoryAPI:
    cfg = Config(conflict_confidence_floor=conflict_floor)
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def node(nid: str, *, ts: str, confidence: float, source: str = "s", **props: object) -> Node:
    return Node(
        id=nid, type="host", props=dict(props),
        confidence=confidence, source=source,
        first_seen=ts, last_seen=ts,
    )


def _claim(value: object, confidence: float, lv: int) -> dict:
    return {
        "value": value,
        "confidence": confidence,
        "logical_version": lv,
        "source": "test",
        "timestamp": now(),
    }


# ---------------------------------------------------------------------------
# 1. Contradictory high-confidence writes create an OPEN conflict
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_contradiction_creates_open_conflict() -> None:
    api = make_api()
    t = now()
    await api.upsert_node(node("host:1", ts=t, confidence=0.9, status="up"))
    await api.upsert_node(node("host:1", ts=t, confidence=0.9, status="down"))

    conflicts = await api.get_conflicts(node_id="host:1")
    assert len(conflicts) == 1
    assert conflicts[0].status == ConflictStatus.open


@pytest.mark.asyncio
async def test_open_conflict_blocks_dependents() -> None:
    api = make_api()
    t = now()
    await api.upsert_node(node("host:2", ts=t, confidence=0.9, mode="active"))
    await api.upsert_node(node("host:2", ts=t, confidence=0.9, mode="passive"))

    blocked = await api.dependents_blocked_by("host:2", "mode")
    assert blocked is True


# ---------------------------------------------------------------------------
# 2. Default policy: higher confidence wins
# ---------------------------------------------------------------------------

def test_resolve_by_policy_higher_confidence_wins() -> None:
    c = make_conflict(
        "node:x", "status",
        claim_a=_claim("up", confidence=0.95, lv=1),
        claim_b=_claim("down", confidence=0.80, lv=2),
    )
    resolved = resolve_by_policy(c)

    assert resolved is True
    assert c.status == ConflictStatus.resolved
    assert c.resolved is True
    assert c.winning_value == "up"        # claim_a has higher confidence
    assert "claim_a" in c.resolution


def test_resolve_by_policy_claim_b_higher_confidence() -> None:
    c = make_conflict(
        "node:x", "status",
        claim_a=_claim("up", confidence=0.80, lv=1),
        claim_b=_claim("down", confidence=0.95, lv=2),
    )
    resolved = resolve_by_policy(c)

    assert resolved is True
    assert c.winning_value == "down"      # claim_b has higher confidence
    assert "claim_b" in c.resolution


# ---------------------------------------------------------------------------
# 3. Default policy: tie on confidence → higher logical_version wins
# ---------------------------------------------------------------------------

def test_resolve_by_policy_lv_tiebreak_claim_b_wins() -> None:
    c = make_conflict(
        "node:y", "version",
        claim_a=_claim("1.0", confidence=0.9, lv=5),
        claim_b=_claim("2.0", confidence=0.9, lv=10),
    )
    resolved = resolve_by_policy(c)

    assert resolved is True
    assert c.status == ConflictStatus.resolved
    assert c.winning_value == "2.0"       # claim_b has higher lv
    assert "claim_b" in c.resolution
    assert "logical_version" in c.resolution


def test_resolve_by_policy_lv_tiebreak_claim_a_wins() -> None:
    c = make_conflict(
        "node:y", "version",
        claim_a=_claim("1.0", confidence=0.9, lv=20),
        claim_b=_claim("2.0", confidence=0.9, lv=10),
    )
    resolved = resolve_by_policy(c)

    assert resolved is True
    assert c.winning_value == "1.0"       # claim_a has higher lv


# ---------------------------------------------------------------------------
# 4. Fully tied → conflict remains OPEN
# ---------------------------------------------------------------------------

def test_resolve_by_policy_tied_remains_open() -> None:
    c = make_conflict(
        "node:z", "score",
        claim_a=_claim(42, confidence=0.9, lv=7),
        claim_b=_claim(99, confidence=0.9, lv=7),
    )
    resolved = resolve_by_policy(c)

    assert resolved is False
    assert c.status == ConflictStatus.open
    assert c.resolved is False
    assert c.winning_value is None
    assert c.resolution is None


# ---------------------------------------------------------------------------
# 5. MemoryAPI.resolve_conflict — default policy path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_auto_resolve_higher_confidence() -> None:
    api = make_api()
    t = now()
    await api.upsert_node(node("host:3", ts=t, confidence=0.95, role="primary"))
    await api.upsert_node(node("host:3", ts=t, confidence=0.80, role="secondary"))

    conflicts = await api.get_conflicts(node_id="host:3")
    assert len(conflicts) == 1
    cid = conflicts[0].id

    resolved = await api.resolve_conflict(cid)
    assert resolved is True

    c = api._conflicts[cid]
    assert c.status == ConflictStatus.resolved
    assert c.winning_value == "primary"   # 0.95 confidence wins


@pytest.mark.asyncio
async def test_api_auto_resolve_lv_tiebreak() -> None:
    api = make_api()
    t = now()
    # First write: lv=1
    await api.upsert_node(node("host:4", ts=t, confidence=0.9, label="alpha"))
    # Second write: same confidence, lv=2 → conflict
    await api.upsert_node(node("host:4", ts=t, confidence=0.9, label="beta"))

    conflicts = await api.get_conflicts(node_id="host:4")
    assert len(conflicts) == 1
    cid = conflicts[0].id
    c = api._conflicts[cid]

    # claim_b should have lv=2 (the second call to _write_clock)
    assert c.claim_b["logical_version"] > c.claim_a["logical_version"]

    resolved = await api.resolve_conflict(cid)
    assert resolved is True
    assert c.status == ConflictStatus.resolved
    assert c.winning_value == "beta"      # higher lv wins


@pytest.mark.asyncio
async def test_api_auto_resolve_tied_remains_open() -> None:
    """Manually constructed conflict with identical confidence and lv — stays open."""
    api = make_api()
    c = make_conflict(
        "node:tied", "val",
        claim_a=_claim("x", confidence=0.9, lv=3),
        claim_b=_claim("y", confidence=0.9, lv=3),
    )
    api._conflicts[c.id] = c

    resolved = await api.resolve_conflict(c.id)
    assert resolved is False
    assert c.status == ConflictStatus.open


# ---------------------------------------------------------------------------
# 6. MemoryAPI.resolve_conflict — explicit override
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_explicit_resolution_override() -> None:
    api = make_api()
    t = now()
    await api.upsert_node(node("host:5", ts=t, confidence=0.9, status="up"))
    await api.upsert_node(node("host:5", ts=t, confidence=0.9, status="down"))

    conflicts = await api.get_conflicts(node_id="host:5")
    cid = conflicts[0].id

    resolved = await api.resolve_conflict(cid, resolution="operator verified: status=up")
    assert resolved is True

    c = api._conflicts[cid]
    assert c.status == ConflictStatus.resolved
    assert "operator verified" in c.resolution


# ---------------------------------------------------------------------------
# 7. Resolved conflict no longer blocks dependents
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolved_conflict_unblocks_dependents() -> None:
    api = make_api()
    t = now()
    await api.upsert_node(node("host:6", ts=t, confidence=0.95, mode="a"))
    await api.upsert_node(node("host:6", ts=t, confidence=0.80, mode="b"))

    conflicts = await api.get_conflicts(node_id="host:6")
    cid = conflicts[0].id

    assert await api.dependents_blocked_by("host:6", "mode") is True

    await api.resolve_conflict(cid)

    assert await api.dependents_blocked_by("host:6", "mode") is False


# ---------------------------------------------------------------------------
# 8. Superseded status
# ---------------------------------------------------------------------------

def test_mark_superseded_unblocks() -> None:
    c = make_conflict(
        "node:s", "field",
        claim_a=_claim("a", confidence=0.9, lv=1),
        claim_b=_claim("b", confidence=0.9, lv=2),
    )
    assert dependents_blocked(c) is True

    mark_superseded(c, reason="overwritten by v3")

    assert c.status == ConflictStatus.superseded
    assert c.resolved is True
    assert dependents_blocked(c) is False
    assert any(e["event"] == "superseded" for e in c.history)


@pytest.mark.asyncio
async def test_api_supersede_conflict() -> None:
    api = make_api()
    c = make_conflict(
        "node:sup", "f",
        claim_a=_claim("x", confidence=0.9, lv=1),
        claim_b=_claim("y", confidence=0.9, lv=2),
    )
    api._conflicts[c.id] = c

    ok = await api.supersede_conflict(c.id, reason="v3 write")
    assert ok is True
    assert c.status == ConflictStatus.superseded
    assert await api.dependents_blocked_by("node:sup", "f") is False


# ---------------------------------------------------------------------------
# 9. Quarantined status
# ---------------------------------------------------------------------------

def test_mark_quarantined_unblocks() -> None:
    c = make_conflict(
        "node:q", "field",
        claim_a=_claim("a", confidence=0.9, lv=1),
        claim_b=_claim("b", confidence=0.9, lv=1),
    )
    assert dependents_blocked(c) is True

    mark_quarantined(c, reason="reflector: confidence collapsed")

    assert c.status == ConflictStatus.quarantined
    assert c.resolved is True
    assert dependents_blocked(c) is False
    assert any(e["event"] == "quarantined" for e in c.history)


@pytest.mark.asyncio
async def test_api_quarantine_conflict() -> None:
    api = make_api()
    c = make_conflict(
        "node:qua", "g",
        claim_a=_claim("p", confidence=0.9, lv=1),
        claim_b=_claim("q", confidence=0.9, lv=1),
    )
    api._conflicts[c.id] = c

    ok = await api.quarantine_conflict(c.id, reason="reflector decay")
    assert ok is True
    assert c.status == ConflictStatus.quarantined
    assert await api.dependents_blocked_by("node:qua", "g") is False


# ---------------------------------------------------------------------------
# 10. History / audit trail
# ---------------------------------------------------------------------------

def test_conflict_history_records_creation() -> None:
    c = make_conflict(
        "node:h", "val",
        claim_a=_claim("x", confidence=0.9, lv=1),
        claim_b=_claim("y", confidence=0.8, lv=2),
    )
    assert len(c.history) == 1
    assert c.history[0]["event"] == "created"


def test_conflict_history_records_resolution() -> None:
    c = make_conflict(
        "node:h", "val",
        claim_a=_claim("x", confidence=0.9, lv=1),
        claim_b=_claim("y", confidence=0.8, lv=2),
    )
    resolve_by_policy(c)

    events = [e["event"] for e in c.history]
    assert "created" in events
    assert "resolved" in events


def test_conflict_history_records_failed_resolution_attempt() -> None:
    c = make_conflict(
        "node:h", "val",
        claim_a=_claim("x", confidence=0.9, lv=3),
        claim_b=_claim("y", confidence=0.9, lv=3),
    )
    resolve_by_policy(c)  # should fail (tie)

    events = [e["event"] for e in c.history]
    assert "resolve_attempted" in events
    assert "resolved" not in events


def test_conflict_record_preserved_after_resolution() -> None:
    """Conflict records are never deleted — audit trail must be intact after resolve."""
    c = make_conflict(
        "node:h", "val",
        claim_a=_claim("x", confidence=0.95, lv=1),
        claim_b=_claim("y", confidence=0.80, lv=2),
    )
    resolve_by_policy(c)

    # Original claims must still be readable
    assert c.claim_a["value"] == "x"
    assert c.claim_b["value"] == "y"
    assert c.node_id == "node:h"
    assert c.field_name == "val"


# ---------------------------------------------------------------------------
# 11. get_conflicts filtering by status
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_conflicts_filter_by_status_open() -> None:
    api = make_api()
    t = now()
    await api.upsert_node(node("host:7", ts=t, confidence=0.9, x="a"))
    await api.upsert_node(node("host:7", ts=t, confidence=0.9, x="b"))

    open_conflicts = await api.get_conflicts(status=ConflictStatus.open)
    assert len(open_conflicts) == 1

    cid = open_conflicts[0].id
    await api.resolve_conflict(cid, resolution="manual")

    # Should now be empty when filtering for open
    open_after = await api.get_conflicts(status=ConflictStatus.open)
    assert len(open_after) == 0

    # But resolved filter should return it
    resolved_after = await api.get_conflicts(status=ConflictStatus.resolved)
    assert len(resolved_after) == 1


# ---------------------------------------------------------------------------
# 12. Idempotency — resolving an already-resolved conflict is safe
# ---------------------------------------------------------------------------

def test_resolve_already_resolved_is_idempotent() -> None:
    c = make_conflict(
        "node:i", "v",
        claim_a=_claim("a", confidence=0.9, lv=1),
        claim_b=_claim("b", confidence=0.8, lv=2),
    )
    resolve_by_policy(c)
    first_resolution = c.resolution

    # Call again — should not change anything
    result = resolve_by_policy(c)
    assert result is True
    assert c.resolution == first_resolution    # unchanged
    assert c.status == ConflictStatus.resolved


def test_supersede_already_resolved_is_idempotent() -> None:
    c = make_conflict(
        "node:i2", "v",
        claim_a=_claim("a", confidence=0.9, lv=1),
        claim_b=_claim("b", confidence=0.8, lv=2),
    )
    resolve_by_policy(c)

    mark_superseded(c, reason="another write")
    # Already resolved — should be no-op (stays resolved, not superseded)
    assert c.status == ConflictStatus.resolved
