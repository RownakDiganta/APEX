# test_conflict.py
# Tests for conflict detection: high-confidence contradiction handling and logical_version in Conflict records.
"""Tests for the conflict detection policy in MemoryAPI.

Key invariants (CLAUDE.md §1.3 and §4):
- Conflict detection is EPISTEMIC, not temporal.  When two writes with
  confidence >= conflict_confidence_floor disagree on a field value, a Conflict
  is created regardless of logical_version ordering.
- The Conflict.claim_b dict includes "logical_version" so the ordering context
  can be inspected by the orchestrator.
- Below-floor confidence writes apply LWW silently; no Conflict is created.
- After a conflict, the EXISTING value is preserved (the new write is rejected
  for that field) until the orchestrator resolves the Conflict.
"""
from __future__ import annotations

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Conflict, Node


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
        id=nid,
        type="host",
        props=dict(props),
        confidence=confidence,
        source=source,
        first_seen=ts,
        last_seen=ts,
    )


def conflicts(api: MemoryAPI) -> list[Conflict]:
    return list(api._conflicts.values())


# ---------------------------------------------------------------------------
# Conflict fires on high-confidence contradiction
# ---------------------------------------------------------------------------

class TestConflictDetection:
    async def test_high_confidence_contradiction_creates_conflict(self) -> None:
        """Two high-confidence writes with different values → Conflict created."""
        api = make_api(conflict_floor=0.8)
        t = now()

        await api.upsert_node(node("h1", ts=t, confidence=0.9, source="scanner", ip="1.2.3.4"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, source="agent", ip="5.6.7.8"))

        cs = conflicts(api)
        assert len(cs) == 1
        c = cs[0]
        assert c.node_id == "h1"
        assert c.field_name == "ip"

    async def test_conflicting_field_value_is_preserved(self) -> None:
        """Existing value must NOT be silently overwritten by a conflicting write."""
        api = make_api(conflict_floor=0.8)
        t = now()

        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="original"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="conflicting"))

        stored = await api._graph.get_node("h1")
        assert stored is not None
        assert stored.props["ip"] == "original", "original value must be preserved when conflict fires"

    async def test_conflict_claim_a_holds_original_value(self) -> None:
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="claim-a"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="claim-b"))

        c = conflicts(api)[0]
        assert c.claim_a["value"] == "claim-a"

    async def test_conflict_claim_b_holds_new_value(self) -> None:
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="old"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="new"))

        c = conflicts(api)[0]
        assert c.claim_b["value"] == "new"

    async def test_conflict_claim_b_includes_logical_version(self) -> None:
        """claim_b must carry logical_version so the orchestrator can see causal order."""
        api = make_api(conflict_floor=0.8)
        t = now()

        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="v1"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="v2"))

        c = conflicts(api)[0]
        assert "logical_version" in c.claim_b, (
            "claim_b must include logical_version so the orchestrator can determine causal order"
        )
        assert c.claim_b["logical_version"] >= 2, (
            "the second write's logical_version must be ≥ 2 (at least two upsert_node calls)"
        )

    async def test_conflict_claim_a_includes_logical_version(self) -> None:
        """claim_a (the existing prov record) must also carry logical_version."""
        api = make_api(conflict_floor=0.8)
        t = now()

        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="v1"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="v2"))

        c = conflicts(api)[0]
        assert "logical_version" in c.claim_a, "claim_a must include logical_version"
        assert c.claim_a["logical_version"] == 1

    async def test_conflict_claim_b_lv_is_greater_than_claim_a_lv(self) -> None:
        """In sequential writes: claim_b (second write) has a higher write_lv."""
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="a"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="b"))

        c = conflicts(api)[0]
        assert c.claim_b["logical_version"] > c.claim_a["logical_version"]

    async def test_conflict_carries_source_and_timestamp(self) -> None:
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, source="nmap", ip="10.0.0.1"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, source="agent", ip="10.0.0.2"))

        c = conflicts(api)[0]
        assert c.claim_a["source"] == "nmap"
        assert c.claim_b["source"] == "agent"
        assert c.claim_a["timestamp"] == t
        assert c.claim_b["timestamp"] == t

    async def test_multiple_fields_conflict_independently(self) -> None:
        """Two fields both at high confidence both contradicted → two Conflicts."""
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(
            node("h1", ts=t, confidence=0.9, ip="1.2.3.4", os="linux")
        )
        await api.upsert_node(
            node("h1", ts=t, confidence=0.9, ip="9.8.7.6", os="windows")
        )

        cs = conflicts(api)
        assert len(cs) == 2
        field_names = {c.field_name for c in cs}
        assert field_names == {"ip", "os"}

    async def test_conflict_has_unique_id_and_node_id(self) -> None:
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="a"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="b"))

        c = conflicts(api)[0]
        assert c.id != ""
        assert c.node_id == "h1"
        assert c.resolved is False

    async def test_conflict_id_is_unique_per_conflict(self) -> None:
        """Each Conflict must have a distinct id even when they share node and field."""
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="a"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="b"))
        # Force a third write that also contradicts "a" (b was rejected → "a" still in place)
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="c"))

        cs = conflicts(api)
        assert len(cs) == 2
        ids = [c.id for c in cs]
        assert len(set(ids)) == 2, "all conflict IDs must be unique"


# ---------------------------------------------------------------------------
# Below-floor confidence: no Conflict — silent LWW
# ---------------------------------------------------------------------------

class TestNoConflictBelowFloor:
    async def test_low_confidence_write_does_not_trigger_conflict(self) -> None:
        """When either write is below the floor, LWW applies silently."""
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="high-conf"))
        await api.upsert_node(node("h1", ts=t, confidence=0.5, ip="low-conf"))  # below floor

        assert len(conflicts(api)) == 0, "no conflict when new write is below confidence floor"

    async def test_both_low_confidence_no_conflict(self) -> None:
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.5, ip="v1"))
        await api.upsert_node(node("h1", ts=t, confidence=0.5, ip="v2"))

        assert len(conflicts(api)) == 0

    async def test_low_confidence_writes_apply_lww(self) -> None:
        """Below-floor: the second (higher logical_version) write wins normally."""
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.5, ip="old"))
        await api.upsert_node(node("h1", ts=t, confidence=0.5, ip="new"))

        stored = await api._graph.get_node("h1")
        assert stored is not None
        assert stored.props["ip"] == "new"

    async def test_exact_floor_both_sides_triggers_conflict(self) -> None:
        """Confidence exactly equal to the floor (>=) must trigger a Conflict."""
        floor = 0.8
        api = make_api(conflict_floor=floor)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=floor, ip="v1"))
        await api.upsert_node(node("h1", ts=t, confidence=floor, ip="v2"))

        assert len(conflicts(api)) == 1, "confidence exactly at floor must count as high-confidence"

    async def test_same_value_no_conflict(self) -> None:
        """Identical values at high confidence do NOT create a Conflict."""
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="same"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="same"))

        assert len(conflicts(api)) == 0, "same value at high confidence must not conflict"


# ---------------------------------------------------------------------------
# Conflict is independent of logical_version ordering
# ---------------------------------------------------------------------------

class TestConflictIsEpistemic:
    async def test_conflict_fires_even_when_new_write_has_higher_lv(self) -> None:
        """A logically-later write that contradicts a high-confidence field still conflicts.

        This confirms conflict detection is EPISTEMIC (do two authoritative
        sources disagree?) not temporal (which is newer?).
        """
        api = make_api(conflict_floor=0.8)
        t = now()

        # First write: high confidence
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="authority-A"))
        # Second write: higher write_lv but contradicting value
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="authority-B"))

        cs = conflicts(api)
        assert len(cs) == 1, (
            "Conflict must fire even though the second write has a higher logical_version"
        )
        c = cs[0]
        # The logically-later write (higher lv) is in claim_b
        assert c.claim_b["value"] == "authority-B"
        assert c.claim_b["logical_version"] > c.claim_a["logical_version"]

    async def test_conflict_does_not_apply_lww_for_conflicted_field(self) -> None:
        """When a Conflict fires, the existing value stays — LWW is NOT applied."""
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="kept"))
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="rejected"))

        stored = await api._graph.get_node("h1")
        assert stored is not None
        assert stored.props["ip"] == "kept", (
            "LWW must not apply to a conflicted field — existing value is preserved"
        )

    async def test_non_conflicted_fields_still_updated_normally(self) -> None:
        """Conflict on field X does not block LWW on unrelated field Y."""
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="old", os="linux"))
        # ip conflicts (both high confidence); hostname is new → unconditional write
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="conflict", hostname="server"))

        stored = await api._graph.get_node("h1")
        assert stored is not None
        assert stored.props["ip"] == "old"      # conflict: original preserved
        assert stored.props["os"] == "linux"     # untouched
        assert stored.props["hostname"] == "server"  # new field: written

    async def test_conflict_count_accumulates_across_writes(self) -> None:
        """Each contradicting pair (field, sources) adds a separate Conflict record."""
        api = make_api(conflict_floor=0.8)
        t = now()
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="a"))
        # Second write conflicts on ip → 1 conflict, "a" preserved
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="b"))
        assert len(conflicts(api)) == 1

        # Third write conflicts on ip (still "a") → 2 conflicts total
        await api.upsert_node(node("h1", ts=t, confidence=0.9, ip="c"))
        assert len(conflicts(api)) == 2
