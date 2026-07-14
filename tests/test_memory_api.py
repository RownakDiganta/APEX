# test_memory_api.py
# Clock-skew and logical_version LWW tests for MemoryAPI.upsert_node.
"""Tests for the logical_version LWW policy in MemoryAPI.

Section summary (CLAUDE.md LWW policy):
  - logical_version is assigned by MemoryAPI at call time (monotonic counter).
  - LWW comparison: logical_version first; wall-clock timestamp tie-breaker only.
  - Wall-clock timestamps are observational metadata, not ordering authority.
  - High-confidence contradictions still produce a Conflict regardless of version.
"""
from __future__ import annotations

import time


from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node


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


def node(
    nid: str,
    *,
    ts: str,
    confidence: float = 0.5,
    source: str = "agent",
    **props: object,
) -> Node:
    return Node(
        id=nid,
        type="host",
        props=dict(props),
        confidence=confidence,
        source=source,
        first_seen=ts,
        last_seen=ts,
    )


# ---------------------------------------------------------------------------
# Provenance — logical_version is recorded per field
# ---------------------------------------------------------------------------

class TestProvenanceRecordsLogicalVersion:
    async def test_first_write_stores_logical_version(self) -> None:
        api = make_api()
        t = now()
        await api.upsert_node(node("n1", ts=t, ip="10.0.0.1"))
        stored = await api._graph.get_node("n1")
        assert stored is not None
        prov = stored._provenance.get("ip", {})
        assert "logical_version" in prov, "provenance must include logical_version"
        assert prov["logical_version"] >= 1

    async def test_second_write_updates_logical_version_in_provenance(self) -> None:
        api = make_api()
        t1 = now()
        await api.upsert_node(node("n1", ts=t1, ip="1.1.1.1", confidence=0.5))
        first_lv = (await api._graph.get_node("n1"))._provenance["ip"]["logical_version"]

        time.sleep(0.01)
        t2 = now()
        await api.upsert_node(node("n1", ts=t2, ip="2.2.2.2", confidence=0.5))
        second_lv = (await api._graph.get_node("n1"))._provenance["ip"]["logical_version"]

        assert second_lv > first_lv, "second write must record higher logical_version"

    async def test_logical_version_increases_monotonically_across_nodes(self) -> None:
        api = make_api()
        t = now()
        await api.upsert_node(node("na", ts=t, ip="1.0.0.1"))
        await api.upsert_node(node("nb", ts=t, ip="1.0.0.2"))

        lv_a = (await api._graph.get_node("na"))._provenance["ip"]["logical_version"]
        lv_b = (await api._graph.get_node("nb"))._provenance["ip"]["logical_version"]
        assert lv_b > lv_a, "each upsert_node call must advance the global write clock"

    async def test_provenance_includes_timestamp_and_source(self) -> None:
        api = make_api()
        t = now()
        await api.upsert_node(node("n1", ts=t, ip="10.0.0.1", source="scanner"))
        prov = (await api._graph.get_node("n1"))._provenance["ip"]
        assert prov["source"] == "scanner"
        assert prov["timestamp"] == t
        assert "logical_version" in prov


# ---------------------------------------------------------------------------
# Clock-skew: call order (logical_version) beats wall-clock timestamp
# ---------------------------------------------------------------------------

class TestClockSkewLWW:
    async def test_second_call_wins_with_earlier_timestamp(self) -> None:
        """Writer B submitted AFTER writer A but carries an EARLIER wall-clock.
        Expected: B wins because write call order is authoritative.
        """
        api = make_api()
        t_earlier = now()
        time.sleep(0.01)
        t_later = now()

        # A submitted first: low confidence, later wall-clock
        await api.upsert_node(node("n1", ts=t_later, ip="192.0.2.1", confidence=0.5))
        # B submitted second: low confidence, earlier wall-clock — but higher write_lv
        await api.upsert_node(node("n1", ts=t_earlier, ip="192.0.2.2", confidence=0.5))

        stored = await api._graph.get_node("n1")
        assert stored is not None
        assert stored.props["ip"] == "192.0.2.2", (
            "B must win: higher write_lv beats A's newer wall-clock timestamp"
        )

    async def test_first_call_loses_despite_later_timestamp(self) -> None:
        """Mirror of the above: A has a later timestamp but was submitted first.
        Under logical_version ordering, A (write_lv=N) loses to B (write_lv=N+1).
        """
        api = make_api()
        t_early = now()
        time.sleep(0.01)
        t_later = now()

        # A submitted first with LATER timestamp
        await api.upsert_node(node("n1", ts=t_later, ip="skew-A", confidence=0.5))
        # B submitted second with EARLIER timestamp — write_lv wins
        await api.upsert_node(node("n1", ts=t_early, ip="skew-B", confidence=0.5))

        stored = await api._graph.get_node("n1")
        assert stored is not None
        assert stored.props["ip"] == "skew-B", (
            "skew-B wins despite earlier timestamp because it was submitted second"
        )

    async def test_identical_timestamps_resolved_by_logical_version(self) -> None:
        """When both writes carry the same timestamp, logical_version is decisive."""
        api = make_api()
        t = now()  # same timestamp for both

        await api.upsert_node(node("n1", ts=t, ip="same-ts-first", confidence=0.5))
        await api.upsert_node(node("n1", ts=t, ip="same-ts-second", confidence=0.5))

        stored = await api._graph.get_node("n1")
        assert stored is not None
        assert stored.props["ip"] == "same-ts-second", (
            "when timestamps are identical, the later call (higher write_lv) must win"
        )

    async def test_multiple_fields_each_resolved_independently(self) -> None:
        """Clock-skew on multi-field writes: each field's provenance is independent."""
        api = make_api()
        t_early = now()
        time.sleep(0.01)
        t_late = now()

        # Write A first: ip=A with late timestamp, os=linux
        await api.upsert_node(node("n1", ts=t_late, ip="ip-A", os="linux", confidence=0.5))

        # Write B second: ip=B with early timestamp (clock-skewed), hostname=host-B
        await api.upsert_node(
            node("n1", ts=t_early, ip="ip-B", hostname="host-B", confidence=0.5)
        )

        stored = await api._graph.get_node("n1")
        assert stored is not None
        # B's write_lv is higher → ip-B wins despite earlier timestamp
        assert stored.props["ip"] == "ip-B"
        # os field from A is preserved (B didn't touch it)
        assert stored.props["os"] == "linux"
        # hostname from B is new — written unconditionally
        assert stored.props["hostname"] == "host-B"

    async def test_write_clock_persists_across_different_nodes(self) -> None:
        """The write_clock is global: writes to different nodes share the counter."""
        api = make_api()
        t = now()

        await api.upsert_node(node("nx", ts=t, ip="10.0.1.1"))   # clock=1
        await api.upsert_node(node("ny", ts=t, ip="10.0.1.2"))   # clock=2
        await api.upsert_node(node("nx", ts=t, ip="10.0.1.3", confidence=0.5))  # clock=3 → wins

        stored_x = await api._graph.get_node("nx")
        assert stored_x is not None
        assert stored_x.props["ip"] == "10.0.1.3", "third call wins for nx"

        lv_x_ip = stored_x._provenance["ip"]["logical_version"]
        stored_y = await api._graph.get_node("ny")
        assert stored_y is not None
        lv_y_ip = stored_y._provenance["ip"]["logical_version"]
        assert lv_x_ip > lv_y_ip, "nx's third write must have higher lv than ny's second"


# ---------------------------------------------------------------------------
# Edge LWW — same logical_version policy
# ---------------------------------------------------------------------------

class TestEdgeClockSkewLWW:
    async def test_second_edge_call_wins_with_earlier_timestamp(self) -> None:
        """Edge LWW follows the same logical_version-first policy as node fields."""
        api = make_api()
        await api.upsert_node(node("a", ts=now()))
        await api.upsert_node(node("b", ts=now()))

        eid = new_id()
        t_early = now()
        time.sleep(0.01)
        t_late = now()

        e1 = Edge(eid, "a", "b", "type-first", {}, 0.5, "s", t_late, t_late)
        await api.upsert_edge(e1)  # write_lv = N, later timestamp

        e2 = Edge(eid, "a", "b", "type-second", {}, 0.5, "s", t_early, t_early)
        await api.upsert_edge(e2)  # write_lv = N+1, earlier timestamp

        result = await api._graph.get_edge(eid)
        assert result is not None
        assert result.type == "type-second", (
            "second edge write must win (higher write_lv) despite earlier wall-clock"
        )

    async def test_first_edge_call_loses_to_second_regardless_of_timestamp(self) -> None:
        """First call (even with newer timestamp) loses to second call in all cases."""
        api = make_api()
        await api.upsert_node(node("a", ts=now()))
        await api.upsert_node(node("b", ts=now()))

        eid = new_id()
        t = now()

        # Both edges get the same timestamp — only call order matters
        e1 = Edge(eid, "a", "b", "v-first", {}, 0.5, "s", t, t)
        await api.upsert_edge(e1)
        e2 = Edge(eid, "a", "b", "v-second", {}, 0.5, "s", t, t)
        await api.upsert_edge(e2)

        result = await api._graph.get_edge(eid)
        assert result is not None
        assert result.type == "v-second"
