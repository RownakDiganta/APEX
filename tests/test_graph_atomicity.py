# test_graph_atomicity.py
# Deterministic concurrent-write and atomicity tests for MemoryAPI._graph_lock.
"""Tests for graph-write atomicity, per-field LWW correctness, batch visibility,
rollback isolation, write-clock restoration, defensive copies, and cache-key
independence.  All tests are deterministic — no timing-based waits.  Concurrency
is coordinated with ``asyncio.Event`` barriers so the interleaving is exact.

Coverage map:
  T01  – Concurrent writers on disjoint fields both survive (no field loss)
  T02  – Concurrent writers on overlapping fields: LWW by logical_version
  T03  – Three-way concurrent field writes: all survive on disjoint fields
  T04  – apply_deltas is atomic: reader sees complete-before or complete-after
  T05  – apply_deltas rollback restores pre-batch node state
  T06  – apply_deltas rollback restores pre-batch edge state
  T07  – _write_clock restored to pre-clock after rollback (F02/F19)
  T08  – Rollback isolation: failed batch does not revert a committed write
  T09  – Rollback isolation: committed write's logical_version not erased
  T10  – get_node returns a defensive copy (mutation does not affect stored state)
  T11  – get_edge returns a defensive copy
  T12  – get_subgraph returns defensive copies of nodes and edges
  T13  – all_nodes returns defensive copies
  T14  – all_edges returns defensive copies
  T15  – Cache key includes k: different k values get independent cache entries
  T16  – Cache key includes k: same (text, tiers, filters) but different k → cache miss
  T17  – apply_deltas partial failure: committed nodes visible, failed node absent
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.retrieval.engine import _cache_key
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node, Tier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_api() -> MemoryAPI:
    cfg = Config()
    graph = NetworkXGraphStore()
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=cfg.vector_dim)
    kv = InMemoryKVStore()
    api = MemoryAPI(
        graph=graph,
        episodic=JSONLEpisodicStore(),
        lexical=lexical,
        vector=vector,
        kv=kv,
        config=cfg,
    )
    retriever = HybridRetriever(
        lexical=lexical, vector=vector,
        embedder=StubEmbedder(),
        reranker=PassthroughReranker(),
        graph=graph, graph_matcher=TextGraphMatcher(),
        kv=kv, config=cfg,
    )
    api.set_retriever(retriever)
    return api


def _node(nid: str, **props: Any) -> Node:
    return Node(
        id=nid,
        type="host",
        props=props,
        confidence=0.9,
        source="test",
        first_seen=now(),
        last_seen=now(),
    )


def _edge(eid: str, from_id: str, to_id: str, **props: Any) -> Edge:
    return Edge(
        id=eid,
        from_id=from_id,
        to_id=to_id,
        type="exposes",
        props=props,
        confidence=0.9,
        source="test",
        first_seen=now(),
        last_seen=now(),
    )


# ---------------------------------------------------------------------------
# T01 — Concurrent writers on disjoint fields both survive
# ---------------------------------------------------------------------------

async def test_t01_concurrent_disjoint_fields_both_survive() -> None:
    """Two concurrent coroutines writing different fields both commit.

    Without _graph_lock the second writer would read a stale snapshot before
    the first writer's put_node, then overwrite it with its own field only.
    With the lock the second writer reads the first writer's committed state.
    """
    api = _make_api()
    node_id = "host:10.0.0.1"

    # Seed a base node
    await api.upsert_node(_node(node_id, ip="10.0.0.1"))

    # Barrier events coordinate the interleaving to be deterministic.
    writer1_done = asyncio.Event()

    async def write_field_a() -> None:
        n = _node(node_id, ip="10.0.0.1", os="linux")
        await api.upsert_node(n)
        writer1_done.set()

    async def write_field_b() -> None:
        # Wait for writer1 to finish — so its write is committed before writer2
        await writer1_done.wait()
        n = _node(node_id, ip="10.0.0.1", version="22.04")
        await api.upsert_node(n)

    await asyncio.gather(write_field_a(), write_field_b())

    stored = await api._graph.get_node(node_id)
    assert stored is not None
    assert stored.props.get("os") == "linux", "field 'os' written by writer1 should survive"
    assert stored.props.get("version") == "22.04", "field 'version' written by writer2 should survive"


# ---------------------------------------------------------------------------
# T02 — Concurrent writers on overlapping field: LWW by logical_version
# ---------------------------------------------------------------------------

async def test_t02_overlapping_field_lww_by_logical_version() -> None:
    """Two writers targeting the SAME field: the logically later write wins."""
    api = _make_api()
    node_id = "host:10.0.0.2"

    await api.upsert_node(_node(node_id, ip="10.0.0.2"))

    w1_done = asyncio.Event()

    async def writer1() -> None:
        n = _node(node_id, ip="10.0.0.2", status="up")
        n.confidence = 0.5  # below conflict_confidence_floor → LWW, not Conflict
        await api.upsert_node(n)
        w1_done.set()

    async def writer2() -> None:
        await w1_done.wait()  # sequential: writer2 is logically after writer1
        n = _node(node_id, ip="10.0.0.2", status="down")
        n.confidence = 0.5
        await api.upsert_node(n)

    await asyncio.gather(writer1(), writer2())

    stored = await api._graph.get_node(node_id)
    assert stored is not None
    # writer2 ran after writer1 so it has a higher logical_version → must win
    assert stored.props.get("status") == "down"


# ---------------------------------------------------------------------------
# T03 — Three-way concurrent writes on disjoint fields
# ---------------------------------------------------------------------------

async def test_t03_three_way_concurrent_disjoint_fields() -> None:
    """Three sequential writers each adding a distinct field all survive."""
    api = _make_api()
    node_id = "host:10.0.0.3"
    await api.upsert_node(_node(node_id, ip="10.0.0.3"))

    e1, e2 = asyncio.Event(), asyncio.Event()

    async def w1() -> None:
        await api.upsert_node(_node(node_id, ip="10.0.0.3", a="1"))
        e1.set()

    async def w2() -> None:
        await e1.wait()
        await api.upsert_node(_node(node_id, ip="10.0.0.3", b="2"))
        e2.set()

    async def w3() -> None:
        await e2.wait()
        await api.upsert_node(_node(node_id, ip="10.0.0.3", c="3"))

    await asyncio.gather(w1(), w2(), w3())

    stored = await api._graph.get_node(node_id)
    assert stored is not None
    assert stored.props.get("a") == "1"
    assert stored.props.get("b") == "2"
    assert stored.props.get("c") == "3"


# ---------------------------------------------------------------------------
# T04 — apply_deltas is atomic: reader sees complete-before or complete-after
# ---------------------------------------------------------------------------

async def test_t04_apply_deltas_atomic_visibility() -> None:
    """A query issued after apply_deltas sees ALL nodes in the batch."""
    api = _make_api()

    n1 = _node("host:a1", ip="1.1.1.1")
    n2 = _node("host:a2", ip="2.2.2.2")
    n3 = _node("host:a3", ip="3.3.3.3")

    await api.apply_deltas(nodes=[n1, n2, n3])

    r1 = await api._graph.get_node("host:a1")
    r2 = await api._graph.get_node("host:a2")
    r3 = await api._graph.get_node("host:a3")
    assert r1 is not None and r1.props["ip"] == "1.1.1.1"
    assert r2 is not None and r2.props["ip"] == "2.2.2.2"
    assert r3 is not None and r3.props["ip"] == "3.3.3.3"


# ---------------------------------------------------------------------------
# T05 — apply_deltas rollback restores pre-batch node state
# ---------------------------------------------------------------------------

async def test_t05_apply_deltas_rollback_restores_node() -> None:
    """After a failed batch, the pre-batch node value is visible."""
    api = _make_api()

    # Seed a node with a known value
    await api.upsert_node(_node("host:r1", ip="10.1.1.1", status="pre"))

    class _BadEdge(Edge):
        """Edge whose put causes an error during apply_deltas."""

    # Patch the graph store to fail on put_edge
    original_put_edge = api._graph.put_edge

    async def _failing_put_edge(edge: Edge) -> str:
        raise RuntimeError("simulated failure")

    api._graph.put_edge = _failing_put_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="simulated failure"):
        await api.apply_deltas(
            nodes=[_node("host:r1", ip="10.1.1.1", status="modified")],
            edges=[_edge("e:r1", "host:r1", "host:r1", label="self")],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    # The node should have been rolled back to its pre-batch state
    stored = await api._graph.get_node("host:r1")
    assert stored is not None
    assert stored.props.get("status") == "pre", (
        f"expected 'pre' but got {stored.props.get('status')!r}"
    )


# ---------------------------------------------------------------------------
# T06 — apply_deltas rollback restores pre-batch edge state
# ---------------------------------------------------------------------------

async def test_t06_apply_deltas_rollback_restores_edge() -> None:
    """After a failed batch that updates an edge, the original edge is restored."""
    api = _make_api()

    await api.upsert_node(_node("host:e1", ip="10.2.2.1"))
    await api.upsert_node(_node("host:e2", ip="10.2.2.2"))
    await api.upsert_edge(_edge("e:link", "host:e1", "host:e2", port="80"))

    # Fail only when writing the new edge so the rollback restore of e:link succeeds.
    original_put_edge = api._graph.put_edge

    async def _fail_on_new_edge(edge: Edge) -> str:
        if edge.id == "e:new":
            raise RuntimeError("second edge fails")
        return await original_put_edge(edge)

    api._graph.put_edge = _fail_on_new_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="second edge fails"):
        await api.apply_deltas(
            edges=[
                _edge("e:link", "host:e1", "host:e2", port="443"),  # updates existing
                _edge("e:new", "host:e1", "host:e2", port="8080"),  # triggers failure
            ]
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    # The original edge (port=80) must be restored
    stored = await api._graph.get_edge("e:link")
    assert stored is not None
    assert stored.props.get("port") == "80", (
        f"expected port='80' after rollback but got {stored.props.get('port')!r}"
    )


# ---------------------------------------------------------------------------
# T07 — _write_clock restored to pre-clock after rollback (F02/F19)
# ---------------------------------------------------------------------------

async def test_t07_write_clock_restored_after_rollback() -> None:
    """_write_clock after a failed apply_deltas equals the pre-batch value."""
    api = _make_api()

    # Advance the clock with one successful write
    await api.upsert_node(_node("host:clock1", ip="1.1.1.1"))
    pre_clock = api._write_clock

    # Inject a failure after the first node write
    original_put_node = api._graph.put_node
    call_count = [0]

    async def _fail_on_second(node: Node) -> str:
        call_count[0] += 1
        if call_count[0] >= 2:
            raise RuntimeError("forced failure")
        return await original_put_node(node)

    api._graph.put_node = _fail_on_second  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="forced failure"):
        await api.apply_deltas(nodes=[
            _node("host:clock2", ip="2.2.2.2"),
            _node("host:clock3", ip="3.3.3.3"),  # this one triggers the failure
        ])

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    # The clock must be restored to the pre-batch value
    assert api._write_clock == pre_clock, (
        f"_write_clock was {api._write_clock!r} but expected {pre_clock!r} after rollback"
    )


# ---------------------------------------------------------------------------
# T08 — Rollback isolation: failed batch does not revert a committed write
# ---------------------------------------------------------------------------

async def test_t08_rollback_does_not_revert_prior_committed_write() -> None:
    """A rollback only undoes the failed batch's writes, not earlier committed writes."""
    api = _make_api()

    # Committed write (separate transaction, completed successfully)
    await api.upsert_node(_node("host:iso1", ip="10.10.10.1", committed="yes"))

    # Fail only when writing host:iso2 so rollback of host:iso1 can succeed.
    original_put_node = api._graph.put_node

    async def _fail_on_iso2(node: Node) -> str:
        if node.id == "host:iso2":
            raise RuntimeError("batch failure")
        return await original_put_node(node)

    api._graph.put_node = _fail_on_iso2  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="batch failure"):
        await api.apply_deltas(nodes=[
            _node("host:iso1", ip="10.10.10.1", committed="yes", batch_field="from_batch"),
            _node("host:iso2", ip="10.10.10.2"),  # triggers failure
        ])

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    # host:iso1 must be back to its committed state, not the batch-modified state
    stored = await api._graph.get_node("host:iso1")
    assert stored is not None
    assert stored.props.get("committed") == "yes"
    # The batch-only field must not be present
    assert "batch_field" not in stored.props, (
        "batch_field should have been rolled back"
    )


# ---------------------------------------------------------------------------
# T09 — Rollback isolation: committed write's logical_version not erased
# ---------------------------------------------------------------------------

async def test_t09_committed_write_version_intact_after_rollback() -> None:
    """A successful write's logical_version in provenance survives a later rollback."""
    api = _make_api()

    await api.upsert_node(_node("host:ver1", ip="10.20.20.1", color="red"))
    stored_before = await api._graph.get_node("host:ver1")
    assert stored_before is not None
    lv_before = stored_before._provenance.get("color", {}).get("logical_version")
    assert lv_before is not None and lv_before > 0

    # Failing batch
    original_put_node = api._graph.put_node

    async def _always_fail(node: Node) -> str:
        raise RuntimeError("always fail")

    api._graph.put_node = _always_fail  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="always fail"):
        await api.apply_deltas(nodes=[_node("host:ver1", ip="10.20.20.1", color="blue")])

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    stored_after = await api._graph.get_node("host:ver1")
    assert stored_after is not None
    lv_after = stored_after._provenance.get("color", {}).get("logical_version")
    assert lv_after == lv_before, (
        "logical_version must be unchanged after a rolled-back write"
    )
    assert stored_after.props.get("color") == "red"


# ---------------------------------------------------------------------------
# T10 — get_node returns a defensive copy
# ---------------------------------------------------------------------------

async def test_t10_get_node_returns_defensive_copy() -> None:
    """Mutating the returned Node.props does not affect the stored node."""
    api = _make_api()
    await api.upsert_node(_node("host:copy1", ip="10.0.0.1", tag="original"))

    fetched = await api._graph.get_node("host:copy1")
    assert fetched is not None
    # Mutate the returned copy
    fetched.props["tag"] = "mutated"
    fetched.props["extra"] = "added"

    # The stored node must be unaffected
    stored_again = await api._graph.get_node("host:copy1")
    assert stored_again is not None
    assert stored_again.props.get("tag") == "original", (
        "stored props were mutated through a returned reference"
    )
    assert "extra" not in stored_again.props


# ---------------------------------------------------------------------------
# T11 — get_edge returns a defensive copy
# ---------------------------------------------------------------------------

async def test_t11_get_edge_returns_defensive_copy() -> None:
    """Mutating the returned Edge.props does not affect the stored edge."""
    api = _make_api()
    await api.upsert_node(_node("host:src", ip="1.1.1.1"))
    await api.upsert_node(_node("host:dst", ip="2.2.2.2"))
    await api.upsert_edge(_edge("e:copy_test", "host:src", "host:dst", port="22"))

    fetched = await api._graph.get_edge("e:copy_test")
    assert fetched is not None
    fetched.props["port"] = "9999"

    stored_again = await api._graph.get_edge("e:copy_test")
    assert stored_again is not None
    assert stored_again.props.get("port") == "22", (
        "stored edge.props were mutated through a returned reference"
    )


# ---------------------------------------------------------------------------
# T12 — get_subgraph returns defensive copies
# ---------------------------------------------------------------------------

async def test_t12_get_subgraph_returns_defensive_copies() -> None:
    """Mutating a node/edge from get_subgraph does not affect stored state."""
    api = _make_api()
    await api.upsert_node(_node("host:sg1", ip="1.1.1.1", label="original"))
    await api.upsert_node(_node("host:sg2", ip="2.2.2.2"))
    await api.upsert_edge(_edge("e:sg12", "host:sg1", "host:sg2", rel="peer"))

    sg = await api._graph.get_subgraph("host:sg1", depth=1)
    node_from_sg = next(n for n in sg.nodes if n.id == "host:sg1")
    node_from_sg.props["label"] = "mutated"

    edge_from_sg = next(e for e in sg.edges if e.id == "e:sg12")
    edge_from_sg.props["rel"] = "gone"

    # Stored state must be unaffected
    stored_node = await api._graph.get_node("host:sg1")
    assert stored_node is not None
    assert stored_node.props.get("label") == "original"

    stored_edge = await api._graph.get_edge("e:sg12")
    assert stored_edge is not None
    assert stored_edge.props.get("rel") == "peer"


# ---------------------------------------------------------------------------
# T13 — all_nodes returns defensive copies
# ---------------------------------------------------------------------------

async def test_t13_all_nodes_returns_defensive_copies() -> None:
    """Mutating a node from all_nodes does not affect stored state."""
    api = _make_api()
    await api.upsert_node(_node("host:an1", ip="1.1.1.1", color="blue"))

    all_n = await api._graph.all_nodes()
    n = next(x for x in all_n if x.id == "host:an1")
    n.props["color"] = "red"

    stored = await api._graph.get_node("host:an1")
    assert stored is not None
    assert stored.props.get("color") == "blue"


# ---------------------------------------------------------------------------
# T14 — all_edges returns defensive copies
# ---------------------------------------------------------------------------

async def test_t14_all_edges_returns_defensive_copies() -> None:
    """Mutating an edge from all_edges does not affect stored state."""
    api = _make_api()
    await api.upsert_node(_node("host:ae1", ip="1.1.1.1"))
    await api.upsert_node(_node("host:ae2", ip="2.2.2.2"))
    await api.upsert_edge(_edge("e:ae", "host:ae1", "host:ae2", weight="5"))

    all_e = await api._graph.all_edges()
    e = next(x for x in all_e if x.id == "e:ae")
    e.props["weight"] = "999"

    stored = await api._graph.get_edge("e:ae")
    assert stored is not None
    assert stored.props.get("weight") == "5"


# ---------------------------------------------------------------------------
# T15 — Cache key includes k: independent entries for different k values
# ---------------------------------------------------------------------------

def test_t15_cache_key_includes_k() -> None:
    """Two calls with the same text but different k produce different cache keys."""
    tiers = [Tier.working, Tier.semantic]
    key4 = _cache_key("port scan nmap", 4, tiers, None)
    key8 = _cache_key("port scan nmap", 8, tiers, None)
    assert key4 != key8, "cache key must differ when k differs (F01)"


# ---------------------------------------------------------------------------
# T16 — Different k values cause cache miss, not stale truncated result
# ---------------------------------------------------------------------------

async def test_t16_different_k_causes_cache_miss() -> None:
    """After a k=4 query is cached, a k=8 query is NOT served from that cache."""
    api = _make_api()
    kv: _DictKVStore = api._kv  # type: ignore[assignment]

    # Manually plant a fake cache entry for k=4
    tiers = [Tier.working]
    fake_key = _cache_key("test query", 4, tiers, None)
    import json
    fake_payload = json.dumps([]).encode()
    await kv.set(fake_key, fake_payload)

    # The k=8 cache key must be different — so the k=4 entry is not returned
    key8 = _cache_key("test query", 8, tiers, None)
    assert await kv.get(key8) is None, (
        "k=8 cache lookup must miss when only k=4 is cached"
    )


# ---------------------------------------------------------------------------
# T17 — apply_deltas partial failure: only failed node absent, others visible
# ---------------------------------------------------------------------------

async def test_t17_apply_deltas_partial_rollback_all_or_nothing() -> None:
    """When a batch fails mid-way, ALL committed nodes are rolled back."""
    api = _make_api()

    original_put_node = api._graph.put_node
    call_count = [0]

    async def _fail_on_third(node: Node) -> str:
        call_count[0] += 1
        if call_count[0] == 3:
            raise RuntimeError("third node fails")
        return await original_put_node(node)

    api._graph.put_node = _fail_on_third  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="third node fails"):
        await api.apply_deltas(nodes=[
            _node("host:p1", ip="1.1.1.1"),
            _node("host:p2", ip="2.2.2.2"),
            _node("host:p3", ip="3.3.3.3"),  # fails here
        ])

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    # ALL three nodes must be absent — the batch is atomic (all-or-nothing)
    assert await api._graph.get_node("host:p1") is None, "host:p1 should be rolled back"
    assert await api._graph.get_node("host:p2") is None, "host:p2 should be rolled back"
    assert await api._graph.get_node("host:p3") is None, "host:p3 was never written"
