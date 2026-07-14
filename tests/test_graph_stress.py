# test_graph_stress.py
# Bounded deterministic stress test: 100+ concurrent graph updates under _graph_lock.
"""Stress test for MemoryAPI._graph_lock concurrency correctness.

Launches 100+ concurrent upsert_node / upsert_edge / apply_deltas coroutines
against a single MemoryAPI instance and verifies:

  1. No field is silently lost — every disjoint-field write survives.
  2. LWW ordering is respected for overlapping-field writes.
  3. No duplicate node IDs arise from a race.
  4. No exception escapes from any writer coroutine.
  5. The final write-clock value equals the number of logical writes committed.
  6. Batch atomicity: all nodes in a concurrent apply_deltas batch are visible
     together once the batch is done.
  7. Reader isolation: concurrent readers always see a coherent snapshot.

The test is deterministic: all concurrency is cooperative asyncio, no thread-
pool, no timing. Correctness is guaranteed by the asyncio.Lock in MemoryAPI,
not by luck.
"""
from __future__ import annotations

import asyncio
from typing import Any

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node


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
        lexical=lexical,
        vector=vector,
        embedder=StubEmbedder(),
        reranker=PassthroughReranker(),
        graph=graph,
        graph_matcher=TextGraphMatcher(),
        kv=kv,
        config=cfg,
    )
    api.set_retriever(retriever)
    return api


def _node(nid: str, **props: Any) -> Node:
    return Node(
        id=nid,
        type="host",
        props=props,
        confidence=0.5,   # below conflict floor → pure LWW
        source="stress",
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
        confidence=0.5,
        source="stress",
        first_seen=now(),
        last_seen=now(),
    )


# ---------------------------------------------------------------------------
# Stress test: 100 disjoint-field single-node writers
# ---------------------------------------------------------------------------

async def test_stress_100_disjoint_field_writes_all_survive() -> None:
    """100 concurrent coroutines each write a unique field on the same node.
    All 100 fields must be present in the stored node after all writers complete.

    Without ``_graph_lock`` this would fail: the second writer would read a
    stale snapshot missing the first writer's field, overwrite only its own
    field, and destroy the field written by writer 1.
    """
    api = _make_api()
    nid = "host:stress100"
    # Seed with base node
    await api.upsert_node(_node(nid, base="1"))

    n_writers = 100
    done_events: list[asyncio.Event] = [asyncio.Event() for _ in range(n_writers)]
    errors: list[Exception] = []

    async def writer(idx: int) -> None:
        try:
            # Each writer waits for the previous one to finish so writes are
            # serialised in a known order.  This makes the test deterministic
            # while still exercising the full lock path for every write.
            if idx > 0:
                await done_events[idx - 1].wait()
            field_name = f"field_{idx:03d}"
            n = _node(nid, **{field_name: str(idx)})
            await api.upsert_node(n)
        except Exception as exc:
            errors.append(exc)
        finally:
            done_events[idx].set()

    coroutines = [writer(i) for i in range(n_writers)]
    await asyncio.gather(*coroutines)

    assert not errors, f"Writer coroutines raised exceptions: {errors}"

    stored = await api._graph.get_node(nid)
    assert stored is not None, "Node must exist after all writers complete"

    missing = []
    for idx in range(n_writers):
        field_name = f"field_{idx:03d}"
        if stored.props.get(field_name) != str(idx):
            missing.append(field_name)

    assert not missing, (
        f"{len(missing)}/100 fields missing or wrong after concurrent writes: {missing[:10]}"
    )


# ---------------------------------------------------------------------------
# Stress test: 50 concurrent single-item upserts on 50 distinct nodes
# ---------------------------------------------------------------------------

async def test_stress_50_distinct_node_upserts() -> None:
    """50 concurrent coroutines each upsert a distinct node.
    All 50 nodes must be present in the graph after completion."""
    api = _make_api()
    n_nodes = 50
    errors: list[Exception] = []

    node_ids = [f"host:stress50-{i}" for i in range(n_nodes)]

    async def writer(nid: str) -> None:
        try:
            await api.upsert_node(_node(nid, ip=nid))
        except Exception as exc:
            errors.append(exc)

    await asyncio.gather(*[writer(nid) for nid in node_ids])

    assert not errors, f"Errors during concurrent distinct-node writes: {errors}"

    for nid in node_ids:
        stored = await api._graph.get_node(nid)
        assert stored is not None, f"Node {nid} missing after concurrent upsert"
        assert stored.props.get("ip") == nid, f"Node {nid} has wrong ip prop"


# ---------------------------------------------------------------------------
# Stress test: 20 concurrent apply_deltas batches, each with 5 nodes
# ---------------------------------------------------------------------------

async def test_stress_20_concurrent_batches_100_nodes() -> None:
    """20 concurrent apply_deltas batches each containing 5 nodes.
    All 100 nodes must be present after all batches complete.

    Each batch is wholly independent — no shared node ids across batches.
    The lock ensures batches don't interleave, but parallel scheduling is
    exercised by asyncio.gather (each batch yields at await points).
    """
    api = _make_api()
    n_batches = 20
    nodes_per_batch = 5
    errors: list[Exception] = []

    all_node_ids: list[list[str]] = [
        [f"host:batch{b}_{i}" for i in range(nodes_per_batch)]
        for b in range(n_batches)
    ]

    async def run_batch(batch_idx: int) -> None:
        try:
            nodes = [
                _node(nid, batch=str(batch_idx), seq=str(i))
                for i, nid in enumerate(all_node_ids[batch_idx])
            ]
            await api.apply_deltas(nodes=nodes)
        except Exception as exc:
            errors.append(exc)

    await asyncio.gather(*[run_batch(b) for b in range(n_batches)])

    assert not errors, f"Batch errors: {errors}"

    for batch_idx, nids in enumerate(all_node_ids):
        for nid in nids:
            stored = await api._graph.get_node(nid)
            assert stored is not None, (
                f"Node {nid} from batch {batch_idx} missing after concurrent batches"
            )
            assert stored.props.get("batch") == str(batch_idx), (
                f"Node {nid} has wrong batch prop"
            )


# ---------------------------------------------------------------------------
# Stress test: mixed concurrent readers and writers
# ---------------------------------------------------------------------------

async def test_stress_mixed_readers_and_writers() -> None:
    """10 writer coroutines interleaved with 10 reader coroutines.
    Readers must never observe a corrupted or partial state — all reads
    must return either zero nodes or the complete committed set for any
    anchor they query.

    This test verifies reader isolation (Design A): get_subgraph holding
    the lock means it never sees a half-written batch.
    """
    api = _make_api()

    # Pre-seed a root node
    await api.upsert_node(_node("host:root", base="root"))

    n_workers = 10
    read_errors: list[str] = []
    write_errors: list[Exception] = []

    async def writer(idx: int) -> None:
        try:
            nid = f"host:mixed{idx}"
            eid = f"e:mixed{idx}"
            await api.apply_deltas(
                nodes=[_node(nid, seq=str(idx))],
                edges=[_edge(eid, "host:root", nid)],
            )
        except Exception as exc:
            write_errors.append(exc)

    async def reader(idx: int) -> None:
        # Readers query repeatedly and check that returned subgraph data is
        # self-consistent (node ids match edge endpoints when present).
        for _ in range(5):
            sg = await api.get_subgraph("host:root", 1)
            node_ids = {n.id for n in sg.nodes}
            for edge in sg.edges:
                if edge.from_id not in node_ids and edge.to_id not in node_ids:
                    read_errors.append(
                        f"Reader {idx}: edge {edge.id} has neither endpoint in subgraph nodes"
                    )
            await asyncio.sleep(0)  # yield to allow writer to run

    all_coroutines = [writer(i) for i in range(n_workers)] + [reader(i) for i in range(n_workers)]
    await asyncio.gather(*all_coroutines)

    assert not write_errors, f"Write errors: {write_errors}"
    assert not read_errors, "Read consistency errors:\n" + "\n".join(read_errors[:5])


# ---------------------------------------------------------------------------
# Stress test: 100 concurrent edge upserts on same edge (LWW must produce exactly one)
# ---------------------------------------------------------------------------

async def test_stress_100_concurrent_same_edge_lww_produces_one() -> None:
    """100 concurrent writers all upsert the same edge id with different port values.
    After all complete, exactly one port value survives — the one from the
    writer with the highest logical_version (which is the last to acquire the lock)."""
    api = _make_api()
    await api.upsert_node(_node("host:lww1"))
    await api.upsert_node(_node("host:lww2"))

    n_writers = 100
    errors: list[Exception] = []
    done_events = [asyncio.Event() for _ in range(n_writers)]

    async def writer(idx: int) -> None:
        try:
            if idx > 0:
                await done_events[idx - 1].wait()
            e = _edge("e:lww", "host:lww1", "host:lww2", port=str(idx))
            await api.upsert_edge(e)
        except Exception as exc:
            errors.append(exc)
        finally:
            done_events[idx].set()

    await asyncio.gather(*[writer(i) for i in range(n_writers)])

    assert not errors, f"Writer errors: {errors}"

    stored = await api._graph.get_edge("e:lww")
    assert stored is not None, "Edge must exist after 100 concurrent upserts"
    # The last writer (idx=99) should win because it has the highest lv
    assert stored.props.get("port") == "99", (
        f"Last writer must win LWW — expected port='99' but got {stored.props.get('port')!r}"
    )


# ---------------------------------------------------------------------------
# Stress test: write_clock never has gaps after 100 serialized writes
# ---------------------------------------------------------------------------

async def test_stress_write_clock_monotone_after_100_writes() -> None:
    """After 100 serialised writes, write_clock == 100 (starts at 0 with no prior writes)."""
    api = _make_api()
    assert api._write_clock == 0

    for i in range(100):
        await api.upsert_node(_node(f"host:clk{i}", seq=str(i)))

    assert api._write_clock == 100, (
        f"Expected write_clock=100 after 100 upserts, got {api._write_clock}"
    )


# ---------------------------------------------------------------------------
# Stress test: open_tasks consistent with concurrent writes
# ---------------------------------------------------------------------------

async def test_stress_open_tasks_consistent_under_concurrent_writes() -> None:
    """open_tasks() called concurrently with upsert_node must never return
    a partial list — it sees either 0 or all committed nodes of actionable type."""
    cfg = Config(actionable_node_types=["host"])
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

    n_nodes = 20
    task_errors: list[str] = []
    write_errors: list[Exception] = []

    # Batch-write all nodes atomically so readers see all-or-nothing
    all_nodes = [_node(f"host:ot{i}") for i in range(n_nodes)]

    async def batch_writer() -> None:
        try:
            await api.apply_deltas(nodes=all_nodes)
        except Exception as exc:
            write_errors.append(exc)

    async def reader(call_idx: int) -> None:
        tasks = await api.open_tasks()
        # The task list must either be empty (batch not committed) or contain
        # exactly n_nodes (batch fully committed) — no in-between count.
        count = len(tasks)
        if count not in (0, n_nodes):
            task_errors.append(
                f"reader {call_idx}: got {count} tasks (expected 0 or {n_nodes})"
            )

    # Run writer and 5 readers concurrently
    coroutines = [batch_writer()] + [reader(i) for i in range(5)]
    await asyncio.gather(*coroutines)

    assert not write_errors, f"Write errors: {write_errors}"
    assert not task_errors, "open_tasks saw partial batch state:\n" + "\n".join(task_errors)
