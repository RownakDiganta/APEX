# test_graph_transaction_complete.py
# Complete Phase 1 transaction guarantee tests: reader isolation, deletion, rollback, defensive copies, architecture scan.
"""Phase 1 Comprehensive Transaction Tests.

These tests verify all transaction guarantees required by the Phase 1
comprehensive specification:

  Section A (Reader Isolation):
    A01 — get_subgraph acquires _graph_lock
    A02 — open_tasks acquires _graph_lock
    A03 — query subgraph attachment acquires _graph_lock
    A04 — get_subgraph blocked while lock is held by batch
    A05 — open_tasks blocked while lock is held by batch
    A06 — get_subgraph sees complete batch after lock released
    A07 — open_tasks sees complete batch after lock released
    A08 — query sees complete batch subgraph after lock released

  Section B (Index/Cache Coherence on Commit):
    B01 — upsert_node immediately retrievable via lexical search
    B02 — upsert_edge immediately retrievable via lexical search
    B03 — apply_deltas batch: all nodes indexed after completion
    B04 — apply_deltas batch: all edges indexed after completion
    B05 — retrieval cache busted after each upsert_node

  Section C (Rollback/Index/Cache Integrity):
    C01 — failed batch removes newly-created node from lexical index
    C02 — failed batch restores updated node text in lexical index
    C03 — failed batch removes newly-created edge from lexical index
    C04 — failed batch does not remove prior knowledge proposals
    C05 — failed batch does not remove prior skill proposals
    C06 — failed batch removes only its own knowledge proposals
    C07 — failed batch removes only its own skill proposals
    C08 — failed batch restores edge LWW clock entry
    C09 — rollback busts retrieval cache
    C10 — failed batch: no half-committed edge visible after rollback

  Section D (Proposal Staging Isolation):
    D01 — propose_knowledge: staged entry not returned by query
    D02 — propose_skill: staged entry not returned by query
    D03 — failed batch knowledge proposal not present in staging
    D04 — prior proposals unaffected by batch failure

  Section E (Public Deletion API):
    E01 — delete_node removes node from graph store
    E02 — delete_node removes entry from lexical index
    E03 — delete_node busts retrieval cache
    E04 — delete_edge removes edge from graph store
    E05 — delete_edge removes entry from lexical index
    E06 — delete_edge removes entry from _edge_write_lv
    E07 — delete_node then upsert creates a fresh independent entry
    E08 — delete_nonexistent_node is a no-op (no crash)
    E09 — delete_nonexistent_edge is a no-op (no crash)
    E10 — delete_node acquires _graph_lock

  Section F (Defensive Copies via MemoryAPI Public Surface):
    F01 — get_subgraph node mutation does not affect stored graph
    F02 — get_subgraph edge mutation does not affect stored graph
    F03 — open_tasks props mutation does not affect stored node
    F04 — two get_subgraph calls return independent objects
    F05 — two open_tasks calls return independent objects
    F06 — pre-batch snapshot independent of batch modifications
    F07 — returned subgraph after apply_deltas is independent copy

  Section G (Architecture Scan):
    G01 — no production code in memfabric/ calls GraphStore mutator directly
    G02 — no production code in memfabric/ calls EpisodicStore.append directly outside MemoryAPI

  Section H (Episode Append Contract):
    H01 — episode rollback removes from in-memory episodic store
    H02 — duplicate episode id raises ValueError (immutability)
    H03 — episode indexed in lexical after append
    H04 — failed batch with nodes + episode: both nodes and episode rolled back
    H05 — episode lexical entry removed during rollback
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Episode, KnowledgeEntry, Node, Outcome, Skill


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


def _node(nid: str, ntype: str = "host", **props: Any) -> Node:
    return Node(
        id=nid,
        type=ntype,
        props=props,
        confidence=0.9,
        source="test",
        first_seen=now(),
        last_seen=now(),
    )


def _low_conf_node(nid: str, **props: Any) -> Node:
    """Node with confidence below conflict_confidence_floor (0.7) for LWW tests."""
    return Node(
        id=nid,
        type="host",
        props=props,
        confidence=0.3,
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


def _episode(**kwargs: Any) -> Episode:
    defaults: dict[str, Any] = dict(
        agent="test.agent",
        action="probe",
        outcome=Outcome.success,
        data={"detail": "test"},
    )
    defaults.update(kwargs)
    return Episode(**defaults)


def _knowledge(text: str = "test knowledge entry", confidence: float = 0.8) -> KnowledgeEntry:
    return KnowledgeEntry(
        text=text,
        source="test",
        confidence=confidence,
    )


def _skill(name: str = "test_skill") -> Skill:
    return Skill(
        name=name,
        description=f"test skill {name}",
        template={},
        preconditions={},
        source_episodes=[],
        confidence=0.7,
    )


# ---------------------------------------------------------------------------
# Section A — Reader Isolation
# ---------------------------------------------------------------------------

async def test_a01_get_subgraph_acquires_graph_lock() -> None:
    """get_subgraph() must call the store while holding _graph_lock."""
    api = _make_api()
    await api.upsert_node(_node("host:a01"))

    lock_was_held: list[bool] = []
    original_get_subgraph = api._graph.get_subgraph

    async def spy_get_subgraph(*args: Any, **kwargs: Any) -> Any:
        lock_was_held.append(api._graph_lock.locked())
        return await original_get_subgraph(*args, **kwargs)

    api._graph.get_subgraph = spy_get_subgraph  # type: ignore[method-assign]
    await api.get_subgraph("host:a01", 1)

    assert lock_was_held, "spy was never called"
    assert all(lock_was_held), "lock must be held on every get_subgraph call"


async def test_a02_open_tasks_acquires_graph_lock() -> None:
    """open_tasks() must call the store while holding _graph_lock."""
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
    await api.upsert_node(_node("host:a02", ntype="host"))

    lock_was_held: list[bool] = []
    original_gbt = api._graph.get_nodes_by_type

    async def spy_gbt(node_type: str) -> Any:
        lock_was_held.append(api._graph_lock.locked())
        return await original_gbt(node_type)

    api._graph.get_nodes_by_type = spy_gbt  # type: ignore[method-assign]
    await api.open_tasks()

    assert lock_was_held, "get_nodes_by_type spy never called"
    assert all(lock_was_held), "lock must be held for all get_nodes_by_type calls"


async def test_a03_query_subgraph_attachment_acquires_graph_lock() -> None:
    """query() with subgraph_anchor must acquire _graph_lock for the subgraph read."""
    api = _make_api()
    await api.upsert_node(_node("host:a03"))

    lock_was_held: list[bool] = []
    original_get_subgraph = api._graph.get_subgraph

    async def spy_get_subgraph(*args: Any, **kwargs: Any) -> Any:
        lock_was_held.append(api._graph_lock.locked())
        return await original_get_subgraph(*args, **kwargs)

    api._graph.get_subgraph = spy_get_subgraph  # type: ignore[method-assign]
    await api.query(text="host", subgraph_anchor="host:a03")

    assert lock_was_held, "subgraph attachment never called store"
    assert all(lock_was_held), "lock must be held during subgraph attachment in query"


async def test_a04_get_subgraph_blocked_while_lock_held() -> None:
    """get_subgraph() is blocked (suspended) while _graph_lock is held externally."""
    api = _make_api()
    await api.upsert_node(_node("host:a04"))

    reader_result: list[Any] = []
    reader_started = asyncio.Event()

    async def reader() -> None:
        reader_started.set()
        sg = await api.get_subgraph("host:a04", 1)
        reader_result.append(sg)

    async with api._graph_lock:
        task = asyncio.create_task(reader())
        await reader_started.wait()
        # yield to let the reader task attempt to acquire the lock
        await asyncio.sleep(0)
        # The reader should be suspended waiting for the lock
        assert len(reader_result) == 0, (
            "get_subgraph should be blocked while _graph_lock is held"
        )
    # Lock released — reader should now complete
    await task
    assert len(reader_result) == 1


async def test_a05_open_tasks_blocked_while_lock_held() -> None:
    """open_tasks() is blocked (suspended) while _graph_lock is held externally."""
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
    await api.upsert_node(_node("host:a05", ntype="host"))

    tasks_result: list[Any] = []
    reader_started = asyncio.Event()

    async def reader() -> None:
        reader_started.set()
        result = await api.open_tasks()
        tasks_result.append(result)

    async with api._graph_lock:
        task = asyncio.create_task(reader())
        await reader_started.wait()
        await asyncio.sleep(0)
        assert len(tasks_result) == 0, (
            "open_tasks should be blocked while _graph_lock is held"
        )
    await task
    assert len(tasks_result) == 1


async def test_a06_get_subgraph_sees_complete_batch() -> None:
    """get_subgraph after apply_deltas sees all batch nodes (not partial state)."""
    api = _make_api()
    n1 = _node("host:a06a", ip="1.1.1.1")
    n2 = _node("host:a06b", ip="2.2.2.2")
    n3 = _node("host:a06c", ip="3.3.3.3")
    await api.upsert_node(n1)
    # Connect n1 to n2 and n3 via edges so they're in the subgraph
    e1 = _edge("e:a06ab", "host:a06a", "host:a06b")
    e2 = _edge("e:a06ac", "host:a06a", "host:a06c")
    await api.apply_deltas(nodes=[n2, n3], edges=[e1, e2])

    sg = await api.get_subgraph("host:a06a", 2)
    ids = {n.id for n in sg.nodes}
    assert "host:a06a" in ids
    assert "host:a06b" in ids
    assert "host:a06c" in ids


async def test_a07_open_tasks_sees_complete_batch() -> None:
    """open_tasks after apply_deltas reflects the complete committed state."""
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
    n1 = _node("host:a07a", ntype="host")
    n2 = _node("host:a07b", ntype="host")
    await api.apply_deltas(nodes=[n1, n2])

    tasks = await api.open_tasks()
    task_ids = {t.node_id for t in tasks}
    assert "host:a07a" in task_ids
    assert "host:a07b" in task_ids


async def test_a08_query_sees_subgraph_after_batch() -> None:
    """query with subgraph_anchor returns correct subgraph after apply_deltas."""
    api = _make_api()
    n1 = _node("host:a08", ip="8.8.8.8")
    await api.apply_deltas(nodes=[n1])
    bundle = await api.query(text="host", subgraph_anchor="host:a08")
    assert bundle.subgraph is not None
    ids = {n.id for n in bundle.subgraph.nodes}
    assert "host:a08" in ids


# ---------------------------------------------------------------------------
# Section B — Index/Cache Coherence on Commit
# ---------------------------------------------------------------------------

async def test_b01_upsert_node_immediately_retrievable_lexical() -> None:
    """After upsert_node, the node is findable via lexical search without any delay."""
    api = _make_api()
    uid = f"host:b01-{new_id()}"
    await api.upsert_node(_node(uid, label="xyzzy-unique-b01"))
    bundle = await api.query(text="xyzzy-unique-b01")
    ids = {e.id for e in bundle.entries}
    assert uid in ids, f"Node {uid} not found in lexical results immediately after upsert"


async def test_b02_upsert_edge_immediately_retrievable_lexical() -> None:
    """After upsert_edge, the edge is findable via lexical search."""
    api = _make_api()
    n1 = _node("host:b02src")
    n2 = _node("host:b02dst")
    await api.upsert_node(n1)
    await api.upsert_node(n2)
    eid = f"e:b02-{new_id()}"
    await api.upsert_edge(_edge(eid, "host:b02src", "host:b02dst", port="b02_xylophone"))
    bundle = await api.query(text="b02_xylophone")
    ids = {e.id for e in bundle.entries}
    assert eid in ids, f"Edge {eid} not found in lexical results immediately after upsert"


async def test_b03_apply_deltas_all_nodes_indexed() -> None:
    """After apply_deltas, ALL nodes in the batch are in the lexical index."""
    api = _make_api()
    nids = [f"host:b03-{i}" for i in range(5)]
    nodes = [_node(nid, label=f"b03label{i}") for i, nid in enumerate(nids)]
    await api.apply_deltas(nodes=nodes)

    for i, nid in enumerate(nids):
        bundle = await api.query(text=f"b03label{i}")
        ids = {e.id for e in bundle.entries}
        assert nid in ids, f"Node {nid} missing from index after batch"


async def test_b04_apply_deltas_all_edges_indexed() -> None:
    """After apply_deltas, all edges in the batch are in the lexical index."""
    api = _make_api()
    n1 = _node("host:b04src")
    n2 = _node("host:b04dst")
    await api.upsert_node(n1)
    await api.upsert_node(n2)
    edges = [
        _edge(f"e:b04-{i}", "host:b04src", "host:b04dst", tag=f"b04tag{i}")
        for i in range(3)
    ]
    await api.apply_deltas(edges=edges)

    for i, e in enumerate(edges):
        bundle = await api.query(text=f"b04tag{i}")
        ids = {entry.id for entry in bundle.entries}
        assert e.id in ids, f"Edge {e.id} missing from index after batch"


async def test_b05_retrieval_cache_busted_on_write() -> None:
    """The retrieval cache must be invalidated after each write so the next
    query gets fresh results, not a stale cached response."""
    api = _make_api()
    # First query caches an empty result
    bundle1 = await api.query(text="zephyr-b05")
    ids1 = {e.id for e in bundle1.entries}
    assert "host:b05" not in ids1

    # Now write
    await api.upsert_node(_node("host:b05", label="zephyr-b05"))

    # Second query must NOT return the stale cached result
    bundle2 = await api.query(text="zephyr-b05")
    ids2 = {e.id for e in bundle2.entries}
    assert "host:b05" in ids2, "Cache was not busted after upsert_node"


# ---------------------------------------------------------------------------
# Section C — Rollback / Index / Cache Integrity
# ---------------------------------------------------------------------------

def _fail_on_put_node_id(api: MemoryAPI, fail_id: str) -> Any:
    """Return (original, patched) put_node that fails when writing fail_id."""
    original = api._graph.put_node

    async def _failing(node: Node) -> str:
        if node.id == fail_id:
            raise RuntimeError(f"simulated put_node failure for {fail_id}")
        return await original(node)

    return original, _failing


async def test_c01_failed_batch_removes_new_node_from_lexical() -> None:
    """If a new node is committed in a batch that later fails, its lexical
    entry is removed during rollback."""
    api = _make_api()

    original_put_node = api._graph.put_node
    call_count = [0]

    async def fail_on_second(node: Node) -> str:
        call_count[0] += 1
        if call_count[0] >= 2:
            raise RuntimeError("fail on second put_node")
        return await original_put_node(node)

    api._graph.put_node = fail_on_second  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="fail on second put_node"):
        await api.apply_deltas(nodes=[
            _node("host:c01a", label="c01_keep"),
            _node("host:c01b", label="c01_fail"),
        ])

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    # Neither node should be in the lexical index after rollback
    bundle = await api.query(text="c01_keep")
    ids = {e.id for e in bundle.entries}
    assert "host:c01a" not in ids, "Rolled-back node c01a should not be in lexical index"
    bundle2 = await api.query(text="c01_fail")
    ids2 = {e.id for e in bundle2.entries}
    assert "host:c01b" not in ids2, "Rolled-back node c01b should not be in lexical index"


async def test_c02_failed_batch_restores_updated_node_in_lexical() -> None:
    """If an existing node is updated in a failed batch, the old text is
    restored in the lexical index."""
    api = _make_api()
    await api.upsert_node(_node("host:c02", label="original_text"))

    original_put_edge = api._graph.put_edge

    async def fail_put_edge(edge: Edge) -> str:
        raise RuntimeError("force rollback via edge failure")

    api._graph.put_edge = fail_put_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            nodes=[_node("host:c02", label="modified_text")],
            edges=[_edge("e:c02", "host:c02", "host:c02")],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    # Lexical should return the original text
    bundle = await api.query(text="original_text")
    ids = {e.id for e in bundle.entries}
    assert "host:c02" in ids, "Rolled-back node should restore to original text in index"


async def test_c03_failed_batch_removes_new_edge_from_lexical() -> None:
    """A new edge committed in a failed batch is removed from the lexical index."""
    api = _make_api()
    await api.upsert_node(_node("host:c03a"))
    await api.upsert_node(_node("host:c03b"))

    original_put_node = api._graph.put_node

    async def fail_put_node(node: Node) -> str:
        raise RuntimeError("force rollback via node failure")

    api._graph.put_node = fail_put_node  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            edges=[_edge("e:c03", "host:c03a", "host:c03b", tag="c03tag")],
            nodes=[_node("host:c03_new")],
        )

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    bundle = await api.query(text="c03tag")
    ids = {e.id for e in bundle.entries}
    assert "e:c03" not in ids, "Rolled-back edge must not appear in lexical index"


async def test_c04_failed_batch_does_not_remove_prior_knowledge_proposals() -> None:
    """A batch failure must not remove knowledge proposals staged before the batch."""
    api = _make_api()
    prior_ke = _knowledge("prior knowledge c04")
    await api.propose_knowledge(prior_ke)

    original_put_node = api._graph.put_node

    async def fail_put_node(node: Node) -> str:
        raise RuntimeError("batch fails")

    api._graph.put_node = fail_put_node  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(nodes=[_node("host:c04")])

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    staged = await api.get_staged_knowledge()
    staged_ids = {k.id for k in staged}
    assert prior_ke.id in staged_ids, "Prior knowledge proposals must survive a batch failure"


async def test_c05_failed_batch_does_not_remove_prior_skill_proposals() -> None:
    """A batch failure must not remove skill proposals staged before the batch."""
    api = _make_api()
    prior_sk = _skill("prior_skill_c05")
    await api.propose_skill(prior_sk)

    original_put_node = api._graph.put_node

    async def fail_put_node(node: Node) -> str:
        raise RuntimeError("batch fails")

    api._graph.put_node = fail_put_node  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(nodes=[_node("host:c05")])

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    staged = await api.get_staged_skills()
    staged_ids = {s.id for s in staged}
    assert prior_sk.id in staged_ids, "Prior skill proposals must survive a batch failure"


async def test_c06_failed_batch_removes_only_its_knowledge_proposals() -> None:
    """The rollback removes the batch's own knowledge proposals, not pre-existing ones."""
    api = _make_api()
    prior = _knowledge("pre-existing knowledge c06")
    await api.propose_knowledge(prior)

    batch_ke = _knowledge("batch knowledge c06")

    original_put_edge = api._graph.put_edge

    async def fail_on_edge(edge: Edge) -> str:
        raise RuntimeError("fail in edge to trigger rollback")

    api._graph.put_edge = fail_on_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            nodes=[_node("host:c06")],
            edges=[_edge("e:c06", "host:c06", "host:c06")],
            knowledge=[batch_ke],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    staged = await api.get_staged_knowledge()
    staged_ids = {k.id for k in staged}
    assert prior.id in staged_ids, "Pre-existing proposal must survive rollback"
    assert batch_ke.id not in staged_ids, "Batch proposal must be removed by rollback"


async def test_c07_failed_batch_removes_only_its_skill_proposals() -> None:
    """The rollback removes the batch's own skill proposals, not pre-existing ones."""
    api = _make_api()
    prior = _skill("prior_c07")
    await api.propose_skill(prior)

    batch_sk = _skill("batch_c07")

    original_put_edge = api._graph.put_edge

    async def fail_on_edge(edge: Edge) -> str:
        raise RuntimeError("fail to trigger rollback")

    api._graph.put_edge = fail_on_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            nodes=[_node("host:c07")],
            edges=[_edge("e:c07", "host:c07", "host:c07")],
            skills=[batch_sk],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    staged = await api.get_staged_skills()
    staged_ids = {s.id for s in staged}
    assert prior.id in staged_ids, "Pre-existing skill must survive rollback"
    assert batch_sk.id not in staged_ids, "Batch skill must be removed by rollback"


async def test_c08_failed_batch_restores_edge_write_lv() -> None:
    """After a failed update of an existing edge, the pre-batch LWW clock is
    restored in _edge_write_lv."""
    api = _make_api()
    await api.upsert_node(_node("host:c08a"))
    await api.upsert_node(_node("host:c08b"))
    await api.upsert_edge(_edge("e:c08", "host:c08a", "host:c08b", port="80"))

    pre_lv = api._edge_write_lv.get("e:c08", 0)

    original_put_node = api._graph.put_node

    async def fail_node(node: Node) -> str:
        raise RuntimeError("fail to trigger rollback")

    api._graph.put_node = fail_node  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            edges=[_edge("e:c08", "host:c08a", "host:c08b", port="443")],
            nodes=[_node("host:c08_new")],
        )

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    post_lv = api._edge_write_lv.get("e:c08", 0)
    assert post_lv == pre_lv, (
        f"Edge LWW clock should be restored to {pre_lv} after rollback, got {post_lv}"
    )


async def test_c09_rollback_busts_retrieval_cache() -> None:
    """After a failed batch, the retrieval cache is invalidated so stale
    results from the mid-batch state are not returned."""
    api = _make_api()
    # Prime the cache with a query result
    await api.upsert_node(_node("host:c09seed", label="c09seed"))
    await api.query(text="c09seed")  # caches the result

    original_put_edge = api._graph.put_edge

    async def fail_put_edge(edge: Edge) -> str:
        raise RuntimeError("force rollback")

    api._graph.put_edge = fail_put_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            nodes=[_node("host:c09new", label="c09new")],
            edges=[_edge("e:c09", "host:c09seed", "host:c09seed")],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    # After rollback the cache should be busted (host:c09new should not appear)
    bundle = await api.query(text="c09new")
    ids = {e.id for e in bundle.entries}
    assert "host:c09new" not in ids, (
        "Rolled-back node must not appear in queries — cache must be busted after rollback"
    )


async def test_c10_failed_batch_no_half_committed_edge() -> None:
    """After a failed batch, neither the partial edge nor the failed node
    should be visible in the graph."""
    api = _make_api()
    await api.upsert_node(_node("host:c10a"))
    await api.upsert_node(_node("host:c10b"))

    original_put_node = api._graph.put_node

    async def fail_new_node(node: Node) -> str:
        if node.id == "host:c10new":
            raise RuntimeError("fail on new node")
        return await original_put_node(node)

    api._graph.put_node = fail_new_node  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            edges=[_edge("e:c10partial", "host:c10a", "host:c10b", tag="partial")],
            nodes=[_node("host:c10new")],
        )

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    # The edge should have been rolled back
    stored_edge = await api._graph.get_edge("e:c10partial")
    assert stored_edge is None, "Partial edge must be absent after batch rollback"
    # The new node should have been rolled back
    stored_node = await api._graph.get_node("host:c10new")
    assert stored_node is None, "Failed node must be absent after batch rollback"


# ---------------------------------------------------------------------------
# Section D — Proposal Staging Isolation
# ---------------------------------------------------------------------------

async def test_d01_propose_knowledge_not_in_query_results() -> None:
    """A staged knowledge entry must NOT appear in normal query results."""
    api = _make_api()
    ke = _knowledge("unique staged text d01 zebra")
    await api.propose_knowledge(ke)

    bundle = await api.query(text="unique staged text d01 zebra")
    ids = {e.id for e in bundle.entries}
    assert ke.id not in ids, "Staged knowledge must not be in query results before promotion"


async def test_d02_propose_skill_not_in_query_results() -> None:
    """A staged skill must NOT appear in normal query results."""
    api = _make_api()
    sk = _skill("unique_skill_d02")
    sk.description = "unique skill d02 wombat"
    await api.propose_skill(sk)

    bundle = await api.query(text="unique skill d02 wombat")
    ids = {e.id for e in bundle.entries}
    assert sk.id not in ids, "Staged skill must not be in query results before promotion"


async def test_d03_failed_batch_knowledge_proposal_not_present() -> None:
    """A knowledge proposal staged inside a failed batch must not remain in staging."""
    api = _make_api()

    batch_ke = _knowledge("batch ke d03 should vanish")

    original_put_edge = api._graph.put_edge

    async def fail_edge(edge: Edge) -> str:
        raise RuntimeError("trigger rollback")

    api._graph.put_edge = fail_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            nodes=[_node("host:d03")],
            edges=[_edge("e:d03", "host:d03", "host:d03")],
            knowledge=[batch_ke],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    staged = await api.get_staged_knowledge()
    assert batch_ke.id not in {k.id for k in staged}, (
        "Failed-batch knowledge proposal must not remain in staging"
    )


async def test_d04_prior_proposals_unaffected_by_batch_failure() -> None:
    """Pre-existing proposals from before the failed batch must still be present."""
    api = _make_api()
    ke1 = _knowledge("prior proposal d04a")
    ke2 = _knowledge("prior proposal d04b")
    await api.propose_knowledge(ke1)
    await api.propose_knowledge(ke2)

    original_put_node = api._graph.put_node

    async def fail_put(node: Node) -> str:
        raise RuntimeError("batch fails")

    api._graph.put_node = fail_put  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            nodes=[_node("host:d04")],
            knowledge=[_knowledge("batch proposal d04")],
        )

    api._graph.put_node = original_put_node  # type: ignore[method-assign]

    staged = await api.get_staged_knowledge()
    staged_ids = {k.id for k in staged}
    assert ke1.id in staged_ids, "Prior proposal ke1 must survive batch failure"
    assert ke2.id in staged_ids, "Prior proposal ke2 must survive batch failure"


# ---------------------------------------------------------------------------
# Section E — Public Deletion API
# ---------------------------------------------------------------------------

async def test_e01_delete_node_removes_from_graph() -> None:
    """After delete_node, the node is gone from the graph store."""
    api = _make_api()
    await api.upsert_node(_node("host:e01"))
    assert await api._graph.get_node("host:e01") is not None

    await api.delete_node("host:e01")
    assert await api._graph.get_node("host:e01") is None


async def test_e02_delete_node_removes_from_lexical_index() -> None:
    """After delete_node, the node text is gone from the lexical index."""
    api = _make_api()
    await api.upsert_node(_node("host:e02", label="e02_unique_token"))
    bundle = await api.query(text="e02_unique_token")
    assert "host:e02" in {e.id for e in bundle.entries}

    await api.delete_node("host:e02")
    bundle2 = await api.query(text="e02_unique_token")
    assert "host:e02" not in {e.id for e in bundle2.entries}


async def test_e03_delete_node_busts_retrieval_cache() -> None:
    """delete_node invalidates the retrieval cache."""
    api = _make_api()
    await api.upsert_node(_node("host:e03", label="e03_label"))
    # Prime the cache
    await api.query(text="e03_label")

    await api.delete_node("host:e03")

    # Query must not return the cached stale result
    bundle = await api.query(text="e03_label")
    assert "host:e03" not in {e.id for e in bundle.entries}


async def test_e04_delete_edge_removes_from_graph() -> None:
    """After delete_edge, the edge is gone from the graph store."""
    api = _make_api()
    await api.upsert_node(_node("host:e04a"))
    await api.upsert_node(_node("host:e04b"))
    await api.upsert_edge(_edge("e:e04", "host:e04a", "host:e04b"))
    assert await api._graph.get_edge("e:e04") is not None

    await api.delete_edge("e:e04")
    assert await api._graph.get_edge("e:e04") is None


async def test_e05_delete_edge_removes_from_lexical_index() -> None:
    """After delete_edge, the edge text is gone from the lexical index."""
    api = _make_api()
    await api.upsert_node(_node("host:e05src"))
    await api.upsert_node(_node("host:e05dst"))
    await api.upsert_edge(_edge("e:e05", "host:e05src", "host:e05dst", tag="e05unique"))
    bundle = await api.query(text="e05unique")
    assert "e:e05" in {e.id for e in bundle.entries}

    await api.delete_edge("e:e05")
    bundle2 = await api.query(text="e05unique")
    assert "e:e05" not in {e.id for e in bundle2.entries}


async def test_e06_delete_edge_removes_from_edge_write_lv() -> None:
    """After delete_edge, the edge's LWW clock entry is removed from _edge_write_lv."""
    api = _make_api()
    await api.upsert_node(_node("host:e06src"))
    await api.upsert_node(_node("host:e06dst"))
    await api.upsert_edge(_edge("e:e06", "host:e06src", "host:e06dst"))
    assert "e:e06" in api._edge_write_lv

    await api.delete_edge("e:e06")
    assert "e:e06" not in api._edge_write_lv, (
        "_edge_write_lv must not retain entry for a deleted edge"
    )


async def test_e07_delete_node_then_upsert_creates_fresh_entry() -> None:
    """After delete_node, a new upsert_node with the same id creates a clean entry
    with no provenance from the deleted node's fields."""
    api = _make_api()
    await api.upsert_node(_node("host:e07", old_field="old_value"))
    await api.delete_node("host:e07")

    await api.upsert_node(_node("host:e07", new_field="new_value"))
    stored = await api._graph.get_node("host:e07")
    assert stored is not None
    assert stored.props.get("new_field") == "new_value"
    assert "old_field" not in stored.props, (
        "Old field must not persist after delete + re-upsert"
    )


async def test_e08_delete_nonexistent_node_is_noop() -> None:
    """delete_node on a non-existent id must not raise."""
    api = _make_api()
    await api.delete_node("host:e08_does_not_exist")  # must not raise


async def test_e09_delete_nonexistent_edge_is_noop() -> None:
    """delete_edge on a non-existent id must not raise."""
    api = _make_api()
    await api.delete_edge("e:e09_does_not_exist")  # must not raise


async def test_e10_delete_node_acquires_graph_lock() -> None:
    """delete_node must hold _graph_lock when calling the graph store."""
    api = _make_api()
    await api.upsert_node(_node("host:e10"))

    lock_was_held: list[bool] = []
    original_delete_node = api._graph.delete_node

    async def spy_delete(node_id: str) -> None:
        lock_was_held.append(api._graph_lock.locked())
        return await original_delete_node(node_id)

    api._graph.delete_node = spy_delete  # type: ignore[method-assign]
    await api.delete_node("host:e10")

    assert lock_was_held, "delete_node spy never called"
    assert all(lock_was_held), "lock must be held during all store delete_node calls"


# ---------------------------------------------------------------------------
# Section F — Defensive Copies via MemoryAPI Public Surface
# ---------------------------------------------------------------------------

async def test_f01_get_subgraph_node_mutation_does_not_affect_stored() -> None:
    """Mutating a node returned by get_subgraph must not affect the stored graph."""
    api = _make_api()
    await api.upsert_node(_node("host:f01", color="red"))

    sg = await api.get_subgraph("host:f01", 0)
    assert sg.nodes, "Subgraph must contain at least the anchor node"
    returned_node = next(n for n in sg.nodes if n.id == "host:f01")
    returned_node.props["color"] = "MUTATED"

    # Verify the stored node is unchanged
    stored = await api._graph.get_node("host:f01")
    assert stored is not None
    assert stored.props.get("color") == "red", (
        "Stored node must not be affected by mutation of a returned subgraph node"
    )


async def test_f02_get_subgraph_edge_mutation_does_not_affect_stored() -> None:
    """Mutating an edge returned by get_subgraph must not affect the stored graph."""
    api = _make_api()
    await api.upsert_node(_node("host:f02a"))
    await api.upsert_node(_node("host:f02b"))
    await api.upsert_edge(_edge("e:f02", "host:f02a", "host:f02b", port="80"))

    sg = await api.get_subgraph("host:f02a", 1)
    edge = next((e for e in sg.edges if e.id == "e:f02"), None)
    assert edge is not None
    edge.props["port"] = "MUTATED"

    stored_edge = await api._graph.get_edge("e:f02")
    assert stored_edge is not None
    assert stored_edge.props.get("port") == "80", (
        "Stored edge must not be affected by mutation of a returned subgraph edge"
    )


async def test_f03_open_tasks_props_mutation_does_not_affect_stored() -> None:
    """Mutating props in an OpenTask result must not affect the stored node."""
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
    await api.upsert_node(_node("host:f03", status="open"))
    tasks = await api.open_tasks()
    f03_task = next((t for t in tasks if t.node_id == "host:f03"), None)
    assert f03_task is not None
    f03_task.props["status"] = "MUTATED"

    stored = await api._graph.get_node("host:f03")
    assert stored is not None
    assert stored.props.get("status") == "open", (
        "Stored node must not be affected by mutation of OpenTask.props"
    )


async def test_f04_two_get_subgraph_calls_return_independent_objects() -> None:
    """Two calls to get_subgraph with the same anchor return independent objects."""
    api = _make_api()
    await api.upsert_node(_node("host:f04", tag="original"))

    sg1 = await api.get_subgraph("host:f04", 0)
    sg2 = await api.get_subgraph("host:f04", 0)

    node1 = next(n for n in sg1.nodes if n.id == "host:f04")
    node2 = next(n for n in sg2.nodes if n.id == "host:f04")
    node1.props["tag"] = "mutated"

    assert node2.props.get("tag") == "original", (
        "Mutating a node from call 1 must not affect nodes from call 2"
    )


async def test_f05_two_open_tasks_calls_return_independent_objects() -> None:
    """Two calls to open_tasks return independent task objects."""
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
    await api.upsert_node(_node("host:f05", tag="original"))
    tasks1 = await api.open_tasks()
    tasks2 = await api.open_tasks()

    t1 = next((t for t in tasks1 if t.node_id == "host:f05"), None)
    t2 = next((t for t in tasks2 if t.node_id == "host:f05"), None)
    assert t1 is not None and t2 is not None

    t1.props["tag"] = "mutated"
    assert t2.props.get("tag") == "original", (
        "Mutating task from call 1 must not affect task from call 2"
    )


async def test_f06_pre_batch_snapshot_independent_of_batch_writes() -> None:
    """The pre-batch snapshot captured by apply_deltas must be a copy that is
    not mutated by the in-progress batch writes.  Verified by checking that a
    failed batch restores correctly — if the snapshot were a live reference, the
    restored value would be the post-write value rather than the pre-write one."""
    api = _make_api()
    await api.upsert_node(_node("host:f06", value="pre"))

    original_put_edge = api._graph.put_edge

    async def fail_edge(edge: Edge) -> str:
        raise RuntimeError("force rollback")

    api._graph.put_edge = fail_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            nodes=[_node("host:f06", value="post")],
            edges=[_edge("e:f06", "host:f06", "host:f06")],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    stored = await api._graph.get_node("host:f06")
    assert stored is not None
    assert stored.props.get("value") == "pre", (
        "Rollback must restore the pre-batch snapshot value, not the in-progress write"
    )


async def test_f07_returned_subgraph_after_batch_is_independent_copy() -> None:
    """The subgraph returned by apply_deltas (via get_subgraph after batch) is a copy."""
    api = _make_api()
    await api.upsert_node(_node("host:f07", tag="original"))
    await api.apply_deltas(nodes=[])  # no-op batch

    sg = await api.get_subgraph("host:f07", 0)
    node = next((n for n in sg.nodes if n.id == "host:f07"), None)
    assert node is not None
    node.props["tag"] = "mutated"

    stored = await api._graph.get_node("host:f07")
    assert stored is not None
    assert stored.props.get("tag") == "original", (
        "Mutating subgraph node must not affect stored state"
    )


# ---------------------------------------------------------------------------
# Section G — Architecture Scan
# ---------------------------------------------------------------------------

def _find_py_files(root: Path, exclude_dirs: list[str]) -> list[Path]:
    result = []
    for p in root.rglob("*.py"):
        if any(ex in p.parts for ex in exclude_dirs):
            continue
        result.append(p)
    return result


def _get_direct_store_mutation_calls(source: str) -> list[tuple[int, str]]:
    """Return (lineno, line) tuples for direct graph-store mutation calls outside MemoryAPI."""
    violations = []
    suspicious = (
        ".put_node(", ".put_edge(", ".delete_node(", ".delete_edge(",
        "._graph.put_node", "._graph.put_edge", "._graph.delete_node", "._graph.delete_edge",
    )
    for lineno, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pat in suspicious:
            if pat in line:
                violations.append((lineno, line.rstrip()))
                break
    return violations


def test_g01_no_production_graph_mutation_bypasses_memory_api() -> None:
    """No production memfabric source file (outside MemoryAPI and GraphStore
    implementations) should call GraphStore mutation methods directly."""
    root = Path(__file__).parent.parent / "memfabric"
    # These files ARE allowed to call store mutation methods:
    allowed_files = {
        "api.py",            # MemoryAPI — the sole mutation surface
        "graph_networkx.py", # GraphStore implementation
    }
    # Scan all other memfabric source files
    violations: list[str] = []
    for py_file in sorted(root.rglob("*.py")):
        if py_file.name in allowed_files:
            continue
        if "__pycache__" in str(py_file):
            continue
        source = py_file.read_text()
        hits = _get_direct_store_mutation_calls(source)
        if hits:
            for lineno, line in hits:
                violations.append(f"{py_file.relative_to(root.parent)}:{lineno}: {line}")

    assert not violations, (
        "Direct GraphStore mutation calls found outside allowed files:\n"
        + "\n".join(violations)
    )


def test_g02_no_direct_append_outside_memory_api() -> None:
    """No production memfabric source file (outside MemoryAPI and EpisodicStore
    implementations) should call EpisodicStore.append() directly."""
    root = Path(__file__).parent.parent / "memfabric"
    allowed_files = {"api.py", "episodic_jsonl.py"}
    violations: list[str] = []
    for py_file in sorted(root.rglob("*.py")):
        if py_file.name in allowed_files:
            continue
        if "__pycache__" in str(py_file):
            continue
        source = py_file.read_text()
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "._episodic.append(" in line or ".episodic.append(" in line:
                violations.append(
                    f"{py_file.relative_to(root.parent)}:{lineno}: {line.rstrip()}"
                )

    assert not violations, (
        "Direct EpisodicStore.append() calls found outside allowed files:\n"
        + "\n".join(violations)
    )


# ---------------------------------------------------------------------------
# Section H — Episode Append Contract
# ---------------------------------------------------------------------------

async def test_h01_episode_rollback_removes_from_episodic_store() -> None:
    """A failed batch that appended an episode must remove it from the episodic store."""
    api = _make_api()

    ep = _episode()
    original_put_edge = api._graph.put_edge

    async def fail_edge(edge: Edge) -> str:
        raise RuntimeError("trigger rollback after episode")

    api._graph.put_edge = fail_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            episodes=[ep],
            edges=[_edge("e:h01", "x", "y")],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    # Episode must be absent from the store
    episodes = await api._episodic.all()
    episode_ids = {e.id for e in episodes}
    assert ep.id not in episode_ids, "Rolled-back episode must not remain in the episodic store"


async def test_h02_duplicate_episode_id_raises() -> None:
    """append_episode with an id that already exists must raise ValueError."""
    api = _make_api()
    ep = _episode()
    ep.id = "ep-fixed-id"
    await api.append_episode(ep)

    ep2 = _episode()
    ep2.id = "ep-fixed-id"
    with pytest.raises(ValueError):
        await api.append_episode(ep2)


async def test_h03_episode_indexed_in_lexical() -> None:
    """After append_episode, the episode is findable via lexical search."""
    api = _make_api()
    ep = _episode(action="probe_unique_h03", data={"detail": "h03_unique"})
    await api.append_episode(ep)

    bundle = await api.query(text="probe_unique_h03")
    ids = {e.id for e in bundle.entries}
    assert ep.id in ids, "Episode must be in lexical index after append"


async def test_h04_failed_batch_with_episode_rolls_back_nodes_too() -> None:
    """A failed batch that includes both nodes and an episode must roll back both."""
    api = _make_api()
    ep = _episode()

    original_put_edge = api._graph.put_edge

    async def fail_edge(edge: Edge) -> str:
        raise RuntimeError("trigger rollback")

    api._graph.put_edge = fail_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            nodes=[_node("host:h04")],
            episodes=[ep],
            edges=[_edge("e:h04", "x", "y")],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    # Both the node and episode should be absent
    assert await api._graph.get_node("host:h04") is None, "Node must be rolled back"
    episodes = await api._episodic.all()
    episode_ids = {e.id for e in episodes}
    assert ep.id not in episode_ids, "Episode must be rolled back"


async def test_h05_episode_lexical_removed_on_rollback() -> None:
    """An episode appended during a failed batch is removed from the lexical index."""
    api = _make_api()
    ep = _episode(action="h05_unique_action")

    original_put_edge = api._graph.put_edge

    async def fail_edge(edge: Edge) -> str:
        raise RuntimeError("trigger rollback")

    api._graph.put_edge = fail_edge  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await api.apply_deltas(
            episodes=[ep],
            edges=[_edge("e:h05", "x", "y")],
        )

    api._graph.put_edge = original_put_edge  # type: ignore[method-assign]

    bundle = await api.query(text="h05_unique_action")
    ids = {e.id for e in bundle.entries}
    assert ep.id not in ids, "Rolled-back episode must not be in lexical index"
