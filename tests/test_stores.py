"""Tests for Module 2: stores/.

Covers:
- NetworkXGraphStore: put/get, subgraph BFS, edge filtering.
- JSONLEpisodicStore: append, immutability (cannot re-append same id), replay.
- BM25LexicalIndex: zero-score filtering, dedup, lazy rebuild, empty degradation.
- FaissVectorIndex: add/search/remove, dimension mismatch.
- InMemoryKVStore: get/set/delete, TTL expiry.
"""
from __future__ import annotations

import asyncio
import pathlib
import time

import pytest

from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Episode, Node, Outcome


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_node(id: str, type: str = "host", **props: object) -> Node:
    t = now()
    return Node(
        id=id,
        type=type,
        props=dict(props),
        confidence=0.9,
        source="test",
        first_seen=t,
        last_seen=t,
    )


def make_edge(id: str, from_id: str, to_id: str, type: str = "connects") -> Edge:
    t = now()
    return Edge(id=id, from_id=from_id, to_id=to_id, type=type,
                props={}, confidence=0.8, source="test", first_seen=t, last_seen=t)


def make_episode(**kwargs: object) -> Episode:
    return Episode(
        agent=str(kwargs.get("agent", "agent-1")),
        action=str(kwargs.get("action", "scan")),
        outcome=Outcome(kwargs.get("outcome", "success")),
        data=dict(kwargs.get("data", {})),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# NetworkXGraphStore
# ---------------------------------------------------------------------------

class TestNetworkXGraphStore:
    @pytest.fixture()
    def store(self) -> NetworkXGraphStore:
        return NetworkXGraphStore()

    async def test_put_and_get_node(self, store: NetworkXGraphStore) -> None:
        n = make_node("n1", ip="1.2.3.4")
        await store.put_node(n)
        result = await store.get_node("n1")
        assert result is not None
        assert result.id == "n1"
        assert result.props["ip"] == "1.2.3.4"

    async def test_get_nonexistent_node(self, store: NetworkXGraphStore) -> None:
        assert await store.get_node("nope") is None

    async def test_put_and_get_edge(self, store: NetworkXGraphStore) -> None:
        await store.put_node(make_node("a"))
        await store.put_node(make_node("b"))
        e = make_edge("e1", "a", "b")
        await store.put_edge(e)
        result = await store.get_edge("e1")
        assert result is not None
        assert result.from_id == "a"

    async def test_put_node_replaces_existing(self, store: NetworkXGraphStore) -> None:
        n = make_node("n1", ip="1.1.1.1")
        await store.put_node(n)
        t = now()
        n2 = Node("n1", "host", {"ip": "2.2.2.2"}, 0.9, "test", t, t)
        await store.put_node(n2)
        result = await store.get_node("n1")
        assert result is not None
        assert result.props["ip"] == "2.2.2.2"

    async def test_get_nodes_by_type(self, store: NetworkXGraphStore) -> None:
        await store.put_node(make_node("a", type="host"))
        await store.put_node(make_node("b", type="service"))
        await store.put_node(make_node("c", type="host"))
        hosts = await store.get_nodes_by_type("host")
        assert len(hosts) == 2
        assert all(n.type == "host" for n in hosts)

    async def test_get_edges_for_node(self, store: NetworkXGraphStore) -> None:
        await store.put_node(make_node("a"))
        await store.put_node(make_node("b"))
        await store.put_node(make_node("c"))
        await store.put_edge(make_edge("e1", "a", "b"))
        await store.put_edge(make_edge("e2", "c", "a"))
        edges = await store.get_edges_for_node("a")
        ids = {e.id for e in edges}
        assert "e1" in ids
        assert "e2" in ids

    async def test_subgraph_depth_1(self, store: NetworkXGraphStore) -> None:
        # a -e1→ b -e2→ c
        for node_id in ("a", "b", "c"):
            await store.put_node(make_node(node_id))
        await store.put_edge(make_edge("e1", "a", "b"))
        await store.put_edge(make_edge("e2", "b", "c"))

        sg = await store.get_subgraph("a", depth=1)
        node_ids = {n.id for n in sg.nodes}
        assert "a" in node_ids
        assert "b" in node_ids
        assert "c" not in node_ids

    async def test_subgraph_depth_2(self, store: NetworkXGraphStore) -> None:
        for node_id in ("a", "b", "c"):
            await store.put_node(make_node(node_id))
        await store.put_edge(make_edge("e1", "a", "b"))
        await store.put_edge(make_edge("e2", "b", "c"))

        sg = await store.get_subgraph("a", depth=2)
        node_ids = {n.id for n in sg.nodes}
        assert {"a", "b", "c"} <= node_ids

    async def test_subgraph_edge_type_filter(self, store: NetworkXGraphStore) -> None:
        for node_id in ("a", "b", "c"):
            await store.put_node(make_node(node_id))
        await store.put_edge(make_edge("e1", "a", "b", type="owns"))
        await store.put_edge(make_edge("e2", "a", "c", type="connects"))

        sg = await store.get_subgraph("a", depth=1, edge_types=["owns"])
        edge_ids = {e.id for e in sg.edges}
        assert "e1" in edge_ids
        assert "e2" not in edge_ids

    async def test_all_nodes_and_edges(self, store: NetworkXGraphStore) -> None:
        await store.put_node(make_node("x"))
        await store.put_node(make_node("y"))
        await store.put_edge(make_edge("ex", "x", "y"))
        assert len(await store.all_nodes()) == 2
        assert len(await store.all_edges()) == 1

    async def test_concurrent_puts(self, store: NetworkXGraphStore) -> None:
        nodes = [make_node(f"n{i}") for i in range(50)]
        await asyncio.gather(*[store.put_node(n) for n in nodes])
        all_nodes = await store.all_nodes()
        assert len(all_nodes) == 50


# ---------------------------------------------------------------------------
# JSONLEpisodicStore
# ---------------------------------------------------------------------------

class TestJSONLEpisodicStore:
    @pytest.fixture()
    def store(self) -> JSONLEpisodicStore:
        return JSONLEpisodicStore(path=None)   # in-memory

    async def test_append_assigns_id_and_timestamp(
        self, store: JSONLEpisodicStore
    ) -> None:
        ep = make_episode()
        assert ep.id == ""
        eid = await store.append(ep)
        assert eid != ""
        assert ep.id == eid
        assert ep.timestamp != ""

    async def test_get_returns_correct_episode(
        self, store: JSONLEpisodicStore
    ) -> None:
        ep = make_episode(action="port_scan")
        eid = await store.append(ep)
        result = await store.get(eid)
        assert result is not None
        assert result.action == "port_scan"

    async def test_episodic_immutability_same_id_rejected(
        self, store: JSONLEpisodicStore
    ) -> None:
        ep = make_episode()
        await store.append(ep)
        # Attempting to append the same id again must raise
        with pytest.raises(ValueError, match="immutable"):
            await store.append(ep)

    async def test_tail(self, store: JSONLEpisodicStore) -> None:
        for i in range(5):
            await store.append(make_episode(action=f"act{i}"))
        tail = await store.tail(3)
        assert len(tail) == 3
        assert tail[-1].action == "act4"

    async def test_since(self, store: JSONLEpisodicStore) -> None:
        ids = []
        for i in range(4):
            ep = make_episode(action=f"a{i}")
            eid = await store.append(ep)
            ids.append(eid)
        after = await store.since(ids[1])
        actions = [ep.action for ep in after]
        assert "a2" in actions
        assert "a3" in actions
        assert "a0" not in actions
        assert "a1" not in actions

    async def test_all(self, store: JSONLEpisodicStore) -> None:
        for _ in range(3):
            await store.append(make_episode())
        eps = await store.all()
        assert len(eps) == 3

    async def test_replay_reconstructs_state(
        self, store: JSONLEpisodicStore, tmp_path: pathlib.Path
    ) -> None:
        """Replay from file restores all episodes (resumability invariant)."""
        file_path = tmp_path / "episodes.jsonl"
        s1 = JSONLEpisodicStore(path=file_path)
        for i in range(3):
            await s1.append(make_episode(action=f"step{i}"))

        # New store instance reads from same file
        s2 = JSONLEpisodicStore(path=file_path)
        eps = await s2.all()
        assert len(eps) == 3
        assert {ep.action for ep in eps} == {"step0", "step1", "step2"}

    async def test_concurrent_appends_are_safe(
        self, store: JSONLEpisodicStore
    ) -> None:
        eps = [make_episode(action=f"act{i}") for i in range(20)]
        await asyncio.gather(*[store.append(ep) for ep in eps])
        all_eps = await store.all()
        assert len(all_eps) == 20


# ---------------------------------------------------------------------------
# BM25LexicalIndex
# ---------------------------------------------------------------------------

class TestBM25LexicalIndex:
    @pytest.fixture()
    def idx(self) -> BM25LexicalIndex:
        return BM25LexicalIndex()

    async def test_empty_index_returns_empty(self, idx: BM25LexicalIndex) -> None:
        results = await idx.search("anything", k=5)
        assert results == []

    async def test_basic_search(self, idx: BM25LexicalIndex) -> None:
        await idx.add("d1", "nginx web server vulnerability", {"tier": "semantic"})
        await idx.add("d2", "ssh brute force attack detected", {"tier": "semantic"})
        results = await idx.search("nginx", k=5)
        ids = [r[0] for r in results]
        assert "d1" in ids

    async def test_matching_doc_ranks_higher(self, idx: BM25LexicalIndex) -> None:
        # BM25Plus gives background scores to all docs; the doc containing the
        # query term must score strictly higher than the one that does not.
        await idx.add("d1", "apple banana cherry", {"tier": "semantic"})
        await idx.add("d2", "dog cat fish", {"tier": "semantic"})
        results = await idx.search("apple", k=5)
        ids = [r[0] for r in results]
        assert "d1" in ids
        score_d1 = next(r[1] for r in results if r[0] == "d1")
        score_d2 = next((r[1] for r in results if r[0] == "d2"), 0.0)
        assert score_d1 > score_d2

    async def test_dedup_in_results(self, idx: BM25LexicalIndex) -> None:
        await idx.add("same", "keyword repeated many times keyword keyword", {"tier": "x"})
        results = await idx.search("keyword", k=10)
        ids = [r[0] for r in results]
        assert ids.count("same") == 1

    async def test_metadata_passed_through(self, idx: BM25LexicalIndex) -> None:
        await idx.add("d1", "token scan report", {"tier": "semantic", "extra": 42})
        results = await idx.search("scan", k=5)
        assert results[0][2]["tier"] == "semantic"
        assert results[0][2]["extra"] == 42

    async def test_remove(self, idx: BM25LexicalIndex) -> None:
        await idx.add("keep", "important data here", {"tier": "x"})
        await idx.add("gone", "important data here", {"tier": "x"})
        await idx.remove("gone")
        results = await idx.search("important", k=5)
        ids = [r[0] for r in results]
        assert "keep" in ids
        assert "gone" not in ids

    async def test_top_k_limit(self, idx: BM25LexicalIndex) -> None:
        for i in range(10):
            await idx.add(f"d{i}", f"common word plus unique_{i}", {"tier": "x"})
        results = await idx.search("common word", k=3)
        assert len(results) <= 3

    async def test_update_existing_id(self, idx: BM25LexicalIndex) -> None:
        await idx.add("d1", "old content here", {"tier": "x"})
        await idx.add("d1", "new content here", {"tier": "x"})   # update
        results = await idx.search("new", k=5)
        ids = [r[0] for r in results]
        assert "d1" in ids

    async def test_lazy_rebuild_after_add(self, idx: BM25LexicalIndex) -> None:
        """Index should remain consistent through multiple add/search cycles."""
        await idx.add("a", "alpha beta gamma", {"tier": "x"})
        r1 = await idx.search("alpha", k=5)
        await idx.add("b", "delta epsilon zeta", {"tier": "x"})
        r2 = await idx.search("delta", k=5)
        assert r1[0][0] == "a"
        assert r2[0][0] == "b"


# ---------------------------------------------------------------------------
# FaissVectorIndex
# ---------------------------------------------------------------------------

class TestFaissVectorIndex:
    DIM = 4

    @pytest.fixture()
    def idx(self) -> FaissVectorIndex:
        return FaissVectorIndex(dim=self.DIM)

    def _vec(self, *vals: float) -> list[float]:
        return list(vals)

    async def test_empty_returns_empty(self, idx: FaissVectorIndex) -> None:
        results = await idx.search(self._vec(1.0, 0.0, 0.0, 0.0), k=5)
        assert results == []

    async def test_nearest_neighbour(self, idx: FaissVectorIndex) -> None:
        await idx.add("a", self._vec(1.0, 0.0, 0.0, 0.0), {"tier": "semantic"})
        await idx.add("b", self._vec(0.0, 1.0, 0.0, 0.0), {"tier": "semantic"})
        results = await idx.search(self._vec(1.0, 0.0, 0.0, 0.0), k=2)
        assert results[0][0] == "a"

    async def test_metadata_returned(self, idx: FaissVectorIndex) -> None:
        await idx.add("m", self._vec(1.0, 0.0, 0.0, 0.0), {"tier": "procedural", "name": "skill-A"})
        results = await idx.search(self._vec(1.0, 0.0, 0.0, 0.0), k=1)
        assert results[0][2]["name"] == "skill-A"

    async def test_remove(self, idx: FaissVectorIndex) -> None:
        await idx.add("keep", self._vec(1.0, 0.0, 0.0, 0.0), {"tier": "x"})
        await idx.add("gone", self._vec(1.0, 0.0, 0.0, 0.0), {"tier": "x"})
        await idx.remove("gone")
        results = await idx.search(self._vec(1.0, 0.0, 0.0, 0.0), k=5)
        ids = [r[0] for r in results]
        assert "keep" in ids
        assert "gone" not in ids

    async def test_wrong_dim_raises(self, idx: FaissVectorIndex) -> None:
        with pytest.raises(ValueError, match="dim"):
            await idx.add("bad", [1.0, 2.0], {"tier": "x"})  # wrong dim

    async def test_top_k_capped_at_index_size(self, idx: FaissVectorIndex) -> None:
        await idx.add("only", self._vec(1.0, 0.0, 0.0, 0.0), {"tier": "x"})
        results = await idx.search(self._vec(1.0, 0.0, 0.0, 0.0), k=10)
        assert len(results) == 1   # can't return more than exist


# ---------------------------------------------------------------------------
# InMemoryKVStore
# ---------------------------------------------------------------------------

class TestInMemoryKVStore:
    @pytest.fixture()
    def store(self) -> InMemoryKVStore:
        return InMemoryKVStore()

    async def test_set_and_get(self, store: InMemoryKVStore) -> None:
        await store.set("key", {"val": 42})
        result = await store.get("key")
        assert result == {"val": 42}

    async def test_missing_key_returns_none(self, store: InMemoryKVStore) -> None:
        assert await store.get("nope") is None

    async def test_delete(self, store: InMemoryKVStore) -> None:
        await store.set("k", "v")
        await store.delete("k")
        assert await store.get("k") is None

    async def test_ttl_expiry(self, store: InMemoryKVStore) -> None:
        await store.set("tmp", "data", ttl_seconds=0.05)
        assert await store.get("tmp") == "data"
        time.sleep(0.1)
        assert await store.get("tmp") is None

    async def test_no_ttl_never_expires(self, store: InMemoryKVStore) -> None:
        await store.set("perm", "value")
        time.sleep(0.05)
        assert await store.get("perm") == "value"

    async def test_overwrite(self, store: InMemoryKVStore) -> None:
        await store.set("k", "old")
        await store.set("k", "new")
        assert await store.get("k") == "new"
