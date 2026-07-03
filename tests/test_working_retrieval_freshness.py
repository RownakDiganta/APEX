# test_working_retrieval_freshness.py
# Tests proving that working-tier graph writes are immediately visible in retrieval (no stale cache or duplicate index entries).
"""Freshness invariant tests for the working-tier retrieval path.

Invariant: every ``upsert_node`` / ``upsert_edge`` call must synchronously
refresh the retrieval indexes and invalidate the retrieval cache so that the
next ``query()`` call sees current graph state — no wait for Reflector
promotion, no wait for cache TTL expiry.

Three fix surfaces verified here:
  1. BM25 lexical freshness (always active)
  2. Retrieval-cache invalidation (always active via ``kv.delete_prefix``)
  3. Dense (vector) freshness when an Embedder is injected into MemoryAPI
"""
from __future__ import annotations

import hashlib
from typing import Any

import pytest

from memfabric.api import MemoryAPI, _edge_text, _node_text
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node, Tier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeEmbedder:
    """Deterministic test embedder — hash-seeded vector per text, no ML."""

    def __init__(self, dim: int = 384) -> None:
        self._dim = dim

    async def embed(self, texts: list[str]) -> list[list[float]]:
        result = []
        for text in texts:
            seed = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
            vec = [
                float((seed * 1664525 + i * 1013904223) & 0xFFFFFF) / float(0xFFFFFF)
                for i in range(self._dim)
            ]
            result.append(vec)
        return result


def make_api(
    *,
    embedder: FakeEmbedder | None = None,
    gate_always_open: bool = False,
) -> tuple[MemoryAPI, Any]:
    """Return (api, retriever) wired with a real HybridRetriever."""
    from memfabric.retrieval.engine import HybridRetriever
    from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher

    tau = 1000.0 if gate_always_open else 0.0
    cfg = Config(low_confidence_tau=tau)

    graph = NetworkXGraphStore()
    episodic = JSONLEpisodicStore(path=None)
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=cfg.vector_dim)
    kv = InMemoryKVStore()

    # The retriever's own embedder (used at search time for the dense channel)
    retriever_embedder = embedder if embedder is not None else StubEmbedder()

    api = MemoryAPI(
        graph=graph, episodic=episodic, lexical=lexical,
        vector=vector, kv=kv, config=cfg,
        embedder=embedder,  # write-time embedder: updates vector index on upsert
    )
    retriever = HybridRetriever(
        lexical=lexical, vector=vector,
        embedder=retriever_embedder,
        reranker=PassthroughReranker(),
        graph=graph, graph_matcher=TextGraphMatcher(),
        kv=kv, config=cfg,
    )
    api.set_retriever(retriever)
    return api, retriever


def svc_node(nid: str, **props: object) -> Node:
    t = now()
    return Node(id=nid, type="service", props=dict(props),
                confidence=0.7, source="nmap", first_seen=t, last_seen=t)


def edge(eid: str, from_id: str, to_id: str, etype: str, **props: object) -> Edge:
    t = now()
    return Edge(id=eid, from_id=from_id, to_id=to_id, type=etype,
                props=dict(props), confidence=0.7, source="parser",
                first_seen=t, last_seen=t)


# ---------------------------------------------------------------------------
# 1. Lexical freshness — BM25 sees upserted nodes immediately
# ---------------------------------------------------------------------------

class TestLexicalFreshness:
    async def test_upserted_node_is_immediately_queryable(self) -> None:
        """upsert a service node → query("ssh") must return it without any delay."""
        api, _ = make_api()
        n = svc_node("svc1", port="22", service="ssh", proto="tcp")
        await api.upsert_node(n)

        bundle = await api.query(text="ssh", tiers=[Tier.working])
        ids = {e.id for e in bundle.entries}
        assert "svc1" in ids, "upserted ssh node must appear in immediate query"

    async def test_updated_node_text_visible_in_next_query(self) -> None:
        """After a field update the enriched text must be retrievable."""
        api, _ = make_api()
        n = svc_node("svc1", port="22", service="ssh")
        await api.upsert_node(n)

        # Enrich: add version field so "OpenSSH 8.2" appears in node text
        n2 = svc_node("svc1", port="22", service="ssh", version="OpenSSH 8.2")
        await api.upsert_node(n2)

        bundle = await api.query(text="OpenSSH", tiers=[Tier.working])
        ids = {e.id for e in bundle.entries}
        assert "svc1" in ids, "updated node must appear in query for newly added field text"

    async def test_no_stale_duplicate_text_after_update(self) -> None:
        """The lexical index must update in-place — no duplicate doc per node."""
        api, _ = make_api()
        n = svc_node("svc1", port="22", service="ssh")
        await api.upsert_node(n)
        # Second upsert adds new field
        n2 = svc_node("svc1", port="22", service="ssh", version="OpenSSH 8.2")
        await api.upsert_node(n2)

        # BM25 internally keeps one doc per id.  If there were a duplicate,
        # searching for a term unique to the ORIGINAL text would still return
        # a result.  But there is no such unique term here — instead we verify
        # the count: the same node id should appear AT MOST once.
        bundle = await api.query(text="ssh", tiers=[Tier.working])
        matching_ids = [e.id for e in bundle.entries if e.id == "svc1"]
        assert len(matching_ids) == 1, "the same node must not appear twice (no stale duplicate)"

    async def test_node_text_in_scored_entry_is_latest(self) -> None:
        """The ScoredEntry.text field must reflect the post-update merged text."""
        api, _ = make_api()
        n = svc_node("svc1", service="ssh")
        await api.upsert_node(n)
        n2 = svc_node("svc1", service="ssh", version="OpenSSH 8.2")
        await api.upsert_node(n2)

        bundle = await api.query(text="OpenSSH", tiers=[Tier.working])
        entry = next((e for e in bundle.entries if e.id == "svc1"), None)
        assert entry is not None
        assert "OpenSSH" in entry.text, "ScoredEntry.text must carry the updated node text"

    async def test_multiple_nodes_all_queryable(self) -> None:
        """Multiple upserted nodes are all independently queryable."""
        api, _ = make_api()
        await api.upsert_node(svc_node("s1", service="ssh", port="22"))
        await api.upsert_node(svc_node("s2", service="ftp", port="21"))
        await api.upsert_node(svc_node("s3", service="http", port="80"))

        for text, expected_id in [("ssh", "s1"), ("ftp", "s2"), ("http", "s3")]:
            bundle = await api.query(text=text, tiers=[Tier.working])
            ids = {e.id for e in bundle.entries}
            assert expected_id in ids, f"node {expected_id!r} must appear for query {text!r}"


# ---------------------------------------------------------------------------
# 2. Cache invalidation — same query after an update must see fresh data
# ---------------------------------------------------------------------------

class TestCacheInvalidation:
    async def test_same_query_after_update_returns_fresh_result(self) -> None:
        """The retrieval cache must be busted on node write.

        Without cache invalidation: query("ssh") → cached → update node to add
        "OpenSSH 8.2" → query("ssh") returns STALE cached text (no OpenSSH).
        With invalidation: second query runs fresh BM25 → returns updated text.
        """
        api, _ = make_api()
        n = svc_node("svc1", service="ssh")
        await api.upsert_node(n)

        # First query: populates cache
        bundle1 = await api.query(text="ssh", tiers=[Tier.working])
        entry1 = next((e for e in bundle1.entries if e.id == "svc1"), None)
        assert entry1 is not None
        assert "OpenSSH" not in (entry1.text or "")

        # Update the node
        n2 = svc_node("svc1", service="ssh", version="OpenSSH 8.2")
        await api.upsert_node(n2)

        # Second query with SAME text: must NOT return stale cached version
        bundle2 = await api.query(text="ssh", tiers=[Tier.working])
        entry2 = next((e for e in bundle2.entries if e.id == "svc1"), None)
        assert entry2 is not None
        assert "OpenSSH" in entry2.text, (
            "cache must be busted after upsert_node so the updated text is visible"
        )

    async def test_cache_is_invalidated_before_query_returns(self) -> None:
        """Verify the KV cache has no retrieval entries immediately after a write."""
        api, _ = make_api()
        n = svc_node("svc1", service="ssh")
        await api.upsert_node(n)

        # Prime the cache with a query
        await api.query(text="ssh", tiers=[Tier.working])
        # Verify cache was populated
        kv = api._kv  # type: ignore[attr-defined]
        assert isinstance(kv, InMemoryKVStore)
        retrieval_keys_before = [k for k in kv._data if k.startswith("retrieval:")]
        assert len(retrieval_keys_before) >= 1, "cache should have been set after first query"

        # Write: must bust cache
        n2 = svc_node("svc1", service="ssh", version="OpenSSH 8.2")
        await api.upsert_node(n2)

        retrieval_keys_after = [k for k in kv._data if k.startswith("retrieval:")]
        assert len(retrieval_keys_after) == 0, (
            "upsert_node must delete all retrieval: cache keys synchronously"
        )

    async def test_new_node_does_not_interfere_with_cache_of_other_queries(self) -> None:
        """Inserting node A busts ALL retrieval cache entries (including unrelated queries)."""
        api, _ = make_api()
        await api.upsert_node(svc_node("s1", service="ssh"))
        await api.upsert_node(svc_node("s2", service="ftp"))

        # Prime two cache entries
        await api.query(text="ssh", tiers=[Tier.working])
        await api.query(text="ftp", tiers=[Tier.working])

        kv = api._kv  # type: ignore[attr-defined]
        assert isinstance(kv, InMemoryKVStore)
        assert len([k for k in kv._data if k.startswith("retrieval:")]) == 2

        # Write a third node — must clear ALL cached queries
        await api.upsert_node(svc_node("s3", service="http"))
        assert len([k for k in kv._data if k.startswith("retrieval:")]) == 0, (
            "any graph write must bust the entire retrieval cache"
        )

    async def test_query_after_cache_bust_re_populates_cache(self) -> None:
        """After cache invalidation, the next query caches its fresh result."""
        api, _ = make_api()
        await api.upsert_node(svc_node("s1", service="ssh"))

        # First query: cache populated
        await api.query(text="ssh", tiers=[Tier.working])
        # Write: cache cleared
        await api.upsert_node(svc_node("s2", service="ftp"))
        kv = api._kv  # type: ignore[attr-defined]
        assert isinstance(kv, InMemoryKVStore)
        assert len([k for k in kv._data if k.startswith("retrieval:")]) == 0

        # Second query: runs fresh, then re-populates cache
        await api.query(text="ssh", tiers=[Tier.working])
        assert len([k for k in kv._data if k.startswith("retrieval:")]) >= 1, (
            "query after cache bust must re-populate the cache"
        )


# ---------------------------------------------------------------------------
# 3. Edge indexing — edge mutations are retrievable
# ---------------------------------------------------------------------------

class TestEdgeIndexing:
    async def test_upserted_edge_is_immediately_queryable(self) -> None:
        """An upserted edge must appear in query() without any separate index step."""
        api, _ = make_api()
        await api.upsert_node(svc_node("host1", ip="10.0.0.1"))
        await api.upsert_node(svc_node("svc1", service="ssh"))

        e = edge("e1", "host1", "svc1", "exposes")
        await api.upsert_edge(e)

        bundle = await api.query(text="exposes", tiers=[Tier.working])
        ids = {entry.id for entry in bundle.entries}
        assert "e1" in ids, "upserted edge must be queryable by its type text"

    async def test_updated_edge_text_visible_in_next_query(self) -> None:
        """After upsert_edge replaces an edge, the new text must be retrievable."""
        api, _ = make_api()
        await api.upsert_node(svc_node("host1", ip="10.0.0.1"))
        await api.upsert_node(svc_node("svc1", service="ssh"))

        e1 = edge("e1", "host1", "svc1", "exposes", proto="tcp")
        await api.upsert_edge(e1)

        # Replace with a new edge that has an additional prop
        e2 = edge("e1", "host1", "svc1", "exposes", proto="tcp", banner="OpenSSH_8.2")
        await api.upsert_edge(e2)

        bundle = await api.query(text="OpenSSH_8.2", tiers=[Tier.working])
        ids = {entry.id for entry in bundle.entries}
        assert "e1" in ids, "updated edge props must be visible in next query"

    async def test_edge_query_busts_cache(self) -> None:
        """upsert_edge must bust the retrieval cache just like upsert_node."""
        api, _ = make_api()
        await api.upsert_node(svc_node("host1"))
        await api.upsert_node(svc_node("svc1"))

        # Prime cache with a query
        await api.query(text="exposes", tiers=[Tier.working])
        kv = api._kv  # type: ignore[attr-defined]
        assert isinstance(kv, InMemoryKVStore)
        # May or may not have results in cache yet — but after the edge write it must be empty
        e = edge("e1", "host1", "svc1", "exposes")
        await api.upsert_edge(e)

        retrieval_keys = [k for k in kv._data if k.startswith("retrieval:")]
        assert len(retrieval_keys) == 0, "upsert_edge must bust the retrieval cache"

    async def test_edge_text_contains_type_and_endpoints(self) -> None:
        """The indexed edge text must include the type, from_id, and to_id."""
        e = edge("e1", "host:10.0.0.1", "svc:22", "exposes", banner="vsftpd 3.0")
        text = _edge_text(e)
        assert "exposes" in text
        assert "host:10.0.0.1" in text
        assert "svc:22" in text
        assert "vsftpd 3.0" in text


# ---------------------------------------------------------------------------
# 4. Dense (vector) freshness — working nodes found via dense channel
# ---------------------------------------------------------------------------

class TestDenseFreshness:
    async def test_node_added_to_vector_index_on_upsert(self) -> None:
        """When an Embedder is injected, upsert_node must add the node to the vector index."""
        embedder = FakeEmbedder()
        api, _ = make_api(embedder=embedder)
        n = svc_node("svc1", service="ssh", port="22")
        await api.upsert_node(n)

        # Inspect vector index internals: svc1 must have been indexed
        assert "svc1" in api._vector._str_to_int, (  # type: ignore[attr-defined]
            "upsert_node with embedder must add node to vector index"
        )

    async def test_updated_node_replaces_vector_entry(self) -> None:
        """A second upsert must replace (not duplicate) the vector index entry."""
        embedder = FakeEmbedder()
        api, _ = make_api(embedder=embedder)
        n1 = svc_node("svc1", service="ssh")
        await api.upsert_node(n1)
        n_total_after_first = api._vector._index.ntotal  # type: ignore[attr-defined]

        n2 = svc_node("svc1", service="ssh", version="OpenSSH 8.2")
        await api.upsert_node(n2)
        n_total_after_second = api._vector._index.ntotal  # type: ignore[attr-defined]

        assert n_total_after_second == n_total_after_first, (
            "second upsert must replace the vector entry, not add a duplicate"
        )
        assert "svc1" in api._vector._str_to_int, (  # type: ignore[attr-defined]
            "node must remain in vector index after update"
        )

    async def test_dense_channel_finds_node_after_upsert(self) -> None:
        """With gate open and a real embedder, dense channel must find the upserted node."""
        embedder = FakeEmbedder()
        api, retriever = make_api(embedder=embedder, gate_always_open=True)

        n = svc_node("svc1", service="ssh", port="22")
        await api.upsert_node(n)

        # Verify dense channel fires
        bundle = await api.query(text="ssh service port", tiers=[Tier.working])
        assert retriever._last_dense_fired, "dense channel must have fired (tau is very high)"

        # With FakeEmbedder the dense results are hash-based (not semantic),
        # so we verify node appears through EITHER BM25 or dense channels.
        ids = {e.id for e in bundle.entries}
        assert "svc1" in ids, "node must be findable when gate is open (via BM25 or dense)"

    async def test_no_embedder_does_not_update_vector_index(self) -> None:
        """Without an embedder, the vector index must remain empty after node upsert."""
        api, _ = make_api(embedder=None)  # no embedder
        n = svc_node("svc1", service="ssh")
        await api.upsert_node(n)

        assert "svc1" not in api._vector._str_to_int, (  # type: ignore[attr-defined]
            "without an embedder, upsert_node must not touch the vector index"
        )

    async def test_edge_added_to_vector_index_on_upsert(self) -> None:
        """upsert_edge with embedder must also index the edge in the vector index."""
        embedder = FakeEmbedder()
        api, _ = make_api(embedder=embedder)
        await api.upsert_node(svc_node("host1"))
        await api.upsert_node(svc_node("svc1"))

        e = edge("e1", "host1", "svc1", "exposes")
        await api.upsert_edge(e)

        assert "e1" in api._vector._str_to_int, (  # type: ignore[attr-defined]
            "upsert_edge with embedder must add edge to vector index"
        )
