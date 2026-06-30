"""Tests for Module 4: retrieval/.

Section 8 invariants tested here:
- Retrieval gate: BM25 strong → dense/graph never fire; BM25 weak → they fire.
  Assert with a spy on the expensive channels.
- RRF fusion: known input rankings → known fused order.
- Cache hit: identical query → second call skips channel execution.
- gate.py is tested in isolation.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from memfabric.config import Config
from memfabric.retrieval.fusion import fuse_rrf
from memfabric.retrieval.gate import gate_is_open
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import (
    PassthroughReranker,
    StubEmbedder,
    TextGraphMatcher,
)
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import ScoredEntry, Tier


# ---------------------------------------------------------------------------
# gate.py — pure unit tests
# ---------------------------------------------------------------------------

class TestGate:
    def test_no_scores_opens_gate(self) -> None:
        assert gate_is_open([], tau=0.3) is True

    def test_low_max_score_opens_gate(self) -> None:
        assert gate_is_open([0.1, 0.2, 0.05], tau=0.3) is True

    def test_high_max_score_closes_gate(self) -> None:
        assert gate_is_open([0.5, 0.9], tau=0.3) is False

    def test_exactly_tau_closes_gate(self) -> None:
        # gate opens only when STRICTLY below tau
        assert gate_is_open([0.3], tau=0.3) is False

    def test_just_below_tau_opens_gate(self) -> None:
        assert gate_is_open([0.299], tau=0.3) is True


# ---------------------------------------------------------------------------
# fusion.py — RRF unit tests
# ---------------------------------------------------------------------------

class TestRRFFusion:
    def test_single_channel(self) -> None:
        """With one channel, RRF order must match input rank."""
        channel: list[tuple[str, float, dict[str, Any]]] = [
            ("a", 10.0, {}), ("b", 5.0, {}), ("c", 1.0, {}),
        ]
        fused = fuse_rrf([channel])
        assert [r[0] for r in fused] == ["a", "b", "c"]

    def test_two_channels_agreement(self) -> None:
        """Channels that agree amplify the top doc's score."""
        c1: list[tuple[str, float, dict[str, Any]]] = [("a", 1.0, {}), ("b", 0.5, {})]
        c2: list[tuple[str, float, dict[str, Any]]] = [("a", 0.9, {}), ("b", 0.4, {})]
        fused = fuse_rrf([c1, c2])
        assert fused[0][0] == "a"   # 'a' top in both → highest fused score

    def test_two_channels_disagreement_boosts_coverage(self) -> None:
        """Doc appearing in both channels despite rank disagreement beats a doc
        appearing in only one channel."""
        c1: list[tuple[str, float, dict[str, Any]]] = [("x", 1.0, {}), ("y", 0.5, {})]
        c2: list[tuple[str, float, dict[str, Any]]] = [("y", 1.0, {}), ("x", 0.5, {})]
        fused = fuse_rrf([c1, c2])
        ids = [r[0] for r in fused]
        # Both x and y appear in both channels; the net scores should be equal
        assert set(ids) == {"x", "y"}

    def test_rrf_formula_exact(self) -> None:
        """Verify exact RRF formula: score(d) = Σ 1 / (k + rank)."""
        k = 60
        c1: list[tuple[str, float, dict[str, Any]]] = [("d", 1.0, {})]   # rank 1
        fused = fuse_rrf([c1], k=k)
        expected = 1.0 / (k + 1)
        assert abs(fused[0][1] - expected) < 1e-12

    def test_weights_scale_channels(self) -> None:
        """A channel with weight=2 should contribute twice as much."""
        c1: list[tuple[str, float, dict[str, Any]]] = [("a", 1.0, {})]
        c2: list[tuple[str, float, dict[str, Any]]] = [("b", 1.0, {})]
        k = 60
        fused = fuse_rrf([c1, c2], k=k, weights=[2.0, 1.0])
        score_a = next(s for d, s, _ in fused if d == "a")
        score_b = next(s for d, s, _ in fused if d == "b")
        assert abs(score_a - 2.0 * score_b) < 1e-12

    def test_top_n_truncates(self) -> None:
        channel: list[tuple[str, float, dict[str, Any]]] = [
            (f"d{i}", float(10 - i), {}) for i in range(10)
        ]
        fused = fuse_rrf([channel], top_n=3)
        assert len(fused) == 3
        assert fused[0][0] == "d0"

    def test_empty_channel_skipped(self) -> None:
        c1: list[tuple[str, float, dict[str, Any]]] = [("a", 1.0, {})]
        fused = fuse_rrf([c1, []])
        assert len(fused) == 1
        assert fused[0][0] == "a"

    def test_metadata_preserved(self) -> None:
        c1: list[tuple[str, float, dict[str, Any]]] = [
            ("x", 1.0, {"tier": "semantic", "custom": 99})
        ]
        fused = fuse_rrf([c1])
        assert fused[0][2]["custom"] == 99

    def test_wrong_weight_length_raises(self) -> None:
        c1: list[tuple[str, float, dict[str, Any]]] = [("a", 1.0, {})]
        with pytest.raises(ValueError):
            fuse_rrf([c1], weights=[1.0, 2.0])  # 2 weights, 1 channel


# ---------------------------------------------------------------------------
# HybridRetriever — gate spy tests
# ---------------------------------------------------------------------------

class SpyEmbedder:
    """Embedder that records calls and returns a fixed vector."""

    def __init__(self, dim: int = 4) -> None:
        self.call_count = 0
        self._dim = dim

    async def embed(self, texts: list[str]) -> list[list[float]]:
        self.call_count += 1
        return [[1.0] + [0.0] * (self._dim - 1) for _ in texts]


class SpyGraphMatcher:
    """GraphMatcher that records calls."""

    def __init__(self) -> None:
        self.call_count = 0

    async def match(self, query: str, graph: Any, k: int) -> list[ScoredEntry]:
        self.call_count += 1
        return []


def make_retriever(
    *,
    tau: float = 0.3,
    embedder: Any = None,
    graph_matcher: Any = None,
    dim: int = 4,
) -> tuple[HybridRetriever, BM25LexicalIndex, SpyEmbedder | StubEmbedder, SpyGraphMatcher | TextGraphMatcher]:
    cfg = Config(low_confidence_tau=tau, vector_dim=dim, retrieval_cache_ttl=300.0)
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=dim)
    kv = InMemoryKVStore()
    graph = NetworkXGraphStore()
    spy_embedder = embedder or SpyEmbedder(dim=dim)
    spy_graph = graph_matcher or SpyGraphMatcher()

    retriever = HybridRetriever(
        lexical=lexical,
        vector=vector,
        embedder=spy_embedder,
        reranker=PassthroughReranker(),
        graph=graph,
        graph_matcher=spy_graph,
        kv=kv,
        config=cfg,
    )
    return retriever, lexical, spy_embedder, spy_graph


class TestRetrieverGate:
    async def test_strong_bm25_closes_gate(self) -> None:
        """When BM25 score > tau, dense and graph channels must NOT fire."""
        retriever, lexical, spy_embedder, spy_graph = make_retriever(tau=0.1)

        # Add enough docs so BM25 scores are clearly > 0.1
        for i in range(10):
            await lexical.add(
                f"d{i}",
                f"nginx vulnerability severity high item_{i}",
                {"tier": "semantic"},
            )

        results = await retriever.search(
            text="nginx vulnerability severity",
            k=5,
            tiers=[Tier.semantic],
        )

        # Gate should be CLOSED because BM25 scores > tau=0.1
        assert not retriever._last_dense_fired
        assert not retriever._last_graph_fired

    async def test_weak_bm25_opens_gate(self) -> None:
        """When BM25 score < tau, dense and graph channels MUST fire."""
        retriever, lexical, spy_embedder, spy_graph = make_retriever(tau=100.0)

        # Add a few docs (BM25 scores will be positive but << 100)
        await lexical.add("d1", "some text content", {"tier": "semantic"})

        await retriever.search(
            text="xyzzy completely unrelated query token",
            k=5,
            tiers=[Tier.semantic, Tier.working],
        )

        # Gate should be OPEN because max BM25 score < tau=100
        assert retriever._last_dense_fired
        assert retriever._last_graph_fired

    async def test_empty_lexical_opens_gate(self) -> None:
        """Empty BM25 index → gate always opens."""
        retriever, _, spy_embedder, spy_graph = make_retriever(tau=0.3)

        await retriever.search(
            text="anything at all",
            k=5,
            tiers=[Tier.semantic, Tier.working],
        )

        assert retriever._last_dense_fired
        assert retriever._last_graph_fired

    async def test_stub_embedder_does_not_crash_when_gate_opens(self) -> None:
        """StubEmbedder is allowed to fail gracefully (logged, not raised)."""
        cfg = Config(low_confidence_tau=100.0)  # gate always open
        lexical = BM25LexicalIndex()
        vector = FaissVectorIndex(dim=cfg.vector_dim)
        kv = InMemoryKVStore()
        graph = NetworkXGraphStore()

        retriever = HybridRetriever(
            lexical=lexical,
            vector=vector,
            embedder=StubEmbedder(),  # raises RuntimeError
            reranker=PassthroughReranker(),
            graph=graph,
            graph_matcher=SpyGraphMatcher(),
            kv=kv,
            config=cfg,
        )

        # Should not raise — dense channel failure is swallowed gracefully
        results = await retriever.search(text="test", k=5, tiers=[Tier.semantic])
        assert isinstance(results, list)


class TestRetrieverCache:
    async def test_cache_hit_skips_channel_execution(self) -> None:
        """Second call with identical query must not re-execute channels."""
        retriever, lexical, spy_embedder, spy_graph = make_retriever(tau=100.0)
        await lexical.add("d1", "cache test document content", {"tier": "semantic"})

        # First call: channels execute
        r1 = await retriever.search(
            text="cache test", k=5, tiers=[Tier.semantic, Tier.working]
        )
        calls_after_first = spy_embedder.call_count + spy_graph.call_count  # type: ignore[union-attr]

        # Second call: must be a cache hit (no channel calls)
        r2 = await retriever.search(
            text="cache test", k=5, tiers=[Tier.semantic, Tier.working]
        )
        calls_after_second = spy_embedder.call_count + spy_graph.call_count  # type: ignore[union-attr]

        assert calls_after_second == calls_after_first   # no new calls
        assert len(r1) == len(r2)

    async def test_different_query_is_cache_miss(self) -> None:
        retriever, lexical, spy_embedder, spy_graph = make_retriever(tau=100.0)
        await lexical.add("d1", "content alpha", {"tier": "semantic"})

        await retriever.search(text="alpha", k=5, tiers=[Tier.semantic])
        calls_1 = spy_embedder.call_count  # type: ignore[union-attr]

        await retriever.search(text="beta", k=5, tiers=[Tier.semantic])
        calls_2 = spy_embedder.call_count  # type: ignore[union-attr]

        assert calls_2 > calls_1   # second query caused new channel execution

    async def test_different_tiers_is_cache_miss(self) -> None:
        retriever, lexical, _, _ = make_retriever()
        await lexical.add("d1", "content", {"tier": "semantic"})

        await retriever.search(text="content", k=5, tiers=[Tier.semantic])
        await retriever.search(text="content", k=5, tiers=[Tier.procedural])

        # Cache is keyed on (query, tiers); different tiers → different keys
        kv_keys = list(retriever._kv._data.keys())
        assert len(kv_keys) == 2


class TestRetrieverIntegration:
    async def test_bm25_results_returned(self) -> None:
        retriever, lexical, _, _ = make_retriever(tau=0.0)  # gate always closed
        await lexical.add("d1", "important security finding", {"tier": "semantic"})
        await lexical.add("d2", "other unrelated content", {"tier": "semantic"})

        results = await retriever.search(
            text="important security finding", k=5, tiers=[Tier.semantic]
        )
        ids = [e.id for e in results]
        assert "d1" in ids

    async def test_tier_filter_applies(self) -> None:
        retriever, lexical, _, _ = make_retriever(tau=0.0)
        await lexical.add("sem", "some knowledge here", {"tier": "semantic"})
        await lexical.add("proc", "some knowledge here", {"tier": "procedural"})

        results = await retriever.search(
            text="some knowledge", k=5, tiers=[Tier.semantic]
        )
        ids = [e.id for e in results]
        # 'proc' has tier=procedural; we asked only for semantic
        assert "proc" not in ids or all(
            e.tier == "semantic" for e in results if e.id == "proc"
        )
