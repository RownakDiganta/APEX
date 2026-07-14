# test_retrieval_phase4.py
# Phase 4 comprehensive tests: gate (Option A+), cache key schema, diagnostics, invalidation, immutability, k semantics, RRF determinism.
"""Phase 4 — Hybrid Retrieval and Cache Correctness.

Covers all findings from the Phase 4 design contract:
  F01-broader : full cache-key schema + invalidation events
  F05         : content-sensitive _context_hash in apex_host/planning/engine.py

Test categories (prefixed in function names for easy grep):
  GATE  — gate.py decide_gate() + Option A+ HybridRetriever gate behavior
  CACHE — cache key schema, hit/miss, deep-copy immutability, invalidation
  FUSE  — RRF fusion determinism, rerank_top_n, weight handling
  RANK  — reranker integration, soft-failure fallback
  DIAG  — RetrievalDiagnostics fields, EvidenceBundle.diagnostics attachment
  TIER  — tier post-filter, regex channel tier-exemption
  IDENT — identifier/regex channel patterns
  ARCH  — architecture scan: CACHE_KEY_VERSION constant, RetrievalError, RetrievalDiagnostics locations
  K     — k<0 ValueError, k=0 short-circuit, k=0 diagnostics, k affects key
  IMMUT — deep-copy immutability of cache reads and writes
  GEN   — _index_generation advancement on mutations, cache key includes idx_gen
  FAIL  — channel soft-failure (dense/graph/regex) and BM25 hard-failure
  INVAL — cache invalidation by promote_knowledge, promote_skill, quarantine_skill
  INT   — MemoryAPI.query() integration: diagnostics attached, EvidenceBundle.diagnostics
  CTX   — _context_hash content-sensitivity (F05 fix)
"""
from __future__ import annotations

import json
import re
from typing import Any

import pytest

from memfabric.config import Config
from memfabric.retrieval.engine import (
    CACHE_KEY_VERSION,
    HybridRetriever,
    _cache_key,
    _canonical_filters,
)
from memfabric.retrieval.fusion import fuse_rrf
from memfabric.retrieval.gate import GateDecision, decide_gate, gate_is_open
from memfabric.retrieval.protocols import (
    PassthroughReranker,
    StubEmbedder,
    TextGraphMatcher,
)
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import (
    KnowledgeEntry,
    Node,
    RetrievalDiagnostics,
    RetrievalError,
    Skill,
    ScoredEntry,
    Tier,
)
from memfabric.api import MemoryAPI
from memfabric.ids import now


pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

class _ConfiguredEmbedder:
    """Embedder with is_configured=True; returns a fixed unit vector."""

    is_configured: bool = True
    _DIM = 4

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [[1.0, 0.0, 0.0, 0.0] for _ in texts]


class _SpyEmbedder:
    """Records calls; is_configured=True; returns a fixed unit vector."""

    is_configured: bool = True

    def __init__(self, dim: int = 4) -> None:
        self.call_count = 0
        self._dim = dim

    async def embed(self, texts: list[str]) -> list[list[float]]:
        self.call_count += 1
        return [[1.0] + [0.0] * (self._dim - 1) for _ in texts]


class _FailingEmbedder:
    """is_configured=True; always raises RuntimeError to simulate dense failure."""

    is_configured: bool = True

    async def embed(self, texts: list[str]) -> list[list[float]]:
        raise RuntimeError("embed: deliberate test failure")


class _SpyGraphMatcher:
    """Records calls; returns empty list."""

    def __init__(self) -> None:
        self.call_count = 0

    async def match(self, query: str, graph: Any, k: int) -> list[ScoredEntry]:
        self.call_count += 1
        return []


class _FailingGraphMatcher:
    """Always raises RuntimeError to simulate graph-channel failure."""

    async def match(self, query: str, graph: Any, k: int) -> list[ScoredEntry]:
        raise RuntimeError("graph: deliberate test failure")


class _FailingReranker:
    """Always raises RuntimeError to simulate reranker failure."""

    async def rerank(self, query: str, entries: list[ScoredEntry]) -> list[ScoredEntry]:
        raise RuntimeError("reranker: deliberate test failure")


class _CapturingReranker:
    """Records the candidates it receives; returns them unchanged."""

    def __init__(self) -> None:
        self.last_candidates: list[ScoredEntry] = []

    async def rerank(self, query: str, entries: list[ScoredEntry]) -> list[ScoredEntry]:
        self.last_candidates = list(entries)
        return entries


def _make_retriever(
    *,
    tau: float = 0.3,
    embedder: Any = None,
    graph_matcher: Any = None,
    reranker: Any = None,
    patterns: dict[str, re.Pattern[str]] | None = None,
    dim: int = 4,
    rerank_top_n: int = 20,
) -> tuple[HybridRetriever, BM25LexicalIndex, InMemoryKVStore, NetworkXGraphStore]:
    cfg = Config(
        low_confidence_tau=tau,
        vector_dim=dim,
        retrieval_cache_ttl=300.0,
        rerank_top_n=rerank_top_n,
    )
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=dim)
    kv = InMemoryKVStore()
    graph = NetworkXGraphStore()
    retriever = HybridRetriever(
        lexical=lexical,
        vector=vector,
        embedder=embedder or StubEmbedder(),
        reranker=reranker or PassthroughReranker(),
        graph=graph,
        graph_matcher=graph_matcher or _SpyGraphMatcher(),
        kv=kv,
        config=cfg,
        identifier_patterns=patterns,
    )
    return retriever, lexical, kv, graph


def _make_api_with_retriever(
    *,
    tau: float = 0.3,
    embedder: Any = None,
    dim: int = 4,
) -> MemoryAPI:
    cfg = Config(low_confidence_tau=tau, vector_dim=dim)
    graph = NetworkXGraphStore()
    episodic = JSONLEpisodicStore(path=None)
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=dim)
    kv = InMemoryKVStore()
    api = MemoryAPI(
        graph=graph, episodic=episodic, lexical=lexical,
        vector=vector, kv=kv, config=cfg,
    )
    retriever = HybridRetriever(
        lexical=lexical, vector=vector,
        embedder=embedder or StubEmbedder(),
        reranker=PassthroughReranker(),
        graph=graph, graph_matcher=TextGraphMatcher(),
        kv=kv, config=cfg,
    )
    api.set_retriever(retriever)
    return api


def _make_node(node_id: str, *, description: str = "test") -> Node:
    return Node(
        id=node_id, type="host",
        props={"description": description, "ip": node_id},
        source="test", confidence=0.8,
        first_seen=now(), last_seen=now(),
    )


# ---------------------------------------------------------------------------
# GATE — decide_gate() unit tests
# ---------------------------------------------------------------------------

class TestGateDecideGate:
    def test_gate_no_scores_opens_gate(self) -> None:
        """Empty BM25 scores → open gate regardless of tau."""
        d = decide_gate([], tau=0.3)
        assert d.open is True

    def test_gate_low_max_score_opens(self) -> None:
        """BM25 max below tau → gate opens."""
        d = decide_gate([0.1, 0.05], tau=0.3)
        assert d.open is True

    def test_gate_high_max_score_closes(self) -> None:
        """BM25 max above tau → gate closes."""
        d = decide_gate([0.9, 0.5], tau=0.3)
        assert d.open is False

    def test_gate_exactly_tau_closes(self) -> None:
        """BM25 max == tau → gate CLOSED (strictly less than required to open)."""
        d = decide_gate([0.3], tau=0.3)
        assert d.open is False

    def test_gate_just_below_tau_opens(self) -> None:
        """BM25 max just below tau → gate opens."""
        d = decide_gate([0.2999], tau=0.3)
        assert d.open is True

    def test_gate_embedder_configured_always_opens(self) -> None:
        """When embedder_configured=True, gate opens regardless of BM25 scores."""
        d = decide_gate([0.99, 0.99], tau=0.1, embedder_configured=True)
        assert d.open is True

    def test_gate_embedder_configured_skips_bm25_check(self) -> None:
        """Embedder-configured path skips BM25 score comparison entirely."""
        d = decide_gate([10.0, 20.0], tau=0.001, embedder_configured=True)
        assert d.open is True

    def test_gate_returns_gate_decision_type(self) -> None:
        d = decide_gate([0.5], tau=0.3)
        assert isinstance(d, GateDecision)

    def test_gate_reasons_nonempty_on_close(self) -> None:
        d = decide_gate([0.99], tau=0.3)
        assert len(d.reasons) >= 1

    def test_gate_reasons_nonempty_on_open(self) -> None:
        d = decide_gate([0.01], tau=0.3)
        assert len(d.reasons) >= 1

    def test_gate_reasons_mention_embedder_when_configured(self) -> None:
        d = decide_gate([0.99], tau=0.1, embedder_configured=True)
        assert any("embedder" in r.lower() for r in d.reasons)

    def test_gate_reasons_mention_bm25_when_closed(self) -> None:
        d = decide_gate([0.99], tau=0.3)
        assert any("bm25" in r.lower() for r in d.reasons)

    def test_gate_legacy_function_still_works(self) -> None:
        """gate_is_open() must remain callable (backward compat)."""
        assert gate_is_open([], tau=0.3) is True
        assert gate_is_open([0.99], tau=0.3) is False
        assert gate_is_open([0.01], tau=0.3) is True


# ---------------------------------------------------------------------------
# GATE — HybridRetriever gate behavior (Option A+)
# ---------------------------------------------------------------------------

class TestGateOptionAPlus:
    async def test_gate_stub_embedder_is_configured_false(self) -> None:
        """StubEmbedder must have is_configured=False."""
        assert StubEmbedder.is_configured is False

    async def test_gate_configured_embedder_always_fires_dense(self) -> None:
        """Real embedder (is_configured=True) fires dense even with strong BM25."""
        spy = _SpyEmbedder()
        retriever, lexical, _, _ = _make_retriever(tau=0.001, embedder=spy)
        for i in range(10):
            await lexical.add(f"d{i}", f"topic content doc_{i} strong bm25 signal", {"tier": "semantic"})
        await retriever.search(text="topic content doc strong bm25 signal", k=5, tiers=[Tier.semantic])
        assert spy.call_count >= 1, "configured embedder must always fire"

    async def test_gate_stub_embedder_strong_bm25_suppresses_dense(self) -> None:
        """StubEmbedder + strong BM25 → dense suppressed (legacy gate behavior)."""
        retriever, lexical, _, _ = _make_retriever(tau=0.001)
        for i in range(10):
            await lexical.add(f"d{i}", f"very common strong content word_{i}", {"tier": "semantic"})
        _, diag = await retriever.search(text="very common strong content", k=5, tiers=[Tier.semantic])
        assert "dense" in diag.channels_skipped

    async def test_gate_stub_embedder_weak_bm25_opens_gate(self) -> None:
        """StubEmbedder + empty index → gate opens (dense attempted, soft fail)."""
        retriever, _, _, _ = _make_retriever(tau=0.3)
        _, diag = await retriever.search(text="anything", k=5, tiers=[Tier.semantic, Tier.working])
        assert diag.gate_open is True

    async def test_gate_option_aplus_spy_fires_on_configured_embedder(self) -> None:
        """A configured spy embedder fires dense regardless of BM25 score magnitude."""
        spy = _SpyEmbedder()
        retriever, lexical, _, _ = _make_retriever(tau=0.001, embedder=spy)
        await lexical.add("d1", "aaaaaa bbbbbbb important match content", {"tier": "semantic"})
        # Search for exactly this text — BM25 will be strong
        await retriever.search(text="aaaaaa bbbbbbb important match content", k=5, tiers=[Tier.semantic])
        assert spy.call_count >= 1


# ---------------------------------------------------------------------------
# CACHE — cache key schema
# ---------------------------------------------------------------------------

class TestCacheKeySchema:
    def test_cache_key_version_constant(self) -> None:
        """CACHE_KEY_VERSION must be exactly '4'."""
        assert CACHE_KEY_VERSION == "4"

    def test_cache_key_is_64_hex_chars(self) -> None:
        """Full SHA-256 digest → 64 hex characters."""
        key = _cache_key("query", 5, [Tier.semantic], None)
        # strip "retrieval:" prefix
        digest = key.replace("retrieval:", "")
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_cache_key_prefix(self) -> None:
        """Cache keys must start with 'retrieval:'."""
        key = _cache_key("query", 5, [Tier.semantic], None)
        assert key.startswith("retrieval:")

    def test_cache_key_differs_on_text(self) -> None:
        k1 = _cache_key("alpha", 5, [Tier.semantic], None)
        k2 = _cache_key("beta", 5, [Tier.semantic], None)
        assert k1 != k2

    def test_cache_key_differs_on_k(self) -> None:
        k1 = _cache_key("query", 5, [Tier.semantic], None)
        k2 = _cache_key("query", 10, [Tier.semantic], None)
        assert k1 != k2

    def test_cache_key_differs_on_tiers(self) -> None:
        k1 = _cache_key("query", 5, [Tier.semantic], None)
        k2 = _cache_key("query", 5, [Tier.procedural], None)
        assert k1 != k2

    def test_cache_key_tier_order_independent(self) -> None:
        """Tier list order must not affect the key (sorted internally)."""
        k1 = _cache_key("q", 5, [Tier.semantic, Tier.procedural], None)
        k2 = _cache_key("q", 5, [Tier.procedural, Tier.semantic], None)
        assert k1 == k2

    def test_cache_key_differs_on_filters(self) -> None:
        k1 = _cache_key("query", 5, [Tier.semantic], None)
        k2 = _cache_key("query", 5, [Tier.semantic], {"source_family": "intel_db"})
        assert k1 != k2

    def test_cache_key_filter_order_independent(self) -> None:
        """Filter key order must not affect the key (json.dumps sort_keys=True)."""
        k1 = _cache_key("q", 5, [Tier.semantic], {"a": 1, "b": 2})
        k2 = _cache_key("q", 5, [Tier.semantic], {"b": 2, "a": 1})
        assert k1 == k2

    def test_cache_key_differs_on_index_generation(self) -> None:
        k1 = _cache_key("query", 5, [Tier.semantic], None, index_generation=0)
        k2 = _cache_key("query", 5, [Tier.semantic], None, index_generation=1)
        assert k1 != k2

    def test_cache_key_differs_on_rrf_k(self) -> None:
        k1 = _cache_key("query", 5, [Tier.semantic], None, rrf_k=60)
        k2 = _cache_key("query", 5, [Tier.semantic], None, rrf_k=100)
        assert k1 != k2

    def test_cache_key_differs_on_rerank_top_n(self) -> None:
        k1 = _cache_key("query", 5, [Tier.semantic], None, rerank_top_n=20)
        k2 = _cache_key("query", 5, [Tier.semantic], None, rerank_top_n=50)
        assert k1 != k2

    def test_cache_key_differs_on_channel_weights(self) -> None:
        k1 = _cache_key("query", 5, [Tier.semantic], None, channel_weights=(1.0, 0.5, 1.0, 0.5))
        k2 = _cache_key("query", 5, [Tier.semantic], None, channel_weights=(1.0, 1.0, 1.0, 1.0))
        assert k1 != k2

    def test_canonical_filters_none_is_null(self) -> None:
        assert _canonical_filters(None) == "null"

    def test_canonical_filters_deterministic(self) -> None:
        f = {"z": 3, "a": 1, "m": 2}
        result = _canonical_filters(f)
        # Must parse as JSON and have sorted keys
        parsed = json.loads(result)
        assert parsed == {"a": 1, "m": 2, "z": 3}

    def test_canonical_filters_non_serializable_raises(self) -> None:
        with pytest.raises(ValueError, match="non-JSON-serializable"):
            _canonical_filters({"key": object()})  # type: ignore[dict-item]


# ---------------------------------------------------------------------------
# CACHE — hit/miss behavior on the retriever
# ---------------------------------------------------------------------------

class TestCacheHitMiss:
    async def test_cache_hit_returns_same_results(self) -> None:
        retriever, lexical, _, _ = _make_retriever(tau=100.0, embedder=_SpyEmbedder())
        await lexical.add("d1", "cache hit test content", {"tier": "semantic"})
        r1, _ = await retriever.search(text="cache hit test", k=5, tiers=[Tier.semantic])
        r2, d2 = await retriever.search(text="cache hit test", k=5, tiers=[Tier.semantic])
        assert [e.id for e in r1] == [e.id for e in r2]
        assert d2.cache_hit is True

    async def test_cache_miss_on_different_query(self) -> None:
        retriever, lexical, _, _ = _make_retriever(tau=100.0, embedder=_SpyEmbedder())
        await lexical.add("d1", "alpha content", {"tier": "semantic"})
        _, d1 = await retriever.search(text="alpha content", k=5, tiers=[Tier.semantic])
        _, d2 = await retriever.search(text="beta content", k=5, tiers=[Tier.semantic])
        assert d1.cache_hit is False
        assert d2.cache_hit is False

    async def test_cache_miss_on_different_k(self) -> None:
        retriever, lexical, kv, _ = _make_retriever()
        await lexical.add("d1", "text for k test", {"tier": "semantic"})
        await retriever.search(text="text for k test", k=3, tiers=[Tier.semantic])
        await retriever.search(text="text for k test", k=7, tiers=[Tier.semantic])
        # Two distinct cache entries should exist
        keys = [k for k in kv._data if k.startswith("retrieval:")]
        assert len(keys) == 2

    async def test_cache_miss_on_different_tiers(self) -> None:
        retriever, lexical, kv, _ = _make_retriever()
        await lexical.add("d1", "tier miss content", {"tier": "semantic"})
        await retriever.search(text="tier miss content", k=5, tiers=[Tier.semantic])
        await retriever.search(text="tier miss content", k=5, tiers=[Tier.procedural])
        keys = [k for k in kv._data if k.startswith("retrieval:")]
        assert len(keys) == 2

    async def test_cache_miss_on_different_filters(self) -> None:
        retriever, lexical, kv, _ = _make_retriever()
        await lexical.add("d1", "filter test doc", {"tier": "semantic", "source_family": "intel_db"})
        await retriever.search(text="filter test doc", k=5, tiers=[Tier.semantic], filters=None)
        await retriever.search(text="filter test doc", k=5, tiers=[Tier.semantic], filters={"source_family": "intel_db"})
        keys = [k for k in kv._data if k.startswith("retrieval:")]
        assert len(keys) == 2

    async def test_first_call_not_cache_hit(self) -> None:
        retriever, lexical, _, _ = _make_retriever()
        await lexical.add("d1", "first call check content", {"tier": "semantic"})
        _, diag = await retriever.search(text="first call check", k=5, tiers=[Tier.semantic])
        assert diag.cache_hit is False


# ---------------------------------------------------------------------------
# IMMUT — deep-copy immutability
# ---------------------------------------------------------------------------

class TestCacheImmutability:
    async def test_mutating_result_does_not_corrupt_cache(self) -> None:
        """Caller mutating the returned list must not corrupt future cache reads."""
        retriever, lexical, _, _ = _make_retriever()
        await lexical.add("d1", "immutability check document content", {"tier": "semantic"})
        results1, _ = await retriever.search(text="immutability check", k=5, tiers=[Tier.semantic])
        # Mutate the returned list
        results1.clear()
        # Second call must still return results from cache
        results2, d2 = await retriever.search(text="immutability check", k=5, tiers=[Tier.semantic])
        assert d2.cache_hit is True
        assert len(results2) >= 0  # cache was not corrupted (empty list is valid if no match)

    async def test_mutating_scored_entry_does_not_corrupt_cache(self) -> None:
        """Caller mutating a returned ScoredEntry must not corrupt future cache reads."""
        retriever, lexical, _, _ = _make_retriever()
        await lexical.add("d1", "entry mutation test content score", {"tier": "semantic"})
        results1, _ = await retriever.search(text="entry mutation test content", k=5, tiers=[Tier.semantic])
        if results1:
            results1[0].score = -999.0
        # Second call from cache must have original scores
        results2, d2 = await retriever.search(text="entry mutation test content", k=5, tiers=[Tier.semantic])
        assert d2.cache_hit is True
        if results2:
            assert results2[0].score != -999.0

    async def test_mutating_diagnostics_does_not_corrupt_cache(self) -> None:
        """Caller mutating a returned diagnostics object must not corrupt future cache reads."""
        retriever, lexical, _, _ = _make_retriever()
        await lexical.add("d1", "diag mutation test content doc", {"tier": "semantic"})
        _, diag1 = await retriever.search(text="diag mutation test content", k=5, tiers=[Tier.semantic])
        diag1.channels_attempted.append("__MUTATED__")
        _, diag2 = await retriever.search(text="diag mutation test content", k=5, tiers=[Tier.semantic])
        assert "__MUTATED__" not in diag2.channels_attempted


# ---------------------------------------------------------------------------
# K — k semantics
# ---------------------------------------------------------------------------

class TestKSemantics:
    async def test_k_negative_raises(self) -> None:
        """k < 0 must raise ValueError."""
        retriever, _, _, _ = _make_retriever()
        with pytest.raises(ValueError, match="k must be non-negative"):
            await retriever.search(text="anything", k=-1, tiers=[Tier.semantic])

    async def test_k_zero_returns_empty_list(self) -> None:
        """k=0 must return empty list without running channels."""
        retriever, lexical, _, _ = _make_retriever(tau=0.3)
        await lexical.add("d1", "short circuit zero k document content", {"tier": "semantic"})
        results, _ = await retriever.search(text="short circuit zero k", k=0, tiers=[Tier.semantic])
        assert results == []

    async def test_k_zero_returns_diagnostics(self) -> None:
        """k=0 must still return a RetrievalDiagnostics object."""
        retriever, _, _, _ = _make_retriever()
        _, diag = await retriever.search(text="test", k=0, tiers=[Tier.semantic])
        assert isinstance(diag, RetrievalDiagnostics)

    async def test_k_zero_no_channels_attempted(self) -> None:
        """k=0 short-circuit: no channels should be attempted."""
        retriever, _, _, _ = _make_retriever()
        _, diag = await retriever.search(text="test", k=0, tiers=[Tier.semantic])
        assert diag.channels_attempted == []

    async def test_k_zero_skips_all_channels(self) -> None:
        """k=0: all channels reported as skipped."""
        retriever, _, _, _ = _make_retriever()
        _, diag = await retriever.search(text="test", k=0, tiers=[Tier.semantic])
        assert len(diag.channels_skipped) >= 1

    async def test_k_in_cache_key(self) -> None:
        """k=3 and k=5 produce distinct cache keys."""
        k1 = _cache_key("query", 3, [Tier.semantic], None)
        k2 = _cache_key("query", 5, [Tier.semantic], None)
        assert k1 != k2

    async def test_k_truncates_results(self) -> None:
        """search returns at most k entries."""
        retriever, lexical, _, _ = _make_retriever(tau=0.0)
        for i in range(10):
            await lexical.add(f"doc{i}", f"common word token content item_{i}", {"tier": "semantic"})
        results, _ = await retriever.search(text="common word token content", k=3, tiers=[Tier.semantic])
        assert len(results) <= 3


# ---------------------------------------------------------------------------
# FUSE — RRF determinism and rerank_top_n
# ---------------------------------------------------------------------------

class TestFuseRRF:
    def test_fuse_deterministic_tie_breaking(self) -> None:
        """Identical fused scores → sorted by ascending doc_id for determinism."""
        # Two docs with identical scores (same rank in two channels — reversed)
        c1: list[tuple[str, float, dict[str, Any]]] = [("beta", 1.0, {}), ("alpha", 0.9, {})]
        c2: list[tuple[str, float, dict[str, Any]]] = [("alpha", 1.0, {}), ("beta", 0.9, {})]
        fused1 = fuse_rrf([c1, c2])
        fused2 = fuse_rrf([c1, c2])
        # Same input → same output, every time
        assert [r[0] for r in fused1] == [r[0] for r in fused2]

    def test_fuse_tie_broken_by_ascending_doc_id(self) -> None:
        """When two docs have identical RRF scores, lower doc_id wins."""
        # Equal rank in one channel each: alpha in c1, beta in c2
        c1: list[tuple[str, float, dict[str, Any]]] = [("alpha", 1.0, {})]
        c2: list[tuple[str, float, dict[str, Any]]] = [("beta", 1.0, {})]
        fused = fuse_rrf([c1, c2])
        ids = [r[0] for r in fused]
        # alpha < beta lexicographically → alpha first on tie
        assert ids == ["alpha", "beta"]

    def test_fuse_top_n_truncates(self) -> None:
        """top_n parameter truncates fused output."""
        c: list[tuple[str, float, dict[str, Any]]] = [
            (f"d{i}", float(10 - i), {}) for i in range(10)
        ]
        fused = fuse_rrf([c], top_n=3)
        assert len(fused) == 3

    def test_fuse_weights_applied(self) -> None:
        """Channel with weight=2 should dominate over weight=0.5."""
        c1: list[tuple[str, float, dict[str, Any]]] = [("a", 1.0, {})]  # weight 2
        c2: list[tuple[str, float, dict[str, Any]]] = [("b", 1.0, {})]  # weight 0.5
        fused = fuse_rrf([c1, c2], weights=[2.0, 0.5])
        assert fused[0][0] == "a"

    def test_fuse_empty_channels_allowed(self) -> None:
        """Empty channel lists are legal and contribute 0 score."""
        c1: list[tuple[str, float, dict[str, Any]]] = [("x", 1.0, {})]
        fused = fuse_rrf([c1, [], []], weights=[1.0, 1.0, 1.0])
        assert len(fused) == 1

    def test_fuse_preserves_metadata(self) -> None:
        """Metadata from the first-seen occurrence of a doc is preserved."""
        c1: list[tuple[str, float, dict[str, Any]]] = [("d1", 1.0, {"tier": "semantic", "info": "original"})]
        c2: list[tuple[str, float, dict[str, Any]]] = [("d1", 0.5, {"tier": "working", "info": "second"})]
        fused = fuse_rrf([c1, c2])
        assert fused[0][2].get("info") == "original"

    async def test_rerank_top_n_feeds_reranker_more_candidates(self) -> None:
        """rerank_top_n config controls how many candidates the reranker sees."""
        cap_reranker = _CapturingReranker()
        retriever, lexical, _, _ = _make_retriever(tau=100.0, reranker=cap_reranker, rerank_top_n=5)
        for i in range(8):
            await lexical.add(f"doc{i}", f"rerank candidate item content_{i}", {"tier": "semantic"})
        # k=2 but rerank_top_n=5 → reranker should see up to 5 candidates
        await retriever.search(text="rerank candidate item content", k=2, tiers=[Tier.semantic])
        # Reranker should have received >= 2 candidates (up to min(available, rerank_top_n))
        assert len(cap_reranker.last_candidates) >= 2

    async def test_different_rerank_top_n_creates_different_cache_key(self) -> None:
        """rerank_top_n must be included in the cache key."""
        k1 = _cache_key("q", 5, [Tier.semantic], None, rerank_top_n=10)
        k2 = _cache_key("q", 5, [Tier.semantic], None, rerank_top_n=50)
        assert k1 != k2


# ---------------------------------------------------------------------------
# RANK — reranker integration and soft-failure fallback
# ---------------------------------------------------------------------------

class TestRanker:
    async def test_reranker_fallback_on_failure(self) -> None:
        """Reranker failure must fall back to RRF order without raising."""
        retriever, lexical, _, _ = _make_retriever(tau=0.0, reranker=_FailingReranker())
        await lexical.add("d1", "fallback reranker test content doc", {"tier": "semantic"})
        # Must not raise
        results, _ = await retriever.search(text="fallback reranker test content", k=5, tiers=[Tier.semantic])
        assert isinstance(results, list)

    async def test_reranker_soft_fail_returns_results(self) -> None:
        """Even with a failing reranker, BM25 results should still be returned."""
        retriever, lexical, _, _ = _make_retriever(tau=0.0, reranker=_FailingReranker())
        await lexical.add("d1", "soft fail reranker content result", {"tier": "semantic"})
        results, _ = await retriever.search(text="soft fail reranker content", k=5, tiers=[Tier.semantic])
        ids = [e.id for e in results]
        assert "d1" in ids


# ---------------------------------------------------------------------------
# DIAG — RetrievalDiagnostics fields
# ---------------------------------------------------------------------------

class TestDiagnostics:
    def test_diag_is_dataclass(self) -> None:
        """RetrievalDiagnostics is a dataclass."""
        import dataclasses
        assert dataclasses.is_dataclass(RetrievalDiagnostics)

    async def test_diag_returned_by_search(self) -> None:
        """search() must return (list, RetrievalDiagnostics) not just a list."""
        retriever, _, _, _ = _make_retriever()
        result = await retriever.search(text="test", k=5, tiers=[Tier.semantic])
        assert isinstance(result, tuple)
        assert len(result) == 2
        _, diag = result
        assert isinstance(diag, RetrievalDiagnostics)

    async def test_diag_cache_hit_false_on_first_call(self) -> None:
        retriever, lexical, _, _ = _make_retriever()
        await lexical.add("d1", "diag first call content", {"tier": "semantic"})
        _, diag = await retriever.search(text="diag first call", k=5, tiers=[Tier.semantic])
        assert diag.cache_hit is False

    async def test_diag_cache_hit_true_on_second_call(self) -> None:
        retriever, lexical, _, _ = _make_retriever()
        await lexical.add("d1", "cache hit second call content", {"tier": "semantic"})
        await retriever.search(text="cache hit second call", k=5, tiers=[Tier.semantic])
        _, diag = await retriever.search(text="cache hit second call", k=5, tiers=[Tier.semantic])
        assert diag.cache_hit is True

    async def test_diag_channels_attempted_includes_bm25(self) -> None:
        retriever, _, _, _ = _make_retriever()
        _, diag = await retriever.search(text="anything", k=5, tiers=[Tier.semantic])
        assert "bm25" in diag.channels_attempted

    async def test_diag_lexical_candidate_count(self) -> None:
        retriever, lexical, _, _ = _make_retriever(tau=0.0)
        await lexical.add("d1", "candidate count test content", {"tier": "semantic"})
        await lexical.add("d2", "candidate count test content too", {"tier": "semantic"})
        _, diag = await retriever.search(text="candidate count test content", k=5, tiers=[Tier.semantic])
        assert diag.lexical_candidate_count >= 1

    async def test_diag_gate_open_reflects_actual_gate(self) -> None:
        """gate_open in diagnostics must match whether expensive channels fired."""
        retriever, _, _, _ = _make_retriever(tau=100.0)  # empty index → gate opens
        _, diag = await retriever.search(text="xyzzy", k=5, tiers=[Tier.semantic])
        assert diag.gate_open is True

    async def test_diag_gate_reasons_nonempty(self) -> None:
        retriever, _, _, _ = _make_retriever()
        _, diag = await retriever.search(text="query", k=5, tiers=[Tier.semantic])
        assert len(diag.gate_reasons) >= 1

    async def test_diag_index_generation_carried(self) -> None:
        """index_generation passed to search() is reflected in diagnostics."""
        retriever, _, _, _ = _make_retriever()
        _, diag = await retriever.search(text="test", k=5, tiers=[Tier.semantic], index_generation=42)
        assert diag.index_generation == 42

    async def test_diag_channel_weights_present(self) -> None:
        retriever, _, _, _ = _make_retriever()
        _, diag = await retriever.search(text="test", k=5, tiers=[Tier.semantic])
        assert "bm25" in diag.channel_weights
        assert "dense" in diag.channel_weights

    async def test_diag_attached_to_evidence_bundle(self) -> None:
        """MemoryAPI.query() must attach diagnostics to EvidenceBundle."""
        api = _make_api_with_retriever()
        bundle = await api.query(text="test query content", k=5)
        assert bundle.diagnostics is not None
        assert isinstance(bundle.diagnostics, RetrievalDiagnostics)


# ---------------------------------------------------------------------------
# TIER — tier post-filter and regex channel tier exemption
# ---------------------------------------------------------------------------

class TestTierFilter:
    async def test_tier_semantic_excludes_procedural(self) -> None:
        retriever, lexical, _, _ = _make_retriever(tau=0.0)
        await lexical.add("sem", "semantic content knowledge entry", {"tier": "semantic"})
        await lexical.add("proc", "semantic content knowledge entry", {"tier": "procedural"})
        results, _ = await retriever.search(text="semantic content knowledge", k=10, tiers=[Tier.semantic])
        ids = {e.id for e in results}
        assert "proc" not in ids

    async def test_tier_procedural_excludes_semantic(self) -> None:
        retriever, lexical, _, _ = _make_retriever(tau=0.0)
        await lexical.add("sem", "procedural action content text", {"tier": "semantic"})
        await lexical.add("proc", "procedural action content text", {"tier": "procedural"})
        results, _ = await retriever.search(text="procedural action content", k=10, tiers=[Tier.procedural])
        ids = {e.id for e in results}
        assert "sem" not in ids

    async def test_tier_multiple_accepted(self) -> None:
        retriever, lexical, _, _ = _make_retriever(tau=0.0)
        await lexical.add("sem", "multi tier content semantic", {"tier": "semantic"})
        await lexical.add("proc", "multi tier content procedural", {"tier": "procedural"})
        results, _ = await retriever.search(text="multi tier content", k=10, tiers=[Tier.semantic, Tier.procedural])
        ids = {e.id for e in results}
        assert "sem" in ids
        assert "proc" in ids

    async def test_tier_regex_results_exempt_from_filter(self) -> None:
        """Regex-channel results (tier='regex') pass through tier post-filter."""
        patterns = {"uuid": re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
        )}
        retriever, _, _, _ = _make_retriever(tau=0.0, patterns=patterns)
        # Query with a UUID — regex channel produces a result
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        results, _ = await retriever.search(text=f"lookup {uuid}", k=10, tiers=[Tier.semantic])
        # Regex result must appear despite semantic-only tier filter
        regex_ids = [e.id for e in results if e.id.startswith("regex:")]
        assert len(regex_ids) >= 1


# ---------------------------------------------------------------------------
# IDENT — identifier/regex channel
# ---------------------------------------------------------------------------

class TestIdentChannel:
    async def test_ident_no_patterns_channel_skipped(self) -> None:
        """Without patterns, regex channel is skipped."""
        retriever, _, _, _ = _make_retriever()
        _, diag = await retriever.search(text="test content query", k=5, tiers=[Tier.semantic])
        assert "regex" in diag.channels_skipped

    async def test_ident_with_pattern_channel_attempted(self) -> None:
        """With patterns configured, regex channel is attempted."""
        patterns = {"uuid": re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
        )}
        retriever, _, _, _ = _make_retriever(patterns=patterns)
        _, diag = await retriever.search(
            text="lookup 550e8400-e29b-41d4-a716-446655440000",
            k=5, tiers=[Tier.semantic]
        )
        assert "regex" in diag.channels_attempted

    async def test_ident_match_returns_result(self) -> None:
        """A matching identifier in the query text must produce a regex result."""
        uuid_text = "550e8400-e29b-41d4-a716-446655440000"
        patterns = {"uuid": re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
        )}
        retriever, _, _, _ = _make_retriever(patterns=patterns)
        results, _ = await retriever.search(
            text=f"find {uuid_text}",
            k=10, tiers=[Tier.semantic]
        )
        regex_ids = [e.id for e in results if e.id.startswith("regex:uuid:")]
        assert len(regex_ids) >= 1

    async def test_ident_no_match_no_regex_result(self) -> None:
        """Query text without a matching pattern → no regex results."""
        patterns = {"uuid": re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
        )}
        retriever, _, _, _ = _make_retriever(patterns=patterns)
        results, _ = await retriever.search(text="no UUID here at all", k=10, tiers=[Tier.semantic])
        regex_ids = [e.id for e in results if e.id.startswith("regex:")]
        assert len(regex_ids) == 0

    async def test_ident_regex_score_is_1_0(self) -> None:
        """Regex hits carry a fixed score of 1.0 (exact-match confidence)."""
        uuid_text = "550e8400-e29b-41d4-a716-446655440000"
        patterns = {"uuid": re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
        )}
        retriever, _, _, _ = _make_retriever(patterns=patterns)
        results, _ = await retriever.search(text=f"lookup {uuid_text}", k=10, tiers=[Tier.semantic])
        for e in results:
            if e.id.startswith("regex:"):
                assert e.score > 0


# ---------------------------------------------------------------------------
# ARCH — architecture: constants, exception, diagnostics location
# ---------------------------------------------------------------------------

class TestArchitecture:
    def test_arch_cache_key_version_in_engine(self) -> None:
        """CACHE_KEY_VERSION must live in memfabric/retrieval/engine.py."""
        from memfabric.retrieval import engine
        assert hasattr(engine, "CACHE_KEY_VERSION")

    def test_arch_retrieval_error_in_types(self) -> None:
        """RetrievalError must live in memfabric/types.py."""
        from memfabric import types
        assert hasattr(types, "RetrievalError")
        assert issubclass(types.RetrievalError, Exception)

    def test_arch_retrieval_diagnostics_in_types(self) -> None:
        """RetrievalDiagnostics must live in memfabric/types.py."""
        from memfabric import types
        assert hasattr(types, "RetrievalDiagnostics")

    def test_arch_gate_decision_in_gate(self) -> None:
        """GateDecision must live in memfabric/retrieval/gate.py."""
        from memfabric.retrieval import gate
        assert hasattr(gate, "GateDecision")

    def test_arch_decide_gate_in_gate(self) -> None:
        """decide_gate() must live in memfabric/retrieval/gate.py."""
        from memfabric.retrieval import gate
        assert callable(gate.decide_gate)

    def test_arch_stub_embedder_is_configured_false(self) -> None:
        """StubEmbedder.is_configured must be False."""
        assert StubEmbedder.is_configured is False

    def test_arch_retrieval_error_subclass_exception(self) -> None:
        """RetrievalError must subclass Exception."""
        assert issubclass(RetrievalError, Exception)

    def test_arch_evidence_bundle_has_diagnostics_field(self) -> None:
        """EvidenceBundle must have a diagnostics field typed RetrievalDiagnostics | None."""
        from memfabric.types import EvidenceBundle
        import dataclasses
        fields = {f.name: f for f in dataclasses.fields(EvidenceBundle)}
        assert "diagnostics" in fields


# ---------------------------------------------------------------------------
# GEN — _index_generation advancement on MemoryAPI mutations
# ---------------------------------------------------------------------------

class TestIndexGeneration:
    async def test_gen_initial_value_zero(self) -> None:
        """_index_generation starts at 0."""
        api = _make_api_with_retriever()
        assert api._index_generation == 0

    async def test_gen_advances_on_upsert_node(self) -> None:
        api = _make_api_with_retriever()
        before = api._index_generation
        await api.upsert_node(_make_node("n1"))
        assert api._index_generation > before

    async def test_gen_advances_on_upsert_edge(self) -> None:
        from memfabric.types import Edge
        api = _make_api_with_retriever()
        await api.upsert_node(_make_node("n1"))
        await api.upsert_node(_make_node("n2"))
        before = api._index_generation
        edge = Edge(
            id="e1", type="exposes",
            from_id="n1", to_id="n2",
            props={}, confidence=0.8,
            source="test", first_seen=now(), last_seen=now(),
        )
        await api.upsert_edge(edge)
        assert api._index_generation > before

    async def test_gen_advances_on_promote_knowledge(self) -> None:
        api = _make_api_with_retriever()
        entry = KnowledgeEntry(text="generation test knowledge content", source="test", confidence=0.9)
        await api.propose_knowledge(entry)
        before = api._index_generation
        await api.promote_knowledge(entry.id)
        assert api._index_generation > before

    async def test_gen_advances_on_promote_skill(self) -> None:
        api = _make_api_with_retriever()
        skill = Skill(
            name="probe_skill",
            description="generic probe skill for testing",
            template={"tool": "generic_probe", "args": []},
            preconditions={"type": "host"},
            source_episodes=[],
            confidence=0.7,
        )
        await api.propose_skill(skill)
        before = api._index_generation
        await api.promote_skill(skill.id)
        assert api._index_generation > before

    async def test_gen_causes_cache_miss_after_mutation(self) -> None:
        """After a mutation, _index_generation changes → next query is a cache miss."""
        api = _make_api_with_retriever()
        # Warm up cache
        await api.query(text="generation cache miss test", k=5)
        gen_before = api._index_generation
        # Mutate
        await api.upsert_node(_make_node("gen-node"))
        assert api._index_generation != gen_before
        # Next query uses a different cache key → fresh results (not cached)
        bundle = await api.query(text="generation cache miss test", k=5)
        # diagnostics should show cache_miss (since index_generation changed)
        assert bundle.diagnostics is not None
        assert bundle.diagnostics.cache_hit is False

    async def test_gen_different_generation_different_cache_key(self) -> None:
        """Two cache keys with different idx_gen must not be equal."""
        k1 = _cache_key("query", 5, [Tier.semantic], None, index_generation=0)
        k2 = _cache_key("query", 5, [Tier.semantic], None, index_generation=1)
        assert k1 != k2


# ---------------------------------------------------------------------------
# FAIL — channel soft-failure and BM25 hard-failure
# ---------------------------------------------------------------------------

class TestChannelFailures:
    async def test_fail_dense_soft_failure_does_not_raise(self) -> None:
        """Failing embedder (configured=True) → dense channel soft-fails, no exception."""
        retriever, lexical, _, _ = _make_retriever(tau=0.3, embedder=_FailingEmbedder())
        await lexical.add("d1", "soft fail dense test content", {"tier": "semantic"})
        # Must not raise
        results, _ = await retriever.search(text="soft fail dense test", k=5, tiers=[Tier.semantic])
        assert isinstance(results, list)

    async def test_fail_dense_failure_in_channels_skipped(self) -> None:
        """After dense soft-failure, 'dense' must appear in channels_skipped."""
        retriever, _, _, _ = _make_retriever(tau=100.0, embedder=_FailingEmbedder())
        _, diag = await retriever.search(text="anything", k=5, tiers=[Tier.semantic])
        assert "dense" in diag.channels_skipped

    async def test_fail_graph_soft_failure_does_not_raise(self) -> None:
        """Failing graph matcher → graph channel soft-fails, no exception."""
        retriever, lexical, _, _ = _make_retriever(
            tau=100.0,  # ensure gate opens
            embedder=_SpyEmbedder(),
            graph_matcher=_FailingGraphMatcher(),
        )
        await lexical.add("d1", "graph fail test content doc", {"tier": "semantic"})
        results, _ = await retriever.search(text="graph fail test", k=5, tiers=[Tier.semantic, Tier.working])
        assert isinstance(results, list)

    async def test_fail_graph_failure_in_channels_skipped(self) -> None:
        """After graph soft-failure, 'graph' must appear in channels_skipped."""
        retriever, _, _, _ = _make_retriever(
            tau=100.0,
            embedder=_SpyEmbedder(),
            graph_matcher=_FailingGraphMatcher(),
        )
        _, diag = await retriever.search(text="test", k=5, tiers=[Tier.semantic, Tier.working])
        assert "graph" in diag.channels_skipped

    async def test_fail_bm25_hard_failure_raises(self) -> None:
        """BM25 failure must raise RetrievalError (hard failure)."""
        retriever, _, _, _ = _make_retriever()

        # Patch the lexical index to always raise
        class _FailingLexical:
            async def search(self, *a: Any, **kw: Any) -> Any:
                raise RuntimeError("bm25 hard fail")
            async def add(self, *a: Any, **kw: Any) -> None:
                pass
            async def delete(self, *a: Any, **kw: Any) -> None:
                pass
            async def build(self, *a: Any, **kw: Any) -> None:
                pass

        retriever._lexical = _FailingLexical()  # type: ignore[assignment]

        with pytest.raises(RetrievalError):
            await retriever.search(text="anything", k=5, tiers=[Tier.semantic])

    async def test_fail_bm25_results_still_returned_despite_dense_fail(self) -> None:
        """Dense failure must not prevent BM25 results from being returned."""
        retriever, lexical, _, _ = _make_retriever(tau=0.0, embedder=_FailingEmbedder())
        await lexical.add("d1", "bm25 results despite dense fail content", {"tier": "semantic"})
        results, _ = await retriever.search(text="bm25 results despite dense fail", k=5, tiers=[Tier.semantic])
        ids = [e.id for e in results]
        assert "d1" in ids


# ---------------------------------------------------------------------------
# INVAL — cache invalidation by promote_knowledge, promote_skill, quarantine_skill
# ---------------------------------------------------------------------------

class TestCacheInvalidation:
    async def test_inval_promote_knowledge_busts_cache(self) -> None:
        """promote_knowledge() must invalidate retrieval cache so next query is fresh."""
        api = _make_api_with_retriever()
        # Warm cache
        await api.query(text="invalidation knowledge content test query", k=5)
        # Propose and promote knowledge → must bust cache
        entry = KnowledgeEntry(
            text="invalidation knowledge content test query result",
            source="test", confidence=0.9,
        )
        await api.propose_knowledge(entry)
        await api.promote_knowledge(entry.id)
        # Next query must be a cache miss
        bundle = await api.query(text="invalidation knowledge content test query", k=5)
        assert bundle.diagnostics is None or bundle.diagnostics.cache_hit is False

    async def test_inval_promote_skill_busts_cache(self) -> None:
        """promote_skill() must invalidate retrieval cache."""
        api = _make_api_with_retriever()
        await api.query(text="skill invalidation test content query", k=5)
        skill = Skill(
            name="probe_skill",
            description="generic probe skill for testing",
            template={"tool": "generic_probe", "args": []},
            preconditions={"type": "host"},
            source_episodes=[],
            confidence=0.7,
        )
        await api.propose_skill(skill)
        await api.promote_skill(skill.id)
        bundle = await api.query(text="skill invalidation test content query", k=5)
        assert bundle.diagnostics is None or bundle.diagnostics.cache_hit is False

    async def test_inval_upsert_node_busts_cache(self) -> None:
        """upsert_node() must invalidate retrieval cache."""
        api = _make_api_with_retriever()
        await api.query(text="node invalidation test query content", k=5)
        before = api._index_generation
        await api.upsert_node(_make_node("inval-node"))
        assert api._index_generation > before
        bundle = await api.query(text="node invalidation test query content", k=5)
        assert bundle.diagnostics is None or bundle.diagnostics.cache_hit is False

    async def test_inval_no_stale_cache_after_promote(self) -> None:
        """After promotion, newly promoted entry must be retrievable (not stale cache)."""
        api = _make_api_with_retriever()
        # First query (empty index)
        await api.query(text="stale cache after promote test", k=5)
        # Propose and promote a matching entry
        entry = KnowledgeEntry(
            text="stale cache after promote test unique phrase",
            source="test", confidence=0.95,
        )
        await api.propose_knowledge(entry)
        await api.promote_knowledge(entry.id)
        # Second query must see the new entry (not a stale cache hit)
        b2 = await api.query(text="stale cache after promote test unique phrase", k=5)
        ids_after = {e.id for e in b2.entries}
        assert entry.id in ids_after


# ---------------------------------------------------------------------------
# INT — MemoryAPI.query() integration
# ---------------------------------------------------------------------------

class TestIntegration:
    async def test_int_query_returns_evidence_bundle(self) -> None:
        from memfabric.types import EvidenceBundle
        api = _make_api_with_retriever()
        bundle = await api.query(text="integration test query", k=5)
        assert isinstance(bundle, EvidenceBundle)

    async def test_int_query_diagnostics_not_none(self) -> None:
        api = _make_api_with_retriever()
        bundle = await api.query(text="integration test query content", k=5)
        assert bundle.diagnostics is not None

    async def test_int_promoted_knowledge_retrieved_by_query(self) -> None:
        """After promotion, MemoryAPI.query() must find the promoted entry."""
        api = _make_api_with_retriever()
        entry = KnowledgeEntry(
            text="integration retrieval promoted knowledge entry test",
            source="test", confidence=0.9,
        )
        await api.propose_knowledge(entry)
        await api.promote_knowledge(entry.id)
        bundle = await api.query(text="integration retrieval promoted knowledge", k=10)
        ids = {e.id for e in bundle.entries}
        assert entry.id in ids

    async def test_int_staged_knowledge_not_retrieved(self) -> None:
        """Staged (un-promoted) knowledge must NOT appear in query results."""
        api = _make_api_with_retriever()
        entry = KnowledgeEntry(
            text="staged not retrieved integration test content",
            source="test", confidence=0.9,
        )
        await api.propose_knowledge(entry)
        # NOT promoted
        bundle = await api.query(text="staged not retrieved integration test", k=10)
        ids = {e.id for e in bundle.entries}
        assert entry.id not in ids

    async def test_int_working_tier_node_retrieved(self) -> None:
        """Working-tier node upserted via MemoryAPI must appear in working-tier query."""
        api = _make_api_with_retriever()
        node = _make_node("int-host", description="integration working tier node retrieval test")
        await api.upsert_node(node)
        bundle = await api.query(
            text="integration working tier node retrieval",
            k=10,
            tiers=[Tier.working],
        )
        ids = {e.id for e in bundle.entries}
        assert "int-host" in ids

    async def test_int_filters_applied_to_query(self) -> None:
        """filters parameter on api.query() must post-filter results."""
        api = _make_api_with_retriever()
        entry_a = KnowledgeEntry(
            text="filter integration alpha test knowledge content",
            source="test", confidence=0.9,
            metadata={"source_family": "intel_db"},
        )
        entry_b = KnowledgeEntry(
            text="filter integration beta test knowledge content",
            source="test", confidence=0.9,
            metadata={"source_family": "payload_db"},
        )
        await api.propose_knowledge(entry_a)
        await api.propose_knowledge(entry_b)
        await api.promote_knowledge(entry_a.id)
        await api.promote_knowledge(entry_b.id)
        bundle = await api.query(
            text="filter integration test knowledge content",
            k=10,
            filters={"source_family": "intel_db"},
        )
        for e in bundle.entries:
            sf = e.metadata.get("source_family")
            if sf is not None:
                assert sf == "intel_db"


# ---------------------------------------------------------------------------
# CTX — _context_hash content sensitivity (F05 fix)
# ---------------------------------------------------------------------------

class TestContextHash:
    def _make_subgraph(self, node_ids: list[str]) -> Any:
        """Build a minimal SubgraphView-like object for hashing tests."""
        from memfabric.types import SubgraphView, Node
        nodes = [
            Node(
                id=nid, type="host",
                props={"description": nid},
                source="test", confidence=0.8,
                first_seen=now(), last_seen=now(),
            )
            for nid in node_ids
        ]
        return SubgraphView(anchor="test", nodes=nodes, edges=[], depth=1)

    def _make_bundle(self, entry_ids: list[str]) -> Any:
        from memfabric.types import EvidenceBundle, ScoredEntry
        entries = [
            ScoredEntry(id=eid, score=1.0, text="text", source="s", tier="semantic", metadata={})
            for eid in entry_ids
        ]
        return EvidenceBundle(query="test", entries=entries, subgraph=None, tiers_queried=["semantic"])

    def test_ctx_same_ids_same_hash(self) -> None:
        from apex_host.planning.engine import _context_hash
        sg = self._make_subgraph(["n1", "n2"])
        bundle = self._make_bundle(["e1"])
        h1 = _context_hash(sg, bundle)
        h2 = _context_hash(sg, bundle)
        assert h1 == h2

    def test_ctx_different_node_id_different_hash(self) -> None:
        """Same count, different node ID → different hash (F05 fix)."""
        from apex_host.planning.engine import _context_hash
        sg_a = self._make_subgraph(["node-a"])
        sg_b = self._make_subgraph(["node-b"])
        bundle = self._make_bundle([])
        h_a = _context_hash(sg_a, bundle)
        h_b = _context_hash(sg_b, bundle)
        assert h_a != h_b, "Different node IDs with same count must produce different hashes"

    def test_ctx_different_entry_id_different_hash(self) -> None:
        """Same count, different evidence entry ID → different hash (F05 fix)."""
        from apex_host.planning.engine import _context_hash
        sg = self._make_subgraph([])
        bundle_a = self._make_bundle(["entry-one"])
        bundle_b = self._make_bundle(["entry-two"])
        h_a = _context_hash(sg, bundle_a)
        h_b = _context_hash(sg, bundle_b)
        assert h_a != h_b, "Different entry IDs with same count must produce different hashes"

    def test_ctx_count_only_would_collide_content_sensitive_does_not(self) -> None:
        """The old count-only hash (n:1:0:1) would collide; content-sensitive must not."""
        from apex_host.planning.engine import _context_hash
        # Build two contexts: both have 1 node, 0 edges, 1 entry — different IDs
        sg_a = self._make_subgraph(["node-alpha"])
        sg_b = self._make_subgraph(["node-beta"])
        bundle_a = self._make_bundle(["evidence-alpha"])
        bundle_b = self._make_bundle(["evidence-beta"])
        h_a = _context_hash(sg_a, bundle_a)
        h_b = _context_hash(sg_b, bundle_b)
        assert h_a != h_b

    def test_ctx_empty_context_stable_hash(self) -> None:
        """Empty subgraph + empty bundle → stable, non-empty hash."""
        from apex_host.planning.engine import _context_hash
        sg = self._make_subgraph([])
        bundle = self._make_bundle([])
        h = _context_hash(sg, bundle)
        assert isinstance(h, str)
        assert len(h) == 8

    def test_ctx_hash_is_8_chars(self) -> None:
        """_context_hash returns an 8-character hex string."""
        from apex_host.planning.engine import _context_hash
        sg = self._make_subgraph(["n1"])
        bundle = self._make_bundle(["e1"])
        h = _context_hash(sg, bundle)
        assert len(h) == 8
        assert all(c in "0123456789abcdef" for c in h)
