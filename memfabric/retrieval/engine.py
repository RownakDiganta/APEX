# engine.py
# HybridRetriever that fuses BM25, regex identifier lookup, dense vector, and graph-match channels via RRF with a low-confidence gate controlling the expensive channels.
"""HybridRetriever — the unified retrieval engine.

Pipeline per query:
1. BM25 (always runs)
2. Regex / identifier lookup (always runs; empty pattern set by default)
3. Low-confidence gate: if max BM25 score < tau → also run dense + graph
4. Reciprocal-rank fusion of active channels
5. Cross-encoder rerank (no-op by default)
6. Cache result in KVStore
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from typing import TYPE_CHECKING, Any

from memfabric.retrieval.fusion import fuse_rrf
from memfabric.retrieval.gate import gate_is_open
from memfabric.types import ScoredEntry, Tier

if TYPE_CHECKING:
    from memfabric.config import Config
    from memfabric.retrieval.protocols import Embedder, GraphMatcher, Reranker
    from memfabric.stores.protocols import (
        GraphStore,
        KVStore,
        LexicalIndex,
        VectorIndex,
    )

logger = logging.getLogger(__name__)


def _cache_key(text: str, tiers: list[Tier], filters: dict[str, Any] | None) -> str:
    payload = json.dumps(
        {"text": text, "tiers": sorted(t.value for t in tiers), "filters": filters},
        sort_keys=True,
    )
    return "retrieval:" + hashlib.sha256(payload.encode()).hexdigest()[:16]


class HybridRetriever:
    """Fused BM25 + dense + graph + regex retrieval engine.

    Parameters
    ----------
    lexical:       BM25 index (searches all tiers via metadata)
    vector:        Dense ANN index
    embedder:      Text→vector embedder (stub raises if unconfigured)
    reranker:      Cross-encoder reranker (no-op by default)
    graph:         EKG graph store (for graph channel)
    graph_matcher: Structural/text matcher against the EKG
    kv:            Cache store (KVStore)
    config:        Config dataclass
    identifier_patterns: Dict mapping pattern-name → compiled regex.  Empty
                   by default; host app supplies domain-specific patterns.
    """

    def __init__(
        self,
        lexical: LexicalIndex,
        vector: VectorIndex,
        embedder: Embedder,
        reranker: Reranker,
        graph: GraphStore,
        graph_matcher: GraphMatcher,
        kv: KVStore,
        *,
        config: Config,
        identifier_patterns: dict[str, re.Pattern[str]] | None = None,
    ) -> None:
        self._lexical = lexical
        self._vector = vector
        self._embedder = embedder
        self._reranker = reranker
        self._graph = graph
        self._graph_matcher = graph_matcher
        self._kv = kv
        self._config = config
        self._patterns: dict[str, re.Pattern[str]] = identifier_patterns or {}

        # Track whether expensive channels fired (for test introspection)
        self._last_dense_fired = False
        self._last_graph_fired = False

    async def search(
        self,
        *,
        text: str,
        k: int,
        tiers: list[Tier],
        filters: dict[str, Any] | None = None,
    ) -> list[ScoredEntry]:
        """Run the full retrieval pipeline and return top-k scored entries."""
        cache_key = _cache_key(text, tiers, filters)

        # --- cache hit ---
        cached = await self._kv.get(cache_key)
        if cached is not None:
            logger.debug("cache hit key=%s", cache_key[:24])
            return cached  # type: ignore[no-any-return]

        tier_values = {t.value for t in tiers}
        multiplier = self._config.retrieval_top_k_multiplier

        # --- BM25 channel (always) ---
        raw_bm25 = await self._lexical.search(text, k * multiplier)
        # Filter by requested tiers
        bm25_results = [
            (id_, score, meta)
            for id_, score, meta in raw_bm25
            if meta.get("tier") in tier_values
        ]
        bm25_scores = [score for _, score, _ in bm25_results]

        # --- Regex / identifier channel (always; empty by default) ---
        regex_results: list[tuple[str, float, dict[str, Any]]] = []
        if self._patterns:
            regex_results = self._regex_search(text, tier_values)

        # --- Gate decision ---
        self._last_dense_fired = False
        self._last_graph_fired = False
        expensive_open = gate_is_open(bm25_scores, self._config.low_confidence_tau)

        # --- Dense channel (conditional) ---
        dense_results: list[tuple[str, float, dict[str, Any]]] = []
        if expensive_open:
            dense_results = await self._dense_search(text, k, tier_values)
            self._last_dense_fired = True

        # --- Graph channel (conditional) ---
        graph_results: list[tuple[str, float, dict[str, Any]]] = []
        if expensive_open and Tier.working in tiers:
            graph_scored = await self._graph_matcher.match(text, self._graph, k)
            graph_results = [(e.id, e.score, e.metadata) for e in graph_scored]
            self._last_graph_fired = True

        # --- RRF fusion ---
        weights = [
            self._config.channel_weight_lexical,
            self._config.channel_weight_regex,
            self._config.channel_weight_dense,
            self._config.channel_weight_graph,
        ]
        fused = fuse_rrf(
            [bm25_results, regex_results, dense_results, graph_results],
            k=self._config.rrf_k,
            weights=weights,
            top_n=k,
        )

        # --- Rerank ---
        candidates = [
            ScoredEntry(
                id=doc_id,
                score=score,
                text=str(meta.get("_text", "")),
                source=str(meta.get("source", "")),
                tier=str(meta.get("tier", "")),
                metadata=dict(meta),
            )
            for doc_id, score, meta in fused
        ]
        reranked = await self._reranker.rerank(text, candidates)

        # --- Metadata post-filter ---
        # Applied after reranking so the cache stores the filtered result.
        if filters:
            reranked = [
                e for e in reranked
                if all(e.metadata.get(k) == v for k, v in filters.items())
            ]

        # --- Cache ---
        await self._kv.set(
            cache_key, reranked, ttl_seconds=self._config.retrieval_cache_ttl
        )
        return reranked

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _regex_search(
        self, text: str, tier_values: set[str]
    ) -> list[tuple[str, float, dict[str, Any]]]:
        """Run all configured identifier patterns against the query text."""
        results: list[tuple[str, float, dict[str, Any]]] = []
        for pattern_name, pattern in self._patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                results.append(
                    (
                        f"regex:{pattern_name}:{match}",
                        1.0,
                        {"tier": "regex", "pattern": pattern_name, "match": match},
                    )
                )
        return results

    async def _dense_search(
        self, text: str, k: int, tier_values: set[str]
    ) -> list[tuple[str, float, dict[str, Any]]]:
        """Embed query and search the vector index."""
        try:
            embeddings = await self._embedder.embed([text])
        except RuntimeError:
            logger.debug("embedder not configured; skipping dense channel")
            return []
        vec = embeddings[0]
        raw = await self._vector.search(vec, k * self._config.retrieval_top_k_multiplier)
        return [
            (id_, score, meta)
            for id_, score, meta in raw
            if meta.get("tier") in tier_values
        ][:k]
