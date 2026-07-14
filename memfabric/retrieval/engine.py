# engine.py
# HybridRetriever that fuses BM25, regex identifier lookup, dense vector, and graph-match channels via RRF with Option A+ gate and complete cache-key schema.
"""HybridRetriever — the unified retrieval engine.

Pipeline per query:
1. k validation: k < 0 → ValueError; k == 0 → short-circuit with empty diagnostics
2. Cache check (full SHA-256 key with version, index_generation, all shape params)
3. BM25 (always runs)
4. Regex / identifier lookup (always; empty pattern set by default)
5. Gate decision (Option A+): when real embedder configured → dense+graph always;
   when StubEmbedder → use BM25-score gate (legacy backward-compatible behavior)
6. Dense vector channel (conditional)
7. Graph channel (conditional on Tier.working)
8. Reciprocal-rank fusion (RRF) with deterministic tie-breaking
9. Reranker with fallback on failure
10. Metadata post-filter (tier + user filters)
11. Cache result (deep-copied for immutability)
12. Return (entries, RetrievalDiagnostics)

Cache key schema (CACHE_KEY_VERSION="4"):
  SHA-256({v, text, k, tiers, filters_canonical, idx_gen, rrf_k, rerank_top_n, weights})

Cache immutability:
  Write: store copy.deepcopy(result) in KVStore
  Read: return copy.deepcopy(cached) to caller
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
from typing import TYPE_CHECKING, Any

from memfabric.retrieval.fusion import fuse_rrf
from memfabric.retrieval.gate import decide_gate
from memfabric.types import RetrievalDiagnostics, RetrievalError, ScoredEntry, Tier

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

# Increment when the cache key schema changes incompatibly.
# Old entries from a prior version will not match new keys → safe upgrade.
CACHE_KEY_VERSION = "4"


def _canonical_filters(filters: dict[str, Any] | None) -> str:
    """Serialize filters to a deterministic string for cache-key inclusion.

    Sorts all dict keys recursively via ``json.dumps(sort_keys=True)``.
    Raises ``ValueError`` for any non-JSON-serializable value so the error
    surfaces at query time rather than silently producing a broken key.
    """
    if filters is None:
        return "null"
    try:
        return json.dumps(filters, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"filters contains non-JSON-serializable value; "
            f"wrap it before calling query(): {exc}"
        ) from exc


def _cache_key(
    text: str,
    k: int,
    tiers: list[Tier],
    filters: dict[str, Any] | None,
    *,
    index_generation: int = 0,
    rrf_k: int = 60,
    rerank_top_n: int = 20,
    channel_weights: tuple[float, float, float, float] = (1.0, 0.5, 1.0, 0.5),
) -> str:
    """Build a complete, collision-resistant cache key.

    Includes every parameter that shapes the result set so two queries that
    differ in any result-shaping dimension produce independent cache entries.
    Uses the full SHA-256 digest (64 hex chars = 32 bytes) to avoid birthday
    collisions from the previous 16-char truncation.
    """
    payload = json.dumps(
        {
            "v": CACHE_KEY_VERSION,
            "text": text,
            "k": k,
            "tiers": sorted(t.value for t in tiers),
            "filters": _canonical_filters(filters),
            "idx_gen": index_generation,
            "rrf_k": rrf_k,
            "rerank_top_n": rerank_top_n,
            "weights": list(channel_weights),
        },
        sort_keys=True,
    )
    return "retrieval:" + hashlib.sha256(payload.encode()).hexdigest()


class HybridRetriever:
    """Fused BM25 + dense + graph + regex retrieval engine.

    Parameters
    ----------
    lexical:       BM25 index (searches all tiers via metadata)
    vector:        Dense ANN index
    embedder:      Text→vector embedder.  ``embedder.is_configured`` controls the gate:
                   False (StubEmbedder) → legacy BM25-score gate;
                   True (real embedder) → dense+graph always fire (Option A+).
    reranker:      Cross-encoder reranker (no-op PassthroughReranker by default)
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

        # Track whether expensive channels fired (for test introspection).
        # True iff the channel was *attempted* — not whether it returned results.
        self._last_dense_fired = False
        self._last_graph_fired = False

    async def search(
        self,
        *,
        text: str,
        k: int,
        tiers: list[Tier],
        filters: dict[str, Any] | None = None,
        index_generation: int = 0,
    ) -> tuple[list[ScoredEntry], RetrievalDiagnostics]:
        """Run the full retrieval pipeline and return (top-k entries, diagnostics).

        Parameters
        ----------
        text:             Query text.
        k:                Number of results to return.  k<0 raises ValueError;
                          k=0 returns ([], diagnostics) without running channels.
        tiers:            Logical tiers to include in the result.
        filters:          Additional metadata key-value post-filters.
        index_generation: Opaque counter from MemoryAPI that advances on every
                          retrieval-affecting mutation.  Included in the cache key
                          so a post-write query always sees a cache miss.
        """
        # --- k validation ---
        if k < 0:
            raise ValueError(f"k must be non-negative, got {k!r}")
        if k == 0:
            diag = RetrievalDiagnostics(
                cache_hit=False,
                channels_attempted=[],
                channels_skipped=["bm25", "regex", "dense", "graph"],
                lexical_top_score=0.0,
                lexical_candidate_count=0,
                dense_candidate_count=0,
                graph_candidate_count=0,
                regex_candidate_count=0,
                fused_candidate_count=0,
                reranked_candidate_count=0,
                gate_open=False,
                gate_reasons=["k=0: short-circuit, no channels run"],
                index_generation=index_generation,
                channel_weights=self._channel_weights_dict(),
            )
            return [], diag

        weights_tuple = (
            self._config.channel_weight_lexical,
            self._config.channel_weight_regex,
            self._config.channel_weight_dense,
            self._config.channel_weight_graph,
        )
        cache_key = _cache_key(
            text, k, tiers, filters,
            index_generation=index_generation,
            rrf_k=self._config.rrf_k,
            rerank_top_n=self._config.rerank_top_n,
            channel_weights=weights_tuple,
        )

        # --- cache hit (deep-copied for immutability) ---
        cached = await self._kv.get(cache_key)
        if cached is not None:
            logger.debug("cache hit key=%s", cache_key[:24])
            entries, diag = cached
            diag_copy = copy.deepcopy(diag)
            diag_copy.cache_hit = True
            return copy.deepcopy(entries), diag_copy

        tier_values = {t.value for t in tiers}
        multiplier = self._config.retrieval_top_k_multiplier

        channels_attempted: list[str] = []
        channels_skipped: list[str] = []

        # --- BM25 channel (always) ---
        channels_attempted.append("bm25")
        try:
            raw_bm25 = await self._lexical.search(text, k * multiplier)
        except Exception as exc:
            raise RetrievalError(f"BM25 channel failed: {exc}") from exc

        # BM25 scores BEFORE tier filter (for gate decision)
        all_bm25_scores = [score for _, score, _ in raw_bm25]
        lexical_top_score = max(all_bm25_scores) if all_bm25_scores else 0.0

        # Filter by requested tiers
        bm25_results = [
            (id_, score, meta)
            for id_, score, meta in raw_bm25
            if meta.get("tier") in tier_values
        ]
        # --- Regex / identifier channel (always; empty by default) ---
        regex_results: list[tuple[str, float, dict[str, Any]]] = []
        if self._patterns:
            channels_attempted.append("regex")
            try:
                regex_results = self._regex_search(text)
            except Exception as exc:
                logger.warning("regex channel failed: %s", exc)
                channels_skipped.append("regex")
        else:
            channels_skipped.append("regex")

        # --- Gate decision (Option A+) ---
        embedder_configured = bool(getattr(self._embedder, "is_configured", False))
        gate_decision = decide_gate(
            all_bm25_scores,
            self._config.low_confidence_tau,
            embedder_configured=embedder_configured,
        )
        gate_open = gate_decision.open

        self._last_dense_fired = False
        self._last_graph_fired = False

        # --- Dense channel (conditional) ---
        dense_results: list[tuple[str, float, dict[str, Any]]] = []
        if gate_open:
            channels_attempted.append("dense")
            try:
                dense_results = await self._dense_search(text, k, tier_values)
                self._last_dense_fired = True
            except Exception as exc:
                logger.warning("dense channel failed: %s", exc)
                channels_skipped.append("dense")
        else:
            channels_skipped.append("dense")

        # --- Graph channel (conditional on Tier.working) ---
        graph_results: list[tuple[str, float, dict[str, Any]]] = []
        if gate_open and Tier.working in tiers:
            channels_attempted.append("graph")
            try:
                graph_scored = await self._graph_matcher.match(text, self._graph, k)
                graph_results = [(e.id, e.score, e.metadata) for e in graph_scored]
                self._last_graph_fired = True
            except Exception as exc:
                logger.warning("graph channel failed: %s", exc)
                channels_skipped.append("graph")
        else:
            channels_skipped.append("graph")

        # --- RRF fusion ---
        # Use max(k, rerank_top_n) candidates so the reranker sees enough options.
        rerank_budget = max(k, self._config.rerank_top_n)
        weights_list = [
            self._config.channel_weight_lexical,
            self._config.channel_weight_regex,
            self._config.channel_weight_dense,
            self._config.channel_weight_graph,
        ]
        fused = fuse_rrf(
            [bm25_results, regex_results, dense_results, graph_results],
            k=self._config.rrf_k,
            weights=weights_list,
            top_n=rerank_budget,
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
        try:
            reranked = await self._reranker.rerank(text, candidates)
        except Exception as exc:
            logger.warning("reranker failed, using fused order as fallback: %s", exc)
            reranked = candidates

        # --- Tier post-filter ---
        # Applied after reranking.  Regex results (tier="regex" or missing tier) are
        # exempt from tier filtering — they are cross-tier exact-match identifiers.
        # Only results with a real Tier value in metadata are filtered.
        filtered: list[ScoredEntry] = []
        for entry in reranked:
            entry_tier = entry.metadata.get("tier", entry.tier)
            if entry_tier in tier_values or entry_tier not in {t.value for t in Tier}:
                # Keep: tier matches request OR entry has no standard tier (e.g. regex results)
                filtered.append(entry)

        # --- User-supplied metadata post-filter ---
        if filters:
            filtered = [
                e for e in filtered
                if all(e.metadata.get(fk) == fv for fk, fv in filters.items())
            ]

        # Truncate to final k
        result = filtered[:k]

        diag = RetrievalDiagnostics(
            cache_hit=False,
            channels_attempted=channels_attempted,
            channels_skipped=channels_skipped,
            lexical_top_score=lexical_top_score,
            lexical_candidate_count=len(bm25_results),
            dense_candidate_count=len(dense_results),
            graph_candidate_count=len(graph_results),
            regex_candidate_count=len(regex_results),
            fused_candidate_count=len(fused),
            reranked_candidate_count=len(reranked),
            gate_open=gate_open,
            gate_reasons=gate_decision.reasons,
            index_generation=index_generation,
            channel_weights=self._channel_weights_dict(),
        )

        # --- Cache (deep-copied so caller or future mutations cannot corrupt cache) ---
        await self._kv.set(
            cache_key,
            (copy.deepcopy(result), copy.deepcopy(diag)),
            ttl_seconds=self._config.retrieval_cache_ttl,
        )
        return result, diag

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _channel_weights_dict(self) -> dict[str, float]:
        return {
            "bm25": self._config.channel_weight_lexical,
            "regex": self._config.channel_weight_regex,
            "dense": self._config.channel_weight_dense,
            "graph": self._config.channel_weight_graph,
        }

    def _regex_search(
        self, text: str
    ) -> list[tuple[str, float, dict[str, Any]]]:
        """Run all configured identifier patterns against the query text.

        Regex results carry ``tier="regex"`` which is NOT a standard Tier value.
        They are treated as cross-tier exact-match identifiers and are exempt
        from the tier post-filter in ``search()``.
        """
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
        """Embed query and search the vector index.

        Returns empty list if the embedder raises (StubEmbedder path).
        Caller is responsible for logging the warning.
        """
        embeddings = await self._embedder.embed([text])
        vec = embeddings[0]
        raw = await self._vector.search(vec, k * self._config.retrieval_top_k_multiplier)
        return [
            (id_, score, meta)
            for id_, score, meta in raw
            if meta.get("tier") in tier_values
        ][:k]
