# protocols.py
# Retrieval-layer Protocol definitions (Embedder, Reranker, GraphMatcher) plus built-in stub implementations shipped with the substrate.
"""Retrieval-layer Protocols.

These are the pluggable boundaries for expensive, model-dependent components.
The substrate ships stub implementations only; real models are supplied by the
host application.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from memfabric.stores.protocols import GraphStore
    from memfabric.types import ScoredEntry


@runtime_checkable
class Embedder(Protocol):
    """Turns text into a dense vector."""

    async def embed(self, texts: list[str]) -> list[list[float]]: ...


@runtime_checkable
class Reranker(Protocol):
    """Cross-encoder reranker: given a query and candidates, re-score."""

    async def rerank(
        self, query: str, entries: list[ScoredEntry]
    ) -> list[ScoredEntry]: ...


@runtime_checkable
class GraphMatcher(Protocol):
    """Match a query's structural/text pattern against the EKG."""

    async def match(
        self, query: str, graph: GraphStore, k: int
    ) -> list[ScoredEntry]: ...


# ---------------------------------------------------------------------------
# Built-in stub implementations
# ---------------------------------------------------------------------------

class StubEmbedder:
    """Raises if used without a real embedder being configured."""

    async def embed(self, texts: list[str]) -> list[list[float]]:
        raise RuntimeError(
            "No Embedder configured.  Provide a real Embedder via the host app."
        )


class PassthroughReranker:
    """No-op reranker: returns candidates unchanged (preserves RRF order)."""

    async def rerank(
        self, query: str, entries: list[ScoredEntry]
    ) -> list[ScoredEntry]:
        return entries


class TextGraphMatcher:
    """Simple graph matcher: BFS from nodes whose type/props match query text."""

    async def match(
        self, query: str, graph: GraphStore, k: int
    ) -> list[ScoredEntry]:
        from memfabric.api import _node_text
        from memfabric.types import ScoredEntry, Tier

        q_lower = query.lower()
        nodes = await graph.all_nodes()
        results: list[ScoredEntry] = []
        for node in nodes:
            text = _node_text(node).lower()
            # Count overlapping tokens as a simple relevance proxy
            q_tokens = set(q_lower.split())
            t_tokens = set(text.split())
            overlap = len(q_tokens & t_tokens)
            if overlap > 0:
                results.append(
                    ScoredEntry(
                        id=node.id,
                        score=float(overlap),
                        text=_node_text(node),
                        source=node.source,
                        tier=Tier.working.value,
                        metadata={"type": node.type},
                    )
                )
        results.sort(key=lambda e: e.score, reverse=True)
        return results[:k]
