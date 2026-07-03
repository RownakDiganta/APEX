# protocols.py
# Store Protocol definitions (GraphStore, EpisodicStore, LexicalIndex, VectorIndex, KVStore) as structural Protocols so any conforming object can be injected without subclassing.
"""Store Protocol definitions.

Every boundary here is a structural Protocol so that any conforming object
(mock, real DB, cloud store) can be injected without subclassing.
"""
from __future__ import annotations

from typing import Any, Protocol, Sequence, runtime_checkable

from memfabric.types import Edge, Episode, Node, SubgraphView


@runtime_checkable
class GraphStore(Protocol):
    """Mutable episodic knowledge graph."""

    async def get_node(self, node_id: str) -> Node | None: ...
    async def put_node(self, node: Node) -> str:
        """Replace (or insert) a node.  Caller is responsible for merging."""
        ...
    async def delete_node(self, node_id: str) -> None:
        """Remove a node and all its incident edges.

        Used by ``MemoryAPI.apply_deltas`` during transactional rollback to
        undo a newly-created node.  Not intended for general use — normal
        working-memory mutations go through ``upsert_node``.
        """
        ...
    async def get_edge(self, edge_id: str) -> Edge | None: ...
    async def put_edge(self, edge: Edge) -> str: ...
    async def delete_edge(self, edge_id: str) -> None:
        """Remove a single edge.

        Used by ``MemoryAPI.apply_deltas`` during transactional rollback to
        undo a newly-created edge.
        """
        ...
    async def get_subgraph(
        self,
        anchor: str,
        depth: int,
        edge_types: Sequence[str] | None = None,
    ) -> SubgraphView: ...
    async def get_nodes_by_type(self, node_type: str) -> list[Node]: ...
    async def get_edges_for_node(self, node_id: str) -> list[Edge]: ...
    async def all_nodes(self) -> list[Node]: ...
    async def all_edges(self) -> list[Edge]: ...


@runtime_checkable
class EpisodicStore(Protocol):
    """Append-only event log.  Episodes are immutable once written."""

    async def append(self, episode: Episode) -> str: ...
    async def get(self, episode_id: str) -> Episode | None: ...
    async def tail(self, n: int = 100) -> list[Episode]: ...
    async def since(self, cursor: str) -> list[Episode]:
        """Return all episodes with id > cursor (lexicographic on timestamp+id)."""
        ...
    async def all(self) -> list[Episode]: ...


@runtime_checkable
class LexicalIndex(Protocol):
    """BM25-based full-text index shared across all tiers.

    All four tiers (working, episodic, semantic, procedural) store their
    retrievable text representations in the SAME physical index instance by
    default.  Tier isolation is enforced logically: every entry's ``metadata``
    dict MUST include a ``"tier"`` key so that the retrieval engine can
    post-filter results.  The ``HybridRetriever`` never returns an entry whose
    ``metadata["tier"]`` is not in the requested tier set.

    Physical separation per tier (a separate ``LexicalIndex`` instance per tier)
    is possible but not the default — inject separate instances if required.
    """

    async def add(self, id: str, text: str, metadata: dict[str, Any]) -> None: ...
    async def search(
        self, query: str, k: int
    ) -> list[tuple[str, float, dict[str, Any]]]:
        """Return up to *k* results as (id, bm25_score, metadata) triples."""
        ...
    async def remove(self, id: str) -> None: ...
    async def rebuild(self) -> None: ...


@runtime_checkable
class VectorIndex(Protocol):
    """Dense ANN index shared across all tiers.

    Like ``LexicalIndex``, a single instance serves all tiers by default.
    Each entry's ``metadata`` dict MUST include a ``"tier"`` key so the
    retrieval engine can post-filter by tier.  Physical separation per tier
    is possible by injecting separate instances; it is not the default.
    """

    async def add(self, id: str, vector: list[float], metadata: dict[str, Any]) -> None: ...
    async def search(
        self, vector: list[float], k: int
    ) -> list[tuple[str, float, dict[str, Any]]]:
        """Return up to *k* results as (id, similarity_score, metadata) triples."""
        ...
    async def remove(self, id: str) -> None: ...


@runtime_checkable
class KVStore(Protocol):
    """Simple key-value cache with optional TTL."""

    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any, ttl_seconds: float | None = None) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def delete_prefix(self, prefix: str) -> None:
        """Delete all keys whose name starts with *prefix*.

        Used by ``MemoryAPI`` to synchronously invalidate the retrieval cache
        (key prefix ``"retrieval:"``) on every working-tier write, so callers
        always see fresh graph state without waiting for cache TTL expiry.
        """
        ...
