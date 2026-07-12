# graph_networkx.py
# In-memory EKG reference implementation backed by networkx.DiGraph with asyncio locking for concurrent-safe node/edge upserts and BFS subgraph extraction.
"""In-memory EKG reference implementation backed by networkx.DiGraph.

This is the reference GraphStore.  Every mutation is protected by an
asyncio.Lock so concurrent async writers don't interleave mid-update.
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Any, Sequence

import networkx as nx

from memfabric.types import Edge, Node, SubgraphView

logger = logging.getLogger(__name__)


class NetworkXGraphStore:
    """GraphStore backed by a networkx DiGraph held entirely in memory."""

    def __init__(self) -> None:
        self._g: nx.DiGraph[str, dict[str, Any], dict[str, Any]] = nx.DiGraph()
        self._edges: dict[str, Edge] = {}   # edge_id → Edge
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------

    async def get_node(self, node_id: str) -> Node | None:
        async with self._lock:
            if not self._g.has_node(node_id):
                return None
            return self._g.nodes[node_id]["data"]  # type: ignore[no-any-return]

    async def put_node(self, node: Node) -> str:
        """Insert or fully replace a node (caller owns merge logic)."""
        async with self._lock:
            self._g.add_node(node.id, data=node)
            logger.debug("put_node id=%s type=%s", node.id, node.type)
            return node.id

    async def delete_node(self, node_id: str) -> None:
        """Remove a node and its incident edges from the graph (rollback use only)."""
        async with self._lock:
            if not self._g.has_node(node_id):
                return
            # Remove incident edges from the edges dict before removing the node
            stale_eids = [
                eid for eid, e in self._edges.items()
                if e.from_id == node_id or e.to_id == node_id
            ]
            for eid in stale_eids:
                self._edges.pop(eid, None)
            self._g.remove_node(node_id)
            logger.debug("delete_node id=%s", node_id)

    async def get_nodes_by_type(self, node_type: str) -> list[Node]:
        async with self._lock:
            return [
                self._g.nodes[n]["data"]
                for n in self._g.nodes
                if self._g.nodes[n]["data"].type == node_type
            ]

    async def all_nodes(self) -> list[Node]:
        async with self._lock:
            return [self._g.nodes[n]["data"] for n in self._g.nodes]

    # ------------------------------------------------------------------
    # Edges
    # ------------------------------------------------------------------

    async def get_edge(self, edge_id: str) -> Edge | None:
        async with self._lock:
            return self._edges.get(edge_id)

    async def put_edge(self, edge: Edge) -> str:
        async with self._lock:
            self._edges[edge.id] = edge
            self._g.add_edge(edge.from_id, edge.to_id, id=edge.id, data=edge)
            logger.debug("put_edge id=%s type=%s", edge.id, edge.type)
            return edge.id

    async def delete_edge(self, edge_id: str) -> None:
        """Remove a single edge from the graph (rollback use only)."""
        async with self._lock:
            edge = self._edges.pop(edge_id, None)
            if edge is None:
                return
            if self._g.has_edge(edge.from_id, edge.to_id):
                self._g.remove_edge(edge.from_id, edge.to_id)
            logger.debug("delete_edge id=%s", edge_id)

    async def get_edges_for_node(self, node_id: str) -> list[Edge]:
        async with self._lock:
            result: list[Edge] = []
            if not self._g.has_node(node_id):
                return result
            for _src, _dst, data in self._g.out_edges(node_id, data=True):
                result.append(data["data"])
            for _src, _dst, data in self._g.in_edges(node_id, data=True):
                result.append(data["data"])
            return result

    async def all_edges(self) -> list[Edge]:
        async with self._lock:
            return list(self._edges.values())

    # ------------------------------------------------------------------
    # Subgraph
    # ------------------------------------------------------------------

    async def get_subgraph(
        self,
        anchor: str,
        depth: int,
        edge_types: Sequence[str] | None = None,
    ) -> SubgraphView:
        async with self._lock:
            visited_nodes: set[str] = set()
            visited_edges: list[Edge] = []

            if not self._g.has_node(anchor):
                return SubgraphView(anchor=anchor, nodes=[], edges=[], depth=depth)

            # BFS up to `depth` hops in both directions
            queue: deque[tuple[str, int]] = deque([(anchor, 0)])
            while queue:
                node_id, hops = queue.popleft()
                if node_id in visited_nodes or hops > depth:
                    continue
                visited_nodes.add(node_id)

                if hops < depth:
                    neighbors: list[str] = list(self._g.predecessors(node_id)) + list(
                        self._g.successors(node_id)
                    )
                    for nbr in neighbors:
                        if nbr not in visited_nodes:
                            queue.append((nbr, hops + 1))

            # Collect edges whose both endpoints are in the visited set
            for eid, edge in self._edges.items():
                if edge.from_id in visited_nodes and edge.to_id in visited_nodes:
                    if edge_types is None or edge.type in edge_types:
                        visited_edges.append(edge)

            nodes = [self._g.nodes[n]["data"] for n in visited_nodes]
            return SubgraphView(
                anchor=anchor, nodes=nodes, edges=visited_edges, depth=depth
            )
