"""Parses ffuf default-text output into Endpoint nodes + exposes edges."""
from __future__ import annotations

import re

from memfabric.ids import new_id, now
from memfabric.types import Edge, Node, ParsedObservation

_LINE_RE = re.compile(r"^(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+)")


class FfufParser:
    """Stateless parser: ffuf stdout text -> ParsedObservation."""

    def parse_text(self, output: str, *, target: str, source: str = "ffuf") -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()
        host_id = f"host:{target}"

        for line in output.splitlines():
            match = _LINE_RE.match(line.strip())
            if not match:
                continue
            path = match.group("path")
            status = match.group("status")
            url = f"{target.rstrip('/')}/{path.lstrip('/')}"
            endpoint_id = f"endpoint:{url}"
            nodes.append(
                Node(
                    id=endpoint_id,
                    type="endpoint",
                    props={"url": url, "path": path, "status": status},
                    confidence=0.7,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=new_id(),
                    from_id=host_id,
                    to_id=endpoint_id,
                    type="exposes",
                    props={},
                    confidence=0.7,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
