# ffuf_parser.py
# Stateless parser that extracts discovered HTTP paths and status codes from ffuf stdout into Endpoint nodes and host-exposes edges.
"""Parses ffuf default-text output into Endpoint nodes + exposes edges."""
from __future__ import annotations

import re

from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation
from apex_host.graph_ids import host_id as _host_id_fn, endpoint_id as _endpoint_id, exposes_edge_id

_LINE_RE = re.compile(r"^(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+)")


class FfufParser:
    """Stateless parser: ffuf stdout text -> ParsedObservation."""

    def parse_text(self, output: str, *, target: str, source: str = "ffuf") -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()
        h_id = _host_id_fn(target)

        for line in output.splitlines():
            match = _LINE_RE.match(line.strip())
            if not match:
                continue
            path = match.group("path")
            status = match.group("status")
            url = f"{target.rstrip('/')}/{path.lstrip('/')}"
            ep_id = _endpoint_id(url)
            nodes.append(
                Node(
                    id=ep_id,
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
                    id=exposes_edge_id(h_id, ep_id),
                    from_id=h_id,
                    to_id=ep_id,
                    type="exposes",
                    props={},
                    confidence=0.7,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
