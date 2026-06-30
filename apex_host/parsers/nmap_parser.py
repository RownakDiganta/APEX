"""Parses nmap text-mode output (``nmap -oN`` / default stdout format) into
memfabric Node/Edge deltas. No payload or exploit content — purely structural
parsing of host/port/service/version text.
"""
from __future__ import annotations

import re

from memfabric.ids import new_id, now
from memfabric.types import Edge, Node, ParsedObservation

_HOST_RE = re.compile(r"^Nmap scan report for (?:(?P<name>\S+) \()?(?P<addr>[\w.:]+)\)?$")
_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$"
)


class NmapParser:
    """Stateless parser: nmap stdout text -> ParsedObservation."""

    def parse_text(self, output: str, *, target: str, source: str = "nmap") -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()

        host_addr = target
        for line in output.splitlines():
            match = _HOST_RE.match(line.strip())
            if match:
                host_addr = match.group("addr")
                break

        host_id = f"host:{host_addr}"
        nodes.append(
            Node(
                id=host_id,
                type="host",
                props={"ip": host_addr, "target": target},
                confidence=0.9,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )

        for line in output.splitlines():
            match = _PORT_RE.match(line.strip())
            if not match:
                continue
            port = match.group("port")
            proto = match.group("proto")
            state = match.group("state")
            service = match.group("service")
            version = (match.group("version") or "").strip()

            service_id = f"service:{host_addr}:{port}/{proto}"
            nodes.append(
                Node(
                    id=service_id,
                    type="service",
                    props={
                        "port": port,
                        "proto": proto,
                        "state": state,
                        "service": service,
                        "version": version,
                    },
                    confidence=0.85,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=new_id(),
                    from_id=host_id,
                    to_id=service_id,
                    type="exposes",
                    props={},
                    confidence=0.85,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
