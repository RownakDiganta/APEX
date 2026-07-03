# nmap_parser.py
# Stateless parser that converts nmap text-mode stdout into Host, Service, and Tech EKG nodes plus host-exposes and service-runs edges.
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

# States that indicate the port is reachable — create EKG nodes for these only.
# "open|filtered" is a valid nmap state for UDP services or when packet-filter
# ambiguity exists; we include it so UDP recon is not silently dropped.
_OPEN_STATES: frozenset[str] = frozenset({"open", "open|filtered"})


def _extract_tech(version_str: str) -> tuple[str, str] | None:
    """Return (display_name, version_string) from an nmap version field, or None.

    Strategy: find the first whitespace-token that begins with a digit — that is
    the version string.  Everything before it (up to 3 tokens) is the product
    name.  Examples:
      "OpenSSH 8.4p1 Ubuntu …"  → ("OpenSSH", "8.4p1")
      "Apache httpd 2.4.41 …"   → ("Apache httpd", "2.4.41")
      "vsftpd 3.0.3"            → ("vsftpd", "3.0.3")
      "Linux telnetd"            → ("Linux telnetd", "")
    """
    v = version_str.strip()
    if not v:
        return None
    tokens = v.split()
    ver_idx = next((i for i, t in enumerate(tokens) if t and t[0].isdigit()), len(tokens))
    name_tokens = tokens[: max(ver_idx, 1)][:3]
    ver = tokens[ver_idx] if ver_idx < len(tokens) else ""
    name = " ".join(name_tokens).rstrip("/(")
    return (name, ver) if name else None


def _tech_id(host_addr: str, tech_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", tech_name.lower()).strip("_")
    return f"tech:{host_addr}:{slug}"


class NmapParser:
    """Stateless parser: nmap stdout text -> ParsedObservation."""

    def parse_text(self, output: str, *, target: str, source: str = "nmap") -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()

        host_addr = target
        for line in output.splitlines():
            m = _HOST_RE.match(line.strip())
            if m:
                host_addr = m.group("addr")
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
            pm = _PORT_RE.match(line.strip())
            if not pm:
                continue
            port = pm.group("port")
            proto = pm.group("proto")
            state = pm.group("state")
            service = pm.group("service")
            # raw_version: the full nmap version banner as-is (may be empty)
            raw_version = (pm.group("version") or "").strip()

            # Only create EKG nodes for ports that are reachable.
            # Closed/filtered ports carry no actionable service info.
            if state not in _OPEN_STATES:
                continue

            # Extract product/short-version from the raw banner for the tech node
            # and for the service node's version field.
            tech = _extract_tech(raw_version)
            short_version = tech[1] if tech else ""

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
                        "target": host_addr,
                        # raw_version: full nmap version banner (may include OS/extra info)
                        "raw_version": raw_version,
                        # version: short product-version string extracted from banner
                        "version": short_version,
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

            # Tech node: only when version banner is non-empty and parseable
            if tech:
                tech_name, tech_ver = tech
                tid = _tech_id(host_addr, tech_name)
                nodes.append(
                    Node(
                        id=tid,
                        type="tech",
                        props={"name": tech_name, "version": tech_ver, "service": service},
                        confidence=0.8,
                        source=source,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )
                edges.append(
                    Edge(
                        id=new_id(),
                        from_id=service_id,
                        to_id=tid,
                        type="runs",
                        props={},
                        confidence=0.8,
                        source=source,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
