# nmap_parser.py
# Stateless parser that converts nmap text-mode stdout into Host, Service, and Tech EKG nodes plus host-exposes and service-runs edges.
"""Parses nmap text-mode output (``nmap -oN`` / default stdout format) into
memfabric Node/Edge deltas. No payload or exploit content — purely structural
parsing of host/port/service/version text.
"""
from __future__ import annotations

import re

from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation
from apex_host.graph_ids import (
    host_id as _host_id,
    service_id as _service_id,
    tech_id as _tech_id_fn,
    exposes_edge_id,
    runs_edge_id,
)

_HOST_RE = re.compile(r"^Nmap scan report for (?:(?P<name>\S+) \()?(?P<addr>[\w.:]+)\)?$")
_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$"
)

# States that indicate the port is reachable — create EKG nodes for these only.
# "open|filtered" is a valid nmap state for UDP services or when packet-filter
# ambiguity exists; we include it so UDP recon is not silently dropped.
_OPEN_STATES: frozenset[str] = frozenset({"open", "open|filtered"})

# Substrings (matched case-insensitively) nmap prints to stderr when it
# cannot open a raw socket — the exact failure mode of a non-root
# execution backend (e.g. the Kali tool-service container, which runs as
# a non-root user with zero added Linux capabilities — see
# docs/kali-container.md §5/§14) attempting a scan mode that requires
# CAP_NET_RAW/root (nmap's default "-sV" alone implies a SYN scan; it does
# NOT automatically fall back to a TCP-connect scan on permission
# failure — it exits nonzero and prints exactly this). Verified live text,
# recorded in docs/kali-container.md §5:
#   "Couldn't open a raw socket. Error: (1) Operation not permitted
#    Couldn't open a raw socket or eth handle.
#    QUITTING!"
_RAW_SOCKET_PERMISSION_MARKERS: tuple[str, ...] = (
    "couldn't open a raw socket",
    "requires root privileges",
)

#: Fixed, small diagnostic-error vocabulary for nmap task results — used
#: only for structured diagnostics (never for parsing/EKG-write decisions,
#: which remain driven entirely by whether stdout actually matches
#: ``_PORT_RE``). Empty string means "nmap reported success" (returncode 0
#: and no transport-level error); every other value is a nonzero-exit
#: failure, classified as precisely as the fixed vocabulary allows.
NMAP_ERROR_CATEGORY_SUCCESS = ""
NMAP_ERROR_CATEGORY_RAW_SOCKET_PERMISSION_DENIED = "raw_socket_permission_denied"
NMAP_ERROR_CATEGORY_EXECUTION_FAILED = "nmap_execution_failed"


def classify_nmap_error(returncode: int, stdout: str, stderr: str) -> str:
    """Classify why an nmap invocation failed, for structured diagnostics
    only — never affects EKG parsing, which is driven purely by whether
    ``output`` matches the expected nmap text format (see
    :meth:`NmapParser.parse_text`).

    Returns :data:`NMAP_ERROR_CATEGORY_SUCCESS` (``""``) when *returncode*
    is ``0`` — there is nothing to classify. Otherwise returns
    :data:`NMAP_ERROR_CATEGORY_RAW_SOCKET_PERMISSION_DENIED` when *stderr*
    (or, defensively, *stdout* — some environments interleave nmap's
    diagnostic output onto stdout) contains one of the known raw-socket
    permission-failure markers, or the generic
    :data:`NMAP_ERROR_CATEGORY_EXECUTION_FAILED` for any other nonzero-exit
    failure (host down, invalid target, unreachable network, ...).
    """
    if returncode == 0:
        return NMAP_ERROR_CATEGORY_SUCCESS
    combined = f"{stderr}\n{stdout}".lower()
    if any(marker in combined for marker in _RAW_SOCKET_PERMISSION_MARKERS):
        return NMAP_ERROR_CATEGORY_RAW_SOCKET_PERMISSION_DENIED
    return NMAP_ERROR_CATEGORY_EXECUTION_FAILED


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

        h_id = _host_id(host_addr)
        nodes.append(
            Node(
                id=h_id,
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
            raw_version = (pm.group("version") or "").strip()

            if state not in _OPEN_STATES:
                continue

            tech = _extract_tech(raw_version)
            short_version = tech[1] if tech else ""

            svc_id = _service_id(host_addr, port, proto)
            nodes.append(
                Node(
                    id=svc_id,
                    type="service",
                    props={
                        "port": port,
                        "proto": proto,
                        "state": state,
                        "service": service,
                        "target": host_addr,
                        "raw_version": raw_version,
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
                    id=exposes_edge_id(h_id, svc_id),
                    from_id=h_id,
                    to_id=svc_id,
                    type="exposes",
                    props={},
                    confidence=0.85,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

            if tech:
                tech_name, tech_ver = tech
                tid = _tech_id_fn(host_addr, tech_name)
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
                        id=runs_edge_id(svc_id, tid),
                        from_id=svc_id,
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
