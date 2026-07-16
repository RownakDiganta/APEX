# capabilities.py
# Maps observed EKG service and tech nodes to safe supported planner capabilities.
"""Generic capability layer for APEX planners.

Derives a list of safe, supported planner actions from whatever the EKG
subgraph currently contains.  Purely deterministic — no IO, no MemoryAPI
calls, no machine-specific logic.

Planners call ``capabilities_from_subgraph(subgraph)`` and filter the
returned list by ``Capability.name`` to decide which tasks to emit.  All
service-classification knowledge (what constitutes HTTP, what ports are
worth probing, etc.) lives here — not scattered across individual planners.

Capability names
----------------
service_probe           Open service on a probeworthy port with no protocol match.
web_probe               HTTP/HTTPS service or known endpoint — ffuf/curl applicable.
browser_observe         HTTP/HTTPS service — Playwright/browser applicable.
access_validate_telnet  Telnet service — login prompt accessible; consumed by CredentialPlanner + TelnetExecutor.
access_validate_ssh     SSH service — auth surface present; consumed by CredentialPlanner + SSHExecutor (Phase 12B).
access_validate_ftp     FTP service — auth surface present; consumed by CredentialPlanner + FTPExecutor (Phase 12B).
exploit_research        Service with a known version string — searchsploit applicable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from memfabric.types import SubgraphView

# ---------------------------------------------------------------------------
# Critical fields — contestation on any of these blocks capability derivation
# ---------------------------------------------------------------------------

# If a service node has an open conflict on any of these fields, no capability
# is emitted for that node.  A contested field could cause a task to probe the
# wrong port, wrong protocol, wrong state, or wrong service name.
_CRITICAL_SERVICE_FIELDS: frozenset[str] = frozenset({
    "port", "service", "proto", "state",
})

# Endpoint nodes: if url is contested, web-phase tasks would target the wrong URL.
_CRITICAL_ENDPOINT_FIELDS: frozenset[str] = frozenset({"url"})

# ---------------------------------------------------------------------------
# Service / port classification sets
# ---------------------------------------------------------------------------

_HTTP_SERVICES: frozenset[str] = frozenset({
    "http", "ssl/http", "https", "http-alt", "http-proxy",
})
_HTTP_PORTS: frozenset[str] = frozenset({"80", "443", "8080", "8443", "8000", "8888"})

_SSH_SERVICES: frozenset[str] = frozenset({"ssh"})
_SSH_PORTS: frozenset[str] = frozenset({"22"})

_TELNET_SERVICES: frozenset[str] = frozenset({"telnet"})
_TELNET_PORTS: frozenset[str] = frozenset({"23"})

_FTP_SERVICES: frozenset[str] = frozenset({"ftp", "ftp-data"})
_FTP_PORTS: frozenset[str] = frozenset({"21", "20"})

# Ports worth a raw banner probe even when nmap didn't name the service.
# Unclassified services on these ports produce ``service_probe``; all others
# produce nothing (avoids probing arbitrary high ports).
_PROBEWORTHY_PORTS: frozenset[str] = frozenset({
    "21", "22", "23", "25", "3306", "5432", "6379",
})


# ---------------------------------------------------------------------------
# Capability record
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Capability:
    """A single safe planner action derivable from the current EKG state."""
    name: str
    target: str
    port: str
    service: str
    confidence: float
    source_node_id: str


# ---------------------------------------------------------------------------
# Internal mapping helpers
# ---------------------------------------------------------------------------

def _anchor_to_target(anchor: str) -> str:
    if anchor.startswith("host:"):
        return anchor[5:]
    return anchor


def _map_service_node(node_id: str, props: dict[str, object], confidence: float, target: str) -> list[Capability]:
    port = str(props.get("port", ""))
    proto = str(props.get("proto", "tcp")).lower()
    service = str(props.get("service", "")).lower()
    state = str(props.get("state", "open")).lower()
    version = str(props.get("version", "")).strip()

    if proto != "tcp":
        return []
    if state not in ("open", ""):
        return []

    caps: list[Capability] = []
    classified = False

    # Version info → exploit research (coexists with other caps)
    if version:
        caps.append(Capability(
            name="exploit_research",
            target=target, port=port, service=service,
            confidence=round(confidence * 0.8, 4),
            source_node_id=node_id,
        ))

    if service in _HTTP_SERVICES or port in _HTTP_PORTS:
        caps.append(Capability(
            name="web_probe",
            target=target, port=port, service=service,
            confidence=confidence,
            source_node_id=node_id,
        ))
        caps.append(Capability(
            name="browser_observe",
            target=target, port=port, service=service,
            confidence=round(confidence * 0.9, 4),
            source_node_id=node_id,
        ))
        classified = True

    if service in _TELNET_SERVICES or port in _TELNET_PORTS:
        caps.append(Capability(
            name="access_validate_telnet",
            target=target, port=port, service=service,
            confidence=confidence,
            source_node_id=node_id,
        ))
        classified = True

    if service in _SSH_SERVICES or port in _SSH_PORTS:
        caps.append(Capability(
            name="access_validate_ssh",
            target=target, port=port, service=service,
            confidence=round(confidence * 0.5, 4),
            source_node_id=node_id,
        ))
        classified = True

    if service in _FTP_SERVICES or port in _FTP_PORTS:
        caps.append(Capability(
            name="access_validate_ftp",
            target=target, port=port, service=service,
            confidence=round(confidence * 0.5, 4),
            source_node_id=node_id,
        ))
        classified = True

    if not classified and port in _PROBEWORTHY_PORTS:
        caps.append(Capability(
            name="service_probe",
            target=target, port=port, service=service,
            confidence=round(confidence * 0.7, 4),
            source_node_id=node_id,
        ))

    return caps


def _map_endpoint_node(node_id: str, props: dict[str, object], confidence: float, target: str) -> list[Capability]:
    url = str(props.get("url", ""))
    port = "443" if ("443" in url or url.startswith("https://")) else "80"
    return [
        Capability(
            name="web_probe",
            target=target, port=port, service="http",
            confidence=confidence,
            source_node_id=node_id,
        ),
        Capability(
            name="browser_observe",
            target=target, port=port, service="http",
            confidence=round(confidence * 0.9, 4),
            source_node_id=node_id,
        ),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def capabilities_from_subgraph(subgraph: "SubgraphView") -> list[Capability]:
    """Derive all safe planner capabilities from the current EKG subgraph.

    Only ``service`` and ``endpoint`` nodes are inspected.  Returned
    capabilities are ordered in node-traversal order — planners should sort
    by confidence if priority matters.

    Conflict filtering (Phase 2):
        Any node with an open ``Conflict`` on a critical field is skipped
        entirely — no capability is produced from it.  Critical fields for
        ``service`` nodes are ``port``, ``service``, ``proto``, and ``state``.
        Critical fields for ``endpoint`` nodes are ``url``.

        The ``SubgraphView.open_conflicts`` list is populated centrally by
        ``MemoryAPI.get_subgraph()`` before the subgraph is passed to planners.
        Conflict blocking is enforced here by skipping contested nodes — callers
        never need to inspect the conflict registry directly.

    Args:
        subgraph: A ``SubgraphView`` as retrieved from ``MemoryAPI``.

    Returns:
        A list of ``Capability`` records (may be empty if the subgraph
        contains no classified service or endpoint nodes, or all such nodes
        have contested critical fields).
    """
    target = _anchor_to_target(subgraph.anchor)

    # Build lookup: (node_id, field_name) → True for all absent critical fields.
    # "absent" = either open-conflict (contested) OR quarantined (untrusted).
    # Both must suppress capability derivation from that field.
    absent: frozenset[tuple[str, str]] = frozenset(
        (bc.node_id, bc.field_name)
        for bc in (*subgraph.open_conflicts, *subgraph.quarantined_fields)
    )

    caps: list[Capability] = []
    for node in subgraph.nodes:
        if node.type == "service":
            if any((node.id, f) in absent for f in _CRITICAL_SERVICE_FIELDS):
                continue
            caps.extend(_map_service_node(node.id, node.props, node.confidence, target))
        elif node.type == "endpoint":
            if any((node.id, f) in absent for f in _CRITICAL_ENDPOINT_FIELDS):
                continue
            caps.extend(_map_endpoint_node(node.id, node.props, node.confidence, target))

    return caps
