# banner_parser.py
# Parses simple service banners into EKG service and tech observations.
"""Parses raw service banner strings (from nc/netcat or similar grabs) into
memfabric Node/Edge deltas.

Recognised patterns and their EKG output:
  SSH banner   → service(ssh) + tech(OpenSSH/…)  + runs edge
  FTP vsFTPd   → service(ftp) + tech(vsftpd)     + runs edge
  FTP ProFTPD  → service(ftp) + tech(ProFTPD)    + runs edge
  FTP generic  → service(ftp)  (no tech)
  SMTP ESMTP   → service(smtp) (no tech)
  HTTP status  → service(http) (no tech)
  Telnet login → service(telnet) (no tech)
  Unrecognised → staged KnowledgeEntry (never silently dropped)
"""
from __future__ import annotations

import re
from typing import Any

from memfabric.ids import new_id, now
from memfabric.types import Edge, KnowledgeEntry, Node, ParsedObservation

# Ordered pattern set — first match wins
_SSH_RE = re.compile(r"SSH-(?P<proto>\d+\.\d+)-(?P<software>[^\s\r\n]+)")
_FTP_VSFTPD_RE = re.compile(r"220.*\(vsFTPd\s+(?P<version>[\d.]+)\)", re.IGNORECASE)
_FTP_PROFTPD_RE = re.compile(r"220.*ProFTPD\s+(?P<version>[\d.]+)", re.IGNORECASE)
_FTP_GENERIC_RE = re.compile(r"^220[\s-]", re.MULTILINE)
_SMTP_RE = re.compile(r"^220\s+\S+\s+ESMTP", re.MULTILINE)
_HTTP_RE = re.compile(r"^HTTP/[\d.]+\s+\d{3}", re.MULTILINE)
_TELNET_RE = re.compile(r"(login:\s*$|Escape character is|telnet>)", re.IGNORECASE | re.MULTILINE)


def _service_id(host: str, port: str, service_name: str) -> str:
    if port:
        return f"service:{host}:{port}/tcp"
    return f"service:{host}:banner:{service_name}"


def _tech_id(host: str, tech_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", tech_name.lower()).strip("_")
    return f"tech:{host}:{slug}"


class BannerParser:
    """Stateless parser: raw banner text -> ParsedObservation."""

    def parse_text(
        self,
        text: str,
        *,
        target: str,
        source: str = "nc",
        port: str = "",
    ) -> ParsedObservation:
        """Parse a banner grabbed from *target* (optionally on *port*)."""
        stripped = text.strip()
        if not stripped:
            return ParsedObservation()

        m_ssh = _SSH_RE.search(stripped)
        if m_ssh:
            return self._ssh_obs(m_ssh, target=target, port=port, source=source)

        if _SMTP_RE.search(stripped):
            return self._generic_service_obs(
                "smtp", "", target=target, port=port, source=source,
                extra_props={"banner": stripped[:200]},
            )

        m_vsftpd = _FTP_VSFTPD_RE.search(stripped)
        if m_vsftpd:
            return self._ftp_obs(
                "vsftpd", m_vsftpd.group("version"),
                target=target, port=port or "21", source=source, banner=stripped,
            )

        m_proftpd = _FTP_PROFTPD_RE.search(stripped)
        if m_proftpd:
            return self._ftp_obs(
                "ProFTPD", m_proftpd.group("version"),
                target=target, port=port or "21", source=source, banner=stripped,
            )

        if _FTP_GENERIC_RE.search(stripped):
            return self._generic_service_obs(
                "ftp", "", target=target, port=port or "21", source=source,
                extra_props={"banner": stripped[:200]},
            )

        if _HTTP_RE.search(stripped):
            return self._generic_service_obs(
                "http", "", target=target, port=port or "80", source=source,
                extra_props={"banner": stripped[:200]},
            )

        if _TELNET_RE.search(stripped):
            return self._generic_service_obs(
                "telnet", "", target=target, port=port or "23", source=source,
                extra_props={"banner": stripped[:200]},
            )

        # Unrecognised — never silently drop non-empty banners
        entry = KnowledgeEntry(
            text=stripped[:2000],
            source=source,
            confidence=0.25,
            timestamp=now(),
            metadata={"kind": "unknown_banner", "target": target, "port": port},
        )
        return ParsedObservation(proposed_knowledge=[entry])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ssh_obs(
        self, m: re.Match[str], *, target: str, port: str, source: str
    ) -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()

        proto_ver = m.group("proto")
        software = m.group("software")           # e.g. "OpenSSH_8.4p1"
        sw_clean = software.replace("_", " ", 1) # "OpenSSH 8.4p1"
        sw_parts = sw_clean.split()
        tech_name = sw_parts[0] if sw_parts else software
        tech_ver = sw_parts[1] if len(sw_parts) > 1 else ""

        svc_id = _service_id(target, port or "22", "ssh")
        nodes.append(
            Node(
                id=svc_id,
                type="service",
                props={
                    "service": "ssh",
                    "proto": "tcp",
                    "port": port or "22",
                    "ssh_proto": proto_ver,
                    "banner": m.group(0),
                },
                confidence=0.9,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )
        tid = _tech_id(target, tech_name)
        nodes.append(
            Node(
                id=tid,
                type="tech",
                props={"name": tech_name, "version": tech_ver},
                confidence=0.85,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )
        edges.append(
            Edge(
                id=new_id(),
                from_id=svc_id,
                to_id=tid,
                type="runs",
                props={},
                confidence=0.85,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )
        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)

    def _ftp_obs(
        self,
        tech_name: str,
        tech_ver: str,
        *,
        target: str,
        port: str,
        source: str,
        banner: str,
    ) -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()

        svc_id = _service_id(target, port, "ftp")
        nodes.append(
            Node(
                id=svc_id,
                type="service",
                props={"service": "ftp", "proto": "tcp", "port": port, "banner": banner[:200]},
                confidence=0.85,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )
        tid = _tech_id(target, tech_name)
        nodes.append(
            Node(
                id=tid,
                type="tech",
                props={"name": tech_name, "version": tech_ver},
                confidence=0.8,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )
        edges.append(
            Edge(
                id=new_id(),
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

    def _generic_service_obs(
        self,
        service_name: str,
        tech_name: str,
        *,
        target: str,
        port: str,
        source: str,
        extra_props: dict[str, Any] | None = None,
    ) -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()

        props: dict[str, Any] = {"service": service_name, "proto": "tcp", "port": port}
        if extra_props is not None:
            props.update(extra_props)

        svc_id = _service_id(target, port, service_name)
        nodes.append(
            Node(
                id=svc_id,
                type="service",
                props=props,
                confidence=0.75,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )
        if tech_name:
            tid = _tech_id(target, tech_name)
            nodes.append(
                Node(
                    id=tid,
                    type="tech",
                    props={"name": tech_name, "version": ""},
                    confidence=0.7,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=new_id(),
                    from_id=svc_id,
                    to_id=tid,
                    type="runs",
                    props={},
                    confidence=0.7,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
