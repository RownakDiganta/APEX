# command_parser.py
# Stateless parser for curl HTTP headers and generic command fallback — never silently drops non-empty tool output.
"""Parser for curl -I HTTP header output and generic command fallback.

Implements memfabric.coordination.protocols.Parser.

Dispatch logic inside ``parse()``:
  source == "curl" and output starts with "HTTP/" → parse HTTP headers into
    Endpoint + Tech EKG nodes.
  Anything else → single low-confidence KnowledgeEntry staged for Reflector
    promotion so non-empty output is never silently dropped.
"""
from __future__ import annotations

import re
from typing import Any

from memfabric.ids import now
from memfabric.types import Edge, KnowledgeEntry, Node, ParsedObservation, RawObservation
from apex_host.graph_ids import (
    host_id as _host_id_fn,
    endpoint_id as _endpoint_id,
    tech_id as _tech_id_fn,
    exposes_edge_id,
    runs_edge_id,
    contains_edge_id,
)

_HTTP_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(?P<code>\d{3})")
_HEADER_LINE_RE = re.compile(r"^(?P<name>[A-Za-z-]+):\s*(?P<value>.+)$")
_SERVER_PRODUCT_RE = re.compile(r"^(?P<product>[A-Za-z][^\s/(]*)(?:/(?P<version>[\d.]+))?")


def _host_from_target(target: str) -> str:
    """Strip scheme and path from target to get the bare host."""
    return target.split("//")[-1].split("/")[0]


def _normalize_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


class CommandParser:
    """Stateless parser: RawObservation -> ParsedObservation.

    Handles curl HTTP headers structurally; wraps everything else as a
    low-confidence KnowledgeEntry so output is never silently dropped.
    """

    def parse(self, raw: RawObservation) -> ParsedObservation:
        text = raw.raw.strip()
        if not text:
            return ParsedObservation()

        source = str(raw.metadata.get("source", "command"))
        target = str(raw.metadata.get("target", ""))

        if source == "curl" and text.startswith("HTTP/"):
            return self._parse_curl_headers(text, target=target, source=source)

        return self._fallback_knowledge(text, raw=raw, source=source)

    # ------------------------------------------------------------------
    # curl -I / --head response header parsing
    # ------------------------------------------------------------------

    def _parse_curl_headers(
        self, text: str, *, target: str, source: str
    ) -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()

        lines = text.splitlines()
        status_code = ""
        headers: dict[str, str] = {}

        if lines:
            m = _HTTP_STATUS_RE.match(lines[0].strip())
            if m:
                status_code = m.group("code")
        for line in lines[1:]:
            hm = _HEADER_LINE_RE.match(line.strip())
            if hm:
                # Last-seen wins for duplicate headers
                headers[hm.group("name").lower()] = hm.group("value").strip()

        url = _normalize_url(target)
        host = _host_from_target(target)
        h_id = _host_id_fn(host)
        ep_id = _endpoint_id(url)

        nodes.append(
            Node(
                id=ep_id,
                type="endpoint",
                props={
                    "url": url,
                    "status": status_code,
                    "content_type": headers.get("content-type", ""),
                    "server": headers.get("server", ""),
                },
                confidence=0.85,
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
                confidence=0.85,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )

        server_hdr = headers.get("server", "")
        if server_hdr:
            sm = _SERVER_PRODUCT_RE.match(server_hdr)
            if sm:
                product = sm.group("product").strip()
                version = sm.group("version") or ""
                t_id = _tech_id_fn(host, product)
                nodes.append(
                    Node(
                        id=t_id,
                        type="tech",
                        props={"name": product, "version": version, "source_header": "server"},
                        confidence=0.8,
                        source=source,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )
                edges.append(
                    Edge(
                        id=runs_edge_id(ep_id, t_id),
                        from_id=ep_id,
                        to_id=t_id,
                        type="runs",
                        props={},
                        confidence=0.8,
                        source=source,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)

    # ------------------------------------------------------------------
    # curl body (GET response) parsing — title + relative links
    # ------------------------------------------------------------------

    def parse_curl_body(self, raw: RawObservation) -> ParsedObservation:
        """Parse a ``curl -s <url>`` body response.

        Extracts the HTML ``<title>`` and relative ``href`` links (paths
        starting with ``/``) and represents them as ``endpoint`` nodes.
        Non-HTML responses fall back to ``_fallback_knowledge``.

        At most 20 link endpoint nodes are created per call to stay bounded.
        """
        text = raw.raw.strip()
        if not text:
            return ParsedObservation()

        source = str(raw.metadata.get("source", "curl_body"))
        target = str(raw.metadata.get("target", ""))

        lower = text.lower()
        if "<html" not in lower and "<!doctype" not in lower and "<title" not in lower:
            return self._fallback_knowledge(text, raw=raw, source=source)

        timestamp = now()
        url = _normalize_url(target)
        host = _host_from_target(target)
        h_id = _host_id_fn(host)
        ep_id = _endpoint_id(url)

        # Extract page title
        title = ""
        tm = re.search(r"<title[^>]*>([^<]{1,300})</title>", text, re.IGNORECASE)
        if tm:
            title = " ".join(tm.group(1).split())

        nodes: list[Node] = [
            Node(
                id=ep_id,
                type="endpoint",
                props={"url": url, "title": title},
                confidence=0.75,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        ]
        edges: list[Edge] = [
            Edge(
                id=exposes_edge_id(h_id, ep_id),
                from_id=h_id,
                to_id=ep_id,
                type="exposes",
                props={},
                confidence=0.75,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        ]

        # Extract relative-path hrefs (skip external URLs and anchors)
        seen_paths: set[str] = set()
        for m in re.finditer(r"""href=["']([^"'#?]+)["']""", text, re.IGNORECASE):
            href = m.group(1).strip()
            if href.startswith("http://") or href.startswith("https://"):
                continue
            if not href.startswith("/"):
                continue
            path = href.split("?")[0].rstrip("/") or "/"
            if path in seen_paths or path == "/":
                continue
            seen_paths.add(path)
            if len(seen_paths) > 20:
                break
            link_url = f"{url.rstrip('/')}{path}"
            lnk_id = _endpoint_id(link_url)
            nodes.append(
                Node(
                    id=lnk_id,
                    type="endpoint",
                    props={"url": link_url, "path": path},
                    confidence=0.5,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=contains_edge_id(ep_id, lnk_id),
                    from_id=ep_id,
                    to_id=lnk_id,
                    type="contains",
                    props={},
                    confidence=0.5,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)

    # ------------------------------------------------------------------
    # Fallback: stage as KnowledgeEntry for Reflector
    # ------------------------------------------------------------------

    def _fallback_knowledge(
        self, text: str, *, raw: RawObservation, source: str
    ) -> ParsedObservation:
        entry = KnowledgeEntry(
            text=text[:2000],
            source=source,
            confidence=0.3,
            timestamp=now(),
            metadata={**raw.metadata, "tier": "semantic", "kind": "raw_command_output"},
        )
        return ParsedObservation(proposed_knowledge=[entry])
