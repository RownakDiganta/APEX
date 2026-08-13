# js_parser.py
# Stateless parser: STATIC extraction of referenced API endpoint path literals from a fetched JavaScript body -> endpoint nodes. Never executes/evaluates the JS. Discovery/mapping, never an attack.
"""Static API-endpoint extraction from a fetched JavaScript file (§28.24).

DISCOVERY ONLY. This parser reads literal strings present in a JS file and
records the API endpoint PATHS they reference as ``endpoint`` nodes — it NEVER
executes or evaluates the JavaScript, never deobfuscates beyond reading literal
strings, never calls the endpoints, and never constructs a request. A stateless
``str`` → ``ParsedObservation`` transform like every other parser.

What it extracts (same-origin absolute paths only — starting with ``/``):
  - ``/api`` / ``/api/v1/...`` path literals anywhere in the file,
  - ``fetch("…")`` / ``axios(…)`` URL literals,
  - ``XMLHttpRequest.open("METHOD", "…")`` URL literals,
  - ``url:``/``endpoint:``/``path:`` assignment string literals.

Cross-origin (``http(s)://``, ``//host``) and non-path literals are ignored.
Bounded at ``_MAX_JS_ENDPOINTS`` per file.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation

from apex_host.graph_ids import (
    contains_edge_id as _contains_edge_id,
    endpoint_id as _endpoint_id,
    exposes_edge_id as _exposes_edge_id,
    host_id as _host_id_fn,
)
from apex_host.parsers.command_parser import _host_from_target, _normalize_url

#: Bound on API endpoints extracted from one JS file — keeps the graph bounded
#: on a large/minified bundle. Static string extraction only.
_MAX_JS_ENDPOINTS = 40

#: ``/api`` and ``/api/…`` path literals (the dominant HTB/API convention). The
#: negative lookbehind ``(?<![\w.\-])`` rejects a ``/api`` that is the PATH of a
#: cross-origin URL (e.g. ``https://evil.com/api/x`` — the ``/api`` is preceded by
#: ``m``), so only same-origin absolute-path literals are extracted.
_API_PATH_RE = re.compile(r"(?<![\w.\-])/api(?:/[A-Za-z0-9_.\-]+)*")
#: ``fetch("…")`` / ``axios("…")`` / ``axios.get("…")`` URL literals.
_FETCH_RE = re.compile(r"""(?:fetch|axios(?:\.\w+)?)\s*\(\s*["'`]([^"'`\s]+)["'`]""")
#: ``xhr.open("GET", "…")`` URL literals.
_XHR_OPEN_RE = re.compile(r"""\.open\s*\(\s*["'`][A-Za-z]+["'`]\s*,\s*["'`]([^"'`\s]+)["'`]""")
#: ``url: "/…"`` / ``endpoint = "/…"`` / ``path:"/…"`` assignment literals.
_URL_ASSIGN_RE = re.compile(r"""(?:url|uri|endpoint|api|path)\s*[:=]\s*["'`](/[^"'`\s]+)["'`]""",
                            re.IGNORECASE)


def _same_origin_path(candidate: str) -> str:
    """Return the same-origin absolute path of *candidate* (starting with ``/``),
    or ``""`` for a cross-origin / protocol-relative / non-path literal."""
    c = candidate.strip()
    if not c or "://" in c or c.startswith("//"):
        return ""  # absolute cross-origin URL or protocol-relative — skip
    if not c.startswith("/"):
        return ""  # relative fragment / bare word — not an absolute site path
    return c.split("?")[0].split("#")[0].rstrip("/") or "/"


class JSParser:
    """Stateless parser: JavaScript body text -> ParsedObservation."""

    def parse_js(self, output: str, *, target: str, host_ip: str = "") -> ParsedObservation:
        text = output or ""
        if not text.strip():
            return ParsedObservation()

        timestamp = now()
        js_url = _normalize_url(target)
        split = urlsplit(js_url)
        base = f"{split.scheme or 'http'}://{split.netloc}"
        host = _host_from_target(host_ip) if host_ip.strip() else _host_from_target(target)
        h_id = _host_id_fn(host)
        js_id = _endpoint_id(js_url)

        # Collect candidate same-origin API paths from all patterns (dedup, order
        # preserved). Static literals only — the JS is NEVER executed.
        paths: list[str] = []
        seen: set[str] = set()

        def _add(candidate: str) -> None:
            p = _same_origin_path(candidate)
            if p and p != "/" and p not in seen and len(paths) < _MAX_JS_ENDPOINTS:
                seen.add(p)
                paths.append(p)

        for m in _API_PATH_RE.finditer(text):
            _add(m.group(0))
        for rx in (_FETCH_RE, _XHR_OPEN_RE, _URL_ASSIGN_RE):
            for m in rx.finditer(text):
                _add(m.group(1))

        # Mark the JS asset endpoint analyzed (fetched) so it is not re-fetched.
        nodes: list[Node] = [
            Node(
                id=js_id, type="endpoint",
                props={"url": js_url, "fetched": True, "js_asset": True, "js_analyzed": True},
                confidence=0.7, source="js_analysis", first_seen=timestamp, last_seen=timestamp,
            )
        ]
        edges: list[Edge] = [
            Edge(
                id=_exposes_edge_id(h_id, js_id), from_id=h_id, to_id=js_id, type="exposes",
                props={}, confidence=0.7, source="js_analysis",
                first_seen=timestamp, last_seen=timestamp,
            )
        ]
        for path in paths:
            api_url = f"{base}{path}"
            api_id = _endpoint_id(api_url)
            nodes.append(
                Node(
                    id=api_id, type="endpoint",
                    props={"url": api_url, "path": path, "referenced_by": js_url},
                    confidence=0.6, source="js_analysis",
                    first_seen=timestamp, last_seen=timestamp,
                )
            )
            # host --exposes--> api endpoint (so it is reachable in the
            # host-anchored subgraph and gets GET-fetched), and js --contains-->
            # api endpoint (provenance: this JS referenced it).
            edges.append(Edge(
                id=_exposes_edge_id(h_id, api_id), from_id=h_id, to_id=api_id, type="exposes",
                props={}, confidence=0.6, source="js_analysis",
                first_seen=timestamp, last_seen=timestamp,
            ))
            edges.append(Edge(
                id=_contains_edge_id(js_id, api_id), from_id=js_id, to_id=api_id, type="contains",
                props={}, confidence=0.6, source="js_analysis",
                first_seen=timestamp, last_seen=timestamp,
            ))
        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
