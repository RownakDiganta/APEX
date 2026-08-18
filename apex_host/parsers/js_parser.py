# js_parser.py
# Stateless parser: STATIC extraction of referenced API endpoint path literals from a fetched JavaScript body -> endpoint nodes. Never executes/evaluates the JS. Discovery/mapping, never an attack.
"""Static API-endpoint extraction from a fetched JavaScript file (§28.24).

DISCOVERY ONLY. This parser reads literal strings present in a JS file and
records the API endpoint PATHS they reference as ``endpoint`` nodes — it NEVER
executes or evaluates the JavaScript, never calls the endpoints, and never
constructs a request. A stateless ``str`` → ``ParsedObservation`` transform like
every other parser.

§28.33 — the Dean Edwards ``eval(function(p,a,c,k,e,d){…})`` packer is first
un-packed by ``js_unpack.unpack_payloads``, a GENERIC transform that reimplements
the packer's own base-N word substitution as pure string manipulation (no
``eval``, no JS engine, no machine-specific map — the revealed strings come from
the packed input's OWN keyword array). This still never executes the JS; it turns
an encoded literal back into the literal it encodes (like base64-decoding) so the
same static extractors below can read the API paths hidden inside.

What it extracts (same-origin paths only — a leading ``/`` path or a same-origin
full URL reduced to its path):
  - ``/api`` / ``/api/v1/...`` path literals anywhere in the file,
  - ``fetch("…")`` / ``axios(…)`` URL literals,
  - ``XMLHttpRequest.open("METHOD", "…")`` URL literals,
  - jQuery ``$.ajax({… url: "…" …})`` / ``$.get("…")`` / ``$.post("…")`` /
    ``$.getJSON("…")`` / ``$.load("…")`` URL literals (§28.26),
  - ``url:``/``endpoint:``/``path:`` assignment string literals.

Cross-origin (a different host) and non-path literals are ignored. A same-origin
full URL (``http://<same-host>/api/x``) is reduced to its path. All resolution
goes through the SINGLE shared ``command_parser._resolve_same_origin_url``
(urljoin — a leading ``/`` always resolves to the host root), §28.27. A body that
is NOT JavaScript (an HTML page served for a missing ``.js`` — it begins with
``<``) is never JS-parsed and spawns no references (§28.27). Bounded at
``_MAX_JS_ENDPOINTS`` per file.
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
from apex_host.parsers.command_parser import (
    _host_from_target,
    _normalize_url,
    _resolve_same_origin_url,
)
from apex_host.parsers.js_unpack import is_packed, unpack_payloads

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
#: jQuery ``$.get("…")`` / ``$.post("…")`` / ``$.getJSON("…")`` / ``$.load("…")``
#: / positional ``$.ajax("…")`` URL literals (§28.26). ``$.ajax({url:"…"})`` (the
#: options-object form) is handled by _URL_ASSIGN_RE via its ``url:`` key. Static
#: literal read only — the JS is never executed.
_JQUERY_RE = re.compile(
    r"""\$(?:\.(?:get|post|getJSON|ajax|load))\s*\(\s*["'`]([^"'`\s]+)["'`]""")
#: ``url: "…"`` / ``endpoint = "…"`` / ``path:"…"`` assignment literals. The value
#: is resolved by the SHARED _resolve_same_origin_url (leading-/ path → host root,
#: or a same-origin full URL as-is — cross-origin and bare words rejected), §28.27.
_URL_ASSIGN_RE = re.compile(r"""(?:url|uri|endpoint|api|path)\s*[:=]\s*["'`]([^"'`\s]+)["'`]""",
                            re.IGNORECASE)


class JSParser:
    """Stateless parser: JavaScript body text -> ParsedObservation."""

    def parse_js(self, output: str, *, target: str, host_ip: str = "") -> ParsedObservation:
        text = output or ""
        if not text.strip():
            return ParsedObservation()

        timestamp = now()
        js_url = _normalize_url(target)
        host = _host_from_target(host_ip) if host_ip.strip() else _host_from_target(target)
        h_id = _host_id_fn(host)
        js_id = _endpoint_id(js_url)
        # Same-origin resolution uses the FETCHED JS file's own url as the base and
        # its own host (the vhost, from target) — NOT the authorized EKG host (IP).
        page_host = _host_from_target(target)

        # §28.27 — a JS-asset URL that returns an HTML body (e.g. nginx served the
        # SPA index for a missing .js) is NOT JavaScript: do NOT run the static
        # extractor and do NOT resolve any references from it (that produced the
        # live compound-garbage URLs). Record only that the asset was fetched so it
        # is not re-fetched. A JavaScript body never begins with '<'.
        is_js = not text.lstrip().startswith("<")

        # Collect referenced same-origin API URLs (absolute, dedup, order-preserved)
        # via the SINGLE shared resolver (§28.27) — a leading-/ path resolves to the
        # HOST ROOT, a same-origin full URL is used as-is, cross-origin/bare-relative
        # is rejected. Static literals only — the JS is NEVER executed.
        urls: list[str] = []
        seen: set[str] = set()

        def _add(candidate: str) -> None:
            c = candidate.strip()
            # Only a leading-/ path or a full URL is an unambiguous reference; a
            # bare-relative word in a JS body is not treated as a URL (avoids
            # resolving it against the JS-file directory and producing garbage).
            if not (c.startswith("/") or "://" in c):
                return
            resolved = _resolve_same_origin_url(js_url, c, page_host)
            if resolved is None or urlsplit(resolved).path in ("", "/"):
                return
            if resolved not in seen and len(urls) < _MAX_JS_ENDPOINTS:
                seen.add(resolved)
                urls.append(resolved)

        # §28.33 — reveal strings hidden by the Dean Edwards p,a,c,k,e,d packer
        # WITHOUT executing the JS. `unpack_payloads` reimplements the packer's
        # own base-N word-substitution as a pure string transform (no eval, no JS
        # engine, no machine-specific map — the revealed strings come from the
        # packed input's OWN keyword array). The unpacked payloads are appended to
        # the extraction text so the SAME static regexes below read the now-visible
        # /api/... path literals. HTML-served-as-JS (is_js False, §28.27) is never
        # unpacked. Still DISCOVERY ONLY — the JS is read, never executed.
        deobfuscated = False
        extraction_text = text
        if is_js and is_packed(text):
            unpacked = unpack_payloads(text)
            if unpacked:
                deobfuscated = True
                extraction_text = text + "\n" + "\n".join(unpacked)

        if is_js:
            for m in _API_PATH_RE.finditer(extraction_text):
                _add(m.group(0))
            for rx in (_FETCH_RE, _XHR_OPEN_RE, _JQUERY_RE, _URL_ASSIGN_RE):
                for m in rx.finditer(extraction_text):
                    _add(m.group(1))

        # Mark the JS asset endpoint analyzed (fetched) so it is not re-fetched.
        js_props: dict[str, object] = {
            "url": js_url, "fetched": True, "js_asset": True, "js_analyzed": True,
        }
        if deobfuscated:
            js_props["js_deobfuscated"] = True
        nodes: list[Node] = [
            Node(
                id=js_id, type="endpoint",
                props=js_props,
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
        for api_url in urls:
            api_path = urlsplit(api_url).path or "/"
            api_id = _endpoint_id(api_url)
            nodes.append(
                Node(
                    id=api_id, type="endpoint",
                    props={"url": api_url, "path": api_path, "referenced_by": js_url},
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
