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

import ipaddress
import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from memfabric.ids import now
from memfabric.types import Edge, KnowledgeEntry, Node, ParsedObservation, RawObservation
from apex_host.graph_ids import (
    host_id as _host_id_fn,
    endpoint_id as _endpoint_id,
    service_id as _service_id_fn,
    tech_id as _tech_id_fn,
    vhost_id as _vhost_id_fn,
    exposes_edge_id,
    runs_edge_id,
    contains_edge_id,
)

_HTTP_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(?P<code>\d{3})")
_HEADER_LINE_RE = re.compile(r"^(?P<name>[A-Za-z-]+):\s*(?P<value>.+)$")
_SERVER_PRODUCT_RE = re.compile(r"^(?P<product>[A-Za-z][^\s/(]*)(?:/(?P<version>[\d.]+))?")

#: Default TCP port per URL scheme, used to record the HTTP service a
#: successful curl fetch proves is live.
_SCHEME_DEFAULT_PORT = {"http": "80", "https": "443"}

#: Bound on the number of JSON top-level key NAMES recorded per API response
#: (§28.22) — structure mapping only, keeps the endpoint node bounded.
_MAX_JSON_KEYS = 40
#: Bound on HTML forms extracted from one page (§28.34-forms) and input-field
#: NAMES recorded per form — keeps the graph bounded. Field NAMES only (never
#: values); a form is discovery, never a submission.
_MAX_FORMS = 10
_MAX_FORM_FIELDS = 30


class _FormExtractor(HTMLParser):
    """Stdlib HTML form extractor: collects each ``<form>``'s ``action``/
    ``method`` and its input/select/textarea field NAMES. Read-only — never
    executes anything, never submits. NAMES only, never values."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, object]] = []
        self._cur: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method", "get") or "get").upper(),
                         "fields": []}
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            name = a.get("name", "").strip()
            fields = self._cur["fields"]
            if name and isinstance(fields, list) and len(fields) < _MAX_FORM_FIELDS:
                fields.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            if len(self.forms) < _MAX_FORMS:
                self.forms.append(self._cur)
            self._cur = None


def _extract_forms(html: str) -> list[dict[str, object]]:
    """Return each ``<form>``'s action/method/field-names from *html*. Never
    raises (a malformed document yields whatever was parsed so far)."""
    ex = _FormExtractor()
    try:
        ex.feed(html)
    except (AssertionError, ValueError):
        pass
    if ex._cur is not None and len(ex.forms) < _MAX_FORMS:  # unclosed final form
        ex.forms.append(ex._cur)
    return ex.forms

#: Bound on <script src> JS assets recorded per HTML page (§28.24).
_MAX_JS_ASSETS = 15

#: A syntactically valid DNS hostname (one or more dot-separated labels, at
#: least one dot so a bare word is not treated as a vhost). Deliberately strict
#: so a malformed/dangerous Location value never becomes a vhost that later
#: reaches curl. Contains no shell metacharacters by construction.
_VALID_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _redirect_vhost(location: str, target_host: str) -> str | None:
    """Extract a NEW virtual-host name from a redirect ``Location`` value.

    Returns a validated, lowercased hostname when *location* points at a
    hostname distinct from *target_host* (the IP/host being probed); ``None``
    for a same-host redirect, an IP→IP redirect, a bare-word/malformed host, or
    a relative Location (no host). This is what turns the demonstrated
    ``301 → Location: http://<vhost>/`` into a discovered vhost — the vhost is
    always DISCOVERED here, never hardcoded."""
    loc = (location or "").strip()
    if not loc:
        return None
    try:
        split = urlsplit(loc)
    except ValueError:
        return None
    host = (split.hostname or "").strip().rstrip(".").lower()
    if not host:
        return None  # relative redirect (e.g. "/login") — no new host
    tgt = target_host.strip().rstrip(".").lower()
    if host == tgt:
        return None  # same host — not a vhost
    if _is_ip_literal(host):
        return None  # an IP→IP redirect is not a name-based vhost
    if not _VALID_HOSTNAME_RE.match(host):
        return None  # malformed / single-label — never record as a vhost
    return host


def _host_from_target(target: str) -> str:
    """Return the bare host of *target* — scheme, port, and path all stripped.

    A service/host node is keyed on the bare host (``10.129.40.164``), never a
    URL or ``host:port`` string: ``_service_id(host, port)`` and ``_host_id(host)``
    must receive a clean host so the id is canonical
    (``service:10.129.40.164:80/tcp``) and dedups against the nmap-discovered
    service. Handles ``http://h``, ``http://h:8080/p``, bare ``h``, ``h:8080``,
    and bracketed IPv6 (``http://[::1]:80/``)."""
    t = target.strip()
    if "://" in t:
        host = urlsplit(t).hostname
        if host:
            return host
    # Bare host (possibly host:port or host/path, no scheme).
    t = t.split("//")[-1].split("/")[0]
    if t.startswith("["):  # bracketed IPv6 literal, optionally with :port
        return t[1:].split("]")[0]
    head, sep, tail = t.rpartition(":")
    if sep and tail.isdigit():  # strip a trailing numeric :port
        return head
    return t


def _normalize_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def _resolve_same_origin_url(page_url: str, value: str, page_host: str) -> str | None:
    """Resolve a ``src``/``href`` *value* found on the page at *page_url* to an
    absolute, same-origin URL — or ``None`` if empty, cross-origin,
    protocol-relative, ``data:``, an anchor, a credential URL, or a non-http(s)
    scheme.

    A ROOT-ABSOLUTE value (``/js/x``) resolves against the SCHEME+HOST root
    (``http://h/js/x``); a BARE-RELATIVE value (``sub/x``) against the page's
    DIRECTORY (``/invite/`` → ``/invite/sub/x``); a same-origin FULL URL is used
    as-is. Uses :func:`urllib.parse.urljoin` so ``/js/inviteapi.min.js`` on
    ``http://h/invite`` becomes ``http://h/js/inviteapi.min.js`` (host-root),
    not ``http://h/invite/js/...`` — the pre-fix directory-relative bug (§28.25).
    """
    v = (value or "").strip()
    if not v or v.startswith("data:") or v.startswith("//") or v.startswith("#"):
        return None
    # A trailing slash makes urljoin treat the page path as a DIRECTORY, so a
    # bare-relative "sub/x" on /invite resolves to /invite/sub/x; a root-absolute
    # "/js/x" ignores the base path and resolves against the host root regardless.
    base = page_url if page_url.endswith("/") else page_url + "/"
    try:
        split = urlsplit(urljoin(base, v))
    except ValueError:
        return None
    if split.scheme not in ("http", "https"):
        return None
    if split.username is not None or split.password is not None:
        return None  # never follow a credential-bearing URL
    host = (split.hostname or "").lower()
    if not host or host != page_host.lower():
        return None  # cross-origin — out of scope
    port = f":{split.port}" if split.port else ""
    path = (split.path or "/").rstrip("/") or "/"
    return f"{split.scheme}://{split.hostname}{port}{path}"


def _http_service_from_url(
    url: str, host: str, *, source: str, timestamp: str, confidence: float, version: str = "",
) -> tuple[Node, Edge]:
    """Build the ``service`` node (+ host→service ``exposes`` edge) a successful
    HTTP fetch proves is live.

    Recorded ONLY on a real HTTP response (both callers gate on one — a parsed
    ``HTTP/`` status line, or a returned HTML body); never fabricated. The port
    is the URL's explicit port, else the scheme default (80/443). Same node
    shape as ``NmapParser``'s service nodes so capability derivation and the
    recon "service discovered" criterion treat it identically."""
    split = urlsplit(url)
    scheme = (split.scheme or "http").lower()
    port = str(split.port) if split.port is not None else _SCHEME_DEFAULT_PORT.get(scheme, "80")
    h_id = _host_id_fn(host)
    svc_id = _service_id_fn(host, port, "tcp")
    service_node = Node(
        id=svc_id,
        type="service",
        props={
            "port": port,
            "proto": "tcp",
            "state": "open",
            "service": scheme,  # "http" / "https"
            "target": host,
            "version": version,
        },
        confidence=confidence,
        source=source,
        first_seen=timestamp,
        last_seen=timestamp,
    )
    exposes = Edge(
        id=exposes_edge_id(h_id, svc_id),
        from_id=h_id,
        to_id=svc_id,
        type="exposes",
        props={},
        confidence=confidence,
        source=source,
        first_seen=timestamp,
        last_seen=timestamp,
    )
    return service_node, exposes


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
        host_ip = str(raw.metadata.get("host_ip", ""))

        if source == "curl" and text.startswith("HTTP/"):
            return self._parse_curl_headers(text, target=target, source=source, host_ip=host_ip)

        return self._fallback_knowledge(text, raw=raw, source=source)

    # ------------------------------------------------------------------
    # curl -I / --head response header parsing
    # ------------------------------------------------------------------

    def _parse_curl_headers(
        self, text: str, *, target: str, source: str, host_ip: str = ""
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
        url_host = _host_from_target(target)
        # ``host`` is the node the exposes edges attach to (the AUTHORIZED host
        # node, which already exists), while the endpoint URL keeps the fetched
        # host. For a Host-aware vhost fetch (target = the vhost URL) the
        # supplied ``host_ip`` is the real IP host node, so the endpoint/service
        # link to the existing host instead of a non-existent ``host:<vhost>``
        # (which would dangle and roll back the batch). Absent host_ip (every
        # existing caller), this is the URL host — byte-for-byte unchanged.
        host = _host_from_target(host_ip) if host_ip.strip() else url_host
        h_id = _host_id_fn(host)
        ep_id = _endpoint_id(url)

        nodes.append(
            Node(
                id=ep_id,
                type="endpoint",
                props={
                    "url": url,
                    "status": status_code,
                    # A parsed HTTP status line means this endpoint was
                    # successfully fetched over HTTP — the web-evidence gate
                    # (phase_gates._has_web_content) counts a fetched endpoint.
                    "fetched": True,
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

        # A successful HTTP response proves a live HTTP service — record it so
        # recon's "no services discovered" termination does not fire when a web
        # server was proven by curl. Only when a real status line was parsed.
        if status_code.isdigit():
            server_product = ""
            sm0 = _SERVER_PRODUCT_RE.match(headers.get("server", ""))
            if sm0 and sm0.group("version"):
                server_product = sm0.group("version")
            svc_node, svc_edge = _http_service_from_url(
                url, host, source=source, timestamp=timestamp, confidence=0.8,
                version=server_product,
            )
            nodes.append(svc_node)
            edges.append(svc_edge)

        # A 3xx redirect to a NEW hostname reveals a name-based virtual host —
        # the real app nginx serves only under that vhost, while the bare IP
        # returns an empty 301. Record the DISCOVERED vhost (never hardcoded) so
        # the web executor can re-fetch with the correct Host. Recorded only for
        # a genuine cross-host redirect (see _redirect_vhost).
        if status_code.startswith("3"):
            # Compare the redirect against the FETCHED host (url_host) so a
            # vhost fetch redirecting to its own paths is not re-recorded.
            vhost = _redirect_vhost(headers.get("location", ""), url_host)
            if vhost is not None:
                v_id = _vhost_id_fn(host, vhost)
                nodes.append(
                    Node(
                        id=v_id,
                        type="vhost",
                        props={
                            "hostname": vhost,
                            "ip": host,
                            "discovered_from": "http_redirect",
                            "source_status": status_code,
                        },
                        confidence=0.8,
                        source=source,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )
                edges.append(
                    Edge(
                        id=exposes_edge_id(h_id, v_id),
                        from_id=h_id,
                        to_id=v_id,
                        type="exposes",
                        props={},
                        confidence=0.8,
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
        host_ip = str(raw.metadata.get("host_ip", ""))

        # §28.22 — a JSON API response (body starts with '{' or '[') is mapped to
        # an ``endpoint`` node recording its STRUCTURE (top-level key names only,
        # never values), so the planner sees the API surface. DISCOVERY ONLY.
        if text.lstrip()[:1] in ("{", "["):
            json_obs = self._try_json_body(text, target=target, host_ip=host_ip, source=source)
            if json_obs is not None:
                return json_obs

        lower = text.lower()
        if "<html" not in lower and "<!doctype" not in lower and "<title" not in lower:
            return self._fallback_knowledge(text, raw=raw, source=source)

        timestamp = now()
        url = _normalize_url(target)
        # See _parse_curl_headers: exposes edges attach to the AUTHORIZED host
        # node (host_ip when a vhost fetch supplies it), while endpoint URLs
        # keep the fetched (vhost) host so relative links resolve correctly.
        host = _host_from_target(host_ip) if host_ip.strip() else _host_from_target(target)
        # The same-origin check for links/scripts uses the FETCHED page's host
        # (e.g. the vhost 2million.htb), NOT the authorized EKG host (the IP) —
        # otherwise every vhost-relative link/script is wrongly rejected.
        page_host = _host_from_target(target)
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
                # A returned HTML body is a successful HTTP fetch, even though a
                # GET body carries no status line — mark it fetched so the
                # web-evidence gate counts it (phase_gates._has_web_content).
                props={"url": url, "title": title, "fetched": True},
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

        # A returned HTML body proves a live HTTP service — record it so recon's
        # "no services discovered" termination does not fire when a web server
        # was proven by curl. Only reached when the HTML-content gate above
        # matched a real response (never on a blank/failed request).
        svc_node, svc_edge = _http_service_from_url(
            url, host, source=source, timestamp=timestamp, confidence=0.7,
        )
        nodes.append(svc_node)
        edges.append(svc_edge)

        # Extract same-origin links (href) as endpoint nodes. §28.25 — resolve
        # each href against the fetched page URL so a root-absolute "/foo" on
        # /invite resolves to the HOST ROOT (http://h/foo), not the page dir;
        # a bare-relative "sub" resolves against the page dir; cross-origin,
        # anchors, and non-http schemes are rejected by _resolve_same_origin_url.
        seen_links: set[str] = set()
        for m in re.finditer(r"""href=["']([^"'#?]+)["']""", text, re.IGNORECASE):
            link_url = _resolve_same_origin_url(url, m.group(1), page_host)
            if link_url is None or link_url == url.rstrip("/"):
                continue
            path = urlsplit(link_url).path or "/"
            if path == "/" or link_url in seen_links:
                continue
            seen_links.add(link_url)
            if len(seen_links) > 20:
                break
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
            # §28.32 — ALSO attach the discovered link to the AUTHORIZED host
            # (host --exposes--> link), mirroring js_parser (§28.24) and
            # ffuf/gobuster (§28.12). This keeps the endpoint at DEPTH 1 in the
            # host-anchored subgraph, so a link found on a deep page (homepage →
            # /invite → link) stays visible to the depth-bounded planner
            # subgraph regardless of how deep the discovery chain grows. Without
            # it the link's depth tracks the chain length and can exceed the
            # planner's retrieval depth while the (deeper) phase gate still sees
            # it — the exact mismatch that stalled the web phase on endpoints the
            # planner could not fetch. The `contains` edge above preserves which
            # page referenced it (provenance).
            edges.append(
                Edge(
                    id=exposes_edge_id(h_id, lnk_id),
                    from_id=h_id,
                    to_id=lnk_id,
                    type="exposes",
                    props={},
                    confidence=0.5,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

        # §28.24 — extract <script src> JS assets (same-origin only) so the web
        # planner can FETCH them and statically extract API-endpoint references
        # (e.g. /invite's inviteapi.min.js → /api/v1/...). Recorded as
        # discovered-but-unfetched endpoint nodes marked js_asset=True. DISCOVERY
        # ONLY — the JS is fetched and read, never executed.
        seen_js: set[str] = set()
        for m in re.finditer(r"""<script[^>]*\bsrc=["']([^"'#?]+)["']""", text, re.IGNORECASE):
            js_url = _resolve_same_origin_url(url, m.group(1), page_host)
            if js_url is None or js_url in seen_js:
                continue
            seen_js.add(js_url)
            if len(seen_js) > _MAX_JS_ASSETS:
                break
            js_path = urlsplit(js_url).path or "/"
            js_ep_id = _endpoint_id(js_url)
            nodes.append(
                Node(
                    id=js_ep_id, type="endpoint",
                    props={"url": js_url, "path": js_path, "js_asset": True},
                    confidence=0.5, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=contains_edge_id(ep_id, js_ep_id), from_id=ep_id, to_id=js_ep_id,
                    type="contains", props={}, confidence=0.5, source=source,
                    first_seen=timestamp, last_seen=timestamp,
                )
            )
            # §28.32 — host --exposes--> js_asset (DEPTH 1), same reachability
            # fix as the discovered-link edge above. A JS asset referenced from a
            # deep page (e.g. /invite's inviteapi.min.js at depth 3) must stay
            # visible to the depth-bounded planner so it is fetched + statically
            # parsed for API endpoints; otherwise the phase gate marks the web
            # phase incomplete on a JS asset the planner cannot see and the
            # engagement duplicate-stalls.
            edges.append(
                Edge(
                    id=exposes_edge_id(h_id, js_ep_id), from_id=h_id, to_id=js_ep_id,
                    type="exposes", props={}, confidence=0.5, source=source,
                    first_seen=timestamp, last_seen=timestamp,
                )
            )

        # §28.36 — extract <form action> submission endpoints (same-origin). A
        # form's action is often the REAL registration/login POST endpoint (the
        # one an operator would otherwise have to guess), so record it as an
        # endpoint (source html_form) with its method + input-field NAMES. A
        # self-submitting form (empty/same-URL action) is skipped — the page
        # endpoint already covers it. DISCOVERY ONLY — the form is read, never
        # submitted; NAMES only, never values.
        seen_forms: set[str] = set()
        for form in _extract_forms(text):
            action = str(form.get("action", "")).strip()
            if not action:
                continue
            form_url = _resolve_same_origin_url(url, action, page_host)
            if not form_url or form_url == url or form_url in seen_forms:
                continue
            seen_forms.add(form_url)
            method = str(form.get("method", "GET")).upper()
            raw_fields = form.get("form_fields") or form.get("fields") or []
            fields = [str(f) for f in raw_fields][:_MAX_FORM_FIELDS] if isinstance(raw_fields, list) else []
            form_ep_id = _endpoint_id(form_url)
            nodes.append(Node(
                id=form_ep_id, type="endpoint",
                props={"url": form_url, "path": urlsplit(form_url).path or "/",
                       "method": method, "form_action": True, "form_fields": fields},
                confidence=0.6, source="html_form",
                first_seen=timestamp, last_seen=timestamp,
            ))
            edges.append(Edge(
                id=exposes_edge_id(h_id, form_ep_id), from_id=h_id, to_id=form_ep_id,
                type="exposes", props={}, confidence=0.6, source="html_form",
                first_seen=timestamp, last_seen=timestamp,
            ))

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)

    # ------------------------------------------------------------------
    # JSON API response body — structure mapping only (§28.22)
    # ------------------------------------------------------------------

    def _try_json_body(
        self, text: str, *, target: str, host_ip: str, source: str
    ) -> ParsedObservation | None:
        """Map a JSON API response to an ``endpoint`` node recording its STRUCTURE.

        Records only the top-level key NAMES (a dict's keys, or the keys of a
        list's first object element) — never any value, so no secret/data ever
        enters the graph. Returns ``None`` when the body is not valid JSON (the
        caller then falls through to the HTML/fallback path). Bounded: at most
        ``_MAX_JSON_KEYS`` key names are recorded."""
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None

        timestamp = now()
        url = _normalize_url(target)
        host = _host_from_target(host_ip) if host_ip.strip() else _host_from_target(target)
        h_id = _host_id_fn(host)
        ep_id = _endpoint_id(url)

        props: dict[str, object] = {
            "url": url,
            "fetched": True,
            "content_kind": "json",
            "api_response": True,
        }
        if isinstance(data, dict):
            props["json_keys"] = sorted(str(k) for k in list(data.keys())[:_MAX_JSON_KEYS])
        elif isinstance(data, list):
            props["json_array"] = True
            if data and isinstance(data[0], dict):
                props["json_item_keys"] = sorted(
                    str(k) for k in list(data[0].keys())[:_MAX_JSON_KEYS]
                )

        nodes: list[Node] = [
            Node(
                id=ep_id, type="endpoint", props=props, confidence=0.75,
                source=source, first_seen=timestamp, last_seen=timestamp,
            )
        ]
        edges: list[Edge] = [
            Edge(
                id=exposes_edge_id(h_id, ep_id), from_id=h_id, to_id=ep_id,
                type="exposes", props={}, confidence=0.75, source=source,
                first_seen=timestamp, last_seen=timestamp,
            )
        ]
        # A JSON API response proves a live HTTP service (same as an HTML body).
        svc_node, svc_edge = _http_service_from_url(
            url, host, source=source, timestamp=timestamp, confidence=0.7,
        )
        nodes.append(svc_node)
        edges.append(svc_edge)
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
