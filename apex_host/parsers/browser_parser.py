# browser_parser.py
# Stateless parser that converts a BrowserObservation into Endpoint, Form, AuthFlow, Token, Tech, and WebOpportunity EKG node/edge deltas.
"""Parses a BrowserObservation (real or synthetic, dry_run-aware) into
memfabric Node/Edge deltas — Endpoint, Form, AuthFlow, Token, Tech, and
WebOpportunity nodes.

Phase 14 additions (all additive on top of the existing Endpoint/Form/
AuthFlow/Token behavior — see docs/web-planning.md for the full design):

- The endpoint node for ``obs.url`` is marked ``browsed=True`` — this is
  the "session model" signal ``BrowserPlanner``
  (``apex_host/planners/browser_planner.py``) reads to never revisit an
  identical page. Endpoint nodes created for *discovered but not yet
  browsed* links (from ``obs.links``) are left ``browsed=False``.
- ``form`` nodes gain ``is_login``/``is_upload``/``is_search``/``has_csrf``
  boolean props derived from each field's ``type`` (when the executor
  supplied ``field_types``) or, when absent, the same name-based heuristic
  already used for password-field detection — never regressing older
  callers that only ever pass bare field names.
- ``tech`` nodes are created via deterministic detection
  (``apex_host/parsers/tech_detector.py``) over headers/HTML/URL — no
  fingerprinting tool, no additional request.
- ``web_opportunity`` nodes are derived from the parsed facts (login form,
  admin-like URL, upload/search form, directory listing, API-like URL,
  backup-file-like link, robots.txt Disallow entries, known default install
  pages) — non-executable planning records only, mirroring
  ``apex_host/parsers/priv_esc_parser.py``'s opportunity-derivation style.

Nothing in this module executes a form submission, injects a payload, or
performs SQL injection/XSS/CSRF of any kind — it only reasons about
already-observed structure.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any

from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation

from apex_host.types import BrowserObservation, OpportunityConfidence, WebOpportunityCategory
from apex_host.graph_ids import (
    host_id as _host_id_fn,
    endpoint_id as _endpoint_id,
    form_id as _form_id,
    auth_flow_form_id,
    auth_flow_hint_id,
    token_id as _token_id,
    tech_id as _tech_id_fn,
    web_opportunity_id,
    contains_edge_id,
    requires_edge_id,
    runs_edge_id,
    indicates_edge_id,
    exposes_edge_id,
)
from apex_host.parsers.tech_detector import detect_technologies

_PASSWORD_FIELD_HINTS = ("pass", "pwd", "secret")
_UPLOAD_FIELD_HINTS = ("file", "upload", "attachment")
_SEARCH_FIELD_HINTS = ("search", "query", "q")
_CSRF_FIELD_RE = re.compile(r"csrf|token|nonce|_token|authenticity_token", re.IGNORECASE)

# Bounded caps — mirrors CommandParser.parse_curl_body's 20-link cap and
# PrivEscParser's excerpt/list bounds (never let a single page visit blow
# up the EKG).
_MAX_LINK_ENDPOINTS = 20
_MAX_ROBOTS_ENTRIES = 10
_MAX_EXCERPT_CHARS = 200

# Only these header names are ever copied onto an endpoint node's
# ``headers`` prop — Set-Cookie and any other header that could carry a
# session/secret value is deliberately excluded (technology detection reads
# the raw headers dict transiently but never persists it verbatim).
_SAFE_HEADER_ALLOWLIST: tuple[str, ...] = (
    "server", "x-powered-by", "content-type", "x-aspnet-version", "x-generator",
)

_ADMIN_URL_RE = re.compile(r"/(admin|administrator|wp-admin|manage|dashboard|cpanel)(/|$|\?)", re.IGNORECASE)
_API_URL_RE = re.compile(r"/(api|v1|v2|graphql)(/|$|\?)|\.json(\?|$)", re.IGNORECASE)
_BACKUP_URL_RE = re.compile(r"\.(bak|old|zip|tar\.gz|tgz|sql|swp|orig|~)$|~$", re.IGNORECASE)
_DIRECTORY_LISTING_RE = re.compile(r"index of\s*/", re.IGNORECASE)
_DEFAULT_PAGE_MARKERS: tuple[str, ...] = (
    "apache2 ubuntu default page", "apache2 debian default page",
    "welcome to nginx!", "iis windows server", "internet information services",
)
_ROBOTS_DISALLOW_RE = re.compile(r"^\s*disallow:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def _host_from_url(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_robots_txt(url: str) -> bool:
    return url.rstrip("/").lower().endswith("/robots.txt")


class BrowserParser:
    """Stateless parser: BrowserObservation -> ParsedObservation."""

    def parse_observation(
        self, obs: BrowserObservation, *, target: str, source: str = "browser"
    ) -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()

        host = _host_from_url(obs.url) or _host_from_url(target) or target

        safe_headers = {k: v for k, v in obs.headers.items() if k.lower() in _SAFE_HEADER_ALLOWLIST}
        cookie_names = [str(c.get("name", "")) for c in obs.cookies if c.get("name")]

        ep_id = _endpoint_id(obs.url)
        ep_props: dict[str, Any] = {
            "url": obs.url,
            "title": obs.title,
            "target": target,
            "browsed": True,
            "status": obs.status,
            "headers": safe_headers,
            "cookie_names": cookie_names,
            "favicon_present": obs.favicon_present,
        }
        if obs.final_url and obs.final_url != obs.url:
            ep_props["final_url"] = obs.final_url
        nodes.append(
            Node(
                id=ep_id, type="endpoint", props=ep_props, confidence=0.8,
                source=source, first_seen=timestamp, last_seen=timestamp,
            )
        )
        # Link back to the host node so this endpoint is reachable via a
        # normal host-anchored subgraph traversal — without this edge the
        # node would be an orphan: invisible to get_subgraph() and therefore
        # invisible to every session-model/opportunity dedup check that
        # reads the subgraph (same class of bug Phase 13 hit and fixed for
        # priv_esc_opportunity nodes — see docs/privilege-escalation-planning.md §9).
        h_id = _host_id_fn(host)
        edges.append(
            Edge(
                id=exposes_edge_id(h_id, ep_id), from_id=h_id, to_id=ep_id, type="exposes",
                props={}, confidence=0.8, source=source, first_seen=timestamp, last_seen=timestamp,
            )
        )

        for i, form in enumerate(obs.forms):
            frm_id = _form_id(obs.url, i)
            fields = [str(f) for f in form.get("fields", [])]
            field_types: dict[str, str] = {
                str(k): str(v) for k, v in (form.get("field_types") or {}).items()
            }

            def _has_type(field_type: str, name_hints: tuple[str, ...]) -> bool:
                if any(t == field_type for t in field_types.values()):
                    return True
                return any(hint in f.lower() for f in fields for hint in name_hints)

            is_login = _has_type("password", _PASSWORD_FIELD_HINTS)
            is_upload = _has_type("file", _UPLOAD_FIELD_HINTS)
            is_search = _has_type("search", _SEARCH_FIELD_HINTS) or "search" in form.get("action", "").lower()
            has_csrf = any(_CSRF_FIELD_RE.search(f) for f in fields)

            nodes.append(
                Node(
                    id=frm_id, type="form",
                    props={
                        "action": form.get("action", ""),
                        "method": form.get("method", "GET"),
                        "fields": fields,
                        "field_types": field_types,
                        "is_login": is_login,
                        "is_upload": is_upload,
                        "is_search": is_search,
                        "has_csrf": has_csrf,
                    },
                    confidence=0.75, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=contains_edge_id(ep_id, frm_id), from_id=ep_id, to_id=frm_id, type="contains",
                    props={}, confidence=0.75, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )

            if is_login:
                auth_id = auth_flow_form_id(obs.url, i)
                nodes.append(
                    Node(
                        id=auth_id, type="auth_flow",
                        props={"url": obs.url, "form_action": form.get("action", "")},
                        confidence=0.75, source=source, first_seen=timestamp, last_seen=timestamp,
                    )
                )
                edges.append(
                    Edge(
                        id=requires_edge_id(ep_id, auth_id), from_id=ep_id, to_id=auth_id, type="requires",
                        props={}, confidence=0.75, source=source, first_seen=timestamp, last_seen=timestamp,
                    )
                )
                self._add_opportunity(
                    nodes, edges, target=target, from_id=ep_id, timestamp=timestamp, source=source,
                    category=WebOpportunityCategory.authentication_portal, discriminator=obs.url,
                    confidence=OpportunityConfidence.high,
                    description=f"login form detected at {obs.url!r}",
                    recommended_next_action=(
                        "Manually review the authentication mechanism at this URL; "
                        "APEX does not attempt to log in or bypass authentication automatically"
                    ),
                    evidence_source="form", evidence_excerpt=form.get("action", "")[:_MAX_EXCERPT_CHARS],
                )

            if is_upload:
                self._add_opportunity(
                    nodes, edges, target=target, from_id=ep_id, timestamp=timestamp, source=source,
                    category=WebOpportunityCategory.upload_functionality,
                    discriminator=f"{obs.url}:{i}", confidence=OpportunityConfidence.medium,
                    description=f"file upload form detected at {obs.url!r}",
                    recommended_next_action=(
                        "Manually review upload validation (file type/size/path handling) "
                        "before any authorized action; APEX does not attempt to upload files"
                    ),
                    evidence_source="form", evidence_excerpt=form.get("action", "")[:_MAX_EXCERPT_CHARS],
                )

            if is_search:
                self._add_opportunity(
                    nodes, edges, target=target, from_id=ep_id, timestamp=timestamp, source=source,
                    category=WebOpportunityCategory.search_functionality,
                    discriminator=f"{obs.url}:{i}", confidence=OpportunityConfidence.low,
                    description=f"search form detected at {obs.url!r}",
                    recommended_next_action=(
                        "Manually review search parameter handling for injection risk "
                        "before any authorized action; APEX does not submit test payloads"
                    ),
                    evidence_source="form", evidence_excerpt=form.get("action", "")[:_MAX_EXCERPT_CHARS],
                )

        for hint in obs.auth_hints:
            ah_id = auth_flow_hint_id(obs.url, hint)
            nodes.append(
                Node(
                    id=ah_id, type="auth_flow", props={"url": obs.url, "hint": hint},
                    confidence=0.5, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=requires_edge_id(ep_id, ah_id), from_id=ep_id, to_id=ah_id, type="requires",
                    props={}, confidence=0.5, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )

        for token in obs.tokens:
            tok_id = _token_id(obs.url, token[:24])
            nodes.append(
                Node(
                    id=tok_id, type="token", props={"name": token}, confidence=0.6,
                    source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=contains_edge_id(ep_id, tok_id), from_id=ep_id, to_id=tok_id, type="contains",
                    props={}, confidence=0.6, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )

        # ---- Discovered-but-unvisited links -> endpoint nodes (browsed=False) ----
        seen_link_urls: set[str] = set()
        for link in obs.links:
            if len(seen_link_urls) >= _MAX_LINK_ENDPOINTS:
                break
            if _host_from_url(link) != host:
                continue  # same-origin only — never plan a browse off-target
            if link in seen_link_urls or link == obs.url:
                continue
            seen_link_urls.add(link)
            lnk_id = _endpoint_id(link)
            nodes.append(
                Node(
                    id=lnk_id, type="endpoint",
                    props={"url": link, "target": target, "browsed": False},
                    confidence=0.4, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=contains_edge_id(ep_id, lnk_id), from_id=ep_id, to_id=lnk_id, type="contains",
                    props={}, confidence=0.4, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )
            if _BACKUP_URL_RE.search(link):
                self._add_opportunity(
                    nodes, edges, target=target, from_id=ep_id, timestamp=timestamp, source=source,
                    category=WebOpportunityCategory.backup_file, discriminator=link,
                    confidence=OpportunityConfidence.medium,
                    description=f"backup-file-like link discovered: {link!r}",
                    recommended_next_action=(
                        "Manually review this file for sensitive backup content before "
                        "any authorized action; APEX does not download or open it"
                    ),
                    evidence_source="url", evidence_excerpt=link[:_MAX_EXCERPT_CHARS],
                )

        # ---- Technology detection (headers + HTML + URL) ----
        for finding in detect_technologies(headers=obs.headers, html=obs.html_snippet, url=obs.url):
            t_id = _tech_id_fn(host, finding.name)
            nodes.append(
                Node(
                    id=t_id, type="tech",
                    props={
                        "name": finding.name, "version": finding.version,
                        "source_detector": finding.source, "evidence_excerpt": finding.excerpt,
                    },
                    confidence=finding.confidence, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=runs_edge_id(ep_id, t_id), from_id=ep_id, to_id=t_id, type="runs",
                    props={}, confidence=finding.confidence, source=source, first_seen=timestamp, last_seen=timestamp,
                )
            )

        # ---- URL-pattern opportunities ----
        if _ADMIN_URL_RE.search(obs.url):
            self._add_opportunity(
                nodes, edges, target=target, from_id=ep_id, timestamp=timestamp, source=source,
                category=WebOpportunityCategory.admin_panel, discriminator=obs.url,
                confidence=OpportunityConfidence.medium,
                description=f"admin-panel-like path detected: {obs.url!r}",
                recommended_next_action=(
                    "Manually review this administrative interface's access controls "
                    "before any authorized action; APEX does not attempt to access it"
                ),
                evidence_source="url", evidence_excerpt=obs.url[:_MAX_EXCERPT_CHARS],
            )
        if _API_URL_RE.search(obs.url):
            self._add_opportunity(
                nodes, edges, target=target, from_id=ep_id, timestamp=timestamp, source=source,
                category=WebOpportunityCategory.api_endpoint, discriminator=obs.url,
                confidence=OpportunityConfidence.low,
                description=f"API-like endpoint detected: {obs.url!r}",
                recommended_next_action=(
                    "Manually review this API endpoint's authentication and input "
                    "validation before any authorized action"
                ),
                evidence_source="url", evidence_excerpt=obs.url[:_MAX_EXCERPT_CHARS],
            )

        # ---- Content-marker opportunities (title/body text) ----
        combined_text = f"{obs.title} {obs.html_snippet}"
        if _DIRECTORY_LISTING_RE.search(combined_text):
            self._add_opportunity(
                nodes, edges, target=target, from_id=ep_id, timestamp=timestamp, source=source,
                category=WebOpportunityCategory.directory_listing, discriminator=obs.url,
                confidence=OpportunityConfidence.high,
                description=f"directory listing detected at {obs.url!r}",
                recommended_next_action=(
                    "Manually review the exposed directory contents before any "
                    "authorized action; APEX does not download listed files"
                ),
                evidence_source="html", evidence_excerpt=obs.title[:_MAX_EXCERPT_CHARS],
            )
        lowered_combined = combined_text.lower()
        if any(marker in lowered_combined for marker in _DEFAULT_PAGE_MARKERS):
            self._add_opportunity(
                nodes, edges, target=target, from_id=ep_id, timestamp=timestamp, source=source,
                category=WebOpportunityCategory.default_page, discriminator=obs.url,
                confidence=OpportunityConfidence.low,
                description=f"default/unconfigured web server page detected at {obs.url!r}",
                recommended_next_action=(
                    "Note that the web server appears unconfigured; manually verify "
                    "whether this is intentional before any authorized action"
                ),
                evidence_source="html", evidence_excerpt=obs.title[:_MAX_EXCERPT_CHARS],
            )

        # ---- robots.txt Disallow entries ----
        if _is_robots_txt(obs.url):
            for m in list(_ROBOTS_DISALLOW_RE.finditer(obs.html_snippet))[:_MAX_ROBOTS_ENTRIES]:
                path = m.group(1).strip()
                if not path or path == "/":
                    continue
                self._add_opportunity(
                    nodes, edges, target=target, from_id=ep_id, timestamp=timestamp, source=source,
                    category=WebOpportunityCategory.robots_entry, discriminator=path,
                    confidence=OpportunityConfidence.low,
                    description=f"robots.txt Disallow entry: {path!r}",
                    recommended_next_action=(
                        f"Manually review {path!r} — robots.txt entries often mark "
                        "sensitive paths the operator intended to hide from crawlers"
                    ),
                    evidence_source="robots_txt", evidence_excerpt=path[:_MAX_EXCERPT_CHARS],
                )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)

    def _add_opportunity(
        self,
        nodes: list[Node],
        edges: list[Edge],
        *,
        target: str,
        from_id: str,
        timestamp: str,
        source: str,
        category: WebOpportunityCategory,
        discriminator: str,
        confidence: OpportunityConfidence,
        description: str,
        recommended_next_action: str,
        evidence_source: str,
        evidence_excerpt: str,
    ) -> None:
        """Append one ``web_opportunity`` node + ``indicates`` edge.

        Content-addressed on ``target``+``category``+``discriminator`` (see
        ``apex_host/graph_ids.py::web_opportunity_id``) — re-observing the
        same page/link/marker upserts the same node rather than creating a
        duplicate (memfabric per-field LWW upsert).
        """
        opp_id = web_opportunity_id(target, category.value, discriminator)
        nodes.append(
            Node(
                id=opp_id, type="web_opportunity",
                props={
                    "target": target,
                    "category": category.value,
                    "confidence": confidence.value,
                    "description": description,
                    "recommended_next_action": recommended_next_action,
                    "evidence_source": evidence_source,
                    "evidence_excerpt": evidence_excerpt[:_MAX_EXCERPT_CHARS],
                    "evidence_timestamp": timestamp,
                },
                confidence=confidence.as_float(), source=source, first_seen=timestamp, last_seen=timestamp,
            )
        )
        edges.append(
            Edge(
                id=indicates_edge_id(from_id, opp_id), from_id=from_id, to_id=opp_id, type="indicates",
                props={}, confidence=confidence.as_float(), source=source, first_seen=timestamp, last_seen=timestamp,
            )
        )
