# web_opportunities.py
# Pure, no-IO helpers for reconstructing, ranking, and deduplicating WebOpportunity records and session/session-dedup state from EKG subgraph data.
"""Web-exploitation-planning reasoning helpers (Phase 14).

Everything here is pure — no I/O, no MemoryAPI calls, no browser
navigation, no tool execution — consistent with the blackboard model
(memfabric Invariant 7): planners only ever read the ``SubgraphView`` they
are handed and return ``TaskSpec``s; all persistence happens through the
standard parse_observation -> MemoryAPI.apply_deltas path.

Responsibilities:

1. ``opportunities_from_subgraph`` / ``rank_opportunities`` reconstruct the
   current ``WebOpportunity`` set from ``web_opportunity`` EKG nodes —
   mirrors ``apex_host.planners.priv_esc_opportunities`` exactly.
2. ``visited_urls_from_subgraph`` / ``select_unvisited_endpoints`` implement
   the browser "session model": which pages have already been inspected
   (``endpoint`` nodes with ``browsed=True``), and which same-origin,
   not-yet-inspected pages remain as candidates — this is how
   ``BrowserPlanner`` avoids ever revisiting an identical page.
3. ``technologies_from_subgraph`` reconstructs detected technologies from
   ``tech`` nodes for reporting.
4. ``build_web_session_state`` composes all of the above into one
   ``WebSessionState`` snapshot for state refresh / reporting.
"""
from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

from apex_host.types import (
    OpportunityConfidence,
    WebOpportunity,
    WebOpportunityCategory,
    WebOpportunityEvidence,
    WebSessionState,
)

if TYPE_CHECKING:
    from memfabric.types import Node, SubgraphView

# Deterministic category ordering used only as a ranking tie-breaker (never
# affects which categories exist).
_CATEGORY_PRIORITY: dict[str, int] = {
    WebOpportunityCategory.authentication_portal.value: 0,
    WebOpportunityCategory.admin_panel.value: 1,
    WebOpportunityCategory.upload_functionality.value: 2,
    WebOpportunityCategory.api_endpoint.value: 3,
    WebOpportunityCategory.backup_file.value: 4,
    WebOpportunityCategory.directory_listing.value: 5,
    WebOpportunityCategory.search_functionality.value: 6,
    WebOpportunityCategory.robots_entry.value: 7,
    WebOpportunityCategory.default_page.value: 8,
    WebOpportunityCategory.none.value: 99,
}

# Keyword priority for candidate-page selection — lower number = inspected
# sooner. Purely a pacing heuristic; never affects which pages are
# *eligible*, only the deterministic order they are visited in.
_INTERESTING_PATH_KEYWORDS: tuple[str, ...] = (
    "admin", "login", "administrator", "manage", "dashboard",
    "api", "upload", "backup", "config", "user",
    # §28.28 — generic account/registration flow pages (NOT machine-specific):
    # a linked page like /invite, /register, /signup often carries the JS that
    # references the real API, so fetch it early within the web budget.
    "invite", "register", "signup", "signin",
)


def _node_to_opportunity(node: "Node") -> WebOpportunity | None:
    props = node.props
    try:
        category = WebOpportunityCategory(str(props.get("category", "")))
        confidence = OpportunityConfidence(str(props.get("confidence", "")))
    except ValueError:
        return None
    evidence = WebOpportunityEvidence(
        source=str(props.get("evidence_source", "")),
        excerpt=str(props.get("evidence_excerpt", "")),
        timestamp=str(props.get("evidence_timestamp", "")),
    )
    return WebOpportunity(
        id=node.id,
        category=category,
        confidence=confidence,
        evidence=evidence,
        description=str(props.get("description", "")),
        recommended_next_action=str(props.get("recommended_next_action", "")),
        first_seen=node.first_seen,
        last_seen=node.last_seen,
    )


def opportunities_from_subgraph(subgraph: "SubgraphView") -> list[WebOpportunity]:
    """Reconstruct every recorded ``WebOpportunity`` from the subgraph.

    Nodes whose ``category``/``confidence`` props no longer parse as a
    known enum member are skipped (forward-compatibility, mirrors
    ``priv_esc_opportunities.opportunities_from_subgraph``).
    """
    out: list[WebOpportunity] = []
    for node in subgraph.nodes:
        if node.type != "web_opportunity":
            continue
        opp = _node_to_opportunity(node)
        if opp is not None:
            out.append(opp)
    return out


def rank_opportunities(opportunities: list[WebOpportunity]) -> list[WebOpportunity]:
    """Deterministic ranking: confidence desc, then category priority, then id asc."""
    return sorted(
        opportunities,
        key=lambda o: (
            -o.confidence.as_float(),
            _CATEGORY_PRIORITY.get(o.category.value, 50),
            o.id,
        ),
    )


# ---------------------------------------------------------------------------
# Session model — visited pages, discovered-but-unvisited candidates
# ---------------------------------------------------------------------------

def visited_urls_from_subgraph(subgraph: "SubgraphView") -> set[str]:
    """The set of ``url`` values already actually browsed (``endpoint``
    nodes with ``browsed=True`` — set only by ``BrowserParser`` when a real
    or synthetic browser navigation produced that page, never by a passive
    curl/ffuf/gobuster discovery). ``BrowserPlanner`` must never re-emit a
    browse task for a URL already in this set — see "Avoid revisiting
    identical pages"."""
    return {
        str(n.props.get("url", ""))
        for n in subgraph.nodes
        if n.type == "endpoint" and n.props.get("browsed") is True and n.props.get("url")
    }


def _same_host(url: str, target_host: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    return host == target_host.lower()


def _path_interest_rank(url: str) -> int:
    lowered = url.lower()
    for i, kw in enumerate(_INTERESTING_PATH_KEYWORDS):
        if kw in lowered:
            return i
    return len(_INTERESTING_PATH_KEYWORDS)


def _path_depth(url: str) -> int:
    try:
        path = urllib.parse.urlparse(url).path
    except Exception:
        return 0
    return len([seg for seg in path.split("/") if seg])


def select_unvisited_endpoints(subgraph: "SubgraphView", target_host: str) -> list["Node"]:
    """Same-origin ``endpoint`` nodes not yet browsed, ranked deterministically.

    Ranking: interesting-keyword priority ascending (admin/login/api/...
    first), then path depth ascending (shallower pages first), then URL
    alphabetical — never random, never insertion-order-dependent. Endpoints
    on a different host are never returned (the browser must never be
    planned to navigate off-target based on a discovered external link).
    """
    candidates = [
        n for n in subgraph.nodes
        if n.type == "endpoint"
        and n.props.get("browsed") is not True
        and str(n.props.get("url", ""))
        and _same_host(str(n.props.get("url", "")), target_host)
    ]
    return sorted(
        candidates,
        key=lambda n: (
            _path_interest_rank(str(n.props.get("url", ""))),
            _path_depth(str(n.props.get("url", ""))),
            str(n.props.get("url", "")),
        ),
    )


def _url_path(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).path or "/").rstrip("/") or "/"
    except ValueError:
        return "/"


#: Low-signal static-asset extensions that yield NO API references — never worth
#: a GET for discovery (§28.26). Excluded from the page-fetch loop so the bounded
#: budget goes to real pages (e.g. /invite) and API paths instead of css/images/
#: fonts. ``.js`` is NOT here — script assets are fetched+parsed as JS separately.
_STATIC_ASSET_EXTS: frozenset[str] = frozenset({
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map", ".mp4", ".webm", ".mp3",
    ".wav", ".ogg", ".pdf", ".zip", ".gz", ".tar", ".avif",
})


def _is_static_asset(url: str) -> bool:
    """True if *url*'s path ends in a low-signal static-asset extension."""
    path = _url_path(url).lower()
    dot = path.rfind(".")
    return dot != -1 and path[dot:] in _STATIC_ASSET_EXTS


def _fetch_priority(node: "Node") -> int:
    """Primary page-fetch ordering (§28.26): confirmed API references first.

    A JS-extracted reference (``source=js_analysis``) or an ``/api``-prefixed
    path is a high-value fetch (JSON-structure mapping) and sorts ahead of a
    plain discovered link. 0 = highest priority."""
    if node.source == "js_analysis":
        return 0
    if _url_path(str(node.props.get("url", ""))).lower().startswith("/api"):
        return 0
    return 1


def pending_enumerated_endpoints(subgraph: "SubgraphView") -> list["Node"]:
    """Discovered-but-unfetched enumeration endpoints, ranked highest-signal
    first (§28.13).

    A candidate is an ``endpoint`` node discovered by content enumeration
    (``source`` in ffuf/gobuster) whose URL path has NOT yet been fetched —
    i.e. no ``endpoint`` node marked ``fetched``/``browsed`` shares that path.
    A ``404`` status is low-signal and excluded (the GOAL: non-404, /api-like
    first). Ranking reuses the deterministic interest/depth/url ordering — a
    stateless, blackboard-only view (reads the subgraph). This is what tells the
    web planner to FETCH the paths enumeration found, and keeps the web phase
    incomplete while a productive fetch remains."""
    fetched_paths = {
        _url_path(str(n.props.get("url", "")))
        for n in subgraph.nodes
        if n.type == "endpoint"
        and (n.props.get("fetched") is True or n.props.get("browsed") is True)
        and str(n.props.get("url", ""))
    }
    candidates = [
        n for n in subgraph.nodes
        if n.type == "endpoint"
        # §28.22 — API-wordlist scan endpoints (ffuf_api/gobuster_api) are fetched
        # like content-enum endpoints, so a discovered /api/* path gets GET-fetched
        # and its JSON structure recorded.
        and n.source in ("ffuf", "gobuster", "ffuf_api", "gobuster_api")
        and str(n.props.get("url", ""))
        and str(n.props.get("status", "")).strip() != "404"
        and _url_path(str(n.props.get("url", ""))) not in fetched_paths
    ]
    return sorted(
        candidates,
        key=lambda n: (
            _path_interest_rank(str(n.props.get("url", ""))),
            _path_depth(str(n.props.get("url", ""))),
            str(n.props.get("url", "")),
        ),
    )


#: Endpoint provenance the web fetch loop GETs as PAGES (HTML/JSON), §28.24.
#: Includes content-enum (§28.12/§28.22), relative-link pages discovered from a
#: fetched HTML body (source curl_body — e.g. /invite), and API paths extracted
#: from JS (source js_analysis) — all get GET-fetched so their body is mapped.
_PAGE_FETCH_SOURCES = ("ffuf", "gobuster", "ffuf_api", "gobuster_api", "curl_body",
                       "js_analysis", "html_form")


def pending_page_fetches(subgraph: "SubgraphView") -> list["Node"]:
    """Discovered-but-unfetched PAGE endpoints the web loop should GET (§28.24).

    A superset of ``pending_enumerated_endpoints``: also includes relative-link
    pages discovered from a fetched HTML body (so a linked page like ``/invite``
    gets fetched and its ``<script src>`` seen) and API paths extracted from JS
    (source ``js_analysis``, so a JS-referenced ``/api/v1/...`` gets GET-fetched
    and JSON-mapped). Excludes JS-asset endpoints (those are fetched as JS, see
    ``pending_js_assets``). Unfetched, non-404, path not already fetched, ranked
    highest-signal first. Stateless/blackboard-only."""
    fetched_paths = {
        _url_path(str(n.props.get("url", "")))
        for n in subgraph.nodes
        if n.type == "endpoint"
        and (n.props.get("fetched") is True or n.props.get("browsed") is True)
        and str(n.props.get("url", ""))
    }
    candidates = [
        n for n in subgraph.nodes
        if n.type == "endpoint"
        and n.props.get("js_asset") is not True
        and n.source in _PAGE_FETCH_SOURCES
        and str(n.props.get("url", ""))
        and str(n.props.get("status", "")).strip() != "404"
        # §28.36 — never GET-fetch an endpoint whose known method is non-GET
        # (e.g. a POST-only form action) — a GET would just 405. A GET-method
        # form action is still fetched.
        and str(n.props.get("method", "GET")).upper() in ("", "GET", "HEAD")
        # §28.26 — never spend the bounded page-fetch budget on css/images/fonts;
        # they yield no API references. Real pages (e.g. /invite) and API paths win.
        and not _is_static_asset(str(n.props.get("url", "")))
        and _url_path(str(n.props.get("url", ""))) not in fetched_paths
    ]
    return sorted(
        candidates,
        key=lambda n: (
            _fetch_priority(n),  # §28.26 — confirmed API references (js_analysis/api) first
            _path_interest_rank(str(n.props.get("url", ""))),
            _path_depth(str(n.props.get("url", ""))),
            str(n.props.get("url", "")),
        ),
    )


def pending_js_assets(subgraph: "SubgraphView") -> list["Node"]:
    """Discovered-but-unfetched JavaScript assets (``js_asset=True``) the web loop
    should GET and statically parse for API references (§28.24). Ranked so the JS
    on a HIGH-SIGNAL page (e.g. /invite, /login) is fetched BEFORE homepage bundles
    within the bounded budget (§28.26): by the referencing page's interest, then
    the JS file's own path interest, then URL. The JS is READ, never executed."""
    # Map each js_asset endpoint id -> the highest-signal page that referenced it
    # (via the ``contains`` edge page -> js_asset written by parse_curl_body).
    ref_page_url: dict[str, str] = {}
    node_url = {n.id: str(n.props.get("url", "")) for n in subgraph.nodes if n.type == "endpoint"}
    for e in subgraph.edges:
        if e.type == "contains" and e.to_id in node_url and e.from_id in node_url:
            src_url = node_url[e.from_id]
            cur = ref_page_url.get(e.to_id)
            if cur is None or _path_interest_rank(src_url) < _path_interest_rank(cur):
                ref_page_url[e.to_id] = src_url
    candidates = [
        n for n in subgraph.nodes
        if n.type == "endpoint"
        and n.props.get("js_asset") is True
        and n.props.get("fetched") is not True
        and n.props.get("browsed") is not True
        and str(n.props.get("url", ""))
    ]

    def _rank(n: "Node") -> tuple[int, int, str]:
        own = str(n.props.get("url", ""))
        page = ref_page_url.get(n.id, own)
        return (_path_interest_rank(page), _path_interest_rank(own), own)

    return sorted(candidates, key=_rank)


def technologies_from_subgraph(subgraph: "SubgraphView") -> list[dict[str, Any]]:
    """Reconstruct detected technologies (``tech`` nodes) for reporting.

    Returns plain dicts (not a dedicated dataclass — ``tech`` is a
    domain-generic node type shared with nmap/curl-header detection, not a
    Phase-14-only concept) with ``name``/``version``/``confidence``/``source``.
    """
    out: list[dict[str, Any]] = []
    for n in subgraph.nodes:
        if n.type != "tech":
            continue
        out.append({
            "name": str(n.props.get("name", "")),
            "version": str(n.props.get("version", "")),
            "confidence": n.confidence,
            "source": str(n.props.get("source_header") or n.props.get("source_detector") or ""),
        })
    return out


#: Generic classification of a discovered endpoint into an operator follow-up
#: KIND, reusing the shared _INTERESTING_PATH_KEYWORDS (§28.28 — documented as
#: NOT machine-specific). Advisory only: every note describes a HUMAN send-side
#: action APEX deliberately does not perform itself (§28.30). No decode
#: procedure, concrete path, or machine name is hardcoded here.
_FOLLOWUP_AUTH_KEYWORDS: tuple[str, ...] = (
    "login", "signin", "register", "signup", "invite", "user",
)
_FOLLOWUP_ADMIN_KEYWORDS: tuple[str, ...] = (
    "admin", "administrator", "manage", "dashboard",
)
_FOLLOWUP_NOTES: dict[str, str] = {
    "auth_flow": (
        "authentication/registration flow endpoint — a login or registration "
        "step (a send-side request) may be required; APEX discovers it but does "
        "not submit it autonomously (§28.30)"
    ),
    "admin": "administrative interface — operator review recommended",
    "api": (
        "API endpoint — the operator may need to invoke it manually; APEX "
        "discovers it but does not send requests to it autonomously (§28.30)"
    ),
    "notable": "path of interest — operator review recommended",
}


def _followup_kind(path: str) -> str | None:
    """Generic follow-up KIND for *path*, or None if not interesting."""
    p = path.lower()
    if any(k in p for k in _FOLLOWUP_AUTH_KEYWORDS):
        return "auth_flow"
    if any(k in p for k in _FOLLOWUP_ADMIN_KEYWORDS):
        return "admin"
    if "api" in p:
        return "api"
    if any(k in p for k in _INTERESTING_PATH_KEYWORDS):
        return "notable"
    return None


def operator_followups_from_subgraph(
    subgraph: "SubgraphView", *, limit: int = 25,
) -> list[dict[str, str]]:
    """Read-only, GENERIC advisory list of discovered endpoints a human operator
    may need to act on (§28.34).

    §28.31 routes web discovery through the curl ``web_agent``, so ``web_opportunity``
    nodes (derived only from browser observations) are absent even when useful
    auth/registration/API endpoints were discovered by curl/JS analysis. This
    scans discovered ``endpoint`` nodes and classifies each whose path matches a
    generic interesting/auth/registration/API keyword (the shared
    ``_INTERESTING_PATH_KEYWORDS``, §28.28) into a follow-up KIND with a fixed,
    secret-free advisory note. Pure — no I/O, no writes, no machine-specific
    decode procedure or hardcoded path. Every note describes a HUMAN send-side
    action APEX deliberately does not perform itself (§28.30). Deduped by path,
    ranked highest-interest first, bounded by ``limit``."""
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    endpoints = [n for n in subgraph.nodes if n.type == "endpoint"]
    for node in sorted(
        endpoints,
        key=lambda n: (
            _path_interest_rank(str(n.props.get("url", ""))),
            str(n.props.get("url", "")),
        ),
    ):
        url = str(node.props.get("url", ""))
        path = str(node.props.get("path", "")) or _url_path(url)
        # A JS asset or a static file is a fetch target, not an operator action.
        if (
            not url or path in seen
            or node.props.get("js_asset") is True
            or _is_static_asset(url)
            or path.lower().endswith(".js")
        ):
            continue
        # §28.36 — a discovered <form action> (a submission endpoint) is inherently
        # operator-actionable regardless of keyword, and its note carries the
        # method + input-field NAMES (never values) so the operator can see the
        # REAL registration/login POST endpoint they'd otherwise have to guess.
        if node.props.get("form_action") is True:
            method = str(node.props.get("method", "GET")).upper()
            raw_fields = node.props.get("form_fields") or []
            fields = ", ".join(str(f) for f in raw_fields) if isinstance(raw_fields, list) else ""
            note = (f"HTML form submission endpoint ({method}) — a likely "
                    f"registration/login target; fields: {fields or 'none'}. A "
                    "send-side action APEX does not perform itself (§28.30).")
            seen.add(path)
            out.append({"path": path, "url": url, "kind": "form_action", "note": note})
            if len(out) >= limit:
                break
            continue
        kind = _followup_kind(path)
        if kind is None:
            continue
        seen.add(path)
        out.append({"path": path, "url": url, "kind": kind, "note": _FOLLOWUP_NOTES[kind]})
        if len(out) >= limit:
            break
    return out


def build_web_session_state(target: str, subgraph: "SubgraphView") -> WebSessionState:
    """Build the current ``WebSessionState`` snapshot for *target*.

    ``login_state`` reuses the same success signal every other phase relies
    on (an ``access_state`` node) — never a second, independent notion of
    "logged in".
    """
    opportunities = rank_opportunities(opportunities_from_subgraph(subgraph))
    pages_visited = len(visited_urls_from_subgraph(subgraph))
    forms_discovered = sum(1 for n in subgraph.nodes if n.type == "form")
    technologies_detected = len(technologies_from_subgraph(subgraph))
    has_access_state = any(n.type == "access_state" for n in subgraph.nodes)
    return WebSessionState(
        target=target,
        pages_visited=pages_visited,
        forms_discovered=forms_discovered,
        technologies_detected=technologies_detected,
        opportunities=tuple(opportunities),
        login_state="authenticated" if has_access_state else "anonymous",
    )


def web_session_state_fields(subgraph: "SubgraphView", *, target: str) -> dict[str, Any]:
    """Build the ``ApexGraphState`` partial-update dict for one browser turn.

    Pure derivation from the subgraph. Called only from
    ``apex_host.orchestration.dispatch_node.make_browser_node`` so this state
    summary is refreshed exactly on browser turns; every other node simply
    omits these keys and LangGraph's partial-update semantics preserve the
    last known snapshot (mirrors ``privilege_state_fields``, Phase 13).
    """
    state = build_web_session_state(target, subgraph)
    return {
        "web_session_state": {
            "pages_visited": state.pages_visited,
            "forms_discovered": state.forms_discovered,
            "technologies_detected": state.technologies_detected,
            "opportunity_count": state.opportunity_count,
            "categories": state.categories,
            "login_state": state.login_state,
        },
    }
