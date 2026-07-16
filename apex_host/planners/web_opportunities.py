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
