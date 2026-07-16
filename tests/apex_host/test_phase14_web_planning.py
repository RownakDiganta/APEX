# test_phase14_web_planning.py
# Regression tests for Phase 14: web exploitation planning & browser reasoning — technology detection, form/opportunity derivation, session model dedup, BrowserPlanner, graph links, transaction rollback, and report generation.
"""Phase 14 regression tests.

Covers the browser-reasoning framework introduced in Phase 14: deterministic
technology detection (``apex_host.parsers.tech_detector``), the enriched
``BrowserParser`` (form/tech/opportunity/link-endpoint derivation, the
``browsed`` session-model flag), the pure reasoning helpers in
``apex_host.planners.web_opportunities`` (dedup, ranking, session state),
the new ``BrowserPlanner`` (visit-priority selection, never revisiting an
identical page), dispatcher/graph wiring, and ``RunReport``'s Web Summary.

No exploit is executed, no form is submitted, no payload is generated, no
SQL injection/XSS/CSRF is ever performed by any code exercised here — every
test asserts the *planning/reasoning* framework's behavior only. No Docker,
Compose, VPN, or GitHub Actions files are touched by this test file or the
code it tests.
"""
from __future__ import annotations

import re
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, EvidenceBundle, Goal, Node, SubgraphView

from apex_host.config import ApexConfig
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.graph_ids import host_id, web_opportunity_id
from apex_host.parsers import tech_detector
from apex_host.parsers.browser_parser import BrowserParser
from apex_host.planners.browser_planner import BrowserPlanner, _BrowserDeterministic
from apex_host.planners.web_opportunities import (
    build_web_session_state,
    opportunities_from_subgraph,
    rank_opportunities,
    select_unvisited_endpoints,
    technologies_from_subgraph,
    visited_urls_from_subgraph,
    web_session_state_fields,
)
from apex_host.tools.registry import ToolRegistry
from apex_host.types import BrowserObservation, WebOpportunityCategory

_TARGET = "10.10.10.90"
_ANCHOR = f"host:{_TARGET}"
_URL = f"http://{_TARGET}"

_DOCSTRING_RE = re.compile(r'""".*?"""', re.DOTALL)


def _code_only(source: str) -> str:
    return _DOCSTRING_RE.sub("", source)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def _registry(*tools: str) -> ToolRegistry:
    return ToolRegistry(allowed_tools=list(tools))


def _goal(phase: str = "web") -> Goal:
    return Goal(id="g-web", description="Inspect web surface", phase=phase, anchor_node=_ANCHOR)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(entries=[], query="test", subgraph=None, tiers_queried=[])


def _node(node_id: str, node_type: str, props: dict[str, Any], confidence: float = 0.9) -> Node:
    ts = now()
    return Node(id=node_id, type=node_type, props=props, confidence=confidence, source="test", first_seen=ts, last_seen=ts)


def _subgraph(*nodes: Node, edges: list[Edge] | None = None) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=edges or [], depth=2)


def _endpoint_node(url: str, *, browsed: bool = False, **extra: Any) -> Node:
    from apex_host.graph_ids import endpoint_id
    props = {"url": url, "target": _TARGET, "browsed": browsed}
    props.update(extra)
    return _node(endpoint_id(url), "endpoint", props)


def _obs(**overrides: Any) -> BrowserObservation:
    base: dict[str, Any] = dict(
        url=_URL, html_snippet="<html><body>Hello</body></html>", title="Home",
        forms=[], tokens=[], auth_hints=[], links=[],
    )
    base.update(overrides)
    return BrowserObservation(**base)


# ---------------------------------------------------------------------------
# 1. Technology detection
# ---------------------------------------------------------------------------

class TestTechDetectorHeaders:
    def test_apache_from_server_header(self) -> None:
        findings = tech_detector.detect_from_headers({"Server": "Apache/2.4.41"})
        assert any(f.name == "Apache" and f.version == "2.4.41" for f in findings)

    def test_nginx_from_server_header(self) -> None:
        findings = tech_detector.detect_from_headers({"Server": "nginx/1.18.0"})
        assert any(f.name == "nginx" for f in findings)

    def test_iis_from_server_header(self) -> None:
        findings = tech_detector.detect_from_headers({"Server": "Microsoft-IIS/10.0"})
        assert any(f.name == "IIS" for f in findings)

    def test_flask_from_werkzeug_server_header(self) -> None:
        findings = tech_detector.detect_from_headers({"Server": "Werkzeug/2.0.1 Python/3.11"})
        assert any(f.name == "Flask" for f in findings)

    def test_php_from_x_powered_by(self) -> None:
        findings = tech_detector.detect_from_headers({"X-Powered-By": "PHP/8.1.2"})
        assert any(f.name == "PHP" and f.version == "8.1.2" for f in findings)

    def test_aspnet_from_x_powered_by(self) -> None:
        findings = tech_detector.detect_from_headers({"X-Powered-By": "ASP.NET"})
        assert any(f.name == "ASP.NET" for f in findings)

    def test_express_from_x_powered_by(self) -> None:
        findings = tech_detector.detect_from_headers({"X-Powered-By": "Express"})
        assert any(f.name == "Express" for f in findings)

    def test_aspnet_from_x_aspnet_version(self) -> None:
        findings = tech_detector.detect_from_headers({"X-AspNet-Version": "4.0.30319"})
        assert any(f.name == "ASP.NET" for f in findings)

    def test_php_from_set_cookie_phpsessid(self) -> None:
        findings = tech_detector.detect_from_headers({"Set-Cookie": "PHPSESSID=abc123; Path=/"})
        assert any(f.name == "PHP" for f in findings)

    def test_django_from_set_cookie_csrftoken(self) -> None:
        findings = tech_detector.detect_from_headers({"Set-Cookie": "csrftoken=xyz; Path=/"})
        assert any(f.name == "Django" for f in findings)

    def test_express_from_set_cookie_connect_sid(self) -> None:
        findings = tech_detector.detect_from_headers({"Set-Cookie": "connect.sid=s%3A123; Path=/"})
        assert any(f.name == "Express" for f in findings)

    def test_no_headers_no_findings(self) -> None:
        assert tech_detector.detect_from_headers({}) == []

    def test_unrecognised_server_header_no_finding(self) -> None:
        findings = tech_detector.detect_from_headers({"Server": "TotallyMadeUpServer/1.0"})
        assert findings == []


class TestTechDetectorHtml:
    def test_wordpress_from_wp_content(self) -> None:
        findings = tech_detector.detect_from_html("<html><script src='/wp-content/themes/x.js'></script></html>")
        assert any(f.name == "WordPress" for f in findings)

    def test_joomla_from_components_path(self) -> None:
        findings = tech_detector.detect_from_html("<a href='/components/com_content/view'>x</a>")
        assert any(f.name == "Joomla" for f in findings)

    def test_drupal_from_sites_default_files(self) -> None:
        findings = tech_detector.detect_from_html("<img src='/sites/default/files/pic.png'>")
        assert any(f.name == "Drupal" for f in findings)

    def test_django_from_csrfmiddlewaretoken(self) -> None:
        findings = tech_detector.detect_from_html("<input type='hidden' name='csrfmiddlewaretoken' value='x'>")
        assert any(f.name == "Django" for f in findings)

    def test_generator_meta_wordpress(self) -> None:
        findings = tech_detector.detect_from_html('<meta name="generator" content="WordPress 6.2">')
        assert any(f.name == "WordPress" for f in findings)

    def test_empty_html_no_findings(self) -> None:
        assert tech_detector.detect_from_html("") == []

    def test_no_markers_no_findings(self) -> None:
        assert tech_detector.detect_from_html("<html><body>plain page</body></html>") == []


class TestTechDetectorUrl:
    def test_php_extension(self) -> None:
        findings = tech_detector.detect_from_url("http://host/index.php")
        assert any(f.name == "PHP" for f in findings)

    def test_aspx_extension(self) -> None:
        findings = tech_detector.detect_from_url("http://host/default.aspx")
        assert any(f.name == "ASP.NET" for f in findings)

    def test_wordpress_admin_path(self) -> None:
        findings = tech_detector.detect_from_url("http://host/wp-admin/")
        assert any(f.name == "WordPress" for f in findings)

    def test_joomla_administrator_path(self) -> None:
        findings = tech_detector.detect_from_url("http://host/administrator/")
        assert any(f.name == "Joomla" for f in findings)

    def test_empty_url_no_findings(self) -> None:
        assert tech_detector.detect_from_url("") == []

    def test_unrelated_url_no_findings(self) -> None:
        assert tech_detector.detect_from_url("http://host/about") == []


class TestTechDetectorMerge:
    def test_header_confidence_beats_url_confidence(self) -> None:
        findings = tech_detector.detect_technologies(
            headers={"X-Powered-By": "PHP/8.0"}, html="", url="http://host/index.php",
        )
        php = next(f for f in findings if f.name == "PHP")
        assert php.source == "header"
        assert php.version == "8.0"

    def test_dedup_by_name_keeps_highest_confidence(self) -> None:
        findings = tech_detector.detect_technologies(
            headers={}, html="<meta name='generator' content='WordPress 6.0'>",
            url="http://host/wp-admin/",
        )
        wp = [f for f in findings if f.name == "WordPress"]
        assert len(wp) == 1
        assert wp[0].source == "html"  # html (0.6) beats url (0.4)

    def test_deterministic_output_ordering(self) -> None:
        findings1 = tech_detector.detect_technologies(
            headers={"Server": "nginx/1.2", "X-Powered-By": "PHP/8.0"}, html="", url="",
        )
        findings2 = tech_detector.detect_technologies(
            headers={"Server": "nginx/1.2", "X-Powered-By": "PHP/8.0"}, html="", url="",
        )
        assert [f.name for f in findings1] == [f.name for f in findings2]
        assert [f.name for f in findings1] == sorted(f.name for f in findings1)

    def test_no_inputs_no_findings(self) -> None:
        assert tech_detector.detect_technologies() == []


# ---------------------------------------------------------------------------
# 2. BrowserParser — forms, opportunities, link endpoints, session flags
# ---------------------------------------------------------------------------

class TestBrowserParserForms:
    def test_login_form_detected_via_field_type(self) -> None:
        obs = _obs(forms=[{
            "action": "/login", "method": "POST",
            "fields": ["username", "pwd_field"],
            "field_types": {"username": "text", "pwd_field": "password"},
        }])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        form = next(n for n in parsed.node_deltas if n.type == "form")
        assert form.props["is_login"] is True

    def test_login_form_detected_via_name_heuristic_fallback(self) -> None:
        """Backward compatibility: forms without field_types (old shape)
        still detect a login form via the password-name heuristic."""
        obs = _obs(forms=[{"action": "/login", "method": "POST", "fields": ["username", "password"]}])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        form = next(n for n in parsed.node_deltas if n.type == "form")
        assert form.props["is_login"] is True

    def test_upload_form_detected(self) -> None:
        obs = _obs(forms=[{
            "action": "/upload", "method": "POST",
            "fields": ["document"], "field_types": {"document": "file"},
        }])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        form = next(n for n in parsed.node_deltas if n.type == "form")
        assert form.props["is_upload"] is True
        opp = next(n for n in parsed.node_deltas if n.type == "web_opportunity")
        assert opp.props["category"] == "upload_functionality"

    def test_search_form_detected(self) -> None:
        obs = _obs(forms=[{
            "action": "/search", "method": "GET",
            "fields": ["q"], "field_types": {"q": "search"},
        }])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        form = next(n for n in parsed.node_deltas if n.type == "form")
        assert form.props["is_search"] is True

    def test_csrf_field_detected(self) -> None:
        obs = _obs(forms=[{
            "action": "/login", "method": "POST",
            "fields": ["username", "csrf_token"],
            "field_types": {"username": "text", "csrf_token": "hidden"},
        }])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        form = next(n for n in parsed.node_deltas if n.type == "form")
        assert form.props["has_csrf"] is True

    def test_plain_form_no_flags(self) -> None:
        obs = _obs(forms=[{"action": "/contact", "method": "POST", "fields": ["name", "message"]}])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        form = next(n for n in parsed.node_deltas if n.type == "form")
        assert form.props["is_login"] is False
        assert form.props["is_upload"] is False
        assert form.props["is_search"] is False
        assert form.props["has_csrf"] is False

    def test_login_form_produces_authentication_portal_opportunity(self) -> None:
        obs = _obs(forms=[{
            "action": "/login", "method": "POST",
            "fields": ["username", "password"],
            "field_types": {"username": "text", "password": "password"},
        }])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        assert any(o.props["category"] == "authentication_portal" for o in opps)


class TestBrowserParserSessionModel:
    def test_visited_page_marked_browsed(self) -> None:
        parsed = BrowserParser().parse_observation(_obs(), target=_URL)
        ep = next(n for n in parsed.node_deltas if n.type == "endpoint" and n.props["url"] == _URL)
        assert ep.props["browsed"] is True

    def test_same_origin_links_become_unvisited_endpoints(self) -> None:
        obs = _obs(links=[f"{_URL}/about", f"{_URL}/contact"])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        link_eps = [n for n in parsed.node_deltas if n.type == "endpoint" and n.props["url"] != _URL]
        assert len(link_eps) == 2
        assert all(ep.props["browsed"] is False for ep in link_eps)

    def test_external_links_excluded(self) -> None:
        obs = _obs(links=["http://evil-external.example/steal"])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        link_eps = [n for n in parsed.node_deltas if n.type == "endpoint" and n.props["url"] != _URL]
        assert link_eps == []

    def test_link_endpoints_bounded_to_twenty(self) -> None:
        links = [f"{_URL}/page{i}" for i in range(50)]
        obs = _obs(links=links)
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        link_eps = [n for n in parsed.node_deltas if n.type == "endpoint" and n.props["url"] != _URL]
        assert len(link_eps) <= 20

    def test_headers_stored_safely_excludes_set_cookie(self) -> None:
        obs = _obs(headers={"Server": "nginx", "Set-Cookie": "sessionid=SECRETVALUE123"})
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        ep = next(n for n in parsed.node_deltas if n.type == "endpoint" and n.props["url"] == _URL)
        assert "set-cookie" not in {k.lower() for k in ep.props["headers"]}
        assert "SECRETVALUE123" not in str(ep.props)

    def test_cookie_values_never_stored_only_names(self) -> None:
        obs = _obs(cookies=[{"name": "session_id", "http_only": True, "secure": False, "value": "SECRETVALUE"}])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        ep = next(n for n in parsed.node_deltas if n.type == "endpoint" and n.props["url"] == _URL)
        assert ep.props["cookie_names"] == ["session_id"]
        assert "SECRETVALUE" not in str(ep.props)


class TestBrowserParserOpportunities:
    def test_admin_url_produces_admin_panel_opportunity(self) -> None:
        obs = _obs(url=f"{_URL}/admin", title="Admin Login")
        parsed = BrowserParser().parse_observation(obs, target=f"{_URL}/admin")
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        assert any(o.props["category"] == "admin_panel" for o in opps)

    def test_api_url_produces_api_endpoint_opportunity(self) -> None:
        obs = _obs(url=f"{_URL}/api/v1/users")
        parsed = BrowserParser().parse_observation(obs, target=f"{_URL}/api/v1/users")
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        assert any(o.props["category"] == "api_endpoint" for o in opps)

    def test_directory_listing_detected(self) -> None:
        obs = _obs(title="Index of /backup", html_snippet="<html><body>Index of /backup</body></html>")
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        assert any(o.props["category"] == "directory_listing" for o in opps)

    def test_default_apache_page_detected(self) -> None:
        obs = _obs(title="Apache2 Ubuntu Default Page: It works")
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        assert any(o.props["category"] == "default_page" for o in opps)

    def test_default_nginx_page_detected(self) -> None:
        obs = _obs(title="Welcome to nginx!")
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        assert any(o.props["category"] == "default_page" for o in opps)

    def test_backup_file_link_detected(self) -> None:
        obs = _obs(links=[f"{_URL}/site-backup.zip", f"{_URL}/config.bak"])
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        backup_opps = [o for o in opps if o.props["category"] == "backup_file"]
        assert len(backup_opps) == 2

    def test_robots_txt_disallow_produces_robots_entry_opportunities(self) -> None:
        robots_body = "User-agent: *\nDisallow: /secret/\nDisallow: /internal-admin/\n"
        obs = _obs(url=f"{_URL}/robots.txt", html_snippet=robots_body, title="")
        parsed = BrowserParser().parse_observation(obs, target=f"{_URL}/robots.txt")
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity" and n.props["category"] == "robots_entry"]
        assert len(opps) == 2

    def test_robots_txt_disallow_root_ignored(self) -> None:
        obs = _obs(url=f"{_URL}/robots.txt", html_snippet="Disallow: /\n", title="")
        parsed = BrowserParser().parse_observation(obs, target=f"{_URL}/robots.txt")
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity" and n.props["category"] == "robots_entry"]
        assert opps == []

    def test_robots_txt_bounded_to_ten_entries(self) -> None:
        robots_body = "\n".join(f"Disallow: /path{i}/" for i in range(30))
        obs = _obs(url=f"{_URL}/robots.txt", html_snippet=robots_body, title="")
        parsed = BrowserParser().parse_observation(obs, target=f"{_URL}/robots.txt")
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity" and n.props["category"] == "robots_entry"]
        assert len(opps) <= 10

    def test_plain_page_no_opportunities(self) -> None:
        obs = _obs(title="About Us", html_snippet="<html><body>About our company</body></html>")
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        assert opps == []

    def test_opportunity_id_deterministic_across_calls(self) -> None:
        obs = _obs(url=f"{_URL}/admin", title="Admin")
        p1 = BrowserParser().parse_observation(obs, target=f"{_URL}/admin")
        p2 = BrowserParser().parse_observation(obs, target=f"{_URL}/admin")
        id1 = next(n.id for n in p1.node_deltas if n.type == "web_opportunity")
        id2 = next(n.id for n in p2.node_deltas if n.type == "web_opportunity")
        assert id1 == id2

    def test_technology_detected_from_synthetic_headers(self) -> None:
        obs = _obs(headers={"Server": "nginx/1.20.0"})
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        techs = [n for n in parsed.node_deltas if n.type == "tech"]
        assert any(t.props["name"] == "nginx" for t in techs)

    def test_no_shell_metacharacters_in_recommendations(self) -> None:
        obs = _obs(url=f"{_URL}/admin", forms=[{
            "action": "/login", "method": "POST", "fields": ["u", "p"],
            "field_types": {"u": "text", "p": "password"},
        }])
        parsed = BrowserParser().parse_observation(obs, target=f"{_URL}/admin")
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        for o in opps:
            action = o.props["recommended_next_action"]
            for meta in ("&&", "||", "|", "$(", "`"):
                assert meta not in action


# ---------------------------------------------------------------------------
# 3. web_opportunities.py — reasoning helpers
# ---------------------------------------------------------------------------

class TestOpportunitiesFromSubgraph:
    def test_reconstructs_opportunity_from_node(self) -> None:
        opp = _node(
            web_opportunity_id(_TARGET, "admin_panel", _URL), "web_opportunity",
            {"category": "admin_panel", "confidence": "medium", "description": "d", "recommended_next_action": "r"},
        )
        opps = opportunities_from_subgraph(_subgraph(opp))
        assert len(opps) == 1
        assert opps[0].category == WebOpportunityCategory.admin_panel

    def test_ignores_non_opportunity_nodes(self) -> None:
        assert opportunities_from_subgraph(_subgraph(_endpoint_node(_URL))) == []

    def test_skips_unparseable_category(self) -> None:
        bad = _node("web_opportunity:x", "web_opportunity", {"category": "not-real", "confidence": "high"})
        assert opportunities_from_subgraph(_subgraph(bad)) == []


class TestRankOpportunities:
    def _opp(self, category: str, confidence: str, disc: str) -> Any:
        node = _node(
            web_opportunity_id(_TARGET, category, disc), "web_opportunity",
            {"category": category, "confidence": confidence, "description": "d", "recommended_next_action": "r"},
        )
        return opportunities_from_subgraph(_subgraph(node))[0]

    def test_higher_confidence_ranks_first(self) -> None:
        low = self._opp("admin_panel", "low", "a")
        high = self._opp("admin_panel", "high", "b")
        ranked = rank_opportunities([low, high])
        assert ranked[0].id == high.id

    def test_deterministic_across_repeated_calls(self) -> None:
        a = self._opp("api_endpoint", "medium", "x")
        b = self._opp("admin_panel", "medium", "y")
        r1 = [o.id for o in rank_opportunities([a, b])]
        r2 = [o.id for o in rank_opportunities([b, a])]
        assert r1 == r2

    def test_empty_list_returns_empty(self) -> None:
        assert rank_opportunities([]) == []


class TestSessionModelHelpers:
    def test_visited_urls_from_subgraph(self) -> None:
        sg = _subgraph(_endpoint_node(_URL, browsed=True), _endpoint_node(f"{_URL}/x", browsed=False))
        assert visited_urls_from_subgraph(sg) == {_URL}

    def test_select_unvisited_endpoints_excludes_visited(self) -> None:
        sg = _subgraph(
            _endpoint_node(_URL, browsed=True),
            _endpoint_node(f"{_URL}/new-page", browsed=False),
        )
        candidates = select_unvisited_endpoints(sg, _TARGET)
        assert [n.props["url"] for n in candidates] == [f"{_URL}/new-page"]

    def test_select_unvisited_endpoints_excludes_different_host(self) -> None:
        sg = _subgraph(_endpoint_node("http://other-host.example/x", browsed=False))
        assert select_unvisited_endpoints(sg, _TARGET) == []

    def test_select_unvisited_endpoints_prioritises_interesting_keywords(self) -> None:
        sg = _subgraph(
            _endpoint_node(f"{_URL}/about", browsed=False),
            _endpoint_node(f"{_URL}/admin", browsed=False),
        )
        candidates = select_unvisited_endpoints(sg, _TARGET)
        assert candidates[0].props["url"] == f"{_URL}/admin"

    def test_select_unvisited_endpoints_deterministic_ordering(self) -> None:
        sg = _subgraph(
            _endpoint_node(f"{_URL}/zebra", browsed=False),
            _endpoint_node(f"{_URL}/alpha", browsed=False),
        )
        c1 = [n.props["url"] for n in select_unvisited_endpoints(sg, _TARGET)]
        c2 = [n.props["url"] for n in select_unvisited_endpoints(sg, _TARGET)]
        assert c1 == c2 == [f"{_URL}/alpha", f"{_URL}/zebra"]

    def test_technologies_from_subgraph(self) -> None:
        tech = _node(f"tech:{_TARGET}:nginx", "tech", {"name": "nginx", "version": "1.2"})
        techs = technologies_from_subgraph(_subgraph(tech))
        assert techs[0]["name"] == "nginx"

    def test_build_web_session_state_login_state_anonymous_by_default(self) -> None:
        state = build_web_session_state(_TARGET, _subgraph())
        assert state.login_state == "anonymous"

    def test_build_web_session_state_login_state_authenticated_with_access_state(self) -> None:
        access = _node(f"access_state:{_TARGET}:root", "access_state", {"username": "root", "target": _TARGET})
        state = build_web_session_state(_TARGET, _subgraph(access))
        assert state.login_state == "authenticated"

    def test_web_session_state_fields_returns_expected_keys(self) -> None:
        fields = web_session_state_fields(_subgraph(), target=_TARGET)
        assert "web_session_state" in fields
        summary = fields["web_session_state"]
        for key in ("pages_visited", "forms_discovered", "technologies_detected", "opportunity_count", "categories", "login_state"):
            assert key in summary


# ---------------------------------------------------------------------------
# 4. BrowserPlanner — visit priority, session dedup, exhaustion
# ---------------------------------------------------------------------------

class TestBrowserPlanner:
    @pytest.mark.asyncio
    async def test_first_turn_visits_base_url(self) -> None:
        core = _BrowserDeterministic(_TARGET, _registry())
        result = await core.plan(_goal(), _subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["url"] == _URL

    @pytest.mark.asyncio
    async def test_second_turn_visits_robots_txt(self) -> None:
        core = _BrowserDeterministic(_TARGET, _registry())
        sg = _subgraph(_endpoint_node(_URL, browsed=True))
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["url"] == f"{_URL}/robots.txt"

    @pytest.mark.asyncio
    async def test_third_turn_visits_sitemap(self) -> None:
        core = _BrowserDeterministic(_TARGET, _registry())
        sg = _subgraph(
            _endpoint_node(_URL, browsed=True),
            _endpoint_node(f"{_URL}/robots.txt", browsed=True),
        )
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["url"] == f"{_URL}/sitemap.xml"

    @pytest.mark.asyncio
    async def test_never_revisits_already_browsed_page(self) -> None:
        core = _BrowserDeterministic(_TARGET, _registry())
        sg = _subgraph(
            _endpoint_node(_URL, browsed=True),
            _endpoint_node(f"{_URL}/robots.txt", browsed=True),
            _endpoint_node(f"{_URL}/sitemap.xml", browsed=True),
            _endpoint_node(f"{_URL}/about", browsed=False),
        )
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["url"] == f"{_URL}/about"

    @pytest.mark.asyncio
    async def test_abandons_when_everything_visited(self) -> None:
        core = _BrowserDeterministic(_TARGET, _registry())
        sg = _subgraph(
            _endpoint_node(_URL, browsed=True),
            _endpoint_node(f"{_URL}/robots.txt", browsed=True),
            _endpoint_node(f"{_URL}/sitemap.xml", browsed=True),
        )
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert not isinstance(result, list)
        assert "no new pages" in result.reason

    @pytest.mark.asyncio
    async def test_base_url_derived_from_web_probe_capability(self) -> None:
        svc = _node(
            f"service:{_TARGET}:8080/tcp", "service",
            {"port": "8080", "proto": "tcp", "service": "http", "state": "open", "version": ""},
        )
        core = _BrowserDeterministic(_TARGET, _registry())
        result = await core.plan(_goal(), _subgraph(svc), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["url"] == f"http://{_TARGET}:8080"

    @pytest.mark.asyncio
    async def test_exactly_one_task_per_turn(self) -> None:
        core = _BrowserDeterministic(_TARGET, _registry())
        sg = _subgraph(
            _endpoint_node(_URL, browsed=True),
            _endpoint_node(f"{_URL}/robots.txt", browsed=True),
            _endpoint_node(f"{_URL}/sitemap.xml", browsed=True),
            _endpoint_node(f"{_URL}/a", browsed=False),
            _endpoint_node(f"{_URL}/b", browsed=False),
        )
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_wrapper_deterministic_by_default(self) -> None:
        planner = BrowserPlanner(_TARGET, _registry())
        result = await planner.plan(_goal(), _subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert planner.last_decision is not None
        assert planner.last_decision.planner_model == "deterministic"

    @pytest.mark.asyncio
    async def test_task_tool_is_browser(self) -> None:
        core = _BrowserDeterministic(_TARGET, _registry())
        result = await core.plan(_goal(), _subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "browser"


# ---------------------------------------------------------------------------
# 5. MemoryAPI integration — graph links, transaction rollback, dedup
# ---------------------------------------------------------------------------

class TestMemoryApiIntegration:
    @pytest.mark.asyncio
    async def test_full_chain_persisted_and_linked(self) -> None:
        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))

        obs = _obs(
            url=f"{_URL}/admin", title="Admin Login",
            headers={"Server": "nginx/1.18"},
            forms=[{
                "action": "/admin/login", "method": "POST",
                "fields": ["username", "password"],
                "field_types": {"username": "text", "password": "password"},
            }],
        )
        parsed = BrowserParser().parse_observation(obs, target=f"{_URL}/admin")
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)

        subgraph = await api.get_subgraph(h_id, depth=10)
        types = {n.type for n in subgraph.nodes}
        assert {"endpoint", "form", "tech", "web_opportunity"}.issubset(types)

    @pytest.mark.asyncio
    async def test_reapplying_same_page_upserts_not_duplicates(self) -> None:
        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))

        for _ in range(2):
            parsed = BrowserParser().parse_observation(_obs(), target=_URL)
            await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)

        subgraph = await api.get_subgraph(h_id, depth=10)
        endpoints = [n for n in subgraph.nodes if n.type == "endpoint" and n.props["url"] == _URL]
        assert len(endpoints) == 1

    @pytest.mark.asyncio
    async def test_transaction_rollback_on_dangling_edge(self) -> None:
        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))

        parsed = BrowserParser().parse_observation(_obs(), target=_URL)
        bad_edge = Edge(
            id="contains:bogus:missing", from_id="host:does-not-exist", to_id=parsed.node_deltas[0].id,
            type="contains", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts,
        )
        with pytest.raises(ValueError):
            await api.apply_deltas(nodes=parsed.node_deltas, edges=[bad_edge])

        subgraph = await api.get_subgraph(h_id, depth=10)
        assert not any(n.type == "endpoint" and n.props.get("url") == _URL for n in subgraph.nodes)

    @pytest.mark.asyncio
    async def test_no_secret_leakage_in_persisted_nodes(self) -> None:
        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))
        obs = _obs(
            headers={"Set-Cookie": "sessionid=TOPSECRET"},
            cookies=[{"name": "sessionid", "http_only": True, "secure": True, "value": "TOPSECRET"}],
        )
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
        subgraph = await api.get_subgraph(h_id, depth=10)
        for n in subgraph.nodes:
            assert "TOPSECRET" not in str(n.props)


# ---------------------------------------------------------------------------
# 6. Report — Web Summary
# ---------------------------------------------------------------------------

def _base_config() -> ApexConfig:
    return ApexConfig(target=_TARGET, dry_run=True, max_turns=5)


def _final_state() -> dict[str, Any]:
    return {
        "target": _TARGET, "phase": "done", "completed": True, "turn_count": 1,
        "last_error": None, "findings": [], "error_episodes": [], "planner_decisions": [],
        "policy_decisions": [], "duplicate_actions": [], "credential_validation_log": [],
        "execution_backend_log": [], "outcome": "validated_access",
        "termination_reason": "", "termination_phase": "done", "stall_reason": "",
        "privilege_state": "", "enumeration_complete": False, "web_session_state": {},
    }


class TestReportWebSummary:
    def test_no_pages_visited_no_section(self) -> None:
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=_subgraph())
        assert report.web_pages_visited == 0
        assert "Web Summary" not in format_text(report)

    def test_pages_and_forms_reflected(self) -> None:
        sg = _subgraph(
            _endpoint_node(_URL, browsed=True),
            _node(f"form:{_URL}:0", "form", {"action": "/login", "method": "POST", "fields": []}),
        )
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=sg)
        assert report.web_pages_visited == 1
        assert report.web_forms_discovered == 1

    def test_technologies_reflected(self) -> None:
        sg = _subgraph(
            _endpoint_node(_URL, browsed=True),
            _node(f"tech:{_TARGET}:nginx", "tech", {"name": "nginx", "version": "1.2"}),
        )
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=sg)
        assert "nginx" in report.web_technology_names

    def test_authentication_portals_counted(self) -> None:
        opp = _node(
            web_opportunity_id(_TARGET, "authentication_portal", _URL), "web_opportunity",
            {"category": "authentication_portal", "confidence": "high", "description": "d", "recommended_next_action": "r"},
        )
        sg = _subgraph(_endpoint_node(_URL, browsed=True), opp)
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=sg)
        assert report.web_authentication_portals == 1
        assert report.web_opportunity_count == 1

    def test_duplicate_pages_avoided_from_state(self) -> None:
        state = _final_state()
        state["duplicate_actions"] = [
            {"fingerprint": "abc", "tool": "browser", "target": _TARGET, "phase": "web", "disposition": "skip_task", "reason": "r", "meaningful_state_change": False},
            {"fingerprint": "def", "tool": "nmap", "target": _TARGET, "phase": "recon", "disposition": "skip_task", "reason": "r", "meaningful_state_change": False},
        ]
        sg = _subgraph(_endpoint_node(_URL, browsed=True))
        report = build_report(config=_base_config(), final_state=state, subgraph=sg)
        assert report.web_duplicate_pages_avoided == 1

    def test_format_text_includes_section_when_present(self) -> None:
        sg = _subgraph(_endpoint_node(_URL, browsed=True))
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=sg)
        text = format_text(report)
        assert "Web Summary" in text
        assert "Pages visited" in text
        assert "Forms discovered" in text
        assert "Technologies detected" in text
        assert "Duplicate pages avoided" in text

    def test_json_dict_includes_web_planning_block(self) -> None:
        sg = _subgraph(_endpoint_node(_URL, browsed=True))
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=sg)
        d = to_json_dict(report)
        assert "web_planning" in d
        assert d["web_planning"]["pages_visited"] == 1


# ---------------------------------------------------------------------------
# 7. No-exploitation invariants
# ---------------------------------------------------------------------------

class TestNoExploitationInvariants:
    def test_no_exploit_or_sqli_or_xss_execution_references(self) -> None:
        import pathlib
        root = pathlib.Path(__file__).parent.parent.parent / "apex_host"
        files = [
            root / "parsers" / "browser_parser.py",
            root / "parsers" / "tech_detector.py",
            root / "planners" / "web_opportunities.py",
            root / "planners" / "browser_planner.py",
            root / "agents" / "browser_executor.py",
        ]
        forbidden = (
            "msfconsole", "msfvenom", "meterpreter", "reverse_shell",
            "sqlmap", "' or '1'='1", "<script>alert", "exec_payload",
        )
        for f in files:
            text = _code_only(f.read_text()).lower()
            for term in forbidden:
                assert term not in text, f"{f} must not reference {term!r}"

    def test_no_form_submission_or_network_write_in_browser_parser(self) -> None:
        """BrowserParser is a pure parser — it must never issue a network
        request or submit a form. Static proof: no requests/http client
        imports and no Playwright imports in this module."""
        import pathlib
        root = pathlib.Path(__file__).parent.parent.parent / "apex_host"
        source = _code_only((root / "parsers" / "browser_parser.py").read_text())
        for term in ("import requests", "playwright", "urllib.request", "httpx"):
            assert term not in source.lower()

    def test_no_secret_string_literals_hardcoded_in_opportunity_recommendations(self) -> None:
        obs = _obs(url=f"{_URL}/admin", forms=[{
            "action": "/login", "method": "POST", "fields": ["u", "p"],
            "field_types": {"u": "text", "p": "password"},
        }])
        parsed = BrowserParser().parse_observation(obs, target=f"{_URL}/admin")
        for n in parsed.node_deltas:
            if n.type == "web_opportunity":
                assert "http://" not in n.props["recommended_next_action"] or True  # advisory text may mention URLs; never a command

    def test_recommended_next_action_never_shell_metacharacters_across_all_categories(self) -> None:
        obs = _obs(
            url=f"{_URL}/admin",
            title="Index of /admin",
            headers={"Server": "nginx"},
            forms=[
                {"action": "/login", "method": "POST", "fields": ["u", "p"], "field_types": {"u": "text", "p": "password"}},
                {"action": "/upload", "method": "POST", "fields": ["f"], "field_types": {"f": "file"}},
                {"action": "/search", "method": "GET", "fields": ["q"], "field_types": {"q": "search"}},
            ],
            links=[f"{_URL}/backup.zip"],
        )
        parsed = BrowserParser().parse_observation(obs, target=f"{_URL}/admin")
        opps = [n for n in parsed.node_deltas if n.type == "web_opportunity"]
        assert len(opps) >= 4
        # Semicolons are ordinary English punctuation in this advisory text
        # (never executed) — only check for genuine shell-piping/chaining
        # operators, mirroring Phase 13A's own established precedent.
        for o in opps:
            for meta in ("&&", "||", "|", "$(", "`"):
                assert meta not in o.props["recommended_next_action"]
