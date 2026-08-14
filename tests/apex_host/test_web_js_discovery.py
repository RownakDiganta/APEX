# test_web_js_discovery.py
# §28.24 — linked-JS discovery: <script src> assets are fetched (vhost --resolve
# -L GET) and STATICALLY parsed for /api endpoint references; the JS is never
# executed. Driven through the REAL planner + router + safety + policy.
from __future__ import annotations

import asyncio

from apex_host.config import ApexConfig
from apex_host.orchestration.parsing_node import parse_single_result
from apex_host.planners.web_opportunities import pending_js_assets, pending_page_fetches
from apex_host.planners.web_planner import _WebDeterministic
from apex_host.policy import PolicyAdvisor
from apex_host.policy.policy_loader import load_policy
from apex_host.tools.registry import ToolRegistry
from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand
from memfabric.types import EvidenceBundle, Goal, Node, SubgraphView

_IP = "10.129.45.19"
_ANCHOR = f"host:{_IP}"
_VHOST = "2million.htb"


def _node(nid: str, ntype: str, props: dict, source: str = "seed") -> Node:
    return Node(id=nid, type=ntype, props=props, confidence=0.8,
                source=source, first_seen="", last_seen="")


def _subgraph(nodes: list[Node]) -> SubgraphView:
    return SubgraphView(nodes=nodes, edges=[], anchor=_ANCHOR, depth=3)


def _base_nodes() -> list[Node]:
    return [
        _node(_ANCHOR, "host", {"ip": _IP}),
        _node(f"service:{_IP}:80/tcp", "service", {"port": "80", "service": "http", "state": "open"}),
        _node(f"vhost:{_IP}:{_VHOST}", "vhost", {"hostname": _VHOST, "ip": _IP}),
    ]


def _plan(planner: _WebDeterministic, nodes: list[Node]) -> list:
    goal = Goal(id="g", description="web", phase="web", anchor_node=_ANCHOR)
    ev = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    result = asyncio.run(planner.plan(goal, _subgraph(nodes), ev))
    assert isinstance(result, list)
    return result


# ---------------------------------------------------------------------------
# 1. <script src> extraction from a fetched HTML body (same-origin only)
# ---------------------------------------------------------------------------
class TestScriptSrcExtraction:
    def test_script_src_becomes_js_asset_endpoint(self) -> None:
        # §28.25 — the page is at /invite, so a root-absolute src must resolve to
        # the HOST ROOT, a bare-relative src to the page dir, and cross-origin is
        # dropped. (This FAILS against the pre-fix directory-relative join, which
        # produced http://2million.htb/invite/js/inviteapi.min.js.)
        html = ('<!DOCTYPE html><html><head><title>Invite</title>'
                '<script src="/js/inviteapi.min.js"></script>'   # root-absolute
                '<script src="https://cdn.evil.com/analytics.js"></script>'  # cross-origin
                '<script src="app.js"></script>'                 # relative-to-page dir
                '</head><body><a href="/login">Login</a></body></html>')
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "curl_body", "args": ["-s", f"http://{_VHOST}/invite"],
             "target": f"http://{_VHOST}/invite", "stdout": html},
            {"target": _IP})
        js = {n.props["url"] for n in obs.node_deltas
              if n.type == "endpoint" and n.props.get("js_asset") is True}
        assert js == {
            f"http://{_VHOST}/js/inviteapi.min.js",   # host-root, NOT /invite/js/...
            f"http://{_VHOST}/invite/app.js",         # relative → page dir
        }
        # No cross-origin script recorded anywhere.
        assert not any("evil.com" in str(n.props) for n in obs.node_deltas)

    def test_js_asset_is_pending_and_planner_fetches_it_via_js_parser(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/js/app.js", "endpoint",
                  {"url": f"http://{_VHOST}/js/app.js", "path": "/js/app.js", "js_asset": True},
                  source="curl_body"),
        ]
        assert pending_js_assets(_subgraph(nodes))  # discovered, unfetched
        tasks = _plan(planner, nodes)
        js_fetch = [t for t in tasks if t.params.get("parser") == "js"]
        assert len(js_fetch) == 1
        a = js_fetch[0].params["args"]
        assert js_fetch[0].params["target"] == f"http://{_VHOST}/js/app.js"
        assert "--resolve" in a and f"{_VHOST}:80:{_IP}" in a and "-L" in a  # vhost GET
        assert "-I" not in a  # a GET, not HEAD

    def test_fetched_js_asset_not_refetched(self) -> None:
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/js/app.js", "endpoint",
                  {"url": f"http://{_VHOST}/js/app.js", "js_asset": True, "fetched": True},
                  source="js_analysis"),
        ]
        assert not pending_js_assets(_subgraph(nodes))


# ---------------------------------------------------------------------------
# 2. JS body → static API-path extraction (never executed)
# ---------------------------------------------------------------------------
class TestJsApiExtraction:
    _JS = (
        'const base="/api/v1";'
        'fetch("/api/v1/invite/how/to/generate").then(r=>r.json());'
        'var x=new XMLHttpRequest(); x.open("POST","/api/v1/invite/generate");'
        'const ext="https://evil.com/api/steal";'  # cross-origin — must NOT be recorded
        'url: "/api/v1/user"'
    )

    def test_extracts_api_paths_fetch_and_xhr(self) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "js", "args": ["-s", f"http://{_VHOST}/js/inviteapi.min.js"],
             "target": f"http://{_VHOST}/js/inviteapi.min.js", "stdout": self._JS},
            {"target": _IP})
        paths = {n.props.get("path") for n in obs.node_deltas
                 if n.type == "endpoint" and n.props.get("path")}
        assert "/api/v1/invite/how/to/generate" in paths
        assert "/api/v1/invite/generate" in paths  # from XHR open()
        assert "/api/v1/user" in paths  # from url: assignment
        assert all(n.source == "js_analysis" for n in obs.node_deltas)

    def test_cross_origin_api_not_extracted(self) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "js", "args": ["-s", f"http://{_VHOST}/js/x.js"],
             "target": f"http://{_VHOST}/js/x.js", "stdout": self._JS},
            {"target": _IP})
        assert not any("steal" in str(n.props) or "evil.com" in str(n.props) for n in obs.node_deltas)

    def test_discovered_api_endpoints_link_to_authorized_host(self) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "js", "args": ["-s", f"http://{_VHOST}/js/x.js"],
             "target": f"http://{_VHOST}/js/x.js", "stdout": 'fetch("/api/v1/foo")'},
            {"target": _IP})
        api = [n for n in obs.node_deltas if n.type == "endpoint" and n.props.get("path") == "/api/v1/foo"]
        assert api and api[0].props["url"] == f"http://{_VHOST}/api/v1/foo"
        # exposes edge attaches to the real host (no dangling edge → no rollback).
        assert any(e.type == "exposes" and e.to_id == api[0].id and e.from_id == _ANCHOR
                   for e in obs.edge_deltas)

    def test_js_never_executed_only_literals_read(self) -> None:
        # A JS with a computed (non-literal) URL yields NO endpoint — the parser
        # reads literal strings, it does not evaluate expressions.
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "js", "args": ["-s", f"http://{_VHOST}/js/x.js"],
             "target": f"http://{_VHOST}/js/x.js",
             "stdout": 'var p="/ap"+"i/v1/dynamic"; fetch(base + p)'},
            {"target": _IP})
        # "/ap"+"i/v1/dynamic" is a runtime concatenation — never evaluated.
        assert not any(n.props.get("path") == "/api/v1/dynamic" for n in obs.node_deltas)

    def test_empty_js_maps_nothing(self) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "js", "args": ["-s", f"http://{_VHOST}/js/x.js"],
             "target": f"http://{_VHOST}/js/x.js", "stdout": "   "},
            {"target": _IP})
        assert not obs.node_deltas


# ---------------------------------------------------------------------------
# 3. Discovered API endpoints + relative-link pages feed the fetch loop
# ---------------------------------------------------------------------------
class TestJsApiFeedsFetchLoop:
    def test_js_discovered_api_is_pending_and_fetched(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/api/v1/invite/how/to/generate", "endpoint",
                  {"url": f"http://{_VHOST}/api/v1/invite/how/to/generate",
                   "path": "/api/v1/invite/how/to/generate"}, source="js_analysis"),
        ]
        assert any("/api/v1/invite" in str(n.props.get("url", ""))
                   for n in pending_page_fetches(_subgraph(nodes)))
        tasks = _plan(planner, nodes)
        body = [t for t in tasks
                if t.params.get("parser") == "curl_body"
                and t.params["target"] == f"http://{_VHOST}/api/v1/invite/how/to/generate"]
        assert body and "--resolve" in body[0].params["args"]

    def test_relative_link_page_is_pending_and_fetched(self) -> None:
        # A discovered relative-link page (/invite) is fetched so its <script src>
        # can be seen — the precondition for reaching its JS.
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/invite", "endpoint",
                  {"url": f"http://{_VHOST}/invite", "path": "/invite"}, source="curl_body"),
        ]
        assert any(str(n.props.get("url", "")).endswith("/invite")
                   for n in pending_page_fetches(_subgraph(nodes)))
        tasks = _plan(planner, nodes)
        assert any(t.params["target"] == f"http://{_VHOST}/invite"
                   and t.params.get("parser") == "curl_body" for t in tasks)


# ---------------------------------------------------------------------------
# 4. Safety + policy
# ---------------------------------------------------------------------------
class TestJsFetchSafetyAndPolicy:
    def _cfg(self) -> ApexConfig:
        return ApexConfig(target=_IP, dry_run=True, allowed_tools=["curl"])

    def test_js_fetch_command_passes_safety(self) -> None:
        cfg = self._cfg()
        planner = _WebDeterministic(_IP, ToolRegistry.from_config(cfg))
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/js/app.js", "endpoint",
                  {"url": f"http://{_VHOST}/js/app.js", "js_asset": True}, source="curl_body"),
        ]
        tasks = _plan(planner, nodes)
        for t in tasks:
            check_command(ToolCommand(tool=t.params["tool"], args=t.params["args"]), cfg)

    def test_js_fetch_of_authorized_vhost_is_policy_approved(self) -> None:
        cfg = self._cfg()
        planner = _WebDeterministic(_IP, ToolRegistry.from_config(cfg))
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/js/app.js", "endpoint",
                  {"url": f"http://{_VHOST}/js/app.js", "js_asset": True}, source="curl_body"),
        ]
        tasks = _plan(planner, nodes)
        js = next(t for t in tasks if t.params.get("parser") == "js")
        advisor = PolicyAdvisor(load_policy(cfg), cfg)
        assert advisor.review_task(js, "web", None, cfg).is_approved

    def test_cross_origin_script_never_fetched(self) -> None:
        # A cross-origin <script src> is not recorded (TestScriptSrcExtraction),
        # so it is never in the pending set and never fetched.
        nodes = _base_nodes()  # no js_asset seeded
        assert not pending_js_assets(_subgraph(nodes))


# ---------------------------------------------------------------------------
# 5. §28.25 — src/href URL resolution against the fetched page URL
# ---------------------------------------------------------------------------
class TestScriptSrcUrlResolution:
    """A page fetched at a sub-path (/invite) must resolve links/scripts
    correctly: root-absolute against the HOST ROOT, bare-relative against the
    page DIRECTORY, same-origin full URLs as-is, cross-origin rejected."""

    def _parse(self, html: str, page: str) -> list:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "curl_body", "args": ["-s", page],
             "target": page, "stdout": html},
            {"target": _IP})
        return obs.node_deltas

    def _js_urls(self, nodes: list) -> set:
        return {n.props["url"] for n in nodes
                if n.type == "endpoint" and n.props.get("js_asset") is True}

    def test_root_absolute_script_resolves_to_host_root(self) -> None:
        # THE bug: /js/app.js on /invite must be host-root, not /invite/js/app.js.
        nodes = self._parse('<html><title>x</title><script src="/js/app.js"></script></html>',
                            f"http://{_VHOST}/invite")
        assert self._js_urls(nodes) == {f"http://{_VHOST}/js/app.js"}
        assert f"http://{_VHOST}/invite/js/app.js" not in self._js_urls(nodes)

    def test_relative_script_resolves_to_page_directory(self) -> None:
        nodes = self._parse('<html><title>x</title><script src="sub/x.js"></script></html>',
                            f"http://{_VHOST}/invite")
        assert self._js_urls(nodes) == {f"http://{_VHOST}/invite/sub/x.js"}

    def test_full_url_same_origin_script_used_as_is(self) -> None:
        nodes = self._parse(
            f'<html><title>x</title><script src="http://{_VHOST}/assets/m.js"></script></html>',
            f"http://{_VHOST}/invite")
        assert self._js_urls(nodes) == {f"http://{_VHOST}/assets/m.js"}

    def test_cross_origin_script_rejected(self) -> None:
        nodes = self._parse(
            '<html><title>x</title><script src="https://cdn.evil.com/a.js"></script></html>',
            f"http://{_VHOST}/invite")
        assert self._js_urls(nodes) == set()

    def test_root_absolute_href_resolves_to_host_root(self) -> None:
        # The relative-link extraction gets the same fix: /admin on /invite is
        # host-root http://vhost/admin, not http://vhost/invite/admin.
        nodes = self._parse('<html><title>x</title><a href="/admin">A</a></html>',
                            f"http://{_VHOST}/invite")
        link_urls = {n.props["url"] for n in nodes
                     if n.type == "endpoint" and n.props.get("path") == "/admin"}
        assert link_urls == {f"http://{_VHOST}/admin"}
        assert f"http://{_VHOST}/invite/admin" not in {n.props.get("url") for n in nodes}

    def test_end_to_end_invite_js_url_correct_then_api_extracted(self) -> None:
        # /invite HTML → correct host-root JS URL → fetch that JS (fake body) →
        # /api/v1/... reference statically extracted as an endpoint.
        html = '<html><title>Invite</title><script src="/js/inviteapi.min.js"></script></html>'
        page_nodes = self._parse(html, f"http://{_VHOST}/invite")
        js_url = next(iter(self._js_urls(page_nodes)))
        assert js_url == f"http://{_VHOST}/js/inviteapi.min.js"  # host-root, not /invite/js/...
        # Now fetch that JS asset — the (fake) body references an API path.
        js_body = 'fetch("/api/v1/invite/how/to/generate").then(r=>r.json());'
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "js", "args": ["-s", js_url],
             "target": js_url, "stdout": js_body},
            {"target": _IP})
        api_paths = {n.props.get("path") for n in obs.node_deltas if n.type == "endpoint"}
        assert "/api/v1/invite/how/to/generate" in api_paths


# ---------------------------------------------------------------------------
# 6. §28.26 — jQuery-style extraction coverage (BUG1)
# ---------------------------------------------------------------------------
class TestJqueryExtraction:
    """Static extraction of API refs from jQuery calls — never executes the JS."""

    def _paths(self, js: str) -> set:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "js", "args": ["-s", f"http://{_VHOST}/js/x.js"],
             "target": f"http://{_VHOST}/js/x.js", "stdout": js},
            {"target": _IP})
        return {n.props.get("path") for n in obs.node_deltas
                if n.type == "endpoint" and n.props.get("path")}

    def test_ajax_options_object_url_extracted(self) -> None:
        assert "/api/v1/x" in self._paths('$.ajax({type:"POST",dataType:"json",url:"/api/v1/x"});')

    def test_dollar_get_extracted(self) -> None:
        assert "/api/y" in self._paths('$.get("/api/y");')

    def test_dollar_post_and_getjson_nonapi_extracted(self) -> None:
        # The real gap: jQuery methods with a non-/api same-origin path were missed.
        paths = self._paths('$.post("/login/submit", d); $.getJSON("/user/data");')
        assert "/login/submit" in paths and "/user/data" in paths

    def test_generic_url_key_extracted(self) -> None:
        assert "/api/z" in self._paths('var o={method:"GET",url:"/api/z"};')

    def test_same_origin_full_url_reduced_to_path(self) -> None:
        assert "/api/v1/full" in self._paths(f'$.ajax({{url:"http://{_VHOST}/api/v1/full"}});')

    def test_cross_origin_url_rejected(self) -> None:
        paths = self._paths('$.ajax({url:"https://evil.com/api/steal"}); $.get("https://evil.com/x");')
        assert not any("evil.com" in str(p) or "steal" in str(p) for p in paths)

    def test_bare_word_url_rejected(self) -> None:
        assert self._paths('var o={url:"json"};') == set()

    def test_js_still_never_executed(self) -> None:
        # A runtime-concatenated URL inside a jQuery call is not recovered.
        assert "/api/v1/dyn" not in self._paths('var p="/ap"+"i/v1/dyn"; $.get(base+p);')


# ---------------------------------------------------------------------------
# 7. §28.26 — fetch-loop prioritization (BUG2)
# ---------------------------------------------------------------------------
class TestFetchPrioritization:
    """High-signal JS/API endpoints are fetched before low-signal static assets,
    within the bounded per-turn budget."""

    def _nodes_with_assets(self) -> list[Node]:
        return _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/css/style.css", "endpoint",
                  {"url": f"http://{_VHOST}/css/style.css", "path": "/css/style.css"}, source="curl_body"),
            _node(f"endpoint:http://{_VHOST}/img/logo.png", "endpoint",
                  {"url": f"http://{_VHOST}/img/logo.png", "path": "/img/logo.png"}, source="curl_body"),
            _node(f"endpoint:http://{_VHOST}/fonts/a.woff2", "endpoint",
                  {"url": f"http://{_VHOST}/fonts/a.woff2", "path": "/fonts/a.woff2"}, source="curl_body"),
            _node(f"endpoint:http://{_VHOST}/js/inviteapi.min.js", "endpoint",
                  {"url": f"http://{_VHOST}/js/inviteapi.min.js", "js_asset": True}, source="curl_body"),
        ]

    def test_static_assets_excluded_from_page_fetches(self) -> None:
        pend = pending_page_fetches(_subgraph(self._nodes_with_assets()))
        paths = {n.props.get("path") for n in pend}
        assert "/css/style.css" not in paths
        assert "/img/logo.png" not in paths
        assert "/fonts/a.woff2" not in paths

    def test_invite_js_fetched_and_no_asset_fetch_emitted(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        tasks = _plan(planner, self._nodes_with_assets())
        # The /invite JS IS fetched (parser "js", --resolve GET).
        js_fetch = [t for t in tasks if t.params.get("parser") == "js"]
        assert any("inviteapi.min.js" in t.params["target"] for t in js_fetch)
        # No css/image/font is ever fetched (they yield no API references).
        targets = " ".join(t.params.get("target", "") for t in tasks)
        assert ".css" not in targets and ".png" not in targets and ".woff2" not in targets

    def test_api_endpoint_ranks_before_plain_page(self) -> None:
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/team", "endpoint",
                  {"url": f"http://{_VHOST}/team", "path": "/team"}, source="curl_body"),
            _node(f"endpoint:http://{_VHOST}/api/v1/user", "endpoint",
                  {"url": f"http://{_VHOST}/api/v1/user", "path": "/api/v1/user"}, source="js_analysis"),
        ]
        order = [n.props.get("path") for n in pending_page_fetches(_subgraph(nodes))]
        assert order.index("/api/v1/user") < order.index("/team")

    def test_high_signal_page_js_ranked_first(self) -> None:
        # inviteapi.min.js (own path contains "api") beats a homepage bundle.
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/js/htb-frontpage.min.js", "endpoint",
                  {"url": f"http://{_VHOST}/js/htb-frontpage.min.js", "js_asset": True}, source="curl_body"),
            _node(f"endpoint:http://{_VHOST}/js/inviteapi.min.js", "endpoint",
                  {"url": f"http://{_VHOST}/js/inviteapi.min.js", "js_asset": True}, source="curl_body"),
        ]
        order = [n.props["url"].rsplit("/", 1)[-1] for n in pending_js_assets(_subgraph(nodes))]
        assert order.index("inviteapi.min.js") < order.index("htb-frontpage.min.js")
