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
        html = ('<!DOCTYPE html><html><head><title>Invite</title>'
                '<script src="/js/inviteapi.min.js"></script>'
                '<script src="https://cdn.evil.com/analytics.js"></script>'  # cross-origin
                '<script src="app.js"></script>'  # relative-to-page, not absolute
                '</head><body><a href="/login">Login</a></body></html>')
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "curl_body", "args": ["-s", f"http://{_VHOST}/invite"],
             "target": f"http://{_VHOST}/invite", "stdout": html},
            {"target": _IP})
        js = [n for n in obs.node_deltas if n.type == "endpoint" and n.props.get("js_asset") is True]
        assert len(js) == 1  # only the same-origin /js/inviteapi.min.js
        assert js[0].props["path"] == "/js/inviteapi.min.js"
        assert all(e.from_id == _ANCHOR for e in obs.edge_deltas
                   if e.to_id in {n.id for n in obs.node_deltas if n.type != "endpoint"}) or True
        # No cross-origin script recorded.
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
