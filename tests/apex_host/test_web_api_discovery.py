# test_web_api_discovery.py
# Bounded API-surface DISCOVERY (§28.22): fixed API/GraphQL root probes, an
# operator-wordlist API scan, JSON structure mapping, and read-only GraphQL
# introspection — driven through the REAL planner + router + safety + policy.
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from apex_host.config import ApexConfig
from apex_host.orchestration.parsing_node import parse_single_result
from apex_host.planners.web_opportunities import pending_enumerated_endpoints
from apex_host.planners.web_planner import (
    _API_ROOT_PATHS,
    _GRAPHQL_INTROSPECTION_BODY,
    _GRAPHQL_PATHS,
    _WebDeterministic,
)
from apex_host.policy import PolicyAdvisor
from apex_host.policy.policy_loader import load_policy
from apex_host.tools.registry import ToolRegistry
from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand
from memfabric.types import EvidenceBundle, Goal, Node, SubgraphView

_IP = "10.129.45.19"
_ANCHOR = f"host:{_IP}"
_VHOST = "app.example.htb"


def _node(nid: str, ntype: str, props: dict, source: str = "seed") -> Node:
    return Node(id=nid, type=ntype, props=props, confidence=0.8,
                source=source, first_seen="", last_seen="")


def _subgraph(nodes: list[Node]) -> SubgraphView:
    return SubgraphView(nodes=nodes, edges=[], anchor=_ANCHOR, depth=3)


def _base_nodes(with_vhost: bool = True) -> list[Node]:
    nodes = [
        _node(_ANCHOR, "host", {"ip": _IP}),
        _node(f"service:{_IP}:80/tcp", "service", {"port": "80", "service": "http", "state": "open"}),
    ]
    if with_vhost:
        nodes.append(_node(f"vhost:{_IP}:{_VHOST}", "vhost", {"hostname": _VHOST, "ip": _IP}))
    return nodes


def _plan(planner: _WebDeterministic, nodes: list[Node]) -> list:
    goal = Goal(id="g", description="web", phase="web", anchor_node=_ANCHOR)
    ev = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    result = asyncio.run(planner.plan(goal, _subgraph(nodes), ev))
    assert isinstance(result, list)
    return result


def _paths(tasks: list, parser: str) -> set[str]:
    return {
        urlsplit(t.params["target"]).path.rstrip("/") or "/"
        for t in tasks if t.params.get("parser") == parser
    }


# ---------------------------------------------------------------------------
# 1. Fixed generic API/GraphQL root probes (no wordlist required)
# ---------------------------------------------------------------------------
class TestApiRootProbes:
    def test_probes_generic_api_and_graphql_roots(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        tasks = _plan(planner, _base_nodes(with_vhost=True))
        head_paths = _paths(tasks, "command")
        body_paths = _paths(tasks, "curl_body")
        for p in (*_API_ROOT_PATHS, *_GRAPHQL_PATHS):
            assert p in head_paths, f"{p} HEAD probe missing"
            assert p in body_paths, f"{p} GET probe missing"

    def test_probes_use_vhost_resolve_path(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        tasks = _plan(planner, _base_nodes(with_vhost=True))
        api = next(t for t in tasks
                   if t.params.get("parser") == "command"
                   and urlsplit(t.params["target"]).path == "/api")
        # Host-aware: --resolve pins the vhost to the authorized IP (never a raw
        # off-scope host), and the URL is the vhost URL.
        assert "--resolve" in api.params["args"]
        assert f"{_VHOST}:80:{_IP}" in api.params["args"]
        assert api.params["target"] == f"http://{_VHOST}/api"

    def test_probes_once_per_phase(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        # An endpoint already exists at an API convention → probes not re-emitted.
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_VHOST}/api", "endpoint",
                  {"url": f"http://{_VHOST}/api", "status": "200", "fetched": True}, source="curl"),
        ]
        tasks = _plan(planner, nodes)
        assert "/api/v1" not in _paths(tasks, "command"), "API roots re-probed after prior probe"

    def test_no_probes_without_curl(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["ffuf"]))
        result = asyncio.run(planner.plan(
            Goal(id="g", description="web", phase="web", anchor_node=_ANCHOR),
            _subgraph(_base_nodes()), EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])))
        # No curl → AbandonSignal (no web-capable tools) or no curl tasks.
        if isinstance(result, list):
            assert not any(t.params["tool"] == "curl" for t in result)


# ---------------------------------------------------------------------------
# 1b. §28.23 — API probes are vhost-consistent (--resolve -L GET), host-aware
# gate, and deferred until the base is settled.
# ---------------------------------------------------------------------------
class TestApiProbesVhostConsistent:
    def test_ip_scoped_stub_does_not_block_vhost_probe(self) -> None:
        # §28.23 regression: a pre-vhost bare-IP probe created an IP-scoped /api
        # 301 stub. With a vhost now discovered, the API roots MUST still be
        # probed through the vhost --resolve -L path. FAILS against the old
        # host-agnostic gate (which treated /api as "done" from the IP stub).
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        nodes = _base_nodes(with_vhost=True) + [
            _node(f"endpoint:http://{_IP}/api", "endpoint",
                  {"url": f"http://{_IP}/api", "status": "301", "fetched": True}, source="curl"),
        ]
        tasks = _plan(planner, nodes)
        api_body = [t for t in tasks if t.params.get("parser") == "curl_body"
                    and t.params["target"] == f"http://{_VHOST}/api"]
        assert api_body, "vhost /api GET not emitted despite an IP-scoped stub"
        a = api_body[0].params["args"]
        assert "--resolve" in a and f"{_VHOST}:80:{_IP}" in a and "-L" in a

    def test_api_probes_get_the_body_via_resolve(self) -> None:
        # Every fixed API-root path emits a GET body probe (not only HEAD),
        # through the vhost --resolve -L path.
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        tasks = _plan(planner, _base_nodes(with_vhost=True))
        for p in _API_ROOT_PATHS:
            body = next((t for t in tasks if t.params.get("parser") == "curl_body"
                         and urlsplit(t.params["target"]).path == p), None)
            assert body is not None, f"no GET body probe for {p}"
            assert "--resolve" in body.params["args"] and "-L" in body.params["args"]
            assert "-I" not in body.params["args"]  # it is a GET, not HEAD

    def test_probes_deferred_until_base_settled(self) -> None:
        # No vhost AND no fetched homepage → probes deferred (never premature
        # bare-IP probing on turn 1).
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        nodes = [_node(_ANCHOR, "host", {"ip": _IP}),
                 _node(f"service:{_IP}:80/tcp", "service",
                       {"port": "80", "service": "http", "state": "open"})]
        tasks = _plan(planner, nodes)
        assert not any(urlsplit(t.params["target"]).path == "/api" for t in tasks), \
            "API roots probed before the base was settled"

    def test_no_vhost_probes_after_homepage_fetched(self) -> None:
        # No vhost, homepage fetched (200, no redirect) → the IP is the app →
        # probe API roots against the IP.
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        nodes = [_node(_ANCHOR, "host", {"ip": _IP}),
                 _node(f"service:{_IP}:80/tcp", "service",
                       {"port": "80", "service": "http", "state": "open"}),
                 _node(f"endpoint:http://{_IP}/", "endpoint",
                       {"url": f"http://{_IP}/", "status": "200", "fetched": True}, source="curl")]
        tasks = _plan(planner, nodes)
        assert any(urlsplit(t.params["target"]).path == "/api" for t in tasks)

    def test_no_duplicate_curl_action_when_probe_and_fetch_overlap(self) -> None:
        # A discovered /api endpoint (fetch loop) and the fixed /api probe both
        # resolve to the same vhost URL — the planner emits it only once.
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        nodes = _base_nodes(with_vhost=True) + [
            _node(f"endpoint:http://{_IP}/api", "endpoint",
                  {"url": f"http://{_IP}/api", "status": "200"}, source="ffuf"),
        ]
        tasks = _plan(planner, nodes)
        head_api = [t for t in tasks if t.params.get("parser") == "command"
                    and t.params["target"] == f"http://{_VHOST}/api"]
        assert len(head_api) == 1  # deduped, not two identical fetches


# ---------------------------------------------------------------------------
# 2. API wordlist scan (operator-configured, distinct provenance)
# ---------------------------------------------------------------------------
class TestApiWordlistScan:
    def test_emits_bounded_api_ffuf_with_distinct_parser(self) -> None:
        planner = _WebDeterministic(
            _IP, ToolRegistry(["curl", "ffuf"]),
            web_api_wordlist_path="/api-wl.txt", web_enum_threads=12, web_enum_max_seconds=20)
        tasks = _plan(planner, _base_nodes(with_vhost=True))
        api_scans = [t for t in tasks if t.params.get("parser") == "ffuf_api"]
        assert len(api_scans) == 1
        a = api_scans[0].params["args"]
        assert "/api-wl.txt" in a
        assert "-t" in a and a[a.index("-t") + 1] == "12"
        assert "-maxtime" in a and a[a.index("-maxtime") + 1] == "20"
        assert "-H" in a and f"Host: {_VHOST}" in a
        assert api_scans[0].params["target"] == f"http://{_IP}"  # authorized IP

    def test_no_api_scan_without_wordlist(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl", "ffuf"]))
        tasks = _plan(planner, _base_nodes())
        assert not any(t.params.get("parser") in ("ffuf_api", "gobuster_api") for t in tasks)

    def test_api_scan_once_per_phase_independent_of_content(self) -> None:
        planner = _WebDeterministic(
            _IP, ToolRegistry(["curl", "ffuf"]), web_api_wordlist_path="/api-wl.txt")
        # An ffuf_api endpoint already exists → API scan not re-emitted; but a
        # content-source ffuf endpoint would NOT gate the API scan (independent).
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_IP}/users", "endpoint",
                  {"url": f"http://{_IP}/users", "status": "200"}, source="ffuf_api"),
        ]
        tasks = _plan(planner, nodes)
        assert not any(t.params.get("parser") == "ffuf_api" for t in tasks)

    def test_content_and_api_scans_are_independent(self) -> None:
        planner = _WebDeterministic(
            _IP, ToolRegistry(["curl", "ffuf"]),
            web_wordlist_path="/content-wl.txt", web_api_wordlist_path="/api-wl.txt")
        tasks = _plan(planner, _base_nodes())
        parsers = {t.params.get("parser") for t in tasks}
        assert "ffuf" in parsers and "ffuf_api" in parsers  # both scans emitted

    def test_ffuf_api_hit_routes_to_endpoint_with_distinct_source(self) -> None:
        stdout = "users                   [Status: 200, Size: 40]"
        obs, _ = parse_single_result(
            {"tool": "ffuf", "parser": "ffuf_api", "args": ["-u", f"http://{_IP}/FUZZ"],
             "target": f"http://{_IP}", "stdout": stdout},
            {"target": _IP})
        eps = [n for n in obs.node_deltas if n.type == "endpoint"]
        assert eps and all(n.source == "ffuf_api" for n in eps)
        assert all(e.from_id == _ANCHOR for e in obs.edge_deltas)  # no dangling edge

    def test_api_wordlist_endpoints_are_fetched(self) -> None:
        # A discovered ffuf_api endpoint (not yet fetched) is in the pending set.
        nodes = _base_nodes() + [
            _node(f"endpoint:http://{_IP}/api/v1/users", "endpoint",
                  {"url": f"http://{_IP}/api/v1/users", "status": "200"}, source="ffuf_api"),
        ]
        pending = pending_enumerated_endpoints(_subgraph(nodes))
        assert any(n.props["url"].endswith("/api/v1/users") for n in pending)


# ---------------------------------------------------------------------------
# 3. JSON API response structure mapping (values never recorded)
# ---------------------------------------------------------------------------
class TestJsonStructureMapping:
    def test_json_object_becomes_endpoint_with_keys(self) -> None:
        body = '{"id": 7, "username": "secret-value", "email": "x@y.z", "role": "admin"}'
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "curl_body", "args": ["-s", f"http://{_VHOST}/api"],
             "target": f"http://{_VHOST}/api", "stdout": body},
            {"target": _IP})
        eps = [n for n in obs.node_deltas if n.type == "endpoint"]
        assert eps, "JSON response did not become an endpoint node"
        ep = eps[0]
        assert ep.props.get("content_kind") == "json" and ep.props.get("api_response") is True
        assert ep.props["json_keys"] == ["email", "id", "role", "username"]
        # No VALUE ever recorded — structure only.
        serialized = str([n.props for n in obs.node_deltas])
        assert "secret-value" not in serialized and "x@y.z" not in serialized

    def test_json_array_records_item_keys(self) -> None:
        body = '[{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]'
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "curl_body", "args": ["-s", f"http://{_IP}/api/users"],
             "target": f"http://{_IP}/api/users", "stdout": body},
            {"target": _IP})
        ep = next(n for n in obs.node_deltas if n.type == "endpoint")
        assert ep.props.get("json_array") is True
        assert ep.props["json_item_keys"] == ["id", "name"]
        assert "\"a\"" not in str(ep.props) and "'a'" not in str(ep.props.get("json_item_keys"))

    def test_non_json_non_html_still_falls_back(self) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "curl_body", "args": ["-s", f"http://{_IP}/x"],
             "target": f"http://{_IP}/x", "stdout": "plain text, not json or html"},
            {"target": _IP})
        assert not obs.node_deltas and obs.proposed_knowledge  # KnowledgeEntry fallback

    def test_html_body_unchanged(self) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "curl_body", "args": ["-s", f"http://{_IP}/"],
             "target": f"http://{_IP}/", "stdout": "<html><title>Home</title></html>"},
            {"target": _IP})
        ep = next(n for n in obs.node_deltas if n.type == "endpoint")
        assert ep.props.get("title") == "Home"  # existing HTML path intact

    def test_empty_response_maps_nothing(self) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "curl_body", "args": ["-s", f"http://{_IP}/api/v1"],
             "target": f"http://{_IP}/api/v1", "stdout": ""},
            {"target": _IP})
        assert not obs.node_deltas and not obs.proposed_knowledge

    def test_raw_ip_301_not_mapped_as_api_content(self) -> None:
        # A bare-IP /api HEAD 301 stub becomes a plain endpoint (status 301) — it
        # is NOT recorded as JSON/API content (no content_kind=json/api_response).
        head = "HTTP/1.1 301 Moved Permanently\r\nLocation: http://2million.htb/api/v1\r\n"
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "command", "args": ["-s", "-I", f"http://{_IP}/api/v1"],
             "target": f"http://{_IP}/api/v1", "stdout": head},
            {"target": _IP})
        eps = [n for n in obs.node_deltas if n.type == "endpoint"]
        assert eps and eps[0].props.get("status") == "301"
        assert eps[0].props.get("content_kind") != "json"
        assert eps[0].props.get("api_response") is not True


# ---------------------------------------------------------------------------
# 4. GraphQL introspection (read-only schema READ)
# ---------------------------------------------------------------------------
_INTROSPECTION = (
    '{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},'
    '"types":[{"name":"User","kind":"OBJECT","fields":[{"name":"id"},{"name":"username"}]},'
    '{"name":"Query","kind":"OBJECT","fields":[{"name":"users"}]},'
    '{"name":"__Schema","kind":"OBJECT","fields":[]}]}}}'
)


class TestGraphQLIntrospection:
    def _graphql_present(self) -> list[Node]:
        gql_url = f"http://{_VHOST}/graphql"
        return _base_nodes() + [
            _node(f"endpoint:{gql_url}", "endpoint",
                  {"url": gql_url, "status": "400", "fetched": True}, source="curl"),
        ]

    def test_introspection_emitted_for_live_graphql_endpoint(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        tasks = _plan(planner, self._graphql_present())
        gql = [t for t in tasks if t.params.get("parser") == "graphql"]
        assert len(gql) == 1
        a = gql[0].params["args"]
        assert "-X" in a and "POST" in a
        assert "-d" in a and _GRAPHQL_INTROSPECTION_BODY in a  # the ONE fixed body
        assert gql[0].params["target"] == f"http://{_VHOST}/graphql"

    def test_introspection_gated_once(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        nodes = self._graphql_present() + [
            _node(f"api_schema:http://{_VHOST}/graphql", "api_schema",
                  {"endpoint_url": f"http://{_VHOST}/graphql", "type_names": ["User"]}),
        ]
        tasks = _plan(planner, nodes)
        assert not any(t.params.get("parser") == "graphql" for t in tasks)

    def test_no_introspection_for_404_graphql(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl"]))
        gql_url = f"http://{_VHOST}/graphql"
        nodes = _base_nodes() + [
            _node(f"endpoint:{gql_url}", "endpoint",
                  {"url": gql_url, "status": "404", "fetched": True}, source="curl"),
        ]
        tasks = _plan(planner, nodes)
        assert not any(t.params.get("parser") == "graphql" for t in tasks)

    def test_introspection_response_becomes_schema_node(self) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "graphql", "args": ["-s", "-X", "POST"],
             "target": f"http://{_VHOST}/graphql", "stdout": _INTROSPECTION},
            {"target": _IP})
        schema = [n for n in obs.node_deltas if n.type == "api_schema"]
        assert len(schema) == 1
        s = schema[0]
        assert s.props["query_type"] == "Query" and s.props["mutation_type"] == "Mutation"
        assert s.props["type_names"] == ["Query", "User"]  # __Schema meta type skipped
        assert set(s.props["field_names"]) == {"id", "username", "users"}
        # endpoint --contains--> api_schema, both under the authorized host.
        assert any(e.type == "contains" and e.to_id == s.id for e in obs.edge_deltas)
        assert any(n.type == "endpoint" and n.props.get("graphql") is True for n in obs.node_deltas)

    def test_invalid_introspection_records_nothing(self) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": "graphql", "args": ["-s", "-X", "POST"],
             "target": f"http://{_VHOST}/graphql", "stdout": '{"errors":[{"message":"nope"}]}'},
            {"target": _IP})
        assert not obs.node_deltas  # not a valid __schema → nothing recorded


# ---------------------------------------------------------------------------
# 5. Safety + policy: bounded/safe commands; metachar blocked; off-scope blocked
# ---------------------------------------------------------------------------
class TestApiDiscoverySafetyAndPolicy:
    def _cfg(self, **kw) -> ApexConfig:
        base = dict(target=_IP, dry_run=True, allowed_tools=["curl", "ffuf"],
                    allow_password_lists=True)
        base.update(kw)
        return ApexConfig(**base)

    def test_emitted_commands_pass_safety(self) -> None:
        cfg = self._cfg(web_api_wordlist_path="/api-wl.txt")
        planner = _WebDeterministic(_IP, ToolRegistry.from_config(cfg),
                                    web_api_wordlist_path="/api-wl.txt")
        tasks = _plan(planner, self._graphql_nodes())
        checked = 0
        for t in tasks:
            check_command(ToolCommand(tool=t.params["tool"], args=t.params["args"]), cfg)
            checked += 1
        assert checked == len(tasks)  # every emitted command is metachar-free

    def test_introspection_body_has_no_shell_metacharacters(self) -> None:
        # The one POST body is safe by construction (module constant).
        cfg = self._cfg()
        check_command(
            ToolCommand(tool="curl", args=["-s", "-X", "POST", "-H", "Content-Type: application/json",
                                           "-d", _GRAPHQL_INTROSPECTION_BODY, f"http://{_IP}/graphql"]),
            cfg)

    def test_metacharacter_injected_scan_blocked(self) -> None:
        cfg = self._cfg()
        try:
            check_command(ToolCommand(tool="ffuf",
                          args=["-u", f"http://{_IP}/FUZZ", "-H", "Host: evil; rm -rf /"]), cfg)
        except ValueError:
            return
        raise AssertionError("safety.py did not block a metacharacter-injected scan")

    def test_off_scope_target_policy_blocked(self) -> None:
        cfg = self._cfg()
        advisor = PolicyAdvisor(load_policy(cfg), cfg)
        # An API probe against a DIFFERENT host is off-scope.
        from memfabric.types import TaskSpec
        off = TaskSpec(id="x", goal_id="g", executor_domain="web",
                       params={"tool": "curl", "args": ["-s", "http://10.10.10.99/api"],
                               "target": "http://10.10.10.99/api", "parser": "command"},
                       subgraph_anchor=_ANCHOR, phase="web")
        assert not advisor.review_task(off, "web", None, cfg).is_approved

    def _graphql_nodes(self) -> list[Node]:
        gql_url = f"http://{_IP}/graphql"
        return _base_nodes(with_vhost=False) + [
            _node(f"endpoint:{gql_url}", "endpoint",
                  {"url": gql_url, "status": "400", "fetched": True}, source="curl"),
        ]
