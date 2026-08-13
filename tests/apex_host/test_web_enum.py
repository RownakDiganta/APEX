# test_web_enum.py
# Bounded web content-enumeration (§28.12): ffuf/gobuster hits become vhost-linked
# endpoint nodes through the REAL router, and the emitted scan is bounded + safe.
from __future__ import annotations

import asyncio

import pytest

from apex_host.config import ApexConfig
from apex_host.eval.check_config import validate_combinations
from apex_host.orchestration.parsing_node import parse_single_result
from apex_host.planners.web_planner import _WebDeterministic
from apex_host.policy import PolicyAdvisor
from apex_host.policy.policy_loader import load_policy
from apex_host.tools.registry import ToolRegistry
from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand
from memfabric.ids import new_id
from memfabric.types import (
    EvidenceBundle,
    Goal,
    Node,
    SubgraphView,
    TaskSpec,
)

_IP = "10.129.40.164"
_ANCHOR = f"host:{_IP}"


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
        nodes.append(_node(f"vhost:{_IP}:2million.htb", "vhost",
                           {"hostname": "2million.htb", "ip": _IP}))
    return nodes


def _plan(planner: _WebDeterministic, nodes: list[Node]) -> list:
    goal = Goal(id="g", description="web", phase="web", anchor_node=_ANCHOR)
    ev = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    result = asyncio.run(planner.plan(goal, _subgraph(nodes), ev))
    assert isinstance(result, list)
    return result


# ---------------------------------------------------------------------------
# Router path: a ffuf/gobuster hit becomes a vhost-linked endpoint node.
# Driven through parse_single_result (the REAL router), NOT a direct parser
# call — the §28.11 test-faithfulness lesson.
# ---------------------------------------------------------------------------
class TestEnumHitsBecomeEndpoints:
    def test_ffuf_hit_routes_to_endpoint_under_host(self) -> None:
        stdout = "api                     [Status: 200, Size: 12]\n" \
                 "admin                   [Status: 301, Size: 0]"
        obs, src = parse_single_result(
            {"tool": "ffuf", "parser": "ffuf",
             "args": ["-u", f"http://{_IP}/FUZZ"],
             "target": f"http://{_IP}", "stdout": stdout},
            {"target": _IP},  # ApexGraphState-shaped; only state["target"] is read
        )
        eps = [n for n in obs.node_deltas if n.type == "endpoint"]
        assert {n.props["path"] for n in eps} == {"api", "admin"}
        assert all(n.source == "ffuf" for n in eps)  # provenance
        # No dangling edge — all exposes attach to the real host node.
        assert all(e.from_id == _ANCHOR for e in obs.edge_deltas)

    def test_gobuster_hit_routes_to_endpoint_under_host(self) -> None:
        stdout = "/api (Status: 200) [Size: 12]\n/robots.txt (Status: 200) [Size: 40]"
        obs, _src = parse_single_result(
            {"tool": "gobuster", "parser": "gobuster",
             "args": ["dir", "-u", f"http://{_IP}"],
             "target": f"http://{_IP}", "stdout": stdout},
            {"target": _IP},
        )
        eps = [n for n in obs.node_deltas if n.type == "endpoint"]
        assert any(n.props["path"] == "/api" for n in eps)
        assert all(n.source == "gobuster" for n in eps)
        assert all(e.from_id == _ANCHOR for e in obs.edge_deltas)


# ---------------------------------------------------------------------------
# Planner: one bounded scan, once per phase, prefer ffuf.
# ---------------------------------------------------------------------------
class TestBoundedEnumEmission:
    def _planner(self, tools: list[str], **kw) -> _WebDeterministic:
        return _WebDeterministic(_IP, ToolRegistry(tools), web_wordlist_path="/wl.txt", **kw)

    def test_emits_one_bounded_ffuf_with_vhost_host_header(self) -> None:
        planner = self._planner(["curl", "ffuf", "gobuster"],
                                web_enum_threads=25, web_enum_max_seconds=45)
        tasks = _plan(planner, _base_nodes(with_vhost=True))
        enum = [t for t in tasks if t.params["tool"] in ("ffuf", "gobuster")]
        assert len(enum) == 1 and enum[0].params["tool"] == "ffuf"  # prefer ffuf
        a = enum[0].params["args"]
        # Bounded on BOTH axes + wordlist + vhost Host header.
        assert "-t" in a and a[a.index("-t") + 1] == "25"
        assert "-maxtime" in a and a[a.index("-maxtime") + 1] == "45"
        assert "/wl.txt" in a
        assert "-H" in a and "Host: 2million.htb" in a
        # Target stays the AUTHORIZED IP URL (policy-approved).
        assert enum[0].params["target"] == f"http://{_IP}"

    def test_falls_back_to_gobuster_when_no_ffuf(self) -> None:
        planner = self._planner(["curl", "gobuster"], web_enum_threads=10)
        tasks = _plan(planner, _base_nodes(with_vhost=True))
        enum = [t for t in tasks if t.params["tool"] in ("ffuf", "gobuster")]
        assert len(enum) == 1 and enum[0].params["tool"] == "gobuster"
        assert "-t" in enum[0].params["args"]  # concurrency cap present

    def test_no_enum_without_wordlist(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["curl", "ffuf"]))  # no wordlist
        tasks = _plan(planner, _base_nodes(with_vhost=True))
        assert not any(t.params["tool"] in ("ffuf", "gobuster") for t in tasks)

    def test_enum_runs_once_per_phase(self) -> None:
        planner = self._planner(["curl", "ffuf"])
        nodes = _base_nodes(with_vhost=True) + [
            _node(f"endpoint:http://{_IP}/api", "endpoint",
                  {"url": f"http://{_IP}/api"}, source="ffuf"),
        ]
        tasks = _plan(planner, nodes)
        assert not any(t.params["tool"] in ("ffuf", "gobuster") for t in tasks), \
            "a prior ffuf/gobuster endpoint means enumeration already ran"


# ---------------------------------------------------------------------------
# Safety: the emitted enum command passes safety.py; a metacharacter-injected
# variant is blocked.
# ---------------------------------------------------------------------------
class TestEnumSafety:
    def _cfg(self) -> ApexConfig:
        return ApexConfig(target=_IP, dry_run=True,
                          allowed_tools=["curl", "ffuf", "gobuster"],
                          web_wordlist_path="/wl.txt")

    def test_emitted_enum_command_passes_safety(self) -> None:
        planner = _WebDeterministic(_IP, ToolRegistry(["ffuf"]), web_wordlist_path="/wl.txt")
        enum = next(t for t in _plan(planner, _base_nodes(True)) if t.params["tool"] == "ffuf")
        check_command(ToolCommand(tool="ffuf", args=enum.params["args"]), self._cfg())  # no raise

    def test_metacharacter_injected_enum_is_blocked(self) -> None:
        bad = ToolCommand(
            tool="ffuf",
            args=["-u", f"http://{_IP}/FUZZ", "-H", "Host: evil; rm -rf /"],
        )
        with pytest.raises(ValueError):
            check_command(bad, self._cfg())


# ---------------------------------------------------------------------------
# Policy: an off-scope enumeration target is blocked; the authorized IP is
# approved.
# ---------------------------------------------------------------------------
class TestEnumPolicyScope:
    def _advisor_and_cfg(self, *, allow_password_lists: bool = True):
        # Enumeration requires BOTH a wordlist AND allow_password_lists=True —
        # the §19 no_password_list rule gates wordlist fuzzing behind explicit
        # operator approval, an additional safety layer on top of scope.
        cfg = ApexConfig(target=_IP, dry_run=True,
                         allowed_tools=["curl", "ffuf"], web_wordlist_path="/wl.txt",
                         allow_password_lists=allow_password_lists)
        return PolicyAdvisor(load_policy(cfg), cfg), cfg

    def _ffuf_task(self, target: str) -> TaskSpec:
        return TaskSpec(
            id=new_id(), goal_id="g", executor_domain="web",
            params={"tool": "ffuf", "args": ["-u", f"{target}/FUZZ", "-w", "/wl.txt"],
                    "target": target, "parser": "ffuf"},
            subgraph_anchor=_ANCHOR, phase="web",
        )

    def test_authorized_ip_target_approved_with_wordlists_allowed(self) -> None:
        advisor, cfg = self._advisor_and_cfg(allow_password_lists=True)
        ev = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
        decision = advisor.review_task(self._ffuf_task(f"http://{_IP}"), "web", ev, cfg)
        assert decision.is_approved

    def test_wordlist_enum_blocked_without_operator_approval(self) -> None:
        # The §19 safety gate: no wordlist fuzzing unless allow_password_lists.
        advisor, cfg = self._advisor_and_cfg(allow_password_lists=False)
        ev = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
        decision = advisor.review_task(self._ffuf_task(f"http://{_IP}"), "web", ev, cfg)
        assert not decision.is_approved
        assert decision.rule_name == "no_password_list"

    def test_offscope_target_blocked_even_with_wordlists_allowed(self) -> None:
        # Scope (rule 2) fires before the wordlist rule — an off-scope enum
        # target is blocked regardless of allow_password_lists.
        advisor, cfg = self._advisor_and_cfg(allow_password_lists=True)
        ev = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
        decision = advisor.review_task(self._ffuf_task("http://192.0.2.99"), "web", ev, cfg)
        assert not decision.is_approved


# ---------------------------------------------------------------------------
# Config: the bounding caps are validated.
# ---------------------------------------------------------------------------
class TestEnumConfigValidation:
    def test_defaults(self) -> None:
        c = ApexConfig(target=_IP)
        assert c.web_enum_threads == 20 and c.web_enum_max_seconds == 60
        assert [p for p in validate_combinations(c) if "web_enum" in p] == []

    def test_threads_range_validated(self) -> None:
        assert any("web_enum_threads" in p for p in
                   validate_combinations(ApexConfig(target=_IP, web_enum_threads=0)))
        assert any("web_enum_threads" in p for p in
                   validate_combinations(ApexConfig(target=_IP, web_enum_threads=500)))

    def test_max_seconds_range_validated(self) -> None:
        assert any("web_enum_max_seconds" in p for p in
                   validate_combinations(ApexConfig(target=_IP, web_enum_max_seconds=0)))
        assert any("web_enum_max_seconds" in p for p in
                   validate_combinations(ApexConfig(target=_IP, web_enum_max_seconds=99999)))

    def test_cli_flags_wire_enum_and_password_gate(self) -> None:
        import argparse

        # Absent → safe defaults (allow_password_lists stays False, the §19 gate).
        c0 = ApexConfig.from_cli_args(argparse.Namespace(target=_IP))
        assert c0.allow_password_lists is False
        # Explicit opt-in threads/time/gate flow through.
        c1 = ApexConfig.from_cli_args(argparse.Namespace(
            target=_IP, web_enum_threads=12, web_enum_max_seconds=25,
            allow_password_lists=True,
        ))
        assert c1.web_enum_threads == 12
        assert c1.web_enum_max_seconds == 25
        assert c1.allow_password_lists is True


# ---------------------------------------------------------------------------
# §28.13 — close the loop: the web planner FETCHES discovered (enumerated)
# endpoints instead of stalling; the phase gate defers completion while any
# high-signal discovered endpoint is unfetched.
# ---------------------------------------------------------------------------
def _fetched(nid: str, url: str, source: str = "curl") -> Node:
    return _node(nid, "endpoint", {"url": url, "status": "200", "fetched": True}, source=source)


def _discovered(path: str, status: str = "200", source: str = "ffuf") -> Node:
    url = f"http://{_IP}/{path}"
    return _node(f"endpoint:{url}", "endpoint", {"url": url, "path": path, "status": status}, source=source)


def _nodes_with_vhost_home_and(discovered: list[Node]) -> list[Node]:
    return _base_nodes(with_vhost=True) + [
        _fetched("endpoint:http://2million.htb", "http://2million.htb"),
    ] + discovered


class TestEndpointFetchLoop:
    def _planner(self) -> _WebDeterministic:
        return _WebDeterministic(_IP, ToolRegistry(["curl", "ffuf"]), web_wordlist_path="/wl.txt")

    def test_fetches_discovered_endpoint_via_resolve(self) -> None:
        nodes = _nodes_with_vhost_home_and([_discovered("api")])
        tasks = _plan(self._planner(), nodes)
        fetches = [t for t in tasks if t.params["target"] == "http://2million.htb/api"]
        assert fetches, "planner ignored the discovered /api endpoint"
        # Host-aware --resolve -L fetch, never a bare-IP fetch of /api.
        for t in fetches:
            assert "--resolve" in t.params["args"]
            assert f"2million.htb:80:{_IP}" in t.params["args"]
            assert "-L" in t.params["args"]
        assert not any(t.params["target"] == f"http://{_IP}/api" for t in tasks)

    def test_low_signal_404_not_fetched(self) -> None:
        nodes = _nodes_with_vhost_home_and([_discovered("gone", status="404")])
        tasks = _plan(self._planner(), nodes)
        assert not any("gone" in t.params["target"] for t in tasks)

    def test_each_endpoint_fingerprint_distinct(self) -> None:
        from apex_host.planning.fingerprint import task_fingerprint
        nodes = _nodes_with_vhost_home_and([_discovered("api"), _discovered("admin")])
        tasks = _plan(self._planner(), nodes)
        head = [t for t in tasks if t.params.get("parser") == "command"
                and t.params["target"].startswith("http://2million.htb/")]
        fps = {task_fingerprint("web", "curl", t.params["args"], t.params["target"],
                                "command", "web", "") for t in head}
        assert len(fps) == len(head) and len(head) >= 2  # one distinct action per endpoint

    def test_fetch_bounded_per_turn(self) -> None:
        many = [_discovered(f"p{i}") for i in range(10)]
        tasks = _plan(self._planner(), _nodes_with_vhost_home_and(many))
        # Fetch-loop HEADs target the discovered /p* endpoints; the §28.22 fixed
        # API-root probes (/api, /graphql, …) are a separate bounded mechanism.
        head = [t for t in tasks if t.params.get("parser") == "command"
                and t.params["target"].startswith("http://2million.htb/p")]
        assert len(head) <= 3  # _MAX_ENDPOINT_FETCHES

    def test_already_fetched_endpoint_not_refetched(self) -> None:
        # A discovered /api whose path already has a fetched counterpart is done.
        nodes = _nodes_with_vhost_home_and([
            _discovered("api"),
            _fetched("endpoint:http://2million.htb/api", "http://2million.htb/api"),
        ])
        tasks = _plan(self._planner(), nodes)
        assert not any(t.params["target"] == "http://2million.htb/api"
                       and t.params.get("parser") == "command" for t in tasks)


class TestWebGateDefersForPendingEndpoints:
    def test_gate_incomplete_while_pending(self) -> None:
        from apex_host.planners.phase_gates import (
            WEB_EVIDENCE_PENDING_ENDPOINTS,
            web_evidence_status,
        )
        nodes = _nodes_with_vhost_home_and([_discovered("api")])
        ws = web_evidence_status(_subgraph(nodes))
        assert ws.complete is False and ws.reason == WEB_EVIDENCE_PENDING_ENDPOINTS

    def test_gate_complete_when_endpoints_exhausted(self) -> None:
        from apex_host.planners.phase_gates import web_evidence_status
        nodes = _nodes_with_vhost_home_and([
            _discovered("api"),
            _fetched("endpoint:http://2million.htb/api", "http://2million.htb/api"),
        ])
        assert web_evidence_status(_subgraph(nodes)).complete is True

    def test_gate_complete_when_only_404_discovered(self) -> None:
        from apex_host.planners.phase_gates import web_evidence_status
        # A 404-only enumeration is not high-signal — the phase can complete.
        nodes = _nodes_with_vhost_home_and([_discovered("gone", status="404")])
        assert web_evidence_status(_subgraph(nodes)).complete is True


class TestFetchRoutedThroughRealParser:
    def test_head_fetch_marks_path_fetched(self) -> None:
        # The HEAD fetch result, routed through parse_single_result, records a
        # fetched endpoint whose path clears the pending set (loop terminates).
        from apex_host.planners.web_opportunities import pending_enumerated_endpoints
        header = ("HTTP/1.1 200 OK\r\nServer: nginx\r\n"
                  "Content-Type: application/json\r\n")
        obs, _src = parse_single_result(
            {"tool": "curl", "parser": "command",
             "args": ["-s", "-I", "-L", "--resolve", f"2million.htb:80:{_IP}",
                      "http://2million.htb/api"],
             "target": "http://2million.htb/api", "stdout": header},
            {"target": _IP},
        )
        eps = [n for n in obs.node_deltas if n.type == "endpoint"]
        assert eps and eps[0].props.get("fetched") is True
        assert eps[0].props.get("content_type") == "application/json"
        # Simulate the graph now holding the fetched endpoint + the discovered one.
        combined = _subgraph([_discovered("api"), *obs.node_deltas])
        assert not pending_enumerated_endpoints(combined)  # /api no longer pending
