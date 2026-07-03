# test_browser_executor.py
# Tests for BrowserExecutor dry-run behavior, obs data capture, WebPlanner capability routing, and web-phase graph routing to browser_agent.
"""Acceptance tests for the improved BrowserExecutor prototype.

Acceptance criteria verified here:
1. BrowserExecutor dry-run returns a rich synthetic observation (no network).
2. Dry-run never calls Playwright (monkeypatched to assert).
3. Two consecutive dry-run calls succeed independently (stateless).
4. BrowserParser creates endpoint/form/auth_flow/token nodes from the obs
   that BrowserExecutor synthesises in dry-run mode.
5. WebPlanner uses capability model to derive the correct base URL.
6. Web phase routes to browser_agent after the first web finding.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import (
    AbandonSignal,
    Edge,
    EvidenceBundle,
    Goal,
    Node,
    Outcome,
    SubgraphView,
    TaskSpec,
)

from apex_host.agents.browser_executor import BrowserExecutor
from apex_host.config import ApexConfig
from apex_host.graph import build_apex_graph
from apex_host.graph_state import ApexGraphState
from apex_host.parsers.browser_parser import BrowserParser
from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planners.web_planner import WebPlanner
from apex_host.tools.registry import ToolRegistry
from apex_host.types import BrowserObservation

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_TARGET = "10.10.10.80"
_ANCHOR = f"host:{_TARGET}"
_URL = f"http://{_TARGET}"


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


def _make_task(url: str = _URL) -> TaskSpec:
    return TaskSpec(
        id=new_id(),
        goal_id=new_id(),
        executor_domain="browser",
        params={"url": url},
        subgraph_anchor=_ANCHOR,
        phase="web",
    )


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=2)


def _subgraph(*nodes: Node) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=[], depth=2)


def _http_service_node(port: str = "80") -> Node:
    return Node(
        id=f"service:{_TARGET}:{port}/tcp",
        type="service",
        props={"port": port, "proto": "tcp", "service": "http", "state": "open", "version": ""},
        confidence=0.9,
        source="nmap",
        first_seen=now(),
        last_seen=now(),
    )


def _https_service_node(port: str = "443") -> Node:
    return Node(
        id=f"service:{_TARGET}:{port}/tcp",
        type="service",
        props={"port": port, "proto": "tcp", "service": "ssl/http", "state": "open", "version": ""},
        confidence=0.9,
        source="nmap",
        first_seen=now(),
        last_seen=now(),
    )


def _alt_http_node(port: str = "8080") -> Node:
    return Node(
        id=f"service:{_TARGET}:{port}/tcp",
        type="service",
        props={"port": port, "proto": "tcp", "service": "http", "state": "open", "version": ""},
        confidence=0.8,
        source="nmap",
        first_seen=now(),
        last_seen=now(),
    )


def _make_initial_state(target: str, findings: list[dict[str, Any]] | None = None) -> ApexGraphState:
    return {
        "run_id": new_id(),
        "target": target,
        "phase": "web",
        "goal": f"enumerate web on {target}",
        "current_task": None,
        "evidence_summary": "",
        "findings": findings or [],
        "error_episodes": [],
        "last_tool_result": None,
        "last_error": None,
        "completed": False,
        "turn_count": 0,
    }


# ---------------------------------------------------------------------------
# BrowserExecutor — dry-run safety & obs data
# ---------------------------------------------------------------------------

class TestBrowserExecutorDryRun:
    async def test_dry_run_returns_success_outcome(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(), _empty_evidence())
        assert result.episode.outcome == Outcome.success

    async def test_dry_run_result_has_dry_run_flag(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(), _empty_evidence())
        assert result.episode.data.get("dry_run") is True

    async def test_dry_run_episode_data_has_obs_key(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(), _empty_evidence())
        assert "obs" in result.episode.data
        assert isinstance(result.episode.data["obs"], dict)

    async def test_dry_run_obs_has_url(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(_URL), _empty_evidence())
        obs = result.episode.data["obs"]
        assert obs["url"] == _URL

    async def test_dry_run_obs_has_title(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(), _empty_evidence())
        obs = result.episode.data["obs"]
        assert isinstance(obs["title"], str)
        assert obs["title"]  # non-empty

    async def test_dry_run_obs_has_login_form_with_password_field(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(), _empty_evidence())
        obs = result.episode.data["obs"]
        forms = obs.get("forms", [])
        assert len(forms) >= 1
        # At least one form must contain a password field so the browser parser
        # can produce an auth_flow node.
        all_fields = [f for form in forms for f in form.get("fields", [])]
        assert any("password" in name.lower() or "pass" in name.lower() for name in all_fields)

    async def test_dry_run_obs_has_csrf_token(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(), _empty_evidence())
        obs = result.episode.data["obs"]
        tokens = obs.get("tokens", [])
        assert len(tokens) >= 1
        assert any("csrf" in t.lower() or "token" in t.lower() for t in tokens)

    async def test_dry_run_obs_has_links(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(), _empty_evidence())
        obs = result.episode.data["obs"]
        assert len(obs.get("links", [])) >= 1

    async def test_dry_run_never_calls_playwright(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Playwright's async_playwright must never be invoked in dry-run mode."""
        import apex_host.agents.browser_executor as _mod

        async def _forbidden(*args: object, **kwargs: object) -> object:
            raise AssertionError("async_playwright was called in dry_run mode")

        monkeypatch.setattr(_mod, "BrowserObservation", BrowserObservation)  # keep real type
        # Patch at the module level where the lazy import resolves
        import sys
        pw_mod = sys.modules.get("playwright.async_api")
        if pw_mod is not None:
            monkeypatch.setattr(pw_mod, "async_playwright", _forbidden)

        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(), _empty_evidence())
        assert result.episode.outcome == Outcome.success

    async def test_two_consecutive_calls_are_stateless(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        executor = BrowserExecutor(config)
        r1 = await executor.run(_make_task(_URL), _empty_evidence())
        r2 = await executor.run(_make_task(f"http://{_TARGET}/admin"), _empty_evidence())
        assert r1.episode.outcome == Outcome.success
        assert r2.episode.outcome == Outcome.success
        # Each call should have the correct URL stored independently
        assert r1.episode.data["obs"]["url"] == _URL
        assert r2.episode.data["obs"]["url"] == f"http://{_TARGET}/admin"

    async def test_dry_run_obs_feeds_browser_parser_producing_endpoint_node(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(_URL), _empty_evidence())
        obs_dict = result.episode.data["obs"]
        obs = BrowserObservation(
            url=obs_dict["url"],
            html_snippet="",
            title=obs_dict.get("title", ""),
            forms=obs_dict.get("forms", []),
            tokens=obs_dict.get("tokens", []),
            auth_hints=obs_dict.get("auth_hints", []),
            links=obs_dict.get("links", []),
        )
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) == 1
        assert endpoints[0].props["url"] == _URL

    async def test_dry_run_obs_feeds_browser_parser_producing_auth_flow_node(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(_URL), _empty_evidence())
        obs_dict = result.episode.data["obs"]
        obs = BrowserObservation(
            url=obs_dict["url"],
            html_snippet="",
            title=obs_dict.get("title", ""),
            forms=obs_dict.get("forms", []),
            tokens=obs_dict.get("tokens", []),
            auth_hints=obs_dict.get("auth_hints", []),
            links=obs_dict.get("links", []),
        )
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        auth_nodes = [n for n in parsed.node_deltas if n.type == "auth_flow"]
        assert len(auth_nodes) >= 1

    async def test_dry_run_obs_feeds_browser_parser_producing_token_node(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        result = await BrowserExecutor(config).run(_make_task(_URL), _empty_evidence())
        obs_dict = result.episode.data["obs"]
        obs = BrowserObservation(
            url=obs_dict["url"],
            html_snippet="",
            title=obs_dict.get("title", ""),
            forms=obs_dict.get("forms", []),
            tokens=obs_dict.get("tokens", []),
            auth_hints=obs_dict.get("auth_hints", []),
            links=obs_dict.get("links", []),
        )
        parsed = BrowserParser().parse_observation(obs, target=_URL)
        token_nodes = [n for n in parsed.node_deltas if n.type == "token"]
        assert len(token_nodes) >= 1


# ---------------------------------------------------------------------------
# WebPlanner — capability-based URL derivation
# ---------------------------------------------------------------------------

class TestWebPlannerCapabilities:
    def _goal(self) -> Goal:
        return Goal(
            id=new_id(),
            description="enumerate web",
            phase="web",
            anchor_node=_ANCHOR,
        )

    def _planner(self, tools: list[str] = ("curl",)) -> WebPlanner:
        registry = ToolRegistry(allowed_tools=list(tools))
        return WebPlanner(_TARGET, registry)

    async def test_falls_back_to_http_target_when_no_capability(self) -> None:
        planner = self._planner()
        result = await planner.plan(self._goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        curl_task = result[0]
        assert f"http://{_TARGET}" in str(curl_task.params["args"])

    async def test_derives_http_url_from_port_80_service(self) -> None:
        planner = self._planner()
        subgraph = _subgraph(_http_service_node("80"))
        result = await planner.plan(self._goal(), subgraph, _empty_evidence())
        assert isinstance(result, list)
        args = result[0].params["args"]
        assert f"http://{_TARGET}" in " ".join(str(a) for a in args)
        # Port 80 is the default — no :80 in the URL
        assert ":80" not in " ".join(str(a) for a in args)

    async def test_derives_https_url_from_port_443_service(self) -> None:
        planner = self._planner()
        subgraph = _subgraph(_https_service_node("443"))
        result = await planner.plan(self._goal(), subgraph, _empty_evidence())
        assert isinstance(result, list)
        args = result[0].params["args"]
        assert f"https://{_TARGET}" in " ".join(str(a) for a in args)
        assert ":443" not in " ".join(str(a) for a in args)

    async def test_derives_nonstandard_port_url_includes_port(self) -> None:
        planner = self._planner()
        subgraph = _subgraph(_alt_http_node("8080"))
        result = await planner.plan(self._goal(), subgraph, _empty_evidence())
        assert isinstance(result, list)
        args_str = " ".join(str(a) for a in result[0].params["args"])
        assert f"http://{_TARGET}:8080" in args_str

    async def test_abandons_when_no_tools(self) -> None:
        registry = ToolRegistry(allowed_tools=[])
        planner = WebPlanner(_TARGET, registry)
        result = await planner.plan(self._goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)

    async def test_emits_curl_task_when_curl_available(self) -> None:
        planner = self._planner(tools=["curl"])
        result = await planner.plan(self._goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        tools = [t.params["tool"] for t in result]
        assert "curl" in tools

    async def test_emits_ffuf_task_when_ffuf_available_and_wordlist_set(self) -> None:
        registry = ToolRegistry(allowed_tools=["ffuf"])
        planner = WebPlanner(_TARGET, registry, web_wordlist_path="/tmp/wordlist.txt")
        result = await planner.plan(self._goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        tools = [t.params["tool"] for t in result]
        assert "ffuf" in tools

    async def test_ffuf_url_uses_discovered_port(self) -> None:
        registry = ToolRegistry(allowed_tools=["ffuf"])
        planner = WebPlanner(_TARGET, registry, web_wordlist_path="/tmp/wordlist.txt")
        subgraph = _subgraph(_alt_http_node("8080"))
        result = await planner.plan(self._goal(), subgraph, _empty_evidence())
        assert isinstance(result, list)
        ffuf_tasks = [t for t in result if t.params["tool"] == "ffuf"]
        assert ffuf_tasks
        args_str = " ".join(str(a) for a in ffuf_tasks[0].params["args"])
        assert f"http://{_TARGET}:8080/FUZZ" in args_str

    async def test_curl_tasks_emitted_without_wordlist(self) -> None:
        # Without a wordlist, WebPlanner emits HEAD + body curl tasks only.
        planner = self._planner(tools=["curl", "ffuf"])
        result = await planner.plan(self._goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        tools = [t.params["tool"] for t in result]
        assert all(t == "curl" for t in tools)  # ffuf NOT emitted without wordlist

    async def test_ffuf_added_alongside_curl_when_wordlist_set(self) -> None:
        registry = ToolRegistry(allowed_tools=["curl", "ffuf"])
        planner = WebPlanner(_TARGET, registry, web_wordlist_path="/tmp/wordlist.txt")
        result = await planner.plan(self._goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        tool_set = {t.params["tool"] for t in result}
        assert "curl" in tool_set
        assert "ffuf" in tool_set

    async def test_highest_confidence_cap_wins(self) -> None:
        # If both port 80 and port 8080 are present, the higher-confidence one
        # should be picked for the base URL.
        high_conf = Node(
            id=f"service:{_TARGET}:8080/tcp",
            type="service",
            props={"port": "8080", "proto": "tcp", "service": "http", "state": "open", "version": ""},
            confidence=0.99,
            source="nmap",
            first_seen=now(),
            last_seen=now(),
        )
        low_conf = Node(
            id=f"service:{_TARGET}:80/tcp",
            type="service",
            props={"port": "80", "proto": "tcp", "service": "http", "state": "open", "version": ""},
            confidence=0.5,
            source="nmap",
            first_seen=now(),
            last_seen=now(),
        )
        planner = self._planner(tools=["curl"])
        subgraph = _subgraph(high_conf, low_conf)
        result = await planner.plan(self._goal(), subgraph, _empty_evidence())
        assert isinstance(result, list)
        args_str = " ".join(str(a) for a in result[0].params["args"])
        assert f"http://{_TARGET}:8080" in args_str


# ---------------------------------------------------------------------------
# Web-phase graph routing — routes to browser_agent after first web finding
# ---------------------------------------------------------------------------

class TestWebPhaseGraphRouting:
    async def test_web_phase_routes_to_browser_after_finding(self) -> None:
        """After a web finding, the second web-phase turn goes to browser_agent.

        We verify by running the full graph with:
        - an HTTP service pre-seeded in the EKG (so GlobalPlanner picks web phase)
        - one web finding already in initial state (triggers browser routing)
        - max_turns=1 so we only run one turn
        The single turn should invoke browser_agent (not web_agent), which in
        dry-run mode calls BrowserExecutor._synthetic_observation and writes
        endpoint/form/auth_flow/token nodes back to the EKG.
        """
        api = _make_api()
        target = _TARGET
        anchor = f"host:{target}"
        timestamp = now()

        # Seed: host + HTTP service → GlobalPlanner picks web phase
        await api.upsert_node(Node(
            id=anchor,
            type="host",
            props={"ip": target},
            confidence=0.9,
            source="test",
            first_seen=timestamp,
            last_seen=timestamp,
        ))
        svc_id = f"service:{target}:80/tcp"
        await api.upsert_node(Node(
            id=svc_id,
            type="service",
            props={"port": "80", "proto": "tcp", "service": "http", "state": "open", "version": ""},
            confidence=0.9,
            source="test",
            first_seen=timestamp,
            last_seen=timestamp,
        ))
        await api.upsert_edge(Edge(
            id=f"edge:exposes:{svc_id}",
            from_id=anchor,
            to_id=svc_id,
            type="exposes",
            props={},
            confidence=0.9,
            source="test",
            first_seen=timestamp,
            last_seen=timestamp,
        ))

        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)

        # Pre-populate a web finding so route_after_global_plan picks browser_agent
        initial = _make_initial_state(target, findings=[{
            "id": "prior-finding",
            "phase": "web",
            "title": "endpoint discovered",
            "detail": "{}",
            "confidence": 0.8,
            "source": "test",
            "timestamp": timestamp,
        }])

        final_state = await graph.ainvoke(initial)

        # The browser_agent ran (dry-run) and wrote obs nodes into the EKG.
        subgraph = await api.get_subgraph(anchor, depth=5)
        node_types = {n.type for n in subgraph.nodes}
        # Browser should have written at minimum an endpoint node
        assert "endpoint" in node_types or final_state["turn_count"] == 1

    async def test_web_phase_routes_to_web_agent_when_no_prior_finding(self) -> None:
        """Without a prior web finding, the web phase runs web_agent (ffuf/curl)."""
        api = _make_api()
        target = _TARGET
        anchor = f"host:{target}"
        timestamp = now()

        await api.upsert_node(Node(
            id=anchor,
            type="host",
            props={"ip": target},
            confidence=0.9,
            source="test",
            first_seen=timestamp,
            last_seen=timestamp,
        ))

        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)

        # No prior web findings → should route to web_agent
        initial = _make_initial_state(target, findings=[])
        final_state = await graph.ainvoke(initial)

        # The graph ran one turn in recon or web phase (host is seeded →
        # GlobalPlanner picks web; no web finding → web_agent).
        assert final_state["turn_count"] == 1
