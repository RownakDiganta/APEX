# test_web_planner.py
# Tests for WebPlanner safe web probing: wordlist guard, HEAD + body curl emission, capability URL derivation, and CommandParser curl-body HTML parsing.
"""Acceptance tests for safe web probing.

Acceptance criteria:
1. WebPlanner does not assume a wordlist is available.
2. curl HEAD + body tasks are always emitted when curl is available.
3. ffuf/gobuster are ONLY emitted when web_wordlist_path is configured.
4. CommandParser.parse_curl_body extracts page title and relative links.
"""
from __future__ import annotations

import pytest

from memfabric.ids import new_id, now
from memfabric.types import (
    AbandonSignal,
    EvidenceBundle,
    Goal,
    Node,
    RawObservation,
    SubgraphView,
)

from apex_host.parsers.command_parser import CommandParser
from apex_host.planners.web_planner import WebPlanner
from apex_host.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_TARGET = "10.10.10.80"
_ANCHOR = f"host:{_TARGET}"


def _goal() -> Goal:
    return Goal(
        id=new_id(),
        description="enumerate web",
        phase="web",
        anchor_node=_ANCHOR,
    )


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=2)


def _planner(
    tools: list[str] = ("curl",),
    *,
    wordlist: str | None = None,
    max_paths: int = 50,
) -> WebPlanner:
    registry = ToolRegistry(allowed_tools=list(tools))
    return WebPlanner(_TARGET, registry, web_wordlist_path=wordlist, max_web_paths=max_paths)


# ---------------------------------------------------------------------------
# WordList guard — ffuf/gobuster absent without wordlist
# ---------------------------------------------------------------------------

class TestWebPlannerWordlistGuard:
    async def test_no_ffuf_without_wordlist(self) -> None:
        planner = _planner(tools=["curl", "ffuf"])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert not any(t.params["tool"] == "ffuf" for t in result)

    async def test_no_gobuster_without_wordlist(self) -> None:
        planner = _planner(tools=["curl", "gobuster"])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert not any(t.params["tool"] == "gobuster" for t in result)

    async def test_ffuf_emitted_when_wordlist_configured(self) -> None:
        planner = _planner(tools=["curl", "ffuf"], wordlist="/tmp/wordlist.txt")
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert any(t.params["tool"] == "ffuf" for t in result)

    async def test_gobuster_emitted_when_wordlist_configured(self) -> None:
        planner = _planner(tools=["curl", "gobuster"], wordlist="/tmp/wordlist.txt")
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert any(t.params["tool"] == "gobuster" for t in result)

    async def test_ffuf_args_contain_wordlist_path(self) -> None:
        planner = _planner(tools=["ffuf"], wordlist="/custom/list.txt")
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        ffuf = next(t for t in result if t.params["tool"] == "ffuf")
        assert "/custom/list.txt" in ffuf.params["args"]

    async def test_gobuster_args_contain_wordlist_path(self) -> None:
        planner = _planner(tools=["gobuster"], wordlist="/custom/list.txt")
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        gb = next(t for t in result if t.params["tool"] == "gobuster")
        assert "/custom/list.txt" in gb.params["args"]

    async def test_ffuf_has_status_filter_flag(self) -> None:
        planner = _planner(tools=["ffuf"], wordlist="/tmp/w.txt")
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        ffuf = next(t for t in result if t.params["tool"] == "ffuf")
        assert "-mc" in ffuf.params["args"]

    async def test_ffuf_has_maxtime_flag(self) -> None:
        planner = _planner(tools=["ffuf"], wordlist="/tmp/w.txt")
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        ffuf = next(t for t in result if t.params["tool"] == "ffuf")
        assert "-maxtime" in ffuf.params["args"]


# ---------------------------------------------------------------------------
# Curl task emission — HEAD + body always present when curl available
# ---------------------------------------------------------------------------

class TestWebPlannerCurlTasks:
    async def test_head_task_always_emitted(self) -> None:
        planner = _planner(tools=["curl"])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        head_tasks = [t for t in result if t.params.get("parser") == "command"]
        assert len(head_tasks) == 1
        assert "-I" in head_tasks[0].params["args"]

    async def test_body_task_always_emitted(self) -> None:
        planner = _planner(tools=["curl"])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        body_tasks = [t for t in result if t.params.get("parser") == "curl_body"]
        assert len(body_tasks) == 1
        assert "-I" not in body_tasks[0].params["args"]

    async def test_head_task_is_first(self) -> None:
        planner = _planner(tools=["curl"])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params.get("parser") == "command"

    async def test_body_task_is_second(self) -> None:
        planner = _planner(tools=["curl"])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[1].params.get("parser") == "curl_body"

    async def test_both_curl_tasks_have_same_url(self) -> None:
        planner = _planner(tools=["curl"])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        urls = [t.params["target"] for t in result]
        assert len(set(urls)) == 1  # both point to the same base URL

    async def test_curl_executor_domain_is_web(self) -> None:
        planner = _planner(tools=["curl"])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        for task in result:
            assert task.executor_domain == "web"

    async def test_abandon_when_no_tools(self) -> None:
        planner = _planner(tools=[])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)

    async def test_abandon_reason_is_informative(self) -> None:
        planner = _planner(tools=[])
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "tools" in result.reason.lower()

    async def test_all_tasks_have_phase(self) -> None:
        planner = _planner(tools=["curl", "ffuf"], wordlist="/tmp/w.txt")
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        for task in result:
            assert task.phase == "web"


# ---------------------------------------------------------------------------
# CommandParser.parse_curl_body — HTML title + relative link extraction
# ---------------------------------------------------------------------------

_HTML_WITH_TITLE = """\
<!DOCTYPE html>
<html>
<head><title>HTB Target Login</title></head>
<body>
  <h1>Welcome</h1>
  <a href="/login">Login</a>
  <a href="/admin">Admin</a>
  <a href="/static/app.js">Script</a>
  <a href="https://external.com/page">External</a>
</body>
</html>
"""

_HTML_NO_TITLE = """\
<html><body><a href="/dashboard">Go</a></body></html>
"""

_HTML_WHITESPACE_TITLE = """\
<html><head><title>  My App  </title></head><body></body></html>
"""

_NOT_HTML = "some random command output that is not HTML at all"

_EMPTY_BODY = "   "


class TestCommandParserCurlBody:
    _PARSER = CommandParser()

    def _raw(self, text: str, target: str = "10.10.10.80") -> RawObservation:
        return RawObservation(raw=text, metadata={"source": "curl_body", "target": target})

    def test_creates_endpoint_node(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_WITH_TITLE))
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) >= 1
        base = endpoints[0]
        assert base.props["url"] == "http://10.10.10.80"

    def test_endpoint_node_has_title(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_WITH_TITLE))
        base = next(n for n in parsed.node_deltas if n.props.get("url") == "http://10.10.10.80")
        assert base.props["title"] == "HTB Target Login"

    def test_title_whitespace_is_collapsed(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_WHITESPACE_TITLE))
        base = next(n for n in parsed.node_deltas if n.type == "endpoint" and "title" in n.props)
        assert base.props["title"] == "My App"

    def test_creates_exposes_edge_from_host(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_WITH_TITLE))
        exposes = [e for e in parsed.edge_deltas if e.type == "exposes"]
        assert len(exposes) == 1
        assert exposes[0].from_id == "host:10.10.10.80"

    def test_extracts_relative_link_nodes(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_WITH_TITLE))
        link_endpoints = [n for n in parsed.node_deltas if n.type == "endpoint" and n.props.get("path")]
        paths = {n.props["path"] for n in link_endpoints}
        assert "/login" in paths
        assert "/admin" in paths

    def test_external_links_excluded(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_WITH_TITLE))
        urls = {n.props.get("url", "") for n in parsed.node_deltas}
        assert not any("external.com" in u for u in urls)

    def test_link_endpoint_has_url_prop(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_WITH_TITLE))
        login = next(
            n for n in parsed.node_deltas
            if n.props.get("path") == "/login"
        )
        assert login.props["url"] == "http://10.10.10.80/login"

    def test_link_edges_are_contains_type(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_WITH_TITLE))
        contains = [e for e in parsed.edge_deltas if e.type == "contains"]
        assert len(contains) >= 1

    def test_link_edges_from_base_endpoint(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_WITH_TITLE))
        base_id = "endpoint:http://10.10.10.80"
        contains = [e for e in parsed.edge_deltas if e.type == "contains"]
        for edge in contains:
            assert edge.from_id == base_id

    def test_no_title_still_creates_endpoint(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_HTML_NO_TITLE))
        endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
        assert len(endpoints) >= 1

    def test_non_html_falls_back_to_knowledge_entry(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_NOT_HTML))
        assert parsed.node_deltas == []
        assert len(parsed.proposed_knowledge) == 1
        assert parsed.proposed_knowledge[0].confidence == 0.3

    def test_empty_body_returns_empty_observation(self) -> None:
        parsed = self._PARSER.parse_curl_body(self._raw(_EMPTY_BODY))
        assert parsed.node_deltas == []
        assert parsed.edge_deltas == []
        assert parsed.proposed_knowledge == []

    def test_link_count_bounded_at_twenty(self) -> None:
        # Generate more than 20 unique relative hrefs
        links = "\n".join(f'<a href="/path{i}">link{i}</a>' for i in range(30))
        html = f"<html><head><title>Many</title></head><body>{links}</body></html>"
        parsed = self._PARSER.parse_curl_body(self._raw(html))
        link_nodes = [n for n in parsed.node_deltas if n.props.get("path")]
        assert len(link_nodes) <= 20

    def test_target_url_with_port_is_preserved(self) -> None:
        raw = RawObservation(
            raw="<html><head><title>Alt port</title></head><body></body></html>",
            metadata={"source": "curl_body", "target": "http://10.10.10.80:8080"},
        )
        parsed = self._PARSER.parse_curl_body(raw)
        base = next(n for n in parsed.node_deltas if n.type == "endpoint")
        assert "8080" in base.props["url"]
