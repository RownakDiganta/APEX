# test_web_routing.py
# §28.31 — the web phase keeps running the curl discovery node (web_agent) while
# web discovery has unfetched work, instead of permanently diverting to
# browser_agent after the first web finding. Driven through the REAL routing and
# the REAL compiled graph.
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


from apex_host.config import ApexConfig
from apex_host.eval.release_gate import _make_api
from apex_host.graph import build_apex_graph
from apex_host.orchestration.routing import route_after_global_plan
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ToolCommand, ToolResult
from memfabric.ids import now
from memfabric.types import Edge, Node

_IP = "10.129.229.66"
_VHOST = "2million.htb"
_ANCHOR = f"host:{_IP}"


def _state(**kw: Any) -> dict[str, Any]:
    s: dict[str, Any] = {"completed": False, "phase": "web", "findings": []}
    s.update(kw)
    return s


_WEB_FINDING = {"phase": "web", "title": "endpoint discovered", "id": "ep1",
                "confidence": 0.9, "source": "test", "detail": ""}


# ---------------------------------------------------------------------------
# 1. Routing: keep web_agent running while web discovery is incomplete.
# ---------------------------------------------------------------------------
class TestWebRoutingKeepsCurlDiscovery:
    def test_incomplete_with_finding_stays_web_agent(self) -> None:
        # The exact regression: a web finding already exists, but discovery is
        # incomplete (pending endpoints) → curl web_agent, NOT browser_agent.
        # FAILS against the pre-§28.31 rule ("any web finding → browser_agent").
        st = _state(findings=[_WEB_FINDING], phase_selection={
            "web_evidence_complete": False, "web_reason": "unfetched_discovered_endpoints"})
        assert route_after_global_plan(st) == "web_agent"

    def test_no_content_yet_stays_web_agent(self) -> None:
        st = _state(findings=[_WEB_FINDING], phase_selection={
            "web_evidence_complete": False, "web_reason": "no_web_content_evidence"})
        assert route_after_global_plan(st) == "web_agent"

    def test_first_visit_no_finding_web_agent(self) -> None:
        assert route_after_global_plan(_state(findings=[])) == "web_agent"

    def test_missing_phase_selection_defaults_web_agent(self) -> None:
        # Fail-safe: never divert to the (possibly unavailable) browser on the
        # mere existence of a finding when the signal is absent.
        assert route_after_global_plan(_state(findings=[_WEB_FINDING])) == "web_agent"

    def test_web_agent_re_selected_across_multiple_turns(self) -> None:
        # While pending endpoints remain, every web turn keeps choosing web_agent.
        for _ in range(5):
            st = _state(findings=[_WEB_FINDING, _WEB_FINDING], phase_selection={
                "web_evidence_complete": False, "web_reason": "unfetched_discovered_endpoints"})
            assert route_after_global_plan(st) == "web_agent"

    def test_only_when_complete_goes_browser(self) -> None:
        st = _state(findings=[_WEB_FINDING], phase_selection={
            "web_evidence_complete": True, "web_reason": "page_content_fetched"})
        assert route_after_global_plan(st) == "browser_agent"

    def test_complete_but_no_finding_web_agent(self) -> None:
        st = _state(findings=[], phase_selection={
            "web_evidence_complete": True, "web_reason": "page_content_fetched"})
        assert route_after_global_plan(st) == "web_agent"

    def test_browser_never_starves_curl_while_pending(self) -> None:
        # Even if browsing were unavailable, routing never sends a still-pending
        # web phase to browser_agent — so a browser failure cannot starve the
        # curl discovery path or stall the phase.
        st = _state(findings=[_WEB_FINDING], phase_selection={
            "web_evidence_complete": False, "web_reason": "unfetched_discovered_endpoints"})
        assert route_after_global_plan(st) != "browser_agent"


# ---------------------------------------------------------------------------
# 2. End-to-end through the REAL compiled graph + routing: web_agent fetches
#    /invite → its JS → extracts the API. A fake backend serves the pages.
# ---------------------------------------------------------------------------
class _FakeWebBackend:
    """A ToolBackend that serves a TwoMillion-like site so the REAL graph +
    routing exercise the curl discovery path (never a real subprocess)."""

    def __init__(self) -> None:
        self.fetched: list[str] = []

    async def execute(self, tool: str, arguments: list[str], *,
                      timeout_seconds: float | None = None, stdin: str | None = None) -> ToolResult:
        url = next((a for a in arguments if a.startswith("http")), "")
        self.fetched.append(url)
        cmd = ToolCommand(tool=tool, args=list(arguments))
        if "-I" in arguments:  # HEAD → header response
            body = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
        else:
            body = self._serve(urlsplit(url).path or "/")
        return ToolResult(command=cmd, stdout=body, stderr="", returncode=0,
                          duration_seconds=0.0, dry_run=False, backend="fake-web")

    def _serve(self, path: str) -> str:
        if path in ("", "/"):
            return (f'<html><head><title>{_VHOST}</title>'
                    '<script src="/js/home.min.js"></script></head>'
                    '<body><a href="/invite">invite</a></body></html>')
        if path == "/invite":
            return '<html><head><script src="/js/inviteapi.min.js"></script></head><body>x</body></html>'
        if path == "/js/inviteapi.min.js":
            return '$.post("/api/v1/invite/generate");'
        if path == "/js/home.min.js":
            return "console.log(1)"
        if path.startswith("/api/v1/invite"):
            return '{"success": true, "data": {"code": "x"}}'
        return "<html></html>"


class TestWebAgentReachesInviteEndToEnd:
    async def _seed(self, api: Any) -> None:
        ts = now()

        async def N(nid: str, typ: str, props: dict) -> None:
            await api.upsert_node(Node(id=nid, type=typ, props=props, confidence=0.9,
                                       source="test", first_seen=ts, last_seen=ts))

        async def E(a: str, b: str) -> None:
            await api.upsert_edge(Edge(id=f"exposes:{a}->{b}", from_id=a, to_id=b, type="exposes",
                                       props={}, confidence=0.9, source="test", first_seen=ts, last_seen=ts))
        await N(_ANCHOR, "host", {"ip": _IP})
        await N(f"service:{_IP}:80/tcp", "service",
                {"port": "80", "proto": "tcp", "service": "http", "state": "open"})
        await E(_ANCHOR, f"service:{_IP}:80/tcp")
        await N(f"vhost:{_IP}:{_VHOST}", "vhost", {"hostname": _VHOST, "ip": _IP})
        await E(_ANCHOR, f"vhost:{_IP}:{_VHOST}")

    async def test_curl_path_fetches_invite_and_extracts_api(self) -> None:
        # MUST FAIL against the pre-§28.31 routing: after the first web finding it
        # would divert to browser_agent (synthetic/failed) and never curl-fetch
        # /invite, so /api/v1/invite would never be extracted.
        api = _make_api()
        await self._seed(api)
        backend = _FakeWebBackend()
        config = ApexConfig(target=_IP, dry_run=True, allowed_tools=["curl", "nmap"],
                            max_turns=12, web_phase_budget=10)
        graph = build_apex_graph(api, ToolRegistry.from_config(config), config,
                                 tool_backend=backend)  # type: ignore[arg-type]
        from tests.apex_host.test_browser_executor import _make_initial_state
        initial = _make_initial_state(_IP)
        await graph.ainvoke(initial, config={"configurable": {"thread_id": "t"},
                                             "recursion_limit": 300})

        sub = await api.get_subgraph(_ANCHOR, depth=8)
        urls = {str(n.props.get("url", "")) for n in sub.nodes if n.type == "endpoint"}
        # /invite's body was curl-fetched (web_agent ran past the first finding).
        assert any(u.endswith("/invite") for u in urls)
        assert any("/invite" in u for u in backend.fetched), backend.fetched
        # …and the JS-referenced API endpoint was extracted (the full pipeline ran).
        assert any("/api/v1/invite" in u for u in urls)
