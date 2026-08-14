# test_web_budget.py
# §28.28 — the web-phase turn budget is configurable and large enough to
# traverse homepage → a discovered page (e.g. /invite) → its JS → extract the
# API, within budget. Driven through the REAL web planner + parser + gate.
from __future__ import annotations

import argparse
import asyncio

from apex_host.config import ApexConfig
from apex_host.eval.check_config import validate_combinations
from apex_host.eval.release_gate import _make_api
from apex_host.orchestration.parsing_node import parse_single_result
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.planners.phase_gates import web_evidence_status
from apex_host.planners.web_opportunities import _path_interest_rank
from apex_host.planners.web_planner import _WebDeterministic
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase
from memfabric.types import EvidenceBundle, Edge, Goal, Node

_IP = "10.129.45.19"
_VHOST = "2million.htb"
_ANCHOR = f"host:{_IP}"


# ---------------------------------------------------------------------------
# 1. Config field: default, validation, CLI, builder wiring
# ---------------------------------------------------------------------------
class TestWebPhaseBudgetConfig:
    def test_default_raised_from_five(self) -> None:
        # The old effective web budget was the hardcoded 5 (no config field).
        assert ApexConfig(target=_IP).web_phase_budget == 10

    def test_validation_rejects_below_one_and_over_ceiling(self) -> None:
        assert validate_combinations(ApexConfig(target=_IP, web_phase_budget=10)) == []
        assert any("web_phase_budget" in p
                   for p in validate_combinations(ApexConfig(target=_IP, web_phase_budget=0)))
        assert any("web_phase_budget" in p
                   for p in validate_combinations(ApexConfig(target=_IP, web_phase_budget=101)))

    def test_from_cli_args_override_and_default(self) -> None:
        assert ApexConfig.from_cli_args(
            argparse.Namespace(target=_IP, web_phase_budget=15)).web_phase_budget == 15
        assert ApexConfig.from_cli_args(
            argparse.Namespace(target=_IP)).web_phase_budget == 10

    def test_global_planner_honors_configured_web_budget(self) -> None:
        # This is exactly how builder.py wires it into the GlobalPlanner.
        cfg = ApexConfig(target=_IP, web_phase_budget=7)
        gp = GlobalPlanner(max_turns=20, phase_budgets={"web": cfg.web_phase_budget})
        assert gp.budget_remaining(ApexPhase.web.value) == 7

    def test_builder_wires_web_budget(self) -> None:
        import inspect

        import apex_host.orchestration.builder as b
        src = inspect.getsource(b)
        assert 'phase_budgets={"web": getattr(config, "web_phase_budget"' in src


# ---------------------------------------------------------------------------
# 2. Generic account/registration keywords rank as high-signal (§28.28)
# ---------------------------------------------------------------------------
class TestRegistrationKeywords:
    def test_invite_register_signup_are_interesting(self) -> None:
        non_kw = _path_interest_rank(f"http://{_VHOST}/random-page")
        for kw in ("invite", "register", "signup", "signin"):
            assert _path_interest_rank(f"http://{_VHOST}/{kw}") < non_kw


# ---------------------------------------------------------------------------
# 3. End-to-end flow reaches the invite JS within budget (BUG fix)
# ---------------------------------------------------------------------------
async def _turns_to_invite_api(pages: list[str], max_turns: int) -> tuple[int, bool]:
    """Drive the REAL web planner turn-by-turn from a bare host+service through
    the IP→vhost redirect. Returns (web_turn_invite_api_extracted, gate_stayed
    _incomplete_until_then). 99 if never reached within *max_turns*."""
    api = _make_api()

    async def seed(nid: str, typ: str, props: dict) -> None:
        await api.upsert_node(Node(id=nid, type=typ, props=props, confidence=0.9,
                                   source="s", first_seen="", last_seen=""))

    async def se(a: str, b: str, t: str) -> None:
        await api.upsert_edge(Edge(id=f"{t}:{a}->{b}", from_id=a, to_id=b, type=t,
                                   props={}, confidence=0.9, source="s",
                                   first_seen="", last_seen=""))

    await seed(_ANCHOR, "host", {"ip": _IP})
    await seed(f"service:{_IP}:80/tcp", "service",
               {"port": "80", "service": "http", "state": "open"})
    await se(_ANCHOR, f"service:{_IP}:80/tcp", "exposes")

    cfg = ApexConfig(target=_IP, dry_run=True, allowed_tools=["curl"])
    planner = _WebDeterministic(_IP, ToolRegistry.from_config(cfg))
    goal = Goal(id="g", description="web", phase="web", anchor_node=_ANCHOR)
    empty = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
    st = {"target": _IP}

    async def rf(parser: str, target: str, body: str) -> None:
        obs, _ = parse_single_result(
            {"tool": "curl", "parser": parser, "args": ["-s", target],
             "target": target, "stdout": body}, st)
        await api.apply_deltas(nodes=obs.node_deltas, edges=obs.edge_deltas)

    links = "".join(f'<a href="{p}">x</a>' for p in pages)
    homepage = (f'<html><head><script src="/js/home.min.js"></script></head>'
                f'<body>{links}<link href="/css/a.css"></body></html>')
    invite = '<html><head><script src="/js/inviteapi.min.js"></script></head><body>x</body></html>'

    def resp(target: str, parser: str) -> str:
        if _IP in target:
            return ("HTTP/1.1 301 Moved\r\nLocation: http://2million.htb/\r\n\r\n"
                    if parser == "command" else "<html></html>")
        if target.endswith("/invite"):
            return invite
        if target.endswith("inviteapi.min.js"):
            return '$.post("/api/v1/invite/generate");'
        if target.endswith(".min.js"):
            return "console.log(1)"
        if any(target.endswith(pg) for pg in pages):
            return '<html><head><script src="/js/x.min.js"></script></head></html>'
        return homepage

    fetched: set = set()
    gate_incomplete_throughout = True
    for turn in range(1, max_turns + 1):
        sub = await api.get_subgraph(_ANCHOR, depth=12)
        if web_evidence_status(sub).complete:  # would let the phase router leave web
            gate_incomplete_throughout = False
        res = await planner.plan(goal, sub, empty)
        tasks = res if isinstance(res, list) else []
        for t in tasks:
            key = (t.params["target"], t.params["parser"])
            if t.params.get("parser") in ("command", "curl_body", "js") and key not in fetched:
                fetched.add(key)
                await rf(t.params["parser"], t.params["target"],
                         resp(t.params["target"], t.params["parser"]))
        sub2 = await api.get_subgraph(_ANCHOR, depth=12)
        if any("/api/v1/invite" in str(n.props.get("url", "")) for n in sub2.nodes):
            return turn, gate_incomplete_throughout
    return 99, gate_incomplete_throughout


class TestWebFlowReachesInviteWithinBudget:
    def test_single_page_reaches_invite_api(self) -> None:
        turn, incomplete = asyncio.run(_turns_to_invite_api(["/invite"], max_turns=10))
        assert turn <= 10  # within the new default budget
        assert incomplete  # web never marked complete before the invite API appeared

    def test_multipage_site_needs_more_than_old_budget(self) -> None:
        # A realistic multi-page site takes MORE than the old hardcoded budget of
        # 5 web turns — so the old budget would force-advance out of web before
        # /invite's JS was ever fetched (the live bug). The new budget (10) suffices.
        pages = ["/admin", "/login", "/dashboard", "/user", "/manage",
                 "/config", "/backup", "/upload", "/invite"]
        turn, incomplete = asyncio.run(_turns_to_invite_api(pages, max_turns=15))
        assert turn > 5   # the old budget of 5 would have starved /invite
        assert turn <= 10  # the new default budget of 10 reaches it
        assert incomplete  # never a premature "web complete" while pages pending

    def test_no_premature_completion_while_page_has_unfetched_script(self) -> None:
        # A discovered page (curl_body) with an unfetched <script src> keeps the
        # web phase incomplete — it must be fetched before the phase can end.
        api = _make_api()

        async def build() -> bool:
            async def seed(nid: str, props: dict, src: str = "s") -> None:
                await api.upsert_node(Node(id=nid, type="endpoint", props=props,
                                           confidence=0.7, source=src, first_seen="", last_seen=""))
            await api.upsert_node(Node(id=_ANCHOR, type="host", props={"ip": _IP},
                                       confidence=0.9, source="s", first_seen="", last_seen=""))
            # A discovered-but-unfetched page (a link from the homepage).
            await seed(f"endpoint:http://{_VHOST}/invite",
                       {"url": f"http://{_VHOST}/invite", "path": "/invite"}, src="curl_body")
            sub = await api.get_subgraph(_ANCHOR, depth=4)
            return web_evidence_status(sub).complete

        assert asyncio.run(build()) is False  # not complete — /invite must be fetched
