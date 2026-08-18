# test_operator_followups.py
# Generic, read-only operator follow-up recommendations from discovered endpoints (§28.34).
from __future__ import annotations

from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.planners.web_opportunities import operator_followups_from_subgraph
from memfabric.types import Node, SubgraphView

_IP = "10.129.48.197"
_H = f"host:{_IP}"


def _ep(path: str, *, js_asset: bool = False) -> Node:
    url = f"http://2million.htb{path}"
    props: dict[str, object] = {"url": url, "path": path}
    if js_asset:
        props["js_asset"] = True
    return Node(id=f"endpoint:{url}", type="endpoint", props=props,
                confidence=0.5, source="curl_body", first_seen="t", last_seen="t")


def _sub(nodes: list[Node]) -> SubgraphView:
    return SubgraphView(anchor=_H, nodes=nodes, edges=[], depth=2)


class TestFollowupClassification:
    def test_auth_registration_paths_flagged(self) -> None:
        sub = _sub([_ep("/invite"), _ep("/register"), _ep("/login"), _ep("/signup")])
        fus = {f["path"]: f["kind"] for f in operator_followups_from_subgraph(sub)}
        assert fus == {"/invite": "auth_flow", "/register": "auth_flow",
                       "/login": "auth_flow", "/signup": "auth_flow"}

    def test_api_paths_flagged_as_api(self) -> None:
        sub = _sub([_ep("/api/v1/invite/how/to/generate"), _ep("/api/stats/global")])
        kinds = {f["path"]: f["kind"] for f in operator_followups_from_subgraph(sub)}
        # /api/.../invite matches an auth keyword first (auth_flow wins by order)
        assert kinds["/api/v1/invite/how/to/generate"] == "auth_flow"
        assert kinds["/api/stats/global"] == "api"

    def test_admin_paths_flagged(self) -> None:
        sub = _sub([_ep("/admin"), _ep("/dashboard")])
        kinds = {f["path"]: f["kind"] for f in operator_followups_from_subgraph(sub)}
        assert kinds == {"/admin": "admin", "/dashboard": "admin"}

    def test_uninteresting_paths_ignored(self) -> None:
        sub = _sub([_ep("/about"), _ep("/contact"), _ep("/home")])
        assert operator_followups_from_subgraph(sub) == []

    def test_js_and_static_assets_excluded(self) -> None:
        # A JS asset (even one whose path contains "invite") is never an operator
        # action target; nor is a static asset.
        sub = _sub([
            _ep("/js/inviteapi.min.js", js_asset=True),
            _ep("/js/inviteapi.min.js"),           # .js path, no flag
            _ep("/css/login.css"),                 # static asset with keyword
            _ep("/invite"),                        # real page — kept
        ])
        paths = [f["path"] for f in operator_followups_from_subgraph(sub)]
        assert paths == ["/invite"]

    def test_deduped_and_bounded(self) -> None:
        nodes = [_ep(f"/api/x{i}") for i in range(40)] + [_ep("/api/x0")]  # dup path
        fus = operator_followups_from_subgraph(_sub(nodes), limit=25)
        assert len(fus) == 25
        assert len({f["path"] for f in fus}) == 25

    def test_notes_are_secret_free_and_advisory(self) -> None:
        # Notes must be fixed advisory text — never a decode procedure, never a
        # machine-specific path, never "base64"/"rot13".
        sub = _sub([_ep("/invite"), _ep("/api/stats/global")])
        for f in operator_followups_from_subgraph(sub):
            note = f["note"].lower()
            assert "base64" not in note and "rot13" not in note
            assert "2million" not in note and "/api/v1/invite" not in note

    def test_pure_no_writes(self) -> None:
        # Calling twice yields identical output (no mutation of the subgraph).
        sub = _sub([_ep("/invite"), _ep("/register")])
        a = operator_followups_from_subgraph(sub)
        b = operator_followups_from_subgraph(sub)
        assert a == b
        assert len(sub.nodes) == 2  # unchanged


class TestReportIntegration:
    def _report(self, subgraph: SubgraphView):
        # Reuse the complete state/config fixtures from the report test suite.
        from tests.apex_host.test_report import _config, _state
        return build_report(_state(phase="web"), subgraph, _config())

    def test_report_surfaces_followups_in_text_and_json(self) -> None:
        sub = _sub([_ep("/invite"), _ep("/api/stats/global"), _ep("/admin")])
        report = self._report(sub)
        assert report.operator_followup_count == 3
        txt = format_text(report)
        assert "Operator Follow-Up" in txt
        assert "/invite" in txt
        assert to_json_dict(report)["operator_followups"]["count"] == 3

    def test_report_no_section_when_empty(self) -> None:
        sub = _sub([_ep("/about")])
        report = self._report(sub)
        assert report.operator_followup_count == 0
        assert "Operator Follow-Up" not in format_text(report)
