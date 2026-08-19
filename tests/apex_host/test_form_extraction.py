# test_form_extraction.py
# §28.36 — generic, discovery-only HTML <form action> extraction from a fetched body.
from __future__ import annotations

from apex_host.invite_flow import _resolve_invite_urls
from apex_host.parsers.command_parser import CommandParser, _extract_forms
from apex_host.planners.web_opportunities import (
    operator_followups_from_subgraph,
    pending_page_fetches,
)
from memfabric.types import RawObservation, SubgraphView

_IP = "10.129.49.37"
_H = f"host:{_IP}"


def _parse(html: str, *, page: str = "http://2million.htb/register") -> list:
    # Wrap fragments so parse_curl_body's HTML gate (<html>/<title>/<!doctype>)
    # recognizes the body — a real page always has these.
    doc = html if "<html" in html.lower() else f"<html><body>{html}</body></html>"
    obs = CommandParser().parse_curl_body(
        RawObservation(raw=doc, metadata={"target": page, "host_ip": _IP, "source": "curl_body"}))
    return obs.node_deltas


def _forms(html: str, *, page: str = "http://2million.htb/register") -> list:
    return [n for n in _parse(html, page=page) if n.source == "html_form"]


class TestExtractForms:
    def test_simple_form(self) -> None:
        forms = _extract_forms(
            '<form action="/register" method="post">'
            '<input name="username"><input name="password" type="password"></form>')
        assert forms == [{"action": "/register", "method": "POST",
                          "fields": ["username", "password"]}]

    def test_multiple_forms(self) -> None:
        forms = _extract_forms(
            '<form action="/a"><input name="x"></form>'
            '<form action="/b" method="post"><input name="y"></form>')
        assert [f["action"] for f in forms] == ["/a", "/b"]
        assert [f["method"] for f in forms] == ["GET", "POST"]

    def test_default_method_is_get(self) -> None:
        assert _extract_forms('<form action="/s"><input name="q"></form>')[0]["method"] == "GET"

    def test_select_and_textarea_fields(self) -> None:
        forms = _extract_forms(
            '<form action="/x"><select name="country"></select>'
            '<textarea name="bio"></textarea></form>')
        assert forms[0]["fields"] == ["country", "bio"]

    def test_unclosed_form_still_captured(self) -> None:
        assert _extract_forms('<form action="/x"><input name="y">')[0]["action"] == "/x"

    def test_malformed_never_raises(self) -> None:
        assert isinstance(_extract_forms("<form <<< action= garbage"), list)


class TestFormEndpointNode:
    def test_relative_action_becomes_endpoint(self) -> None:
        nodes = _forms('<form action="/api/user/register" method="post">'
                       '<input name="username"></form>')
        assert len(nodes) == 1
        n = nodes[0]
        assert n.props["url"] == "http://2million.htb/api/user/register"
        assert n.props["method"] == "POST" and n.props["form_action"] is True
        assert n.props["form_fields"] == ["username"]

    def test_absolute_same_origin_action(self) -> None:
        nodes = _forms('<form action="http://2million.htb/do/register" method="post">'
                       '<input name="u"></form>')
        assert nodes and nodes[0].props["path"] == "/do/register"

    def test_cross_origin_action_rejected(self) -> None:
        assert _forms('<form action="http://evil.example/steal" method="post">'
                      '<input name="u"></form>') == []

    def test_self_submitting_form_skipped(self) -> None:
        # empty action → submits to the page itself; the page endpoint already exists
        assert _forms('<form method="post"><input name="u"></form>') == []


class TestFormActionWiring:
    def _sub(self, html: str) -> SubgraphView:
        return SubgraphView(anchor=_H, nodes=_parse(html), edges=[], depth=2)

    def test_operator_followup_lists_form(self) -> None:
        sub = self._sub('<form action="/api/user/register" method="post">'
                        '<input name="username"><input name="password"></form>')
        fu = next(f for f in operator_followups_from_subgraph(sub) if f["kind"] == "form_action")
        assert fu["path"] == "/api/user/register"
        assert "POST" in fu["note"] and "username" in fu["note"]

    def test_form_action_becomes_register_candidate(self) -> None:
        # a form action matching the operator's /register pattern is auto-included
        sub = self._sub('<form action="/api/user/register" method="post">'
                        '<input name="u"></form>')
        urls = _resolve_invite_urls(sub, ["/register"], "http://2million.htb")
        assert "http://2million.htb/api/user/register" in urls

    def test_post_form_excluded_from_get_fetch(self) -> None:
        sub = self._sub('<form action="/api/user/register" method="post">'
                        '<input name="u"></form>')
        # a POST-only form action must never be GET-fetched (would 405)
        assert all("api/user/register" not in str(n.props.get("url"))
                   for n in pending_page_fetches(sub))

    def test_get_form_included_in_fetch(self) -> None:
        sub = self._sub('<form action="/search" method="get"><input name="q"></form>')
        urls = [str(n.props.get("url")) for n in pending_page_fetches(sub)]
        assert any("/search" in u for u in urls)
