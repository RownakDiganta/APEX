# test_browser_parser.py
# Tests for BrowserParser verifying Endpoint, Form, AuthFlow, and Token node creation from BrowserObservation inputs.
from __future__ import annotations

from apex_host.parsers.browser_parser import BrowserParser
from apex_host.types import BrowserObservation


def test_browser_creates_endpoint_node() -> None:
    obs = BrowserObservation(url="http://target/login", html_snippet="<html></html>", title="Login")
    parsed = BrowserParser().parse_observation(obs, target="target")
    endpoints = [n for n in parsed.node_deltas if n.type == "endpoint"]
    assert len(endpoints) == 1
    assert endpoints[0].props["url"] == "http://target/login"


def test_browser_creates_authflow_node_for_password_form() -> None:
    obs = BrowserObservation(
        url="http://target/login",
        html_snippet="<form><input name='user'><input type='password' name='pass'></form>",
        forms=[{"action": "/login", "method": "POST", "fields": ["user", "pass"]}],
    )
    parsed = BrowserParser().parse_observation(obs, target="target")
    node_types = {n.type for n in parsed.node_deltas}
    assert "form" in node_types
    assert "auth_flow" in node_types

    auth_edges = [e for e in parsed.edge_deltas if e.type == "requires"]
    assert len(auth_edges) == 1


def test_browser_non_auth_form_creates_no_authflow() -> None:
    obs = BrowserObservation(
        url="http://target/search",
        html_snippet="<form><input name='q'></form>",
        forms=[{"action": "/search", "method": "GET", "fields": ["q"]}],
    )
    parsed = BrowserParser().parse_observation(obs, target="target")
    node_types = {n.type for n in parsed.node_deltas}
    assert "form" in node_types
    assert "auth_flow" not in node_types


def test_browser_auth_hints_create_authflow() -> None:
    obs = BrowserObservation(
        url="http://target/account",
        html_snippet="<html></html>",
        auth_hints=["login-required"],
    )
    parsed = BrowserParser().parse_observation(obs, target="target")
    auth_nodes = [n for n in parsed.node_deltas if n.type == "auth_flow"]
    assert len(auth_nodes) == 1
    assert auth_nodes[0].props["hint"] == "login-required"


def test_browser_creates_token_nodes() -> None:
    obs = BrowserObservation(
        url="http://target/dashboard",
        html_snippet="<html></html>",
        tokens=["csrf_token_abc123"],
    )
    parsed = BrowserParser().parse_observation(obs, target="target")
    token_nodes = [n for n in parsed.node_deltas if n.type == "token"]
    assert len(token_nodes) == 1
    assert token_nodes[0].props["name"] == "csrf_token_abc123"
