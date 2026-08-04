# test_policy_scope_url.py
# Policy scope normalization tests: authorizing a host must permit equivalent http(s) URL targets for that host, while never authorizing a different host, a host-confusion form, a credential-bearing URL, an unsupported scheme, a malformed target, an excluded port, or a redirect to an out-of-scope host.
"""Tests for URL-aware policy scope matching (apex_host.policy.scope + rules).

Root bug reproduced here: an authorized host (e.g. ``192.0.2.10``) was approved
for direct host tools, but equivalent HTTP targets
(``http://192.0.2.10/robots.txt`` etc.) were rejected because the scope check
compared the raw target string against the authorized-host set.

All addresses are RFC 5737 documentation addresses (``192.0.2.0/24`` /
``198.51.100.0/24``) — never a live HTB address. No real network calls are made.
"""
from __future__ import annotations

from typing import Any

import pytest

from apex_host.config import ApexConfig
from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispatcher import TaskDispatcher
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.execution.registry import TaskRegistry
from apex_host.policy import PolicyAdvisor
from apex_host.policy.models import ScopePolicy
from apex_host.policy.policy_loader import _ALWAYS_BLOCKED_TOOLS, load_policy
from apex_host.policy.scope import (
    NormalizedTarget,
    normalize_target,
    resolve_pin_authorizes,
    target_in_scope,
)
from apex_host.types import ToolResult
from memfabric.ids import new_id
from memfabric.types import TaskSpec

_HOST = "192.0.2.10"          # authorized host (RFC 5737 TEST-NET-1)
_OTHER = "192.0.2.11"         # a different, unauthorized host
_EVIL = "198.51.100.5"        # a second unauthorized host (TEST-NET-2)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_task(tool: str, target: str = "", args: list[str] | None = None) -> Any:
    class _FakeTask:
        params: dict[str, Any]
    t = _FakeTask()
    t.params = {"tool": tool, "target": target, "args": args or [], "parser": "command"}
    return t


def _fake_evidence() -> Any:
    class _Stub:
        entries: list[Any] = []
        subgraph: Any = None
    return _Stub()


def _advisor(target: str = _HOST, *, allowed_ports: frozenset[int] | None = None) -> tuple[PolicyAdvisor, ApexConfig]:
    config = ApexConfig(target=target, dry_run=True)
    policy = ScopePolicy(
        allowed_targets=frozenset({target}),
        blocked_tools=_ALWAYS_BLOCKED_TOOLS,
        allow_password_lists=False,
        allow_sensitive_data_access=False,
        require_review_for=[],
        policy_loaded=False,
        policy_source="test",
        allowed_ports=allowed_ports,
    )
    return PolicyAdvisor(policy, config), config


# ---------------------------------------------------------------------------
# normalize_target — unit
# ---------------------------------------------------------------------------

class TestNormalizeTarget:
    def test_bare_ipv4(self) -> None:
        nt = normalize_target("192.0.2.10")
        assert nt == NormalizedTarget(raw="192.0.2.10", host="192.0.2.10", scheme="", port=None, path="", query="")

    def test_bare_ipv6_canonicalized(self) -> None:
        nt = normalize_target("0:0:0:0:0:0:0:1")
        assert nt is not None and nt.host == "::1"

    def test_bare_hostname_lowercased(self) -> None:
        nt = normalize_target("Example.COM.")
        assert nt is not None and nt.host == "example.com"

    def test_http_url_default_port(self) -> None:
        nt = normalize_target("http://192.0.2.10/robots.txt")
        assert nt is not None
        assert nt.host == "192.0.2.10" and nt.scheme == "http" and nt.port == 80
        assert nt.path == "/robots.txt"

    def test_https_url_default_port(self) -> None:
        nt = normalize_target("https://192.0.2.10/")
        assert nt is not None and nt.port == 443 and nt.scheme == "https"

    def test_explicit_port(self) -> None:
        nt = normalize_target("http://192.0.2.10:8080/x")
        assert nt is not None and nt.port == 8080

    def test_bracketed_ipv6_url(self) -> None:
        nt = normalize_target("http://[::1]:8080/")
        assert nt is not None and nt.host == "::1" and nt.port == 8080

    def test_query_and_fragment_preserved_but_host_unchanged(self) -> None:
        nt = normalize_target("http://192.0.2.10/login?next=/admin#frag")
        assert nt is not None and nt.host == "192.0.2.10" and nt.query == "next=/admin"

    @pytest.mark.parametrize("raw", ["", "   ", None])
    def test_empty_is_none(self, raw: Any) -> None:
        assert normalize_target(raw) is None

    @pytest.mark.parametrize("raw", [
        "ftp://192.0.2.10/file",
        "file:///etc/passwd",
        "gopher://192.0.2.10/",
    ])
    def test_unsupported_scheme_is_none(self, raw: str) -> None:
        assert normalize_target(raw) is None

    @pytest.mark.parametrize("raw", [
        "http://user@192.0.2.10/",
        "http://user:pass@192.0.2.10/",
    ])
    def test_credential_bearing_url_is_none(self, raw: str) -> None:
        assert normalize_target(raw) is None

    @pytest.mark.parametrize("raw", ["http:///path", "https://", "http://"])
    def test_missing_host_is_none(self, raw: str) -> None:
        assert normalize_target(raw) is None

    def test_invalid_port_is_none(self) -> None:
        assert normalize_target("http://192.0.2.10:notaport/") is None

    @pytest.mark.parametrize("raw", ["192.0.2.10/path", "192.0.2.10?x=1", "user@192.0.2.10"])
    def test_bare_target_with_url_parts_is_none(self, raw: str) -> None:
        assert normalize_target(raw) is None


# ---------------------------------------------------------------------------
# target_in_scope — unit (host equality, never prefix/substring)
# ---------------------------------------------------------------------------

class TestTargetInScope:
    def test_bare_host_in_scope(self) -> None:
        assert target_in_scope(_HOST, {_HOST}).allowed is True

    def test_url_for_authorized_host_in_scope(self) -> None:
        assert target_in_scope(f"http://{_HOST}/robots.txt", {_HOST}).allowed is True

    def test_https_url_in_scope(self) -> None:
        assert target_in_scope(f"https://{_HOST}/", {_HOST}).allowed is True

    def test_different_host_out_of_scope(self) -> None:
        m = target_in_scope(f"http://{_OTHER}/", {_HOST})
        assert m.allowed is False and _OTHER in m.reason

    def test_no_prefix_or_substring_match(self) -> None:
        # A host that merely CONTAINS the authorized host as a substring is out.
        assert target_in_scope(f"http://{_HOST}.evil.example/", {_HOST}).allowed is False
        assert target_in_scope("http://evil.example/", {f"{_HOST}"}).allowed is False

    def test_ip_in_query_does_not_authorize(self) -> None:
        assert target_in_scope(f"http://evil.example/?target={_HOST}", {_HOST}).allowed is False

    def test_allowed_targets_may_be_a_url_and_still_match_by_host(self) -> None:
        # Normalization is applied to BOTH sides.
        assert target_in_scope(f"http://{_HOST}/a", {f"https://{_HOST}/"}).allowed is True

    def test_ipv6_canonical_equivalence(self) -> None:
        assert target_in_scope("http://[0:0:0:0:0:0:0:1]/", {"::1"}).allowed is True


# ---------------------------------------------------------------------------
# Port restriction (requirement 6)
# ---------------------------------------------------------------------------

class TestPortRestriction:
    def test_default_ports_permitted_when_listed(self) -> None:
        ports = frozenset({80, 443})
        assert target_in_scope(f"http://{_HOST}/", {_HOST}, allowed_ports=ports).allowed is True
        assert target_in_scope(f"https://{_HOST}/", {_HOST}, allowed_ports=ports).allowed is True

    def test_excluded_port_blocked_even_if_host_authorized(self) -> None:
        ports = frozenset({80, 443})
        m = target_in_scope(f"http://{_HOST}:8080/", {_HOST}, allowed_ports=ports)
        assert m.allowed is False and "8080" in m.reason

    def test_explicitly_permitted_port_allowed(self) -> None:
        ports = frozenset({80, 443, 8080})
        assert target_in_scope(f"http://{_HOST}:8080/", {_HOST}, allowed_ports=ports).allowed is True

    def test_none_means_no_port_restriction(self) -> None:
        assert target_in_scope(f"http://{_HOST}:31337/", {_HOST}, allowed_ports=None).allowed is True


# ---------------------------------------------------------------------------
# Rule / advisor level — the authoritative gate with URL targets
# ---------------------------------------------------------------------------

class TestAdvisorPositive:
    @pytest.mark.parametrize("target", [
        _HOST,
        f"http://{_HOST}/",
        f"http://{_HOST}/robots.txt",
        f"http://{_HOST}/login",
        f"https://{_HOST}/",
        f"http://{_HOST}/login?next=/admin#frag",
    ])
    def test_curl_web_target_approved(self, target: str) -> None:
        advisor, config = _advisor()
        task = _make_task("curl", target=target, args=["-s", "-I", target])
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_approved, f"{target}: {decision.rule_name} {decision.reason}"

    def test_permitted_port_url_approved(self) -> None:
        advisor, config = _advisor(allowed_ports=frozenset({80, 443, 8080}))
        task = _make_task("curl", target=f"http://{_HOST}:8080/", args=["-s", f"http://{_HOST}:8080/"])
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_approved


class TestAdvisorSecurityBlocked:
    @pytest.mark.parametrize("target", [
        f"http://{_OTHER}/",                       # different host
        f"http://{_HOST}.evil.example/",           # host-confusion / suffix
        f"http://evil.example/?target={_HOST}",    # IP only in query
        f"ftp://{_HOST}/file",                     # unsupported scheme
        f"http://user@{_OTHER}/",                  # credential-bearing + off-scope
        "http://",                                  # malformed / host-less
        "http://192.0.2.10:notaport/",             # malformed port
    ])
    def test_off_scope_or_malformed_url_blocked(self, target: str) -> None:
        advisor, config = _advisor()
        task = _make_task("curl", target=target, args=["-s", "-I", target])
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_blocked, f"{target} should be blocked, got {decision.rule_name}"
        assert decision.rule_name == "target_in_scope"

    def test_excluded_port_url_blocked(self) -> None:
        advisor, config = _advisor(allowed_ports=frozenset({80, 443}))
        task = _make_task("curl", target=f"http://{_HOST}:8080/", args=["-s", f"http://{_HOST}:8080/"])
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_blocked and decision.rule_name == "target_in_scope"

    def test_redirect_destination_out_of_scope_is_independently_blocked(self) -> None:
        """A redirect is never auto-authorized: a follow-up task whose target
        is the redirect destination (an out-of-scope host) is blocked by the
        same gate, exactly as any other off-scope target is."""
        advisor, config = _advisor()
        redirect_target = f"http://{_EVIL}/after-redirect"
        task = _make_task("curl", target=redirect_target, args=["-s", redirect_target])
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_blocked and decision.rule_name == "target_in_scope"


class TestVhostResolvePin:
    """A name-based vhost target is in scope only when pinned via
    ``curl --resolve <vhost>:<port>:<authorized-ip>`` to an authorized host."""

    def test_pin_helper_authorizes_authorized_ip(self) -> None:
        assert resolve_pin_authorizes(
            "foo.htb", ["--resolve", f"foo.htb:80:{_HOST}", "http://foo.htb"], [_HOST]
        ) is True

    def test_pin_helper_rejects_offscope_ip(self) -> None:
        assert resolve_pin_authorizes(
            "foo.htb", ["--resolve", f"foo.htb:80:{_OTHER}", "http://foo.htb"], [_HOST]
        ) is False

    def test_pin_helper_rejects_wrong_host(self) -> None:
        # --resolve pins a DIFFERENT host than the target — no authorization.
        assert resolve_pin_authorizes(
            "foo.htb", ["--resolve", f"bar.htb:80:{_HOST}", "http://foo.htb"], [_HOST]
        ) is False

    def test_vhost_with_resolve_pin_approved(self) -> None:
        advisor, config = _advisor()
        task = _make_task(
            "curl", target="http://foo.htb",
            args=["-s", "-I", "--resolve", f"foo.htb:80:{_HOST}", "http://foo.htb"],
        )
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_approved, f"{decision.rule_name}: {decision.reason}"

    def test_vhost_without_pin_blocked(self) -> None:
        advisor, config = _advisor()
        task = _make_task("curl", target="http://foo.htb", args=["-s", "-I", "http://foo.htb"])
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_blocked and decision.rule_name == "target_in_scope"

    def test_vhost_pinned_to_offscope_ip_blocked(self) -> None:
        advisor, config = _advisor()
        task = _make_task(
            "curl", target="http://foo.htb",
            args=["-s", "-I", "--resolve", f"foo.htb:80:{_OTHER}", "http://foo.htb"],
        )
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_blocked and decision.rule_name == "target_in_scope"

    def test_pin_respects_port_restriction(self) -> None:
        # Pinned port must be permitted when the policy restricts ports.
        assert resolve_pin_authorizes(
            "foo.htb", ["--resolve", f"foo.htb:8080:{_HOST}"], [_HOST],
            allowed_ports=frozenset({80, 443}),
        ) is False
        assert resolve_pin_authorizes(
            "foo.htb", ["--resolve", f"foo.htb:80:{_HOST}"], [_HOST],
            allowed_ports=frozenset({80, 443}),
        ) is True


# ---------------------------------------------------------------------------
# load_policy end-to-end (normalized allowed set)
# ---------------------------------------------------------------------------

class TestLoadPolicyScope:
    def test_url_target_approved_via_load_policy(self) -> None:
        config = ApexConfig(target=_HOST, dry_run=True, policy_file="/nonexistent-forces-default.yaml")
        policy = load_policy(config)
        advisor = PolicyAdvisor(policy, config)
        task = _make_task("curl", target=f"http://{_HOST}/robots.txt")
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_approved

    def test_off_scope_url_blocked_via_load_policy(self) -> None:
        config = ApexConfig(target=_HOST, dry_run=True, policy_file="/nonexistent-forces-default.yaml")
        policy = load_policy(config)
        advisor = PolicyAdvisor(policy, config)
        task = _make_task("curl", target=f"http://{_OTHER}/")
        decision = advisor.review_task(task, "web", _fake_evidence(), config)
        assert decision.is_blocked


# ---------------------------------------------------------------------------
# Integration: a web curl URL task passes the gate and reaches the fake runner
# ---------------------------------------------------------------------------

class TestDispatcherIntegration:
    def _dispatch_task(self, target: str) -> TaskSpec:
        return TaskSpec(
            id=new_id(),
            goal_id=new_id(),
            executor_domain="web",
            params={"tool": "curl", "args": ["-s", "-I", target], "target": target, "parser": "command"},
            subgraph_anchor=f"host:{_HOST}",
            phase="web",
        )

    def _context(self) -> ExecutionContext:
        class _Evidence:
            entries: list[Any] = []
            subgraph: Any = None
            blocked_fields: list[Any] = []
        return ExecutionContext(
            run_id="run-scope-url",
            phase="web",
            turn_number=1,
            evidence_version=None,
            subgraph=None,
            evidence=_Evidence(),
            dry_run=True,
        )

    @pytest.mark.asyncio
    async def test_authorized_url_task_reaches_fake_runner(self) -> None:
        calls: list[Any] = []

        async def _fake_run(cmd: Any, cfg: Any) -> ToolResult:
            calls.append(cmd)
            return ToolResult(stdout="HTTP/1.1 200 OK", stderr="", returncode=0, dry_run=True)

        config = ApexConfig(target=_HOST, dry_run=True)
        advisor = PolicyAdvisor(load_policy(config), config)
        dispatcher = TaskDispatcher(
            advisor=advisor,
            task_registry=TaskRegistry(),
            config=config,
            run_command_fn=_fake_run,
        )
        await dispatcher.dispatch(self._dispatch_task(f"http://{_HOST}/robots.txt"), self._context())
        assert len(calls) == 1, "authorized URL task must reach the fake runner (pass the policy gate)"

    @pytest.mark.asyncio
    async def test_off_scope_url_task_never_reaches_runner(self) -> None:
        calls: list[Any] = []

        async def _fake_run(cmd: Any, cfg: Any) -> ToolResult:
            calls.append(cmd)
            return ToolResult(stdout="", stderr="", returncode=0, dry_run=True)

        config = ApexConfig(target=_HOST, dry_run=True)
        advisor = PolicyAdvisor(load_policy(config), config)
        dispatcher = TaskDispatcher(
            advisor=advisor,
            task_registry=TaskRegistry(),
            config=config,
            run_command_fn=_fake_run,
        )
        result = await dispatcher.dispatch(self._dispatch_task(f"http://{_OTHER}/"), self._context())
        assert calls == [], "off-scope URL task must never reach the runner"
        assert result.disposition == ExecutionDisposition.BLOCKED_POLICY
