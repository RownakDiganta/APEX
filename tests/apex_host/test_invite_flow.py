# test_invite_flow.py
# Opt-in, generic auto-invite-flow (§28.35): decode, matching, gate auto-approval,
# orchestrator executor (mocked transport), parser, planner emit, credential handoff.
from __future__ import annotations

import base64
import codecs

import pytest

from apex_host.agents.invite_executor import InviteFlowExecutor
from apex_host.agents.invite_executor import (  # noqa: E501
    _CODE_FIELDS as _CODE,
    _USERNAME_FIELDS as _USER,
)
from apex_host.config import ApexConfig
from apex_host.execution.approval import (
    AutoApproveProvider,
    AutoDenyApprovalProvider,
    build_default_gate,
)
from apex_host.invite_flow import (
    DecodeError,
    action_matches_auto_approve,
    build_invite_flow_task,
    decode_response,
    find_matching_endpoints,
)
from apex_host.parsers.invite_parser import InviteFlowParser
from apex_host.runtime_registry import CapabilityRuntimeRegistry
from apex_host.types import ToolCommand, ToolResult
from memfabric.types import EvidenceBundle, Goal, Node, SubgraphView, TaskSpec

_IP = "10.129.229.66"
_H = f"host:{_IP}"


def _ep(path: str) -> Node:
    url = f"http://2million.htb{path}"
    return Node(id=f"endpoint:{url}", type="endpoint",
                props={"url": url, "path": path}, confidence=0.6,
                source="curl_body", first_seen="t", last_seen="t")


def _sub(nodes: list[Node]) -> SubgraphView:
    return SubgraphView(anchor=_H, nodes=nodes, edges=[], depth=2)


def _cfg(**kw: object) -> ApexConfig:
    base = dict(
        target=_IP, dry_run=False, auto_invite_flow=True,
        invite_generate_patterns=["/api/v1/invite/generate"],
        invite_verify_patterns=["/api/v1/invite/verify"],
        invite_register_patterns=["/register"],
        invite_decode_steps=["base64", "rot13"],
        auto_approve_send_patterns=["POST /api/v1/invite/verify", "POST /register"],
    )
    base.update(kw)
    return ApexConfig(**base)  # type: ignore[arg-type]


def _tr(stdout: str, rc: int = 0, err: str | None = None, dry: bool = False) -> ToolResult:
    return ToolResult(command=ToolCommand(tool="curl", args=[]), stdout=stdout,
                      stderr="", returncode=rc, duration_seconds=0.0, dry_run=dry, error=err)


class TestDecode:
    def test_base64_rot13_chain(self) -> None:
        enc = base64.b64encode(codecs.encode("/api/v1/invite/verify", "rot_13").encode()).decode()
        assert decode_response(enc, ["base64", "rot13"]) == "/api/v1/invite/verify"

    def test_hex_and_url(self) -> None:
        assert decode_response("2f61", ["hex"]) == "/a"
        assert decode_response("%2Fa%2Fb", ["url"]) == "/a/b"

    def test_unknown_step_raises(self) -> None:
        with pytest.raises(DecodeError):
            decode_response("x", ["rot47"])

    def test_bad_base64_raises(self) -> None:
        with pytest.raises(DecodeError):
            decode_response("!!!not base64!!!", ["base64", "hex"])

    def test_empty_steps_passthrough(self) -> None:
        assert decode_response("  hello  ", []) == "hello"


class TestMatching:
    def test_find_matching_endpoints(self) -> None:
        sub = _sub([_ep("/api/v1/invite/generate"), _ep("/login"), _ep("/register")])
        gen = find_matching_endpoints(sub, ["/api/v1/invite/generate"])
        assert [n.props["path"] for n in gen] == ["/api/v1/invite/generate"]
        assert find_matching_endpoints(sub, []) == []

    def test_auto_approve_match(self) -> None:
        pats = ["POST /api/v1/invite/verify", "POST /register"]
        assert action_matches_auto_approve("POST", "http://h/api/v1/invite/verify", pats)
        assert action_matches_auto_approve("POST", "http://h/register", pats)
        assert not action_matches_auto_approve("GET", "http://h/api/v1/invite/verify", pats)
        assert not action_matches_auto_approve("POST", "http://h/other", pats)
        assert not action_matches_auto_approve("POST", "http://h/register", [])  # empty = fail-closed


class TestGate:
    def test_auto_approve_provider_orchestrator_and_pattern(self) -> None:
        from apex_host.execution.approval import ApprovalRequest, bind_approval_token

        prov = AutoApproveProvider(["POST /register"], AutoDenyApprovalProvider())

        def _req(tool: str, method: str, url: str) -> ApprovalRequest:
            return ApprovalRequest(action_id="a", fingerprint="fp", tool=tool, method=method,
                                   url=url, headers=[], body="", args=[], target=_IP,
                                   phase="web", intent="", graph_context="", reason="r")
        # orchestrator task auto-approved
        d = prov.request_approval(_req("invite_flow", "N/A", ""))
        assert d.approved and d.token == bind_approval_token("fp")
        # a listed send pattern auto-approved
        assert prov.request_approval(_req("curl", "POST", "http://h/register")).approved
        # an unlisted send action delegates → fail-closed deny
        assert not prov.request_approval(_req("curl", "POST", "http://h/other")).approved

    def test_build_default_gate_off_by_default(self) -> None:
        # auto_invite_flow off → no AutoApproveProvider wrapping.
        gate = build_default_gate(ApexConfig(target=_IP))
        assert not isinstance(gate._provider, AutoApproveProvider)  # type: ignore[attr-defined]

    def test_build_default_gate_wraps_when_enabled(self) -> None:
        gate = build_default_gate(_cfg())
        assert isinstance(gate._provider, AutoApproveProvider)  # type: ignore[attr-defined]


class _FakeRunner:
    """Fake run_command_fn: returns canned responses per URL. No real network."""

    def __init__(self, *, verify_json: str = '{"code": "INV-123"}',
                 register_json: str = '{"username": "u", "password": "s3cret"}',
                 challenge: str = "") -> None:
        self.calls: list[list[str]] = []
        self._verify = verify_json
        self._register = register_json
        self._challenge = challenge

    async def __call__(self, cmd: ToolCommand, config: object) -> ToolResult:
        self.calls.append(list(cmd.args))
        joined = " ".join(cmd.args)
        if "/api/v1/invite/generate" in joined:
            return _tr(self._challenge)
        if "/api/v1/invite/verify" in joined:
            return _tr(self._verify)
        if "/register" in joined:
            return _tr(self._register)
        return _tr("", rc=1, err="unexpected")


def _challenge() -> str:
    return base64.b64encode(codecs.encode("/api/v1/invite/verify", "rot_13").encode()).decode()


def _task() -> TaskSpec:
    return TaskSpec(
        id="t", goal_id="g", executor_domain="web",
        params={
            "tool": "invite_flow", "target": _IP, "host_ip": _IP,
            "generate_url": "http://2million.htb/api/v1/invite/generate",
            "verify_url": "http://2million.htb/api/v1/invite/verify",
            "register_url": "http://2million.htb/register",
            "decode_steps": ["base64", "rot13"],
            "verify_response_field": "code",
            "register_username_field": "username",
            "register_password_field": "password",
        },
    )


class TestExecutor:
    @pytest.mark.asyncio
    async def test_dry_run_does_nothing(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner()
        ex = InviteFlowExecutor(_cfg(dry_run=True), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert res.dry_run is True and res.success is False
        assert runner.calls == []  # no network
        assert reg.get_manual_credentials() is None

    @pytest.mark.asyncio
    async def test_full_success_stores_runtime_creds_only(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge())
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert res.success and res.credentials_stored and res.username == "u"
        # password is NEVER a field on the result
        assert "s3cret" not in str(res)
        # plaintext lives only in the runtime registry
        assert reg.get_manual_credentials() == ("u", "s3cret")
        # 3 requests: GET generate, POST verify, POST register
        assert len(runner.calls) == 3

    @pytest.mark.asyncio
    async def test_fail_closed_when_post_not_auto_approved(self) -> None:
        # verify POST is NOT in the operator's approve list → aborts before sending it.
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge())
        cfg = _cfg(auto_approve_send_patterns=["POST /register"])  # verify NOT listed
        ex = InviteFlowExecutor(cfg, runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert not res.success and "not in --auto-approve-send-patterns" in (res.error or "")
        assert reg.get_manual_credentials() is None
        # only the read-side GET was issued; no verify POST
        assert len(runner.calls) == 1

    @pytest.mark.asyncio
    async def test_decode_failure_aborts(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge="!!!bad!!!")
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert not res.success and "decode" in (res.error or "").lower()
        assert reg.get_manual_credentials() is None


class TestParser:
    def test_credential_node_is_redacted(self) -> None:
        obs = InviteFlowParser().parse_result(
            {"credentials_stored": True, "invite_username": "u"}, target=_IP)
        # success → an invite_attempt marker AND a redacted credential node
        types = {n.type for n in obs.node_deltas}
        assert types == {"invite_attempt", "credential"}
        cred = next(n for n in obs.node_deltas if n.type == "credential")
        assert cred.props["username"] == "u"
        assert cred.props["secret_hint"] == "[redacted]"
        assert cred.props["source"] == "auto_registration"
        marker = next(n for n in obs.node_deltas if n.type == "invite_attempt")
        assert marker.props["outcome"] == "success"

    def test_failure_writes_marker_but_no_credential(self) -> None:
        obs = InviteFlowParser().parse_result(
            {"credentials_stored": False, "error": "registration was not accepted (HTTP 405)"},
            target=_IP)
        types = [n.type for n in obs.node_deltas]
        assert types == ["invite_attempt"]  # marker only, no credential
        marker = obs.node_deltas[0]
        assert marker.props["outcome"] == "failed"
        assert "405" in marker.props["error"]
        # host --indicates--> invite_attempt (reachable from the host anchor)
        assert any(e.type == "indicates" and e.to_id == marker.id for e in obs.edge_deltas)

    def test_dry_run_writes_nothing(self) -> None:
        assert InviteFlowParser().parse_result(
            {"dry_run": True, "credentials_stored": False}, target=_IP).node_deltas == []


_BASE = "http://2million.htb"


class TestPlannerEmit:
    def _goal(self) -> Goal:
        return Goal(id="g", description="web", phase="web", anchor_node=_H)

    def test_emits_when_enabled_and_endpoints_present(self) -> None:
        sub = _sub([_ep("/api/v1/invite/generate"), _ep("/api/v1/invite/verify"), _ep("/register")])
        task = build_invite_flow_task(sub, _cfg(), target=_IP, host_ip=_IP,
                                      base_url=_BASE, goal_id="g", anchor=_H)
        assert task is not None and task.params["tool"] == "invite_flow"
        # discovered endpoint URL is preferred (its real, vhost-hosted URL)
        assert task.params["verify_url"] == "http://2million.htb/api/v1/invite/verify"

    def test_none_when_disabled(self) -> None:
        sub = _sub([_ep("/api/v1/invite/generate"), _ep("/api/v1/invite/verify"), _ep("/register")])
        assert build_invite_flow_task(sub, ApexConfig(target=_IP), target=_IP, host_ip=_IP,
                                      base_url=_BASE, goal_id="g", anchor=_H) is None

    def test_constructs_from_pattern_when_not_discovered(self) -> None:
        # §28.35 — the generate endpoint (behind obfuscated JS) is NOT discovered,
        # but the operator supplied its literal path: construct it from base_url.
        sub = _sub([])  # nothing discovered
        task = build_invite_flow_task(sub, _cfg(), target=_IP, host_ip=_IP,
                                      base_url=_BASE, goal_id="g", anchor=_H)
        assert task is not None
        assert task.params["generate_url"] == "http://2million.htb/api/v1/invite/generate"
        assert task.params["verify_url"] == "http://2million.htb/api/v1/invite/verify"
        assert task.params["register_url"] == "http://2million.htb/register"

    def test_prefers_discovered_over_constructed(self) -> None:
        # a discovered verify endpoint's actual URL wins over base+path construction
        ep = Node(id="endpoint:http://2million.htb/api/v1/invite/verify?x=1", type="endpoint",
                  props={"url": "http://2million.htb/api/v1/invite/verify?x=1",
                         "path": "/api/v1/invite/verify"}, confidence=0.6,
                  source="js_analysis", first_seen="t", last_seen="t")
        sub = _sub([ep])
        task = build_invite_flow_task(sub, _cfg(), target=_IP, host_ip=_IP,
                                      base_url=_BASE, goal_id="g", anchor=_H)
        assert task is not None
        assert task.params["verify_url"] == "http://2million.htb/api/v1/invite/verify?x=1"

    def test_none_when_no_base_and_not_discovered(self) -> None:
        # No base_url and nothing discovered → cannot construct → None (no blind emit).
        assert build_invite_flow_task(_sub([]), _cfg(), target=_IP, host_ip=_IP,
                                      base_url="", goal_id="g", anchor=_H) is None

    def test_regex_pattern_not_constructable(self) -> None:
        # A regex (non-literal) pattern that matches nothing cannot be constructed.
        cfg = _cfg(invite_verify_patterns=["/api/.*/verify"])
        assert build_invite_flow_task(_sub([]), cfg, target=_IP, host_ip=_IP,
                                      base_url=_BASE, goal_id="g", anchor=_H) is None

    def test_none_when_patterns_missing(self) -> None:
        cfg = _cfg(invite_verify_patterns=[])  # no verify pattern
        assert build_invite_flow_task(_sub([]), cfg, target=_IP, host_ip=_IP,
                                      base_url=_BASE, goal_id="g", anchor=_H) is None

    def test_idempotent_once_registered(self) -> None:
        cred = Node(id="credential:x", type="credential",
                    props={"source": "auto_registration"}, confidence=0.9,
                    source="auto_registration", first_seen="t", last_seen="t")
        sub = _sub([_ep("/api/v1/invite/generate"), _ep("/api/v1/invite/verify"),
                    _ep("/register"), cred])
        assert build_invite_flow_task(sub, _cfg(), target=_IP, host_ip=_IP,
                                      base_url=_BASE, goal_id="g", anchor=_H) is None

    def test_idempotent_after_failed_attempt(self) -> None:
        # §28.35 — an invite_attempt marker (from a FAILED flow) stops re-emit,
        # preventing the duplicate_task_stall seen on a misconfigured flow.
        marker = Node(id="invite_attempt:x", type="invite_attempt",
                      props={"outcome": "failed"}, confidence=0.9,
                      source="invite_flow", first_seen="t", last_seen="t")
        sub = _sub([_ep("/api/v1/invite/generate"), _ep("/api/v1/invite/verify"),
                    _ep("/register"), marker])
        assert build_invite_flow_task(sub, _cfg(), target=_IP, host_ip=_IP,
                                      base_url=_BASE, goal_id="g", anchor=_H) is None


class TestCredentialHandoff:
    def test_credential_planner_reads_runtime_creds(self) -> None:
        from apex_host.planners.credential_planner import _CredentialDeterministic
        from apex_host.tools.registry import ToolRegistry

        reg = CapabilityRuntimeRegistry()
        reg.set_manual_credentials("u", "s3cret")
        planner = _CredentialDeterministic(
            _IP, ToolRegistry(allowed_tools=["nc", "curl"]), capability_registry=reg)
        assert not planner.has_credentials()
        planner._maybe_load_manual_credentials()
        assert planner._usernames == ["u"] and planner._passwords == ["s3cret"]

    def test_no_registry_no_manual_creds(self) -> None:
        from apex_host.planners.credential_planner import _CredentialDeterministic
        from apex_host.tools.registry import ToolRegistry

        planner = _CredentialDeterministic(_IP, ToolRegistry(allowed_tools=["nc"]))
        planner._maybe_load_manual_credentials()
        assert planner._usernames == [] and planner._passwords == []

    def test_cli_creds_win_over_runtime(self) -> None:
        from apex_host.planners.credential_planner import _CredentialDeterministic
        from apex_host.tools.registry import ToolRegistry

        reg = CapabilityRuntimeRegistry()
        reg.set_manual_credentials("runtime", "runtimepw")
        planner = _CredentialDeterministic(
            _IP, ToolRegistry(allowed_tools=["nc"]),
            username_candidates=["cli"], password_candidates=["clipw"],
            capability_registry=reg)
        planner._maybe_load_manual_credentials()
        assert planner._usernames == ["cli"] and planner._passwords == ["clipw"]


class TestRuntimeRegistry:
    def test_set_get_clear(self) -> None:
        reg = CapabilityRuntimeRegistry()
        assert reg.get_manual_credentials() is None
        reg.set_manual_credentials("u", "p")
        assert reg.get_manual_credentials() == ("u", "p")
        reg.clear_manual_credentials()
        assert reg.get_manual_credentials() is None


class TestFieldExtraction:
    """§28.35 — auto-detect the invite-code / credential field names."""

    def test_extract_field_preferred_wins(self) -> None:
        assert InviteFlowExecutor._extract_field(
            {"code": "A", "invite_code": "B"}, "invite_code", _CODE) == "B"

    def test_extract_field_code(self) -> None:
        assert InviteFlowExecutor._extract_field({"code": "X"}, "code", _CODE) == "X"

    def test_extract_field_invite_code(self) -> None:
        assert InviteFlowExecutor._extract_field({"invite_code": "X"}, "code", _CODE) == "X"

    def test_extract_field_token(self) -> None:
        assert InviteFlowExecutor._extract_field({"token": "X"}, "code", _CODE) == "X"

    def test_extract_field_data_and_result(self) -> None:
        assert InviteFlowExecutor._extract_field({"data": "DVAL"}, "code", _CODE) == "DVAL"
        assert InviteFlowExecutor._extract_field({"result": "RVAL"}, "code", _CODE) == "RVAL"

    def test_extract_any_string_fallback_for_code(self) -> None:
        # no common field, but a plausible string value is found (code only)
        assert InviteFlowExecutor._extract_field(
            {"mystery": "abc123xyz"}, "code", _CODE, allow_any_string=True) == "abc123xyz"

    def test_any_string_fallback_skips_status_words(self) -> None:
        assert InviteFlowExecutor._extract_field(
            {"status": "success"}, "code", _CODE, allow_any_string=True) == ""

    def test_no_any_string_fallback_for_credentials(self) -> None:
        # username/password never use the any-string fallback
        assert InviteFlowExecutor._extract_field({"mystery": "somename"}, "username", _USER) == ""

    def test_extract_empty_response(self) -> None:
        assert InviteFlowExecutor._extract_field({}, "code", _CODE, allow_any_string=True) == ""

    def test_parse_json_non_object(self) -> None:
        assert InviteFlowExecutor._parse_json("not json") is None
        assert InviteFlowExecutor._parse_json("[1,2,3]") is None
        assert InviteFlowExecutor._parse_json('{"a": 1}') == {"a": 1}

    @pytest.mark.asyncio
    async def test_executor_finds_alternate_code_field(self) -> None:
        # verify response uses 'invite_code', not the configured 'code' — succeeds.
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge(), verify_json='{"invite_code": "INV-9"}')
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert res.success and reg.get_manual_credentials() == ("u", "s3cret")

    @pytest.mark.asyncio
    async def test_executor_non_json_verify_reports_clearly(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge(), verify_json="<html>nope</html>")
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert not res.success and "not a JSON object" in (res.error or "")

    @pytest.mark.asyncio
    async def test_executor_missing_code_lists_tried_fields(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge(), verify_json='{"status": "ok"}')
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert not res.success and "tried fields:" in (res.error or "")


class TestNestedExtraction:
    """§28.35 — recursive search for the invite code in nested JSON."""

    def test_nested_data_code(self) -> None:
        assert InviteFlowExecutor._extract_field(
            {"data": {"code": "X"}}, "code", _CODE) == "X"

    def test_nested_result_invite_code(self) -> None:
        assert InviteFlowExecutor._extract_field(
            {"result": {"invite_code": "Y"}}, "code", _CODE) == "Y"

    def test_nested_under_non_candidate_container(self) -> None:
        # "response" is not a candidate name, but recursion still descends into it.
        assert InviteFlowExecutor._extract_field(
            {"status": "success", "response": {"invite_code": "Z"}}, "code", _CODE) == "Z"

    def test_deeply_nested_within_depth(self) -> None:
        payload = {"a": {"b": {"code": "DEEP"}}}
        assert InviteFlowExecutor._extract_field(payload, "code", _CODE, max_depth=3) == "DEEP"

    def test_too_deep_beyond_max_depth(self) -> None:
        payload = {"a": {"b": {"c": {"code": "TOODEEP"}}}}
        assert InviteFlowExecutor._extract_field(payload, "code", _CODE, max_depth=2) == ""

    def test_array_of_objects(self) -> None:
        assert InviteFlowExecutor._extract_field(
            {"items": [{"nope": 1}, {"code": "ARR"}]}, "code", _CODE) == "ARR"

    def test_shallower_wins_over_nested(self) -> None:
        # a top-level code beats a nested invite_code
        assert InviteFlowExecutor._extract_field(
            {"code": "TOP", "data": {"invite_code": "NESTED"}}, "code", _CODE) == "TOP"

    def test_toplevel_still_works(self) -> None:
        assert InviteFlowExecutor._extract_field({"code": "FLAT"}, "code", _CODE) == "FLAT"

    def test_nested_credentials(self) -> None:
        # register response nested — username/password found (no any-string).
        data = {"data": {"username": "u2", "password": "p2"}}
        assert InviteFlowExecutor._extract_field(data, "username", _USER) == "u2"

    @pytest.mark.asyncio
    async def test_executor_finds_nested_code(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge(), verify_json='{"data": {"code": "INV-N"}}')
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert res.success and reg.get_manual_credentials() == ("u", "s3cret")


class TestThrowawayCredentials:
    """§28.35 — auto-generate throwaway TARGET-APP credentials for a
    choose-your-own-credentials registration (never a real/HTB credential)."""

    def test_generate_format(self) -> None:
        u, p = InviteFlowExecutor._generate_credentials()
        assert u.startswith("apex_") and len(u) == len("apex_") + 8
        assert all(c.isalnum() for c in u[5:])
        assert len(p) == 16
        u2, p2 = InviteFlowExecutor._generate_credentials()
        assert (u, p) != (u2, p2)  # random each call

    def test_register_succeeded_by_status(self) -> None:
        assert InviteFlowExecutor._register_succeeded("200", "anything")
        assert InviteFlowExecutor._register_succeeded("302", "")
        assert not InviteFlowExecutor._register_succeeded("400", "ok")
        assert not InviteFlowExecutor._register_succeeded("500", "")

    def test_register_succeeded_body_fallback(self) -> None:
        assert InviteFlowExecutor._register_succeeded("", "Welcome to the app")
        assert not InviteFlowExecutor._register_succeeded("", "there was an error")

    def test_split_status(self) -> None:
        assert InviteFlowExecutor._split_status("body here\n200") == ("body here", "200")
        assert InviteFlowExecutor._split_status("no status") == ("no status", "")

    @pytest.mark.asyncio
    async def test_register_generates_creds_on_2xx(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge(),
                             register_json="<html>Account created</html>\n200")
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert res.success and res.credentials_auto_generated
        mc = reg.get_manual_credentials()
        assert mc is not None and mc[0].startswith("apex_")
        assert mc[1] not in str(res)  # generated secret never in the result

    @pytest.mark.asyncio
    async def test_register_fails_on_4xx(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge(), register_json="rejected\n400")
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert not res.success and "not accepted" in (res.error or "")
        assert reg.get_manual_credentials() is None

    @pytest.mark.asyncio
    async def test_server_returned_creds_preferred(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge(),
                             register_json='{"username": "srv_u", "password": "srv_p"}')
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert res.success and not res.credentials_auto_generated
        assert reg.get_manual_credentials() == ("srv_u", "srv_p")

    def test_parser_marks_auto_generated(self) -> None:
        obs = InviteFlowParser().parse_result(
            {"credentials_stored": True, "invite_username": "apex_abc",
             "credentials_auto_generated": True}, target=_IP)
        n = next(x for x in obs.node_deltas if x.type == "credential")
        assert n.props["auto_generated"] is True and n.props["secret_hint"] == "[redacted]"


class TestVerifyMethodAndDiagnostics:
    """§28.35 — verify is a POST (never a GET), and a 4xx/5xx status is surfaced."""

    @pytest.mark.asyncio
    async def test_verify_uses_post_with_decoded_code(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge())
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        verify_call = next(c for c in runner.calls if "/api/v1/invite/verify" in " ".join(c))
        assert "-X" in verify_call and verify_call[verify_call.index("-X") + 1] == "POST"
        assert "-d" in verify_call  # the decoded value is sent in the body

    @pytest.mark.asyncio
    async def test_verify_405_surfaced_clearly(self) -> None:
        reg = CapabilityRuntimeRegistry()
        # verify POST returns a 405 (wrong endpoint/method for this flow)
        runner = _FakeRunner(challenge=_challenge(),
                             verify_json='{"message": "Method Not Allowed"}\n405')
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert not res.success
        assert "HTTP 405" in (res.error or "") and "may not match" in (res.error or "")

    @pytest.mark.asyncio
    async def test_verify_200_with_status_still_extracts(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _FakeRunner(challenge=_challenge(), verify_json='{"code": "OK-1"}\n200')
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        res = await ex.run(_task(), EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert res.success


class _MultiRegRunner:
    """Fake: generate/verify OK; register returns a per-URL status map."""

    def __init__(self, reg_status: dict[str, str]) -> None:
        self.calls: list[list[str]] = []
        self._reg_status = reg_status  # url-substring -> body-with-status

    async def __call__(self, cmd: ToolCommand, config: object) -> ToolResult:
        self.calls.append(list(cmd.args))
        j = " ".join(cmd.args)
        if "generate" in j and "-X" not in cmd.args:
            return _tr(_challenge())
        if "verify" in j:
            return _tr('{"code": "INV-1"}')
        from urllib.parse import urlsplit
        url = next((a for a in cmd.args if a.startswith("http")), "")
        path = urlsplit(url).path
        for frag, resp in self._reg_status.items():
            if path == frag:  # exact path match (avoids /register ⊂ /api/v1/register)
                return _tr(resp)
        return _tr("not found\n404")


def _multi_task(register_urls: list[str], content_type: str = "application/x-www-form-urlencoded") -> TaskSpec:
    t = _task()
    t.params["register_urls"] = register_urls
    t.params["register_url"] = register_urls[0]
    t.params["register_content_type"] = content_type
    return t


class TestMultiRegisterAndContentType:
    """§28.35 — try multiple operator-listed register endpoints (each gated);
    configurable content type."""

    @pytest.mark.asyncio
    async def test_first_405_second_accepted(self) -> None:
        reg = CapabilityRuntimeRegistry()
        # first candidate 405, second 200
        runner = _MultiRegRunner({"/register": "denied\n405",
                                  "/api/v1/register": "created\n200"})
        cfg = _cfg(auto_approve_send_patterns=[
            "POST /api/v1/invite/verify", "POST /register", "POST /api/v1/register"])
        ex = InviteFlowExecutor(cfg, runner, reg)
        res = await ex.run(_multi_task(["http://2million.htb/register",
                                        "http://2million.htb/api/v1/register"]),
                           EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert res.success and res.credentials_auto_generated
        assert res.register_urls_tried == ["http://2million.htb/register",
                                           "http://2million.htb/api/v1/register"]

    @pytest.mark.asyncio
    async def test_unlisted_candidate_skipped(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _MultiRegRunner({"/api/v1/register": "created\n200"})
        # only /api/v1/register is auto-approved; /register is NOT tried
        cfg = _cfg(auto_approve_send_patterns=[
            "POST /api/v1/invite/verify", "POST /api/v1/register"])
        ex = InviteFlowExecutor(cfg, runner, reg)
        res = await ex.run(_multi_task(["http://2million.htb/register",
                                        "http://2million.htb/api/v1/register"]),
                           EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert res.success
        assert res.register_urls_tried == ["http://2million.htb/api/v1/register"]  # /register skipped

    @pytest.mark.asyncio
    async def test_all_candidates_fail(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _MultiRegRunner({"/register": "denied\n405",
                                  "/api/v1/register": "denied\n405"})
        cfg = _cfg(auto_approve_send_patterns=[
            "POST /api/v1/invite/verify", "POST /register", "POST /api/v1/register"])
        ex = InviteFlowExecutor(cfg, runner, reg)
        res = await ex.run(_multi_task(["http://2million.htb/register",
                                        "http://2million.htb/api/v1/register"]),
                           EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        assert not res.success and "any configured endpoint" in (res.error or "")
        assert reg.get_manual_credentials() is None

    @pytest.mark.asyncio
    async def test_json_content_type(self) -> None:
        reg = CapabilityRuntimeRegistry()
        runner = _MultiRegRunner({"/register": "created\n200"})
        ex = InviteFlowExecutor(_cfg(), runner, reg)
        await ex.run(_multi_task(["http://2million.htb/register"],
                                 content_type="application/json"),
                    EvidenceBundle(entries=[], subgraph=None, query="", tiers_queried=[]))
        reg_call = next(c for c in runner.calls if "/register" in " ".join(c) and "-X" in c)
        assert "-H" in reg_call
        assert any("Content-Type: application/json" in a for a in reg_call)
        body = reg_call[reg_call.index("-d") + 1]
        assert body.startswith("{") and '"invite_code"' in body

    def test_resolve_invite_urls_returns_all(self) -> None:
        from apex_host.invite_flow import _resolve_invite_urls
        sub = _sub([_ep("/register")])
        urls = _resolve_invite_urls(sub, ["/register", "/api/v1/register"], "http://2million.htb")
        # discovered /register (real URL) + constructed /api/v1/register
        assert "http://2million.htb/register" in urls
        assert "http://2million.htb/api/v1/register" in urls

    def test_build_task_passes_register_urls_and_content_type(self) -> None:
        sub = _sub([_ep("/api/v1/invite/generate"), _ep("/api/v1/invite/verify")])
        cfg = _cfg(invite_register_patterns=["/register", "/api/v1/register"],
                   invite_register_content_type="application/json")
        task = build_invite_flow_task(sub, cfg, target=_IP, host_ip=_IP,
                                      base_url="http://2million.htb", goal_id="g", anchor=_H)
        assert task is not None
        assert len(task.params["register_urls"]) == 2
        assert task.params["register_content_type"] == "application/json"
