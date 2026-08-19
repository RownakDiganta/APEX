# test_invite_flow.py
# Opt-in, generic auto-invite-flow (§28.35): decode, matching, gate auto-approval,
# orchestrator executor (mocked transport), parser, planner emit, credential handoff.
from __future__ import annotations

import base64
import codecs

import pytest

from apex_host.agents.invite_executor import InviteFlowExecutor
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
        assert len(obs.node_deltas) == 1
        n = obs.node_deltas[0]
        assert n.type == "credential" and n.props["username"] == "u"
        assert n.props["secret_hint"] == "[redacted]"
        assert n.props["source"] == "auto_registration"

    def test_nothing_when_not_stored(self) -> None:
        assert InviteFlowParser().parse_result({"credentials_stored": False}, target=_IP).node_deltas == []


class TestPlannerEmit:
    def _goal(self) -> Goal:
        return Goal(id="g", description="web", phase="web", anchor_node=_H)

    def test_emits_when_enabled_and_endpoints_present(self) -> None:
        sub = _sub([_ep("/api/v1/invite/generate"), _ep("/api/v1/invite/verify"), _ep("/register")])
        task = build_invite_flow_task(sub, _cfg(), target=_IP, host_ip=_IP, goal_id="g", anchor=_H)
        assert task is not None and task.params["tool"] == "invite_flow"
        assert task.params["verify_url"] == "http://2million.htb/api/v1/invite/verify"

    def test_none_when_disabled(self) -> None:
        sub = _sub([_ep("/api/v1/invite/generate"), _ep("/api/v1/invite/verify"), _ep("/register")])
        assert build_invite_flow_task(sub, ApexConfig(target=_IP), target=_IP, host_ip=_IP,
                                      goal_id="g", anchor=_H) is None

    def test_none_when_endpoint_missing(self) -> None:
        sub = _sub([_ep("/api/v1/invite/generate")])  # verify + register missing
        assert build_invite_flow_task(sub, _cfg(), target=_IP, host_ip=_IP, goal_id="g", anchor=_H) is None

    def test_idempotent_once_registered(self) -> None:
        cred = Node(id="credential:x", type="credential",
                    props={"source": "auto_registration"}, confidence=0.9,
                    source="auto_registration", first_seen="t", last_seen="t")
        sub = _sub([_ep("/api/v1/invite/generate"), _ep("/api/v1/invite/verify"),
                    _ep("/register"), cred])
        assert build_invite_flow_task(sub, _cfg(), target=_IP, host_ip=_IP, goal_id="g", anchor=_H) is None


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
