# test_approval_gate.py
# §28.30 — the fail-closed human-approval gate at the dispatch chokepoint:
# classifier, fail-closed enforcement, approval flow, guards-behind-the-gate, and
# the immutable audit record. Drives the REAL TaskDispatcher.dispatch() path.
from __future__ import annotations

import asyncio
import json
from typing import Any

from apex_host.config import ApexConfig
from apex_host.execution.approval import (
    ActionClass,
    ApprovalDecision,
    ApprovalGate,
    AutoDenyApprovalProvider,
    TerminalApprovalProvider,
    bind_approval_token,
    build_default_gate,
    classify_action,
)
from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispatcher import TaskDispatcher
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.execution.registry import TaskRegistry
from apex_host.policy import PolicyAdvisor
from apex_host.policy.policy_loader import load_policy
from apex_host.tools.runner import run_command
from apex_host.types import ToolResult
from memfabric.ids import new_id, now
from memfabric.types import EvidenceBundle, SubgraphView, TaskSpec

_TARGET = "10.129.45.19"


def _task(tool: str, args: list[str], *, target: str = _TARGET, parser: str = "command",
          **params: Any) -> TaskSpec:
    return TaskSpec(
        id=new_id(), goal_id=new_id(), executor_domain="web",
        params={"tool": tool, "args": args, "target": target, "parser": parser, **params},
        subgraph_anchor=f"host:{_TARGET}", phase="web")


def _ctx(dry_run: bool = True) -> ExecutionContext:
    return ExecutionContext(
        run_id="run-1", phase="web", turn_number=1, evidence_version=None,
        subgraph=SubgraphView(nodes=[], edges=[], anchor=f"host:{_TARGET}", depth=1),
        evidence=EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]),
        dry_run=dry_run)


class _ApproveAll:
    def request_approval(self, request: Any) -> ApprovalDecision:
        return ApprovalDecision(True, "test approve", now(),
                                token=bind_approval_token(request.fingerprint))


class _SpyRunner:
    def __init__(self) -> None:
        self.commands: list[Any] = []

    async def __call__(self, cmd: Any, cfg: Any) -> ToolResult:
        self.commands.append(cmd)
        return ToolResult(command=cmd, stdout="ok", stderr="", returncode=0,
                          duration_seconds=0.0, dry_run=True)


def _dispatcher(*, config: ApexConfig, approval_gate: ApprovalGate | None,
                run_command_fn: Any) -> TaskDispatcher:
    advisor = PolicyAdvisor(load_policy(config), config)
    return TaskDispatcher(
        advisor=advisor, task_registry=TaskRegistry(), config=config,
        run_command_fn=run_command_fn, approval_gate=approval_gate)


# ---------------------------------------------------------------------------
# 1. Classifier — shape-based, deterministic, defaults send-side.
# ---------------------------------------------------------------------------
class TestClassifier:
    def test_get_and_head_are_read_side(self) -> None:
        assert classify_action(_task("curl", ["-s", "http://h/"]))[0] is ActionClass.READ_SIDE
        assert classify_action(_task("curl", ["-s", "-I", "http://h/"]))[0] is ActionClass.READ_SIDE

    def test_recon_and_bounded_reads_are_read_side(self) -> None:
        for tool in ("nmap", "nc", "ffuf", "gobuster", "ssh_access", "ftp_access",
                     "user_flag_verify", "priv_esc_enum", "browser"):
            assert classify_action(_task(tool, []))[0] is ActionClass.READ_SIDE, tool

    def test_post_is_send_side(self) -> None:
        assert classify_action(_task("curl", ["-s", "-X", "POST", "http://h/"]))[0] is ActionClass.SEND_SIDE
        assert classify_action(_task("curl", ["-s", "-XPUT", "http://h/"]))[0] is ActionClass.SEND_SIDE

    def test_request_body_is_send_side(self) -> None:
        assert classify_action(_task("curl", ["-s", "-d", "q", "http://h/"]))[0] is ActionClass.SEND_SIDE
        assert classify_action(_task("curl", ["-s", "--data-binary", "@f", "http://h/"]))[0] is ActionClass.SEND_SIDE

    def test_custom_auth_is_send_side(self) -> None:
        assert classify_action(_task("curl", ["-s", "-H", "Authorization: Bearer x", "http://h/"]))[0] is ActionClass.SEND_SIDE
        assert classify_action(_task("curl", ["-s", "-u", "a:b", "http://h/"]))[0] is ActionClass.SEND_SIDE

    def test_non_auth_header_stays_read_side(self) -> None:
        # A Host/Content-Type header alone is not send-side (the --resolve GETs).
        assert classify_action(_task("curl", ["-s", "-H", "Host: v.htb", "http://h/"]))[0] is ActionClass.READ_SIDE

    def test_unknown_tool_defaults_send_side(self) -> None:
        assert classify_action(_task("python3", ["-c", "x"]))[0] is ActionClass.SEND_SIDE
        assert classify_action(_task("", []))[0] is ActionClass.SEND_SIDE

    def test_classifier_error_fails_closed(self) -> None:
        gate = ApprovalGate(AutoDenyApprovalProvider())

        class _Boom:
            @property
            def params(self) -> dict:
                raise RuntimeError("boom")
        cls, reason = gate.classify(_Boom())  # type: ignore[arg-type]
        assert cls is ActionClass.SEND_SIDE and "error" in reason


# ---------------------------------------------------------------------------
# 2. Fail-closed enforcement through the REAL dispatcher.
# ---------------------------------------------------------------------------
class TestFailClosedEnforcement:
    def _cfg(self) -> ApexConfig:
        return ApexConfig(target=_TARGET, dry_run=True, allowed_tools=["curl", "nmap"])

    def test_send_side_without_approval_never_reaches_executor(self) -> None:
        spy = _SpyRunner()
        # Default gate (build_default_gate) is fail-closed in dry-run → deny.
        disp = _dispatcher(config=self._cfg(),
                           approval_gate=build_default_gate(self._cfg()), run_command_fn=spy)
        task = _task("curl", ["-s", "-X", "POST", "-d", "q", f"http://{_TARGET}/gql"])
        res = asyncio.run(disp.dispatch(task, _ctx()))
        assert res.disposition is ExecutionDisposition.BLOCKED_APPROVAL
        assert spy.commands == []  # never reached the executor
        assert "approval_denied" in str(res.tool_result_dict.get("error", ""))

    def test_auto_deny_provider_denies_send_side(self) -> None:
        spy = _SpyRunner()
        disp = _dispatcher(config=self._cfg(),
                           approval_gate=ApprovalGate(AutoDenyApprovalProvider()), run_command_fn=spy)
        res = asyncio.run(disp.dispatch(
            _task("curl", ["-s", "-X", "POST", "-d", "q", f"http://{_TARGET}/x"]), _ctx()))
        assert res.disposition is ExecutionDisposition.BLOCKED_APPROVAL
        assert spy.commands == []

    def test_read_side_passes_through_unchanged(self) -> None:
        spy = _SpyRunner()
        disp = _dispatcher(config=self._cfg(),
                           approval_gate=build_default_gate(self._cfg()), run_command_fn=spy)
        res = asyncio.run(disp.dispatch(
            _task("curl", ["-s", f"http://{_TARGET}/"]), _ctx()))
        # A GET is read-side → not gated → executes (spy reached).
        assert res.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert len(spy.commands) == 1

    def test_blocked_approval_is_never_retried(self) -> None:
        res_disp = ExecutionDisposition.BLOCKED_APPROVAL
        assert res_disp.is_blocked and res_disp.never_retry and res_disp.never_repair


# ---------------------------------------------------------------------------
# 3. Approval flow — approve proceeds; deny drops and the engagement continues.
# ---------------------------------------------------------------------------
class TestApprovalFlow:
    def _cfg(self) -> ApexConfig:
        return ApexConfig(target=_TARGET, dry_run=True, allowed_tools=["curl", "nmap"])

    def test_approved_send_side_reaches_executor(self) -> None:
        spy = _SpyRunner()
        disp = _dispatcher(config=self._cfg(),
                           approval_gate=ApprovalGate(_ApproveAll()), run_command_fn=spy)
        res = asyncio.run(disp.dispatch(
            _task("curl", ["-s", "-X", "POST", "-d", "query", f"http://{_TARGET}/gql"]), _ctx()))
        assert res.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert len(spy.commands) == 1  # the approved action reached the executor

    def test_denied_action_dropped_and_recorded(self) -> None:
        spy = _SpyRunner()
        disp = _dispatcher(config=self._cfg(),
                           approval_gate=ApprovalGate(AutoDenyApprovalProvider()), run_command_fn=spy)
        res = asyncio.run(disp.dispatch(
            _task("curl", ["-s", "-X", "POST", "-d", "q", f"http://{_TARGET}/x"]), _ctx()))
        assert res.disposition is ExecutionDisposition.BLOCKED_APPROVAL
        assert spy.commands == []
        # Recorded (for the episodic event store) and continue-able (not a crash).
        assert res.tool_result_dict.get("approval_blocked") is True
        assert res.tool_result_dict.get("approval_record") is not None

    def test_foreign_token_is_rejected(self) -> None:
        class _WrongToken:
            def request_approval(self, request: Any) -> ApprovalDecision:
                return ApprovalDecision(True, "blanket", now(), token="approved:not-this-action")
        spy = _SpyRunner()
        disp = _dispatcher(config=self._cfg(),
                           approval_gate=ApprovalGate(_WrongToken()), run_command_fn=spy)
        res = asyncio.run(disp.dispatch(
            _task("curl", ["-s", "-X", "POST", "-d", "q", f"http://{_TARGET}/x"]), _ctx()))
        assert res.disposition is ExecutionDisposition.BLOCKED_APPROVAL  # blanket approval rejected
        assert spy.commands == []


# ---------------------------------------------------------------------------
# 4. Guards STAY BEHIND the gate — approval never bypasses safety.py / policy.
# ---------------------------------------------------------------------------
class TestGuardsBehindGate:
    def test_approved_metacharacter_still_blocked_by_safety(self) -> None:
        cfg = ApexConfig(target=_TARGET, dry_run=True, allowed_tools=["curl"])
        # Real run_command → real safety.check_command runs BEFORE dry-run.
        disp = _dispatcher(config=cfg, approval_gate=ApprovalGate(_ApproveAll()),
                           run_command_fn=run_command)
        # A send-side POST with a ';' shell metacharacter in the body token.
        task = _task("curl", ["-s", "-X", "POST", "-d", "a;rm -rf /", f"http://{_TARGET}/x"])
        res = asyncio.run(disp.dispatch(task, _ctx()))
        # Approval let it PAST the gate, but safety.py killed it — never a success.
        assert res.disposition is not ExecutionDisposition.EXECUTED_SUCCESS
        assert res.disposition is not ExecutionDisposition.BLOCKED_APPROVAL  # it got past approval

    def test_approved_off_scope_still_blocked_by_policy(self) -> None:
        cfg = ApexConfig(target=_TARGET, dry_run=True, allowed_tools=["curl"])
        spy = _SpyRunner()
        disp = _dispatcher(config=cfg, approval_gate=ApprovalGate(_ApproveAll()), run_command_fn=spy)
        # Approved send-side action, but the target is a DIFFERENT host (off-scope).
        task = _task("curl", ["-s", "-X", "POST", "-d", "q", "http://192.0.2.9/x"],
                     target="http://192.0.2.9/x")
        res = asyncio.run(disp.dispatch(task, _ctx()))
        assert res.disposition is ExecutionDisposition.BLOCKED_POLICY  # policy killed it after approval
        assert spy.commands == []


# ---------------------------------------------------------------------------
# 5. Immutable audit — every gated decision is recorded, secrets redacted.
# ---------------------------------------------------------------------------
class TestAudit:
    def test_denied_decision_appended_to_durable_log_redacted(self, tmp_path: Any) -> None:
        log = tmp_path / "approval_audit.log"
        gate = ApprovalGate(AutoDenyApprovalProvider(), audit_log_path=str(log),
                            passwords=["hunter2secret"])
        task = _task("curl", ["-s", "-X", "POST", "-H", "Authorization: Bearer sk-abcdef0123456789abcd",
                              "-d", "password=hunter2secret", f"http://{_TARGET}/x"])
        cls, decision, record = gate.review(task, fingerprint="fp-abc", phase="web")
        assert cls is ActionClass.SEND_SIDE and decision.approved is False
        # Durable append-only file has the decision.
        lines = log.read_text().strip().splitlines()
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["kind"] == "approval_gate_decision"
        assert rec["approved"] is False
        assert rec["method"] == "POST"           # action shape recorded
        assert rec["fingerprint"] == "fp-abc"
        # Secrets redacted (the token and the operator password never stored raw).
        blob = json.dumps(rec)
        assert "hunter2secret" not in blob
        assert "sk-abcdef0123456789abcd" not in blob

    def test_read_side_writes_no_audit(self, tmp_path: Any) -> None:
        log = tmp_path / "audit.log"
        gate = ApprovalGate(AutoDenyApprovalProvider(), audit_log_path=str(log))
        cls, decision, record = gate.review(_task("nmap", ["-sT", _TARGET]),
                                            fingerprint="fp", phase="recon")
        assert cls is ActionClass.READ_SIDE and decision is None and record is None
        assert not log.exists()  # read-side actions are not gated → no approval record

    def test_terminal_provider_denies_non_interactive(self) -> None:
        from apex_host.execution.approval import ApprovalRequest
        prov = TerminalApprovalProvider(dry_run=False, interactive=False)
        req = ApprovalRequest(action_id="a", fingerprint="f", tool="curl", method="POST",
                              url="http://h/x", headers=[], body="q", args=[], target="h",
                              phase="web", intent="", graph_context="", reason="POST")
        assert prov.request_approval(req).approved is False
