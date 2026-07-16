# test_dispatcher_credential_protocols.py
# Tests for TaskDispatcher's Phase 12B SSH/FTP routing: dedicated executors, policy gate ordering, and structured failure handling.
"""Phase 12B dispatcher tests for apex_host/execution/dispatcher.py.

Covers SSH/FTP-specific routing on top of the existing Phase 6 dispatcher
test suite (tests/apex_host/test_phase6_dispatcher.py), which already
covers the generic policy/conflict/duplicate gate machinery in depth. These
tests focus narrowly on what Phase 12B added: ssh_access/ftp_access routing
to their own dedicated executors, never through run_command_fn/ToolBackend.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from memfabric.ids import new_id
from memfabric.types import EvidenceBundle, SubgraphView, TaskSpec

from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispatcher import TaskDispatcher
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.execution.registry import TaskRegistry

_TARGET = "10.10.10.61"


def _subgraph() -> SubgraphView:
    return SubgraphView(anchor=f"host:{_TARGET}", nodes=[], edges=[], depth=2)


def _evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=_subgraph(), tiers_queried=[])


def _context(phase: str = "credential", dry_run: bool = False) -> ExecutionContext:
    return ExecutionContext(
        run_id="run-1", phase=phase, turn_number=1, evidence_version=None,
        subgraph=_subgraph(), evidence=_evidence(), dry_run=dry_run,
    )


def _task(tool: str, *, password: str = "s3cr3t-value") -> TaskSpec:
    return TaskSpec(
        id=new_id(), goal_id=new_id(), executor_domain="credential",
        params={
            "tool": tool, "target": _TARGET, "port": "22" if tool == "ssh_access" else "21",
            "username": "root", "password": password, "parser": "access",
        },
        subgraph_anchor=f"host:{_TARGET}", phase="credential",
    )


class _ApprovedAdvisor:
    def review_task(self, task: Any, phase: Any, evidence: Any, config: Any) -> Any:
        decision = MagicMock()
        decision.is_approved = True
        decision.status = MagicMock(value="approved")
        decision.rule_name = "bounded_credential_validation"
        decision.reason = "approved"
        return decision


class _BlockedAdvisor:
    def review_task(self, task: Any, phase: Any, evidence: Any, config: Any) -> Any:
        decision = MagicMock()
        decision.is_approved = False
        decision.status = MagicMock(value="blocked")
        decision.rule_name = "target_in_scope"
        decision.reason = "target out of scope"
        return decision


@dataclass
class _FakeConfig:
    target: str = _TARGET
    dry_run: bool = False
    max_command_seconds: int = 30


def _make_episode_result(*, success: bool, protocol: str) -> Any:
    ep = MagicMock()
    ep.outcome.value = "success" if success else "fundamental"
    ep.data = {
        "protocol": protocol, "target": _TARGET,
        "port": "22" if protocol == "ssh" else "21", "username": "root",
        "success": success, "authenticated": success,
        "operation": "id" if protocol == "ssh" else "PWD",
        "response_summary": "uid=0(root)" if success else "",
        "error_category": "success" if success else "auth_rejected",
        "error_detail": "" if success else f"{protocol} authentication rejected",
        "duration_seconds": 0.01, "timed_out": False, "executor": protocol,
        "dry_run": False,
    }
    result = MagicMock()
    result.episode = ep
    return result


class _RecordingExecutor:
    def __init__(self, *, success: bool = True, protocol: str = "ssh") -> None:
        self.calls = 0
        self._success = success
        self._protocol = protocol

    async def run(self, task: TaskSpec, evidence: Any) -> Any:
        self.calls += 1
        return _make_episode_result(success=self._success, protocol=self._protocol)


class _RaisingExecutor:
    async def run(self, task: TaskSpec, evidence: Any) -> Any:
        raise RuntimeError("simulated executor crash")


async def _default_run(cmd: Any, cfg: Any) -> Any:
    raise AssertionError("generic run_command_fn must never be called for ssh_access/ftp_access")


def _make_dispatcher(
    *,
    advisor: Any | None = None,
    ssh_executor: Any | None = None,
    ftp_executor: Any | None = None,
    telnet_executor: Any | None = None,
) -> TaskDispatcher:
    return TaskDispatcher(
        advisor=advisor or _ApprovedAdvisor(),
        task_registry=TaskRegistry(),
        config=_FakeConfig(),
        run_command_fn=_default_run,
        telnet_executor=telnet_executor,
        ssh_executor=ssh_executor,
        ftp_executor=ftp_executor,
    )


# ---------------------------------------------------------------------------
# 1. SSH task routes only to SSHExecutor
# ---------------------------------------------------------------------------

class TestSshRouting:
    async def test_ssh_task_reaches_ssh_executor(self) -> None:
        ssh = _RecordingExecutor(success=True, protocol="ssh")
        ftp = _RecordingExecutor(success=True, protocol="ftp")
        disp = _make_dispatcher(ssh_executor=ssh, ftp_executor=ftp)
        dr = await disp.dispatch(_task("ssh_access"), _context())
        assert ssh.calls == 1
        assert ftp.calls == 0
        assert dr.tool_result_dict["tool"] == "ssh_access"
        assert dr.disposition is ExecutionDisposition.EXECUTED_SUCCESS

    async def test_ssh_executor_unavailable_returns_tool_unavailable(self) -> None:
        disp = _make_dispatcher(ssh_executor=None)
        dr = await disp.dispatch(_task("ssh_access"), _context())
        assert dr.disposition is ExecutionDisposition.TOOL_UNAVAILABLE


# ---------------------------------------------------------------------------
# 2. FTP task routes only to FTPExecutor
# ---------------------------------------------------------------------------

class TestFtpRouting:
    async def test_ftp_task_reaches_ftp_executor(self) -> None:
        ssh = _RecordingExecutor(success=True, protocol="ssh")
        ftp = _RecordingExecutor(success=True, protocol="ftp")
        disp = _make_dispatcher(ssh_executor=ssh, ftp_executor=ftp)
        dr = await disp.dispatch(_task("ftp_access"), _context())
        assert ftp.calls == 1
        assert ssh.calls == 0
        assert dr.tool_result_dict["tool"] == "ftp_access"

    async def test_ftp_executor_unavailable_returns_tool_unavailable(self) -> None:
        disp = _make_dispatcher(ftp_executor=None)
        dr = await disp.dispatch(_task("ftp_access"), _context())
        assert dr.disposition is ExecutionDisposition.TOOL_UNAVAILABLE


# ---------------------------------------------------------------------------
# 3. Telnet remains unchanged
# ---------------------------------------------------------------------------

class TestTelnetUnaffected:
    async def test_telnet_task_never_reaches_ssh_or_ftp_executor(self) -> None:
        class _FakeTelnetExecutor:
            def __init__(self) -> None:
                self.calls = 0

            async def run(self, task: Any, evidence: Any) -> Any:
                self.calls += 1
                ep = MagicMock()
                ep.outcome.value = "success"
                ep.data = {"stdout": "$ ", "dry_run": False, "error": None}
                result = MagicMock()
                result.episode = ep
                return result

        telnet = _FakeTelnetExecutor()
        ssh = _RecordingExecutor()
        ftp = _RecordingExecutor()
        disp = _make_dispatcher(telnet_executor=telnet, ssh_executor=ssh, ftp_executor=ftp)
        dr = await disp.dispatch(_task("telnet_access"), _context())
        assert telnet.calls == 1
        assert ssh.calls == 0
        assert ftp.calls == 0
        assert dr.tool_result_dict["tool"] == "telnet_access"


# ---------------------------------------------------------------------------
# 4. Policy block produces zero executor calls
# ---------------------------------------------------------------------------

class TestPolicyBlockZeroExecutorCalls:
    async def test_policy_blocked_ssh_never_reaches_executor(self) -> None:
        ssh = _RecordingExecutor()
        disp = _make_dispatcher(advisor=_BlockedAdvisor(), ssh_executor=ssh)
        dr = await disp.dispatch(_task("ssh_access"), _context())
        assert ssh.calls == 0
        assert dr.disposition is ExecutionDisposition.BLOCKED_POLICY
        assert dr.tool_result_dict.get("policy_blocked") is True

    async def test_policy_blocked_ftp_never_reaches_executor(self) -> None:
        ftp = _RecordingExecutor()
        disp = _make_dispatcher(advisor=_BlockedAdvisor(), ftp_executor=ftp)
        dr = await disp.dispatch(_task("ftp_access"), _context())
        assert ftp.calls == 0
        assert dr.disposition is ExecutionDisposition.BLOCKED_POLICY
        assert dr.tool_result_dict.get("policy_blocked") is True

    async def test_policy_blocked_ssh_result_carries_no_password(self) -> None:
        disp = _make_dispatcher(advisor=_BlockedAdvisor(), ssh_executor=_RecordingExecutor())
        dr = await disp.dispatch(_task("ssh_access", password="s3cr3t-value"), _context())
        assert "s3cr3t-value" not in str(dr.tool_result_dict)
        assert "s3cr3t-value" not in str(dr.audit_metadata)


# ---------------------------------------------------------------------------
# 5. Duplicate guard runs correctly for SSH/FTP
# ---------------------------------------------------------------------------

class TestDuplicateGuard:
    async def test_second_identical_ssh_task_is_skipped(self) -> None:
        ssh = _RecordingExecutor()
        disp = _make_dispatcher(ssh_executor=ssh)
        task = _task("ssh_access")
        first = await disp.dispatch(task, _context())
        second = await disp.dispatch(task, _context())
        assert first.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert second.disposition is ExecutionDisposition.SKIPPED_DUPLICATE
        assert ssh.calls == 1


# ---------------------------------------------------------------------------
# 6. Executor exceptions become structured failures rather than crashing the graph
# ---------------------------------------------------------------------------

class TestExecutorExceptionHandling:
    async def test_ssh_executor_exception_is_structured_failure(self) -> None:
        disp = _make_dispatcher(ssh_executor=_RaisingExecutor())
        dr = await disp.dispatch(_task("ssh_access"), _context())
        assert dr.disposition is ExecutionDisposition.EXECUTED_FAILURE
        assert dr.error is not None
        assert "simulated executor crash" in dr.tool_result_dict.get("error", "")

    async def test_ftp_executor_exception_is_structured_failure(self) -> None:
        disp = _make_dispatcher(ftp_executor=_RaisingExecutor())
        dr = await disp.dispatch(_task("ftp_access"), _context())
        assert dr.disposition is ExecutionDisposition.EXECUTED_FAILURE
        assert dr.error is not None


# ---------------------------------------------------------------------------
# 7. Successful result reaches parser-compatible shape
# ---------------------------------------------------------------------------

class TestSuccessfulResultShape:
    async def test_ssh_success_tool_result_has_parser_fields(self) -> None:
        ssh = _RecordingExecutor(success=True, protocol="ssh")
        disp = _make_dispatcher(ssh_executor=ssh)
        dr = await disp.dispatch(_task("ssh_access"), _context())
        tr = dr.tool_result_dict
        assert tr["parser"] == "access"
        assert tr["protocol"] == "ssh"
        assert tr["success"] is True
        assert tr["authenticated"] is True
        assert tr["username"] == "root"


# ---------------------------------------------------------------------------
# 8. Password never enters audit/report output
# ---------------------------------------------------------------------------

class TestPasswordNeverInAuditOutput:
    async def test_password_absent_from_successful_tool_result(self) -> None:
        ssh = _RecordingExecutor(success=True, protocol="ssh")
        disp = _make_dispatcher(ssh_executor=ssh)
        dr = await disp.dispatch(_task("ssh_access", password="s3cr3t-value"), _context())
        assert "s3cr3t-value" not in str(dr.tool_result_dict)
        assert "s3cr3t-value" not in str(dr.audit_metadata)

    async def test_password_absent_from_failed_tool_result(self) -> None:
        ftp = _RecordingExecutor(success=False, protocol="ftp")
        disp = _make_dispatcher(ftp_executor=ftp)
        dr = await disp.dispatch(_task("ftp_access", password="s3cr3t-value"), _context())
        assert "s3cr3t-value" not in str(dr.tool_result_dict)

    async def test_password_absent_from_exception_failure(self) -> None:
        disp = _make_dispatcher(ssh_executor=_RaisingExecutor())
        dr = await disp.dispatch(_task("ssh_access", password="s3cr3t-value"), _context())
        assert "s3cr3t-value" not in str(dr.tool_result_dict)
