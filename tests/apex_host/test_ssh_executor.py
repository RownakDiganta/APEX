# test_ssh_executor.py
# Tests for SSHExecutor: bounded, one-attempt SSH credential validation with no real network access.
"""Tests for apex_host/agents/ssh_executor.py.

No test requires a real SSH server, Docker, VPN, or internet access —
``paramiko.SSHClient`` is monkeypatched with an in-process fake that raises
the real ``paramiko`` exception classes so the executor's own exception
handling is exercised exactly as it runs in production.
"""
from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

import paramiko
import pytest

from memfabric.types import EvidenceBundle, TaskSpec

from apex_host.agents.ssh_executor import SSHExecutor, _attempt_ssh_sync
from apex_host.config import ApexConfig
from apex_host.types import CredentialErrorCategory

_TARGET = "10.10.10.50"

# Strips triple-quoted docstrings before a static source scan, so a method
# name mentioned only in prose (explaining what the module does NOT do)
# never false-positives a "this call is absent from the code" assertion.
_DOCSTRING_RE = re.compile(r'""".*?"""', re.DOTALL)


def _code_only(source: str) -> str:
    return _DOCSTRING_RE.sub("", source)


def _evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _task(
    *, target: str = _TARGET, port: str = "22", username: str = "root",
    password: str = "hunter2", command: str | None = None,
) -> TaskSpec:
    params: dict[str, Any] = {
        "tool": "ssh_access", "target": target, "port": port,
        "username": username, "password": password, "parser": "access",
    }
    if command is not None:
        params["command"] = command
    return TaskSpec(
        id="task-ssh-1", goal_id="goal-1", executor_domain="credential",
        params=params, subgraph_anchor=f"host:{target}", phase="credential",
    )


class _FakeChannel:
    def __init__(self, exit_status: int) -> None:
        self._exit_status = exit_status
        self.recv_exit_status_calls = 0

    def recv_exit_status(self) -> int:
        self.recv_exit_status_calls += 1
        return self._exit_status


class _FakeChannelFile:
    def __init__(self, data: bytes, exit_status: int) -> None:
        self._data = data
        self.channel = _FakeChannel(exit_status)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._data
        return self._data[:size]


class _FakeSSHClient:
    """In-process double for paramiko.SSHClient — no network I/O."""

    #: Class-level behavior knobs, reset per test via fixture.
    connect_raises: Exception | None = None
    exec_raises: Exception | None = None
    stdout_bytes: bytes = b"uid=0(root) gid=0(root) groups=0(root)\n"
    stderr_bytes: bytes = b""
    exit_status: int = 0

    def __init__(self) -> None:
        self.connect_calls: list[dict[str, Any]] = []
        self.exec_calls: list[dict[str, Any]] = []
        self.closed = False
        self.missing_host_key_policy: object | None = None

    def set_missing_host_key_policy(self, policy: object) -> None:
        self.missing_host_key_policy = policy

    def connect(self, **kwargs: Any) -> None:
        self.connect_calls.append(kwargs)
        if type(self).connect_raises is not None:
            raise type(self).connect_raises

    def exec_command(
        self, command: str, bufsize: int = -1, timeout: float | None = None,
        get_pty: bool = False, environment: object = None,
    ) -> tuple[None, _FakeChannelFile, _FakeChannelFile]:
        self.exec_calls.append({"command": command, "timeout": timeout})
        if type(self).exec_raises is not None:
            raise type(self).exec_raises
        return (
            None,
            _FakeChannelFile(type(self).stdout_bytes, type(self).exit_status),
            _FakeChannelFile(type(self).stderr_bytes, type(self).exit_status),
        )

    def open_sftp(self) -> None:
        raise AssertionError("SSHExecutor must never open an SFTP session")

    def get_transport(self) -> None:
        raise AssertionError(
            "SSHExecutor must never touch the raw Transport (used for port forwarding)"
        )

    def close(self) -> None:
        self.closed = True


_last_client: list[_FakeSSHClient] = []


def _install_fake_client(monkeypatch: pytest.MonkeyPatch) -> type[_FakeSSHClient]:
    _FakeSSHClient.connect_raises = None
    _FakeSSHClient.exec_raises = None
    _FakeSSHClient.stdout_bytes = b"uid=0(root) gid=0(root) groups=0(root)\n"
    _FakeSSHClient.stderr_bytes = b""
    _FakeSSHClient.exit_status = 0
    _last_client.clear()

    def _factory() -> _FakeSSHClient:
        client = _FakeSSHClient()
        _last_client.append(client)
        return client

    import apex_host.agents.ssh_executor as mod
    monkeypatch.setattr(mod.paramiko, "SSHClient", _factory)
    return _FakeSSHClient


def _config(**overrides: Any) -> ApexConfig:
    base: dict[str, Any] = {
        "target": _TARGET, "dry_run": False,
        "ssh_connect_timeout_seconds": 1.0, "ssh_auth_timeout_seconds": 1.0,
        "ssh_command_timeout_seconds": 1.0,
    }
    base.update(overrides)
    return ApexConfig(**base)


# ---------------------------------------------------------------------------
# 1. Successful authentication
# ---------------------------------------------------------------------------

class TestSuccessfulAuthentication:
    async def test_success_produces_success_episode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.outcome.value == "success"
        assert result.episode.data["success"] is True
        assert result.episode.data["authenticated"] is True
        assert result.episode.data["error_category"] == CredentialErrorCategory.success.value

    async def test_success_includes_command_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert "uid=0(root)" in result.episode.data["response_summary"]


# ---------------------------------------------------------------------------
# 2. Authentication rejection
# ---------------------------------------------------------------------------

class TestAuthenticationRejection:
    async def test_auth_exception_produces_auth_rejected_category(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.connect_raises = paramiko.AuthenticationException("bad credentials")
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.outcome.value == "fundamental"
        assert result.episode.data["success"] is False
        assert result.episode.data["authenticated"] is False
        assert result.episode.data["error_category"] == CredentialErrorCategory.auth_rejected.value


# ---------------------------------------------------------------------------
# 3. Connect failure
# ---------------------------------------------------------------------------

class TestConnectFailure:
    async def test_connection_refused_produces_connection_failed_category(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.connect_raises = ConnectionRefusedError("refused")
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.connection_failed.value
        assert result.episode.data["success"] is False

    async def test_ssh_exception_before_auth_is_connection_failed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.connect_raises = paramiko.SSHException("protocol negotiation failed")
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.connection_failed.value


# ---------------------------------------------------------------------------
# 4. Connect timeout
# ---------------------------------------------------------------------------

class TestConnectTimeout:
    async def test_socket_timeout_on_connect_produces_connect_timeout_category(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.connect_raises = socket.timeout("timed out")
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.connect_timeout.value
        assert result.episode.data["timed_out"] is True


# ---------------------------------------------------------------------------
# 5. Authentication timeout
# ---------------------------------------------------------------------------

class TestAuthenticationTimeout:
    async def test_overall_wait_for_timeout_produces_connect_timeout_category(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the outer asyncio.wait_for ceiling fires (e.g. a hang deep
        inside a blocking call that ignored its own timeout), the executor
        still produces a bounded, structured result — never hangs forever.
        The outer wait_for itself is monkeypatched to raise immediately so
        this test does not need to actually wait out a real timeout."""
        import apex_host.agents.ssh_executor as mod

        async def _immediate_timeout(coro: Any, timeout: float) -> Any:
            coro.close()
            raise asyncio.TimeoutError()

        monkeypatch.setattr(mod.asyncio, "wait_for", _immediate_timeout)
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["timed_out"] is True
        assert result.episode.data["success"] is False
        assert result.episode.data["error_category"] == CredentialErrorCategory.connect_timeout.value


# ---------------------------------------------------------------------------
# 6. Command timeout
# ---------------------------------------------------------------------------

class TestCommandTimeout:
    async def test_exec_command_timeout_produces_command_timeout_category(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.exec_raises = socket.timeout("command timed out")
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.command_timeout.value
        # Login succeeded even though the follow-up command timed out.
        assert result.episode.data["authenticated"] is True
        assert result.episode.data["success"] is False


# ---------------------------------------------------------------------------
# 7. Harmless command output preserved
# ---------------------------------------------------------------------------

class TestCommandOutputPreserved:
    async def test_whoami_output_preserved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.stdout_bytes = b"root\n"
        executor = SSHExecutor(_config())
        result = await executor.run(_task(command="whoami"), _evidence())
        assert result.episode.data["response_summary"] == "root"
        assert result.episode.data["operation"] == "whoami"


# ---------------------------------------------------------------------------
# 8. Non-zero command result handled
# ---------------------------------------------------------------------------

class TestNonZeroCommandResult:
    async def test_nonzero_exit_status_is_command_failed_not_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.exit_status = 1
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["success"] is False
        assert result.episode.data["error_category"] == CredentialErrorCategory.command_failed.value
        assert result.episode.data["authenticated"] is True


# ---------------------------------------------------------------------------
# 9. Output truncation
# ---------------------------------------------------------------------------

class TestOutputTruncation:
    async def test_large_output_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.stdout_bytes = b"A" * 100_000
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert len(result.episode.data["response_summary"]) <= 4096


# ---------------------------------------------------------------------------
# 10. Session always closed
# ---------------------------------------------------------------------------

class TestSessionAlwaysClosed:
    async def test_closed_on_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        await executor.run(_task(), _evidence())
        assert _last_client[-1].closed is True

    async def test_closed_on_auth_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.connect_raises = paramiko.AuthenticationException("nope")
        executor = SSHExecutor(_config())
        await executor.run(_task(), _evidence())
        assert _last_client[-1].closed is True

    async def test_closed_on_command_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.exec_raises = paramiko.SSHException("channel error")
        executor = SSHExecutor(_config())
        await executor.run(_task(), _evidence())
        assert _last_client[-1].closed is True


# ---------------------------------------------------------------------------
# 11. No local SSH-agent/key discovery
# ---------------------------------------------------------------------------

class TestNoLocalKeyOrAgentDiscovery:
    async def test_connect_disables_agent_and_key_discovery(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        await executor.run(_task(), _evidence())
        kwargs = _last_client[-1].connect_calls[0]
        assert kwargs["allow_agent"] is False
        assert kwargs["look_for_keys"] is False
        assert kwargs.get("pkey") is None
        assert kwargs.get("key_filename") is None


# ---------------------------------------------------------------------------
# 12. Password absent from logs/results/exceptions
# ---------------------------------------------------------------------------

class TestPasswordNeverExposed:
    async def test_password_absent_from_episode_data(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        result = await executor.run(_task(password="s3cr3t-value"), _evidence())
        serialized = str(result.episode.data)
        assert "s3cr3t-value" not in serialized

    async def test_password_absent_on_auth_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.connect_raises = paramiko.AuthenticationException("s3cr3t-value")
        executor = SSHExecutor(_config())
        result = await executor.run(_task(password="s3cr3t-value"), _evidence())
        serialized = str(result.episode.data)
        assert "s3cr3t-value" not in serialized

    async def test_password_absent_from_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        result = await executor.run(_task(password="s3cr3t-value"), _evidence())
        assert "s3cr3t-value" not in repr(result)
        assert "s3cr3t-value" not in repr(result.episode)


# ---------------------------------------------------------------------------
# 13. Exactly one authentication attempt
# ---------------------------------------------------------------------------

class TestExactlyOneAttempt:
    async def test_connect_called_exactly_once_on_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        await executor.run(_task(), _evidence())
        assert len(_last_client[-1].connect_calls) == 1

    async def test_connect_called_exactly_once_on_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _install_fake_client(monkeypatch)
        fake.connect_raises = paramiko.AuthenticationException("nope")
        executor = SSHExecutor(_config())
        await executor.run(_task(), _evidence())
        assert len(_last_client[-1].connect_calls) == 1


# ---------------------------------------------------------------------------
# 14 / 15. No port forwarding, no SFTP/file transfer
# ---------------------------------------------------------------------------

class TestNoForwardingNoFileTransfer:
    async def test_open_sftp_never_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # _FakeSSHClient.open_sftp raises AssertionError if ever invoked —
        # a passing run() call is itself the proof it was never called.
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["success"] is True

    async def test_get_transport_never_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["success"] is True

    def test_no_sftp_or_forwarding_calls_in_source(self) -> None:
        import inspect
        import apex_host.agents.ssh_executor as mod
        source = _code_only(inspect.getsource(mod))
        assert "open_sftp" not in source
        assert "request_port_forward" not in source
        assert "invoke_shell" not in source


# ---------------------------------------------------------------------------
# 16. Host-key strategy behaves as documented
# ---------------------------------------------------------------------------

class TestHostKeyStrategy:
    async def test_uses_auto_add_policy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        await executor.run(_task(), _evidence())
        policy = _last_client[-1].missing_host_key_policy
        assert isinstance(policy, paramiko.AutoAddPolicy)

    def test_never_loads_persistent_host_key_files(self) -> None:
        import inspect
        import apex_host.agents.ssh_executor as mod
        source = _code_only(inspect.getsource(mod))
        assert "load_system_host_keys" not in source
        assert "load_host_keys(" not in source
        assert "save_host_keys" not in source


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------

class TestDryRun:
    async def test_dry_run_never_touches_paramiko(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.agents.ssh_executor as mod

        def _fail(*a: Any, **k: Any) -> None:
            raise AssertionError("dry-run must never construct a real SSHClient")

        monkeypatch.setattr(mod.paramiko, "SSHClient", _fail)
        executor = SSHExecutor(ApexConfig(target=_TARGET, dry_run=True))
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["dry_run"] is True
        assert result.episode.data["success"] is True

    async def test_dry_run_password_not_present(self) -> None:
        executor = SSHExecutor(ApexConfig(target=_TARGET, dry_run=True))
        result = await executor.run(_task(password="s3cr3t-value"), _evidence())
        assert "s3cr3t-value" not in str(result.episode.data)


# ---------------------------------------------------------------------------
# Direct sync-function coverage (bypasses asyncio.to_thread for speed/clarity)
# ---------------------------------------------------------------------------

class TestAttemptSshSyncDirect:
    def test_direct_call_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        result = _attempt_ssh_sync(_TARGET, 22, "root", "hunter2", "id", 1.0, 1.0, 1.0)
        assert result.success is True
        assert result.protocol == "ssh"
        assert result.executor == "ssh"


class TestCommandRejection:
    async def test_arbitrary_command_falls_back_to_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_client(monkeypatch)
        executor = SSHExecutor(_config())
        result = await executor.run(_task(command="rm -rf /"), _evidence())
        assert result.episode.data["operation"] == "id"
