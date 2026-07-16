# test_ftp_executor.py
# Tests for FTPExecutor: bounded, one-attempt FTP credential validation with no real network access.
"""Tests for apex_host/agents/ftp_executor.py.

No test requires a real FTP server, Docker, VPN, or internet access —
``ftplib.FTP`` is monkeypatched with an in-process fake that raises the real
``ftplib`` exception classes so the executor's own exception handling is
exercised exactly as it runs in production.
"""
from __future__ import annotations

import asyncio
import ftplib
import re
import socket
from typing import Any

import pytest

from memfabric.types import EvidenceBundle, TaskSpec

from apex_host.agents.ftp_executor import FTPExecutor, _attempt_ftp_sync
from apex_host.config import ApexConfig
from apex_host.types import CredentialErrorCategory

_TARGET = "10.10.10.51"

_DOCSTRING_RE = re.compile(r'""".*?"""', re.DOTALL)


def _code_only(source: str) -> str:
    return _DOCSTRING_RE.sub("", source)


def _evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _task(
    *, target: str = _TARGET, port: str = "21", username: str = "anonymous",
    password: str = "guest@", operation: str | None = None,
) -> TaskSpec:
    params: dict[str, Any] = {
        "tool": "ftp_access", "target": target, "port": port,
        "username": username, "password": password, "parser": "access",
    }
    if operation is not None:
        params["operation"] = operation
    return TaskSpec(
        id="task-ftp-1", goal_id="goal-1", executor_domain="credential",
        params=params, subgraph_anchor=f"host:{target}", phase="credential",
    )


class _FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)


class _FakeFTP:
    """In-process double for ftplib.FTP — no network I/O."""

    connect_raises: Exception | None = None
    login_raises: Exception | None = None
    op_raises: Exception | None = None
    pwd_response: str = '"/" is the current directory'
    noop_response: str = "200 NOOP command successful"

    def __init__(self) -> None:
        self.encoding = "utf-8"
        self.sock: _FakeSocket | None = _FakeSocket()
        self.connect_calls: list[dict[str, Any]] = []
        self.login_calls: list[dict[str, Any]] = []
        self.pasv_calls: list[bool] = []
        self.quit_called = False
        self.close_called = False

    def connect(
        self, host: str = "", port: int = 0, timeout: float = -999,
        source_address: object = None,
    ) -> str:
        self.connect_calls.append({"host": host, "port": port, "timeout": timeout})
        if type(self).connect_raises is not None:
            raise type(self).connect_raises
        return "220 fake ftp ready"

    def set_pasv(self, value: bool) -> None:
        self.pasv_calls.append(value)

    def login(self, user: str = "", passwd: str = "", acct: str = "") -> str:
        self.login_calls.append({"user": user, "passwd": passwd})
        if type(self).login_raises is not None:
            raise type(self).login_raises
        return "230 login successful"

    def pwd(self) -> str:
        if type(self).op_raises is not None:
            raise type(self).op_raises
        return type(self).pwd_response

    def voidcmd(self, cmd: str) -> str:
        if type(self).op_raises is not None:
            raise type(self).op_raises
        return type(self).noop_response

    def quit(self) -> str:
        self.quit_called = True
        return "221 bye"

    def close(self) -> None:
        self.close_called = True

    # Forbidden operations — a passing test proves these are never called.
    def retrbinary(self, *a: Any, **k: Any) -> None:
        raise AssertionError("FTPExecutor must never RETR (file download)")

    def storbinary(self, *a: Any, **k: Any) -> None:
        raise AssertionError("FTPExecutor must never STOR (file upload)")

    def delete(self, *a: Any, **k: Any) -> None:
        raise AssertionError("FTPExecutor must never DELE")

    def mkd(self, *a: Any, **k: Any) -> None:
        raise AssertionError("FTPExecutor must never MKD")

    def rmd(self, *a: Any, **k: Any) -> None:
        raise AssertionError("FTPExecutor must never RMD")

    def rename(self, *a: Any, **k: Any) -> None:
        raise AssertionError("FTPExecutor must never RNFR/RNTO")

    def nlst(self, *a: Any, **k: Any) -> None:
        raise AssertionError("FTPExecutor must never NLST (recursive listing)")

    def dir(self, *a: Any, **k: Any) -> None:
        raise AssertionError("FTPExecutor must never LIST/dir")

    def retrlines(self, *a: Any, **k: Any) -> None:
        raise AssertionError("FTPExecutor must never retrlines")


_last_client: list[_FakeFTP] = []


def _install_fake_ftp(monkeypatch: pytest.MonkeyPatch) -> type[_FakeFTP]:
    _FakeFTP.connect_raises = None
    _FakeFTP.login_raises = None
    _FakeFTP.op_raises = None
    _FakeFTP.pwd_response = '"/" is the current directory'
    _FakeFTP.noop_response = "200 NOOP command successful"
    _last_client.clear()

    def _factory() -> _FakeFTP:
        client = _FakeFTP()
        _last_client.append(client)
        return client

    import apex_host.agents.ftp_executor as mod
    monkeypatch.setattr(mod.ftplib, "FTP", _factory)
    return _FakeFTP


def _config(**overrides: Any) -> ApexConfig:
    base: dict[str, Any] = {
        "target": _TARGET, "dry_run": False,
        "ftp_connect_timeout_seconds": 1.0, "ftp_login_timeout_seconds": 1.0,
        "ftp_command_timeout_seconds": 1.0,
    }
    base.update(overrides)
    return ApexConfig(**base)


# ---------------------------------------------------------------------------
# 1. Successful login with harmless PWD/NOOP
# ---------------------------------------------------------------------------

class TestSuccessfulLogin:
    async def test_pwd_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_ftp(monkeypatch)
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.outcome.value == "success"
        assert result.episode.data["success"] is True
        assert result.episode.data["authenticated"] is True
        assert result.episode.data["operation"] == "PWD"
        assert "/" in result.episode.data["response_summary"]

    async def test_noop_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_ftp(monkeypatch)
        executor = FTPExecutor(_config())
        result = await executor.run(_task(operation="NOOP"), _evidence())
        assert result.episode.data["success"] is True
        assert result.episode.data["operation"] == "NOOP"
        assert "NOOP" in result.episode.data["response_summary"]


# ---------------------------------------------------------------------------
# 2. Login rejection
# ---------------------------------------------------------------------------

class TestLoginRejection:
    async def test_error_perm_produces_auth_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.login_raises = ftplib.error_perm("530 Login incorrect")
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.outcome.value == "fundamental"
        assert result.episode.data["success"] is False
        assert result.episode.data["authenticated"] is False
        assert result.episode.data["error_category"] == CredentialErrorCategory.auth_rejected.value


# ---------------------------------------------------------------------------
# 3. Connect failure
# ---------------------------------------------------------------------------

class TestConnectFailure:
    async def test_connection_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.connect_raises = ConnectionRefusedError("refused")
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.connection_failed.value
        assert result.episode.data["success"] is False


# ---------------------------------------------------------------------------
# 4. Timeout (connect, login, command — three variants)
# ---------------------------------------------------------------------------

class TestTimeout:
    async def test_connect_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.connect_raises = socket.timeout("connect timed out")
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.connect_timeout.value
        assert result.episode.data["timed_out"] is True

    async def test_login_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.login_raises = socket.timeout("login timed out")
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.auth_timeout.value
        assert result.episode.data["timed_out"] is True

    async def test_command_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.op_raises = socket.timeout("op timed out")
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.command_timeout.value
        assert result.episode.data["authenticated"] is True
        assert result.episode.data["timed_out"] is True

    async def test_overall_wait_for_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.agents.ftp_executor as mod

        async def _immediate_timeout(coro: Any, timeout: float) -> Any:
            coro.close()
            raise asyncio.TimeoutError()

        monkeypatch.setattr(mod.asyncio, "wait_for", _immediate_timeout)
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["timed_out"] is True
        assert result.episode.data["success"] is False


# ---------------------------------------------------------------------------
# 5. Malformed protocol response
# ---------------------------------------------------------------------------

class TestMalformedProtocolResponse:
    async def test_login_protocol_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.login_raises = ftplib.error_proto("garbled response")
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.protocol_error.value

    async def test_login_eof_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.login_raises = EOFError("connection closed unexpectedly")
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.protocol_error.value

    async def test_command_protocol_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.op_raises = ftplib.error_temp("450 temporary failure")
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["error_category"] == CredentialErrorCategory.command_failed.value


# ---------------------------------------------------------------------------
# 6. Passive mode used
# ---------------------------------------------------------------------------

class TestPassiveMode:
    async def test_set_pasv_true_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_ftp(monkeypatch)
        executor = FTPExecutor(_config())
        await executor.run(_task(), _evidence())
        assert _last_client[-1].pasv_calls == [True]

    def test_no_active_mode_call_in_source(self) -> None:
        import inspect
        import apex_host.agents.ftp_executor as mod
        source = _code_only(inspect.getsource(mod))
        assert "set_pasv(False)" not in source
        assert ".makeport(" not in source


# ---------------------------------------------------------------------------
# 7. Connection always closed
# ---------------------------------------------------------------------------

class TestConnectionAlwaysClosed:
    async def test_quit_called_on_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_ftp(monkeypatch)
        executor = FTPExecutor(_config())
        await executor.run(_task(), _evidence())
        assert _last_client[-1].quit_called is True

    async def test_quit_called_on_login_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.login_raises = ftplib.error_perm("530 Login incorrect")
        executor = FTPExecutor(_config())
        await executor.run(_task(), _evidence())
        assert _last_client[-1].quit_called is True

    async def test_close_fallback_when_quit_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_ftp(monkeypatch)

        class _QuitFailsFTP(_FakeFTP):
            def quit(self) -> str:
                raise ftplib.error_temp("connection already gone")

        import apex_host.agents.ftp_executor as mod
        monkeypatch.setattr(mod.ftplib, "FTP", _QuitFailsFTP)
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["success"] is True  # quit failure doesn't affect the result


# ---------------------------------------------------------------------------
# 8 / 9. No LIST recursion, no RETR/STOR/DELE/MKD/RMD/RNFR/RNTO
# ---------------------------------------------------------------------------

class TestNoFileOperations:
    async def test_no_forbidden_calls_reached_on_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # _FakeFTP's retrbinary/storbinary/delete/mkd/rmd/rename/nlst/dir all
        # raise AssertionError if invoked — a passing run() proves they are
        # never called.
        _install_fake_ftp(monkeypatch)
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["success"] is True

    def test_no_file_transfer_or_mutation_calls_in_source(self) -> None:
        import inspect
        import apex_host.agents.ftp_executor as mod
        source = _code_only(inspect.getsource(mod))
        for forbidden in (
            "retrbinary", "retrlines", "storbinary", "storlines",
            "delete(", "mkd(", "rmd(", "rename(", "nlst(", ".dir(",
        ):
            assert forbidden not in source, f"forbidden FTP operation found: {forbidden}"


# ---------------------------------------------------------------------------
# 10. Password absent from logs/results/exceptions
# ---------------------------------------------------------------------------

class TestPasswordNeverExposed:
    async def test_password_absent_from_episode_data(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_ftp(monkeypatch)
        executor = FTPExecutor(_config())
        result = await executor.run(_task(password="s3cr3t-value"), _evidence())
        assert "s3cr3t-value" not in str(result.episode.data)

    async def test_password_absent_on_login_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.login_raises = ftplib.error_perm("530 s3cr3t-value rejected")
        executor = FTPExecutor(_config())
        result = await executor.run(_task(password="s3cr3t-value"), _evidence())
        assert "s3cr3t-value" not in str(result.episode.data)
        assert "s3cr3t-value" not in repr(result)


# ---------------------------------------------------------------------------
# 11. Exactly one login attempt
# ---------------------------------------------------------------------------

class TestExactlyOneAttempt:
    async def test_login_called_exactly_once_on_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_ftp(monkeypatch)
        executor = FTPExecutor(_config())
        await executor.run(_task(), _evidence())
        assert len(_last_client[-1].login_calls) == 1

    async def test_login_called_exactly_once_on_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.login_raises = ftplib.error_perm("530 Login incorrect")
        executor = FTPExecutor(_config())
        await executor.run(_task(), _evidence())
        assert len(_last_client[-1].login_calls) == 1


# ---------------------------------------------------------------------------
# 12. Response bounding
# ---------------------------------------------------------------------------

class TestResponseBounding:
    async def test_large_pwd_response_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _install_fake_ftp(monkeypatch)
        fake.pwd_response = "A" * 100_000
        executor = FTPExecutor(_config())
        result = await executor.run(_task(), _evidence())
        assert len(result.episode.data["response_summary"]) <= 4096


# ---------------------------------------------------------------------------
# Operation allowlist (defense in depth against an arbitrary operation string)
# ---------------------------------------------------------------------------

class TestOperationAllowlist:
    async def test_unsupported_operation_falls_back_to_pwd(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_ftp(monkeypatch)
        executor = FTPExecutor(_config())
        result = await executor.run(_task(operation="LIST"), _evidence())
        assert result.episode.data["operation"] == "PWD"


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------

class TestDryRun:
    async def test_dry_run_never_touches_ftplib(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.agents.ftp_executor as mod

        def _fail(*a: Any, **k: Any) -> None:
            raise AssertionError("dry-run must never construct a real ftplib.FTP")

        monkeypatch.setattr(mod.ftplib, "FTP", _fail)
        executor = FTPExecutor(ApexConfig(target=_TARGET, dry_run=True))
        result = await executor.run(_task(), _evidence())
        assert result.episode.data["dry_run"] is True
        assert result.episode.data["success"] is True

    async def test_dry_run_password_not_present(self) -> None:
        executor = FTPExecutor(ApexConfig(target=_TARGET, dry_run=True))
        result = await executor.run(_task(password="s3cr3t-value"), _evidence())
        assert "s3cr3t-value" not in str(result.episode.data)


# ---------------------------------------------------------------------------
# Direct sync-function coverage
# ---------------------------------------------------------------------------

class TestAttemptFtpSyncDirect:
    def test_direct_call_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_ftp(monkeypatch)
        result = _attempt_ftp_sync(_TARGET, 21, "anonymous", "guest@", "PWD", 1.0, 1.0, 1.0)
        assert result.success is True
        assert result.protocol == "ftp"
        assert result.executor == "ftp"
