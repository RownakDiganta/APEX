# test_ftp_validate.py
# Tests for the tool-service's bounded FTP credential-validation endpoint (§28.16).
"""POST /v1/ftp-validate — one bounded ftplib login on the target-reachable
(Kali/VPN) side. ftplib.FTP is monkeypatched with an in-process fake (no
network). Covers: auth, scope, dry-run, success, connect failure (no crash,
None-sock guard), auth-rejected redaction, bounded one-attempt model, and that
the password never appears in the response or the logs.
"""
from __future__ import annotations

import ftplib
import logging
from typing import Any

import pytest

from apex_tool_service.app import create_app
from apex_tool_service.executor import execute_ftp_validate
from apex_tool_service.settings import ServiceSettings

from tests.apex_tool_service._support import TEST_TOKEN, auth_headers, client_for

_TARGET = "10.129.44.139"  # inside the default authorized 10.129.0.0/16
_SECRET = "hunter2-not-a-real-secret"


def _settings(**overrides: Any) -> ServiceSettings:
    base: dict[str, Any] = {"token": TEST_TOKEN, "authorized_cidrs": ("10.129.0.0/16",)}
    base.update(overrides)
    return ServiceSettings(**base)


class _LiveSock:
    def settimeout(self, v: float) -> None: ...
    def sendall(self, d: bytes) -> None: ...


class _FakeFTP:
    connect_raises: Exception | None = None
    login_raises: Exception | None = None
    pwd_response: str = '"/" is the current directory'

    def __init__(self) -> None:
        self.encoding = "utf-8"
        self.sock: _LiveSock | None = None  # ftplib starts with sock=None
        self.quit_called = False
        self.login_calls = 0

    def connect(self, host: str = "", port: int = 0, timeout: float = -1,
                source_address: object = None) -> str:
        if type(self).connect_raises is not None:
            self.sock = None  # ftplib leaves sock None on connect failure
            raise type(self).connect_raises
        self.sock = _LiveSock()
        return "220 (vsFTPd 3.0.3)"

    def set_pasv(self, v: bool) -> None: ...
    def login(self, user: str = "", passwd: str = "", acct: str = "") -> str:
        self.login_calls += 1
        if type(self).login_raises is not None:
            raise type(self).login_raises
        return "230 Login successful."
    def pwd(self) -> str:
        return type(self).pwd_response
    def voidcmd(self, cmd: str) -> str:
        return "200 NOOP ok."
    def quit(self) -> str:
        self.quit_called = True
        self.sock.sendall(b"QUIT\r\n")  # type: ignore[union-attr]  — None on failed connect
        return "221 Goodbye."
    def close(self) -> None:
        self.sock = None

    # Forbidden — a passing test proves the bounded op never transfers a file.
    def retrbinary(self, *a: Any, **k: Any) -> None:
        raise AssertionError("ftp-validate must never RETR")
    def storbinary(self, *a: Any, **k: Any) -> None:
        raise AssertionError("ftp-validate must never STOR")
    def nlst(self, *a: Any, **k: Any) -> None:
        raise AssertionError("ftp-validate must never NLST")


def _install(monkeypatch: pytest.MonkeyPatch, *, connect_raises: Exception | None = None,
             login_raises: Exception | None = None) -> list[_FakeFTP]:
    _FakeFTP.connect_raises = connect_raises
    _FakeFTP.login_raises = login_raises
    _FakeFTP.pwd_response = '"/" is the current directory'
    captured: list[_FakeFTP] = []

    def _factory() -> _FakeFTP:
        c = _FakeFTP()
        captured.append(c)
        return c

    monkeypatch.setattr(ftplib, "FTP", _factory)
    return captured


def _body(**overrides: Any) -> dict[str, Any]:
    b: dict[str, Any] = {
        "target": _TARGET, "port": 21, "username": "anonymous", "password": _SECRET,
        "operation": "PWD", "connect_timeout_seconds": 1.0,
        "login_timeout_seconds": 1.0, "command_timeout_seconds": 1.0,
    }
    b.update(overrides)
    return b


class TestFtpValidateEndpoint:
    async def test_successful_anonymous_login(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = _install(monkeypatch)
        async with client_for(create_app(_settings())) as client:
            r = await client.post("/v1/ftp-validate", headers=auth_headers(), json=_body())
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True and data["authenticated"] is True
        assert "/" in data["response_summary"]
        assert captured[0].login_calls == 1  # exactly ONE attempt

    async def test_connect_failure_is_clean_not_crash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch, connect_raises=OSError(113, "No route to host"))
        async with client_for(create_app(_settings())) as client:
            r = await client.post("/v1/ftp-validate", headers=auth_headers(), json=_body())
        assert r.status_code == 200  # NOT a 500 crash
        data = r.json()
        assert data["ok"] is False and data["error_code"] == "connection_failed"
        assert "sendall" not in str(data)

    async def test_auth_rejected_redacts_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A hostile/odd server that echoes the password back must not leak it.
        _install(monkeypatch, login_raises=ftplib.error_perm(f"530 Login incorrect: {_SECRET}"))
        async with client_for(create_app(_settings())) as client:
            r = await client.post("/v1/ftp-validate", headers=auth_headers(), json=_body())
        data = r.json()
        assert data["ok"] is False and data["error_code"] == "auth_rejected"
        assert _SECRET not in str(data)

    async def test_password_never_in_response_on_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch)
        async with client_for(create_app(_settings())) as client:
            r = await client.post("/v1/ftp-validate", headers=auth_headers(), json=_body())
        assert _SECRET not in str(r.json())

    async def test_password_never_logged(self, monkeypatch: pytest.MonkeyPatch,
                                         caplog: pytest.LogCaptureFixture) -> None:
        _install(monkeypatch)
        with caplog.at_level(logging.DEBUG):
            async with client_for(create_app(_settings())) as client:
                await client.post("/v1/ftp-validate", headers=auth_headers(), json=_body())
        assert _SECRET not in caplog.text

    async def test_dry_run_no_login(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = _install(monkeypatch)
        async with client_for(create_app(_settings())) as client:
            r = await client.post("/v1/ftp-validate", headers=auth_headers(), json=_body(dry_run=True))
        assert r.json()["error_code"] == "dry_run"
        assert captured == []  # never even constructed an FTP client

    async def test_off_scope_target_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch)
        async with client_for(create_app(_settings())) as client:
            r = await client.post("/v1/ftp-validate", headers=auth_headers(), json=_body(target="8.8.8.8"))
        assert r.status_code == 400

    async def test_missing_auth_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch)
        async with client_for(create_app(_settings())) as client:
            r = await client.post("/v1/ftp-validate", json=_body())
        assert r.status_code == 401

    async def test_bad_operation_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch)
        async with client_for(create_app(_settings())) as client:
            r = await client.post("/v1/ftp-validate", headers=auth_headers(), json=_body(operation="RETR"))
        assert r.status_code == 400

    async def test_oversized_credential_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch)
        async with client_for(create_app(_settings(ftp_validate_max_credential_bytes=8))) as client:
            r = await client.post("/v1/ftp-validate", headers=auth_headers(),
                                   json=_body(password="x" * 100))
        assert r.status_code == 400

    async def test_extra_field_forbidden(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # No command/argv/tool field may ever be smuggled in.
        _install(monkeypatch)
        async with client_for(create_app(_settings())) as client:
            r = await client.post("/v1/ftp-validate", headers=auth_headers(),
                                   json={**_body(), "command": "cat /etc/shadow"})
        assert r.status_code == 400


class TestExecuteFtpValidateDirect:
    async def test_connect_failure_never_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch, connect_raises=OSError(113, "No route to host"))
        result = await execute_ftp_validate(
            target=_TARGET, port=21, username="anonymous", password=_SECRET, operation="PWD",
            connect_timeout=1.0, login_timeout=1.0, command_timeout=1.0,
        )
        assert result.ok is False and result.error_code == "connection_failed"

    async def test_success_quits_and_closes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = _install(monkeypatch)
        result = await execute_ftp_validate(
            target=_TARGET, port=21, username="anonymous", password=_SECRET, operation="PWD",
            connect_timeout=1.0, login_timeout=1.0, command_timeout=1.0,
        )
        assert result.ok is True and captured[0].quit_called is True

    def test_no_apex_host_import_in_tool_service_ftp(self) -> None:
        import apex_tool_service.executor as mod
        import inspect
        src = inspect.getsource(mod)
        assert "import apex_host" not in src and "from apex_host" not in src
