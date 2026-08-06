# test_ftp_remote_routing.py
# §28.16 — FTPExecutor routes credential validation to the Kali/VPN tool-service
# when tool_backend="remote" (where the target is reachable), and in-process
# otherwise. No real FTP/network: ftplib is mocked server-side, and the client
# reaches the tool-service via an in-process ASGI transport.
from __future__ import annotations

import ftplib
from typing import Any

import httpx
import pytest

from apex_host.agents.ftp_executor import FTPExecutor
from apex_host.config import ApexConfig
from memfabric.types import EvidenceBundle, TaskSpec

_TARGET = "10.129.44.139"
_SECRET = "hunter2-not-a-real-secret"
_TOKEN = "tok-not-a-real-secret"


def _task() -> TaskSpec:
    return TaskSpec(
        id="t-ftp", goal_id="g", executor_domain="credential",
        params={"tool": "ftp_access", "target": _TARGET, "port": "21",
                "username": "anonymous", "password": _SECRET, "parser": "access"},
        subgraph_anchor=f"host:{_TARGET}", phase="credential",
    )


def _ev() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


class _LiveSock:
    def settimeout(self, v: float) -> None: ...
    def sendall(self, d: bytes) -> None: ...


class _ServerFakeFTP:
    connect_raises: Exception | None = None

    def __init__(self) -> None:
        self.encoding = "utf-8"
        self.sock: _LiveSock | None = None

    def connect(self, host: str = "", port: int = 0, timeout: float = -1,
                source_address: object = None) -> str:
        if type(self).connect_raises is not None:
            self.sock = None
            raise type(self).connect_raises
        self.sock = _LiveSock()
        return "220 ready"

    def set_pasv(self, v: bool) -> None: ...
    def login(self, user: str = "", passwd: str = "", acct: str = "") -> str:
        return "230 ok"
    def pwd(self) -> str:
        return '"/" is the current directory'
    def voidcmd(self, c: str) -> str:
        return "200 ok"
    def quit(self) -> str:
        self.sock.sendall(b"Q")  # type: ignore[union-attr]
        return "221 bye"
    def close(self) -> None:
        self.sock = None


def _remote_config() -> ApexConfig:
    return ApexConfig(
        target=_TARGET, dry_run=False, tool_backend="remote",
        tool_service_url="http://svc", tool_service_token=_TOKEN,
        ftp_connect_timeout_seconds=1.0, ftp_login_timeout_seconds=1.0,
        ftp_command_timeout_seconds=1.0,
    )


def _wire_tool_service(monkeypatch: pytest.MonkeyPatch, *, connect_raises: Exception | None = None) -> None:
    """Point the FTPExecutor's internally-constructed RemoteToolBackend at an
    in-process tool-service app (real code), with ftplib mocked server-side."""
    from apex_tool_service.app import create_app
    from apex_tool_service.settings import ServiceSettings

    _ServerFakeFTP.connect_raises = connect_raises
    monkeypatch.setattr(ftplib, "FTP", _ServerFakeFTP)

    app = create_app(ServiceSettings(token=_TOKEN, authorized_cidrs=("10.129.0.0/16",)))
    transport = httpx.ASGITransport(app=app)
    import apex_host.tools.remote_backend as rb

    _real_async_client = httpx.AsyncClient  # bind before patching to avoid recursion

    def _client_factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        return _real_async_client(transport=transport)

    monkeypatch.setattr(rb.httpx, "AsyncClient", _client_factory)


class TestRemoteRouting:
    async def test_remote_success_records_validated_access(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire_tool_service(monkeypatch)
        result = await FTPExecutor(_remote_config()).run(_task(), _ev())
        assert result.episode.data["success"] is True
        assert result.episode.data["authenticated"] is True
        assert result.episode.data["executor"] == "ftp"
        assert _SECRET not in str(result.episode.data)  # password never stored

    async def test_remote_connect_failure_is_clean(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire_tool_service(monkeypatch, connect_raises=OSError(113, "No route to host"))
        result = await FTPExecutor(_remote_config()).run(_task(), _ev())
        assert result.episode.data["success"] is False
        assert result.episode.data["error_category"] in ("connection_failed", "connect_timeout")
        assert "sendall" not in str(result.episode.data)

    async def test_remote_routing_does_not_run_in_process(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # With tool_backend="remote", the in-process ftplib path must NOT run —
        # this is what fails against the old (always-in-process) routing.
        import apex_host.agents.ftp_executor as mod

        def _boom(*a: Any, **k: Any) -> None:
            raise AssertionError("in-process _attempt_ftp_sync ran despite tool_backend=remote")

        monkeypatch.setattr(mod, "_attempt_ftp_sync", _boom)
        _wire_tool_service(monkeypatch)
        result = await FTPExecutor(_remote_config()).run(_task(), _ev())
        assert result.episode.data["success"] is True  # went through the remote path

    async def test_local_backend_still_runs_in_process(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # tool_backend defaults to "local" → must NOT call the remote validator.
        called = {"remote": False}

        async def _fake_remote(self: Any, *a: Any, **k: Any) -> Any:
            called["remote"] = True
            raise AssertionError("remote path ran for a local backend")

        monkeypatch.setattr(FTPExecutor, "_remote_validate", _fake_remote)
        monkeypatch.setattr(ftplib, "FTP", _ServerFakeFTP)
        _ServerFakeFTP.connect_raises = None
        config = ApexConfig(target=_TARGET, dry_run=False, tool_backend="local",
                            ftp_connect_timeout_seconds=1.0, ftp_login_timeout_seconds=1.0,
                            ftp_command_timeout_seconds=1.0)
        result = await FTPExecutor(config).run(_task(), _ev())
        assert called["remote"] is False
        assert result.episode.data["success"] is True  # in-process fake login

    async def test_dry_run_never_reaches_remote(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _boom(self: Any, *a: Any, **k: Any) -> Any:
            raise AssertionError("dry-run reached the remote validator")

        monkeypatch.setattr(FTPExecutor, "_remote_validate", _boom)
        config = ApexConfig(target=_TARGET, dry_run=True, tool_backend="remote",
                            tool_service_url="http://svc", tool_service_token=_TOKEN)
        result = await FTPExecutor(config).run(_task(), _ev())
        assert result.episode.data["dry_run"] is True
        assert result.episode.data["success"] is True
