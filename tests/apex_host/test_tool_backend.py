# test_tool_backend.py
# Tests for apex_host/tools/backend.py: ToolBackend protocol conformance, DryRunToolBackend, LocalToolBackend, RemoteToolBackend, and backend selection.
from __future__ import annotations

import asyncio

import pytest

from apex_host.config import ApexConfig
from apex_host.tools.backend import (
    DryRunToolBackend,
    LocalToolBackend,
    RemoteToolBackend,
    ToolBackend,
    VALID_TOOL_BACKENDS,
    select_tool_backend,
    to_run_command_fn,
)


def _config(**overrides: object) -> ApexConfig:
    base: dict[str, object] = {"target": "127.0.0.1", "allowed_tools": ["nmap", "curl", "python3"]}
    base.update(overrides)
    return ApexConfig(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------

def test_dry_run_backend_satisfies_protocol() -> None:
    assert isinstance(DryRunToolBackend(_config()), ToolBackend)


def test_local_backend_satisfies_protocol() -> None:
    assert isinstance(LocalToolBackend(_config()), ToolBackend)


def test_remote_backend_satisfies_protocol() -> None:
    backend = RemoteToolBackend(service_url="http://kali:8080", token="t")
    assert isinstance(backend, ToolBackend)


# ---------------------------------------------------------------------------
# DryRunToolBackend
# ---------------------------------------------------------------------------

async def test_dry_run_backend_never_spawns_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("DryRunToolBackend must never spawn a subprocess")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fail)
    backend = DryRunToolBackend(_config(dry_run=False))  # even with dry_run=False on config
    result = await backend.execute("nmap", ["-T4", "127.0.0.1"])
    assert result.dry_run is True
    assert result.returncode == 0


async def test_dry_run_backend_deterministic_synthetic_result() -> None:
    backend = DryRunToolBackend(_config())
    result = await backend.execute("nmap", ["-T4", "127.0.0.1"])
    assert result.backend == "dry-run"
    assert result.timed_out is False
    assert result.stderr == ""
    assert "nmap" in result.stdout
    assert "-T4" in result.stdout


async def test_dry_run_backend_enforces_safety_gate_allowlist() -> None:
    backend = DryRunToolBackend(_config(allowed_tools=["nmap"]))
    with pytest.raises(ValueError, match="not in allowed_tools"):
        await backend.execute("wget", ["http://evil.example"])


async def test_dry_run_backend_enforces_safety_gate_destructive() -> None:
    backend = DryRunToolBackend(_config(allowed_tools=["rm"]))
    with pytest.raises(ValueError, match="destructive-command blocklist"):
        await backend.execute("rm", ["-rf", "/"])


async def test_dry_run_backend_enforces_safety_gate_shell_metachar() -> None:
    backend = DryRunToolBackend(_config(allowed_tools=["nmap"]))
    with pytest.raises(ValueError, match="shell operator"):
        await backend.execute("nmap", ["127.0.0.1;whoami"])


async def test_dry_run_backend_accepts_stdin_without_error() -> None:
    """DryRunToolBackend is inert — stdin is harmless to accept (nothing runs)."""
    backend = DryRunToolBackend(_config())
    result = await backend.execute("nmap", ["-T4", "127.0.0.1"], stdin="irrelevant")
    assert result.dry_run is True


async def test_dry_run_backend_never_contacts_network(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fail_connect(*args: object, **kwargs: object) -> object:
        raise AssertionError("DryRunToolBackend must not open a network connection")

    monkeypatch.setattr(asyncio, "open_connection", _fail_connect)
    backend = DryRunToolBackend(_config())
    await backend.execute("nmap", ["-T4", "127.0.0.1"])


# ---------------------------------------------------------------------------
# LocalToolBackend
# ---------------------------------------------------------------------------

async def test_local_backend_preserves_stdout() -> None:
    backend = LocalToolBackend(_config(allowed_tools=["python3"], dry_run=False))
    result = await backend.execute("python3", ["-c", "print('hello-from-backend')"], timeout_seconds=5)
    assert result.dry_run is False
    assert result.returncode == 0
    assert "hello-from-backend" in result.stdout
    assert result.backend == "local"


async def test_local_backend_preserves_stderr() -> None:
    backend = LocalToolBackend(_config(allowed_tools=["python3"], dry_run=False))
    result = await backend.execute(
        "python3",
        ["-c", "__import__('sys').stderr.write('err-from-backend')"],
        timeout_seconds=5,
    )
    assert "err-from-backend" in result.stderr


async def test_local_backend_returns_nonzero_exit_code() -> None:
    backend = LocalToolBackend(_config(allowed_tools=["python3"], dry_run=False))
    result = await backend.execute("python3", ["-c", "__import__('sys').exit(3)"], timeout_seconds=5)
    assert result.returncode == 3


async def test_local_backend_timeout_sets_timed_out_flag() -> None:
    cfg = _config(allowed_tools=["python3"], dry_run=False, max_command_seconds=1)
    backend = LocalToolBackend(cfg)
    result = await backend.execute(
        "python3", ["-c", "__import__('time').sleep(5)"], timeout_seconds=1,
    )
    assert result.timed_out is True
    assert result.error is not None
    assert "timed out" in result.error


async def test_local_backend_arguments_passed_as_list_not_shell_expanded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class _FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"", b""

    async def _fake_exec(*args: str, **kwargs: object) -> "_FakeProc":
        captured["args"] = args
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    backend = LocalToolBackend(_config(allowed_tools=["nmap"], dry_run=False))
    await backend.execute("nmap", ["-T4", "127.0.0.1;whoami".replace(";", "-")])
    # Every argument is a separate argv element — never a single shell string.
    assert captured["args"] == ("nmap", "-T4", "127.0.0.1-whoami")


async def test_local_backend_honors_dry_run_internally() -> None:
    """Defense in depth: LocalToolBackend still short-circuits via config.dry_run."""
    backend = LocalToolBackend(_config(dry_run=True))
    result = await backend.execute("nmap", ["-T4", "127.0.0.1"])
    assert result.dry_run is True
    assert result.backend == "dry-run"  # tags the *execution mode*, not the class used


async def test_local_backend_rejects_stdin_explicitly() -> None:
    backend = LocalToolBackend(_config(dry_run=False, allowed_tools=["python3"]))
    with pytest.raises(NotImplementedError):
        await backend.execute("python3", ["-c", "pass"], stdin="unsupported")


async def test_local_backend_enforces_safety_gate() -> None:
    backend = LocalToolBackend(_config(allowed_tools=["nmap"], dry_run=False))
    with pytest.raises(ValueError, match="not in allowed_tools"):
        await backend.execute("wget", ["http://evil.example"])


# ---------------------------------------------------------------------------
# RemoteToolBackend — contract only
# ---------------------------------------------------------------------------

def test_remote_backend_requires_service_url() -> None:
    with pytest.raises(ValueError, match="service_url"):
        RemoteToolBackend(service_url=None)


def test_remote_backend_construction_is_safe() -> None:
    # Must not raise, must not perform any I/O.
    RemoteToolBackend(service_url="http://kali:8080", token="secret", timeout_seconds=30.0)


async def test_remote_backend_execute_raises_not_implemented() -> None:
    backend = RemoteToolBackend(service_url="http://kali:8080")
    with pytest.raises(NotImplementedError):
        await backend.execute("nmap", ["-T4", "127.0.0.1"])


# ---------------------------------------------------------------------------
# select_tool_backend
# ---------------------------------------------------------------------------

def test_select_dry_run_backend() -> None:
    backend = select_tool_backend(_config(tool_backend="dry-run"))
    assert isinstance(backend, DryRunToolBackend)


def test_select_local_backend() -> None:
    backend = select_tool_backend(_config(tool_backend="local"))
    assert isinstance(backend, LocalToolBackend)


def test_select_remote_backend() -> None:
    backend = select_tool_backend(
        _config(tool_backend="remote", tool_service_url="http://kali:8080")
    )
    assert isinstance(backend, RemoteToolBackend)


def test_select_backend_rejects_invalid_value() -> None:
    with pytest.raises(ValueError, match="invalid ApexConfig.tool_backend"):
        select_tool_backend(_config(tool_backend="ssh-into-my-laptop"))


def test_valid_tool_backends_matches_selectable_names() -> None:
    for name in VALID_TOOL_BACKENDS:
        cfg = _config(tool_backend=name, tool_service_url="http://kali:8080")
        select_tool_backend(cfg)  # must not raise for any declared-valid name


def test_default_tool_backend_is_local_preserving_current_behavior() -> None:
    """ApexConfig.tool_backend defaults to "local" — the same execution path
    build_apex_graph() has always used (apex_host.tools.runner.run_command)."""
    assert _config().tool_backend == "local"


# ---------------------------------------------------------------------------
# to_run_command_fn adapter
# ---------------------------------------------------------------------------

async def test_adapter_wraps_backend_for_dispatcher_shape() -> None:
    from apex_host.types import ToolCommand

    cfg = _config()
    fn = to_run_command_fn(DryRunToolBackend(cfg))
    result = await fn(ToolCommand(tool="nmap", args=["-T4", "127.0.0.1"]), cfg)
    assert result.dry_run is True
    assert result.backend == "dry-run"


def test_tool_service_token_redacted_in_safe_dict() -> None:
    cfg = _config(tool_service_token="super-secret-token")
    d = cfg.to_safe_dict()
    assert d["tool_service_token"] != "super-secret-token"


def test_tool_service_token_defaults_empty_no_secret_default() -> None:
    assert _config().tool_service_token == ""
