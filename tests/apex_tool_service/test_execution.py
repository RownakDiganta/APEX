# test_execution.py
# Tests for actual command execution: stdout/stderr capture, exit codes, argv-not-shell, timeout/reap, stdin, output decoding and truncation, backend identity, duration.
from __future__ import annotations

import asyncio

import pytest

from apex_tool_service.app import create_app
from apex_tool_service.executor import _decode_bounded, execute_tool
from apex_tool_service.settings import ServiceSettings
from tests.apex_tool_service._support import auth_headers, client_for, make_settings

# executor.execute_tool() takes an explicit `binary` and does not consult the
# allowlist (allowlist checking is validation.py's job, applied only in
# app.py) — so these tests may safely use any safe local executable
# (python3) without needing it in ALLOWED_TOOLS. This matches the task
# brief's "test-specific injected executable mappings" allowance.


def _settings(**overrides: object) -> ServiceSettings:
    return make_settings(**overrides)


# ---------------------------------------------------------------------------
# executor.execute_tool() — direct unit tests
# ---------------------------------------------------------------------------

async def test_stdout_preserved() -> None:
    result = await execute_tool(
        tool="test", binary="python3",
        arguments=["-c", "print('hello-from-execution-test')"],
        timeout_seconds=5, stdin=None, settings=_settings(),
    )
    assert "hello-from-execution-test" in result.stdout
    assert result.returncode == 0


async def test_stderr_preserved() -> None:
    result = await execute_tool(
        tool="test", binary="python3",
        arguments=["-c", "__import__('sys').stderr.write('err-from-execution-test')"],
        timeout_seconds=5, stdin=None, settings=_settings(),
    )
    assert "err-from-execution-test" in result.stderr


async def test_nonzero_return_code_preserved() -> None:
    result = await execute_tool(
        tool="test", binary="python3",
        arguments=["-c", "__import__('sys').exit(7)"],
        timeout_seconds=5, stdin=None, settings=_settings(),
    )
    assert result.returncode == 7


async def test_arguments_not_shell_expanded(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class _FakeProc:
        returncode = 0

        async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
            return b"", b""

    async def _fake_exec(*args: str, **kwargs: object) -> "_FakeProc":
        captured["args"] = args
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    await execute_tool(
        tool="test", binary="curl",
        arguments=["-T4", "127.0.0.1;whoami".replace(";", "-")],
        timeout_seconds=5, stdin=None, settings=_settings(),
    )
    assert captured["args"] == ("curl", "-T4", "127.0.0.1-whoami")


async def test_timeout_kills_and_reaps_process() -> None:
    result = await execute_tool(
        tool="test", binary="python3",
        arguments=["-c", "__import__('time').sleep(5)"],
        timeout_seconds=1, stdin=None, settings=_settings(),
    )
    assert result.timed_out is True
    assert result.error is not None
    assert "timed out" in result.error


async def test_timed_out_represented_correctly_on_success_path() -> None:
    result = await execute_tool(
        tool="test", binary="python3", arguments=["-c", "pass"],
        timeout_seconds=5, stdin=None, settings=_settings(),
    )
    assert result.timed_out is False


async def test_missing_executable_handled() -> None:
    result = await execute_tool(
        tool="test", binary="_apex_tool_service_definitely_nonexistent_xyz",
        arguments=[], timeout_seconds=5, stdin=None, settings=_settings(),
    )
    assert result.error is not None
    assert "not found in PATH" in result.error
    assert result.returncode == -1


async def test_stdin_delivered_correctly() -> None:
    result = await execute_tool(
        tool="test", binary="python3",
        arguments=["-c", "print(__import__('sys').stdin.read().strip())"],
        timeout_seconds=5, stdin="hello-via-stdin", settings=_settings(),
    )
    assert "hello-via-stdin" in result.stdout


async def test_stdin_none_means_no_pipe_required() -> None:
    result = await execute_tool(
        tool="test", binary="python3", arguments=["-c", "print('no-stdin-needed')"],
        timeout_seconds=5, stdin=None, settings=_settings(),
    )
    assert result.returncode == 0


async def test_backend_identifier_is_correct() -> None:
    result = await execute_tool(
        tool="test", binary="python3", arguments=["-c", "pass"],
        timeout_seconds=5, stdin=None, settings=_settings(),
    )
    assert result.backend == "kali-service"


async def test_duration_is_non_negative() -> None:
    result = await execute_tool(
        tool="test", binary="python3", arguments=["-c", "pass"],
        timeout_seconds=5, stdin=None, settings=_settings(),
    )
    assert result.duration_seconds >= 0.0


async def test_stdout_truncation_works() -> None:
    result = await execute_tool(
        tool="test", binary="python3",
        arguments=["-c", "print('x' * 1000)"],
        timeout_seconds=5, stdin=None, settings=_settings(max_stdout_bytes=10),
    )
    assert len(result.stdout.encode("utf-8")) <= 10


async def test_stderr_truncation_works() -> None:
    result = await execute_tool(
        tool="test", binary="python3",
        arguments=["-c", "__import__('sys').stderr.write('y' * 1000)"],
        timeout_seconds=5, stdin=None, settings=_settings(max_stderr_bytes=10),
    )
    assert len(result.stderr.encode("utf-8")) <= 10


# ---------------------------------------------------------------------------
# _decode_bounded — invalid UTF-8 handling
# ---------------------------------------------------------------------------

def test_decode_bounded_replaces_invalid_utf8_bytes() -> None:
    text, truncated = _decode_bounded(b"valid \xff\xfe bytes", max_bytes=1000)
    assert "�" in text  # replacement character present, no exception raised
    assert truncated is False


def test_decode_bounded_truncates_and_flags() -> None:
    text, truncated = _decode_bounded(b"0123456789", max_bytes=4)
    assert len(text.encode("utf-8")) <= 4
    assert truncated is True


def test_decode_bounded_no_truncation_when_within_limit() -> None:
    text, truncated = _decode_bounded(b"short", max_bytes=100)
    assert text == "short"
    assert truncated is False


# ---------------------------------------------------------------------------
# HTTP-level end-to-end execution (curl is in ALLOWED_TOOLS and universally
# present on macOS + Linux; --version makes no network call)
# ---------------------------------------------------------------------------

async def test_http_execute_happy_path() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "curl", "arguments": ["--version"]}, headers=auth_headers(),
        )
    assert r.status_code == 200
    body = r.json()
    assert body["returncode"] == 0
    assert "curl" in body["stdout"].lower()
    assert body["backend"] == "kali-service"
    assert body["timed_out"] is False
    assert body["error"] is None
    assert body["duration_seconds"] >= 0.0


async def test_http_execute_response_matches_request_tool_and_arguments() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "curl", "arguments": ["--version"]}, headers=auth_headers(),
        )
    body = r.json()
    assert body["tool"] == "curl"
    assert body["arguments"] == ["--version"]
