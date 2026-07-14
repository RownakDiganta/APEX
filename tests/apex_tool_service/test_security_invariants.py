# test_security_invariants.py
# Static and dynamic proof that apex_tool_service never uses a shell, never concatenates a command string, and never lets an unallowlisted binary reach subprocess creation.
from __future__ import annotations

import asyncio
import pathlib
import re

import pytest

from apex_tool_service.app import create_app
from tests.apex_tool_service._support import auth_headers, client_for, make_settings

_PACKAGE_ROOT = pathlib.Path(__file__).parent.parent.parent / "apex_tool_service"


def _source_files() -> list[pathlib.Path]:
    return [p for p in sorted(_PACKAGE_ROOT.rglob("*.py")) if "__pycache__" not in p.parts]


def _non_comment_lines(path: pathlib.Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line for line in lines if not line.strip().startswith("#")]


# ---------------------------------------------------------------------------
# Static scans
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", _source_files(), ids=lambda p: p.name)
def test_no_create_subprocess_shell(path: pathlib.Path) -> None:
    for line in _non_comment_lines(path):
        assert "create_subprocess_shell" not in line, f"{path.name}: {line.strip()!r}"


@pytest.mark.parametrize("path", _source_files(), ids=lambda p: p.name)
def test_no_shell_true(path: pathlib.Path) -> None:
    for line in _non_comment_lines(path):
        assert "shell=True" not in line, f"{path.name}: {line.strip()!r}"


@pytest.mark.parametrize("path", _source_files(), ids=lambda p: p.name)
def test_no_os_system(path: pathlib.Path) -> None:
    for line in _non_comment_lines(path):
        assert re.search(r"\bos\.system\(", line) is None, f"{path.name}: {line.strip()!r}"
        assert re.search(r"\bsubprocess\.(run|Popen|call|check_output)\b", line) is None, (
            f"{path.name}: {line.strip()!r}"
        )


def test_exactly_one_subprocess_creation_call_site() -> None:
    """The only place a process is spawned is executor.py, and it unpacks
    `arguments` as separate argv entries — never a joined command string."""
    hits: list[tuple[str, str]] = []
    for path in _source_files():
        for line in _non_comment_lines(path):
            if "create_subprocess_exec(" in line:
                hits.append((path.name, line.strip()))
    assert len(hits) >= 1, "expected at least one create_subprocess_exec call"
    assert all(name == "executor.py" for name, _ in hits), (
        f"create_subprocess_exec called outside executor.py: {hits}"
    )


def test_no_command_string_join_feeds_subprocess_call() -> None:
    """No " ".join(...)-style command-string construction in executor.py — the
    execution boundary itself (the class of bug this whole service exists to
    prevent). audit.py legitimately joins argument *previews* for logging,
    which never reaches subprocess creation, so it is out of scope here."""
    executor_path = _PACKAGE_ROOT / "executor.py"
    violations: list[str] = []
    for line in _non_comment_lines(executor_path):
        if re.search(r'["\'] ["\']\.join\(', line) or re.search(r"\bshlex\.join\(", line):
            violations.append(line.strip())
    assert violations == [], violations


# ---------------------------------------------------------------------------
# Dynamic proof: an unallowlisted binary never reaches subprocess creation
# ---------------------------------------------------------------------------

async def test_unknown_tool_never_reaches_subprocess_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("create_subprocess_exec must never be called for an unallowlisted tool")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fail)
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "python3", "arguments": ["-c", "pass"]}, headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_never_allowed_tool_rejected_even_if_added_to_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defense in depth: NEVER_ALLOWED wins even over a careless ALLOWED_TOOLS edit."""
    from apex_tool_service import allowlist

    monkeypatch.setitem(allowlist.ALLOWED_TOOLS, "bash", "bash")
    assert allowlist.is_allowed("bash") is False


async def test_dangerous_argument_never_reaches_subprocess_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fail(*args: object, **kwargs: object) -> object:
        raise AssertionError(
            "create_subprocess_exec must never be called when arguments contain shell metacharacters"
        )

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fail)
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute",
            json={"tool": "curl", "arguments": ["x; rm -rf /"]},
            headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_policy_blocked_by_missing_auth_never_reaches_subprocess_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("create_subprocess_exec must never be called for an unauthenticated request")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fail)
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post("/v1/execute", json={"tool": "curl", "arguments": ["--version"]})
    assert r.status_code == 401
