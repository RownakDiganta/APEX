from __future__ import annotations

import pytest

from apex_host.config import ApexConfig
from apex_host.tools.runner import run_command
from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand


def _config(**overrides: object) -> ApexConfig:
    base = {"target": "127.0.0.1", "allowed_tools": ["nmap", "curl"]}
    base.update(overrides)
    return ApexConfig(**base)  # type: ignore[arg-type]


def test_allows_safe_command() -> None:
    cfg = _config()
    cmd = ToolCommand(tool="nmap", args=["-T4", "127.0.0.1"])
    check_command(cmd, cfg)  # must not raise


def test_blocks_tool_not_in_allowlist() -> None:
    cfg = _config()
    cmd = ToolCommand(tool="wget", args=["http://example.com"])
    with pytest.raises(ValueError, match="not in allowed_tools"):
        check_command(cmd, cfg)


def test_blocks_shell_operator_in_args() -> None:
    cfg = _config()
    cmd = ToolCommand(tool="nmap", args=["127.0.0.1", ";", "cat", "/etc/passwd"])
    with pytest.raises(ValueError, match="shell operator"):
        check_command(cmd, cfg)


@pytest.mark.parametrize("op", ["&&", "||", "|", ">>", ">", "<", "$(", "`"])
def test_blocks_each_shell_operator(op: str) -> None:
    cfg = _config()
    cmd = ToolCommand(tool="nmap", args=[f"127.0.0.1{op}whoami"])
    with pytest.raises(ValueError, match="shell operator"):
        check_command(cmd, cfg)


def test_blocks_destructive_command_even_if_allowlisted() -> None:
    cfg = _config(allowed_tools=["rm"])
    cmd = ToolCommand(tool="rm", args=["-rf", "/"])
    with pytest.raises(ValueError, match="destructive-command blocklist"):
        check_command(cmd, cfg)


async def test_dry_run_default_does_not_execute() -> None:
    cfg = _config()
    assert cfg.dry_run is True
    cmd = ToolCommand(tool="nmap", args=["-T4", "127.0.0.1"])
    result = await run_command(cmd, cfg)
    assert result.dry_run is True
    assert result.returncode == 0
    assert "dry-run" in result.stdout


async def test_dry_run_rejects_unsafe_command_before_simulating() -> None:
    cfg = _config()
    cmd = ToolCommand(tool="wget", args=["http://evil.example"])
    with pytest.raises(ValueError):
        await run_command(cmd, cfg)


async def test_real_execution_uses_exec_not_shell() -> None:
    cfg = _config(allowed_tools=["python3"], dry_run=False)
    cmd = ToolCommand(tool="python3", args=["-c", "print('hello-from-apex')"], timeout_seconds=5)
    result = await run_command(cmd, cfg)
    assert result.dry_run is False
    assert result.returncode == 0
    assert "hello-from-apex" in result.stdout


async def test_real_execution_timeout_enforced() -> None:
    cfg = _config(allowed_tools=["python3"], dry_run=False, max_command_seconds=1)
    cmd = ToolCommand(tool="python3", args=["-c", "__import__('time').sleep(5)"], timeout_seconds=1)
    result = await run_command(cmd, cfg)
    assert result.error is not None
    assert "timed out" in result.error
