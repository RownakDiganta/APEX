"""Command safety gate.

Every ToolCommand passes through ``check_command`` before
``apex_host/tools/runner.py`` will run it. This module makes no exceptions:
- Tool name must be in ``ApexConfig.allowed_tools`` (allowlist).
- Destructive commands are blocked unconditionally, even if accidentally
  added to the allowlist.
- Shell metacharacters in any token raise ValueError — defence in depth on
  top of runner.py never invoking a shell.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from apex_host.types import ToolCommand

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

_SHELL_OPERATORS: tuple[str, ...] = (";", "&&", "||", "|", ">>", ">", "<", "$(", "`")

_DESTRUCTIVE_COMMANDS: frozenset[str] = frozenset(
    {"rm", "mkfs", "dd", "shutdown", "reboot", "halt", "poweroff", "fdisk", "format", "mkswap"}
)


def check_command(cmd: ToolCommand, config: "ApexConfig") -> None:
    """Raise ValueError if *cmd* fails any safety gate. Does not execute anything."""
    tool = cmd.tool.strip()

    if tool in _DESTRUCTIVE_COMMANDS:
        raise ValueError(f"tool {tool!r} is in the destructive-command blocklist")

    if tool not in config.allowed_tools:
        raise ValueError(f"tool {tool!r} is not in allowed_tools: {config.allowed_tools}")

    for token in (tool, *cmd.args):
        for op in _SHELL_OPERATORS:
            if op in token:
                raise ValueError(
                    f"shell operator {op!r} found in command token {token!r}; "
                    "commands are passed as argv lists, not shell strings"
                )
