"""The ONLY place in apex_host that may spawn a subprocess.

``run_command`` always checks ``tools/safety.py`` first, always uses
``asyncio.create_subprocess_exec`` (never ``shell=True``), always enforces a
timeout, and short-circuits with a synthetic ToolResult when
``ApexConfig.dry_run`` is True (the default).
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand, ToolResult

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)


async def run_command(cmd: ToolCommand, config: "ApexConfig") -> ToolResult:
    """Safely run *cmd*, or simulate it when ``config.dry_run`` is True."""
    check_command(cmd, config)

    if config.dry_run:
        logger.info("dry-run: %s %s", cmd.tool, " ".join(cmd.args))
        return ToolResult(
            command=cmd,
            stdout=f"[dry-run] would execute: {cmd.tool} {' '.join(cmd.args)}",
            stderr="",
            returncode=0,
            duration_seconds=0.0,
            dry_run=True,
        )

    timeout = min(cmd.timeout_seconds, config.max_command_seconds)
    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            cmd.tool,
            *cmd.args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(
                command=cmd,
                stdout="",
                stderr="",
                returncode=-1,
                duration_seconds=time.monotonic() - start,
                dry_run=False,
                error=f"command timed out after {timeout}s",
            )

        return ToolResult(
            command=cmd,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            returncode=proc.returncode if proc.returncode is not None else -1,
            duration_seconds=time.monotonic() - start,
            dry_run=False,
        )
    except OSError as exc:
        return ToolResult(
            command=cmd,
            stdout="",
            stderr="",
            returncode=-1,
            duration_seconds=time.monotonic() - start,
            dry_run=False,
            error=str(exc),
        )
