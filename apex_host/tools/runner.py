# runner.py
# The only place in apex_host that spawns a subprocess, always via asyncio.create_subprocess_exec after a safety check and with dry-run short-circuit support.
"""The ONLY place in apex_host that may spawn a subprocess.

``run_command`` always checks ``tools/safety.py`` first, always uses
``asyncio.create_subprocess_exec`` (never ``shell=True``), always enforces a
timeout, and short-circuits with a synthetic ToolResult when
``ApexConfig.dry_run`` is True (the default).

Phase 7 subprocess lifecycle (P7-I03 / A07, P7-I04 / A08)
-----------------------------------------------------------
On timeout:
    1. Send SIGTERM to the child.
    2. Wait up to ``config.subprocess_sigterm_grace_seconds`` (default 5 s).
    3. If the child is still alive after the grace period, send SIGKILL.

On ``asyncio.CancelledError``:
    - Send SIGTERM, wait for the child to exit, then re-raise.
    - This prevents zombie / orphan processes when the calling coroutine is
      cancelled.

On ``OSError`` during launch:
    - Return a ``ToolResult`` with an error message (unchanged from before).
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from typing import TYPE_CHECKING

from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand, ToolResult

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

# Default SIGTERM grace period when config attribute is absent (seconds).
_DEFAULT_SIGTERM_GRACE: float = 5.0


async def _terminate_and_wait(
    proc: asyncio.subprocess.Process,
    grace_seconds: float,
) -> None:
    """Send SIGTERM to *proc*; after *grace_seconds* send SIGKILL if still alive.

    Used both on timeout and on ``CancelledError`` to guarantee the child
    process exits and does not become a zombie / orphan.
    """
    try:
        proc.terminate()
    except ProcessLookupError:
        return  # already dead

    try:
        await asyncio.wait_for(proc.wait(), timeout=grace_seconds)
    except asyncio.TimeoutError:
        # Grace period elapsed — escalate to SIGKILL.
        try:
            proc.kill()
        except ProcessLookupError:
            pass  # already dead
        try:
            await proc.wait()
        except Exception:
            pass


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

    if shutil.which(cmd.tool) is None:
        return ToolResult(
            command=cmd,
            stdout="",
            stderr="",
            returncode=-1,
            duration_seconds=0.0,
            dry_run=False,
            error=f"tool '{cmd.tool}' not found in PATH",
        )

    grace = float(getattr(config, "subprocess_sigterm_grace_seconds", _DEFAULT_SIGTERM_GRACE))
    timeout = min(cmd.timeout_seconds, config.max_command_seconds)
    start = time.monotonic()
    proc: asyncio.subprocess.Process | None = None
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
            # P7-I03 / A07: SIGTERM → grace period → SIGKILL (never immediate SIGKILL).
            await _terminate_and_wait(proc, grace)
            return ToolResult(
                command=cmd,
                stdout="",
                stderr="",
                returncode=-1,
                duration_seconds=time.monotonic() - start,
                dry_run=False,
                error=f"command timed out after {timeout}s",
            )
        except asyncio.CancelledError:
            # P7-I04 / A08: terminate child before propagating cancellation.
            await _terminate_and_wait(proc, grace)
            raise

        return ToolResult(
            command=cmd,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            returncode=proc.returncode if proc.returncode is not None else -1,
            duration_seconds=time.monotonic() - start,
            dry_run=False,
        )
    except asyncio.CancelledError:
        # CancelledError raised during proc creation (before communicate).
        if proc is not None:
            await _terminate_and_wait(proc, grace)
        raise
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
