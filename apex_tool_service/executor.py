# executor.py
# The sole place apex_tool_service spawns a process — argv-list only, shell=False, SIGTERM-then-SIGKILL on timeout, bounded/safely-decoded output.
"""Subprocess execution for apex_tool_service.

Structurally parallel to ``apex_host/tools/runner.py::run_command`` (same
SIGTERM-then-grace-then-SIGKILL timeout handling, same
``asyncio.create_subprocess_exec``-only, ``shell=False``-always discipline)
but implemented independently: this package does not import ``apex_host``.

This is the only function in ``apex_tool_service`` that calls
``asyncio.create_subprocess_exec`` — enforced by
``tests/apex_tool_service/test_security_invariants.py``.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time

from apex_tool_service.models import ExecuteResponse
from apex_tool_service.settings import ServiceSettings

logger = logging.getLogger("apex_tool_service.executor")

_SIGTERM_GRACE_SECONDS = 5.0


def _decode_bounded(data: bytes, max_bytes: int) -> tuple[str, bool]:
    """Decode *data* as UTF-8 with replacement, bounded to *max_bytes*.

    Truncation happens on the raw bytes (before decoding) so a multi-byte
    UTF-8 sequence split by the cut is handled by ``errors="replace"``
    rather than raising. Returns ``(text, was_truncated)``.
    """
    truncated = len(data) > max_bytes
    bounded = data[:max_bytes]
    return bounded.decode("utf-8", errors="replace"), truncated


async def _terminate_and_wait(proc: "asyncio.subprocess.Process", grace_seconds: float) -> None:
    """SIGTERM, wait up to *grace_seconds*, escalate to SIGKILL if still alive."""
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=grace_seconds)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            await proc.wait()
        except Exception:  # noqa: BLE001 - best-effort reap after kill
            pass


async def execute_tool(
    *,
    tool: str,
    binary: str,
    arguments: list[str],
    timeout_seconds: float,
    stdin: str | None,
    settings: ServiceSettings,
) -> ExecuteResponse:
    """Run *binary* with *arguments* and return a structured ``ExecuteResponse``.

    Callers (``app.py``) are responsible for allowlist/argument/timeout
    validation *before* calling this function — this function assumes the
    request has already cleared ``apex_tool_service/validation.py``. It
    still performs the PATH-availability check and never raises for an
    ordinary execution failure (missing binary, non-zero exit, timeout,
    launch ``OSError``) — those are represented in the returned
    ``ExecuteResponse``, never as an exception.
    """
    if shutil.which(binary) is None:
        return ExecuteResponse(
            tool=tool, arguments=arguments, stdout="", stderr="",
            returncode=-1, duration_seconds=0.0, timed_out=False,
            error=f"tool '{tool}' (binary {binary!r}) not found in PATH",
        )

    start = time.monotonic()
    proc: "asyncio.subprocess.Process | None" = None
    stdin_bytes = stdin.encode("utf-8") if stdin is not None else None
    try:
        proc = await asyncio.create_subprocess_exec(
            binary,
            *arguments,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes), timeout=timeout_seconds
            )
        except asyncio.TimeoutError:
            await _terminate_and_wait(proc, _SIGTERM_GRACE_SECONDS)
            return ExecuteResponse(
                tool=tool, arguments=arguments, stdout="", stderr="",
                returncode=-1, duration_seconds=time.monotonic() - start,
                timed_out=True, error=f"command timed out after {timeout_seconds}s",
            )
        except asyncio.CancelledError:
            await _terminate_and_wait(proc, _SIGTERM_GRACE_SECONDS)
            raise

        stdout_text, stdout_truncated = _decode_bounded(stdout_bytes, settings.max_stdout_bytes)
        stderr_text, stderr_truncated = _decode_bounded(stderr_bytes, settings.max_stderr_bytes)
        error = None
        if stdout_truncated or stderr_truncated:
            parts = [p for p, t in (("stdout", stdout_truncated), ("stderr", stderr_truncated)) if t]
            logger.info("output truncated for tool=%s fields=%s", tool, parts)
        return ExecuteResponse(
            tool=tool, arguments=arguments,
            stdout=stdout_text, stderr=stderr_text,
            returncode=proc.returncode if proc.returncode is not None else -1,
            duration_seconds=time.monotonic() - start,
            timed_out=False, error=error,
        )
    except asyncio.CancelledError:
        if proc is not None:
            await _terminate_and_wait(proc, _SIGTERM_GRACE_SECONDS)
        raise
    except OSError as exc:
        return ExecuteResponse(
            tool=tool, arguments=arguments, stdout="", stderr="",
            returncode=-1, duration_seconds=time.monotonic() - start,
            timed_out=False, error=str(exc),
        )
