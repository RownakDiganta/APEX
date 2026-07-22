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
from dataclasses import dataclass

from apex_tool_service.models import ExecuteResponse
from apex_tool_service.settings import ServiceSettings

logger = logging.getLogger("apex_tool_service.executor")

_SIGTERM_GRACE_SECONDS = 5.0

#: Phase 22 — the ONE fixed executable the dedicated bounded-file-read
#: operation may ever launch. Never operator/task/environment-configurable —
#: changing this requires a source-code change to this trusted module, not
#: a request field, a config value, or an environment variable.
_BOUNDED_READ_EXECUTABLE = "cat"

#: Chunk size for incremental, bounded stdout reads (execute_bounded_file_read).
_READ_CHUNK_BYTES = 4096

#: Read markers inspected on a non-zero exit — matched against the bounded,
#: never-persisted stderr text, then discarded. Mirrors
#: apex_host.verification.user_flag's own conservative error-marker
#: philosophy (a fixed, generic vocabulary — never a specific known value).
_FILE_NOT_FOUND_MARKERS = ("no such file or directory",)
_PERMISSION_DENIED_MARKERS = ("permission denied",)
_IS_DIRECTORY_MARKERS = ("is a directory",)


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


# ---------------------------------------------------------------------------
# Phase 22 — dedicated bounded-file-read execution
# (POST /v1/bounded-file-read; see docs/user-flag-objective.md §19).
#
# This is the SECOND (and only other) `asyncio.create_subprocess_exec` call
# site in this package — both remain confined to this one trusted module.
# Unlike `execute_tool()` above (an arbitrary allowlisted-tool invocation
# with caller-supplied arguments), this function accepts only a single,
# already-validated candidate *path* — the executable (`cat`) and the fixed
# `--` separator are hardcoded constants, never caller/config-controlled.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BoundedFileReadResult:
    """Service-internal result of one ``execute_bounded_file_read()`` call —
    distinct from the Pydantic ``ReadBoundedFileResponse`` (the HTTP
    boundary type built from this in ``app.py``). ``output`` is populated
    ONLY on ``ok=True`` — every rejection/failure path returns an empty
    string, never a partial/truncated prefix."""

    ok: bool
    output: str = ""
    error_code: str | None = None
    return_code: int | None = None
    bytes_received: int = 0
    oversized: bool = False
    timed_out: bool = False
    duration_seconds: float = 0.0


def _classify_stderr(stderr_text: str) -> str:
    """Map bounded, already-captured stderr text to a stable error category.
    The raw text itself is discarded by the caller immediately after this
    call — it is never returned, logged, or persisted."""
    low = stderr_text.lower()
    if any(marker in low for marker in _FILE_NOT_FOUND_MARKERS):
        return "file_not_found"
    if any(marker in low for marker in _PERMISSION_DENIED_MARKERS):
        return "permission_denied"
    if any(marker in low for marker in _IS_DIRECTORY_MARKERS):
        return "invalid_path"
    return "process_failed"


async def _read_stdout_bounded(
    stream: "asyncio.StreamReader", max_bytes: int,
) -> tuple[bytes, bool]:
    """Read incrementally from *stream* in small chunks, stopping the
    moment more than *max_bytes* has been received — never buffers an
    unbounded amount of data before checking the limit. Returns
    ``(collected_bytes, oversized)``; *collected_bytes* is discarded by the
    caller entirely when ``oversized`` is True."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            return b"", True
    return b"".join(chunks), False


async def execute_bounded_file_read(
    *, path: str, timeout_seconds: float, max_output_bytes: int,
) -> BoundedFileReadResult:
    """Read *path* via a fixed, non-configurable ``cat -- <path>`` argv
    invocation and return a structured, sanitized result.

    Callers (``app.py``) are responsible for target-authorization,
    path-validation, and limit-resolution *before* calling this function —
    this function assumes *path* has already cleared
    ``apex_tool_service/validation.py::validate_bounded_path``. It never
    raises for an ordinary execution failure (missing binary, non-zero
    exit, timeout, oversized output, launch ``OSError``) — those are
    represented in the returned ``BoundedFileReadResult``, never as an
    exception. Oversized output is discarded completely — this function
    never returns a truncated prefix.
    """
    if shutil.which(_BOUNDED_READ_EXECUTABLE) is None:
        return BoundedFileReadResult(ok=False, error_code="backend_unavailable")

    start = time.monotonic()
    argv = [_BOUNDED_READ_EXECUTABLE, "--", path]
    proc: "asyncio.subprocess.Process | None" = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None and proc.stderr is not None  # PIPE was requested above
        stdout_stream: asyncio.StreamReader = proc.stdout
        stderr_stream: asyncio.StreamReader = proc.stderr

        async def _read_both() -> tuple[bytes, bool, bytes]:
            stdout_bytes, oversized = await _read_stdout_bounded(stdout_stream, max_output_bytes)
            # stderr is bounded too, but far more generously — cat's own
            # error messages are always short and fixed-shape; this is
            # defense in depth against a pathological/hostile binary
            # substitution, not an expected code path.
            stderr_bytes, _ = await _read_stdout_bounded(stderr_stream, max(max_output_bytes, 4096))
            return stdout_bytes, oversized, stderr_bytes

        try:
            stdout_bytes, oversized, stderr_bytes = await asyncio.wait_for(
                _read_both(), timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            await _terminate_and_wait(proc, _SIGTERM_GRACE_SECONDS)
            return BoundedFileReadResult(
                ok=False, error_code="timeout", timed_out=True,
                duration_seconds=time.monotonic() - start,
            )
        except asyncio.CancelledError:
            await _terminate_and_wait(proc, _SIGTERM_GRACE_SECONDS)
            raise

        await asyncio.wait_for(proc.wait(), timeout=_SIGTERM_GRACE_SECONDS)
        duration = time.monotonic() - start

        if oversized:
            # Discard everything collected so far — never pass a truncated
            # prefix through. The process may still be running (stdout
            # exceeded the bound before EOF); terminate it defensively.
            await _terminate_and_wait(proc, _SIGTERM_GRACE_SECONDS)
            return BoundedFileReadResult(
                ok=False, error_code="oversized_output", oversized=True,
                duration_seconds=duration,
            )

        returncode = proc.returncode if proc.returncode is not None else -1
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        if returncode != 0:
            stderr_text = stderr_bytes.decode("utf-8", errors="replace")
            error_code = _classify_stderr(stderr_text)
            # stderr_text is deliberately allowed to fall out of scope here —
            # never returned, logged, or otherwise persisted beyond this
            # classification step.
            return BoundedFileReadResult(
                ok=False, error_code=error_code, return_code=returncode,
                duration_seconds=duration,
            )

        return BoundedFileReadResult(
            ok=True, output=stdout_text, return_code=returncode,
            bytes_received=len(stdout_bytes), duration_seconds=duration,
        )
    except asyncio.CancelledError:
        if proc is not None:
            await _terminate_and_wait(proc, _SIGTERM_GRACE_SECONDS)
        raise
    except OSError:
        return BoundedFileReadResult(
            ok=False, error_code="process_failed", duration_seconds=time.monotonic() - start,
        )
