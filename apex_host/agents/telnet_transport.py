# telnet_transport.py
# Shared IAC-aware bounded telnet transport: one login + one optional fixed command read.
"""Low-level telnet transport shared by ``TelnetExecutor`` (credential
validation) and ``TelnetCapabilityAdapter`` (bounded flag read).

Kept deliberately separate from both callers so the IAC-negotiation and
prompt-detection logic lives in exactly one place (mirrors this codebase's
"single authoritative implementation" discipline). No stored state across
calls, ``asyncio`` only (never a subprocess), one bounded attempt.

Handles the two reasons the pre-existing ``TelnetExecutor`` could not
classify a passwordless-root shell (e.g. an HTB Starting-Point telnetd):

1. Telnet ``IAC`` option-negotiation bytes were never answered, so some
   servers stalled or the decoded banner was corrupted. This module
   answers every ``DO``/``WILL`` with a refusal (``WONT``/``DONT``) and
   strips ``IAC`` sequences from the decoded text (with a small carry
   buffer for sequences split across reads).
2. A single post-username read often missed the shell prompt that arrives
   with no intervening password prompt. This module accumulates across
   reads until it sees a password prompt, a shell prompt, or a failure
   phrase (bounded by a deadline and a byte cap).
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass

# Telnet protocol bytes (RFC 854).
_IAC = 0xFF
_DONT = 0xFE
_DO = 0xFD
_WONT = 0xFC
_WILL = 0xFB
_SB = 0xFA
_SE = 0xF0

_LOGIN_RE = re.compile(r"(login|user\s*name)\s*:\s*$", re.IGNORECASE | re.MULTILINE)
_PASSWORD_RE = re.compile(r"password\s*:\s*$", re.IGNORECASE | re.MULTILINE)
_SHELL_PROMPT_RE = re.compile(r"[$#>]\s*$", re.MULTILINE)
_FAILURE_RE = re.compile(
    r"(login\s+incorrect|authentication\s+failed|access\s+denied"
    r"|invalid\s+password|permission\s+denied|login\s+failed)",
    re.IGNORECASE,
)

#: Fixed sentinels bracketing a bounded command read so the file content can
#: be isolated from the interactive session's command echo and trailing
#: shell prompt. Chosen so they can never collide with a flag value and are
#: recognised only as standalone lines (the echoed command line contains
#: both markers inline and is therefore never mistaken for a marker line).
_MARK_START = "__APEX_READ_START__"
_MARK_END = "__APEX_READ_END__"

#: Hard cap on total decoded text held for any single accumulate call, so a
#: chatty or hostile server cannot exhaust memory even before the deadline.
_MAX_ACCUMULATE_BYTES = 65536


@dataclass(frozen=True, slots=True)
class TelnetSessionResult:
    """Outcome of one bounded telnet session. Never carries the password."""

    connected: bool         # TCP established (banner reached)
    authenticated: bool     # shell prompt reached with no failure phrase
    command_output: str     # bounded content between markers ("" if none/failed)
    error: str | None       # secret-free description, or None on full success


class _TelnetChannel:
    """IAC-aware read/write wrapper over an ``asyncio`` stream pair."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        self._carry = bytearray()  # partial IAC sequence spanning a read boundary

    async def write_line(self, line: str) -> None:
        self._writer.write((line + "\r\n").encode("utf-8", errors="replace"))
        await self._writer.drain()

    async def read_text(self, timeout: float) -> str:
        try:
            data = await asyncio.wait_for(self._reader.read(4096), timeout=timeout)
        except asyncio.TimeoutError:
            return ""
        except OSError:
            return ""
        if not data:
            return ""
        text, response = self._process(bytes(data))
        if response:
            try:
                self._writer.write(response)
                await self._writer.drain()
            except OSError:
                pass
        return text

    def _process(self, data: bytes) -> tuple[str, bytes]:
        buf = bytes(self._carry) + data
        self._carry = bytearray()
        out = bytearray()
        resp = bytearray()
        i = 0
        n = len(buf)
        while i < n:
            b = buf[i]
            if b != _IAC:
                out.append(b)
                i += 1
                continue
            if i + 1 >= n:
                self._carry = bytearray(buf[i:])
                break
            cmd = buf[i + 1]
            if cmd == _IAC:  # escaped literal 0xFF
                out.append(_IAC)
                i += 2
                continue
            if cmd in (_DO, _DONT, _WILL, _WONT):
                if i + 2 >= n:
                    self._carry = bytearray(buf[i:])
                    break
                opt = buf[i + 2]
                if cmd == _DO:
                    resp += bytes([_IAC, _WONT, opt])
                elif cmd == _WILL:
                    resp += bytes([_IAC, _DONT, opt])
                # DONT/WONT from the server need no reply.
                i += 3
                continue
            if cmd == _SB:  # subnegotiation — skip to IAC SE
                j = i + 2
                while j + 1 < n and not (buf[j] == _IAC and buf[j + 1] == _SE):
                    j += 1
                if j + 1 >= n:
                    self._carry = bytearray(buf[i:])
                    break
                i = j + 2
                continue
            i += 2  # any other 2-byte command
        return out.decode("utf-8", errors="replace"), bytes(resp)


async def _accumulate(
    channel: _TelnetChannel,
    predicate: Callable[[str], bool],
    *,
    read_timeout: float,
    deadline: float,
) -> str:
    """Read until *predicate(text)* is true, the server goes idle after
    producing some output, the byte cap is hit, or *deadline* passes."""
    loop = asyncio.get_event_loop()
    acc = ""
    while loop.time() < deadline and len(acc.encode("utf-8", errors="replace")) < _MAX_ACCUMULATE_BYTES:
        remaining = deadline - loop.time()
        chunk = await channel.read_text(min(read_timeout, max(0.1, remaining)))
        if chunk:
            acc += chunk
            if predicate(acc):
                break
        elif acc:
            # Idle after we already have data: nothing more is coming.
            break
    return acc


def _extract_between_markers(text: str) -> str | None:
    """Return the content between a standalone ``_MARK_START`` line and the
    following standalone ``_MARK_END`` line, or ``None`` if not both present.
    Ignores the echoed command line (which contains both markers inline)."""
    lines = [ln.strip("\r ") for ln in text.split("\n")]
    start = end = -1
    for idx, ln in enumerate(lines):
        if ln.strip() == _MARK_START:
            start = idx
            break
    if start == -1:
        return None
    for idx in range(start + 1, len(lines)):
        if lines[idx].strip() == _MARK_END:
            end = idx
            break
    if end == -1:
        return None
    body = [lines[i].strip() for i in range(start + 1, end) if lines[i].strip()]
    return "\n".join(body)


async def telnet_session(
    *,
    target: str,
    port: int,
    username: str,
    password: str,
    command: str | None,
    login_timeout: float,
    read_timeout: float,
    max_seconds: float,
    max_bytes: int,
) -> TelnetSessionResult:
    """One bounded telnet login and, optionally, one fixed command read.

    ``command`` is a fixed, caller-constructed command string (e.g.
    ``cat -- <validated-path>``) — never a task/LLM-controlled value. When
    supplied, it is bracketed with fixed sentinels so its output can be
    isolated from the session's echo/prompt noise, and only the content
    between the sentinels is returned (bounded to *max_bytes*).
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + max_seconds
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=login_timeout
        )
    except (OSError, asyncio.TimeoutError) as exc:
        return TelnetSessionResult(False, False, "", f"telnet connection failed: {type(exc).__name__}")

    channel = _TelnetChannel(reader, writer)
    try:
        # 1) Banner + login prompt (a shell prompt here would be unusual but is accepted).
        text = await _accumulate(
            channel,
            lambda t: _LOGIN_RE.search(t) is not None or _SHELL_PROMPT_RE.search(t) is not None,
            read_timeout=read_timeout,
            deadline=deadline,
        )

        # 2) Username, then password-prompt / shell / failure.
        if _SHELL_PROMPT_RE.search(text) is None:
            await channel.write_line(username)
            text = await _accumulate(
                channel,
                lambda t: (
                    _PASSWORD_RE.search(t) is not None
                    or _SHELL_PROMPT_RE.search(t) is not None
                    or _FAILURE_RE.search(t) is not None
                ),
                read_timeout=read_timeout,
                deadline=deadline,
            )

        if _FAILURE_RE.search(text) is not None:
            return TelnetSessionResult(True, False, "", "telnet authentication rejected")

        # 3) Password only if the server actually prompted for one (passwordless
        #    root shells reach the prompt directly and skip this entirely).
        if _PASSWORD_RE.search(text) is not None and _SHELL_PROMPT_RE.search(text) is None:
            await channel.write_line(password)
            text = await _accumulate(
                channel,
                lambda t: _SHELL_PROMPT_RE.search(t) is not None or _FAILURE_RE.search(t) is not None,
                read_timeout=read_timeout,
                deadline=deadline,
            )
            if _FAILURE_RE.search(text) is not None:
                return TelnetSessionResult(True, False, "", "telnet authentication rejected")

        if _SHELL_PROMPT_RE.search(text) is None:
            return TelnetSessionResult(True, False, "", "no shell prompt after login")

        if command is None:
            return TelnetSessionResult(True, True, "", None)

        # 4) Bounded marked command read.
        marked = f"echo {_MARK_START}; {command}; echo {_MARK_END}"
        await channel.write_line(marked)
        text = await _accumulate(
            channel,
            lambda t: _extract_between_markers(t) is not None,
            read_timeout=read_timeout,
            deadline=deadline,
        )
        body = _extract_between_markers(text)
        if body is None:
            return TelnetSessionResult(True, True, "", "bounded read did not complete")
        return TelnetSessionResult(True, True, body[:max_bytes], None)
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=3.0)
        except (OSError, asyncio.TimeoutError):
            pass
