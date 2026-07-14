# telnet_executor.py
# Performs a bounded authorized telnet login validation using configured credentials.
"""Bounded telnet login executor. Implements memfabric Executor protocol.

Safety invariants:
- Dry-run (config.dry_run=True, the default): returns a synthetic result
  immediately with no network activity whatsoever.
- Stateless across calls: no connection handle is held on self.
- One attempt only: no credential looping, no brute force.
- Uses asyncio.open_connection, never subprocess or shell=True.
- Credentials must come from explicit operator config (task.params), never
  guessed by this executor.
- Live session stdout is NEVER stored in episode.data — only a
  [session_redacted] placeholder is kept (P8-S03).  Use
  apex_host.security.redaction for any further scrubbing needs.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from memfabric.types import Episode, EvidenceBundle, ExecutorResult, Outcome, TaskSpec
from apex_host.security.redaction import SESSION_REDACTED_PLACEHOLDER

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

_READ_BYTES: int = 4096


def _login_succeeded(stdout: str) -> bool:
    """Return True when stdout looks like a shell prompt after successful login."""
    lower = stdout.lower()
    failure_indicators = (
        "login incorrect",
        "authentication failed",
        "access denied",
        "permission denied",
        "invalid password",
        "login failed",
    )
    if any(indicator in lower for indicator in failure_indicators):
        return False
    return "$" in stdout or "#" in stdout


class TelnetExecutor:
    """Stateless executor: one bounded telnet login validation per run() call."""

    domain: str = "credential"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        params = task.params
        target = str(params.get("target", ""))
        port_str = str(params.get("port", "23"))
        username = str(params.get("username", ""))
        password = str(params.get("password", ""))

        if self._config.dry_run:
            return self._dry_run_result(task, target, port_str, username)

        try:
            port = int(port_str)
        except ValueError:
            port = 23

        try:
            stdout = await asyncio.wait_for(
                self._attempt_login(target, port, username, password),
                timeout=float(self._config.max_command_seconds),
            )
        except asyncio.TimeoutError:
            episode = Episode(
                agent="apex.credential",
                action=f"telnet {target}:{port_str}",
                outcome=Outcome.fixable,
                data={
                    "error": "connection timed out",
                    "target": target,
                    "port": port_str,
                    "dry_run": False,
                },
                task_id=task.id,
                phase=task.phase,
            )
            return ExecutorResult(task_id=task.id, episode=episode)
        except OSError as exc:
            episode = Episode(
                agent="apex.credential",
                action=f"telnet {target}:{port_str}",
                outcome=Outcome.fundamental,
                data={
                    "error": str(exc) or "connection error",
                    "target": target,
                    "port": port_str,
                    "dry_run": False,
                },
                task_id=task.id,
                phase=task.phase,
            )
            return ExecutorResult(task_id=task.id, episode=episode)

        outcome = Outcome.success if _login_succeeded(stdout) else Outcome.fundamental
        logger.info("telnet %s:%s user=%r outcome=%s", target, port_str, username, outcome.value)
        # P8-S03: never store raw session transcript in the episodic log.
        # Keep length + outcome flag for debugging without leaking credentials.
        episode = Episode(
            agent="apex.credential",
            action=f"telnet {target}:{port_str} user={username}",
            outcome=outcome,
            data={
                "stdout": SESSION_REDACTED_PLACEHOLDER,
                "stdout_length": len(stdout),
                "shell_found": _login_succeeded(stdout),
                "target": target,
                "port": port_str,
                "username": username,
                "dry_run": False,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)

    def _dry_run_result(
        self, task: TaskSpec, target: str, port: str, username: str
    ) -> ExecutorResult:
        # Synthetic output includes a shell prompt so AccessParser._login_succeeded
        # returns True and creates an access_state node in the EKG — this lets the
        # dry-run engagement verify the full credential→priv_esc routing path.
        stdout = (
            f"telnet {target} {port}\r\n"
            f"Connected to {target}.\r\n"
            f"Escape character is '^]'.\r\n"
            f"login: {username}\r\n"
            f"Password: \r\n"
            f"Welcome!\r\n"
            f"[dry-run: no real connection — synthetic shell]\r\n"
            f"# "
        )
        episode = Episode(
            agent="apex.credential",
            action=f"telnet {target}:{port} user={username} (dry-run)",
            outcome=Outcome.success,
            data={
                "stdout": stdout,
                "dry_run": True,
                "target": target,
                "port": port,
                "username": username,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)

    async def _attempt_login(
        self, target: str, port: int, username: str, password: str
    ) -> str:
        reader, writer = await asyncio.open_connection(target, port)
        try:
            return await self._do_login(reader, writer, username, password)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _do_login(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        username: str,
        password: str,
    ) -> str:
        buf: list[str] = []

        # Read banner + login prompt
        data = await reader.read(_READ_BYTES)
        buf.append(data.decode("utf-8", errors="replace"))

        # Send username
        writer.write((username + "\r\n").encode())
        await writer.drain()

        # Read post-username response (password prompt or shell)
        data = await reader.read(_READ_BYTES)
        chunk = data.decode("utf-8", errors="replace")
        buf.append(chunk)

        if "password" in chunk.lower():
            # Send password — empty string sends only "\r\n" (correct for no-auth services).
            writer.write((password + "\r\n").encode())
            await writer.drain()
            data = await reader.read(_READ_BYTES)
            buf.append(data.decode("utf-8", errors="replace"))

        # If we have a shell, send a harmless command to confirm access level.
        combined = "".join(buf)
        if _login_succeeded(combined):
            try:
                writer.write(b"id\r\n")
                await writer.drain()
                data = await reader.read(_READ_BYTES)
                buf.append(data.decode("utf-8", errors="replace"))
            except Exception:
                pass  # id probe failure is non-fatal; we already know login succeeded

        return "".join(buf)
