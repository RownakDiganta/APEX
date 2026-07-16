# priv_esc_enum_executor.py
# Bounded, read-only privilege-escalation enumeration executor: runs exactly one fixed, allowlisted command per call over an already-validated SSH session.
"""Bounded privilege-escalation enumeration executor (Phase 13B).

Mirrors ``apex_host/agents/ssh_executor.py``'s safety model exactly — this is
the same "one bounded, stateless SSH exchange per call" pattern already
reviewed and tested for credential validation, extended to a small, fixed
set of *read-only enumeration* commands instead of a single identity check.

Nothing here executes an exploit, escalates privileges, generates a
payload, or performs any write to the target. Every command in
``ENUM_COMMANDS`` is read-only (``id``, ``uname -a``, ``sudo -n -l``,
``find ... -perm -4000``, ``getcap -r /``, ``mount``, ``crontab -l``,
``systemctl list-units``, ...) — no writes, no file creation, no service
mutation, no persistence mechanism of any kind.

Why this reuses SSHExecutor's model instead of ``ToolBackend``
----------------------------------------------------------------
``apex_host/tools/backend.py``'s ``ToolBackend`` (``DryRunToolBackend`` /
``LocalToolBackend`` / ``RemoteToolBackend``) runs a LOCAL binary (nmap,
curl, ...) from the APEX/Kali machine *against* the network target — it has
no concept of "run this command inside an already-authenticated remote
shell." Enumeration commands like ``sudo -l`` or ``find / -perm -4000``
only make sense executed *on* the target, which requires the same kind of
authenticated session Phase 12B's ``SSHExecutor`` already established (and
already reviewed for safety) — not a new local-subprocess channel. This
executor is that established, audited pattern, generalized from one fixed
command to a small, fixed command set. It still respects every principle
``ToolBackend`` embodies: ``config.dry_run`` gates all real I/O, the
command is never built from free-form input, and there is no shell-string
concatenation of caller-supplied data (see ``ENUM_COMMANDS`` below).

Safety properties enforced by construction (not configuration)
----------------------------------------------------------------
- **Fixed allowlist only.** A task may select a ``command_key`` (e.g.
  ``"sudo_l"``); the actual command STRING executed is always looked up
  from ``ENUM_COMMANDS`` — never constructed from ``task.params`` free text.
  An unrecognised ``command_key`` fails closed (no connection is even
  attempted) — mirrors ``SSHExecutor``'s ``_ALLOWED_VALIDATION_COMMANDS``
  defense-in-depth check, reinforced again at the policy layer (see
  ``apex_host/policy/rules.py::check_bounded_priv_esc_enumeration``).
- **One command, one connection, per call.** Exactly one
  ``SSHClient.connect()`` and one ``exec_command()`` per ``run()`` — no
  looping across commands inside the executor (the planner decides how
  many separate calls to make per turn, bounded — see
  ``apex_host/planners/priv_esc_planner.py``).
- **No persistent session, no file transfer, no port forwarding.** Same
  construction-level guarantees as ``SSHExecutor``: ``allow_agent=False``,
  ``look_for_keys=False``, no ``pkey``/``key_filename``, no
  ``open_sftp()``/``request_port_forward()``/``invoke_shell()`` anywhere in
  this module, and the client is closed in a ``finally`` block on every path.
- **Dry-run (config.dry_run=True, the default): returns a synthetic,
  deterministic, deliberately unremarkable result immediately** — no
  network activity whatsoever. The synthetic output never fabricates an
  "interesting" finding (no NOPASSWD sudo rule, no SUID hit) so a dry-run
  engagement never manufactures a privilege-escalation opportunity that
  didn't come from real enumeration.
- **Stateless across calls** (memfabric Invariant 6): no connection or
  Paramiko client is held on ``self``.
- **The password is never logged, stored in the episode, or included in
  any exception text** — mirrors ``SSHExecutor``'s own discipline exactly.

Host-key strategy: identical to ``SSHExecutor`` — a fresh, never-persisted,
in-memory-only ``SSHClient`` with ``paramiko.AutoAddPolicy()`` per call. See
``ssh_executor.py``'s "Host-key strategy" docstring for the full rationale;
it applies unchanged here.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import TYPE_CHECKING

import paramiko

from memfabric.types import Episode, EvidenceBundle, ExecutorResult, Outcome, TaskSpec

from apex_host.planners.priv_esc_opportunities import ENUM_COMMANDS

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

# ``command_key`` is the only thing a task may select; the command STRING
# actually executed always comes from ``ENUM_COMMANDS`` (the single source
# of truth shared with ``PrivEscPlanner`` — see
# ``apex_host/planners/priv_esc_opportunities.py``) — never from free-form
# task params.

# Deterministic, deliberately unremarkable dry-run stdout per command_key —
# demonstrates the full parse/opportunity pipeline without ever fabricating
# an "interesting" finding (no NOPASSWD rule, no SUID hit, no cron job).
_DRY_RUN_STDOUT: dict[str, str] = {
    "identity": "uid=1000(user) gid=1000(user) groups=1000(user)",
    "os_info": 'NAME="Ubuntu"\nVERSION="20.04 LTS"\n',
    "kernel_version": "Linux target 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux",
    "sudo_l": "Sorry, user user may not run sudo on target.\n",
    "suid": "/usr/bin/passwd\n/usr/bin/sudo\n",
    "capabilities": "",
    "mounts": "/dev/sda1 on / type ext4 (rw,relatime)\n",
    "cron": "",
    "service_info": "",
}

#: Bounded response size — mirrors SSHExecutor's _MAX_OUTPUT_BYTES, widened
#: slightly since some enumeration output (SUID listings, unit lists) is
#: naturally longer than a one-line identity command.
_MAX_OUTPUT_BYTES: int = 8192


class PrivEscEnumExecutor:
    """Stateless executor: one bounded, read-only enumeration command per run() call."""

    domain: str = "priv_esc"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        params = task.params
        target = str(params.get("target", ""))
        port_str = str(params.get("port", "22"))
        username = str(params.get("username", ""))
        password = str(params.get("password", ""))
        command_key = str(params.get("command_key", ""))

        entry = ENUM_COMMANDS.get(command_key)
        if entry is None:
            return self._episode_result(
                task, target, port_str, command_key, "", "",
                success=False, stdout="", error=f"unknown enumeration command_key {command_key!r}",
                dry_run=self._config.dry_run,
            )
        command, category = entry

        if self._config.dry_run:
            return self._dry_run_result(task, target, port_str, command_key, command, category)

        try:
            port = int(port_str)
        except ValueError:
            port = 22

        connect_timeout = float(getattr(self._config, "ssh_connect_timeout_seconds", 10.0))
        auth_timeout = float(getattr(self._config, "ssh_auth_timeout_seconds", 10.0))
        command_timeout = float(getattr(self._config, "ssh_command_timeout_seconds", 10.0))
        # Second, independent ceiling in case a blocking call inside the
        # thread does not honor its own timeout — mirrors SSHExecutor.
        overall_timeout = connect_timeout + auth_timeout + command_timeout + 5.0

        start = time.monotonic()
        try:
            stdout, error = await asyncio.wait_for(
                asyncio.to_thread(
                    _run_enum_command_sync,
                    target, port, username, password, command,
                    connect_timeout, auth_timeout, command_timeout,
                ),
                timeout=overall_timeout,
            )
        except asyncio.TimeoutError:
            stdout, error = "", "enumeration command exceeded the overall bounded timeout"

        duration = time.monotonic() - start
        success = error is None
        logger.info(
            "priv_esc_enum %s:%s command=%r outcome=%s",
            target, port_str, command_key, "success" if success else "failure",
        )
        return self._episode_result(
            task, target, port_str, command_key, command, category,
            success=success, stdout=stdout, error=error, dry_run=False,
            duration_seconds=duration,
        )

    def _episode_result(
        self,
        task: TaskSpec,
        target: str,
        port: str,
        command_key: str,
        command: str,
        category: str,
        *,
        success: bool,
        stdout: str,
        error: str | None,
        dry_run: bool,
        duration_seconds: float = 0.0,
    ) -> ExecutorResult:
        episode = Episode(
            agent="apex.priv_esc",
            action=f"priv_esc_enum {target}:{port} cmd={command_key}",
            outcome=Outcome.success if success else Outcome.fundamental,
            data={
                "target": target,
                "port": port,
                "command_key": command_key,
                "source_command": command,
                "category": category,
                "stdout": stdout[:_MAX_OUTPUT_BYTES],
                "success": success,
                "error": error,
                "dry_run": dry_run,
                "duration_seconds": duration_seconds,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)

    def _dry_run_result(
        self, task: TaskSpec, target: str, port: str, command_key: str, command: str, category: str,
    ) -> ExecutorResult:
        stdout = _DRY_RUN_STDOUT.get(command_key, "")
        return self._episode_result(
            task, target, port, command_key, command, category,
            success=True, stdout=stdout, error=None, dry_run=True,
        )


def _run_enum_command_sync(
    target: str,
    port: int,
    username: str,
    password: str,
    command: str,
    connect_timeout: float,
    auth_timeout: float,
    command_timeout: float,
) -> tuple[str, str | None]:
    """Synchronous Paramiko session — run via ``asyncio.to_thread`` only.

    Performs exactly one ``connect()`` and, on success, exactly one
    ``exec_command()`` call for the fixed *command* string. The client is
    always closed. Never raises — every Paramiko/socket exception is caught
    here and converted into an error string. Never returns or logs the
    password. Returns ``(stdout, error)`` — ``error`` is ``None`` on success.

    Unlike ``SSHExecutor``'s credential-validation path, a non-zero exit
    status from the remote command is NOT treated as a failure here: several
    enumeration commands (``sudo -n -l`` without configured rules,
    ``find ... 2>/dev/null`` skipping permission-denied entries) legitimately
    exit non-zero while still producing useful, safe stdout. Only a
    connection/authentication/protocol failure is a real failure.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            client.connect(
                hostname=target,
                port=port,
                username=username,
                password=password,
                timeout=connect_timeout,
                banner_timeout=connect_timeout,
                auth_timeout=auth_timeout,
                allow_agent=False,
                look_for_keys=False,
                pkey=None,
                key_filename=None,
            )
        except paramiko.AuthenticationException:
            return "", "ssh authentication rejected"
        except socket.timeout:
            return "", "ssh connect/auth timed out"
        except (OSError, paramiko.SSHException) as exc:
            return "", f"ssh connection failed: {type(exc).__name__}"

        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=command_timeout)
            out_bytes = stdout.read(_MAX_OUTPUT_BYTES)
            err_bytes = stderr.read(_MAX_OUTPUT_BYTES)
            stdout.channel.recv_exit_status()
        except socket.timeout:
            return "", "enumeration command timed out"
        except paramiko.SSHException as exc:
            return "", f"ssh protocol error running enumeration command: {type(exc).__name__}"

        out_text = out_bytes.decode("utf-8", errors="replace").strip()
        err_text = err_bytes.decode("utf-8", errors="replace").strip()
        return (out_text or err_text), None
    finally:
        client.close()
