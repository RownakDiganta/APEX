# ssh_executor.py
# Performs a bounded, one-attempt authorized SSH login validation using explicit, operator-supplied credentials.
"""Bounded SSH login-validation executor. Implements memfabric Executor protocol.

Mirrors ``apex_host/agents/telnet_executor.py``'s safety model exactly, adapted
for SSH via Paramiko instead of a raw TCP banner exchange:

- Dry-run (config.dry_run=True, the default): returns a synthetic result
  immediately with no network activity whatsoever.
- Stateless across calls: no connection or Paramiko client is held on self.
- One attempt only: exactly one ``SSHClient.connect()`` call, no credential
  looping, no brute force.
- Credentials must come from explicit operator config (task.params), never
  guessed by this executor.
- Live command output is truncated and stored directly in episode.data
  (unlike Telnet's raw session transcript, SSH's harmless-command stdout is
  not a login-prompt/shell transcript, so P8-S03's full-session redaction
  does not apply the same way — but the password itself is NEVER included
  anywhere in the episode, exception text, or logs; see ``_run_sync``).

Safety properties enforced by construction (not configuration):
- ``allow_agent=False``, ``look_for_keys=False``, no ``pkey``/``key_filename``
  passed to ``SSHClient.connect()`` — this disables local ~/.ssh key
  discovery and SSH-agent forwarding entirely, and (per Paramiko's own
  ``SSHClient._auth`` implementation) guarantees the keyboard-interactive
  fallback path is never reached, since that fallback only triggers when a
  public-key attempt returns a two-factor-eligible method set — no key
  attempt is ever made here.
- No port forwarding, no SFTP/file transfer, no persistent session: this
  module never calls ``open_sftp()``, ``request_port_forward()``, or any
  forwarding/tunnel API — the only channel opened is the one
  ``exec_command()`` uses for the single harmless validation command, and
  the client is closed in a ``finally`` block on every path.
- Exactly one harmless command is ever executed (default ``id``, operator
  may override to another read-only identity command such as ``whoami`` —
  never an arbitrary string; see ``_ALLOWED_VALIDATION_COMMANDS``).

Host-key strategy (documented per this phase's own requirement — see
docs/credential-validation.md "SSH host-key behavior" for the full
rationale): this executor uses ``paramiko.AutoAddPolicy()`` with a fresh,
never-persisted, in-memory-only ``SSHClient`` per call (no
``load_system_host_keys()``, no ``load_host_keys()``, no ``save_host_keys()``
— the host-key store starts empty and is discarded when the client is
closed). This is a deliberate trust-on-first-use decision scoped to a
single bounded validation attempt against an already-authorized lab target:
HTB lab machines are ephemeral and their host key changes across resets, so
persisting an accepted key to disk (as interactive ``ssh`` normally does)
would provide no real security benefit while adding stale-entry operational
complexity. It is not silent — this docstring and docs/credential-validation.md
are the documentation this file's own review checklist requires.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import TYPE_CHECKING

import paramiko

from memfabric.types import Episode, EvidenceBundle, ExecutorResult, Outcome, TaskSpec
from apex_host.types import CredentialErrorCategory, CredentialValidationResult

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

#: Default harmless identity command — never changed to anything destructive.
DEFAULT_VALIDATION_COMMAND: str = "id"

#: The only commands this executor will ever run over the SSH channel.
#: A task requesting anything else is rejected before any connection is made
#: (defense in depth on top of the policy-layer check in
#: apex_host/policy/rules.py::check_bounded_credential_validation).
_ALLOWED_VALIDATION_COMMANDS: frozenset[str] = frozenset({"id", "whoami"})

#: Bounded response size — mirrors TelnetExecutor's _READ_BYTES.
_MAX_OUTPUT_BYTES: int = 4096


class SSHExecutor:
    """Stateless executor: one bounded SSH login validation per run() call."""

    domain: str = "credential"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        params = task.params
        target = str(params.get("target", ""))
        port_str = str(params.get("port", "22"))
        username = str(params.get("username", ""))
        password = str(params.get("password", ""))
        command = str(params.get("command") or DEFAULT_VALIDATION_COMMAND)
        if command not in _ALLOWED_VALIDATION_COMMANDS:
            command = DEFAULT_VALIDATION_COMMAND

        if self._config.dry_run:
            return self._dry_run_result(task, target, port_str, username, command)

        try:
            port = int(port_str)
        except ValueError:
            port = 22

        connect_timeout = float(getattr(self._config, "ssh_connect_timeout_seconds", 10.0))
        auth_timeout = float(getattr(self._config, "ssh_auth_timeout_seconds", 10.0))
        command_timeout = float(getattr(self._config, "ssh_command_timeout_seconds", 10.0))
        # Outer defensive bound — Paramiko's own connect/auth/channel timeouts
        # should fire first; this is a second, independent ceiling in case a
        # blocking call inside the thread does not honor its own timeout.
        overall_timeout = connect_timeout + auth_timeout + command_timeout + 5.0

        start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    _attempt_ssh_sync,
                    target, port, username, password, command,
                    connect_timeout, auth_timeout, command_timeout,
                ),
                timeout=overall_timeout,
            )
        except asyncio.TimeoutError:
            result = CredentialValidationResult(
                protocol="ssh", target=target, port=port_str, username=username,
                success=False, authenticated=False, operation=command,
                response_summary="", error_category=CredentialErrorCategory.connect_timeout.value,
                error_detail="ssh validation exceeded the overall bounded timeout",
                duration_seconds=time.monotonic() - start, timed_out=True, executor="ssh",
            )

        outcome = Outcome.success if result.success else Outcome.fundamental
        logger.info(
            "ssh %s:%s user=%r outcome=%s category=%s",
            target, port_str, username, outcome.value, result.error_category,
        )
        episode = Episode(
            agent="apex.credential",
            action=f"ssh {target}:{port_str} user={username} cmd={command}",
            outcome=outcome,
            data={
                "protocol": "ssh",
                "target": result.target,
                "port": result.port,
                "username": result.username,
                "success": result.success,
                "authenticated": result.authenticated,
                "operation": result.operation,
                "response_summary": result.response_summary,
                "error_category": result.error_category,
                "error_detail": result.error_detail,
                "duration_seconds": result.duration_seconds,
                "timed_out": result.timed_out,
                "executor": "ssh",
                "dry_run": False,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)

    def _dry_run_result(
        self, task: TaskSpec, target: str, port: str, username: str, command: str
    ) -> ExecutorResult:
        # Synthetic output simulates a successful identity command so the
        # dry-run engagement can verify the full credential->priv_esc
        # routing path — no real network connection is ever made.
        response_summary = "uid=1000(user) gid=1000(user) groups=1000(user)"
        episode = Episode(
            agent="apex.credential",
            action=f"ssh {target}:{port} user={username} cmd={command} (dry-run)",
            outcome=Outcome.success,
            data={
                "protocol": "ssh",
                "target": target,
                "port": port,
                "username": username,
                "success": True,
                "authenticated": True,
                "operation": command,
                "response_summary": response_summary,
                "error_category": CredentialErrorCategory.success.value,
                "error_detail": "",
                "duration_seconds": 0.0,
                "timed_out": False,
                "executor": "ssh",
                "dry_run": True,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)


def _attempt_ssh_sync(
    target: str,
    port: int,
    username: str,
    password: str,
    command: str,
    connect_timeout: float,
    auth_timeout: float,
    command_timeout: float,
) -> CredentialValidationResult:
    """Synchronous Paramiko session — run via ``asyncio.to_thread`` only.

    Performs exactly one ``connect()`` (one authentication attempt) and, on
    success, exactly one ``exec_command()`` call. The client is always
    closed. Never raises — every Paramiko/socket exception is caught here
    and converted into a ``CredentialValidationResult`` with the
    appropriate ``error_category``. Never returns or logs the password.
    """
    start = time.monotonic()
    client = paramiko.SSHClient()
    # See module docstring "Host-key strategy" — deliberate, documented,
    # in-memory-only trust-on-first-use for a single bounded attempt.
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
                # Explicit, not merely default-inherited: no local key
                # discovery, no SSH-agent use, no key material of any kind —
                # this is a password-only bounded validation attempt.
                allow_agent=False,
                look_for_keys=False,
                pkey=None,
                key_filename=None,
            )
        except paramiko.AuthenticationException:
            return CredentialValidationResult(
                protocol="ssh", target=target, port=str(port), username=username,
                success=False, authenticated=False, operation=command,
                response_summary="", error_category=CredentialErrorCategory.auth_rejected.value,
                error_detail="ssh authentication rejected",
                duration_seconds=time.monotonic() - start, timed_out=False, executor="ssh",
            )
        except socket.timeout:
            return CredentialValidationResult(
                protocol="ssh", target=target, port=str(port), username=username,
                success=False, authenticated=False, operation=command,
                response_summary="", error_category=CredentialErrorCategory.connect_timeout.value,
                error_detail="ssh connect/auth timed out",
                duration_seconds=time.monotonic() - start, timed_out=True, executor="ssh",
            )
        except (OSError, paramiko.SSHException) as exc:
            return CredentialValidationResult(
                protocol="ssh", target=target, port=str(port), username=username,
                success=False, authenticated=False, operation=command,
                response_summary="", error_category=CredentialErrorCategory.connection_failed.value,
                error_detail=f"ssh connection failed: {type(exc).__name__}",
                duration_seconds=time.monotonic() - start, timed_out=False, executor="ssh",
            )

        # Authenticated — run exactly one harmless, fixed validation command.
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=command_timeout)
            out_bytes = stdout.read(_MAX_OUTPUT_BYTES)
            err_bytes = stderr.read(_MAX_OUTPUT_BYTES)
            exit_status = stdout.channel.recv_exit_status()
        except socket.timeout:
            return CredentialValidationResult(
                protocol="ssh", target=target, port=str(port), username=username,
                success=False, authenticated=True, operation=command,
                response_summary="", error_category=CredentialErrorCategory.command_timeout.value,
                error_detail="ssh validation command timed out",
                duration_seconds=time.monotonic() - start, timed_out=True, executor="ssh",
            )
        except paramiko.SSHException as exc:
            return CredentialValidationResult(
                protocol="ssh", target=target, port=str(port), username=username,
                success=False, authenticated=True, operation=command,
                response_summary="", error_category=CredentialErrorCategory.protocol_error.value,
                error_detail=f"ssh protocol error running validation command: {type(exc).__name__}",
                duration_seconds=time.monotonic() - start, timed_out=False, executor="ssh",
            )

        out_text = out_bytes.decode("utf-8", errors="replace").strip()
        err_text = err_bytes.decode("utf-8", errors="replace").strip()
        if exit_status != 0:
            return CredentialValidationResult(
                protocol="ssh", target=target, port=str(port), username=username,
                success=False, authenticated=True, operation=command,
                response_summary=(out_text or err_text)[:_MAX_OUTPUT_BYTES],
                error_category=CredentialErrorCategory.command_failed.value,
                error_detail=f"ssh validation command exited {exit_status}",
                duration_seconds=time.monotonic() - start, timed_out=False, executor="ssh",
            )

        return CredentialValidationResult(
            protocol="ssh", target=target, port=str(port), username=username,
            success=True, authenticated=True, operation=command,
            response_summary=out_text[:_MAX_OUTPUT_BYTES],
            error_category=CredentialErrorCategory.success.value, error_detail="",
            duration_seconds=time.monotonic() - start, timed_out=False, executor="ssh",
        )
    finally:
        client.close()
