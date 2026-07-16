# ftp_executor.py
# Performs a bounded, one-attempt authorized FTP login validation using explicit, operator-supplied credentials.
"""Bounded FTP login-validation executor. Implements memfabric Executor protocol.

Mirrors ``apex_host/agents/telnet_executor.py``'s and ``ssh_executor.py``'s
safety model, adapted for FTP via the standard-library ``ftplib`` — no new
third-party dependency was needed (docs/credential-validation.md
"Current limitations" records this decision).

Safety properties enforced by construction (not configuration):
- Dry-run (config.dry_run=True, the default): returns a synthetic result
  immediately with no network activity whatsoever.
- Stateless across calls: no ``ftplib.FTP`` instance is held on self.
- Exactly one ``login()`` call — no credential looping, no brute force.
- Passive mode is used (``ftplib.FTP``'s own default since Python 3 — this
  module also calls ``set_pasv(True)`` explicitly so the choice is visible
  in code and does not silently depend on the stdlib default never
  changing), so no server-directed "PORT" callback to an arbitrary
  operator-chosen address is ever issued.
- After a successful login, exactly one harmless, read-only operation is
  run (``PWD`` by default, or ``NOOP``) — never ``LIST`` (would recurse an
  arbitrary directory tree), never ``RETR``/``STOR``/``DELE``/``MKD``/
  ``RMD``/``RNFR``/``RNTO`` (file transfer, deletion, or mutation). This
  module contains no calls to any of those methods at all — see
  ``_ALLOWED_VALIDATION_OPERATIONS`` and the security-invariant tests in
  ``tests/apex_host/test_credential_validation_security.py``.
- The connection is always closed (``QUIT`` on the clean path, socket
  ``close()`` in the ``finally`` block otherwise) — no persistent session.
- The password is never logged, stored, or included in any exception
  message raised by this module.
"""
from __future__ import annotations

import asyncio
import ftplib
import logging
import socket
import time
from typing import TYPE_CHECKING

from memfabric.types import Episode, EvidenceBundle, ExecutorResult, Outcome, TaskSpec
from apex_host.security.redaction import redact_session_text
from apex_host.types import CredentialErrorCategory, CredentialValidationResult

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

#: Default harmless validation operation — never changed to anything
#: destructive or recursive.
DEFAULT_VALIDATION_OPERATION: str = "PWD"

#: The only operations this executor will ever run after a successful login.
_ALLOWED_VALIDATION_OPERATIONS: frozenset[str] = frozenset({"PWD", "NOOP"})

#: Bounded response size — mirrors TelnetExecutor's _READ_BYTES /
#: SSHExecutor's _MAX_OUTPUT_BYTES.
_MAX_RESPONSE_BYTES: int = 4096


class FTPExecutor:
    """Stateless executor: one bounded FTP login validation per run() call."""

    domain: str = "credential"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        params = task.params
        target = str(params.get("target", ""))
        port_str = str(params.get("port", "21"))
        username = str(params.get("username", ""))
        password = str(params.get("password", ""))
        operation = str(params.get("operation") or DEFAULT_VALIDATION_OPERATION).upper()
        if operation not in _ALLOWED_VALIDATION_OPERATIONS:
            operation = DEFAULT_VALIDATION_OPERATION

        if self._config.dry_run:
            return self._dry_run_result(task, target, port_str, username, operation)

        try:
            port = int(port_str)
        except ValueError:
            port = 21

        connect_timeout = float(getattr(self._config, "ftp_connect_timeout_seconds", 10.0))
        login_timeout = float(getattr(self._config, "ftp_login_timeout_seconds", 10.0))
        command_timeout = float(getattr(self._config, "ftp_command_timeout_seconds", 10.0))
        overall_timeout = connect_timeout + login_timeout + command_timeout + 5.0

        start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    _attempt_ftp_sync,
                    target, port, username, password, operation,
                    connect_timeout, login_timeout, command_timeout,
                ),
                timeout=overall_timeout,
            )
        except asyncio.TimeoutError:
            result = CredentialValidationResult(
                protocol="ftp", target=target, port=port_str, username=username,
                success=False, authenticated=False, operation=operation,
                response_summary="", error_category=CredentialErrorCategory.connect_timeout.value,
                error_detail="ftp validation exceeded the overall bounded timeout",
                duration_seconds=time.monotonic() - start, timed_out=True, executor="ftp",
            )

        outcome = Outcome.success if result.success else Outcome.fundamental
        logger.info(
            "ftp %s:%s user=%r outcome=%s category=%s",
            target, port_str, username, outcome.value, result.error_category,
        )
        episode = Episode(
            agent="apex.credential",
            action=f"ftp {target}:{port_str} user={username} op={operation}",
            outcome=outcome,
            data={
                "protocol": "ftp",
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
                "executor": "ftp",
                "dry_run": False,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)

    def _dry_run_result(
        self, task: TaskSpec, target: str, port: str, username: str, operation: str
    ) -> ExecutorResult:
        response_summary = '"/" is the current directory' if operation == "PWD" else "200 NOOP ok"
        episode = Episode(
            agent="apex.credential",
            action=f"ftp {target}:{port} user={username} op={operation} (dry-run)",
            outcome=Outcome.success,
            data={
                "protocol": "ftp",
                "target": target,
                "port": port,
                "username": username,
                "success": True,
                "authenticated": True,
                "operation": operation,
                "response_summary": response_summary,
                "error_category": CredentialErrorCategory.success.value,
                "error_detail": "",
                "duration_seconds": 0.0,
                "timed_out": False,
                "executor": "ftp",
                "dry_run": True,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)


def _attempt_ftp_sync(
    target: str,
    port: int,
    username: str,
    password: str,
    operation: str,
    connect_timeout: float,
    login_timeout: float,
    command_timeout: float,
) -> CredentialValidationResult:
    """Synchronous ftplib session — run via ``asyncio.to_thread`` only.

    Performs exactly one ``connect()`` + ``login()`` (one authentication
    attempt) and, on success, exactly one harmless operation (``PWD`` or
    ``NOOP``). The connection is always closed. Never raises — every
    ftplib/socket exception is caught here and converted into a
    ``CredentialValidationResult``. Never returns or logs the password.
    """
    start = time.monotonic()
    ftp = ftplib.FTP()  # noqa: S321 — deliberate: passive mode, one bounded op, never plaintext-transfers a secret
    ftp.encoding = "utf-8"
    try:
        try:
            ftp.connect(host=target, port=port, timeout=connect_timeout)
        except socket.timeout:
            return CredentialValidationResult(
                protocol="ftp", target=target, port=str(port), username=username,
                success=False, authenticated=False, operation=operation,
                response_summary="", error_category=CredentialErrorCategory.connect_timeout.value,
                error_detail="ftp connect timed out",
                duration_seconds=time.monotonic() - start, timed_out=True, executor="ftp",
            )
        except OSError as exc:
            return CredentialValidationResult(
                protocol="ftp", target=target, port=str(port), username=username,
                success=False, authenticated=False, operation=operation,
                response_summary="", error_category=CredentialErrorCategory.connection_failed.value,
                error_detail=f"ftp connection failed: {type(exc).__name__}",
                duration_seconds=time.monotonic() - start, timed_out=False, executor="ftp",
            )

        # Passive mode explicitly, even though it is ftplib's own default —
        # never active-mode (which would direct the server to open a
        # connection back to an operator-chosen PORT address).
        ftp.set_pasv(True)
        if ftp.sock is not None:
            ftp.sock.settimeout(login_timeout)

        try:
            ftp.login(user=username, passwd=password)
        except ftplib.error_perm as exc:
            # P8-S06: the server's own response text is included for
            # diagnostics, but it is untrusted content — route it through
            # the sole redaction function before it ever leaves this
            # function, in case a server response happens to echo back the
            # submitted password (defense in depth; no normal FTP server
            # does this, but the redaction is unconditional and cheap).
            safe_detail = redact_session_text(str(exc)[:200], passwords=[password])
            return CredentialValidationResult(
                protocol="ftp", target=target, port=str(port), username=username,
                success=False, authenticated=False, operation=operation,
                response_summary="", error_category=CredentialErrorCategory.auth_rejected.value,
                error_detail=f"ftp login rejected: {safe_detail}",
                duration_seconds=time.monotonic() - start, timed_out=False, executor="ftp",
            )
        except socket.timeout:
            return CredentialValidationResult(
                protocol="ftp", target=target, port=str(port), username=username,
                success=False, authenticated=False, operation=operation,
                response_summary="", error_category=CredentialErrorCategory.auth_timeout.value,
                error_detail="ftp login timed out",
                duration_seconds=time.monotonic() - start, timed_out=True, executor="ftp",
            )
        except (ftplib.error_temp, ftplib.error_proto, ftplib.Error, EOFError, OSError) as exc:
            return CredentialValidationResult(
                protocol="ftp", target=target, port=str(port), username=username,
                success=False, authenticated=False, operation=operation,
                response_summary="", error_category=CredentialErrorCategory.protocol_error.value,
                error_detail=f"ftp login protocol error: {type(exc).__name__}",
                duration_seconds=time.monotonic() - start, timed_out=False, executor="ftp",
            )

        # Authenticated — run exactly one harmless, fixed validation operation.
        if ftp.sock is not None:
            ftp.sock.settimeout(command_timeout)
        try:
            if operation == "NOOP":
                response = ftp.voidcmd("NOOP")
            else:
                response = ftp.pwd()
        except socket.timeout:
            return CredentialValidationResult(
                protocol="ftp", target=target, port=str(port), username=username,
                success=False, authenticated=True, operation=operation,
                response_summary="", error_category=CredentialErrorCategory.command_timeout.value,
                error_detail="ftp validation operation timed out",
                duration_seconds=time.monotonic() - start, timed_out=True, executor="ftp",
            )
        except (ftplib.Error, EOFError, OSError) as exc:
            return CredentialValidationResult(
                protocol="ftp", target=target, port=str(port), username=username,
                success=False, authenticated=True, operation=operation,
                response_summary="", error_category=CredentialErrorCategory.command_failed.value,
                error_detail=f"ftp validation operation failed: {type(exc).__name__}",
                duration_seconds=time.monotonic() - start, timed_out=False, executor="ftp",
            )

        return CredentialValidationResult(
            protocol="ftp", target=target, port=str(port), username=username,
            success=True, authenticated=True, operation=operation,
            response_summary=str(response)[:_MAX_RESPONSE_BYTES],
            error_category=CredentialErrorCategory.success.value, error_detail="",
            duration_seconds=time.monotonic() - start, timed_out=False, executor="ftp",
        )
    finally:
        try:
            ftp.quit()
        except (ftplib.Error, OSError, EOFError):
            try:
                ftp.close()
            except OSError:
                pass
