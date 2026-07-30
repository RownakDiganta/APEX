# telnet_executor.py
# Performs a bounded authorized telnet login validation using configured credentials.
"""Bounded telnet login executor. Implements memfabric Executor protocol.

Safety invariants:
- Dry-run (config.dry_run=True, the default): returns a synthetic result
  immediately with no network activity whatsoever.
- Stateless across calls: no connection handle is held on self.
- One attempt only: no credential looping, no brute force.
- Uses asyncio (via apex_host.agents.telnet_transport), never subprocess or
  shell=True.
- Credentials must come from explicit operator config (task.params), never
  guessed by this executor.
- Live session stdout is NEVER stored in episode.data — only a
  [session_redacted] placeholder is kept (P8-S03), plus a short, redacted,
  secret-free proof snippet (the harmless ``id`` output) as
  ``response_summary`` — mirroring SSHExecutor's own structured result.

Structured-result upgrade: this executor now emits the SAME structured
episode-data shape as SSHExecutor/FTPExecutor (``protocol``/``success``/
``authenticated``/``error_category``/``response_summary``/...), so a
telnet login flows through ``_credential_result_to_tr`` and
``AccessParser.parse_structured`` exactly like SSH/FTP. This fixes the
prior behavior where a live telnet success could never create an
``access_state`` (the raw session was redacted to ``[session_redacted]``
and the downstream text heuristic then found no shell prompt), and it
handles passwordless-root shells (see ``telnet_transport``).
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from memfabric.types import Episode, EvidenceBundle, ExecutorResult, Outcome, TaskSpec
from apex_host.agents.telnet_transport import TelnetSessionResult, telnet_session
from apex_host.security.redaction import SESSION_REDACTED_PLACEHOLDER, redact_session_text
from apex_host.types import CredentialErrorCategory

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

#: Fixed, harmless validation command run once after a shell is reached, to
#: confirm the access level. Never task/LLM-controlled.
_VALIDATION_COMMAND = "id"


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

        read_timeout = float(getattr(self._config, "telnet_read_timeout_seconds", 10.0))
        max_seconds = float(self._config.max_command_seconds)
        login_timeout = float(min(self._config.max_command_seconds, 15))
        max_bytes = int(getattr(self._config, "user_flag_max_output_bytes", 4096) or 4096)

        start = time.monotonic()
        session = await telnet_session(
            target=target, port=port, username=username, password=password,
            command=_VALIDATION_COMMAND,
            login_timeout=login_timeout, read_timeout=read_timeout,
            max_seconds=max_seconds, max_bytes=max_bytes,
        )
        duration = time.monotonic() - start

        success = session.authenticated
        error_category, error_detail = self._classify(session)
        response_summary = ""
        if success:
            response_summary = redact_session_text(
                session.command_output[:200], passwords=[password] if password else []
            )
        outcome = Outcome.success if success else Outcome.fundamental
        logger.info(
            "telnet %s:%s user=%r outcome=%s category=%s",
            target, port_str, username, outcome.value, error_category,
        )
        episode = Episode(
            agent="apex.credential",
            action=f"telnet {target}:{port_str} user={username}",
            outcome=outcome,
            data={
                "protocol": "telnet",
                "target": target,
                "port": port_str,
                "username": username,
                "success": success,
                "authenticated": session.authenticated,
                "operation": _VALIDATION_COMMAND,
                "response_summary": response_summary,
                "error_category": error_category,
                "error_detail": error_detail,
                "duration_seconds": duration,
                "timed_out": False,
                "executor": "telnet",
                # P8-S03: never store the raw session transcript.
                "stdout": SESSION_REDACTED_PLACEHOLDER,
                "shell_found": session.authenticated,
                "dry_run": False,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)

    @staticmethod
    def _classify(session: TelnetSessionResult) -> tuple[str, str]:
        if session.authenticated:
            return CredentialErrorCategory.success.value, ""
        detail = session.error or "login failed"
        if not session.connected:
            return CredentialErrorCategory.connection_failed.value, detail
        if "rejected" in detail.lower() or "incorrect" in detail.lower():
            return CredentialErrorCategory.auth_rejected.value, detail
        return CredentialErrorCategory.protocol_error.value, detail

    def _dry_run_result(
        self, task: TaskSpec, target: str, port: str, username: str
    ) -> ExecutorResult:
        # Synthetic success so the dry-run engagement verifies the full
        # credential -> objective routing path (mirrors SSHExecutor's dry-run).
        episode = Episode(
            agent="apex.credential",
            action=f"telnet {target}:{port} user={username} (dry-run)",
            outcome=Outcome.success,
            data={
                "protocol": "telnet",
                "target": target,
                "port": port,
                "username": username,
                "success": True,
                "authenticated": True,
                "operation": _VALIDATION_COMMAND,
                "response_summary": "[dry-run: synthetic shell]",
                "error_category": CredentialErrorCategory.success.value,
                "error_detail": "",
                "duration_seconds": 0.0,
                "timed_out": False,
                "executor": "telnet",
                # Dry-run has no real session, so nothing to redact here — a
                # descriptive synthetic stdout is safe and keeps the dry-run
                # self-explanatory (the live path redacts stdout, above).
                "stdout": f"[dry-run] would telnet {target}:{port} as {username} — no connection made",
                "shell_found": True,
                "dry_run": True,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)
