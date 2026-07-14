# backend.py
# ToolBackend protocol and its three implementations (dry-run, local, remote-contract-only) — see docs/tool-execution-architecture.md.
"""Replaceable tool-execution backend abstraction (Infra Phase 2).

This module formalizes, as an explicit ``typing.Protocol``, a seam that
already existed implicitly in ``apex_host.execution.dispatcher.TaskDispatcher``
(the ``run_command_fn`` constructor parameter). It does not change how
``TaskDispatcher`` is wired by default — see ``docs/tool-execution-architecture.md``
for the full rationale and the phase-by-phase plan that adopts this
abstraction more deeply.

Three implementations:

- ``DryRunToolBackend`` — never executes a process; returns a deterministic
  synthetic result. Safe to use unconditionally.
- ``LocalToolBackend`` — the existing trusted local-subprocess pathway.
  Delegates to ``apex_host.tools.runner.run_command``, which still honors
  ``ApexConfig.dry_run`` internally as the primary safety switch (defense in
  depth: even if backend selection is misconfigured, dry-run mode cannot be
  bypassed).
- ``RemoteToolBackend`` — contract only in this phase. Constructing it is
  safe; calling ``execute()`` always raises ``NotImplementedError``. No
  network transport is implemented here.

All three call ``apex_host.tools.safety.check_command`` before doing
anything else, exactly as ``run_command`` does today — the safety gate is
never bypassed regardless of which backend is selected.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Awaitable, Callable, Protocol, runtime_checkable

from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand, ToolResult

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

# ToolBackend.execute() returns a ToolResult. The architecture-document
# pseudocode calls this ``ToolExecutionResult`` — this alias documents that
# mapping without introducing a duplicate parallel model (CLAUDE.md-style
# "prefer existing models" discipline).
ToolExecutionResult = ToolResult

VALID_TOOL_BACKENDS: frozenset[str] = frozenset({"dry-run", "local", "remote"})


@runtime_checkable
class ToolBackend(Protocol):
    """Protocol for a replaceable tool-execution backend.

    Every implementation must:
    - accept an executable/tool name and an argument *list* (never a raw
      shell string);
    - accept an optional timeout and an optional stdin payload;
    - return a structured ``ToolResult`` (never raise for an *ordinary*
      command failure — non-zero exit codes are represented in the result,
      not as exceptions);
    - call ``apex_host.tools.safety.check_command`` (directly or indirectly)
      before taking any action, and let ``ValueError`` propagate when the
      safety gate rejects the command — this is the one exception type
      backends are expected to raise, and callers (``TaskDispatcher``)
      already handle it.
    """

    name: str

    async def execute(
        self,
        tool: str,
        arguments: list[str],
        *,
        timeout_seconds: float | None = None,
        stdin: str | None = None,
    ) -> ToolExecutionResult: ...


class DryRunToolBackend:
    """Never executes a process. Deterministic, synthetic, offline.

    Compatible with the dry-run branch of ``apex_host.tools.runner.run_command``
    (same stdout message shape, returncode, dry_run flag) but implemented
    independently so that selecting this backend is an unconditional
    guarantee — it does not depend on, and cannot be defeated by, any other
    configuration value. It must never contact a remote service.
    """

    name = "dry-run"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    async def execute(
        self,
        tool: str,
        arguments: list[str],
        *,
        timeout_seconds: float | None = None,
        stdin: str | None = None,
    ) -> ToolExecutionResult:
        cmd = ToolCommand(
            tool=tool,
            args=list(arguments),
            timeout_seconds=int(timeout_seconds or self._config.max_command_seconds),
            stdin=stdin,
        )
        # Safety gate applies even though nothing will actually run — a
        # dry-run backend that "approves" a disallowed/destructive command
        # would be a silent regression versus today's run_command behavior.
        check_command(cmd, self._config)
        logger.info("dry-run backend: %s %s", tool, " ".join(arguments))
        return ToolResult(
            command=cmd,
            stdout=f"[dry-run] would execute: {tool} {' '.join(arguments)}",
            stderr="",
            returncode=0,
            duration_seconds=0.0,
            dry_run=True,
            backend="dry-run",
        )


class LocalToolBackend:
    """The existing trusted local-subprocess pathway, wrapped as a ``ToolBackend``.

    Delegates entirely to ``apex_host.tools.runner.run_command`` — no
    subprocess logic is duplicated here. This means the Phase 7 hardening in
    ``runner.py`` (SIGTERM-then-SIGKILL on timeout, cancellation cleanup,
    PATH check, argv-list-only child-process invocation via the stdlib
    asyncio subprocess API) applies unchanged, and ``ApexConfig.dry_run`` is
    still honored as the primary safety switch even when this backend is
    explicitly selected.

    Does not become the default execution path for any containerized /
    production deployment unless a later phase's backend-selection wiring
    explicitly configures it — this class by itself does not change how
    ``TaskDispatcher`` is constructed today.
    """

    name = "local"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    async def execute(
        self,
        tool: str,
        arguments: list[str],
        *,
        timeout_seconds: float | None = None,
        stdin: str | None = None,
    ) -> ToolExecutionResult:
        if stdin is not None:
            # Deferred wiring: runner.py's subprocess call does not yet pipe
            # stdin. Raising here is safer than silently dropping the
            # caller's input. See docs/tool-execution-architecture.md
            # ("Open risks and deferred questions").
            raise NotImplementedError(
                "LocalToolBackend does not yet support stdin piping; "
                "apex_host/tools/runner.py's subprocess invocation has no "
                "stdin wiring in this phase."
            )
        from apex_host.tools.runner import run_command

        cmd = ToolCommand(
            tool=tool,
            args=list(arguments),
            timeout_seconds=int(timeout_seconds or self._config.max_command_seconds),
        )
        return await run_command(cmd, self._config)


class RemoteToolBackend:
    """Contract-only stub for a restricted Kali tool-execution service.

    Constructing this class is always safe (pure data holder, no I/O).
    Calling ``execute()`` always raises ``NotImplementedError`` — the HTTP
    transport, request/response contract, and server-side allowlisting are
    specified in ``docs/tool-execution-architecture.md`` for a later phase to
    implement. This class exists so callers can already depend on a stable
    import path and constructor shape ahead of that work.
    """

    name = "remote"

    def __init__(
        self,
        *,
        service_url: str | None,
        token: str = "",
        timeout_seconds: float = 120.0,
    ) -> None:
        if not service_url:
            raise ValueError(
                "RemoteToolBackend requires a non-empty service_url "
                "(ApexConfig.tool_service_url)"
            )
        self._service_url = service_url
        self._token = token
        self._timeout_seconds = timeout_seconds

    async def execute(
        self,
        tool: str,
        arguments: list[str],
        *,
        timeout_seconds: float | None = None,
        stdin: str | None = None,
    ) -> ToolExecutionResult:
        raise NotImplementedError(
            "RemoteToolBackend network transport is not implemented. "
            "See docs/tool-execution-architecture.md for the request/response "
            "contract a later phase will implement against a restricted "
            "Kali tool service at "
            f"{self._service_url!r}."
        )


def select_tool_backend(config: "ApexConfig") -> ToolBackend:
    """Construct the ``ToolBackend`` named by ``config.tool_backend``.

    Raises ``ValueError`` for any value outside ``VALID_TOOL_BACKENDS`` —
    fails loudly rather than silently falling back to a default, since a
    typo here is a configuration bug, not a recoverable condition.
    """
    name = config.tool_backend
    if name == "dry-run":
        return DryRunToolBackend(config)
    if name == "local":
        return LocalToolBackend(config)
    if name == "remote":
        return RemoteToolBackend(
            service_url=config.tool_service_url,
            token=config.tool_service_token,
            timeout_seconds=config.tool_service_timeout_seconds,
        )
    raise ValueError(
        f"invalid ApexConfig.tool_backend {name!r}; must be one of "
        f"{sorted(VALID_TOOL_BACKENDS)}"
    )


def to_run_command_fn(
    backend: ToolBackend,
) -> Callable[[ToolCommand, "ApexConfig"], Awaitable[ToolResult]]:
    """Adapt a ``ToolBackend`` to the ``run_command_fn`` shape ``TaskDispatcher`` expects.

    This is the concrete seam ``build_apex_graph(tool_backend=...)`` uses to
    let a caller substitute any ``ToolBackend`` for the default
    ``apex_host.tools.runner.run_command`` without changing
    ``TaskDispatcher`` itself.
    """

    async def _run(cmd: ToolCommand, _config: "ApexConfig") -> ToolResult:
        return await backend.execute(
            cmd.tool, cmd.args, timeout_seconds=float(cmd.timeout_seconds), stdin=cmd.stdin
        )

    return _run
