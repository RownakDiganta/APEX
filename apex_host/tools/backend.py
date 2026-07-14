# backend.py
# ToolBackend protocol and its three implementations (dry-run, local, remote) — see docs/tool-execution-architecture.md.
"""Replaceable tool-execution backend abstraction (Infra Phase 2; Infra
Phase 4 completed the ``RemoteToolBackend`` transport).

This module formalizes, as an explicit ``typing.Protocol``, a seam that
already existed implicitly in ``apex_host.execution.dispatcher.TaskDispatcher``
(the ``run_command_fn`` constructor parameter). See
``docs/tool-execution-architecture.md`` for the full rationale and
``docs/remote-tool-backend.md`` for the Infra Phase 4 client implementation
detail.

Three implementations:

- ``DryRunToolBackend`` — never executes a process; returns a deterministic
  synthetic result. Safe to use unconditionally.
- ``LocalToolBackend`` — the existing trusted local-subprocess pathway.
  Delegates to ``apex_host.tools.runner.run_command``, which still honors
  ``ApexConfig.dry_run`` internally as the primary safety switch (defense in
  depth: even if backend selection is misconfigured, dry-run mode cannot be
  bypassed).
- ``RemoteToolBackend`` (``apex_host/tools/remote_backend.py`` — re-exported
  here for backward compatibility with existing imports) — a real
  asynchronous HTTP client for a Phase 3 ``apex_tool_service`` instance.
  Also defense-in-depth-safe against ``dry_run=True``.

All three call ``apex_host.tools.safety.check_command`` before doing
anything else, exactly as ``run_command`` does today — the safety gate is
never bypassed regardless of which backend is selected.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Awaitable, Callable, Protocol, runtime_checkable

from apex_host.tools.remote_backend import RemoteToolBackend
from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand, ToolResult

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

__all__ = [
    "ToolBackend",
    "ToolExecutionResult",
    "DryRunToolBackend",
    "LocalToolBackend",
    "RemoteToolBackend",
    "VALID_TOOL_BACKENDS",
    "select_tool_backend",
    "select_runtime_backend",
    "to_run_command_fn",
]

# ToolBackend.execute() returns a ToolResult. The architecture-document
# pseudocode calls this ``ToolExecutionResult`` — this alias documents that
# mapping without introducing a duplicate parallel model (CLAUDE.md-style
# "prefer existing models" discipline).
ToolExecutionResult = ToolResult

VALID_TOOL_BACKENDS: frozenset[str] = frozenset({"dry-run", "local", "remote"})


def _normalize_backend_name(name: str) -> str:
    """Case/whitespace-normalize a ``tool_backend`` value for comparison.

    ``config.tool_backend`` itself is never mutated — normalization happens
    only at the point of interpretation, so ``" Remote "``, ``"REMOTE"``,
    and ``"remote"`` all select the same backend.
    """
    return name.strip().lower()


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


def select_tool_backend(config: "ApexConfig") -> ToolBackend:
    """Construct the ``ToolBackend`` named by ``config.tool_backend``.

    ``config.tool_backend`` is normalized (case/whitespace) before matching,
    but the field on ``config`` itself is left untouched. Raises
    ``ValueError`` for any value outside ``VALID_TOOL_BACKENDS`` — fails
    loudly rather than silently falling back to a default, since a typo
    here is a configuration bug, not a recoverable condition.

    This function does **not** apply the ``dry_run``-overrides-``remote``/
    ``local`` invariant — it returns exactly the backend named by
    ``config.tool_backend``, nothing else. Use ``select_runtime_backend()``
    for the safety-aware selection used by the actual engagement runtime
    (``apex_host/runtime.py``, ``apex_host/orchestration/builder.py``).
    """
    name = _normalize_backend_name(config.tool_backend)
    if name == "dry-run":
        return DryRunToolBackend(config)
    if name == "local":
        return LocalToolBackend(config)
    if name == "remote":
        return RemoteToolBackend(config)
    raise ValueError(
        f"invalid ApexConfig.tool_backend {config.tool_backend!r}; must be one of "
        f"{sorted(VALID_TOOL_BACKENDS)} (case/whitespace-insensitive)"
    )


def select_runtime_backend(config: "ApexConfig") -> ToolBackend:
    """The safety-aware backend selector used by the real engagement runtime.

    Binding invariant (docs/tool-execution-architecture.md;
    docs/remote-tool-backend.md): **when ``config.dry_run`` is ``True``,
    execution always uses ``DryRunToolBackend``, regardless of
    ``config.tool_backend``.** ``dry_run=True`` must never be able to reach
    ``RemoteToolBackend`` — not even indirectly through a misconfigured
    ``tool_backend="remote"``. This is the single, centralized place that
    invariant is enforced for the default (no explicit backend injected)
    construction path; ``RemoteToolBackend.execute()`` also enforces it a
    second time internally (defense in depth — see its docstring), so even
    a caller that bypasses this function and constructs
    ``RemoteToolBackend`` directly still cannot contact the network while
    ``dry_run=True``.

    When ``config.dry_run`` is ``False``, delegates to ``select_tool_backend()``
    — the configured ``local`` or ``remote`` backend is used exactly as
    named. An explicitly inconsistent configuration (e.g.
    ``tool_backend="remote"`` with no ``tool_service_url``) fails clearly
    via ``RemoteToolBackend.__init__``'s own ``ValueError``, the moment this
    function is called — never silently normalized to something else.
    """
    if config.dry_run:
        return DryRunToolBackend(config)
    return select_tool_backend(config)


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
