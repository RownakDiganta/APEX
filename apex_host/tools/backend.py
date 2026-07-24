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

from apex_host.runtime_registry import BoundedReadResult
from apex_host.tools.remote_backend import RemoteToolBackend
from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand, ToolResult

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

__all__ = [
    "ToolBackend",
    "ToolExecutionResult",
    "BoundedFileReadBackend",
    "DryRunToolBackend",
    "LocalToolBackend",
    "RemoteToolBackend",
    "VALID_TOOL_BACKENDS",
    "backend_supports_raw_sockets",
    "backend_capability_mode",
    "CAPABILITY_MODE_RAW_SOCKET",
    "CAPABILITY_MODE_TCP_CONNECT",
    "select_tool_backend",
    "select_runtime_backend",
    "to_run_command_fn",
]

#: Phase 22 — the one fixed executable a ``read_bounded_file()``
#: implementation backed by a generic ``execute()`` call may ever request.
#: Never operator/task-controlled — see ``_execute_bounded_read_via_cat``.
_BOUNDED_READ_TOOL = "cat"

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


@runtime_checkable
class BoundedFileReadBackend(Protocol):
    """Narrow, OPTIONAL capability seam (Phase 21/22) for a backend that can
    perform one dedicated, structured bounded-file-read operation — never a
    generalization of ``ToolBackend.execute()``'s broader "run any
    allowlisted tool" capability.

    Deliberately a SEPARATE Protocol from ``ToolBackend``, not an addition
    to it: not every ``ToolBackend`` needs to implement this (a backend that
    only ever runs `nmap`/`curl`-style recon tools has no reason to grow a
    file-read method), and forcing every backend to implement unsafe or
    irrelevant behavior would violate the "narrow protocol, only what's
    needed" discipline this codebase follows elsewhere (e.g.
    ``BoundedCommandReadStrategy`` in ``apex_host/runtime_registry.py``).

    Callers must check support via ``isinstance(backend,
    BoundedFileReadBackend)`` — a real, checked capability test (this
    Protocol is ``@runtime_checkable``), never blind duck-typing (e.g.
    ``hasattr(backend, "read_bounded_file")`` alone, which would also match
    an unrelated object that happens to define a same-named method with a
    different contract).

    ``target`` exists so a remote implementation (``RemoteToolBackend``) can
    bind the read to an authorized-target check on the SERVER side —
    local/dry-run implementations accept it for interface parity but do not
    need to use it (there is no remote target-authorization concern for a
    read that happens on the same machine already running this process).
    """

    async def read_bounded_file(
        self, target: str, path: str, *, timeout_seconds: float, max_output_bytes: int,
    ) -> BoundedReadResult: ...


def _execute_result_to_bounded_read(result: ToolResult) -> BoundedReadResult:
    """Map a generic ``ToolResult`` (from an ``execute("cat", ["--", path])``
    call) onto a ``BoundedReadResult`` — shared by ``DryRunToolBackend`` and
    ``LocalToolBackend``'s own ``read_bounded_file()`` implementations.
    Identical mapping logic to what ``apex_host.runtime_registry
    .ToolBackendCommandReadStrategy`` used to perform itself before Phase 22
    moved "construct the fixed cat -- path invocation" down into each
    backend's own dedicated method.
    """
    success = result.returncode == 0 and not result.timed_out
    output = result.stdout if success else ""
    error: str | None = None
    if result.timed_out:
        error = "timeout: bounded command read timed out"
    elif not success:
        error = (result.error or result.stderr or "non-zero exit")[:200]
    return BoundedReadResult(
        connected=not result.timed_out,
        output=output,
        error=error,
        return_code=result.returncode,
        bytes_received=len(output.encode("utf-8", errors="replace")),
        truncated=False,
        method=f"cmd_{result.backend or 'local'}",
    )


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

    async def read_bounded_file(
        self, target: str, path: str, *, timeout_seconds: float, max_output_bytes: int,
    ) -> BoundedReadResult:
        """Never performs a real read — returns a deterministic, synthetic,
        never-executed result unconditionally (satisfies
        ``BoundedFileReadBackend`` for interface parity with the other
        backends).

        Deliberately does NOT delegate to ``self.execute()`` (unlike
        ``LocalToolBackend.read_bounded_file()``): ``execute()`` still runs
        ``check_command()`` even in dry-run (so a disallowed/destructive
        *generic* command is still flagged as a configuration problem), but
        a bounded file read has no equivalent "was this approved" concern —
        the operation's shape is fixed and safe regardless of
        ``ApexConfig.allowed_tools``. This backend's entire purpose is to be
        an unconditional safe backstop (docs/remote-tool-backend.md §4) —
        making it depend on an unrelated tool-allowlist entry would
        undermine that guarantee for an operator who only ever configured
        the ``remote_command``/``web_command`` capability path (which never
        needs local ``cat`` allowlisting at all).
        """
        logger.info("dry-run backend: bounded file read of an approved candidate path")
        return BoundedReadResult(
            connected=True,
            output="[dry-run] would read bounded candidate path",
            error=None,
            return_code=0,
            bytes_received=0,
            truncated=False,
            method="dry-run",
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

    async def read_bounded_file(
        self, target: str, path: str, *, timeout_seconds: float, max_output_bytes: int,
    ) -> BoundedReadResult:
        """Local execution reuses the existing trusted ``execute()`` path
        (``cat -- <path>``, a fixed, non-caller-controlled argv) — this is
        the operator's own machine, not a shared multi-tenant service, so
        the "do not add unrestricted cat to a shared allowlist" concern
        that motivates ``RemoteToolBackend``'s dedicated endpoint does not
        apply here. ``cat`` must still be present in
        ``ApexConfig.allowed_tools`` (an optional, not-default tool — see
        ``apex_host/tools/registry.py``) or ``check_command`` rejects it,
        which this method maps to a bounded, sanitized error rather than
        letting the exception escape.
        """
        try:
            result = await self.execute(_BOUNDED_READ_TOOL, ["--", path], timeout_seconds=timeout_seconds)
        except ValueError as exc:
            return BoundedReadResult(
                connected=False, output="", error=f"execution_context_unavailable: {type(exc).__name__}",
            )
        return _execute_result_to_bounded_read(result)


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


def backend_supports_raw_sockets(config: "ApexConfig") -> bool:
    """Capability seam: does the tool-execution backend named by
    ``config.tool_backend`` have the OS privilege (``CAP_NET_RAW``, or
    running as root) required for nmap's default SYN-scan (``-sS``, the
    implicit default of plain ``-sV``) or other raw-socket scan modes?

    This is the single, named source of truth planners consult before
    choosing an nmap scan mode — never a scattered
    ``if config.tool_backend == "remote"`` check inline in planner logic
    (per the explicit "derive scan mode from backend capabilities rather
    than scattering backend-name checks" requirement this function exists
    to satisfy).

    ``config.tool_backend_raw_socket_capable`` (an explicit tri-state
    override — ``None`` is "derive automatically") always wins when set,
    for the rare case an operator knows their specific deployment differs
    from the default assumption below (e.g. a remote backend granted
    ``NET_RAW``, or a sandboxed local backend that is *not* root).

    Default assumption when no override is set: the Kali tool-service
    container (``tool_backend="remote"``) is documented
    (``docs/kali-container.md`` §5/§14) to run its restricted service as a
    non-root user with zero added Linux capabilities — verified empirically
    to lack raw-socket privilege — so ``remote`` defaults to ``False``.
    Every other backend (``"local"``, ``"dry-run"``, and any future name)
    defaults to ``True`` — the historical default before this capability
    seam existed — so a local, potentially root-capable backend is never
    unintentionally forced into TCP-connect-only mode.
    """
    override = getattr(config, "tool_backend_raw_socket_capable", None)
    if override is not None:
        return bool(override)
    return _normalize_backend_name(config.tool_backend) != "remote"


#: Fixed, reportable vocabulary for the "relevant backend capability mode"
#: component of a canonical action fingerprint (Phase 2, post-live-test
#: debugging — see apex_host.planning.fingerprint.task_fingerprint). Two
#: values only: this is deliberately not an open string so the fingerprint
#: component stays a small, auditable enum-like vocabulary rather than an
#: unbounded set of ad-hoc labels.
CAPABILITY_MODE_RAW_SOCKET = "raw_socket"
CAPABILITY_MODE_TCP_CONNECT = "tcp_connect"


def backend_capability_mode(config: "ApexConfig") -> str:
    """Return the fixed capability-mode label for *config*'s tool backend —
    ``CAPABILITY_MODE_RAW_SOCKET`` or ``CAPABILITY_MODE_TCP_CONNECT`` — a
    thin, named wrapper around :func:`backend_supports_raw_sockets` so
    that ``TaskDispatcher`` can include the "relevant backend capability
    mode" component of a canonical action fingerprint without duplicating
    the derivation logic. A task planned identically but under a DIFFERENT
    capability mode is treated as a distinct action — see
    ``apex_host.planning.fingerprint.task_fingerprint``'s ``capability_mode``
    parameter.
    """
    return CAPABILITY_MODE_RAW_SOCKET if backend_supports_raw_sockets(config) else CAPABILITY_MODE_TCP_CONNECT


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
