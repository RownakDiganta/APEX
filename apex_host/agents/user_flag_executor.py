# user_flag_executor.py
# Bounded, transport-independent user-flag candidate read: resolves a capability_id to a runtime adapter, calls its read_bounded_file(path), and verifies the result — never knows or cares whether the underlying capability is SSH, Telnet, or anything else.
"""Bounded, transport-independent user-flag candidate-read executor
(Phase 18; made capability-generic in the access-capability refactor).

Before this refactor, this executor spoke SSH/Paramiko directly. It now
never knows or cares what transport backs the capability it was given —
it resolves ``capability_id`` (chosen by ``ObjectivePlanner`` from the live
EKG's ``AccessCapability`` records) to a runtime adapter via
``apex_host.runtime_registry.CapabilityRuntimeRegistry``, calls that
adapter's ONE exposed operation
(``apex_host.runtime_registry.FlagReadCapability.read_bounded_file``), and
passes the result into the one authoritative verifier,
``apex_host.verification.user_flag.verify_user_flag()``. Adding a new
capability type (Telnet, a local shell, an HTTP file-read API, ...) later
requires only a new adapter class + one more registration branch in
``apex_host.orchestration.dispatch_node`` — this executor's own code never
changes.

Why verification now happens HERE (not in the parser)
--------------------------------------------------------
Prior to this refactor, this executor returned the raw candidate stdout
and ``apex_host/parsers/objective_parser.py`` called ``verify_user_flag()``
itself. That required a downstream redaction step in
``apex_host.orchestration.memory_node.write_memory`` to keep the raw
candidate value out of the persisted episodic log — a real leak was found
and fixed there once (see ``docs/user-flag-objective.md`` §8). Moving the
ONE ``verify_user_flag()`` call site into this executor closes that gap at
its root: the raw candidate value now never leaves this module's stack
frame at all. Only ``verified: bool``, ``value_digest``, and
``redacted_value`` are ever placed into the episode/tool_result — the
parser (``ObjectiveParser``) no longer touches the verifier at all; it only
builds EKG nodes from these already-computed, already-secret-free fields.
"The one authoritative verifier" is unaffected — it is still implemented
in exactly one function, only its call site moved.

Why this reuses a registry-resolved adapter instead of ``ToolBackend``
------------------------------------------------------------------------
Identical rationale to the pre-refactor design: reading a file *inside* an
already-authenticated remote session is not something
``apex_host/tools/backend.py``'s ``ToolBackend`` (which runs a LOCAL binary
against the network target) has any concept of. The capability adapter
abstraction generalizes that reasoning to any transport, not just SSH.

Safety properties enforced by construction (not configuration)
----------------------------------------------------------------
- **Bounded path only.** ``candidate_path`` is validated against
  :func:`apex_host.verification.user_flag.is_bounded_candidate_path` BEFORE
  any adapter is ever invoked — an invalid path fails closed with no I/O of
  any kind. Defense in depth on top of the identical check already
  performed at the policy boundary
  (``apex_host/policy/rules.py::check_bounded_user_flag_verification``).
- **One read, one call, per turn.** Exactly one
  ``adapter.read_bounded_file()`` call per ``run()`` — no looping across
  candidates or capabilities inside the executor (``ObjectivePlanner``
  decides which capability and which candidate, bounded and one-per-turn).
- **This executor never knows the transport.** It only ever calls
  ``FlagReadCapability.read_bounded_file(path)`` — no branch anywhere in
  this file inspects ``capability_type`` to decide behavior.
- **Dry-run (config.dry_run=True, the default): returns a synthetic,
  deliberately unremarkable "file not found" result immediately** — no
  registry lookup, no adapter call, no network activity whatsoever, and
  the synthetic output can never verify as a plausible flag.
- **Stateless across calls** (memfabric Invariant 6): no adapter, session,
  or connection is held on ``self`` — the registry (injected once at
  construction) is the only thing referenced, and it is itself runtime-only
  (never persisted — see ``apex_host.runtime_registry``'s module docstring).
- **The raw candidate value is never logged, stored in the episode, or
  included in any exception text** — see "Why verification now happens
  HERE" above.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from memfabric.types import Episode, EvidenceBundle, ExecutorResult, Outcome, TaskSpec

from apex_host.runtime_registry import BoundedReadResult
from apex_host.verification.user_flag import FlagVerificationResult, is_bounded_candidate_path, verify_user_flag

if TYPE_CHECKING:
    from apex_host.config import ApexConfig
    from apex_host.runtime_registry import CapabilityRuntimeRegistry

logger = logging.getLogger(__name__)

_DEFAULT_MAX_OUTPUT_BYTES: int = 4096
#: Fallback outer defensive timeout ceiling when the config value is
#: missing/invalid (belt-and-suspenders, matching the pre-refactor
#: executor's identical "second, independent ceiling" discipline). The
#: real ceiling is ``ApexConfig.user_flag_read_timeout_seconds``.
_DEFAULT_READ_TIMEOUT_SECONDS: float = 35.0
#: Deliberately unremarkable — never a real-looking flag value, so a
#: default dry-run engagement can never manufacture a verified success.
_DRY_RUN_ERROR: str = "no such file or directory (dry-run)"
_NOT_CONNECTED_VERIFICATION = FlagVerificationResult(False, "not connected", "", "", 0, "n/a")


class UserFlagExecutor:
    """Stateless executor: one bounded, capability-agnostic candidate-path
    read + verification per ``run()`` call.

    Kept under its established name (``UserFlagExecutor``) rather than
    renamed: it is still specifically the executor for the ``user_flag``
    OBJECTIVE (per ``ApexConfig.objective_type``) — only the ACCESS
    TRANSPORT underneath it became generic. Renaming risked implying the
    objective itself is now generic, which it is not (see
    docs/user-flag-objective.md "Access capability abstraction" for the
    explicit scope boundary).
    """

    domain: str = "objective"

    def __init__(self, config: "ApexConfig", registry: "CapabilityRuntimeRegistry | None" = None) -> None:
        self._config = config
        self._registry = registry

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        params = task.params
        capability_id = str(params.get("capability_id", ""))
        capability_type = str(params.get("capability_type", ""))
        principal = str(params.get("principal", ""))
        candidate_path = str(params.get("candidate_path", ""))
        max_bytes = int(getattr(self._config, "user_flag_max_output_bytes", _DEFAULT_MAX_OUTPUT_BYTES) or _DEFAULT_MAX_OUTPUT_BYTES)
        allowed_filenames = frozenset(getattr(self._config, "user_flag_candidate_filenames", None) or [])
        format_regex = params.get("format_regex")

        if not is_bounded_candidate_path(candidate_path, allowed_filenames=allowed_filenames):
            return self._result(
                task, capability_id, capability_type, principal, candidate_path,
                connected=False, success=False, verification=_NOT_CONNECTED_VERIFICATION,
                error=f"candidate_path {candidate_path!r} failed bounded-path validation",
                dry_run=self._config.dry_run,
            )

        if self._config.dry_run:
            return self._dry_run_result(task, capability_id, capability_type, principal, candidate_path)

        adapter = self._registry.get(capability_id) if self._registry is not None else None
        if adapter is None:
            return self._result(
                task, capability_id, capability_type, principal, candidate_path,
                connected=False, success=False, verification=_NOT_CONNECTED_VERIFICATION,
                error=f"access capability {capability_id!r} has no registered runtime adapter",
                dry_run=False,
            )

        read_timeout = float(
            getattr(self._config, "user_flag_read_timeout_seconds", _DEFAULT_READ_TIMEOUT_SECONDS)
            or _DEFAULT_READ_TIMEOUT_SECONDS
        )
        start = time.monotonic()
        try:
            read_result = await asyncio.wait_for(
                adapter.read_bounded_file(candidate_path),
                timeout=read_timeout,
            )
        except asyncio.TimeoutError:
            read_result = BoundedReadResult(
                connected=False, output="", error="user-flag verification exceeded the overall bounded timeout",
            )

        duration = time.monotonic() - start
        verification = (
            verify_user_flag(
                read_result.output, raw_error=read_result.error or "",
                format_regex=format_regex, max_output_bytes=max_bytes,
            )
            if read_result.connected else _NOT_CONNECTED_VERIFICATION
        )
        # "success" preserves the pre-refactor disposition semantics: True
        # once the read itself completed without an operational error —
        # independent of whether the content turned out to be a verified
        # flag (a clean "no such file" read is still an executed, non-
        # repairable read, not a system failure). "verified" is the new,
        # separate signal the parser consumes to build objective_evidence.
        success = read_result.error is None
        logger.info(
            "user_flag_verify capability=%s(%s) path=%r connected=%s verified=%s",
            capability_id, capability_type, candidate_path, read_result.connected, verification.verified,
        )
        return self._result(
            task, capability_id, capability_type, principal, candidate_path,
            connected=read_result.connected, success=success, verification=verification,
            error=read_result.error, dry_run=False, duration_seconds=duration,
            read_result=read_result,
        )

    def _result(
        self,
        task: TaskSpec,
        capability_id: str,
        capability_type: str,
        principal: str,
        candidate_path: str,
        *,
        connected: bool,
        success: bool,
        verification: FlagVerificationResult,
        error: str | None,
        dry_run: bool,
        duration_seconds: float = 0.0,
        read_result: BoundedReadResult | None = None,
    ) -> ExecutorResult:
        episode = Episode(
            agent="apex.objective",
            action=f"user_flag_verify capability={capability_id} path={candidate_path}",
            outcome=Outcome.success if success else Outcome.fundamental,
            data={
                "capability_id": capability_id,
                "capability_type": capability_type,
                "principal": principal,
                "candidate_path": candidate_path,
                "connected": connected,
                "success": success,
                # Never the raw candidate value — only the verifier's
                # secret-free result fields. See module docstring "Why
                # verification now happens HERE."
                "verified": verification.verified,
                "value_digest": verification.digest,
                "redacted_value": verification.redacted,
                "verification_method": verification.method if verification.verified else "",
                "error": error,
                "dry_run": dry_run,
                "duration_seconds": duration_seconds,
                # Phase 20 — transport-neutral, secret-free BoundedReadResult
                # metadata (never the raw output itself). "" / None when no
                # real read was attempted (bounded-path rejection, dry-run,
                # missing adapter).
                "status_code": read_result.status_code if read_result else None,
                "bytes_received": read_result.bytes_received if read_result else 0,
                "truncated": read_result.truncated if read_result else False,
                "read_method": read_result.method if read_result else "",
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)

    def _dry_run_result(
        self, task: TaskSpec, capability_id: str, capability_type: str, principal: str, candidate_path: str,
    ) -> ExecutorResult:
        return self._result(
            task, capability_id, capability_type, principal, candidate_path,
            connected=True, success=False, verification=_NOT_CONNECTED_VERIFICATION,
            error=_DRY_RUN_ERROR, dry_run=True,
        )
