# dispatcher.py
# TaskDispatcher: single entry point for all task execution in the APEX engagement loop.
"""Single-point task execution dispatcher for APEX.

``TaskDispatcher.dispatch()`` is the ONLY call-site that:

1. Computes the canonical SHA-256 task fingerprint (16 hex chars).
2. Checks policy via ``PolicyAdvisor.review_task()`` before any I/O.
3. Checks conflict dependencies via ``check_conflict_dependencies()`` before
   any I/O.
4. Atomically reserves the fingerprint in ``TaskRegistry`` (check + register
   under asyncio.Lock) to prevent concurrent duplicate submissions.
5. Routes to the correct executor — ``TelnetExecutor``, ``BrowserExecutor``,
   or the safety-gated ``run_command`` subprocess runner.
6. Records the final status back in ``TaskRegistry`` so checkpoint snapshots
   are accurate.
7. Returns a fully-typed ``DispatchResult`` that callers convert to the
   state-dict format consumed by ``parse_observation`` / ``write_memory``.

Security invariants (non-negotiable):
- Policy gate runs BEFORE conflict gate, BEFORE duplicate gate, BEFORE executor.
- Blocked (policy/conflict) tasks are NEVER registered in ``TaskRegistry``
  (they leave no fingerprint trail — the operator may re-run after fixing
  the policy or resolving the conflict).
- Skipped duplicates (``TaskRegistry.reserve()`` returns False) are returned
  with disposition ``SKIPPED_DUPLICATE`` and never touch any executor.
- All subprocess execution goes through the caller-supplied ``run_command_fn``
  — no raw subprocess calls here (CLAUDE.md §11.2).
- ``dry_run=True`` propagates from ``context.dry_run`` to all executors.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from memfabric.coordination.conflict import check_conflict_dependencies
from memfabric.ids import now
from memfabric.types import TaskSpec

from apex_host.execution.context import DispatchResult, ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition, classify_retry
from apex_host.execution.errors import ErrorCategory, ExecutionError
from apex_host.execution.registry import TaskRegistry, TaskStatus
from apex_host.planning.fingerprint import task_fingerprint
from apex_host.tools.backend import backend_capability_mode

if TYPE_CHECKING:
    from apex_host.agents.browser_executor import BrowserExecutor
    from apex_host.agents.ftp_executor import FTPExecutor
    from apex_host.agents.priv_esc_analysis_executor import PrivEscAnalysisExecutor
    from apex_host.agents.priv_esc_enum_executor import PrivEscEnumExecutor
    from apex_host.agents.ssh_executor import SSHExecutor
    from apex_host.agents.telnet_executor import TelnetExecutor
    from apex_host.agents.user_flag_executor import UserFlagExecutor
    from apex_host.config import ApexConfig
    from apex_host.policy import PolicyAdvisor
    from apex_host.types import ToolCommand, ToolResult

logger = logging.getLogger(__name__)

# Constant sets shared between dispatcher and graph.py (no duplication).
_CONFLICT_SENSITIVE_TOOLS: frozenset[str] = frozenset({
    "nc", "netcat", "curl", "ffuf", "gobuster",
})
_CONFLICT_CRITICAL_FIELDS: frozenset[str] = frozenset({
    "port", "service", "proto", "state", "ip",
})


def _make_blocked_result(
    task: TaskSpec,
    disposition: ExecutionDisposition,
    error_msg: str,
    *,
    phase: str,
    dry_run: bool,
    tool: str,
    args: list[str],
    target: str,
    parser: str,
    policy_blocked: bool = False,
    conflict_blocked: bool = False,
    policy_rule: str = "",
    conflict_block_reason: str = "",
    conflict_fields: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the backward-compatible tool-result dict for blocked/skipped tasks."""
    d: dict[str, Any] = {
        "task_id": task.id,
        "tool": tool,
        "args": args,
        "target": target,
        "parser": parser,
        "stdout": "",
        "stderr": "",
        "returncode": 1 if disposition is ExecutionDisposition.BLOCKED_POLICY else 0,
        "dry_run": dry_run,
        "error": error_msg if policy_blocked or conflict_blocked else None,
        "phase": phase,
    }
    # Phase 20 — carried through, harmless/empty for non-user_flag_verify
    # tools, so a blocked direct-file-read attempt can still be attributed
    # to its capability_type in write_memory's metrics (see
    # apex_host/orchestration/memory_node.py).
    if tool == "user_flag_verify":
        d["capability_id"] = str(task.params.get("capability_id", ""))
        d["capability_type"] = str(task.params.get("capability_type", ""))
    if policy_blocked:
        d["policy_blocked"] = True
        d["policy_rule"] = policy_rule
    if conflict_blocked:
        d["conflict_blocked"] = True
        d["conflict_block_reason"] = conflict_block_reason
        d["conflict_fields"] = conflict_fields or []
    return d


def _credential_result_to_tr(
    task: TaskSpec,
    result: Any,
    tool: str,
    target: str,
    parser: str,
    phase: str,
) -> tuple[dict[str, Any], ExecutionDisposition]:
    """Shared tool-result-dict builder for SSHExecutor/FTPExecutor results
    (Phase 12B). Never includes the password — ``result.episode.data`` never
    contains it (see ``apex_host/agents/ssh_executor.py`` /
    ``ftp_executor.py``).

    Disposition mapping:
    - ``success`` -> EXECUTED_SUCCESS.
    - ``error_category == "auth_rejected"`` -> EXECUTED_VALID_NEGATIVE (a
      clean, definitive "wrong credentials" signal — never retried/repaired,
      matching TelnetExecutor's own success/valid-negative split).
    - Anything else (connection failure, any timeout, protocol error, or the
      harmless validation command itself failing after a successful login)
      -> EXECUTED_FAILURE, distinct from a clean auth rejection.
    """
    ep_data = result.episode.data
    success = bool(ep_data.get("success", False))
    error_category = str(ep_data.get("error_category", ""))
    if success:
        disposition = ExecutionDisposition.EXECUTED_SUCCESS
    elif error_category == "auth_rejected":
        disposition = ExecutionDisposition.EXECUTED_VALID_NEGATIVE
    else:
        disposition = ExecutionDisposition.EXECUTED_FAILURE

    error_detail = str(ep_data.get("error_detail") or "")
    tr: dict[str, Any] = {
        "task_id": task.id, "tool": tool, "args": [],
        "target": target, "parser": parser,
        "stdout": str(ep_data.get("response_summary", "")), "stderr": "",
        "returncode": 0 if success else 1,
        "dry_run": bool(ep_data.get("dry_run", False)),
        "error": error_detail or None, "phase": phase,
        "username": str(ep_data.get("username", "")),
        "port": str(ep_data.get("port", "")),
        "proto": "tcp",
        "protocol": str(ep_data.get("protocol", "")),
        "success": success,
        "authenticated": bool(ep_data.get("authenticated", False)),
        "operation": str(ep_data.get("operation", "")),
        "response_summary": str(ep_data.get("response_summary", "")),
        "error_category": error_category,
        "timed_out": bool(ep_data.get("timed_out", False)),
        # Phase 17: real, measured wall-clock validation time (set by
        # SSHExecutor/FTPExecutor — see apex_host/eval/benchmark.py).
        "duration_seconds": float(ep_data.get("duration_seconds", 0.0) or 0.0),
    }
    return tr, disposition


class TaskDispatcher:
    """Single entry point for all executor invocations in the APEX graph.

    One ``TaskDispatcher`` instance is created per engagement run inside
    ``build_apex_graph()``.  It is captured by all graph node closures that
    execute tools — it is NEVER stored in ``ApexGraphState``.
    """

    def __init__(
        self,
        *,
        advisor: "PolicyAdvisor",
        task_registry: TaskRegistry,
        config: "ApexConfig",
        run_command_fn: Callable[["ToolCommand", "ApexConfig"], Awaitable["ToolResult"]],
        telnet_executor: "TelnetExecutor | None" = None,
        browser_executor: "BrowserExecutor | None" = None,
        ssh_executor: "SSHExecutor | None" = None,
        ftp_executor: "FTPExecutor | None" = None,
        priv_esc_analysis_executor: "PrivEscAnalysisExecutor | None" = None,
        priv_esc_enum_executor: "PrivEscEnumExecutor | None" = None,
        user_flag_executor: "UserFlagExecutor | None" = None,
    ) -> None:
        self._advisor = advisor
        self._registry = task_registry
        self._config = config
        self._run_command_fn = run_command_fn
        self._telnet_executor = telnet_executor
        self._browser_executor = browser_executor
        self._ssh_executor = ssh_executor
        self._ftp_executor = ftp_executor
        self._priv_esc_analysis_executor = priv_esc_analysis_executor
        self._priv_esc_enum_executor = priv_esc_enum_executor
        self._user_flag_executor = user_flag_executor

    @property
    def task_registry(self) -> TaskRegistry:
        """The ``TaskRegistry`` this dispatcher reserves fingerprints
        against. Exposed (Phase 2, post-live-test debugging) so
        ``apex_host.orchestration.repair_node`` can mark a superseded
        fingerprint's status after a materially-changed repair is
        dispatched — never used to bypass ``dispatch()``'s own gates."""
        return self._registry

    async def dispatch(
        self,
        task: TaskSpec,
        context: ExecutionContext,
    ) -> DispatchResult:
        """Execute one task through all safety gates, then route to the correct executor.

        Call-site contract
        ------------------
        Every caller must:
        - Pass a fully-populated ``ExecutionContext`` (run_id, phase, evidence, …).
        - Interpret the returned ``DispatchResult.disposition`` to decide retry/repair.
        - Never call ``run_command_fn``, ``TelnetExecutor``, or ``BrowserExecutor``
          directly — everything goes through ``dispatch()``.
        """
        tool = str(task.params.get("tool", ""))
        args = [str(a) for a in task.params.get("args", [])]
        target = str(task.params.get("target", self._config.target))
        parser = str(task.params.get("parser", "command"))
        phase = context.phase
        # Phase 3 (post-live-test debugging): captured once, threaded into
        # the final tool_result dict at step 6 below so every execution
        # path (policy-blocked, duplicate-skipped, or actually executed)
        # can report a start/end timestamp for diagnostics.
        _dispatch_start_ts = now()

        # ── 1. Policy gate ────────────────────────────────────────────────
        pd = self._advisor.review_task(task, phase, context.evidence, self._config)
        pd_meta = {
            "tool": tool,
            "target": target,
            "phase": phase,
            "status": pd.status.value,
            "rule_name": pd.rule_name,
            "reason": pd.reason,
        }

        if not pd.is_approved:
            logger.info(
                "dispatcher: policy gate [%s] blocked tool=%r target=%r rule=%r",
                phase, tool, target, pd.rule_name,
            )
            error_msg = f"policy_blocked: {pd.reason}"
            err = ExecutionError(
                category=ErrorCategory.POLICY_DENIED,
                message=error_msg,
                task_id=task.id,
                policy_decision=pd,
            )
            tr = _make_blocked_result(
                task, ExecutionDisposition.BLOCKED_POLICY, error_msg,
                phase=phase, dry_run=context.dry_run, tool=tool, args=args,
                target=target, parser=parser, policy_blocked=True,
                policy_rule=pd.rule_name,
            )
            return DispatchResult(
                disposition=ExecutionDisposition.BLOCKED_POLICY,
                task_id=task.id,
                fingerprint="",
                tool_result_dict=tr,
                policy_decision=pd,
                error=err,
                retryable=False,
                repairable=False,
                audit_metadata={"policy_decision": pd_meta},
            )

        # ── 2. Conflict gate ──────────────────────────────────────────────
        blocking_claims: list[Any] = []
        if task.claim_dependencies and context.evidence.blocked_fields:
            blocking_claims = check_conflict_dependencies(
                task.claim_dependencies, context.evidence.blocked_fields
            )
        elif (
            not task.claim_dependencies
            and context.evidence.blocked_fields
            and tool in _CONFLICT_SENSITIVE_TOOLS
        ):
            blocking_claims = [
                bc for bc in context.evidence.blocked_fields
                if bc.field_name in _CONFLICT_CRITICAL_FIELDS
                and bc.node_type in {"service", "host"}
            ]

        if blocking_claims:
            conflict_reason = (
                f"task tool={tool!r} depends on contested fields: "
                + ", ".join(
                    f"{bc.node_type}.{bc.field_name}" for bc in blocking_claims
                )
            )
            logger.info(
                "dispatcher: conflict gate [%s] blocked tool=%r: %s",
                phase, tool, conflict_reason,
            )
            err = ExecutionError(
                category=ErrorCategory.CONFLICT_BLOCKED,
                message=conflict_reason,
                task_id=task.id,
                conflict_block_reason=conflict_reason,
            )
            tr = _make_blocked_result(
                task, ExecutionDisposition.BLOCKED_CONFLICT, conflict_reason,
                phase=phase, dry_run=context.dry_run, tool=tool, args=args,
                target=target, parser=parser, conflict_blocked=True,
                conflict_block_reason=conflict_reason,
                conflict_fields=[
                    {"node_id": bc.node_id, "field": bc.field_name,
                     "conflict_id": bc.conflict_id}
                    for bc in blocking_claims
                ],
            )
            return DispatchResult(
                disposition=ExecutionDisposition.BLOCKED_CONFLICT,
                task_id=task.id,
                fingerprint="",
                tool_result_dict=tr,
                error=err,
                retryable=False,
                repairable=False,
                audit_metadata={"policy_decision": pd_meta},
            )

        # ── 3. Duplicate gate (TaskRegistry, atomic check-and-reserve) ───
        # Phase 2 (post-live-test debugging): capability_mode is part of the
        # canonical action identity — a task planned identically but under a
        # different backend capability assumption (e.g. raw-socket-capable
        # vs TCP-connect-only) is a distinct action. See
        # apex_host.tools.backend.backend_capability_mode.
        executor_domain = str(task.params.get("executor_domain", phase))
        capability_mode = backend_capability_mode(self._config)
        fingerprint = task_fingerprint(
            phase, tool, args, target, parser, executor_domain, capability_mode
        )

        ts = now()
        reserved, existing = await self._registry.reserve(
            fingerprint=fingerprint,
            task_id=task.id,
            run_id=context.run_id,
            phase=phase,
            evidence_version=context.evidence_version,
            timestamp=ts,
        )

        if not reserved:
            prior_task_id = existing.task_id if existing else ""
            prior_status = existing.status.value if existing else ""
            prior_disposition = existing.disposition if existing else ""
            prior_attempts = self._registry.attempt_count(fingerprint)
            logger.info(
                "dispatcher: duplicate [%s] fingerprint=%s prior=%s prior_status=%s attempts=%d",
                phase, fingerprint, prior_task_id, prior_status, prior_attempts,
            )
            err = ExecutionError(
                category=ErrorCategory.DUPLICATE_TASK,
                message=f"task matches completed fingerprint={fingerprint}",
                task_id=task.id,
                duplicate_fingerprint=fingerprint,
            )
            tr = _make_blocked_result(
                task, ExecutionDisposition.SKIPPED_DUPLICATE, "",
                phase=phase, dry_run=context.dry_run, tool=tool, args=args,
                target=target, parser=parser,
            )
            tr["skipped_duplicate"] = True
            tr["duplicate_fingerprint"] = fingerprint
            # Phase 2 (post-live-test debugging): carried through so
            # apex_host.orchestration.dispatch_node._dup_entry and the
            # report builder can show WHY this specific action is being
            # suppressed (previous outcome, attempt count) — not just that
            # it was suppressed.
            tr["duplicate_previous_status"] = prior_status
            tr["duplicate_previous_disposition"] = prior_disposition
            tr["duplicate_attempt_count"] = prior_attempts
            tr["returncode"] = 0
            tr["error"] = None
            return DispatchResult(
                disposition=ExecutionDisposition.SKIPPED_DUPLICATE,
                task_id=task.id,
                fingerprint=fingerprint,
                duplicate_of=prior_task_id,
                tool_result_dict=tr,
                error=err,
                retryable=False,
                repairable=False,
                audit_metadata={"policy_decision": pd_meta},
            )

        # ── 4. Mark as EXECUTING ──────────────────────────────────────────
        await self._registry.update_status(
            fingerprint, TaskStatus.EXECUTING,
            retry_count=context.retry_count,
        )

        # ── 5. Route to executor ──────────────────────────────────────────
        disposition: ExecutionDisposition
        tr_dict: dict[str, Any]

        logger.info(
            "dispatcher: executing [%s] tool=%r target=%r task_id=%s",
            phase, tool, target, task.id,
        )
        try:
            if tool == "browser":
                tr_dict, disposition = await self._run_browser(task, context, args, target, parser, phase)
            elif tool == "telnet_access":
                tr_dict, disposition = await self._run_telnet(task, context, args, target, parser, phase)
            elif tool == "ssh_access":
                tr_dict, disposition = await self._run_ssh(task, context, args, target, parser, phase)
            elif tool == "ftp_access":
                tr_dict, disposition = await self._run_ftp(task, context, args, target, parser, phase)
            elif tool == "priv_esc_analyze":
                tr_dict, disposition = await self._run_priv_esc_analysis(task, context, args, target, parser, phase)
            elif tool == "priv_esc_enum":
                tr_dict, disposition = await self._run_priv_esc_enum(task, context, args, target, parser, phase)
            elif tool == "user_flag_verify":
                tr_dict, disposition = await self._run_user_flag_verify(task, context, args, target, parser, phase)
            else:
                tr_dict, disposition = await self._run_command(task, context, args, target, parser, phase)
        except asyncio.CancelledError:
            await self._registry.update_status(
                fingerprint, TaskStatus.CANCELLED, disposition="cancelled",
            )
            err = ExecutionError(
                category=ErrorCategory.EXECUTION_CANCELLED,
                message="task cancelled",
                task_id=task.id,
            )
            return DispatchResult(
                disposition=ExecutionDisposition.CANCELLED,
                task_id=task.id,
                fingerprint=fingerprint,
                tool_result_dict={
                    "task_id": task.id, "tool": tool, "args": args,
                    "target": target, "parser": parser, "stdout": "",
                    "stderr": "", "returncode": 1, "dry_run": context.dry_run,
                    "error": "cancelled", "phase": phase,
                },
                error=err,
                retryable=False,
                repairable=False,
                audit_metadata={"policy_decision": pd_meta},
            )
        except Exception as exc:
            await self._registry.update_status(
                fingerprint, TaskStatus.FAILED_RETRYABLE,
                disposition="external_error",
            )
            err = ExecutionError(
                category=ErrorCategory.EXTERNAL_EXECUTION_ERROR,
                message=str(exc),
                task_id=task.id,
            )
            return DispatchResult(
                disposition=ExecutionDisposition.EXECUTED_FAILURE,
                task_id=task.id,
                fingerprint=fingerprint,
                tool_result_dict={
                    "task_id": task.id, "tool": tool, "args": args,
                    "target": target, "parser": parser, "stdout": "",
                    "stderr": str(exc), "returncode": 1,
                    "dry_run": context.dry_run, "error": str(exc), "phase": phase,
                },
                error=err,
                retryable=True,
                repairable=False,
                audit_metadata={"policy_decision": pd_meta},
            )

        logger.info(
            "dispatcher: completed [%s] tool=%r target=%r task_id=%s disposition=%s "
            "returncode=%r error_category=%r timed_out=%r",
            phase, tool, target, task.id, disposition.value,
            tr_dict.get("returncode"), tr_dict.get("error_category", ""),
            tr_dict.get("timed_out", False),
        )
        logger.debug(
            "dispatcher: task_id=%s stdout=%r stderr=%r",
            task.id, str(tr_dict.get("stdout", ""))[:500], str(tr_dict.get("stderr", ""))[:500],
        )

        # ── 6. Record final status ────────────────────────────────────────
        # Phase 2 (post-live-test debugging) fix: the SPECIFIC retry
        # decision from classify_retry() — which inspects the actual error
        # text (e.g. "connection refused" vs an nmap raw-socket permission
        # failure) — now drives TaskRegistry suppression, not the coarse
        # disposition.is_retryable "shape" check. The old code treated
        # EVERY EXECUTED_FAILURE as retryable-shaped regardless of whether
        # classify_retry() had already determined the specific error was
        # NOT retryable, so a genuinely non-retryable failure (like a raw-
        # socket permission error) never suppressed resubmission — the
        # identical failing action re-executed every turn (the confirmed
        # live-test bug: six identical Nmap failures, duplicate_actions
        # .total_skipped stayed zero). classify_retry() is computed FIRST
        # so the real decision, not the shape, drives status assignment.
        #
        # Bounded retries: even a genuinely retryable (transient) failure
        # is only permitted ApexConfig.max_fingerprint_retries additional
        # resubmissions under the SAME fingerprint before it, too, is
        # forced to FAILED_TERMINAL — "one bounded retry", never unbounded.
        retry_decision = classify_retry(disposition, tr_dict.get("error") or "")
        attempt_count = self._registry.attempt_count(fingerprint)
        bounded_retry_available = attempt_count <= self._config.max_fingerprint_retries

        if disposition.is_success:
            final_status = TaskStatus.COMPLETED
        elif disposition is ExecutionDisposition.TIMED_OUT:
            final_status = (
                TaskStatus.TIMED_OUT if bounded_retry_available else TaskStatus.FAILED_TERMINAL
            )
        elif retry_decision.may_retry and bounded_retry_available:
            final_status = TaskStatus.FAILED_RETRYABLE
        else:
            final_status = TaskStatus.FAILED_TERMINAL
            if retry_decision.may_retry and not bounded_retry_available:
                # Genuinely transient per classify_retry(), but this
                # fingerprint's bounded retry budget is exhausted — record
                # WHY it is terminal now, distinct from "never retryable".
                tr_dict["retry_budget_exhausted"] = True

        await self._registry.update_status(
            fingerprint, final_status,
            disposition=disposition.value,
            retry_count=attempt_count - 1,
        )

        # Phase 3 (post-live-test debugging): thread the canonical action
        # fingerprint, retry index, wall-clock timestamps, the classifier's
        # own reason string, and the final disposition into the SAME
        # tool_result dict every downstream consumer (write_memory,
        # apex_host.execution.diagnostics.build_execution_diagnostic) already
        # reads — one insertion point covers every executor path (this
        # method is reached from every _run_* branch via the shared
        # tr_dict/disposition tuple). Never overwrites a key an executor
        # already set (e.g. a structured executor's own "agent"-shaped
        # value), only fills in what dispatch() alone knows.
        tr_dict.setdefault("fingerprint", fingerprint)
        tr_dict.setdefault("retry_index", max(0, attempt_count - 1))
        tr_dict.setdefault("start_timestamp", _dispatch_start_ts)
        tr_dict.setdefault("end_timestamp", now())
        tr_dict.setdefault("classifier_reason", retry_decision.reason)
        tr_dict.setdefault("final_disposition", disposition.value)
        tr_dict.setdefault("agent", f"apex.{phase}")
        if pd.rule_name:
            tr_dict.setdefault("policy_rule", pd.rule_name)

        return DispatchResult(
            disposition=disposition,
            task_id=task.id,
            fingerprint=fingerprint,
            tool_result_dict=tr_dict,
            policy_decision=pd,
            retryable=retry_decision.may_retry,
            repairable=retry_decision.may_repair,
            audit_metadata={"policy_decision": pd_meta},
        )

    # ── Private executor helpers ────────────────────────────────────────────

    async def _run_command(
        self,
        task: TaskSpec,
        context: ExecutionContext,
        args: list[str],
        target: str,
        parser: str,
        phase: str,
    ) -> tuple[dict[str, Any], ExecutionDisposition]:
        """Run a subprocess tool via the safety-gated runner.py."""
        from apex_host.types import ToolCommand

        tool = str(task.params.get("tool", ""))
        cmd = ToolCommand(tool=tool, args=args, timeout_seconds=self._config.max_command_seconds)
        try:
            result = await self._run_command_fn(cmd, self._config)
        except ValueError as exc:
            # Safety gate in runner.py (or a ToolBackend's own check_command
            # call) rejected the command before any backend was reached.
            tr: dict[str, Any] = {
                "task_id": task.id, "tool": tool, "args": args,
                "target": target, "parser": parser, "stdout": "",
                "stderr": "", "returncode": 1, "dry_run": self._config.dry_run,
                "error": str(exc), "phase": phase,
                "timed_out": False, "backend": "",
            }
            return tr, ExecutionDisposition.INVALID_TASK

        error = result.error
        disposition = (
            ExecutionDisposition.EXECUTED_SUCCESS
            if (result.returncode == 0 and not error)
            else ExecutionDisposition.EXECUTED_FAILURE
        )
        tr = {
            "task_id": task.id, "tool": tool, "args": args,
            "target": target, "parser": parser,
            "stdout": result.stdout, "stderr": result.stderr,
            "returncode": result.returncode, "dry_run": result.dry_run,
            "error": error, "phase": phase,
            # Infra Phase 4: identifies which ToolBackend actually produced
            # this result ("dry-run" | "local" | "remote") and whether
            # execution was terminated by its own timeout. See
            # docs/remote-tool-backend.md "Report fields".
            "timed_out": result.timed_out, "backend": result.backend,
            # Phase 17: real, measured wall-clock execution time — feeds the
            # benchmarking subsystem's average-task-latency metric (see
            # apex_host/eval/benchmark.py). Always present on this path
            # (ToolResult.duration_seconds is populated for every backend,
            # including dry-run, where it is ~0).
            "duration_seconds": result.duration_seconds,
        }
        if tool == "nmap":
            # Live-test debugging fix (Phase 1 of 4): classify WHY nmap
            # failed (e.g. a raw-socket permission failure on a non-root
            # backend) into a bounded diagnostic vocabulary, distinct from
            # the generic "error"/"returncode" fields — flows automatically
            # into episode.data via the existing tr-dict spread in
            # apex_host/orchestration/memory_node.py, no further plumbing
            # needed. Never affects parsing/EKG-write decisions.
            from apex_host.parsers.nmap_parser import classify_nmap_error

            tr["error_category"] = classify_nmap_error(
                result.returncode, result.stdout, result.stderr
            )
        return tr, disposition

    async def _run_telnet(
        self,
        task: TaskSpec,
        context: ExecutionContext,
        args: list[str],
        target: str,
        parser: str,
        phase: str,
    ) -> tuple[dict[str, Any], ExecutionDisposition]:
        """Run a telnet_access task via TelnetExecutor."""
        if self._telnet_executor is None:
            tr: dict[str, Any] = {
                "task_id": task.id, "tool": "telnet_access", "args": [],
                "target": target, "parser": parser, "stdout": "",
                "stderr": "", "returncode": 1, "dry_run": context.dry_run,
                "error": "telnet executor not configured", "phase": phase,
            }
            return tr, ExecutionDisposition.TOOL_UNAVAILABLE

        result = await self._telnet_executor.run(task, context.evidence)
        ep_data = result.episode.data
        outcome_is_success = result.episode.outcome.value == "success"
        stdout = str(ep_data.get("stdout", ""))
        raw_error: object = ep_data.get("error")
        if not outcome_is_success and raw_error is None:
            raw_error = "login failed"
        error_str: str | None = str(raw_error) if raw_error is not None else None

        disposition = (
            ExecutionDisposition.EXECUTED_SUCCESS
            if outcome_is_success
            else ExecutionDisposition.EXECUTED_VALID_NEGATIVE
        )
        tr = {
            "task_id": task.id, "tool": "telnet_access", "args": [],
            "target": target, "parser": parser, "stdout": stdout,
            "stderr": "", "returncode": 0 if outcome_is_success else 1,
            "dry_run": bool(ep_data.get("dry_run", False)),
            "error": error_str, "phase": phase,
            "username": str(task.params.get("username", "")),
            "port": str(task.params.get("port", "")),
            "proto": "tcp",
        }
        return tr, disposition

    async def _run_ssh(
        self,
        task: TaskSpec,
        context: ExecutionContext,
        args: list[str],
        target: str,
        parser: str,
        phase: str,
    ) -> tuple[dict[str, Any], ExecutionDisposition]:
        """Run an ssh_access task via SSHExecutor."""
        if self._ssh_executor is None:
            tr: dict[str, Any] = {
                "task_id": task.id, "tool": "ssh_access", "args": [],
                "target": target, "parser": parser, "stdout": "",
                "stderr": "", "returncode": 1, "dry_run": context.dry_run,
                "error": "ssh executor not configured", "phase": phase,
            }
            return tr, ExecutionDisposition.TOOL_UNAVAILABLE

        result = await self._ssh_executor.run(task, context.evidence)
        return _credential_result_to_tr(task, result, "ssh_access", target, parser, phase)

    async def _run_ftp(
        self,
        task: TaskSpec,
        context: ExecutionContext,
        args: list[str],
        target: str,
        parser: str,
        phase: str,
    ) -> tuple[dict[str, Any], ExecutionDisposition]:
        """Run an ftp_access task via FTPExecutor."""
        if self._ftp_executor is None:
            tr: dict[str, Any] = {
                "task_id": task.id, "tool": "ftp_access", "args": [],
                "target": target, "parser": parser, "stdout": "",
                "stderr": "", "returncode": 1, "dry_run": context.dry_run,
                "error": "ftp executor not configured", "phase": phase,
            }
            return tr, ExecutionDisposition.TOOL_UNAVAILABLE

        result = await self._ftp_executor.run(task, context.evidence)
        return _credential_result_to_tr(task, result, "ftp_access", target, parser, phase)

    async def _run_priv_esc_analysis(
        self,
        task: TaskSpec,
        context: ExecutionContext,
        args: list[str],
        target: str,
        parser: str,
        phase: str,
    ) -> tuple[dict[str, Any], ExecutionDisposition]:
        """Run a priv_esc_analyze task via PrivEscAnalysisExecutor.

        Zero network, zero subprocess — see
        ``apex_host/agents/priv_esc_analysis_executor.py``. Always
        EXECUTED_SUCCESS on completion (there is no failure mode: the
        executor only echoes already-computed fields; a missing/unconfigured
        executor is the only failure path, mirrored on the other
        specialised executors above).
        """
        if self._priv_esc_analysis_executor is None:
            tr: dict[str, Any] = {
                "task_id": task.id, "tool": "priv_esc_analyze", "args": args,
                "target": target, "parser": parser, "stdout": "",
                "stderr": "", "returncode": 1, "dry_run": context.dry_run,
                "error": "priv_esc analysis executor not configured", "phase": phase,
            }
            return tr, ExecutionDisposition.TOOL_UNAVAILABLE

        result = await self._priv_esc_analysis_executor.run(task, context.evidence)
        ep_data = result.episode.data
        tr = {
            "task_id": task.id, "tool": "priv_esc_analyze", "args": args,
            "target": target, "parser": parser, "stdout": "",
            "stderr": "", "returncode": 0, "dry_run": False,
            "error": None, "phase": phase,
            "category": str(ep_data.get("category", "")),
            "confidence": str(ep_data.get("confidence", "")),
            "description": str(ep_data.get("description", "")),
            "recommended_next_action": str(ep_data.get("recommended_next_action", "")),
            "discriminator": str(ep_data.get("discriminator", "")),
            "evidence_source": str(ep_data.get("evidence_source", "")),
            "evidence_excerpt": str(ep_data.get("evidence_excerpt", "")),
            "source_node_id": str(ep_data.get("source_node_id", "")),
        }
        return tr, ExecutionDisposition.EXECUTED_SUCCESS

    async def _run_priv_esc_enum(
        self,
        task: TaskSpec,
        context: ExecutionContext,
        args: list[str],
        target: str,
        parser: str,
        phase: str,
    ) -> tuple[dict[str, Any], ExecutionDisposition]:
        """Run a priv_esc_enum task via PrivEscEnumExecutor (Phase 13B).

        A bounded, read-only enumeration command over an already-validated
        SSH session — see ``apex_host/agents/priv_esc_enum_executor.py``.
        Never includes the password anywhere in the returned dict.
        """
        if self._priv_esc_enum_executor is None:
            tr: dict[str, Any] = {
                "task_id": task.id, "tool": "priv_esc_enum", "args": args,
                "target": target, "parser": parser, "stdout": "",
                "stderr": "", "returncode": 1, "dry_run": context.dry_run,
                "error": "priv_esc enumeration executor not configured", "phase": phase,
            }
            return tr, ExecutionDisposition.TOOL_UNAVAILABLE

        result = await self._priv_esc_enum_executor.run(task, context.evidence)
        ep_data = result.episode.data
        success = bool(ep_data.get("success", False))
        tr = {
            "task_id": task.id, "tool": "priv_esc_enum", "args": args,
            "target": target, "parser": parser,
            "stdout": str(ep_data.get("stdout", "")), "stderr": "",
            "returncode": 0 if success else 1,
            "dry_run": bool(ep_data.get("dry_run", False)),
            "error": ep_data.get("error"), "phase": phase,
            "port": str(ep_data.get("port", "")),
            "command_key": str(ep_data.get("command_key", "")),
            "source_command": str(ep_data.get("source_command", "")),
            "category": str(ep_data.get("category", "")),
            # Phase 17: real, measured wall-clock enumeration-command time
            # (set by PrivEscEnumExecutor — see apex_host/eval/benchmark.py).
            "duration_seconds": float(ep_data.get("duration_seconds", 0.0) or 0.0),
        }
        disposition = (
            ExecutionDisposition.EXECUTED_SUCCESS if success
            else ExecutionDisposition.EXECUTED_FAILURE
        )
        return tr, disposition

    async def _run_user_flag_verify(
        self,
        task: TaskSpec,
        context: ExecutionContext,
        args: list[str],
        target: str,
        parser: str,
        phase: str,
    ) -> tuple[dict[str, Any], ExecutionDisposition]:
        """Run a user_flag_verify task via UserFlagExecutor (Phase 18; made
        capability-generic in the access-capability refactor).

        A bounded, read-only candidate-path read against whichever
        ``AccessCapability`` ``ObjectivePlanner`` selected — see
        ``apex_host/agents/user_flag_executor.py``. Never includes a
        password or the raw candidate value anywhere in the returned dict:
        verification now happens inside the executor itself, so this
        dict only ever carries the verifier's already-computed,
        secret-free result fields (``verified``/``value_digest``/
        ``redacted_value``).
        """
        if self._user_flag_executor is None:
            tr: dict[str, Any] = {
                "task_id": task.id, "tool": "user_flag_verify", "args": args,
                "target": target, "parser": parser, "stdout": "",
                "stderr": "", "returncode": 1, "dry_run": context.dry_run,
                "error": "user-flag executor not configured", "phase": phase,
            }
            return tr, ExecutionDisposition.TOOL_UNAVAILABLE

        result = await self._user_flag_executor.run(task, context.evidence)
        ep_data = result.episode.data
        success = bool(ep_data.get("success", False))
        tr = {
            "task_id": task.id, "tool": "user_flag_verify", "args": args,
            "target": target, "parser": parser,
            # Never the raw candidate value — only the verifier's
            # secret-free fields (see method docstring).
            "stdout": "", "stderr": "",
            "returncode": 0 if success else 1,
            "dry_run": bool(ep_data.get("dry_run", False)),
            "error": ep_data.get("error"), "phase": phase,
            "connected": bool(ep_data.get("connected", False)),
            "candidate_path": str(ep_data.get("candidate_path", "")),
            "objective_type": str(task.params.get("objective_type", "user_flag")),
            "capability_id": str(ep_data.get("capability_id", "")),
            "capability_type": str(ep_data.get("capability_type", "")),
            "principal": str(ep_data.get("principal", "")),
            "verified": bool(ep_data.get("verified", False)),
            "value_digest": str(ep_data.get("value_digest", "")),
            "redacted_value": str(ep_data.get("redacted_value", "")),
            "verification_method": str(ep_data.get("verification_method", "")),
            "attempted_paths": list(task.params.get("attempted_paths", [])),
            "attempted_capability_paths": list(task.params.get("attempted_capability_paths", [])),
            "is_last_candidate": bool(task.params.get("is_last_candidate", False)),
            # Phase 17: real, measured wall-clock read time.
            "duration_seconds": float(ep_data.get("duration_seconds", 0.0) or 0.0),
            # Phase 20 — transport-neutral BoundedReadResult metadata (never
            # the raw candidate output). "" / None when no real read was
            # attempted (bounded-path rejection, dry-run, missing adapter).
            "status_code": ep_data.get("status_code"),
            "bytes_received": int(ep_data.get("bytes_received", 0) or 0),
            "truncated": bool(ep_data.get("truncated", False)),
            "read_method": str(ep_data.get("read_method", "")),
        }
        disposition = (
            ExecutionDisposition.EXECUTED_SUCCESS if success
            else ExecutionDisposition.EXECUTED_FAILURE
        )
        return tr, disposition

    async def _run_browser(
        self,
        task: TaskSpec,
        context: ExecutionContext,
        args: list[str],
        target: str,
        parser: str,
        phase: str,
    ) -> tuple[dict[str, Any], ExecutionDisposition]:
        """Run a browser task via BrowserExecutor."""
        if self._browser_executor is None:
            tr: dict[str, Any] = {
                "kind": "browser", "task_id": task.id,
                "url": str(task.params.get("url", target)),
                "dry_run": context.dry_run, "outcome": "fundamental",
                "phase": phase, "obs": {},
                "error": "browser executor not configured",
            }
            return tr, ExecutionDisposition.TOOL_UNAVAILABLE

        result = await self._browser_executor.run(task, context.evidence)
        ep_data = result.episode.data
        outcome_value = result.episode.outcome.value
        task_error = ep_data.get("error")
        disposition = (
            ExecutionDisposition.EXECUTED_SUCCESS
            if outcome_value == "success" and not task_error
            else ExecutionDisposition.EXECUTED_FAILURE
        )
        tr = {
            "kind": "browser",
            "task_id": task.id,
            "url": str(task.params.get("url", target)),
            "dry_run": context.dry_run,
            "outcome": outcome_value,
            "phase": phase,
            "obs": ep_data.get("obs", {}),
            "error": task_error,
        }
        return tr, disposition
