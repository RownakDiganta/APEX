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

if TYPE_CHECKING:
    from apex_host.agents.browser_executor import BrowserExecutor
    from apex_host.agents.ftp_executor import FTPExecutor
    from apex_host.agents.ssh_executor import SSHExecutor
    from apex_host.agents.telnet_executor import TelnetExecutor
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
    ) -> None:
        self._advisor = advisor
        self._registry = task_registry
        self._config = config
        self._run_command_fn = run_command_fn
        self._telnet_executor = telnet_executor
        self._browser_executor = browser_executor
        self._ssh_executor = ssh_executor
        self._ftp_executor = ftp_executor

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
        executor_domain = str(task.params.get("executor_domain", phase))
        fingerprint = task_fingerprint(phase, tool, args, target, parser, executor_domain)

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
            logger.info(
                "dispatcher: duplicate [%s] fingerprint=%s prior=%s",
                phase, fingerprint, prior_task_id,
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

        try:
            if tool == "browser":
                tr_dict, disposition = await self._run_browser(task, context, args, target, parser, phase)
            elif tool == "telnet_access":
                tr_dict, disposition = await self._run_telnet(task, context, args, target, parser, phase)
            elif tool == "ssh_access":
                tr_dict, disposition = await self._run_ssh(task, context, args, target, parser, phase)
            elif tool == "ftp_access":
                tr_dict, disposition = await self._run_ftp(task, context, args, target, parser, phase)
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

        # ── 6. Record final status ────────────────────────────────────────
        final_status = (
            TaskStatus.COMPLETED if disposition.is_success
            else TaskStatus.FAILED_RETRYABLE if disposition.is_retryable
            else TaskStatus.FAILED_TERMINAL
        )
        await self._registry.update_status(
            fingerprint, final_status,
            disposition=disposition.value,
            retry_count=context.retry_count,
        )

        retry_decision = classify_retry(disposition, tr_dict.get("error") or "")
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
        }
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
