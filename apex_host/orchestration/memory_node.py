# memory_node.py
# Factory for the write_memory LangGraph node: appends Episodes to the episodic store.
"""Memory-writing node factory for the APEX orchestration layer.

``make_memory_node`` returns the ``write_memory`` async LangGraph node that
creates one ``Episode`` record per tool_result and appends them all through
``MemoryAPI.apply_deltas``.  Skipped-duplicate results are never episoded
(F13 fix).  Browser outcome is derived from the browser tool_result's own
error field, not from ``state["last_error"]`` (F07 fix).

Phase 12C: an ``apply_deltas`` exception here is caught and converted into
an ``EngagementOutcome.memory_failure`` upstream-preset outcome (see
``apex_host.orchestration.outcome`` module docstring, precedence level 2)
rather than propagating and crashing ``graph.ainvoke()``. Any tool_results
already written before the failure keep their normal episodes and error
entries — only the remaining, unwritten results are skipped.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from memfabric.types import Episode, Outcome

from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.completion import outcome_for
from apex_host.orchestration.outcome import EngagementOutcome

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps

logger = logging.getLogger(__name__)


def make_memory_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``write_memory`` async node bound to *deps*."""

    async def write_memory(state: "ApexGraphState") -> dict[str, Any]:
        raw_results = state.get("tool_results")
        results_to_write: list[dict[str, Any]] = (
            raw_results if raw_results
            else ([state["last_tool_result"]] if state["last_tool_result"] else [])
        )
        if not results_to_write:
            return {}

        error_entries: list[dict[str, Any]] = []
        backend_entries: list[dict[str, Any]] = []
        credential_entries: list[dict[str, Any]] = []
        latency_entries: list[dict[str, Any]] = []
        for tr in results_to_write:
            # F13: skipped-duplicate tasks never executed — skip episode creation.
            if tr.get("skipped_duplicate"):
                continue

            # F07: derive browser outcome from this tool_result's own error field.
            if tr.get("kind") == "browser":
                o = Outcome.success if not tr.get("error") else Outcome.fundamental
            else:
                o = outcome_for(int(tr.get("returncode", 0) or 0), tr.get("error"))

            episode = Episode(
                agent=f"apex.{state['phase']}",
                action=(
                    f"{tr.get('tool', tr.get('kind', 'unknown'))} "
                    f"{tr.get('target', tr.get('url', ''))}"
                ).strip(),
                outcome=o,
                data=tr,
                task_id=tr.get("task_id"),
                phase=state["phase"],
            )
            try:
                await deps.api.apply_deltas(episodes=[episode])
            except Exception as exc:
                logger.error("apply_deltas failed in write_memory: %s", exc)
                failure_result: dict[str, Any] = {
                    "outcome": EngagementOutcome.memory_failure.value,
                    "termination_reason": f"{type(exc).__name__}: {exc}",
                    "termination_phase": state["phase"],
                }
                if error_entries:
                    failure_result["error_episodes"] = error_entries
                if backend_entries:
                    failure_result["execution_backend_log"] = backend_entries
                if credential_entries:
                    failure_result["credential_validation_log"] = credential_entries
                if latency_entries:
                    failure_result["task_latency_log"] = latency_entries
                return failure_result

            if o != Outcome.success:
                error_entries.append({
                    "outcome": o.value,
                    "tool": tr.get("tool", tr.get("kind", "unknown")),
                    "error": tr.get("error") or state.get("last_error"),
                    "phase": state["phase"],
                })

            # Infra Phase 4: only generic-command results carry a "backend"
            # tag (from ToolBackend.execute()) — telnet/browser tool_results
            # use TelnetExecutor/BrowserExecutor directly and have no
            # "backend" key, so they are naturally excluded here.
            backend = tr.get("backend")
            if backend:
                backend_entries.append({
                    "tool": tr.get("tool", "unknown"),
                    "backend": backend,
                    "timed_out": bool(tr.get("timed_out", False)),
                    "phase": state["phase"],
                })

            # Phase 17: task-latency audit log for the benchmarking subsystem
            # (apex_host/eval/benchmark.py). Only tool_results that carry a
            # real, measured "duration_seconds" key contribute an entry —
            # TelnetExecutor (byte-for-byte unchanged since Phase 12B),
            # BrowserExecutor, and PrivEscAnalysisExecutor (zero-I/O) never
            # set this key, so they are naturally excluded rather than
            # contributing a fabricated zero.
            duration = tr.get("duration_seconds")
            if duration is not None:
                latency_entries.append({
                    "tool": tr.get("tool", tr.get("kind", "unknown")),
                    "phase": state["phase"],
                    "duration_seconds": float(duration),
                })

            # Phase 12B: credential-validation audit log — never the password.
            # ssh_access/ftp_access tool_results carry protocol/success/
            # authenticated/error_category explicitly (set by
            # TaskDispatcher._credential_result_to_tr). telnet_access
            # predates that shape (Phase 12A invariant: unchanged), so its
            # entry is derived best-effort from the fields it does have.
            tool_name = str(tr.get("tool", ""))
            if tool_name in ("telnet_access", "ssh_access", "ftp_access"):
                success = bool(tr.get("success", o == Outcome.success))
                default_protocol = {
                    "telnet_access": "telnet", "ssh_access": "ssh", "ftp_access": "ftp",
                }[tool_name]
                protocol = str(tr.get("protocol") or default_protocol)
                error_category = str(
                    tr.get("error_category") or ("success" if success else "unknown")
                )
                credential_entries.append({
                    "protocol": protocol,
                    "target": str(tr.get("target", "")),
                    "port": str(tr.get("port", "")),
                    "username": str(tr.get("username", "")),
                    "success": success,
                    "authenticated": bool(tr.get("authenticated", success)),
                    "error_category": error_category,
                    "timed_out": bool(tr.get("timed_out", False)),
                    "phase": state["phase"],
                })

        result: dict[str, Any] = {}
        if error_entries:
            result["error_episodes"] = error_entries
        if backend_entries:
            result["execution_backend_log"] = backend_entries
        if credential_entries:
            result["credential_validation_log"] = credential_entries
        if latency_entries:
            result["task_latency_log"] = latency_entries
        return result

    return write_memory
