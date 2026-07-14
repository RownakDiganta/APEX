# memory_node.py
# Factory for the write_memory LangGraph node: appends Episodes to the episodic store.
"""Memory-writing node factory for the APEX orchestration layer.

``make_memory_node`` returns the ``write_memory`` async LangGraph node that
creates one ``Episode`` record per tool_result and appends them all through
``MemoryAPI.apply_deltas``.  Skipped-duplicate results are never episoded
(F13 fix).  Browser outcome is derived from the browser tool_result's own
error field, not from ``state["last_error"]`` (F07 fix).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memfabric.types import Episode, Outcome

from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.completion import outcome_for

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps


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
            await deps.api.apply_deltas(episodes=[episode])

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

        result: dict[str, Any] = {}
        if error_entries:
            result["error_episodes"] = error_entries
        if backend_entries:
            result["execution_backend_log"] = backend_entries
        return result

    return write_memory
