# graph_state.py
# ApexGraphState TypedDict holding only JSON-serializable engagement fields for the APEX LangGraph; no infrastructure objects in state payloads.
"""ApexGraphState TypedDict for the APEX multi-phase engagement LangGraph.

This is a **separate** state shape from memfabric.coordination.graph_state.
TurnState — see CLAUDE.md Section 11.3 for why apex_host needs its own
StateGraph. State holds ONLY JSON-serializable primitives: MemoryAPI, the
tool registry, executors, planners, and LLM client objects are injected via
closures in graph.build_apex_graph(); they must NEVER appear as state
payloads (mirrors memfabric Invariant 1 and Invariant 7).
"""
from __future__ import annotations

import operator
from typing import Annotated, Any

from typing_extensions import TypedDict


class ApexGraphState(TypedDict):
    """Checkpoint-serialisable state for one APEX engagement run.

    ``findings`` and ``error_episodes`` and ``planner_decisions`` use
    ``operator.add`` so each turn's nodes append rather than replace.
    Every other field is overwritten per turn — this is intentional: context
    is retrieved and scoped fresh each turn (memfabric Invariant 5), never
    accumulated.

    New fields added for the complete planning loop
    -----------------------------------------------
    planner_decisions:
        Append-only audit log of every planner invocation this run.
        Each entry is a ``PlanDecision.to_dict()`` dict.  Used by the run
        report, JSON export, and the Reflector to learn from both LLM-backed
        and deterministic decisions.

    tool_results:
        List of all tool-result dicts produced by the current turn's agent
        node (one per task when multiple tasks ran concurrently).  ``None``
        when the agent abandoned or when only ``last_tool_result`` is set for
        backward-compatible single-task turns.

    repair_count:
        Number of repair attempts consumed this turn.  Reset to 0 by
        ``reflect_or_continue`` at the end of every turn.  The
        ``repair_agent`` node increments it; ``route_after_write`` gates
        further repair attempts based on ``config.max_repair_attempts``.
    """

    run_id: str
    target: str
    phase: str
    goal: str
    current_task: dict[str, Any] | None
    evidence_summary: str
    findings: Annotated[list[dict[str, Any]], operator.add]
    # error_episodes accumulates one summary dict per non-success turn so the
    # report can surface error counts and samples without querying the episodic store.
    error_episodes: Annotated[list[dict[str, Any]], operator.add]
    last_tool_result: dict[str, Any] | None
    last_error: str | None
    completed: bool
    turn_count: int
    # Complete planning loop fields
    planner_decisions: Annotated[list[dict[str, Any]], operator.add]
    tool_results: list[dict[str, Any]] | None
    repair_count: int
    # Policy gate audit log: one entry per task reviewed by PolicyAdvisor.
    # Fields per entry: tool, target, phase, status, rule_name, reason.
    # Accumulated with operator.add so every turn's decisions append.
    policy_decisions: Annotated[list[dict[str, Any]], operator.add]
    # Duplicate action audit log: one entry per task skipped by the duplicate
    # action gate.  Fields per entry: fingerprint, tool, target, phase,
    # disposition, reason, meaningful_state_change.
    duplicate_actions: Annotated[list[dict[str, Any]], operator.add]
    # Checkpoint-persistent TaskRegistry snapshots.  Each entry is a
    # TaskRecord.to_dict() dict.  ``operator.add`` accumulates records across
    # turns; ``TaskRegistry.restore_from_snapshot()`` uses this to skip
    # already-completed tasks after a resume from checkpoint.
    completed_fingerprints: Annotated[list[dict[str, Any]], operator.add]
    # Infra Phase 4: lightweight per-execution backend/timeout audit log.
    # One entry per non-skipped tool_result written in write_memory, with
    # fields {tool, backend, timed_out, phase}. Distinct from the full
    # tool_result (stored verbatim in episode.data) — this accumulated list
    # exists so apex_host/eval/report.py can summarize which backend
    # ("dry-run" | "local" | "remote") executed each task and how many
    # timed out, across the whole run, without re-querying the episodic
    # store. See docs/remote-tool-backend.md "Report fields".
    execution_backend_log: Annotated[list[dict[str, Any]], operator.add]


CompiledApexGraph = Any
