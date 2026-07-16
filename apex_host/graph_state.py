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
    # Phase 12A (R1, Bug E): one entry per state-machine anomaly the
    # orchestration layer could not route normally — currently populated
    # only by ``unknown_phase_agent`` when GlobalPlanner produces a phase
    # value with no registered dispatch node (e.g. a not-yet-routable
    # ApexPhase member). Fields per entry: {phase, turn_count, reason}.
    # An unroutable phase must never disappear silently into END — this
    # field is the durable, checkpoint-visible record of why it stopped.
    diagnostic_events: Annotated[list[dict[str, Any]], operator.add]
    # Phase 12B: one entry per telnet_access/ssh_access/ftp_access tool_result
    # written in write_memory, with fields {protocol, target, port, username,
    # success, authenticated, error_category, timed_out, phase} — never the
    # password. Lets apex_host/eval/report.py summarize attempted /
    # authenticated / rejected / timed_out / connection_failed / protocol_error
    # counts per protocol across the whole run without re-querying the
    # episodic store. See docs/credential-validation.md "Reporting".
    credential_validation_log: Annotated[list[dict[str, Any]], operator.add]
    # Phase 12C — canonical engagement outcome (apex_host.orchestration.outcome
    # .EngagementOutcome value; "" until the terminating turn). Overwrite,
    # not accumulated: set exactly once, on the single turn that terminates
    # the engagement, either by an upstream node (planner_failure/
    # parser_failure/memory_failure/unknown_phase) or by reflect_or_continue
    # itself (validated_access/goal_completed/max_turns_exhausted/
    # phase_budget_exhausted/no_actionable_task/duplicate_task_stall/
    # policy_blocked). See docs/engagement-outcomes.md.
    outcome: str
    # Human-readable reason paired with `outcome` — "" until termination.
    termination_reason: str
    # The phase active at the moment termination was decided (captured
    # before `phase` itself is overwritten to "done") — "" until termination.
    termination_phase: str
    # Set only when `outcome` is one of the three stall-derived values
    # (duplicate_task_stall / no_actionable_task / policy_blocked); mirrors
    # `termination_reason` for that case specifically so report consumers
    # can distinguish "stalled" terminations without string-matching
    # `outcome`. "" otherwise.
    stall_reason: str
    # Phase 13 — privilege-escalation planning summary. Refreshed every
    # priv_esc_agent turn from a fresh EKG read (apex_host.orchestration
    # .dispatch_node.make_priv_esc_node); every other node simply omits
    # these keys, so LangGraph's partial-update semantics preserve the last
    # known snapshot across non-priv_esc turns and after termination. This
    # is a derived VIEW over priv_esc_opportunity EKG nodes — never a
    # second, independent store of opportunity data (memfabric Invariant 1).
    # privilege_state: a PrivilegeEnumerationStatus value ("" before the
    # first priv_esc turn).
    privilege_state: str
    # privilege_summary: {opportunity_count, categories (dict[str,int]),
    # attempted_count, exhausted_count, remaining_count}.
    privilege_summary: dict[str, Any]
    # opportunity_ids / attempted_opportunities: EKG node IDs of every
    # recorded priv_esc_opportunity / the subset already attempted.
    opportunity_ids: list[str]
    attempted_opportunities: list[str]
    # enumeration_complete: True once PrivilegeEnumerationStatus is
    # `exhausted` (see apex_host.planners.priv_esc_opportunities
    # .build_privilege_escalation_state).
    enumeration_complete: bool
    # Phase 14 — web-exploitation-planning / browser-reasoning summary.
    # Refreshed every browser_agent turn from a fresh EKG read
    # (apex_host.orchestration.dispatch_node.make_browser_node); every
    # other node simply omits this key, so LangGraph's partial-update
    # semantics preserve the last known snapshot (mirrors
    # `privilege_summary` above). Derived VIEW over endpoint/form/tech/
    # web_opportunity EKG nodes — never a second, independent store
    # (memfabric Invariant 1). Shape: {pages_visited, forms_discovered,
    # technologies_detected, opportunity_count, categories (dict[str,int]),
    # login_state ("anonymous"|"authenticated")}.
    web_session_state: dict[str, Any]


CompiledApexGraph = Any
