# report.py
# Builds a human-readable run report from final graph state, EKG, and episodes.
"""Run-report builder for APEX engagements.

All inputs are pure data (no async, no MemoryAPI calls).  The runner
collects the required data then passes it here for formatting and export.

Public API:
    build_report(final_state, subgraph, config, ...) -> RunReport
    format_text(report) -> str          — human-readable string
    to_json_dict(report) -> dict        — JSON-serialisable dict
    write_report_json(report, path)     — write JSON to disk

Phase 12C — canonical outcome integration
------------------------------------------
``RunReport.outcome``/``success``/``termination_reason``/``termination_phase``/
``termination_turn``/``stall_reason`` are a direct projection of
``apex_host.orchestration.outcome.EngagementOutcome`` — the SAME model the
compiled graph itself uses to decide when and why an engagement ends (see
that module's docstring for the full precedence rules). This module never
computes a second, independent classification: ``status`` (the older,
four-value string: "success"/"stopped_max_turns"/"stopped_error"/
"abandoned") and ``completed_successfully`` are both derived FROM the
canonical outcome via ``legacy_status_for()``/``is_success_outcome()``, not
computed independently.

``final_state["outcome"]`` is set by the graph itself on every real
engagement run. ``_derive_outcome_from_state()`` provides a best-effort
fallback ONLY for a ``final_state`` that predates Phase 12C (never had the
``outcome`` field populated — e.g. hand-constructed test fixtures) so
``build_report()`` remains backward compatible; it reproduces the exact
conditions the old ``_determine_status()`` used, mapped onto
``EngagementOutcome`` values, and is never consulted when the graph already
supplied a real outcome.
"""
from __future__ import annotations

import collections
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apex_host.eval.findings import deduplicate_findings
from apex_host.eval.report_invariants import check_report_invariants
from apex_host.orchestration.outcome import (
    EngagementOutcome,
    is_success_outcome,
    legacy_status_for,
)
from apex_host.planners.priv_esc_opportunities import (
    ENUM_COMMANDS,
    already_run_commands,
    evidence_from_subgraph,
    opportunities_from_subgraph,
    rank_opportunities,
)
from apex_host.planners.web_opportunities import (
    opportunities_from_subgraph as web_opportunities_from_subgraph,
    rank_opportunities as rank_web_opportunities,
    technologies_from_subgraph,
    visited_urls_from_subgraph,
)
from apex_host.planners.workflow_orchestration import (
    derive_sessions_from_subgraph,
    derive_workflows_from_subgraph,
    rank_sessions,
    rank_workflows,
    workflow_recommendations_from_workflows,
)
from apex_host.planners.experience_replay import (
    experiences_from_subgraph,
    rank_experiences,
)
from apex_host.planners.access_capabilities import capability_type_label
from apex_host.planners.objective import objective_report_fields
from apex_host.eval.benchmark import compute_benchmark, benchmark_to_json_dict, format_benchmark_text
from apex_host.eval.evaluation import build_htb_evaluation, evaluation_to_json_dict, format_evaluation_text

if TYPE_CHECKING:
    from memfabric.types import SubgraphView
    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState

_SEP = "═" * 60

#: Phase 20 — the two capability_type values counted toward the Direct
#: File Read summary below (mirrors apex_host.orchestration.memory_node's
#: identical constant — kept separate to avoid a report -> orchestration
#: import for a two-string set).
_DIRECT_FILE_READ_CAPABILITY_TYPES = frozenset({"arbitrary_file_read", "api_file_read"})

#: Phase 21 — the three capability_type values counted toward the Bounded
#: Command summary below (mirrors apex_host.orchestration.memory_node's
#: _COMMAND_CAPABILITY_TYPES — kept separate for the same reason as above).
_COMMAND_CAPABILITY_TYPES = frozenset({"local_shell", "remote_command", "web_command"})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RunReport:
    """Structured summary of one APEX engagement run."""

    target: str
    mode: str                           # "dry-run" | "live"
    turns_used: int
    completed: bool
    # status: "success" | "stopped_max_turns" | "stopped_error" | "abandoned"
    status: str
    completed_successfully: bool        # True only when terminal success condition exists
    # final_phase: the raw terminal ApexGraphState["phase"] value — always
    # "done" once completed=True. Phase 3: kept unchanged for backward
    # compatibility; final_runtime_state (below) is the same value under a
    # clearer name — the two are guaranteed to always be equal.
    final_phase: str
    # phases_reached: Phase 3 CORRECTED semantic (report_schema_version 2).
    # Before this phase, this was derived from state["findings"]' own
    # "phase" field — a phase the planner entered but which never produced
    # a parseable node delta (e.g. CredentialPlanner returning an
    # AbandonSignal on a host-only graph) was silently absent, even though
    # planner_decisions and termination_phase both showed it was entered.
    # This field is now IDENTICAL to phases_attempted (see below) — kept
    # under its original name for backward compatibility. See
    # docs/report-schema.md "Schema version 2" for the full migration note.
    phases_reached: list[str]
    finding_count: int
    # findings: the DEDUPLICATED, unique-entity view (Phase 3) — one entry
    # per unique finding "id" (the EKG node ID), never one entry per raw
    # observation. See apex_host.eval.findings.deduplicate_findings and
    # `observation_count` below for the raw, pre-dedup count.
    findings: list[dict[str, Any]]
    node_counts: dict[str, int]         # by node type
    edge_counts: dict[str, int]         # by edge type
    total_nodes: int
    total_edges: int
    episodes_by_outcome: dict[str, int] # derived or runner-supplied
    script_error_count: int             # turns that produced script_error outcome
    fixable_count: int                  # turns that produced fixable outcome
    fundamental_count: int              # turns that produced fundamental outcome
    error_samples: list[str]            # up to 3 error strings from failed turns
    evidence_samples: list[str]         # text snippets from last evidence
    last_error: str | None
    # Phase 25 — increment whenever a field is added, removed, or its
    # meaning changes in a backward-incompatible way. Exposed in both
    # format_text() and to_json_dict() so a downstream consumer (a CI
    # pipeline, a comparison tool) can detect an incompatible report shape
    # rather than silently misreading a renamed/missing field.
    #
    # Phase 3 (post-live-test debugging) bumped this to "2": `findings`
    # changed from a raw, possibly-repeated observation list to a
    # deduplicated unique-entity list; `phases_reached`'s derivation
    # changed from "phases with a parseable finding" to "phases the
    # planner actually entered". Every OTHER field on this dataclass is
    # purely additive (new fields, all with safe defaults) — a schema-v1
    # consumer reading a schema-v2 JSON export will not KeyError on
    # missing fields, but should not assume `findings`/`phases_reached`
    # still mean what they meant under v1. See docs/report-schema.md
    # "Schema version 2 migration" for the full compatibility note.
    report_schema_version: str = "2"
    planner_decisions: list[dict[str, Any]] = field(default_factory=list)
    # Accumulated planner audit log: one PlanDecision.to_dict() per invocation.

    # Policy gate summary — derived from state["policy_decisions"].
    policy_approved_count: int = 0
    policy_blocked_count: int = 0
    policy_needs_review_count: int = 0
    last_blocked_reasons: list[str] = field(default_factory=list)
    # Raw per-task policy decision audit log (one entry per reviewed task).
    policy_decisions: list[dict[str, Any]] = field(default_factory=list)

    # Knowledge seeding summary — populated when seed_all() ran with a
    # knowledge_root and returned a _promotion key.
    # seeding_counts: per-family record counts (family → staged count).
    # seeding_promotion: PromotionSummary.to_dict() fields.
    # policy_source: string describing which policy file/fallback was used.
    seeding_counts: dict[str, Any] = field(default_factory=dict)
    seeding_promotion: dict[str, Any] = field(default_factory=dict)
    policy_source: str = ""

    # Knowledge-initialization cache summary (Phase 4 — post-live-test
    # debugging) — populated from seed_results["_init"]
    # (KnowledgeInitReport.to_dict()) when compiled knowledge was
    # configured. Empty dict when no compiled knowledge was configured at
    # all (e.g. neither --knowledge-root nor any per-family path was set).
    knowledge_init: dict[str, Any] = field(default_factory=dict)

    # LLM call budget summary — populated from LLMBudgetTracker.to_dict() when
    # --use-llm is set.  Empty dict when running in deterministic mode.
    llm_usage: dict[str, Any] = field(default_factory=dict)

    # Duplicate action summary — populated from state["duplicate_actions"].
    # duplicate_action_count: total tasks skipped by the duplicate gate.
    # duplicate_action_entries: the raw audit entries (one per skipped task).
    duplicate_action_count: int = 0
    duplicate_action_entries: list[dict[str, Any]] = field(default_factory=list)

    # Infra Phase 4 — tool-execution backend summary, populated from
    # state["execution_backend_log"]. backend_usage counts executions per
    # backend identifier ("dry-run" | "local" | "remote"); timed_out_count
    # is the number of executions that hit their timeout. Telnet/browser
    # tool_results carry no "backend" tag and are not represented here (see
    # apex_host/orchestration/memory_node.py).
    backend_usage: dict[str, int] = field(default_factory=dict)
    timed_out_count: int = 0

    # Phase 12B — credential-validation summary, populated from
    # state["credential_validation_log"]. credential_attempts_by_protocol
    # counts every telnet/ssh/ftp attempt per protocol; credential_outcome_counts
    # breaks every attempt down by error_category (includes "success"). Never
    # contains a password — see apex_host/orchestration/memory_node.py.
    credential_attempts_by_protocol: dict[str, int] = field(default_factory=dict)
    credential_outcome_counts: dict[str, int] = field(default_factory=dict)
    credential_validation_entries: list[dict[str, Any]] = field(default_factory=list)

    # Phase 12C — canonical engagement outcome. `outcome`/`success` are the
    # single source of truth for how and why this run ended; `status` and
    # `completed_successfully` above are derived FROM these, never computed
    # independently (see module docstring). `termination_reason`/
    # `termination_phase`/`termination_turn` describe exactly where and why;
    # `stall_reason` is set only for the three stall-derived outcomes
    # (duplicate_task_stall / no_actionable_task / policy_blocked).
    outcome: str = ""
    success: bool = False
    termination_reason: str = ""
    termination_phase: str = ""
    termination_turn: int = 0
    stall_reason: str = ""
    # no_action_count: turns whose planner produced zero selected tasks
    # (derived from `planner_decisions`, which browser-phase turns never
    # populate — see apex_host/orchestration/dispatch_node.py).
    no_action_count: int = 0
    # access_summary: {"validated": bool, "protocol": str|None,
    # "username": str|None} — never a password. Empty username/protocol
    # when validated is False.
    access_summary: dict[str, Any] = field(default_factory=dict)

    # Phase 18 — user-flag objective summary. Always derived directly from
    # the FINAL subgraph's `objective`/`objective_evidence` nodes (see
    # apex_host.planners.objective.objective_report_fields) — never a
    # second, independent classification of "did we succeed." A validated
    # access_state (see access_summary above) is an important intermediate
    # milestone but is NEVER, by itself, benchmark success — only
    # `objective_verified` (equivalently `success` above, since
    # `EngagementOutcome.user_flag_verified` is the sole success outcome)
    # means the objective was actually retrieved and confirmed. The raw
    # flag value itself is never present anywhere on this dataclass —
    # `objective_evidence_digest`/`objective_evidence_redacted` are the
    # only representations, per docs/user-flag-objective.md.
    objective_type: str = ""
    objective_status: str = ""
    objective_verified: bool = False
    objective_attempts: int = 0
    objective_evidence_digest: str = ""
    objective_evidence_redacted: str = ""
    objective_evidence_source_path: str = ""
    objective_evidence_access_identity: str = ""
    objective_verification_timestamp: str = ""
    # Access-capability refactor — which AccessCapability transport type
    # produced the verified evidence (e.g. "ssh_command"). Deliberately a
    # capability-type label, never a "Transport: SSH" framing — a future
    # adapter (Telnet, arbitrary file read, ...) needs no change here or in
    # any rendering logic below, only a new entry in
    # apex_host.planners.access_capabilities.CAPABILITY_TYPE_LABELS.
    objective_evidence_capability_type: str = ""

    # Phase 20 — direct-file-read capability summary. Capability/adapter
    # counts are derived directly from the final subgraph's
    # access_capability nodes (never a second, independent store); attempt/
    # blocked/verified/rejection counts come from the accumulated
    # state["direct_file_read_log"] (mirrors credential_validation_log's
    # own convention — the EKG has no node-level representation of a
    # *blocked* or *rejected* attempt). Never the raw candidate output.
    direct_file_read_capabilities_derived: int = 0
    direct_file_read_adapters_registered: int = 0
    direct_file_read_attempts: int = 0
    direct_file_read_blocked_attempts: int = 0
    direct_file_read_verified_count: int = 0
    direct_file_read_rejected_oversized: int = 0
    direct_file_read_rejected_cross_origin: int = 0

    # Phase 21 — bounded command-execution capability summary. Same
    # derivation convention as the Direct File Read summary above:
    # capability/adapter counts from the final subgraph's access_capability
    # nodes; attempt/blocked/verified/timeout/oversized counts from the
    # accumulated state["bounded_command_log"].
    # unavailable_strategies = capabilities_derived - adapters_registered
    # (bounded at >= 0) — capabilities whose metadata exists but which
    # never got a runtime adapter registered.
    bounded_command_capabilities_derived: int = 0
    bounded_command_adapters_registered: int = 0
    bounded_command_unavailable_strategies: int = 0
    bounded_command_attempts: int = 0
    bounded_command_blocked_attempts: int = 0
    bounded_command_timeouts: int = 0
    bounded_command_oversized: int = 0
    bounded_command_verified_count: int = 0

    # Phase 23 — deterministic capability-discovery summary. Aggregated
    # from accumulated state["capability_discovery_log"] (one
    # CapabilityDiscoveryResult.to_dict() per turn that emitted at least
    # one CapabilityEvidence — see apex_host.capabilities.discovery and
    # apex_host.orchestration.parsing_node). Capability-derivation itself
    # is never a benchmark success condition — verified user flag remains
    # the only exit-code-0 outcome regardless of these counts.
    capability_discovery_evidence_evaluated: int = 0
    capability_discovery_evidence_accepted: int = 0
    capability_discovery_evidence_rejected: int = 0
    capability_discovery_duplicate_evidence: int = 0
    capability_discovery_capabilities_derived: int = 0
    capability_discovery_capabilities_updated: int = 0
    capability_discovery_adapters_registered: int = 0
    capability_discovery_validated_but_unavailable: int = 0
    capability_discovery_provider_failures: int = 0

    # Phase 13 — privilege-escalation planning summary, derived from
    # final_state["privilege_summary"]/["privilege_state"]/["enumeration_complete"]
    # (populated by apex_host.orchestration.dispatch_node.make_priv_esc_node
    # on every priv_esc turn). A planning/reasoning summary only — never
    # reflects an executed exploit or an actually-elevated shell.
    privilege_state: str = ""
    privilege_opportunity_count: int = 0
    privilege_categories: dict[str, int] = field(default_factory=dict)
    privilege_attempted_count: int = 0
    privilege_exhausted_count: int = 0
    privilege_remaining_count: int = 0
    privilege_enumeration_complete: bool = False
    # Up to 5 recommended_next_action strings from the highest-ranked
    # remaining (non-exhausted) opportunities — advisory text for a human
    # operator, never an executable command APEX itself would run.
    privilege_recommendations: list[str] = field(default_factory=list)

    # Phase 13B — safe privilege enumeration & evidence collection summary.
    # All derived directly from the final subgraph's priv_esc_evidence /
    # priv_esc_opportunity nodes (never from the possibly-one-turn-stale
    # state snapshot) except enum_commands_failed, which is derived from
    # error_episodes (a failed enumeration command produces no EKG node at
    # all — see apex_host/parsers/priv_esc_parser.py::parse_enumeration).
    enum_commands_completed: int = 0
    enum_commands_failed: int = 0
    enum_evidence_count: int = 0
    enum_evidence_categories: dict[str, int] = field(default_factory=dict)
    # Opportunities whose source_tool is "priv_esc_enum" specifically (as
    # opposed to the Phase 13A searchsploit/analytical producers).
    enum_new_opportunities: int = 0
    # Duplicate priv_esc-phase tasks the dispatcher's fingerprint gate
    # prevented from executing a second time (a real, observed count from
    # state["duplicate_actions"] — see apex_host.orchestration.dispatch_node).
    enum_duplicate_opportunities_avoided: int = 0
    # True once every command in ENUM_COMMANDS has been recorded as evidence
    # for this target — never True if enumeration never started.
    enum_completeness: bool = False

    # Phase 14 — web exploitation planning & browser reasoning summary. All
    # derived directly from the final subgraph (never from the possibly
    # one-turn-stale state["web_session_state"] snapshot) except
    # web_duplicate_pages_avoided, which has no EKG representation (a
    # duplicate-skipped browse task produces no node at all).
    web_pages_visited: int = 0
    web_forms_discovered: int = 0
    web_technologies_detected: int = 0
    web_technology_names: list[str] = field(default_factory=list)
    web_authentication_portals: int = 0
    web_opportunity_count: int = 0
    web_opportunity_categories: dict[str, int] = field(default_factory=dict)
    web_duplicate_pages_avoided: int = 0
    # Up to 5 recommended_next_action strings from the highest-ranked
    # web opportunities — advisory text for a human operator, never an
    # executable action APEX itself would take.
    web_recommendations: list[str] = field(default_factory=list)

    # Phase 15 — multi-step exploitation orchestration summary. Every field
    # is derived directly from the final subgraph at report-build time
    # (never from the possibly-one-turn-stale state["workflow_summary"]
    # snapshot), using the REAL final engagement_completed/engagement_outcome
    # values so abandoned/stalled classification is always accurate — unlike
    # the live per-turn sync, which can never know in advance which turn
    # terminates the engagement.
    workflow_count: int = 0
    workflows_completed: int = 0
    workflows_blocked: int = 0
    workflows_running: int = 0
    workflows_stalled: int = 0
    workflows_abandoned: int = 0
    # Average completion_percentage across all applicable workflows; 0.0
    # when no workflow's prerequisites were ever met this engagement.
    workflow_completion_percentage: float = 0.0
    # One entry per session: {"kind", "status", "detail"} — never a
    # password/cookie value (see apex_host.types.Session).
    active_sessions: list[dict[str, Any]] = field(default_factory=list)
    # One entry per applicable workflow: {"workflow", "objective", "status",
    # "steps": [{"name", "status"}, ...]} — the full reasoning chain for
    # transparency/audit, not just the summary counts above.
    reasoning_chains: list[dict[str, Any]] = field(default_factory=list)
    # Up to 5 advisory recommendation strings — never an executable command.
    workflow_recommendations: list[str] = field(default_factory=list)

    # Phase 16 — adaptive learning / experience-replay summary. The
    # experience listing/count/category-breakdown fields are derived
    # directly from the final subgraph at report-build time (same
    # convention as every other Phase 13-15 section above). Only
    # ``learning_experiences_created``/``learning_experiences_reused``/
    # ``learning_replay_hits`` are an exception — a point-in-time
    # before/after delta computed once by the reflection pass itself
    # (apex_host.runtime.ApexRuntime.run()) and threaded through via
    # ``final_state["learning_summary"]``, mirroring the documented
    # ``enum_duplicate_opportunities_avoided`` exception in Phase 13B —
    # a single post-hoc EKG snapshot cannot recover a delta.
    learning_experience_count: int = 0
    learning_experience_categories: dict[str, int] = field(default_factory=dict)
    learning_experiences_created: int = 0
    learning_experiences_reused: int = 0
    learning_replay_hits: int = 0
    learning_repeated_failures: int = 0
    # Up to 5 advisory recommendation strings from the highest-ranked
    # experiences — never an executable command, never overrides a planner.
    learning_recommendations: list[str] = field(default_factory=list)

    # Phase 17 — benchmarking subsystem raw inputs. All computed *metrics*
    # (planner_efficiency, duplicate_avoidance_percentage, browser_coverage,
    # credential_success_rate, privilege_opportunity_density,
    # replay_usefulness, average_task_latency_seconds, evidence_density,
    # graph_growth_rate) are deliberately NOT stored as separate RunReport
    # fields — they are pure, single-source-of-truth functions of fields
    # already on this dataclass (see apex_host/eval/benchmark.py), computed
    # on demand by format_text()/to_json_dict() via
    # ``compute_benchmark(report, ...)``. Only the two genuinely-external
    # wall-clock measurements (which nothing on this dataclass can derive)
    # and the raw per-task latency log are stored here.
    task_latency_log: list[dict[str, Any]] = field(default_factory=list)
    benchmark_total_runtime_seconds: float = 0.0
    benchmark_report_generation_seconds: float = 0.0

    # Phase 17 — HTB evaluation-mode metadata. Operator-supplied, never
    # inferred from the target IP or EKG content (CLAUDE.md §13.8/§13.9).
    # Every other HTBEvaluation field (services_discovered,
    # credentials_validated, web_findings, privilege_opportunities,
    # final_outcome, success) is derived from fields already on this
    # dataclass at format_text()/to_json_dict() time — see
    # apex_host/eval/evaluation.py::build_htb_evaluation. The "Evaluation
    # Summary" section/JSON block is shown only when machine_name is set.
    evaluation_machine_name: str = ""
    evaluation_difficulty: str = ""

    # ------------------------------------------------------------------
    # Phase 3 (post-live-test debugging) — execution diagnostics, finding
    # observation count, phase semantics, and report-consistency fields.
    # See docs/report-schema.md for the full design record.
    # ------------------------------------------------------------------

    # One bounded, redacted apex_host.execution.diagnostics
    # .build_execution_diagnostic() record per ACTUAL tool execution
    # (never for a skipped-duplicate or repair_no_change non-execution).
    # This is what a report needs to diagnose a specific failed execution
    # — returncode, a bounded/redacted stderr sample, timeout state, the
    # unified diagnostic_category (apex_host.execution.error_classifier),
    # and the tool-specific error_category when a finer-grained tool
    # classifier (e.g. nmap's) already ran. Never the complete raw output.
    execution_diagnostics: list[dict[str, Any]] = field(default_factory=list)

    # observation_count: the RAW, pre-deduplication count of finding
    # observations (len(state["findings"]) before dedup) — preserved for
    # transparency even though `findings`/`finding_count` above are now
    # the deduplicated, unique-entity view. A report showing
    # observation_count=6, finding_count=1 tells the whole story: one
    # real entity, observed six times.
    observation_count: int = 0

    # Phase semantics (see module docstring "Phase semantics" and
    # docs/report-schema.md for the full definitions):
    # - phases_attempted: every phase whose own agent node actually ran
    #   this engagement (derived from planner_decisions' "phase" field,
    #   union termination_phase) — regardless of whether that phase
    #   selected or executed any task.
    # - phases_entered: identical to phases_attempted in this
    #   architecture. Documented, deliberate choice: APEX's graph routes
    #   directly into each selected phase's own agent node — there is no
    #   "planned but not entered" distinction to represent separately
    #   (see docs/report-schema.md). Kept as a separate field name for
    #   forward compatibility and because the requirement that motivated
    #   this phase named both explicitly.
    # - phases_completed: phases_attempted MINUS termination_phase — every
    #   attempted phase other than the one the engagement was still in
    #   when it stopped is considered to have been left behind
    #   (completed), matching this architecture's mostly-monotonic phase
    #   ladder (GlobalPlanner never regresses to an earlier phase).
    phases_attempted: list[str] = field(default_factory=list)
    phases_entered: list[str] = field(default_factory=list)
    phases_completed: list[str] = field(default_factory=list)

    # final_runtime_state: identical to final_phase (the raw terminal
    # ApexGraphState["phase"] value) under an explicitly clearer name —
    # "the state the RUNTIME (LangGraph) ended in", as distinct from
    # termination_phase ("the phase GlobalPlanner was IN when the decision
    # to terminate was made") and phases_reached/phases_attempted ("every
    # phase visited over the whole run"). final_phase is retained,
    # unchanged, for backward compatibility; the two are guaranteed equal.
    final_runtime_state: str = ""

    # completion_summary: a single, human-readable sentence disambiguating
    # `completed` / `completed_successfully` / `status` / `outcome` for an
    # operator who does not want to cross-reference four separate fields —
    # see build_report()'s construction of this string and
    # docs/report-schema.md "Top-level field semantics".
    completion_summary: str = ""

    # invariant_violations: apex_host.eval.report_invariants
    # .check_report_invariants(report)'s own output, run automatically by
    # build_report(). Empty list means the report is internally
    # consistent. NEVER causes build_report() to raise — "prefer a safe
    # diagnostic status rather than crashing after an engagement". Tests
    # that want strict enforcement call
    # apex_host.eval.report_invariants.assert_report_invariants(report)
    # explicitly.
    invariant_violations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Canonical outcome resolution
# ---------------------------------------------------------------------------

def _derive_outcome_from_state(
    node_counts: dict[str, int],
    turns_used: int,
    max_turns: int,
    error_episodes: list[dict[str, Any]],
    completed: bool,
) -> EngagementOutcome:
    """Best-effort ``EngagementOutcome`` for a ``final_state`` that predates
    Phase 12C (never had ``outcome`` populated by the graph). Reproduces the
    exact conditions the old ``_determine_status()`` used, one-to-one, so
    every pre-Phase-12C scenario still classifies identically — this is a
    fallback path, never a second independent model (see module docstring).
    """
    if "access_state" in node_counts:
        return EngagementOutcome.validated_access

    total_errors = len(error_episodes)
    if turns_used > 0 and total_errors >= turns_used and not node_counts:
        return EngagementOutcome.tool_failure

    if turns_used >= max_turns:
        return EngagementOutcome.max_turns_exhausted

    if completed:
        return EngagementOutcome.no_actionable_task

    return EngagementOutcome.max_turns_exhausted


def _resolve_outcome(
    final_state: "ApexGraphState",
    node_counts: dict[str, int],
    turns_used: int,
    max_turns: int,
    error_episodes: list[dict[str, Any]],
    completed: bool,
) -> EngagementOutcome:
    """The one place ``RunReport`` decides which ``EngagementOutcome``
    applies — the graph's own ``final_state["outcome"]`` when present
    (every real engagement run sets this), else the backward-compatible
    fallback above."""
    raw = final_state.get("outcome")
    if raw:
        try:
            return EngagementOutcome(raw)
        except ValueError:
            pass
    return _derive_outcome_from_state(node_counts, turns_used, max_turns, error_episodes, completed)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_report(
    final_state: "ApexGraphState",
    subgraph: "SubgraphView",
    config: "ApexConfig",
    *,
    episodes_by_outcome: dict[str, int] | None = None,
    evidence_samples: list[str] | None = None,
    seed_results: dict[str, Any] | None = None,
    policy_source: str = "",
    llm_budget: dict[str, Any] | None = None,
    total_runtime_seconds: float = 0.0,
    report_generation_seconds: float = 0.0,
    htb_machine_name: str | None = None,
    htb_difficulty: str | None = None,
) -> RunReport:
    """Build a ``RunReport`` from engagement outputs.

    Args:
        final_state:          The completed ``ApexGraphState`` from the graph run.
        subgraph:             EKG subgraph rooted at ``host:<target>``.
        config:               The ``ApexConfig`` for this run.
        episodes_by_outcome:  Optional pre-computed outcome counts; if omitted,
                              derived from ``final_state`` as a best-effort.
        evidence_samples:     Optional list of evidence text snippets; if omitted,
                              extracted from ``final_state["evidence_summary"]``.
        total_runtime_seconds: Phase 17 — wall-clock seconds for the whole
                              engagement, measured by the caller (e.g.
                              ``time.monotonic()`` around ``run_engagement()``).
                              Defaults to ``0.0`` when not measured.
        report_generation_seconds: Phase 17 — wall-clock seconds spent
                              building + formatting this report, measured
                              by the caller. Defaults to ``0.0``.
        htb_machine_name:     Phase 17 — operator-supplied HTB machine name.
                              When set (together with ``htb_difficulty``),
                              the report gains an "Evaluation Summary"
                              section/JSON block. Never inferred from the
                              target or EKG content.
        htb_difficulty:       Phase 17 — operator-supplied HTB difficulty
                              label (e.g. "Easy", "Medium").
    """
    # Phase 3 (post-live-test debugging): findings are deduplicated to the
    # unique-entity view here — raw_findings (the append-only observation
    # log) is preserved only as a count (observation_count below), never
    # mutated or discarded. See apex_host.eval.findings.deduplicate_findings.
    raw_findings = list(final_state["findings"])
    deduped_findings = deduplicate_findings(raw_findings)

    # planner_decisions is needed early for phase-semantics computation —
    # the SAME list is reused below for the planner-decision summary.
    planner_decisions = list(final_state.get("planner_decisions") or [])
    _termination_phase_early = str(final_state.get("termination_phase") or "")

    # Phase 3: phases_attempted/phases_entered/phases_completed replace the
    # old finding-derived phases_reached computation (a phase entered by
    # the planner but which produced no parseable finding — e.g.
    # CredentialPlanner abandoning on a host-only graph — was silently
    # absent under the old definition; see docs/report-schema.md "Schema
    # version 2 migration"). A phase counts as "attempted"/"entered" the
    # moment its own agent node ran (one planner_decisions entry recorded
    # for it), regardless of whether it selected or executed any task —
    # entering is a documented, deliberate choice distinct from "produced
    # a finding". termination_phase is always included even when no
    # planner_decisions entry exists for it (e.g. an upstream failure).
    phases_attempted = sorted(
        {str(d.get("phase")) for d in planner_decisions if d.get("phase")}
        | ({_termination_phase_early} if _termination_phase_early else set())
    )
    phases_entered = list(phases_attempted)
    phases_completed = sorted(set(phases_attempted) - {_termination_phase_early})
    phases_reached = phases_attempted

    node_counts: dict[str, int] = dict(
        collections.Counter(n.type for n in subgraph.nodes)
    )
    edge_counts: dict[str, int] = dict(
        collections.Counter(e.type for e in subgraph.edges)
    )

    if episodes_by_outcome is None:
        # Best-effort derivation without episodic store access:
        # - total_turns: every turn appended at least one episode
        # - turns_with_findings: turns that produced at least one finding
        #   (conservative undercount since multiple findings per turn is possible)
        episodes_by_outcome = {
            "total_turns": final_state["turn_count"],
            "turns_with_findings": min(
                len(final_state["findings"]), final_state["turn_count"]
            ),
        }

    if evidence_samples is None:
        evidence_samples = _samples_from_summary(final_state)

    turns_used = final_state["turn_count"]
    error_episodes: list[dict[str, Any]] = list(final_state.get("error_episodes") or [])
    script_error_count = sum(1 for e in error_episodes if e.get("outcome") == "script_error")
    fixable_count = sum(1 for e in error_episodes if e.get("outcome") == "fixable")
    fundamental_count = sum(1 for e in error_episodes if e.get("outcome") == "fundamental")
    # Phase 3 (post-live-test debugging) fix: an ordinary nonzero-exit tool
    # failure with no transport-level exception (e.g. nmap's raw-socket
    # permission error) always has error_episodes[i]["error"] == None — the
    # OLD error_samples computation (`if e.get("error")`) silently dropped
    # every such entry, so a report could show script_error_count=6 with
    # error_samples=[] (the confirmed live-test defect: "error_samples was
    # empty" / "the final report did not expose the bounded return code/
    # stderr needed to diagnose Nmap"). Falls back to the bounded, redacted
    # returncode/diagnostic_category/stderr_sample fields
    # apex_host.orchestration.memory_node now always attaches to a failed
    # entry (see that module's own error_entries.append call) whenever
    # "error" itself is empty.
    error_samples: list[str] = []
    for e in error_episodes:
        if len(error_samples) >= 3:
            break
        if e.get("error"):
            error_samples.append(str(e["error"]))
            continue
        returncode = e.get("returncode")
        category = str(e.get("diagnostic_category", "") or "")
        stderr_sample = str(e.get("stderr_sample", "") or "")
        if returncode in (0, None) and not category and not stderr_sample:
            continue
        tool = str(e.get("tool", "unknown"))
        parts = [f"{tool}: {category}" if category else tool]
        if returncode not in (0, None):
            parts.append(f"returncode={returncode}")
        if stderr_sample:
            parts.append(f"stderr={stderr_sample[:120]!r}")
        error_samples.append(" ".join(parts))

    resolved_outcome = _resolve_outcome(
        final_state, node_counts, turns_used, config.max_turns,
        error_episodes, final_state["completed"],
    )
    completed_successfully = is_success_outcome(resolved_outcome)
    status = legacy_status_for(resolved_outcome)

    # Policy gate summary
    raw_pd = list(final_state.get("policy_decisions") or [])
    policy_approved_count = sum(1 for d in raw_pd if d.get("status") == "approved")
    policy_blocked_count = sum(1 for d in raw_pd if d.get("status") == "blocked")
    policy_needs_review_count = sum(
        1 for d in raw_pd if d.get("status") == "needs_human_review"
    )
    last_blocked_reasons = [
        str(d.get("reason", ""))
        for d in raw_pd
        if d.get("status") in ("blocked", "needs_human_review") and d.get("reason")
    ][:3]

    # Extract seeding summary from seed_results (if available).
    seeding_counts: dict[str, Any] = {}
    seeding_promotion: dict[str, Any] = {}
    knowledge_init: dict[str, Any] = {}
    if seed_results:
        seeding_counts = {
            k: v for k, v in seed_results.items()
            if k not in ("_promotion", "_init") and not k.startswith("_")
        }
        promo = seed_results.get("_promotion")
        if isinstance(promo, dict):
            seeding_promotion = promo
        init_report = seed_results.get("_init")
        if isinstance(init_report, dict):
            knowledge_init = init_report

    # Duplicate action summary
    raw_dup = list(final_state.get("duplicate_actions") or [])

    # Infra Phase 4: tool-execution backend summary
    raw_backend_log = list(final_state.get("execution_backend_log") or [])
    backend_usage: dict[str, int] = {}
    timed_out_count = 0
    for entry in raw_backend_log:
        name = str(entry.get("backend", "unknown"))
        backend_usage[name] = backend_usage.get(name, 0) + 1
        if entry.get("timed_out"):
            timed_out_count += 1

    # Phase 12B: credential-validation summary (attempted / authenticated /
    # rejected / timed out / connection failed / protocol error — never a
    # password; entries themselves already never contain one).
    raw_cred_log = list(final_state.get("credential_validation_log") or [])
    credential_attempts_by_protocol: dict[str, int] = {}
    credential_outcome_counts: dict[str, int] = {}
    for entry in raw_cred_log:
        protocol = str(entry.get("protocol", "unknown"))
        credential_attempts_by_protocol[protocol] = (
            credential_attempts_by_protocol.get(protocol, 0) + 1
        )
        category = str(entry.get("error_category", "unknown"))
        credential_outcome_counts[category] = credential_outcome_counts.get(category, 0) + 1

    # Phase 12C: no-action count — turns whose planner produced zero
    # selected tasks (an AbandonSignal or empty task list). Never counts
    # browser-phase turns, which do not call a planner at all.
    no_action_count = sum(
        1 for d in planner_decisions if int(d.get("selected_task_count", 0) or 0) == 0
    )

    # Phase 12C: access summary — never a password. The successful
    # credential_validation_log entry (if any) supplies protocol/username;
    # falls back to "telnet" when access_state exists but no Phase 12B
    # credential_validation_log entry was recorded (matches Telnet's
    # pre-Phase-12B behavior, which predates that log).
    access_summary: dict[str, Any] = {"validated": False, "protocol": None, "username": None}
    if "access_state" in node_counts:
        successful_entry = next((e for e in raw_cred_log if e.get("success")), None)
        access_summary = {
            "validated": True,
            "protocol": str(successful_entry.get("protocol")) if successful_entry else "telnet",
            "username": str(successful_entry.get("username")) if successful_entry else None,
        }

    termination_reason = str(final_state.get("termination_reason") or "")
    termination_phase = str(final_state.get("termination_phase") or "")
    stall_reason = str(final_state.get("stall_reason") or "")

    # Phase 18: user-flag objective summary, derived directly from the
    # final subgraph (never the possibly-one-turn-stale
    # final_state["objective_summary"] snapshot) — mirrors every other
    # Phase 13-17 report section's convention.
    objective_fields = objective_report_fields(subgraph, config.target, config.objective_type)

    # Phase 20: direct-file-read capability summary. Capability
    # derivation/registration counts come directly from the final subgraph
    # (never the state snapshot); attempt/blocked/verified/rejection counts
    # come from state["direct_file_read_log"] (an accumulated audit log —
    # mirrors credential_validation_log's own convention, since the EKG has
    # no representation of a *blocked* or *rejected* attempt beyond the
    # objective node's own attempted_capability_paths list).
    raw_dfr_log = list(final_state.get("direct_file_read_log") or [])
    direct_file_read_capabilities_derived = sum(
        1 for n in subgraph.nodes
        if n.type == "access_capability" and str(n.props.get("capability_type", "")) in _DIRECT_FILE_READ_CAPABILITY_TYPES
    )
    direct_file_read_adapters_registered = sum(
        1 for n in subgraph.nodes
        if n.type == "access_capability"
        and str(n.props.get("capability_type", "")) in _DIRECT_FILE_READ_CAPABILITY_TYPES
        and bool(n.props.get("runtime_available", False))
    )
    direct_file_read_blocked_attempts = sum(1 for e in raw_dfr_log if e.get("blocked"))
    direct_file_read_attempts = sum(1 for e in raw_dfr_log if not e.get("blocked"))
    direct_file_read_verified_count = sum(1 for e in raw_dfr_log if e.get("verified"))
    direct_file_read_rejected_oversized = sum(1 for e in raw_dfr_log if e.get("truncated"))
    direct_file_read_rejected_cross_origin = sum(
        1 for e in raw_dfr_log
        if "outside the authorized origin" in str(e.get("error") or "")
        or "redirects are disabled" in str(e.get("error") or "")
    )

    # Phase 21: bounded command-execution capability summary — same
    # derivation convention as the direct-file-read summary above.
    raw_cmd_log = list(final_state.get("bounded_command_log") or [])
    bounded_command_capabilities_derived = sum(
        1 for n in subgraph.nodes
        if n.type == "access_capability" and str(n.props.get("capability_type", "")) in _COMMAND_CAPABILITY_TYPES
    )
    bounded_command_adapters_registered = sum(
        1 for n in subgraph.nodes
        if n.type == "access_capability"
        and str(n.props.get("capability_type", "")) in _COMMAND_CAPABILITY_TYPES
        and bool(n.props.get("runtime_available", False))
    )
    bounded_command_unavailable_strategies = max(
        0, bounded_command_capabilities_derived - bounded_command_adapters_registered
    )
    bounded_command_blocked_attempts = sum(1 for e in raw_cmd_log if e.get("blocked"))
    bounded_command_attempts = sum(1 for e in raw_cmd_log if not e.get("blocked"))
    bounded_command_verified_count = sum(1 for e in raw_cmd_log if e.get("verified"))
    bounded_command_oversized = sum(1 for e in raw_cmd_log if e.get("truncated"))
    bounded_command_timeouts = sum(
        1 for e in raw_cmd_log if "timeout" in str(e.get("error") or "").lower()
    )

    # Phase 23: deterministic capability-discovery summary — a plain sum
    # across every turn's accumulated CapabilityDiscoveryResult.to_dict()
    # entry (each entry is already a per-turn total, not a per-evidence-item
    # record, so summing across turns is the correct aggregation).
    raw_discovery_log = list(final_state.get("capability_discovery_log") or [])
    capability_discovery_evidence_evaluated = sum(int(e.get("evidence_evaluated", 0)) for e in raw_discovery_log)
    capability_discovery_evidence_accepted = sum(int(e.get("evidence_accepted", 0)) for e in raw_discovery_log)
    capability_discovery_evidence_rejected = sum(int(e.get("evidence_rejected", 0)) for e in raw_discovery_log)
    capability_discovery_duplicate_evidence = sum(int(e.get("duplicate_evidence", 0)) for e in raw_discovery_log)
    capability_discovery_capabilities_derived = sum(
        int(e.get("capabilities_derived", 0)) for e in raw_discovery_log
    )
    capability_discovery_capabilities_updated = sum(
        int(e.get("capabilities_updated", 0)) for e in raw_discovery_log
    )
    capability_discovery_adapters_registered = sum(
        int(e.get("runtime_adapters_registered", 0)) for e in raw_discovery_log
    )
    capability_discovery_validated_but_unavailable = sum(
        int(e.get("validated_but_unavailable", 0)) for e in raw_discovery_log
    )
    capability_discovery_provider_failures = sum(
        int(e.get("provider_failures", 0)) for e in raw_discovery_log
    )

    # Phase 13: privilege-escalation planning summary. Derived directly from
    # the FINAL subgraph's priv_esc_opportunity nodes (not from
    # final_state["privilege_summary"]) so the report is always complete and
    # accurate — the state-field snapshot is refreshed at the START of each
    # priv_esc turn (before that turn's own opportunities are parsed and
    # written), so it is always exactly one turn stale; the report, built
    # after the engagement fully completes, has no such lag. `enumeration_complete`
    # is still cross-checked against the state field as a defensive fallback.
    ranked_opportunities = rank_opportunities(opportunities_from_subgraph(subgraph))
    privilege_categories: dict[str, int] = {}
    for o in ranked_opportunities:
        privilege_categories[o.category.value] = privilege_categories.get(o.category.value, 0) + 1
    privilege_opportunity_count = len(ranked_opportunities)
    privilege_attempted_count = sum(1 for o in ranked_opportunities if o.attempted)
    privilege_exhausted_count = sum(1 for o in ranked_opportunities if o.exhausted)
    privilege_remaining_count = sum(1 for o in ranked_opportunities if not o.exhausted)
    if ranked_opportunities:
        privilege_state = (
            "exhausted" if privilege_remaining_count == 0 else "opportunities_found"
        )
    else:
        privilege_state = str(final_state.get("privilege_state") or "")
    privilege_enumeration_complete = (
        bool(ranked_opportunities) and privilege_remaining_count == 0
    ) or bool(final_state.get("enumeration_complete", False))
    privilege_recommendations = [
        o.recommended_next_action for o in ranked_opportunities if not o.exhausted
    ][:5]

    # Phase 13B: safe privilege enumeration & evidence collection summary.
    # Derived directly from the final subgraph's priv_esc_evidence nodes
    # (one per completed+parsed enumeration command — see
    # apex_host/parsers/priv_esc_parser.py::parse_enumeration) and from
    # error_episodes for the failed-command count (a failed command never
    # produces an evidence node at all).
    enum_evidence = evidence_from_subgraph(subgraph)
    enum_commands_completed = len(enum_evidence)
    enum_evidence_categories: dict[str, int] = {}
    for ev in enum_evidence:
        enum_evidence_categories[ev.category.value] = (
            enum_evidence_categories.get(ev.category.value, 0) + 1
        )
    enum_commands_failed = sum(
        1 for e in error_episodes if str(e.get("tool", "")) == "priv_esc_enum"
    )
    enum_new_opportunities = sum(
        1 for n in subgraph.nodes
        if n.type == "priv_esc_opportunity" and n.props.get("source_tool") == "priv_esc_enum"
    )
    enum_duplicate_opportunities_avoided = sum(
        1 for d in raw_dup if d.get("phase") == "priv_esc"
    )
    # Completeness: every fixed enumeration command has a recorded
    # priv_esc_evidence node for this target (already_run_commands reads the
    # same command_key prop this parser writes).
    enum_completed_keys = already_run_commands(subgraph)
    enum_completeness = bool(enum_completed_keys) and set(ENUM_COMMANDS).issubset(enum_completed_keys)

    # Phase 14: web exploitation planning & browser reasoning summary.
    # Derived directly from the FINAL subgraph — never from
    # final_state["web_session_state"] (refreshed one turn early, same
    # staleness caveat as Phase 13's privilege_summary).
    web_pages_visited = len(visited_urls_from_subgraph(subgraph))
    web_forms_discovered = sum(1 for n in subgraph.nodes if n.type == "form")
    web_technologies = technologies_from_subgraph(subgraph)
    web_technology_names = sorted({t["name"] for t in web_technologies if t.get("name")})
    ranked_web_opportunities = rank_web_opportunities(web_opportunities_from_subgraph(subgraph))
    web_opportunity_categories: dict[str, int] = {}
    for web_o in ranked_web_opportunities:
        web_opportunity_categories[web_o.category.value] = web_opportunity_categories.get(web_o.category.value, 0) + 1
    web_authentication_portals = web_opportunity_categories.get("authentication_portal", 0)
    web_duplicate_pages_avoided = sum(
        1 for d in raw_dup if d.get("tool") == "browser"
    )
    web_recommendations = [web_o.recommended_next_action for web_o in ranked_web_opportunities][:5]

    # Phase 15: multi-step exploitation orchestration summary. Uses the
    # REAL final completed/outcome values (unlike the live per-turn sync in
    # continuation_node.py, which cannot know in advance which turn will
    # terminate the engagement) so abandoned/stalled classification here is
    # always accurate.
    ranked_workflows = rank_workflows(
        derive_workflows_from_subgraph(
            config.target, subgraph,
            engagement_completed=bool(final_state["completed"]),
            engagement_outcome=resolved_outcome.value,
        )
    )
    ranked_sessions = rank_sessions(derive_sessions_from_subgraph(config.target, subgraph))
    workflow_status_counts: dict[str, int] = {}
    for wf in ranked_workflows:
        workflow_status_counts[wf.status.value] = workflow_status_counts.get(wf.status.value, 0) + 1
    workflow_completion_percentage = (
        round(sum(wf.completion_percentage for wf in ranked_workflows) / len(ranked_workflows), 1)
        if ranked_workflows else 0.0
    )
    active_sessions = [
        {"kind": s.kind.value, "status": s.status.value, "detail": s.detail} for s in ranked_sessions
    ]
    reasoning_chains = [
        {
            "workflow": wf.key, "objective": wf.objective, "status": wf.status.value,
            "steps": [{"name": s.name, "status": s.status.value} for s in wf.steps],
        }
        for wf in ranked_workflows
    ]
    workflow_recommendations = [
        wr.text for wr in workflow_recommendations_from_workflows(ranked_workflows)
    ][:5]

    # Phase 16: adaptive learning / experience-replay summary. The listing
    # is derived directly from the FINAL subgraph (the reflection pass in
    # ApexRuntime.run() already wrote experience/experience_recommendation
    # nodes back through MemoryAPI before this report is built). Only the
    # created/reused/replay-hit counts come from the one-shot
    # final_state["learning_summary"] delta — see the RunReport field
    # docstring above for why that specific exception exists.
    ranked_experiences = rank_experiences(experiences_from_subgraph(subgraph))
    learning_experience_categories: dict[str, int] = {}
    for exp in ranked_experiences:
        learning_experience_categories[exp.category.value] = (
            learning_experience_categories.get(exp.category.value, 0) + 1
        )
    learning_recommendations = [exp.recommendation for exp in ranked_experiences][:5]
    learning_summary = dict(final_state.get("learning_summary") or {})

    # Phase 3: raw, bounded, redacted per-execution diagnostic records —
    # see apex_host.execution.diagnostics.build_execution_diagnostic and
    # apex_host.orchestration.memory_node (the sole producer).
    execution_diagnostics = list(final_state.get("execution_diagnostics") or [])

    # Phase 3: a single, human-readable sentence disambiguating the four
    # top-level completion/status fields for an operator who does not want
    # to cross-reference them — see docs/report-schema.md "Top-level field
    # semantics".
    _runtime_clause = (
        "runtime reached a terminal state" if final_state["completed"]
        else "runtime has NOT yet reached a terminal state"
    )
    _objective_clause = (
        "the configured objective was verified" if completed_successfully
        else "the configured objective was NOT verified"
    )
    completion_summary = (
        f"{_runtime_clause} (completed={final_state['completed']!s}); "
        f"{_objective_clause} (completed_successfully={completed_successfully!s}); "
        f"status={status!r}; outcome={resolved_outcome.value!r}."
    )

    report = RunReport(
        target=config.target,
        mode="dry-run" if config.dry_run else "live",
        turns_used=turns_used,
        completed=final_state["completed"],
        status=status,
        completed_successfully=completed_successfully,
        final_phase=final_state["phase"],
        phases_reached=phases_reached,
        finding_count=len(deduped_findings),
        findings=deduped_findings,
        node_counts=node_counts,
        edge_counts=edge_counts,
        total_nodes=len(subgraph.nodes),
        total_edges=len(subgraph.edges),
        episodes_by_outcome=episodes_by_outcome,
        script_error_count=script_error_count,
        fixable_count=fixable_count,
        fundamental_count=fundamental_count,
        error_samples=error_samples,
        evidence_samples=evidence_samples,
        last_error=final_state["last_error"],
        planner_decisions=planner_decisions,
        policy_approved_count=policy_approved_count,
        policy_blocked_count=policy_blocked_count,
        policy_needs_review_count=policy_needs_review_count,
        last_blocked_reasons=last_blocked_reasons,
        policy_decisions=raw_pd,
        seeding_counts=seeding_counts,
        seeding_promotion=seeding_promotion,
        knowledge_init=knowledge_init,
        policy_source=policy_source,
        llm_usage=llm_budget if llm_budget is not None else {},
        duplicate_action_count=len(raw_dup),
        duplicate_action_entries=raw_dup,
        backend_usage=backend_usage,
        timed_out_count=timed_out_count,
        credential_attempts_by_protocol=credential_attempts_by_protocol,
        credential_outcome_counts=credential_outcome_counts,
        credential_validation_entries=raw_cred_log,
        outcome=resolved_outcome.value,
        success=completed_successfully,
        termination_reason=termination_reason,
        termination_phase=termination_phase,
        termination_turn=turns_used,
        stall_reason=stall_reason,
        no_action_count=no_action_count,
        access_summary=access_summary,
        objective_type=str(objective_fields["objective_type"]),
        objective_status=str(objective_fields["objective_status"]),
        objective_verified=bool(objective_fields["objective_verified"]),
        objective_attempts=int(objective_fields["objective_attempts"]),
        objective_evidence_digest=str(objective_fields["objective_evidence_digest"]),
        objective_evidence_redacted=str(objective_fields["objective_evidence_redacted"]),
        objective_evidence_source_path=str(objective_fields["objective_evidence_source_path"]),
        objective_evidence_access_identity=str(objective_fields["objective_evidence_access_identity"]),
        objective_verification_timestamp=str(objective_fields["objective_verification_timestamp"]),
        objective_evidence_capability_type=str(objective_fields.get("objective_evidence_capability_type", "")),
        direct_file_read_capabilities_derived=direct_file_read_capabilities_derived,
        direct_file_read_adapters_registered=direct_file_read_adapters_registered,
        direct_file_read_attempts=direct_file_read_attempts,
        direct_file_read_blocked_attempts=direct_file_read_blocked_attempts,
        direct_file_read_verified_count=direct_file_read_verified_count,
        direct_file_read_rejected_oversized=direct_file_read_rejected_oversized,
        direct_file_read_rejected_cross_origin=direct_file_read_rejected_cross_origin,
        bounded_command_capabilities_derived=bounded_command_capabilities_derived,
        bounded_command_adapters_registered=bounded_command_adapters_registered,
        bounded_command_unavailable_strategies=bounded_command_unavailable_strategies,
        bounded_command_attempts=bounded_command_attempts,
        bounded_command_blocked_attempts=bounded_command_blocked_attempts,
        bounded_command_timeouts=bounded_command_timeouts,
        bounded_command_oversized=bounded_command_oversized,
        bounded_command_verified_count=bounded_command_verified_count,
        capability_discovery_evidence_evaluated=capability_discovery_evidence_evaluated,
        capability_discovery_evidence_accepted=capability_discovery_evidence_accepted,
        capability_discovery_evidence_rejected=capability_discovery_evidence_rejected,
        capability_discovery_duplicate_evidence=capability_discovery_duplicate_evidence,
        capability_discovery_capabilities_derived=capability_discovery_capabilities_derived,
        capability_discovery_capabilities_updated=capability_discovery_capabilities_updated,
        capability_discovery_adapters_registered=capability_discovery_adapters_registered,
        capability_discovery_validated_but_unavailable=capability_discovery_validated_but_unavailable,
        capability_discovery_provider_failures=capability_discovery_provider_failures,
        privilege_state=privilege_state,
        privilege_opportunity_count=privilege_opportunity_count,
        privilege_categories=privilege_categories,
        privilege_attempted_count=privilege_attempted_count,
        privilege_exhausted_count=privilege_exhausted_count,
        privilege_remaining_count=privilege_remaining_count,
        privilege_enumeration_complete=privilege_enumeration_complete,
        privilege_recommendations=privilege_recommendations,
        enum_commands_completed=enum_commands_completed,
        enum_commands_failed=enum_commands_failed,
        enum_evidence_count=enum_commands_completed,
        enum_evidence_categories=enum_evidence_categories,
        enum_new_opportunities=enum_new_opportunities,
        enum_duplicate_opportunities_avoided=enum_duplicate_opportunities_avoided,
        enum_completeness=enum_completeness,
        web_pages_visited=web_pages_visited,
        web_forms_discovered=web_forms_discovered,
        web_technologies_detected=len(web_technologies),
        web_technology_names=web_technology_names,
        web_authentication_portals=web_authentication_portals,
        web_opportunity_count=len(ranked_web_opportunities),
        web_opportunity_categories=web_opportunity_categories,
        web_duplicate_pages_avoided=web_duplicate_pages_avoided,
        web_recommendations=web_recommendations,
        workflow_count=len(ranked_workflows),
        workflows_completed=workflow_status_counts.get("completed", 0),
        workflows_blocked=workflow_status_counts.get("blocked", 0),
        workflows_running=workflow_status_counts.get("running", 0),
        workflows_stalled=workflow_status_counts.get("stalled", 0),
        workflows_abandoned=workflow_status_counts.get("abandoned", 0),
        workflow_completion_percentage=workflow_completion_percentage,
        active_sessions=active_sessions,
        reasoning_chains=reasoning_chains,
        workflow_recommendations=workflow_recommendations,
        learning_experience_count=len(ranked_experiences),
        learning_experience_categories=learning_experience_categories,
        learning_experiences_created=int(learning_summary.get("experiences_created", 0) or 0),
        learning_experiences_reused=int(learning_summary.get("experiences_reused", 0) or 0),
        learning_replay_hits=int(learning_summary.get("replay_hits", 0) or 0),
        learning_repeated_failures=int(learning_summary.get("repeated_failures", 0) or 0),
        learning_recommendations=learning_recommendations,
        task_latency_log=list(final_state.get("task_latency_log") or []),
        benchmark_total_runtime_seconds=total_runtime_seconds,
        benchmark_report_generation_seconds=report_generation_seconds,
        evaluation_machine_name=htb_machine_name or "",
        evaluation_difficulty=htb_difficulty or "",
        execution_diagnostics=execution_diagnostics,
        observation_count=len(raw_findings),
        phases_attempted=phases_attempted,
        phases_entered=phases_entered,
        phases_completed=phases_completed,
        final_runtime_state=final_state["phase"],
        completion_summary=completion_summary,
    )

    # Phase 3: run the report-consistency invariants exactly once, here —
    # the SOLE place build_report() ever validates itself. Never raises in
    # production ("prefer a safe diagnostic status rather than crashing
    # after an engagement"); a non-empty list IS the safe diagnostic
    # signal. Tests that want strict enforcement call
    # apex_host.eval.report_invariants.assert_report_invariants(report)
    # explicitly on the returned report.
    report.invariant_violations = check_report_invariants(report)
    return report


def _samples_from_summary(final_state: "ApexGraphState") -> list[str]:
    """Extract up to 5 non-empty lines from the state's evidence_summary."""
    summary = str(final_state.get("evidence_summary", "") or "")
    return [ln.strip() for ln in summary.splitlines() if ln.strip()][:5]


# ---------------------------------------------------------------------------
# Human-readable formatter
# ---------------------------------------------------------------------------

# Phase 12C: (headline word, human-readable phrase) per outcome — used to
# render lines like "SUCCESS — validated SSH access" / "STOPPED — maximum
# turns exhausted" / "BLOCKED — policy prevented further progress" /
# "FAILED — parser error" / "CANCELLED — user interrupted run".
_OUTCOME_HEADLINE: dict[EngagementOutcome, tuple[str, str]] = {
    EngagementOutcome.user_flag_verified: ("SUCCESS", "user flag verified"),
    # Phase 18: an intermediate milestone only — never benchmark success.
    EngagementOutcome.validated_access: ("PARTIAL", "validated {protocol} access — objective not verified"),
    EngagementOutcome.goal_completed: ("STOPPED", "engagement reached its organic completion state"),
    EngagementOutcome.max_turns_exhausted: ("STOPPED", "maximum turns exhausted"),
    EngagementOutcome.phase_budget_exhausted: ("STOPPED", "phase budget exhausted"),
    EngagementOutcome.no_actionable_task: ("STOPPED", "no actionable task remained"),
    EngagementOutcome.duplicate_task_stall: ("STOPPED", "repeated duplicate or stagnant tasks"),
    EngagementOutcome.policy_blocked: ("BLOCKED", "policy prevented further progress"),
    EngagementOutcome.planner_failure: ("FAILED", "planner error"),
    EngagementOutcome.parser_failure: ("FAILED", "parser error"),
    EngagementOutcome.tool_failure: ("FAILED", "tool/backend failure"),
    EngagementOutcome.memory_failure: ("FAILED", "memory failure"),
    EngagementOutcome.unknown_phase: ("FAILED", "unroutable phase"),
    EngagementOutcome.llm_unavailable: ("FAILED", "LLM required but provider unavailable"),
    EngagementOutcome.configuration_failure: ("FAILED", "configuration error"),
    EngagementOutcome.internal_error: ("FAILED", "internal error"),
    EngagementOutcome.cancelled: ("CANCELLED", "user interrupted run"),
}


def outcome_headline(report: RunReport) -> str:
    """Render the one-line headline for *report*'s outcome, e.g.
    ``"SUCCESS — validated ssh access"`` or ``"BLOCKED — policy prevented
    further progress"``. Falls back to the raw outcome string for any value
    not in the table (forward-compatible with a future enum member)."""
    try:
        outcome = EngagementOutcome(report.outcome)
    except ValueError:
        return f"UNKNOWN — {report.outcome or 'no outcome recorded'}"
    category, phrase = _OUTCOME_HEADLINE.get(outcome, ("UNKNOWN", report.outcome))
    if "{protocol}" in phrase:
        protocol = str(report.access_summary.get("protocol") or "telnet")
        phrase = phrase.format(protocol=protocol)
    return f"{category} — {phrase}"


def format_text(report: RunReport) -> str:
    """Render a human-readable engagement report string."""
    lines: list[str] = []

    success_label = "Yes" if report.completed_successfully else "No"
    lines += [
        "",
        _SEP,
        f" APEX HTB Engagement Report (schema v{report.report_schema_version})",
        f" Target : {report.target}   Mode : {report.mode}",
        f" Status : {report.status.upper()}   Successful : {success_label}",
        f" Outcome: {outcome_headline(report)}",
        f" Turns  : {report.turns_used}   "
        f"Final phase : {report.final_phase}   "
        f"Completed : {'Yes' if report.completed else 'No'}",
        f" Summary: {report.completion_summary}",
        _SEP,
    ]

    if report.invariant_violations:
        lines.append("\n/!\\ REPORT INVARIANT VIOLATIONS — treat this report's contents with caution:")
        for violation in report.invariant_violations:
            lines.append(f"  - {violation}")

    # Engagement Outcome detail (Phase 12C — the canonical model; always
    # shown, even for a run that never terminated cleanly, so `outcome`
    # being empty is itself visible rather than silently omitted)
    lines.append("\nEngagement Outcome")
    lines.append(f"  Outcome           : {report.outcome or '(none — run did not terminate)'}")
    lines.append(f"  Termination phase : {report.termination_phase or 'n/a'}")
    lines.append(f"  Termination turn  : {report.termination_turn}")
    lines.append(f"  Reason            : {report.termination_reason or 'n/a'}")
    if report.stall_reason:
        lines.append(f"  Stall reason      : {report.stall_reason}")
    if report.access_summary.get("validated"):
        lines.append(
            f"  Access validated  : protocol={report.access_summary.get('protocol')} "
            f"username={report.access_summary.get('username')}"
        )
    if report.no_action_count:
        lines.append(f"  No-action turns   : {report.no_action_count}")

    # Phase semantics (Phase 3) — always shown when at least one phase was
    # attempted, so an operator can immediately see the difference between
    # "attempted" (planner ran), "completed" (moved past), and the single
    # phase the engagement was still in when it stopped.
    if report.phases_attempted:
        lines.append("\nPhases")
        lines.append(f"  Attempted  : {', '.join(report.phases_attempted)}")
        lines.append(f"  Completed  : {', '.join(report.phases_completed) or '(none)'}")
        lines.append(f"  Findings   : {report.finding_count} unique ({report.observation_count} observations)")

    # Objective Summary (Phase 18 — the authoritative benchmark-success
    # breakdown: access alone is never enough. Always shown, since
    # objective_type defaults to "user_flag" for every engagement — mirrors
    # the always-shown "Policy Gate" section's convention).
    lines.append("\nObjective Summary")
    lines.append(f"  Objective type     : {report.objective_type or 'n/a'}")
    lines.append(f"  Status             : {report.objective_status or 'pending'}")
    lines.append(f"  Attempts           : {report.objective_attempts}")
    lines.append(f"  Access obtained    : {'Yes' if report.access_summary.get('validated') else 'No'}")
    lines.append(f"  Flag attempted     : {'Yes' if report.objective_attempts else 'No'}")
    lines.append(f"  Flag verified      : {'Yes' if report.objective_verified else 'No'}")
    lines.append(f"  Benchmark success  : {'Yes' if report.success else 'No'}")
    if report.objective_verified:
        lines.append(f"  Verified at        : {report.objective_verification_timestamp or 'n/a'}")
        lines.append(f"  Evidence digest    : {report.objective_evidence_digest or 'n/a'}")
        lines.append(f"  Evidence (redacted): {report.objective_evidence_redacted or 'n/a'}")
        lines.append(f"  Source path        : {report.objective_evidence_source_path or 'n/a'}")
        lines.append(f"  Access identity    : {report.objective_evidence_access_identity or 'n/a'}")
        # Access-capability refactor: a capability-type LABEL only (e.g.
        # "SSH Command") — deliberately never framed as "Transport: SSH",
        # so a future capability type (Telnet, arbitrary file read, ...)
        # needs no change to this rendering logic, only a new entry in
        # apex_host.planners.access_capabilities.CAPABILITY_TYPE_LABELS.
        if report.objective_evidence_capability_type:
            lines.append(
                f"  Capability used    : {capability_type_label(report.objective_evidence_capability_type)}"
            )

    # Direct File Read Summary (Phase 20 — shown only when at least one
    # direct-file-read capability was ever derived; a target with none
    # configured shows nothing here). Never a raw URL, header, cookie, or
    # candidate output — bounded, sanitized metrics only.
    if report.direct_file_read_capabilities_derived:
        lines.append("\nDirect File Read Summary")
        lines.append(f"  Capabilities derived : {report.direct_file_read_capabilities_derived}")
        lines.append(f"  Adapters registered  : {report.direct_file_read_adapters_registered}")
        lines.append(f"  Bounded attempts     : {report.direct_file_read_attempts}")
        lines.append(f"  Blocked attempts     : {report.direct_file_read_blocked_attempts}")
        lines.append(f"  Verified reads       : {report.direct_file_read_verified_count}")
        lines.append(f"  Rejected (oversized) : {report.direct_file_read_rejected_oversized}")
        lines.append(f"  Rejected (cross-origin redirect): {report.direct_file_read_rejected_cross_origin}")

    # Bounded Command Summary (Phase 21 — shown only when at least one
    # bounded command-execution capability was ever derived). Never a raw
    # command string, session handle, or candidate output — bounded,
    # sanitized metrics only.
    if report.bounded_command_capabilities_derived:
        lines.append("\nBounded Command Summary")
        lines.append(f"  Capabilities derived : {report.bounded_command_capabilities_derived}")
        lines.append(f"  Adapters registered  : {report.bounded_command_adapters_registered}")
        lines.append(f"  Strategies unavailable: {report.bounded_command_unavailable_strategies}")
        lines.append(f"  Bounded attempts     : {report.bounded_command_attempts}")
        lines.append(f"  Blocked attempts     : {report.bounded_command_blocked_attempts}")
        lines.append(f"  Timeouts             : {report.bounded_command_timeouts}")
        lines.append(f"  Oversized outputs    : {report.bounded_command_oversized}")
        lines.append(f"  Verified reads       : {report.bounded_command_verified_count}")

    # Capability Discovery Summary (Phase 23 — shown only when at least one
    # piece of CapabilityEvidence was ever evaluated this engagement, which
    # covers both automatically-derived and operator-attested capabilities
    # since Phase 23 routes both through the same discovery pipeline).
    # Capability derivation is never itself a benchmark-success signal —
    # this section is purely informational.
    if report.capability_discovery_evidence_evaluated:
        lines.append("\nCapability Discovery Summary")
        lines.append(f"  Evidence evaluated   : {report.capability_discovery_evidence_evaluated}")
        lines.append(f"  Evidence accepted    : {report.capability_discovery_evidence_accepted}")
        lines.append(f"  Evidence rejected    : {report.capability_discovery_evidence_rejected}")
        lines.append(f"  Duplicate evidence   : {report.capability_discovery_duplicate_evidence}")
        lines.append(f"  Capabilities derived : {report.capability_discovery_capabilities_derived}")
        lines.append(f"  Capabilities updated : {report.capability_discovery_capabilities_updated}")
        lines.append(f"  Adapters registered  : {report.capability_discovery_adapters_registered}")
        lines.append(f"  Validated but unavailable: {report.capability_discovery_validated_but_unavailable}")
        if report.capability_discovery_provider_failures:
            lines.append(f"  Provider failures    : {report.capability_discovery_provider_failures}")

    # Privilege Escalation Summary (Phase 13 — shown only when the priv_esc
    # phase produced any state at all; a target never reaching that phase
    # shows nothing here). Planning/reasoning output only — never reflects
    # an executed exploit or an actually-elevated shell.
    if report.privilege_state:
        lines.append("\nPrivilege Escalation Summary")
        lines.append(f"  Enumeration status : {report.privilege_state}")
        lines.append(f"  Opportunity count  : {report.privilege_opportunity_count}")
        cat_detail = ", ".join(
            f"{cat}={count}" for cat, count in sorted(report.privilege_categories.items())
        )
        lines.append(f"  Categories         : {cat_detail or 'none'}")
        lines.append(f"  Attempted          : {report.privilege_attempted_count}")
        lines.append(f"  Exhausted          : {report.privilege_exhausted_count}")
        lines.append(f"  Remaining          : {report.privilege_remaining_count}")
        lines.append(f"  Enumeration done   : {'Yes' if report.privilege_enumeration_complete else 'No'}")
        if report.privilege_recommendations:
            lines.append("  Recommendations:")
            for rec in report.privilege_recommendations:
                lines.append(f"    {rec[:160]}")

    # Privilege Enumeration Summary (Phase 13B — shown only when at least
    # one enumeration command was ever attempted; a target that never
    # reached bounded SSH enumeration shows nothing here). Read-only
    # enumeration output only — never reflects an executed exploit.
    if report.enum_commands_completed or report.enum_commands_failed:
        lines.append("\nPrivilege Enumeration Summary")
        lines.append(
            f"  Commands executed  : {report.enum_commands_completed} "
            f"(failed: {report.enum_commands_failed})"
        )
        lines.append(f"  Evidence collected : {report.enum_evidence_count}")
        ev_cat_detail = ", ".join(
            f"{cat}={count}" for cat, count in sorted(report.enum_evidence_categories.items())
        )
        lines.append(f"  Evidence categories: {ev_cat_detail or 'none'}")
        lines.append(f"  New opportunities  : {report.enum_new_opportunities}")
        lines.append(f"  Duplicates avoided : {report.enum_duplicate_opportunities_avoided}")
        lines.append(f"  Enumeration done   : {'Yes' if report.enum_completeness else 'No'}")

    # Web Summary (Phase 14 — shown only when the browser visited at least
    # one page; a target that never reached browser-based inspection shows
    # nothing here). Browser reasoning/planning output only — never
    # reflects an executed form submission, injection, or exploit.
    if report.web_pages_visited:
        lines.append("\nWeb Summary")
        lines.append(f"  Pages visited        : {report.web_pages_visited}")
        lines.append(f"  Forms discovered     : {report.web_forms_discovered}")
        tech_detail = ", ".join(report.web_technology_names) or "none"
        lines.append(f"  Technologies detected: {tech_detail}")
        lines.append(f"  Authentication portals: {report.web_authentication_portals}")
        cat_detail = ", ".join(
            f"{cat}={count}" for cat, count in sorted(report.web_opportunity_categories.items())
        )
        lines.append(f"  Potential opportunities: {report.web_opportunity_count} ({cat_detail or 'none'})")
        lines.append(f"  Duplicate pages avoided: {report.web_duplicate_pages_avoided}")
        if report.web_recommendations:
            lines.append("  Recommendations:")
            for rec in report.web_recommendations:
                lines.append(f"    {rec[:160]}")

    # Workflow Summary (Phase 15 — shown only when at least one workflow's
    # prerequisites were ever met; a target that never reached any
    # workflow's prerequisites shows nothing here). Reasoning/coordination
    # output only — never reflects an executed exploit or payload.
    if report.workflow_count:
        lines.append("\nWorkflow Summary")
        lines.append(
            f"  Workflows            : {report.workflow_count} "
            f"(completed={report.workflows_completed}, blocked={report.workflows_blocked}, "
            f"running={report.workflows_running}, stalled={report.workflows_stalled}, "
            f"abandoned={report.workflows_abandoned})"
        )
        lines.append(f"  Completion           : {report.workflow_completion_percentage}%")
        if report.active_sessions:
            sess_detail = ", ".join(f"{s['kind']}={s['status']}" for s in report.active_sessions)
            lines.append(f"  Active sessions      : {sess_detail}")
        planner_decisions = report.planner_decisions
        det_count = sum(1 for d in planner_decisions if d.get("planner_model") == "deterministic")
        llm_count = len(planner_decisions) - det_count
        lines.append(
            f"  Planner decisions    : {len(planner_decisions)} "
            f"(deterministic={det_count}, llm={llm_count})"
        )
        if report.reasoning_chains:
            lines.append("  Reasoning chains:")
            for chain in report.reasoning_chains:
                steps_str = " -> ".join(
                    f"[{s['name']}]" if s["status"] != "completed" else s["name"]
                    for s in chain["steps"]
                )
                lines.append(f"    {chain['workflow']} ({chain['status']}): {steps_str}")
        if report.workflow_recommendations:
            lines.append("  Recommendations:")
            for rec in report.workflow_recommendations:
                lines.append(f"    {rec[:160]}")

    # Learning Summary (Phase 16 — shown only when at least one experience
    # exists; a target with no repeated patterns or terminal workflow
    # outcome shows nothing here). Deterministic reflection/replay output
    # only — advisory guidance for a human operator, never an executable
    # action and never an automatic planner override.
    if report.learning_experience_count:
        lines.append("\nLearning Summary")
        cat_detail = ", ".join(
            f"{cat}={count}" for cat, count in sorted(report.learning_experience_categories.items())
        )
        lines.append(f"  Experiences          : {report.learning_experience_count} ({cat_detail or 'none'})")
        lines.append(
            f"  Reflection pass      : created={report.learning_experiences_created} "
            f"reused={report.learning_experiences_reused} replay_hits={report.learning_replay_hits} "
            f"repeated_failures={report.learning_repeated_failures}"
        )
        if report.learning_recommendations:
            lines.append("  Recommendations:")
            for rec in report.learning_recommendations:
                lines.append(f"    {rec[:160]}")

    # Benchmark Summary + Performance/Planner/Memory/Learning Metrics
    # (Phase 17 — shown only when at least one turn ran; an unstarted or
    # hand-built test fixture shows nothing here). All metric FORMULAS live
    # in exactly one place, apex_host/eval/benchmark.py::compute_benchmark —
    # this is a display-only call, never a second computation.
    if report.turns_used:
        bench = compute_benchmark(
            report,
            total_runtime_seconds=report.benchmark_total_runtime_seconds,
            report_generation_seconds=report.benchmark_report_generation_seconds,
            task_latency_log=report.task_latency_log,
        )
        lines.append("\n" + format_benchmark_text(bench))

    # Evaluation Summary (Phase 17 — HTB evaluation mode; shown only when
    # the operator supplied --htb-machine-name). Records what was
    # objectively observed, never assumes the machine was compromised — see
    # apex_host/eval/evaluation.py module docstring.
    if report.evaluation_machine_name:
        evaluation = build_htb_evaluation(
            report, machine_name=report.evaluation_machine_name, difficulty=report.evaluation_difficulty,
        )
        lines.append("\n" + format_evaluation_text(evaluation))

    # Phase summary
    phase_table: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for f in report.findings:
        phase_table[str(f.get("phase", "unknown"))].append(f)

    lines.append("\nPhase Summary")
    if phase_table:
        for phase, phase_findings in phase_table.items():
            lines.append(f"  {phase:<14} {len(phase_findings)} finding(s)")
    else:
        lines.append("  (no findings)")

    # Findings detail
    lines.append(f"\nFindings ({report.finding_count} total)")
    if report.findings:
        for f in report.findings:
            lines.append(
                f"  [{f.get('phase','?'):<12}] {f.get('title',''):<28}"
                f"  {str(f.get('id',''))[:40]}  (conf={f.get('confidence', 0):.2f})"
            )
    else:
        lines.append("  (no findings recorded)")

    # EKG summary
    node_detail = "  ".join(f"{t}={c}" for t, c in sorted(report.node_counts.items()))
    edge_detail = "  ".join(f"{t}={c}" for t, c in sorted(report.edge_counts.items()))
    lines.append(f"\nEKG Summary (anchor: host:{report.target}, depth=10)")
    lines.append(f"  Nodes ({report.total_nodes}):  {node_detail or 'none'}")
    lines.append(f"  Edges ({report.total_edges}):  {edge_detail or 'none'}")

    # Episodes
    lines.append("\nEpisodes")
    for k, v in sorted(report.episodes_by_outcome.items()):
        lines.append(f"  {k:<24}: {v}")
    lines.append(f"  {'last_error':<24}: {report.last_error or 'none'}")

    # Error breakdown (only shown when errors occurred)
    total_errors = report.script_error_count + report.fixable_count + report.fundamental_count
    if total_errors > 0:
        lines.append("\nError Breakdown")
        lines.append(f"  {'script_error':<20}: {report.script_error_count}")
        lines.append(f"  {'fixable':<20}: {report.fixable_count}")
        lines.append(f"  {'fundamental':<20}: {report.fundamental_count}")
        if report.error_samples:
            lines.append("  Samples:")
            for sample in report.error_samples:
                lines.append(f"    {sample[:120]}")

    # Execution Diagnostics (Phase 3) — bounded, redacted per-execution
    # records; shown only for the non-success ones (a full listing of every
    # successful execution belongs in the episodic log, not this summary).
    # See docs/report-schema.md "Diagnosing a failed tool execution".
    failed_diagnostics = [
        d for d in report.execution_diagnostics if d.get("diagnostic_category") not in ("success", "")
    ]
    if failed_diagnostics:
        lines.append("\nExecution Diagnostics (failed executions)")
        for d in failed_diagnostics[:5]:
            lines.append(
                f"  [{d.get('phase', '?')}] {d.get('tool', '?')} target={d.get('target', '?')} "
                f"backend={d.get('backend', '?')} returncode={d.get('returncode')} "
                f"timed_out={d.get('timed_out')} category={d.get('diagnostic_category', '?')}"
                + (f" tool_category={d['tool_error_category']}" if d.get("tool_error_category") else "")
            )
            if d.get("stderr_sample"):
                trunc = " (truncated)" if d.get("stderr_truncated") else ""
                lines.append(f"      stderr: {str(d['stderr_sample'])[:200]}{trunc}")
        if len(failed_diagnostics) > 5:
            lines.append(f"  ... and {len(failed_diagnostics) - 5} more (see execution_diagnostics in JSON export)")

    # Evidence samples
    if report.evidence_samples:
        lines.append("\nRetrieved Evidence (last turn)")
        for sample in report.evidence_samples:
            lines.append(f"  {sample[:120]}")

    # Planner decisions audit log (condensed summary)
    if report.planner_decisions:
        llm_turns = sum(1 for d in report.planner_decisions if not d.get("fallback_used"))
        fallback_turns = len(report.planner_decisions) - llm_turns
        lines.append("\nPlanner Decisions")
        lines.append(f"  Total invocations : {len(report.planner_decisions)}")
        lines.append(f"  LLM-backed        : {llm_turns}")
        lines.append(f"  Deterministic     : {fallback_turns}")
        for d in report.planner_decisions[-5:]:  # last 5
            phase = d.get("phase", "?")
            model = d.get("planner_model", "?")
            conf = float(d.get("confidence", 0.0))
            fb = " [fallback]" if d.get("fallback_used") else ""
            lines.append(f"  [{phase:<12}] {model:<16} conf={conf:.2f}{fb}")

    # Knowledge seeding summary (shown when compiled knowledge was loaded)
    if report.seeding_counts:
        lines.append("\nKnowledge Seeding")
        for family, count in sorted(report.seeding_counts.items()):
            lines.append(f"  {family:<20}: {count:,}")
        if report.seeding_promotion:
            p = report.seeding_promotion
            lines.append("  Reflector bootstrap:")
            lines.append(f"    passes        : {p.get('passes_run', 'n/a')}")
            lines.append(f"    promoted      : {p.get('records_promoted', 'n/a')}")
            lines.append(f"    remaining     : {p.get('records_remaining', 'n/a')}")
            lines.append(f"    stop_reason   : {p.get('stop_reason', 'n/a')}")
            lines.append(f"    elapsed_s     : {p.get('elapsed_seconds', 'n/a')}")
            blocked = p.get("blocked_reason_counts")
            if isinstance(blocked, dict) and blocked:
                reasons = ", ".join(f"{k}={v}" for k, v in sorted(blocked.items()))
                lines.append(f"    blocked_reasons: {reasons}")

    # Knowledge Initialization summary (Phase 4 — cold/warm/incremental cache)
    ki = report.knowledge_init
    if ki:
        lines.append("\nKnowledge Initialization")
        lines.append(f"  mode                    : {ki.get('initialization_mode', 'n/a')}")
        lines.append(f"  persistence_enabled     : {ki.get('persistence_enabled', False)}")
        lines.append(f"  persistence_path        : {ki.get('persistence_path_category', 'n/a')}")
        if ki.get("reuse_rejected_reason"):
            lines.append(f"  reuse_rejected_reason   : {ki['reuse_rejected_reason']}")
        reused = ki.get("families_reused") or []
        changed = ki.get("families_changed") or []
        if reused:
            lines.append(f"  families_reused         : {', '.join(reused)}")
        if changed:
            lines.append(f"  families_changed        : {', '.join(changed)}")
        lines.append(
            f"  records examined/staged/promoted/skipped/blocked : "
            f"{ki.get('records_examined', 0):,}/{ki.get('records_staged', 0):,}/"
            f"{ki.get('records_promoted', 0):,}/{ki.get('records_skipped_existing', 0):,}/"
            f"{ki.get('records_blocked', 0):,}"
        )
        ki_blocked = ki.get("blocked_reason_counts")
        if isinstance(ki_blocked, dict) and ki_blocked:
            reasons = ", ".join(f"{k}={v}" for k, v in sorted(ki_blocked.items()))
            lines.append(f"  blocked_reason_counts   : {reasons}")
        lines.append(f"  elapsed_s               : {ki.get('elapsed_seconds', 'n/a')}")

    # Policy Gate summary (always shown — all-approved is the expected baseline)
    total_policy = (
        report.policy_approved_count
        + report.policy_blocked_count
        + report.policy_needs_review_count
    )
    lines.append("\nPolicy Gate")
    if report.policy_source:
        lines.append(f"  Policy source   : {report.policy_source}")
    lines.append(f"  Total reviewed  : {total_policy}")
    lines.append(f"  Approved        : {report.policy_approved_count}")
    lines.append(f"  Blocked         : {report.policy_blocked_count}")
    lines.append(f"  Needs review    : {report.policy_needs_review_count}")
    if report.last_blocked_reasons:
        lines.append("  Last blocked reasons:")
        for reason in report.last_blocked_reasons:
            lines.append(f"    {reason[:120]}")

    # LLM Usage (shown only when LLM planning was active this run)
    if report.llm_usage:
        u = report.llm_usage
        lines.append("\nLLM Usage")
        lines.append(f"  Calls attempted   : {u.get('calls_attempted', 0)}")
        lines.append(f"  Calls succeeded   : {u.get('calls_succeeded', 0)}")
        lines.append(f"  Calls failed      : {u.get('calls_failed', 0)}")
        lines.append(f"  Fallbacks (total) : {u.get('fallbacks', 0)}")
        lines.append(f"  Retries           : {u.get('retries', 0)}")
        lines.append(f"  Total elapsed s   : {u.get('total_elapsed_seconds', 0.0):.2f}")
        if u.get("stop_reason"):
            lines.append(f"  Stop reason       : {u['stop_reason']}")
        repeated = sum(v for v in (u.get("repeated_skips") or {}).values())
        if repeated:
            lines.append(f"  Repeated skips    : {repeated}")
        per_phase = u.get("phase_counts") or {}
        if per_phase:
            for ph, cnt in sorted(per_phase.items()):
                lines.append(f"    {ph:<16}: {cnt} call(s)")

    # Execution Backend summary (shown only when any backend-tagged
    # execution occurred — dry-run engagements without any generic command
    # execution, e.g. all-preflight runs, show nothing here)
    if report.backend_usage:
        lines.append("\nExecution Backend")
        for name, count in sorted(report.backend_usage.items()):
            lines.append(f"  {name:<20}: {count}")
        lines.append(f"  {'timed_out':<20}: {report.timed_out_count}")

    # Credential Validation summary (Phase 12B — shown only when at least
    # one telnet/ssh/ftp attempt occurred this run; never shows a password)
    if report.credential_attempts_by_protocol:
        lines.append("\nCredential Validation")
        for protocol, count in sorted(report.credential_attempts_by_protocol.items()):
            lines.append(f"  {protocol:<20}: {count} attempt(s)")
        lines.append("  Outcomes:")
        for category, count in sorted(report.credential_outcome_counts.items()):
            lines.append(f"    {category:<24}: {count}")

    # Duplicate Actions (shown only when any tasks were skipped)
    if report.duplicate_action_count > 0:
        lines.append("\nDuplicate Actions Skipped")
        lines.append(f"  Total skipped     : {report.duplicate_action_count}")
        phase_dups: dict[str, int] = {}
        for e in report.duplicate_action_entries:
            ph = str(e.get("phase", "unknown"))
            phase_dups[ph] = phase_dups.get(ph, 0) + 1
        for ph, cnt in sorted(phase_dups.items()):
            lines.append(f"  {ph:<16}: {cnt}")
        for e in report.duplicate_action_entries[:3]:
            detail = (
                f"  [{e.get('phase','?'):<12}] fp={e.get('fingerprint','?')} "
                f"tool={e.get('tool','?')!r} {e.get('reason','')[:60]}"
            )
            if e.get("previous_status"):
                detail += f" prev_status={e.get('previous_status')}"
            if e.get("retry_count"):
                detail += f" retries={e.get('retry_count')}"
            if "repair_changed_action" in e:
                detail += f" repair_changed_action={e.get('repair_changed_action')}"
            lines.append(detail)

    lines += ["", _SEP, ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------

def to_json_dict(report: RunReport) -> dict[str, Any]:
    """Return a JSON-serialisable dict of the full report."""
    return {
        "report_schema_version": report.report_schema_version,
        "target": report.target,
        "mode": report.mode,
        "turns_used": report.turns_used,
        "completed": report.completed,
        "status": report.status,
        "completed_successfully": report.completed_successfully,
        "final_phase": report.final_phase,
        "final_runtime_state": report.final_runtime_state,
        "phases_reached": report.phases_reached,
        "phases_attempted": report.phases_attempted,
        "phases_entered": report.phases_entered,
        "phases_completed": report.phases_completed,
        "finding_count": report.finding_count,
        "findings": report.findings,
        "observation_count": report.observation_count,
        "completion_summary": report.completion_summary,
        "invariant_violations": report.invariant_violations,
        "ekg": {
            "total_nodes": report.total_nodes,
            "total_edges": report.total_edges,
            "node_counts": report.node_counts,
            "edge_counts": report.edge_counts,
        },
        "episodes_by_outcome": report.episodes_by_outcome,
        "error_counts": {
            "script_error": report.script_error_count,
            "fixable": report.fixable_count,
            "fundamental": report.fundamental_count,
        },
        "error_samples": report.error_samples,
        "execution_diagnostics": report.execution_diagnostics,
        "evidence_samples": report.evidence_samples,
        "last_error": report.last_error,
        "planner_decisions": report.planner_decisions,
        "policy_gate": {
            "policy_source": report.policy_source,
            "approved": report.policy_approved_count,
            "blocked": report.policy_blocked_count,
            "needs_human_review": report.policy_needs_review_count,
            "last_blocked_reasons": report.last_blocked_reasons,
        },
        "policy_decisions": report.policy_decisions,
        "knowledge_seeding": {
            "family_counts": report.seeding_counts,
            "promotion": report.seeding_promotion,
            "initialization": report.knowledge_init,
        },
        "llm_usage": report.llm_usage,
        "duplicate_actions": {
            "total_skipped": report.duplicate_action_count,
            "entries": report.duplicate_action_entries,
        },
        "execution_backend": {
            "usage": report.backend_usage,
            "timed_out_count": report.timed_out_count,
        },
        "credential_validation": {
            "attempts_by_protocol": report.credential_attempts_by_protocol,
            "outcome_counts": report.credential_outcome_counts,
            "entries": report.credential_validation_entries,
        },
        "engagement_outcome": {
            "outcome": report.outcome,
            "success": report.success,
            "headline": outcome_headline(report),
            "termination_reason": report.termination_reason,
            "termination_phase": report.termination_phase,
            "termination_turn": report.termination_turn,
            "stall_reason": report.stall_reason,
            "no_action_count": report.no_action_count,
            "access_summary": report.access_summary,
        },
        "objective": {
            "objective_type": report.objective_type,
            "status": report.objective_status,
            "verified": report.objective_verified,
            "attempts": report.objective_attempts,
            "access_obtained": bool(report.access_summary.get("validated")),
            "attempted": bool(report.objective_attempts),
            "benchmark_success": report.success,
            "verification_timestamp": report.objective_verification_timestamp,
            "evidence_digest": report.objective_evidence_digest,
            "evidence_redacted": report.objective_evidence_redacted,
            "evidence_source_path": report.objective_evidence_source_path,
            "evidence_access_identity": report.objective_evidence_access_identity,
            "capability_type": report.objective_evidence_capability_type,
            "capability_label": (
                capability_type_label(report.objective_evidence_capability_type)
                if report.objective_evidence_capability_type else ""
            ),
        },
        "direct_file_read": {
            "capabilities_derived": report.direct_file_read_capabilities_derived,
            "adapters_registered": report.direct_file_read_adapters_registered,
            "attempts": report.direct_file_read_attempts,
            "blocked_attempts": report.direct_file_read_blocked_attempts,
            "verified_count": report.direct_file_read_verified_count,
            "rejected_oversized": report.direct_file_read_rejected_oversized,
            "rejected_cross_origin": report.direct_file_read_rejected_cross_origin,
        },
        "bounded_command": {
            "capabilities_derived": report.bounded_command_capabilities_derived,
            "adapters_registered": report.bounded_command_adapters_registered,
            "unavailable_strategies": report.bounded_command_unavailable_strategies,
            "attempts": report.bounded_command_attempts,
            "blocked_attempts": report.bounded_command_blocked_attempts,
            "timeouts": report.bounded_command_timeouts,
            "oversized": report.bounded_command_oversized,
            "verified_count": report.bounded_command_verified_count,
        },
        "capability_discovery": {
            "evidence_evaluated": report.capability_discovery_evidence_evaluated,
            "evidence_accepted": report.capability_discovery_evidence_accepted,
            "evidence_rejected": report.capability_discovery_evidence_rejected,
            "duplicate_evidence": report.capability_discovery_duplicate_evidence,
            "capabilities_derived": report.capability_discovery_capabilities_derived,
            "capabilities_updated": report.capability_discovery_capabilities_updated,
            "adapters_registered": report.capability_discovery_adapters_registered,
            "validated_but_unavailable": report.capability_discovery_validated_but_unavailable,
            "provider_failures": report.capability_discovery_provider_failures,
        },
        "privilege_escalation": {
            "state": report.privilege_state,
            "opportunity_count": report.privilege_opportunity_count,
            "categories": report.privilege_categories,
            "attempted_count": report.privilege_attempted_count,
            "exhausted_count": report.privilege_exhausted_count,
            "remaining_count": report.privilege_remaining_count,
            "enumeration_complete": report.privilege_enumeration_complete,
            "recommendations": report.privilege_recommendations,
        },
        "privilege_enumeration": {
            "commands_completed": report.enum_commands_completed,
            "commands_failed": report.enum_commands_failed,
            "evidence_count": report.enum_evidence_count,
            "evidence_categories": report.enum_evidence_categories,
            "new_opportunities": report.enum_new_opportunities,
            "duplicate_opportunities_avoided": report.enum_duplicate_opportunities_avoided,
            "enumeration_complete": report.enum_completeness,
        },
        "web_planning": {
            "pages_visited": report.web_pages_visited,
            "forms_discovered": report.web_forms_discovered,
            "technologies_detected": report.web_technologies_detected,
            "technology_names": report.web_technology_names,
            "authentication_portals": report.web_authentication_portals,
            "opportunity_count": report.web_opportunity_count,
            "opportunity_categories": report.web_opportunity_categories,
            "duplicate_pages_avoided": report.web_duplicate_pages_avoided,
            "recommendations": report.web_recommendations,
        },
        "workflow_orchestration": {
            "workflow_count": report.workflow_count,
            "completed": report.workflows_completed,
            "blocked": report.workflows_blocked,
            "running": report.workflows_running,
            "stalled": report.workflows_stalled,
            "abandoned": report.workflows_abandoned,
            "completion_percentage": report.workflow_completion_percentage,
            "active_sessions": report.active_sessions,
            "reasoning_chains": report.reasoning_chains,
            "recommendations": report.workflow_recommendations,
        },
        "learning": {
            "experience_count": report.learning_experience_count,
            "experience_categories": report.learning_experience_categories,
            "experiences_created": report.learning_experiences_created,
            "experiences_reused": report.learning_experiences_reused,
            "replay_hits": report.learning_replay_hits,
            "repeated_failures": report.learning_repeated_failures,
            "recommendations": report.learning_recommendations,
        },
        "benchmark": benchmark_to_json_dict(compute_benchmark(
            report,
            total_runtime_seconds=report.benchmark_total_runtime_seconds,
            report_generation_seconds=report.benchmark_report_generation_seconds,
            task_latency_log=report.task_latency_log,
        )),
        "evaluation": evaluation_to_json_dict(build_htb_evaluation(
            report, machine_name=report.evaluation_machine_name, difficulty=report.evaluation_difficulty,
        )) if report.evaluation_machine_name else None,
    }


def write_report_json(report: RunReport, path: str | Path) -> None:
    """Write the full report as pretty-printed JSON to *path*.

    The write is atomic (P7-I06 / A05): data is first written to a temporary
    sibling file, synced, then renamed into place.  A process crash during the
    write leaves the original file intact — never a truncated or zero-byte file.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(to_json_dict(report), indent=2, default=str)
    # Write to a temp sibling in the same directory so that rename is atomic.
    fd, tmp_path = tempfile.mkstemp(dir=out.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp_path).replace(out)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
