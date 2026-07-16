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
"""
from __future__ import annotations

import collections
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from memfabric.types import SubgraphView
    from apex_host.config import ApexConfig
    from apex_host.graph_state import ApexGraphState

_SEP = "═" * 60


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
    final_phase: str
    phases_reached: list[str]           # unique phases seen in findings
    finding_count: int
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


# ---------------------------------------------------------------------------
# Status helper
# ---------------------------------------------------------------------------

def _determine_status(
    node_counts: dict[str, int],
    turns_used: int,
    max_turns: int,
    error_episodes: list[dict[str, Any]],
    completed: bool,
) -> str:
    """Derive a run status string from terminal conditions.

    Returns one of: "success" | "stopped_max_turns" | "stopped_error" | "abandoned"
    """
    if "access_state" in node_counts:
        return "success"

    total_errors = len(error_episodes)
    if turns_used > 0 and total_errors >= turns_used and not node_counts:
        return "stopped_error"

    if turns_used >= max_turns:
        return "stopped_max_turns"

    if completed:
        return "abandoned"

    return "stopped_max_turns"


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
    """
    phases_reached = sorted({
        str(f.get("phase", "unknown"))
        for f in final_state["findings"]
    })

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
    error_samples = [
        str(e["error"])
        for e in error_episodes
        if e.get("error")
    ][:3]

    completed_successfully = "access_state" in node_counts
    status = _determine_status(
        node_counts, turns_used, config.max_turns, error_episodes, final_state["completed"]
    )

    planner_decisions = list(final_state.get("planner_decisions") or [])

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
    if seed_results:
        seeding_counts = {
            k: v for k, v in seed_results.items()
            if k not in ("_promotion",) and not k.startswith("_")
        }
        promo = seed_results.get("_promotion")
        if isinstance(promo, dict):
            seeding_promotion = promo

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

    return RunReport(
        target=config.target,
        mode="dry-run" if config.dry_run else "live",
        turns_used=turns_used,
        completed=final_state["completed"],
        status=status,
        completed_successfully=completed_successfully,
        final_phase=final_state["phase"],
        phases_reached=phases_reached,
        finding_count=len(final_state["findings"]),
        findings=list(final_state["findings"]),
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
        policy_source=policy_source,
        llm_usage=llm_budget if llm_budget is not None else {},
        duplicate_action_count=len(raw_dup),
        duplicate_action_entries=raw_dup,
        backend_usage=backend_usage,
        timed_out_count=timed_out_count,
        credential_attempts_by_protocol=credential_attempts_by_protocol,
        credential_outcome_counts=credential_outcome_counts,
        credential_validation_entries=raw_cred_log,
    )


def _samples_from_summary(final_state: "ApexGraphState") -> list[str]:
    """Extract up to 5 non-empty lines from the state's evidence_summary."""
    summary = str(final_state.get("evidence_summary", "") or "")
    return [ln.strip() for ln in summary.splitlines() if ln.strip()][:5]


# ---------------------------------------------------------------------------
# Human-readable formatter
# ---------------------------------------------------------------------------

def format_text(report: RunReport) -> str:
    """Render a human-readable engagement report string."""
    lines: list[str] = []

    success_label = "Yes" if report.completed_successfully else "No"
    lines += [
        "",
        _SEP,
        " APEX HTB Engagement Report",
        f" Target : {report.target}   Mode : {report.mode}",
        f" Status : {report.status.upper()}   Successful : {success_label}",
        f" Turns  : {report.turns_used}   "
        f"Final phase : {report.final_phase}   "
        f"Completed : {'Yes' if report.completed else 'No'}",
        _SEP,
    ]

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
            lines.append(
                f"  [{e.get('phase','?'):<12}] fp={e.get('fingerprint','?')} "
                f"tool={e.get('tool','?')!r} {e.get('reason','')[:60]}"
            )

    lines += ["", _SEP, ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------

def to_json_dict(report: RunReport) -> dict[str, Any]:
    """Return a JSON-serialisable dict of the full report."""
    return {
        "target": report.target,
        "mode": report.mode,
        "turns_used": report.turns_used,
        "completed": report.completed,
        "status": report.status,
        "completed_successfully": report.completed_successfully,
        "final_phase": report.final_phase,
        "phases_reached": report.phases_reached,
        "finding_count": report.finding_count,
        "findings": report.findings,
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
