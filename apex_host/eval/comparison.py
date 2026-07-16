# comparison.py
# Deterministic comparison between two engagement reports (in-process RunReport objects or previously-exported to_json_dict() JSON) — new/missing findings, planner/workflow/timing/opportunity/learning differences.
"""Run comparison (Phase 17).

Compares two engagement reports and produces a deterministic
``ComparisonResult`` — never a heuristic or fuzzy "similarity score".
Every field is either a set-difference (new/missing findings, by stable
EKG node ID) or a plain numeric/dict delta (``b - a`` for numeric fields).

Two input shapes are supported, both normalised into the same flat
``ComparisonInput`` dict before comparing, so ``compare_reports()`` itself
never has to know which shape it received:

1. **In-process** — ``comparison_input_from_report(report)`` on a
   ``RunReport`` object built in the same process (e.g. comparing the
   current run against one built earlier in the same script).
2. **Cross-process** — ``comparison_input_from_json_export(data)`` on a
   plain dict loaded from a JSON file previously written by
   ``apex_host.eval.report.write_report_json`` (the realistic "compare
   this HTB run against last week's run" workflow, where the two runs are
   two separate process invocations).

Both extractors read exactly the same set of fields, so a report compared
against itself (either shape) produces an all-zero, no-diff
``ComparisonResult`` — verified directly by
``tests/apex_host/test_phase17_benchmarking.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from apex_host.eval.report import RunReport


def comparison_input_from_report(report: "RunReport") -> dict[str, Any]:
    """Flatten a ``RunReport`` object into the comparison-input shape."""
    det_count = sum(1 for d in report.planner_decisions if d.get("planner_model") == "deterministic")
    return {
        "target": report.target,
        "turns_used": report.turns_used,
        "outcome": report.outcome,
        "success": report.success,
        "findings": list(report.findings),
        "total_nodes": report.total_nodes,
        "total_edges": report.total_edges,
        "planner_decision_count": len(report.planner_decisions),
        "planner_deterministic_count": det_count,
        "planner_llm_count": len(report.planner_decisions) - det_count,
        "no_action_count": report.no_action_count,
        "duplicate_action_count": report.duplicate_action_count,
        "workflow_count": report.workflow_count,
        "workflows_completed": report.workflows_completed,
        "workflows_blocked": report.workflows_blocked,
        "workflow_completion_percentage": report.workflow_completion_percentage,
        "privilege_opportunity_count": report.privilege_opportunity_count,
        "privilege_categories": dict(report.privilege_categories),
        "web_opportunity_count": report.web_opportunity_count,
        "web_opportunity_categories": dict(report.web_opportunity_categories),
        "learning_experience_count": report.learning_experience_count,
        "learning_experiences_created": report.learning_experiences_created,
        "learning_replay_hits": report.learning_replay_hits,
    }


def comparison_input_from_json_export(data: dict[str, Any]) -> dict[str, Any]:
    """Flatten a previously-exported ``to_json_dict()`` JSON payload
    (e.g. loaded via ``json.load(open(path))``) into the same
    comparison-input shape ``comparison_input_from_report`` produces."""
    ekg = data.get("ekg", {}) or {}
    outcome = data.get("engagement_outcome", {}) or {}
    workflow = data.get("workflow_orchestration", {}) or {}
    privilege = data.get("privilege_escalation", {}) or {}
    web = data.get("web_planning", {}) or {}
    learning = data.get("learning", {}) or {}
    planner_decisions = data.get("planner_decisions", []) or []
    det_count = sum(1 for d in planner_decisions if d.get("planner_model") == "deterministic")
    return {
        "target": str(data.get("target", "")),
        "turns_used": int(data.get("turns_used", 0) or 0),
        "outcome": str(outcome.get("outcome", "")),
        "success": bool(outcome.get("success", False)),
        "findings": list(data.get("findings", []) or []),
        "total_nodes": int(ekg.get("total_nodes", 0) or 0),
        "total_edges": int(ekg.get("total_edges", 0) or 0),
        "planner_decision_count": len(planner_decisions),
        "planner_deterministic_count": det_count,
        "planner_llm_count": len(planner_decisions) - det_count,
        "no_action_count": int(outcome.get("no_action_count", 0) or 0),
        "duplicate_action_count": int((data.get("duplicate_actions", {}) or {}).get("total_skipped", 0) or 0),
        "workflow_count": int(workflow.get("workflow_count", 0) or 0),
        "workflows_completed": int(workflow.get("completed", 0) or 0),
        "workflows_blocked": int(workflow.get("blocked", 0) or 0),
        "workflow_completion_percentage": float(workflow.get("completion_percentage", 0.0) or 0.0),
        "privilege_opportunity_count": int(privilege.get("opportunity_count", 0) or 0),
        "privilege_categories": dict(privilege.get("categories", {}) or {}),
        "web_opportunity_count": int(web.get("opportunity_count", 0) or 0),
        "web_opportunity_categories": dict(web.get("opportunity_categories", {}) or {}),
        "learning_experience_count": int(learning.get("experience_count", 0) or 0),
        "learning_experiences_created": int(learning.get("experiences_created", 0) or 0),
        "learning_replay_hits": int(learning.get("replay_hits", 0) or 0),
    }


def _category_delta(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    """Per-key delta (``b[k] - a[k]``) over the union of both dicts' keys.
    A key present in only one side is treated as 0 on the other — never
    a KeyError."""
    return {
        key: b.get(key, 0) - a.get(key, 0)
        for key in sorted(set(a) | set(b))
    }


@dataclass(slots=True)
class ComparisonResult:
    """Deterministic diff between two engagement reports ("a" = baseline,
    "b" = candidate). Every ``*_differences`` field is a plain dict of
    named deltas — documented exactly in ``docs/benchmarking.md`` §5."""
    target_a: str = ""
    target_b: str = ""
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    missing_findings: list[dict[str, Any]] = field(default_factory=list)
    planner_differences: dict[str, Any] = field(default_factory=dict)
    workflow_differences: dict[str, Any] = field(default_factory=dict)
    timing_differences: dict[str, Any] = field(default_factory=dict)
    opportunity_differences: dict[str, Any] = field(default_factory=dict)
    learning_differences: dict[str, Any] = field(default_factory=dict)


def compare_reports(a: dict[str, Any], b: dict[str, Any]) -> ComparisonResult:
    """Compare two flattened comparison-input dicts (see
    ``comparison_input_from_report``/``comparison_input_from_json_export``).

    ``a`` is the baseline, ``b`` is the candidate. Findings are matched by
    their stable ``id`` field (a canonical EKG node ID — CLAUDE.md
    §12.8/`apex_host/graph_ids.py`) so the comparison is exact and
    order-independent, never a fuzzy text match.
    """
    findings_a = {str(f.get("id", "")): f for f in a.get("findings", [])}
    findings_b = {str(f.get("id", "")): f for f in b.get("findings", [])}
    new_ids = sorted(set(findings_b) - set(findings_a))
    missing_ids = sorted(set(findings_a) - set(findings_b))

    planner_differences = {
        "decision_count_delta": b["planner_decision_count"] - a["planner_decision_count"],
        "deterministic_count_delta": b["planner_deterministic_count"] - a["planner_deterministic_count"],
        "llm_count_delta": b["planner_llm_count"] - a["planner_llm_count"],
        "no_action_count_delta": b["no_action_count"] - a["no_action_count"],
        "duplicate_action_count_delta": b["duplicate_action_count"] - a["duplicate_action_count"],
    }
    workflow_differences = {
        "workflow_count_delta": b["workflow_count"] - a["workflow_count"],
        "workflows_completed_delta": b["workflows_completed"] - a["workflows_completed"],
        "workflows_blocked_delta": b["workflows_blocked"] - a["workflows_blocked"],
        "completion_percentage_delta": round(
            b["workflow_completion_percentage"] - a["workflow_completion_percentage"], 2,
        ),
    }
    timing_differences = {
        "turns_used_delta": b["turns_used"] - a["turns_used"],
        "total_nodes_delta": b["total_nodes"] - a["total_nodes"],
        "total_edges_delta": b["total_edges"] - a["total_edges"],
    }
    opportunity_differences = {
        "privilege_opportunity_count_delta": b["privilege_opportunity_count"] - a["privilege_opportunity_count"],
        "web_opportunity_count_delta": b["web_opportunity_count"] - a["web_opportunity_count"],
        "privilege_category_deltas": _category_delta(a["privilege_categories"], b["privilege_categories"]),
        "web_category_deltas": _category_delta(a["web_opportunity_categories"], b["web_opportunity_categories"]),
    }
    learning_differences = {
        "experience_count_delta": b["learning_experience_count"] - a["learning_experience_count"],
        "experiences_created_delta": b["learning_experiences_created"] - a["learning_experiences_created"],
        "replay_hits_delta": b["learning_replay_hits"] - a["learning_replay_hits"],
    }

    return ComparisonResult(
        target_a=a["target"],
        target_b=b["target"],
        new_findings=[findings_b[i] for i in new_ids],
        missing_findings=[findings_a[i] for i in missing_ids],
        planner_differences=planner_differences,
        workflow_differences=workflow_differences,
        timing_differences=timing_differences,
        opportunity_differences=opportunity_differences,
        learning_differences=learning_differences,
    )


def comparison_to_json_dict(comparison: ComparisonResult) -> dict[str, Any]:
    """JSON-serialisable dict for ``ComparisonResult``."""
    return {
        "target_a": comparison.target_a,
        "target_b": comparison.target_b,
        "new_findings": comparison.new_findings,
        "missing_findings": comparison.missing_findings,
        "planner_differences": comparison.planner_differences,
        "workflow_differences": comparison.workflow_differences,
        "timing_differences": comparison.timing_differences,
        "opportunity_differences": comparison.opportunity_differences,
        "learning_differences": comparison.learning_differences,
    }


def format_comparison_text(comparison: ComparisonResult) -> str:
    """Human-readable "Comparison Summary" section text."""
    lines = [
        "Comparison Summary",
        f"  Baseline (a)         : {comparison.target_a}",
        f"  Candidate (b)        : {comparison.target_b}",
        f"  New findings         : {len(comparison.new_findings)}",
        f"  Missing findings     : {len(comparison.missing_findings)}",
        f"  Planner differences  : {comparison.planner_differences}",
        f"  Workflow differences : {comparison.workflow_differences}",
        f"  Timing differences   : {comparison.timing_differences}",
        f"  Opportunity diffs    : {comparison.opportunity_differences}",
        f"  Learning differences : {comparison.learning_differences}",
    ]
    return "\n".join(lines)
