# evaluation.py
# Structured HTB evaluation-mode record: machine metadata plus objective, already-derived engagement facts — never an assumption that the machine was compromised.
"""HTB evaluation support (Phase 17).

Provides a structured record for comparing APEX's behavior across
different HackTheBox machines — recording what an engagement *objectively
observed and did*, never assuming the target was compromised.

Why this never assumes compromise
----------------------------------
``HTBEvaluation.success`` is copied verbatim from ``RunReport.success``,
which is itself ``is_success_outcome(EngagementOutcome(...))`` — the SAME
canonical, single-source-of-truth success definition every other part of
this codebase uses (Phase 12C, ``apex_host/orchestration/outcome.py``):
exactly one thing means success, a validated ``access_state`` node in the
EKG. This module does not introduce a second, looser definition (e.g.
"reached the priv_esc phase" or "found more than N services") that could
make an unsuccessful engagement look like a win. An engagement that
discovered ten services, five web findings, and three privilege-escalation
opportunities but never validated a credential is recorded exactly as
``success=False`` — evaluation mode reports *what was observed*, not what
might have been achievable.

``machine_name``/``difficulty`` are operator-supplied metadata, never
inferred from the target IP or any EKG content (CLAUDE.md §13.8/§13.9 — no
machine-specific behavior or hardcoded expectations anywhere in this
codebase; this module is no exception).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from apex_host.eval.report import RunReport


@dataclass(slots=True)
class HTBEvaluation:
    """One machine's evaluation record — operator-supplied metadata plus
    objective, already-derived facts from a completed engagement's
    ``RunReport``. Never a live, running evaluation session; a snapshot."""
    machine_name: str
    difficulty: str
    target: str
    services_discovered: int
    credentials_validated: int
    web_findings: int
    privilege_opportunities: int
    final_outcome: str
    success: bool
    turns_used: int


def build_htb_evaluation(
    report: "RunReport", *, machine_name: str, difficulty: str,
) -> HTBEvaluation:
    """Build an ``HTBEvaluation`` from an already-built ``RunReport``.

    ``services_discovered`` is ``report.node_counts.get("service", 0)`` —
    the count of distinct ``service`` EKG nodes (one per open port/protocol
    binding, see CLAUDE.md §12.8). ``credentials_validated`` is
    ``report.node_counts.get("access_state", 0)`` — each ``access_state``
    node is proof one protocol/username pair was genuinely validated
    (Phase 12B), never a guess or an attempt count.
    """
    return HTBEvaluation(
        machine_name=machine_name,
        difficulty=difficulty,
        target=report.target,
        services_discovered=report.node_counts.get("service", 0),
        credentials_validated=report.node_counts.get("access_state", 0),
        web_findings=report.web_opportunity_count,
        privilege_opportunities=report.privilege_opportunity_count,
        final_outcome=report.outcome,
        success=report.success,
        turns_used=report.turns_used,
    )


def evaluation_to_json_dict(evaluation: HTBEvaluation) -> dict[str, Any]:
    """JSON-serialisable dict — the shape ``to_json_dict()``
    (apex_host/eval/report.py) nests under ``"evaluation"`` when an
    ``HTBEvaluation`` was supplied to ``build_report()``."""
    return {
        "machine_name": evaluation.machine_name,
        "difficulty": evaluation.difficulty,
        "target": evaluation.target,
        "services_discovered": evaluation.services_discovered,
        "credentials_validated": evaluation.credentials_validated,
        "web_findings": evaluation.web_findings,
        "privilege_opportunities": evaluation.privilege_opportunities,
        "final_outcome": evaluation.final_outcome,
        "success": evaluation.success,
        "turns_used": evaluation.turns_used,
    }


def format_evaluation_text(evaluation: HTBEvaluation) -> str:
    """Human-readable "Evaluation Summary" section text."""
    lines = [
        "Evaluation Summary",
        f"  Machine              : {evaluation.machine_name} ({evaluation.difficulty})",
        f"  Target               : {evaluation.target}",
        f"  Services discovered  : {evaluation.services_discovered}",
        f"  Credentials validated: {evaluation.credentials_validated}",
        f"  Web findings         : {evaluation.web_findings}",
        f"  Privilege opps       : {evaluation.privilege_opportunities}",
        f"  Turns used           : {evaluation.turns_used}",
        f"  Final outcome        : {evaluation.final_outcome}",
        f"  Success              : {'Yes' if evaluation.success else 'No'}",
    ]
    return "\n".join(lines)
