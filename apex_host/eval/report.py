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
from dataclasses import asdict, dataclass, field
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
    final_phase: str
    phases_reached: list[str]           # unique phases seen in findings
    finding_count: int
    findings: list[dict[str, Any]]
    node_counts: dict[str, int]         # by node type
    edge_counts: dict[str, int]         # by edge type
    total_nodes: int
    total_edges: int
    episodes_by_outcome: dict[str, int] # derived or runner-supplied
    evidence_samples: list[str]         # text snippets from last evidence
    last_error: str | None


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

    return RunReport(
        target=config.target,
        mode="dry-run" if config.dry_run else "live",
        turns_used=final_state["turn_count"],
        completed=final_state["completed"],
        final_phase=final_state["phase"],
        phases_reached=phases_reached,
        finding_count=len(final_state["findings"]),
        findings=list(final_state["findings"]),
        node_counts=node_counts,
        edge_counts=edge_counts,
        total_nodes=len(subgraph.nodes),
        total_edges=len(subgraph.edges),
        episodes_by_outcome=episodes_by_outcome,
        evidence_samples=evidence_samples,
        last_error=final_state["last_error"],
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

    lines += [
        "",
        _SEP,
        " APEX HTB Engagement Report",
        f" Target : {report.target}   Mode : {report.mode}",
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

    # Evidence samples
    if report.evidence_samples:
        lines.append("\nRetrieved Evidence (last turn)")
        for sample in report.evidence_samples:
            lines.append(f"  {sample[:120]}")

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
        "evidence_samples": report.evidence_samples,
        "last_error": report.last_error,
    }


def write_report_json(report: RunReport, path: str | Path) -> None:
    """Write the full report as pretty-printed JSON to *path*."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(to_json_dict(report), indent=2, default=str),
        encoding="utf-8",
    )
