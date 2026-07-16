# benchmark.py
# Deterministic benchmarking subsystem: turns an already-built RunReport plus externally-measured wall-clock timing into a structured, reproducible BenchmarkResult with computed efficiency/coverage/density metrics.
"""Benchmark subsystem (Phase 17).

This module computes **deterministic, reproducible metrics from data an
engagement already produced** — it is not a profiler, not a load-testing
tool, and not a source of new EKG data. Every metric here is a pure
arithmetic function of fields already present on a built ``RunReport``
(see ``apex_host/eval/report.py``), plus two pieces of externally-measured
wall-clock timing that only the caller can supply (``total_runtime_seconds``,
``report_generation_seconds`` — see "Why timing is an external input"
below) and one accumulated per-task timing log
(``ApexGraphState["task_latency_log"]``, populated by
``apex_host/orchestration/memory_node.py``).

No I/O, no MemoryAPI calls, no async — ``compute_benchmark()`` is a plain
function over already-in-memory data, consistent with this codebase's
"pure reasoning helper" convention (mirrors
``apex_host/planners/{priv_esc_opportunities,web_opportunities,
workflow_orchestration,experience_replay}.py``).

Why timing is an external input
--------------------------------
``RunReport`` itself carries no wall-clock timestamps beyond ``turns_used``
— it is built from ``ApexGraphState``, which (memfabric Invariant 5 /
CLAUDE.md's "context is retrieved and scoped, never accumulated") does not
track real-world elapsed time. Measuring "how long did this engagement
actually take" and "how long did building this report actually take" can
only be done by the caller wrapping the relevant calls in
``time.monotonic()`` — see ``apex_host/eval/run_htb_local.py``'s
``_async_main()`` for where this happens. ``compute_benchmark()`` accepts
these as plain float arguments (both defaulting to ``0.0`` so existing
callers that never measure them are unaffected and simply see zero-valued,
non-misleading benchmark fields).

Why ``tasks_executed``/``planner_efficiency`` avoid ``planner_decisions``
--------------------------------------------------------------------------
Investigating a real engagement's output while building this module
surfaced a pre-existing gap (not introduced here, not fixed here — out of
this phase's scope, documented for a future phase):
``PlanningEngine._record_fallback()`` (``apex_host/planning/engine.py``)
always records ``selected_task_count=0`` for every deterministic-fallback
``PlanDecision`` — even when the wrapped deterministic planner selected and
returned real tasks — because it is called *before* the fallback planner's
own result is known, at every one of its ~13 call sites. Since
``ApexRuntime.run()`` always constructs a real (possibly ``FakeModelRouter``)
``ModelRouter`` and always wires every planner through ``PlanningEngine``,
this affects the deterministic-only default mode too (the vast majority of
real usage per this project's own README), not just LLM-backed runs. The
pre-existing ``RunReport.no_action_count`` field (Phase 12C) is built from
the same ``selected_task_count`` data and inherits the same gap.

Rather than silently producing a misleading always-zero
``planner_efficiency``/``duplicate_avoidance_percentage`` for the common
case, this module counts real execution evidence directly instead:
``task_latency_log`` (populated only for genuinely-executed, non-skipped
tool_results) plus telnet credential attempts (the one executor with no
measurable duration). See the comments beside ``tasks_executed``'s
computation in ``compute_benchmark()`` for the exact formula.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from apex_host.eval.report import RunReport

# Node types counted as "evidence-bearing" for the evidence_density metric —
# EKG nodes that represent a concrete, human-actionable observation rather
# than pure structural scaffolding (host/workflow_step/session are excluded
# as coordination bookkeeping, not evidence).
_EVIDENCE_NODE_TYPES: frozenset[str] = frozenset({
    "service", "tech", "endpoint", "form", "token", "auth_flow",
    "credential", "access_state",
    "priv_esc_opportunity", "priv_esc_evidence", "priv_esc_recommendation",
    "web_opportunity",
    "workflow_recommendation",
    "experience", "experience_recommendation",
})


@dataclass(slots=True)
class BenchmarkMetrics:
    """Computed, deterministic metrics — every field is a pure function of
    already-known counts (see ``compute_benchmark`` for the exact formula
    behind each one; also documented in ``docs/benchmarking.md`` §3).

    Every ratio metric is bounded to ``[0.0, 1.0]`` and defaults to ``0.0``
    on an empty/zero denominator — never a division error, never ``None``.
    """
    planner_efficiency: float = 0.0
    workflow_completion_percentage: float = 0.0
    duplicate_avoidance_percentage: float = 0.0
    browser_coverage: float = 0.0
    credential_success_rate: float = 0.0
    privilege_opportunity_density: float = 0.0
    replay_usefulness: float = 0.0
    average_task_latency_seconds: float = 0.0
    evidence_density: float = 0.0
    graph_growth_rate: float = 0.0
    report_generation_seconds: float = 0.0


@dataclass(slots=True)
class BenchmarkResult:
    """One engagement's benchmark record — raw counters plus computed
    ``BenchmarkMetrics``. JSON-serialisable via ``benchmark_to_json_dict``.
    """
    target: str = ""
    total_runtime_seconds: float = 0.0
    planner_decision_count: int = 0
    tasks_selected_total: int = 0
    tasks_executed: int = 0
    tasks_skipped: int = 0
    duplicate_avoidance_count: int = 0
    opportunities_discovered: int = 0
    browser_findings: int = 0
    credential_attempts: int = 0
    privilege_opportunities: int = 0
    workflow_completion_percentage: float = 0.0
    learning_replay_hits: int = 0
    engagement_outcome: str = ""
    metrics: BenchmarkMetrics = field(default_factory=BenchmarkMetrics)


def _ratio(numerator: float, denominator: float) -> float:
    """Bounded ``numerator / denominator`` — 0.0 on a zero/negative
    denominator, clamped to [0.0, 1.0]. The single shared formula every
    ratio metric in this module uses, so rounding/clamping behavior is
    identical across all of them."""
    if denominator <= 0:
        return 0.0
    return max(0.0, min(1.0, numerator / denominator))


def compute_benchmark(
    report: "RunReport",
    *,
    total_runtime_seconds: float = 0.0,
    report_generation_seconds: float = 0.0,
    task_latency_log: list[dict[str, Any]] | None = None,
) -> BenchmarkResult:
    """Compute a deterministic ``BenchmarkResult`` from an already-built
    ``RunReport``.

    Args:
        report: A ``RunReport`` produced by ``apex_host.eval.report.build_report``.
        total_runtime_seconds: Wall-clock seconds for the whole engagement,
            measured by the caller around ``run_engagement()``/``runtime.run()``.
            Defaults to ``0.0`` when not measured (e.g. a test fixture).
        report_generation_seconds: Wall-clock seconds spent building +
            formatting the report itself, measured by the caller. Defaults
            to ``0.0``.
        task_latency_log: The accumulated
            ``ApexGraphState["task_latency_log"]`` list (one dict per
            non-skipped tool_result that carried a real, measured
            ``duration_seconds`` — see
            ``apex_host/orchestration/memory_node.py``). ``None``/empty
            produces ``average_task_latency_seconds == 0.0``, never a
            division error.
    """
    latency_entries = task_latency_log or []
    durations = [
        float(entry.get("duration_seconds", 0.0) or 0.0) for entry in latency_entries
    ]
    average_task_latency_seconds = (
        round(sum(durations) / len(durations), 6) if durations else 0.0
    )

    planner_decision_count = len(report.planner_decisions)
    duplicate_avoidance_count = report.duplicate_action_count
    tasks_skipped = duplicate_avoidance_count

    # tasks_executed deliberately does NOT sum `selected_task_count` off
    # `report.planner_decisions` — see the module-level note below
    # ("Why tasks_executed avoids planner_decisions") for why that field is
    # not a reliable executed-task count for deterministic-fallback
    # decisions (the overwhelming common case: FakeModelRouter/no-LLM mode
    # is the system default). Instead this counts real execution evidence
    # directly: one entry per generic/SSH/FTP/priv_esc_enum tool_result
    # (``task_latency_log``, which only ever contains genuinely-executed,
    # non-skipped tasks — see apex_host/orchestration/memory_node.py) plus
    # telnet credential attempts specifically (the one executor that never
    # produces a ``duration_seconds`` entry — Phase 12B invariant: byte-
    # for-byte unchanged). Browser and priv_esc_analyze tasks (zero
    # measurable duration, zero-I/O) are not counted here, the same
    # documented exclusion already applied to average_task_latency_seconds.
    telnet_attempts = sum(
        1 for e in report.credential_validation_entries if e.get("protocol") == "telnet"
    )
    tasks_executed = len(latency_entries) + telnet_attempts
    tasks_selected_total = tasks_executed + tasks_skipped

    opportunities_discovered = report.privilege_opportunity_count + report.web_opportunity_count

    credential_attempts = sum(report.credential_attempts_by_protocol.values())
    credential_successes = report.credential_outcome_counts.get("success", 0)

    total_nodes = report.total_nodes
    evidence_node_count = sum(
        count for node_type, count in report.node_counts.items()
        if node_type in _EVIDENCE_NODE_TYPES
    )
    endpoint_node_count = report.node_counts.get("endpoint", 0)

    # planner_efficiency deliberately does NOT use `report.no_action_count`
    # for the same reason `tasks_executed` avoids `selected_task_count` —
    # see the note above. "Efficiency" here means: of all planner
    # invocations, what fraction resulted in genuinely executed, non-
    # duplicate work (rather than being wasted on an abandon signal or
    # exclusively producing duplicate-skipped tasks).
    planner_efficiency = _ratio(tasks_executed, planner_decision_count)
    duplicate_avoidance_percentage = _ratio(
        duplicate_avoidance_count, tasks_selected_total,
    ) * 100.0
    browser_coverage = _ratio(report.web_pages_visited, endpoint_node_count)
    credential_success_rate = _ratio(credential_successes, credential_attempts)
    privilege_opportunity_density = _ratio(report.privilege_opportunity_count, total_nodes)
    replay_usefulness = _ratio(report.learning_replay_hits, report.learning_experience_count)
    evidence_density = _ratio(evidence_node_count, total_nodes)
    graph_growth_rate = (
        round(total_nodes / report.turns_used, 4) if report.turns_used > 0 else float(total_nodes)
    )

    metrics = BenchmarkMetrics(
        planner_efficiency=round(planner_efficiency, 4),
        workflow_completion_percentage=report.workflow_completion_percentage,
        duplicate_avoidance_percentage=round(duplicate_avoidance_percentage, 2),
        browser_coverage=round(browser_coverage, 4),
        credential_success_rate=round(credential_success_rate, 4),
        privilege_opportunity_density=round(privilege_opportunity_density, 4),
        replay_usefulness=round(replay_usefulness, 4),
        average_task_latency_seconds=average_task_latency_seconds,
        evidence_density=round(evidence_density, 4),
        graph_growth_rate=graph_growth_rate,
        report_generation_seconds=round(report_generation_seconds, 6),
    )

    return BenchmarkResult(
        target=report.target,
        total_runtime_seconds=round(total_runtime_seconds, 6),
        planner_decision_count=planner_decision_count,
        tasks_selected_total=tasks_selected_total,
        tasks_executed=tasks_executed,
        tasks_skipped=tasks_skipped,
        duplicate_avoidance_count=duplicate_avoidance_count,
        opportunities_discovered=opportunities_discovered,
        browser_findings=report.web_opportunity_count,
        credential_attempts=credential_attempts,
        privilege_opportunities=report.privilege_opportunity_count,
        workflow_completion_percentage=report.workflow_completion_percentage,
        learning_replay_hits=report.learning_replay_hits,
        engagement_outcome=report.outcome,
        metrics=metrics,
    )


def benchmark_to_json_dict(bench: BenchmarkResult) -> dict[str, Any]:
    """JSON-serialisable dict for ``BenchmarkResult`` — the shape
    ``to_json_dict()`` (apex_host/eval/report.py) nests under
    ``"benchmark"``, and what ``--export-benchmark`` writes standalone."""
    return {
        "target": bench.target,
        "total_runtime_seconds": bench.total_runtime_seconds,
        "planner_decision_count": bench.planner_decision_count,
        "tasks_selected_total": bench.tasks_selected_total,
        "tasks_executed": bench.tasks_executed,
        "tasks_skipped": bench.tasks_skipped,
        "duplicate_avoidance_count": bench.duplicate_avoidance_count,
        "opportunities_discovered": bench.opportunities_discovered,
        "browser_findings": bench.browser_findings,
        "credential_attempts": bench.credential_attempts,
        "privilege_opportunities": bench.privilege_opportunities,
        "workflow_completion_percentage": bench.workflow_completion_percentage,
        "learning_replay_hits": bench.learning_replay_hits,
        "engagement_outcome": bench.engagement_outcome,
        "metrics": {
            "planner_efficiency": bench.metrics.planner_efficiency,
            "workflow_completion_percentage": bench.metrics.workflow_completion_percentage,
            "duplicate_avoidance_percentage": bench.metrics.duplicate_avoidance_percentage,
            "browser_coverage": bench.metrics.browser_coverage,
            "credential_success_rate": bench.metrics.credential_success_rate,
            "privilege_opportunity_density": bench.metrics.privilege_opportunity_density,
            "replay_usefulness": bench.metrics.replay_usefulness,
            "average_task_latency_seconds": bench.metrics.average_task_latency_seconds,
            "evidence_density": bench.metrics.evidence_density,
            "graph_growth_rate": bench.metrics.graph_growth_rate,
            "report_generation_seconds": bench.metrics.report_generation_seconds,
        },
    }


def format_benchmark_text(bench: BenchmarkResult) -> str:
    """Human-readable "Benchmark Summary" + per-category metrics sections —
    the text ``apex_host/eval/report.py::format_text`` inlines when a
    benchmark was computed for that report."""
    m = bench.metrics
    lines = [
        "Benchmark Summary",
        f"  Total runtime        : {bench.total_runtime_seconds}s",
        f"  Planner decisions    : {bench.planner_decision_count}",
        f"  Tasks executed       : {bench.tasks_executed} (skipped: {bench.tasks_skipped})",
        f"  Duplicate avoidance  : {bench.duplicate_avoidance_count}",
        f"  Opportunities found  : {bench.opportunities_discovered}",
        f"  Browser findings     : {bench.browser_findings}",
        f"  Credential attempts  : {bench.credential_attempts}",
        f"  Privilege opps       : {bench.privilege_opportunities}",
        f"  Workflow completion  : {bench.workflow_completion_percentage}%",
        f"  Learning replay hits : {bench.learning_replay_hits}",
        f"  Engagement outcome   : {bench.engagement_outcome}",
        "",
        "Performance Metrics",
        f"  Average task latency : {m.average_task_latency_seconds}s",
        f"  Graph growth rate    : {m.graph_growth_rate} nodes/turn",
        f"  Report generation    : {m.report_generation_seconds}s",
        "",
        "Planner Metrics",
        f"  Planner efficiency   : {m.planner_efficiency}",
        f"  Duplicate avoidance %: {m.duplicate_avoidance_percentage}%",
        "",
        "Memory Metrics",
        f"  Evidence density     : {m.evidence_density}",
        f"  Privilege opp density: {m.privilege_opportunity_density}",
        f"  Browser coverage     : {m.browser_coverage}",
        f"  Credential success % : {m.credential_success_rate}",
        "",
        "Learning Metrics",
        f"  Workflow completion %: {m.workflow_completion_percentage}%",
        f"  Replay usefulness    : {m.replay_usefulness}",
    ]
    return "\n".join(lines)
