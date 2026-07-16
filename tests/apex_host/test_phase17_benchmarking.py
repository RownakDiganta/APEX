# test_phase17_benchmarking.py
# Regression tests for Phase 17: benchmarking, HTB evaluation mode, and deterministic run comparison — metric formulas, latency/duplicate calculations, report generation, JSON export, and comparison determinism.
"""Phase 17 regression tests.

Covers ``apex_host.eval.benchmark`` (deterministic metric computation),
``apex_host.eval.evaluation`` (HTB evaluation-mode records, never assuming
compromise), and ``apex_host.eval.comparison`` (deterministic diff between
two engagement reports), plus their wiring into ``apex_host.eval.report``.

No exploit is executed, no payload is generated, no reverse shell is
created, no new tool execution or exploitation capability was added by any
code exercised here — every test asserts pure arithmetic/formatting over
already-known data. No Docker, Compose, VPN, or GitHub Actions files are
touched by this test file or the code it tests.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from memfabric.ids import now
from memfabric.types import Edge, Node, SubgraphView

from apex_host.config import ApexConfig
from apex_host.eval.benchmark import (
    BenchmarkMetrics,
    BenchmarkResult,
    _ratio,
    benchmark_to_json_dict,
    compute_benchmark,
    format_benchmark_text,
)
from apex_host.eval.comparison import (
    ComparisonResult,
    comparison_input_from_json_export,
    comparison_input_from_report,
    comparison_to_json_dict,
    compare_reports,
    format_comparison_text,
)
from apex_host.eval.evaluation import (
    HTBEvaluation,
    build_htb_evaluation,
    evaluation_to_json_dict,
    format_evaluation_text,
)
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.graph_ids import host_id

_TARGET = "10.10.10.201"
_ANCHOR = host_id(_TARGET)
_PROJECT_ROOT = Path(__file__).parent.parent.parent


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _host_node(target: str = _TARGET) -> Node:
    ts = now()
    return Node(id=host_id(target), type="host", props={"ip": target}, confidence=0.9, source="t", first_seen=ts, last_seen=ts)


def _service_node(target: str = _TARGET, port: str = "22") -> Node:
    ts = now()
    return Node(
        id=f"service:{target}:{port}/tcp", type="service",
        props={"port": port, "proto": "tcp", "service": "ssh", "state": "open", "version": ""},
        confidence=0.9, source="t", first_seen=ts, last_seen=ts,
    )


def _endpoint_node(target: str = _TARGET, idx: int = 0) -> Node:
    ts = now()
    return Node(
        id=f"endpoint:http://{target}/{idx}", type="endpoint",
        props={"url": f"http://{target}/{idx}"}, confidence=0.7, source="t", first_seen=ts, last_seen=ts,
    )


def _subgraph(*nodes: Node, edges: list[Edge] | None = None, target: str = _TARGET) -> SubgraphView:
    return SubgraphView(anchor=host_id(target), nodes=list(nodes), edges=edges or [], depth=10)


def _base_config(target: str = _TARGET) -> ApexConfig:
    return ApexConfig(target=target, dry_run=True, max_turns=5)


def _report_final_state(target: str = _TARGET, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "target": target, "phase": "done", "completed": True, "turn_count": 2,
        "last_error": None, "findings": [], "error_episodes": [],
        "planner_decisions": [], "policy_decisions": [], "duplicate_actions": [],
        "credential_validation_log": [], "execution_backend_log": [],
        "outcome": "validated_access", "termination_reason": "", "termination_phase": "done",
        "stall_reason": "", "privilege_state": "", "enumeration_complete": False,
        "web_session_state": {}, "workflow_summary": {}, "learning_summary": {},
        "task_latency_log": [],
    }
    base.update(overrides)
    return base


def _make_report(subgraph: SubgraphView, target: str = _TARGET, **state_overrides: Any) -> Any:
    return build_report(
        config=_base_config(target),
        final_state=_report_final_state(target, **state_overrides),
        subgraph=subgraph,
    )


# ---------------------------------------------------------------------------
# 1. _ratio helper — bounded division
# ---------------------------------------------------------------------------

class TestRatioHelper:
    def test_normal_ratio(self) -> None:
        assert _ratio(1, 4) == 0.25

    def test_zero_denominator_returns_zero(self) -> None:
        assert _ratio(5, 0) == 0.0

    def test_negative_denominator_returns_zero(self) -> None:
        assert _ratio(5, -1) == 0.0

    def test_clamped_at_one(self) -> None:
        assert _ratio(10, 2) == 1.0

    def test_zero_numerator(self) -> None:
        assert _ratio(0, 5) == 0.0


# ---------------------------------------------------------------------------
# 2. Latency calculations
# ---------------------------------------------------------------------------

class TestLatencyCalculations:
    def test_empty_latency_log_is_zero(self) -> None:
        report = _make_report(_subgraph(_host_node()), task_latency_log=[])
        bench = compute_benchmark(report, task_latency_log=[])
        assert bench.metrics.average_task_latency_seconds == 0.0

    def test_single_entry_average(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        log = [{"tool": "nmap", "phase": "recon", "duration_seconds": 2.5}]
        bench = compute_benchmark(report, task_latency_log=log)
        assert bench.metrics.average_task_latency_seconds == 2.5

    def test_multiple_entries_average(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        log = [
            {"tool": "nmap", "phase": "recon", "duration_seconds": 1.0},
            {"tool": "curl", "phase": "web", "duration_seconds": 2.0},
            {"tool": "ssh_access", "phase": "credential", "duration_seconds": 3.0},
        ]
        bench = compute_benchmark(report, task_latency_log=log)
        assert bench.metrics.average_task_latency_seconds == 2.0

    def test_none_task_latency_log_defaults_to_empty(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        bench = compute_benchmark(report, task_latency_log=None)
        assert bench.metrics.average_task_latency_seconds == 0.0

    def test_missing_duration_key_treated_as_zero(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        log = [{"tool": "nmap", "phase": "recon"}]  # no duration_seconds key
        bench = compute_benchmark(report, task_latency_log=log)
        assert bench.metrics.average_task_latency_seconds == 0.0

    def test_average_is_rounded(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        log = [
            {"tool": "a", "phase": "p", "duration_seconds": 1 / 3},
            {"tool": "b", "phase": "p", "duration_seconds": 1 / 3},
            {"tool": "c", "phase": "p", "duration_seconds": 1 / 3},
        ]
        bench = compute_benchmark(report, task_latency_log=log)
        assert bench.metrics.average_task_latency_seconds == round(1 / 3, 6)


# ---------------------------------------------------------------------------
# 3. Duplicate calculations
# ---------------------------------------------------------------------------

class TestDuplicateCalculations:
    def test_no_duplicates_no_latency_is_all_zero(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        bench = compute_benchmark(report)
        assert bench.tasks_executed == 0
        assert bench.tasks_skipped == 0
        assert bench.metrics.duplicate_avoidance_percentage == 0.0

    def test_executed_and_skipped_counted_correctly(self) -> None:
        latency_log = [{"tool": "nmap", "phase": "recon", "duration_seconds": 1.0}]
        report = _make_report(
            _subgraph(_host_node()),
            duplicate_actions=[
                {"tool": "nmap", "phase": "recon"},
                {"tool": "nmap", "phase": "recon"},
                {"tool": "nmap", "phase": "recon"},
            ],
            task_latency_log=latency_log,
        )
        bench = compute_benchmark(report, task_latency_log=latency_log)
        assert bench.tasks_executed == 1
        assert bench.tasks_skipped == 3
        assert bench.duplicate_avoidance_count == 3
        assert bench.metrics.duplicate_avoidance_percentage == 75.0

    def test_telnet_attempts_counted_as_executed_without_latency_entry(self) -> None:
        # TelnetExecutor never produces a duration_seconds entry (Phase 12B
        # invariant: byte-for-byte unchanged) — its executed attempts must
        # still count via credential_validation_entries.
        report = _make_report(
            _subgraph(_host_node()),
            credential_validation_log=[
                {"protocol": "telnet", "target": _TARGET, "success": True, "error_category": "success"},
            ],
        )
        bench = compute_benchmark(report, task_latency_log=[])
        assert bench.tasks_executed == 1

    def test_ssh_attempts_not_double_counted(self) -> None:
        # SSH DOES produce a task_latency_log entry (unlike telnet) — an SSH
        # credential_validation_log entry must not also be counted via the
        # telnet-specific fallback, or tasks_executed would double-count it.
        latency_log = [{"tool": "ssh_access", "phase": "credential", "duration_seconds": 0.5}]
        report = _make_report(
            _subgraph(_host_node()),
            credential_validation_log=[
                {"protocol": "ssh", "target": _TARGET, "success": True, "error_category": "success"},
            ],
            task_latency_log=latency_log,
        )
        bench = compute_benchmark(report, task_latency_log=latency_log)
        assert bench.tasks_executed == 1

    def test_all_skipped_zero_executed_full_avoidance(self) -> None:
        report = _make_report(
            _subgraph(_host_node()),
            duplicate_actions=[{"tool": "nmap", "phase": "recon"}],
        )
        bench = compute_benchmark(report, task_latency_log=[])
        assert bench.tasks_executed == 0
        assert bench.tasks_skipped == 1
        assert bench.metrics.duplicate_avoidance_percentage == 100.0


# ---------------------------------------------------------------------------
# 4. Planner efficiency
# ---------------------------------------------------------------------------

class TestPlannerEfficiency:
    def test_zero_decisions_is_zero(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        bench = compute_benchmark(report)
        assert bench.metrics.planner_efficiency == 0.0

    def test_efficiency_ratio(self) -> None:
        latency_log = [
            {"tool": "nmap", "phase": "recon", "duration_seconds": 1.0},
            {"tool": "curl", "phase": "web", "duration_seconds": 1.0},
        ]
        decisions = [
            {"planner_model": "deterministic", "selected_task_count": 0},
            {"planner_model": "deterministic", "selected_task_count": 0},
            {"planner_model": "deterministic", "selected_task_count": 0},
            {"planner_model": "deterministic", "selected_task_count": 0},
        ]
        report = _make_report(
            _subgraph(_host_node()), planner_decisions=decisions, task_latency_log=latency_log,
        )
        bench = compute_benchmark(report, task_latency_log=latency_log)
        assert bench.planner_decision_count == 4
        assert bench.metrics.planner_efficiency == 0.5  # 2 executed / 4 decisions

    def test_efficiency_bounded_at_one(self) -> None:
        # More executed tasks than decisions (e.g. concurrent multi-task
        # turns) must never push the ratio above 1.0.
        latency_log = [
            {"tool": "nmap", "phase": "recon", "duration_seconds": 1.0},
            {"tool": "curl", "phase": "web", "duration_seconds": 1.0},
            {"tool": "ffuf", "phase": "web", "duration_seconds": 1.0},
        ]
        decisions = [{"planner_model": "deterministic", "selected_task_count": 0}]
        report = _make_report(
            _subgraph(_host_node()), planner_decisions=decisions, task_latency_log=latency_log,
        )
        bench = compute_benchmark(report, task_latency_log=latency_log)
        assert bench.metrics.planner_efficiency == 1.0


# ---------------------------------------------------------------------------
# 5. Graph metrics — evidence density, growth rate, opportunity density
# ---------------------------------------------------------------------------

class TestGraphMetrics:
    def test_evidence_density_counts_only_evidence_types(self) -> None:
        subgraph = _subgraph(_host_node(), _service_node(), _endpoint_node())
        report = _make_report(subgraph)
        bench = compute_benchmark(report)
        # 3 total nodes (host, service, endpoint); host is NOT an evidence
        # type, service + endpoint are -> 2/3.
        assert bench.metrics.evidence_density == round(2 / 3, 4)

    def test_evidence_density_zero_when_no_nodes(self) -> None:
        report = _make_report(_subgraph())
        bench = compute_benchmark(report)
        assert bench.metrics.evidence_density == 0.0

    def test_graph_growth_rate_divides_by_turns(self) -> None:
        subgraph = _subgraph(_host_node(), _service_node())
        report = _make_report(subgraph, turn_count=2)
        bench = compute_benchmark(report)
        assert bench.metrics.graph_growth_rate == round(2 / 2, 4)

    def test_graph_growth_rate_falls_back_to_node_count_when_no_turns(self) -> None:
        subgraph = _subgraph(_host_node())
        report = _make_report(subgraph, turn_count=0)
        bench = compute_benchmark(report)
        assert bench.metrics.graph_growth_rate == 1.0

    def test_privilege_opportunity_density(self) -> None:
        ts = now()
        priv_node = Node(
            id=f"priv_esc_opportunity:{_TARGET}:docker:0", type="priv_esc_opportunity",
            props={"category": "docker", "confidence": "medium", "attempted": True, "attempt_count": 1, "exhausted": True},
            confidence=0.6, source="t", first_seen=ts, last_seen=ts,
        )
        subgraph = _subgraph(_host_node(), _service_node(), priv_node)
        report = _make_report(subgraph)
        bench = compute_benchmark(report)
        assert bench.privilege_opportunities == 1
        assert bench.metrics.privilege_opportunity_density == round(1 / 3, 4)


# ---------------------------------------------------------------------------
# 6. Browser coverage / credential success rate
# ---------------------------------------------------------------------------

class TestBrowserAndCredentialMetrics:
    def test_browser_coverage_zero_with_no_endpoints(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        bench = compute_benchmark(report)
        assert bench.metrics.browser_coverage == 0.0

    def test_credential_success_rate_zero_with_no_attempts(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        bench = compute_benchmark(report)
        assert bench.metrics.credential_success_rate == 0.0

    def test_credential_success_rate_ratio(self) -> None:
        report = _make_report(
            _subgraph(_host_node()),
            credential_validation_log=[
                {"protocol": "ssh", "target": _TARGET, "success": True, "error_category": "success"},
                {"protocol": "ftp", "target": _TARGET, "success": False, "error_category": "auth_rejected"},
            ],
        )
        bench = compute_benchmark(report)
        assert bench.credential_attempts == 2
        assert bench.metrics.credential_success_rate == 0.5


# ---------------------------------------------------------------------------
# 7. Replay usefulness / workflow completion passthrough
# ---------------------------------------------------------------------------

class TestReplayAndWorkflowMetrics:
    def test_replay_usefulness_zero_with_no_experiences(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        bench = compute_benchmark(report)
        assert bench.metrics.replay_usefulness == 0.0

    def test_replay_usefulness_ratio(self) -> None:
        ts = now()
        exp_node = Node(
            id=f"experience:{_TARGET}:repeated_planner_mistake:nmap-recon", type="experience",
            props={
                "category": "repeated_planner_mistake", "target": _TARGET, "discriminator": "nmap:recon",
                "context": "c", "evidence_excerpt": "", "outcome": "duplicate_task",
                "recommendation": "r", "confidence": "medium", "occurrence_count": 2,
            },
            confidence=0.6, source="t", first_seen=ts, last_seen=ts,
        )
        subgraph = _subgraph(_host_node(), exp_node)
        report = _make_report(
            subgraph, learning_summary={"experiences_created": 0, "experiences_reused": 1, "replay_hits": 1, "repeated_failures": 0, "improved_recommendations": []},
        )
        bench = compute_benchmark(report)
        assert bench.learning_replay_hits == 1
        assert bench.metrics.replay_usefulness == 1.0

    def test_workflow_completion_percentage_passthrough(self) -> None:
        service = _service_node()
        subgraph = _subgraph(_host_node(), service)
        report = _make_report(subgraph)
        bench = compute_benchmark(report)
        assert bench.workflow_completion_percentage == report.workflow_completion_percentage
        assert bench.metrics.workflow_completion_percentage == report.workflow_completion_percentage


# ---------------------------------------------------------------------------
# 8. Deterministic ordering / repeatability
# ---------------------------------------------------------------------------

class TestDeterministicBenchmark:
    def test_same_report_same_benchmark_every_time(self) -> None:
        latency_log = [
            {"tool": "nmap", "phase": "recon", "duration_seconds": 1.0},
            {"tool": "curl", "phase": "web", "duration_seconds": 2.0},
        ]
        subgraph = _subgraph(_host_node(), _service_node(), _endpoint_node())
        report = _make_report(subgraph, task_latency_log=latency_log)
        results = [
            compute_benchmark(report, total_runtime_seconds=1.5, task_latency_log=latency_log)
            for _ in range(5)
        ]
        first = benchmark_to_json_dict(results[0])
        for r in results[1:]:
            assert benchmark_to_json_dict(r) == first

    def test_benchmark_result_and_metrics_are_dataclasses(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        bench = compute_benchmark(report)
        assert isinstance(bench, BenchmarkResult)
        assert isinstance(bench.metrics, BenchmarkMetrics)


# ---------------------------------------------------------------------------
# 9. Benchmark JSON export
# ---------------------------------------------------------------------------

class TestBenchmarkJsonExport:
    def test_json_dict_is_json_serialisable(self) -> None:
        report = _make_report(_subgraph(_host_node(), _service_node()))
        bench = compute_benchmark(report, total_runtime_seconds=3.2, report_generation_seconds=0.01)
        payload = benchmark_to_json_dict(bench)
        text = json.dumps(payload)
        round_tripped = json.loads(text)
        assert round_tripped["total_runtime_seconds"] == 3.2
        assert "metrics" in round_tripped
        assert "planner_efficiency" in round_tripped["metrics"]

    def test_format_benchmark_text_contains_all_required_sections(self) -> None:
        report = _make_report(_subgraph(_host_node()))
        bench = compute_benchmark(report)
        text = format_benchmark_text(bench)
        for header in ("Benchmark Summary", "Performance Metrics", "Planner Metrics", "Memory Metrics", "Learning Metrics"):
            assert header in text


# ---------------------------------------------------------------------------
# 10. Report generation — integration with build_report/format_text/to_json_dict
# ---------------------------------------------------------------------------

class TestReportIntegration:
    def test_benchmark_section_present_when_turns_used(self) -> None:
        report = build_report(
            config=_base_config(), final_state=_report_final_state(turn_count=2),
            subgraph=_subgraph(_host_node()),
            total_runtime_seconds=1.23,
        )
        text = format_text(report)
        assert "Benchmark Summary" in text
        assert "Performance Metrics" in text

    def test_benchmark_section_absent_when_no_turns(self) -> None:
        report = build_report(
            config=_base_config(), final_state=_report_final_state(turn_count=0),
            subgraph=_subgraph(_host_node()),
        )
        text = format_text(report)
        assert "Benchmark Summary" not in text

    def test_json_dict_always_includes_benchmark_block(self) -> None:
        report = build_report(
            config=_base_config(), final_state=_report_final_state(),
            subgraph=_subgraph(_host_node()),
            total_runtime_seconds=5.0,
        )
        j = to_json_dict(report)
        assert j["benchmark"]["total_runtime_seconds"] == 5.0

    def test_evaluation_section_present_when_machine_name_set(self) -> None:
        report = build_report(
            config=_base_config(), final_state=_report_final_state(),
            subgraph=_subgraph(_host_node()),
            htb_machine_name="Meow", htb_difficulty="Easy",
        )
        text = format_text(report)
        assert "Evaluation Summary" in text
        assert "Meow" in text
        j = to_json_dict(report)
        assert j["evaluation"] is not None
        assert j["evaluation"]["machine_name"] == "Meow"
        assert j["evaluation"]["difficulty"] == "Easy"

    def test_evaluation_section_absent_when_no_machine_name(self) -> None:
        report = build_report(
            config=_base_config(), final_state=_report_final_state(),
            subgraph=_subgraph(_host_node()),
        )
        text = format_text(report)
        assert "Evaluation Summary" not in text
        j = to_json_dict(report)
        assert j["evaluation"] is None

    def test_report_generation_seconds_recorded(self) -> None:
        report = build_report(
            config=_base_config(), final_state=_report_final_state(),
            subgraph=_subgraph(_host_node()),
            total_runtime_seconds=1.0, report_generation_seconds=0.05,
        )
        assert report.benchmark_report_generation_seconds == 0.05
        j = to_json_dict(report)
        assert j["benchmark"]["metrics"]["report_generation_seconds"] == 0.05


# ---------------------------------------------------------------------------
# 11. HTB evaluation — never assumes compromise
# ---------------------------------------------------------------------------

class TestHTBEvaluation:
    def test_success_mirrors_report_success_exactly(self) -> None:
        # Even with services/web/priv findings, success must be False unless
        # report.success is True (i.e. validated_access outcome).
        ts = now()
        priv_node = Node(
            id=f"priv_esc_opportunity:{_TARGET}:docker:0", type="priv_esc_opportunity",
            props={"category": "docker", "confidence": "medium", "attempted": True, "attempt_count": 1, "exhausted": True},
            confidence=0.6, source="t", first_seen=ts, last_seen=ts,
        )
        subgraph = _subgraph(_host_node(), _service_node(), _service_node(port="80"), priv_node)
        report = build_report(
            config=_base_config(), final_state=_report_final_state(outcome="max_turns_exhausted"),
            subgraph=subgraph,
        )
        assert report.success is False
        evaluation = build_htb_evaluation(report, machine_name="Cap", difficulty="Easy")
        assert evaluation.success is False
        assert evaluation.privilege_opportunities == 1  # findings exist but success is still False

    def test_success_true_only_on_validated_access(self) -> None:
        access_node = Node(
            id=f"access_state:{_TARGET}:root:ssh", type="access_state",
            props={"username": "root", "target": _TARGET, "service": "ssh"},
            confidence=0.9, source="t", first_seen=now(), last_seen=now(),
        )
        subgraph = _subgraph(_host_node(), access_node)
        report = build_report(
            config=_base_config(), final_state=_report_final_state(outcome="validated_access"),
            subgraph=subgraph,
        )
        evaluation = build_htb_evaluation(report, machine_name="Cap", difficulty="Easy")
        assert evaluation.success is True
        assert evaluation.credentials_validated == 1

    def test_services_discovered_from_node_counts(self) -> None:
        subgraph = _subgraph(_host_node(), _service_node(port="22"), _service_node(port="80"))
        report = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=subgraph)
        evaluation = build_htb_evaluation(report, machine_name="M", difficulty="Medium")
        assert evaluation.services_discovered == 2

    def test_evaluation_json_dict_shape(self) -> None:
        evaluation = HTBEvaluation(
            machine_name="M", difficulty="Easy", target=_TARGET,
            services_discovered=1, credentials_validated=0, web_findings=0,
            privilege_opportunities=0, final_outcome="max_turns_exhausted",
            success=False, turns_used=3,
        )
        payload = evaluation_to_json_dict(evaluation)
        assert payload["machine_name"] == "M"
        assert payload["success"] is False
        text = format_evaluation_text(evaluation)
        assert "M" in text
        assert "No" in text

    def test_machine_name_never_inferred_from_target(self) -> None:
        # machine_name/difficulty must be exactly what was passed in — never
        # derived from the target string.
        subgraph = _subgraph(_host_node())
        report = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=subgraph)
        evaluation = build_htb_evaluation(report, machine_name="Unrelated Name", difficulty="Hard")
        assert evaluation.machine_name == "Unrelated Name"
        assert evaluation.target == _TARGET


# ---------------------------------------------------------------------------
# 12. Comparison engine
# ---------------------------------------------------------------------------

class TestComparisonEngine:
    def test_identical_reports_produce_no_diff(self) -> None:
        subgraph = _subgraph(_host_node(), _service_node())
        report = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=subgraph)
        a = comparison_input_from_report(report)
        b = comparison_input_from_report(report)
        result = compare_reports(a, b)
        assert result.new_findings == []
        assert result.missing_findings == []
        assert all(v == 0 for v in result.planner_differences.values())
        assert result.workflow_differences["workflow_count_delta"] == 0
        assert result.timing_differences["turns_used_delta"] == 0

    def test_new_and_missing_findings_by_id(self) -> None:
        finding_a = {"id": "endpoint:http://a/1", "phase": "web", "title": "t", "detail": "d", "confidence": 0.5, "source": "s", "timestamp": "t"}
        finding_b = {"id": "endpoint:http://b/2", "phase": "web", "title": "t2", "detail": "d2", "confidence": 0.5, "source": "s", "timestamp": "t"}
        report_a = build_report(
            config=_base_config(), final_state=_report_final_state(findings=[finding_a]),
            subgraph=_subgraph(_host_node()),
        )
        report_b = build_report(
            config=_base_config(), final_state=_report_final_state(findings=[finding_b]),
            subgraph=_subgraph(_host_node()),
        )
        a = comparison_input_from_report(report_a)
        b = comparison_input_from_report(report_b)
        result = compare_reports(a, b)
        assert len(result.new_findings) == 1
        assert result.new_findings[0]["id"] == "endpoint:http://b/2"
        assert len(result.missing_findings) == 1
        assert result.missing_findings[0]["id"] == "endpoint:http://a/1"

    def test_shared_findings_are_neither_new_nor_missing(self) -> None:
        finding = {"id": "host:10.10.10.201", "phase": "recon", "title": "t", "detail": "d", "confidence": 0.9, "source": "s", "timestamp": "t"}
        report_a = build_report(
            config=_base_config(), final_state=_report_final_state(findings=[finding]),
            subgraph=_subgraph(_host_node()),
        )
        report_b = build_report(
            config=_base_config(), final_state=_report_final_state(findings=[finding]),
            subgraph=_subgraph(_host_node()),
        )
        result = compare_reports(comparison_input_from_report(report_a), comparison_input_from_report(report_b))
        assert result.new_findings == []
        assert result.missing_findings == []

    def test_opportunity_category_deltas(self) -> None:
        ts = now()
        docker_node = Node(
            id=f"priv_esc_opportunity:{_TARGET}:docker:0", type="priv_esc_opportunity",
            props={"category": "docker", "confidence": "medium", "attempted": True, "attempt_count": 1, "exhausted": True},
            confidence=0.6, source="t", first_seen=ts, last_seen=ts,
        )
        sudo_node = Node(
            id=f"priv_esc_opportunity:{_TARGET}:sudo:0", type="priv_esc_opportunity",
            props={"category": "sudo", "confidence": "medium", "attempted": True, "attempt_count": 1, "exhausted": True},
            confidence=0.6, source="t", first_seen=ts, last_seen=ts,
        )
        report_a = build_report(
            config=_base_config(), final_state=_report_final_state(),
            subgraph=_subgraph(_host_node(), docker_node),
        )
        report_b = build_report(
            config=_base_config(), final_state=_report_final_state(),
            subgraph=_subgraph(_host_node(), docker_node, sudo_node),
        )
        result = compare_reports(comparison_input_from_report(report_a), comparison_input_from_report(report_b))
        assert result.opportunity_differences["privilege_opportunity_count_delta"] == 1
        assert result.opportunity_differences["privilege_category_deltas"]["sudo"] == 1
        assert result.opportunity_differences["privilege_category_deltas"]["docker"] == 0

    def test_learning_differences(self) -> None:
        report_a = build_report(
            config=_base_config(), final_state=_report_final_state(), subgraph=_subgraph(_host_node()),
        )
        report_b = build_report(
            config=_base_config(),
            final_state=_report_final_state(learning_summary={"experiences_created": 2, "experiences_reused": 0, "replay_hits": 0, "repeated_failures": 0, "improved_recommendations": []}),
            subgraph=_subgraph(_host_node()),
        )
        result = compare_reports(comparison_input_from_report(report_a), comparison_input_from_report(report_b))
        assert result.learning_differences["experiences_created_delta"] == 2

    def test_comparison_result_is_dataclass(self) -> None:
        report = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=_subgraph(_host_node()))
        a = comparison_input_from_report(report)
        result = compare_reports(a, a)
        assert isinstance(result, ComparisonResult)

    def test_deterministic_repeated_comparison(self) -> None:
        report_a = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=_subgraph(_host_node()))
        report_b = build_report(config=_base_config(target="10.10.10.202"), final_state=_report_final_state(target="10.10.10.202"), subgraph=_subgraph(_host_node(target="10.10.10.202"), target="10.10.10.202"))
        a = comparison_input_from_report(report_a)
        b = comparison_input_from_report(report_b)
        results = [comparison_to_json_dict(compare_reports(a, b)) for _ in range(5)]
        first = results[0]
        for r in results[1:]:
            assert r == first


# ---------------------------------------------------------------------------
# 13. Comparison JSON export + cross-process input extraction
# ---------------------------------------------------------------------------

class TestComparisonJsonExportAndCrossProcess:
    def test_comparison_to_json_dict_serialisable(self) -> None:
        report = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=_subgraph(_host_node()))
        a = comparison_input_from_report(report)
        result = compare_reports(a, a)
        payload = comparison_to_json_dict(result)
        text = json.dumps(payload)
        assert json.loads(text) == payload

    def test_format_comparison_text_contains_all_sections(self) -> None:
        report = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=_subgraph(_host_node()))
        a = comparison_input_from_report(report)
        result = compare_reports(a, a)
        text = format_comparison_text(result)
        for header in ("Comparison Summary", "New findings", "Missing findings", "Planner differences", "Workflow differences", "Timing differences", "Opportunity diffs", "Learning differences"):
            assert header in text

    def test_json_export_extractor_matches_in_process_extractor(self) -> None:
        """The two input paths (in-process RunReport vs. loaded
        to_json_dict() JSON) must produce equivalent comparison-input
        shapes for the same underlying report — proving --compare-with
        (cross-process) and in-process comparison agree."""
        subgraph = _subgraph(_host_node(), _service_node(), _endpoint_node())
        report = build_report(
            config=_base_config(), final_state=_report_final_state(),
            subgraph=subgraph, total_runtime_seconds=1.0,
        )
        from_report = comparison_input_from_report(report)
        from_json = comparison_input_from_json_export(to_json_dict(report))
        assert from_report == from_json

    def test_compare_json_loaded_baseline_against_live_report(self) -> None:
        subgraph_a = _subgraph(_host_node())
        report_a = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=subgraph_a)
        exported = json.loads(json.dumps(to_json_dict(report_a), default=str))

        subgraph_b = _subgraph(_host_node(), _service_node())
        report_b = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=subgraph_b)

        result = compare_reports(
            comparison_input_from_json_export(exported),
            comparison_input_from_report(report_b),
        )
        assert result.timing_differences["total_nodes_delta"] == 1


# ---------------------------------------------------------------------------
# 14. Safety — no I/O / no subprocess / no network in the new modules
# ---------------------------------------------------------------------------

class TestNoIOInNewModules:
    @pytest.mark.parametrize("filename", ["benchmark.py", "evaluation.py", "comparison.py"])
    def test_no_subprocess_or_network_calls(self, filename: str) -> None:
        src = (_PROJECT_ROOT / "apex_host" / "eval" / filename).read_text(encoding="utf-8")
        for marker in ("subprocess", "asyncio.create_subprocess", "socket.", "requests.", "httpx.", "urlopen"):
            assert marker not in src

    @pytest.mark.parametrize("filename", ["benchmark.py", "evaluation.py", "comparison.py"])
    def test_module_has_file_header(self, filename: str) -> None:
        path = _PROJECT_ROOT / "apex_host" / "eval" / filename
        lines = path.read_text(encoding="utf-8").splitlines()
        assert lines[0] == f"# {filename}"
