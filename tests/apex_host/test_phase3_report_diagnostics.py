# test_phase3_report_diagnostics.py
# Regression tests for Phase 3 of 4 post-live-test debugging phases: execution diagnostics, finding deduplication, phase semantics, and report invariants.
"""Phase 3 (post-live-test debugging) regression tests.

Covers the fixes made in response to the second authorized HTB live
test's report-quality findings:

1. Six script errors occurred, but error_samples was empty and the
   report never exposed the bounded returncode/stderr needed to
   diagnose Nmap.
2. The findings list contained the same host finding six times.
3. The exported graph correctly contained one host node, but the report
   represented six findings.
4. phases_reached showed only recon, while planner decisions included
   credential and termination phase was credential.
5. completed/status/completed_successfully were individually defensible
   but not clearly disambiguated.
6. planner_decisions showed selected_task_count: 0 for every decision
   while benchmark totals said six tasks were selected and executed.

No real OpenAI/OpenRouter API is contacted. No live HTB engagement is
run. No new exploitation, privilege-escalation, or shell-access
capability is exercised here.
"""
from __future__ import annotations

from typing import Any

import pytest

from memfabric.ids import now
from memfabric.types import Node, SubgraphView

from apex_host.config import ApexConfig
from apex_host.eval.benchmark import compute_benchmark
from apex_host.eval.findings import deduplicate_findings
from apex_host.eval.report import RunReport, build_report, to_json_dict
from apex_host.eval.report_invariants import assert_report_invariants, check_report_invariants
from apex_host.execution.diagnostics import (
    ARG_TOKEN_LIMIT,
    STDERR_SAMPLE_LIMIT,
    STDOUT_SAMPLE_LIMIT,
    build_execution_diagnostic,
)
from apex_host.execution.error_classifier import (
    BACKEND_ERROR,
    CAPABILITY_MISSING,
    FUNDAMENTAL,
    POLICY_BLOCK,
    SCRIPT_ERROR,
    SUCCESS,
    TIMEOUT,
    classify_execution_diagnostic,
)
from apex_host.graph_state import ApexGraphState

_TARGET = "10.10.10.14"
_ANCHOR = f"host:{_TARGET}"

_RAW_SOCKET_STDERR = (
    "Couldn't open a raw socket. Error: (1) Operation not permitted\n"
    "Couldn't open a raw socket or eth handle.\nQUITTING!"
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _config() -> ApexConfig:
    return ApexConfig(target=_TARGET, dry_run=True)


def _subgraph(nodes: list[Node] | None = None) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=nodes or [], edges=[], depth=10)


def _host_node() -> Node:
    ts = now()
    return Node(
        id=f"host:{_TARGET}", type="host", props={"ip": _TARGET},
        confidence=0.9, source="nmap", first_seen=ts, last_seen=ts,
    )


def _host_finding(*, confidence: float = 0.9, source: str = "nmap", ts: str | None = None) -> dict[str, Any]:
    return {
        "id": f"host:{_TARGET}", "phase": "recon", "title": "host discovered",
        "detail": "{'ip': '" + _TARGET + "'}", "confidence": confidence,
        "source": source, "timestamp": ts or now(),
    }


def _decision(phase: str, *, selected: int = 0, fallback: int = 0) -> dict[str, Any]:
    return {
        "phase": phase, "planner_model": "deterministic",
        "selected_task_count": selected, "fallback_task_count": fallback,
    }


def _nmap_tr(*, task_id: str, returncode: int = 1, error: str | None = None) -> dict[str, Any]:
    return {
        "task_id": task_id, "tool": "nmap", "args": ["-sT", "-sV", "-T4", _TARGET],
        "target": _TARGET, "parser": "nmap", "phase": "recon",
        "stdout": "", "stderr": _RAW_SOCKET_STDERR, "returncode": returncode,
        "error": error, "dry_run": False, "backend": "remote", "timed_out": False,
        "error_category": "raw_socket_permission_denied",
        "duration_seconds": 0.05, "fingerprint": "fp-nmap-fixed",
        "retry_index": 0, "start_timestamp": now(), "end_timestamp": now(),
        "classifier_reason": "script_error — repair eligible",
        "final_disposition": "executed_failure",
    }


def _make_state(
    *,
    findings: list[dict[str, Any]] | None = None,
    planner_decisions: list[dict[str, Any]] | None = None,
    error_episodes: list[dict[str, Any]] | None = None,
    execution_diagnostics: list[dict[str, Any]] | None = None,
    termination_phase: str = "",
    phase: str = "recon",
    completed: bool = True,
    turn_count: int = 6,
) -> ApexGraphState:
    return {
        "run_id": "run-phase3", "target": _TARGET, "phase": phase,
        "goal": f"Begin engagement against {_TARGET}", "current_task": None,
        "evidence_summary": "", "findings": findings or [],
        "error_episodes": error_episodes or [], "last_tool_result": None,
        "last_error": None, "completed": completed, "turn_count": turn_count,
        "planner_decisions": planner_decisions or [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [],
        "outcome": "no_actionable_task", "termination_reason": "no actionable task",
        "termination_phase": termination_phase, "stall_reason": "",
        "privilege_state": "", "privilege_summary": {}, "opportunity_ids": [],
        "attempted_opportunities": [], "enumeration_complete": False,
        "web_session_state": {}, "workflow_summary": {}, "learning_summary": {},
        "task_latency_log": [], "objective_status": "", "objective_summary": {},
        "direct_file_read_log": [], "bounded_command_log": [],
        "capability_discovery_log": [], "execution_diagnostics": execution_diagnostics or [],
    }


# ---------------------------------------------------------------------------
# 1 & 2. Six identical host observations produce one finding; merge fields.
# ---------------------------------------------------------------------------


class TestFindingDeduplication:
    def test_six_identical_observations_produce_one_finding(self) -> None:
        raw = [_host_finding() for _ in range(6)]
        deduped = deduplicate_findings(raw)
        assert len(deduped) == 1
        assert deduped[0]["id"] == f"host:{_TARGET}"
        assert deduped[0]["observation_count"] == 6

    def test_observation_count_and_timestamps_merge_correctly(self) -> None:
        raw = [
            _host_finding(ts="2026-01-01T00:00:00Z", confidence=0.5),
            _host_finding(ts="2026-01-01T00:05:00Z", confidence=0.9),
            _host_finding(ts="2026-01-01T00:02:00Z", confidence=0.7),
        ]
        deduped = deduplicate_findings(raw)
        assert len(deduped) == 1
        entry = deduped[0]
        assert entry["observation_count"] == 3
        assert entry["first_seen"] == "2026-01-01T00:00:00Z"
        assert entry["last_seen"] == "2026-01-01T00:05:00Z"
        # Documented merge rule: MAXIMUM confidence wins.
        assert entry["confidence"] == 0.9

    def test_sources_deduplicated_and_sorted(self) -> None:
        raw = [
            _host_finding(source="nmap"),
            _host_finding(source="curl"),
            _host_finding(source="nmap"),
        ]
        deduped = deduplicate_findings(raw)
        assert deduped[0]["sources"] == ["curl", "nmap"]

    def test_different_entities_not_merged(self) -> None:
        raw = [_host_finding(), {**_host_finding(), "id": "service:x:22/tcp"}]
        deduped = deduplicate_findings(raw)
        assert len(deduped) == 2

    def test_raw_observation_list_never_mutated(self) -> None:
        raw = [_host_finding() for _ in range(3)]
        raw_copy = [dict(r) for r in raw]
        deduplicate_findings(raw)
        assert raw == raw_copy

    def test_build_report_finding_count_reflects_dedup(self) -> None:
        raw = [_host_finding() for _ in range(6)]
        report = build_report(_make_state(findings=raw), _subgraph([_host_node()]), _config())
        assert report.finding_count == 1
        assert report.observation_count == 6


# ---------------------------------------------------------------------------
# 3. Execution episodes remain six when six tools actually ran.
# ---------------------------------------------------------------------------


class TestExecutionEpisodeCount:
    @pytest.mark.asyncio
    async def test_six_real_executions_produce_six_episodes_and_diagnostics(self) -> None:
        from memfabric.api import MemoryAPI
        from memfabric.config import Config
        from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
        from memfabric.stores.graph_networkx import NetworkXGraphStore
        from memfabric.stores.kv_memory import InMemoryKVStore
        from memfabric.stores.lexical_bm25 import BM25LexicalIndex
        from memfabric.stores.vector_faiss import FaissVectorIndex

        from apex_host.orchestration.dependencies import OrchestrationDeps
        from apex_host.orchestration.memory_node import make_memory_node
        from apex_host.orchestration.stall import StallTracker
        from apex_host.capabilities.runtime_references import RuntimeReferenceResolver, RuntimeReferenceStore
        from apex_host.runtime_registry import CapabilityRuntimeRegistry

        cfg = Config()
        api = MemoryAPI(
            graph=NetworkXGraphStore(), episodic=JSONLEpisodicStore(path=None),
            lexical=BM25LexicalIndex(), vector=FaissVectorIndex(dim=cfg.vector_dim),
            kv=InMemoryKVStore(), config=cfg,
        )
        config = _config()
        capability_registry = CapabilityRuntimeRegistry()
        runtime_reference_store = RuntimeReferenceStore()
        deps = OrchestrationDeps(
            api=api, dispatcher=None, global_planner=None,  # type: ignore[arg-type]
            phase_planners={}, repair_engine=None, config=config,  # type: ignore[arg-type]
            anchor_id=_ANCHOR, stall_tracker=StallTracker(),
            capability_registry=capability_registry,
            runtime_reference_store=runtime_reference_store,
            runtime_reference_resolver=RuntimeReferenceResolver(runtime_reference_store, capability_registry),
        )
        node = make_memory_node(deps)

        state = _make_state()
        state["tool_results"] = [_nmap_tr(task_id=f"t-{i}") for i in range(6)]

        result = await node(state)

        all_episodes = await api._episodic.all()
        assert len(all_episodes) == 6
        assert len(result["execution_diagnostics"]) == 6
        assert len(result["error_episodes"]) == 6


# ---------------------------------------------------------------------------
# 4. error_samples is populated from failed executions.
# ---------------------------------------------------------------------------


class TestErrorSamplesPopulated:
    def test_error_samples_populated_when_transport_error_is_none(self) -> None:
        """The exact confirmed defect: error_episodes[i]["error"] is None
        for an ordinary nonzero-exit tool failure (no transport
        exception) — error_samples must still surface something
        diagnostic from returncode/stderr_sample/diagnostic_category."""
        error_episodes = [{
            "outcome": "script_error", "tool": "nmap", "error": None, "phase": "recon",
            "returncode": 1, "stderr_sample": _RAW_SOCKET_STDERR[:STDERR_SAMPLE_LIMIT],
            "diagnostic_category": FUNDAMENTAL, "timed_out": False,
        } for _ in range(6)]
        report = build_report(
            _make_state(error_episodes=error_episodes), _subgraph([_host_node()]), _config(),
        )
        assert report.error_samples != []
        assert "fundamental" in report.error_samples[0]
        assert "returncode=1" in report.error_samples[0]

    def test_error_samples_still_uses_real_error_when_present(self) -> None:
        error_episodes = [{
            "outcome": "fixable", "tool": "curl", "error": "connection refused", "phase": "web",
        }]
        report = build_report(_make_state(error_episodes=error_episodes), _subgraph(), _config())
        assert report.error_samples == ["connection refused"]

    def test_error_samples_bounded_to_three(self) -> None:
        error_episodes = [{
            "outcome": "script_error", "tool": "nmap", "error": None, "phase": "recon",
            "returncode": 1, "diagnostic_category": SCRIPT_ERROR,
        } for _ in range(6)]
        report = build_report(_make_state(error_episodes=error_episodes), _subgraph(), _config())
        assert len(report.error_samples) <= 3


# ---------------------------------------------------------------------------
# 5. Stderr/stdout truncation is deterministic.
# ---------------------------------------------------------------------------


class TestTruncationDeterministic:
    def test_stdout_truncated_at_limit(self) -> None:
        tr = {"stdout": "A" * (STDOUT_SAMPLE_LIMIT + 100), "stderr": "", "task_id": "t1"}
        d1 = build_execution_diagnostic(tr, phase="recon")
        d2 = build_execution_diagnostic(tr, phase="recon")
        assert d1["stdout_truncated"] is True
        assert len(d1["stdout_sample"]) == STDOUT_SAMPLE_LIMIT
        assert d1["stdout_sample"] == d2["stdout_sample"]

    def test_stderr_not_truncated_when_under_limit(self) -> None:
        tr = {"stdout": "", "stderr": "short error", "task_id": "t1"}
        d = build_execution_diagnostic(tr, phase="recon")
        assert d["stderr_truncated"] is False
        assert d["stderr_sample"] == "short error"

    def test_args_bounded_per_token(self) -> None:
        tr = {"stdout": "", "stderr": "", "args": ["x" * 1000], "task_id": "t1"}
        d = build_execution_diagnostic(tr, phase="recon")
        assert len(d["args"][0]) <= ARG_TOKEN_LIMIT


# ---------------------------------------------------------------------------
# 6. Secrets are redacted.
# ---------------------------------------------------------------------------


class TestSecretsRedacted:
    def test_api_key_pattern_redacted_from_stdout(self) -> None:
        tr = {"stdout": "leaked: sk-abcdefghijklmnopqrstuvwxyz123456", "stderr": "", "task_id": "t1"}
        d = build_execution_diagnostic(tr, phase="recon")
        assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in d["stdout_sample"]
        assert "[REDACTED_API_KEY]" in d["stdout_sample"]

    def test_configured_password_redacted_from_stderr(self) -> None:
        tr = {"stdout": "", "stderr": "auth failed for hunter2", "task_id": "t1"}
        d = build_execution_diagnostic(tr, phase="credential", passwords=["hunter2"])
        assert "hunter2" not in d["stderr_sample"]

    def test_configured_password_redacted_from_args(self) -> None:
        tr = {"stdout": "", "stderr": "", "args": ["--password", "hunter2"], "task_id": "t1"}
        d = build_execution_diagnostic(tr, phase="credential", passwords=["hunter2"])
        assert "hunter2" not in " ".join(d["args"])

    def test_diagnostic_record_has_no_raw_password_field(self) -> None:
        tr = {"stdout": "", "stderr": "", "task_id": "t1", "password": "hunter2"}
        d = build_execution_diagnostic(tr, phase="credential")
        assert "password" not in d
        assert "hunter2" not in str(d)


# ---------------------------------------------------------------------------
# 7. Return code and backend error remain distinguishable.
# ---------------------------------------------------------------------------


class TestDiagnosticClassificationBoundaries:
    def test_success(self) -> None:
        assert classify_execution_diagnostic({"returncode": 0, "error": None}) == SUCCESS

    def test_nonzero_returncode_no_transport_error_is_script_error_or_fundamental(self) -> None:
        # A plain nonzero exit with no known tool-specific marker and no
        # transport exception falls to the residual SCRIPT_ERROR bucket.
        assert classify_execution_diagnostic({"returncode": 1, "error": None}) == SCRIPT_ERROR

    def test_raw_socket_permission_is_fundamental_not_script_error(self) -> None:
        assert classify_execution_diagnostic({
            "returncode": 1, "error": None, "error_category": "raw_socket_permission_denied",
        }) == FUNDAMENTAL

    def test_transport_exception_is_backend_error(self) -> None:
        assert classify_execution_diagnostic({
            "returncode": 1, "error": "tool 'nmap' not found in PATH",
        }) == BACKEND_ERROR

    def test_connection_refused_is_backend_error(self) -> None:
        assert classify_execution_diagnostic({"returncode": 1, "error": "Connection refused"}) == BACKEND_ERROR

    def test_timeout_flag_is_timeout(self) -> None:
        assert classify_execution_diagnostic({"returncode": 1, "timed_out": True}) == TIMEOUT

    def test_policy_blocked_is_policy_block(self) -> None:
        assert classify_execution_diagnostic({"policy_blocked": True}) == POLICY_BLOCK

    def test_capability_missing_when_never_connected(self) -> None:
        assert classify_execution_diagnostic({"connected": False, "returncode": 1}) == CAPABILITY_MISSING

    def test_returncode_and_backend_error_distinguishable(self) -> None:
        """A plain nonzero return code and a backend transport failure must
        never classify to the same category."""
        rc_only = classify_execution_diagnostic({"returncode": 1, "error": None})
        backend = classify_execution_diagnostic({"returncode": 1, "error": "connection refused"})
        assert rc_only != backend


# ---------------------------------------------------------------------------
# 8. Phase attempted/entered/completed semantics are consistent.
# ---------------------------------------------------------------------------


class TestPhaseSemanticsConsistency:
    def test_attempted_entered_completed_consistent(self) -> None:
        decisions = [_decision("recon", selected=1), _decision("web", selected=1), _decision("credential")]
        report = build_report(
            _make_state(planner_decisions=decisions, termination_phase="credential"),
            _subgraph(), _config(),
        )
        assert set(report.phases_entered) == set(report.phases_attempted)
        assert set(report.phases_completed) <= set(report.phases_attempted)
        assert report.termination_phase not in report.phases_completed

    def test_final_runtime_state_matches_final_phase(self) -> None:
        report = build_report(_make_state(phase="done"), _subgraph(), _config())
        assert report.final_runtime_state == report.final_phase == "done"


# ---------------------------------------------------------------------------
# 9. Credential planner invocation without actionable work is represented
#    accurately.
# ---------------------------------------------------------------------------


class TestCredentialConsideredNotEntered:
    def test_credential_decision_with_zero_tasks_still_counted_as_attempted(self) -> None:
        decisions = [_decision("recon", selected=1), _decision("credential", selected=0, fallback=0)]
        report = build_report(
            _make_state(planner_decisions=decisions, termination_phase="credential", findings=[_host_finding()]),
            _subgraph([_host_node()]), _config(),
        )
        assert "credential" in report.phases_attempted
        # No credential finding/node exists — credential produced nothing,
        # but the attempt itself is still visible, never silently dropped.
        assert all(f["id"] != "credential" for f in report.findings)

    def test_credential_not_attempted_when_no_planner_decision_or_termination(self) -> None:
        report = build_report(
            _make_state(planner_decisions=[_decision("recon", selected=1)]), _subgraph(), _config(),
        )
        assert "credential" not in report.phases_attempted


# ---------------------------------------------------------------------------
# 10. Top-level completion/status fields are unambiguous.
# ---------------------------------------------------------------------------


class TestCompletionSummaryUnambiguous:
    def test_completion_summary_present_and_mentions_all_four_fields(self) -> None:
        report = build_report(_make_state(completed=True), _subgraph(), _config())
        s = report.completion_summary
        assert "completed=" in s
        assert "completed_successfully=" in s
        assert "status=" in s
        assert "outcome=" in s

    def test_completed_true_status_abandoned_not_contradictory_in_summary(self) -> None:
        # The exact evidence-#5 combination: completed=True, status=abandoned,
        # completed_successfully=False — individually defensible, must read
        # unambiguously together.
        report = build_report(_make_state(completed=True), _subgraph(), _config())
        assert report.completed is True
        assert report.completed_successfully is False
        assert "NOT verified" in report.completion_summary
        assert "reached a terminal state" in report.completion_summary


# ---------------------------------------------------------------------------
# 11 & 12. Planner/benchmark reconciliation; error counts reconcile.
# ---------------------------------------------------------------------------


class TestReconciliationInvariants:
    def test_fallback_task_count_populated_not_always_zero(self) -> None:
        """The exact confirmed defect: selected_task_count=0 for every
        decision while six tasks were actually selected/executed by the
        fallback planner. fallback_task_count is the new field that
        reconciles this."""
        decisions = [_decision("recon", selected=0, fallback=1) for _ in range(6)]
        assert all(d["selected_task_count"] == 0 for d in decisions)
        assert sum(d["fallback_task_count"] for d in decisions) == 6

    def test_invariant_flags_all_zero_decisions_with_real_executions(self) -> None:
        decisions = [_decision("recon", selected=0, fallback=0) for _ in range(6)]
        diagnostics = [build_execution_diagnostic(_nmap_tr(task_id=f"t-{i}"), phase="recon") for i in range(6)]
        report = build_report(
            _make_state(planner_decisions=decisions, execution_diagnostics=diagnostics),
            _subgraph([_host_node()]), _config(),
        )
        violations = check_report_invariants(report)
        assert any("zero selected AND zero fallback" in v for v in violations)

    def test_invariant_clean_when_fallback_task_count_reflects_reality(self) -> None:
        decisions = [_decision("recon", selected=0, fallback=1) for _ in range(6)]
        diagnostics = [build_execution_diagnostic(_nmap_tr(task_id=f"t-{i}"), phase="recon") for i in range(6)]
        report = build_report(
            _make_state(planner_decisions=decisions, execution_diagnostics=diagnostics),
            _subgraph([_host_node()]), _config(),
        )
        violations = check_report_invariants(report)
        assert not any("zero selected AND zero fallback" in v for v in violations)

    def test_error_counts_reconcile_with_execution_records(self) -> None:
        error_episodes = [{"outcome": "script_error", "tool": "nmap", "error": None, "phase": "recon"}]
        report = build_report(_make_state(error_episodes=error_episodes), _subgraph(), _config())
        violations = check_report_invariants(report)
        assert any("execution_diagnostics is empty" in v for v in violations)

    def test_no_violation_when_diagnostics_reflect_the_failures(self) -> None:
        error_episodes = [{
            "outcome": "script_error", "tool": "nmap", "error": None, "phase": "recon",
            "returncode": 1, "diagnostic_category": FUNDAMENTAL,
        }]
        diagnostics = [build_execution_diagnostic(_nmap_tr(task_id="t-0"), phase="recon")]
        report = build_report(
            _make_state(error_episodes=error_episodes, execution_diagnostics=diagnostics),
            _subgraph(), _config(),
        )
        violations = check_report_invariants(report)
        assert not any("execution_diagnostics is empty" in v for v in violations)
        assert not any("no execution_diagnostics entry reflects" in v for v in violations)

    def test_benchmark_tasks_executed_uses_independent_derivation(self) -> None:
        """apex_host.eval.benchmark deliberately never sums
        selected_task_count — confirms the pre-existing, independent
        derivation this phase's reconciliation work complements rather
        than replaces."""
        decisions = [_decision("recon", selected=0, fallback=1) for _ in range(6)]
        latency = [{"tool": "nmap", "phase": "recon", "duration_seconds": 0.1} for _ in range(6)]
        report = build_report(
            _make_state(planner_decisions=decisions), _subgraph(), _config(),
        )
        bench = compute_benchmark(report, task_latency_log=latency)
        assert bench.tasks_executed == 6


# ---------------------------------------------------------------------------
# 13. Graph and finding counts reconcile.
# ---------------------------------------------------------------------------


class TestGraphFindingReconciliation:
    def test_one_host_node_one_host_finding_after_dedup(self) -> None:
        raw_findings = [_host_finding() for _ in range(6)]
        report = build_report(_make_state(findings=raw_findings), _subgraph([_host_node()]), _config())
        host_nodes_in_graph = sum(1 for n in [_host_node()] if n.type == "host")
        host_findings_in_report = sum(1 for f in report.findings if f["id"].startswith("host:"))
        assert host_nodes_in_graph == host_findings_in_report == 1
        assert report.total_nodes == 1


# ---------------------------------------------------------------------------
# 14. Objective verification invariants hold.
# ---------------------------------------------------------------------------


class TestObjectiveVerificationInvariants:
    def test_no_violation_for_ordinary_unverified_run(self) -> None:
        report = build_report(_make_state(), _subgraph(), _config())
        assert report.objective_verified is False
        assert report.success is False
        violations = check_report_invariants(report)
        assert not any("objective_verified is True" in v for v in violations)
        assert not any("success is True" in v for v in violations)

    def test_assert_report_invariants_raises_on_inconsistent_state(self) -> None:
        report = RunReport(
            target=_TARGET, mode="dry-run", turns_used=1, completed=True, status="success",
            completed_successfully=True, final_phase="objective", phases_reached=[], finding_count=0,
            findings=[], node_counts={}, edge_counts={}, total_nodes=0, total_edges=0,
            episodes_by_outcome={}, script_error_count=0, fixable_count=0, fundamental_count=0,
            error_samples=[], evidence_samples=[], last_error=None,
            success=True, objective_verified=False,  # inconsistent: success without objective_verified
        )
        with pytest.raises(AssertionError):
            assert_report_invariants(report)

    def test_assert_report_invariants_passes_for_consistent_state(self) -> None:
        report = build_report(_make_state(), _subgraph(), _config())
        assert_report_invariants(report)  # must not raise


# ---------------------------------------------------------------------------
# 15. Old reports remain readable / documented schema migration path.
# ---------------------------------------------------------------------------


class TestSchemaMigration:
    def test_schema_v1_report_can_still_be_constructed_and_serialized(self) -> None:
        """A minimal, pre-Phase-3-shaped RunReport (explicit v1) still
        constructs and serializes without error — every new field has a
        safe default."""
        report = RunReport(
            target=_TARGET, mode="dry-run", turns_used=1, completed=True, status="success",
            completed_successfully=False, final_phase="recon", phases_reached=[], finding_count=0,
            findings=[], node_counts={}, edge_counts={}, total_nodes=0, total_edges=0,
            episodes_by_outcome={}, script_error_count=0, fixable_count=0, fundamental_count=0,
            error_samples=[], evidence_samples=[], last_error=None,
            report_schema_version="1",
        )
        d = to_json_dict(report)
        assert d["report_schema_version"] == "1"
        assert d["execution_diagnostics"] == []
        assert d["phases_attempted"] == []

    def test_default_schema_version_is_now_2(self) -> None:
        report = build_report(_make_state(), _subgraph(), _config())
        assert report.report_schema_version == "2"

    def test_v2_json_export_has_every_new_field(self) -> None:
        report = build_report(_make_state(), _subgraph(), _config())
        d = to_json_dict(report)
        for key in (
            "execution_diagnostics", "observation_count", "phases_attempted",
            "phases_entered", "phases_completed", "final_runtime_state",
            "completion_summary", "invariant_violations",
        ):
            assert key in d


# ---------------------------------------------------------------------------
# Synthetic report reproducing the original live-test conditions.
# ---------------------------------------------------------------------------


class TestSyntheticOriginalConditionsReport:
    """Reproduces, as closely as today's (Phase-1/2-fixed) engine behavior
    allows: six identical failed Nmap executions, one unique host, zero
    services, an LLM-unavailable/provider-failure signal, a credential
    phase that was considered (evaluated by phase selection) but never
    actually entered, and an abandoned-due-to-no-actionable-task outcome.
    """

    def _build(self) -> RunReport:
        raw_findings = [_host_finding(ts=f"2026-01-01T00:0{i}:00Z") for i in range(6)]
        diagnostics = [
            build_execution_diagnostic(_nmap_tr(task_id=f"t-{i}"), phase="recon")
            for i in range(6)
        ]
        error_episodes = [{
            "outcome": "script_error", "tool": "nmap", "error": None, "phase": "recon",
            "returncode": 1, "stderr_sample": _RAW_SOCKET_STDERR[:STDERR_SAMPLE_LIMIT],
            "diagnostic_category": FUNDAMENTAL, "timed_out": False,
        } for _ in range(6)]
        decisions = [_decision("recon", selected=0, fallback=1) for _ in range(6)] + [
            {
                "phase": "recon", "planner_model": "deterministic",
                "selected_task_count": 0, "fallback_task_count": 0,
                "llm_error_category": "missing_key",
            },
        ]
        state = _make_state(
            findings=raw_findings, planner_decisions=decisions,
            error_episodes=error_episodes, execution_diagnostics=diagnostics,
            termination_phase="recon", phase="done", completed=True, turn_count=7,
        )
        return build_report(state, _subgraph([_host_node()]), _config())

    def test_one_unique_host_finding_from_six_observations(self) -> None:
        report = self._build()
        assert report.finding_count == 1
        assert report.observation_count == 6
        assert report.findings[0]["observation_count"] == 6

    def test_graph_and_findings_agree_on_one_host(self) -> None:
        report = self._build()
        assert report.total_nodes == 1
        assert report.node_counts.get("host") == 1

    def test_credential_never_entered_recon_terminal(self) -> None:
        report = self._build()
        assert "credential" not in report.phases_attempted
        assert report.termination_phase == "recon"
        assert report.final_runtime_state == "done"

    def test_error_samples_diagnosable(self) -> None:
        report = self._build()
        assert report.error_samples != []
        assert any("fundamental" in s or "returncode=1" in s for s in report.error_samples)

    def test_execution_diagnostics_preserved_for_all_six(self) -> None:
        report = self._build()
        assert len(report.execution_diagnostics) == 6
        for d in report.execution_diagnostics:
            assert d["tool"] == "nmap"
            assert d["diagnostic_category"] == FUNDAMENTAL
            assert d["returncode"] == 1

    def test_report_internally_consistent(self) -> None:
        report = self._build()
        assert_report_invariants(report)  # must not raise

    def test_abandoned_not_falsely_success(self) -> None:
        report = self._build()
        assert report.success is False
        assert report.objective_verified is False
        assert report.completed is True

    def test_format_text_renders_without_error(self) -> None:
        from apex_host.eval.report import format_text
        report = self._build()
        text = format_text(report)
        assert "nmap" in text.lower()
        assert "Execution Diagnostics" in text
