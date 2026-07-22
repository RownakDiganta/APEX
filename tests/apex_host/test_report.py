# test_report.py
# Tests for apex_host/eval/report.py: RunReport construction, text formatting, JSON serialization, and file export.
"""Acceptance tests for the run-report module.

Acceptance criteria:
1. build_report produces a RunReport with correct field values.
2. phases_reached is derived from findings, not stored elsewhere.
3. node/edge counts by type match the supplied subgraph.
4. format_text output contains all required sections.
5. to_json_dict is JSON-serialisable and has the expected keys.
6. write_report_json writes a valid JSON file to disk.
7. episodes_by_outcome is populated even without an explicit argument.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any


from memfabric.ids import new_id, now
from memfabric.types import Edge, Node, SubgraphView

from apex_host.config import ApexConfig
from apex_host.eval.report import (
    RunReport,
    build_report,
    format_text,
    to_json_dict,
    write_report_json,
)
from apex_host.graph_state import ApexGraphState

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_TARGET = "10.10.10.99"
_ANCHOR = f"host:{_TARGET}"


def _config(*, dry_run: bool = True) -> ApexConfig:
    return ApexConfig(target=_TARGET, dry_run=dry_run)


def _state(
    *,
    findings: list[dict[str, Any]] | None = None,
    turn_count: int = 4,
    phase: str = "credential",
    completed: bool = True,
    last_error: str | None = None,
    evidence_summary: str = "",
    error_episodes: list[dict[str, Any]] | None = None,
) -> ApexGraphState:
    return {
        "run_id": "test-run-1",
        "target": _TARGET,
        "phase": phase,
        "goal": "test",
        "current_task": None,
        "evidence_summary": evidence_summary,
        "findings": findings or [],
        "error_episodes": error_episodes if error_episodes is not None else [],
        "last_tool_result": None,
        "last_error": last_error,
        "completed": completed,
        "turn_count": turn_count,
    }


def _ts() -> str:
    return now()


def _node(ntype: str) -> Node:
    nid = new_id()
    ts = _ts()
    return Node(
        id=nid, type=ntype,
        props={"label": ntype},
        confidence=0.8, source="test",
        first_seen=ts, last_seen=ts,
    )


def _edge(etype: str, from_id: str = "a", to_id: str = "b") -> Edge:
    ts = _ts()
    return Edge(
        id=new_id(), from_id=from_id, to_id=to_id, type=etype,
        props={}, confidence=0.8, source="test",
        first_seen=ts, last_seen=ts,
    )


def _subgraph(nodes: list[Node] | None = None, edges: list[Edge] | None = None) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=nodes or [], edges=edges or [], depth=10)


def _finding(phase: str, title: str = "test", confidence: float = 0.9) -> dict[str, Any]:
    return {"id": new_id(), "phase": phase, "title": title, "confidence": confidence, "source": "test", "detail": ""}


# ---------------------------------------------------------------------------
# build_report: field correctness
# ---------------------------------------------------------------------------

class TestBuildReport:
    def test_target_matches_config(self) -> None:
        report = build_report(_state(), _subgraph(), _config())
        assert report.target == _TARGET

    def test_mode_dry_run(self) -> None:
        report = build_report(_state(), _subgraph(), _config(dry_run=True))
        assert report.mode == "dry-run"

    def test_mode_live(self) -> None:
        report = build_report(_state(), _subgraph(), _config(dry_run=False))
        assert report.mode == "live"

    def test_turns_used(self) -> None:
        report = build_report(_state(turn_count=7), _subgraph(), _config())
        assert report.turns_used == 7

    def test_completed_true(self) -> None:
        report = build_report(_state(completed=True), _subgraph(), _config())
        assert report.completed is True

    def test_completed_false(self) -> None:
        report = build_report(_state(completed=False), _subgraph(), _config())
        assert report.completed is False

    def test_final_phase(self) -> None:
        report = build_report(_state(phase="web"), _subgraph(), _config())
        assert report.final_phase == "web"

    def test_last_error_none(self) -> None:
        report = build_report(_state(last_error=None), _subgraph(), _config())
        assert report.last_error is None

    def test_last_error_string(self) -> None:
        report = build_report(_state(last_error="timeout"), _subgraph(), _config())
        assert report.last_error == "timeout"

    def test_finding_count(self) -> None:
        findings = [_finding("recon"), _finding("web")]
        report = build_report(_state(findings=findings), _subgraph(), _config())
        assert report.finding_count == 2

    def test_findings_list_preserved(self) -> None:
        findings = [_finding("recon", title="host discovered")]
        report = build_report(_state(findings=findings), _subgraph(), _config())
        assert report.findings[0]["title"] == "host discovered"


# ---------------------------------------------------------------------------
# build_report: phases_reached derived from findings
# ---------------------------------------------------------------------------

class TestPhasesReached:
    def test_phases_derived_from_findings(self) -> None:
        findings = [
            _finding("recon"),
            _finding("web"),
            _finding("recon"),   # duplicate — should appear once
        ]
        report = build_report(_state(findings=findings), _subgraph(), _config())
        assert sorted(report.phases_reached) == ["recon", "web"]

    def test_phases_empty_when_no_findings(self) -> None:
        report = build_report(_state(findings=[]), _subgraph(), _config())
        assert report.phases_reached == []

    def test_phases_sorted_alphabetically(self) -> None:
        findings = [_finding("web"), _finding("credential"), _finding("recon")]
        report = build_report(_state(findings=findings), _subgraph(), _config())
        assert report.phases_reached == sorted(report.phases_reached)

    def test_phases_not_taken_from_final_phase(self) -> None:
        # final_phase="done" but no finding with phase="done" → "done" not in phases_reached
        report = build_report(_state(phase="done", findings=[_finding("recon")]), _subgraph(), _config())
        assert "done" not in report.phases_reached
        assert "recon" in report.phases_reached


# ---------------------------------------------------------------------------
# build_report: node and edge counts from subgraph
# ---------------------------------------------------------------------------

class TestNodeEdgeCounts:
    def test_node_counts_by_type(self) -> None:
        nodes = [_node("host"), _node("service"), _node("service")]
        report = build_report(_state(), _subgraph(nodes=nodes), _config())
        assert report.node_counts == {"host": 1, "service": 2}

    def test_edge_counts_by_type(self) -> None:
        edges = [_edge("exposes"), _edge("runs"), _edge("exposes")]
        report = build_report(_state(), _subgraph(edges=edges), _config())
        assert report.edge_counts == {"exposes": 2, "runs": 1}

    def test_total_nodes(self) -> None:
        nodes = [_node("host"), _node("service"), _node("tech")]
        report = build_report(_state(), _subgraph(nodes=nodes), _config())
        assert report.total_nodes == 3

    def test_total_edges(self) -> None:
        edges = [_edge("exposes"), _edge("runs")]
        report = build_report(_state(), _subgraph(edges=edges), _config())
        assert report.total_edges == 2

    def test_empty_subgraph_gives_zero_counts(self) -> None:
        report = build_report(_state(), _subgraph(), _config())
        assert report.total_nodes == 0
        assert report.total_edges == 0
        assert report.node_counts == {}
        assert report.edge_counts == {}


# ---------------------------------------------------------------------------
# build_report: episodes_by_outcome default derivation
# ---------------------------------------------------------------------------

class TestEpisodesByOutcome:
    def test_total_turns_in_default_outcomes(self) -> None:
        report = build_report(_state(turn_count=5), _subgraph(), _config())
        assert report.episodes_by_outcome.get("total_turns") == 5

    def test_caller_supplied_outcomes_respected(self) -> None:
        custom = {"success": 3, "script_error": 1}
        report = build_report(_state(), _subgraph(), _config(), episodes_by_outcome=custom)
        assert report.episodes_by_outcome == custom

    def test_with_findings_key_bounded_by_turn_count(self) -> None:
        # Ensure turns_with_findings <= total turns even with many findings
        findings = [_finding("recon")] * 10
        report = build_report(_state(turn_count=3, findings=findings), _subgraph(), _config())
        assert report.episodes_by_outcome.get("turns_with_findings", 0) <= 3


# ---------------------------------------------------------------------------
# build_report: evidence_samples
# ---------------------------------------------------------------------------

class TestEvidenceSamples:
    def test_samples_from_evidence_summary(self) -> None:
        summary = "line one\nline two\nline three"
        report = build_report(_state(evidence_summary=summary), _subgraph(), _config())
        assert "line one" in report.evidence_samples
        assert "line two" in report.evidence_samples

    def test_samples_capped_at_five(self) -> None:
        summary = "\n".join(f"item {i}" for i in range(20))
        report = build_report(_state(evidence_summary=summary), _subgraph(), _config())
        assert len(report.evidence_samples) <= 5

    def test_blank_summary_gives_empty_samples(self) -> None:
        report = build_report(_state(evidence_summary=""), _subgraph(), _config())
        assert report.evidence_samples == []

    def test_caller_supplied_samples_respected(self) -> None:
        report = build_report(
            _state(), _subgraph(), _config(),
            evidence_samples=["custom sample"],
        )
        assert report.evidence_samples == ["custom sample"]


# ---------------------------------------------------------------------------
# format_text: section presence
# ---------------------------------------------------------------------------

class TestFormatText:
    def _report(self, **kwargs: Any) -> RunReport:
        return build_report(_state(**kwargs), _subgraph(), _config())

    def test_contains_target(self) -> None:
        text = format_text(self._report())
        assert _TARGET in text

    def test_contains_phase_summary_header(self) -> None:
        text = format_text(self._report())
        assert "Phase Summary" in text

    def test_contains_findings_header(self) -> None:
        text = format_text(self._report())
        assert "Findings" in text

    def test_contains_ekg_summary_header(self) -> None:
        text = format_text(self._report())
        assert "EKG Summary" in text

    def test_contains_episodes_header(self) -> None:
        text = format_text(self._report())
        assert "Episodes" in text

    def test_dry_run_label_present(self) -> None:
        text = format_text(self._report())
        assert "dry-run" in text

    def test_live_label_when_not_dry_run(self) -> None:
        report = build_report(_state(), _subgraph(), _config(dry_run=False))
        text = format_text(report)
        assert "live" in text

    def test_finding_count_in_output(self) -> None:
        findings = [_finding("recon"), _finding("web")]
        text = format_text(build_report(_state(findings=findings), _subgraph(), _config()))
        assert "2 total" in text

    def test_phase_name_appears_in_phase_summary(self) -> None:
        findings = [_finding("recon")]
        text = format_text(build_report(_state(findings=findings), _subgraph(), _config()))
        assert "recon" in text

    def test_evidence_section_when_samples_present(self) -> None:
        report = build_report(
            _state(), _subgraph(), _config(),
            evidence_samples=["something interesting"],
        )
        text = format_text(report)
        assert "Evidence" in text
        assert "something interesting" in text

    def test_no_evidence_section_when_no_samples(self) -> None:
        report = build_report(_state(evidence_summary=""), _subgraph(), _config())
        text = format_text(report)
        assert "Retrieved Evidence" not in text


# ---------------------------------------------------------------------------
# to_json_dict: structure
# ---------------------------------------------------------------------------

class TestToJsonDict:
    def _report(self) -> RunReport:
        return build_report(
            _state(findings=[_finding("recon")]),
            _subgraph(nodes=[_node("host")], edges=[_edge("exposes")]),
            _config(),
        )

    def test_top_level_keys(self) -> None:
        d = to_json_dict(self._report())
        for key in ("target", "mode", "turns_used", "completed", "final_phase",
                    "phases_reached", "finding_count", "findings",
                    "ekg", "episodes_by_outcome", "evidence_samples", "last_error"):
            assert key in d, f"missing key: {key}"

    def test_ekg_subdict_keys(self) -> None:
        d = to_json_dict(self._report())
        for key in ("total_nodes", "total_edges", "node_counts", "edge_counts"):
            assert key in d["ekg"], f"missing ekg key: {key}"

    def test_json_serialisable(self) -> None:
        d = to_json_dict(self._report())
        serialised = json.dumps(d)  # must not raise
        assert isinstance(serialised, str)

    def test_target_value(self) -> None:
        d = to_json_dict(self._report())
        assert d["target"] == _TARGET

    def test_finding_count_matches_findings_list_length(self) -> None:
        d = to_json_dict(self._report())
        assert d["finding_count"] == len(d["findings"])

    def test_node_counts_in_ekg(self) -> None:
        d = to_json_dict(self._report())
        assert d["ekg"]["node_counts"].get("host") == 1


# ---------------------------------------------------------------------------
# write_report_json: file output
# ---------------------------------------------------------------------------

class TestWriteReportJson:
    def _report(self) -> RunReport:
        return build_report(_state(), _subgraph(), _config())

    def test_file_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "run_report.json"
            write_report_json(self._report(), path)
            assert path.exists()

    def test_file_is_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "run_report.json"
            write_report_json(self._report(), path)
            data = json.loads(path.read_text(encoding="utf-8"))
            assert isinstance(data, dict)

    def test_file_contains_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "run_report.json"
            write_report_json(self._report(), path)
            data = json.loads(path.read_text(encoding="utf-8"))
            assert data["target"] == _TARGET

    def test_parent_directories_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nested" / "dir" / "report.json"
            write_report_json(self._report(), path)
            assert path.exists()


# ---------------------------------------------------------------------------
# Status and completed_successfully — correctness of run classification
# ---------------------------------------------------------------------------

_SCRIPT_ERR = {"outcome": "script_error", "tool": "nmap", "error": "nmap returned rc=1", "phase": "recon"}
_FIXABLE_ERR = {"outcome": "fixable", "tool": "curl", "error": "connection refused", "phase": "web"}
_FUND_ERR = {"outcome": "fundamental", "tool": "nc", "error": "host unreachable", "phase": "recon"}


def _config_maxturns(max_turns: int = 5) -> "ApexConfig":
    return ApexConfig(target=_TARGET, max_turns=max_turns)


class TestStatusAndCompleteness:
    """Verify that status and completed_successfully reflect the actual run outcome."""

    def test_access_state_in_ekg_alone_is_not_success(self) -> None:
        # Phase 18: a validated access_state is an important intermediate
        # milestone but is never, by itself, benchmark success — only a
        # verified objective (EngagementOutcome.user_flag_verified) is.
        # The legacy fallback (_derive_outcome_from_state, used only when
        # final_state has no "outcome" key) still classifies access_state
        # presence as EngagementOutcome.validated_access, which now maps to
        # legacy status "abandoned", never "success".
        nodes = [_node("host"), _node("access_state")]
        report = build_report(_state(turn_count=3, completed=True), _subgraph(nodes=nodes), _config())
        assert report.status != "success"
        assert report.completed_successfully is False

    def test_not_successful_when_no_access_state(self) -> None:
        nodes = [_node("host"), _node("service")]
        report = build_report(_state(turn_count=5, completed=True), _subgraph(nodes=nodes), _config())
        assert report.completed_successfully is False

    def test_stopped_max_turns_when_budget_exhausted_no_access(self) -> None:
        nodes = [_node("host")]
        report = build_report(
            _state(turn_count=5, completed=True),
            _subgraph(nodes=nodes),
            _config_maxturns(max_turns=5),
        )
        assert report.status == "stopped_max_turns"

    def test_stopped_error_when_all_turns_failed_and_no_nodes(self) -> None:
        errors = [_SCRIPT_ERR, _SCRIPT_ERR, _SCRIPT_ERR]
        report = build_report(
            _state(turn_count=3, completed=True, error_episodes=errors),
            _subgraph(),            # empty EKG — even host node missing
            _config_maxturns(max_turns=5),
        )
        assert report.status == "stopped_error"

    def test_stopped_max_turns_when_errors_but_host_node_exists(self) -> None:
        # nmap failing loop: host node written but no services; hits max_turns
        errors = [_SCRIPT_ERR] * 5
        nodes = [_node("host")]
        report = build_report(
            _state(turn_count=5, completed=True, error_episodes=errors),
            _subgraph(nodes=nodes),
            _config_maxturns(max_turns=5),
        )
        # host node was written so node_counts is non-empty → stopped_max_turns not stopped_error
        assert report.status == "stopped_max_turns"
        assert report.completed_successfully is False

    def test_abandoned_when_completed_before_max_turns_no_access(self) -> None:
        report = build_report(
            _state(turn_count=0, completed=True),
            _subgraph(),
            _config_maxturns(max_turns=10),
        )
        assert report.status == "abandoned"

    def test_script_error_count(self) -> None:
        errors = [_SCRIPT_ERR, _SCRIPT_ERR, _FIXABLE_ERR]
        report = build_report(_state(error_episodes=errors), _subgraph(), _config())
        assert report.script_error_count == 2
        assert report.fixable_count == 1
        assert report.fundamental_count == 0


# ---------------------------------------------------------------------------
# Infra Phase 4 — execution backend summary (backend_usage / timed_out_count)
# ---------------------------------------------------------------------------

class TestExecutionBackendSummary:
    def test_backend_usage_counts_by_backend_name(self) -> None:
        state = _state()
        state["execution_backend_log"] = [
            {"tool": "nmap", "backend": "local", "timed_out": False, "phase": "recon"},
            {"tool": "curl", "backend": "local", "timed_out": False, "phase": "web"},
            {"tool": "nc", "backend": "dry-run", "timed_out": False, "phase": "recon"},
        ]
        report = build_report(state, _subgraph(), _config())
        assert report.backend_usage == {"local": 2, "dry-run": 1}

    def test_timed_out_count_derived_from_log(self) -> None:
        state = _state()
        state["execution_backend_log"] = [
            {"tool": "nmap", "backend": "remote", "timed_out": True, "phase": "recon"},
            {"tool": "curl", "backend": "remote", "timed_out": False, "phase": "web"},
        ]
        report = build_report(state, _subgraph(), _config())
        assert report.timed_out_count == 1

    def test_backend_field_identifies_remote_as_kali_service_value(self) -> None:
        """apex_tool_service self-identifies as "kali-service"; the client-side
        RemoteToolBackend preserves that literal value in ToolResult.backend
        and therefore in this log entry (docs/kali-tool-service.md §5)."""
        state = _state()
        state["execution_backend_log"] = [
            {"tool": "nmap", "backend": "kali-service", "timed_out": False, "phase": "recon"},
        ]
        report = build_report(state, _subgraph(), _config())
        assert report.backend_usage == {"kali-service": 1}

    def test_no_backend_log_yields_empty_summary(self) -> None:
        """Backward compatibility: a state dict built before Infra Phase 4
        (missing the execution_backend_log key entirely) must not raise."""
        report = build_report(_state(), _subgraph(), _config())
        assert report.backend_usage == {}
        assert report.timed_out_count == 0

    def test_format_text_shows_execution_backend_section_when_present(self) -> None:
        state = _state()
        state["execution_backend_log"] = [
            {"tool": "nmap", "backend": "local", "timed_out": False, "phase": "recon"},
        ]
        report = build_report(state, _subgraph(), _config())
        text = format_text(report)
        assert "Execution Backend" in text
        assert "local" in text

    def test_format_text_omits_execution_backend_section_when_empty(self) -> None:
        report = build_report(_state(), _subgraph(), _config())
        text = format_text(report)
        assert "Execution Backend" not in text

    def test_to_json_dict_includes_execution_backend_key(self) -> None:
        state = _state()
        state["execution_backend_log"] = [
            {"tool": "nmap", "backend": "local", "timed_out": True, "phase": "recon"},
        ]
        report = build_report(state, _subgraph(), _config())
        d = to_json_dict(report)
        assert d["execution_backend"] == {"usage": {"local": 1}, "timed_out_count": 1}

    def test_no_token_appears_in_serialized_report(self) -> None:
        """ApexConfig.tool_service_token never flows into RunReport at all —
        build_report() never reads it — so it cannot leak into any report
        output regardless of what value is configured."""
        state = _state()
        state["execution_backend_log"] = [
            {"tool": "nmap", "backend": "remote", "timed_out": False, "phase": "recon"},
        ]
        cfg = ApexConfig(
            target=_TARGET, dry_run=False, tool_backend="remote",
            tool_service_url="http://kali:8080",
            tool_service_token="super-secret-report-test-token",
        )
        report = build_report(state, _subgraph(), cfg)
        assert "super-secret-report-test-token" not in json.dumps(to_json_dict(report), default=str)
        assert "super-secret-report-test-token" not in format_text(report)

    def test_existing_report_consumers_unaffected_by_new_fields(self) -> None:
        """A report built the old way (no execution_backend_log at all) still
        produces every previously-existing field with its previous meaning."""
        report = build_report(_state(turn_count=2), _subgraph(), _config())
        assert report.turns_used == 2
        assert isinstance(report.backend_usage, dict)
        assert isinstance(report.timed_out_count, int)

    def test_fundamental_count(self) -> None:
        errors = [_FUND_ERR]
        report = build_report(_state(error_episodes=errors), _subgraph(), _config())
        assert report.fundamental_count == 1

    def test_error_samples_populated_from_error_episodes(self) -> None:
        errors = [_SCRIPT_ERR, _FIXABLE_ERR]
        report = build_report(_state(error_episodes=errors), _subgraph(), _config())
        assert len(report.error_samples) == 2
        assert "nmap returned rc=1" in report.error_samples
        assert "connection refused" in report.error_samples

    def test_error_samples_capped_at_three(self) -> None:
        errors = [_SCRIPT_ERR] * 10
        report = build_report(_state(error_episodes=errors), _subgraph(), _config())
        assert len(report.error_samples) <= 3

    def test_no_error_samples_when_no_error_field(self) -> None:
        # error_episodes with no "error" key → no samples
        errors = [{"outcome": "script_error", "tool": "nmap", "phase": "recon"}]
        report = build_report(_state(error_episodes=errors), _subgraph(), _config())
        assert report.error_samples == []

    def test_format_text_shows_status(self) -> None:
        nodes = [_node("host")]
        report = build_report(
            _state(turn_count=5, completed=True),
            _subgraph(nodes=nodes),
            _config_maxturns(max_turns=5),
        )
        text = format_text(report)
        assert "STOPPED_MAX_TURNS" in text
        assert "Successful" in text

    def test_format_text_shows_error_breakdown_when_errors(self) -> None:
        errors = [_SCRIPT_ERR, _SCRIPT_ERR]
        report = build_report(_state(error_episodes=errors), _subgraph(), _config())
        text = format_text(report)
        assert "Error Breakdown" in text
        assert "script_error" in text

    def test_format_text_no_error_section_when_no_errors(self) -> None:
        report = build_report(_state(), _subgraph(), _config())
        text = format_text(report)
        assert "Error Breakdown" not in text

    def test_format_text_not_success_label_when_only_access_state(self) -> None:
        # Phase 18: access_state alone is not success — the "Successful"
        # header line must read "No", not "Yes".
        nodes = [_node("access_state")]
        report = build_report(_state(completed=True), _subgraph(nodes=nodes), _config())
        text = format_text(report)
        assert "Successful : No" in text

    def test_format_text_success_label_when_user_flag_verified(self) -> None:
        nodes = [_node("access_state")]
        state = {**_state(completed=True), "outcome": "user_flag_verified"}
        report = build_report(state, _subgraph(nodes=nodes), _config())  # type: ignore[arg-type]
        text = format_text(report)
        assert "SUCCESS" in text
        assert "Successful : Yes" in text

    def test_json_dict_has_status_key(self) -> None:
        report = build_report(_state(), _subgraph(), _config())
        d = to_json_dict(report)
        assert "status" in d
        assert "completed_successfully" in d

    def test_json_dict_has_error_counts(self) -> None:
        errors = [_SCRIPT_ERR, _FUND_ERR]
        report = build_report(_state(error_episodes=errors), _subgraph(), _config())
        d = to_json_dict(report)
        assert "error_counts" in d
        assert d["error_counts"]["script_error"] == 1
        assert d["error_counts"]["fundamental"] == 1

    def test_json_dict_has_error_samples(self) -> None:
        errors = [_SCRIPT_ERR]
        report = build_report(_state(error_episodes=errors), _subgraph(), _config())
        d = to_json_dict(report)
        assert "error_samples" in d
        assert len(d["error_samples"]) == 1

    def test_max_turns_without_success_is_not_completed_successfully(self) -> None:
        # Regression: hitting max_turns must NOT set completed_successfully=True
        nodes = [_node("host"), _node("service")]
        report = build_report(
            _state(turn_count=20, completed=True, phase="recon"),
            _subgraph(nodes=nodes),
            _config_maxturns(max_turns=20),
        )
        assert report.completed_successfully is False
        assert report.status != "success"

    def test_last_error_not_hidden_when_errors_occurred(self) -> None:
        # Regression: last_error must appear in report even when completed=True
        report = build_report(
            _state(last_error="nmap returned rc=1", completed=True),
            _subgraph(),
            _config(),
        )
        assert report.last_error == "nmap returned rc=1"
        text = format_text(report)
        assert "nmap returned rc=1" in text
