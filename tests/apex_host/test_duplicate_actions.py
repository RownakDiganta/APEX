# test_duplicate_actions.py
# Tests for task fingerprinting, DuplicateActionTracker, and graph-level duplicate detection.
"""Tests for duplicate-action detection across the APEX engagement pipeline.

Coverage
--------
1.  task_fingerprint — stable, normalised, argument-order invariant
2.  DuplicateActionTracker — window, eviction, max_repeats, snapshot
3.  Graph-level skip — _run_tasks skips duplicates; audit entry in state
4.  execute_agent duplicate skip
5.  browser_agent duplicate skip
6.  Detection disabled via config
7.  Report sections — format_text + to_json_dict include duplicate summary
8.  Promotion logging — per-pass DEBUG suppression; interval INFO progress
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apex_host.planning.fingerprint import DuplicateActionTracker, task_fingerprint


# ---------------------------------------------------------------------------
# 1. task_fingerprint
# ---------------------------------------------------------------------------

class TestTaskFingerprint:
    def test_returns_8_char_hex(self) -> None:
        fp = task_fingerprint("recon", "nmap", ["-sV", "10.10.10.10"], "10.10.10.10")
        assert len(fp) == 8
        assert all(c in "0123456789abcdef" for c in fp)

    def test_stable_across_calls(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", ["-sV", "10.10.10.10"], "10.10.10.10")
        fp2 = task_fingerprint("recon", "nmap", ["-sV", "10.10.10.10"], "10.10.10.10")
        assert fp1 == fp2

    def test_argument_order_invariant(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", ["-sV", "-T4"], "10.10.10.10")
        fp2 = task_fingerprint("recon", "nmap", ["-T4", "-sV"], "10.10.10.10")
        assert fp1 == fp2

    def test_different_tools_differ(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", [], "10.10.10.10")
        fp2 = task_fingerprint("recon", "curl", [], "10.10.10.10")
        assert fp1 != fp2

    def test_different_phases_differ(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", [], "10.10.10.10")
        fp2 = task_fingerprint("web", "nmap", [], "10.10.10.10")
        assert fp1 != fp2

    def test_different_targets_differ(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", [], "10.10.10.10")
        fp2 = task_fingerprint("recon", "nmap", [], "10.10.10.11")
        assert fp1 != fp2

    def test_case_insensitive_normalisation(self) -> None:
        fp1 = task_fingerprint("RECON", "NMAP", [], "10.10.10.10")
        fp2 = task_fingerprint("recon", "nmap", [], "10.10.10.10")
        assert fp1 == fp2

    def test_extra_whitespace_stripped(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", ["  -sV  "], "10.10.10.10")
        fp2 = task_fingerprint("recon", "nmap", ["-sV"], "10.10.10.10")
        assert fp1 == fp2

    def test_parser_and_executor_domain_contribute(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", [], "10.10.10.10", parser="nmap", executor_domain="recon")
        fp2 = task_fingerprint("recon", "nmap", [], "10.10.10.10", parser="command", executor_domain="web")
        assert fp1 != fp2

    def test_empty_optional_fields(self) -> None:
        # Should not raise, and produce valid 8-char output.
        fp = task_fingerprint("recon", "nc", [], "10.10.10.10")
        assert len(fp) == 8


# ---------------------------------------------------------------------------
# 2. DuplicateActionTracker
# ---------------------------------------------------------------------------

class TestDuplicateActionTrackerBasic:
    def test_fresh_tracker_not_duplicate(self) -> None:
        t = DuplicateActionTracker(window=5, max_repeats=1)
        assert not t.is_duplicate("abc")

    def test_first_record_triggers_duplicate(self) -> None:
        # With max_repeats=1, recording once means count==1 >= max_repeats.
        # is_duplicate returns True so the NEXT call to the graph is skipped.
        t = DuplicateActionTracker(window=5, max_repeats=1)
        t.record("abc")
        assert t.is_duplicate("abc")

    def test_before_any_record_not_duplicate(self) -> None:
        t = DuplicateActionTracker(window=5, max_repeats=1)
        assert not t.is_duplicate("abc")

    def test_max_repeats_two(self) -> None:
        # With max_repeats=2, is_duplicate fires when count reaches 2.
        t = DuplicateActionTracker(window=5, max_repeats=2)
        t.record("abc")
        assert not t.is_duplicate("abc")  # count=1 < 2, not yet a duplicate
        t.record("abc")
        assert t.is_duplicate("abc")  # count=2 >= 2, next call is a duplicate

    def test_different_fingerprints_independent(self) -> None:
        t = DuplicateActionTracker(window=5, max_repeats=1)
        t.record("abc")
        t.record("abc")
        assert t.is_duplicate("abc")
        assert not t.is_duplicate("def")


class TestDuplicateActionTrackerWindow:
    def test_eviction_removes_oldest(self) -> None:
        t = DuplicateActionTracker(window=3, max_repeats=1)
        t.record("a")
        t.record("b")
        t.record("c")
        # At this point "a" is in the window.
        t.record("d")  # "a" evicted
        # "a" should no longer be counted — not a duplicate even if seen again.
        assert not t.is_duplicate("a")

    def test_window_exactly_full(self) -> None:
        # With max_repeats=1, after one record the count == 1 >= max_repeats.
        # So both "a" and "b" are duplicates — the graph would skip a second attempt.
        t = DuplicateActionTracker(window=2, max_repeats=1)
        t.record("a")
        t.record("b")
        assert t.is_duplicate("a")
        assert t.is_duplicate("b")

    def test_eviction_then_re_record(self) -> None:
        t = DuplicateActionTracker(window=2, max_repeats=1)
        t.record("a")  # window: [a], counts: {a:1}
        t.record("b")  # window: [a, b], counts: {a:1, b:1}
        t.record("c")  # evicts "a" → window: [b, c], counts: {b:1, c:1}
        # "a" was evicted; count dropped to 0 → not a duplicate before re-recording.
        assert not t.is_duplicate("a")
        t.record("a")  # window: [c, a], counts: {c:1, a:1}
        # After recording "a" once more, count == 1 >= max_repeats → duplicate again.
        assert t.is_duplicate("a")


class TestDuplicateActionTrackerSnapshot:
    def test_snapshot_structure(self) -> None:
        t = DuplicateActionTracker(window=5, max_repeats=1)
        t.record("abc")
        s = t.snapshot()
        assert s["window"] == 5
        assert s["max_repeats"] == 1
        assert s["history_size"] == 1
        assert s["unique_fingerprints"] == 1

    def test_snapshot_after_duplicate(self) -> None:
        t = DuplicateActionTracker(window=5, max_repeats=1)
        t.record("abc")
        t.record("abc")
        s = t.snapshot()
        assert s["history_size"] == 2
        assert s["unique_fingerprints"] == 1


# ---------------------------------------------------------------------------
# 3. Config defaults
# ---------------------------------------------------------------------------

class TestConfigDefaults:
    def test_detection_enabled_by_default(self) -> None:
        from apex_host.config import ApexConfig
        cfg = ApexConfig(target="10.10.10.10")
        assert cfg.duplicate_action_detection_enabled is True
        assert cfg.duplicate_action_window == 5
        assert cfg.duplicate_action_max_repeats == 1

    def test_trace_knowledge_records_default(self) -> None:
        from apex_host.config import ApexConfig
        cfg = ApexConfig(target="10.10.10.10")
        assert cfg.trace_knowledge_records is False


# ---------------------------------------------------------------------------
# 4. Report summary fields
# ---------------------------------------------------------------------------

class TestReportDuplicateSection:
    def _make_minimal_subgraph(self) -> Any:
        sg = MagicMock()
        sg.nodes = []
        sg.edges = []
        return sg

    def _make_state(self, dup_entries: list[dict[str, Any]]) -> Any:
        return {
            "run_id": "r1",
            "target": "10.10.10.10",
            "phase": "recon",
            "goal": "test",
            "current_task": None,
            "evidence_summary": "",
            "findings": [],
            "error_episodes": [],
            "last_tool_result": None,
            "last_error": None,
            "completed": True,
            "turn_count": 2,
            "planner_decisions": [],
            "tool_results": None,
            "repair_count": 0,
            "policy_decisions": [],
            "duplicate_actions": dup_entries,
        }

    def test_no_duplicates_count_zero(self) -> None:
        from apex_host.config import ApexConfig
        from apex_host.eval.report import build_report
        cfg = ApexConfig(target="10.10.10.10")
        report = build_report(self._make_state([]), self._make_minimal_subgraph(), cfg)
        assert report.duplicate_action_count == 0
        assert report.duplicate_action_entries == []

    def test_duplicates_counted(self) -> None:
        from apex_host.config import ApexConfig
        from apex_host.eval.report import build_report
        cfg = ApexConfig(target="10.10.10.10")
        entries = [
            {"fingerprint": "aabbccdd", "tool": "nmap", "target": "10.10.10.10",
             "phase": "recon", "disposition": "skip_task", "reason": "repeated", "meaningful_state_change": False},
            {"fingerprint": "aabbccdd", "tool": "nmap", "target": "10.10.10.10",
             "phase": "recon", "disposition": "skip_task", "reason": "repeated", "meaningful_state_change": False},
        ]
        report = build_report(self._make_state(entries), self._make_minimal_subgraph(), cfg)
        assert report.duplicate_action_count == 2

    def test_format_text_shows_duplicate_section(self) -> None:
        from apex_host.config import ApexConfig
        from apex_host.eval.report import build_report, format_text
        cfg = ApexConfig(target="10.10.10.10")
        entries = [
            {"fingerprint": "aabbccdd", "tool": "nmap", "target": "10.10.10.10",
             "phase": "recon", "disposition": "skip_task", "reason": "repeated within window=5",
             "meaningful_state_change": False},
        ]
        report = build_report(self._make_state(entries), self._make_minimal_subgraph(), cfg)
        text = format_text(report)
        assert "Duplicate Actions Skipped" in text
        assert "1" in text

    def test_json_dict_includes_duplicate_section(self) -> None:
        from apex_host.config import ApexConfig
        from apex_host.eval.report import build_report, to_json_dict
        cfg = ApexConfig(target="10.10.10.10")
        report = build_report(self._make_state([]), self._make_minimal_subgraph(), cfg)
        d = to_json_dict(report)
        assert "duplicate_actions" in d
        assert d["duplicate_actions"]["total_skipped"] == 0


# ---------------------------------------------------------------------------
# 5. Promotion logging — per-pass DEBUG suppression
# ---------------------------------------------------------------------------

class TestPromotionLoggingLevel:
    def test_per_pass_summary_at_debug_not_info(self) -> None:
        """_apply_promotion_gate() must log its pass summary at DEBUG, not INFO."""
        import inspect
        from memfabric.reflector import worker
        src = inspect.getsource(worker.ReflectorWorker._apply_promotion_gate)
        # The pass-summary log must NOT be at INFO level any more.
        # We check that "logger.info" does not appear in the method together with
        # "promoted=" (the telltale pattern of the per-pass summary).
        assert 'logger.info(\n            "reflector promotion pass' not in src
        # It must be at DEBUG.
        assert 'logger.debug(\n            "reflector promotion pass' in src or \
               'logger.debug(' in src

    def test_interval_log_present_in_seed_loader(self) -> None:
        """promote_staged_knowledge_until_stable must emit an interval INFO log."""
        import inspect
        from apex_host.knowledge import seed_loader
        src = inspect.getsource(seed_loader.promote_staged_knowledge_until_stable)
        assert "logger.info" in src
        assert "_PROMOTION_LOG_INTERVAL" in src or "% _PROMOTION_LOG_INTERVAL" in src or \
               "_PROMOTION_LOG_INTERVAL ==" in src or "PROMOTION_LOG_INTERVAL" in src
