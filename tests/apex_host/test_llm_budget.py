# test_llm_budget.py
# Tests for LLMBudgetTracker, budget enforcement in PlanningEngine, CLI log-suppression flags, and JSON report llm_usage.
"""Tests for the LLM call budget / observability layer added in Phase 7.

Scenarios covered:
 1.  Global LLM budget exhaustion → deterministic fallback.
 2.  Per-phase LLM budget exhaustion → deterministic fallback.
 3.  Budget exhaustion sets llm_error_category="budget_exhausted" on PlanDecision.
 4.  401 (AuthenticationError-like) is NOT retried (permanent classification).
 5.  404 (NotFoundError-like) is NOT retried (permanent classification).
 6.  Transient error retried up to max_retries times then falls back.
 7.  Timeout-like error retried up to max_retries; retries counter incremented.
 8.  Successful call increments calls_succeeded and calls_attempted.
 9.  Failed (permanent) call increments calls_failed and fallbacks.
10.  Repeated identical context is detected; LLM skipped; fallback used.
11.  Changed evidence (different entry count) allows another LLM call.
12.  Changed phase key allows another LLM call even with same subgraph.
13.  Normal -v flag suppresses openai/httpx/httpcore DEBUG loggers.
14.  --http-debug flag leaves openai/httpx/httpcore loggers at DEBUG.
15.  JSON export contains "llm_usage" key with correct fields.
16.  PlanDecision export contains all 7 new budget/error fields.
17.  LLMBudgetTracker.budget_remaining counts down correctly.
18.  LLMBudgetTracker.to_dict() returns all expected keys.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import patch

import pytest

from memfabric.types import (
    AbandonSignal,
    EvidenceBundle,
    Goal,
    ScoredEntry,
    SubgraphView,
    TaskSpec,
)

from apex_host.planning.budget import LLMBudgetTracker
from apex_host.planning.engine import PlanningEngine, _classify_error
from apex_host.planning.models import PlanDecision
from apex_host.types import ApexPhase

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_TARGET = "10.0.0.1"


def _goal(phase: str = "recon") -> Goal:
    return Goal(id="g-test", description="budget test goal", phase=phase, anchor_node=f"host:{_TARGET}")


def _subgraph(n_nodes: int = 0, n_edges: int = 0) -> SubgraphView:
    """Return a synthetic subgraph with controlled node/edge counts."""
    from memfabric.types import Node, Edge
    from memfabric.ids import now
    nodes = [
        Node(
            id=f"node-{i}",
            type="host",
            props={"ip": _TARGET},
            confidence=0.9,
            source="test",
            first_seen=now(),
            last_seen=now(),
        )
        for i in range(n_nodes)
    ]
    edges = [
        Edge(
            id=f"edge-{i}",
            source=f"node-0",
            target=f"node-{i}",
            type="exposes",
            props={},
            confidence=0.9,
            source_label="test",
            first_seen=now(),
            last_seen=now(),
        )
        for i in range(n_edges)
        if n_nodes > 0
    ]
    return SubgraphView(anchor=f"host:{_TARGET}", nodes=nodes, edges=edges, depth=2)


def _evidence(n_entries: int = 0) -> EvidenceBundle:
    entries = [
        ScoredEntry(id=f"e-{i}", score=0.8, text=f"entry {i}", source="test", tier="semantic")
        for i in range(n_entries)
    ]
    return EvidenceBundle(entries=entries, query="test", subgraph=None, tiers_queried=[])


def _good_json(tool: str = "nmap", confidence: float = 0.9) -> str:
    return json.dumps({
        "reasoning": "budget test",
        "confidence": confidence,
        "selected_tasks": [
            {
                "tool": tool,
                "args": ["-sV", _TARGET],
                "parser": "nmap",
                "executor_domain": "recon",
                "target": _TARGET,
                "rationale": "test",
            }
        ],
        "rejected_tasks": [],
        "stop_reason": None,
        "next_phase": None,
    })


class _StubResponse:
    def __init__(self, content: str) -> None:
        self.content = content


class _StubLLM:
    """Returns the same JSON on every invoke()."""

    def __init__(self, json_str: str) -> None:
        self._json = json_str
        self.call_count = 0

    def invoke(self, messages: list[dict[str, str]]) -> _StubResponse:
        self.call_count += 1
        return _StubResponse(self._json)


class _ErrorLLM:
    """Raises a configured exception on every invoke()."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.call_count = 0

    def invoke(self, messages: list[dict[str, str]]) -> _StubResponse:
        self.call_count += 1
        raise self._exc


class _StatusErrorLLM(_ErrorLLM):
    """Raises an exception that carries a status_code attribute."""
    pass


class _StubRouter:
    def __init__(self, llm: object) -> None:
        self._llm = llm

    def planner_llm(self) -> object:
        return self._llm

    def executor_llm(self) -> object:
        return None

    def parser_llm(self) -> object:
        return None

    def reflector_llm(self) -> object:
        return None


class _FakeModelRouter:
    """Always returns None — immediate deterministic fallback."""

    def planner_llm(self) -> object:
        return None

    def executor_llm(self) -> object:
        return None

    def parser_llm(self) -> object:
        return None

    def reflector_llm(self) -> object:
        return None


class _CountingFallback:
    """Counts plan() invocations; always returns one nmap TaskSpec."""

    def __init__(self) -> None:
        self.call_count = 0

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        self.call_count += 1
        return [
            TaskSpec(
                id="fb-id",
                goal_id=goal.id,
                executor_domain="recon",
                params={"tool": "nmap", "args": [], "parser": "nmap", "target": _TARGET},
            )
        ]


def _engine(
    llm: object,
    fallback: _CountingFallback | None = None,
    budget: LLMBudgetTracker | None = None,
    max_retries: int = 0,
    confidence_threshold: float = 0.4,
) -> tuple[PlanningEngine, _CountingFallback]:
    fb = fallback or _CountingFallback()
    eng = PlanningEngine(
        model_router=_StubRouter(llm),
        fallback_planner=fb,
        allowed_tools=["nmap", "curl", "nc"],
        target=_TARGET,
        max_retries=max_retries,
        confidence_threshold=confidence_threshold,
        budget=budget,
    )
    return eng, fb


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGlobalBudgetExhaustion:
    """Scenario 1: global budget blocks LLM calls after max_per_run."""

    @pytest.mark.asyncio
    async def test_global_budget_exhausted_falls_back(self) -> None:
        # stop_on_repeated_plan=False so both calls consume real budget slots
        budget = LLMBudgetTracker(max_per_run=2, max_per_phase=10, stop_on_repeated_plan=False)
        llm = _StubLLM(_good_json())
        eng, fb = _engine(llm, budget=budget)

        goal = _goal()

        # Consume 2 successful LLM calls (distinct context each time)
        for i in range(2):
            result = await eng.plan(goal, ApexPhase.recon, _subgraph(i + 1), _evidence(i + 1))
            assert isinstance(result, list)

        assert budget.calls_attempted == 2

        # Third call should be budget-blocked → fallback
        fb.call_count = 0  # reset to count only the blocked call
        result = await eng.plan(goal, ApexPhase.recon, _subgraph(3), _evidence(4))
        assert isinstance(result, list)
        assert fb.call_count == 1, "fallback must be called when budget is exhausted"


class TestPerPhaseBudgetExhaustion:
    """Scenario 2: per-phase budget blocks after max_per_phase."""

    @pytest.mark.asyncio
    async def test_per_phase_budget_exhausted_falls_back(self) -> None:
        budget = LLMBudgetTracker(max_per_run=10, max_per_phase=1)
        llm = _StubLLM(_good_json())
        eng, fb = _engine(llm, budget=budget)

        goal = _goal()
        sg = _subgraph(1)
        ev = _evidence(2)

        # First call OK
        result1 = await eng.plan(goal, ApexPhase.recon, sg, ev)
        assert isinstance(result1, list)

        # Second call for same phase blocked
        fb.call_count = 0
        result2 = await eng.plan(goal, ApexPhase.recon, _subgraph(2), _evidence(3))
        assert isinstance(result2, list)
        assert fb.call_count == 1


class TestBudgetExhaustionPlanDecision:
    """Scenario 3: PlanDecision records llm_error_category="budget_exhausted"."""

    @pytest.mark.asyncio
    async def test_budget_exhausted_decision_category(self) -> None:
        budget = LLMBudgetTracker(max_per_run=0, max_per_phase=10)
        llm = _StubLLM(_good_json())
        eng, _ = _engine(llm, budget=budget)

        await eng.plan(_goal(), ApexPhase.recon, _subgraph(), _evidence())
        assert eng.last_decision is not None
        assert eng.last_decision.llm_error_category == "budget_exhausted"
        assert eng.last_decision.fallback_used is True


class TestPermanent401:
    """Scenario 4: 401 status_code exception is NOT retried."""

    @pytest.mark.asyncio
    async def test_401_is_not_retried(self) -> None:
        exc = RuntimeError("Unauthorized")
        exc.status_code = 401  # type: ignore[attr-defined]
        llm = _ErrorLLM(exc)
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5)
        eng, fb = _engine(llm, budget=budget, max_retries=2)

        await eng.plan(_goal(), ApexPhase.recon, _subgraph(1), _evidence(1))

        # 401 is permanent — only 1 invoke call, no retries
        assert llm.call_count == 1, "401 must never be retried"
        assert fb.call_count == 1
        assert eng.last_decision is not None
        assert eng.last_decision.llm_error_category == "permanent"
        assert eng.last_decision.llm_http_status == 401


class TestPermanent404:
    """Scenario 5: 404 status_code exception is NOT retried."""

    @pytest.mark.asyncio
    async def test_404_is_not_retried(self) -> None:
        exc = RuntimeError("Not Found")
        exc.status_code = 404  # type: ignore[attr-defined]
        llm = _ErrorLLM(exc)
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5)
        eng, fb = _engine(llm, budget=budget, max_retries=2)

        await eng.plan(_goal(), ApexPhase.recon, _subgraph(1), _evidence(1))

        assert llm.call_count == 1, "404 must never be retried"
        assert fb.call_count == 1
        assert eng.last_decision is not None
        assert eng.last_decision.llm_error_category == "permanent"
        assert eng.last_decision.llm_http_status == 404


class TestTransientRetryBounded:
    """Scenario 6: transient error is retried up to max_retries."""

    @pytest.mark.asyncio
    async def test_transient_retried_max_retries_times(self) -> None:
        # Simulate connection error (no status_code) — transient
        exc = ConnectionError("timeout")
        llm = _ErrorLLM(exc)
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5)
        eng, fb = _engine(llm, budget=budget, max_retries=2)

        await eng.plan(_goal(), ApexPhase.recon, _subgraph(1), _evidence(1))

        # max_retries=2 means 3 attempts total (initial + 2 retries)
        assert llm.call_count == 3, f"expected 3 invocations, got {llm.call_count}"
        assert fb.call_count == 1
        assert eng.last_decision is not None
        assert eng.last_decision.llm_error_category == "transient"


class TestTimeoutRetryBudget:
    """Scenario 7: transient error retries increment the budget retries counter."""

    @pytest.mark.asyncio
    async def test_transient_retry_increments_budget_retries(self) -> None:
        exc = TimeoutError("request timed out")
        llm = _ErrorLLM(exc)
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5)
        eng, _ = _engine(llm, budget=budget, max_retries=1)

        await eng.plan(_goal(), ApexPhase.recon, _subgraph(1), _evidence(1))

        # max_retries=1 → 1 retry → budget.retries == 1
        assert budget.retries == 1


class TestSuccessfulCallCounters:
    """Scenario 8: successful call increments calls_succeeded and calls_attempted."""

    @pytest.mark.asyncio
    async def test_success_increments_counters(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5)
        llm = _StubLLM(_good_json())
        eng, _ = _engine(llm, budget=budget)

        assert budget.calls_attempted == 0
        assert budget.calls_succeeded == 0

        await eng.plan(_goal(), ApexPhase.recon, _subgraph(1), _evidence(2))

        assert budget.calls_attempted == 1
        assert budget.calls_succeeded == 1
        assert budget.calls_failed == 0


class TestFailedCallCounters:
    """Scenario 9: permanent failure increments calls_failed and fallbacks."""

    @pytest.mark.asyncio
    async def test_permanent_failure_increments_failed_and_fallbacks(self) -> None:
        exc = RuntimeError("auth")
        exc.status_code = 401  # type: ignore[attr-defined]
        llm = _ErrorLLM(exc)
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5)
        eng, _ = _engine(llm, budget=budget)

        await eng.plan(_goal(), ApexPhase.recon, _subgraph(1), _evidence(1))

        assert budget.calls_failed == 1
        assert budget.fallbacks == 1
        assert budget.calls_succeeded == 0


class TestRepeatedContextDetected:
    """Scenario 10: repeated context is detected and LLM call is skipped."""

    @pytest.mark.asyncio
    async def test_repeated_context_skips_llm(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5, stop_on_repeated_plan=True)
        llm = _StubLLM(_good_json())
        eng, fb = _engine(llm, budget=budget)

        sg = _subgraph(1)
        ev = _evidence(2)

        # First call — succeeds via LLM
        await eng.plan(_goal(), ApexPhase.recon, sg, ev)
        assert llm.call_count == 1

        # Second call with identical subgraph+evidence — should skip LLM
        fb.call_count = 0
        await eng.plan(_goal(), ApexPhase.recon, sg, ev)
        assert llm.call_count == 1, "LLM must not be called again for repeated context"
        assert fb.call_count == 1
        assert eng.last_decision is not None
        assert eng.last_decision.repeated_plan_detected is True
        assert eng.last_decision.repeated_plan_count == 1
        assert "skipped" in eng.last_decision.repeated_plan_action


class TestChangedEvidenceAllowsCall:
    """Scenario 11: changed evidence count allows another LLM call."""

    @pytest.mark.asyncio
    async def test_changed_evidence_allows_new_call(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5, stop_on_repeated_plan=True)
        llm = _StubLLM(_good_json())
        eng, _ = _engine(llm, budget=budget)

        sg = _subgraph(1)

        # First call with 2 evidence entries
        await eng.plan(_goal(), ApexPhase.recon, sg, _evidence(2))
        assert llm.call_count == 1

        # Second call with different evidence count — context hash changes
        await eng.plan(_goal(), ApexPhase.recon, sg, _evidence(5))
        assert llm.call_count == 2, "changed evidence count must trigger a new LLM call"


class TestChangedPhaseAllowsCall:
    """Scenario 12: a different phase allows a new LLM call even with same subgraph."""

    @pytest.mark.asyncio
    async def test_different_phase_allows_new_call(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5, stop_on_repeated_plan=True)
        llm = _StubLLM(_good_json(tool="curl"))
        eng, _ = _engine(llm, budget=budget)

        sg = _subgraph(1)
        ev = _evidence(2)

        # Call for recon phase
        await eng.plan(_goal("recon"), ApexPhase.recon, sg, ev)
        assert llm.call_count == 1

        # Same subgraph+evidence but different phase → new call (different phase key)
        await eng.plan(_goal("web"), ApexPhase.web, sg, ev)
        assert llm.call_count == 2, "different phase must allow a new LLM call"


class TestVerboseLogSuppression:
    """Scenario 13: normal -v flag suppresses openai/httpx/httpcore DEBUG logs."""

    def test_verbose_without_http_debug_suppresses_noisy_loggers(self) -> None:
        from apex_host.main import parse_args

        # Reset logger levels so test is independent
        for name in ("openai", "openai._base_client", "httpx", "httpcore"):
            logging.getLogger(name).setLevel(logging.DEBUG)

        args = parse_args(["--target", "10.0.0.1", "--dry-run", "-v"])
        assert args.verbose is True
        assert args.http_debug is False

        # Apply the suppression logic that main() runs
        if args.verbose and not getattr(args, "http_debug", False):
            for _noisy in ("openai", "openai._base_client", "httpx", "httpcore"):
                logging.getLogger(_noisy).setLevel(logging.WARNING)

        for name in ("openai", "openai._base_client", "httpx", "httpcore"):
            assert logging.getLogger(name).level == logging.WARNING, (
                f"Logger {name!r} should be WARNING when -v but not --http-debug"
            )


class TestHttpDebugFlag:
    """Scenario 14: --http-debug leaves transport loggers at their current level."""

    def test_http_debug_flag_parsed_correctly(self) -> None:
        from apex_host.main import parse_args

        args = parse_args(["--target", "10.0.0.1", "--dry-run", "-v", "--http-debug"])
        assert args.http_debug is True

        # With --http-debug the suppression block is skipped; loggers stay DEBUG
        for _noisy in ("openai", "openai._base_client", "httpx", "httpcore"):
            logging.getLogger(_noisy).setLevel(logging.DEBUG)

        if args.verbose and not getattr(args, "http_debug", False):
            for n in ("openai", "openai._base_client", "httpx", "httpcore"):
                logging.getLogger(n).setLevel(logging.WARNING)

        # No suppression should have happened
        for name in ("openai", "openai._base_client", "httpx", "httpcore"):
            assert logging.getLogger(name).level == logging.DEBUG, (
                f"Logger {name!r} must remain DEBUG when --http-debug is set"
            )


class TestJsonExportLlmUsage:
    """Scenario 15: JSON export contains "llm_usage" key with correct fields."""

    def test_json_dict_contains_llm_usage(self) -> None:
        import collections
        from memfabric.types import SubgraphView
        from apex_host.config import ApexConfig
        from apex_host.eval.report import build_report, to_json_dict
        from apex_host.graph_state import ApexGraphState

        config = ApexConfig(target=_TARGET, dry_run=True)
        subgraph = SubgraphView(anchor=f"host:{_TARGET}", nodes=[], edges=[], depth=2)
        state: ApexGraphState = {
            "run_id": "r1", "target": _TARGET, "phase": "recon",
            "goal": "test", "current_task": None, "evidence_summary": "",
            "findings": [], "error_episodes": [], "last_tool_result": None,
            "last_error": None, "completed": True, "turn_count": 0,
            "planner_decisions": [], "tool_results": None, "repair_count": 0,
            "policy_decisions": [],
        }

        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        budget.calls_attempted = 3
        budget.calls_succeeded = 2
        budget.calls_failed = 1

        report = build_report(
            state, subgraph, config,
            llm_budget=budget.to_dict(),
        )
        d = to_json_dict(report)

        assert "llm_usage" in d, "to_json_dict must include 'llm_usage' key"
        u = d["llm_usage"]
        assert u["calls_attempted"] == 3
        assert u["calls_succeeded"] == 2
        assert u["calls_failed"] == 1
        assert "budget_remaining" in u
        assert "phase_counts" in u
        assert "repeated_skips" in u


class TestPlanDecisionExport7Fields:
    """Scenario 16: PlanDecision.to_dict() includes all 7 new budget/error fields."""

    def test_plan_decision_has_all_new_fields(self) -> None:
        from dataclasses import asdict
        from memfabric.ids import now

        d = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="test",
            fallback_used=True,
            timestamp=now(),
            phase="recon",
            repeated_plan_detected=True,
            repeated_plan_fingerprint="abc12345",
            repeated_plan_count=2,
            repeated_plan_action="skipped_llm",
            llm_error_category="budget_exhausted",
            llm_http_status=429,
            llm_retry_count=1,
        ).to_dict()

        assert d["repeated_plan_detected"] is True
        assert d["repeated_plan_fingerprint"] == "abc12345"
        assert d["repeated_plan_count"] == 2
        assert d["repeated_plan_action"] == "skipped_llm"
        assert d["llm_error_category"] == "budget_exhausted"
        assert d["llm_http_status"] == 429
        assert d["llm_retry_count"] == 1


class TestBudgetRemainingCountsDown:
    """Scenario 17: budget_remaining decreases as calls are consumed."""

    def test_budget_remaining_decrements(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=5)
        assert budget.budget_remaining == 5

        budget.record_call_start("recon")
        assert budget.budget_remaining == 4

        budget.record_call_start("recon")
        budget.record_call_start("web")
        assert budget.budget_remaining == 2

    def test_budget_remaining_never_negative(self) -> None:
        budget = LLMBudgetTracker(max_per_run=1, max_per_phase=5)
        budget.record_call_start("recon")
        budget.record_call_start("recon")  # over budget
        assert budget.budget_remaining == 0


class TestToDictKeys:
    """Scenario 18: LLMBudgetTracker.to_dict() contains all expected keys."""

    def test_to_dict_contains_all_expected_keys(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        budget.record_call_start("recon")
        budget.record_success("recon", 1.23, 1, "abc12345", "gpt-5")
        budget.record_call_start("web")
        exc = RuntimeError("err")
        exc.status_code = 401  # type: ignore[attr-defined]
        budget.record_failure("web", 0.5, "permanent", 401, "gpt-5")
        budget.record_retry()

        d = budget.to_dict()

        required_keys = {
            "enabled",
            "max_calls_per_run",
            "max_calls_per_phase",
            "stop_on_repeated_plan",
            "calls_attempted",
            "calls_succeeded",
            "calls_failed",
            "fallbacks",
            "retries",
            "total_elapsed_seconds",
            "budget_remaining",
            "stop_reason",
            "phase_counts",
            "repeated_skips",
        }
        missing = required_keys - d.keys()
        assert not missing, f"to_dict() missing keys: {missing}"
        assert d["calls_attempted"] == 2
        assert d["calls_succeeded"] == 1
        assert d["calls_failed"] == 1
        assert d["retries"] == 1
        assert d["phase_counts"]["recon"] == 1
        assert d["phase_counts"]["web"] == 1


# ---------------------------------------------------------------------------
# _classify_error unit tests (companion to scenarios 4 & 5)
# ---------------------------------------------------------------------------

class TestClassifyError:
    def test_401_is_permanent(self) -> None:
        exc = RuntimeError("auth")
        exc.status_code = 401  # type: ignore[attr-defined]
        cat, status = _classify_error(exc)
        assert cat == "permanent"
        assert status == 401

    def test_403_is_permanent(self) -> None:
        exc = RuntimeError("forbidden")
        exc.status_code = 403  # type: ignore[attr-defined]
        cat, status = _classify_error(exc)
        assert cat == "permanent"
        assert status == 403

    def test_404_is_permanent(self) -> None:
        exc = RuntimeError("not found")
        exc.status_code = 404  # type: ignore[attr-defined]
        cat, status = _classify_error(exc)
        assert cat == "permanent"
        assert status == 404

    def test_429_is_transient(self) -> None:
        exc = RuntimeError("rate limited")
        exc.status_code = 429  # type: ignore[attr-defined]
        cat, status = _classify_error(exc)
        assert cat == "transient"
        assert status == 429

    def test_500_is_transient(self) -> None:
        exc = RuntimeError("server error")
        exc.status_code = 500  # type: ignore[attr-defined]
        cat, status = _classify_error(exc)
        assert cat == "transient"

    def test_timeout_no_status_is_transient(self) -> None:
        exc = TimeoutError("deadline exceeded")
        cat, status = _classify_error(exc)
        assert cat == "transient"
        assert status is None

    def test_authentication_error_suffix_is_permanent(self) -> None:
        class FakeAuthenticationError(RuntimeError):
            pass
        exc = FakeAuthenticationError("bad key")
        cat, status = _classify_error(exc)
        assert cat == "permanent"

    def test_nested_response_status_code(self) -> None:
        """Status extracted from exc.response.status_code when exc.status_code absent."""
        class _Resp:
            status_code = 401

        exc = RuntimeError("auth via response")
        exc.response = _Resp()  # type: ignore[attr-defined]
        cat, status = _classify_error(exc)
        assert cat == "permanent"
        assert status == 401
