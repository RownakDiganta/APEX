# test_llm_budget_efficiency.py
# Tests for the LLM-budget efficiency fixes: deterministic-first abandon gate (no LLM call when the deterministic planner abandons), per-reason fallback accounting, budget range validation, and the release-gate regression scenario.
"""Bounded-LLM-budget efficiency regression tests (CLAUDE.md §28).

Proves the fixes that stopped the global LLM budget being exhausted during
minimal recon + failed web attempts:

- a budgeted PlanningEngine does NOT spend an LLM call (or a budget slot) when
  the deterministic planner abandons (no actionable candidate / prerequisite
  absent) — the primary budget-waste fix;
- with no budget tracker the LLM-primary behavior is preserved (the LLM is
  still attempted even when the deterministic planner would abandon);
- one deterministic decision is produced per turn and reused on fallback;
- fallbacks are accounted per reason (fallbacks == sum(fallback_reasons));
- the LLM-budget config ranges are validated (zero/negative/excessive rejected);
- the release-gate recon->web regression scenario passes.

All fakes — no real provider, no network, no subprocess.
"""
from __future__ import annotations

import pytest

from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.config import ApexConfig
from apex_host.eval.check_config import validate_combinations
from apex_host.planning.budget import LLMBudgetTracker
from apex_host.planning.engine import PlanningEngine
from apex_host.types import ApexPhase

_TARGET = "192.0.2.10"
_ANCHOR = f"host:{_TARGET}"


def _goal(phase: str = "recon") -> Goal:
    return Goal(id="g", description="d", phase=phase, anchor_node=_ANCHOR)


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=2)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=_empty_subgraph(), tiers_queried=[])


class _AbandonFallback:
    """Deterministic planner that always abandons (no actionable candidate)."""

    def __init__(self) -> None:
        self.call_count = 0

    async def plan(self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle):
        self.call_count += 1
        return AbandonSignal(reason="no actionable candidate")


class _TaskFallback:
    """Deterministic planner that always produces one task."""

    def __init__(self) -> None:
        self.call_count = 0

    async def plan(self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle):
        self.call_count += 1
        return [TaskSpec(
            id="t", goal_id=goal.id, executor_domain="recon",
            params={"tool": "nmap", "args": ["-sV"], "target": _TARGET, "parser": "nmap"},
            subgraph_anchor=_ANCHOR, phase=goal.phase,
        )]


class _ExplodingLLM:
    """A chat model whose invoke() must never be called."""

    def invoke(self, messages):  # noqa: ANN001, ANN201
        raise AssertionError("the LLM must not be invoked on a deterministic-abandon turn")


class _Router:
    def __init__(self, llm=None) -> None:  # noqa: ANN001
        self._llm = llm

    def planner_llm(self):  # noqa: ANN201
        return self._llm


class _FakeRouter:
    def planner_llm(self):  # noqa: ANN201
        return None


# ===========================================================================
# Deterministic-first abandon gate
# ===========================================================================


class TestAbandonGate:
    @pytest.mark.asyncio
    async def test_budgeted_abandon_skips_llm_and_budget(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        engine = PlanningEngine(
            model_router=_Router(_ExplodingLLM()), fallback_planner=_AbandonFallback(),
            allowed_tools=["nmap"], target=_TARGET, budget=budget,
        )
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        # No budget slot consumed — the LLM was never even constructed/consulted.
        assert budget.calls_attempted == 0
        assert budget.fallbacks == 1
        assert budget.fallback_reasons.get("no_actionable_candidate") == 1

    @pytest.mark.asyncio
    async def test_unbudgeted_abandon_still_attempts_llm(self) -> None:
        # With no budget, the LLM-primary contract is preserved: an abandoning
        # deterministic planner does NOT gate out the LLM. The stub LLM raises
        # only if invoked; here it must be invoked (proving the gate is off).
        class _MarkerLLM:
            def __init__(self) -> None:
                self.invoked = False

            def invoke(self, messages):  # noqa: ANN001, ANN201
                self.invoked = True
                raise RuntimeError("marker")  # forces fallback after invocation

        llm = _MarkerLLM()
        engine = PlanningEngine(
            model_router=_Router(llm), fallback_planner=_AbandonFallback(),
            allowed_tools=["nmap"], target=_TARGET, budget=None, max_retries=0,
        )
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert llm.invoked is True
        assert isinstance(result, AbandonSignal)

    @pytest.mark.asyncio
    async def test_deterministic_candidate_still_consults_llm(self) -> None:
        # When the deterministic planner DOES have candidates, the gate does not
        # fire — the fake router returns None so we fall back, but the point is
        # the abandon-gate did not short-circuit before the LLM path.
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        fb = _TaskFallback()
        engine = PlanningEngine(
            model_router=_FakeRouter(), fallback_planner=fb,
            allowed_tools=["nmap"], target=_TARGET, budget=budget,
        )
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list) and len(result) == 1
        # no_llm_configured fallback (router returned None), not the abandon gate.
        assert budget.fallback_reasons.get("no_actionable_candidate") is None
        assert budget.fallback_reasons.get("no_llm_configured") == 1

    @pytest.mark.asyncio
    async def test_one_deterministic_decision_reused_on_fallback(self) -> None:
        # The deterministic planner is consulted exactly ONCE per turn even when
        # the LLM path falls back (reuse one decision — CLAUDE.md §28).
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        fb = _TaskFallback()
        engine = PlanningEngine(
            model_router=_FakeRouter(), fallback_planner=fb,
            allowed_tools=["nmap"], target=_TARGET, budget=budget,
        )
        await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert fb.call_count == 1


# ===========================================================================
# Fallback-reason accounting
# ===========================================================================


class TestFallbackReasons:
    def test_fallbacks_equal_sum_of_reasons(self) -> None:
        b = LLMBudgetTracker()
        b.record_fallback_only("no_actionable_candidate")
        b.record_fallback_only("budget_exhausted")
        b.record_fallback_only("no_actionable_candidate")
        b.record_failure("recon", 0.1, "transient", None)
        assert b.fallbacks == sum(b.fallback_reasons.values()) == 4
        assert b.fallback_reasons["no_actionable_candidate"] == 2
        assert b.fallback_reasons["transient"] == 1

    def test_empty_reason_recorded_as_unspecified(self) -> None:
        b = LLMBudgetTracker()
        b.record_fallback_only("")
        assert b.fallback_reasons.get("unspecified") == 1

    def test_reasons_survive_serialization(self) -> None:
        b = LLMBudgetTracker()
        b.record_fallback_only("no_actionable_candidate")
        restored = LLMBudgetTracker.from_dict(b.to_dict())
        assert restored.fallback_reasons.get("no_actionable_candidate") == 1
        assert "fallback_reasons" in b.to_dict()


# ===========================================================================
# Budget range validation (req 8)
# ===========================================================================


class TestBudgetValidation:
    def _problems(self, **kw) -> list[str]:  # noqa: ANN003
        cfg = ApexConfig(target=_TARGET, dry_run=True, **kw)
        return validate_combinations(cfg)

    def test_zero_per_run_rejected(self) -> None:
        assert any("max_llm_calls_per_run" in p for p in self._problems(max_llm_calls_per_run=0))

    def test_negative_per_run_rejected(self) -> None:
        assert any("max_llm_calls_per_run" in p for p in self._problems(max_llm_calls_per_run=-1))

    def test_excessive_per_run_rejected(self) -> None:
        assert any("exceeds the sanity ceiling" in p for p in self._problems(max_llm_calls_per_run=100000))

    def test_zero_per_phase_rejected(self) -> None:
        assert any("max_llm_calls_per_phase" in p for p in self._problems(max_llm_calls_per_phase=0))

    def test_per_phase_exceeding_per_run_rejected(self) -> None:
        problems = self._problems(max_llm_calls_per_run=3, max_llm_calls_per_phase=10)
        assert any("must not exceed" in p for p in problems)

    def test_practical_bounded_budget_is_valid(self) -> None:
        # The documented live-test values (§28) must validate cleanly.
        assert self._problems(max_llm_calls_per_run=20, max_llm_calls_per_phase=4) == []


# ===========================================================================
# Release gate
# ===========================================================================


class TestReleaseGate:
    @pytest.mark.asyncio
    async def test_recon_web_regression_scenario_passes(self) -> None:
        from apex_host.eval.release_gate import scenario_recon_web_engagement_regression

        result = await scenario_recon_web_engagement_regression()
        assert result.passed is True, result.detail

    @pytest.mark.asyncio
    async def test_full_release_gate_passes(self) -> None:
        from apex_host.eval.release_gate import run_release_gate

        report = await run_release_gate()
        assert report.passed is True, report.format_text()
