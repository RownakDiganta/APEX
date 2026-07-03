# test_planners_with_engine.py
# Tests for domain planners wired through PlanningEngine: LLM path, fallback, confidence gate, retry, GlobalPlanner budget.
"""Tests for planners wired through PlanningEngine.

Covers:
- Each domain planner (Recon, Web, Credential, PrivEsc): LLM path, fallback
  path, confidence-gate fallback, and retry-then-fallback on validator rejection.
- GlobalPlanner: phase selection, budget tracking, force-advance on budget
  exhaustion.
- PlanningEngine: confidence threshold, max_retries, stop_reason.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from memfabric.types import (
    AbandonSignal,
    EvidenceBundle,
    Goal,
    SubgraphView,
    TaskSpec,
)

from apex_host.planners.capabilities import Capability
from apex_host.planners.credential_planner import CredentialPlanner, _CredentialDeterministic
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.planners.priv_esc_planner import PrivEscPlanner, _PrivEscDeterministic
from apex_host.planners.recon_planner import ReconPlanner, _ReconDeterministic
from apex_host.planners.web_planner import WebPlanner, _WebDeterministic
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

# ---------------------------------------------------------------------------
# Shared stubs
# ---------------------------------------------------------------------------

_TARGET = "10.0.0.1"


def _goal(phase: str = "recon") -> Goal:
    return Goal(id="g-1", description="test goal", phase=phase, anchor_node=f"host:{_TARGET}")


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=f"host:{_TARGET}", nodes=[], edges=[], depth=2)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(entries=[], query="test", subgraph=None, tiers_queried=[])


def _registry(*tools: str) -> ToolRegistry:
    return ToolRegistry(allowed_tools=list(tools))


class _StubLLMResponse:
    def __init__(self, content: str) -> None:
        self.content = content


class _StubLLM:
    """Returns the same JSON string on every invoke()."""

    def __init__(self, json_str: str) -> None:
        self._json_str = json_str
        self.call_count = 0

    def invoke(self, messages: list[dict[str, str]]) -> _StubLLMResponse:
        self.call_count += 1
        return _StubLLMResponse(self._json_str)


class _RaisingLLM:
    """Raises RuntimeError on every invoke()."""

    def __init__(self) -> None:
        self.call_count = 0

    def invoke(self, messages: list[dict[str, str]]) -> _StubLLMResponse:
        self.call_count += 1
        raise RuntimeError("simulated LLM failure")


class _RotatingLLM:
    """Returns bad JSON the first N times, then good JSON."""

    def __init__(self, bad_count: int, good_json: str) -> None:
        self._bad_count = bad_count
        self._good_json = good_json
        self.call_count = 0

    def invoke(self, messages: list[dict[str, str]]) -> _StubLLMResponse:
        self.call_count += 1
        if self.call_count <= self._bad_count:
            return _StubLLMResponse("NOT VALID JSON {{{{")
        return _StubLLMResponse(self._good_json)


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
    """Always returns None — triggers deterministic fallback."""

    def planner_llm(self) -> object:
        return None

    def executor_llm(self) -> object:
        return None

    def parser_llm(self) -> object:
        return None

    def reflector_llm(self) -> object:
        return None


class _FallbackCounter:
    """Counts how many times the fallback planner was called."""

    def __init__(self) -> None:
        self.call_count = 0

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        self.call_count += 1
        return [
            TaskSpec(
                id="fallback-id",
                goal_id=goal.id,
                executor_domain="recon",
                params={"tool": "nmap", "args": ["-sV", _TARGET], "parser": "nmap", "target": _TARGET},
            )
        ]


def _good_json(tool: str = "nmap", args: list[str] | None = None, confidence: float = 0.9) -> str:
    return json.dumps({
        "reasoning": "test",
        "confidence": confidence,
        "selected_tasks": [
            {
                "tool": tool,
                "args": args or ["-sV", _TARGET],
                "parser": "nmap",
                "executor_domain": "recon",
                "target": _TARGET,
                "rationale": "test task",
            }
        ],
        "rejected_tasks": [],
        "stop_reason": None,
        "next_phase": None,
    })


# ---------------------------------------------------------------------------
# PlanningEngine: confidence_threshold + max_retries
# ---------------------------------------------------------------------------

class TestPlanningEngineEnhanced:
    """PlanningEngine with confidence_threshold and max_retries."""

    @pytest.fixture()
    def fallback(self) -> _FallbackCounter:
        return _FallbackCounter()

    def _engine(self, llm: object, fallback: _FallbackCounter, **kw: Any):  # type: ignore[no-untyped-def]
        from apex_host.planning.engine import PlanningEngine
        return PlanningEngine(
            model_router=_StubRouter(llm),
            fallback_planner=fallback,  # type: ignore[arg-type]
            allowed_tools=["nmap"],
            target=_TARGET,
            **kw,
        )

    async def test_high_confidence_executes_llm_tasks(self, fallback: _FallbackCounter) -> None:
        llm = _StubLLM(_good_json(confidence=0.9))
        engine = self._engine(llm, fallback, confidence_threshold=0.4, max_retries=1)
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"
        assert fallback.call_count == 0

    async def test_low_confidence_triggers_fallback_immediately(self, fallback: _FallbackCounter) -> None:
        llm = _StubLLM(_good_json(confidence=0.2))
        engine = self._engine(llm, fallback, confidence_threshold=0.4, max_retries=2)
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"  # fallback task
        assert fallback.call_count == 1
        # Low confidence must NOT retry — it's epistemic, not transient.
        assert llm.call_count == 1

    async def test_llm_error_retries_then_fallback(self, fallback: _FallbackCounter) -> None:
        llm = _RaisingLLM()
        engine = self._engine(llm, fallback, confidence_threshold=0.4, max_retries=2)
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert fallback.call_count == 1
        assert llm.call_count == 3  # initial + 2 retries

    async def test_validator_rejection_retries_then_fallback(self, fallback: _FallbackCounter) -> None:
        llm = _StubLLM("NOT VALID JSON {{{{")
        engine = self._engine(llm, fallback, confidence_threshold=0.4, max_retries=1)
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert fallback.call_count == 1
        assert llm.call_count == 2  # initial + 1 retry

    async def test_retry_succeeds_on_second_attempt(self, fallback: _FallbackCounter) -> None:
        good_json = _good_json(confidence=0.85)
        llm = _RotatingLLM(bad_count=1, good_json=good_json)
        engine = self._engine(llm, fallback, confidence_threshold=0.4, max_retries=2)
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"
        assert fallback.call_count == 0  # succeeded on retry
        assert llm.call_count == 2

    async def test_stop_reason_returns_abandon_signal(self, fallback: _FallbackCounter) -> None:
        json_str = json.dumps({
            "reasoning": "stuck",
            "confidence": 0.8,
            "selected_tasks": [],
            "rejected_tasks": [],
            "stop_reason": "cannot proceed without more info",
            "next_phase": None,
        })
        llm = _StubLLM(json_str)
        engine = self._engine(llm, fallback, confidence_threshold=0.4, max_retries=0)
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "cannot proceed" in result.reason

    async def test_no_llm_uses_fallback_directly(self, fallback: _FallbackCounter) -> None:
        engine = self._engine(None, fallback, confidence_threshold=0.4, max_retries=1)
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert fallback.call_count == 1
        assert isinstance(result, list)

    async def test_zero_retries_no_retry_on_error(self, fallback: _FallbackCounter) -> None:
        llm = _RaisingLLM()
        engine = self._engine(llm, fallback, confidence_threshold=0.4, max_retries=0)
        await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert llm.call_count == 1  # exactly one attempt, then fallback
        assert fallback.call_count == 1

    async def test_confidence_exactly_at_threshold_executes(self, fallback: _FallbackCounter) -> None:
        llm = _StubLLM(_good_json(confidence=0.4))
        engine = self._engine(llm, fallback, confidence_threshold=0.4, max_retries=0)
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        # Exactly at threshold is NOT below threshold — should execute
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"
        assert fallback.call_count == 0

    async def test_confidence_just_below_threshold_fallback(self, fallback: _FallbackCounter) -> None:
        llm = _StubLLM(_good_json(confidence=0.39))
        engine = self._engine(llm, fallback, confidence_threshold=0.4, max_retries=0)
        result = await engine.plan(_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert fallback.call_count == 1


# ---------------------------------------------------------------------------
# ReconPlanner with engine
# ---------------------------------------------------------------------------

class TestReconPlannerWithEngine:
    async def test_without_model_router_uses_deterministic(self) -> None:
        reg = _registry("nmap")
        planner = ReconPlanner(_TARGET, reg)
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"

    async def test_with_fake_router_uses_deterministic_fallback(self) -> None:
        reg = _registry("nmap")
        planner = ReconPlanner(_TARGET, reg, model_router=_FakeModelRouter())
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"

    async def test_with_real_llm_uses_llm_tasks(self) -> None:
        reg = _registry("nmap")
        llm = _StubLLM(_good_json(confidence=0.9))
        planner = ReconPlanner(_TARGET, reg, model_router=_StubRouter(llm))
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"
        assert llm.call_count == 1

    async def test_with_low_confidence_falls_back(self) -> None:
        reg = _registry("nmap")
        llm = _StubLLM(_good_json(confidence=0.1))
        fallback_count = [0]
        original_core_plan = _ReconDeterministic(target=_TARGET, registry=reg).plan

        planner = ReconPlanner(
            _TARGET, reg,
            model_router=_StubRouter(llm),
            confidence_threshold=0.4,
        )
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        # Still gets nmap task (from deterministic fallback)
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"

    async def test_engine_created_only_with_router(self) -> None:
        reg = _registry("nmap")
        planner_no_router = ReconPlanner(_TARGET, reg)
        planner_with_router = ReconPlanner(_TARGET, reg, model_router=_FakeModelRouter())
        assert planner_no_router._engine is None
        assert planner_with_router._engine is not None

    async def test_recon_deterministic_nmap_no_services(self) -> None:
        reg = _registry("nmap")
        core = _ReconDeterministic(_TARGET, reg)
        result = await core.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"
        assert "-Pn" in result[0].params["args"]

    async def test_recon_deterministic_abandon_no_nmap(self) -> None:
        reg = _registry("curl")  # no nmap
        core = _ReconDeterministic(_TARGET, reg)
        result = await core.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "nmap" in result.reason


# ---------------------------------------------------------------------------
# WebPlanner with engine
# ---------------------------------------------------------------------------

class TestWebPlannerWithEngine:
    async def test_without_model_router_uses_deterministic(self) -> None:
        reg = _registry("curl")
        planner = WebPlanner(_TARGET, reg)
        result = await planner.plan(_goal("web"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        tools = [t.params["tool"] for t in result]
        assert "curl" in tools

    async def test_with_fake_router_uses_deterministic_fallback(self) -> None:
        reg = _registry("curl")
        planner = WebPlanner(_TARGET, reg, model_router=_FakeModelRouter())
        result = await planner.plan(_goal("web"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert all(t.params["tool"] == "curl" for t in result)

    async def test_with_llm_produces_tasks(self) -> None:
        reg = _registry("curl")
        llm = _StubLLM(_good_json(tool="curl", args=["-s", "-I", f"http://{_TARGET}"], confidence=0.85))
        planner = WebPlanner(_TARGET, reg, model_router=_StubRouter(llm))
        result = await planner.plan(_goal("web"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert llm.call_count == 1

    async def test_with_raising_llm_falls_back(self) -> None:
        reg = _registry("curl")
        llm = _RaisingLLM()
        planner = WebPlanner(_TARGET, reg, model_router=_StubRouter(llm), max_retries=0)
        result = await planner.plan(_goal("web"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        # Deterministic fallback produces curl tasks
        assert result[0].params["tool"] == "curl"

    async def test_engine_created_only_with_router(self) -> None:
        reg = _registry("curl")
        planner_no_router = WebPlanner(_TARGET, reg)
        planner_with_router = WebPlanner(_TARGET, reg, model_router=_FakeModelRouter())
        assert planner_no_router._engine is None
        assert planner_with_router._engine is not None

    async def test_web_deterministic_head_task_is_first(self) -> None:
        reg = _registry("curl")
        core = _WebDeterministic(_TARGET, reg)
        result = await core.plan(_goal("web"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["args"][1] == "-I"  # HEAD probe first

    async def test_web_deterministic_body_task_is_second(self) -> None:
        reg = _registry("curl")
        core = _WebDeterministic(_TARGET, reg)
        result = await core.plan(_goal("web"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[1].params["parser"] == "curl_body"

    async def test_web_deterministic_abandon_no_tools(self) -> None:
        reg = _registry()  # no tools
        core = _WebDeterministic(_TARGET, reg)
        result = await core.plan(_goal("web"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)


# ---------------------------------------------------------------------------
# CredentialPlanner with engine
# ---------------------------------------------------------------------------

class TestCredentialPlannerWithEngine:
    async def test_without_model_router_uses_deterministic(self) -> None:
        reg = _registry("curl")
        planner = CredentialPlanner(_TARGET, reg)
        result = await planner.plan(_goal("credential"), _empty_subgraph(), _empty_evidence())
        # No telnet cap, no auth_flow → abandon
        assert isinstance(result, AbandonSignal)

    async def test_with_fake_router_same_behaviour(self) -> None:
        reg = _registry("curl")
        planner = CredentialPlanner(_TARGET, reg, model_router=_FakeModelRouter())
        result = await planner.plan(_goal("credential"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)

    async def test_with_llm_produces_tasks(self) -> None:
        reg = _registry("nmap")
        llm = _StubLLM(_good_json(confidence=0.9))
        planner = CredentialPlanner(_TARGET, reg, model_router=_StubRouter(llm))
        result = await planner.plan(_goal("credential"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert llm.call_count == 1

    async def test_engine_created_only_with_router(self) -> None:
        reg = _registry("curl")
        assert CredentialPlanner(_TARGET, reg)._engine is None
        assert CredentialPlanner(_TARGET, reg, model_router=_FakeModelRouter())._engine is not None

    async def test_credential_deterministic_abandons_no_credentials(self) -> None:
        from memfabric.types import Node
        reg = _registry("nc")
        # Build a subgraph with a telnet service node
        telnet_node = Node(
            id="service:10.0.0.1:23",
            type="service",
            props={"port": "23", "proto": "tcp", "service": "telnet"},
            confidence=0.9,
            source="nmap",
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-01T00:00:00Z",
        )
        subgraph = SubgraphView(anchor=f"host:{_TARGET}", nodes=[telnet_node], edges=[], depth=2)
        core = _CredentialDeterministic(_TARGET, reg)
        result = await core.plan(_goal("credential"), subgraph, _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "credentials" in result.reason.lower()

    async def test_credential_deterministic_emits_one_task_with_credentials(self) -> None:
        from memfabric.types import Node
        reg = _registry("nc")
        telnet_node = Node(
            id="service:10.0.0.1:23",
            type="service",
            props={"port": "23", "proto": "tcp", "service": "telnet"},
            confidence=0.9,
            source="nmap",
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-01T00:00:00Z",
        )
        subgraph = SubgraphView(anchor=f"host:{_TARGET}", nodes=[telnet_node], edges=[], depth=2)
        core = _CredentialDeterministic(
            _TARGET, reg,
            username_candidates=["root"],
            password_candidates=[""],
        )
        result = await core.plan(_goal("credential"), subgraph, _empty_evidence())
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0].params["tool"] == "telnet_access"
        assert result[0].params["username"] == "root"


# ---------------------------------------------------------------------------
# PrivEscPlanner with engine
# ---------------------------------------------------------------------------

class TestPrivEscPlannerWithEngine:
    async def test_without_model_router_uses_deterministic(self) -> None:
        reg = _registry("searchsploit")
        planner = PrivEscPlanner(_TARGET, reg)
        result = await planner.plan(_goal("priv_esc"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)  # no capabilities in empty subgraph

    async def test_with_fake_router_same_behaviour(self) -> None:
        reg = _registry("searchsploit")
        planner = PrivEscPlanner(_TARGET, reg, model_router=_FakeModelRouter())
        result = await planner.plan(_goal("priv_esc"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)

    async def test_with_llm_produces_tasks(self) -> None:
        reg = _registry("nmap")
        llm = _StubLLM(_good_json(confidence=0.9))
        planner = PrivEscPlanner(_TARGET, reg, model_router=_StubRouter(llm))
        result = await planner.plan(_goal("priv_esc"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert llm.call_count == 1

    async def test_engine_created_only_with_router(self) -> None:
        reg = _registry("searchsploit")
        assert PrivEscPlanner(_TARGET, reg)._engine is None
        assert PrivEscPlanner(_TARGET, reg, model_router=_FakeModelRouter())._engine is not None

    async def test_priv_esc_deterministic_abandon_no_searchsploit(self) -> None:
        reg = _registry("nmap")  # no searchsploit
        core = _PrivEscDeterministic(_TARGET, reg)
        result = await core.plan(_goal("priv_esc"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "searchsploit" in result.reason

    async def test_priv_esc_deterministic_emits_searchsploit_task(self) -> None:
        from memfabric.types import Node
        reg = _registry("searchsploit")
        svc_node = Node(
            id=f"service:{_TARGET}:22",
            type="service",
            props={"port": "22", "proto": "tcp", "service": "ssh", "version": "7.6p1"},
            confidence=0.9,
            source="nmap",
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-01T00:00:00Z",
        )
        subgraph = SubgraphView(anchor=f"host:{_TARGET}", nodes=[svc_node], edges=[], depth=2)
        core = _PrivEscDeterministic(_TARGET, reg)
        result = await core.plan(_goal("priv_esc"), subgraph, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "searchsploit"


# ---------------------------------------------------------------------------
# GlobalPlanner: phase selection + budget
# ---------------------------------------------------------------------------

class TestGlobalPlannerPhaseSelection:
    def test_no_host_returns_recon(self) -> None:
        gp = GlobalPlanner(max_turns=20)
        assert gp.decide_phase(node_types_seen=set(), turn_count=0) == ApexPhase.recon

    def test_host_no_service_returns_recon(self) -> None:
        gp = GlobalPlanner(max_turns=20)
        assert gp.decide_phase(node_types_seen={"host"}, turn_count=0) == ApexPhase.recon

    def test_host_and_service_no_endpoint_returns_web(self) -> None:
        gp = GlobalPlanner(max_turns=20)
        phase = gp.decide_phase(node_types_seen={"host", "service"}, turn_count=0)
        assert phase == ApexPhase.web

    def test_host_service_endpoint_no_auth_returns_credential(self) -> None:
        gp = GlobalPlanner(max_turns=20)
        phase = gp.decide_phase(
            node_types_seen={"host", "service", "endpoint"}, turn_count=0
        )
        assert phase == ApexPhase.credential

    def test_host_service_endpoint_auth_returns_priv_esc(self) -> None:
        gp = GlobalPlanner(max_turns=20)
        phase = gp.decide_phase(
            node_types_seen={"host", "service", "endpoint", "auth_flow"}, turn_count=0
        )
        assert phase == ApexPhase.priv_esc

    def test_max_turns_returns_done(self) -> None:
        gp = GlobalPlanner(max_turns=5)
        assert gp.decide_phase(node_types_seen=set(), turn_count=5) == ApexPhase.done
        assert gp.decide_phase(node_types_seen=set(), turn_count=10) == ApexPhase.done

    def test_goal_for_phase_formats_target(self) -> None:
        gp = GlobalPlanner(max_turns=20)
        text = gp.goal_for_phase(ApexPhase.recon, "192.168.1.1")
        assert "192.168.1.1" in text
        assert "reconnaissance" in text.lower() or "recon" in text.lower()


class TestGlobalPlannerBudget:
    def test_budget_remaining_starts_at_default(self) -> None:
        gp = GlobalPlanner(max_turns=100)
        assert gp.budget_remaining(ApexPhase.recon) > 0

    def test_record_turn_decrements_budget(self) -> None:
        gp = GlobalPlanner(max_turns=100)
        before = gp.budget_remaining(ApexPhase.recon)
        gp.record_turn(ApexPhase.recon)
        assert gp.budget_remaining(ApexPhase.recon) == before - 1

    def test_budget_exhausted_triggers_phase_advance(self) -> None:
        # Set a tiny recon budget so it exhausts immediately
        gp = GlobalPlanner(max_turns=100, phase_budgets={ApexPhase.recon.value: 1})
        gp.record_turn(ApexPhase.recon)  # exhaust the budget
        # With budget exhausted, recon should force-advance to web
        # (even though only host is present, service requirement would normally hold us)
        phase = gp.decide_phase(
            node_types_seen={"host"},
            turn_count=1,
            current_phase=ApexPhase.recon.value,
        )
        # Force-advance: recon completion node "service" is injected → go to web
        assert phase == ApexPhase.web

    def test_budget_not_exhausted_stays_in_recon(self) -> None:
        gp = GlobalPlanner(max_turns=100, phase_budgets={ApexPhase.recon.value: 5})
        gp.record_turn(ApexPhase.recon)
        phase = gp.decide_phase(
            node_types_seen={"host"},
            turn_count=1,
            current_phase=ApexPhase.recon.value,
        )
        assert phase == ApexPhase.recon

    def test_record_turn_with_string_phase(self) -> None:
        gp = GlobalPlanner(max_turns=100)
        gp.record_turn("recon")
        assert gp.budget_remaining("recon") == gp.budget_remaining(ApexPhase.recon)

    def test_custom_phase_budgets_override_defaults(self) -> None:
        gp = GlobalPlanner(max_turns=100, phase_budgets={"web": 2})
        assert gp.budget_remaining(ApexPhase.web) == 2

    def test_budget_remaining_never_negative(self) -> None:
        gp = GlobalPlanner(max_turns=100, phase_budgets={ApexPhase.recon.value: 1})
        for _ in range(10):
            gp.record_turn(ApexPhase.recon)
        assert gp.budget_remaining(ApexPhase.recon) == 0

    def test_web_budget_exhausted_forces_credential_phase(self) -> None:
        gp = GlobalPlanner(max_turns=100, phase_budgets={ApexPhase.web.value: 1})
        gp.record_turn(ApexPhase.web)
        phase = gp.decide_phase(
            node_types_seen={"host", "service"},
            turn_count=2,
            current_phase=ApexPhase.web.value,
        )
        # web budget exhausted: endpoint completion node injected → go to credential
        assert phase == ApexPhase.credential

    def test_no_force_advance_when_budget_not_specified(self) -> None:
        gp = GlobalPlanner(max_turns=100)
        # Don't exhaust budget — stays at web normally
        phase = gp.decide_phase(
            node_types_seen={"host", "service"},
            turn_count=1,
            current_phase=ApexPhase.web.value,
        )
        assert phase == ApexPhase.web

    def test_decide_phase_without_current_phase_kwarg_works(self) -> None:
        # Backward compatibility: current_phase is optional
        gp = GlobalPlanner(max_turns=20)
        phase = gp.decide_phase(node_types_seen={"host", "service"}, turn_count=0)
        assert phase == ApexPhase.web


# ---------------------------------------------------------------------------
# Planner confidence threshold via constructor param
# ---------------------------------------------------------------------------

class TestPlannerConfidenceThreshold:
    """Ensure confidence_threshold flows correctly through each planner's constructor."""

    async def test_recon_planner_confidence_threshold_flows_to_engine(self) -> None:
        reg = _registry("nmap")
        llm = _StubLLM(_good_json(confidence=0.5))
        planner = ReconPlanner(_TARGET, reg, model_router=_StubRouter(llm), confidence_threshold=0.6)
        # confidence=0.5 < threshold=0.6 → should use deterministic fallback
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "nmap"
        # LLM was called but confidence gate triggered fallback
        assert llm.call_count == 1

    async def test_web_planner_confidence_threshold_flows_to_engine(self) -> None:
        reg = _registry("curl")
        llm = _StubLLM(_good_json(tool="curl", args=["-s", "-I", f"http://{_TARGET}"], confidence=0.2))
        planner = WebPlanner(_TARGET, reg, model_router=_StubRouter(llm), confidence_threshold=0.5)
        result = await planner.plan(_goal("web"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert llm.call_count == 1  # called, but confidence gate blocked it


# ---------------------------------------------------------------------------
# Planner retry policy via constructor param
# ---------------------------------------------------------------------------

class TestPlannerRetryPolicy:
    async def test_recon_planner_retries_up_to_max(self) -> None:
        reg = _registry("nmap")
        llm = _RaisingLLM()
        planner = ReconPlanner(_TARGET, reg, model_router=_StubRouter(llm), max_retries=3)
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)  # deterministic fallback
        assert llm.call_count == 4  # 1 initial + 3 retries

    async def test_web_planner_no_retries_on_zero(self) -> None:
        reg = _registry("curl")
        llm = _RaisingLLM()
        planner = WebPlanner(_TARGET, reg, model_router=_StubRouter(llm), max_retries=0)
        result = await planner.plan(_goal("web"), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert llm.call_count == 1  # single attempt, then fallback
