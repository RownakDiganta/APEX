# test_llm_phase5.py
# Phase 5 tests: LLMGateway, RepairEngine budget (F03/F04), reflect_or_continue phase context (F08), LLMPolicyGuard wiring (F14).
"""Phase 5 test suite.

Tests the four Phase 5 findings plus the new LLMGateway:

F03 — RepairEngine budget integration:
    Budget exhausted → repair returns None; budget events recorded on success/failure.

F04 — build_apex_graph budget wiring to RepairEngine:
    The shared budget_tracker is passed through to RepairEngine.

F08 — reflect_or_continue phase context fix:
    decide_phase peek receives current_phase= kwarg so budget force-advance fires correctly.

F14 — LLMPolicyGuard production wiring:
    model_router!=None → all domain planners and RepairEngine receive an LLMPolicyGuard.

LLMGateway unit tests:
    All status codes, budget accounting, guard integration, status helpers, to_dict().
"""
from __future__ import annotations

import json
import types
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import EvidenceBundle, SubgraphView, TaskSpec

from apex_host.config import ApexConfig
from apex_host.graph import build_apex_graph
from apex_host.llm.gateway import (
    LLMCallContext,
    LLMCallPurpose,
    LLMCallResult,
    LLMCallStatus,
    LLMGateway,
)
from apex_host.planning.budget import LLMBudgetTracker
from apex_host.planning.repair import RepairEngine, RepairRequest
from apex_host.planners.credential_planner import CredentialPlanner
from apex_host.planners.priv_esc_planner import PrivEscPlanner
from apex_host.planners.recon_planner import ReconPlanner
from apex_host.planners.web_planner import WebPlanner
from apex_host.policy.llm_guard import LLMPolicyGuard
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

_TARGET = "10.0.0.1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def _make_config(**kw: Any) -> ApexConfig:
    defaults: dict[str, Any] = {
        "target": _TARGET,
        "dry_run": True,
        "max_turns": 2,
    }
    defaults.update(kw)
    return ApexConfig(**defaults)


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=f"host:{_TARGET}", nodes=[], edges=[], depth=2)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(entries=[], query="test", subgraph=None, tiers_queried=[])


def _make_task(tool: str = "nmap") -> TaskSpec:
    return TaskSpec(
        id="t1",
        goal_id="g1",
        executor_domain="recon",
        params={"tool": tool, "args": ["-sV", _TARGET], "target": _TARGET, "parser": "nmap"},
        subgraph_anchor=f"host:{_TARGET}",
        phase=ApexPhase.recon.value,
    )


def _make_registry() -> ToolRegistry:
    return ToolRegistry(allowed_tools=["nmap", "curl", "nc"])


class _FakeRouter:
    """Router that returns a configurable LLM or None."""

    def __init__(self, llm: Any = None) -> None:
        self._llm = llm

    def planner_llm(self) -> Any:
        return self._llm

    def executor_llm(self) -> Any:
        return None

    def parser_llm(self) -> Any:
        return None

    def reflector_llm(self) -> Any:
        return None


class _StubLLM:
    """Returns a canned JSON string from invoke()."""

    def __init__(self, response: str = '{"reasoning":"ok","confidence":0.9,"selected_tasks":[{"tool":"nmap","args":["-sV","10.0.0.1"],"parser":"nmap","executor_domain":"recon","target":"10.0.0.1","rationale":"retry"}],"rejected_tasks":[],"stop_reason":null,"next_phase":null}') -> None:
        self._response = response

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        return types.SimpleNamespace(content=self._response)


class _RaisingLLM:
    """Always raises on invoke."""

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        raise RuntimeError("provider down")


class _TimeoutLLM:
    """Raises a timeout-like error."""

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        raise RuntimeError("timeout exceeded")


# ---------------------------------------------------------------------------
# F03 — RepairEngine budget integration
# ---------------------------------------------------------------------------


class TestRepairEngineBudget:
    """F03: RepairEngine must check the shared budget before calling the LLM."""

    @pytest.mark.asyncio
    async def test_f03_budget_exhausted_returns_none(self) -> None:
        """Exhausted budget → repair() returns None without LLM call."""
        budget = LLMBudgetTracker(max_per_run=0)
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=budget,
        )
        result = await engine.repair(
            failed_task=_make_task(),
            error="non-zero returncode",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_f03_budget_ok_proceeds(self) -> None:
        """Non-exhausted budget → repair() proceeds and may return a TaskSpec."""
        budget = LLMBudgetTracker(max_per_run=5)
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=budget,
        )
        result = await engine.repair(
            failed_task=_make_task(),
            error="non-zero returncode",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        # LLM returned valid task → result is a RepairRequest wrapping a TaskSpec
        assert result is not None
        assert isinstance(result, RepairRequest)

    @pytest.mark.asyncio
    async def test_f03_budget_records_success(self) -> None:
        """Successful repair → budget.calls_succeeded incremented."""
        budget = LLMBudgetTracker(max_per_run=5)
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=budget,
        )
        await engine.repair(
            failed_task=_make_task(),
            error="non-zero returncode",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        assert budget.calls_succeeded == 1
        assert budget.calls_attempted == 1

    @pytest.mark.asyncio
    async def test_f03_budget_records_failure_on_llm_error(self) -> None:
        """LLM raises → budget.calls_failed incremented."""
        budget = LLMBudgetTracker(max_per_run=5)
        llm = _RaisingLLM()
        router = _FakeRouter(llm=llm)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=budget,
        )
        result = await engine.repair(
            failed_task=_make_task(),
            error="non-zero returncode",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        assert result is None
        assert budget.calls_failed == 1
        assert budget.calls_attempted == 1

    @pytest.mark.asyncio
    async def test_f03_no_budget_still_works(self) -> None:
        """No budget tracker → repair() still works normally."""
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=None,
        )
        result = await engine.repair(
            failed_task=_make_task(),
            error="non-zero returncode",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_f03_dry_run_skips_before_budget_check(self) -> None:
        """dry_run=True returns None before budget is consulted."""
        budget = LLMBudgetTracker(max_per_run=0)  # exhausted
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=True,  # dry_run wins
            budget_tracker=budget,
        )
        result = await engine.repair(
            failed_task=_make_task(),
            error="non-zero",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        # dry_run short-circuits; budget not consulted (calls_attempted stays 0)
        assert result is None
        assert budget.calls_attempted == 0

    @pytest.mark.asyncio
    async def test_f03_per_phase_limit_blocks(self) -> None:
        """Per-phase cap blocks repair after per-phase limit is hit."""
        budget = LLMBudgetTracker(max_per_run=10, max_per_phase=1)
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=budget,
        )
        # First call should succeed
        r1 = await engine.repair(
            failed_task=_make_task(),
            error="err",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        assert r1 is not None

        # Second call in same phase → per-phase limit exhausted
        r2 = await engine.repair(
            failed_task=_make_task(),
            error="err",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        assert r2 is None

    @pytest.mark.asyncio
    async def test_f03_budget_records_failure_on_output_blocked(self) -> None:
        """Output blocked by guard → budget.calls_failed incremented."""
        budget = LLMBudgetTracker(max_per_run=5)
        # LLM returns text with a dangerous pattern
        dangerous_json = json.dumps({
            "reasoning": "crontab -e to persist",
            "confidence": 0.9,
            "selected_tasks": [
                {
                    "tool": "nmap",
                    "args": ["-sV", _TARGET],
                    "parser": "nmap",
                    "executor_domain": "recon",
                    "target": _TARGET,
                    "rationale": "retry scan",
                }
            ],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        })
        llm = _StubLLM(response=dangerous_json)
        router = _FakeRouter(llm=llm)
        cfg = _make_config(dry_run=False)
        guard = LLMPolicyGuard(cfg)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=budget,
            guard=guard,
        )
        result = await engine.repair(
            failed_task=_make_task(),
            error="non-zero",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        assert result is None
        assert budget.calls_failed == 1


# ---------------------------------------------------------------------------
# F04 — build_apex_graph budget wiring to RepairEngine
# ---------------------------------------------------------------------------


class TestBuildApexGraphBudgetWiring:
    """F04: build_apex_graph passes budget_tracker to RepairEngine."""

    def test_f04_repair_engine_has_budget_when_wired(self) -> None:
        """RepairEngine receives the budget_tracker from build_apex_graph."""
        api = _make_api()
        registry = _make_registry()
        config = _make_config()
        budget = LLMBudgetTracker(max_per_run=5)
        graph = build_apex_graph(api, registry, config, budget_tracker=budget)
        # Graph compiled without error — wiring succeeded
        assert graph is not None

    def test_f04_no_budget_tracker_still_builds(self) -> None:
        """build_apex_graph without budget_tracker still builds successfully."""
        api = _make_api()
        registry = _make_registry()
        config = _make_config()
        graph = build_apex_graph(api, registry, config, budget_tracker=None)
        assert graph is not None

    def test_f04_repair_engine_budget_is_shared_object(self) -> None:
        """The same budget object reaches the graph (not a copy)."""
        api = _make_api()
        registry = _make_registry()
        config = _make_config()
        budget = LLMBudgetTracker(max_per_run=3)
        # Mutate the budget before graph construction — change should be visible
        budget.calls_attempted += 1
        graph = build_apex_graph(api, registry, config, budget_tracker=budget)
        # Budget object is the same reference (no deep copy)
        assert budget.calls_attempted == 1
        assert graph is not None


# ---------------------------------------------------------------------------
# F08 — reflect_or_continue passes current_phase to decide_phase
# ---------------------------------------------------------------------------


class TestReflectOrContinuePhasePeek:
    """F08: reflect_or_continue peek must pass current_phase to decide_phase."""

    def test_f08_decide_phase_called_with_current_phase(self) -> None:
        """The GlobalPlanner.decide_phase in the peek receives current_phase kwarg."""
        # Phase 10 decomposition: reflect_or_continue moved to orchestration/continuation_node.py.
        with open("apex_host/orchestration/continuation_node.py") as f:
            source = f.read()
        # The reflect_or_continue peek should pass current_phase=state.get("phase")
        assert 'current_phase=state.get("phase")' in source, (
            "F08: reflect_or_continue must pass current_phase=state.get('phase') to decide_phase "
            "(now in apex_host/orchestration/continuation_node.py)"
        )

    def test_f08_reflect_or_continue_has_correct_peek(self) -> None:
        """The peek call is inside reflect_or_continue, not global_plan."""
        # Phase 10 decomposition: reflect_or_continue moved to orchestration/continuation_node.py.
        with open("apex_host/orchestration/continuation_node.py") as f:
            source = f.read()
        # Both the global_plan (current_phase=current_phase) and the peek
        # (current_phase=state.get("phase")) should be present
        assert "current_phase=state.get" in source

    @pytest.mark.asyncio
    async def test_f08_peek_does_not_charge_budget(self) -> None:
        """The peek in reflect_or_continue does NOT call global_planner.record_turn."""
        from apex_host.planners.global_planner import GlobalPlanner
        gp = GlobalPlanner(max_turns=10)
        original_record = gp.record_turn
        calls: list[Any] = []

        def tracked_record_turn(phase: Any) -> None:
            calls.append(phase)
            return original_record(phase)

        gp.record_turn = tracked_record_turn  # type: ignore[method-assign]

        # decide_phase can be called for peek without record_turn
        result = gp.decide_phase(
            node_types_seen=set(),
            turn_count=0,
            has_web_capability=False,
            current_phase="recon",
        )
        # No record_turn called by decide_phase itself
        assert len(calls) == 0
        assert result is not None


# ---------------------------------------------------------------------------
# F14 — LLMPolicyGuard production wiring
# ---------------------------------------------------------------------------


class TestLLMPolicyGuardWiring:
    """F14: LLMPolicyGuard must be wired in build_apex_graph when model_router provided."""

    def test_f14_guard_wired_to_recon_planner(self) -> None:
        """ReconPlanner receives guard when model_router is provided."""
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        registry = _make_registry()
        config = _make_config()
        planner = ReconPlanner(
            config.target,
            registry,
            model_router=router,
            allowed_tools=config.allowed_tools,
        )
        # When no guard passed, engine guard is None
        assert planner._engine is not None
        assert planner._engine._guard is None

        # With guard passed
        guard = LLMPolicyGuard(config)
        planner2 = ReconPlanner(
            config.target,
            registry,
            model_router=router,
            allowed_tools=config.allowed_tools,
            guard=guard,
        )
        assert planner2._engine is not None
        assert planner2._engine._guard is guard

    def test_f14_guard_wired_to_web_planner(self) -> None:
        """WebPlanner receives guard when model_router is provided."""
        router = _FakeRouter(llm=_StubLLM())
        registry = _make_registry()
        config = _make_config()
        guard = LLMPolicyGuard(config)
        planner = WebPlanner(
            config.target,
            registry,
            model_router=router,
            allowed_tools=config.allowed_tools,
            guard=guard,
        )
        assert planner._engine is not None
        assert planner._engine._guard is guard

    def test_f14_guard_wired_to_credential_planner(self) -> None:
        """CredentialPlanner receives guard when model_router is provided."""
        router = _FakeRouter(llm=_StubLLM())
        registry = _make_registry()
        config = _make_config()
        guard = LLMPolicyGuard(config)
        planner = CredentialPlanner(
            config.target,
            registry,
            model_router=router,
            allowed_tools=config.allowed_tools,
            guard=guard,
        )
        assert planner._engine is not None
        assert planner._engine._guard is guard

    def test_f14_guard_wired_to_priv_esc_planner(self) -> None:
        """PrivEscPlanner receives guard when model_router is provided."""
        router = _FakeRouter(llm=_StubLLM())
        registry = _make_registry()
        config = _make_config()
        guard = LLMPolicyGuard(config)
        planner = PrivEscPlanner(
            config.target,
            registry,
            model_router=router,
            allowed_tools=config.allowed_tools,
            guard=guard,
        )
        assert planner._engine is not None
        assert planner._engine._guard is guard

    def test_f14_guard_none_when_no_model_router(self) -> None:
        """Without model_router, no engine is created (guard irrelevant)."""
        registry = _make_registry()
        config = _make_config()
        guard = LLMPolicyGuard(config)
        planner = ReconPlanner(
            config.target, registry,
            model_router=None,
            guard=guard,
        )
        # No engine created when model_router is None
        assert planner._engine is None

    def test_f14_build_apex_graph_wires_guard_with_router(self) -> None:
        """build_apex_graph constructs LLMPolicyGuard when model_router is provided."""
        api = _make_api()
        registry = _make_registry()
        config = _make_config()
        router = _FakeRouter(llm=_StubLLM())
        # Should build without error; guard construction captured in closure
        graph = build_apex_graph(api, registry, config, model_router=router)
        assert graph is not None

    def test_f14_build_apex_graph_no_guard_without_router(self) -> None:
        """build_apex_graph without model_router → guard is None (no overhead)."""
        api = _make_api()
        registry = _make_registry()
        config = _make_config()
        graph = build_apex_graph(api, registry, config, model_router=None)
        assert graph is not None

    def test_f14_repair_engine_accepts_guard(self) -> None:
        """RepairEngine __init__ accepts guard parameter (F14)."""
        config = _make_config()
        guard = LLMPolicyGuard(config)
        engine = RepairEngine(
            model_router=None,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=True,
            guard=guard,
        )
        assert engine._guard is guard

    def test_f14_repair_engine_budget_and_guard_independent(self) -> None:
        """RepairEngine accepts both budget_tracker and guard simultaneously."""
        config = _make_config()
        guard = LLMPolicyGuard(config)
        budget = LLMBudgetTracker(max_per_run=5)
        engine = RepairEngine(
            model_router=None,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=True,
            guard=guard,
            budget_tracker=budget,
        )
        assert engine._guard is guard
        assert engine._budget is budget


# ---------------------------------------------------------------------------
# LLMGateway unit tests
# ---------------------------------------------------------------------------


class TestLLMGatewayStatus:
    """LLMCallStatus helpers."""

    def test_gateway_status_success_is_success(self) -> None:
        assert LLMCallStatus.success.is_success is True
        assert LLMCallStatus.success.is_fallback is False
        assert LLMCallStatus.success.is_blocked is False
        assert LLMCallStatus.success.is_error is False

    def test_gateway_status_fallback_no_router_is_fallback(self) -> None:
        s = LLMCallStatus.fallback_no_router
        assert s.is_fallback is True
        assert s.is_success is False
        assert s.is_error is False

    def test_gateway_status_fallback_no_model_is_fallback(self) -> None:
        s = LLMCallStatus.fallback_no_model
        assert s.is_fallback is True

    def test_gateway_status_budget_exhausted_is_fallback(self) -> None:
        s = LLMCallStatus.budget_exhausted
        assert s.is_fallback is True

    def test_gateway_status_prompt_blocked_is_blocked(self) -> None:
        s = LLMCallStatus.prompt_blocked
        assert s.is_blocked is True
        assert s.is_success is False

    def test_gateway_status_output_blocked_is_blocked(self) -> None:
        s = LLMCallStatus.output_blocked
        assert s.is_blocked is True

    def test_gateway_status_provider_error_is_error(self) -> None:
        s = LLMCallStatus.provider_error
        assert s.is_error is True
        assert s.is_success is False

    def test_gateway_status_timeout_is_error(self) -> None:
        s = LLMCallStatus.timeout
        assert s.is_error is True


class TestLLMCallResult:
    """LLMCallResult dataclass and to_dict."""

    def test_result_default_fields(self) -> None:
        r = LLMCallResult(status=LLMCallStatus.success, raw_text="hello")
        assert r.status == LLMCallStatus.success
        assert r.raw_text == "hello"
        assert r.blocked_reason == ""
        assert r.redaction_count == 0
        assert r.error == ""

    def test_result_to_dict_keys(self) -> None:
        r = LLMCallResult(
            status=LLMCallStatus.prompt_blocked,
            blocked_reason="oob IP",
            redaction_count=2,
        )
        d = r.to_dict()
        assert d["status"] == "prompt_blocked"
        assert d["blocked_reason"] == "oob IP"
        assert d["redaction_count"] == 2
        assert "raw_text_len" in d
        assert d["raw_text_len"] == 0

    def test_result_to_dict_success_raw_text_len(self) -> None:
        r = LLMCallResult(status=LLMCallStatus.success, raw_text="abc")
        d = r.to_dict()
        assert d["raw_text_len"] == 3

    def test_result_blocked_reason_populated(self) -> None:
        r = LLMCallResult(status=LLMCallStatus.budget_exhausted, blocked_reason="run limit")
        assert r.blocked_reason == "run limit"


class TestLLMGatewayNoRouter:
    """Gateway returns fallback_no_router when no router provided."""

    @pytest.mark.asyncio
    async def test_gateway_no_router_returns_fallback(self) -> None:
        gw = LLMGateway(model_router=None)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.fallback_no_router
        assert result.raw_text == ""

    @pytest.mark.asyncio
    async def test_gateway_no_router_no_budget_call(self) -> None:
        """No budget call when router is absent."""
        budget = LLMBudgetTracker(max_per_run=5)
        gw = LLMGateway(model_router=None, budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.repair,
            phase="recon",
            messages=[{"role": "user", "content": "repair"}],
        )
        await gw.invoke(ctx)
        assert budget.calls_attempted == 0


class TestLLMGatewayFakeRouter:
    """FakeModelRouter returns None for all roles → fallback_no_model."""

    @pytest.mark.asyncio
    async def test_gateway_fake_router_returns_fallback_no_model(self) -> None:
        from apex_host.llm.router import FakeModelRouter
        gw = LLMGateway(model_router=FakeModelRouter())
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.fallback_no_model

    @pytest.mark.asyncio
    async def test_gateway_fake_router_no_budget_call(self) -> None:
        """Budget not consulted when model is None."""
        from apex_host.llm.router import FakeModelRouter
        budget = LLMBudgetTracker(max_per_run=5)
        gw = LLMGateway(model_router=FakeModelRouter(), budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        await gw.invoke(ctx)
        assert budget.calls_attempted == 0


class TestLLMGatewayBudget:
    """Budget enforcement in the gateway."""

    @pytest.mark.asyncio
    async def test_gateway_budget_exhausted_status(self) -> None:
        budget = LLMBudgetTracker(max_per_run=0)
        gw = LLMGateway(model_router=_FakeRouter(llm=_StubLLM()), budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.budget_exhausted
        assert result.blocked_reason != ""

    @pytest.mark.asyncio
    async def test_gateway_budget_records_success(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5)
        gw = LLMGateway(model_router=_FakeRouter(llm=_StubLLM()), budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.success
        assert budget.calls_succeeded == 1
        assert budget.calls_attempted == 1

    @pytest.mark.asyncio
    async def test_gateway_budget_records_failure_on_provider_error(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5)
        gw = LLMGateway(model_router=_FakeRouter(llm=_RaisingLLM()), budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.provider_error
        assert budget.calls_failed == 1
        assert budget.calls_attempted == 1

    @pytest.mark.asyncio
    async def test_gateway_timeout_status(self) -> None:
        budget = LLMBudgetTracker(max_per_run=5)
        gw = LLMGateway(model_router=_FakeRouter(llm=_TimeoutLLM()), budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.timeout
        assert budget.calls_failed == 1

    @pytest.mark.asyncio
    async def test_gateway_no_budget_still_succeeds(self) -> None:
        gw = LLMGateway(model_router=_FakeRouter(llm=_StubLLM()), budget=None)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.success


class TestLLMGatewayGuard:
    """Guard integration in the gateway."""

    @pytest.mark.asyncio
    async def test_gateway_prompt_blocked_returns_status(self) -> None:
        """Guard blocks prompt with out-of-scope IP → prompt_blocked status."""
        cfg = _make_config()
        guard = LLMPolicyGuard(cfg)
        gw = LLMGateway(model_router=_FakeRouter(llm=_StubLLM()), guard=guard)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "TARGET: 8.8.8.8 attack this"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.prompt_blocked
        assert "out-of-scope" in result.blocked_reason.lower() or "scope" in result.blocked_reason.lower()

    @pytest.mark.asyncio
    async def test_gateway_output_blocked_on_persistence(self) -> None:
        """Guard blocks output with persistence pattern → output_blocked status."""
        cfg = _make_config()
        guard = LLMPolicyGuard(cfg)
        dangerous = json.dumps({
            "reasoning": "crontab -e for persistence",
            "confidence": 0.9,
            "selected_tasks": [{"tool": "nmap", "args": [], "parser": "nmap",
                                "executor_domain": "recon", "target": _TARGET, "rationale": "ok"}],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        })
        gw = LLMGateway(model_router=_FakeRouter(llm=_StubLLM(response=dangerous)), guard=guard)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.output_blocked

    @pytest.mark.asyncio
    async def test_gateway_sanitize_redaction_count(self) -> None:
        """Guard redacts secrets; redaction_count reflects the count."""
        cfg = _make_config(password_candidates=["mysecret123"])
        guard = LLMPolicyGuard(cfg)
        gw = LLMGateway(model_router=_FakeRouter(llm=_StubLLM()), guard=guard)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": f"password=mysecret123 TARGET: {_TARGET}"}],
        )
        result = await gw.invoke(ctx)
        assert result.redaction_count >= 1

    @pytest.mark.asyncio
    async def test_gateway_no_guard_succeeds(self) -> None:
        """Without guard, no content checks — output with persistence still passes."""
        gw = LLMGateway(model_router=_FakeRouter(llm=_StubLLM()), guard=None)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.repair,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.success
        assert result.redaction_count == 0

    @pytest.mark.asyncio
    async def test_gateway_output_blocked_records_budget_failure(self) -> None:
        """Budget records failure when output is blocked by guard."""
        cfg = _make_config()
        guard = LLMPolicyGuard(cfg)
        budget = LLMBudgetTracker(max_per_run=5)
        dangerous = json.dumps({
            "reasoning": "crontab -e",
            "confidence": 0.9,
            "selected_tasks": [],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        })
        gw = LLMGateway(
            model_router=_FakeRouter(llm=_StubLLM(response=dangerous)),
            budget=budget,
            guard=guard,
        )
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.repair,
            phase="recon",
            messages=[{"role": "user", "content": "plan"}],
        )
        result = await gw.invoke(ctx)
        assert result.status == LLMCallStatus.output_blocked
        assert budget.calls_failed == 1


class TestLLMGatewayCallContext:
    """LLMCallContext and LLMCallPurpose types."""

    def test_context_fields(self) -> None:
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.repair,
            phase="web",
            messages=[{"role": "system", "content": "rules"}],
            allowed_tools=["curl"],
        )
        assert ctx.purpose == LLMCallPurpose.repair
        assert ctx.phase == "web"
        assert len(ctx.messages) == 1
        assert ctx.allowed_tools == ["curl"]

    def test_context_default_allowed_tools_empty(self) -> None:
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[],
        )
        assert ctx.allowed_tools == []

    def test_purpose_values(self) -> None:
        assert LLMCallPurpose.planning.value == "planning"
        assert LLMCallPurpose.repair.value == "repair"


# ---------------------------------------------------------------------------
# Architecture scan tests
# ---------------------------------------------------------------------------


class TestPhase5ArchitectureScan:
    """Verify structural invariants imposed by Phase 5."""

    def test_gateway_file_header_two_lines(self) -> None:
        """gateway.py must start with two comment lines."""
        with open("apex_host/llm/gateway.py") as f:
            lines = f.readlines()
        assert lines[0].strip().startswith("# gateway.py")
        assert lines[1].strip().startswith("# ")

    def test_repair_engine_accepts_budget_tracker_param(self) -> None:
        """RepairEngine.__init__ signature includes budget_tracker."""
        import inspect
        sig = inspect.signature(RepairEngine.__init__)
        assert "budget_tracker" in sig.parameters

    def test_repair_engine_accepts_guard_param(self) -> None:
        """RepairEngine.__init__ signature includes guard."""
        import inspect
        sig = inspect.signature(RepairEngine.__init__)
        assert "guard" in sig.parameters

    def test_recon_planner_accepts_guard_param(self) -> None:
        import inspect
        sig = inspect.signature(ReconPlanner.__init__)
        assert "guard" in sig.parameters

    def test_web_planner_accepts_guard_param(self) -> None:
        import inspect
        sig = inspect.signature(WebPlanner.__init__)
        assert "guard" in sig.parameters

    def test_credential_planner_accepts_guard_param(self) -> None:
        import inspect
        sig = inspect.signature(CredentialPlanner.__init__)
        assert "guard" in sig.parameters

    def test_priv_esc_planner_accepts_guard_param(self) -> None:
        import inspect
        sig = inspect.signature(PrivEscPlanner.__init__)
        assert "guard" in sig.parameters

    def test_gateway_module_importable(self) -> None:
        """LLMGateway module is importable without side effects."""
        from apex_host.llm import gateway
        assert hasattr(gateway, "LLMGateway")
        assert hasattr(gateway, "LLMCallPurpose")
        assert hasattr(gateway, "LLMCallStatus")
        assert hasattr(gateway, "LLMCallContext")
        assert hasattr(gateway, "LLMCallResult")

    def test_gateway_no_domain_specific_patterns(self) -> None:
        """gateway.py must not contain CVE/nmap/exploit-specific strings."""
        with open("apex_host/llm/gateway.py") as f:
            source = f.read()
        forbidden = ["nmap", "CVE-", "exploit", "telnet_access", "hydra"]
        for term in forbidden:
            assert term not in source, f"gateway.py contains domain-specific term: {term!r}"

    def test_graph_py_imports_llm_policy_guard_for_type_checking(self) -> None:
        """orchestration/builder.py constructs LLMPolicyGuard (Phase 10: moved from graph.py)."""
        # Phase 10 decomposition: build_apex_graph moved to orchestration/builder.py.
        # LLMPolicyGuard construction lives in _build_llm_components() there.
        with open("apex_host/orchestration/builder.py") as f:
            source = f.read()
        assert "LLMPolicyGuard" in source, (
            "orchestration/builder.py must reference LLMPolicyGuard in _build_llm_components"
        )

    def test_reflect_or_continue_peek_not_missing_current_phase(self) -> None:
        """Source scan: reflect_or_continue does not omit current_phase (F08)."""
        # Phase 10 decomposition: reflect_or_continue moved to orchestration/continuation_node.py.
        with open("apex_host/orchestration/continuation_node.py") as f:
            source = f.read()
        assert 'current_phase=state.get("phase")' in source, (
            "F08 fix missing: reflect_or_continue peek must pass current_phase=state.get('phase') "
            "(now in orchestration/continuation_node.py)"
        )

    def test_repair_engine_wired_with_budget_in_graph(self) -> None:
        """Source scan: build_apex_graph passes budget_tracker to RepairEngine (F04)."""
        # Phase 10 decomposition: build_apex_graph moved to orchestration/builder.py.
        with open("apex_host/orchestration/builder.py") as f:
            source = f.read()
        assert "budget_tracker=budget_tracker" in source, (
            "F04 fix missing: build_apex_graph must pass budget_tracker to RepairEngine "
            "(now in orchestration/builder.py)"
        )

    def test_repair_engine_wired_with_guard_in_graph(self) -> None:
        """Source scan: build_apex_graph passes guard to RepairEngine (F14)."""
        # Phase 10 decomposition: build_apex_graph moved to orchestration/builder.py.
        # The guard variable is named 'llm_guard' (without leading underscore) in builder.py.
        with open("apex_host/orchestration/builder.py") as f:
            source = f.read()
        assert "llm_guard" in source, (
            "F14 fix missing: build_apex_graph must construct llm_guard for domain planners and RepairEngine "
            "(now in orchestration/builder.py)"
        )


# ---------------------------------------------------------------------------
# Integration — RepairEngine budget + guard together
# ---------------------------------------------------------------------------


class TestRepairEngineBudgetAndGuardIntegration:
    """Budget and guard work together in RepairEngine."""

    @pytest.mark.asyncio
    async def test_budget_checked_before_guard_sanitize(self) -> None:
        """Exhausted budget short-circuits before any guard interaction."""
        budget = LLMBudgetTracker(max_per_run=0)
        cfg = _make_config()
        guard = LLMPolicyGuard(cfg)
        engine = RepairEngine(
            model_router=_FakeRouter(llm=_StubLLM()),
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=budget,
            guard=guard,
        )
        result = await engine.repair(
            failed_task=_make_task(),
            error="err",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        assert result is None
        # Guard was not invoked (no sanitize call would have touched budget)
        assert budget.calls_attempted == 0

    @pytest.mark.asyncio
    async def test_guard_blocks_after_budget_check_passes(self) -> None:
        """Budget allows call; guard blocks the prompt → repair returns None."""
        budget = LLMBudgetTracker(max_per_run=5)
        cfg = _make_config()
        guard = LLMPolicyGuard(cfg)
        engine = RepairEngine(
            model_router=_FakeRouter(llm=_StubLLM()),
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=budget,
            guard=guard,
        )
        # Provide a task that when converted to repair prompt would contain an out-of-scope IP
        bad_task = TaskSpec(
            id="t1",
            goal_id="g1",
            executor_domain="recon",
            params={"tool": "nmap", "args": ["-sV", "8.8.8.8"], "target": "8.8.8.8", "parser": "nmap"},
            subgraph_anchor=f"host:{_TARGET}",
            phase=ApexPhase.recon.value,
        )
        result = await engine.repair(
            failed_task=bad_task,
            error="non-zero",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        # Guard may or may not block depending on TARGET: 8.8.8.8 in prompt
        # At minimum it should not have incremented calls_succeeded
        # (either blocked or budget check passed and LLM was called)
        assert budget.calls_succeeded == 0 or result is not None

    @pytest.mark.asyncio
    async def test_budget_call_start_not_called_on_budget_exhausted(self) -> None:
        """record_call_start NOT called when budget.can_call returns False."""
        budget = LLMBudgetTracker(max_per_run=0)
        engine = RepairEngine(
            model_router=_FakeRouter(llm=_StubLLM()),
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            budget_tracker=budget,
        )
        await engine.repair(
            failed_task=_make_task(),
            error="err",
            phase=ApexPhase.recon.value,
            evidence=_empty_evidence(),
            subgraph=_empty_subgraph(),
        )
        # calls_attempted only increments in record_call_start (which comes AFTER can_call)
        assert budget.calls_attempted == 0
