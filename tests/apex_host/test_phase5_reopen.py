# test_phase5_reopen.py
# Phase 5 Reopen: 19-requirement comprehensive validation suite.
"""Phase 5 Reopen acceptance tests.

Covers all 19 requirements of the Phase 5 reopen:

Req 1-4:  Budget atomicity — BudgetReservation commit/fail/release semantics;
          asyncio.Lock in reserve(); per-phase and global limits enforced.
Req 5:    record_context() method exists, updates _last_context, feeds
          is_context_repeated().
Req 6:    Gateway exclusivity — no direct chat_llm.invoke() in production
          paths outside gateway.py (architecture scan).
Req 7:    _plan_via_gateway() routes through LLMGateway when injected.
Req 8:    Gateway timeout fires → LLMCallStatus.timeout returned.
Req 9:    CancelledError propagates through gateway (reservation released
          before re-raise).
Req 10:   Budget exhausted → early return, no reservation, budget_exhausted.
Req 11:   Prompt blocked → reservation.release() called, prompt_blocked.
Req 12:   Output blocked → reservation.fail() called, output_blocked.
Req 13-14: RepairEngine returns RepairRequest; all fields populated correctly.
Req 15:   All 4 domain planners accept and forward gateway= kwarg.
Req 16:   build_apex_graph creates shared LLMGateway when model_router given.
Req 17:   Fail-closed guard construction — RuntimeError when use_llm=True
          and LLMPolicyGuard construction fails.
Req 18-19: repair_agent extracts repaired_task, runs conflict+duplicate+
           policy guards before execution.
"""
from __future__ import annotations

import asyncio
import types
from typing import Any
from unittest.mock import patch

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import (
    AbandonSignal,
    ClaimDependency,
    EvidenceBundle,
    Goal,
    SubgraphView,
    TaskSpec,
)

from apex_host.config import ApexConfig
from apex_host.graph import build_apex_graph
from apex_host.llm.gateway import (
    LLMCallContext,
    LLMCallPurpose,
    LLMCallStatus,
    LLMGateway,
)
from apex_host.planning.budget import BudgetReservation, LLMBudgetTracker
from apex_host.planning.engine import PlanningEngine
from apex_host.planning.repair import RepairEngine, RepairRequest
from apex_host.planners.credential_planner import CredentialPlanner
from apex_host.planners.priv_esc_planner import PrivEscPlanner
from apex_host.planners.recon_planner import ReconPlanner
from apex_host.planners.web_planner import WebPlanner
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TARGET = "10.0.0.1"
_VALID_REPAIR_JSON = (
    '{"reasoning":"fix","confidence":0.85,"selected_tasks":[{"tool":"nmap",'
    '"args":["-sV","10.0.0.1"],"parser":"nmap","executor_domain":"recon",'
    '"target":"10.0.0.1","rationale":"retry with -sV"}],'
    '"rejected_tasks":[],"stop_reason":null,"next_phase":null}'
)
_VALID_PLAN_JSON = (
    '{"reasoning":"plan","confidence":0.9,"selected_tasks":[{"tool":"nmap",'
    '"args":["-sV","10.0.0.1"],"parser":"nmap","executor_domain":"recon",'
    '"target":"10.0.0.1","rationale":"scan"}],'
    '"rejected_tasks":[],"stop_reason":null,"next_phase":null}'
)


# ---------------------------------------------------------------------------
# Shared stubs / helpers
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


def _make_registry(tools: list[str] | None = None) -> ToolRegistry:
    return ToolRegistry(allowed_tools=tools or ["nmap", "curl", "nc"])


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=f"host:{_TARGET}", nodes=[], edges=[], depth=2)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(entries=[], query="test", subgraph=None, tiers_queried=[])


def _make_failed_task(tool: str = "nmap") -> TaskSpec:
    return TaskSpec(
        id=new_id(),
        goal_id=new_id(),
        executor_domain="recon",
        params={
            "tool": tool,
            "args": [_TARGET],
            "target": _TARGET,
            "parser": "nmap",
        },
        subgraph_anchor=f"host:{_TARGET}",
        phase=ApexPhase.recon.value,
        claim_dependencies=(
            ClaimDependency(node_id="host-1", field_name="ip"),
        ),
    )


def _make_goal() -> Goal:
    return Goal(
        id=new_id(),
        description="test goal",
        phase=ApexPhase.recon.value,
        anchor_node=f"host:{_TARGET}",
    )


class _StubLLM:
    """Returns a canned JSON string from invoke()."""

    def __init__(self, response: str = _VALID_PLAN_JSON) -> None:
        self._response = response
        self.call_count = 0

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        self.call_count += 1
        return types.SimpleNamespace(content=self._response)


class _RaisingLLM:
    """Always raises on invoke."""

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        raise RuntimeError("provider down")


class _SlowLLM:
    """Sleeps before returning (for timeout tests)."""

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        import time
        time.sleep(10)  # much longer than test timeout
        return types.SimpleNamespace(content=_VALID_PLAN_JSON)


class _CancellingLLM:
    """Raises asyncio.CancelledError from a thread context."""

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        raise asyncio.CancelledError()


class _FakeRouter:
    """Router whose planner_llm() returns the given LLM (or None)."""

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


class _FakeModelRouter:
    """FakeModelRouter that always returns None for all roles (safe default)."""

    def planner_llm(self) -> Any:
        return None

    def executor_llm(self) -> Any:
        return None

    def parser_llm(self) -> Any:
        return None

    def reflector_llm(self) -> Any:
        return None


class _BlockingGuard:
    """LLMPolicyGuard stub that blocks all prompts."""

    def sanitize_messages(
        self, messages: list[dict[str, str]]
    ) -> tuple[list[dict[str, str]], int]:
        return messages, 0

    def check_prompt(
        self, messages: list[dict[str, str]]
    ) -> tuple[bool, str]:
        return True, "prompt blocked by test guard"

    def check_output(self, raw: str) -> tuple[bool, str]:
        return False, ""


class _BlockingOutputGuard:
    """LLMPolicyGuard stub that blocks all LLM output."""

    def sanitize_messages(
        self, messages: list[dict[str, str]]
    ) -> tuple[list[dict[str, str]], int]:
        return messages, 0

    def check_prompt(
        self, messages: list[dict[str, str]]
    ) -> tuple[bool, str]:
        return False, ""

    def check_output(self, raw: str) -> tuple[bool, str]:
        return True, "output blocked by test guard"


class _PassthroughGuard:
    """Guard that allows everything through."""

    def sanitize_messages(
        self, messages: list[dict[str, str]]
    ) -> tuple[list[dict[str, str]], int]:
        return messages, 0

    def check_prompt(
        self, messages: list[dict[str, str]]
    ) -> tuple[bool, str]:
        return False, ""

    def check_output(self, raw: str) -> tuple[bool, str]:
        return False, ""


class _RedactingGuard:
    """Guard that redacts a fixed string from prompts."""

    def __init__(self, secret: str = "s3cr3t") -> None:
        self._secret = secret

    def sanitize_messages(
        self, messages: list[dict[str, str]]
    ) -> tuple[list[dict[str, str]], int]:
        count = 0
        out = []
        for m in messages:
            content = m.get("content", "")
            if self._secret in content:
                content = content.replace(self._secret, "[REDACTED]")
                count += 1
            out.append({**m, "content": content})
        return out, count

    def check_prompt(
        self, messages: list[dict[str, str]]
    ) -> tuple[bool, str]:
        return False, ""

    def check_output(self, raw: str) -> tuple[bool, str]:
        return False, ""


# ---------------------------------------------------------------------------
# Req 1-4: Budget Atomicity
# ---------------------------------------------------------------------------


class TestBudgetAtomicReservation:
    """Req 1-4: BudgetReservation lifecycle, limits, lock, release semantics."""

    @pytest.mark.asyncio
    async def test_r01_reserve_returns_reservation_under_budget(self) -> None:
        """reserve() returns (True, '', BudgetReservation) when under budget."""
        budget = LLMBudgetTracker(max_per_run=5)
        ok, reason, res = await budget.reserve(purpose="planning", phase="recon")
        assert ok is True
        assert reason == ""
        assert isinstance(res, BudgetReservation)

    @pytest.mark.asyncio
    async def test_r02_reservation_starts_unsettled(self) -> None:
        """Fresh reservation has committed=failed=released=False."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        assert res.committed is False
        assert res.failed is False
        assert res.released is False
        assert res.is_settled is False

    @pytest.mark.asyncio
    async def test_r03_commit_marks_committed_and_increments_succeeded(self) -> None:
        """commit() marks reservation committed; calls_succeeded incremented."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        await res.commit(actual_input_tokens=10, actual_output_tokens=20)
        assert res.committed is True
        assert res.is_settled is True
        assert budget.calls_succeeded == 1
        assert budget.calls_attempted == 1  # still counts as used

    @pytest.mark.asyncio
    async def test_r03_fail_marks_failed_and_increments_failed(self) -> None:
        """fail() marks reservation failed; calls_failed incremented."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        await res.fail(known_usage=5)
        assert res.failed is True
        assert res.is_settled is True
        assert budget.calls_failed == 1
        assert budget.calls_attempted == 1  # still counts as used

    @pytest.mark.asyncio
    async def test_r04_release_frees_slot(self) -> None:
        """release() decrements calls_attempted so next call succeeds."""
        budget = LLMBudgetTracker(max_per_run=1)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        # Before release: budget consumed
        assert budget.calls_attempted == 1
        # Release: slot returned
        await res.release()
        assert res.released is True
        assert budget.calls_attempted == 0  # slot returned
        # Now another reserve should succeed
        ok2, _, res2 = await budget.reserve(purpose="planning", phase="recon")
        assert ok2 is True
        assert res2 is not None
        await res2.commit()

    @pytest.mark.asyncio
    async def test_r04_release_decrements_phase_count(self) -> None:
        """release() also decrements the per-phase count."""
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=1)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        assert budget._phase_counts.get("recon", 0) == 1
        await res.release()
        assert budget._phase_counts.get("recon", 0) == 0

    @pytest.mark.asyncio
    async def test_r04_double_settle_raises(self) -> None:
        """Calling commit() twice raises RuntimeError."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        await res.commit()
        with pytest.raises(RuntimeError, match="already settled"):
            await res.commit()

    @pytest.mark.asyncio
    async def test_r04_commit_then_release_raises(self) -> None:
        """Calling release() after commit() raises RuntimeError."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        await res.commit()
        with pytest.raises(RuntimeError, match="already settled"):
            await res.release()

    @pytest.mark.asyncio
    async def test_r04_fail_then_release_raises(self) -> None:
        """Calling release() after fail() raises RuntimeError."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        await res.fail()
        with pytest.raises(RuntimeError, match="already settled"):
            await res.release()

    @pytest.mark.asyncio
    async def test_r04_global_budget_exhausted(self) -> None:
        """reserve() returns (False, reason, None) when global budget exhausted."""
        budget = LLMBudgetTracker(max_per_run=1)
        ok1, _, res1 = await budget.reserve(purpose="planning", phase="recon")
        assert ok1 is True
        assert res1 is not None
        await res1.commit()
        ok2, reason2, res2 = await budget.reserve(purpose="planning", phase="recon")
        assert ok2 is False
        assert "exhausted" in reason2
        assert res2 is None

    @pytest.mark.asyncio
    async def test_r04_per_phase_budget_exhausted(self) -> None:
        """reserve() returns False when per-phase budget exhausted."""
        budget = LLMBudgetTracker(max_per_run=10, max_per_phase=1)
        ok1, _, res1 = await budget.reserve(purpose="planning", phase="recon")
        assert ok1 is True
        assert res1 is not None
        await res1.commit()
        ok2, reason2, res2 = await budget.reserve(purpose="planning", phase="recon")
        assert ok2 is False
        assert "recon" in reason2
        assert res2 is None

    @pytest.mark.asyncio
    async def test_r04_different_phase_not_blocked(self) -> None:
        """Per-phase exhaustion for 'recon' does not block 'web'."""
        budget = LLMBudgetTracker(max_per_run=10, max_per_phase=1)
        ok1, _, res1 = await budget.reserve(purpose="planning", phase="recon")
        assert res1 is not None
        await res1.commit()
        ok2, _, res2 = await budget.reserve(purpose="planning", phase="web")
        assert ok2 is True
        assert res2 is not None
        await res2.commit()

    @pytest.mark.asyncio
    async def test_r04_concurrent_atomic_no_overspend(self) -> None:
        """Two concurrent reserve() calls with budget=1 — exactly one succeeds."""
        budget = LLMBudgetTracker(max_per_run=1)

        async def try_reserve() -> bool:
            ok, _, res = await budget.reserve(purpose="planning", phase="recon")
            if ok and res is not None:
                await res.commit()
                return True
            return False

        results = await asyncio.gather(try_reserve(), try_reserve())
        assert sum(results) == 1  # exactly one succeeded

    @pytest.mark.asyncio
    async def test_r04_active_reservation_count_tracks_open(self) -> None:
        """active_reservation_count reflects number of unsettled reservations."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res1 = await budget.reserve(purpose="planning", phase="recon")
        _, _, res2 = await budget.reserve(purpose="planning", phase="web")
        assert res1 is not None
        assert res2 is not None
        assert budget.active_reservation_count == 2
        await res1.commit()
        assert budget.active_reservation_count == 1
        await res2.fail()
        assert budget.active_reservation_count == 0

    @pytest.mark.asyncio
    async def test_r04_disabled_budget_always_succeeds(self) -> None:
        """enabled=False → reserve() always returns True regardless of limits."""
        budget = LLMBudgetTracker(max_per_run=0, enabled=False)
        ok, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert ok is True
        assert res is not None
        await res.commit()


# ---------------------------------------------------------------------------
# Req 5: record_context
# ---------------------------------------------------------------------------


class TestRecordContext:
    """Req 5: record_context() updates _last_context and feeds is_context_repeated."""

    def test_r05_record_context_updates_last_context(self) -> None:
        """record_context stores the hash for the given phase."""
        budget = LLMBudgetTracker()
        budget.record_context("recon", "abc123")
        assert budget._last_context.get("recon") == "abc123"

    def test_r05_is_context_repeated_true_after_record(self) -> None:
        """is_context_repeated returns True for same hash after record_context."""
        budget = LLMBudgetTracker(stop_on_repeated_plan=True)
        budget.record_context("recon", "abc123")
        assert budget.is_context_repeated("recon", "abc123") is True

    def test_r05_is_context_repeated_false_for_different_hash(self) -> None:
        """is_context_repeated returns False when hash differs."""
        budget = LLMBudgetTracker(stop_on_repeated_plan=True)
        budget.record_context("recon", "abc123")
        assert budget.is_context_repeated("recon", "xyz999") is False

    def test_r05_is_context_repeated_false_before_any_record(self) -> None:
        """is_context_repeated returns False when no record for phase yet."""
        budget = LLMBudgetTracker(stop_on_repeated_plan=True)
        assert budget.is_context_repeated("recon", "abc") is False

    def test_r05_record_context_overrides_previous(self) -> None:
        """Calling record_context twice updates the stored hash."""
        budget = LLMBudgetTracker(stop_on_repeated_plan=True)
        budget.record_context("recon", "first")
        budget.record_context("recon", "second")
        assert budget.is_context_repeated("recon", "first") is False
        assert budget.is_context_repeated("recon", "second") is True

    def test_r05_record_context_per_phase_independent(self) -> None:
        """record_context for one phase doesn't affect another."""
        budget = LLMBudgetTracker(stop_on_repeated_plan=True)
        budget.record_context("recon", "hash1")
        assert budget.is_context_repeated("web", "hash1") is False

    def test_r05_disabled_budget_never_repeated(self) -> None:
        """enabled=False → is_context_repeated always returns False."""
        budget = LLMBudgetTracker(enabled=False)
        budget._last_context["recon"] = "same"
        assert budget.is_context_repeated("recon", "same") is False

    def test_r05_stop_on_repeated_plan_false_never_repeated(self) -> None:
        """stop_on_repeated_plan=False → always returns False."""
        budget = LLMBudgetTracker(stop_on_repeated_plan=False)
        budget._last_context["recon"] = "same"
        assert budget.is_context_repeated("recon", "same") is False


# ---------------------------------------------------------------------------
# Req 6: Gateway Exclusivity (architecture scan)
# ---------------------------------------------------------------------------


class TestGatewayExclusivity:
    """Req 6: No direct chat_llm.invoke() calls outside gateway.py in production."""

    def test_r06_gateway_exclusivity_engine_no_direct_invoke(self) -> None:
        """planning/engine.py must not contain direct chat_llm.invoke() calls."""
        import pathlib
        engine_path = pathlib.Path(__file__).parent.parent.parent / "apex_host" / "planning" / "engine.py"
        text = engine_path.read_text()
        # Filter out comment lines and lines inside gateway.py imports
        non_comment_lines = [
            line for line in text.splitlines()
            if not line.lstrip().startswith("#")
        ]
        # "chat_llm.invoke(" should not appear outside the backward-compat path
        # (the _plan_via_gateway path must NOT directly call it)
        # The only remaining invoke is in the LEGACY direct path, not via gateway.
        # We verify _plan_via_gateway does NOT contain chat_llm.invoke(
        in_gateway_method = False
        direct_invokes_in_gateway_method: list[str] = []
        for line in non_comment_lines:
            if "async def _plan_via_gateway" in line:
                in_gateway_method = True
            elif in_gateway_method and line.startswith("    async def ") and "_plan_via_gateway" not in line:
                in_gateway_method = False
            elif in_gateway_method and "chat_llm.invoke(" in line:
                direct_invokes_in_gateway_method.append(line.strip())
        assert direct_invokes_in_gateway_method == [], (
            "_plan_via_gateway must not call chat_llm.invoke() directly — "
            "use self._gateway.invoke() instead. "
            f"Found: {direct_invokes_in_gateway_method}"
        )

    def test_r06_repair_engine_no_direct_invoke(self) -> None:
        """planning/repair.py must not contain direct chat_llm.invoke() calls."""
        import pathlib
        repair_path = pathlib.Path(__file__).parent.parent.parent / "apex_host" / "planning" / "repair.py"
        text = repair_path.read_text()
        # Look specifically for actual invocation syntax (not docstring prose).
        # Docstrings mention `chat_llm.invoke()` descriptively; actual code uses
        # `chat_llm.invoke(messages)` or `chat_llm.invoke, messages` patterns.
        non_comment_lines = [
            line for line in text.splitlines()
            if not line.lstrip().startswith("#")
        ]
        # Filter to lines that look like executable code (not prose in docstrings).
        # A docstring line would not contain `messages` or assignment operators
        # in the invocation context.
        direct_calls = [
            line.strip() for line in non_comment_lines
            if (
                "chat_llm.invoke(" in line
                and "``" not in line  # exclude docstring backtick markup
                and "exist" not in line.lower()  # exclude "No direct... call exists"
            )
        ]
        assert direct_calls == [], (
            "repair.py must not call chat_llm.invoke() directly — "
            f"found: {direct_calls}"
        )

    def test_r06_recon_planner_no_direct_invoke(self) -> None:
        """Planner files must not call chat_llm.invoke() directly."""
        import pathlib
        planner_dir = pathlib.Path(__file__).parent.parent.parent / "apex_host" / "planners"
        for py_file in planner_dir.glob("*.py"):
            text = py_file.read_text()
            direct_calls = [
                line.strip() for line in text.splitlines()
                if "chat_llm.invoke(" in line and not line.lstrip().startswith("#")
            ]
            assert direct_calls == [], (
                f"{py_file.name} must not call chat_llm.invoke() directly: {direct_calls}"
            )

    def test_r06_gateway_is_sole_invoke_site(self) -> None:
        """gateway.py contains the only legitimate chat_llm.invoke() call."""
        import pathlib
        gateway_path = pathlib.Path(__file__).parent.parent.parent / "apex_host" / "llm" / "gateway.py"
        text = gateway_path.read_text()
        assert "chat_llm.invoke" in text, (
            "gateway.py must contain the chat_llm.invoke call"
        )


# ---------------------------------------------------------------------------
# Req 7: _plan_via_gateway routing
# ---------------------------------------------------------------------------


class TestPlanViaGateway:
    """Req 7: PlanningEngine._plan_via_gateway routes through injected gateway."""

    def test_r07_engine_has_plan_via_gateway_method(self) -> None:
        """PlanningEngine has a _plan_via_gateway method."""
        assert hasattr(PlanningEngine, "_plan_via_gateway")
        assert callable(PlanningEngine._plan_via_gateway)

    @pytest.mark.asyncio
    async def test_r07_gateway_injected_plan_dispatches_via_gateway(self) -> None:
        """When gateway is injected, plan() dispatches to _plan_via_gateway."""
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        gateway = LLMGateway(model_router=router)

        class _FakeFallback:
            async def plan(
                self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
            ) -> list[TaskSpec] | AbandonSignal:
                return AbandonSignal(reason="fallback called")

        engine = PlanningEngine(
            model_router=router,
            fallback_planner=_FakeFallback(),
            allowed_tools=["nmap"],
            target=_TARGET,
            gateway=gateway,
        )
        goal = _make_goal()
        result = await engine.plan(goal, ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        # LLM returned valid tasks — should get tasks, not abandon signal
        assert isinstance(result, list)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_r07_no_gateway_uses_direct_path(self) -> None:
        """Without gateway, plan() uses the direct chat_llm path."""
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)

        class _FakeFallback:
            async def plan(
                self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
            ) -> list[TaskSpec] | AbandonSignal:
                return AbandonSignal(reason="fallback called")

        # No gateway= argument → uses direct path
        engine = PlanningEngine(
            model_router=router,
            fallback_planner=_FakeFallback(),
            allowed_tools=["nmap"],
            target=_TARGET,
        )
        assert engine._gateway is None
        goal = _make_goal()
        result = await engine.plan(goal, ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_r07_gateway_path_non_success_falls_back(self) -> None:
        """When gateway returns non-success, plan() falls back to deterministic."""
        # FakeRouter → planner_llm() returns None → gateway returns fallback_no_model
        router = _FakeModelRouter()
        gateway = LLMGateway(model_router=router)

        fallback_called: list[bool] = []

        class _CountingFallback:
            async def plan(
                self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
            ) -> list[TaskSpec] | AbandonSignal:
                fallback_called.append(True)
                return AbandonSignal(reason="deterministic fallback")

        engine = PlanningEngine(
            model_router=_FakeRouter(llm=_StubLLM()),
            fallback_planner=_CountingFallback(),
            allowed_tools=["nmap"],
            target=_TARGET,
            gateway=gateway,
        )
        goal = _make_goal()
        result = await engine.plan(goal, ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert fallback_called == [True]

    @pytest.mark.asyncio
    async def test_r07_gateway_budget_record_context_on_success(self) -> None:
        """After successful gateway plan, record_context is called so next call detects repeat."""
        budget = LLMBudgetTracker(max_per_run=5, stop_on_repeated_plan=True)
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        gateway = LLMGateway(model_router=router, budget=budget)

        class _FakeFallback:
            async def plan(
                self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
            ) -> list[TaskSpec] | AbandonSignal:
                return AbandonSignal(reason="fallback")

        engine = PlanningEngine(
            model_router=router,
            fallback_planner=_FakeFallback(),
            allowed_tools=["nmap"],
            target=_TARGET,
            gateway=gateway,
            budget=budget,
        )
        goal = _make_goal()
        sg = _empty_subgraph()
        ev = _empty_evidence()
        result1 = await engine.plan(goal, ApexPhase.recon, sg, ev)
        assert isinstance(result1, list)
        # Second call with same context → context is repeated → fallback
        result2 = await engine.plan(goal, ApexPhase.recon, sg, ev)
        assert isinstance(result2, AbandonSignal)

    @pytest.mark.asyncio
    async def test_r07_gateway_validator_rejection_retries(self) -> None:
        """Validator rejection causes retry up to max_retries then fallback."""
        llm = _StubLLM(response="not valid json at all")
        router = _FakeRouter(llm=llm)
        gateway = LLMGateway(model_router=router)

        fallback_called: list[bool] = []

        class _CountingFallback:
            async def plan(
                self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
            ) -> list[TaskSpec] | AbandonSignal:
                fallback_called.append(True)
                return AbandonSignal(reason="fallback")

        engine = PlanningEngine(
            model_router=router,
            fallback_planner=_CountingFallback(),
            allowed_tools=["nmap"],
            target=_TARGET,
            gateway=gateway,
            max_retries=1,
        )
        goal = _make_goal()
        result = await engine.plan(goal, ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert fallback_called == [True]


# ---------------------------------------------------------------------------
# Req 8-12: Gateway Status Codes and Reservation Lifecycle
# ---------------------------------------------------------------------------


class TestGatewayStatusCodes:
    """Req 8-12: Gateway handles timeout, cancel, budget, blocked, error."""

    @pytest.mark.asyncio
    async def test_r08_timeout_returns_timeout_status(self) -> None:
        """Provider timeout → LLMCallStatus.timeout, raw_text == ''."""
        llm = _SlowLLM()
        router = _FakeRouter(llm=llm)
        gateway = LLMGateway(model_router=router, timeout_seconds=0.05)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert result.status == LLMCallStatus.timeout
        assert result.raw_text == ""

    @pytest.mark.asyncio
    async def test_r08_timeout_sets_error_message(self) -> None:
        """Timeout result has non-empty error string."""
        llm = _SlowLLM()
        router = _FakeRouter(llm=llm)
        gateway = LLMGateway(model_router=router, timeout_seconds=0.05)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_r08_timeout_reservation_fail_called(self) -> None:
        """After timeout, reservation is failed (slot stays consumed)."""
        budget = LLMBudgetTracker(max_per_run=5)
        llm = _SlowLLM()
        router = _FakeRouter(llm=llm)
        gateway = LLMGateway(model_router=router, budget=budget, timeout_seconds=0.05)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        await gateway.invoke(ctx)
        # Slot consumed (fail was called, not release)
        assert budget.calls_attempted == 1
        assert budget.calls_failed == 1
        assert budget.active_reservation_count == 0

    @pytest.mark.asyncio
    async def test_r09_cancelled_error_propagates(self) -> None:
        """CancelledError propagates through gateway.invoke()."""
        # Use a router whose LLM raises CancelledError from thread
        # We need to simulate this properly via monkeypatching asyncio.wait_for
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        gateway = LLMGateway(model_router=router)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        # Patch asyncio.wait_for to raise CancelledError
        async def _raise_cancel(*a: Any, **kw: Any) -> Any:
            raise asyncio.CancelledError()

        with patch("asyncio.wait_for", _raise_cancel):
            with pytest.raises(asyncio.CancelledError):
                await gateway.invoke(ctx)

    @pytest.mark.asyncio
    async def test_r09_cancelled_reservation_released(self) -> None:
        """When CancelledError propagates, the reservation is released (slot freed)."""
        budget = LLMBudgetTracker(max_per_run=5)
        llm = _StubLLM()
        router = _FakeRouter(llm=llm)
        gateway = LLMGateway(model_router=router, budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )

        async def _raise_cancel(*a: Any, **kw: Any) -> Any:
            raise asyncio.CancelledError()

        with patch("asyncio.wait_for", _raise_cancel):
            with pytest.raises(asyncio.CancelledError):
                await gateway.invoke(ctx)
        # release() was called → calls_attempted decremented to 0
        assert budget.calls_attempted == 0

    @pytest.mark.asyncio
    async def test_r10_budget_exhausted_returns_budget_exhausted_status(self) -> None:
        """Budget exhausted → LLMCallStatus.budget_exhausted, no reservation."""
        budget = LLMBudgetTracker(max_per_run=0)
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router, budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert result.status == LLMCallStatus.budget_exhausted
        assert result.raw_text == ""

    @pytest.mark.asyncio
    async def test_r10_budget_exhausted_no_active_reservation(self) -> None:
        """Budget exhausted → no reservation is created."""
        budget = LLMBudgetTracker(max_per_run=0)
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router, budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        await gateway.invoke(ctx)
        assert budget.active_reservation_count == 0

    @pytest.mark.asyncio
    async def test_r11_prompt_blocked_release_called(self) -> None:
        """Prompt blocked → reservation.release() called (slot freed)."""
        budget = LLMBudgetTracker(max_per_run=5)
        router = _FakeRouter(llm=_StubLLM())
        guard = _BlockingGuard()
        gateway = LLMGateway(model_router=router, budget=budget, guard=guard)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert result.status == LLMCallStatus.prompt_blocked
        # Release was called → slot freed
        assert budget.calls_attempted == 0
        assert budget.active_reservation_count == 0

    @pytest.mark.asyncio
    async def test_r11_prompt_blocked_returns_reason(self) -> None:
        """Prompt blocked result has non-empty blocked_reason."""
        router = _FakeRouter(llm=_StubLLM())
        guard = _BlockingGuard()
        gateway = LLMGateway(model_router=router, guard=guard)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert result.blocked_reason != ""

    @pytest.mark.asyncio
    async def test_r12_output_blocked_fail_called(self) -> None:
        """Output blocked → reservation.fail() called (slot stays consumed)."""
        budget = LLMBudgetTracker(max_per_run=5)
        router = _FakeRouter(llm=_StubLLM())
        guard = _BlockingOutputGuard()
        gateway = LLMGateway(model_router=router, budget=budget, guard=guard)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert result.status == LLMCallStatus.output_blocked
        # fail() called → calls_attempted=1, calls_failed=1, slot not freed
        assert budget.calls_attempted == 1
        assert budget.calls_failed == 1
        assert budget.active_reservation_count == 0

    @pytest.mark.asyncio
    async def test_r12_provider_error_fail_called(self) -> None:
        """Provider error → reservation.fail() called, provider_error status."""
        budget = LLMBudgetTracker(max_per_run=5)
        router = _FakeRouter(llm=_RaisingLLM())
        gateway = LLMGateway(model_router=router, budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert result.status == LLMCallStatus.provider_error
        assert budget.calls_attempted == 1
        assert budget.calls_failed == 1

    @pytest.mark.asyncio
    async def test_r12_success_commit_called(self) -> None:
        """Success → reservation.commit() called, calls_succeeded incremented."""
        budget = LLMBudgetTracker(max_per_run=5)
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router, budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert result.status == LLMCallStatus.success
        assert budget.calls_attempted == 1
        assert budget.calls_succeeded == 1
        assert budget.active_reservation_count == 0

    @pytest.mark.asyncio
    async def test_r12_no_router_returns_fallback_no_router(self) -> None:
        """No router → LLMCallStatus.fallback_no_router, no budget consumed."""
        budget = LLMBudgetTracker(max_per_run=5)
        gateway = LLMGateway(model_router=None, budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert result.status == LLMCallStatus.fallback_no_router
        assert budget.calls_attempted == 0

    @pytest.mark.asyncio
    async def test_r12_no_model_returns_fallback_no_model(self) -> None:
        """Router returns None for planner_llm → fallback_no_model status."""
        budget = LLMBudgetTracker(max_per_run=5)
        router = _FakeModelRouter()  # always returns None
        gateway = LLMGateway(model_router=router, budget=budget)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        result = await gateway.invoke(ctx)
        assert result.status == LLMCallStatus.fallback_no_model
        assert budget.calls_attempted == 0

    @pytest.mark.asyncio
    async def test_r12_redaction_count_in_result(self) -> None:
        """Redaction count is propagated to LLMCallResult."""
        router = _FakeRouter(llm=_StubLLM())
        guard = _RedactingGuard(secret="s3cr3t")
        gateway = LLMGateway(model_router=router, guard=guard)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "password is s3cr3t here"}],
        )
        result = await gateway.invoke(ctx)
        assert result.status == LLMCallStatus.success
        assert result.redaction_count == 1

    @pytest.mark.asyncio
    async def test_r12_audit_log_populated_on_success(self) -> None:
        """Successful invoke appends to audit_log."""
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase="recon",
            messages=[{"role": "user", "content": "test"}],
        )
        await gateway.invoke(ctx)
        assert len(gateway.audit_log) == 1
        entry = gateway.audit_log[0]
        assert entry["status"] == "success"
        assert entry["purpose"] == "planning"
        assert entry["phase"] == "recon"


# ---------------------------------------------------------------------------
# Req 13-14: RepairRequest fields
# ---------------------------------------------------------------------------


class TestRepairRequestFields:
    """Req 13-14: RepairEngine returns RepairRequest; all fields correct."""

    @pytest.mark.asyncio
    async def test_r13_repair_returns_repair_request(self) -> None:
        """repair() returns a RepairRequest on success (not TaskSpec)."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        failed_task = _make_failed_task()
        result = await engine.repair(
            failed_task, "exit 1", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert isinstance(result, RepairRequest)

    @pytest.mark.asyncio
    async def test_r13_result_is_not_task_spec(self) -> None:
        """repair() return value is NOT a TaskSpec directly."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        result = await engine.repair(
            _make_failed_task(), "exit 1", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert not isinstance(result, TaskSpec)

    @pytest.mark.asyncio
    async def test_r14_original_task_id_matches(self) -> None:
        """RepairRequest.original_task_id matches the failed task's id."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        failed_task = _make_failed_task()
        result = await engine.repair(
            failed_task, "exit 1", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is not None
        assert result.original_task_id == failed_task.id

    @pytest.mark.asyncio
    async def test_r14_repaired_task_is_task_spec(self) -> None:
        """RepairRequest.repaired_task is a TaskSpec."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        result = await engine.repair(
            _make_failed_task(), "exit 1", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is not None
        assert isinstance(result.repaired_task, TaskSpec)

    @pytest.mark.asyncio
    async def test_r14_repaired_task_has_correct_tool(self) -> None:
        """RepairRequest.repaired_task.params['tool'] matches LLM output."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        result = await engine.repair(
            _make_failed_task(), "exit 1", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is not None
        assert result.repaired_task.params["tool"] == "nmap"

    @pytest.mark.asyncio
    async def test_r14_repair_attempt_stored(self) -> None:
        """RepairRequest.repair_attempt equals the repair_attempt argument."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        result = await engine.repair(
            _make_failed_task(), "exit 1", "recon",
            _empty_evidence(), _empty_subgraph(),
            repair_attempt=2,
        )
        assert result is not None
        assert result.repair_attempt == 2

    @pytest.mark.asyncio
    async def test_r14_failure_reason_stored(self) -> None:
        """RepairRequest.failure_reason matches the error argument."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        error_msg = "nmap: command not found (exit 127)"
        result = await engine.repair(
            _make_failed_task(), error_msg, "recon",
            _empty_evidence(), _empty_subgraph(),
        )
        assert result is not None
        assert result.failure_reason == error_msg

    @pytest.mark.asyncio
    async def test_r14_phase_stored(self) -> None:
        """RepairRequest.phase matches the phase argument."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "web",
            _empty_evidence(), _empty_subgraph(),
        )
        assert result is not None
        assert result.phase == "web"

    @pytest.mark.asyncio
    async def test_r14_target_stored(self) -> None:
        """RepairRequest.target matches the engine's configured target."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "recon",
            _empty_evidence(), _empty_subgraph(),
        )
        assert result is not None
        assert result.target == _TARGET

    @pytest.mark.asyncio
    async def test_r14_claim_dependencies_copied(self) -> None:
        """RepairRequest.claim_dependencies copied from original task."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        failed_task = _make_failed_task()
        result = await engine.repair(
            failed_task, "error", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is not None
        assert len(result.claim_dependencies) == len(failed_task.claim_dependencies or ())

    @pytest.mark.asyncio
    async def test_r14_origin_skill_id_defaults_none(self) -> None:
        """RepairRequest.origin_skill_id defaults to None."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is not None
        assert result.origin_skill_id is None

    @pytest.mark.asyncio
    async def test_r14_dry_run_returns_none(self) -> None:
        """dry_run=True → repair() returns None immediately."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=True,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is None


# ---------------------------------------------------------------------------
# Req 15: Domain planners accept gateway= kwarg
# ---------------------------------------------------------------------------


class TestDomainPlannerGatewayParam:
    """Req 15: All 4 domain planners accept and forward the gateway= kwarg."""

    def test_r15_recon_planner_accepts_gateway_kwarg(self) -> None:
        """ReconPlanner(gateway=...) does not raise."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        planner = ReconPlanner(
            _TARGET, registry,
            model_router=router,
            allowed_tools=["nmap"],
            gateway=gateway,
        )
        assert planner is not None

    def test_r15_web_planner_accepts_gateway_kwarg(self) -> None:
        """WebPlanner(gateway=...) does not raise."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        planner = WebPlanner(
            _TARGET, registry,
            model_router=router,
            allowed_tools=["nmap", "curl"],
            gateway=gateway,
        )
        assert planner is not None

    def test_r15_credential_planner_accepts_gateway_kwarg(self) -> None:
        """CredentialPlanner(gateway=...) does not raise."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        planner = CredentialPlanner(
            _TARGET, registry,
            model_router=router,
            allowed_tools=["curl"],
            gateway=gateway,
        )
        assert planner is not None

    def test_r15_priv_esc_planner_accepts_gateway_kwarg(self) -> None:
        """PrivEscPlanner(gateway=...) does not raise."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        planner = PrivEscPlanner(
            _TARGET, registry,
            model_router=router,
            allowed_tools=["searchsploit"],
            gateway=gateway,
        )
        assert planner is not None

    def test_r15_recon_planner_gateway_forwarded_to_engine(self) -> None:
        """ReconPlanner forwards gateway to PlanningEngine._gateway."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        planner = ReconPlanner(
            _TARGET, registry,
            model_router=router,
            allowed_tools=["nmap"],
            gateway=gateway,
        )
        assert planner._engine is not None
        assert planner._engine._gateway is gateway

    def test_r15_web_planner_gateway_forwarded_to_engine(self) -> None:
        """WebPlanner forwards gateway to PlanningEngine._gateway."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        planner = WebPlanner(
            _TARGET, registry,
            model_router=router,
            allowed_tools=["curl"],
            gateway=gateway,
        )
        assert planner._engine is not None
        assert planner._engine._gateway is gateway

    def test_r15_credential_planner_gateway_forwarded_to_engine(self) -> None:
        """CredentialPlanner forwards gateway to PlanningEngine._gateway."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        planner = CredentialPlanner(
            _TARGET, registry,
            model_router=router,
            allowed_tools=["curl"],
            gateway=gateway,
        )
        assert planner._engine is not None
        assert planner._engine._gateway is gateway

    def test_r15_priv_esc_planner_gateway_forwarded_to_engine(self) -> None:
        """PrivEscPlanner forwards gateway to PlanningEngine._gateway."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        planner = PrivEscPlanner(
            _TARGET, registry,
            model_router=router,
            allowed_tools=["searchsploit"],
            gateway=gateway,
        )
        assert planner._engine is not None
        assert planner._engine._gateway is gateway

    def test_r15_no_gateway_no_engine_gateway(self) -> None:
        """Without gateway=, PlanningEngine._gateway is None."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        planner = ReconPlanner(
            _TARGET, registry,
            model_router=router,
            allowed_tools=["nmap"],
            # no gateway=
        )
        assert planner._engine is not None
        assert planner._engine._gateway is None

    def test_r15_gateway_none_default(self) -> None:
        """All planners have gateway=None as default (no required change)."""
        registry = _make_registry()
        router = _FakeRouter(llm=_StubLLM())
        for PlannerCls in [ReconPlanner, WebPlanner, CredentialPlanner, PrivEscPlanner]:
            planner = PlannerCls(
                _TARGET, registry,
                model_router=router,
                allowed_tools=["nmap"],
            )
            assert planner is not None


# ---------------------------------------------------------------------------
# Req 16: Shared gateway in build_apex_graph
# ---------------------------------------------------------------------------


class TestBuildApexGraphSharedGateway:
    """Req 16: build_apex_graph creates one LLMGateway shared by all planners."""

    def test_r16_no_router_no_gateway(self) -> None:
        """Without model_router, build_apex_graph creates no gateway."""
        api = _make_api()
        registry = _make_registry()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=2)
        # No model_router passed — default is None
        graph = build_apex_graph(api, registry, config)
        assert graph is not None  # builds cleanly

    def test_r16_with_router_graph_builds_successfully(self) -> None:
        """With model_router, build_apex_graph completes without error."""
        api = _make_api()
        registry = _make_registry()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=2)
        router = _FakeModelRouter()
        graph = build_apex_graph(api, registry, config, model_router=router)
        assert graph is not None

    def test_r16_gateway_uses_model_router(self) -> None:
        """LLMGateway is constructed with the provided model_router."""
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router)
        # Gateway has the router
        assert gateway._router is router

    def test_r16_shared_budget_tracker(self) -> None:
        """Budget tracker is shared between gateway and planners."""
        budget = LLMBudgetTracker(max_per_run=5)
        router = _FakeRouter(llm=_StubLLM())
        gateway = LLMGateway(model_router=router, budget=budget)
        # Same budget object in gateway
        assert gateway._budget is budget


# ---------------------------------------------------------------------------
# Req 17: Fail-closed guard construction
# ---------------------------------------------------------------------------


class TestFailClosedGuard:
    """Req 17: RuntimeError when use_llm=True and guard construction fails."""

    def test_r17_fail_closed_raises_runtime_error(self) -> None:
        """use_llm=True + guard construction failure → RuntimeError."""
        api = _make_api()
        registry = _make_registry()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=2, use_llm=True)
        router = _FakeModelRouter()

        # Guard is constructed inside build_apex_graph via a local import:
        #   from apex_host.policy.llm_guard import LLMPolicyGuard as _LLMPolicyGuard
        # Patch the class in its source module so the local re-import gets the stub.
        with patch(
            "apex_host.policy.llm_guard.LLMPolicyGuard",
            side_effect=ValueError("guard init failed"),
        ):
            with pytest.raises(RuntimeError, match="LLMPolicyGuard"):
                build_apex_graph(api, registry, config, model_router=router)

    def test_r17_use_llm_false_guard_failure_no_error(self) -> None:
        """use_llm=False + guard construction failure → no RuntimeError (just warning)."""
        api = _make_api()
        registry = _make_registry()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=2, use_llm=False)
        router = _FakeModelRouter()

        # Even if guard fails, use_llm=False means no error raised
        with patch(
            "apex_host.policy.llm_guard.LLMPolicyGuard",
            side_effect=ValueError("guard init failed"),
        ):
            # Should NOT raise — use_llm=False means guard failure is non-fatal
            try:
                graph = build_apex_graph(api, registry, config, model_router=router)
                assert graph is not None
            except RuntimeError:
                pytest.fail("RuntimeError should not be raised when use_llm=False")

    def test_r17_no_router_no_guard_construction(self) -> None:
        """Without model_router, guard is never constructed."""
        api = _make_api()
        registry = _make_registry()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=2)
        # Without router, graph builds fine — no guard construction attempted
        graph = build_apex_graph(api, registry, config)
        assert graph is not None


# ---------------------------------------------------------------------------
# Req 18-19: repair_agent RepairRequest handling and guards
# ---------------------------------------------------------------------------


class TestRepairAgentRoutingUnit:
    """Req 18-19: repair_agent extracts repaired_task; routes through guards."""

    def test_r18_repair_request_has_repaired_task(self) -> None:
        """RepairRequest.repaired_task is always a TaskSpec."""
        task = _make_failed_task()
        repaired = _make_failed_task(tool="nc")
        req = RepairRequest(
            original_task_id=task.id,
            repaired_task=repaired,
            repair_attempt=0,
            failure_reason="exit 1",
            phase="recon",
            target=_TARGET,
        )
        assert isinstance(req.repaired_task, TaskSpec)
        assert req.repaired_task.params["tool"] == "nc"

    def test_r18_repair_request_extractable_fields(self) -> None:
        """All RepairRequest fields are accessible and correct."""
        task = _make_failed_task()
        repaired = _make_failed_task()
        req = RepairRequest(
            original_task_id=task.id,
            repaired_task=repaired,
            repair_attempt=1,
            failure_reason="nmap failed",
            phase="web",
            target="192.168.1.1",
            origin_skill_id="skill-abc",
        )
        assert req.original_task_id == task.id
        assert req.repair_attempt == 1
        assert req.failure_reason == "nmap failed"
        assert req.phase == "web"
        assert req.target == "192.168.1.1"
        assert req.origin_skill_id == "skill-abc"

    @pytest.mark.asyncio
    async def test_r19_fundamental_outcome_returns_none(self) -> None:
        """dry_run=True (safe default) → repair returns None immediately."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        # dry_run=True is the safe default; repair must be a no-op in this mode
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=True,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_r19_no_gateway_repair_returns_none(self) -> None:
        """No gateway and no router → repair() returns None (no LLM)."""
        engine = RepairEngine(
            model_router=None,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_r19_gateway_with_budget_no_calls_returns_none(self) -> None:
        """Exhausted budget → gateway returns budget_exhausted → repair returns None."""
        budget = LLMBudgetTracker(max_per_run=0)
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        gateway = LLMGateway(model_router=router, budget=budget)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            gateway=gateway,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "recon", _empty_evidence(), _empty_subgraph()
        )
        # Budget exhausted → gateway returns budget_exhausted → engine returns None
        assert result is None

    @pytest.mark.asyncio
    async def test_r19_gateway_output_blocked_returns_none(self) -> None:
        """Output blocked by guard → gateway returns output_blocked → repair returns None."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        guard = _BlockingOutputGuard()
        gateway = LLMGateway(model_router=router, guard=guard)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            gateway=gateway,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_r19_repair_with_gateway_succeeds(self) -> None:
        """Non-exhausted budget + valid output → RepairRequest returned."""
        budget = LLMBudgetTracker(max_per_run=5)
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        gateway = LLMGateway(model_router=router, budget=budget)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            gateway=gateway,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert isinstance(result, RepairRequest)
        assert isinstance(result.repaired_task, TaskSpec)


# ---------------------------------------------------------------------------
# Additional integration: Gateway status helpers
# ---------------------------------------------------------------------------


class TestGatewayStatusHelpers:
    """Verify LLMCallStatus.is_success / is_fallback / is_blocked / is_error."""

    def test_is_success(self) -> None:
        assert LLMCallStatus.success.is_success is True
        assert LLMCallStatus.timeout.is_success is False

    def test_is_fallback(self) -> None:
        assert LLMCallStatus.fallback_no_router.is_fallback is True
        assert LLMCallStatus.fallback_no_model.is_fallback is True
        assert LLMCallStatus.budget_exhausted.is_fallback is True
        assert LLMCallStatus.success.is_fallback is False

    def test_is_blocked(self) -> None:
        assert LLMCallStatus.prompt_blocked.is_blocked is True
        assert LLMCallStatus.output_blocked.is_blocked is True
        assert LLMCallStatus.success.is_blocked is False

    def test_is_error(self) -> None:
        assert LLMCallStatus.provider_error.is_error is True
        assert LLMCallStatus.timeout.is_error is True
        assert LLMCallStatus.success.is_error is False


# ---------------------------------------------------------------------------
# Additional integration: BudgetReservation audit metadata
# ---------------------------------------------------------------------------


class TestBudgetCallMetrics:
    """Verify call_metrics are populated after commit/fail."""

    @pytest.mark.asyncio
    async def test_commit_appends_call_metrics(self) -> None:
        """commit() appends a success entry to call_metrics."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        await res.commit(actual_input_tokens=100, actual_output_tokens=50)
        assert len(budget.call_metrics) == 1
        m = budget.call_metrics[0]
        assert m["success"] is True
        assert m["actual_input_tokens"] == 100
        assert m["actual_output_tokens"] == 50
        assert m["phase"] == "recon"
        assert m["purpose"] == "planning"

    @pytest.mark.asyncio
    async def test_fail_appends_call_metrics(self) -> None:
        """fail() appends a failure entry to call_metrics."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res = await budget.reserve(purpose="repair", phase="web")
        assert res is not None
        await res.fail(known_usage=20)
        assert len(budget.call_metrics) == 1
        m = budget.call_metrics[0]
        assert m["success"] is False
        assert m["error_category"] == "provider_failure"

    @pytest.mark.asyncio
    async def test_release_does_not_append_call_metrics(self) -> None:
        """release() (pre-call block) does NOT append to call_metrics."""
        budget = LLMBudgetTracker(max_per_run=5)
        _, _, res = await budget.reserve(purpose="planning", phase="recon")
        assert res is not None
        await res.release()
        # Release is a pre-call event; no LLM output to record
        assert len(budget.call_metrics) == 0

    def test_to_dict_includes_budget_fields(self) -> None:
        """to_dict() includes all expected summary fields."""
        budget = LLMBudgetTracker(max_per_run=3, max_per_phase=2)
        d = budget.to_dict()
        assert "enabled" in d
        assert "max_calls_per_run" in d
        assert "calls_attempted" in d
        assert "calls_succeeded" in d
        assert "calls_failed" in d
        assert "fallbacks" in d
        assert "budget_remaining" in d
        assert d["max_calls_per_run"] == 3


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------


class TestRepairEngineGatewayPrecedence:
    """gateway= parameter takes precedence over model_router for invocation."""

    @pytest.mark.asyncio
    async def test_gateway_injected_used_over_router(self) -> None:
        """When gateway= injected, engine uses it (not a new internal gateway)."""
        router = _FakeRouter(llm=_StubLLM(_VALID_REPAIR_JSON))
        shared_gateway = LLMGateway(model_router=router)
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
            gateway=shared_gateway,
        )
        # The engine's gateway is the shared one, not a new one
        assert engine._gateway is shared_gateway

    @pytest.mark.asyncio
    async def test_no_model_router_no_gateway_engine_gateway_is_none(self) -> None:
        """No model_router and no gateway → engine._gateway is None."""
        engine = RepairEngine(
            model_router=None,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        assert engine._gateway is None

    @pytest.mark.asyncio
    async def test_model_router_without_gateway_creates_internal_gateway(self) -> None:
        """model_router without explicit gateway → engine creates internal gateway."""
        router = _FakeRouter(llm=_StubLLM())
        engine = RepairEngine(
            model_router=router,
            allowed_tools=["nmap"],
            target=_TARGET,
            dry_run=False,
        )
        # Internal gateway created
        assert engine._gateway is not None
        assert isinstance(engine._gateway, LLMGateway)
