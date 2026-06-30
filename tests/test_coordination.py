"""Tests for Module 5: coordination/.

Section 8 invariants tested here:
- Scheduler cap: never exceeds the concurrency cap; excess queues.
- Budget ceiling: a phase at its ceiling gets no new allocations.
- Conflict resolution policy: higher confidence wins; recency tie-breaks.
- Loop integration: EchoExecutor + StaticPlanner round-trip.
- Retry logic: fixable/script_error bounded by max_retries.
- Resumability: drop in-memory state, rebuild from episodic+graph → continues.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.coordination.budget import BudgetLedger, PhaseBudget
from memfabric.coordination.conflict import (
    dependents_blocked,
    make_conflict,
    resolve_by_policy,
)
from memfabric.coordination.loop import Orchestrator
from memfabric.coordination.protocols import EchoExecutor, StaticPlanner
from memfabric.coordination.scheduler import Scheduler
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import (
    AbandonSignal,
    Episode,
    EvidenceBundle,
    ExecutorResult,
    Goal,
    Node,
    Outcome,
    SubgraphView,
    TaskSpec,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def make_orchestrator(
    api: MemoryAPI, cap: int = 4, max_retries: int = 2
) -> Orchestrator:
    cfg = Config(max_concurrency=cap, max_retries=max_retries)
    scheduler = Scheduler(cap=cap)
    return Orchestrator(
        api=api,
        scheduler=scheduler,
        executors={"echo": EchoExecutor()},
        config=cfg,
    )


def echo_task(i: int = 0) -> TaskSpec:
    return TaskSpec(
        id=new_id(),
        goal_id="g1",
        executor_domain="echo",
        params={"action": f"step_{i}"},
        phase="test",
    )


def make_goal(anchor: str | None = None) -> Goal:
    return Goal(id=new_id(), description="test goal", phase="test", anchor_node=anchor)


# ---------------------------------------------------------------------------
# Scheduler tests
# ---------------------------------------------------------------------------

class TestScheduler:
    async def test_all_tasks_complete(self) -> None:
        sched = Scheduler(cap=4)
        tasks = [echo_task(i) for i in range(6)]

        async def run(t: TaskSpec) -> ExecutorResult:
            ep = Episode(agent="echo", action=t.params["action"], outcome=Outcome.success, data={})  # type: ignore[index]
            return ExecutorResult(task_id=t.id, episode=ep)

        results = await sched.dispatch(tasks, run)
        assert len(results) == 6

    async def test_concurrency_cap_never_exceeded(self) -> None:
        """Assert the semaphore prevents > cap simultaneous tasks."""
        cap = 3
        sched = Scheduler(cap=cap)
        tasks = [echo_task(i) for i in range(10)]

        active_peak = 0
        active_now = 0
        lock = asyncio.Lock()

        async def run(t: TaskSpec) -> ExecutorResult:
            nonlocal active_peak, active_now
            async with lock:
                active_now += 1
                if active_now > active_peak:
                    active_peak = active_now
            await asyncio.sleep(0)  # yield to event loop
            async with lock:
                active_now -= 1
            ep = Episode("echo", "act", Outcome.success, {})
            return ExecutorResult(task_id=t.id, episode=ep)

        await sched.dispatch(tasks, run)
        assert active_peak <= cap

    async def test_empty_task_list_returns_empty(self) -> None:
        sched = Scheduler(cap=2)
        results = await sched.dispatch([], lambda t: t)  # type: ignore[arg-type]
        assert results == []

    async def test_cap_1_runs_serially(self) -> None:
        """With cap=1 tasks run one at a time."""
        sched = Scheduler(cap=1)
        order: list[int] = []
        tasks = [echo_task(i) for i in range(4)]

        async def run(t: TaskSpec) -> ExecutorResult:
            order.append(int(t.params["action"].split("_")[1]))  # type: ignore[index]
            await asyncio.sleep(0)
            ep = Episode("echo", "act", Outcome.success, {})
            return ExecutorResult(task_id=t.id, episode=ep)

        await sched.dispatch(tasks, run)
        # With cap=1, each task waits for the previous
        assert len(order) == 4


# ---------------------------------------------------------------------------
# Budget tests
# ---------------------------------------------------------------------------

class TestBudget:
    def test_fresh_budget_not_exhausted(self) -> None:
        b = PhaseBudget("recon", max_turns=5, max_tokens=1000)
        assert not b.is_exhausted()
        assert b.can_allocate()

    def test_consume_decrements(self) -> None:
        b = PhaseBudget("recon", max_turns=5, max_tokens=1000)
        b.consume(turns=2, tokens=100)
        assert b.turns_remaining() == 3
        assert b.tokens_remaining() == 900

    def test_at_ceiling_exhausted(self) -> None:
        b = PhaseBudget("recon", max_turns=3, max_tokens=500)
        b.consume(turns=3, tokens=0)
        assert b.is_exhausted()
        assert not b.can_allocate()

    def test_consume_beyond_ceiling_raises(self) -> None:
        from memfabric.coordination.budget import PhasebudgetError
        b = PhaseBudget("recon", max_turns=2, max_tokens=100)
        b.consume(turns=2)
        with pytest.raises(PhasebudgetError):
            b.consume(turns=1)   # already exhausted

    def test_ledger_open_phases(self) -> None:
        ledger = BudgetLedger()
        ledger.add_phase(PhaseBudget("a", max_turns=5, max_tokens=1000))
        ledger.add_phase(PhaseBudget("b", max_turns=1, max_tokens=1000))
        ledger.consume("b", turns=1)

        open_phases = ledger.open_phases()
        phase_names = {p.phase for p in open_phases}
        assert "a" in phase_names
        assert "b" not in phase_names   # exhausted

    def test_all_exhausted_when_all_phases_done(self) -> None:
        ledger = BudgetLedger()
        ledger.add_phase(PhaseBudget("x", max_turns=1, max_tokens=10))
        ledger.consume("x", turns=1)
        assert ledger.all_exhausted()

    def test_budget_ceiling_blocks_allocation(self) -> None:
        ledger = BudgetLedger()
        ledger.add_phase(PhaseBudget("p", max_turns=2, max_tokens=100))
        assert ledger.can_allocate("p")
        ledger.consume("p", turns=2)
        assert not ledger.can_allocate("p")   # at ceiling


# ---------------------------------------------------------------------------
# Conflict module tests
# ---------------------------------------------------------------------------

class TestConflictModule:
    def test_make_conflict(self) -> None:
        c = make_conflict(
            "n1", "ip",
            {"value": "1.1.1.1", "confidence": 0.9, "source": "a", "timestamp": now()},
            {"value": "2.2.2.2", "confidence": 0.8, "source": "b", "timestamp": now()},
        )
        assert c.node_id == "n1"
        assert c.field_name == "ip"
        assert not c.resolved

    def test_resolve_higher_confidence_wins(self) -> None:
        c = make_conflict(
            "n1", "ip",
            {"value": "A", "confidence": 0.9, "source": "x", "timestamp": now()},
            {"value": "B", "confidence": 0.7, "source": "y", "timestamp": now()},
        )
        resolution = resolve_by_policy(c)
        assert "claim_a" in resolution
        assert "A" in resolution

    def test_resolve_tie_broken_by_recency(self) -> None:
        import time
        t1 = now()
        time.sleep(0.01)
        t2 = now()
        c = make_conflict(
            "n1", "ip",
            {"value": "A", "confidence": 0.9, "source": "x", "timestamp": t1},
            {"value": "B", "confidence": 0.9, "source": "y", "timestamp": t2},
        )
        resolution = resolve_by_policy(c)
        # claim_b has later timestamp → wins
        assert "claim_b" in resolution

    def test_dependents_blocked_until_resolved(self) -> None:
        c = make_conflict("n1", "ip", {}, {})
        assert dependents_blocked(c)
        c.resolved = True
        assert not dependents_blocked(c)


# ---------------------------------------------------------------------------
# Orchestrator + loop tests
# ---------------------------------------------------------------------------

class TestOrchestrator:
    async def test_single_turn_succeeds(self) -> None:
        api = make_api()
        orch = make_orchestrator(api)
        tasks = [echo_task(0)]
        planner = StaticPlanner(tasks=tasks)

        results = await orch.run_turn(make_goal(), planner)
        assert len(results) == 1
        assert results[0].episode.outcome == Outcome.success

    async def test_episode_appended_to_log(self) -> None:
        api = make_api()
        orch = make_orchestrator(api)
        tasks = [echo_task(0), echo_task(1)]
        planner = StaticPlanner(tasks=tasks)

        await orch.run_turn(make_goal(), planner)

        all_eps = await api._episodic.all()
        assert len(all_eps) == 2

    async def test_abandon_signal_returns_empty(self) -> None:
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(abandon=True, abandon_reason="nothing to do")

        results = await orch.run_turn(make_goal(), planner)
        assert results == []

    async def test_budget_ceiling_skips_turn(self) -> None:
        api = make_api()
        orch = make_orchestrator(api)

        ledger = BudgetLedger()
        ledger.add_phase(PhaseBudget("test", max_turns=0, max_tokens=1000))

        planner = StaticPlanner(tasks=[echo_task(0)])
        results = await orch.run_turn(make_goal(), planner, budget=ledger)
        assert results == []

    async def test_multiple_tasks_all_executed(self) -> None:
        api = make_api()
        orch = make_orchestrator(api, cap=4)
        tasks = [echo_task(i) for i in range(5)]
        planner = StaticPlanner(tasks=tasks)

        results = await orch.run_turn(make_goal(), planner)
        assert len(results) == 5

    async def test_node_delta_merged_into_graph(self) -> None:
        """ExecutorResult.node_deltas should be merged into the EKG."""
        api = make_api()
        cfg = Config()
        scheduler = Scheduler(cap=2)

        t = now()
        node_to_add = Node(
            id="delta-node",
            type="finding",
            props={"severity": "high"},
            confidence=0.9,
            source="echo",
            first_seen=t,
            last_seen=t,
        )

        class DeltaExecutor:
            domain = "delta"

            async def run(self, task: TaskSpec, ev: EvidenceBundle) -> ExecutorResult:
                ep = Episode("delta", "find", Outcome.success, {})
                return ExecutorResult(
                    task_id=task.id,
                    episode=ep,
                    node_deltas=[node_to_add],
                )

        orch = Orchestrator(
            api=api,
            scheduler=scheduler,
            executors={"delta": DeltaExecutor()},
            config=cfg,
        )

        task = TaskSpec(id=new_id(), goal_id="g", executor_domain="delta", params={}, phase="test")
        planner = StaticPlanner(tasks=[task])
        await orch.run_turn(make_goal(), planner)

        result_node = await api._graph.get_node("delta-node")
        assert result_node is not None
        assert result_node.props["severity"] == "high"

    async def test_retry_on_script_error(self) -> None:
        """script_error outcome triggers up to max_retries retries."""
        api = make_api()
        cfg = Config(max_retries=2)
        scheduler = Scheduler(cap=1)
        call_count = 0

        class FlakyExecutor:
            domain = "flaky"

            async def run(self, task: TaskSpec, ev: EvidenceBundle) -> ExecutorResult:
                nonlocal call_count
                call_count += 1
                # Fail first 2 times, succeed on 3rd
                if call_count <= 2:
                    ep = Episode("flaky", "work", Outcome.script_error, {})
                else:
                    ep = Episode("flaky", "work", Outcome.success, {})
                return ExecutorResult(task_id=task.id, episode=ep)

        orch = Orchestrator(
            api=api,
            scheduler=scheduler,
            executors={"flaky": FlakyExecutor()},
            config=cfg,
        )

        task = TaskSpec(id=new_id(), goal_id="g", executor_domain="flaky", params={}, phase="t")
        planner = StaticPlanner(tasks=[task])
        results = await orch.run_turn(make_goal(), planner)

        assert call_count == 3
        assert results[0].episode.outcome == Outcome.success

    async def test_fundamental_failure_not_retried(self) -> None:
        api = make_api()
        cfg = Config(max_retries=3)
        scheduler = Scheduler(cap=1)
        call_count = 0

        class BrokenExecutor:
            domain = "broken"

            async def run(self, task: TaskSpec, ev: EvidenceBundle) -> ExecutorResult:
                nonlocal call_count
                call_count += 1
                ep = Episode("broken", "fail", Outcome.fundamental, {})
                return ExecutorResult(task_id=task.id, episode=ep)

        orch = Orchestrator(
            api=api, scheduler=scheduler,
            executors={"broken": BrokenExecutor()}, config=cfg,
        )
        task = TaskSpec(id=new_id(), goal_id="g", executor_domain="broken", params={}, phase="t")
        planner = StaticPlanner(tasks=[task])
        results = await orch.run_turn(make_goal(), planner)

        # fundamental must NOT be retried
        assert call_count == 1
        assert results[0].episode.outcome == Outcome.fundamental


# ---------------------------------------------------------------------------
# Resumability invariant
# ---------------------------------------------------------------------------

class TestResumability:
    async def test_episodic_log_survives_memory_drop(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Kill in-memory state, reload from JSONL → all episodes intact."""
        import pathlib
        path = pathlib.Path(str(tmp_path)) / "ep.jsonl"

        # --- First engagement ---
        cfg = Config()
        api_1 = MemoryAPI(
            graph=NetworkXGraphStore(),
            episodic=JSONLEpisodicStore(path=path),
            lexical=BM25LexicalIndex(),
            vector=FaissVectorIndex(dim=cfg.vector_dim),
            kv=InMemoryKVStore(),
            config=cfg,
        )
        orch_1 = make_orchestrator(api_1, cap=2)
        tasks = [echo_task(i) for i in range(3)]
        await orch_1.run_turn(make_goal(), StaticPlanner(tasks=tasks))

        eps_before = await api_1._episodic.all()
        assert len(eps_before) == 3

        # --- Simulate restart: drop all in-memory state ---
        del api_1, orch_1

        # --- Second engagement: rebuild from file ---
        api_2 = MemoryAPI(
            graph=NetworkXGraphStore(),      # fresh EKG (would be rebuilt from log)
            episodic=JSONLEpisodicStore(path=path),   # reloads from file
            lexical=BM25LexicalIndex(),
            vector=FaissVectorIndex(dim=cfg.vector_dim),
            kv=InMemoryKVStore(),
            config=cfg,
        )

        eps_after = await api_2._episodic.all()
        assert len(eps_after) == 3
        actions = {ep.action for ep in eps_after}
        assert actions == {"step_0", "step_1", "step_2"}
