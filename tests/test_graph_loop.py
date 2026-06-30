"""Tests for the LangGraph coordination loop (graph_state + graph_loop + loop).

Section 8 invariants tested here:
- Turn round-trip parity: graph produces same outcomes as the old hand-rolled loop.
- Conditional abandon edge: AbandonSignal → graph ends at plan, no dispatch.
- Outcome routing / retries: script_error retried; fundamental not retried.
- Checkpoint round-trip: state is written to MemorySaver and readable back.
- State-stays-generic: TurnState fields contain only substrate types, never
  MemoryAPI / Scheduler / Executor objects.
- Budget ceiling: exhausted budget skips graph invocation.
- Node deltas merged via MemoryAPI (Invariant 1).
- Multiple tasks dispatched concurrently through the graph.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.coordination.graph_loop import build_graph
from memfabric.coordination.graph_state import TurnState
from memfabric.coordination.budget import BudgetLedger, PhaseBudget
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
    api: MemoryAPI,
    cap: int = 4,
    max_retries: int = 2,
) -> Orchestrator:
    cfg = Config(max_concurrency=cap, max_retries=max_retries)
    scheduler = Scheduler(cap=cap)
    return Orchestrator(
        api=api,
        scheduler=scheduler,
        executors={"echo": EchoExecutor()},
        config=cfg,
    )


def echo_task(i: int = 0, outcome: Outcome = Outcome.success) -> TaskSpec:
    return TaskSpec(
        id=new_id(),
        goal_id="g1",
        executor_domain="echo",
        params={"action": f"step_{i}", "outcome": outcome.value},
        phase="test",
    )


def make_goal(anchor: str | None = None) -> Goal:
    return Goal(
        id=new_id(), description="test goal", phase="test", anchor_node=anchor
    )


# ---------------------------------------------------------------------------
# TurnState structure tests (no I/O — pure type inspection)
# ---------------------------------------------------------------------------

class TestTurnStateStructure:
    def test_state_stays_generic_no_api_objects(self) -> None:
        """TurnState must NOT contain MemoryAPI, Scheduler, or Executor types.

        Note: ExecutorResult is an allowed substrate type; only the Protocol
        class 'Executor' is disallowed.  We check by module-qualified name so
        we don't accidentally match 'ExecutorResult' when looking for 'Executor'.
        """
        from typing import get_type_hints
        import memfabric.api as _api_mod
        import memfabric.coordination.scheduler as _sched_mod
        import memfabric.coordination.protocols as _proto_mod
        import memfabric.config as _cfg_mod

        # Collect the actual class objects that must not appear in field types
        banned_classes = (
            _api_mod.MemoryAPI,
            _sched_mod.Scheduler,
            _proto_mod.Executor,   # Protocol — not ExecutorResult
            _proto_mod.Planner,
            _cfg_mod.Config,
        )

        def _flatten(hint: object) -> set[object]:
            """Recursively collect all type arguments."""
            import typing
            args = getattr(hint, "__args__", None) or ()
            result: set[object] = {hint}
            for a in args:
                result |= _flatten(a)
            return result

        hints = get_type_hints(TurnState, include_extras=True)
        for field_name, hint in hints.items():
            for cls in banned_classes:
                assert cls not in _flatten(hint), (
                    f"TurnState.{field_name} must not reference {cls.__name__}; "
                    f"got: {hint}"
                )

    def test_state_contains_expected_substrate_types(self) -> None:
        from typing import get_type_hints
        hints = get_type_hints(TurnState, include_extras=True)
        assert "goal" in hints
        assert "tasks" in hints
        assert "results" in hints
        assert "evidence" in hints
        assert "abandoned" in hints
        assert "abandon_reason" in hints
        assert "retry_counts" in hints

    def test_retry_counts_reducer_keeps_max(self) -> None:
        from memfabric.coordination.graph_state import _merge_retry_counts
        result = _merge_retry_counts({"a": 1, "b": 3}, {"b": 2, "c": 5})
        assert result == {"a": 1, "b": 3, "c": 5}

    def test_retry_counts_reducer_empty_inputs(self) -> None:
        from memfabric.coordination.graph_state import _merge_retry_counts
        assert _merge_retry_counts({}, {}) == {}
        assert _merge_retry_counts({"x": 2}, {}) == {"x": 2}
        assert _merge_retry_counts({}, {"x": 2}) == {"x": 2}


# ---------------------------------------------------------------------------
# Round-trip parity: graph produces same results as the former hand-rolled loop
# ---------------------------------------------------------------------------

class TestRoundTripParity:
    async def test_single_task_success(self) -> None:
        """Graph-backed Orchestrator returns success for a single echo task."""
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(tasks=[echo_task(0)])

        results = await orch.run_turn(make_goal(), planner)

        assert len(results) == 1
        assert results[0].episode.outcome == Outcome.success

    async def test_multiple_tasks_all_executed(self) -> None:
        api = make_api()
        orch = make_orchestrator(api, cap=4)
        planner = StaticPlanner(tasks=[echo_task(i) for i in range(5)])

        results = await orch.run_turn(make_goal(), planner)

        assert len(results) == 5
        assert all(r.episode.outcome == Outcome.success for r in results)

    async def test_episodes_appended_to_fabric(self) -> None:
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(tasks=[echo_task(0), echo_task(1)])

        await orch.run_turn(make_goal(), planner)

        all_eps = await api._episodic.all()
        assert len(all_eps) == 2

    async def test_node_deltas_written_through_api(self) -> None:
        """ExecutorResult.node_deltas are upserted into the EKG (Invariant 1)."""
        api = make_api()
        cfg = Config()
        scheduler = Scheduler(cap=2)

        t = now()
        expected_node = Node(
            id="graph-delta-node",
            type="finding",
            props={"severity": "high"},
            confidence=0.9,
            source="graph_test",
            first_seen=t,
            last_seen=t,
        )

        class DeltaExecutor:
            domain = "delta"

            async def run(
                self, task: TaskSpec, ev: EvidenceBundle
            ) -> ExecutorResult:
                ep = Episode("delta", "find", Outcome.success, {})
                return ExecutorResult(
                    task_id=task.id, episode=ep, node_deltas=[expected_node]
                )

        orch = Orchestrator(
            api=api,
            scheduler=scheduler,
            executors={"delta": DeltaExecutor()},
            config=cfg,
        )
        task = TaskSpec(
            id=new_id(), goal_id="g", executor_domain="delta",
            params={}, phase="test",
        )
        await orch.run_turn(make_goal(), StaticPlanner(tasks=[task]))

        result_node = await api._graph.get_node("graph-delta-node")
        assert result_node is not None
        assert result_node.props["severity"] == "high"


# ---------------------------------------------------------------------------
# Conditional abandon edge
# ---------------------------------------------------------------------------

class TestConditionalAbandonEdge:
    async def test_abandon_signal_returns_empty(self) -> None:
        """AbandonSignal → plan node sets abandoned=True → route to END → []."""
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(abandon=True, abandon_reason="nothing to do")

        results = await orch.run_turn(make_goal(), planner)

        assert results == []

    async def test_abandon_writes_no_episodes(self) -> None:
        """Dispatch is never reached; no episodes are appended."""
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(abandon=True)

        await orch.run_turn(make_goal(), planner)

        all_eps = await api._episodic.all()
        assert len(all_eps) == 0

    async def test_non_abandon_reaches_dispatch(self) -> None:
        """Non-abandon path: dispatch IS reached; episodes ARE written."""
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(tasks=[echo_task(0)])

        results = await orch.run_turn(make_goal(), planner)

        assert results  # dispatch was reached
        all_eps = await api._episodic.all()
        assert len(all_eps) == 1


# ---------------------------------------------------------------------------
# Outcome routing / retries
# ---------------------------------------------------------------------------

class TestOutcomeRoutingRetries:
    async def test_script_error_retried_up_to_max_retries(self) -> None:
        """script_error triggers bounded retries; 3rd attempt succeeds."""
        api = make_api()
        cfg = Config(max_retries=2)
        scheduler = Scheduler(cap=1)
        call_count = 0

        class FlakyExecutor:
            domain = "flaky"

            async def run(
                self, task: TaskSpec, ev: EvidenceBundle
            ) -> ExecutorResult:
                nonlocal call_count
                call_count += 1
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
        task = TaskSpec(
            id=new_id(), goal_id="g", executor_domain="flaky",
            params={}, phase="t",
        )
        results = await orch.run_turn(make_goal(), StaticPlanner(tasks=[task]))

        assert call_count == 3
        assert results[0].episode.outcome == Outcome.success

    async def test_fundamental_not_retried(self) -> None:
        """fundamental outcome is returned immediately without retry."""
        api = make_api()
        cfg = Config(max_retries=3)
        scheduler = Scheduler(cap=1)
        call_count = 0

        class BrokenExecutor:
            domain = "broken"

            async def run(
                self, task: TaskSpec, ev: EvidenceBundle
            ) -> ExecutorResult:
                nonlocal call_count
                call_count += 1
                ep = Episode("broken", "fail", Outcome.fundamental, {})
                return ExecutorResult(task_id=task.id, episode=ep)

        orch = Orchestrator(
            api=api, scheduler=scheduler,
            executors={"broken": BrokenExecutor()}, config=cfg,
        )
        task = TaskSpec(
            id=new_id(), goal_id="g", executor_domain="broken",
            params={}, phase="t",
        )
        results = await orch.run_turn(make_goal(), StaticPlanner(tasks=[task]))

        assert call_count == 1
        assert results[0].episode.outcome == Outcome.fundamental

    async def test_fixable_clue_passed_on_retry(self) -> None:
        """fixable outcome: clue is injected into params on next attempt."""
        api = make_api()
        cfg = Config(max_retries=2)
        scheduler = Scheduler(cap=1)
        received_params: list[dict[str, Any]] = []

        class FixableExecutor:
            domain = "fixable"

            async def run(
                self, task: TaskSpec, ev: EvidenceBundle
            ) -> ExecutorResult:
                received_params.append(dict(task.params))
                if "clue" not in task.params:
                    ep = Episode("fixable", "try", Outcome.fixable, {})
                    return ExecutorResult(
                        task_id=task.id, episode=ep, clue="use-port-443"
                    )
                ep = Episode("fixable", "try", Outcome.success, {})
                return ExecutorResult(task_id=task.id, episode=ep)

        orch = Orchestrator(
            api=api, scheduler=scheduler,
            executors={"fixable": FixableExecutor()}, config=cfg,
        )
        task = TaskSpec(
            id=new_id(), goal_id="g", executor_domain="fixable",
            params={"action": "connect"}, phase="t",
        )
        results = await orch.run_turn(make_goal(), StaticPlanner(tasks=[task]))

        assert results[0].episode.outcome == Outcome.success
        # Second call must have received the clue
        assert received_params[1].get("clue") == "use-port-443"


# ---------------------------------------------------------------------------
# Checkpoint round-trip
# ---------------------------------------------------------------------------

class TestCheckpointRoundTrip:
    async def test_checkpoint_written_after_turn(self) -> None:
        """MemorySaver holds state for the completed turn's thread_id."""
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(tasks=[echo_task(0)])

        await orch.run_turn(make_goal(), planner)

        thread_id = orch.last_thread_id
        assert thread_id is not None

        cfg = {"configurable": {"thread_id": thread_id}}
        snapshot = await orch.last_graph.aget_state(cfg)
        assert snapshot is not None

    async def test_checkpoint_contains_correct_goal(self) -> None:
        """Checkpoint values include the goal that was executed."""
        api = make_api()
        orch = make_orchestrator(api)
        goal = make_goal()
        planner = StaticPlanner(tasks=[echo_task(0)])

        await orch.run_turn(goal, planner)

        cfg = {"configurable": {"thread_id": orch.last_thread_id}}
        snapshot = await orch.last_graph.aget_state(cfg)
        stored_goal: Goal = snapshot.values["goal"]
        assert stored_goal.id == goal.id

    async def test_checkpoint_results_match_return_value(self) -> None:
        """Checkpoint results match what run_turn returned."""
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(tasks=[echo_task(0), echo_task(1)])

        returned = await orch.run_turn(make_goal(), planner)

        cfg = {"configurable": {"thread_id": orch.last_thread_id}}
        snapshot = await orch.last_graph.aget_state(cfg)
        checkpointed_results: list[ExecutorResult] = snapshot.values["results"]

        assert len(checkpointed_results) == len(returned)
        returned_ids = {r.task_id for r in returned}
        checkpointed_ids = {r.task_id for r in checkpointed_results}
        assert returned_ids == checkpointed_ids

    async def test_abandon_checkpoint_marks_abandoned(self) -> None:
        """Checkpoint for an abandoned turn has abandoned=True."""
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(abandon=True, abandon_reason="test reason")

        await orch.run_turn(make_goal(), planner)

        cfg = {"configurable": {"thread_id": orch.last_thread_id}}
        snapshot = await orch.last_graph.aget_state(cfg)
        assert snapshot.values["abandoned"] is True
        assert snapshot.values["abandon_reason"] == "test reason"

    async def test_each_turn_gets_distinct_thread_id(self) -> None:
        """Successive run_turn calls produce distinct thread IDs."""
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(tasks=[echo_task(0)])

        await orch.run_turn(make_goal(), planner)
        tid1 = orch.last_thread_id

        await orch.run_turn(make_goal(), planner)
        tid2 = orch.last_thread_id

        assert tid1 != tid2

    async def test_older_turn_checkpoint_still_accessible(self) -> None:
        """Earlier turns' checkpoints are retained in the shared MemorySaver."""
        api = make_api()
        orch = make_orchestrator(api)
        planner = StaticPlanner(tasks=[echo_task(0)])

        await orch.run_turn(make_goal(), planner)
        tid1 = orch.last_thread_id
        graph1 = orch.last_graph

        await orch.run_turn(make_goal(), planner)

        # Turn 1 checkpoint is still accessible via its original thread_id
        cfg1 = {"configurable": {"thread_id": tid1}}
        snap1 = await graph1.aget_state(cfg1)
        assert snap1 is not None
        assert len(snap1.values["results"]) == 1


# ---------------------------------------------------------------------------
# Budget integration
# ---------------------------------------------------------------------------

class TestBudgetIntegration:
    async def test_exhausted_budget_returns_empty_without_graph_run(self) -> None:
        """Pre-exhausted budget short-circuits before graph is invoked."""
        api = make_api()
        orch = make_orchestrator(api)

        ledger = BudgetLedger()
        ledger.add_phase(PhaseBudget("test", max_turns=0, max_tokens=1000))
        planner = StaticPlanner(tasks=[echo_task(0)])

        results = await orch.run_turn(make_goal(), planner, budget=ledger)
        assert results == []
        # No graph was invoked; last_thread_id stays None
        assert orch.last_thread_id is None

    async def test_budget_consumed_when_tasks_executed(self) -> None:
        """Budget.consume is called once when tasks are actually dispatched."""
        api = make_api()
        orch = make_orchestrator(api)

        ledger = BudgetLedger()
        ledger.add_phase(PhaseBudget("test", max_turns=3, max_tokens=1000))
        planner = StaticPlanner(tasks=[echo_task(0)])

        await orch.run_turn(make_goal(), planner, budget=ledger)
        phase = ledger.get("test")
        assert phase is not None
        assert phase.turns_used == 1

    async def test_budget_not_consumed_on_abandon(self) -> None:
        """Budget.consume is NOT called when planner abandons."""
        api = make_api()
        orch = make_orchestrator(api)

        ledger = BudgetLedger()
        ledger.add_phase(PhaseBudget("test", max_turns=3, max_tokens=1000))
        planner = StaticPlanner(abandon=True)

        await orch.run_turn(make_goal(), planner, budget=ledger)
        phase = ledger.get("test")
        assert phase is not None
        assert phase.turns_used == 0


# ---------------------------------------------------------------------------
# build_graph used directly (unit-test the compiled graph independently)
# ---------------------------------------------------------------------------

class TestBuildGraphDirect:
    async def test_build_graph_returns_invokable(self) -> None:
        """build_graph() returns a graph that can be ainvoked."""
        api = make_api()
        cfg = Config()
        scheduler = Scheduler(cap=2)
        planner = StaticPlanner(tasks=[echo_task(0)])

        graph = build_graph(
            api, scheduler, {"echo": EchoExecutor()}, planner, cfg
        )

        initial: TurnState = {
            "goal": make_goal(),
            "subgraph": None,
            "evidence": None,
            "tasks": [],
            "results": [],
            "abandoned": False,
            "abandon_reason": "",
            "retry_counts": {},
        }
        result = await graph.ainvoke(initial)
        assert isinstance(result["results"], list)

    async def test_build_graph_abandon_path(self) -> None:
        """Direct graph invocation: abandon planner → abandoned=True, results=[]."""
        api = make_api()
        cfg = Config()
        scheduler = Scheduler(cap=2)
        planner = StaticPlanner(abandon=True, abandon_reason="direct test")

        graph = build_graph(
            api, scheduler, {"echo": EchoExecutor()}, planner, cfg
        )
        initial: TurnState = {
            "goal": make_goal(),
            "subgraph": None,
            "evidence": None,
            "tasks": [],
            "results": [],
            "abandoned": False,
            "abandon_reason": "",
            "retry_counts": {},
        }
        final = await graph.ainvoke(initial)
        assert final["abandoned"] is True
        assert final["abandon_reason"] == "direct test"
        assert final["results"] == []
