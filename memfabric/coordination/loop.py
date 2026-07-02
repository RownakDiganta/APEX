# loop.py
# Orchestrator control loop that builds and invokes the LangGraph state machine per turn, manages a shared MemorySaver checkpointer, and enforces budget pre-checks.
"""Orchestrator control loop — delegates to the LangGraph state machine.

Public API is unchanged:

    results = await orchestrator.run_turn(goal, planner, budget=budget_ledger)

Internally each turn is now a compiled LangGraph StateGraph (Section 6.5):

    START → read_context → plan ─┬─ (abandoned) → END
                                  └─ dispatch → merge → END

The checkpointer (MemorySaver) is created once at __init__ and shared
across turns, giving a per-thread-id audit trail.  Use
``orchestrator.last_thread_id`` + ``orchestrator.checkpointer`` to
inspect the most recent turn's checkpoint.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from memfabric.coordination.graph_loop import build_graph
from memfabric.coordination.graph_state import TurnState
from memfabric.ids import new_id
from memfabric.types import (
    ExecutorResult,
    Goal,
)

# Explicitly register all substrate types so MemorySaver's msgpack serde
# does not emit "Deserializing unregistered type" warnings in LangGraph 1.x.
_MEMFABRIC_SERDE = JsonPlusSerializer(
    allowed_msgpack_modules=[
        ("memfabric.types", cls)
        for cls in (
            "Goal", "SubgraphView", "EvidenceBundle", "TaskSpec",
            "ExecutorResult", "Episode", "Outcome", "ScoredEntry",
            "Node", "Edge", "KnowledgeEntry", "Skill",
        )
    ]
)

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI
    from memfabric.config import Config
    from memfabric.coordination.budget import BudgetLedger
    from memfabric.coordination.protocols import Executor, Planner
    from memfabric.coordination.scheduler import Scheduler

logger = logging.getLogger(__name__)


class Orchestrator:
    """Stateless engagement driver backed by a LangGraph state machine.

    All durable state lives in the MemoryAPI fabric.  The orchestrator
    can be restarted from the episodic log + graph snapshot with no
    information loss (Invariant 6 — stateless executors).

    Parameters
    ----------
    api:        MemoryAPI — the sole state surface.
    scheduler:  Concurrency-capped task dispatcher.
    executors:  Map of domain name → Executor implementation.
    config:     Typed configuration dataclass.
    """

    def __init__(
        self,
        api: "MemoryAPI",
        scheduler: "Scheduler",
        executors: "dict[str, Executor]",
        *,
        config: "Config",
    ) -> None:
        self._api = api
        self._scheduler = scheduler
        self._executors = executors
        self._config = config
        # One MemorySaver shared across all turns for cross-turn auditability.
        # Pre-registered serde silences the "unregistered type" msgpack warning
        # introduced in LangGraph 1.x for our substrate dataclasses.
        self._checkpointer: MemorySaver = MemorySaver(serde=_MEMFABRIC_SERDE)
        self._last_thread_id: str | None = None
        self._last_graph: Any = None

    # ------------------------------------------------------------------
    # Public read-only properties (used by tests for checkpoint inspection)
    # ------------------------------------------------------------------

    @property
    def checkpointer(self) -> MemorySaver:
        """The shared MemorySaver; holds one checkpoint per thread_id."""
        return self._checkpointer

    @property
    def last_thread_id(self) -> str | None:
        """Thread ID assigned to the most recent ``run_turn`` invocation."""
        return self._last_thread_id

    @property
    def last_graph(self) -> Any:
        """The compiled graph used in the most recent ``run_turn`` invocation.

        Use ``await orch.last_graph.aget_state(config)`` to inspect the
        checkpoint written by that turn.
        """
        return self._last_graph

    # ------------------------------------------------------------------
    # Main entry point (public API — signature unchanged)
    # ------------------------------------------------------------------

    async def run_turn(
        self,
        goal: Goal,
        planner: "Planner",
        budget: "BudgetLedger | None" = None,
    ) -> list[ExecutorResult]:
        """Execute one orchestrator turn for *goal* via the LangGraph graph.

        Returns the list of ``ExecutorResult``s collected during this turn.
        An empty list is returned when:
        - The budget for this phase is exhausted (pre-check).
        - The planner returns an ``AbandonSignal``.
        - The planner returns no tasks.
        """
        # 1. Budget pre-check (unchanged behaviour)
        if budget is not None and not budget.can_allocate(goal.phase):
            logger.info("phase %r budget exhausted; skipping turn", goal.phase)
            return []

        # 2. Build the compiled graph for this turn.
        #    Each turn may have a different planner, so we rebuild cheaply.
        graph = build_graph(
            self._api,
            self._scheduler,
            self._executors,
            planner,
            self._config,
            checkpointer=self._checkpointer,
        )
        self._last_graph = graph

        # 3. Assign a unique thread ID for this turn's checkpoint.
        thread_id = new_id()
        self._last_thread_id = thread_id
        invoke_config: dict[str, Any] = {
            "configurable": {"thread_id": thread_id}
        }

        # 4. Build the initial state.
        initial: TurnState = {
            "goal": goal,
            "subgraph": None,
            "evidence": None,
            "tasks": [],
            "results": [],
            "abandoned": False,
            "abandon_reason": "",
            "retry_counts": {},
        }

        # 5. Run the graph to completion.
        final_state: dict[str, Any] = await graph.ainvoke(
            initial, config=invoke_config
        )

        results: list[ExecutorResult] = list(final_state.get("results") or [])

        # 6. Consume budget only when real work was dispatched (matches
        #    original behaviour: no consume on abandon or empty task list).
        if (
            budget is not None
            and results
            and not final_state.get("abandoned", False)
        ):
            budget.consume(goal.phase, turns=1)

        return results
