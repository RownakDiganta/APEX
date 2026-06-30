"""LangGraph StateGraph for the coordination loop.

``build_graph()`` compiles the turn state machine:

    START → read_context → plan ─┬─ (abandoned) → END
                                  └─ dispatch → merge → END

Design constraints honoured:
- MemoryAPI, Scheduler, Executors, Planner are NEVER stored in TurnState.
  They are captured via closures when build_graph() is called.
- All cross-component communication goes through MemoryAPI (Invariant 1).
- No agent-to-agent calls (Invariant 7 — blackboard model).
- LangGraph is confined to generic coordination; no domain logic, no
  offensive tools, no browser automation.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from memfabric.coordination.graph_state import CompiledTurnGraph, TurnState
from memfabric.types import (
    AbandonSignal,
    EvidenceBundle,
    ExecutorResult,
    Outcome,
    SubgraphView,
    TaskSpec,
)

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI
    from memfabric.config import Config
    from memfabric.coordination.protocols import Executor, Planner
    from memfabric.coordination.scheduler import Scheduler

logger = logging.getLogger(__name__)


def build_graph(
    api: "MemoryAPI",
    scheduler: "Scheduler",
    executors: "dict[str, Executor]",
    planner: "Planner",
    config: "Config",
    *,
    checkpointer: "MemorySaver | None" = None,
) -> CompiledTurnGraph:
    """Compile and return the turn StateGraph.

    Parameters ``api``, ``scheduler``, ``executors``, ``planner``, and
    ``config`` are captured in node closures — they never appear in
    ``TurnState`` payloads.

    ``build_graph`` is called once per ``run_turn`` invocation (each turn
    can have a different planner).  LangGraph graph compilation is cheap
    (pure DAG construction; no model weights).  The ``checkpointer`` is
    shared across turns by the caller for cross-turn auditability.
    """

    # ------------------------------------------------------------------
    # Node: read_context
    # Pull scoped subgraph + EvidenceBundle from MemoryAPI.
    # ------------------------------------------------------------------
    async def read_context(state: TurnState) -> dict[str, Any]:
        goal = state["goal"]

        if goal.anchor_node:
            subgraph: SubgraphView = await api.get_subgraph(
                goal.anchor_node, depth=2
            )
        else:
            subgraph = SubgraphView(anchor="", nodes=[], edges=[], depth=0)

        evidence: EvidenceBundle = await api.query(
            text=goal.description,
            subgraph_anchor=goal.anchor_node,
        )

        return {"subgraph": subgraph, "evidence": evidence}

    # ------------------------------------------------------------------
    # Node: plan
    # Ask the planner for TaskSpecs or an AbandonSignal.
    # ------------------------------------------------------------------
    async def plan(state: TurnState) -> dict[str, Any]:
        goal = state["goal"]
        subgraph = state["subgraph"] or SubgraphView(
            anchor="", nodes=[], edges=[], depth=0
        )
        evidence = state["evidence"] or EvidenceBundle(
            query="", entries=[], subgraph=None, tiers_queried=[]
        )

        plan_result = await planner.plan(goal, subgraph, evidence)

        if isinstance(plan_result, AbandonSignal):
            logger.info("goal %r abandoned: %s", goal.id, plan_result.reason)
            return {"abandoned": True, "abandon_reason": plan_result.reason}

        new_tasks: list[TaskSpec] = list(plan_result) if plan_result else []
        # ``tasks`` has operator.add as reducer → new list is appended
        return {"tasks": new_tasks}

    # ------------------------------------------------------------------
    # Node: dispatch
    # Run tasks through the concurrency-capped scheduler with retry logic.
    # ------------------------------------------------------------------
    async def dispatch(state: TurnState) -> dict[str, Any]:
        tasks = state["tasks"]
        if not tasks:
            return {}

        async def _execute(task: TaskSpec) -> ExecutorResult:
            executor = executors.get(task.executor_domain)
            if executor is None:
                raise ValueError(
                    f"No executor registered for domain {task.executor_domain!r}"
                )

            task_evidence: EvidenceBundle = await api.query(
                text=task.params.get("description", ""),
                subgraph_anchor=task.subgraph_anchor,
            )

            current_task = task
            retries = 0
            while True:
                result = await executor.run(current_task, task_evidence)
                outcome = result.episode.outcome

                if outcome == Outcome.success:
                    return result

                if outcome == Outcome.fundamental:
                    logger.warning("fundamental failure task=%s", current_task.id)
                    return result

                if retries >= config.max_retries:
                    logger.warning(
                        "task=%s exceeded max_retries=%d outcome=%s",
                        current_task.id,
                        config.max_retries,
                        outcome.value,
                    )
                    return result

                retries += 1
                logger.info(
                    "retry %d/%d task=%s outcome=%s",
                    retries,
                    config.max_retries,
                    current_task.id,
                    outcome.value,
                )

                if outcome == Outcome.fixable and result.clue:
                    current_task = TaskSpec(
                        id=current_task.id,
                        goal_id=current_task.goal_id,
                        executor_domain=current_task.executor_domain,
                        params={**current_task.params, "clue": result.clue},
                        subgraph_anchor=current_task.subgraph_anchor,
                        phase=current_task.phase,
                        retries=retries,
                    )

        new_results: list[ExecutorResult] = await scheduler.dispatch(
            tasks, _execute
        )
        # ``results`` has operator.add as reducer → appended
        return {"results": new_results}

    # ------------------------------------------------------------------
    # Node: merge
    # Write all executor deltas back through MemoryAPI (Invariant 1).
    # ------------------------------------------------------------------
    async def merge(state: TurnState) -> dict[str, Any]:
        for result in state["results"]:
            for node in result.node_deltas:
                await api.upsert_node(node)
            for edge in result.edge_deltas:
                await api.upsert_edge(edge)
            await api.append_episode(result.episode)
            for ke in result.proposed_knowledge:
                await api.propose_knowledge(ke)
            for sk in result.proposed_skills:
                await api.propose_skill(sk)
        return {}

    # ------------------------------------------------------------------
    # Routing: after plan, abandon or continue to dispatch?
    # ------------------------------------------------------------------
    def route_after_plan(state: TurnState) -> str:
        return END if state["abandoned"] else "dispatch"

    # ------------------------------------------------------------------
    # Compile
    # ------------------------------------------------------------------
    builder: Any = StateGraph(TurnState)

    builder.add_node("read_context", read_context)
    builder.add_node("plan", plan)
    builder.add_node("dispatch", dispatch)
    builder.add_node("merge", merge)

    builder.add_edge(START, "read_context")
    builder.add_edge("read_context", "plan")
    builder.add_conditional_edges(
        "plan",
        route_after_plan,
        {"dispatch": "dispatch", END: END},
    )
    builder.add_edge("dispatch", "merge")
    builder.add_edge("merge", END)

    return builder.compile(checkpointer=checkpointer)
