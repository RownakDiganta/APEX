# protocols.py
# Executor, Parser, and Planner Protocol definitions and their deterministic test fakes (EchoExecutor, PassthroughParser, StaticPlanner) — the host-app extension seams.
"""Executor, Parser, Planner Protocols — the host-app extension seams.

The substrate defines these interfaces and ships ONLY deterministic test fakes.
Real executors/planners live in the host application and must never appear here.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from memfabric.ids import new_id
from memfabric.types import (
    AbandonSignal,
    Episode,
    EvidenceBundle,
    ExecutorResult,
    Goal,
    Outcome,
    ParsedObservation,
    RawObservation,
    SubgraphView,
    TaskSpec,
)


@runtime_checkable
class Executor(Protocol):
    """Stateless work unit.  Returns EKG deltas + an Episode."""
    domain: str

    async def run(
        self, task: TaskSpec, evidence: EvidenceBundle
    ) -> ExecutorResult: ...


@runtime_checkable
class Parser(Protocol):
    """Parse raw tool output into structured EKG deltas."""

    def parse(self, raw: RawObservation) -> ParsedObservation: ...


@runtime_checkable
class Planner(Protocol):
    """Decompose a goal into TaskSpecs or abandon."""

    async def plan(
        self,
        goal: Goal,
        subgraph: SubgraphView,
        evidence: EvidenceBundle,
    ) -> list[TaskSpec] | AbandonSignal: ...


# ---------------------------------------------------------------------------
# Test fakes (deterministic; used only in tests and the smoke run)
# ---------------------------------------------------------------------------

class EchoExecutor:
    """Deterministic executor: echoes task params back as episode data."""

    domain: str = "echo"

    async def run(
        self, task: TaskSpec, evidence: EvidenceBundle
    ) -> ExecutorResult:
        episode = Episode(
            agent=self.domain,
            action=task.params.get("action", "echo"),
            outcome=Outcome(task.params.get("outcome", Outcome.success.value)),
            data={"task_id": task.id, "params": task.params, "echoed": True},
            task_id=task.id,
            phase=task.phase,
            chain_id=task.params.get("chain_id"),
        )
        return ExecutorResult(task_id=task.id, episode=episode)


class PassthroughParser:
    """Trivial parser: returns empty deltas (real parsers live in host app)."""

    def parse(self, raw: RawObservation) -> ParsedObservation:
        return ParsedObservation()


class StaticPlanner:
    """Deterministic planner: emits a pre-configured list of TaskSpecs.

    Pass ``tasks`` at construction; ``plan()`` returns them unchanged.
    Pass ``abandon=True`` to always emit an AbandonSignal instead.
    """

    def __init__(
        self,
        tasks: list[TaskSpec] | None = None,
        *,
        abandon: bool = False,
        abandon_reason: str = "no tasks",
    ) -> None:
        self._tasks: list[TaskSpec] = tasks or []
        self._abandon = abandon
        self._reason = abandon_reason

    async def plan(
        self,
        goal: Goal,
        subgraph: SubgraphView,
        evidence: EvidenceBundle,
    ) -> list[TaskSpec] | AbandonSignal:
        if self._abandon:
            return AbandonSignal(reason=self._reason)
        # Attach goal_id if not already set
        return [
            TaskSpec(
                id=t.id or new_id(),
                goal_id=goal.id,
                executor_domain=t.executor_domain,
                params=t.params,
                subgraph_anchor=t.subgraph_anchor or goal.anchor_node,
                phase=t.phase or goal.phase,
                retries=t.retries,
            )
            for t in self._tasks
        ]
