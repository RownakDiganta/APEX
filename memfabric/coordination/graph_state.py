# graph_state.py
# TurnState TypedDict and operator.add/merge reducers for the LangGraph coordination loop; holds only generic substrate types, never infrastructure objects.
"""TurnState TypedDict and its field reducers for the LangGraph coordination loop.

State holds ONLY generic substrate types.  MemoryAPI, Scheduler, Executors,
and Planner are injected via closures in graph_loop.build_graph(); they must
NEVER appear as state payloads (Invariant 7 — blackboard, no agent-to-agent
objects; Invariant 1 — MemoryAPI is the sole state surface).

Reducers follow the LangGraph convention: the second element of an Annotated
type is the merge function applied when a node returns a partial state update.
"""
from __future__ import annotations

import operator
from typing import Annotated, Any

from typing_extensions import TypedDict

from memfabric.types import (
    EvidenceBundle,
    ExecutorResult,
    Goal,
    SubgraphView,
    TaskSpec,
)


def _merge_retry_counts(
    a: dict[str, int], b: dict[str, int]
) -> dict[str, int]:
    """Reducer: merge retry-count dicts, keeping the maximum for each key."""
    merged = dict(a)
    for k, v in b.items():
        merged[k] = max(merged.get(k, 0), v)
    return merged


class TurnState(TypedDict):
    """Checkpoint-serialisable state for one orchestrator turn.

    All fields contain only generic substrate types so the checkpoint is
    domain-agnostic and can be stored/resumed without any host-app objects.

    Field reducers (Annotated second argument):
    - ``tasks``       : lists are concatenated across node updates
    - ``results``     : lists are concatenated across node updates
    - ``retry_counts``: dicts are merged; larger retry count wins per key
    """

    goal: Goal
    """The high-level objective being pursued this turn."""

    subgraph: SubgraphView | None
    """Scoped EKG neighbourhood around the goal anchor (populated by read_context)."""

    evidence: EvidenceBundle | None
    """Fused retrieval context for the planner (populated by read_context)."""

    tasks: Annotated[list[TaskSpec], operator.add]
    """TaskSpecs emitted by the planner; appended across node invocations."""

    results: Annotated[list[ExecutorResult], operator.add]
    """ExecutorResults gathered by dispatch; appended across node invocations."""

    abandoned: bool
    """True iff the planner emitted an AbandonSignal."""

    abandon_reason: str
    """Human-readable reason from the AbandonSignal (empty string otherwise)."""

    retry_counts: Annotated[dict[str, int], _merge_retry_counts]
    """Per-task retry counter; used by dispatch for bounded retry accounting."""


# Convenience: a type alias for the compiled graph so callers can annotate
# without importing LangGraph types directly.
CompiledTurnGraph = Any
