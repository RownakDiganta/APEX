# graph_state.py
# ApexGraphState TypedDict holding only JSON-serializable engagement fields for the APEX LangGraph; no infrastructure objects in state payloads.
"""ApexGraphState TypedDict for the APEX multi-phase engagement LangGraph.

This is a **separate** state shape from memfabric.coordination.graph_state.
TurnState — see CLAUDE.md Section 11.3 for why apex_host needs its own
StateGraph. State holds ONLY JSON-serializable primitives: MemoryAPI, the
tool registry, executors, planners, and LLM client objects are injected via
closures in graph.build_apex_graph(); they must NEVER appear as state
payloads (mirrors memfabric Invariant 1 and Invariant 7).
"""
from __future__ import annotations

import operator
from typing import Annotated, Any

from typing_extensions import TypedDict


class ApexGraphState(TypedDict):
    """Checkpoint-serialisable state for one APEX engagement run.

    ``findings`` uses ``operator.add`` so each turn's parse_observation node
    appends rather than replaces. Every other field is overwritten per turn —
    this is intentional: context is retrieved and scoped fresh each turn
    (memfabric Invariant 5), never accumulated.
    """

    run_id: str
    target: str
    phase: str
    goal: str
    current_task: dict[str, Any] | None
    evidence_summary: str
    findings: Annotated[list[dict[str, Any]], operator.add]
    last_tool_result: dict[str, Any] | None
    last_error: str | None
    completed: bool
    turn_count: int


CompiledApexGraph = Any
