# priv_esc_planner.py
# Deterministic privilege-escalation-phase planner with an optional PlanningEngine LLM seam.
"""Deterministic privilege-escalation-phase planner with optional LLM backend.

``_PrivEscDeterministic`` contains the original rule-based logic — safe,
read-only local enumeration via searchsploit lookups against already-known
service/version strings. No privilege-escalation attempts, no destructive
commands.

``PrivEscPlanner`` is the public thin wrapper: when a ``model_router`` is
provided it constructs a ``PlanningEngine`` and routes through it; otherwise
it delegates directly to ``_PrivEscDeterministic``.

"Do not make autonomous high-risk exploit decisions yet" applies here most
strongly: this planner only ever proposes enumeration.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from memfabric.ids import new_id, now
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planning.models import PlanDecision
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.planning.engine import PlanningEngine


class _PrivEscDeterministic:
    """Pure rule-based priv-esc planner — the fallback for PlanningEngine."""

    def __init__(self, target: str, registry: ToolRegistry) -> None:
        self._target = target
        self._registry = registry

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        if self._registry.get("searchsploit") is None:
            return AbandonSignal(reason="searchsploit not available in allowed_tools")

        # Use the capability layer to find services with known version strings.
        # Service classification lives in capabilities.py — not here.
        caps = capabilities_from_subgraph(subgraph)
        research = [c for c in caps if c.name == "exploit_research"]
        if not research:
            return AbandonSignal(reason="no enumerable service/version strings")

        node_by_id = {n.id: n for n in subgraph.nodes}
        tasks: list[TaskSpec] = []
        for cap in research[:3]:
            node = node_by_id.get(cap.source_node_id)
            if node is None:
                continue
            version = str(node.props.get("version", "")).strip()
            query = f"{cap.service} {version}".strip()
            if not query:
                continue
            tasks.append(
                TaskSpec(
                    id=new_id(),
                    goal_id=goal.id,
                    executor_domain="priv_esc",
                    params={
                        "tool": "searchsploit",
                        "args": [query],
                        "target": self._target,
                        "parser": "command",
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                )
            )

        if not tasks:
            return AbandonSignal(reason="no enumerable service/version strings")
        return tasks


class PrivEscPlanner:
    """Thin wrapper: routes through PlanningEngine when model_router is provided,
    falls back to _PrivEscDeterministic otherwise."""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        *,
        model_router: "ModelRouter | None" = None,
        allowed_tools: list[str] | None = None,
        confidence_threshold: float = 0.4,
        max_retries: int = 1,
        budget_tracker: "LLMBudgetTracker | None" = None,
    ) -> None:
        self._core = _PrivEscDeterministic(target, registry)
        self._engine: PlanningEngine | None = None
        self._last_decision: PlanDecision | None = None
        if model_router is not None:
            from apex_host.planning.engine import PlanningEngine as _PE
            tools = allowed_tools if allowed_tools is not None else registry.available()
            self._engine = _PE(
                model_router=model_router,
                fallback_planner=self._core,
                allowed_tools=tools,
                target=target,
                confidence_threshold=confidence_threshold,
                max_retries=max_retries,
                budget=budget_tracker,
            )

    @property
    def last_decision(self) -> PlanDecision | None:
        """Most recent ``PlanDecision`` from the last ``plan()`` call."""
        if self._engine is not None:
            return self._engine.last_decision
        return self._last_decision

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        if self._engine is not None:
            return await self._engine.plan(goal, ApexPhase.priv_esc, subgraph, evidence)
        self._last_decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="deterministic",
            fallback_used=True,
            timestamp=now(),
            phase=ApexPhase.priv_esc.value,
        )
        return await self._core.plan(goal, subgraph, evidence)
