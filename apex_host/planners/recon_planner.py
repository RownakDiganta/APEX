"""Deterministic recon-phase planner.

Implements memfabric.coordination.protocols.Planner. Emits exactly one safe
enumeration TaskSpec per turn for the recon executor. Rule-based today, with
a clean seam (swap construction for an LLM-backed planner later) — it does
not make autonomous high-risk exploit decisions.
"""
from __future__ import annotations

from memfabric.ids import new_id
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.tools.registry import ToolRegistry


class ReconPlanner:
    def __init__(self, target: str, registry: ToolRegistry) -> None:
        self._target = target
        self._registry = registry

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        if self._registry.get("nmap") is None:
            return AbandonSignal(reason="nmap not available in allowed_tools")

        return [
            TaskSpec(
                id=new_id(),
                goal_id=goal.id,
                executor_domain="recon",
                params={
                    "tool": "nmap",
                    "args": ["-T4", "-sV"],
                    "target": self._target,
                },
                subgraph_anchor=goal.anchor_node,
                phase=goal.phase,
            )
        ]
