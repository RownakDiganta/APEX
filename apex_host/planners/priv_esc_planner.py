# priv_esc_planner.py
# Deterministic privilege-escalation-phase planner that emits read-only searchsploit enumeration tasks against known service/version strings without any exploit execution.
"""Deterministic privilege-escalation-phase planner.

Implements memfabric.coordination.protocols.Planner. Emits only safe,
read-only local enumeration via searchsploit lookups against already-known
service/version strings — no privilege-escalation attempts, no destructive
commands. "Do not make autonomous high-risk exploit decisions yet" applies
here most strongly: this planner only ever proposes enumeration.
"""
from __future__ import annotations

from memfabric.ids import new_id
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.tools.registry import ToolRegistry


class PrivEscPlanner:
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
