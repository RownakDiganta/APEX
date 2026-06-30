"""Deterministic credential-phase planner.

Implements memfabric.coordination.protocols.Planner. Emits only a single
benign probe (HTTP HEAD via curl) against a known auth_flow endpoint — never
credential stuffing, brute force, or any submission of credential material.
Credential testing in the real sense is explicitly out of scope until a
future, more carefully scoped iteration.
"""
from __future__ import annotations

from memfabric.ids import new_id
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.tools.registry import ToolRegistry


class CredentialPlanner:
    def __init__(self, target: str, registry: ToolRegistry) -> None:
        self._target = target
        self._registry = registry

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        if self._registry.get("curl") is None:
            return AbandonSignal(reason="curl not available in allowed_tools")

        auth_nodes = [n for n in subgraph.nodes if n.type == "auth_flow"]
        if not auth_nodes:
            return AbandonSignal(reason="no known auth_flow endpoints")

        target_url = str(auth_nodes[0].props.get("url", self._target))
        return [
            TaskSpec(
                id=new_id(),
                goal_id=goal.id,
                executor_domain="credential",
                params={
                    "tool": "curl",
                    "args": ["-s", "-I", target_url],
                    "target": target_url,
                    "parser": "command",
                },
                subgraph_anchor=goal.anchor_node,
                phase=goal.phase,
            )
        ]
