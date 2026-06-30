"""Deterministic web-phase planner.

Implements memfabric.coordination.protocols.Planner. Emits safe endpoint
probing tasks (ffuf directory discovery + a single curl probe). Does not
emit any payload/exploit tasks — payload knowledge retrieval already
happened upstream via MemoryAPI.query() into the EvidenceBundle this
planner receives; it does not query MemoryAPI itself (planners only see
what's handed to them, consistent with the blackboard model).
"""
from __future__ import annotations

from memfabric.ids import new_id
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.tools.registry import ToolRegistry


def _base_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


class WebPlanner:
    def __init__(self, target: str, registry: ToolRegistry) -> None:
        self._target = target
        self._registry = registry

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        base_url = _base_url(self._target)
        tasks: list[TaskSpec] = []

        if self._registry.get("ffuf") is not None:
            tasks.append(
                TaskSpec(
                    id=new_id(),
                    goal_id=goal.id,
                    executor_domain="web",
                    params={
                        "tool": "ffuf",
                        "args": ["-u", f"{base_url}/FUZZ", "-w", "wordlist.txt"],
                        "target": base_url,
                        "parser": "ffuf",
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                )
            )

        if self._registry.get("curl") is not None:
            tasks.append(
                TaskSpec(
                    id=new_id(),
                    goal_id=goal.id,
                    executor_domain="web",
                    params={
                        "tool": "curl",
                        "args": ["-s", "-I", base_url],
                        "target": base_url,
                        "parser": "command",
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                )
            )

        if not tasks:
            return AbandonSignal(reason="no web-capable tools in allowed_tools")
        return tasks
