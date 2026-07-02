# recon_planner.py
# Deterministic two-phase recon planner: nmap enumeration when no services are known, nc banner probes when services are already in the EKG.
"""Deterministic recon-phase planner.

Implements memfabric.coordination.protocols.Planner.  Two-phase logic
driven entirely by the SubgraphView passed in — no direct MemoryAPI
calls, consistent with the blackboard model (Invariant 7):

Phase 1 — no service nodes in subgraph:
    Emit one ``nmap -sV -T4 <target>`` TaskSpec.

Phase 2 — service nodes exist:
    Derive capabilities from the subgraph via ``capabilities_from_subgraph``
    and emit up to _MAX_BANNER_TASKS nc banner-probe TaskSpecs for open TCP
    services that carry a probeable capability.  Falls back to another nmap
    if no suitable probe targets are found.

All emitted args are **complete** (target already included), so
``graph.py:_run_one_task`` never needs to append target separately.
"""
from __future__ import annotations

from memfabric.ids import new_id
from memfabric.types import (
    AbandonSignal,
    EvidenceBundle,
    Goal,
    SubgraphView,
    TaskSpec,
)

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.tools.registry import ToolRegistry

# Capability names that a raw nc banner probe is safe and informative for.
# All service-classification knowledge lives in capabilities.py; this set
# just maps capability names to the "nc-probeable" decision.
_BANNER_PROBE_CAPABILITIES: frozenset[str] = frozenset({
    "access_validate_ssh",
    "access_validate_telnet",
    "access_validate_ftp",
    "service_probe",
})
_MAX_BANNER_TASKS: int = 3


class ReconPlanner:
    def __init__(self, target: str, registry: ToolRegistry) -> None:
        self._target = target
        self._registry = registry

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        service_nodes = [n for n in subgraph.nodes if n.type == "service"]

        if not service_nodes:
            return self._nmap_task(goal)

        banner_tasks = self._banner_tasks(goal, subgraph)
        return banner_tasks if banner_tasks else self._nmap_task(goal)

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _nmap_task(self, goal: Goal) -> list[TaskSpec] | AbandonSignal:
        if self._registry.get("nmap") is None:
            return AbandonSignal(reason="nmap not available in allowed_tools")
        return [
            TaskSpec(
                id=new_id(),
                goal_id=goal.id,
                executor_domain="recon",
                params={
                    "tool": "nmap",
                    "args": ["-sV", "-T4", self._target],
                    "target": self._target,
                    "parser": "nmap",
                },
                subgraph_anchor=goal.anchor_node,
                phase=goal.phase,
            )
        ]

    def _banner_tasks(
        self, goal: Goal, subgraph: SubgraphView
    ) -> list[TaskSpec]:
        nc_tool = (
            "nc" if self._registry.get("nc") is not None
            else "netcat" if self._registry.get("netcat") is not None
            else None
        )
        if nc_tool is None:
            return []

        # Derive probeable services via the capability layer — no scattered
        # service-name or port sets here; that knowledge lives in capabilities.py.
        caps = capabilities_from_subgraph(subgraph)
        probeable = [c for c in caps if c.name in _BANNER_PROBE_CAPABILITIES]

        tasks: list[TaskSpec] = []
        seen_ports: set[str] = set()

        for cap in probeable:
            if len(tasks) >= _MAX_BANNER_TASKS:
                break
            if not cap.port or cap.port in seen_ports:
                continue
            seen_ports.add(cap.port)
            tasks.append(
                TaskSpec(
                    id=new_id(),
                    goal_id=goal.id,
                    executor_domain="recon",
                    params={
                        "tool": nc_tool,
                        "args": ["-nv", self._target, cap.port],
                        "target": self._target,
                        "parser": "banner",
                        "port": cap.port,
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                )
            )

        return tasks
