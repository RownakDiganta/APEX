# recon_planner.py
# Deterministic two-phase recon planner with an optional PlanningEngine LLM seam.
"""Deterministic recon-phase planner with optional LLM backend.

``_ReconDeterministic`` contains the original rule-based logic — two phases
driven entirely by the SubgraphView passed in, no direct MemoryAPI calls
(blackboard model, Invariant 7).

``ReconPlanner`` is the public thin wrapper: when a ``model_router`` is
provided it constructs a ``PlanningEngine`` and routes through it; otherwise
it delegates directly to ``_ReconDeterministic``.  The public ``plan()``
signature is identical in both cases so ``graph.py`` needs no changes.

Two-phase deterministic logic:

Phase 1 — no service nodes in subgraph:
    Emit one ``nmap -sV -T4 -Pn <target>`` TaskSpec.

Phase 2 — service nodes exist:
    Derive capabilities from the subgraph via ``capabilities_from_subgraph``
    and emit up to _MAX_BANNER_TASKS nc banner-probe TaskSpecs for open TCP
    services that carry a probeable capability.  Falls back to another nmap
    if no suitable probe targets are found.

All emitted args are **complete** (target already included), so
``graph.py:_run_one_task`` never needs to append target separately.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from memfabric.ids import new_id, now
from memfabric.types import (
    AbandonSignal,
    ClaimDependency,
    EvidenceBundle,
    Goal,
    SubgraphView,
    TaskSpec,
)

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planning.models import PlanDecision
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.llm.gateway import LLMGateway
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.policy.llm_guard import LLMPolicyGuard
    from apex_host.planning.engine import PlanningEngine

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


class _ReconDeterministic:
    """Pure rule-based recon planner — the fallback for PlanningEngine."""

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
        host_node_id = f"host:{self._target}"
        return [
            TaskSpec(
                id=new_id(),
                goal_id=goal.id,
                executor_domain="recon",
                params={
                    "tool": "nmap",
                    # -Pn skips host-discovery ping — required on HTB networks
                    # where ICMP is blocked; without it nmap reports "host down"
                    # and exits with rc=1 even when the target is reachable.
                    "args": ["-sV", "-T4", "-Pn", self._target],
                    "target": self._target,
                    "parser": "nmap",
                },
                subgraph_anchor=goal.anchor_node,
                phase=goal.phase,
                # Nmap probes the host IP — depends on ip being undisputed.
                claim_dependencies=(
                    ClaimDependency(node_id=host_node_id, field_name="ip"),
                ),
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

        # Loop guard: skip services whose banner has already been captured.
        # A 'runs' edge from a service node to a tech node signals that
        # BannerParser (or NmapParser) already produced banner information for
        # that port — probing it again with nc would be redundant.
        services_with_tech: set[str] = {
            e.from_id for e in subgraph.edges if e.type == "runs"
        }

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
            # Skip services that already have tech/banner information.
            if cap.source_node_id in services_with_tech:
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
                    # Banner probe reads the port and state from the service node.
                    claim_dependencies=(
                        ClaimDependency(
                            node_id=cap.source_node_id, field_name="port"
                        ),
                        ClaimDependency(
                            node_id=cap.source_node_id, field_name="state"
                        ),
                    ),
                )
            )

        return tasks


class ReconPlanner:
    """Thin wrapper: routes through PlanningEngine when model_router is provided,
    falls back to _ReconDeterministic otherwise."""

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
        guard: "LLMPolicyGuard | None" = None,
        gateway: "LLMGateway | None" = None,
    ) -> None:
        self._core = _ReconDeterministic(target, registry)
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
                guard=guard,
                gateway=gateway,
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
            return await self._engine.plan(goal, ApexPhase.recon, subgraph, evidence)
        self._last_decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="deterministic",
            fallback_used=True,
            timestamp=now(),
            phase=ApexPhase.recon.value,
        )
        return await self._core.plan(goal, subgraph, evidence)
