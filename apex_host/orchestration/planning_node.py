# planning_node.py
# Factory for the global_plan LangGraph node: decides phase and goal for the turn.
"""Global-planning node factory for the APEX orchestration layer.

``make_global_plan_node`` returns the ``global_plan`` async function that is
registered as the second LangGraph node in every engagement turn.  It consults
``GlobalPlanner.decide_phase`` based on the live EKG subgraph, records the
turn against the per-phase budget, and writes the decided phase and goal into
state.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from apex_host.graph_state import ApexGraphState
from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planners.objective import objective_status_from_subgraph
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps


def make_global_plan_node(
    deps: "OrchestrationDeps",
) -> Any:
    """Return the ``global_plan`` async node function bound to *deps*."""

    async def global_plan(state: "ApexGraphState") -> dict[str, Any]:
        subgraph = await deps.api.get_subgraph(deps.anchor_id, depth=3)
        node_types_seen = {n.type for n in subgraph.nodes}
        caps = capabilities_from_subgraph(subgraph)
        has_web = any(c.name == "web_probe" for c in caps)
        objective_status = objective_status_from_subgraph(
            subgraph, deps.config.target, deps.config.objective_type
        )

        phase = deps.global_planner.decide_phase(
            node_types_seen=node_types_seen,
            turn_count=state["turn_count"],
            current_phase=state.get("phase"),
            has_web_capability=has_web,
            objective_status=objective_status,
        )
        if phase != ApexPhase.done:
            deps.global_planner.record_turn(phase)

        goal_text = deps.global_planner.goal_for_phase(phase, deps.config.target)
        return {
            "phase": phase.value,
            "goal": goal_text,
            "completed": phase == ApexPhase.done,
        }

    return global_plan
