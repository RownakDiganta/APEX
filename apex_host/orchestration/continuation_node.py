# continuation_node.py
# Factory for the reflect_or_continue LangGraph node: dynamic replanning and turn counter.
"""Continuation node factory for the APEX orchestration layer.

``make_continuation_node`` returns the ``reflect_or_continue`` async
LangGraph node.  After each turn it:

1. Increments the turn counter and checks the max-turns ceiling.
2. Checks for an ``access_state`` node in the EKG — if found, the primary
   objective is achieved and the engagement stops early.
3. Peeks at the live EKG to derive the most accurate next-phase value
   without charging the GlobalPlanner budget (``global_plan`` charges the
   budget at the start of the next turn).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.completion import should_complete
from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps

logger = logging.getLogger(__name__)


def make_continuation_node(deps: "OrchestrationDeps") -> Any:
    """Return the ``reflect_or_continue`` async node bound to *deps*."""

    async def reflect_or_continue(state: "ApexGraphState") -> dict[str, Any]:
        turn_count = state["turn_count"] + 1
        completed = should_complete(state, deps.config.max_turns)

        next_phase_value = state["phase"]
        if not completed:
            try:
                subgraph = await deps.api.get_subgraph(deps.anchor_id, depth=2)
                node_types_seen = {n.type for n in subgraph.nodes}

                # Early stop: successful login was recorded — primary objective achieved.
                if "access_state" in node_types_seen:
                    logger.info(
                        "access_state in EKG after turn %d — engagement succeeded, stopping early",
                        turn_count,
                    )
                    return {
                        "turn_count": turn_count, "completed": True,
                        "phase": ApexPhase.done.value, "repair_count": 0,
                    }

                peek_caps = capabilities_from_subgraph(subgraph)
                has_web_peek = any(c.name == "web_probe" for c in peek_caps)
                # F08: pass current_phase so budget force-advance fires correctly
                # during the inter-turn peek (without charging the budget counter).
                next_phase = deps.global_planner.decide_phase(
                    node_types_seen=node_types_seen,
                    turn_count=turn_count,
                    has_web_capability=has_web_peek,
                    current_phase=state.get("phase"),
                )
                next_phase_value = next_phase.value
            except Exception as exc:
                logger.debug("reflect_or_continue: dynamic replan peek failed (%s)", exc)

        return {
            "turn_count": turn_count, "completed": completed,
            "phase": next_phase_value, "repair_count": 0,
        }

    return reflect_or_continue
