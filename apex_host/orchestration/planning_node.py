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
from apex_host.orchestration.outcome import EngagementOutcome
from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planners.objective import objective_reopening_eligible, objective_status_from_subgraph
from apex_host.planners.phase_gates import credential_hypothesis, web_evidence_status
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps


def _phase_reason(phase: "ApexPhase", hypothesis: Any, web_evidence: Any, has_web: bool) -> str:
    """A short, secret-free explanation of why *phase* was selected — the
    prerequisite that made it actionable, or why an alternative was unavailable."""
    if phase == ApexPhase.web:
        return f"web discovery incomplete ({web_evidence.reason})"
    if phase == ApexPhase.credential:
        return f"credential hypothesis available ({hypothesis.source})"
    if phase == ApexPhase.done and not hypothesis.available:
        # Reached done without access and without a credential hypothesis: the
        # credential phase was unavailable for a typed reason.
        return f"no actionable phase: {hypothesis.reason}"
    return f"selected {phase.value}"


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
        objective_reopened = objective_reopening_eligible(
            subgraph, deps.config.target, deps.config.objective_type
        )

        # Evidence gates (apex_host.planners.phase_gates): whether an actionable
        # credential hypothesis exists (never merely a capability), and whether
        # web discovery has produced meaningful evidence.
        has_operator_credentials = bool(
            deps.config.username_candidates and deps.config.password_candidates
        )
        hypothesis = credential_hypothesis(
            subgraph,
            has_operator_credentials=has_operator_credentials,
            allow_default_credentials=bool(getattr(deps.config, "allow_default_credentials", False)),
        )
        web_evidence = web_evidence_status(subgraph, has_web_capability=has_web)

        phase = deps.global_planner.decide_phase(
            node_types_seen=node_types_seen,
            turn_count=state["turn_count"],
            current_phase=state.get("phase"),
            has_web_capability=has_web,
            has_credential_hypothesis=hypothesis.available,
            web_evidence_complete=web_evidence.complete,
            objective_status=objective_status,
            objective_reopened=objective_reopened,
        )
        if phase != ApexPhase.done:
            deps.global_planner.record_turn(phase)

        goal_text = deps.global_planner.goal_for_phase(phase, deps.config.target)
        result: dict[str, Any] = {
            "phase": phase.value,
            "goal": goal_text,
            "completed": phase == ApexPhase.done,
            # Secret-free record of WHY this phase was selected (see
            # ApexGraphState.phase_selection). credential_source is a label
            # (operator_supplied / discovered_evidence / ...), never a value.
            "phase_selection": {
                "phase": phase.value,
                "reason": _phase_reason(phase, hypothesis, web_evidence, has_web),
                "has_credential_hypothesis": hypothesis.available,
                "credential_source": hypothesis.source,
                "credential_reason": hypothesis.reason,
                "web_evidence_complete": web_evidence.complete,
                "web_reason": web_evidence.reason,
            },
        }

        # If the router terminated because NO phase is actionable (no access
        # and no credential hypothesis, with a real service present and turns
        # remaining), set a precise, truthful upstream outcome. reflect_or_
        # continue (precedence level 2) picks this up and writes the canonical
        # terminal episode — a truthful terminal decision with a typed reason,
        # never a fabricated phase/finding/success.
        has_access = (
            "access_state" in node_types_seen or "access_capability" in node_types_seen
        )
        if (
            phase == ApexPhase.done
            and not has_access
            and not hypothesis.available
            and "service" in node_types_seen
            and state["turn_count"] < deps.config.max_turns
        ):
            result["outcome"] = EngagementOutcome.no_actionable_task.value
            result["termination_reason"] = f"no actionable phase: {hypothesis.reason}"
            result["termination_phase"] = ApexPhase.credential.value

        return result

    return global_plan
