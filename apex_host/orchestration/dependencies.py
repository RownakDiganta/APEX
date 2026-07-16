# dependencies.py
# OrchestrationDeps frozen dataclass and planner-builder factory for the APEX loop.
"""Service-container for the APEX orchestration layer.

``OrchestrationDeps`` is the single typed object passed into every node
factory function.  It holds all non-state services (MemoryAPI, dispatcher,
planners, config …) that are captured by the LangGraph node closures.
Nothing in ``OrchestrationDeps`` is ever stored in ``ApexGraphState``.

``build_planners`` constructs the four phase-planner instances from an
``ApexConfig`` and optional LLM components.  Separating this factory from
``build_apex_graph`` keeps ``builder.py`` within its 100-line target.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.config import ApexConfig
    from apex_host.execution.dispatcher import TaskDispatcher
    from apex_host.llm.gateway import LLMGateway
    from apex_host.orchestration.stall import StallTracker
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.planning.repair import RepairEngine
    from apex_host.planners.global_planner import GlobalPlanner
    from apex_host.policy.llm_guard import LLMPolicyGuard
    from apex_host.tools.registry import ToolRegistry
    from memfabric.api import MemoryAPI
    from memfabric.coordination.protocols import Planner


@dataclass(slots=True, frozen=True)
class OrchestrationDeps:
    """Typed container for all non-state services used by orchestration nodes."""

    api: "MemoryAPI"
    dispatcher: "TaskDispatcher"
    global_planner: "GlobalPlanner"
    phase_planners: dict[str, "Planner"]
    repair_engine: "RepairEngine"
    config: "ApexConfig"
    anchor_id: str
    # Phase 12C — bounded stall detector, one instance per engagement.
    # Mutated turn-over-turn by reflect_or_continue; not stored in
    # ApexGraphState (mirrors GlobalPlanner's own _spent budget counters —
    # see apex_host/orchestration/stall.py's module docstring).
    stall_tracker: "StallTracker"


def build_planners(
    config: "ApexConfig",
    registry: "ToolRegistry",
    *,
    model_router: Any | None = None,
    budget_tracker: "LLMBudgetTracker | None" = None,
    llm_guard: "LLMPolicyGuard | None" = None,
    llm_gateway: "LLMGateway | None" = None,
) -> dict[str, "Planner"]:
    """Construct the phase-planner instances for an engagement.

    Includes a ``"browser"`` entry (Phase 14) alongside the four
    ``ApexPhase``-keyed entries — ``make_browser_node`` looks this up by the
    plain string key ``"browser"`` since the browser agent is a distinct
    graph node from ``web_agent`` even though both execute during the
    ``web`` phase (see ``apex_host/orchestration/routing.py``).
    """
    from apex_host.planners.browser_planner import BrowserPlanner
    from apex_host.planners.credential_planner import CredentialPlanner
    from apex_host.planners.priv_esc_planner import PrivEscPlanner
    from apex_host.planners.recon_planner import ReconPlanner
    from apex_host.planners.web_planner import WebPlanner

    _ct = getattr(config, "planning_confidence_threshold", 0.4)
    _mr = getattr(config, "max_planning_retries", 1)
    _mr_arg = model_router  # convenience alias
    _at = config.allowed_tools if _mr_arg else None

    def _kwargs(**extra: Any) -> dict[str, Any]:
        return dict(
            model_router=_mr_arg,
            allowed_tools=_at,
            confidence_threshold=_ct,
            max_retries=_mr,
            budget_tracker=budget_tracker,
            guard=llm_guard,
            gateway=llm_gateway,
            **extra,
        )

    return {
        ApexPhase.recon.value: ReconPlanner(config.target, registry, **_kwargs()),
        ApexPhase.web.value: WebPlanner(
            config.target,
            registry,
            web_wordlist_path=config.web_wordlist_path,
            max_web_paths=config.max_web_paths,
            **_kwargs(),
        ),
        ApexPhase.credential.value: CredentialPlanner(
            config.target,
            registry,
            username_candidates=config.username_candidates,
            password_candidates=config.password_candidates,
            max_access_attempts=config.max_access_attempts,
            **_kwargs(),
        ),
        ApexPhase.priv_esc.value: PrivEscPlanner(
            config.target,
            registry,
            username_candidates=config.username_candidates,
            password_candidates=config.password_candidates,
            **_kwargs(),
        ),
        "browser": BrowserPlanner(config.target, registry, **_kwargs()),
    }
