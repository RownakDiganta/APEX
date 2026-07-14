# builder.py
# build_apex_graph: thin orchestrator that wires the APEX LangGraph from focused node factories.
"""Thin orchestration builder for the APEX engagement StateGraph.

``build_apex_graph`` has the same public signature as the original monolithic
function in ``apex_host/graph.py``.  All node implementations live in the
sibling modules; this file only wires them together into a compiled StateGraph.

The function is re-exported from ``apex_host.graph`` so existing callers are
unaffected by the decomposition.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from langgraph.graph import END, START, StateGraph

from apex_host.graph_ids import host_id as _host_id
from apex_host.graph_state import ApexGraphState, CompiledApexGraph
from apex_host.orchestration.context_node import make_context_node
from apex_host.orchestration.continuation_node import make_continuation_node
from apex_host.orchestration.dependencies import OrchestrationDeps, build_planners
from apex_host.orchestration.dispatch_node import (
    make_browser_node,
    make_execute_node,
    make_priv_esc_node,
    make_recon_node,
    make_web_node,
)
from apex_host.orchestration.memory_node import make_memory_node
from apex_host.orchestration.parsing_node import make_parsing_node
from apex_host.orchestration.planning_node import make_global_plan_node
from apex_host.orchestration.repair_node import make_repair_node
from apex_host.orchestration.routing import (
    route_after_global_plan,
    route_after_reflect,
    route_after_write,
)
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.policy import PolicyAdvisor, load_policy
from apex_host.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from apex_host.config import ApexConfig
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.tools.backend import ToolBackend
    from memfabric.api import MemoryAPI

logger = logging.getLogger(__name__)


def _build_llm_components(
    model_router: "ModelRouter | None",
    config: "ApexConfig",
    budget_tracker: "LLMBudgetTracker | None",
) -> tuple[Any, Any]:
    """Construct LLMPolicyGuard + LLMGateway when a real router is supplied."""
    if model_router is None:
        return None, None
    from apex_host.llm.gateway import LLMGateway
    from apex_host.policy.llm_guard import LLMPolicyGuard as _Guard
    llm_guard = None
    try:
        llm_guard = _Guard(config)
    except Exception as exc:
        if getattr(config, "use_llm", False):
            raise RuntimeError(
                f"LLMPolicyGuard construction failed with use_llm=True: {exc}"
            ) from exc
        logger.warning("LLMPolicyGuard construction failed (use_llm=False): %s", exc)
    gateway = LLMGateway(model_router=model_router, budget=budget_tracker, guard=llm_guard)
    return llm_guard, gateway


def build_apex_graph(
    api: "MemoryAPI",
    registry: ToolRegistry,
    config: "ApexConfig",
    *,
    checkpointer: Any | None = None,
    model_router: "ModelRouter | None" = None,
    advisor: "PolicyAdvisor | None" = None,
    budget_tracker: "LLMBudgetTracker | None" = None,
    tool_backend: "ToolBackend | None" = None,
) -> CompiledApexGraph:
    """Compile and return the APEX engagement StateGraph.

    Public signature is backward compatible with ``apex_host/graph.py``: all
    prior parameters are unchanged, and the new ``tool_backend`` parameter is
    optional and defaults to ``None``, which preserves the exact prior
    behavior (subprocess execution via ``apex_host.tools.runner.run_command``).
    The implementation delegates to node factories in the orchestration package.

    ``tool_backend`` (Infra Phase 2 — see ``docs/tool-execution-architecture.md``):
    when provided, ``TaskDispatcher`` calls this ``ToolBackend`` (via
    ``apex_host.tools.backend.to_run_command_fn``) instead of the default
    ``run_command``. This is a narrow, opt-in seam — it does not change
    default behavior and does not itself read ``config.tool_backend``
    (callers construct the backend explicitly, e.g. via
    ``apex_host.tools.backend.select_tool_backend(config)``, and pass it
    here). Policy approval in ``TaskDispatcher.dispatch()`` runs identically
    regardless of which backend is supplied — this parameter only replaces
    *how* an already-approved command is executed, never whether it is
    approved.
    """
    from apex_host.agents.browser_executor import BrowserExecutor
    from apex_host.agents.telnet_executor import TelnetExecutor
    from apex_host.execution.dispatcher import TaskDispatcher
    from apex_host.execution.registry import TaskRegistry
    from apex_host.planning.repair import RepairEngine

    if advisor is None:
        advisor = PolicyAdvisor(load_policy(config), config)

    if tool_backend is not None:
        from apex_host.tools.backend import to_run_command_fn

        run_command_fn = to_run_command_fn(tool_backend)
    else:
        from apex_host.tools.runner import run_command

        run_command_fn = run_command

    llm_guard, llm_gateway = _build_llm_components(model_router, config, budget_tracker)
    phase_planners = build_planners(
        config, registry,
        model_router=model_router, budget_tracker=budget_tracker,
        llm_guard=llm_guard, llm_gateway=llm_gateway,
    )
    telnet_executor = TelnetExecutor(config)
    browser_executor = BrowserExecutor(config)
    repair_engine = RepairEngine(
        model_router=model_router, allowed_tools=config.allowed_tools,
        target=config.target, dry_run=config.dry_run,
        budget_tracker=budget_tracker, guard=llm_guard, gateway=llm_gateway,
    )
    task_registry = TaskRegistry()
    dispatcher = TaskDispatcher(
        advisor=advisor, task_registry=task_registry, config=config,
        run_command_fn=run_command_fn,
        telnet_executor=telnet_executor, browser_executor=browser_executor,
    )
    _max_repair = getattr(config, "max_repair_attempts", 1)

    deps = OrchestrationDeps(
        api=api, dispatcher=dispatcher,
        global_planner=GlobalPlanner(max_turns=config.max_turns),
        phase_planners=phase_planners,
        repair_engine=repair_engine, config=config,
        anchor_id=_host_id(config.target),
    )

    # Node instantiation
    sg: Any = StateGraph(ApexGraphState)
    sg.add_node("load_context", make_context_node(deps))
    sg.add_node("global_plan", make_global_plan_node(deps))
    sg.add_node("recon_agent", make_recon_node(deps))
    sg.add_node("web_agent", make_web_node(deps))
    sg.add_node("browser_agent", make_browser_node(deps))
    sg.add_node("execute_agent", make_execute_node(deps))
    sg.add_node("priv_esc_agent", make_priv_esc_node(deps))
    sg.add_node("parse_observation", make_parsing_node(deps))
    sg.add_node("write_memory", make_memory_node(deps))
    sg.add_node("repair_agent", make_repair_node(deps))
    sg.add_node("reflect_or_continue", make_continuation_node(deps))

    # Edges
    sg.add_edge(START, "load_context")
    sg.add_edge("load_context", "global_plan")
    sg.add_conditional_edges(
        "global_plan", route_after_global_plan,
        {
            "recon_agent": "recon_agent", "web_agent": "web_agent",
            "browser_agent": "browser_agent", "execute_agent": "execute_agent",
            "priv_esc_agent": "priv_esc_agent", END: END,
        },
    )
    for _an in ("recon_agent", "web_agent", "browser_agent", "execute_agent", "priv_esc_agent"):
        sg.add_edge(_an, "parse_observation")
    sg.add_edge("parse_observation", "write_memory")
    sg.add_conditional_edges(
        "write_memory",
        lambda s: route_after_write(s, _max_repair),
        {"repair_agent": "repair_agent", "reflect_or_continue": "reflect_or_continue"},
    )
    sg.add_edge("repair_agent", "reflect_or_continue")
    sg.add_conditional_edges(
        "reflect_or_continue", route_after_reflect,
        {"load_context": "load_context", END: END},
    )
    return sg.compile(checkpointer=checkpointer)
