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
from apex_host.orchestration.diagnostics_node import make_unknown_phase_node
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
    UNKNOWN_PHASE_NODE,
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
    prior parameters are unchanged. The implementation delegates to node
    factories in the orchestration package.

    ``tool_backend`` (Infra Phase 2 seam; Infra Phase 4 centralized default
    selection — see ``docs/tool-execution-architecture.md`` and
    ``docs/remote-tool-backend.md``):

    - When provided explicitly, ``TaskDispatcher`` calls this ``ToolBackend``
      (via ``apex_host.tools.backend.to_run_command_fn``) instead of any
      config-derived default. Tests and other direct callers that need a
      specific backend (e.g. a spy, or a real ``LocalToolBackend`` under a
      dry-run config) should keep injecting it this way.
    - When ``None`` (the default), the backend is derived centrally from
      *config* via ``apex_host.tools.backend.select_runtime_backend(config)``
      — this is what makes normal engagement construction (``apex_host.runtime.
      ApexRuntime.run()``, ``apex_host.eval.run_htb_local``) select the
      correct backend automatically without manual injection.
      ``select_runtime_backend`` enforces the binding safety invariant that
      ``config.dry_run=True`` always yields ``DryRunToolBackend`` regardless
      of ``config.tool_backend`` — see that function's docstring.
    - For the *unchanged* default configuration (``dry_run=True`` or
      ``dry_run=False`` with ``tool_backend="local"``, both true of a
      default-constructed ``ApexConfig``), the resulting behavior is
      identical to calling ``apex_host.tools.runner.run_command`` directly, as it always
      was — ``LocalToolBackend``/``DryRunToolBackend`` are thin wrappers
      around exactly that function.
    - **Lifecycle note:** when this function constructs the backend
      internally (``tool_backend=None`` and ``config.tool_backend="remote"``
      with ``dry_run=False``), the resulting ``RemoteToolBackend`` owns an
      ``httpx.AsyncClient`` that this function does not close — callers who
      want managed lifecycle (client construction *and* ``aclose()`` after
      the run) should use ``apex_host.runtime.ApexRuntime.run()``, which
      constructs the backend explicitly and closes it in a ``finally``
      block. Direct ``build_apex_graph()`` callers that end up with a
      lazily-constructed remote backend and care about clean shutdown
      should inject ``tool_backend=`` explicitly instead and manage its
      ``aclose()`` themselves.

    Policy approval in ``TaskDispatcher.dispatch()`` runs identically
    regardless of which backend is supplied — this parameter only replaces
    *how* an already-approved generic command executes, never whether it is
    approved. ``TelnetExecutor``, ``BrowserExecutor``, and (Phase 12B)
    ``SSHExecutor``/``FTPExecutor`` are all unaffected by ``tool_backend``
    entirely — each is wired into ``TaskDispatcher`` through its own
    dedicated constructor parameter and is never routed through
    ``run_command_fn`` (see ``docs/remote-tool-backend.md`` "Generic versus
    interactive routing" and ``docs/credential-validation.md``).
    """
    from apex_host.agents.browser_executor import BrowserExecutor
    from apex_host.agents.ftp_executor import FTPExecutor
    from apex_host.agents.ssh_executor import SSHExecutor
    from apex_host.agents.telnet_executor import TelnetExecutor
    from apex_host.execution.dispatcher import TaskDispatcher
    from apex_host.execution.registry import TaskRegistry
    from apex_host.planning.repair import RepairEngine
    from apex_host.tools.backend import select_runtime_backend, to_run_command_fn

    if advisor is None:
        advisor = PolicyAdvisor(load_policy(config), config)

    if tool_backend is not None:
        run_command_fn = to_run_command_fn(tool_backend)
    else:
        run_command_fn = to_run_command_fn(select_runtime_backend(config))

    llm_guard, llm_gateway = _build_llm_components(model_router, config, budget_tracker)
    phase_planners = build_planners(
        config, registry,
        model_router=model_router, budget_tracker=budget_tracker,
        llm_guard=llm_guard, llm_gateway=llm_gateway,
    )
    telnet_executor = TelnetExecutor(config)
    browser_executor = BrowserExecutor(config)
    # Phase 12B — dedicated protocol executors, routed by TaskDispatcher
    # exactly like TelnetExecutor/BrowserExecutor (never through the generic
    # ToolBackend/run_command_fn path; see docs/credential-validation.md
    # "Planner integration").
    ssh_executor = SSHExecutor(config)
    ftp_executor = FTPExecutor(config)
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
        ssh_executor=ssh_executor, ftp_executor=ftp_executor,
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
    # Bug E (Phase 12A/R1) fix: dedicated diagnostic-and-terminate node for
    # any phase route_after_global_plan cannot dispatch — never falls
    # through silently to END. See orchestration/diagnostics_node.py.
    sg.add_node(UNKNOWN_PHASE_NODE, make_unknown_phase_node(deps))

    # Edges
    sg.add_edge(START, "load_context")
    sg.add_edge("load_context", "global_plan")
    sg.add_conditional_edges(
        "global_plan", route_after_global_plan,
        {
            "recon_agent": "recon_agent", "web_agent": "web_agent",
            "browser_agent": "browser_agent", "execute_agent": "execute_agent",
            "priv_esc_agent": "priv_esc_agent", UNKNOWN_PHASE_NODE: UNKNOWN_PHASE_NODE,
            END: END,
        },
    )
    sg.add_edge(UNKNOWN_PHASE_NODE, END)
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
