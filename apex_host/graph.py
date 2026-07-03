# graph.py
# The APEX multi-phase engagement LangGraph that orchestrates recon, web, browser, credential, and priv-esc agent nodes through a safety-gated multi-turn loop.
"""The APEX multi-phase engagement LangGraph.

This is a **separate** StateGraph from memfabric.coordination.graph_loop —
see CLAUDE.md Section 11.3. memfabric's graph_loop.py is the generic
one-turn substrate loop; this is the APEX-specific multi-turn cyber
engagement workflow:

    START -> load_context -> global_plan -> route_phase
          -> [recon_agent | web_agent | browser_agent | execute_agent | priv_esc_agent]
          -> parse_observation -> write_memory
          -> route_after_write -> repair_agent (optional)
          -> reflect_or_continue -> END  (or loop back to load_context)

MemoryAPI, the ToolRegistry, planners, and config are captured via closures
in build_apex_graph() — they never appear in ApexGraphState payloads
(mirrors memfabric Invariant 1 and Invariant 7). Tool execution only ever
happens through apex_host/tools/runner.py (which is itself safety-gated by
tools/safety.py and dry_run-aware) — no raw subprocess calls live here.

Complete planning loop additions
---------------------------------
- Concurrent multi-task execution: _run_tasks() runs all planner-produced
  TaskSpecs concurrently (asyncio.gather with semaphore cap) and stores all
  results in state["tool_results"].  parse_observation and write_memory
  iterate over tool_results so every result is parsed and logged.
- Decision logging: every planner invocation produces a PlanDecision record
  (from planner.last_decision) stored in state["planner_decisions"].
- Repair agent: when a task fails with script_error or fixable outcome,
  repair_agent calls RepairEngine to produce a corrected TaskSpec, executes
  it, and writes the repaired observation through MemoryAPI.  No repair in
  dry_run mode (RepairEngine returns None immediately).
- Dynamic replanning: reflect_or_continue peeks at the current EKG after
  every write_memory pass and updates state["phase"] to the freshest phase
  the GlobalPlanner would select.  This ensures state snapshots between
  turns always carry an accurate phase hint without charging the budget
  counter (global_plan charges the counter at the start of each turn).
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from langgraph.graph import END, START, StateGraph

from memfabric.types import (
    AbandonSignal,
    Episode,
    EvidenceBundle,
    Goal,
    Outcome,
    ParsedObservation,
    RawObservation,
    SubgraphView,
    TaskSpec,
)

from apex_host.agents.browser_executor import BrowserExecutor
from apex_host.agents.telnet_executor import TelnetExecutor
from apex_host.graph_state import ApexGraphState, CompiledApexGraph
from apex_host.parsers.access_parser import AccessParser
from apex_host.parsers.banner_parser import BannerParser
from apex_host.parsers.browser_parser import BrowserParser
from apex_host.parsers.command_parser import CommandParser
from apex_host.parsers.ffuf_parser import FfufParser
from apex_host.parsers.gobuster_parser import GobusterParser
from apex_host.parsers.nmap_parser import NmapParser
from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planners.credential_planner import CredentialPlanner
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.planners.priv_esc_planner import PrivEscPlanner
from apex_host.planners.recon_planner import ReconPlanner
from apex_host.planners.web_planner import WebPlanner
from apex_host.planning.models import PlanDecision
from apex_host.planning.repair import RepairEngine
from apex_host.tools.registry import ToolRegistry
from apex_host.tools.runner import run_command
from apex_host.types import ApexPhase, BrowserObservation, ToolCommand

if TYPE_CHECKING:
    from apex_host.config import ApexConfig
    from apex_host.llm.router import ModelRouter
    from memfabric.api import MemoryAPI
    from memfabric.coordination.protocols import Planner

logger = logging.getLogger(__name__)

_NMAP = NmapParser()
_FFUF = FfufParser()
_GOBUSTER = GobusterParser()
_COMMAND = CommandParser()
_BANNER = BannerParser()
_BROWSER_PARSER = BrowserParser()
_ACCESS = AccessParser()

# phase -> name of the LangGraph node reached from route_phase
_PHASE_NODE: dict[str, str] = {
    ApexPhase.recon.value: "recon_agent",
    ApexPhase.web.value: "web_agent",
    ApexPhase.credential.value: "execute_agent",
    ApexPhase.priv_esc.value: "priv_esc_agent",
}


def _evidence_summary(evidence: EvidenceBundle) -> str:
    if not evidence.entries:
        return ""
    top = sorted(evidence.entries, key=lambda e: e.score, reverse=True)[:5]
    return " | ".join(f"[{e.tier}:{e.source}] {e.text[:120]}" for e in top)


def _outcome_for(returncode: int, error: str | None) -> Outcome:
    if error:
        return Outcome.fixable if "timed out" in error else Outcome.fundamental
    if returncode != 0:
        return Outcome.script_error
    return Outcome.success


def _port_from_nc_args(args: list[str]) -> str:
    """Return the port from nc/netcat argv (last positional — non-flag — token)."""
    positional = [a for a in args if not a.startswith("-")]
    return positional[-1] if len(positional) >= 2 else ""


def _findings_from_parsed(
    parsed: ParsedObservation, *, phase: str, source: str, timestamp: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for node in parsed.node_deltas:
        findings.append(
            {
                "id": node.id,
                "phase": phase,
                "title": f"{node.type} discovered",
                "detail": str(node.props)[:300],
                "confidence": node.confidence,
                "source": source,
                "timestamp": timestamp,
            }
        )
    return findings


def _parse_single_result(
    tool_result: dict[str, Any], state: ApexGraphState
) -> tuple[ParsedObservation, str]:
    """Parse ONE tool_result dict into (ParsedObservation, source_str).

    Extracted from parse_observation so it can be reused by repair_agent.
    Returns the parsed observation and the source label for findings.
    """
    if tool_result.get("kind") == "browser":
        obs_dict = tool_result.get("obs") or {}
        fallback_url = tool_result["url"]
        fallback_title = "(dry-run)" if tool_result.get("dry_run") else ""
        obs = BrowserObservation(
            url=str(obs_dict.get("url", fallback_url)),
            html_snippet="",
            title=str(obs_dict.get("title", fallback_title)),
            forms=list(obs_dict.get("forms", [])),
            tokens=list(obs_dict.get("tokens", [])),
            auth_hints=list(obs_dict.get("auth_hints", [])),
            links=list(obs_dict.get("links", [])),
        )
        obs_target = str(obs_dict.get("url", fallback_url))
        parsed = _BROWSER_PARSER.parse_observation(obs, target=obs_target, source="browser")
        return parsed, "browser"
    else:
        target = tool_result.get("target", state["target"])
        stdout = tool_result.get("stdout", "")
        parser_name = tool_result.get("parser", "command")
        tool_name = tool_result.get("tool", "")
        if parser_name == "nmap" or tool_name == "nmap":
            parsed = _NMAP.parse_text(stdout, target=target)
        elif parser_name == "ffuf":
            parsed = _FFUF.parse_text(stdout, target=target)
        elif parser_name == "gobuster":
            parsed = _GOBUSTER.parse_text(stdout, target=target)
        elif tool_name in ("nc", "netcat") or parser_name == "banner":
            port = _port_from_nc_args(tool_result.get("args", []))
            parsed = _BANNER.parse_text(stdout, target=target, source=tool_name, port=port)
        elif parser_name == "access":
            username = str(tool_result.get("username", ""))
            parsed = _ACCESS.parse_text(
                stdout, target=target, username=username,
                source=str(tool_result.get("tool", "telnet_access")),
                port=str(tool_result.get("port", "")),
                proto=str(tool_result.get("proto", "tcp")),
            )
        elif parser_name == "curl_body":
            raw = RawObservation(raw=stdout, metadata={"source": "curl_body", "target": target})
            parsed = _COMMAND.parse_curl_body(raw)
        else:
            raw = RawObservation(raw=stdout, metadata={"source": tool_name, "target": target})
            parsed = _COMMAND.parse(raw)
        return parsed, tool_result.get("tool", "command")


def build_apex_graph(
    api: "MemoryAPI",
    registry: ToolRegistry,
    config: "ApexConfig",
    *,
    checkpointer: Any | None = None,
    model_router: "ModelRouter | None" = None,
) -> CompiledApexGraph:
    """Compile and return the APEX engagement StateGraph.

    ``api``, ``registry``, and ``config`` are captured in node closures.
    Planners are constructed here (bound to ``config.target`` + ``registry``,
    consistent with the closure-DI pattern used throughout planners/).

    When ``model_router`` is provided (non-None), each domain planner is wired
    to a ``PlanningEngine`` that may call the LLM for reasoning, with automatic
    fallback to the deterministic core on any error or low confidence.
    The default (``None``) preserves the fully-deterministic behaviour so that
    existing tests and dry-run engagements need no changes.
    """
    _ct = getattr(config, "planning_confidence_threshold", 0.4)
    _mr = getattr(config, "max_planning_retries", 1)
    _max_repair = getattr(config, "max_repair_attempts", 1)

    global_planner = GlobalPlanner(max_turns=config.max_turns)
    phase_planners: dict[str, "Planner"] = {
        ApexPhase.recon.value: ReconPlanner(
            config.target,
            registry,
            model_router=model_router,
            allowed_tools=config.allowed_tools if model_router else None,
            confidence_threshold=_ct,
            max_retries=_mr,
        ),
        ApexPhase.web.value: WebPlanner(
            config.target,
            registry,
            web_wordlist_path=config.web_wordlist_path,
            max_web_paths=config.max_web_paths,
            model_router=model_router,
            allowed_tools=config.allowed_tools if model_router else None,
            confidence_threshold=_ct,
            max_retries=_mr,
        ),
        ApexPhase.credential.value: CredentialPlanner(
            config.target,
            registry,
            username_candidates=config.username_candidates,
            password_candidates=config.password_candidates,
            max_access_attempts=config.max_access_attempts,
            model_router=model_router,
            allowed_tools=config.allowed_tools if model_router else None,
            confidence_threshold=_ct,
            max_retries=_mr,
        ),
        ApexPhase.priv_esc.value: PrivEscPlanner(
            config.target,
            registry,
            model_router=model_router,
            allowed_tools=config.allowed_tools if model_router else None,
            confidence_threshold=_ct,
            max_retries=_mr,
        ),
    }
    browser_executor = BrowserExecutor(config)
    telnet_executor = TelnetExecutor(config)

    # RepairEngine: dry_run=True means no real repairs (all dry-run failures
    # are synthetic and do not need LLM-backed correction).
    # model_router=None is accepted by RepairEngine (it returns None immediately).
    repair_engine = RepairEngine(
        model_router=model_router,
        allowed_tools=config.allowed_tools,
        target=config.target,
        dry_run=config.dry_run,
    )

    def _anchor() -> str:
        return f"host:{config.target}"

    # ------------------------------------------------------------------
    # Node: load_context
    # ------------------------------------------------------------------
    async def load_context(state: ApexGraphState) -> dict[str, Any]:
        evidence = await api.query(text=state["goal"] or config.target, subgraph_anchor=_anchor())
        return {"evidence_summary": _evidence_summary(evidence)}

    # ------------------------------------------------------------------
    # Node: global_plan
    # ------------------------------------------------------------------
    async def global_plan(state: ApexGraphState) -> dict[str, Any]:
        subgraph: SubgraphView = await api.get_subgraph(_anchor(), depth=3)
        node_types_seen = {n.type for n in subgraph.nodes}
        current_phase: str | None = state.get("phase")
        caps = capabilities_from_subgraph(subgraph)
        has_web = any(c.name == "web_probe" for c in caps)
        phase = global_planner.decide_phase(
            node_types_seen=node_types_seen,
            turn_count=state["turn_count"],
            current_phase=current_phase,
            has_web_capability=has_web,
        )
        # Record that a turn was consumed in the decided phase for budget tracking.
        if phase != ApexPhase.done:
            global_planner.record_turn(phase)
        goal_text = global_planner.goal_for_phase(phase, config.target)
        return {
            "phase": phase.value,
            "goal": goal_text,
            "completed": phase == ApexPhase.done,
        }

    # ------------------------------------------------------------------
    # Routing: after global_plan, which agent runs this turn?
    #
    # web phase routes to browser_agent on the SECOND+ visit (once a prior
    # web_agent turn has already produced a finding) so the engagement
    # fuzzes endpoints first, then inspects the landing page with a
    # browser — both are real, independently reachable nodes.
    # ------------------------------------------------------------------
    def route_after_global_plan(state: ApexGraphState) -> str:
        if state["completed"]:
            return END
        phase = state["phase"]
        if phase == ApexPhase.web.value:
            has_web_finding = any(
                f.get("phase") == ApexPhase.web.value for f in state["findings"]
            )
            return "browser_agent" if has_web_finding else "web_agent"
        return _PHASE_NODE.get(phase, END)

    # ------------------------------------------------------------------
    # Shared helper: ask a phase planner for tasks, run ALL concurrently.
    # ------------------------------------------------------------------
    async def _run_tasks(state: ApexGraphState, planner: "Planner") -> dict[str, Any]:
        anchor = _anchor()
        goal = Goal(
            id=state["run_id"],
            description=state["goal"],
            phase=state["phase"],
            anchor_node=anchor,
        )
        subgraph = await api.get_subgraph(anchor, depth=2)
        evidence = await api.query(text=goal.description, subgraph_anchor=anchor)

        plan_result = await planner.plan(goal, subgraph, evidence)

        # Collect decision log from the planner wrapper
        decision: PlanDecision | None = getattr(planner, "last_decision", None)
        decision_list: list[dict[str, Any]] = (
            [decision.to_dict()] if decision is not None else []
        )

        if isinstance(plan_result, AbandonSignal):
            logger.info("phase %s abandoned: %s", state["phase"], plan_result.reason)
            return {
                "current_task": None,
                "last_tool_result": None,
                "tool_results": None,
                "last_error": plan_result.reason,
                "planner_decisions": decision_list,
            }

        tasks: list[TaskSpec] = list(plan_result) if plan_result else []
        if not tasks:
            return {
                "current_task": None,
                "last_tool_result": None,
                "tool_results": None,
                "last_error": "planner returned no tasks",
                "planner_decisions": decision_list,
            }

        # Concurrency cap from config; always at least 1.
        concurrency_cap = max(1, min(config.max_concurrency, len(tasks)))
        sem = asyncio.Semaphore(concurrency_cap)

        async def _run_one_cmd(task: TaskSpec) -> dict[str, Any]:
            async with sem:
                tool = str(task.params.get("tool", ""))
                args = [str(a) for a in task.params.get("args", [])]
                target = str(task.params.get("target", config.target))
                parser_name = str(task.params.get("parser", "command"))
                cmd = ToolCommand(tool=tool, args=args, timeout_seconds=config.max_command_seconds)
                try:
                    result = await run_command(cmd, config)
                except ValueError as exc:
                    return {
                        "task_id": task.id,
                        "tool": tool,
                        "args": args,
                        "target": target,
                        "parser": parser_name,
                        "stdout": "",
                        "stderr": "",
                        "returncode": 1,
                        "dry_run": config.dry_run,
                        "error": str(exc),
                        "phase": state["phase"],
                    }
                return {
                    "task_id": task.id,
                    "tool": tool,
                    "args": args,
                    "target": target,
                    "parser": parser_name,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                    "dry_run": result.dry_run,
                    "error": result.error,
                    "phase": state["phase"],
                }

        results = list(await asyncio.gather(*[_run_one_cmd(t) for t in tasks]))
        first_result = results[0] if results else None
        first_task = tasks[0] if tasks else None

        return {
            "current_task": {
                "id": first_task.id,
                "executor_domain": first_task.executor_domain,
                "params": first_task.params,
            } if first_task else None,
            "last_tool_result": first_result,
            "tool_results": results,
            "last_error": first_result.get("error") if first_result else None,
            "planner_decisions": decision_list,
        }

    async def recon_agent(state: ApexGraphState) -> dict[str, Any]:
        return await _run_tasks(state, phase_planners[ApexPhase.recon.value])

    async def web_agent(state: ApexGraphState) -> dict[str, Any]:
        return await _run_tasks(state, phase_planners[ApexPhase.web.value])

    async def execute_agent(state: ApexGraphState) -> dict[str, Any]:
        """Credential-phase agent: routes to TelnetExecutor or run_command."""
        anchor = _anchor()
        goal = Goal(
            id=state["run_id"], description=state["goal"],
            phase=state["phase"], anchor_node=anchor,
        )
        subgraph = await api.get_subgraph(anchor, depth=2)
        evidence = await api.query(text=goal.description, subgraph_anchor=anchor)

        planner = phase_planners[ApexPhase.credential.value]
        plan_result = await planner.plan(goal, subgraph, evidence)

        decision: PlanDecision | None = getattr(planner, "last_decision", None)
        decision_list: list[dict[str, Any]] = (
            [decision.to_dict()] if decision is not None else []
        )

        if isinstance(plan_result, AbandonSignal):
            logger.info("credential phase abandoned: %s", plan_result.reason)
            return {
                "current_task": None,
                "last_tool_result": None,
                "tool_results": None,
                "last_error": plan_result.reason,
                "planner_decisions": decision_list,
            }

        tasks: list[TaskSpec] = list(plan_result) if plan_result else []
        if not tasks:
            return {
                "current_task": None,
                "last_tool_result": None,
                "tool_results": None,
                "last_error": "planner returned no tasks",
                "planner_decisions": decision_list,
            }

        task = tasks[0]
        tool = str(task.params.get("tool", ""))
        parser_name = str(task.params.get("parser", "command"))
        target = str(task.params.get("target", config.target))
        current_task_info: dict[str, Any] = {
            "id": task.id,
            "executor_domain": task.executor_domain,
            "params": task.params,
        }

        if tool == "telnet_access":
            result = await telnet_executor.run(task, evidence)
            ep_data = result.episode.data
            outcome_is_success = result.episode.outcome == Outcome.success
            stdout = str(ep_data.get("stdout", ""))
            raw_error: object = ep_data.get("error")
            if not outcome_is_success and raw_error is None:
                raw_error = "login failed"
            error_str: str | None = str(raw_error) if raw_error is not None else None
            tool_result: dict[str, Any] = {
                "task_id": task.id,
                "tool": tool,
                "args": [],
                "target": target,
                "parser": parser_name,
                "stdout": stdout,
                "stderr": "",
                "returncode": 0 if outcome_is_success else 1,
                "dry_run": bool(ep_data.get("dry_run", False)),
                "error": error_str,
                "phase": state["phase"],
                "username": str(task.params.get("username", "")),
                "port": str(task.params.get("port", "")),
                "proto": "tcp",
            }
            return {
                "current_task": current_task_info,
                "last_tool_result": tool_result,
                "tool_results": [tool_result],
                "last_error": error_str,
                "planner_decisions": decision_list,
            }

        # Fallback: shell-based tools via safety-gated runner.py
        args = [str(a) for a in task.params.get("args", [])]
        cmd = ToolCommand(tool=tool, args=args, timeout_seconds=config.max_command_seconds)
        try:
            run_result = await run_command(cmd, config)
        except ValueError as exc:
            return {
                "current_task": current_task_info,
                "last_tool_result": None,
                "tool_results": None,
                "last_error": str(exc),
                "planner_decisions": decision_list,
            }
        cmd_tool_result: dict[str, Any] = {
            "task_id": task.id,
            "tool": tool,
            "args": args,
            "target": target,
            "parser": parser_name,
            "stdout": run_result.stdout,
            "stderr": run_result.stderr,
            "returncode": run_result.returncode,
            "dry_run": run_result.dry_run,
            "error": run_result.error,
            "phase": state["phase"],
        }
        return {
            "current_task": current_task_info,
            "last_tool_result": cmd_tool_result,
            "tool_results": [cmd_tool_result],
            "last_error": run_result.error,
            "planner_decisions": decision_list,
        }

    async def priv_esc_agent(state: ApexGraphState) -> dict[str, Any]:
        return await _run_tasks(state, phase_planners[ApexPhase.priv_esc.value])

    # ------------------------------------------------------------------
    # Node: browser_agent
    # ------------------------------------------------------------------
    async def browser_agent(state: ApexGraphState) -> dict[str, Any]:
        anchor = _anchor()
        url = state["target"]
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        task = TaskSpec(
            id=state["run_id"],
            goal_id=state["run_id"],
            executor_domain="browser",
            params={"url": url},
            subgraph_anchor=anchor,
            phase=state["phase"],
        )
        evidence = await api.query(text=state["goal"], subgraph_anchor=anchor)
        result = await browser_executor.run(task, evidence)

        ep_data = result.episode.data
        last_error = ep_data.get("error") if result.episode.outcome != Outcome.success else None
        tool_result = {
            "kind": "browser",
            "task_id": task.id,
            "url": url,
            "dry_run": config.dry_run,
            "outcome": result.episode.outcome.value,
            "phase": state["phase"],
            "obs": ep_data.get("obs", {}),
        }
        return {
            "current_task": {"id": task.id, "executor_domain": "browser", "params": task.params},
            "last_tool_result": tool_result,
            "tool_results": [tool_result],
            "last_error": last_error,
            "planner_decisions": [],  # browser_agent has no planner decision
        }

    # ------------------------------------------------------------------
    # Node: parse_observation
    # Iterates over tool_results (or falls back to last_tool_result) and
    # writes all node/edge deltas through MemoryAPI.
    # ------------------------------------------------------------------
    async def parse_observation(state: ApexGraphState) -> dict[str, Any]:
        raw_results = state.get("tool_results")
        results_to_parse: list[dict[str, Any]]
        if raw_results:
            results_to_parse = raw_results
        elif state["last_tool_result"]:
            results_to_parse = [state["last_tool_result"]]
        else:
            return {}

        all_findings: list[dict[str, Any]] = []
        for tool_result in results_to_parse:
            parsed, source = _parse_single_result(tool_result, state)
            await api.apply_deltas(
                nodes=parsed.node_deltas,
                edges=parsed.edge_deltas,
                knowledge=parsed.proposed_knowledge,
            )
            phase = state["phase"]
            timestamp = tool_result.get("timestamp", "")
            all_findings.extend(
                _findings_from_parsed(parsed, phase=phase, source=source, timestamp=timestamp)
            )

        return {"findings": all_findings}

    # ------------------------------------------------------------------
    # Node: write_memory
    # Creates one Episode per tool_result and appends all via apply_deltas.
    # ------------------------------------------------------------------
    async def write_memory(state: ApexGraphState) -> dict[str, Any]:
        raw_results = state.get("tool_results")
        results_to_write: list[dict[str, Any]]
        if raw_results:
            results_to_write = raw_results
        elif state["last_tool_result"]:
            results_to_write = [state["last_tool_result"]]
        else:
            return {}

        error_entries: list[dict[str, Any]] = []
        for tool_result in results_to_write:
            if tool_result.get("kind") == "browser":
                outcome = (
                    Outcome.success if not state.get("last_error") else Outcome.fundamental
                )
            else:
                outcome = _outcome_for(
                    int(tool_result.get("returncode", 0) or 0),
                    tool_result.get("error"),
                )

            episode = Episode(
                agent=f"apex.{state['phase']}",
                action=(
                    f"{tool_result.get('tool', tool_result.get('kind', 'unknown'))} "
                    f"{tool_result.get('target', tool_result.get('url', ''))}"
                ).strip(),
                outcome=outcome,
                data=tool_result,
                task_id=tool_result.get("task_id"),
                phase=state["phase"],
            )
            await api.apply_deltas(episodes=[episode])

            if outcome != Outcome.success:
                error_entries.append({
                    "outcome": outcome.value,
                    "tool": tool_result.get("tool", tool_result.get("kind", "unknown")),
                    "error": tool_result.get("error") or state.get("last_error"),
                    "phase": state["phase"],
                })

        return {"error_episodes": error_entries} if error_entries else {}

    # ------------------------------------------------------------------
    # Routing: after write_memory — try repair if first result failed and
    # repair budget allows; otherwise go to reflect_or_continue.
    # ------------------------------------------------------------------
    def route_after_write(state: ApexGraphState) -> str:
        tool_result = state.get("last_tool_result")
        if not tool_result or tool_result.get("kind") == "browser":
            return "reflect_or_continue"

        outcome = _outcome_for(
            int(tool_result.get("returncode", 0) or 0),
            tool_result.get("error"),
        )
        repair_count = int(state.get("repair_count") or 0)
        if (
            outcome in (Outcome.script_error, Outcome.fixable)
            and repair_count < _max_repair
        ):
            return "repair_agent"
        return "reflect_or_continue"

    # ------------------------------------------------------------------
    # Node: repair_agent
    # Calls RepairEngine to get a corrected TaskSpec, executes it,
    # parses + writes results through MemoryAPI, updates repair_count.
    # No-op when RepairEngine returns None (dry_run or no LLM).
    # ------------------------------------------------------------------
    async def repair_agent(state: ApexGraphState) -> dict[str, Any]:
        tool_result = state.get("last_tool_result")
        if not tool_result:
            return {"repair_count": int(state.get("repair_count") or 0) + 1}

        failed_task_params = (state.get("current_task") or {}).get("params", {})
        error = str(tool_result.get("error") or state.get("last_error") or "non-zero returncode")

        # Reconstruct a minimal TaskSpec for the repair engine
        failed_task = TaskSpec(
            id=str(tool_result.get("task_id", "unknown")),
            goal_id=state["run_id"],
            executor_domain=str(
                (state.get("current_task") or {}).get("executor_domain", "recon")
            ),
            params=dict(failed_task_params),
            subgraph_anchor=_anchor(),
            phase=state["phase"],
        )

        anchor = _anchor()
        subgraph = await api.get_subgraph(anchor, depth=2)
        evidence = await api.query(text=state["goal"], subgraph_anchor=anchor)

        repaired_task = await repair_engine.repair(
            failed_task=failed_task,
            error=error,
            phase=state["phase"],
            evidence=evidence,
            subgraph=subgraph,
        )

        new_repair_count = int(state.get("repair_count") or 0) + 1

        if repaired_task is None:
            # No repair available — proceed to reflect_or_continue unchanged.
            logger.debug("repair_agent: no repair available for phase=%s", state["phase"])
            return {"repair_count": new_repair_count}

        # Execute the repaired task via runner.py (safety-gated, dry_run-aware).
        r_tool = str(repaired_task.params.get("tool", ""))
        r_args = [str(a) for a in repaired_task.params.get("args", [])]
        r_target = str(repaired_task.params.get("target", config.target))
        r_parser = str(repaired_task.params.get("parser", "command"))
        r_cmd = ToolCommand(tool=r_tool, args=r_args, timeout_seconds=config.max_command_seconds)
        try:
            r_result = await run_command(r_cmd, config)
        except ValueError as exc:
            logger.warning("repair_agent: repaired task raised ValueError: %s", exc)
            return {"repair_count": new_repair_count}

        repaired_tool_result: dict[str, Any] = {
            "task_id": repaired_task.id,
            "tool": r_tool,
            "args": r_args,
            "target": r_target,
            "parser": r_parser,
            "stdout": r_result.stdout,
            "stderr": r_result.stderr,
            "returncode": r_result.returncode,
            "dry_run": r_result.dry_run,
            "error": r_result.error,
            "phase": state["phase"],
            "repaired": True,
        }

        # Parse + write the repaired observation through MemoryAPI.
        parsed, source = _parse_single_result(repaired_tool_result, state)
        await api.apply_deltas(
            nodes=parsed.node_deltas,
            edges=parsed.edge_deltas,
            knowledge=parsed.proposed_knowledge,
        )

        r_outcome = _outcome_for(r_result.returncode, r_result.error)
        repair_episode = Episode(
            agent=f"apex.{state['phase']}.repair",
            action=f"repair/{r_tool} {r_target}".strip(),
            outcome=r_outcome,
            data=repaired_tool_result,
            task_id=repaired_task.id,
            phase=state["phase"],
        )
        await api.apply_deltas(episodes=[repair_episode])

        return {
            "repair_count": new_repair_count,
            "last_tool_result": repaired_tool_result,
            "last_error": r_result.error,
        }

    # ------------------------------------------------------------------
    # Node: reflect_or_continue
    # Dynamic replanning: peek at current EKG after write_memory to update
    # the phase hint in state without charging the GlobalPlanner budget
    # (global_plan charges the budget at the start of the next turn).
    # ------------------------------------------------------------------
    async def reflect_or_continue(state: ApexGraphState) -> dict[str, Any]:
        turn_count = state["turn_count"] + 1
        completed = state["completed"] or turn_count >= config.max_turns

        # Dynamic replanning: derive the freshest phase from live EKG state
        # so that state checkpoints between turns are accurate.
        # global_plan will re-derive and charge the budget at the next turn start.
        next_phase_value = state["phase"]
        if not completed:
            try:
                subgraph = await api.get_subgraph(_anchor(), depth=2)
                node_types_seen = {n.type for n in subgraph.nodes}

                # Early stop: access_state in the EKG means a successful login
                # was recorded this turn.  The primary objective is achieved —
                # stop now rather than burning remaining turns on priv_esc probes
                # that the rule-based planner cannot act on yet.
                if "access_state" in node_types_seen:
                    logger.info(
                        "access_state in EKG after turn %d — engagement succeeded, stopping early",
                        turn_count,
                    )
                    return {
                        "turn_count": turn_count,
                        "completed": True,
                        "phase": ApexPhase.done.value,
                        "repair_count": 0,
                    }

                peek_caps = capabilities_from_subgraph(subgraph)
                has_web_peek = any(c.name == "web_probe" for c in peek_caps)
                next_phase = global_planner.decide_phase(
                    node_types_seen=node_types_seen,
                    turn_count=turn_count,
                    has_web_capability=has_web_peek,
                )
                next_phase_value = next_phase.value
            except Exception as exc:
                logger.debug("reflect_or_continue: dynamic replan peek failed (%s)", exc)

        return {
            "turn_count": turn_count,
            "completed": completed,
            "phase": next_phase_value,
            "repair_count": 0,  # reset for next turn
        }

    def route_after_reflect(state: ApexGraphState) -> str:
        return END if state["completed"] else "load_context"

    # ------------------------------------------------------------------
    # Compile
    # ------------------------------------------------------------------
    builder: Any = StateGraph(ApexGraphState)

    builder.add_node("load_context", load_context)
    builder.add_node("global_plan", global_plan)
    builder.add_node("recon_agent", recon_agent)
    builder.add_node("web_agent", web_agent)
    builder.add_node("browser_agent", browser_agent)
    builder.add_node("execute_agent", execute_agent)
    builder.add_node("priv_esc_agent", priv_esc_agent)
    builder.add_node("parse_observation", parse_observation)
    builder.add_node("write_memory", write_memory)
    builder.add_node("repair_agent", repair_agent)
    builder.add_node("reflect_or_continue", reflect_or_continue)

    builder.add_edge(START, "load_context")
    builder.add_edge("load_context", "global_plan")
    builder.add_conditional_edges(
        "global_plan",
        route_after_global_plan,
        {
            "recon_agent": "recon_agent",
            "web_agent": "web_agent",
            "browser_agent": "browser_agent",
            "execute_agent": "execute_agent",
            "priv_esc_agent": "priv_esc_agent",
            END: END,
        },
    )
    for agent_node in ("recon_agent", "web_agent", "browser_agent", "execute_agent", "priv_esc_agent"):
        builder.add_edge(agent_node, "parse_observation")
    builder.add_edge("parse_observation", "write_memory")
    builder.add_conditional_edges(
        "write_memory",
        route_after_write,
        {
            "repair_agent": "repair_agent",
            "reflect_or_continue": "reflect_or_continue",
        },
    )
    builder.add_edge("repair_agent", "reflect_or_continue")
    builder.add_conditional_edges(
        "reflect_or_continue",
        route_after_reflect,
        {"load_context": "load_context", END: END},
    )

    return builder.compile(checkpointer=checkpointer)
