"""The APEX multi-phase engagement LangGraph.

This is a **separate** StateGraph from memfabric.coordination.graph_loop —
see CLAUDE.md Section 11.3. memfabric's graph_loop.py is the generic
one-turn substrate loop; this is the APEX-specific multi-turn cyber
engagement workflow:

    START -> load_context -> global_plan -> route_phase
          -> [recon_agent | web_agent | browser_agent | execute_agent | priv_esc_agent]
          -> parse_observation -> write_memory -> reflect_or_continue
          -> END  (or loop back to load_context)

MemoryAPI, the ToolRegistry, planners, and config are captured via closures
in build_apex_graph() — they never appear in ApexGraphState payloads
(mirrors memfabric Invariant 1 and Invariant 7). Tool execution only ever
happens through apex_host/tools/runner.py (which is itself safety-gated by
tools/safety.py and dry_run-aware) — no raw subprocess calls live here.
"""
from __future__ import annotations

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
from apex_host.graph_state import ApexGraphState, CompiledApexGraph
from apex_host.parsers.browser_parser import BrowserParser
from apex_host.parsers.command_parser import CommandParser
from apex_host.parsers.ffuf_parser import FfufParser
from apex_host.parsers.gobuster_parser import GobusterParser
from apex_host.parsers.nmap_parser import NmapParser
from apex_host.planners.credential_planner import CredentialPlanner
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.planners.priv_esc_planner import PrivEscPlanner
from apex_host.planners.recon_planner import ReconPlanner
from apex_host.planners.web_planner import WebPlanner
from apex_host.tools.registry import ToolRegistry
from apex_host.tools.runner import run_command
from apex_host.types import ApexPhase, BrowserObservation, ToolCommand

if TYPE_CHECKING:
    from apex_host.config import ApexConfig
    from memfabric.api import MemoryAPI
    from memfabric.coordination.protocols import Planner

logger = logging.getLogger(__name__)

_NMAP = NmapParser()
_FFUF = FfufParser()
_GOBUSTER = GobusterParser()
_COMMAND = CommandParser()
_BROWSER_PARSER = BrowserParser()

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


def build_apex_graph(
    api: "MemoryAPI",
    registry: ToolRegistry,
    config: "ApexConfig",
    *,
    checkpointer: Any | None = None,
) -> CompiledApexGraph:
    """Compile and return the APEX engagement StateGraph.

    ``api``, ``registry``, and ``config`` are captured in node closures.
    Planners are constructed here (bound to ``config.target`` + ``registry``,
    consistent with the closure-DI pattern used throughout planners/).
    """

    global_planner = GlobalPlanner(max_turns=config.max_turns)
    phase_planners: dict[str, "Planner"] = {
        ApexPhase.recon.value: ReconPlanner(config.target, registry),
        ApexPhase.web.value: WebPlanner(config.target, registry),
        ApexPhase.credential.value: CredentialPlanner(config.target, registry),
        ApexPhase.priv_esc.value: PrivEscPlanner(config.target, registry),
    }
    browser_executor = BrowserExecutor(config)

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
        phase = global_planner.decide_phase(
            node_types_seen=node_types_seen, turn_count=state["turn_count"]
        )
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
    # Shared helper: ask a phase planner for tasks, run the first one.
    # ------------------------------------------------------------------
    async def _run_one_task(state: ApexGraphState, planner: "Planner") -> dict[str, Any]:
        anchor = _anchor()
        goal = Goal(id=state["run_id"], description=state["goal"], phase=state["phase"], anchor_node=anchor)
        subgraph = await api.get_subgraph(anchor, depth=2)
        evidence = await api.query(text=goal.description, subgraph_anchor=anchor)

        plan_result = await planner.plan(goal, subgraph, evidence)
        if isinstance(plan_result, AbandonSignal):
            logger.info("phase %s abandoned: %s", state["phase"], plan_result.reason)
            return {"current_task": None, "last_tool_result": None, "last_error": plan_result.reason}

        tasks: list[TaskSpec] = list(plan_result) if plan_result else []
        if not tasks:
            return {"current_task": None, "last_tool_result": None, "last_error": "planner returned no tasks"}

        task = tasks[0]
        tool = str(task.params.get("tool", ""))
        args = [str(a) for a in task.params.get("args", [])]
        target = str(task.params.get("target", config.target))
        parser_name = str(task.params.get("parser", "command"))

        cmd = ToolCommand(tool=tool, args=args, timeout_seconds=config.max_command_seconds)
        try:
            result = await run_command(cmd, config)
        except ValueError as exc:
            return {
                "current_task": {"id": task.id, "executor_domain": task.executor_domain, "params": task.params},
                "last_tool_result": None,
                "last_error": str(exc),
            }

        tool_result = {
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
        return {
            "current_task": {"id": task.id, "executor_domain": task.executor_domain, "params": task.params},
            "last_tool_result": tool_result,
            "last_error": result.error,
        }

    async def recon_agent(state: ApexGraphState) -> dict[str, Any]:
        return await _run_one_task(state, phase_planners[ApexPhase.recon.value])

    async def web_agent(state: ApexGraphState) -> dict[str, Any]:
        return await _run_one_task(state, phase_planners[ApexPhase.web.value])

    async def execute_agent(state: ApexGraphState) -> dict[str, Any]:
        return await _run_one_task(state, phase_planners[ApexPhase.credential.value])

    async def priv_esc_agent(state: ApexGraphState) -> dict[str, Any]:
        return await _run_one_task(state, phase_planners[ApexPhase.priv_esc.value])

    # ------------------------------------------------------------------
    # Node: browser_agent
    # Drives Playwright only when config.dry_run is False; stateless
    # across tasks (no browser handle is held on self).
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

        tool_result = {
            "kind": "browser",
            "task_id": task.id,
            "url": url,
            "dry_run": config.dry_run,
            "outcome": result.episode.outcome.value,
            "phase": state["phase"],
        }
        last_error = result.episode.data.get("error") if result.episode.outcome != Outcome.success else None
        return {
            "current_task": {"id": task.id, "executor_domain": "browser", "params": task.params},
            "last_tool_result": tool_result,
            "last_error": last_error,
        }

    # ------------------------------------------------------------------
    # Node: parse_observation
    # Re-parses the raw tool output recorded in last_tool_result and
    # writes node/edge deltas through MemoryAPI immediately (deltas are
    # not state-serializable, so they cannot be deferred to a later node).
    # ------------------------------------------------------------------
    async def parse_observation(state: ApexGraphState) -> dict[str, Any]:
        tool_result = state["last_tool_result"]
        if not tool_result:
            return {}

        phase = state["phase"]
        timestamp = tool_result.get("timestamp", "")

        if tool_result.get("kind") == "browser":
            obs = BrowserObservation(
                url=tool_result["url"],
                html_snippet="",
                title="(dry-run)" if tool_result.get("dry_run") else "",
            )
            parsed = _BROWSER_PARSER.parse_observation(obs, target=tool_result["url"], source="browser")
            source = "browser"
        else:
            target = tool_result.get("target", state["target"])
            stdout = tool_result.get("stdout", "")
            parser_name = tool_result.get("parser", "command")
            tool_name = tool_result.get("tool", "")
            if parser_name == "nmap":
                parsed = _NMAP.parse_text(stdout, target=target)
            elif parser_name == "ffuf":
                parsed = _FFUF.parse_text(stdout, target=target)
            elif parser_name == "gobuster":
                parsed = _GOBUSTER.parse_text(stdout, target=target)
            else:
                raw = RawObservation(raw=stdout, metadata={"source": tool_name, "target": target})
                parsed = _COMMAND.parse(raw)
            source = tool_result.get("tool", "command")

        for node in parsed.node_deltas:
            await api.upsert_node(node)
        for edge in parsed.edge_deltas:
            await api.upsert_edge(edge)
        for entry in parsed.proposed_knowledge:
            await api.propose_knowledge(entry)

        new_findings = _findings_from_parsed(parsed, phase=phase, source=source, timestamp=timestamp)
        return {"findings": new_findings}

    # ------------------------------------------------------------------
    # Node: write_memory
    # Appends this turn's Episode (built from primitives in state).
    # ------------------------------------------------------------------
    async def write_memory(state: ApexGraphState) -> dict[str, Any]:
        tool_result = state["last_tool_result"]
        if not tool_result:
            return {}

        outcome = _outcome_for(
            int(tool_result.get("returncode", 0) or 0), tool_result.get("error")
        ) if tool_result.get("kind") != "browser" else (
            Outcome.success if not state.get("last_error") else Outcome.fundamental
        )

        episode = Episode(
            agent=f"apex.{state['phase']}",
            action=f"{tool_result.get('tool', tool_result.get('kind', 'unknown'))} {tool_result.get('target', tool_result.get('url', ''))}".strip(),
            outcome=outcome,
            data=tool_result,
            task_id=tool_result.get("task_id"),
            phase=state["phase"],
        )
        await api.append_episode(episode)
        return {}

    # ------------------------------------------------------------------
    # Node: reflect_or_continue
    # ------------------------------------------------------------------
    async def reflect_or_continue(state: ApexGraphState) -> dict[str, Any]:
        turn_count = state["turn_count"] + 1
        completed = state["completed"] or turn_count >= config.max_turns
        return {"turn_count": turn_count, "completed": completed}

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
    builder.add_edge("write_memory", "reflect_or_continue")
    builder.add_conditional_edges(
        "reflect_or_continue",
        route_after_reflect,
        {"load_context": "load_context", END: END},
    )

    return builder.compile(checkpointer=checkpointer)
