# routing.py
# Pure routing functions for the APEX LangGraph conditional edges.
"""Routing predicates for the APEX engagement StateGraph.

All functions here are pure (no I/O, no state mutation).  They inspect
``ApexGraphState`` dicts and return the name of the next LangGraph node.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langgraph.graph import END

from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.completion import is_repairable
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    pass

# Canonical mapping from ApexPhase value → LangGraph node name.
PHASE_NODE: dict[str, str] = {
    ApexPhase.recon.value: "recon_agent",
    ApexPhase.web.value: "web_agent",
    ApexPhase.credential.value: "execute_agent",
    ApexPhase.priv_esc.value: "priv_esc_agent",
}

# Bug E (Phase 12A/R1) fix: the node reached when route_after_global_plan
# receives a phase value it cannot dispatch — e.g. a not-yet-routable
# ApexPhase member such as `exploit`/`lateral`, or any unexpected string.
# Previously such a phase fell through to a bare `PHASE_NODE.get(phase, END)`
# default, silently ending the engagement with no episode, no error, and no
# trace of why. `unknown_phase_agent` records a diagnostic Episode and
# terminates cleanly instead — see apex_host/orchestration/diagnostics_node.py.
UNKNOWN_PHASE_NODE: str = "unknown_phase_agent"


def route_after_global_plan(state: "ApexGraphState") -> str:
    """Choose which agent node executes after the global planner decides a phase.

    The web phase routes to ``browser_agent`` on the second+ visit so the
    engagement does curl/ffuf first, then inspects the page with a browser.

    An unrecognized phase (anything not in PHASE_NODE, not `web`, and not
    `done`) never falls through silently to END — it routes to
    UNKNOWN_PHASE_NODE, which records why before terminating (Bug E fix).
    """
    if state["completed"]:
        return END
    phase = state["phase"]
    if phase == ApexPhase.web.value:
        has_web_finding = any(
            f.get("phase") == ApexPhase.web.value for f in state["findings"]
        )
        return "browser_agent" if has_web_finding else "web_agent"
    node = PHASE_NODE.get(phase)
    if node is not None:
        return node
    if phase == ApexPhase.done.value:
        return END
    return UNKNOWN_PHASE_NODE


def route_after_write(state: "ApexGraphState", max_repair: int) -> str:
    """Decide whether to try repair or proceed to reflect_or_continue.

    Checks ALL tool_results for repairability (F06 fix).  The first
    eligible repairable result triggers the repair agent.
    """
    raw_results: list[dict[str, Any]] = list(state.get("tool_results") or [])
    _ltr = state.get("last_tool_result")
    if not raw_results and _ltr is not None:
        raw_results = [_ltr]
    if not raw_results:
        return "reflect_or_continue"

    repair_count = int(state.get("repair_count") or 0)
    for tr in raw_results:
        if is_repairable(tr, repair_count, max_repair):
            return "repair_agent"
    return "reflect_or_continue"


def route_after_reflect(state: "ApexGraphState") -> str:
    """End the engagement or loop back to context loading."""
    return END if state["completed"] else "load_context"
