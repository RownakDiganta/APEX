# browser_planner.py
# Deterministic browser-phase planner: selects the next unvisited page to inspect, implementing the browser "session model" (never revisit an identical page).
"""Deterministic browser-phase planner with an optional PlanningEngine LLM seam.

``_BrowserDeterministic`` replaces the pre-Phase-14 hard-coded behavior
(``apex_host/orchestration/dispatch_node.py::make_browser_node`` always
requested ``state["target"]`` — the same URL every single turn, which meant
a second browser turn could only ever re-request an already-completed
fingerprint and be silently duplicate-skipped). It now reasons about the
EKG's own "session model": which pages have already been browsed
(``endpoint`` nodes with ``browsed=True`` — see
``apex_host/parsers/browser_parser.py``) and which same-origin discovered
links remain unvisited (``apex_host.planners.web_opportunities
.select_unvisited_endpoints``).

Visit priority (deterministic, never random):

1. The base URL (derived from the highest-confidence ``web_probe``
   capability, same logic ``WebPlanner`` already uses — so the browser
   inspects the SAME site WebPlanner already found, not a hardcoded port).
2. ``{base}/robots.txt`` — a normal part of browser reasoning; parsed by
   ``BrowserParser`` for ``Disallow:`` entries.
3. ``{base}/sitemap.xml``.
4. The highest-priority same-origin discovered-but-unvisited endpoint (see
   ``select_unvisited_endpoints`` for the exact ranking rule).

Exactly one page is visited per turn (mirrors the pre-Phase-14 "one browse
task per turn" behavior — bounded, deterministic, never a batch of
navigations in one turn). Once every known candidate has been visited, the
planner returns an explicit "nothing left to browse" ``AbandonSignal``
instead of silently re-requesting an already-visited page (which the
generic ``TaskDispatcher`` duplicate gate would only catch after the fact).

``BrowserPlanner`` is the public thin wrapper: when a ``model_router`` is
provided it constructs a ``PlanningEngine`` and routes through it; otherwise
it delegates directly to ``_BrowserDeterministic`` — same
``_<Name>Deterministic`` + thin-wrapper convention as every other domain
planner (CLAUDE.md §15.2).
"""
from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

from memfabric.ids import new_id, now
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planners.web_planner import _base_url, _url_from_cap
from apex_host.planners.web_opportunities import (
    select_unvisited_endpoints,
    visited_urls_from_subgraph,
)
from apex_host.planning.models import PlanDecision
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.llm.gateway import LLMGateway
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.planning.engine import PlanningEngine
    from apex_host.policy.llm_guard import LLMPolicyGuard


def _host_from_url(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


class _BrowserDeterministic:
    """Pure rule-based browser planner — the fallback for PlanningEngine."""

    def __init__(self, target: str, registry: ToolRegistry) -> None:
        self._target = target
        self._registry = registry

    def _resolve_base_url(self, subgraph: SubgraphView) -> str:
        caps = [c for c in capabilities_from_subgraph(subgraph) if c.name == "web_probe"]
        caps_sorted = sorted(caps, key=lambda c: c.confidence, reverse=True)
        if caps_sorted:
            return _url_from_cap(caps_sorted[0].target, caps_sorted[0].port)
        return _base_url(self._target)

    def _build_task(self, goal: Goal, url: str) -> TaskSpec:
        return TaskSpec(
            id=new_id(),
            goal_id=goal.id,
            executor_domain="browser",
            params={"tool": "browser", "url": url, "target": self._target, "args": []},
            subgraph_anchor=goal.anchor_node,
            phase=goal.phase,
        )

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        base = self._resolve_base_url(subgraph)
        visited = visited_urls_from_subgraph(subgraph)

        # Priority candidates considered before any discovered link — see
        # module docstring "Visit priority".
        for candidate in (base, f"{base.rstrip('/')}/robots.txt", f"{base.rstrip('/')}/sitemap.xml"):
            if candidate not in visited:
                return [self._build_task(goal, candidate)]

        host = _host_from_url(base) or self._target
        discovered = select_unvisited_endpoints(subgraph, host)
        if discovered:
            next_url = str(discovered[0].props.get("url", ""))
            if next_url:
                return [self._build_task(goal, next_url)]

        return AbandonSignal(
            reason=(
                "all discovered pages already inspected by the browser; "
                "no new pages to visit"
            )
        )


class BrowserPlanner:
    """Thin wrapper: routes through PlanningEngine when model_router is provided,
    falls back to _BrowserDeterministic otherwise."""

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
        self._core = _BrowserDeterministic(target, registry)
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
            return await self._engine.plan(goal, ApexPhase.web, subgraph, evidence)
        self._last_decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="deterministic",
            fallback_used=True,
            timestamp=now(),
            phase=ApexPhase.web.value,
        )
        return await self._core.plan(goal, subgraph, evidence)
