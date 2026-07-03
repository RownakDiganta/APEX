# engine.py
# PlanningEngine — the only component that calls ModelRouter; wraps LLM invocation, validation, TaskSpec conversion, and deterministic fallback.
"""The LLM Planning Engine for apex_host.

``PlanningEngine`` is the **only** component in ``apex_host`` permitted to
call ``ModelRouter.planner_llm()``.  All planners that want LLM-backed
reasoning must go through this class; they must NOT call the router or
construct prompts directly.

Design
------
- When the router returns ``None`` (e.g. ``FakeModelRouter``), the engine
  immediately delegates to the ``fallback_planner`` — the deterministic
  rule-based planner registered at construction time.
- When a real LLM is configured, the engine builds a prompt via
  ``PromptBuilder``, invokes the model, validates the response via
  ``Validator``, and converts the ``PlannerOutput`` to ``TaskSpec`` objects.
- Any LLM exception or validator rejection triggers an automatic fallback to
  the deterministic planner — the engagement never stalls due to LLM issues.

Invariants preserved
--------------------
- MemoryAPI is the sole state source (Invariant 1): the engine reads context
  through the ``EvidenceBundle`` and ``SubgraphView`` passed in, never
  directly from any store.
- Executors and planners are stateless (Invariant 6): the engine itself holds
  no mutable turn state.
- No agent-to-agent calls (Invariant 7): the engine writes nothing; all state
  changes flow through MemoryAPI in the graph's merge node.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol, cast

from memfabric.ids import new_id
from memfabric.types import (
    AbandonSignal,
    EvidenceBundle,
    Goal,
    SubgraphView,
    TaskSpec,
)

from memfabric.ids import now

from apex_host.planning.models import PlanDecision, PlannedTask, PlannerOutput
from apex_host.planning.prompt_builder import PromptBuilder
from apex_host.planning.validator import Validator
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.llm.router import ModelRouter


class _LLMChatModel(Protocol):
    """Minimal protocol for a LangChain-compatible chat model.

    Any object returned by ``ModelRouter.planner_llm()`` that is not None
    must satisfy this protocol.  ``invoke`` accepts a list of message dicts
    (role + content) and returns an object whose ``.content`` attribute is
    the model's text reply.
    """

    def invoke(self, messages: list[dict[str, str]]) -> object: ...

logger = logging.getLogger(__name__)

# Confidence below this threshold causes the engine to log an advisory, but
# the plan is still executed if the validator otherwise accepts it.
_LOW_CONFIDENCE_THRESHOLD = 0.35


# ---------------------------------------------------------------------------
# Helper: summarize a SubgraphView into a compact text string
# ---------------------------------------------------------------------------

def summarize_subgraph(subgraph: SubgraphView | None) -> str:
    """Return a short text summary of an EKG subgraph for inclusion in prompts.

    The summary is intentionally terse — it describes node-type counts and a
    few key properties (IP, port, service name) so the LLM can orient itself
    without receiving raw node dicts.
    """
    if subgraph is None or not subgraph.nodes:
        return "(empty — no EKG nodes observed yet)"

    node_types: dict[str, list[str]] = {}
    for node in subgraph.nodes:
        entry = node_types.setdefault(node.type, [])
        if node.type == "host":
            entry.append(str(node.props.get("ip", node.id)))
        elif node.type == "service":
            port = node.props.get("port", "?")
            svc = node.props.get("service", "")
            entry.append(f"port {port}" + (f" ({svc})" if svc else ""))
        elif node.type in ("endpoint", "auth_flow"):
            entry.append(str(node.props.get("url", node.id))[:60])
        elif node.type == "tech":
            name = node.props.get("name", "")
            ver = node.props.get("version", "")
            entry.append(f"{name} {ver}".strip() or node.id)
        else:
            entry.append(node.id)

    lines = [f"anchor: {subgraph.anchor}"]
    for ntype, items in sorted(node_types.items()):
        lines.append(f"  {ntype} ({len(items)}): " + ", ".join(items[:5]))
    lines.append(f"  edges: {len(subgraph.edges)}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fallback planner Protocol
# ---------------------------------------------------------------------------

class _FallbackPlanner(Protocol):
    """The Planner Protocol — what every rule-based fallback planner provides."""

    async def plan(
        self,
        goal: Goal,
        subgraph: SubgraphView,
        evidence: EvidenceBundle,
    ) -> list[TaskSpec] | AbandonSignal: ...


# ---------------------------------------------------------------------------
# TaskSpec conversion
# ---------------------------------------------------------------------------

def _to_task_spec(
    task: PlannedTask,
    goal: Goal,
    default_target: str,
) -> TaskSpec:
    """Convert a ``PlannedTask`` (from LLM output) into a ``TaskSpec``."""
    params: dict[str, Any] = {
        "tool": task.tool,
        "args": list(task.args),
        "parser": task.parser,
        "target": task.target or default_target,
    }
    return TaskSpec(
        id=new_id(),
        goal_id=goal.id,
        executor_domain=task.executor_domain,
        params=params,
        subgraph_anchor=goal.anchor_node,
        phase=goal.phase,
    )


# ---------------------------------------------------------------------------
# PlanningEngine
# ---------------------------------------------------------------------------

class PlanningEngine:
    """Unified LLM planning interface for ``apex_host`` planners.

    Every planner in ``apex_host`` that may benefit from LLM reasoning
    should delegate to this engine.  The engine handles:

    - Calling ``ModelRouter.planner_llm()`` (the **only** place in
      ``apex_host`` where this call may be made).
    - Building the structured prompt via ``PromptBuilder``.
    - Validating the LLM response via ``Validator``.
    - Converting a valid ``PlannerOutput`` into ``TaskSpec`` objects.
    - Falling back to the deterministic ``fallback_planner`` on any error,
      invalid output, or when no LLM is configured.

    Parameters
    ----------
    model_router:
        A ``ModelRouter`` instance.  ``FakeModelRouter`` returns ``None``
        for all roles, which triggers the fallback immediately — safe for
        tests and dry-run engagements.
    fallback_planner:
        The rule-based planner to call when the LLM path is unavailable or
        produces invalid output.  This must implement
        ``async plan(goal, subgraph, evidence)``.
    allowed_tools:
        Tool names permitted in the current engagement (from
        ``ApexConfig.allowed_tools``).  Passed to ``Validator`` so the
        safety gate knows what is allowed.
    target:
        The primary engagement target (IP / hostname).  Used as the default
        ``target`` field on any ``TaskSpec`` produced by LLM output that
        omits the target.
    """

    def __init__(
        self,
        model_router: "ModelRouter",
        fallback_planner: _FallbackPlanner,
        allowed_tools: list[str],
        target: str = "",
        confidence_threshold: float = 0.4,
        max_retries: int = 1,
    ) -> None:
        self._router = model_router
        self._fallback = fallback_planner
        self._allowed_tools = allowed_tools
        self._target = target
        self._confidence_threshold = confidence_threshold
        self._max_retries = max_retries
        self._prompt_builder = PromptBuilder()
        self._validator = Validator()
        self._last_decision: PlanDecision | None = None

    @property
    def last_decision(self) -> PlanDecision | None:
        """Most recent ``PlanDecision`` from the last ``plan()`` call.

        Reading this property immediately after ``await planner.plan()`` is
        safe because the graph is single-threaded async and there is no
        ``await`` between the read and the property access in any call site.
        """
        return self._last_decision

    def _record_fallback(self, phase: ApexPhase) -> None:
        """Record a deterministic-fallback decision (no LLM output available)."""
        self._last_decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="deterministic",
            fallback_used=True,
            timestamp=now(),
            phase=phase.value,
        )

    def _record_llm(self, output: PlannerOutput, phase: ApexPhase, *, fallback_used: bool = False) -> None:
        """Record an LLM-backed decision (success or low-confidence fallback)."""
        self._last_decision = PlanDecision(
            planner_model="llm",
            confidence=output.confidence,
            selected_task_count=len(output.selected_tasks),
            rejected_task_count=len(output.rejected_tasks),
            reasoning_summary=output.reasoning[:200],
            fallback_used=fallback_used,
            timestamp=now(),
            phase=phase.value,
        )

    async def plan(
        self,
        goal: Goal,
        phase: ApexPhase,
        subgraph: SubgraphView,
        evidence: EvidenceBundle,
    ) -> list[TaskSpec] | AbandonSignal:
        """Produce a plan for *goal* in *phase*.

        Returns a list of ``TaskSpec`` objects (possibly empty) or an
        ``AbandonSignal``.  Never raises — any internal failure results in
        a fallback to the deterministic planner.

        Retry policy:
        - On LLM exception or validator rejection: retry up to ``max_retries``
          times, then fall back to the deterministic planner.
        - On low confidence (< ``confidence_threshold``): fall back immediately
          without retrying — low confidence is a signal, not a transient error.
        """
        llm = self._router.planner_llm()
        if llm is None:
            logger.debug("planning_engine: no LLM configured — using fallback planner")
            self._record_fallback(phase)
            return await self._fallback.plan(goal, subgraph, evidence)

        ekg_summary = summarize_subgraph(subgraph)
        messages = self._prompt_builder.build_messages(
            goal, phase, evidence, ekg_summary, self._allowed_tools
        )
        chat_llm = cast(_LLMChatModel, llm)

        last_output: PlannerOutput | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = chat_llm.invoke(messages)
                raw = str(getattr(response, "content", response))
            except Exception as exc:
                logger.warning(
                    "planning_engine: attempt %d/%d LLM error (%s) — %s",
                    attempt + 1,
                    self._max_retries + 1,
                    exc,
                    "retrying" if attempt < self._max_retries else "falling back",
                )
                if attempt < self._max_retries:
                    continue
                self._record_fallback(phase)
                return await self._fallback.plan(goal, subgraph, evidence)

            output: PlannerOutput | None = self._validator.validate(
                raw, self._allowed_tools
            )
            if output is None:
                logger.info(
                    "planning_engine: attempt %d/%d validator rejected — %s",
                    attempt + 1,
                    self._max_retries + 1,
                    "retrying" if attempt < self._max_retries else "falling back",
                )
                if attempt < self._max_retries:
                    continue
                self._record_fallback(phase)
                return await self._fallback.plan(goal, subgraph, evidence)

            last_output = output

            # Low confidence: advisory log + hard fallback (don't retry — it's
            # epistemic, not transient).
            if output.confidence < self._confidence_threshold:
                logger.info(
                    "planning_engine: confidence %.2f < threshold %.2f (phase=%s) — falling back",
                    output.confidence,
                    self._confidence_threshold,
                    phase.value,
                )
                self._record_llm(output, phase, fallback_used=True)
                return await self._fallback.plan(goal, subgraph, evidence)

            if output.stop_reason:
                logger.info(
                    "planning_engine: LLM signalled stop — reason: %s",
                    output.stop_reason,
                )
                self._record_llm(output, phase)
                return AbandonSignal(reason=output.stop_reason)

            if not output.selected_tasks:
                logger.info(
                    "planning_engine: no tasks in output (attempt %d) — %s",
                    attempt + 1,
                    "retrying" if attempt < self._max_retries else "falling back",
                )
                if attempt < self._max_retries:
                    continue
                self._record_fallback(phase)
                return await self._fallback.plan(goal, subgraph, evidence)

            task_specs = [
                _to_task_spec(t, goal, self._target) for t in output.selected_tasks
            ]
            logger.info(
                "planning_engine: LLM produced %d task(s) for phase=%s (attempt %d)",
                len(task_specs),
                phase.value,
                attempt + 1,
            )
            self._record_llm(output, phase)
            return task_specs

        if last_output is not None:
            self._record_llm(last_output, phase, fallback_used=True)
        else:
            self._record_fallback(phase)
        return await self._fallback.plan(goal, subgraph, evidence)
