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

Budget and observability
------------------------
- An optional ``LLMBudgetTracker`` (from ``apex_host.planning.budget``) is
  consulted before every LLM call.  When either the global run budget or the
  per-phase budget is exhausted, the engine falls back immediately.
- Context-hash comparison detects when the EKG + evidence is unchanged since
  the last call for this phase; the LLM is then skipped to save the budget.
- Every call is timed and the elapsed time is logged at INFO level:
    ``LLM call 2/5 phase=recon model=gpt-5 elapsed=14.7s result=success tasks=1``
- Exceptions are classified as ``"permanent"`` (never retry: 4xx) or
  ``"transient"`` (retry bounded: timeout, 429, 5xx) before the retry loop.

Invariants preserved
--------------------
- MemoryAPI is the sole state source (Invariant 1): the engine reads context
  through the ``EvidenceBundle`` and ``SubgraphView`` passed in, never
  directly from any store.
- Executors and planners are stateless (Invariant 6): the engine itself holds
  no mutable turn state beyond ``last_decision``.
- No agent-to-agent calls (Invariant 7): the engine writes nothing; all state
  changes flow through MemoryAPI in the graph's merge node.
"""
from __future__ import annotations

import hashlib
import logging
import time
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
    from apex_host.llm.gateway import LLMGateway
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.policy.llm_guard import LLMPolicyGuard


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

# HTTP status codes that should never be retried (permanent auth/route errors).
_PERMANENT_HTTP_STATUSES: frozenset[int] = frozenset({400, 401, 403, 404})

# Exception type name suffixes that indicate a permanent (non-retriable) error.
_PERMANENT_EXC_SUFFIXES: frozenset[str] = frozenset({
    "AuthenticationError",
    "PermissionDeniedError",
    "NotFoundError",
    "BadRequestError",
})


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
# Context hash — lightweight fingerprint for repeated-context detection
# ---------------------------------------------------------------------------

def _context_hash(subgraph: SubgraphView, evidence: EvidenceBundle) -> str:
    """Return a content-sensitive hash representing the structural state of the context.

    Hashes the sorted set of node IDs, edge IDs, and evidence entry IDs so that
    two calls with the same count but different IDs (e.g. one node replaced by
    another) produce different hashes — preventing stale-context false positives.
    """
    node_ids = sorted(n.id for n in subgraph.nodes)
    edge_ids = sorted(e.id for e in subgraph.edges)
    entry_ids = sorted(e.id for e in evidence.entries)
    data = f"n:{','.join(node_ids)}|e:{','.join(edge_ids)}|ev:{','.join(entry_ids)}"
    return hashlib.md5(data.encode()).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------

def _classify_error(exc: Exception) -> tuple[str, int | None]:
    """Classify an LLM exception as ``"permanent"`` or ``"transient"``.

    Returns ``(category, http_status)`` where ``category`` is one of:
    - ``"permanent"`` — should never be retried (401, 403, 404, bad request).
    - ``"transient"`` — may be retried (timeout, 429, 5xx, connection errors).

    Extracts the HTTP status from the exception's ``status_code`` attribute or
    nested ``response.status_code`` without importing the openai package.
    """
    # Extract HTTP status without requiring openai to be importable.
    http_status: int | None = None
    raw_status = getattr(exc, "status_code", None)
    if isinstance(raw_status, int):
        http_status = raw_status
    if http_status is None:
        response = getattr(exc, "response", None)
        if response is not None:
            nested = getattr(response, "status_code", None)
            if isinstance(nested, int):
                http_status = nested

    if http_status is not None and http_status in _PERMANENT_HTTP_STATUSES:
        return "permanent", http_status

    # Classify by exception type name suffix (no openai import required).
    exc_type = type(exc).__name__
    if any(exc_type.endswith(suffix) for suffix in _PERMANENT_EXC_SUFFIXES):
        return "permanent", http_status

    return "transient", http_status


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
    - Budget checking via an optional ``LLMBudgetTracker``.
    - Repeated-context detection (skip LLM when context is unchanged).
    - Building the structured prompt via ``PromptBuilder``.
    - Validating the LLM response via ``Validator``.
    - Error classification: permanent (401/403/404 — never retry) vs
      transient (timeout/429/5xx — retry bounded).
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
    budget:
        Optional shared ``LLMBudgetTracker``.  When provided, every call is
        counted against global and per-phase call budgets.  When ``None``
        (the default), no budget is enforced.
    """

    def __init__(
        self,
        model_router: "ModelRouter",
        fallback_planner: _FallbackPlanner,
        allowed_tools: list[str],
        target: str = "",
        confidence_threshold: float = 0.4,
        max_retries: int = 1,
        guard: "LLMPolicyGuard | None" = None,
        budget: "LLMBudgetTracker | None" = None,
        gateway: "LLMGateway | None" = None,
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
        self._guard = guard
        self._budget = budget
        # When a pre-constructed LLMGateway is injected, all LLM invocations
        # route through it (atomic budget, guard, audit).  No direct model call
        # occurs in this file when _gateway is not None.
        self._gateway: "LLMGateway | None" = gateway

    @property
    def last_decision(self) -> PlanDecision | None:
        """Most recent ``PlanDecision`` from the last ``plan()`` call.

        Reading this property immediately after ``await planner.plan()`` is
        safe because the graph is single-threaded async and there is no
        ``await`` between the read and the property access in any call site.
        """
        return self._last_decision

    def _record_fallback(
        self,
        phase: ApexPhase,
        *,
        policy_checkpoint_status: str = "",
        redaction_count: int = 0,
        policy_block_reason: str = "",
        repeated_plan_detected: bool = False,
        repeated_plan_count: int = 0,
        repeated_plan_action: str = "",
        llm_error_category: str = "",
        llm_http_status: int | None = None,
        llm_retry_count: int = 0,
    ) -> None:
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
            policy_checkpoint_status=policy_checkpoint_status,
            redaction_count=redaction_count,
            policy_block_reason=policy_block_reason,
            repeated_plan_detected=repeated_plan_detected,
            repeated_plan_count=repeated_plan_count,
            repeated_plan_action=repeated_plan_action,
            llm_error_category=llm_error_category,
            llm_http_status=llm_http_status,
            llm_retry_count=llm_retry_count,
        )

    def _record_llm(
        self,
        output: PlannerOutput,
        phase: ApexPhase,
        *,
        fallback_used: bool = False,
        policy_checkpoint_status: str = "",
        redaction_count: int = 0,
        policy_block_reason: str = "",
        repeated_plan_detected: bool = False,
        repeated_plan_count: int = 0,
        repeated_plan_action: str = "",
        llm_error_category: str = "",
        llm_http_status: int | None = None,
        llm_retry_count: int = 0,
    ) -> None:
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
            policy_checkpoint_status=policy_checkpoint_status,
            redaction_count=redaction_count,
            policy_block_reason=policy_block_reason,
            repeated_plan_detected=repeated_plan_detected,
            repeated_plan_count=repeated_plan_count,
            repeated_plan_action=repeated_plan_action,
            llm_error_category=llm_error_category,
            llm_http_status=llm_http_status,
            llm_retry_count=llm_retry_count,
        )

    async def _plan_via_gateway(
        self,
        goal: Goal,
        phase: ApexPhase,
        subgraph: SubgraphView,
        evidence: EvidenceBundle,
    ) -> "list[TaskSpec] | AbandonSignal":
        """Route all LLM invocations through the injected ``LLMGateway``.

        This path is taken when ``self._gateway is not None``.  The gateway
        handles atomic budget reservation, prompt sanitization, pre/post guard
        checks, timeout, and audit logging.  This method only handles
        validation retries and TaskSpec conversion.

        Retry policy (simplified — provider errors handled by gateway):
        - Validator rejection: retry up to ``max_retries`` times, then fallback.
        - No tasks in output: retry up to ``max_retries`` times, then fallback.
        - Low confidence: fallback immediately (no retry — epistemic signal).
        - Non-success gateway status: fallback immediately (no retry).
        """
        from apex_host.llm.gateway import LLMCallContext, LLMCallPurpose

        # Repeated-context detection — same logic as direct path.
        ctx_hash = _context_hash(subgraph, evidence)
        if self._budget is not None and self._budget.is_context_repeated(phase.value, ctx_hash):
            repeated_count = self._budget.record_repeated_skip(phase.value)
            self._budget.record_fallback_only()
            self._record_fallback(
                phase,
                repeated_plan_detected=True,
                repeated_plan_count=repeated_count,
                repeated_plan_action="skipped_llm",
            )
            return await self._fallback.plan(goal, subgraph, evidence)

        # Build prompt messages.
        ekg_summary = summarize_subgraph(subgraph)
        messages = self._prompt_builder.build_messages(
            goal, phase, evidence, ekg_summary, self._allowed_tools
        )

        ctx = LLMCallContext(
            purpose=LLMCallPurpose.planning,
            phase=phase.value,
            messages=messages,
            allowed_tools=self._allowed_tools,
        )

        _retry_count = 0

        for attempt in range(self._max_retries + 1):
            assert self._gateway is not None  # type narrowing
            result = await self._gateway.invoke(ctx)

            if not result.status.is_success:
                # Gateway returned non-success (budget exhausted, blocked, error, etc.)
                # Do not retry — the gateway already handles provider retries internally.
                _checkpoint = "blocked" if result.status.is_blocked else ""
                logger.info(
                    "planning_engine[gateway]: status=%s phase=%s — falling back",
                    result.status.value, phase.value,
                )
                if self._budget is not None:
                    self._budget.record_fallback_only()
                self._record_fallback(
                    phase,
                    policy_checkpoint_status=_checkpoint,
                    redaction_count=result.redaction_count,
                    policy_block_reason=result.blocked_reason,
                    llm_error_category=result.status.value,
                    llm_retry_count=_retry_count,
                )
                return await self._fallback.plan(goal, subgraph, evidence)

            raw = result.raw_text
            _redaction_count = result.redaction_count
            _checkpoint_status = "redacted" if _redaction_count > 0 else "clean"

            # Validate the raw output (gateway's post-call guard already ran).
            output = self._validator.validate(raw, self._allowed_tools)
            if output is None:
                logger.info(
                    "planning_engine[gateway]: validator rejected (attempt %d/%d) — %s",
                    attempt + 1, self._max_retries + 1,
                    "retrying" if attempt < self._max_retries else "falling back",
                )
                if attempt < self._max_retries:
                    _retry_count += 1
                    continue
                self._record_fallback(
                    phase,
                    policy_checkpoint_status=_checkpoint_status,
                    redaction_count=_redaction_count,
                    llm_error_category="validation",
                    llm_retry_count=_retry_count,
                )
                return await self._fallback.plan(goal, subgraph, evidence)

            # Low confidence — epistemic signal, not transient; fallback immediately.
            if output.confidence < self._confidence_threshold:
                logger.info(
                    "planning_engine[gateway]: confidence %.2f < threshold %.2f phase=%s — falling back",
                    output.confidence, self._confidence_threshold, phase.value,
                )
                self._record_llm(
                    output, phase,
                    fallback_used=True,
                    policy_checkpoint_status=_checkpoint_status,
                    redaction_count=_redaction_count,
                    llm_retry_count=_retry_count,
                )
                return await self._fallback.plan(goal, subgraph, evidence)

            # Stop signal from LLM.
            if output.stop_reason:
                logger.info(
                    "planning_engine[gateway]: stop_reason=%s phase=%s",
                    output.stop_reason, phase.value,
                )
                self._record_llm(
                    output, phase,
                    policy_checkpoint_status=_checkpoint_status,
                    redaction_count=_redaction_count,
                    llm_retry_count=_retry_count,
                )
                return AbandonSignal(reason=output.stop_reason)

            # No tasks — retry.
            if not output.selected_tasks:
                logger.info(
                    "planning_engine[gateway]: no tasks (attempt %d/%d) — %s",
                    attempt + 1, self._max_retries + 1,
                    "retrying" if attempt < self._max_retries else "falling back",
                )
                if attempt < self._max_retries:
                    _retry_count += 1
                    continue
                self._record_fallback(
                    phase,
                    policy_checkpoint_status=_checkpoint_status,
                    redaction_count=_redaction_count,
                    llm_error_category="validation",
                    llm_retry_count=_retry_count,
                )
                return await self._fallback.plan(goal, subgraph, evidence)

            # Success — convert to TaskSpecs.
            task_specs = [
                _to_task_spec(t, goal, self._target) for t in output.selected_tasks
            ]
            # Update context hash so repeated-context detection works next call.
            if self._budget is not None:
                self._budget.record_context(phase.value, ctx_hash)
            self._record_llm(
                output, phase,
                policy_checkpoint_status=_checkpoint_status,
                redaction_count=_redaction_count,
                llm_retry_count=_retry_count,
            )
            return task_specs

        # Exhausted retries.
        self._record_fallback(phase, llm_retry_count=_retry_count)
        return await self._fallback.plan(goal, subgraph, evidence)

    async def plan(
        self,
        goal: Goal,
        phase: ApexPhase,
        subgraph: SubgraphView,
        evidence: EvidenceBundle,
    ) -> list[TaskSpec] | AbandonSignal:
        """Produce a plan for *goal* in *phase*.

        Routes through ``LLMGateway`` when one was injected at construction;
        otherwise uses the direct provider path (backward-compatible fallback
        for tests and contexts where no gateway is available).

        Returns a list of ``TaskSpec`` objects (possibly empty) or an
        ``AbandonSignal``.  Never raises — any internal failure results in
        a fallback to the deterministic planner.

        Retry policy (direct path only — gateway path delegates retries):
        - Permanent errors (401, 403, 404, BadRequest): no retry, immediate
          fallback.
        - Transient errors (timeout, 429, 5xx): retry up to ``max_retries``
          times, then fallback.
        - Validator rejection: retry up to ``max_retries`` times, then fallback.
        - Low confidence (< ``confidence_threshold``): fallback immediately
          without retrying — low confidence is a signal, not a transient error.
        """
        if self._gateway is not None:
            return await self._plan_via_gateway(goal, phase, subgraph, evidence)

        llm = self._router.planner_llm()
        if llm is None:
            logger.debug("planning_engine: no LLM configured — using fallback planner")
            if self._budget is not None:
                self._budget.record_fallback_only()
            self._record_fallback(phase)
            return await self._fallback.plan(goal, subgraph, evidence)

        # ------------------------------------------------------------------ #
        # Budget check
        # ------------------------------------------------------------------ #
        if self._budget is not None:
            can_call, budget_reason = self._budget.can_call(phase.value)
            if not can_call:
                logger.info(
                    "planning_engine: budget blocked LLM call (%s) — using fallback",
                    budget_reason,
                )
                self._budget.record_fallback_only()
                self._record_fallback(phase, llm_error_category="budget_exhausted")
                return await self._fallback.plan(goal, subgraph, evidence)

        # ------------------------------------------------------------------ #
        # Repeated-context detection (skip LLM when nothing changed)
        # ------------------------------------------------------------------ #
        ctx_hash = _context_hash(subgraph, evidence)
        if self._budget is not None and self._budget.is_context_repeated(phase.value, ctx_hash):
            repeated_count = self._budget.record_repeated_skip(phase.value)
            self._budget.record_fallback_only()
            self._record_fallback(
                phase,
                repeated_plan_detected=True,
                repeated_plan_count=repeated_count,
                repeated_plan_action="skipped_llm",
            )
            return await self._fallback.plan(goal, subgraph, evidence)

        # ------------------------------------------------------------------ #
        # Prompt building and guard sanitization
        # ------------------------------------------------------------------ #
        ekg_summary = summarize_subgraph(subgraph)
        messages = self._prompt_builder.build_messages(
            goal, phase, evidence, ekg_summary, self._allowed_tools
        )
        chat_llm = cast(_LLMChatModel, llm)

        _redaction_count = 0
        _checkpoint_status = ""
        if self._guard is not None:
            messages, _redaction_count = self._guard.sanitize_messages(messages)
            _checkpoint_status = "redacted" if _redaction_count > 0 else "clean"
            if _redaction_count > 0:
                logger.debug(
                    "planning_engine: %d secret(s) redacted from prompt", _redaction_count
                )
            prompt_blocked, prompt_reason = self._guard.check_prompt(messages)
            if prompt_blocked:
                logger.warning(
                    "planning_engine: prompt blocked by LLM guard (%s) — falling back",
                    prompt_reason,
                )
                if self._budget is not None:
                    self._budget.record_fallback_only()
                self._record_fallback(
                    phase,
                    policy_checkpoint_status="blocked",
                    redaction_count=_redaction_count,
                    policy_block_reason=prompt_reason,
                )
                return await self._fallback.plan(goal, subgraph, evidence)

        # ------------------------------------------------------------------ #
        # Consume budget slot — we are committed to attempting the LLM call
        # ------------------------------------------------------------------ #
        if self._budget is not None:
            self._budget.record_call_start(phase.value)

        # Try to derive a model name for logging (best-effort, no import required).
        _model_name = ""
        try:
            _cfg = getattr(self._router, "_config", None)
            if _cfg is not None:
                _model_name = str(getattr(_cfg, "planner_model", "")) or ""
        except Exception:
            pass

        last_output: PlannerOutput | None = None
        _retry_count = 0
        t0 = time.monotonic()

        for attempt in range(self._max_retries + 1):
            try:
                response = chat_llm.invoke(messages)
                raw = str(getattr(response, "content", response))

            except Exception as exc:
                error_category, http_status = _classify_error(exc)
                elapsed = time.monotonic() - t0
                _retry_count = attempt

                if error_category == "permanent":
                    # Never retry permanent errors.
                    logger.warning(
                        "planning_engine: permanent LLM error (attempt %d/%d) "
                        "status=%s exc=%s — falling back immediately",
                        attempt + 1, self._max_retries + 1,
                        http_status or "?", exc,
                    )
                    if self._budget is not None:
                        self._budget.record_failure(
                            phase.value, elapsed, "permanent", http_status, _model_name,
                        )
                    self._record_fallback(
                        phase,
                        policy_checkpoint_status=_checkpoint_status,
                        redaction_count=_redaction_count,
                        llm_error_category="permanent",
                        llm_http_status=http_status,
                        llm_retry_count=_retry_count,
                    )
                    return await self._fallback.plan(goal, subgraph, evidence)

                # Transient error — retry if attempts remain.
                logger.warning(
                    "planning_engine: transient LLM error (attempt %d/%d) "
                    "exc=%s — %s",
                    attempt + 1, self._max_retries + 1, exc,
                    "retrying" if attempt < self._max_retries else "falling back",
                )
                if attempt < self._max_retries:
                    if self._budget is not None:
                        self._budget.record_retry()
                    _retry_count += 1
                    continue

                if self._budget is not None:
                    self._budget.record_failure(
                        phase.value, elapsed, "transient", http_status, _model_name,
                    )
                self._record_fallback(
                    phase,
                    policy_checkpoint_status=_checkpoint_status,
                    redaction_count=_redaction_count,
                    llm_error_category="transient",
                    llm_http_status=http_status,
                    llm_retry_count=_retry_count,
                )
                return await self._fallback.plan(goal, subgraph, evidence)

            # ---------------------------------------------------------------- #
            # Post-output guard check
            # ---------------------------------------------------------------- #
            if self._guard is not None:
                out_blocked, out_reason = self._guard.check_output(raw)
                if out_blocked:
                    logger.warning(
                        "planning_engine: attempt %d/%d output blocked by LLM guard (%s) — %s",
                        attempt + 1,
                        self._max_retries + 1,
                        out_reason,
                        "retrying" if attempt < self._max_retries else "falling back",
                    )
                    if attempt < self._max_retries:
                        if self._budget is not None:
                            self._budget.record_retry()
                        _retry_count += 1
                        continue
                    elapsed = time.monotonic() - t0
                    if self._budget is not None:
                        self._budget.record_failure(
                            phase.value, elapsed, "validation", None, _model_name,
                        )
                    self._record_fallback(
                        phase,
                        policy_checkpoint_status="blocked",
                        redaction_count=_redaction_count,
                        policy_block_reason=out_reason,
                        llm_error_category="validation",
                        llm_retry_count=_retry_count,
                    )
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
                    if self._budget is not None:
                        self._budget.record_retry()
                    _retry_count += 1
                    continue
                elapsed = time.monotonic() - t0
                if self._budget is not None:
                    self._budget.record_failure(
                        phase.value, elapsed, "validation", None, _model_name,
                    )
                self._record_fallback(
                    phase,
                    policy_checkpoint_status=_checkpoint_status,
                    redaction_count=_redaction_count,
                    llm_error_category="validation",
                    llm_retry_count=_retry_count,
                )
                return await self._fallback.plan(goal, subgraph, evidence)

            last_output = output

            # Low confidence: advisory log + hard fallback (don't retry — it's
            # epistemic, not transient).
            if output.confidence < self._confidence_threshold:
                elapsed = time.monotonic() - t0
                logger.info(
                    "planning_engine: confidence %.2f < threshold %.2f (phase=%s) — falling back",
                    output.confidence,
                    self._confidence_threshold,
                    phase.value,
                )
                if self._budget is not None:
                    self._budget.record_failure(
                        phase.value, elapsed, "low_confidence", None, _model_name,
                    )
                self._record_llm(
                    output,
                    phase,
                    fallback_used=True,
                    policy_checkpoint_status=_checkpoint_status,
                    redaction_count=_redaction_count,
                    llm_retry_count=_retry_count,
                )
                return await self._fallback.plan(goal, subgraph, evidence)

            if output.stop_reason:
                elapsed = time.monotonic() - t0
                logger.info(
                    "planning_engine: LLM signalled stop — reason: %s",
                    output.stop_reason,
                )
                if self._budget is not None:
                    self._budget.record_success(
                        phase.value, elapsed, 0, ctx_hash, _model_name,
                    )
                self._record_llm(
                    output,
                    phase,
                    policy_checkpoint_status=_checkpoint_status,
                    redaction_count=_redaction_count,
                    llm_retry_count=_retry_count,
                )
                return AbandonSignal(reason=output.stop_reason)

            if not output.selected_tasks:
                logger.info(
                    "planning_engine: no tasks in output (attempt %d) — %s",
                    attempt + 1,
                    "retrying" if attempt < self._max_retries else "falling back",
                )
                if attempt < self._max_retries:
                    if self._budget is not None:
                        self._budget.record_retry()
                    _retry_count += 1
                    continue
                elapsed = time.monotonic() - t0
                if self._budget is not None:
                    self._budget.record_failure(
                        phase.value, elapsed, "validation", None, _model_name,
                    )
                self._record_fallback(
                    phase,
                    policy_checkpoint_status=_checkpoint_status,
                    redaction_count=_redaction_count,
                    llm_error_category="validation",
                    llm_retry_count=_retry_count,
                )
                return await self._fallback.plan(goal, subgraph, evidence)

            # ---------------------------------------------------------------- #
            # Success path
            # ---------------------------------------------------------------- #
            elapsed = time.monotonic() - t0
            task_specs = [
                _to_task_spec(t, goal, self._target) for t in output.selected_tasks
            ]
            if self._budget is not None:
                self._budget.record_success(
                    phase.value, elapsed, len(task_specs), ctx_hash, _model_name,
                )
            logger.debug(
                "planning_engine: LLM produced %d task(s) for phase=%s (attempt %d)",
                len(task_specs),
                phase.value,
                attempt + 1,
            )
            self._record_llm(
                output,
                phase,
                policy_checkpoint_status=_checkpoint_status,
                redaction_count=_redaction_count,
                llm_retry_count=_retry_count,
            )
            return task_specs

        # Exhausted all retries without a conclusive result.
        elapsed = time.monotonic() - t0
        if last_output is not None:
            if self._budget is not None:
                self._budget.record_failure(
                    phase.value, elapsed, "validation", None, _model_name,
                )
            self._record_llm(
                last_output,
                phase,
                fallback_used=True,
                policy_checkpoint_status=_checkpoint_status,
                redaction_count=_redaction_count,
                llm_retry_count=_retry_count,
            )
        else:
            if self._budget is not None:
                self._budget.record_failure(
                    phase.value, elapsed, "transient", None, _model_name,
                )
            self._record_fallback(
                phase,
                policy_checkpoint_status=_checkpoint_status,
                redaction_count=_redaction_count,
                llm_retry_count=_retry_count,
            )
        return await self._fallback.plan(goal, subgraph, evidence)
