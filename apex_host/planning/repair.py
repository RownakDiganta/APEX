# repair.py
# RepairEngine: generates a RepairRequest (containing a corrected TaskSpec) when a task fails.
"""Repair planner for failed task correction.

``RepairEngine`` is called by the ``repair_agent`` graph node when a task
fails with a ``script_error`` or ``fixable`` ``Outcome``.

Architecture
------------
``repair()`` returns a **``RepairRequest``** (not a ``TaskSpec`` directly).
``repair_agent`` in ``graph.py`` extracts the contained ``TaskSpec`` and
routes it through the normal pre-execution safeguards:

  1. Conflict guard — ``dependents_blocked_by()`` for any claim dependencies.
  2. Duplicate guard — same action-deduplication logic as main execution.
  3. Policy gate  — ``PolicyAdvisor.review_task()`` (already in repair_agent).

Only after all three checks pass does ``repair_agent`` execute the repaired
task via ``runner.py``.

``RepairEngine`` itself NEVER executes a task.  It produces a request and
returns.  Execution is strictly the graph's responsibility.

LLM invocation path
--------------------
All model calls go through ``LLMGateway.invoke()``:

  1. Atomic budget reservation.
  2. Prompt sanitization and pre-call guard check.
  3. Provider invocation in a thread pool (never blocks event loop).
  4. Post-call guard check.
  5. Reservation commit or fail.

No direct ``chat_llm.invoke()`` call exists in this file.

Safety invariants (non-negotiable)
------------------------------------
- Returns ``None`` immediately when ``config.dry_run is True``.
- Returns ``None`` when no gateway/router is available.
- All proposed args go through the same ``Validator`` used by
  ``PlanningEngine``.
- Only one corrected ``TaskSpec`` is produced per call.
- Secret material is redacted from prompts by the gateway before any
  provider I/O.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from memfabric.types import (
    ClaimDependency,
    EvidenceBundle,
    Goal,
    SubgraphView,
    TaskSpec,
)

from apex_host.planning.engine import _to_task_spec, summarize_subgraph
from apex_host.planning.validator import Validator

if TYPE_CHECKING:
    from apex_host.llm.gateway import LLMGateway
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.policy.llm_guard import LLMPolicyGuard

logger = logging.getLogger(__name__)

_REPAIR_SCHEMA = json.dumps(
    {
        "reasoning": "<string: why the previous call failed and what to change>",
        "confidence": "<float 0..1>",
        "selected_tasks": [
            {
                "tool": "<tool name from allowed list>",
                "args": ["<corrected arg1>", "<corrected arg2>"],
                "parser": "<nmap|banner|command|curl_body|ffuf|gobuster|access>",
                "executor_domain": "<recon|web|credential|priv_esc>",
                "target": "<target IP or URL>",
                "rationale": "<one-line: what was fixed>",
            }
        ],
        "rejected_tasks": [],
        "stop_reason": "<null or 'cannot_repair' if fix is impossible>",
        "next_phase": None,
    },
    indent=2,
)

_REPAIR_SYSTEM = """\
You are APEX-Repair, a focused task-correction planner.
A tool call in an authorized penetration test failed.  Your ONLY job is to
produce ONE corrected version of the failing task.

CRITICAL RULES:
- Only use tools from the ALLOWED TOOLS list.
- Never propose destructive commands (rm, mkfs, dd, shutdown, reboot, halt, format).
- Never include shell operators (;, &&, ||, |, >, >>, <, $(), `) in args.
- Produce exactly ONE corrected task — no chains, no sequences.
- Set stop_reason="cannot_repair" if you cannot determine a safe correction.
- Output ONLY valid JSON matching the schema — no prose before or after.

OUTPUT SCHEMA:
{schema}
""".format(schema=_REPAIR_SCHEMA)


def _build_repair_messages(
    failed_task: TaskSpec,
    error: str,
    phase: str,
    ekg_summary: str,
    allowed_tools: list[str],
) -> list[dict[str, str]]:
    """Build [system_msg, user_msg] for the repair LLM."""
    tool = str(failed_task.params.get("tool", ""))
    args = list(failed_task.params.get("args", []))
    parser = str(failed_task.params.get("parser", "command"))
    target = str(failed_task.params.get("target", ""))

    user_content = "\n".join([
        f"PHASE: {phase}",
        f"FAILED TOOL: {tool}",
        f"FAILED ARGS: {json.dumps(args)}",
        f"PARSER: {parser}",
        f"TARGET: {target}",
        f"ERROR: {error}",
        "",
        "ALLOWED TOOLS:",
        "  " + ", ".join(allowed_tools) if allowed_tools else "  (none)",
        "",
        "EKG STATE:",
        ekg_summary or "  (empty — no nodes observed yet)",
        "",
        "Produce ONE corrected task or set stop_reason=cannot_repair.",
        "Output your JSON plan now.",
    ])
    return [
        {"role": "system", "content": _REPAIR_SYSTEM},
        {"role": "user", "content": user_content},
    ]


# ---------------------------------------------------------------------------
# RepairRequest — typed result returned by RepairEngine.repair()
# ---------------------------------------------------------------------------


@dataclass
class RepairRequest:
    """A validated corrected task produced by ``RepairEngine``.

    ``repair_agent`` in ``graph.py`` extracts ``repaired_task`` and routes it
    through the conflict guard, duplicate guard, and policy gate before
    execution.  ``RepairEngine`` itself does NOT execute.

    Fields
    ------
    original_task_id:
        ID of the ``TaskSpec`` that failed.
    repaired_task:
        The corrected ``TaskSpec`` ready for pre-execution safeguard checks.
    repair_attempt:
        0-based repair count for this turn (from ``state["repair_count"]``).
    failure_reason:
        The error string from the failing tool result.
    phase:
        Phase during which the failure occurred.
    target:
        Primary engagement target (IP or URL).
    origin_skill_id:
        ID of the ``Skill`` that suggested the original task, if known.
    claim_dependencies:
        Copied from the original ``TaskSpec``.
    """

    original_task_id: str
    repaired_task: TaskSpec
    repair_attempt: int
    failure_reason: str
    phase: str
    target: str
    origin_skill_id: str | None = None
    claim_dependencies: tuple[ClaimDependency, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# RepairEngine
# ---------------------------------------------------------------------------


class RepairEngine:
    """Produces a ``RepairRequest`` when a planner task fails.

    ``repair()`` is the only public entry point.  It returns ``None``
    immediately when no LLM is available or when ``dry_run=True``.

    Parameters
    ----------
    model_router:
        A ``ModelRouter`` instance (used to create an internal gateway when
        no explicit gateway is injected).  ``FakeModelRouter`` returns ``None``
        for all roles — repair becomes a no-op.
    allowed_tools:
        Tool names permitted in the current engagement.
    target:
        Primary engagement target.
    dry_run:
        When ``True``, ``repair()`` returns ``None`` without any LLM call.
    guard:
        ``LLMPolicyGuard`` for prompt/output content checks.  Passed to the
        internal gateway.
    budget_tracker:
        Shared budget tracker.  Passed to the internal gateway so repair calls
        compete for the same run-level budget as planning calls.
    gateway:
        Pre-constructed ``LLMGateway`` (injected by ``build_apex_graph``).
        When provided, ``model_router``, ``guard``, and ``budget_tracker`` are
        ignored for invocation purposes (the gateway owns them).
    """

    def __init__(
        self,
        model_router: "ModelRouter | None",
        allowed_tools: list[str],
        target: str = "",
        dry_run: bool = True,
        guard: "LLMPolicyGuard | None" = None,
        budget_tracker: "LLMBudgetTracker | None" = None,
        gateway: "LLMGateway | None" = None,
    ) -> None:
        self._router = model_router
        self._allowed_tools = allowed_tools
        self._target = target
        self._dry_run = dry_run
        self._validator = Validator()
        self._guard = guard
        self._budget = budget_tracker

        # Use injected gateway if provided; else create one from router.
        # Lazy import breaks circular dependency between planning.repair and llm.gateway.
        from apex_host.llm.gateway import LLMGateway as _LLMGateway
        if gateway is not None:
            self._gateway: "_LLMGateway | None" = gateway
        elif model_router is not None:
            self._gateway = _LLMGateway(
                model_router=model_router,
                budget=budget_tracker,
                guard=guard,
            )
        else:
            self._gateway = None

    async def repair(
        self,
        failed_task: TaskSpec,
        error: str,
        phase: str,
        evidence: EvidenceBundle,
        subgraph: SubgraphView,
        repair_attempt: int = 0,
    ) -> RepairRequest | None:
        """Return a ``RepairRequest`` or ``None`` if repair is unavailable.

        Parameters
        ----------
        failed_task:
            The ``TaskSpec`` that produced the failing tool result.
        error:
            The error string from the failing tool result.
        phase:
            The current engagement phase (``ApexPhase.value``).
        evidence:
            The ``EvidenceBundle`` from the current turn.
        subgraph:
            The current EKG subgraph.
        repair_attempt:
            Current repair count (0-based) for provenance in ``RepairRequest``.
        """
        if self._dry_run:
            logger.debug("repair_engine: dry_run=True — skipping repair")
            return None

        if self._gateway is None:
            logger.debug("repair_engine: no gateway/router configured — skipping repair")
            return None

        # Phase 2 (post-live-test debugging): a CONFIRMED permanent LLM
        # provider misconfiguration (missing key, invalid model,
        # authentication failure, unsupported endpoint, malformed
        # response — apex_host.llm.errors.PERMANENT_LLM_ERROR_CATEGORIES)
        # already observed anywhere this run (PlanningEngine records it on
        # the SAME shared LLMBudgetTracker — see
        # apex_host.planning.budget.LLMBudgetTracker
        # .permanent_provider_error_category's docstring) can never be
        # fixed by retrying the identical broken configuration from the
        # repair path either. Without this check, every failed task in a
        # live run with a broken LLM configuration would independently
        # attempt (and burn a real, doomed network call on) repair —
        # "A provider configuration error must not trigger repeated repair
        # attempts."
        if self._budget is not None and self._budget.permanent_provider_error_category:
            logger.debug(
                "repair_engine: skipping — confirmed permanent provider error %r already observed this run",
                self._budget.permanent_provider_error_category,
            )
            return None

        ekg_summary = summarize_subgraph(subgraph)
        messages = _build_repair_messages(
            failed_task, error, phase, ekg_summary, self._allowed_tools
        )

        from apex_host.llm.gateway import LLMCallContext as _LLMCallCtx, LLMCallPurpose as _LLMCallPurp
        ctx = _LLMCallCtx(
            purpose=_LLMCallPurp.repair,
            phase=phase,
            messages=messages,
            allowed_tools=self._allowed_tools,
        )
        result = await self._gateway.invoke(ctx)

        if not result.status.is_success:
            logger.debug(
                "repair_engine: gateway returned %s (phase=%s) — skipping repair",
                result.status.value, phase,
            )
            return None

        raw = result.raw_text
        output = self._validator.validate(raw, self._allowed_tools)
        if output is None:
            logger.info("repair_engine: validator rejected repair output — skipping")
            return None

        if output.stop_reason:
            logger.info("repair_engine: LLM signalled cannot_repair — skipping")
            return None

        if not output.selected_tasks:
            logger.info("repair_engine: no tasks in repair output — skipping")
            return None

        goal = Goal(
            id=failed_task.goal_id,
            description=f"repair/{phase}",
            phase=phase,
            anchor_node=failed_task.subgraph_anchor or "",
        )
        task_spec = _to_task_spec(output.selected_tasks[0], goal, self._target)
        logger.info(
            "repair_engine: produced RepairRequest tool=%s phase=%s attempt=%d",
            task_spec.params.get("tool"),
            phase,
            repair_attempt,
        )
        return RepairRequest(
            original_task_id=failed_task.id,
            repaired_task=task_spec,
            repair_attempt=repair_attempt,
            failure_reason=error,
            phase=phase,
            target=self._target,
            origin_skill_id=None,
            claim_dependencies=tuple(failed_task.claim_dependencies or ()),
        )
