# models.py
# Pydantic v2 models for structured LLM planner output — PlannerOutput, PlannedTask, and PlanDecision audit record.
"""Pydantic v2 models for the structured LLM planner response.

``PlannerOutput`` is the schema the LLM must conform to.  The ``Validator``
parses raw LLM text into this model, rejecting any output that does not
validate.  Keeping the schema here (not in engine.py) allows tests to
construct ``PlannerOutput`` instances directly without instantiating the
full engine.

``PlanDecision`` is an append-only audit record written to the episodic
stream after every planner invocation so the Reflector can learn from
both LLM-backed and deterministic decisions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from pydantic import BaseModel, Field


class PlannedTask(BaseModel):
    """One task proposed by the LLM planner.

    Maps directly onto ``memfabric.types.TaskSpec.params`` when the
    ``PlanningEngine`` converts valid ``PlannerOutput`` into ``TaskSpec``
    objects.  The LLM must populate ``tool`` and ``args``; all other fields
    have safe defaults so partial responses still validate.
    """

    tool: str
    args: list[str] = Field(default_factory=list)
    parser: str = "command"
    executor_domain: str = "recon"
    target: str = ""
    rationale: str = ""


@dataclass(slots=True)
class PlanDecision:
    """Append-only audit record for one planner invocation.

    Written to ``ApexGraphState.planner_decisions`` after every ``plan()``
    call so that the Reflector, the run report, and the JSON export can
    surface per-turn planning metadata without querying the episodic store.

    ``planner_model`` is ``"llm"`` when the LLM path was attempted,
    ``"deterministic"`` when only the rule-based fallback ran.
    ``fallback_used`` is ``True`` whenever the deterministic planner
    produced the final result, regardless of whether the LLM was tried first.

    LLM policy checkpoint fields (populated when ``LLMPolicyGuard`` is wired
    into ``PlanningEngine``):
    - ``policy_checkpoint_status``: ``""`` = guard not configured; ``"clean"``
      = guard ran, nothing flagged; ``"redacted"`` = guard applied redactions;
      ``"blocked"`` = guard blocked the prompt or output (fallback used).
    - ``redaction_count``: number of secret substitutions applied by
      ``sanitize_messages``.
    - ``policy_block_reason``: human-readable reason string when status is
      ``"blocked"``; empty string otherwise.
    """

    planner_model: str           # "llm" | "deterministic"
    confidence: float            # LLM self-reported confidence, or 1.0 for deterministic
    selected_task_count: int
    rejected_task_count: int
    reasoning_summary: str       # first 200 chars of LLM reasoning, or "deterministic"
    fallback_used: bool          # True when deterministic planner produced the result
    timestamp: str               # ISO-8601
    phase: str                   # ApexPhase value at the time of the call
    # LLM policy checkpoint fields (default to not-checked / no activity)
    policy_checkpoint_status: str = ""    # "" | "clean" | "redacted" | "blocked"
    redaction_count: int = 0
    policy_block_reason: str = ""
    # Repeated-plan detection — set when the engine skipped an LLM call
    # because the context (EKG + evidence) was unchanged since the last call
    # for this phase.  ``repeated_plan_action`` is "skipped_llm" when the
    # skip happened, "executed" when the plan ran despite matching fingerprint,
    # or "" when no repeat was detected.
    repeated_plan_detected: bool = False
    repeated_plan_fingerprint: str | None = None
    repeated_plan_count: int = 0
    repeated_plan_action: str = ""
    # LLM error classification — populated when an exception was caught during
    # the LLM call.  ``llm_error_category`` is "permanent" for 4xx errors that
    # should never be retried (401, 403, 404), "transient" for errors where
    # retrying is safe (timeout, 429, 5xx), "validation" when the Validator
    # rejected the output, or "" when no error occurred.
    llm_error_category: str = ""
    llm_http_status: int | None = None
    llm_retry_count: int = 0
    # Phase 3 (post-live-test debugging): the ACTUAL number of tasks the
    # deterministic fallback planner produced when this decision fell back
    # (0 for an LLM-backed decision — see PlanningEngine._record_llm,
    # which continues to use selected_task_count for that case).
    # selected_task_count stays 0 for every fallback decision by its own,
    # correct, pre-existing definition ("how many tasks did the LLM
    # select" — genuinely zero when the LLM path was never used or never
    # produced anything) — this is a SEPARATE field, not a redefinition,
    # so no existing consumer of selected_task_count's meaning breaks.
    # apex_host/eval/report.py and apex_host/eval/report_invariants.py
    # read BOTH fields together (whichever is nonzero) to reconcile
    # planner decisions with real executions — see the confirmed
    # live-test defect this closes: "planner decisions showed
    # selected_task_count: 0, while benchmark totals said six tasks were
    # selected and executed."
    fallback_task_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict (for state and report storage)."""
        return asdict(self)


class PlannerOutput(BaseModel):
    """Full structured response from the LLM planner.

    Fields
    ------
    reasoning:
        The LLM's chain-of-thought before committing to tasks.  Stored for
        auditability; not forwarded to executors.
    confidence:
        Self-assessed confidence in the plan (0..1).  Low confidence
        (<0.4) triggers an additional fallback guard in ``PlanningEngine``.
    selected_tasks:
        Tasks the LLM chose to execute this turn.  Each is validated by
        ``Validator`` before being converted to a ``TaskSpec``.
    rejected_tasks:
        Tasks considered but rejected (free-form dicts for auditability).
        Not executed; stored for debugging and Reflector learning.
    stop_reason:
        When set, the planner signals that this goal branch should be
        abandoned.  ``PlanningEngine`` converts this to an
        ``AbandonSignal`` and skips ``selected_tasks``.
    next_phase:
        Optional hint to ``GlobalPlanner`` about which phase to enter
        next.  Used informatively — the graph still decides via
        ``decide_phase``; this is a suggestion only.
    """

    reasoning: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    selected_tasks: list[PlannedTask] = Field(default_factory=list)
    rejected_tasks: list[dict[str, Any]] = Field(default_factory=list)
    stop_reason: str | None = None
    next_phase: str | None = None
