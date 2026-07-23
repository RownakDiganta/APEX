# outcome.py
# Canonical EngagementOutcome model and the pure termination evaluator — the single source of truth for how and why an APEX engagement ends.
"""Canonical engagement-outcome model (Phase 12C; success redefined in Phase 18).

Before Phase 12C, APEX could stop in many different ways that all looked
identical in ``ApexGraphState`` — ``completed=True`` with no indication of
*why*. This module introduces ``EngagementOutcome`` (an ``Enum``, matching
this project's established data-shape style — see CLAUDE.md §2, "pydantic
v2 only at the external API boundary", which this is not) as the single
canonical model, plus ``evaluate_termination()``, a pure, reusable
termination evaluator that replaces the scattered completion checks
previously spread across ``continuation_node.py``, ``diagnostics_node.py``,
and ``planning_node.py``.

There must never be a second, competing outcome model. ``apex_host.eval.report``
derives its (older, four-value) ``status`` string and ``completed_successfully``
boolean *from* ``EngagementOutcome`` via ``legacy_status_for()`` and
``is_success_outcome()`` — they are projections of this one model, not an
independent classification.

Success invariant (non-negotiable) — Phase 18
-----------------------------------------------
``is_success_outcome()`` returns ``True`` for exactly one value:
``EngagementOutcome.user_flag_verified``. Nothing else — including
``validated_access`` (a validated ``access_state`` node — an important
INTERMEDIATE milestone, never independently success) and ``goal_completed``
— is ever treated as success. See docs/user-flag-objective.md for the full
rationale: for the selected HTB benchmark, success means verified
retrieval of the configured objective (``ApexConfig.objective_type``,
default ``"user_flag"``), never merely reaching a foothold. This is a
deliberate, confirmed change from Phase 12C's original definition (which
treated ``validated_access`` as the sole success outcome) — see the
project's remediation history for how ``validated_access``'s exit code and
legacy status changed accordingly.

Outcome precedence
-------------------
When more than one condition could apply in the same turn, this is the
binding order (highest precedence first) — see ``evaluate_termination()``:

1. ``user_flag_verified`` — the configured objective's EKG ``objective``
   node has ``status == "verified"`` (Phase 18). Checked first,
   unconditionally, so an objective verified on the very last allowed turn
   is still reported as success, never as an exhaustion outcome. A
   validated ``access_state`` alone never satisfies this condition — see
   ``apex_host.planners.objective.objective_status_from_subgraph``.
2. An upstream node already produced a definitive terminal outcome this
   turn (``planner_failure``, ``parser_failure``, ``memory_failure``,
   ``unknown_phase``, ``llm_unavailable``) — the caller
   (``continuation_node.py``) detects this via ``state.get("outcome")``
   already being set and passes it straight through;
   ``evaluate_termination()`` itself is only reached when no such
   upstream outcome exists.
3. Stall-derived outcomes (``duplicate_task_stall``, ``no_actionable_task``,
   ``policy_blocked``) — from ``apex_host.orchestration.stall.StallTracker``.
4. ``phase_budget_exhausted`` / ``goal_completed`` — the phase router
   (``GlobalPlanner``) returned ``ApexPhase.done`` for a reason other than
   the hard turn ceiling.
5. ``max_turns_exhausted`` — the hard turn ceiling.

``validated_access`` is never produced by ``evaluate_termination()`` — a
validated access_state alone no longer terminates the engagement at all;
the ``GlobalPlanner`` phase ladder instead routes it toward the
``objective`` phase (Phase 18). ``validated_access`` remains a member of
this enum only for the backward-compatible ``_derive_outcome_from_state()``
fallback in ``apex_host.eval.report`` (a ``final_state`` predating Phase
12C, which never had ``outcome`` populated at all).

``cancelled``, ``configuration_failure``, and ``internal_error`` are never
produced by this evaluator — they can only occur outside the compiled
graph (before it starts, or via an exception/interrupt that escapes
``graph.ainvoke()``) and are classified by ``apex_host.runtime.ApexRuntime.run()``
and the CLI entry points instead. They remain part of the same enum so
every consumer (reports, CLI exit codes, documentation) has one complete,
canonical vocabulary.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apex_host.orchestration.stall import StallDecision


class EngagementOutcome(str, Enum):
    """The canonical, exhaustive set of reasons an APEX engagement ends."""

    # Success — exactly one value ever means success (is_success_outcome()).
    # Phase 18: the configured objective (default "user_flag") has been
    # verified — see apex_host.planners.objective / objective_parser.py.
    user_flag_verified = "user_flag_verified"
    # An intermediate milestone — a validated access_state node exists —
    # NEVER success on its own (Phase 18). Never produced by
    # evaluate_termination() itself; kept only for the backward-compatible
    # report fallback (see module docstring and apex_host.eval.report
    # ._derive_outcome_from_state).
    validated_access = "validated_access"
    # Organic, non-success completion of the phase ladder (see module
    # docstring — not reachable via the current GlobalPlanner logic, kept
    # for completeness and forward-compatibility; never marked success).
    goal_completed = "goal_completed"
    # Resource-exhaustion terminations.
    max_turns_exhausted = "max_turns_exhausted"
    phase_budget_exhausted = "phase_budget_exhausted"
    # Stall-detector terminations (apex_host.orchestration.stall).
    no_actionable_task = "no_actionable_task"
    duplicate_task_stall = "duplicate_task_stall"
    policy_blocked = "policy_blocked"
    # Hard failures caught at their source and converted into a terminal
    # outcome rather than an uncaught exception crashing graph.ainvoke().
    planner_failure = "planner_failure"
    parser_failure = "parser_failure"
    tool_failure = "tool_failure"
    memory_failure = "memory_failure"
    unknown_phase = "unknown_phase"
    # Phase 1 (post-live-test debugging) — set only when ApexConfig
    # .llm_required is True AND a CONFIRMED permanent LLM provider
    # misconfiguration has been observed (missing key, invalid model,
    # authentication failure, unsupported endpoint, malformed response —
    # apex_host.llm.errors.PERMANENT_LLM_ERROR_CATEGORIES). Detected by
    # apex_host.orchestration.dispatch_node._dispatch_tasks (an
    # upstream-preset outcome, precedence level 2, same as
    # planner_failure/parser_failure/memory_failure — never produced by
    # evaluate_termination() itself). When llm_required is False (the
    # default), the SAME permanent provider failure never produces this
    # outcome — the engagement continues with deterministic fallback,
    # exactly as before this phase.
    llm_unavailable = "llm_unavailable"
    # Outside-the-graph outcomes — classified by ApexRuntime/CLI, never by
    # evaluate_termination().
    cancelled = "cancelled"
    configuration_failure = "configuration_failure"
    internal_error = "internal_error"


def is_success_outcome(outcome: "EngagementOutcome") -> bool:
    """True for exactly one outcome — never invent success.

    Phase 18: success means the configured objective (default
    ``"user_flag"``) has been verified. A validated ``access_state`` alone
    (``EngagementOutcome.validated_access``) is explicitly NOT success —
    see module docstring.
    """
    return outcome is EngagementOutcome.user_flag_verified


# Exit codes (CLI contract — see docs/engagement-outcomes.md "CLI exit codes").
_EXIT_CODE_FOR_OUTCOME: dict[EngagementOutcome, int] = {
    EngagementOutcome.user_flag_verified: 0,
    # Phase 18: a validated access_state alone is access-only exhaustion,
    # not benchmark success — bucketed with the other "nothing went wrong,
    # but the run did not achieve the objective" outcomes.
    EngagementOutcome.validated_access: 1,
    # Phase 25 audit fix: this entry was still 0 (a leftover from Phase
    # 12C's original definition, where `goal_completed` WAS success) after
    # Phase 18 redefined success — `validated_access`'s exit code was
    # updated at that time but this one was missed, leaving
    # `is_success_outcome(goal_completed) is False` inconsistent with an
    # exit code of 0 (the CLI's own definition of "success" for any
    # scripting/CI consumer). `goal_completed` is currently unreachable
    # through GlobalPlanner (reserved for forward compatibility — see this
    # module's own docstring), so this had no live-run impact, but the
    # invariant "no outcome other than user_flag_verified maps to exit
    # code 0" must hold unconditionally, not just for reachable outcomes.
    EngagementOutcome.goal_completed: 1,
    EngagementOutcome.max_turns_exhausted: 1,
    EngagementOutcome.phase_budget_exhausted: 1,
    EngagementOutcome.no_actionable_task: 1,
    EngagementOutcome.duplicate_task_stall: 1,
    EngagementOutcome.configuration_failure: 2,
    EngagementOutcome.policy_blocked: 3,
    EngagementOutcome.planner_failure: 4,
    EngagementOutcome.parser_failure: 4,
    EngagementOutcome.tool_failure: 4,
    EngagementOutcome.memory_failure: 4,
    EngagementOutcome.unknown_phase: 4,
    EngagementOutcome.llm_unavailable: 4,
    EngagementOutcome.internal_error: 4,
    EngagementOutcome.cancelled: 130,
}


def exit_code_for(outcome: "EngagementOutcome") -> int:
    """Deterministic CLI exit code for a terminal outcome."""
    return _EXIT_CODE_FOR_OUTCOME[outcome]


# Backward-compatible projection onto apex_host.eval.report's original
# four-value `status` string — a *view* of this model, not a second model.
# Existing scenarios (pre-Phase-12C tests) only ever produce
# validated_access/max_turns_exhausted/tool_failure/no_actionable_task-shaped
# states, so their expected legacy strings are preserved exactly; new
# outcome values introduced by Phase 12C map onto the closest existing
# bucket, except `cancelled`, which is distinct enough to warrant its own
# legacy string (no pre-Phase-12C scenario ever produced it, so introducing
# it cannot break backward compatibility).
_LEGACY_STATUS_FOR_OUTCOME: dict[EngagementOutcome, str] = {
    EngagementOutcome.user_flag_verified: "success",
    # Phase 18: access alone is partial progress, not success.
    EngagementOutcome.validated_access: "abandoned",
    EngagementOutcome.goal_completed: "abandoned",
    EngagementOutcome.max_turns_exhausted: "stopped_max_turns",
    EngagementOutcome.phase_budget_exhausted: "stopped_max_turns",
    EngagementOutcome.no_actionable_task: "abandoned",
    EngagementOutcome.duplicate_task_stall: "abandoned",
    EngagementOutcome.policy_blocked: "abandoned",
    EngagementOutcome.planner_failure: "stopped_error",
    EngagementOutcome.parser_failure: "stopped_error",
    EngagementOutcome.tool_failure: "stopped_error",
    EngagementOutcome.memory_failure: "stopped_error",
    EngagementOutcome.unknown_phase: "stopped_error",
    EngagementOutcome.llm_unavailable: "stopped_error",
    EngagementOutcome.configuration_failure: "stopped_error",
    EngagementOutcome.internal_error: "stopped_error",
    EngagementOutcome.cancelled: "cancelled",
}


def legacy_status_for(outcome: "EngagementOutcome") -> str:
    return _LEGACY_STATUS_FOR_OUTCOME[outcome]


@dataclass(slots=True)
class TerminationDecision:
    """The single structured result of a termination evaluation.

    Every engagement terminates with exactly one of these — threaded into
    ``ApexGraphState`` (``outcome``, ``termination_reason``,
    ``termination_phase``) and used verbatim to build the one terminal
    ``Episode`` (see ``apex_host.orchestration.terminal_episode``).
    """

    terminate: bool
    outcome: EngagementOutcome | None
    success: bool
    reason: str
    phase: str
    turn: int


def evaluate_termination(
    *,
    max_turns: int,
    turn_count: int,
    objective_verified: bool,
    next_phase: str,
    current_phase: str,
    stall: "StallDecision",
) -> TerminationDecision:
    """Pure termination evaluator — precedence levels 1 and 3-5 (see module
    docstring; level 2, upstream-preset outcomes, is handled by the caller
    before this function is ever invoked).

    No I/O. Safe to unit-test directly with synthetic inputs — this is the
    single reusable decision point that replaces every ad-hoc completion
    check previously scattered across the orchestration package.

    Args:
        objective_verified: Phase 18 — True when the configured objective's
            EKG ``objective`` node has ``status == "verified"`` (see
            ``apex_host.planners.objective.objective_status_from_subgraph``).
            A validated ``access_state`` alone must NOT be passed here —
            see module docstring "Success invariant".
    """
    if objective_verified:
        return TerminationDecision(
            terminate=True, outcome=EngagementOutcome.user_flag_verified, success=True,
            reason="configured objective verified — evidence recorded in the EKG",
            phase=current_phase, turn=turn_count,
        )

    if next_phase == "done":
        if turn_count >= max_turns:
            return TerminationDecision(
                terminate=True, outcome=EngagementOutcome.max_turns_exhausted, success=False,
                reason=f"reached the maximum turn budget ({max_turns})",
                phase=current_phase, turn=turn_count,
            )
        # ApexPhase.priv_esc has no further useful phase to force-advance
        # into (see apex_host/planners/global_planner.py) — reaching
        # "done" from priv_esc without max_turns means its own phase
        # budget ran out. Any other phase reaching "done" here (without
        # max_turns, without access_state) is the organic
        # _select_phase() fallback — currently unreachable in practice,
        # documented in the module docstring as `goal_completed`.
        if current_phase == "priv_esc":
            return TerminationDecision(
                terminate=True, outcome=EngagementOutcome.phase_budget_exhausted, success=False,
                reason=f"phase {current_phase!r} exhausted its turn budget with no further useful phase to advance to",
                phase=current_phase, turn=turn_count,
            )
        return TerminationDecision(
            terminate=True, outcome=EngagementOutcome.goal_completed, success=False,
            reason="engagement reached its organic completion state without validated access",
            phase=current_phase, turn=turn_count,
        )

    if stall.stalled:
        assert stall.outcome is not None  # StallDecision.stalled=True always carries an outcome
        return TerminationDecision(
            terminate=True, outcome=stall.outcome, success=False,
            reason=stall.reason, phase=current_phase, turn=turn_count,
        )

    if turn_count >= max_turns:
        return TerminationDecision(
            terminate=True, outcome=EngagementOutcome.max_turns_exhausted, success=False,
            reason=f"reached the maximum turn budget ({max_turns})",
            phase=current_phase, turn=turn_count,
        )

    return TerminationDecision(
        terminate=False, outcome=None, success=False, reason="", phase=current_phase, turn=turn_count,
    )
