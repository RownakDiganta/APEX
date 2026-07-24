# gates.py
# Pure policy functions for the Reflector promotion gate, confidence decay, and win-rate quarantine — all state mutations go through MemoryAPI, not here.
"""Promotion, decay, and quarantine policy (Section 7 — gates).

These are PURE POLICY FUNCTIONS.  They take a Skill or KnowledgeEntry and
a Config, and return whether it should be promoted, decayed, or quarantined.
All actual state mutations go through MemoryAPI.

Promotion gate:
    evidence_count >= config.min_evidence_count AND confidence >= config.min_confidence

Decay:
    confidence × config.decay_factor when unused for too long

Quarantine:
    win_rate < config.winrate_floor (only skills with enough data)

Skill outcome classification:
    classify_skill_outcome() maps Outcome + execution flags → SkillOutcomeDisposition
"""
from __future__ import annotations

from memfabric.types import KnowledgeEntry, Outcome, Skill, SkillOutcomeDisposition


def should_promote_knowledge(entry: KnowledgeEntry, *, min_confidence: float) -> bool:
    """Return True if the staged knowledge entry clears the promotion gate."""
    return not entry.promoted and entry.confidence >= min_confidence


def should_promote_skill(
    skill: Skill,
    *,
    min_evidence_count: int,
    min_confidence: float,
) -> bool:
    """Return True if the staged skill clears the promotion gate."""
    if skill.promoted or skill.quarantined:
        return False
    return (
        skill.evidence_count >= min_evidence_count
        and skill.confidence >= min_confidence
    )


def should_decay(
    skill: Skill,
    *,
    current_run: int,
    decay_unused_runs: int,
    grace_runs: int = 0,
) -> bool:
    """Return True if the skill should have its confidence decayed this pass.

    Decay is suppressed during the grace period after promotion (``grace_runs``
    Reflector passes).  This prevents freshly promoted skills from immediately
    losing confidence before they have had a chance to be selected and executed.

    ``last_used_run_number`` (set by MemoryAPI lifecycle methods) is used
    preferentially over the legacy ``last_used_run`` field so that usage recorded
    via ``record_skill_retrieved`` / ``record_skill_selected`` /
    ``record_skill_execution`` correctly resets the decay clock.

    The idempotence guard (``last_decay_run_number``) is enforced by
    ``MemoryAPI.decay_skill()``, not here — this function is a pure predicate.
    """
    if skill.quarantined:
        return False

    # Grace period: suppress decay for newly promoted skills.
    if skill.promoted_run_number is not None and grace_runs > 0:
        if (current_run - skill.promoted_run_number) < grace_runs:
            return False

    # Use last_used_run_number (new field) preferentially over legacy last_used_run.
    last_used = (
        skill.last_used_run_number
        if skill.last_used_run_number is not None
        else skill.last_used_run
    )
    return (current_run - last_used) >= decay_unused_runs


def decayed_confidence(skill: Skill, *, decay_factor: float) -> float:
    """Return the new confidence after one decay step."""
    return max(0.0, skill.confidence * decay_factor)


def win_rate(skill: Skill) -> float | None:
    """Compute win rate, or None if there is insufficient data."""
    total = skill.wins + skill.losses
    if total == 0:
        return None
    return skill.wins / total


def should_quarantine(
    skill: Skill,
    *,
    winrate_floor: float,
    min_evidence_count: int = 0,
) -> bool:
    """Return True if the skill's live win-rate is below the quarantine floor.

    ``min_evidence_count`` is the minimum number of executions (or wins+losses for
    backward compatibility) before quarantine is considered.  Default 0 preserves
    existing behaviour: any skill with any win/loss data is eligible for quarantine.

    Evidence count uses ``max(execution_count, wins + losses)`` for backward
    compatibility with tests that set wins/losses directly without going through
    ``record_skill_execution()``.
    """
    if skill.quarantined:
        return False

    # Evidence threshold.
    evidence = max(skill.execution_count, skill.wins + skill.losses)
    if evidence < min_evidence_count:
        return False

    rate = win_rate(skill)
    if rate is None:
        return False
    return rate < winrate_floor


def classify_unpromoted_knowledge(entry: KnowledgeEntry, *, min_confidence: float) -> str:
    """Return why *entry* has not (yet) been promoted.

    Pure diagnostic predicate — no state mutation, no I/O. Companion to
    ``should_promote_knowledge``; the two are kept in sync deliberately so a
    caller that wants a *reason* rather than a bool always gets a category
    consistent with what the actual gate decision would be.

    Categories:
    - ``"promoted"`` — already promoted; nothing left to explain.
    - ``"below_min_confidence"`` — ``entry.confidence < min_confidence``. A
      ``KnowledgeEntry``'s confidence is fixed at proposal time; nothing in
      this codebase mutates it afterward, so this is a **permanent**
      blocker for the current run — re-running the promotion pass on this
      entry can never change the outcome. The caller (typically a bounded
      promotion loop) should stop retrying an entry in this category rather
      than re-evaluating it on every subsequent pass.
    - ``"eligible_pending_pass"`` — clears the gate but has not been
      promoted yet (e.g. a per-pass promotion cap was reached before this
      entry was reached). Not permanent; a future pass may promote it.
    """
    if entry.promoted:
        return "promoted"
    if entry.confidence < min_confidence:
        return "below_min_confidence"
    return "eligible_pending_pass"


def classify_unpromoted_skill(
    skill: Skill, *, min_evidence_count: int, min_confidence: float
) -> str:
    """Return why *skill* has not (yet) been promoted. See ``classify_unpromoted_knowledge``.

    Categories:
    - ``"promoted"`` — already promoted.
    - ``"quarantined"`` — will never be promoted while quarantined.
    - ``"below_min_evidence"`` — ``evidence_count < min_evidence_count``.
      Not necessarily permanent: evidence accumulates as the Reflector
      merges more matching chains (``MemoryAPI.merge_skill_candidate``).
    - ``"below_min_confidence"`` — ``confidence < min_confidence``. Also not
      necessarily permanent for a skill (unlike a ``KnowledgeEntry``),
      since a merge can raise confidence over time.
    - ``"eligible_pending_pass"`` — clears the gate but has not been
      promoted yet (per-pass cap reached first).
    """
    if skill.promoted:
        return "promoted"
    if skill.quarantined:
        return "quarantined"
    if skill.evidence_count < min_evidence_count:
        return "below_min_evidence"
    if skill.confidence < min_confidence:
        return "below_min_confidence"
    return "eligible_pending_pass"


def classify_skill_outcome(
    outcome: Outcome,
    *,
    is_policy_blocked: bool = False,
    is_conflict_blocked: bool = False,
    is_duplicate_skipped: bool = False,
) -> SkillOutcomeDisposition:
    """Map an execution outcome to a SkillOutcomeDisposition.

    Blocking events (policy block, conflict block, duplicate skip) take
    precedence over the outcome value — they indicate the task was never
    executed, so no skill performance data can be inferred.

    ``WIN``  — task succeeded (``Outcome.success``).
    ``LOSS`` — task failed fundamentally (``Outcome.fundamental``).
    ``NEUTRAL`` — transient failure (``script_error``, ``fixable``); skill is not
      penalised as the error may be infrastructure-related, not skill quality.
    ``NOT_EXECUTED`` — the task was blocked before any tool ran.
    """
    if is_policy_blocked or is_conflict_blocked or is_duplicate_skipped:
        return SkillOutcomeDisposition.NOT_EXECUTED
    if outcome == Outcome.success:
        return SkillOutcomeDisposition.WIN
    if outcome == Outcome.fundamental:
        return SkillOutcomeDisposition.LOSS
    # script_error and fixable are transient; no penalty.
    return SkillOutcomeDisposition.NEUTRAL
