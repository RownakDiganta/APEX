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
"""
from __future__ import annotations

from memfabric.types import KnowledgeEntry, Skill


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


def should_decay(skill: Skill, *, current_run: int, decay_unused_runs: int) -> bool:
    """Return True if the skill should have its confidence decayed this pass."""
    return (current_run - skill.last_used_run) >= decay_unused_runs


def decayed_confidence(skill: Skill, *, decay_factor: float) -> float:
    """Return the new confidence after one decay step."""
    return max(0.0, skill.confidence * decay_factor)


def win_rate(skill: Skill) -> float | None:
    """Compute win rate, or None if there is insufficient data."""
    total = skill.wins + skill.losses
    if total == 0:
        return None
    return skill.wins / total


def should_quarantine(skill: Skill, *, winrate_floor: float) -> bool:
    """Return True if the skill's live win-rate is below the quarantine floor."""
    if skill.quarantined:
        return False   # already quarantined
    rate = win_rate(skill)
    if rate is None:
        return False   # no data yet
    return rate < winrate_floor
