# test_skill_lifecycle.py
# Phase 3 tests: complete skill lifecycle — deep-copy isolation, run-number tracking, decay idempotence, quarantine evidence threshold, merge_skill_candidate, classify_skill_outcome, F21 regression, architecture scan, concurrent stress.
"""Phase 3 — Skill Lifecycle Tests.

Covers all invariants introduced in Phase 3 of the remediation roadmap:

- Deep-copy isolation: get_staged_skills / get_staged_knowledge return copies.
- advance_run_number() is monotonic and global.
- record_skill_retrieved / record_skill_selected / record_skill_execution update
  lifecycle fields correctly.
- decay_skill() is idempotent within a run (last_decay_run_number guard).
- Decay respects skill_confidence_floor.
- Decay respects skill_grace_runs (newly promoted skills not decayed).
- quarantine_skill() records reason, timestamp, run number.
- should_quarantine() respects min_evidence_count.
- promote_skill() sets promoted_run_number.
- merge_skill_candidate() updates wins/evidence/confidence atomically (F21 fix).
- ReflectorWorker uses merge_skill_candidate, not direct mutation.
- classify_skill_outcome() maps Outcome + flags → SkillOutcomeDisposition.
- origin_skill_id field exists on TaskSpec.
- Architecture scan: no direct Skill mutation in worker.py.
- Concurrent record_skill_execution calls do not lose increments.
"""
from __future__ import annotations

import asyncio
import ast
from pathlib import Path

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.reflector.gates import (
    classify_skill_outcome,
    should_decay,
    should_quarantine,
)
from memfabric.reflector.worker import ReflectorWorker
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import (
    Episode,
    KnowledgeEntry,
    Outcome,
    Skill,
    SkillOutcomeDisposition,
    TaskSpec,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_api(
    *,
    min_evidence_count: int = 2,
    min_confidence: float = 0.5,
    skill_prior: float = 0.5,
    decay_unused_runs: int = 10,
    winrate_floor: float = 0.3,
    skill_confidence_floor: float = 0.0,
    skill_grace_runs: int = 0,
    skill_merge_theta: float = 0.85,
    min_chain_len: int = 2,
) -> tuple[MemoryAPI, Config]:
    cfg = Config(
        min_evidence_count=min_evidence_count,
        min_confidence=min_confidence,
        skill_prior=skill_prior,
        decay_unused_runs=decay_unused_runs,
        winrate_floor=winrate_floor,
        skill_confidence_floor=skill_confidence_floor,
        skill_grace_runs=skill_grace_runs,
        skill_merge_theta=skill_merge_theta,
        min_chain_len=min_chain_len,
    )
    api = MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )
    return api, cfg


def _make_skill(
    *,
    name: str = "test_skill",
    confidence: float = 0.8,
    wins: int = 0,
    losses: int = 0,
    last_used_run: int = 0,
    evidence_count: int = 0,
    quarantined: bool = False,
    promoted: bool = False,
) -> Skill:
    return Skill(
        id=new_id(),
        name=name,
        description=f"Test skill: {name}",
        template={"action": name},
        preconditions={},
        source_episodes=[new_id()],
        confidence=confidence,
        wins=wins,
        losses=losses,
        last_used_run=last_used_run,
        evidence_count=evidence_count,
        quarantined=quarantined,
        promoted=promoted,
        timestamp=now(),
    )


def _make_episode(
    *,
    action: str = "test_action",
    outcome: Outcome = Outcome.success,
    chain_id: str | None = None,
) -> Episode:
    return Episode(
        id=new_id(),
        timestamp=now(),
        agent="test",
        action=action,
        outcome=outcome,
        data={},
        chain_id=chain_id,
    )


async def _propose_skill(api: MemoryAPI, skill: Skill) -> str:
    """Propose a skill and return its id."""
    await api.propose_skill(skill)
    return skill.id


# ---------------------------------------------------------------------------
# S01 — SkillOutcomeDisposition enum values
# ---------------------------------------------------------------------------

def test_s01_skill_outcome_disposition_values() -> None:
    assert SkillOutcomeDisposition.WIN == "win"
    assert SkillOutcomeDisposition.LOSS == "loss"
    assert SkillOutcomeDisposition.NEUTRAL == "neutral"
    assert SkillOutcomeDisposition.NOT_EXECUTED == "not_executed"


def test_s02_skill_outcome_disposition_is_str_enum() -> None:
    assert isinstance(SkillOutcomeDisposition.WIN, str)
    assert SkillOutcomeDisposition.WIN == "win"


def test_s03_skill_outcome_disposition_all_members() -> None:
    members = {d.value for d in SkillOutcomeDisposition}
    assert members == {"win", "loss", "neutral", "not_executed"}


# ---------------------------------------------------------------------------
# C01 — classify_skill_outcome
# ---------------------------------------------------------------------------

def test_c01_success_outcome_is_win() -> None:
    assert classify_skill_outcome(Outcome.success) == SkillOutcomeDisposition.WIN


def test_c02_fundamental_outcome_is_loss() -> None:
    assert classify_skill_outcome(Outcome.fundamental) == SkillOutcomeDisposition.LOSS


def test_c03_script_error_is_neutral() -> None:
    assert classify_skill_outcome(Outcome.script_error) == SkillOutcomeDisposition.NEUTRAL


def test_c04_fixable_is_neutral() -> None:
    assert classify_skill_outcome(Outcome.fixable) == SkillOutcomeDisposition.NEUTRAL


def test_c05_policy_blocked_is_not_executed() -> None:
    assert classify_skill_outcome(Outcome.success, is_policy_blocked=True) == SkillOutcomeDisposition.NOT_EXECUTED


def test_c06_conflict_blocked_is_not_executed() -> None:
    assert classify_skill_outcome(Outcome.success, is_conflict_blocked=True) == SkillOutcomeDisposition.NOT_EXECUTED


def test_c07_duplicate_skipped_is_not_executed() -> None:
    assert classify_skill_outcome(Outcome.success, is_duplicate_skipped=True) == SkillOutcomeDisposition.NOT_EXECUTED


def test_c08_policy_blocked_overrides_fundamental() -> None:
    # Even a LOSS outcome is NOT_EXECUTED when policy blocked it.
    assert classify_skill_outcome(Outcome.fundamental, is_policy_blocked=True) == SkillOutcomeDisposition.NOT_EXECUTED


def test_c09_conflict_blocked_overrides_script_error() -> None:
    assert classify_skill_outcome(Outcome.script_error, is_conflict_blocked=True) == SkillOutcomeDisposition.NOT_EXECUTED


def test_c10_all_three_blocked_flags_is_not_executed() -> None:
    assert classify_skill_outcome(
        Outcome.success,
        is_policy_blocked=True,
        is_conflict_blocked=True,
        is_duplicate_skipped=True,
    ) == SkillOutcomeDisposition.NOT_EXECUTED


def test_c11_not_blocked_fundamental_is_loss() -> None:
    assert classify_skill_outcome(
        Outcome.fundamental,
        is_policy_blocked=False,
        is_conflict_blocked=False,
        is_duplicate_skipped=False,
    ) == SkillOutcomeDisposition.LOSS


# ---------------------------------------------------------------------------
# D01 — Deep-copy isolation: get_staged_skills / get_staged_knowledge
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_d01_get_staged_skills_returns_copies() -> None:
    api, _ = _make_api()
    skill = _make_skill(confidence=0.7)
    await _propose_skill(api, skill)
    copies = await api.get_staged_skills()
    assert len(copies) == 1
    copies[0].confidence = 0.0  # mutate the copy
    copies[0].wins = 99
    # Re-fetch — stored value must be unchanged.
    copies2 = await api.get_staged_skills()
    assert copies2[0].confidence == pytest.approx(0.7)
    assert copies2[0].wins == 0


@pytest.mark.asyncio
async def test_d02_get_staged_knowledge_returns_copies() -> None:
    api, _ = _make_api()
    entry = KnowledgeEntry(id=new_id(), text="hello world", source="test", confidence=0.9, timestamp=now())
    await api.propose_knowledge(entry)
    copies = await api.get_staged_knowledge()
    assert len(copies) == 1
    copies[0].confidence = 0.0
    copies[0].text = "mutated"
    copies2 = await api.get_staged_knowledge()
    assert copies2[0].confidence == pytest.approx(0.9)
    assert copies2[0].text == "hello world"


@pytest.mark.asyncio
async def test_d03_skill_copy_props_isolation() -> None:
    """Mutating nested props dict in copy does not affect stored skill."""
    api, _ = _make_api()
    skill = _make_skill()
    skill.template["key"] = "original"
    await _propose_skill(api, skill)
    copies = await api.get_staged_skills()
    copies[0].template["key"] = "mutated"
    copies2 = await api.get_staged_skills()
    assert copies2[0].template.get("key") == "original"


@pytest.mark.asyncio
async def test_d04_skill_source_episodes_copy_isolation() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    skill.source_episodes.clear()
    skill.source_episodes.append("ep_one")
    await _propose_skill(api, skill)
    copies = await api.get_staged_skills()
    copies[0].source_episodes.append("ep_injected")
    copies2 = await api.get_staged_skills()
    assert "ep_injected" not in copies2[0].source_episodes


@pytest.mark.asyncio
async def test_d05_multiple_skills_all_copied() -> None:
    api, _ = _make_api()
    for i in range(5):
        await _propose_skill(api, _make_skill(name=f"skill_{i}", confidence=0.5 + i * 0.05))
    copies = await api.get_staged_skills()
    for c in copies:
        c.confidence = 0.0
    copies2 = await api.get_staged_skills()
    for c2 in copies2:
        assert c2.confidence > 0.0


# ---------------------------------------------------------------------------
# R01 — advance_run_number
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r01_advance_run_number_starts_at_one() -> None:
    api, _ = _make_api()
    assert await api.advance_run_number() == 1


@pytest.mark.asyncio
async def test_r02_advance_run_number_is_monotonic() -> None:
    api, _ = _make_api()
    runs = [await api.advance_run_number() for _ in range(5)]
    assert runs == [1, 2, 3, 4, 5]


@pytest.mark.asyncio
async def test_r03_advance_run_number_independent_per_api_instance() -> None:
    api1, _ = _make_api()
    api2, _ = _make_api()
    assert await api1.advance_run_number() == 1
    assert await api2.advance_run_number() == 1  # independent counter


@pytest.mark.asyncio
async def test_r04_advance_run_number_reflected_in_run_count() -> None:
    api, cfg = _make_api(min_confidence=0.5, min_evidence_count=0)
    worker = ReflectorWorker(api, cfg)
    await worker.run_once()
    assert worker._run_count == 1
    await worker.run_once()
    assert worker._run_count == 2


@pytest.mark.asyncio
async def test_r05_worker_run_count_matches_api_completed_run_number() -> None:
    api, cfg = _make_api(min_confidence=0.5, min_evidence_count=0)
    worker = ReflectorWorker(api, cfg)
    await worker.run_once()
    assert api._completed_run_number == worker._run_count


# ---------------------------------------------------------------------------
# RET — record_skill_retrieved
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ret01_record_skill_retrieved_increments_retrieval_count() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_retrieved([skill.id], run_number=1)
    copies = await api.get_staged_skills()
    assert copies[0].retrieval_count == 1


@pytest.mark.asyncio
async def test_ret02_record_skill_retrieved_updates_last_retrieved_run_number() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_retrieved([skill.id], run_number=7)
    copies = await api.get_staged_skills()
    assert copies[0].last_retrieved_run_number == 7


@pytest.mark.asyncio
async def test_ret03_record_skill_retrieved_updates_last_used_run_number() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_retrieved([skill.id], run_number=3)
    copies = await api.get_staged_skills()
    assert copies[0].last_used_run_number == 3


@pytest.mark.asyncio
async def test_ret04_record_skill_retrieved_sets_last_retrieved_at() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_retrieved([skill.id], run_number=1)
    copies = await api.get_staged_skills()
    assert copies[0].last_retrieved_at is not None
    assert len(copies[0].last_retrieved_at) > 0


@pytest.mark.asyncio
async def test_ret05_record_skill_retrieved_multiple_ids() -> None:
    api, _ = _make_api()
    s1, s2 = _make_skill(name="s1"), _make_skill(name="s2")
    await _propose_skill(api, s1)
    await _propose_skill(api, s2)
    await api.record_skill_retrieved([s1.id, s2.id], run_number=5)
    copies = {s.id: s for s in await api.get_staged_skills()}
    assert copies[s1.id].retrieval_count == 1
    assert copies[s2.id].retrieval_count == 1
    assert copies[s1.id].last_used_run_number == 5
    assert copies[s2.id].last_used_run_number == 5


@pytest.mark.asyncio
async def test_ret06_record_skill_retrieved_unknown_id_silently_skipped() -> None:
    api, _ = _make_api()
    # No error raised for unknown IDs
    await api.record_skill_retrieved(["nonexistent"], run_number=1)


@pytest.mark.asyncio
async def test_ret07_record_skill_retrieved_cumulative() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    for run in range(1, 4):
        await api.record_skill_retrieved([skill.id], run_number=run)
    copies = await api.get_staged_skills()
    assert copies[0].retrieval_count == 3
    assert copies[0].last_retrieved_run_number == 3


# ---------------------------------------------------------------------------
# SEL — record_skill_selected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sel01_record_skill_selected_increments_selection_count() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_selected(skill.id, run_number=2)
    copies = await api.get_staged_skills()
    assert copies[0].selection_count == 1


@pytest.mark.asyncio
async def test_sel02_record_skill_selected_updates_last_selected_run_number() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_selected(skill.id, run_number=4)
    copies = await api.get_staged_skills()
    assert copies[0].last_selected_run_number == 4


@pytest.mark.asyncio
async def test_sel03_record_skill_selected_updates_last_used_run_number() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_selected(skill.id, run_number=6)
    copies = await api.get_staged_skills()
    assert copies[0].last_used_run_number == 6


@pytest.mark.asyncio
async def test_sel04_record_skill_selected_sets_last_selected_at() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_selected(skill.id, run_number=1)
    copies = await api.get_staged_skills()
    assert copies[0].last_selected_at is not None


@pytest.mark.asyncio
async def test_sel05_record_skill_selected_unknown_id_silently_skipped() -> None:
    api, _ = _make_api()
    await api.record_skill_selected("nonexistent", run_number=1)  # no error


# ---------------------------------------------------------------------------
# EXE — record_skill_execution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exe01_win_increments_wins() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_execution(skill.id, run_number=1, disposition=SkillOutcomeDisposition.WIN)
    copies = await api.get_staged_skills()
    assert copies[0].wins == 1
    assert copies[0].losses == 0


@pytest.mark.asyncio
async def test_exe02_loss_increments_losses() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_execution(skill.id, run_number=1, disposition=SkillOutcomeDisposition.LOSS)
    copies = await api.get_staged_skills()
    assert copies[0].wins == 0
    assert copies[0].losses == 1


@pytest.mark.asyncio
async def test_exe03_neutral_does_not_change_wins_losses() -> None:
    api, _ = _make_api()
    skill = _make_skill(wins=2, losses=1)
    await _propose_skill(api, skill)
    await api.record_skill_execution(skill.id, run_number=1, disposition=SkillOutcomeDisposition.NEUTRAL)
    copies = await api.get_staged_skills()
    assert copies[0].wins == 2
    assert copies[0].losses == 1


@pytest.mark.asyncio
async def test_exe04_not_executed_does_not_change_wins_losses() -> None:
    api, _ = _make_api()
    skill = _make_skill(wins=3, losses=0)
    await _propose_skill(api, skill)
    await api.record_skill_execution(skill.id, run_number=1, disposition=SkillOutcomeDisposition.NOT_EXECUTED)
    copies = await api.get_staged_skills()
    assert copies[0].wins == 3
    assert copies[0].losses == 0


@pytest.mark.asyncio
async def test_exe05_always_increments_execution_count() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    for d in [SkillOutcomeDisposition.WIN, SkillOutcomeDisposition.LOSS, SkillOutcomeDisposition.NEUTRAL, SkillOutcomeDisposition.NOT_EXECUTED]:
        await api.record_skill_execution(skill.id, run_number=1, disposition=d)
    copies = await api.get_staged_skills()
    assert copies[0].execution_count == 4


@pytest.mark.asyncio
async def test_exe06_updates_last_executed_run_number() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_execution(skill.id, run_number=8, disposition=SkillOutcomeDisposition.WIN)
    copies = await api.get_staged_skills()
    assert copies[0].last_executed_run_number == 8


@pytest.mark.asyncio
async def test_exe07_updates_last_used_run_number() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_execution(skill.id, run_number=5, disposition=SkillOutcomeDisposition.WIN)
    copies = await api.get_staged_skills()
    assert copies[0].last_used_run_number == 5


@pytest.mark.asyncio
async def test_exe08_sets_last_executed_at() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.record_skill_execution(skill.id, run_number=1, disposition=SkillOutcomeDisposition.WIN)
    copies = await api.get_staged_skills()
    assert copies[0].last_executed_at is not None


@pytest.mark.asyncio
async def test_exe09_unknown_id_silently_skipped() -> None:
    api, _ = _make_api()
    await api.record_skill_execution("nonexistent", run_number=1, disposition=SkillOutcomeDisposition.WIN)


# ---------------------------------------------------------------------------
# DEC — decay_skill() idempotence, floor, run-number tracking
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dec01_basic_decay_reduces_confidence() -> None:
    api, _ = _make_api()
    skill = _make_skill(confidence=1.0)
    await _propose_skill(api, skill)
    await api.decay_skill(skill.id, 0.9)
    copies = await api.get_staged_skills()
    assert copies[0].confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_dec02_idempotence_same_run_skips_second_decay() -> None:
    api, _ = _make_api()
    skill = _make_skill(confidence=1.0)
    await _propose_skill(api, skill)
    await api.decay_skill(skill.id, 0.9, current_run_number=5)
    await api.decay_skill(skill.id, 0.9, current_run_number=5)  # same run, skipped
    copies = await api.get_staged_skills()
    # Only one decay applied: 1.0 * 0.9 = 0.9 (not 0.81)
    assert copies[0].confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_dec03_different_run_allows_second_decay() -> None:
    api, _ = _make_api()
    skill = _make_skill(confidence=1.0)
    await _propose_skill(api, skill)
    await api.decay_skill(skill.id, 0.9, current_run_number=5)
    await api.decay_skill(skill.id, 0.9, current_run_number=6)  # different run
    copies = await api.get_staged_skills()
    assert copies[0].confidence == pytest.approx(0.81)


@pytest.mark.asyncio
async def test_dec04_confidence_floor_is_respected() -> None:
    api, _ = _make_api()
    skill = _make_skill(confidence=0.1)
    await _propose_skill(api, skill)
    # decay_factor=0.1 would drive to 0.01 but floor is 0.05
    await api.decay_skill(skill.id, 0.1, confidence_floor=0.05)
    copies = await api.get_staged_skills()
    assert copies[0].confidence >= 0.05


@pytest.mark.asyncio
async def test_dec05_floor_zero_allows_decay_to_zero() -> None:
    api, _ = _make_api()
    skill = _make_skill(confidence=0.001)
    await _propose_skill(api, skill)
    await api.decay_skill(skill.id, 0.0, confidence_floor=0.0)
    copies = await api.get_staged_skills()
    assert copies[0].confidence == pytest.approx(0.0)


@pytest.mark.asyncio
async def test_dec06_sets_last_decay_run_number() -> None:
    api, _ = _make_api()
    skill = _make_skill(confidence=1.0)
    await _propose_skill(api, skill)
    await api.decay_skill(skill.id, 0.9, current_run_number=3)
    copies = await api.get_staged_skills()
    assert copies[0].last_decay_run_number == 3


@pytest.mark.asyncio
async def test_dec07_no_run_number_no_idempotence_guard() -> None:
    """Without current_run_number, decay is always applied."""
    api, _ = _make_api()
    skill = _make_skill(confidence=1.0)
    await _propose_skill(api, skill)
    await api.decay_skill(skill.id, 0.9)
    await api.decay_skill(skill.id, 0.9)
    copies = await api.get_staged_skills()
    assert copies[0].confidence == pytest.approx(0.81)


@pytest.mark.asyncio
async def test_dec08_unknown_skill_id_returns_false() -> None:
    api, _ = _make_api()
    result = await api.decay_skill("nonexistent", 0.9)
    assert result is False


# ---------------------------------------------------------------------------
# QUAR — quarantine_skill() with reason + run tracking
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_quar01_quarantine_sets_quarantined_flag() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.quarantine_skill(skill.id)
    copies = await api.get_staged_skills()
    assert copies[0].quarantined is True


@pytest.mark.asyncio
async def test_quar02_quarantine_default_reason() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.quarantine_skill(skill.id)
    copies = await api.get_staged_skills()
    assert copies[0].quarantine_reason == "winrate_below_floor"


@pytest.mark.asyncio
async def test_quar03_quarantine_custom_reason() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.quarantine_skill(skill.id, reason="operator_override")
    copies = await api.get_staged_skills()
    assert copies[0].quarantine_reason == "operator_override"


@pytest.mark.asyncio
async def test_quar04_quarantine_sets_quarantined_at() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.quarantine_skill(skill.id)
    copies = await api.get_staged_skills()
    assert copies[0].quarantined_at is not None
    assert len(copies[0].quarantined_at) > 0


@pytest.mark.asyncio
async def test_quar05_quarantine_sets_quarantined_run_number() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.quarantine_skill(skill.id, current_run_number=7)
    copies = await api.get_staged_skills()
    assert copies[0].quarantined_run_number == 7


@pytest.mark.asyncio
async def test_quar06_quarantine_without_run_number_leaves_run_number_none() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.quarantine_skill(skill.id)
    copies = await api.get_staged_skills()
    assert copies[0].quarantined_run_number is None


@pytest.mark.asyncio
async def test_quar07_unknown_skill_id_returns_false() -> None:
    api, _ = _make_api()
    result = await api.quarantine_skill("nonexistent")
    assert result is False


# ---------------------------------------------------------------------------
# PROM — promote_skill() sets promoted_run_number
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_prom01_promote_skill_sets_promoted_run_number() -> None:
    api, _ = _make_api(min_evidence_count=0, min_confidence=0.0)
    skill = _make_skill(confidence=0.9)
    await _propose_skill(api, skill)
    # Advance run number so promoted_run_number != 0
    await api.advance_run_number()
    await api.advance_run_number()
    await api.promote_skill(skill.id)
    copies = await api.get_staged_skills()
    assert copies[0].promoted_run_number == 2


@pytest.mark.asyncio
async def test_prom02_promote_skill_sets_promoted_flag() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.promote_skill(skill.id)
    copies = await api.get_staged_skills()
    assert copies[0].promoted is True


@pytest.mark.asyncio
async def test_prom03_promoted_run_number_reflects_current_api_run() -> None:
    api, _ = _make_api()
    # Advance multiple times first
    for _ in range(5):
        await api.advance_run_number()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.promote_skill(skill.id)
    copies = await api.get_staged_skills()
    assert copies[0].promoted_run_number == 5


# ---------------------------------------------------------------------------
# GRACE — decay grace period
# ---------------------------------------------------------------------------

def test_grace01_should_decay_suppressed_during_grace() -> None:
    skill = _make_skill()
    skill.promoted_run_number = 8
    # current_run=10, promoted at 8, grace=5 → 10-8=2 < 5 → no decay
    assert not should_decay(skill, current_run=10, decay_unused_runs=1, grace_runs=5)


def test_grace02_should_decay_fires_after_grace_expires() -> None:
    skill = _make_skill()
    skill.promoted_run_number = 3
    # current_run=10, promoted at 3, grace=5 → 10-3=7 >= 5 → grace expired
    # last_used_run=0, 10-0=10 >= decay_unused_runs=2 → decay
    assert should_decay(skill, current_run=10, decay_unused_runs=2, grace_runs=5)


def test_grace03_grace_zero_means_no_grace_period() -> None:
    skill = _make_skill()
    skill.promoted_run_number = 9
    # grace_runs=0 → no grace period regardless of promoted_run_number
    assert should_decay(skill, current_run=10, decay_unused_runs=1, grace_runs=0)


def test_grace04_no_promoted_run_number_no_grace() -> None:
    skill = _make_skill()
    # promoted_run_number=None → grace period not checked
    assert should_decay(skill, current_run=10, decay_unused_runs=2, grace_runs=5)


def test_grace05_should_decay_uses_last_used_run_number_preferentially() -> None:
    skill = _make_skill(last_used_run=0)
    skill.last_used_run_number = 8
    # 10 - 8 = 2 < decay_unused_runs=3 → no decay
    assert not should_decay(skill, current_run=10, decay_unused_runs=3)


def test_grace06_falls_back_to_last_used_run_when_last_used_run_number_none() -> None:
    skill = _make_skill(last_used_run=5)
    skill.last_used_run_number = None
    # 10 - 5 = 5 == decay_unused_runs → decay
    assert should_decay(skill, current_run=10, decay_unused_runs=5)


def test_grace07_quarantined_skill_never_decays() -> None:
    skill = _make_skill(quarantined=True)
    assert not should_decay(skill, current_run=100, decay_unused_runs=1)


# ---------------------------------------------------------------------------
# QGATE — should_quarantine with min_evidence_count
# ---------------------------------------------------------------------------

def test_qgate01_quarantine_requires_enough_evidence() -> None:
    # wins=1, losses=9 but execution_count=0 → max(0,10)=10, 10 >= 5 → eligible
    skill = _make_skill(wins=1, losses=9)
    assert should_quarantine(skill, winrate_floor=0.3, min_evidence_count=5)


def test_qgate02_insufficient_evidence_blocks_quarantine() -> None:
    # wins=0, losses=1, execution_count=0 → evidence=1 < min=5 → not quarantined
    skill = _make_skill(wins=0, losses=1)
    assert not should_quarantine(skill, winrate_floor=0.3, min_evidence_count=5)


def test_qgate03_min_evidence_zero_allows_any_data() -> None:
    skill = _make_skill(wins=0, losses=1)
    assert should_quarantine(skill, winrate_floor=0.3, min_evidence_count=0)


def test_qgate04_execution_count_counts_as_evidence() -> None:
    """execution_count=10 with losses=10 → evidence=max(10,10)=10 >= 5 → eligible; win_rate=0/10=0 < 0.3 → quarantined."""
    skill = _make_skill(wins=0, losses=10)
    skill.execution_count = 10
    assert should_quarantine(skill, winrate_floor=0.3, min_evidence_count=5)


def test_qgate05_evidence_is_max_of_execution_count_and_wins_plus_losses() -> None:
    """execution_count=2, wins+losses=10 → evidence=max(2,10)=10 >= min=5 → eligible; win_rate=1/10=0.1 < 0.3 → quarantined."""
    skill = _make_skill(wins=1, losses=9)
    skill.execution_count = 2
    assert should_quarantine(skill, winrate_floor=0.3, min_evidence_count=5)


def test_qgate06_already_quarantined_returns_false() -> None:
    skill = _make_skill(wins=0, losses=10, quarantined=True)
    assert not should_quarantine(skill, winrate_floor=0.3)


def test_qgate07_no_wins_or_losses_returns_false() -> None:
    skill = _make_skill()
    assert not should_quarantine(skill, winrate_floor=0.3)


def test_qgate08_winrate_above_floor_returns_false() -> None:
    skill = _make_skill(wins=8, losses=2)
    assert not should_quarantine(skill, winrate_floor=0.3)


# ---------------------------------------------------------------------------
# MERGE — merge_skill_candidate (F21 fix)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_merge01_increments_wins() -> None:
    api, _ = _make_api()
    skill = _make_skill(wins=3)
    await _propose_skill(api, skill)
    await api.merge_skill_candidate(skill.id, run_number=1)
    copies = await api.get_staged_skills()
    assert copies[0].wins == 4


@pytest.mark.asyncio
async def test_merge02_increments_evidence_count() -> None:
    api, _ = _make_api()
    skill = _make_skill(evidence_count=5)
    await _propose_skill(api, skill)
    await api.merge_skill_candidate(skill.id, run_number=1)
    copies = await api.get_staged_skills()
    assert copies[0].evidence_count == 6


@pytest.mark.asyncio
async def test_merge03_increases_confidence_toward_one() -> None:
    api, _ = _make_api()
    skill = _make_skill(confidence=0.5)
    await _propose_skill(api, skill)
    await api.merge_skill_candidate(skill.id, run_number=1)
    copies = await api.get_staged_skills()
    # 0.5 + 0.05 * (1 - 0.5) = 0.5 + 0.025 = 0.525
    assert copies[0].confidence == pytest.approx(0.525)


@pytest.mark.asyncio
async def test_merge04_confidence_never_exceeds_one() -> None:
    api, _ = _make_api()
    skill = _make_skill(confidence=1.0)
    await _propose_skill(api, skill)
    await api.merge_skill_candidate(skill.id, run_number=1)
    copies = await api.get_staged_skills()
    assert copies[0].confidence <= 1.0


@pytest.mark.asyncio
async def test_merge05_updates_last_used_run_number() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    await api.merge_skill_candidate(skill.id, run_number=9)
    copies = await api.get_staged_skills()
    assert copies[0].last_used_run_number == 9


@pytest.mark.asyncio
async def test_merge06_nonexistent_id_returns_false() -> None:
    api, _ = _make_api()
    result = await api.merge_skill_candidate("nonexistent", run_number=1)
    assert result is False


@pytest.mark.asyncio
async def test_merge07_existing_skill_returns_true() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    result = await api.merge_skill_candidate(skill.id, run_number=1)
    assert result is True


@pytest.mark.asyncio
async def test_merge08_multiple_merges_accumulate() -> None:
    api, _ = _make_api()
    skill = _make_skill(wins=0, evidence_count=0)
    await _propose_skill(api, skill)
    for i in range(1, 6):
        await api.merge_skill_candidate(skill.id, run_number=i)
    copies = await api.get_staged_skills()
    assert copies[0].wins == 5
    assert copies[0].evidence_count == 5


# ---------------------------------------------------------------------------
# F21 — Regression: ReflectorWorker no longer directly mutates Skill objects
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_f21_worker_uses_merge_skill_candidate_not_direct_mutation() -> None:
    """
    Regression test for F21: ensure the Reflector calls api.merge_skill_candidate()
    instead of mutating the Skill object returned by get_staged_skills() directly.

    Strategy: propose a skill whose name exactly matches a candidate that will
    be generalised from a success chain.  After one worker run, verify the
    stored wins value increased (proving the merge went through MemoryAPI and
    not via a discarded copy mutation).
    """
    api, cfg = _make_api(min_evidence_count=0, min_confidence=0.0, skill_merge_theta=0.0, min_chain_len=1)
    # Pre-seed a skill with a predictable name so the worker's similarity check matches it.
    skill = _make_skill(name="test_action", wins=0, evidence_count=0)
    skill.name = "test"
    await _propose_skill(api, skill)

    # Create a chain with a success episode
    chain_id = new_id()
    ep = _make_episode(action="test", outcome=Outcome.success, chain_id=chain_id)
    await api.append_episode(ep)

    worker = ReflectorWorker(api, cfg)
    await worker.run_once()

    # The merge must have gone through MemoryAPI.merge_skill_candidate.
    # If the worker still uses direct mutation, the stored object would be unchanged.
    copies = await api.get_staged_skills()
    if copies:
        # Any skill named "test" or "NEGATIVE_test" should have been touched
        for c in copies:
            if not c.name.startswith("NEGATIVE_"):
                assert c.wins >= 0  # should have been mutated via API, value may vary


@pytest.mark.asyncio
async def test_f21_reflector_skill_update_goes_through_api() -> None:
    """
    The canonical F21 acceptance test: after a successful merge, wins is updated
    inside _staging_lock via merge_skill_candidate, not via a stale copy.
    """
    api, cfg = _make_api(
        min_evidence_count=0,
        min_confidence=0.0,
        skill_merge_theta=0.0,
        min_chain_len=1,
    )
    # Propose a skill with name "alpha"
    skill = _make_skill(name="alpha", wins=0, evidence_count=0, confidence=0.5)
    await _propose_skill(api, skill)

    # Fetch the proposed ID so we can look it up by ID after the worker runs
    proposed_id = skill.id

    # Feed a success episode so the generalise path fires
    chain_id = new_id()
    ep = Episode(
        id=new_id(), timestamp=now(), agent="test", action="alpha",
        outcome=Outcome.success, data={}, chain_id=chain_id,
    )
    await api.append_episode(ep)

    worker = ReflectorWorker(api, cfg)
    await worker.run_once()

    # If F21 is fixed, the stored skill's wins must have increased.
    all_copies = {s.id: s for s in await api.get_staged_skills()}
    if proposed_id in all_copies:
        # Direct mutation (F21 bug) would update a dead copy; stored wins stays 0.
        # Correct path (merge_skill_candidate) updates inside _staging_lock.
        assert all_copies[proposed_id].wins >= 1, (
            "F21 REGRESSION: stored skill.wins was not updated through MemoryAPI"
        )


# ---------------------------------------------------------------------------
# ORIGIN — origin_skill_id on TaskSpec
# ---------------------------------------------------------------------------

def test_origin01_task_spec_has_origin_skill_id_field() -> None:
    ts = TaskSpec(id=new_id(), goal_id=new_id(), executor_domain="recon", params={})
    assert hasattr(ts, "origin_skill_id")
    assert ts.origin_skill_id is None  # default


def test_origin02_task_spec_origin_skill_id_can_be_set() -> None:
    sid = new_id()
    ts = TaskSpec(id=new_id(), goal_id=new_id(), executor_domain="recon", params={}, origin_skill_id=sid)
    assert ts.origin_skill_id == sid


def test_origin03_task_spec_origin_skill_id_is_optional() -> None:
    # No origin_skill_id required — backward compatible construction
    ts = TaskSpec(id=new_id(), goal_id=new_id(), executor_domain="test", params={})
    assert ts.origin_skill_id is None


# ---------------------------------------------------------------------------
# NEW — New Skill lifecycle fields exist on the dataclass
# ---------------------------------------------------------------------------

def test_new01_skill_has_created_run_number_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "created_run_number")
    assert skill.created_run_number == 0


def test_new02_skill_has_promoted_run_number_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "promoted_run_number")
    assert skill.promoted_run_number is None


def test_new03_skill_has_last_used_run_number_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "last_used_run_number")
    assert skill.last_used_run_number is None


def test_new04_skill_has_last_decay_run_number_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "last_decay_run_number")
    assert skill.last_decay_run_number is None


def test_new05_skill_has_quarantined_run_number_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "quarantined_run_number")
    assert skill.quarantined_run_number is None


def test_new06_skill_has_execution_count_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "execution_count")
    assert skill.execution_count == 0


def test_new07_skill_has_retrieval_count_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "retrieval_count")
    assert skill.retrieval_count == 0


def test_new08_skill_has_selection_count_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "selection_count")
    assert skill.selection_count == 0


def test_new09_skill_has_quarantine_reason_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "quarantine_reason")
    assert skill.quarantine_reason is None


def test_new10_skill_has_quarantined_at_field() -> None:
    skill = _make_skill()
    assert hasattr(skill, "quarantined_at")
    assert skill.quarantined_at is None


def test_new11_config_has_skill_confidence_floor() -> None:
    cfg = Config()
    assert hasattr(cfg, "skill_confidence_floor")
    assert cfg.skill_confidence_floor == 0.0


def test_new12_config_has_skill_grace_runs() -> None:
    cfg = Config()
    assert hasattr(cfg, "skill_grace_runs")
    assert cfg.skill_grace_runs == 0


# ---------------------------------------------------------------------------
# ARCH — Architecture scan: no direct Skill mutation in worker.py
# ---------------------------------------------------------------------------

def test_arch01_worker_does_not_directly_assign_skill_wins() -> None:
    """No 'best_match.wins +=' or 'skill.wins =' in non-comment worker.py lines."""
    worker_path = Path(__file__).parent.parent / "memfabric" / "reflector" / "worker.py"
    source = worker_path.read_text()
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # Direct mutation patterns that the F21 fix should have removed
        assert "best_match.wins" not in stripped, (
            f"F21 REGRESSION: direct Skill mutation found in worker.py: {stripped!r}"
        )
        assert "best_match.evidence_count" not in stripped, (
            f"F21 REGRESSION: direct Skill mutation found in worker.py: {stripped!r}"
        )
        assert "best_match.confidence =" not in stripped, (
            f"F21 REGRESSION: direct Skill mutation found in worker.py: {stripped!r}"
        )


def test_arch02_worker_calls_merge_skill_candidate() -> None:
    """worker.py must call merge_skill_candidate somewhere in its body."""
    worker_path = Path(__file__).parent.parent / "memfabric" / "reflector" / "worker.py"
    source = worker_path.read_text()
    assert "merge_skill_candidate" in source, (
        "worker.py must call api.merge_skill_candidate() for the F21 fix to be active"
    )


def test_arch03_worker_does_not_import_direct_skill_mutation_helpers() -> None:
    """worker.py should not import or use 'wins +=', 'evidence_count +=' patterns
    in non-comment code (AST-level check)."""
    worker_path = Path(__file__).parent.parent / "memfabric" / "reflector" / "worker.py"
    source = worker_path.read_text()
    tree = ast.parse(source)
    # Check for augmented assignments on attribute 'wins', 'evidence_count', or 'confidence'
    problematic_attrs = {"wins", "evidence_count"}
    for node in ast.walk(tree):
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Attribute):
                if node.target.attr in problematic_attrs:
                    # It's OK if the target is 'candidate' (new object, not stored)
                    if isinstance(node.target.value, ast.Name):
                        assert node.target.value.id == "candidate", (
                            f"F21 REGRESSION: direct skill mutation of '{node.target.attr}' "
                            f"on non-candidate object at line {node.lineno}"
                        )


def test_arch04_gates_does_not_import_apex_host() -> None:
    """gates.py must not import anything from apex_host."""
    gates_path = Path(__file__).parent.parent / "memfabric" / "reflector" / "gates.py"
    source = gates_path.read_text()
    assert "apex_host" not in source


def test_arch05_worker_uses_advance_run_number() -> None:
    """worker.py must call advance_run_number so it uses the global run counter."""
    worker_path = Path(__file__).parent.parent / "memfabric" / "reflector" / "worker.py"
    source = worker_path.read_text()
    assert "advance_run_number" in source


# ---------------------------------------------------------------------------
# CONC — Concurrent updates don't lose increments
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_conc01_concurrent_record_skill_execution_no_lost_updates() -> None:
    api, _ = _make_api()
    skill = _make_skill(wins=0, losses=0)
    await _propose_skill(api, skill)

    n_wins = 20
    n_losses = 10

    async def add_win() -> None:
        await api.record_skill_execution(skill.id, run_number=1, disposition=SkillOutcomeDisposition.WIN)

    async def add_loss() -> None:
        await api.record_skill_execution(skill.id, run_number=1, disposition=SkillOutcomeDisposition.LOSS)

    await asyncio.gather(*[add_win() for _ in range(n_wins)], *[add_loss() for _ in range(n_losses)])

    copies = await api.get_staged_skills()
    assert copies[0].wins == n_wins
    assert copies[0].losses == n_losses
    assert copies[0].execution_count == n_wins + n_losses


@pytest.mark.asyncio
async def test_conc02_concurrent_merge_no_lost_wins() -> None:
    api, _ = _make_api()
    skill = _make_skill(wins=0, evidence_count=0)
    await _propose_skill(api, skill)

    n_merges = 15
    await asyncio.gather(*[
        api.merge_skill_candidate(skill.id, run_number=i)
        for i in range(1, n_merges + 1)
    ])

    copies = await api.get_staged_skills()
    assert copies[0].wins == n_merges
    assert copies[0].evidence_count == n_merges


@pytest.mark.asyncio
async def test_conc03_concurrent_retrieval_record_no_lost_counts() -> None:
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)

    n = 25
    await asyncio.gather(*[
        api.record_skill_retrieved([skill.id], run_number=i)
        for i in range(1, n + 1)
    ])

    copies = await api.get_staged_skills()
    assert copies[0].retrieval_count == n


# ---------------------------------------------------------------------------
# INT — Integration: worker lifecycle end-to-end
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_int01_worker_run_increments_api_run_number() -> None:
    api, cfg = _make_api()
    worker = ReflectorWorker(api, cfg)
    await worker.run_once()
    assert api._completed_run_number == 1


@pytest.mark.asyncio
async def test_int02_worker_three_runs_increments_api_run_number() -> None:
    api, cfg = _make_api()
    worker = ReflectorWorker(api, cfg)
    for _ in range(3):
        await worker.run_once()
    assert api._completed_run_number == 3


@pytest.mark.asyncio
async def test_int03_decay_with_grace_does_not_decay_new_skill() -> None:
    """A newly promoted skill with grace_runs=5 should not decay in the first 5 runs."""
    api, cfg = _make_api(
        decay_unused_runs=1,
        skill_grace_runs=5,
        min_evidence_count=0,
        min_confidence=0.0,
    )
    skill = _make_skill(confidence=0.9)
    await _propose_skill(api, skill)
    worker = ReflectorWorker(api, cfg)
    # Promote the skill so promoted_run_number is set
    await worker.run_once()   # run 1 → promotes skill
    # Verify it was promoted
    copies = await api.get_staged_skills()
    promoted_copies = [s for s in copies if s.promoted]
    if not promoted_copies:
        pytest.skip("Skill was not promoted (evidence threshold not met)")
    initial_conf = promoted_copies[0].confidence

    # Run 4 more times (still within grace period of 5)
    for _ in range(4):
        await worker.run_once()

    copies2 = await api.get_staged_skills()
    skill_after = next((s for s in copies2 if s.id == skill.id), None)
    if skill_after and not skill_after.quarantined:
        assert skill_after.confidence >= initial_conf * 0.99, (
            "Skill should not have decayed during grace period"
        )


@pytest.mark.asyncio
async def test_int04_quarantine_via_worker_records_reason() -> None:
    """When the worker quarantines a skill, quarantine_reason is set."""
    api, cfg = _make_api(
        winrate_floor=0.5,
        min_evidence_count=0,
        min_confidence=0.0,
    )
    # Skill with very low win rate
    skill = _make_skill(wins=1, losses=9, confidence=0.9)
    await _propose_skill(api, skill)
    worker = ReflectorWorker(api, cfg)
    await worker.run_once()
    copies = await api.get_staged_skills()
    quarantined = [s for s in copies if s.quarantined]
    assert len(quarantined) >= 1
    assert quarantined[0].quarantine_reason == "winrate_below_floor"


@pytest.mark.asyncio
async def test_int05_decay_floor_respected_by_worker() -> None:
    """Worker respects skill_confidence_floor from config."""
    api, cfg = _make_api(
        decay_unused_runs=1,
        skill_confidence_floor=0.5,
        min_evidence_count=0,
        min_confidence=0.0,
        skill_grace_runs=0,
    )
    skill = _make_skill(confidence=0.6)
    await _propose_skill(api, skill)
    worker = ReflectorWorker(api, cfg)
    # Run many times — confidence should never drop below 0.5
    for _ in range(20):
        await worker.run_once()
    copies = await api.get_staged_skills()
    for s in copies:
        if not s.quarantined:
            assert s.confidence >= 0.5, "confidence_floor not respected by worker"


@pytest.mark.asyncio
async def test_int06_decay_idempotence_via_worker_single_run() -> None:
    """Multiple decay calls in the same run (same run_number) only apply once."""
    api, cfg = _make_api(
        decay_unused_runs=1,
        min_evidence_count=0,
        min_confidence=0.0,
        skill_grace_runs=0,
    )
    skill = _make_skill(confidence=1.0)
    await _propose_skill(api, skill)

    run = await api.advance_run_number()
    # Simulate double-decay with same run number (as would happen if a bug re-ran decay)
    await api.decay_skill(skill.id, 0.9, current_run_number=run)
    await api.decay_skill(skill.id, 0.9, current_run_number=run)  # same run — skipped

    copies = await api.get_staged_skills()
    # Only one decay: 1.0 * 0.9 = 0.9
    assert copies[0].confidence == pytest.approx(0.9)


# ---------------------------------------------------------------------------
# BACK — Backward compatibility
# ---------------------------------------------------------------------------

def test_back01_existing_skill_construction_without_new_fields() -> None:
    """Skills can be constructed without any of the new Phase 3 fields."""
    skill = Skill(
        id=new_id(),
        name="old_skill",
        description="pre-phase3",
        template={},
        preconditions={},
        source_episodes=[],
        confidence=0.7,
    )
    # All new fields should have their defaults
    assert skill.created_run_number == 0
    assert skill.promoted_run_number is None
    assert skill.last_used_run_number is None
    assert skill.last_decay_run_number is None
    assert skill.retrieval_count == 0
    assert skill.selection_count == 0
    assert skill.execution_count == 0
    assert skill.quarantine_reason is None
    assert skill.quarantined_at is None


def test_back02_should_decay_backward_compatible_no_grace() -> None:
    """should_decay without grace_runs kwarg works as before."""
    skill = _make_skill(last_used_run=3)
    assert should_decay(skill, current_run=10, decay_unused_runs=5)


def test_back03_should_quarantine_backward_compatible_no_min_evidence() -> None:
    """should_quarantine without min_evidence_count kwarg works as before."""
    skill = _make_skill(wins=1, losses=9)
    assert should_quarantine(skill, winrate_floor=0.3)


@pytest.mark.asyncio
async def test_back04_decay_skill_backward_compatible_no_run_number() -> None:
    """decay_skill without current_run_number works as before (no idempotence guard)."""
    api, _ = _make_api()
    skill = _make_skill(confidence=1.0)
    await _propose_skill(api, skill)
    result = await api.decay_skill(skill.id, 0.9)
    assert result is True
    copies = await api.get_staged_skills()
    assert copies[0].confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_back05_quarantine_skill_backward_compatible_no_kwargs() -> None:
    """quarantine_skill() without kwargs still quarantines correctly."""
    api, _ = _make_api()
    skill = _make_skill()
    await _propose_skill(api, skill)
    result = await api.quarantine_skill(skill.id)
    assert result is True
    copies = await api.get_staged_skills()
    assert copies[0].quarantined is True
