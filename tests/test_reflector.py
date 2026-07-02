# test_reflector.py
# Tests for the Reflector covering promotion gates, skill decay, quarantine, and episodic-to-skill consolidation.
"""Tests for Module 6: reflector/.

Section 8 invariants tested here:
- Reflector gates: below-threshold staged skill never promoted.
- Unused skill decays.
- Losing skill quarantined and removed from retrieval.
- Positive success chain → skill generalised and staged.
- Fundamental failure → negative skill staged.
- Promotion only after meeting evidence_count AND confidence thresholds.
"""
from __future__ import annotations

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.reflector.consolidate import generalize
from memfabric.reflector.gates import (
    decayed_confidence,
    should_decay,
    should_promote_knowledge,
    should_promote_skill,
    should_quarantine,
    win_rate,
)
from memfabric.reflector.worker import ReflectorWorker
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Episode, KnowledgeEntry, Outcome, Skill


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_api(
    min_evidence_count: int = 2,
    min_confidence: float = 0.5,
    skill_prior: float = 0.5,
    min_chain_len: int = 2,
    decay_unused_runs: int = 5,
    winrate_floor: float = 0.3,
) -> tuple[MemoryAPI, Config]:
    cfg = Config(
        min_evidence_count=min_evidence_count,
        min_confidence=min_confidence,
        skill_prior=skill_prior,
        min_chain_len=min_chain_len,
        decay_unused_runs=decay_unused_runs,
        winrate_floor=winrate_floor,
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


def make_episode(
    action: str = "scan",
    outcome: Outcome = Outcome.success,
    chain_id: str | None = None,
) -> Episode:
    return Episode(
        id=new_id(),
        timestamp=now(),
        agent="test-agent",
        action=action,
        outcome=outcome,
        data={"target": "192.168.1.1", "port": "8080"},
        chain_id=chain_id,
    )


def make_skill(
    *,
    confidence: float = 0.5,
    wins: int = 0,
    losses: int = 0,
    evidence_count: int = 0,
    last_used_run: int = 0,
    promoted: bool = False,
    quarantined: bool = False,
) -> Skill:
    return Skill(
        id=new_id(),
        timestamp=now(),
        name="test_skill",
        description="A test skill",
        template={},
        preconditions={},
        source_episodes=[],
        confidence=confidence,
        wins=wins,
        losses=losses,
        evidence_count=evidence_count,
        last_used_run=last_used_run,
        promoted=promoted,
        quarantined=quarantined,
    )


# ---------------------------------------------------------------------------
# gates.py — pure policy unit tests
# ---------------------------------------------------------------------------

class TestPromotionGate:
    def test_knowledge_below_confidence_not_promoted(self) -> None:
        ke = KnowledgeEntry(text="x", source="a", confidence=0.3)
        assert not should_promote_knowledge(ke, min_confidence=0.5)

    def test_knowledge_at_confidence_promoted(self) -> None:
        ke = KnowledgeEntry(text="x", source="a", confidence=0.5)
        assert should_promote_knowledge(ke, min_confidence=0.5)

    def test_already_promoted_knowledge_not_re_promoted(self) -> None:
        ke = KnowledgeEntry(text="x", source="a", confidence=0.9, promoted=True)
        assert not should_promote_knowledge(ke, min_confidence=0.5)

    def test_skill_below_evidence_count_not_promoted(self) -> None:
        sk = make_skill(confidence=0.9, evidence_count=1)
        assert not should_promote_skill(sk, min_evidence_count=2, min_confidence=0.5)

    def test_skill_below_confidence_not_promoted(self) -> None:
        sk = make_skill(confidence=0.3, evidence_count=5)
        assert not should_promote_skill(sk, min_evidence_count=2, min_confidence=0.5)

    def test_skill_meets_both_gates_promoted(self) -> None:
        sk = make_skill(confidence=0.7, evidence_count=3)
        assert should_promote_skill(sk, min_evidence_count=2, min_confidence=0.5)

    def test_quarantined_skill_never_promoted(self) -> None:
        sk = make_skill(confidence=0.9, evidence_count=10, quarantined=True)
        assert not should_promote_skill(sk, min_evidence_count=1, min_confidence=0.1)

    def test_already_promoted_not_re_promoted(self) -> None:
        sk = make_skill(confidence=0.9, evidence_count=10, promoted=True)
        assert not should_promote_skill(sk, min_evidence_count=1, min_confidence=0.1)


class TestDecayGate:
    def test_recently_used_not_decayed(self) -> None:
        sk = make_skill(last_used_run=8)
        assert not should_decay(sk, current_run=10, decay_unused_runs=5)

    def test_unused_long_enough_decayed(self) -> None:
        sk = make_skill(last_used_run=0)
        assert should_decay(sk, current_run=5, decay_unused_runs=5)

    def test_decay_reduces_confidence(self) -> None:
        sk = make_skill(confidence=1.0)
        new_conf = decayed_confidence(sk, decay_factor=0.9)
        assert abs(new_conf - 0.9) < 1e-9

    def test_decay_never_below_zero(self) -> None:
        sk = make_skill(confidence=0.0)
        new_conf = decayed_confidence(sk, decay_factor=0.9)
        assert new_conf == 0.0


class TestQuarantineGate:
    def test_win_rate_computed_correctly(self) -> None:
        sk = make_skill(wins=3, losses=1)
        assert abs(win_rate(sk) - 0.75) < 1e-9

    def test_no_data_win_rate_is_none(self) -> None:
        sk = make_skill(wins=0, losses=0)
        assert win_rate(sk) is None

    def test_below_floor_quarantined(self) -> None:
        sk = make_skill(wins=1, losses=9)   # 10% win rate
        assert should_quarantine(sk, winrate_floor=0.3)

    def test_above_floor_not_quarantined(self) -> None:
        sk = make_skill(wins=4, losses=1)   # 80% win rate
        assert not should_quarantine(sk, winrate_floor=0.3)

    def test_already_quarantined_not_re_quarantined(self) -> None:
        sk = make_skill(wins=0, losses=10, quarantined=True)
        assert not should_quarantine(sk, winrate_floor=0.3)

    def test_no_data_not_quarantined(self) -> None:
        sk = make_skill(wins=0, losses=0)
        assert not should_quarantine(sk, winrate_floor=0.3)


# ---------------------------------------------------------------------------
# consolidate.py
# ---------------------------------------------------------------------------

class TestGeneralize:
    def test_produces_skill_from_chain(self) -> None:
        chain = [
            make_episode("port_scan"),
            make_episode("service_detect"),
        ]
        skill = generalize(chain, confidence=0.5)
        assert skill.name != ""
        assert len(skill.template["steps"]) == 2
        assert skill.confidence == 0.5

    def test_concrete_ip_replaced_with_slot(self) -> None:
        ep = Episode("a", "connect", Outcome.success, {"target": "192.168.1.1"}, id=new_id(), timestamp=now())
        skill = generalize([ep])
        steps = skill.template["steps"]
        assert "192.168.1.1" not in str(steps)
        assert "<SLOT_" in str(steps)

    def test_source_episodes_recorded(self) -> None:
        chain = [make_episode("step_a"), make_episode("step_b")]
        skill = generalize(chain)
        assert len(skill.source_episodes) == 2

    def test_empty_chain_produces_skill(self) -> None:
        skill = generalize([])
        assert skill.name == "skill_unknown"
        assert skill.template["steps"] == []


# ---------------------------------------------------------------------------
# ReflectorWorker integration tests
# ---------------------------------------------------------------------------

class TestReflectorWorker:
    async def test_success_chain_staged_as_skill(self) -> None:
        api, cfg = make_api(min_chain_len=2)
        worker = ReflectorWorker(api, cfg)

        chain_id = new_id()
        ep1 = make_episode("scan", Outcome.success, chain_id=chain_id)
        ep2 = make_episode("exploit", Outcome.success, chain_id=chain_id)
        await api.append_episode(ep1)
        await api.append_episode(ep2)

        await worker.run_once()

        skills = await api.get_staged_skills()
        skill_names = [s.name for s in skills]
        assert any("scan" in n for n in skill_names)

    async def test_fundamental_produces_negative_skill(self) -> None:
        api, cfg = make_api(min_chain_len=1)
        worker = ReflectorWorker(api, cfg)

        ep = make_episode("attempt", Outcome.fundamental)
        await api.append_episode(ep)

        await worker.run_once()

        skills = await api.get_staged_skills()
        assert any("NEGATIVE" in s.name for s in skills)

    async def test_below_threshold_skill_not_promoted(self) -> None:
        """A staged skill below min_evidence_count must NOT be promoted."""
        api, cfg = make_api(min_evidence_count=3, min_confidence=0.5)
        worker = ReflectorWorker(api, cfg)

        from memfabric.types import Skill
        skill = Skill(
            id=new_id(), timestamp=now(),
            name="weak_skill", description="weak",
            template={}, preconditions={}, source_episodes=[],
            confidence=0.7, evidence_count=1,   # below min_evidence_count=3
        )
        await api.propose_skill(skill)

        await worker.run_once()

        # Must not be promoted
        staged = await api.get_staged_skills()
        assert any(s.id == skill.id and not s.promoted for s in staged)

    async def test_skill_promoted_after_threshold(self) -> None:
        """Skill meeting both evidence_count and confidence gates is promoted."""
        api, cfg = make_api(min_evidence_count=2, min_confidence=0.5)
        worker = ReflectorWorker(api, cfg)

        from memfabric.types import Skill
        skill = Skill(
            id=new_id(), timestamp=now(),
            name="strong_skill", description="strong skill procedure",
            template={}, preconditions={}, source_episodes=[],
            confidence=0.7, evidence_count=3,   # meets both gates
        )
        await api.propose_skill(skill)

        await worker.run_once()

        # Check it is now in the lexical index (promoted)
        results = await api._lexical.search("strong skill procedure", k=5)
        ids = [r[0] for r in results]
        assert skill.id in ids

    async def test_unused_skill_confidence_decays(self) -> None:
        """A skill unused for >= decay_unused_runs passes has reduced confidence."""
        api, cfg = make_api(decay_unused_runs=1)
        worker = ReflectorWorker(api, cfg)

        from memfabric.types import Skill
        skill = Skill(
            id=new_id(), timestamp=now(),
            name="old_skill", description="old",
            template={}, preconditions={}, source_episodes=[],
            confidence=1.0, last_used_run=0,
        )
        await api.propose_skill(skill)

        # Run enough times to trigger decay (run_count - last_used_run >= decay_unused_runs=1)
        await worker.run_once()   # run_count=1, last_used_run=0, diff=1 → decay

        staged = await api.get_staged_skills()
        decayed_skill = next(s for s in staged if s.id == skill.id)
        assert decayed_skill.confidence < 1.0

    async def test_losing_skill_quarantined_and_removed_from_retrieval(self) -> None:
        """Skill with win-rate below floor is quarantined + removed from indexes."""
        api, cfg = make_api(winrate_floor=0.3, min_evidence_count=1, min_confidence=0.5)
        worker = ReflectorWorker(api, cfg)

        from memfabric.types import Skill
        skill = Skill(
            id=new_id(), timestamp=now(),
            name="bad_skill", description="losing skill technique",
            template={}, preconditions={}, source_episodes=[],
            confidence=0.7, evidence_count=3,
            wins=1, losses=9,   # 10% win rate < 30% floor
        )
        await api.propose_skill(skill)

        # Promote first so it's in the lexical index
        await api.promote_skill(skill.id)

        # Verify it's findable before quarantine
        before = await api._lexical.search("losing skill technique", k=5)
        assert any(r[0] == skill.id for r in before)

        # Run reflector → quarantine triggers
        await worker.run_once()

        staged = await api.get_staged_skills()
        qs = next(s for s in staged if s.id == skill.id)
        assert qs.quarantined

        # Verify removed from lexical index
        after = await api._lexical.search("losing skill technique", k=5)
        assert not any(r[0] == skill.id for r in after)

    async def test_knowledge_promoted_when_meets_confidence(self) -> None:
        api, cfg = make_api(min_confidence=0.5)
        worker = ReflectorWorker(api, cfg)

        ke = KnowledgeEntry(
            id=new_id(), timestamp=now(),
            text="important fact about the system",
            source="agent",
            confidence=0.8,   # above min_confidence=0.5
        )
        await api.propose_knowledge(ke)

        await worker.run_once()

        # Check in lexical index
        results = await api._lexical.search("important fact system", k=5)
        ids = [r[0] for r in results]
        assert ke.id in ids

    async def test_knowledge_below_confidence_not_promoted(self) -> None:
        api, cfg = make_api(min_confidence=0.8)
        worker = ReflectorWorker(api, cfg)

        ke = KnowledgeEntry(
            id=new_id(), timestamp=now(),
            text="weak fact barely credible",
            source="agent",
            confidence=0.4,   # below min_confidence=0.8
        )
        await api.propose_knowledge(ke)

        await worker.run_once()

        results = await api._lexical.search("weak fact barely", k=5)
        ids = [r[0] for r in results]
        assert ke.id not in ids
        # Still in staging
        staged_ke = await api.get_staged_knowledge()
        assert any(e.id == ke.id and not e.promoted for e in staged_ke)
