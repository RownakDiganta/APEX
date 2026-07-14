# test_foundation.py
# Tests for the memfabric foundation modules — ids.py, types.py, and config.py — verifying ID uniqueness, UTC timestamp format, dataclass slot correctness, and default thresholds.
"""Tests for Module 1: ids.py, types.py, config.py."""
from __future__ import annotations

import uuid
from datetime import datetime

import pytest

from memfabric.ids import new_id, now
from memfabric.config import Config
from memfabric.types import (
    ALL_TIERS,
    AbandonSignal,
    Conflict,
    Edge,
    Episode,
    EvidenceBundle,
    ExecutorResult,
    Goal,
    KnowledgeEntry,
    Node,
    OpenTask,
    Outcome,
    Skill,
    TaskSpec,
    Tier,
)


# ---------------------------------------------------------------------------
# ids.py
# ---------------------------------------------------------------------------

class TestNewId:
    def test_returns_string(self) -> None:
        assert isinstance(new_id(), str)

    def test_valid_uuid4(self) -> None:
        uid = new_id()
        parsed = uuid.UUID(uid, version=4)
        assert parsed.version == 4

    def test_unique(self) -> None:
        ids = {new_id() for _ in range(1000)}
        assert len(ids) == 1000


class TestNow:
    def test_returns_string(self) -> None:
        assert isinstance(now(), str)

    def test_utc_iso8601(self) -> None:
        ts = now()
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo is not None
        # Must be UTC
        assert dt.utcoffset() is not None and dt.utcoffset().total_seconds() == 0  # type: ignore[union-attr]

    def test_monotonically_increasing(self) -> None:
        import time
        t1 = now()
        time.sleep(0.01)
        t2 = now()
        assert t2 > t1


# ---------------------------------------------------------------------------
# config.py
# ---------------------------------------------------------------------------

class TestConfig:
    def test_default_construction(self) -> None:
        cfg = Config()
        assert 0.0 < cfg.conflict_confidence_floor <= 1.0
        assert 0.0 < cfg.low_confidence_tau <= 1.0
        assert cfg.max_concurrency >= 1
        assert cfg.min_chain_len >= 1

    def test_override(self) -> None:
        cfg = Config(conflict_confidence_floor=0.95, max_concurrency=2)
        assert cfg.conflict_confidence_floor == 0.95
        assert cfg.max_concurrency == 2

    def test_actionable_node_types_is_list(self) -> None:
        cfg = Config()
        assert isinstance(cfg.actionable_node_types, list)
        assert len(cfg.actionable_node_types) > 0

    def test_two_configs_are_independent(self) -> None:
        c1 = Config()
        c2 = Config()
        c1.actionable_node_types.append("custom")
        assert "custom" not in c2.actionable_node_types


# ---------------------------------------------------------------------------
# types.py
# ---------------------------------------------------------------------------

class TestTier:
    def test_all_tiers_excludes_staged(self) -> None:
        assert Tier.staged not in ALL_TIERS

    def test_string_values(self) -> None:
        assert Tier.working == "working"
        assert Tier.episodic == "episodic"


class TestOutcome:
    def test_string_values(self) -> None:
        assert Outcome.success == "success"
        assert Outcome.fundamental == "fundamental"


class TestNode:
    def test_construction(self) -> None:
        t = now()
        n = Node(
            id="n1",
            type="host",
            props={"ip": "1.2.3.4"},
            confidence=0.9,
            source="scanner",
            first_seen=t,
            last_seen=t,
        )
        assert n.id == "n1"
        assert n._provenance == {}

    def test_provenance_default_independent(self) -> None:
        t = now()
        n1 = Node("a", "t", {}, 1.0, "s", t, t)
        n2 = Node("b", "t", {}, 1.0, "s", t, t)
        n1._provenance["x"] = {"value": 1}
        assert "x" not in n2._provenance

    def test_slots_prevent_arbitrary_attrs(self) -> None:
        t = now()
        n = Node("a", "t", {}, 1.0, "s", t, t)
        with pytest.raises(AttributeError):
            n.nonexistent = "oops"  # type: ignore[attr-defined]


class TestEdge:
    def test_construction(self) -> None:
        t = now()
        e = Edge("e1", "n1", "n2", "connects", {}, 0.7, "src", t, t)
        assert e.from_id == "n1"
        assert e.to_id == "n2"


class TestEpisode:
    def test_construction(self) -> None:
        ep = Episode(
            agent="agent-1",
            action="scan_host",
            outcome=Outcome.success,
            data={"result": "open"},
        )
        assert ep.id == ""  # blank until appended
        assert ep.chain_id is None

    def test_outcome_enum(self) -> None:
        ep = Episode("a", "b", Outcome.fundamental, {})
        assert ep.outcome == Outcome.fundamental


class TestKnowledgeEntry:
    def test_defaults(self) -> None:
        ke = KnowledgeEntry(text="A fact.", source="agent", confidence=0.6)
        assert not ke.promoted
        assert ke.embedding is None


class TestSkill:
    def test_defaults(self) -> None:
        s = Skill(
            name="port_scan",
            description="Scan ports",
            template={},
            preconditions={},
            source_episodes=[],
            confidence=0.5,
        )
        assert not s.quarantined
        assert not s.promoted
        assert s.wins == 0

    def test_winrate(self) -> None:
        s = Skill("x", "d", {}, {}, [], 0.5, wins=3, losses=1)
        total = s.wins + s.losses
        assert total == 4
        assert s.wins / total == 0.75


class TestConflict:
    def test_construction(self) -> None:
        c = Conflict(
            id="c1",
            node_id="n1",
            field_name="ip",
            claim_a={"value": "1.1.1.1", "confidence": 0.9, "source": "a", "timestamp": now()},
            claim_b={"value": "2.2.2.2", "confidence": 0.9, "source": "b", "timestamp": now()},
            timestamp=now(),
        )
        assert not c.resolved
        assert c.resolution is None


class TestCoordinationTypes:
    def test_task_spec(self) -> None:
        ts = TaskSpec(id="t1", goal_id="g1", executor_domain="echo", params={})
        assert ts.retries == 0
        assert ts.subgraph_anchor is None

    def test_executor_result(self) -> None:
        ep = Episode("a", "b", Outcome.success, {})
        r = ExecutorResult(task_id="t1", episode=ep)
        assert r.node_deltas == []
        assert r.clue is None

    def test_abandon_signal(self) -> None:
        sig = AbandonSignal(reason="dead end")
        assert sig.reason == "dead end"

    def test_goal(self) -> None:
        g = Goal(id="g1", description="test", phase="recon")
        assert g.priority == 1.0

    def test_evidence_bundle(self) -> None:
        bundle = EvidenceBundle(query="test", entries=[], subgraph=None, tiers_queried=[])
        assert bundle.entries == []

    def test_open_task(self) -> None:
        ot = OpenTask(node_id="n1", node_type="weakness", props={}, created=now())
        assert ot.node_type == "weakness"
