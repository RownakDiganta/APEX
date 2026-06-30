"""Tests for Module 3: api.py (MemoryAPI).

Section 8 invariants tested here:
- Per-field LWW upsert: two writers, overlapping fields → correct field-level
  merge, provenance recorded, no whole-node clobber.
- Episodic immutability: append then attempt mutation → rejected; replay works.
- Staging isolation: propose_* entry NOT returned by query until promoted.
- Open-task view: derived, not stored — graph mutation changes view immediately.
- Conflict: contradictory high-confidence writes → Conflict created, value kept.
"""
from __future__ import annotations

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import (
    ALL_TIERS,
    Edge,
    Episode,
    KnowledgeEntry,
    Node,
    Outcome,
    Skill,
    Tier,
)


# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

def make_api(
    conflict_confidence_floor: float = 0.8,
    actionable_node_types: list[str] | None = None,
    terminal_edge_types: list[str] | None = None,
) -> MemoryAPI:
    cfg_kwargs: dict[str, object] = {
        "conflict_confidence_floor": conflict_confidence_floor,
    }
    if actionable_node_types is not None:
        cfg_kwargs["actionable_node_types"] = actionable_node_types
    if terminal_edge_types is not None:
        cfg_kwargs["terminal_edge_types"] = terminal_edge_types
    cfg = Config(**cfg_kwargs)  # type: ignore[arg-type]
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def make_node(
    id: str,
    type: str = "host",
    confidence: float = 0.9,
    source: str = "agent-A",
    **props: object,
) -> Node:
    t = now()
    return Node(
        id=id,
        type=type,
        props=dict(props),
        confidence=confidence,
        source=source,
        first_seen=t,
        last_seen=t,
    )


def make_edge(
    from_id: str, to_id: str, type: str, *, id: str = "", source: str = "test"
) -> Edge:
    t = now()
    return Edge(
        id=id or new_id(),
        from_id=from_id,
        to_id=to_id,
        type=type,
        props={},
        confidence=0.9,
        source=source,
        first_seen=t,
        last_seen=t,
    )


def make_episode(**kwargs: object) -> Episode:
    return Episode(
        agent=str(kwargs.get("agent", "agent-1")),
        action=str(kwargs.get("action", "scan")),
        outcome=Outcome(kwargs.get("outcome", "success")),
        data=dict(kwargs.get("data", {})),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Per-field LWW upsert invariant
# ---------------------------------------------------------------------------

class TestUpsertNodeLWW:
    async def test_first_write_stores_node(self) -> None:
        api = make_api()
        n = make_node("n1", ip="1.2.3.4", os="linux")
        await api.upsert_node(n)
        result = await api._graph.get_node("n1")
        assert result is not None
        assert result.props["ip"] == "1.2.3.4"
        assert result.props["os"] == "linux"

    async def test_second_write_wins_for_updated_field(self) -> None:
        """LWW applies when confidence is below the conflict floor.

        When both writes have low confidence (< floor), the newer timestamp
        wins for that field; fields not in the new write are preserved.
        """
        api = make_api(conflict_confidence_floor=0.8)
        import time

        # Low confidence (0.5 < 0.8) → no conflict, pure LWW
        n1 = Node("n1", "host", {"ip": "1.1.1.1", "os": "linux"},
                  0.5, "agent-A", now(), now())
        await api.upsert_node(n1)

        time.sleep(0.01)
        t2 = now()
        n2 = Node("n1", "host", {"ip": "2.2.2.2"}, 0.5, "agent-B", t2, t2)
        await api.upsert_node(n2)

        result = await api._graph.get_node("n1")
        assert result is not None
        # agent-B's ip wins (newer timestamp, low-confidence → no conflict)
        assert result.props["ip"] == "2.2.2.2"
        # os field from agent-A is preserved — no whole-node clobber
        assert result.props["os"] == "linux"

    async def test_provenance_recorded_per_field(self) -> None:
        api = make_api()
        import time

        n1 = make_node("n1", source="agent-A", ip="1.1.1.1")
        await api.upsert_node(n1)

        time.sleep(0.01)
        t2 = now()
        n2 = Node("n1", "host", {"os": "windows"}, 0.9, "agent-B", t2, t2)
        await api.upsert_node(n2)

        result = await api._graph.get_node("n1")
        assert result is not None
        # ip was written by agent-A
        assert result._provenance["ip"]["source"] == "agent-A"
        # os was written by agent-B
        assert result._provenance["os"]["source"] == "agent-B"

    async def test_older_write_does_not_clobber(self) -> None:
        """A write with an OLDER last_seen should not win per-field."""
        import time

        api = make_api()
        t_old = now()
        time.sleep(0.01)
        t_new = now()

        # Write the newer node first
        n_new = Node("n1", "host", {"ip": "2.2.2.2"}, 0.9, "agent-B", t_new, t_new)
        await api.upsert_node(n_new)

        # Try to write the older node second (should not overwrite ip)
        n_old = Node("n1", "host", {"ip": "1.1.1.1"}, 0.9, "agent-A", t_old, t_old)
        await api.upsert_node(n_old)

        result = await api._graph.get_node("n1")
        assert result is not None
        assert result.props["ip"] == "2.2.2.2"

    async def test_first_seen_is_immutable(self) -> None:
        import time

        api = make_api()
        t1 = now()
        n1 = Node("n1", "host", {}, 0.9, "a", t1, t1)
        await api.upsert_node(n1)

        time.sleep(0.01)
        t2 = now()
        n2 = Node("n1", "host", {}, 0.9, "b", t2, t2)
        await api.upsert_node(n2)

        result = await api._graph.get_node("n1")
        assert result is not None
        assert result.first_seen == t1   # must not be changed


# ---------------------------------------------------------------------------
# Conflict invariant
# ---------------------------------------------------------------------------

class TestConflictDetection:
    async def test_high_confidence_contradiction_creates_conflict(self) -> None:
        api = make_api(conflict_confidence_floor=0.8)
        import time

        # Agent A writes ip with confidence 0.9
        t1 = now()
        n1 = Node("n1", "host", {"ip": "1.1.1.1"}, 0.9, "agent-A", t1, t1)
        await api.upsert_node(n1)

        time.sleep(0.01)
        # Agent B writes a DIFFERENT ip with confidence 0.9 → conflict
        t2 = now()
        n2 = Node("n1", "host", {"ip": "9.9.9.9"}, 0.9, "agent-B", t2, t2)
        await api.upsert_node(n2)

        conflicts = await api.get_conflicts("n1")
        assert len(conflicts) == 1
        c = conflicts[0]
        assert c.node_id == "n1"
        assert c.field_name == "ip"
        assert not c.resolved

    async def test_conflict_does_not_silently_overwrite(self) -> None:
        """When a conflict is detected, existing value is preserved."""
        api = make_api(conflict_confidence_floor=0.8)
        import time

        t1 = now()
        n1 = Node("n1", "host", {"ip": "1.1.1.1"}, 0.9, "A", t1, t1)
        await api.upsert_node(n1)

        time.sleep(0.01)
        t2 = now()
        n2 = Node("n1", "host", {"ip": "9.9.9.9"}, 0.9, "B", t2, t2)
        await api.upsert_node(n2)

        result = await api._graph.get_node("n1")
        assert result is not None
        # Original value preserved
        assert result.props["ip"] == "1.1.1.1"

    async def test_low_confidence_write_no_conflict(self) -> None:
        """Below-floor confidence should overwrite without creating a Conflict."""
        api = make_api(conflict_confidence_floor=0.8)
        import time

        t1 = now()
        n1 = Node("n1", "host", {"ip": "1.1.1.1"}, 0.5, "A", t1, t1)
        await api.upsert_node(n1)

        time.sleep(0.01)
        t2 = now()
        n2 = Node("n1", "host", {"ip": "9.9.9.9"}, 0.5, "B", t2, t2)
        await api.upsert_node(n2)

        conflicts = await api.get_conflicts("n1")
        assert len(conflicts) == 0

        result = await api._graph.get_node("n1")
        assert result is not None
        assert result.props["ip"] == "9.9.9.9"   # LWW wins

    async def test_resolve_conflict(self) -> None:
        api = make_api()
        import time

        t1 = now()
        n1 = Node("n1", "host", {"ip": "1.1.1.1"}, 0.9, "A", t1, t1)
        await api.upsert_node(n1)

        time.sleep(0.01)
        t2 = now()
        n2 = Node("n1", "host", {"ip": "9.9.9.9"}, 0.9, "B", t2, t2)
        await api.upsert_node(n2)

        conflicts = await api.get_conflicts("n1")
        assert len(conflicts) == 1
        ok = await api.resolve_conflict(conflicts[0].id, resolution="agent-B wins")
        assert ok
        conflicts_after = await api.get_conflicts("n1")
        assert conflicts_after[0].resolved
        assert conflicts_after[0].resolution == "agent-B wins"


# ---------------------------------------------------------------------------
# Episodic immutability
# ---------------------------------------------------------------------------

class TestEpisodicImmutability:
    async def test_append_creates_episode(self) -> None:
        api = make_api()
        ep = make_episode(action="port_scan")
        eid = await api.append_episode(ep)
        assert eid != ""

    async def test_same_episode_rejected_on_second_append(self) -> None:
        api = make_api()
        ep = make_episode()
        await api.append_episode(ep)
        with pytest.raises(ValueError, match="immutable"):
            await api.append_episode(ep)

    async def test_episodes_are_retrievable_by_episodic_store(self) -> None:
        api = make_api()
        ep = make_episode(action="scan_host")
        eid = await api.append_episode(ep)
        fetched = await api._episodic.get(eid)
        assert fetched is not None
        assert fetched.action == "scan_host"


# ---------------------------------------------------------------------------
# Staging isolation invariant (security-relevant)
# ---------------------------------------------------------------------------

class TestStagingIsolation:
    async def test_proposed_knowledge_not_in_normal_query(self) -> None:
        """propose_knowledge must NOT appear in query results until promoted."""
        api = make_api()
        entry = KnowledgeEntry(
            text="secret knowledge about target alpha",
            source="agent",
            confidence=0.9,
        )
        await api.propose_knowledge(entry)

        # Normal query (no STAGED tier) must not include this entry
        bundle = await api.query(
            text="secret knowledge target alpha",
            tiers=list(ALL_TIERS),
        )
        staged_ids = {e.id for e in bundle.entries if e.tier == Tier.staged.value}
        assert entry.id not in staged_ids

    async def test_proposed_skill_not_in_normal_query(self) -> None:
        api = make_api()
        skill = Skill(
            name="exploit_template",
            description="staged exploit procedure secret",
            template={},
            preconditions={},
            source_episodes=[],
            confidence=0.5,
        )
        await api.propose_skill(skill)

        bundle = await api.query(
            text="exploit procedure secret",
            tiers=list(ALL_TIERS),
        )
        staged_ids = {e.id for e in bundle.entries if e.tier == Tier.staged.value}
        assert skill.id not in staged_ids

    async def test_staged_tier_reveals_proposals(self) -> None:
        """Explicitly requesting Tier.staged must reveal staged entries."""
        api = make_api()
        entry = KnowledgeEntry(
            text="staged knowledge entry visible",
            source="agent",
            confidence=0.7,
        )
        await api.propose_knowledge(entry)

        bundle = await api.query(
            text="staged knowledge",
            tiers=[Tier.staged],
        )
        staged_ids = {e.id for e in bundle.entries}
        assert entry.id in staged_ids

    async def test_promote_knowledge_makes_it_retrievable(self) -> None:
        """After promote_knowledge, entry appears in lexical index (semantic tier)."""
        api = make_api()
        entry = KnowledgeEntry(
            text="promoted knowledge about important system",
            source="agent",
            confidence=0.9,
        )
        await api.propose_knowledge(entry)
        await api.promote_knowledge(entry.id)

        # Directly check lexical index
        results = await api._lexical.search("promoted knowledge important", k=5)
        ids = [r[0] for r in results]
        assert entry.id in ids


# ---------------------------------------------------------------------------
# Open-task view (derived, not stored)
# ---------------------------------------------------------------------------

class TestOpenTaskView:
    async def test_empty_graph_has_no_open_tasks(self) -> None:
        api = make_api(actionable_node_types=["weakness"])
        tasks = await api.open_tasks()
        assert tasks == []

    async def test_actionable_node_is_open_task(self) -> None:
        api = make_api(
            actionable_node_types=["weakness"],
            terminal_edge_types=["resolved"],
        )
        n = make_node("w1", type="weakness", description="SQL injection")
        await api.upsert_node(n)

        tasks = await api.open_tasks()
        assert any(t.node_id == "w1" for t in tasks)

    async def test_terminal_edge_closes_task(self) -> None:
        """Adding a 'resolved' edge to a weakness removes it from open tasks."""
        api = make_api(
            actionable_node_types=["weakness"],
            terminal_edge_types=["resolved"],
        )
        n = make_node("w1", type="weakness")
        await api.upsert_node(n)

        fix = make_node("fix1", type="fix")
        await api.upsert_node(fix)

        assert len(await api.open_tasks()) == 1

        # Add terminal edge
        edge = make_edge("w1", "fix1", "resolved")
        await api.upsert_edge(edge)

        tasks_after = await api.open_tasks()
        assert not any(t.node_id == "w1" for t in tasks_after)

    async def test_open_task_view_changes_with_graph(self) -> None:
        """No separate write needed — graph mutation immediately reflects."""
        api = make_api(
            actionable_node_types=["task"],
            terminal_edge_types=["completed"],
        )
        n = make_node("t1", type="task")
        await api.upsert_node(n)

        before = await api.open_tasks()
        assert len(before) == 1

        # Resolve by adding terminal edge
        await api.upsert_node(make_node("done", type="result"))
        await api.upsert_edge(make_edge("t1", "done", "completed"))

        after = await api.open_tasks()
        assert len(after) == 0

    async def test_non_actionable_type_excluded(self) -> None:
        """Nodes of non-actionable types are not returned as open tasks."""
        api = make_api(actionable_node_types=["weakness"])
        n = make_node("h1", type="host")   # 'host' is not actionable
        await api.upsert_node(n)
        tasks = await api.open_tasks()
        assert len(tasks) == 0


# ---------------------------------------------------------------------------
# Upsert edge
# ---------------------------------------------------------------------------

class TestUpsertEdge:
    async def test_upsert_edge_basic(self) -> None:
        api = make_api()
        await api.upsert_node(make_node("a"))
        await api.upsert_node(make_node("b"))
        e = make_edge("a", "b", "owns")
        eid = await api.upsert_edge(e)
        result = await api._graph.get_edge(eid)
        assert result is not None
        assert result.type == "owns"

    async def test_older_edge_write_does_not_win(self) -> None:
        import time

        api = make_api()
        await api.upsert_node(make_node("a"))
        await api.upsert_node(make_node("b"))

        edge_id = new_id()
        t_new = now()
        time.sleep(0.01)

        # Write newer edge first
        t_newer = now()
        e_new = Edge(edge_id, "a", "b", "v1", {}, 0.9, "s", t_newer, t_newer)
        await api.upsert_edge(e_new)

        # Try to overwrite with older timestamp
        e_old = Edge(edge_id, "a", "b", "v2", {}, 0.9, "s", t_new, t_new)
        await api.upsert_edge(e_old)

        result = await api._graph.get_edge(edge_id)
        assert result is not None
        assert result.type == "v1"   # newer write preserved
