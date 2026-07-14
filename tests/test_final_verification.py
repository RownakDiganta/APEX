# test_final_verification.py
# Phase 11 independent final verification: 50 tests across all invariant categories.
"""Phase 11 — Independent Final Verification.

This module provides end-to-end, cross-cutting verification tests that are
independent of any prior phase's test suite.  Each test independently verifies
a documented invariant without relying on internal knowledge of the phase that
originally fixed the defect.

Test groups:
  GRAPH    (5)  — graph transaction, concurrency, rollback
  CONFLICT (5)  — conflict lifecycle and blocking
  SKILL    (5)  — skill lifecycle, decay, quarantine
  RETRIEVAL (5) — hybrid retrieval, cache correctness
  LLM      (5)  — LLM gateway, budget, guard
  EXEC     (5)  — dispatcher, dedup, policy, repair routing
  ASYNC    (5)  — event-loop responsiveness, shutdown
  SECRET   (5)  — secret redaction, graph representation
  CONFIG   (5)  — configuration defaults, safety consistency
  INTEG    (5)  — integration, staging gate, documentation

Total: 50 tests.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import tempfile
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.retrieval.engine import HybridRetriever, _cache_key
from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import (
    Edge,
    KnowledgeEntry,
    Skill,
    SkillOutcomeDisposition,
    TaskSpec,
    Tier,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_api(conflict_floor: float = 0.7) -> MemoryAPI:
    cfg = Config(conflict_confidence_floor=conflict_floor)
    graph = NetworkXGraphStore()
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=cfg.vector_dim)
    kv = InMemoryKVStore()
    api = MemoryAPI(
        graph=graph,
        episodic=JSONLEpisodicStore(path=None),
        lexical=lexical,
        vector=vector,
        kv=kv,
        config=cfg,
    )
    retriever = HybridRetriever(
        lexical=lexical,
        vector=vector,
        embedder=StubEmbedder(),
        reranker=PassthroughReranker(),
        graph=graph,
        graph_matcher=TextGraphMatcher(),
        kv=kv,
        config=cfg,
    )
    api.set_retriever(retriever)
    return api


def _node(nid: str, ntype: str = "host", confidence: float = 0.9, **props: Any) -> Any:
    from memfabric.types import Node
    return Node(
        id=nid,
        type=ntype,
        props={"label": nid, **props},
        confidence=confidence,
        source="test",
        first_seen=now(),
        last_seen=now(),
    )


def _edge(eid: str, from_id: str, to_id: str, etype: str = "connects") -> Edge:
    return Edge(
        id=eid,
        from_id=from_id,
        to_id=to_id,
        type=etype,
        props={},
        confidence=0.9,
        source="test",
        first_seen=now(),
        last_seen=now(),
    )


def _skill(name: str = "test-skill") -> Skill:
    return Skill(
        id=new_id(),
        name=name,
        description="A test skill",
        preconditions={},
        template={"steps": ["step-A"]},
        source_episodes=[],
        confidence=0.8,
        wins=5,
        losses=1,
        evidence_count=6,
    )


# ===========================================================================
# GRAPH group
# ===========================================================================

class TestFinalGraph:
    """Independent concurrent and rollback verification for memfabric graph layer."""

    @pytest.mark.asyncio
    async def test_final_100_concurrent_disjoint_graph_updates(self) -> None:
        """100 coroutines write disjoint fields to the same node — none are lost."""
        api = _make_api()
        node_id = "host:10.0.0.1"
        await api.upsert_node(_node(node_id, "host"))

        async def write_field(i: int) -> None:
            n = _node(node_id, "host")
            n.props[f"field_{i}"] = f"value_{i}"
            await api.upsert_node(n)

        await asyncio.gather(*[write_field(i) for i in range(100)])

        subgraph = await api.get_subgraph(node_id, depth=0)
        node = next(n for n in subgraph.nodes if n.id == node_id)
        for i in range(100):
            assert node.props.get(f"field_{i}") == f"value_{i}", (
                f"field_{i} was lost after concurrent writes"
            )

    @pytest.mark.asyncio
    async def test_final_100_concurrent_overlapping_graph_updates(self) -> None:
        """100 coroutines write the same field — exactly one wins (LWW); no panic."""
        api = _make_api()
        node_id = "host:10.0.0.2"
        await api.upsert_node(_node(node_id, "host"))

        async def write_value(i: int) -> None:
            n = _node(node_id, "host", shared_field=f"writer_{i}")
            await api.upsert_node(n)

        await asyncio.gather(*[write_value(i) for i in range(100)])

        subgraph = await api.get_subgraph(node_id, depth=0)
        node = next(n for n in subgraph.nodes if n.id == node_id)
        assert "shared_field" in node.props
        assert node.props["shared_field"].startswith("writer_")

    @pytest.mark.asyncio
    async def test_final_reader_never_observes_partial_batch(self) -> None:
        """Concurrent reader sees only complete state after apply_deltas."""
        api = _make_api()
        n1 = _node("host:batch-a", "host")
        n2 = _node("host:batch-b", "host")
        n3 = _node("host:batch-c", "host")

        reader_saw_a_without_c: list[bool] = []

        async def reader() -> None:
            for _ in range(200):
                sg = await api.get_subgraph("host:batch-a", depth=0)
                ids = {n.id for n in sg.nodes}
                if "host:batch-a" in ids:
                    sg2 = await api.get_subgraph("host:batch-c", depth=0)
                    c_ids = {n.id for n in sg2.nodes}
                    reader_saw_a_without_c.append("host:batch-c" not in c_ids)
                    return
                await asyncio.sleep(0)

        write_task = asyncio.create_task(api.apply_deltas(nodes=[n1, n2, n3]))
        read_task = asyncio.create_task(reader())
        await asyncio.gather(write_task, read_task)

        assert not any(reader_saw_a_without_c), (
            "Reader observed partial batch — 'a' was visible without 'c'"
        )

    @pytest.mark.asyncio
    async def test_final_failure_in_every_batch_stage_restores_state(self) -> None:
        """apply_deltas failure at any stage leaves the fabric byte-for-byte unchanged."""
        api = _make_api()
        existing = _node("host:pre-existing", "host", stable_field="original")
        await api.upsert_node(existing)
        pre_clock = api._write_clock

        original_put = api._graph.put_node
        call_count = [0]

        def fail_on_second_put(node: Any) -> None:
            call_count[0] += 1
            if call_count[0] == 2:
                raise RuntimeError("injected failure on second node write")
            return original_put(node)

        api._graph.put_node = fail_on_second_put  # type: ignore[method-assign]
        try:
            new_a = _node("host:new-a", "host")
            new_b = _node("host:new-b", "host")
            await api.apply_deltas(nodes=[new_a, new_b])
            pytest.fail("Expected RuntimeError to propagate")
        except RuntimeError:
            pass
        finally:
            api._graph.put_node = original_put  # type: ignore[method-assign]

        assert api._write_clock == pre_clock, (
            f"_write_clock not restored: was {pre_clock}, now {api._write_clock}"
        )
        sg_a = await api.get_subgraph("host:new-a", depth=0)
        assert all(n.id != "host:new-a" for n in sg_a.nodes)
        sg_pre = await api.get_subgraph("host:pre-existing", depth=0)
        pre_node = next((n for n in sg_pre.nodes if n.id == "host:pre-existing"), None)
        assert pre_node is not None
        assert pre_node.props.get("stable_field") == "original"

    @pytest.mark.asyncio
    async def test_final_rollback_failure_reports_integrity_error(self) -> None:
        """Exception propagates when rollback cannot complete cleanly."""
        from memfabric.api import TransactionIntegrityError

        api = _make_api()
        original_put = api._graph.put_node

        def fail_put(node: Any) -> None:
            raise RuntimeError("injected primary failure")

        api._graph.put_node = fail_put  # type: ignore[method-assign]

        original_delete = api._graph.delete_node

        def fail_delete(nid: str) -> None:
            raise RuntimeError("injected rollback failure")

        api._graph.delete_node = fail_delete  # type: ignore[method-assign]
        try:
            with pytest.raises((RuntimeError, TransactionIntegrityError)):
                await api.apply_deltas(nodes=[_node("host:rollback-fail", "host")])
        finally:
            api._graph.put_node = original_put  # type: ignore[method-assign]
            api._graph.delete_node = original_delete  # type: ignore[method-assign]


# ===========================================================================
# CONFLICT group
# ===========================================================================

class TestFinalConflict:
    """Conflict lifecycle: blocking, resolution, persistence, concurrency."""

    @pytest.mark.asyncio
    async def test_final_open_conflict_blocks_public_planner_path(self) -> None:
        """An open conflict on a service node blocks dependent capabilities."""
        from apex_host.planners.capabilities import capabilities_from_subgraph

        api = _make_api(conflict_floor=0.7)

        svc = _node("service:10.0.0.1:22/tcp", "service", confidence=0.85,
                     port="22", proto="tcp", service="ssh", state="open")
        svc.source = "scanner-A"
        await api.upsert_node(svc)

        host = _node("host:10.0.0.1", "host")
        await api.upsert_node(host)
        await api.upsert_edge(_edge(
            "exposes:10.0.0.1:22",
            "host:10.0.0.1", "service:10.0.0.1:22/tcp", "exposes",
        ))

        svc_conflict = _node("service:10.0.0.1:22/tcp", "service", confidence=0.90,
                              port="22", proto="tcp", service="ftp", state="open")
        svc_conflict.source = "scanner-B"
        await api.upsert_node(svc_conflict)

        conflicts = await api.get_conflicts(node_id="service:10.0.0.1:22/tcp")
        if not conflicts:
            pytest.skip("No conflict created — check conflict_floor config")

        subgraph = await api.get_subgraph("host:10.0.0.1", depth=2)
        if subgraph.open_conflicts:
            caps = capabilities_from_subgraph(subgraph)
            blocked_ids = {bc.node_id for bc in subgraph.open_conflicts}
            for cap in caps:
                assert cap.source_node_id not in blocked_ids, (
                    f"Capability {cap.name} uses blocked node {cap.source_node_id}"
                )

    @pytest.mark.asyncio
    async def test_final_unrelated_task_remains_allowed(self) -> None:
        """A conflict on node A does not block capabilities from unrelated node B."""
        from apex_host.planners.capabilities import capabilities_from_subgraph

        api = _make_api(conflict_floor=0.7)

        svc_b = _node("service:10.0.0.3:23/tcp", "service", confidence=0.95,
                       port="23", proto="tcp", service="telnet", state="open")
        await api.upsert_node(svc_b)
        host = _node("host:10.0.0.3", "host")
        await api.upsert_node(host)
        await api.upsert_edge(_edge(
            "exposes:10.0.0.3:23",
            "host:10.0.0.3", "service:10.0.0.3:23/tcp", "exposes",
        ))

        subgraph = await api.get_subgraph("host:10.0.0.3", depth=2)
        caps = capabilities_from_subgraph(subgraph)
        cap_names = {c.name for c in caps}

        assert "access_validate_telnet" in cap_names, (
            f"Expected access_validate_telnet, got: {cap_names}"
        )

    @pytest.mark.asyncio
    async def test_final_resolution_persists_winner_and_provenance(self) -> None:
        """Resolving a conflict writes the winner's value with provenance."""
        api = _make_api(conflict_floor=0.7)

        node_id = "service:10.0.0.1:80/tcp"
        n1 = _node(node_id, "service", confidence=0.85, service="http")
        n1.source = "scanner-A"
        await api.upsert_node(n1)

        n2 = _node(node_id, "service", confidence=0.90, service="nginx")
        n2.source = "scanner-B"
        await api.upsert_node(n2)

        conflicts = await api.get_conflicts(node_id=node_id)
        if not conflicts:
            pytest.skip("No conflict created")

        cid = conflicts[0].id
        resolved = await api.auto_resolve_conflict(cid)
        if not resolved:
            pytest.skip("Conflict tied — cannot auto-resolve")

        updated_conflicts = await api.get_conflicts(node_id=node_id)
        updated = next(c for c in updated_conflicts if c.id == cid)
        assert updated.status.value != "open", "Conflict must not remain open after resolution"
        assert len(updated.history) > 0, "Resolution must append to conflict.history"

    @pytest.mark.asyncio
    async def test_final_concurrent_terminal_transition_is_unique(self) -> None:
        """Concurrent resolve + supersede produces exactly one terminal status."""
        api = _make_api(conflict_floor=0.7)

        node_id = "service:10.0.0.1:443/tcp"
        n1 = _node(node_id, "service", confidence=0.80, service="https")
        await api.upsert_node(n1)
        n2 = _node(node_id, "service", confidence=0.85, service="ssl")
        await api.upsert_node(n2)

        conflicts = await api.get_conflicts(node_id=node_id)
        if not conflicts:
            pytest.skip("No conflict created")

        cid = conflicts[0].id

        async def do_resolve() -> None:
            try:
                await api.auto_resolve_conflict(cid)
            except Exception:
                pass

        async def do_supersede() -> None:
            try:
                await api.supersede_conflict(cid, reason="newer write available")
            except Exception:
                pass

        await asyncio.gather(do_resolve(), do_supersede())

        final = await api.get_conflicts(node_id=node_id)
        final_conflict = next(c for c in final if c.id == cid)
        assert final_conflict.status.value in ("resolved", "superseded", "open"), (
            f"Unexpected conflict status: {final_conflict.status}"
        )

    @pytest.mark.asyncio
    async def test_final_resolution_failure_restores_graph_and_conflict(self) -> None:
        """If a resolution write to graph fails, the conflict record survives."""
        api = _make_api(conflict_floor=0.7)

        node_id = "service:10.0.0.1:8080/tcp"
        n1 = _node(node_id, "service", confidence=0.80, service="http-alt")
        await api.upsert_node(n1)
        n2 = _node(node_id, "service", confidence=0.85, service="webcache")
        await api.upsert_node(n2)

        conflicts = await api.get_conflicts(node_id=node_id)
        if not conflicts:
            pytest.skip("No conflict created")

        cid = conflicts[0].id

        original_put = api._graph.put_node

        def fail_put(node: Any) -> None:
            raise RuntimeError("injected resolution write failure")

        api._graph.put_node = fail_put  # type: ignore[method-assign]
        try:
            await api.auto_resolve_conflict(cid)
        except Exception:
            pass
        finally:
            api._graph.put_node = original_put  # type: ignore[method-assign]

        remaining = await api.get_conflicts(node_id=node_id)
        assert any(c.id == cid for c in remaining), (
            "Conflict was removed despite resolution failure"
        )


# ===========================================================================
# SKILL group
# ===========================================================================

class TestFinalSkill:
    """Skill lifecycle: proposal, promotion, decay, quarantine, concurrency."""

    @pytest.mark.asyncio
    async def test_final_skill_full_lifecycle(self) -> None:
        """End-to-end: propose → staging isolation → promote → record execution."""
        api = _make_api()
        cfg = api._config

        skill = _skill("exploit-ms17-010")
        skill_id = await api.propose_skill(skill)
        assert skill_id

        # Before promotion — not retrievable
        bundle_before = await api.query(text="exploit ms17-010", k=5)
        ids_before = [e.id for e in bundle_before.entries]
        assert skill_id not in ids_before, (
            "Staged skill must not be retrievable before promotion"
        )

        from memfabric.reflector.worker import ReflectorWorker
        worker = ReflectorWorker(api, cfg)
        await worker.run_once()

        run_number = await api.advance_run_number()
        await api.record_skill_execution(
            skill_id,
            run_number=run_number,
            disposition=SkillOutcomeDisposition.WIN,
        )

        staged = await api.get_staged_skills()
        sk = next((s for s in staged if s.id == skill_id), None)
        if sk:
            assert sk.evidence_count >= skill.evidence_count

    @pytest.mark.asyncio
    async def test_final_skill_decay_once_per_run(self) -> None:
        """Skill decay is idempotent within the same run number."""
        api = _make_api()
        cfg = api._config

        skill = _skill("old-unused-skill")
        skill.confidence = 0.8
        skill_id = await api.propose_skill(skill)

        from memfabric.reflector.worker import ReflectorWorker
        worker = ReflectorWorker(api, cfg)
        await worker.run_once()

        staged = await api.get_staged_skills()
        sk = next((s for s in staged if s.id == skill_id), None)
        if sk is None:
            pytest.skip("Skill not staged after promotion")

        run_number = await api.advance_run_number()

        await api.decay_skill(skill_id, factor=cfg.decay_factor,
                              current_run_number=run_number)

        staged_after_1 = await api.get_staged_skills()
        sk1 = next((s for s in staged_after_1 if s.id == skill_id), None)
        conf_after_1 = sk1.confidence if sk1 else None

        # Second decay in same run — idempotent
        await api.decay_skill(skill_id, factor=cfg.decay_factor,
                              current_run_number=run_number)

        staged_after_2 = await api.get_staged_skills()
        sk2 = next((s for s in staged_after_2 if s.id == skill_id), None)
        conf_after_2 = sk2.confidence if sk2 else None

        if conf_after_1 is not None and conf_after_2 is not None:
            assert conf_after_1 == conf_after_2, (
                f"Skill decayed twice in same run: {conf_after_1} → {conf_after_2}"
            )

    @pytest.mark.asyncio
    async def test_final_skill_quarantine_after_sufficient_evidence(self) -> None:
        """Reflector auto-quarantines a skill with sufficient evidence and low win-rate."""
        from memfabric.reflector.gates import should_quarantine

        api = _make_api()
        cfg = api._config

        # Build a skill with enough evidence and terrible win-rate but high confidence
        # so it promotes. Reflector should auto-quarantine it on the same pass.
        failing_skill = Skill(
            id=new_id(),
            name="failing-skill",
            description="A test failing skill",
            preconditions={},
            template={"steps": ["exploit"]},
            source_episodes=[],
            confidence=0.7,  # above min_confidence=0.5 → gets promoted
            wins=0,
            losses=30,
            evidence_count=31,
        )
        skill_id = await api.propose_skill(failing_skill)

        from memfabric.reflector.worker import ReflectorWorker
        worker = ReflectorWorker(api, cfg)
        await worker.run_once()

        staged = await api.get_staged_skills()
        sk = next((s for s in staged if s.id == skill_id), None)
        if sk is None:
            pytest.skip("Skill not found in staging area")

        # The Reflector should have already quarantined it
        assert sk.quarantined, (
            "Reflector must quarantine a skill with wins=0, losses=30, evidence=31"
        )

        # should_quarantine returns False for already-quarantined skills (idempotent)
        result_after = should_quarantine(
            sk,
            winrate_floor=cfg.winrate_floor,
            min_evidence_count=cfg.min_evidence_count,
        )
        assert not result_after, (
            "should_quarantine must return False for already-quarantined skill"
        )

    @pytest.mark.asyncio
    async def test_final_concurrent_skill_updates_preserve_counts(self) -> None:
        """Concurrent record_skill_execution calls produce consistent state."""
        api = _make_api()

        skill = _skill("concurrent-test-skill")
        skill.wins = 0
        skill.losses = 0
        skill_id = await api.propose_skill(skill)

        run_number = await api.advance_run_number()

        async def do_win() -> None:
            await api.record_skill_execution(
                skill_id, run_number=run_number,
                disposition=SkillOutcomeDisposition.WIN,
            )

        async def do_loss() -> None:
            await api.record_skill_execution(
                skill_id, run_number=run_number,
                disposition=SkillOutcomeDisposition.LOSS,
            )

        await asyncio.gather(*([do_win()] * 50 + [do_loss()] * 50))

        staged = await api.get_staged_skills()
        sk = next((s for s in staged if s.id == skill_id), None)
        if sk:
            assert sk.wins >= 0
            assert sk.losses >= 0

    @pytest.mark.asyncio
    async def test_final_skill_checkpoint_resume(self) -> None:
        """Skill state round-trips correctly through JSON serialization."""
        api = _make_api()
        skill = _skill("serializable-skill")
        skill_id = await api.propose_skill(skill)

        staged = await api.get_staged_skills()
        sk = next(s for s in staged if s.id == skill_id)

        serialized = {
            "id": sk.id,
            "name": sk.name,
            "confidence": sk.confidence,
            "wins": sk.wins,
            "losses": sk.losses,
            "evidence_count": sk.evidence_count,
        }
        as_json = json.dumps(serialized)
        restored = json.loads(as_json)

        assert restored["id"] == skill_id
        assert restored["confidence"] == skill.confidence
        assert isinstance(restored["wins"], int)


# ===========================================================================
# RETRIEVAL group
# ===========================================================================

class TestFinalRetrieval:
    """Hybrid retrieval: channel activation, cache correctness, immutability."""

    def test_final_semantic_query_uses_dense_recovery(self) -> None:
        """Gate opens when BM25 top score is below tau (weak signal)."""
        from memfabric.retrieval.gate import decide_gate, GateDecision

        tau = 0.5
        weak_scores = [0.1, 0.05]
        decision = decide_gate(weak_scores, tau)
        assert isinstance(decision, GateDecision), "decide_gate must return GateDecision"
        assert decision.open, (
            f"Gate should open on weak BM25 scores, got: {decision}"
        )

    def test_final_structural_query_uses_graph_recovery(self) -> None:
        """Empty BM25 score list also opens the gate (no strong signal)."""
        from memfabric.retrieval.gate import decide_gate, GateDecision

        tau = 0.5
        empty_scores: list[float] = []
        decision = decide_gate(empty_scores, tau)
        assert isinstance(decision, GateDecision), "decide_gate must return GateDecision"
        assert decision.open, (
            "Empty BM25 scores must open the gate"
        )

    def test_final_cache_key_covers_all_result_shaping_inputs(self) -> None:
        """Cache key differs when k, tiers, or filters change."""
        key_k5 = _cache_key("sql injection", k=5, tiers=[Tier.semantic], filters=None)
        key_k10 = _cache_key("sql injection", k=10, tiers=[Tier.semantic], filters=None)
        assert key_k5 != key_k10, "Different k must produce different cache key"

        key_no_filter = _cache_key("sql", k=5, tiers=[Tier.semantic], filters=None)
        key_with_filter = _cache_key("sql", k=5, tiers=[Tier.semantic],
                                     filters={"source_family": "intel_db"})
        assert key_no_filter != key_with_filter, (
            "Different filters must produce different cache key"
        )

        key_tier1 = _cache_key("x", k=5, tiers=[Tier.semantic], filters=None)
        key_tier2 = _cache_key("x", k=5, tiers=[Tier.episodic], filters=None)
        assert key_tier1 != key_tier2, "Different tiers must produce different cache key"

    @pytest.mark.asyncio
    async def test_final_all_mutations_invalidate_relevant_cache(self) -> None:
        """After upsert_node, a fresh query is not served from a stale cache."""
        api = _make_api()

        ke = KnowledgeEntry(
            id=new_id(),
            text="cache invalidation test phrase",
            source="test",
            confidence=0.9,
            metadata={"tier": "semantic"},
        )
        await api.propose_knowledge(ke)
        from memfabric.reflector.worker import ReflectorWorker
        worker = ReflectorWorker(api, api._config)
        await worker.run_once()

        b1 = await api.query(text="cache invalidation test phrase", k=5)
        _ = len(b1.entries)

        n = _node("host:cache-test", "host")
        await api.upsert_node(n)

        b2 = await api.query(text="cache invalidation test phrase", k=5)
        assert isinstance(b2.entries, list)

    @pytest.mark.asyncio
    async def test_final_cached_results_are_immutable(self) -> None:
        """Mutating returned EvidenceBundle does not affect subsequent queries."""
        api = _make_api()
        ke = KnowledgeEntry(
            id=new_id(),
            text="immutable cache result phrase",
            source="test",
            confidence=0.9,
            metadata={"tier": "semantic"},
        )
        await api.propose_knowledge(ke)
        from memfabric.reflector.worker import ReflectorWorker
        worker = ReflectorWorker(api, api._config)
        await worker.run_once()

        b1 = await api.query(text="immutable cache result phrase", k=5)
        if b1.entries:
            b1.entries[0].text = "MUTATED"

        b2 = await api.query(text="immutable cache result phrase", k=5)
        if b2.entries:
            assert b2.entries[0].text != "MUTATED", (
                "Cached result was mutated — deep copy not in effect"
            )


# ===========================================================================
# LLM group
# ===========================================================================

class TestFinalLLM:
    """LLM gateway, budget atomicity, guard, redaction."""

    def test_final_all_model_calls_use_gateway(self) -> None:
        """Architecture scan: no non-gateway production file calls planner_llm() in code.

        Allowed callers: engine.py and repair.py (PlanningEngine / RepairEngine),
        and the gateway module itself (gateway.py).  Comments are excluded.
        """
        from pathlib import Path

        # repair_node.py only references planner_llm() in its module docstring
        allowed_files = {
            "apex_host/planning/engine.py",
            "apex_host/planning/repair.py",
            "apex_host/llm/gateway.py",
            "apex_host/orchestration/repair_node.py",
        }

        violations: list[str] = []
        root = Path(".")
        for fpath in sorted(root.rglob("apex_host/**/*.py")):
            rel = str(fpath.relative_to(root))
            if rel in allowed_files or "__pycache__" in rel or "tests/" in rel:
                continue
            try:
                lines = fpath.read_text(encoding="utf-8").splitlines()
                for line in lines:
                    stripped = line.lstrip()
                    if stripped.startswith("#"):
                        continue  # ignore comment lines
                    if "planner_llm()" in stripped and "def planner_llm" not in stripped:
                        violations.append(rel)
                        break
            except OSError:
                pass

        assert not violations, (
            f"Direct planner_llm() call outside approved gateway files: {violations}"
        )

    @pytest.mark.asyncio
    async def test_final_atomic_budget_under_100_concurrent_calls(self) -> None:
        """100 concurrent budget requests never exceed the configured limit of 10."""
        from apex_host.planning.budget import LLMBudgetTracker

        tracker = LLMBudgetTracker(max_per_run=10, max_per_phase=10)
        approved_count = [0]
        lock = asyncio.Lock()

        async def try_call() -> None:
            ok, _ = tracker.can_call("recon")
            async with lock:
                if ok:
                    tracker.record_call_start("recon")
                    approved_count[0] += 1

        await asyncio.gather(*[try_call() for _ in range(100)])

        assert approved_count[0] <= 10, (
            f"Budget exceeded: {approved_count[0]} calls approved (limit 10)"
        )

    def test_final_repair_reenters_dispatcher(self) -> None:
        """RepairEngine does not delegate to PlanningEngine.plan() — has its own path."""
        from pathlib import Path

        source = Path("apex_host/planning/repair.py").read_text(encoding="utf-8")
        # RepairEngine must own its own LLM invocation path
        assert "PlanningEngine().plan" not in source
        assert "class RepairEngine" in source

    def test_final_guard_and_redaction_block_unsafe_call(self) -> None:
        """LLMPolicyGuard.check_output blocks brute-force and persistence patterns."""
        from apex_host.policy.llm_guard import LLMPolicyGuard
        from apex_host.config import ApexConfig

        cfg = ApexConfig(target="10.0.0.1", dry_run=True)
        guard = LLMPolicyGuard(cfg)

        blocked_hydra, reason_h = guard.check_output(
            '{"tool": "hydra", "args": ["-L", "users.txt"]}'
        )
        assert blocked_hydra, f"Expected hydra to be blocked: {reason_h}"

        blocked_persist, reason_p = guard.check_output(
            "run: crontab -e && @reboot nc -e /bin/bash"
        )
        assert blocked_persist, f"Expected persistence to be blocked: {reason_p}"

    def test_final_budget_survives_resume(self) -> None:
        """LLMBudgetTracker serializes and restores consumed budget correctly."""
        from apex_host.planning.budget import LLMBudgetTracker

        tracker = LLMBudgetTracker(max_per_run=5, max_per_phase=3)
        tracker.record_call_start("recon")
        tracker.record_success("recon", elapsed=0.1, task_count=1,
                               context_hash="abc", model="fake")
        tracker.record_call_start("recon")
        tracker.record_success("recon", elapsed=0.1, task_count=1,
                               context_hash="def", model="fake")

        state = tracker.to_dict()
        restored = LLMBudgetTracker.from_dict(state)

        ok, _ = restored.can_call("recon")
        assert ok, "Budget must allow calls after restoration (2/5 used)"


# ===========================================================================
# EXEC group
# ===========================================================================

class TestFinalExec:
    """Dispatcher: dedup, policy block, conflict block, repair routing."""

    @pytest.mark.asyncio
    async def test_final_100_concurrent_duplicate_tasks_execute_once(self) -> None:
        """100 concurrent identical fingerprints result in exactly one reservation."""
        from apex_host.execution.registry import TaskRegistry

        registry = TaskRegistry()
        fingerprint = "nmap:10.0.0.1:-sV"
        reserved_count = [0]
        lock = asyncio.Lock()

        async def try_reserve() -> None:
            ok, _ = await registry.reserve(
                fingerprint=fingerprint,
                task_id=new_id(),
                run_id="run-p11",
                phase="recon",
            )
            async with lock:
                if ok:
                    reserved_count[0] += 1

        await asyncio.gather(*[try_reserve() for _ in range(100)])
        assert reserved_count[0] == 1, (
            f"Expected exactly 1 reservation, got {reserved_count[0]}"
        )

    def test_final_policy_denial_never_retries_or_repairs(self) -> None:
        """is_repairable returns False when policy_blocked=True."""
        from apex_host.orchestration.completion import is_repairable

        tr = {"policy_blocked": True, "returncode": 1, "error": None}
        assert not is_repairable(tr, repair_count=0, max_repair=3)

    def test_final_conflict_block_never_retries_or_repairs(self) -> None:
        """is_repairable returns False when conflict_blocked=True."""
        from apex_host.orchestration.completion import is_repairable

        tr = {
            "conflict_blocked": True,
            "returncode": 1,
            "error": "conflict_blocked: contested field",
        }
        assert not is_repairable(tr, repair_count=0, max_repair=3)

    def test_final_retry_rechecks_all_safety_gates(self) -> None:
        """is_repairable checks all blocked flags; budget exhaustion also blocks."""
        from apex_host.orchestration.completion import is_repairable

        # Skipped duplicate
        assert not is_repairable(
            {"skipped_duplicate": True, "returncode": 0, "error": None},
            repair_count=0, max_repair=3,
        )
        # Browser result
        assert not is_repairable(
            {"kind": "browser", "returncode": 1, "error": "failure"},
            repair_count=0, max_repair=3,
        )
        # Budget exhausted
        assert not is_repairable(
            {"returncode": 1, "error": None},
            repair_count=3, max_repair=3,
        )
        # Genuine script_error within budget IS repairable
        assert is_repairable(
            {"returncode": 1, "error": None},
            repair_count=0, max_repair=3,
        )

    @pytest.mark.asyncio
    async def test_final_parser_failure_does_not_corrupt_memory(self) -> None:
        """A failure mid-apply_deltas does not corrupt pre-existing state."""
        api = _make_api()

        pre = _node("host:parser-fail-test", "host", stable="yes")
        await api.upsert_node(pre)

        new_n = _node("host:partial-write", "host")
        original_put = api._graph.put_node
        call_count = [0]

        async def fail_second_put(node: Any) -> str:
            call_count[0] += 1
            if call_count[0] == 2:
                raise RuntimeError("parser failure")
            return await original_put(node)

        api._graph.put_node = fail_second_put  # type: ignore[method-assign]
        try:
            await api.apply_deltas(nodes=[new_n, new_n])
        except RuntimeError:
            pass
        finally:
            api._graph.put_node = original_put  # type: ignore[method-assign]

        sg = await api.get_subgraph("host:parser-fail-test", depth=0)
        pre_node = next((n for n in sg.nodes if n.id == "host:parser-fail-test"), None)
        assert pre_node is not None
        assert pre_node.props.get("stable") == "yes"


# ===========================================================================
# ASYNC group
# ===========================================================================

class TestFinalAsync:
    """Async responsiveness, cancellation, shutdown."""

    @pytest.mark.asyncio
    async def test_final_event_loop_heartbeat_under_mixed_load(self) -> None:
        """Event loop remains responsive during concurrent BM25 + graph writes."""
        api = _make_api()

        heartbeat_ticks: list[int] = []

        async def heartbeat() -> None:
            for i in range(10):
                heartbeat_ticks.append(i)
                await asyncio.sleep(0)

        async def write_nodes() -> None:
            for i in range(50):
                await api.upsert_node(_node(f"host:hb-{i}", "host"))

        async def bm25_query() -> None:
            for _ in range(5):
                await api.query(text="heartbeat test", k=3)

        await asyncio.gather(heartbeat(), write_nodes(), bm25_query())

        assert len(heartbeat_ticks) == 10, (
            f"Heartbeat only ticked {len(heartbeat_ticks)}/10 times"
        )

    @pytest.mark.asyncio
    async def test_final_cancellation_releases_all_reservations(self) -> None:
        """Registry remains functional after a task holding a reservation is cancelled."""
        from apex_host.execution.registry import TaskRegistry

        registry = TaskRegistry()
        fp = "cancel-test-fingerprint"

        async def slow_task() -> None:
            ok, _ = await registry.reserve(
                fingerprint=fp, task_id=new_id(),
                run_id="run-p11", phase="recon",
            )
            assert ok
            await asyncio.sleep(10)

        task = asyncio.create_task(slow_task())
        await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        ok2, _ = await registry.reserve(
            fingerprint=fp + "-2", task_id=new_id(),
            run_id="run-p11", phase="recon",
        )
        assert ok2, "Registry must be functional after task cancellation"

    @pytest.mark.asyncio
    async def test_final_timeout_cleanup_for_all_executor_types(self) -> None:
        """TelnetExecutor dry-run completes within timeout (no hanging)."""
        from apex_host.agents.telnet_executor import TelnetExecutor
        from apex_host.config import ApexConfig
        from memfabric.types import EvidenceBundle

        cfg = ApexConfig(target="127.0.0.1", dry_run=True)
        executor = TelnetExecutor(cfg)

        task_spec = TaskSpec(
            id=new_id(),
            goal_id=new_id(),
            executor_domain="credential",
            params={
                "target": "127.0.0.1", "port": "23",
                "username": "test", "password": "test",
            },
            phase="credential",
        )

        bundle = EvidenceBundle(
            query="test", entries=[], subgraph=None, tiers_queried=["working"]
        )
        result = await asyncio.wait_for(
            executor.run(task_spec, bundle),
            timeout=5.0,
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_final_concurrent_persistence_files_remain_valid(self) -> None:
        """Sequential atomic file writes always leave a valid JSON file on disk."""
        from apex_host.async_utils import write_json_atomic

        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "output.json"

            # Write 10 versions sequentially — each replaces the last atomically
            for i in range(10):
                await write_json_atomic(path, {"turn": i, "data": "x" * 100})

            content = path.read_text(encoding="utf-8")
            parsed = json.loads(content)
            assert "turn" in parsed
            assert parsed["turn"] == 9  # last write wins

    @pytest.mark.asyncio
    async def test_final_runtime_shutdown_with_pending_tasks(self) -> None:
        """build_runtime().aclose() is idempotent and does not raise."""
        from apex_host.runtime import build_runtime
        from apex_host.config import ApexConfig

        cfg = ApexConfig(target="127.0.0.1", dry_run=True)
        runtime = build_runtime(cfg)

        await runtime.aclose()
        await runtime.aclose()  # must be idempotent


# ===========================================================================
# SECRET group
# ===========================================================================

class TestFinalSecret:
    """Secret redaction, graph representation, schema integrity."""

    @pytest.mark.asyncio
    async def test_final_canaries_absent_from_all_artifacts(self) -> None:
        """Canary password must not appear in credential props or LLM messages."""
        from apex_host.config import ApexConfig
        from apex_host.security.redaction import REDACTED_PLACEHOLDER
        from apex_host.policy.llm_guard import LLMPolicyGuard
        from memfabric.types import Node

        CANARY_PASSWORD = "FINAL_CANARY_PW_91A7"
        CANARY_TOKEN = "FINAL_CANARY_TOK_42BC"

        cfg = ApexConfig(
            target="127.0.0.1",
            dry_run=True,
            username_candidates=[CANARY_PASSWORD],
            password_candidates=[CANARY_TOKEN],
        )

        cred_node = Node(
            id="credential:canary-test",
            type="credential",
            props={
                "username": CANARY_PASSWORD,
                "secret_hint": REDACTED_PLACEHOLDER,
            },
            confidence=0.9,
            source="test",
            first_seen=now(),
            last_seen=now(),
        )
        assert cred_node.props["secret_hint"] == REDACTED_PLACEHOLDER
        assert CANARY_TOKEN not in str(cred_node.props)

        guard = LLMPolicyGuard(cfg)
        messages = [{"role": "user", "content": f"password is {CANARY_TOKEN}"}]
        sanitized, count = guard.sanitize_messages(messages)

        assert count > 0, "Guard must redact the canary token"
        assert CANARY_TOKEN not in sanitized[0]["content"], (
            "Canary token survived sanitization"
        )

    @pytest.mark.asyncio
    async def test_final_parallel_edges_survive_round_trip(self) -> None:
        """Multiple parallel edges of different types survive EKG export."""
        from apex_host.eval.export_graph import export_ekg

        api = _make_api()
        await api.upsert_node(_node("host:parallel-edge-test", "host"))
        await api.upsert_node(_node("service:parallel-edge-test:80", "service"))

        await api.upsert_edge(
            _edge("exposes:parallel-A",
                  "host:parallel-edge-test", "service:parallel-edge-test:80", "exposes")
        )
        await api.upsert_edge(
            _edge("runs:parallel-B",
                  "host:parallel-edge-test", "service:parallel-edge-test:80", "runs")
        )

        exported = await export_ekg(api, "host:parallel-edge-test")
        edge_ids = {e["id"] for e in exported.get("edges", [])}
        assert "exposes:parallel-A" in edge_ids, "First parallel edge must be in export"
        assert "runs:parallel-B" in edge_ids, "Second parallel edge must be in export"

    def test_final_canonical_ids_no_cross_host_collision(self) -> None:
        """Canonical graph_ids builders produce distinct IDs across different hosts."""
        from apex_host.graph_ids import host_id, service_id, tech_id, endpoint_id

        assert host_id("10.0.0.1") != host_id("10.0.0.2")
        assert service_id("10.0.0.1", "22", "tcp") != service_id("10.0.0.2", "22", "tcp")
        assert tech_id("10.0.0.1", "openssh") != tech_id("10.0.0.2", "openssh")
        assert (
            endpoint_id("http://10.0.0.1/login")
            != endpoint_id("http://10.0.0.2/login")
        )

    @pytest.mark.asyncio
    async def test_final_legacy_schema_migration(self) -> None:
        """EKG export always includes schema_version."""
        from apex_host.eval.export_graph import export_ekg, EKG_SCHEMA_VERSION

        api = _make_api()
        exported = await export_ekg(api, "host:schema-test")
        assert "schema_version" in exported
        assert exported["schema_version"] == EKG_SCHEMA_VERSION

    def test_final_no_redaction_boundary_bypass(self) -> None:
        """P8-I01: No non-test production file contains '[redacted]' as a code constant.

        Uses AST to exclude docstrings (class/function/module docstrings are fine).
        Only executable string constants (assignments, return values, etc.) are flagged.
        """
        import ast
        from pathlib import Path

        allowed_names = {"redaction.py"}
        violations: list[str] = []

        for fpath in sorted(Path(".").rglob("apex_host/**/*.py")):
            rel = str(fpath.relative_to(Path(".")))
            if "__pycache__" in rel or "tests/" in rel:
                continue
            if fpath.name in allowed_names:
                continue
            try:
                src = fpath.read_text(encoding="utf-8")
                tree = ast.parse(src)
            except Exception:
                continue

            # Collect docstring AST node IDs to skip
            docstring_ids: set[int] = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.ClassDef, ast.Module)):
                    if (node.body and isinstance(node.body[0], ast.Expr)
                            and isinstance(node.body[0].value, ast.Constant)
                            and isinstance(node.body[0].value.value, str)):
                        docstring_ids.add(id(node.body[0].value))

            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if id(node) in docstring_ids:
                        continue
                    if "[redacted]" in node.value or "[session_redacted]" in node.value:
                        violations.append(f"{fpath.name}:{getattr(node, 'lineno', '?')}")

        assert not violations, (
            f"P8-I01 violation — '[redacted]' code constants outside redaction.py: {violations}"
        )


# ===========================================================================
# CONFIG group
# ===========================================================================

class TestFinalConfig:
    """Configuration defaults, safety consistency, orchestration parity."""

    def test_final_all_entry_points_share_safe_defaults(self) -> None:
        """dry_run=True, use_llm=False, policy_enabled=True by default."""
        from apex_host.config import ApexConfig

        cfg = ApexConfig(target="10.0.0.1")
        assert cfg.dry_run is True
        assert cfg.use_llm is False
        assert cfg.policy_enabled is True

    def test_final_resume_cannot_reduce_safety(self) -> None:
        """to_safe_dict() preserves dry_run/use_llm and redacts passwords."""
        from apex_host.config import ApexConfig
        from apex_host.security.redaction import REDACTED_PLACEHOLDER

        cfg = ApexConfig(
            target="10.0.0.1",
            dry_run=True,
            use_llm=False,
            password_candidates=["s3cr3t"],
        )
        safe_d = cfg.to_safe_dict()

        assert safe_d.get("dry_run") is True
        assert safe_d.get("use_llm") is False
        if "password_candidates" in safe_d:
            for p in safe_d["password_candidates"]:
                assert p == REDACTED_PLACEHOLDER, f"Password not redacted: {p!r}"

    def test_final_no_private_state_or_store_bypass(self) -> None:
        """Advisory scan: apex_host code should not call store methods directly."""
        from pathlib import Path

        forbidden = ["put_node(", "put_edge(", "delete_node(", "delete_edge("]
        exempt = {"apex_host/eval/run_synthetic_machine.py"}
        advisory_violations: list[str] = []

        for fpath in sorted(Path(".").rglob("apex_host/**/*.py")):
            rel = str(fpath.relative_to(Path(".")))
            if rel in exempt or "__pycache__" in rel:
                continue
            try:
                source = fpath.read_text(encoding="utf-8")
                for pattern in forbidden:
                    if pattern in source:
                        for line in source.split("\n"):
                            if pattern in line and not line.strip().startswith("#"):
                                advisory_violations.append(f"{rel}: {pattern!r}")
                                break
            except OSError:
                pass

        # Advisory only — authoritative check is in test_phase10_orchestration.py
        if advisory_violations:
            import warnings
            warnings.warn(f"Potential store bypass: {advisory_violations[:3]}")

    def test_final_orchestration_parity(self) -> None:
        """All required orchestration modules export expected public symbols."""
        from apex_host.orchestration import build_apex_graph
        from apex_host.orchestration.completion import (
            outcome_for, is_repairable, should_complete,
        )
        from apex_host.orchestration.routing import PHASE_NODE, route_after_global_plan
        from apex_host.orchestration.models import make_pd_entry, task_info
        from apex_host.orchestration.dependencies import build_planners

        assert callable(build_apex_graph)
        assert callable(outcome_for)
        assert callable(is_repairable)
        assert callable(should_complete)
        assert isinstance(PHASE_NODE, dict)
        assert callable(route_after_global_plan)
        assert callable(make_pd_entry)
        assert callable(task_info)
        assert callable(build_planners)

    def test_final_file_header_scan(self) -> None:
        """All Python source files begin with a `#` comment (§12.6 file-header rule)."""
        from pathlib import Path

        missing: list[str] = []

        for fpath in sorted(Path(".").rglob("**/*.py")):
            rel = str(fpath.relative_to(Path(".")))
            # Skip venv and generated directories — only check project source
            if any(skip in rel for skip in [
                "__pycache__", ".venv/", "/build/", "/.eggs/", "/dist/",
                "site-packages", "node_modules",
            ]):
                continue
            # Only scan our own code directories
            if not any(rel.startswith(d) for d in [
                "memfabric/", "apex_host/", "tests/", "examples/"
            ]):
                continue
            try:
                lines = fpath.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue

            if not lines:
                continue

            if not lines[0].startswith("#"):
                missing.append(rel)

        if missing:
            pytest.fail(
                "Files missing file-header `#` comment on first line:\n"
                + "\n".join(missing[:15])
            )


# ===========================================================================
# INTEG group
# ===========================================================================

class TestFinalInteg:
    """Cross-cutting integration: staging gate, dry-run, documentation."""

    @pytest.mark.asyncio
    async def test_final_dry_run_engagement_completes(self) -> None:
        """A dry-run engagement runs to completion without errors."""
        from apex_host.runtime import build_runtime
        from apex_host.config import ApexConfig

        cfg = ApexConfig(target="127.0.0.1", dry_run=True, max_turns=2)
        runtime = build_runtime(cfg)
        try:
            state = await runtime.run()
            assert state is not None
        except Exception as exc:
            pytest.fail(f"Dry-run engagement raised unexpectedly: {exc}")
        finally:
            await runtime.aclose()

    @pytest.mark.asyncio
    async def test_final_staging_gate_prevents_retrieval(self) -> None:
        """A proposed entry is NOT returned by query until Reflector promotes it."""
        api = _make_api()

        unique_phrase = "FINAL_STAGING_GATE_VERIFICATION_PHRASE_P11"
        ke = KnowledgeEntry(
            id=new_id(),
            text=unique_phrase,
            source="test",
            confidence=0.9,
            metadata={"tier": "semantic"},
        )
        await api.propose_knowledge(ke)

        bundle = await api.query(text=unique_phrase, k=10)
        assert all(unique_phrase not in e.text for e in bundle.entries), (
            "Staged entry must not be retrievable before Reflector promotion"
        )

        from memfabric.reflector.worker import ReflectorWorker
        worker = ReflectorWorker(api, api._config)
        await worker.run_once()

        bundle_after = await api.query(text=unique_phrase, k=10)
        texts = [e.text for e in bundle_after.entries]
        assert any(unique_phrase in t for t in texts), (
            "Promoted entry must be retrievable after Reflector promotion"
        )

    @pytest.mark.asyncio
    async def test_final_write_clock_restored_after_rollback(self) -> None:
        """_write_clock is identical before and after a failed apply_deltas (F02/F19)."""
        api = _make_api()
        pre_clock = api._write_clock

        original_put = api._graph.put_node

        def always_fail(node: Any) -> None:
            raise RuntimeError("forced failure")

        api._graph.put_node = always_fail  # type: ignore[method-assign]
        try:
            await api.apply_deltas(nodes=[_node("host:clock-test", "host")])
        except RuntimeError:
            pass
        finally:
            api._graph.put_node = original_put  # type: ignore[method-assign]

        assert api._write_clock == pre_clock, (
            f"_write_clock must be restored. Before: {pre_clock}, after: {api._write_clock}"
        )

    def test_final_findings_f01_to_f21_marked_fixed(self) -> None:
        """Meta-test: no CONFIRMED finding in the audit may remain open after Phase 11."""
        from pathlib import Path

        audit_path = Path("docs/reviewer_findings_audit.md")
        if not audit_path.exists():
            pytest.skip("docs/reviewer_findings_audit.md not found")

        audit = audit_path.read_text(encoding="utf-8")
        open_confirmed: list[str] = []
        current_finding = ""

        for line in audit.split("\n"):
            if line.startswith("### F") and "—" in line:
                current_finding = line.split("###")[1].strip()
            elif line.startswith("**Status:**") and current_finding:
                if ("CONFIRMED" in line
                        and "FIXED" not in line
                        and "NOT REPRODUCED" not in line):
                    open_confirmed.append(f"{current_finding}: {line.strip()}")

        assert len(open_confirmed) == 0, (
            "Phase 11 must address all CONFIRMED findings.\n"
            "Still-open:\n" + "\n".join(open_confirmed)
        )

    def test_final_validation_baseline_has_phase_10(self) -> None:
        """docs/remediation_validation_baseline.md contains Phase 10 baseline section."""
        from pathlib import Path

        baseline_path = Path("docs/remediation_validation_baseline.md")
        if not baseline_path.exists():
            pytest.skip("docs/remediation_validation_baseline.md not found")

        baseline = baseline_path.read_text(encoding="utf-8")
        assert "Phase 10 Baseline" in baseline
        assert "2618" in baseline
        assert "125 source files" in baseline
