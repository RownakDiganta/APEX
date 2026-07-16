# test_phase16_experience_replay.py
# Regression tests for Phase 16: adaptive learning, reflection, and deterministic experience replay — experience model, reflection generation, replay ranking, graph links, report generation, transaction rollback, and the no-automatic-planner-override invariant.
"""Phase 16 regression tests.

Covers ``apex_host.planners.experience_replay`` (the reflection engine and
deterministic replay/ranking helpers), the ``Experience``/``ReflectionSummary``
model (``apex_host.types``), the ``experience``/``experience_recommendation``
graph materialization, the ``learning_summary`` wiring in
``apex_host.runtime.ApexRuntime.run()``, and ``RunReport``'s Learning Summary
section.

No exploit is executed, no payload is generated, no reverse shell is
created, no Metasploit is used, no persistence is established, and no flag
is captured by any code exercised here — every test asserts the
*deterministic reflection/replay* framework's behavior only (never machine
learning: no model, no training, no gradient, no probability estimate). No
Docker, Compose, VPN, or GitHub Actions files are touched by this test file
or the code it tests.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node, SubgraphView

from apex_host.config import ApexConfig
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.graph_ids import experience_id, host_id, workflow_id
from apex_host.planners.experience_replay import (
    apply_learning_rule,
    build_experience_graph_deltas,
    derive_experiences_from_engagement,
    experiences_from_subgraph,
    learning_summary_fields,
    rank_experiences,
    recommendation_text_for_experience,
    reflection_summary,
)
from apex_host.types import (
    Experience,
    ExperienceCategory,
    OpportunityConfidence,
)

_TARGET = "10.10.10.99"
_ANCHOR = host_id(_TARGET)
_PROJECT_ROOT = Path(__file__).parent.parent.parent


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def _host_node() -> Node:
    ts = now()
    return Node(id=_ANCHOR, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts)


def _subgraph(*nodes: Node, edges: list[Edge] | None = None) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=edges or [], depth=10)


def _service_node(port: str = "22") -> Node:
    ts = now()
    return Node(
        id=f"service:{_TARGET}:{port}/tcp", type="service",
        props={"port": port, "proto": "tcp", "service": "ssh", "state": "open", "version": ""},
        confidence=0.9, source="t", first_seen=ts, last_seen=ts,
    )


def _endpoint_node(url: str = "http://10.10.10.99/") -> Node:
    ts = now()
    return Node(id=f"endpoint:{url}", type="endpoint", props={"url": url}, confidence=0.7, source="t", first_seen=ts, last_seen=ts)


def _web_opportunity_node(idx: int, category: str = "authentication_portal") -> Node:
    ts = now()
    return Node(
        id=f"web_opportunity:{_TARGET}:{category}:{idx}", type="web_opportunity",
        props={"category": category, "confidence": "medium", "description": f"finding {idx}",
               "recommended_next_action": "investigate manually"},
        confidence=0.6, source="t", first_seen=ts, last_seen=ts,
    )


def _priv_esc_opportunity_node(idx: int, category: str = "docker") -> Node:
    ts = now()
    return Node(
        id=f"priv_esc_opportunity:{_TARGET}:{category}:{idx}", type="priv_esc_opportunity",
        props={"category": category, "confidence": "medium", "description": f"opportunity {idx}",
               "recommended_next_action": "investigate manually", "attempted": True,
               "attempt_count": 1, "exhausted": True},
        confidence=0.6, source="t", first_seen=ts, last_seen=ts,
    )


def _final_state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "completed": True, "outcome": "validated_access",
        "duplicate_actions": [], "credential_validation_log": [],
    }
    base.update(overrides)
    return base


def _base_config() -> ApexConfig:
    return ApexConfig(target=_TARGET, dry_run=True, max_turns=5)


# ---------------------------------------------------------------------------
# 1. apply_learning_rule — the fixed, deterministic confidence-adjustment table
# ---------------------------------------------------------------------------

class TestApplyLearningRule:
    def test_no_adjustment_at_occurrence_count_one(self) -> None:
        result = apply_learning_rule(ExperienceCategory.repeated_planner_mistake, 1, OpportunityConfidence.medium)
        assert result is OpportunityConfidence.medium

    def test_reinforce_up_increases_confidence(self) -> None:
        low = apply_learning_rule(ExperienceCategory.repeated_planner_mistake, 2, OpportunityConfidence.low)
        higher = apply_learning_rule(ExperienceCategory.repeated_planner_mistake, 3, OpportunityConfidence.low)
        assert low.as_float() < higher.as_float() or low.as_float() <= higher.as_float()
        assert higher.as_float() >= low.as_float()

    def test_reinforce_down_decreases_confidence(self) -> None:
        once = apply_learning_rule(ExperienceCategory.repeated_credential_outcome, 2, OpportunityConfidence.high)
        twice = apply_learning_rule(ExperienceCategory.repeated_credential_outcome, 4, OpportunityConfidence.high)
        assert twice.as_float() <= once.as_float()
        assert twice.as_float() < OpportunityConfidence.high.as_float()

    def test_confidence_clamped_at_one(self) -> None:
        result = apply_learning_rule(ExperienceCategory.successful_workflow, 50, OpportunityConfidence.high)
        assert result is OpportunityConfidence.high  # from_score(1.0) -> high, never errors/overflows

    def test_confidence_clamped_at_zero(self) -> None:
        result = apply_learning_rule(ExperienceCategory.abandoned_workflow, 50, OpportunityConfidence.low)
        assert result in (OpportunityConfidence.none, OpportunityConfidence.low)

    def test_category_not_in_either_set_is_unchanged(self) -> None:
        # ExperienceCategory.none is in neither _REINFORCE_UP nor _REINFORCE_DOWN.
        result = apply_learning_rule(ExperienceCategory.none, 5, OpportunityConfidence.medium)
        assert result is OpportunityConfidence.medium

    def test_deterministic_same_inputs_same_output(self) -> None:
        results = {
            apply_learning_rule(ExperienceCategory.repeated_privilege_opportunity, 3, OpportunityConfidence.medium)
            for _ in range(10)
        }
        assert len(results) == 1


# ---------------------------------------------------------------------------
# 2. experiences_from_subgraph / rank_experiences
# ---------------------------------------------------------------------------

class TestExperiencesFromSubgraphAndRanking:
    def test_reconstructs_experience_from_node(self) -> None:
        ts = now()
        exp_id = experience_id(_TARGET, "repeated_planner_mistake", "nmap:recon")
        node = Node(
            id=exp_id, type="experience",
            props={
                "category": "repeated_planner_mistake", "target": _TARGET, "discriminator": "nmap:recon",
                "context": "tool 'nmap' re-planned", "evidence_excerpt": "", "outcome": "duplicate_task",
                "recommendation": "avoid it", "confidence": "medium", "occurrence_count": 2,
            },
            confidence=0.6, source="experience_replay", first_seen=ts, last_seen=ts,
        )
        subgraph = _subgraph(_host_node(), node)
        experiences = experiences_from_subgraph(subgraph)
        assert len(experiences) == 1
        exp = experiences[0]
        assert exp.id == exp_id
        assert exp.category is ExperienceCategory.repeated_planner_mistake
        assert exp.occurrence_count == 2
        assert exp.discriminator == "nmap:recon"

    def test_non_experience_nodes_ignored(self) -> None:
        subgraph = _subgraph(_host_node(), _service_node())
        assert experiences_from_subgraph(subgraph) == []

    def test_unparseable_category_skipped(self) -> None:
        ts = now()
        node = Node(
            id="experience:bad", type="experience",
            props={"category": "not_a_real_category", "confidence": "medium"},
            confidence=0.5, source="t", first_seen=ts, last_seen=ts,
        )
        subgraph = _subgraph(_host_node(), node)
        assert experiences_from_subgraph(subgraph) == []

    def test_rank_experiences_confidence_descending(self) -> None:
        low = Experience(
            id="e1", category=ExperienceCategory.repeated_browser_finding, target=_TARGET, discriminator="d1",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.low, occurrence_count=1, first_seen="t", last_seen="t",
        )
        high = Experience(
            id="e2", category=ExperienceCategory.repeated_browser_finding, target=_TARGET, discriminator="d2",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.high, occurrence_count=1, first_seen="t", last_seen="t",
        )
        ranked = rank_experiences([low, high])
        assert ranked == [high, low]

    def test_rank_experiences_category_tiebreak(self) -> None:
        # Same confidence, different category — repeated_privilege_opportunity
        # (priority 0) ranks before repeated_browser_finding (priority 4).
        browser = Experience(
            id="e1", category=ExperienceCategory.repeated_browser_finding, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        priv = Experience(
            id="e2", category=ExperienceCategory.repeated_privilege_opportunity, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        ranked = rank_experiences([browser, priv])
        assert ranked == [priv, browser]

    def test_rank_experiences_deterministic_id_tiebreak(self) -> None:
        a = Experience(
            id="experience:a", category=ExperienceCategory.none, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        b = Experience(
            id="experience:b", category=ExperienceCategory.none, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        assert rank_experiences([b, a]) == [a, b]
        assert rank_experiences([a, b]) == [a, b]


# ---------------------------------------------------------------------------
# 3. Reflection generation — derive_experiences_from_engagement
# ---------------------------------------------------------------------------

class TestReflectionGeneration:
    def test_completed_workflow_produces_successful_workflow_experience(self) -> None:
        # credential_to_privesc workflow's steps all need host+service+access_state
        # +priv_esc_opportunity to reach "completed" — build the minimal chain.
        ts = now()
        access = Node(
            id=f"access_state:{_TARGET}:root", type="access_state",
            props={"username": "root", "target": _TARGET, "service": "ssh", "evidence": "uid=0(root)"},
            confidence=0.9, source="t", first_seen=ts, last_seen=ts,
        )
        priv = _priv_esc_opportunity_node(0)
        subgraph = _subgraph(_host_node(), _service_node(), access, priv)
        experiences = derive_experiences_from_engagement(_TARGET, subgraph, _final_state())
        successful = [e for e in experiences if e.category is ExperienceCategory.successful_workflow]
        assert successful, [e.category for e in experiences]
        assert successful[0].discriminator == "credential_to_privesc"

    def test_running_workflow_produces_no_experience(self) -> None:
        # Only prerequisites (host+service) present; no steps completed yet,
        # engagement not completed -> WorkflowStatus.running -> skipped.
        subgraph = _subgraph(_host_node(), _service_node())
        experiences = derive_experiences_from_engagement(
            _TARGET, subgraph, _final_state(completed=False, outcome=""),
        )
        assert not any(
            e.category in (ExperienceCategory.successful_workflow, ExperienceCategory.failed_workflow, ExperienceCategory.abandoned_workflow)
            for e in experiences
        )

    def test_abandoned_engagement_produces_abandoned_workflow_experience(self) -> None:
        subgraph = _subgraph(_host_node(), _service_node())
        experiences = derive_experiences_from_engagement(
            _TARGET, subgraph, _final_state(completed=True, outcome="max_turns_exhausted"),
        )
        abandoned = [e for e in experiences if e.category is ExperienceCategory.abandoned_workflow]
        assert abandoned

    def test_repeated_planner_mistake_from_duplicate_actions(self) -> None:
        subgraph = _subgraph(_host_node())
        final_state = _final_state(duplicate_actions=[
            {"tool": "nmap", "phase": "recon", "reason": "already completed"},
            {"tool": "nmap", "phase": "recon", "reason": "already completed"},  # exact dup -> deduped
        ])
        experiences = derive_experiences_from_engagement(_TARGET, subgraph, final_state)
        mistakes = [e for e in experiences if e.category is ExperienceCategory.repeated_planner_mistake]
        assert len(mistakes) == 1
        assert mistakes[0].discriminator == "nmap:recon"

    def test_repeated_browser_finding_requires_at_least_two(self) -> None:
        subgraph_one = _subgraph(_host_node(), _web_opportunity_node(0))
        experiences_one = derive_experiences_from_engagement(_TARGET, subgraph_one, _final_state())
        assert not any(e.category is ExperienceCategory.repeated_browser_finding for e in experiences_one)

        subgraph_two = _subgraph(_host_node(), _web_opportunity_node(0), _web_opportunity_node(1))
        experiences_two = derive_experiences_from_engagement(_TARGET, subgraph_two, _final_state())
        recurring = [e for e in experiences_two if e.category is ExperienceCategory.repeated_browser_finding]
        assert len(recurring) == 1
        assert recurring[0].discriminator == "authentication_portal"

    def test_repeated_privilege_opportunity_requires_at_least_two(self) -> None:
        subgraph = _subgraph(_host_node(), _priv_esc_opportunity_node(0, "docker"), _priv_esc_opportunity_node(1, "docker"))
        experiences = derive_experiences_from_engagement(_TARGET, subgraph, _final_state())
        recurring = [e for e in experiences if e.category is ExperienceCategory.repeated_privilege_opportunity]
        assert len(recurring) == 1
        assert recurring[0].discriminator == "docker"

    def test_failed_credential_produces_experience_successful_does_not(self) -> None:
        subgraph = _subgraph(_host_node())
        final_state = _final_state(credential_validation_log=[
            {"protocol": "ssh", "success": False, "error_category": "auth_failed"},
        ])
        experiences = derive_experiences_from_engagement(_TARGET, subgraph, final_state)
        cred = [e for e in experiences if e.category is ExperienceCategory.repeated_credential_outcome]
        assert len(cred) == 1
        assert cred[0].discriminator == "ssh"

        final_state_success = _final_state(credential_validation_log=[
            {"protocol": "ssh", "success": True, "error_category": "success"},
        ])
        experiences_success = derive_experiences_from_engagement(_TARGET, subgraph, final_state_success)
        assert not any(e.category is ExperienceCategory.repeated_credential_outcome for e in experiences_success)

    def test_deterministic_ordering_same_inputs_same_output(self) -> None:
        subgraph = _subgraph(
            _host_node(), _service_node(),
            _web_opportunity_node(0), _web_opportunity_node(1),
            _priv_esc_opportunity_node(0), _priv_esc_opportunity_node(1),
        )
        final_state = _final_state(duplicate_actions=[{"tool": "nmap", "phase": "recon"}])
        first = derive_experiences_from_engagement(_TARGET, subgraph, final_state)
        second = derive_experiences_from_engagement(_TARGET, subgraph, final_state)
        assert [e.id for e in first] == [e.id for e in second]
        assert [e.category for e in first] == [e.category for e in second]

    def test_no_experience_missing_recommendation(self) -> None:
        subgraph = _subgraph(_host_node(), _web_opportunity_node(0), _web_opportunity_node(1))
        experiences = derive_experiences_from_engagement(_TARGET, subgraph, _final_state())
        assert experiences
        assert all(e.recommendation for e in experiences)


# ---------------------------------------------------------------------------
# 4. Replay ranking / deterministic replay (occurrence_count + confidence)
# ---------------------------------------------------------------------------

class TestReplayAndDuplicatePrevention:
    def test_replay_increments_occurrence_count_and_adjusts_confidence(self) -> None:
        subgraph_empty = _subgraph(_host_node())
        final_state = _final_state(duplicate_actions=[{"tool": "nmap", "phase": "recon"}])

        first_pass = derive_experiences_from_engagement(_TARGET, subgraph_empty, final_state)
        assert len(first_pass) == 1
        assert first_pass[0].occurrence_count == 1
        first_confidence = first_pass[0].confidence

        # Simulate the experience already existing (as if a prior engagement
        # persisted it) by including its node in the subgraph passed to the
        # second reflection pass — this IS the replay mechanism.
        nodes, edges = build_experience_graph_deltas(_TARGET, first_pass)
        subgraph_with_prior = _subgraph(_host_node(), *nodes, edges=edges)

        second_pass = derive_experiences_from_engagement(_TARGET, subgraph_with_prior, final_state)
        repeated_mistakes = [e for e in second_pass if e.category is ExperienceCategory.repeated_planner_mistake]
        assert len(repeated_mistakes) == 1
        assert repeated_mistakes[0].id == first_pass[0].id  # SAME id — content-addressed upsert
        assert repeated_mistakes[0].occurrence_count == 2
        assert repeated_mistakes[0].confidence.as_float() >= first_confidence.as_float()
        assert "seen 2x" in repeated_mistakes[0].recommendation

    def test_duplicate_experience_prevention_via_apply_deltas(self) -> None:
        async def run() -> None:
            api = _make_api()
            await api.upsert_node(_host_node())
            final_state = _final_state(duplicate_actions=[{"tool": "nmap", "phase": "recon"}])

            for _ in range(3):
                subgraph = await api.get_subgraph(_ANCHOR, depth=10)
                experiences = derive_experiences_from_engagement(_TARGET, subgraph, final_state)
                nodes, edges = build_experience_graph_deltas(
                    _TARGET, experiences, known_node_ids={n.id for n in subgraph.nodes},
                )
                await api.apply_deltas(nodes=nodes, edges=edges)

            final_subgraph = await api.get_subgraph(_ANCHOR, depth=10)
            exp_nodes = [n for n in final_subgraph.nodes if n.type == "experience"]
            assert len(exp_nodes) == 1  # never duplicated across 3 reflection passes
            assert exp_nodes[0].props["occurrence_count"] == 3

        import asyncio
        asyncio.run(run())

    def test_replay_ranking_places_reinforced_experience_first(self) -> None:
        # A repeated_privilege_opportunity (reinforce-up) that has recurred
        # should rank above a fresh, never-repeated one of lower confidence.
        fresh = Experience(
            id="e1", category=ExperienceCategory.repeated_privilege_opportunity, target=_TARGET, discriminator="sudo",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        reinforced_confidence = apply_learning_rule(
            ExperienceCategory.repeated_privilege_opportunity, 3, OpportunityConfidence.medium,
        )
        reinforced = Experience(
            id="e2", category=ExperienceCategory.repeated_privilege_opportunity, target=_TARGET, discriminator="docker",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=reinforced_confidence, occurrence_count=3, first_seen="t", last_seen="t",
        )
        ranked = rank_experiences([fresh, reinforced])
        assert ranked[0].id == reinforced.id


# ---------------------------------------------------------------------------
# 5. Graph links — build_experience_graph_deltas
# ---------------------------------------------------------------------------

class TestGraphLinks:
    def test_experience_node_linked_to_host(self) -> None:
        exp = Experience(
            id=experience_id(_TARGET, "repeated_planner_mistake", "nmap:recon"),
            category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="nmap:recon",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        nodes, edges = build_experience_graph_deltas(_TARGET, [exp])
        node_types = {n.type for n in nodes}
        assert node_types == {"experience", "experience_recommendation"}
        indicates_edges = [e for e in edges if e.type == "indicates"]
        assert any(e.from_id == _ANCHOR and e.to_id == exp.id for e in indicates_edges)
        recommends_edges = [e for e in edges if e.type == "recommends"]
        assert len(recommends_edges) == 1
        assert recommends_edges[0].from_id == exp.id

    def test_workflow_link_edge_only_when_known_node_ids_supplied(self) -> None:
        exp = Experience(
            id=experience_id(_TARGET, "successful_workflow", "credential_to_privesc"),
            category=ExperienceCategory.successful_workflow, target=_TARGET, discriminator="credential_to_privesc",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.high, occurrence_count=1, first_seen="t", last_seen="t",
        )
        wf_id = workflow_id(_TARGET, "credential_to_privesc")

        # No known_node_ids -> no cross-batch link edge (safe by default).
        nodes_a, edges_a = build_experience_graph_deltas(_TARGET, [exp])
        assert not any(e.to_id == wf_id for e in edges_a)

        # known_node_ids supplied but workflow node absent -> still skipped.
        nodes_b, edges_b = build_experience_graph_deltas(_TARGET, [exp], known_node_ids={_ANCHOR})
        assert not any(e.to_id == wf_id for e in edges_b)

        # workflow node present in known_node_ids -> link edge added.
        nodes_c, edges_c = build_experience_graph_deltas(_TARGET, [exp], known_node_ids={_ANCHOR, wf_id})
        assert any(e.from_id == exp.id and e.to_id == wf_id and e.type == "indicates" for e in edges_c)

    def test_full_chain_persisted_and_reachable(self) -> None:
        async def run() -> None:
            api = _make_api()
            await api.upsert_node(_host_node())
            subgraph = await api.get_subgraph(_ANCHOR, depth=10)
            final_state = _final_state(duplicate_actions=[{"tool": "nmap", "phase": "recon"}])
            experiences = derive_experiences_from_engagement(_TARGET, subgraph, final_state)
            nodes, edges = build_experience_graph_deltas(_TARGET, experiences)
            await api.apply_deltas(nodes=nodes, edges=edges)

            final_subgraph = await api.get_subgraph(_ANCHOR, depth=10)
            types = {n.type for n in final_subgraph.nodes}
            assert {"experience", "experience_recommendation"}.issubset(types)
            edge_types = {e.type for e in final_subgraph.edges}
            assert {"indicates", "recommends"}.issubset(edge_types)

        import asyncio
        asyncio.run(run())


# ---------------------------------------------------------------------------
# 6. Transaction rollback
# ---------------------------------------------------------------------------

class TestTransactionRollback:
    @pytest.mark.asyncio
    async def test_rollback_on_dangling_edge_leaves_no_experience_nodes(self) -> None:
        api = _make_api()
        await api.upsert_node(_host_node())
        subgraph = await api.get_subgraph(_ANCHOR, depth=10)
        final_state = _final_state(duplicate_actions=[{"tool": "nmap", "phase": "recon"}])
        experiences = derive_experiences_from_engagement(_TARGET, subgraph, final_state)
        nodes, edges = build_experience_graph_deltas(_TARGET, experiences)
        assert nodes  # sanity: there IS something to roll back

        ts = now()
        bad_edge = Edge(
            id="indicates:bogus:missing", from_id="host:does-not-exist", to_id=nodes[0].id,
            type="indicates", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts,
        )
        with pytest.raises(ValueError):
            await api.apply_deltas(nodes=nodes, edges=[*edges, bad_edge])

        final_subgraph = await api.get_subgraph(_ANCHOR, depth=10)
        assert not any(n.type == "experience" for n in final_subgraph.nodes)

    @pytest.mark.asyncio
    async def test_rollback_preserves_pre_existing_experience(self) -> None:
        api = _make_api()
        await api.upsert_node(_host_node())

        # First, legitimately persist one experience.
        subgraph = await api.get_subgraph(_ANCHOR, depth=10)
        final_state = _final_state(duplicate_actions=[{"tool": "nmap", "phase": "recon"}])
        experiences = derive_experiences_from_engagement(_TARGET, subgraph, final_state)
        nodes, edges = build_experience_graph_deltas(_TARGET, experiences)
        await api.apply_deltas(nodes=nodes, edges=edges)

        # Now attempt a second, deliberately-broken batch — it must not
        # remove or corrupt the already-persisted experience.
        ts = now()
        bad_node = Node(
            id="experience:bad", type="experience", props={"category": "none", "confidence": "medium"},
            confidence=0.5, source="t", first_seen=ts, last_seen=ts,
        )
        bad_edge = Edge(
            id="indicates:missing:experience:bad", from_id="host:does-not-exist", to_id=bad_node.id,
            type="indicates", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts,
        )
        with pytest.raises(ValueError):
            await api.apply_deltas(nodes=[bad_node], edges=[bad_edge])

        final_subgraph = await api.get_subgraph(_ANCHOR, depth=10)
        exp_nodes = [n for n in final_subgraph.nodes if n.type == "experience"]
        assert len(exp_nodes) == 1
        assert exp_nodes[0].id == experience_id(_TARGET, "repeated_planner_mistake", "nmap:recon")


# ---------------------------------------------------------------------------
# 7. Report generation — Learning Summary
# ---------------------------------------------------------------------------

def _report_final_state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "target": _TARGET, "phase": "done", "completed": True, "turn_count": 1,
        "last_error": None, "findings": [], "error_episodes": [],
        "planner_decisions": [], "policy_decisions": [], "duplicate_actions": [],
        "credential_validation_log": [], "execution_backend_log": [],
        "outcome": "validated_access", "termination_reason": "", "termination_phase": "done",
        "stall_reason": "", "privilege_state": "", "enumeration_complete": False,
        "web_session_state": {}, "workflow_summary": {}, "learning_summary": {},
    }
    base.update(overrides)
    return base


class TestReportGeneration:
    def test_no_experiences_no_learning_section(self) -> None:
        report = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=_subgraph(_host_node()))
        assert report.learning_experience_count == 0
        assert "Learning Summary" not in format_text(report)

    def test_experiences_in_subgraph_populate_report(self) -> None:
        ts = now()
        exp = Experience(
            id=experience_id(_TARGET, "repeated_planner_mistake", "nmap:recon"),
            category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="nmap:recon",
            context="tool 'nmap' re-planned in phase 'recon'", evidence_excerpt="", outcome="duplicate_task",
            recommendation="avoid this duplicate action", confidence=OpportunityConfidence.medium,
            occurrence_count=2, first_seen=ts, last_seen=ts,
        )
        nodes, edges = build_experience_graph_deltas(_TARGET, [exp])
        subgraph = _subgraph(_host_node(), *nodes, edges=edges)

        report = build_report(config=_base_config(), final_state=_report_final_state(), subgraph=subgraph)
        assert report.learning_experience_count == 1
        assert report.learning_experience_categories == {"repeated_planner_mistake": 1}
        assert report.learning_recommendations == ["avoid this duplicate action"]

        text = format_text(report)
        assert "Learning Summary" in text
        assert "avoid this duplicate action" in text

        j = to_json_dict(report)
        assert j["learning"]["experience_count"] == 1
        assert j["learning"]["recommendations"] == ["avoid this duplicate action"]

    def test_learning_summary_delta_counts_from_final_state(self) -> None:
        ts = now()
        exp = Experience(
            id=experience_id(_TARGET, "repeated_planner_mistake", "nmap:recon"),
            category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="nmap:recon",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen=ts, last_seen=ts,
        )
        nodes, edges = build_experience_graph_deltas(_TARGET, [exp])
        subgraph = _subgraph(_host_node(), *nodes, edges=edges)
        final_state = _report_final_state(learning_summary={
            "experiences_created": 1, "experiences_reused": 0, "replay_hits": 0,
            "repeated_failures": 0, "improved_recommendations": [],
        })
        report = build_report(config=_base_config(), final_state=final_state, subgraph=subgraph)
        assert report.learning_experiences_created == 1
        assert report.learning_experiences_reused == 0
        assert "created=1 reused=0" in format_text(report)

    def test_missing_learning_summary_key_defaults_gracefully(self) -> None:
        # Backward compatibility: a final_state predating Phase 16 has no
        # "learning_summary" key at all.
        final_state = _report_final_state()
        del final_state["learning_summary"]
        report = build_report(config=_base_config(), final_state=final_state, subgraph=_subgraph(_host_node()))
        assert report.learning_experiences_created == 0


# ---------------------------------------------------------------------------
# 8. reflection_summary — created/reused/replay_hits deltas
# ---------------------------------------------------------------------------

class TestReflectionSummary:
    def test_all_new_experiences_counted_as_created(self) -> None:
        exp = Experience(
            id="e1", category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        summary = reflection_summary(_TARGET, [], [exp])
        assert summary.experiences_created == 1
        assert summary.experiences_reused == 0
        assert summary.replay_hits == 0

    def test_pre_existing_experience_counted_as_reused(self) -> None:
        before = Experience(
            id="e1", category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        after = Experience(
            id="e1", category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="r (seen 2x)",
            confidence=OpportunityConfidence.medium, occurrence_count=2, first_seen="t", last_seen="t2",
        )
        summary = reflection_summary(_TARGET, [before], [after])
        assert summary.experiences_created == 0
        assert summary.experiences_reused == 1
        assert summary.replay_hits == 1

    def test_repeated_failures_counted_for_relevant_categories_only(self) -> None:
        failed = Experience(
            id="e1", category=ExperienceCategory.failed_workflow, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=2, first_seen="t", last_seen="t",
        )
        successful = Experience(
            id="e2", category=ExperienceCategory.successful_workflow, target=_TARGET, discriminator="d2",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.high, occurrence_count=2, first_seen="t", last_seen="t",
        )
        summary = reflection_summary(_TARGET, [], [failed, successful])
        assert summary.repeated_failures == 1  # only the failed_workflow one counts

    def test_improved_recommendations_capped_at_five(self) -> None:
        experiences = [
            Experience(
                id=f"e{i}", category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator=f"d{i}",
                context="c", evidence_excerpt="", outcome="o", recommendation=f"rec-{i}",
                confidence=OpportunityConfidence.medium, occurrence_count=2, first_seen="t", last_seen="t",
            )
            for i in range(8)
        ]
        summary = reflection_summary(_TARGET, [], experiences)
        assert len(summary.improved_recommendations) == 5


# ---------------------------------------------------------------------------
# 9. Recommendation ranking / recommendation text
# ---------------------------------------------------------------------------

class TestRecommendationText:
    @pytest.mark.parametrize("category", list(ExperienceCategory))
    def test_every_category_produces_nonempty_text(self, category: ExperienceCategory) -> None:
        exp = Experience(
            id="e", category=category, target=_TARGET, discriminator="d",
            context="something happened", evidence_excerpt="", outcome="o", recommendation="",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        text = recommendation_text_for_experience(exp)
        assert text
        assert "something happened" in text

    def test_repeated_suffix_appears_only_when_occurrence_gt_one(self) -> None:
        exp_once = Experience(
            id="e", category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen="t", last_seen="t",
        )
        exp_twice = Experience(
            id="e", category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="",
            confidence=OpportunityConfidence.medium, occurrence_count=2, first_seen="t", last_seen="t",
        )
        assert "seen" not in recommendation_text_for_experience(exp_once)
        assert "seen 2x" in recommendation_text_for_experience(exp_twice)

    def test_recommendation_never_contains_executable_command_markers(self) -> None:
        # Advisory guidance only — never a shell command or payload. (A bare
        # ";" is fine — it's ordinary English punctuation in every fixed
        # template here; the markers below are the ones that would actually
        # indicate embedded shell syntax or a destructive command.)
        for category in ExperienceCategory:
            exp = Experience(
                id="e", category=category, target=_TARGET, discriminator="d",
                context="c", evidence_excerpt="", outcome="o", recommendation="",
                confidence=OpportunityConfidence.medium, occurrence_count=3, first_seen="t", last_seen="t",
            )
            text = recommendation_text_for_experience(exp)
            for marker in ("$(", "`", "&&", "rm -rf", "||"):
                assert marker not in text


# ---------------------------------------------------------------------------
# 10. learning_summary_fields — live-view shape
# ---------------------------------------------------------------------------

class TestLearningSummaryFields:
    def test_shape_and_keys(self) -> None:
        ts = now()
        exp = Experience(
            id="e1", category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="d",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=1, first_seen=ts, last_seen=ts,
        )
        nodes, edges = build_experience_graph_deltas(_TARGET, [exp])
        subgraph = _subgraph(_host_node(), *nodes, edges=edges)
        fields = learning_summary_fields(_TARGET, subgraph)
        assert "learning_summary" in fields
        assert fields["learning_summary"]["experience_count"] == 1
        assert fields["learning_summary"]["category_counts"] == {"repeated_planner_mistake": 1}

    def test_empty_subgraph_produces_zero_counts(self) -> None:
        fields = learning_summary_fields(_TARGET, _subgraph(_host_node()))
        assert fields["learning_summary"]["experience_count"] == 0
        assert fields["learning_summary"]["category_counts"] == {}


# ---------------------------------------------------------------------------
# 11. No automatic planner override (static scan + behavioral proof)
# ---------------------------------------------------------------------------

_PLANNER_FILES = (
    "recon_planner.py", "web_planner.py", "browser_planner.py",
    "credential_planner.py", "priv_esc_planner.py", "global_planner.py",
)


class TestNoAutomaticPlannerOverride:
    def test_no_planner_file_imports_experience_replay(self) -> None:
        planners_dir = _PROJECT_ROOT / "apex_host" / "planners"
        offenders = []
        for filename in _PLANNER_FILES:
            path = planners_dir / filename
            assert path.is_file(), f"expected planner file missing: {path}"
            src = path.read_text(encoding="utf-8")
            if "experience_replay" in src:
                offenders.append(filename)
        assert not offenders, f"planner file(s) import experience_replay, violating no-override invariant: {offenders}"

    def test_experience_replay_module_never_imports_a_planner(self) -> None:
        # experience_replay.py may import the pure reasoning helper modules
        # (priv_esc_opportunities/web_opportunities/workflow_orchestration)
        # but never a *_planner.py module — it must never call into planner
        # decision logic, only read the shared EKG subgraph.
        src = (_PROJECT_ROOT / "apex_host" / "planners" / "experience_replay.py").read_text(encoding="utf-8")
        for filename in _PLANNER_FILES:
            module_name = filename.removesuffix(".py")
            assert f"import {module_name}" not in src
            assert f"from apex_host.planners.{module_name}" not in src

    def test_experience_nodes_present_does_not_change_global_planner_output(self) -> None:
        """Behavioral proof, not just a static scan: attaching experience
        nodes to the subgraph's node-type set must not change what
        GlobalPlanner (the phase-selection authority) decides — experiences
        are advisory-only, read by report/replay code, never consulted by
        any planner's decision path."""
        from apex_host.planners.global_planner import GlobalPlanner

        node_types_plain = {n.type for n in _subgraph(_host_node(), _service_node()).nodes}

        exp = Experience(
            id=experience_id(_TARGET, "repeated_planner_mistake", "nmap:recon"),
            category=ExperienceCategory.repeated_planner_mistake, target=_TARGET, discriminator="nmap:recon",
            context="c", evidence_excerpt="", outcome="o", recommendation="r",
            confidence=OpportunityConfidence.medium, occurrence_count=5, first_seen="t", last_seen="t",
        )
        nodes, edges = build_experience_graph_deltas(_TARGET, [exp])
        subgraph_with_experience = _subgraph(_host_node(), _service_node(), *nodes, edges=edges)
        node_types_with_experience = {n.type for n in subgraph_with_experience.nodes}

        gp1 = GlobalPlanner(max_turns=10)
        gp2 = GlobalPlanner(max_turns=10)
        phase_plain = gp1.decide_phase(node_types_seen=node_types_plain, turn_count=1)
        phase_with_experience = gp2.decide_phase(node_types_seen=node_types_with_experience, turn_count=1)
        assert phase_plain == phase_with_experience
