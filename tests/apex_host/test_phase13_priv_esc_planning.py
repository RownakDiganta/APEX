# test_phase13_priv_esc_planning.py
# Regression tests for Phase 13: the privilege-escalation planning framework — opportunity model, parser, dedup/ranking/exhaustion logic, planner, executor, dispatcher/policy wiring, graph-state fields, and reporting.
"""Phase 13 regression tests.

Covers the privilege-escalation PLANNING framework introduced in Phase 13:
the ``PrivilegeOpportunity``/``OpportunityCategory``/``OpportunityConfidence``/
``PrivilegeEnumerationStatus`` model (``apex_host.types``), the EKG ID
builders (``apex_host.graph_ids``), ``PrivEscParser``, the pure reasoning
helpers in ``apex_host.planners.priv_esc_opportunities`` (dedup, ranking,
analytical derivation, exhaustion), the rewritten ``PrivEscPlanner``, the
zero-network ``PrivEscAnalysisExecutor``, ``TaskDispatcher``/policy wiring,
the additive ``ApexGraphState`` fields, and ``RunReport``'s privilege
escalation summary.

No exploit is executed, no payload is generated, no privilege escalation is
ever performed by any code exercised here — every test asserts the
*planning* framework's behavior only. No Docker, Compose, VPN, or GitHub
Actions files are touched by this test file or the code it tests.
"""
from __future__ import annotations

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
from memfabric.types import AbandonSignal, Edge, EvidenceBundle, Goal, Node, SubgraphView, TaskSpec

from apex_host.config import ApexConfig
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.graph_ids import host_id, indicates_edge_id, priv_esc_opportunity_id
from apex_host.parsers.priv_esc_parser import PrivEscParser
from apex_host.planners.priv_esc_opportunities import (
    build_privilege_escalation_state,
    derive_analytical_opportunities,
    opportunities_from_subgraph,
    privilege_state_fields,
    rank_opportunities,
)
from apex_host.planners.priv_esc_planner import PrivEscPlanner, _PrivEscDeterministic
from apex_host.tools.registry import ToolRegistry
from apex_host.types import (
    OpportunityCategory,
    OpportunityConfidence,
    PrivilegeEnumerationStatus,
    PrivilegeEscalationState,
    PrivilegeOpportunity,
    PrivilegeOpportunityEvidence,
)

_TARGET = "10.10.10.200"
_ANCHOR = f"host:{_TARGET}"


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


def _registry(*tools: str) -> ToolRegistry:
    return ToolRegistry(allowed_tools=list(tools))


def _goal(phase: str = "priv_esc") -> Goal:
    return Goal(id="g-priv-esc", description="Enumerate privilege-escalation surface", phase=phase, anchor_node=_ANCHOR)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(entries=[], query="test", subgraph=None, tiers_queried=[])


def _node(node_id: str, node_type: str, props: dict[str, Any], confidence: float = 0.9) -> Node:
    ts = now()
    return Node(id=node_id, type=node_type, props=props, confidence=confidence, source="test", first_seen=ts, last_seen=ts)


def _edge(from_id: str, to_id: str, edge_type: str = "exposes") -> Edge:
    ts = now()
    return Edge(
        id=f"{edge_type}:{from_id}:{to_id}", from_id=from_id, to_id=to_id, type=edge_type,
        props={}, confidence=0.9, source="test", first_seen=ts, last_seen=ts,
    )


def _subgraph(*nodes: Node, edges: list[Edge] | None = None) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=edges or [], depth=2)


def _service_node(port: str, service: str, version: str = "") -> Node:
    return _node(
        f"service:{_TARGET}:{port}/tcp", "service",
        {"port": port, "proto": "tcp", "service": service, "state": "open", "version": version},
    )


def _access_state_node(username: str = "root", evidence: str = "", proof: str = "") -> Node:
    return _node(
        f"access_state:{_TARGET}:{username}", "access_state",
        {"level": "user", "username": username, "target": _TARGET, "evidence": evidence, "proof": proof},
    )


def _opportunity(
    category: OpportunityCategory = OpportunityCategory.sudo,
    confidence: OpportunityConfidence = OpportunityConfidence.medium,
    exhausted: bool = True,
    discriminator: str = "sudo-group-root",
) -> PrivilegeOpportunity:
    return PrivilegeOpportunity(
        id=priv_esc_opportunity_id(_TARGET, category.value, discriminator),
        category=category,
        confidence=confidence,
        evidence=PrivilegeOpportunityEvidence(source="test", supporting_node_ids=(), excerpt="", timestamp=now()),
        description="test opportunity",
        recommended_next_action="manually verify",
        attempted=True,
        attempt_count=1,
        exhausted=exhausted,
        first_seen=now(),
        last_seen=now(),
    )


# ---------------------------------------------------------------------------
# 1. Model — enums, dataclasses, category handling, confidence handling
# ---------------------------------------------------------------------------

class TestOpportunityModel:
    def test_all_suggested_categories_present(self) -> None:
        suggested = {
            "sudo", "suid", "capabilities", "cron", "writable_service",
            "path_issue", "kernel_version", "docker", "mounted_filesystem",
            "credentials", "scheduled_task", "windows_service", "registry",
            "startup_item",
        }
        actual = {c.value for c in OpportunityCategory}
        assert suggested.issubset(actual)

    def test_category_is_str_enum_serializable(self) -> None:
        assert OpportunityCategory("sudo") is OpportunityCategory.sudo
        assert OpportunityCategory.sudo.value == "sudo"

    @pytest.mark.parametrize(
        "confidence,expected_float",
        [
            (OpportunityConfidence.none, 0.0),
            (OpportunityConfidence.low, 0.3),
            (OpportunityConfidence.medium, 0.6),
            (OpportunityConfidence.high, 0.9),
        ],
    )
    def test_confidence_as_float(self, confidence: OpportunityConfidence, expected_float: float) -> None:
        assert confidence.as_float() == expected_float

    @pytest.mark.parametrize(
        "score,expected",
        [
            (0.0, OpportunityConfidence.none),
            (0.2, OpportunityConfidence.low),
            (0.5, OpportunityConfidence.medium),
            (0.84, OpportunityConfidence.medium),
            (0.85, OpportunityConfidence.high),
            (1.0, OpportunityConfidence.high),
        ],
    )
    def test_confidence_from_score(self, score: float, expected: OpportunityConfidence) -> None:
        assert OpportunityConfidence.from_score(score) is expected

    def test_enumeration_status_has_five_members_including_future_capability(self) -> None:
        values = {s.value for s in PrivilegeEnumerationStatus}
        assert values == {
            "not_started", "running", "opportunities_found", "exhausted",
            "elevated_access_validated",
        }

    def test_opportunity_supporting_node_ids_property(self) -> None:
        opp = PrivilegeOpportunity(
            id="x", category=OpportunityCategory.sudo, confidence=OpportunityConfidence.medium,
            evidence=PrivilegeOpportunityEvidence(source="s", supporting_node_ids=("n1", "n2")),
            description="d", recommended_next_action="r", attempted=True, attempt_count=1,
            exhausted=False, first_seen="t1", last_seen="t2",
        )
        assert opp.supporting_node_ids == ("n1", "n2")

    def test_privilege_escalation_state_derived_properties(self) -> None:
        opps = (
            _opportunity(OpportunityCategory.sudo, exhausted=True),
            _opportunity(OpportunityCategory.docker, exhausted=False, discriminator="docker-group-root"),
            _opportunity(OpportunityCategory.vulnerable_service, exhausted=True, discriminator="ftp-vsftpd"),
        )
        state = PrivilegeEscalationState(target=_TARGET, status=PrivilegeEnumerationStatus.opportunities_found, opportunities=opps)
        assert state.opportunity_count == 3
        assert state.attempted_count == 3
        assert state.exhausted_count == 2
        assert state.remaining_count == 1
        assert state.categories == {"sudo": 1, "docker": 1, "vulnerable_service": 1}
        assert state.enumeration_complete is False

    def test_enumeration_complete_true_only_when_status_exhausted(self) -> None:
        state = PrivilegeEscalationState(target=_TARGET, status=PrivilegeEnumerationStatus.exhausted, opportunities=())
        assert state.enumeration_complete is True


# ---------------------------------------------------------------------------
# 2. graph_ids builders
# ---------------------------------------------------------------------------

class TestGraphIdBuilders:
    def test_priv_esc_opportunity_id_deterministic(self) -> None:
        id1 = priv_esc_opportunity_id(_TARGET, "vulnerable_service", "vsftpd 2.3.4")
        id2 = priv_esc_opportunity_id(_TARGET, "vulnerable_service", "vsftpd 2.3.4")
        assert id1 == id2
        assert id1.startswith(f"priv_esc_opportunity:{_TARGET}:vulnerable_service:")

    def test_priv_esc_opportunity_id_slugs_discriminator(self) -> None:
        opp_id = priv_esc_opportunity_id(_TARGET, "vulnerable_service", "vsftpd 2.3.4")
        assert "vsftpd-2-3-4" in opp_id

    def test_priv_esc_opportunity_id_differs_by_category(self) -> None:
        id1 = priv_esc_opportunity_id(_TARGET, "sudo", "root")
        id2 = priv_esc_opportunity_id(_TARGET, "docker", "root")
        assert id1 != id2

    def test_indicates_edge_id_deterministic(self) -> None:
        e1 = indicates_edge_id("host:x", "priv_esc_opportunity:x:sudo:root")
        e2 = indicates_edge_id("host:x", "priv_esc_opportunity:x:sudo:root")
        assert e1 == e2
        assert e1.startswith("indicates:")


# ---------------------------------------------------------------------------
# 3. PrivEscParser
# ---------------------------------------------------------------------------

_SEARCHSPLOIT_HITS = """\
------------------------------------------- ---------------------------------
 Exploit Title                              |  Path
------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution   | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor (Metasploit)        | unix/remote/17491.rb
------------------------------------------- ---------------------------------
"""

_SEARCHSPLOIT_NO_HITS = """\
------------------------------------------- ---------------------------------
 Exploit Title                              |  Path
------------------------------------------- ---------------------------------
------------------------------------------- ---------------------------------
"""


class TestPrivEscParser:
    def test_parse_searchsploit_hits_produces_vulnerable_service_opportunity(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_searchsploit(_SEARCHSPLOIT_HITS, target=_TARGET, service="vsftpd", version="2.3.4")
        assert len(parsed.node_deltas) == 1
        node = parsed.node_deltas[0]
        assert node.type == "priv_esc_opportunity"
        assert node.props["category"] == "vulnerable_service"
        assert node.props["exhausted"] is True
        assert node.props["attempted"] is True
        assert "2 known exploit-db" in node.props["description"]

    def test_parse_searchsploit_hits_confidence_scales_with_hit_count(self) -> None:
        parser = PrivEscParser()
        two_hits = parser.parse_searchsploit(_SEARCHSPLOIT_HITS, target=_TARGET, service="vsftpd", version="2.3.4")
        assert two_hits.node_deltas[0].props["confidence"] == "medium"

        many_hits = "\n".join(f"Exploit {i}   | unix/remote/{i}.py" for i in range(5))
        three_plus = parser.parse_searchsploit(many_hits, target=_TARGET, service="vsftpd", version="2.3.4")
        assert three_plus.node_deltas[0].props["confidence"] == "high"

    def test_parse_searchsploit_no_hits_produces_none_category_exhausted(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_searchsploit(_SEARCHSPLOIT_NO_HITS, target=_TARGET, service="obscure", version="9.9")
        assert len(parsed.node_deltas) == 1
        node = parsed.node_deltas[0]
        assert node.props["category"] == "none"
        assert node.props["confidence"] == "none"
        assert node.props["exhausted"] is True

    def test_parse_searchsploit_links_edge_from_host(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_searchsploit(_SEARCHSPLOIT_HITS, target=_TARGET, service="vsftpd", version="2.3.4")
        assert len(parsed.edge_deltas) == 1
        edge = parsed.edge_deltas[0]
        assert edge.from_id == host_id(_TARGET)
        assert edge.type == "indicates"

    def test_parse_searchsploit_no_service_returns_empty(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_searchsploit("", target=_TARGET, service="", version="")
        assert parsed.node_deltas == []
        assert parsed.edge_deltas == []

    def test_parse_searchsploit_evidence_excerpt_never_contains_full_line_count_over_five(self) -> None:
        parser = PrivEscParser()
        many_hits = "\n".join(f"Exploit Title {i}   | unix/remote/{i}.py" for i in range(20))
        parsed = parser.parse_searchsploit(many_hits, target=_TARGET, service="thing", version="1.0")
        excerpt = parsed.node_deltas[0].props["evidence_excerpt"]
        # Only first 5 titles ever included, bounded length.
        assert excerpt.count("Exploit Title") <= 5
        assert len(excerpt) <= 200

    def test_parse_searchsploit_no_exploit_code_in_output(self) -> None:
        """The parser must never embed anything beyond bounded titles — no
        shell commands, no payload bytes, no base64 blobs."""
        parser = PrivEscParser()
        parsed = parser.parse_searchsploit(_SEARCHSPLOIT_HITS, target=_TARGET, service="vsftpd", version="2.3.4")
        node = parsed.node_deltas[0]
        for value in node.props.values():
            if isinstance(value, str):
                assert "```" not in value
                assert "#!/" not in value
                assert "import os" not in value

    def test_parse_analytical_produces_opportunity_node_and_edge(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_analytical(
            target=_TARGET, category="docker", confidence="high",
            description="user in docker group", recommended_next_action="manually verify",
            discriminator="docker-group-root", evidence_source="id_groups",
            evidence_excerpt="groups=1000(user),999(docker)",
            source_node_id="access_state:10.10.10.200:root",
        )
        assert len(parsed.node_deltas) == 1
        node = parsed.node_deltas[0]
        assert node.type == "priv_esc_opportunity"
        assert node.props["category"] == "docker"
        assert len(parsed.edge_deltas) == 1
        assert parsed.edge_deltas[0].from_id == "access_state:10.10.10.200:root"

    def test_parse_analytical_no_source_node_produces_no_edge(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_analytical(
            target=_TARGET, category="sudo", confidence="medium",
            description="d", recommended_next_action="r", discriminator="sudo-group-root",
            evidence_source="id_groups", evidence_excerpt="", source_node_id="",
        )
        assert len(parsed.node_deltas) == 1
        assert parsed.edge_deltas == []

    def test_parse_analytical_missing_category_returns_empty(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_analytical(
            target=_TARGET, category="", confidence="medium", description="d",
            recommended_next_action="r", discriminator="x", evidence_source="s",
            evidence_excerpt="", source_node_id="",
        )
        assert parsed.node_deltas == []


# ---------------------------------------------------------------------------
# 4. priv_esc_opportunities.py — dedup / ranking / analytical derivation
# ---------------------------------------------------------------------------

class TestOpportunitiesFromSubgraph:
    def test_reconstructs_opportunity_from_node(self) -> None:
        node = _node(
            priv_esc_opportunity_id(_TARGET, "sudo", "root"), "priv_esc_opportunity",
            {
                "target": _TARGET, "category": "sudo", "confidence": "medium",
                "description": "d", "recommended_next_action": "r",
                "attempted": True, "attempt_count": 1, "exhausted": True,
                "evidence_source": "id_groups", "evidence_excerpt": "", "evidence_timestamp": now(),
            },
        )
        opps = opportunities_from_subgraph(_subgraph(node))
        assert len(opps) == 1
        assert opps[0].category is OpportunityCategory.sudo
        assert opps[0].exhausted is True

    def test_ignores_non_opportunity_nodes(self) -> None:
        svc = _service_node("22", "ssh", "7.4")
        opps = opportunities_from_subgraph(_subgraph(svc))
        assert opps == []

    def test_skips_unparseable_category_forward_compat(self) -> None:
        node = _node(
            "priv_esc_opportunity:x:unknown:y", "priv_esc_opportunity",
            {"category": "some_future_category_value", "confidence": "medium"},
        )
        opps = opportunities_from_subgraph(_subgraph(node))
        assert opps == []


class TestRankOpportunities:
    def test_higher_confidence_ranks_first(self) -> None:
        low = _opportunity(OpportunityCategory.sudo, OpportunityConfidence.low, discriminator="a")
        high = _opportunity(OpportunityCategory.docker, OpportunityConfidence.high, discriminator="b")
        ranked = rank_opportunities([low, high])
        assert ranked[0] is high

    def test_deterministic_across_repeated_calls(self) -> None:
        opps = [
            _opportunity(OpportunityCategory.sudo, OpportunityConfidence.medium, discriminator=f"d{i}")
            for i in range(5)
        ]
        r1 = [o.id for o in rank_opportunities(opps)]
        r2 = [o.id for o in rank_opportunities(list(reversed(opps)))]
        assert r1 == r2

    def test_category_priority_tiebreaks_equal_confidence(self) -> None:
        sudo_opp = _opportunity(OpportunityCategory.sudo, OpportunityConfidence.medium, discriminator="a")
        registry_opp = _opportunity(OpportunityCategory.registry, OpportunityConfidence.medium, discriminator="b")
        ranked = rank_opportunities([registry_opp, sudo_opp])
        assert ranked[0] is sudo_opp  # sudo has higher category priority than registry

    def test_empty_list_returns_empty(self) -> None:
        assert rank_opportunities([]) == []


class TestBuildPrivilegeEscalationState:
    def test_not_started_without_access_state(self) -> None:
        state = build_privilege_escalation_state(_TARGET, _subgraph(), has_access_state=False)
        assert state.status is PrivilegeEnumerationStatus.not_started

    def test_running_with_access_state_no_opportunities(self) -> None:
        state = build_privilege_escalation_state(_TARGET, _subgraph(), has_access_state=True)
        assert state.status is PrivilegeEnumerationStatus.running

    def test_opportunities_found_when_any_remain(self) -> None:
        node = _node(
            priv_esc_opportunity_id(_TARGET, "docker", "root"), "priv_esc_opportunity",
            {"category": "docker", "confidence": "high", "exhausted": False, "attempted": True},
        )
        state = build_privilege_escalation_state(_TARGET, _subgraph(node), has_access_state=True)
        assert state.status is PrivilegeEnumerationStatus.opportunities_found

    def test_exhausted_when_all_recorded_and_exhausted(self) -> None:
        node = _node(
            priv_esc_opportunity_id(_TARGET, "none", "ftp-x"), "priv_esc_opportunity",
            {"category": "none", "confidence": "none", "exhausted": True, "attempted": True},
        )
        state = build_privilege_escalation_state(_TARGET, _subgraph(node), has_access_state=True)
        assert state.status is PrivilegeEnumerationStatus.exhausted

    def test_never_returns_elevated_access_validated(self) -> None:
        """Future capability — no code path in Phase 13 ever produces this."""
        for has_access in (True, False):
            node = _node(
                priv_esc_opportunity_id(_TARGET, "docker", "root"), "priv_esc_opportunity",
                {"category": "docker", "confidence": "high", "exhausted": True, "attempted": True},
            )
            state = build_privilege_escalation_state(_TARGET, _subgraph(node), has_access_state=has_access)
            assert state.status is not PrivilegeEnumerationStatus.elevated_access_validated


class TestDeriveAnalyticalOpportunities:
    def test_docker_group_hint_detected(self) -> None:
        access = _access_state_node(evidence="uid=0(root) gid=0(root) groups=0(root),999(docker)")
        candidates = derive_analytical_opportunities(_subgraph(access))
        categories = {c.category for c in candidates}
        assert "docker" in categories

    def test_sudo_group_hint_detected(self) -> None:
        access = _access_state_node(evidence="uid=1000(user) groups=1000(user),27(sudo)")
        candidates = derive_analytical_opportunities(_subgraph(access))
        categories = {c.category for c in candidates}
        assert "sudo" in categories

    def test_wheel_group_also_detected_as_sudo(self) -> None:
        access = _access_state_node(evidence="uid=1000(user) groups=1000(user),10(wheel)")
        candidates = derive_analytical_opportunities(_subgraph(access))
        assert any(c.category == "sudo" for c in candidates)

    def test_no_hints_produces_no_candidates(self) -> None:
        access = _access_state_node(evidence="uid=1000(user) gid=1000(user) groups=1000(user)")
        candidates = derive_analytical_opportunities(_subgraph(access))
        assert candidates == []

    def test_no_access_state_produces_no_candidates(self) -> None:
        svc = _service_node("22", "ssh", "7.4")
        candidates = derive_analytical_opportunities(_subgraph(svc))
        assert candidates == []

    def test_discriminator_includes_username(self) -> None:
        access = _access_state_node(username="alice", evidence="groups=1000(alice),999(docker)")
        candidates = derive_analytical_opportunities(_subgraph(access))
        docker_cand = next(c for c in candidates if c.category == "docker")
        assert "alice" in docker_cand.discriminator

    def test_evidence_excerpt_bounded_to_200_chars(self) -> None:
        long_evidence = "groups=1000(user),999(docker) " + ("x" * 500)
        access = _access_state_node(evidence=long_evidence)
        candidates = derive_analytical_opportunities(_subgraph(access))
        for c in candidates:
            assert len(c.evidence_excerpt) <= 200

    def test_kernel_and_suid_never_derived_analytically(self) -> None:
        """No reliable EKG data source exists for these — see module
        docstring 'Deliberately does NOT attempt...'."""
        access = _access_state_node(evidence="Linux kernel 4.4.0 groups=1000(user),999(docker)")
        candidates = derive_analytical_opportunities(_subgraph(access))
        categories = {c.category for c in candidates}
        assert "kernel_version" not in categories
        assert "suid" not in categories


class TestPrivilegeStateFields:
    def test_returns_expected_keys(self) -> None:
        fields = privilege_state_fields(_subgraph(), target=_TARGET)
        assert set(fields.keys()) == {
            "privilege_state", "privilege_summary", "opportunity_ids",
            "attempted_opportunities", "enumeration_complete",
        }

    def test_empty_subgraph_not_started(self) -> None:
        fields = privilege_state_fields(_subgraph(), target=_TARGET)
        assert fields["privilege_state"] == "not_started"
        assert fields["enumeration_complete"] is False
        assert fields["opportunity_ids"] == []


# ---------------------------------------------------------------------------
# 5. PrivEscAnalysisExecutor — zero network, zero subprocess
# ---------------------------------------------------------------------------

class TestPrivEscAnalysisExecutor:
    @pytest.mark.asyncio
    async def test_echoes_params_into_episode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.agents.priv_esc_analysis_executor import PrivEscAnalysisExecutor

        def _forbidden_subprocess(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("PrivEscAnalysisExecutor must never spawn a subprocess")

        def _forbidden_socket(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("PrivEscAnalysisExecutor must never open a socket")

        import asyncio
        import socket
        monkeypatch.setattr(asyncio, "create_subprocess_exec", _forbidden_subprocess)
        monkeypatch.setattr(socket, "socket", _forbidden_socket)

        executor = PrivEscAnalysisExecutor()
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="priv_esc",
            params={
                "category": "docker", "confidence": "high", "description": "d",
                "recommended_next_action": "r", "discriminator": "docker-group-root",
                "evidence_source": "id_groups", "evidence_excerpt": "e",
                "source_node_id": "access_state:x:root", "target": _TARGET,
            },
            phase="priv_esc",
        )
        result = await executor.run(task, _empty_evidence())
        assert result.episode.data["category"] == "docker"
        assert result.episode.outcome.value == "success"
        assert result.episode.data["evidence_excerpt"] == "e"

    @pytest.mark.asyncio
    async def test_evidence_excerpt_truncated_to_200(self) -> None:
        from apex_host.agents.priv_esc_analysis_executor import PrivEscAnalysisExecutor

        executor = PrivEscAnalysisExecutor()
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="priv_esc",
            params={"category": "sudo", "evidence_excerpt": "x" * 500},
            phase="priv_esc",
        )
        result = await executor.run(task, _empty_evidence())
        assert len(result.episode.data["evidence_excerpt"]) <= 200

    @pytest.mark.asyncio
    async def test_stateless_across_calls(self) -> None:
        from apex_host.agents.priv_esc_analysis_executor import PrivEscAnalysisExecutor

        executor = PrivEscAnalysisExecutor()
        t1 = TaskSpec(id="t1", goal_id="g1", executor_domain="priv_esc", params={"category": "docker"}, phase="priv_esc")
        t2 = TaskSpec(id="t2", goal_id="g1", executor_domain="priv_esc", params={"category": "sudo"}, phase="priv_esc")
        r1 = await executor.run(t1, _empty_evidence())
        r2 = await executor.run(t2, _empty_evidence())
        assert r1.episode.data["category"] == "docker"
        assert r2.episode.data["category"] == "sudo"


# ---------------------------------------------------------------------------
# 6. TaskDispatcher / policy wiring
# ---------------------------------------------------------------------------

def _build_dispatcher_with_priv_esc_executor(config: ApexConfig) -> Any:
    from apex_host.agents.priv_esc_analysis_executor import PrivEscAnalysisExecutor
    from apex_host.execution.dispatcher import TaskDispatcher
    from apex_host.execution.registry import TaskRegistry
    from apex_host.policy import PolicyAdvisor, load_policy

    return TaskDispatcher(
        advisor=PolicyAdvisor(load_policy(config), config),
        task_registry=TaskRegistry(), config=config,
        run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type,return-value]
        priv_esc_analysis_executor=PrivEscAnalysisExecutor(),
    )


class TestDispatcherPrivEscRouting:
    @pytest.mark.asyncio
    async def test_priv_esc_analyze_routes_to_executor(self) -> None:
        from apex_host.execution.context import ExecutionContext
        from apex_host.execution.dispositions import ExecutionDisposition

        config = ApexConfig(target=_TARGET, dry_run=True)
        dispatcher = _build_dispatcher_with_priv_esc_executor(config)
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="priv_esc",
            params={
                "tool": "priv_esc_analyze", "target": _TARGET,
                "args": ["docker", "docker-group-root"], "parser": "priv_esc",
                "category": "docker", "confidence": "high", "description": "d",
                "recommended_next_action": "r", "discriminator": "docker-group-root",
                "evidence_source": "id_groups", "evidence_excerpt": "e", "source_node_id": "",
            },
            phase="priv_esc",
        )
        ctx = ExecutionContext(
            run_id="r1", phase="priv_esc", turn_number=1, evidence_version=None,
            subgraph=_subgraph(), evidence=_empty_evidence(), dry_run=True,
        )
        result = await dispatcher.dispatch(task, ctx)
        assert result.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert result.tool_result_dict["category"] == "docker"

    @pytest.mark.asyncio
    async def test_missing_executor_returns_tool_unavailable(self) -> None:
        from apex_host.execution.context import ExecutionContext
        from apex_host.execution.dispatcher import TaskDispatcher
        from apex_host.execution.dispositions import ExecutionDisposition
        from apex_host.execution.registry import TaskRegistry
        from apex_host.policy import PolicyAdvisor, load_policy

        config = ApexConfig(target=_TARGET, dry_run=True)
        dispatcher = TaskDispatcher(
            advisor=PolicyAdvisor(load_policy(config), config),
            task_registry=TaskRegistry(), config=config,
            run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type,return-value]
            # priv_esc_analysis_executor intentionally omitted
        )
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="priv_esc",
            params={"tool": "priv_esc_analyze", "target": _TARGET, "args": ["docker", "root"], "parser": "priv_esc"},
            phase="priv_esc",
        )
        ctx = ExecutionContext(
            run_id="r1", phase="priv_esc", turn_number=1, evidence_version=None,
            subgraph=_subgraph(), evidence=_empty_evidence(), dry_run=True,
        )
        result = await dispatcher.dispatch(task, ctx)
        assert result.disposition is ExecutionDisposition.TOOL_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_two_distinct_analytical_tasks_do_not_collide_as_duplicates(self) -> None:
        """docker and sudo candidates for the same user must fingerprint
        differently — args must encode the discriminator (regression guard
        for a real bug found during manual verification: an empty args list
        made every analytical task fingerprint-identical)."""
        from apex_host.execution.context import ExecutionContext
        from apex_host.execution.dispositions import ExecutionDisposition

        config = ApexConfig(target=_TARGET, dry_run=True)
        dispatcher = _build_dispatcher_with_priv_esc_executor(config)
        ctx = ExecutionContext(
            run_id="r1", phase="priv_esc", turn_number=1, evidence_version=None,
            subgraph=_subgraph(), evidence=_empty_evidence(), dry_run=True,
        )

        def _mk(category: str, discriminator: str) -> TaskSpec:
            return TaskSpec(
                id=f"t-{category}", goal_id="g1", executor_domain="priv_esc",
                params={
                    "tool": "priv_esc_analyze", "target": _TARGET,
                    "args": [category, discriminator], "parser": "priv_esc",
                    "category": category, "confidence": "high", "description": "d",
                    "recommended_next_action": "r", "discriminator": discriminator,
                    "evidence_source": "id_groups", "evidence_excerpt": "", "source_node_id": "",
                },
                phase="priv_esc",
            )

        r1 = await dispatcher.dispatch(_mk("docker", "docker-group-root"), ctx)
        r2 = await dispatcher.dispatch(_mk("sudo", "sudo-group-root"), ctx)
        assert r1.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert r2.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert r1.fingerprint != r2.fingerprint


class TestPolicyBoundedPrivEscEnumeration:
    def test_priv_esc_analyze_approved_against_target(self) -> None:
        from apex_host.policy.rules import check_bounded_priv_esc_enumeration
        from apex_host.policy.models import ScopePolicy

        config = ApexConfig(target=_TARGET, dry_run=True)
        policy = ScopePolicy(
            allowed_targets=frozenset({_TARGET}), blocked_tools=frozenset(),
            allow_password_lists=False, allow_sensitive_data_access=False,
            require_review_for=[], policy_loaded=False, policy_source="test",
        )
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="priv_esc",
            params={"tool": "priv_esc_analyze", "target": _TARGET}, phase="priv_esc",
        )
        decision = check_bounded_priv_esc_enumeration(task, policy, config)
        assert decision is not None
        assert decision.status.value == "approved"
        assert decision.rule_name == "bounded_priv_esc_enumeration"

    def test_searchsploit_approved_against_target(self) -> None:
        from apex_host.policy.rules import check_bounded_priv_esc_enumeration
        from apex_host.policy.models import ScopePolicy

        config = ApexConfig(target=_TARGET, dry_run=True)
        policy = ScopePolicy(
            allowed_targets=frozenset({_TARGET}), blocked_tools=frozenset(),
            allow_password_lists=False, allow_sensitive_data_access=False,
            require_review_for=[], policy_loaded=False, policy_source="test",
        )
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="priv_esc",
            params={"tool": "searchsploit", "target": _TARGET}, phase="priv_esc",
        )
        decision = check_bounded_priv_esc_enumeration(task, policy, config)
        assert decision is not None
        assert decision.status.value == "approved"

    def test_unrelated_tool_returns_none(self) -> None:
        from apex_host.policy.rules import check_bounded_priv_esc_enumeration
        from apex_host.policy.models import ScopePolicy

        config = ApexConfig(target=_TARGET, dry_run=True)
        policy = ScopePolicy(
            allowed_targets=frozenset({_TARGET}), blocked_tools=frozenset(),
            allow_password_lists=False, allow_sensitive_data_access=False,
            require_review_for=[], policy_loaded=False, policy_source="test",
        )
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="recon",
            params={"tool": "nmap", "target": _TARGET}, phase="recon",
        )
        assert check_bounded_priv_esc_enumeration(task, policy, config) is None

    def test_off_scope_target_falls_through(self) -> None:
        from apex_host.policy.rules import check_bounded_priv_esc_enumeration
        from apex_host.policy.models import ScopePolicy

        config = ApexConfig(target=_TARGET, dry_run=True)
        policy = ScopePolicy(
            allowed_targets=frozenset({_TARGET}), blocked_tools=frozenset(),
            allow_password_lists=False, allow_sensitive_data_access=False,
            require_review_for=[], policy_loaded=False, policy_source="test",
        )
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="priv_esc",
            params={"tool": "priv_esc_analyze", "target": "10.99.99.99"}, phase="priv_esc",
        )
        assert check_bounded_priv_esc_enumeration(task, policy, config) is None

    def test_hydra_never_approved_by_this_rule(self) -> None:
        """Sanity guard: this rule's tool allowlist is exactly two names —
        a mistaken future reuse for an exploitation tool has no effect."""
        from apex_host.policy.rules import check_bounded_priv_esc_enumeration
        from apex_host.policy.models import ScopePolicy

        config = ApexConfig(target=_TARGET, dry_run=True)
        policy = ScopePolicy(
            allowed_targets=frozenset({_TARGET}), blocked_tools=frozenset(),
            allow_password_lists=False, allow_sensitive_data_access=False,
            require_review_for=[], policy_loaded=False, policy_source="test",
        )
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="priv_esc",
            params={"tool": "hydra", "target": _TARGET}, phase="priv_esc",
        )
        assert check_bounded_priv_esc_enumeration(task, policy, config) is None


# ---------------------------------------------------------------------------
# 7. PrivEscPlanner — ranking, dedup, exhaustion
# ---------------------------------------------------------------------------

class TestPrivEscPlannerDeterministic:
    @pytest.mark.asyncio
    async def test_no_searchsploit_no_analytical_abandons_with_searchsploit_reason(self) -> None:
        reg = _registry("nmap")
        core = _PrivEscDeterministic(_TARGET, reg)
        result = await core.plan(_goal(), _subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "searchsploit" in result.reason

    @pytest.mark.asyncio
    async def test_emits_searchsploit_task_for_versioned_service(self) -> None:
        reg = _registry("searchsploit")
        core = _PrivEscDeterministic(_TARGET, reg)
        svc = _service_node("22", "ssh", "7.6p1")
        result = await core.plan(_goal(), _subgraph(svc), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "searchsploit"
        assert result[0].params["service"] == "ssh"
        assert result[0].params["version"] == "7.6p1"

    @pytest.mark.asyncio
    async def test_emits_analytical_task_for_docker_group_hint(self) -> None:
        reg = _registry("nmap")  # no searchsploit — analytical path is independent
        core = _PrivEscDeterministic(_TARGET, reg)
        access = _access_state_node(evidence="groups=1000(user),999(docker)")
        result = await core.plan(_goal(), _subgraph(access), _empty_evidence())
        assert isinstance(result, list)
        assert any(t.params["tool"] == "priv_esc_analyze" for t in result)

    @pytest.mark.asyncio
    async def test_does_not_reemit_already_recorded_searchsploit_opportunity(self) -> None:
        """Core duplicate-prevention proof: once an opportunity node exists
        for a service+version, the planner must not emit that task again."""
        reg = _registry("searchsploit")
        core = _PrivEscDeterministic(_TARGET, reg)
        svc = _service_node("21", "ftp", "vsftpd 2.3.4")
        already_recorded = _node(
            priv_esc_opportunity_id(_TARGET, "vulnerable_service", "ftp vsftpd 2.3.4"),
            "priv_esc_opportunity",
            {"category": "vulnerable_service", "confidence": "high", "exhausted": True, "attempted": True},
        )
        result = await core.plan(_goal(), _subgraph(svc, already_recorded), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "exhausted" in result.reason

    @pytest.mark.asyncio
    async def test_does_not_reemit_already_recorded_analytical_opportunity(self) -> None:
        reg = _registry("nmap")
        core = _PrivEscDeterministic(_TARGET, reg)
        access = _access_state_node(evidence="groups=1000(user),999(docker)")
        already_recorded = _node(
            priv_esc_opportunity_id(_TARGET, "docker", "docker-group-root"),
            "priv_esc_opportunity",
            {"category": "docker", "confidence": "high", "exhausted": True, "attempted": True},
        )
        result = await core.plan(_goal(), _subgraph(access, already_recorded), _empty_evidence())
        assert isinstance(result, AbandonSignal)

    @pytest.mark.asyncio
    async def test_no_hit_searchsploit_result_also_prevents_reemission(self) -> None:
        """A 'none' category node (searched, nothing found) must also block
        re-searching the same service/version."""
        reg = _registry("searchsploit")
        core = _PrivEscDeterministic(_TARGET, reg)
        svc = _service_node("8080", "http", "CustomApp 1.0")
        already_recorded = _node(
            priv_esc_opportunity_id(_TARGET, "none", "http CustomApp 1.0"),
            "priv_esc_opportunity",
            {"category": "none", "confidence": "none", "exhausted": True, "attempted": True},
        )
        result = await core.plan(_goal(), _subgraph(svc, already_recorded), _empty_evidence())
        assert isinstance(result, AbandonSignal)

    @pytest.mark.asyncio
    async def test_max_tasks_per_turn_bounded(self) -> None:
        reg = _registry("searchsploit")
        core = _PrivEscDeterministic(_TARGET, reg)
        services = [_service_node(str(1000 + i), f"svc{i}", f"1.{i}") for i in range(10)]
        result = await core.plan(_goal(), _subgraph(*services), _empty_evidence())
        assert isinstance(result, list)
        assert len(result) <= 3

    @pytest.mark.asyncio
    async def test_analytical_and_searchsploit_can_coexist_in_one_turn(self) -> None:
        reg = _registry("searchsploit")
        core = _PrivEscDeterministic(_TARGET, reg)
        access = _access_state_node(evidence="groups=1000(user),999(docker)")
        svc = _service_node("21", "ftp", "vsftpd 2.3.4")
        result = await core.plan(_goal(), _subgraph(access, svc), _empty_evidence())
        assert isinstance(result, list)
        tools = {t.params["tool"] for t in result}
        assert "priv_esc_analyze" in tools
        assert "searchsploit" in tools

    @pytest.mark.asyncio
    async def test_searchsploit_task_has_version_and_service_claim_dependencies(self) -> None:
        """Preserves pre-Phase-13 contract (test_r49 in test_conflict_phase2_reopen.py)."""
        reg = _registry("searchsploit")
        core = _PrivEscDeterministic(_TARGET, reg)
        svc = _service_node("22", "ssh", "OpenSSH 7.4")
        result = await core.plan(_goal(), _subgraph(svc), _empty_evidence())
        dep_fields = {d.field_name for t in result for d in t.claim_dependencies}
        assert "version" in dep_fields
        assert "service" in dep_fields

    @pytest.mark.asyncio
    async def test_no_service_version_no_analytical_signal_original_message(self) -> None:
        reg = _registry("searchsploit")
        core = _PrivEscDeterministic(_TARGET, reg)
        svc = _service_node("80", "http")  # no version
        result = await core.plan(_goal(), _subgraph(svc), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "no enumerable service/version strings" in result.reason

    @pytest.mark.asyncio
    async def test_ranking_prefers_higher_capability_confidence_service_first(self) -> None:
        """Two versioned services -> the one whose capability confidence is
        higher (from a higher-confidence service node) is emitted first
        when both would fit the per-turn cap but ordering is observable."""
        reg = _registry("searchsploit")
        core = _PrivEscDeterministic(_TARGET, reg)
        low_conf_svc = _node(
            f"service:{_TARGET}:9001/tcp", "service",
            {"port": "9001", "proto": "tcp", "service": "alpha", "state": "open", "version": "1.0"},
            confidence=0.3,
        )
        high_conf_svc = _node(
            f"service:{_TARGET}:9002/tcp", "service",
            {"port": "9002", "proto": "tcp", "service": "beta", "state": "open", "version": "2.0"},
            confidence=0.95,
        )
        result = await core.plan(_goal(), _subgraph(low_conf_svc, high_conf_svc), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["service"] == "beta"


class TestPrivEscPlannerWrapper:
    @pytest.mark.asyncio
    async def test_deterministic_by_default(self) -> None:
        reg = _registry("searchsploit")
        planner = PrivEscPlanner(_TARGET, reg)
        assert planner._engine is None
        result = await planner.plan(_goal(), _subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert planner.last_decision is not None
        assert planner.last_decision.phase == "priv_esc"


# ---------------------------------------------------------------------------
# 8. Full graph integration
# ---------------------------------------------------------------------------

def _make_initial_state(target: str, run_id: str = "run-p13", phase: str = "priv_esc") -> dict[str, Any]:
    return {
        "run_id": run_id, "target": target, "phase": phase,
        "goal": f"Enumerate privilege-escalation surface on {target}",
        "current_task": None, "evidence_summary": "", "findings": [],
        "error_episodes": [], "last_tool_result": None, "last_error": None,
        "completed": False, "turn_count": 0, "planner_decisions": [],
        "tool_results": None, "repair_count": 0, "policy_decisions": [],
        "duplicate_actions": [], "completed_fingerprints": [],
        "execution_backend_log": [], "diagnostic_events": [],
        "credential_validation_log": [], "outcome": "", "termination_reason": "",
        "termination_phase": "", "stall_reason": "", "privilege_state": "",
        "privilege_summary": {}, "opportunity_ids": [], "attempted_opportunities": [],
        "enumeration_complete": False,
    }


class TestFullGraphIntegration:
    async def test_searchsploit_and_analytical_opportunities_persisted(self) -> None:
        from apex_host.graph import build_apex_graph

        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))
        svc_id = f"service:{_TARGET}:21/tcp"
        await api.upsert_node(Node(
            id=svc_id, type="service",
            props={"port": "21", "proto": "tcp", "service": "ftp", "state": "open", "version": "vsftpd 2.3.4"},
            confidence=0.9, source="t", first_seen=ts, last_seen=ts,
        ))
        await api.upsert_edge(Edge(id="e1", from_id=h_id, to_id=svc_id, type="exposes", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))
        access_id = f"access_state:{_TARGET}:root:ssh"
        await api.upsert_node(Node(
            id=access_id, type="access_state",
            props={"level": "user", "username": "root", "target": _TARGET, "service": "ssh",
                   "evidence": "uid=0(root) groups=0(root),27(sudo),999(docker)", "proof": "uid=0(root)"},
            confidence=0.85, source="ssh", first_seen=ts, last_seen=ts,
        ))
        await api.upsert_edge(Edge(id="e2", from_id=h_id, to_id=access_id, type="exposes", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))

        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=2, allowed_tools=["nmap", "curl", "nc", "searchsploit"])
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        subgraph = await api.get_subgraph(h_id, depth=10)
        opps = opportunities_from_subgraph(subgraph)
        categories = {o.category.value for o in opps}
        assert "docker" in categories
        assert "sudo" in categories
        # searchsploit ran too (dry-run synthesises "no results" — category none)
        assert any(o.category.value in ("vulnerable_service", "none") for o in opps)
        del final_state

    async def test_no_duplicate_opportunity_across_multiple_turns(self) -> None:
        """Running two priv_esc turns in a row must not double-record the
        same opportunity — the planner's own EKG dedup must prevent it
        (not merely rely on the generic TaskDispatcher fingerprint gate)."""
        from apex_host.orchestration.dependencies import build_planners
        from apex_host.types import ApexPhase

        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))
        access_id = f"access_state:{_TARGET}:root"
        await api.upsert_node(Node(
            id=access_id, type="access_state",
            props={"level": "user", "username": "root", "target": _TARGET,
                   "evidence": "groups=1000(root),999(docker)", "proof": ""},
            confidence=0.85, source="ssh", first_seen=ts, last_seen=ts,
        ))
        await api.upsert_edge(Edge(id="e1", from_id=h_id, to_id=access_id, type="exposes", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))

        config = ApexConfig(target=_TARGET, dry_run=True, allowed_tools=["nmap"])
        registry = ToolRegistry.from_config(config)
        planners = build_planners(config, registry)
        planner = planners[ApexPhase.priv_esc.value]

        subgraph1 = await api.get_subgraph(h_id, depth=10)
        goal = _goal()
        result1 = await planner.plan(goal, subgraph1, _empty_evidence())
        assert isinstance(result1, list) and len(result1) >= 1

        # Simulate parse_observation writing the resulting deltas.
        from apex_host.orchestration.parsing_node import parse_single_result
        tr = {
            "tool": "priv_esc_analyze", "parser": "priv_esc", "target": _TARGET,
            "category": result1[0].params["category"], "confidence": result1[0].params["confidence"],
            "description": result1[0].params["description"],
            "recommended_next_action": result1[0].params["recommended_next_action"],
            "discriminator": result1[0].params["discriminator"],
            "evidence_source": result1[0].params["evidence_source"],
            "evidence_excerpt": result1[0].params["evidence_excerpt"],
            "source_node_id": result1[0].params["source_node_id"],
        }
        state_stub = {"target": _TARGET}
        parsed, _src = parse_single_result(tr, state_stub)  # type: ignore[arg-type]
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)

        subgraph2 = await api.get_subgraph(h_id, depth=10)
        result2 = await planner.plan(goal, subgraph2, _empty_evidence())
        # The specific opportunity just recorded must not be re-emitted.
        recorded_discriminator = result1[0].params["discriminator"]
        if isinstance(result2, list):
            assert all(t.params.get("discriminator") != recorded_discriminator for t in result2)


# ---------------------------------------------------------------------------
# 9. Report — privilege escalation summary
# ---------------------------------------------------------------------------

def _empty_report_subgraph() -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)


class TestReportPrivilegeEscalationSummary:
    def _state(self) -> dict[str, Any]:
        return _make_initial_state(_TARGET)

    def test_no_opportunities_privilege_state_empty(self) -> None:
        state = self._state()
        state["completed"] = True
        state["outcome"] = "max_turns_exhausted"
        config = ApexConfig(target=_TARGET, dry_run=True)
        report = build_report(state, _empty_report_subgraph(), config)
        assert report.privilege_opportunity_count == 0
        assert report.privilege_state == ""

    def test_opportunities_in_subgraph_reflected_in_report(self) -> None:
        state = self._state()
        state["completed"] = True
        state["outcome"] = "validated_access"
        opp = _node(
            priv_esc_opportunity_id(_TARGET, "sudo", "root"), "priv_esc_opportunity",
            {
                "target": _TARGET, "category": "sudo", "confidence": "medium",
                "description": "d", "recommended_next_action": "manually run sudo -l",
                "attempted": True, "attempt_count": 1, "exhausted": False,
                "evidence_source": "id_groups", "evidence_excerpt": "", "evidence_timestamp": now(),
            },
        )
        subgraph = _subgraph(opp)
        config = ApexConfig(target=_TARGET, dry_run=True)
        report = build_report(state, subgraph, config)
        assert report.privilege_opportunity_count == 1
        assert report.privilege_categories == {"sudo": 1}
        assert report.privilege_remaining_count == 1
        assert report.privilege_exhausted_count == 0
        assert report.privilege_enumeration_complete is False
        assert "manually run sudo -l" in report.privilege_recommendations

    def test_all_exhausted_marks_enumeration_complete(self) -> None:
        state = self._state()
        state["completed"] = True
        state["outcome"] = "phase_budget_exhausted"
        opp = _node(
            priv_esc_opportunity_id(_TARGET, "none", "ftp-x"), "priv_esc_opportunity",
            {
                "target": _TARGET, "category": "none", "confidence": "none",
                "description": "d", "recommended_next_action": "r",
                "attempted": True, "attempt_count": 1, "exhausted": True,
                "evidence_source": "searchsploit", "evidence_excerpt": "", "evidence_timestamp": now(),
            },
        )
        subgraph = _subgraph(opp)
        config = ApexConfig(target=_TARGET, dry_run=True)
        report = build_report(state, subgraph, config)
        assert report.privilege_enumeration_complete is True
        assert report.privilege_recommendations == []

    def test_format_text_includes_privilege_section_when_present(self) -> None:
        state = self._state()
        state["completed"] = True
        state["outcome"] = "validated_access"
        opp = _node(
            priv_esc_opportunity_id(_TARGET, "docker", "root"), "priv_esc_opportunity",
            {
                "target": _TARGET, "category": "docker", "confidence": "high",
                "description": "user in docker group", "recommended_next_action": "manually verify docker escalation",
                "attempted": True, "attempt_count": 1, "exhausted": False,
                "evidence_source": "id_groups", "evidence_excerpt": "", "evidence_timestamp": now(),
            },
        )
        config = ApexConfig(target=_TARGET, dry_run=True)
        report = build_report(state, _subgraph(opp), config)
        text = format_text(report)
        assert "Privilege Escalation Summary" in text
        assert "Opportunity count  : 1" in text
        assert "docker=1" in text
        assert "manually verify docker escalation" in text

    def test_format_text_omits_section_when_no_state(self) -> None:
        state = self._state()
        state["completed"] = True
        state["outcome"] = "max_turns_exhausted"
        config = ApexConfig(target=_TARGET, dry_run=True)
        report = build_report(state, _empty_report_subgraph(), config)
        text = format_text(report)
        assert "Privilege Escalation Summary" not in text

    def test_json_dict_includes_privilege_escalation_block(self) -> None:
        state = self._state()
        state["completed"] = True
        state["outcome"] = "validated_access"
        opp = _node(
            priv_esc_opportunity_id(_TARGET, "vulnerable_service", "ftp-vsftpd-2-3-4"), "priv_esc_opportunity",
            {
                "target": _TARGET, "category": "vulnerable_service", "confidence": "high",
                "description": "2 known exploit-db entries", "recommended_next_action": "manually review",
                "attempted": True, "attempt_count": 1, "exhausted": True,
                "evidence_source": "searchsploit", "evidence_excerpt": "title one; title two", "evidence_timestamp": now(),
            },
        )
        config = ApexConfig(target=_TARGET, dry_run=True)
        report = build_report(state, _subgraph(opp), config)
        data = to_json_dict(report)
        assert "privilege_escalation" in data
        pe = data["privilege_escalation"]
        assert pe["opportunity_count"] == 1
        assert pe["categories"] == {"vulnerable_service": 1}
        assert pe["exhausted_count"] == 1


# ---------------------------------------------------------------------------
# 10. Security / no-exploitation invariants
# ---------------------------------------------------------------------------

class TestNoExploitationInvariants:
    def test_no_metasploit_or_exploit_execution_references_in_priv_esc_modules(self) -> None:
        import pathlib
        root = pathlib.Path(__file__).parent.parent.parent / "apex_host"
        files = [
            root / "planners" / "priv_esc_planner.py",
            root / "planners" / "priv_esc_opportunities.py",
            root / "parsers" / "priv_esc_parser.py",
            root / "agents" / "priv_esc_analysis_executor.py",
        ]
        forbidden = ("msfconsole", "msfvenom", "meterpreter", "reverse_shell", "exec_payload")
        for f in files:
            text = f.read_text().lower()
            for term in forbidden:
                assert term not in text, f"{f} must not reference {term!r}"

    def test_recommended_next_action_never_a_shell_pipe_command(self) -> None:
        """Recommendations are advisory text for a human, never something
        APEX would itself pipe into a shell."""
        parser = PrivEscParser()
        parsed = parser.parse_searchsploit(_SEARCHSPLOIT_HITS, target=_TARGET, service="vsftpd", version="2.3.4")
        action = parsed.node_deltas[0].props["recommended_next_action"]
        # Semicolons are ordinary English punctuation in this advisory text
        # (never executed) — only check for genuine shell-piping/chaining
        # operators that would matter if this string were ever misused as
        # a command.
        for meta in ("&&", "||", "|", "$(", "`"):
            assert meta not in action

    def test_analytical_recommendations_never_contain_shell_metacharacters(self) -> None:
        access = _access_state_node(evidence="groups=1000(user),999(docker),27(sudo)")
        candidates = derive_analytical_opportunities(_subgraph(access))
        for cand in candidates:
            for meta in ("&&", "||", "|", "$(", "`"):
                assert meta not in cand.recommended_next_action

    def test_status_taxonomy_never_silently_claims_elevated_access(self) -> None:
        """No code path in the planner/parser/opportunities modules ever
        *constructs* PrivilegeEnumerationStatus.elevated_access_validated —
        grep-level static proof. Docstrings are allowed to (and do)
        *mention* the member name to document that it is a future
        capability; only the qualified, constructible reference is
        forbidden here."""
        import pathlib
        root = pathlib.Path(__file__).parent.parent.parent / "apex_host"
        files = [
            root / "planners" / "priv_esc_planner.py",
            root / "planners" / "priv_esc_opportunities.py",
            root / "parsers" / "priv_esc_parser.py",
        ]
        for f in files:
            text = f.read_text()
            assert "PrivilegeEnumerationStatus.elevated_access_validated" not in text

    def test_no_secret_leakage_in_opportunity_props(self) -> None:
        access = _access_state_node(evidence="groups=1000(user),999(docker)")
        candidates = derive_analytical_opportunities(_subgraph(access))
        parser = PrivEscParser()
        for cand in candidates:
            parsed = parser.parse_analytical(
                target=_TARGET, category=cand.category, confidence=cand.confidence,
                description=cand.description, recommended_next_action=cand.recommended_next_action,
                discriminator=cand.discriminator, evidence_source=cand.evidence_source,
                evidence_excerpt=cand.evidence_excerpt, source_node_id=cand.source_node_id,
            )
            for node in parsed.node_deltas:
                serialized = str(node.props)
                assert "password" not in serialized.lower()
