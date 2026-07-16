# test_phase15_workflow_orchestration.py
# Regression tests for Phase 15: multi-step exploitation orchestration — workflow construction, dependency ordering, blocked/resumed chains, session tracking, graph links, transaction rollback, and report generation.
"""Phase 15 regression tests.

Covers the reasoning-and-coordination framework introduced in Phase 15: the
``Workflow``/``WorkflowStep``/``Session``/``WorkflowRecommendation`` model
(``apex_host.types``), the pure reasoning helpers in
``apex_host.planners.workflow_orchestration`` (dependency-ordered step
evaluation, ranking, session derivation, recommendation text, graph
materialization), the ``reflect_or_continue`` wiring, and ``RunReport``'s
Workflow Summary.

No exploit is executed, no payload is generated, no reverse shell is
created, no Metasploit is used, no persistence is established, and no flag
is captured by any code exercised here — every test asserts the
*reasoning/coordination* framework's behavior only. No Docker, Compose,
VPN, or GitHub Actions files are touched by this test file or the code it
tests.
"""
from __future__ import annotations

import re
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
from apex_host.graph_ids import host_id, workflow_id
from apex_host.planners.workflow_orchestration import (
    WORKFLOW_TEMPLATES,
    build_workflow_graph_deltas,
    derive_sessions_from_subgraph,
    derive_workflows_from_subgraph,
    rank_sessions,
    rank_workflows,
    workflow_recommendation_text,
    workflow_recommendations_from_workflows,
    workflow_summary_fields,
)
from apex_host.types import (
    SessionKind,
    SessionStatus,
    WorkflowStatus,
    WorkflowStepStatus,
)

_TARGET = "10.10.10.95"
_ANCHOR = f"host:{_TARGET}"

_DOCSTRING_RE = re.compile(r'""".*?"""', re.DOTALL)


def _code_only(source: str) -> str:
    return _DOCSTRING_RE.sub("", source)


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


def _node(node_id: str, node_type: str, props: dict[str, Any], confidence: float = 0.9) -> Node:
    ts = now()
    return Node(id=node_id, type=node_type, props=props, confidence=confidence, source="test", first_seen=ts, last_seen=ts)


def _subgraph(*nodes: Node, edges: list[Edge] | None = None) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=edges or [], depth=2)


def _host_node() -> Node:
    return _node(host_id(_TARGET), "host", {"ip": _TARGET})


def _service_node(port: str = "22", service: str = "ssh") -> Node:
    return _node(
        f"service:{_TARGET}:{port}/tcp", "service",
        {"port": port, "proto": "tcp", "service": service, "state": "open", "version": ""},
    )


def _unclassified_service_node() -> Node:
    """A service node that satisfies the "service" prerequisite without
    granting any access_validate_* capability (unlike port 22/ssh, which
    capabilities.py classifies immediately) — used to test the pure
    "nothing discovered yet" starting state."""
    return _node(
        f"service:{_TARGET}:31337/tcp", "service",
        {"port": "31337", "proto": "tcp", "service": "unknownsvc", "state": "open", "version": ""},
    )


def _endpoint_node(url: str, *, browsed: bool = False) -> Node:
    from apex_host.graph_ids import endpoint_id
    return _node(endpoint_id(url), "endpoint", {"url": url, "target": _TARGET, "browsed": browsed})


def _credential_node(username: str = "root", protocol: str = "ssh") -> Node:
    from apex_host.graph_ids import credential_id
    return _node(
        credential_id(_TARGET, username, protocol=protocol), "credential",
        {"username": username, "secret_hint": "[redacted]", "target": _TARGET, "protocol": protocol},
    )


def _access_state_node(username: str = "root", protocol: str = "ssh") -> Node:
    from apex_host.graph_ids import access_state_id
    return _node(
        access_state_id(_TARGET, username, protocol=protocol), "access_state",
        {"level": "user", "username": username, "target": _TARGET, "service": protocol, "evidence": "uid=0(root)"},
    )


def _priv_esc_opportunity_node() -> Node:
    from apex_host.graph_ids import priv_esc_opportunity_id
    return _node(
        priv_esc_opportunity_id(_TARGET, "sudo", "sudo-group-root"), "priv_esc_opportunity",
        {"category": "sudo", "confidence": "medium", "description": "d", "recommended_next_action": "r"},
    )


def _form_node(url: str = "") -> Node:
    from apex_host.graph_ids import form_id
    url = url or f"http://{_TARGET}"
    return _node(form_id(url, 0), "form", {"action": "/login", "method": "POST", "fields": []})


def _tech_node() -> Node:
    from apex_host.graph_ids import tech_id
    return _node(tech_id(_TARGET, "nginx"), "tech", {"name": "nginx", "version": "1.2"})


def _web_opportunity_node() -> Node:
    from apex_host.graph_ids import web_opportunity_id
    return _node(
        web_opportunity_id(_TARGET, "admin_panel", f"http://{_TARGET}/admin"), "web_opportunity",
        {"category": "admin_panel", "confidence": "medium", "description": "d", "recommended_next_action": "r"},
    )


# ---------------------------------------------------------------------------
# 1. Workflow construction & prerequisites
# ---------------------------------------------------------------------------

class TestWorkflowConstruction:
    def test_no_prerequisites_no_workflows(self) -> None:
        workflows = derive_workflows_from_subgraph(_TARGET, _subgraph())
        assert workflows == []

    def test_credential_workflow_requires_host_and_service(self) -> None:
        workflows = derive_workflows_from_subgraph(_TARGET, _subgraph(_host_node()))
        assert not any(w.key == "credential_to_privesc" for w in workflows)
        workflows = derive_workflows_from_subgraph(_TARGET, _subgraph(_host_node(), _service_node()))
        assert any(w.key == "credential_to_privesc" for w in workflows)

    def test_web_workflow_requires_host_and_endpoint(self) -> None:
        workflows = derive_workflows_from_subgraph(_TARGET, _subgraph(_host_node()))
        assert not any(w.key == "web_discovery_to_opportunity" for w in workflows)
        workflows = derive_workflows_from_subgraph(
            _TARGET, _subgraph(_host_node(), _endpoint_node(f"http://{_TARGET}"))
        )
        assert any(w.key == "web_discovery_to_opportunity" for w in workflows)

    def test_workflow_id_content_addressed(self) -> None:
        sg = _subgraph(_host_node(), _service_node())
        w1 = derive_workflows_from_subgraph(_TARGET, sg)[0]
        w2 = derive_workflows_from_subgraph(_TARGET, sg)[0]
        assert w1.id == w2.id == workflow_id(_TARGET, "credential_to_privesc")

    def test_workflow_has_objective_and_prerequisites(self) -> None:
        sg = _subgraph(_host_node(), _service_node())
        wf = derive_workflows_from_subgraph(_TARGET, sg)[0]
        assert wf.objective
        assert wf.prerequisites == ("host", "service")

    def test_empty_subgraph_no_crash(self) -> None:
        assert derive_workflows_from_subgraph(_TARGET, _subgraph()) == []


# ---------------------------------------------------------------------------
# 2. Dependency ordering — later stages cannot begin until prerequisites exist
# ---------------------------------------------------------------------------

class TestDependencyOrdering:
    def test_all_steps_pending_or_blocked_with_only_prerequisites(self) -> None:
        sg = _subgraph(_host_node(), _unclassified_service_node())
        wf = derive_workflows_from_subgraph(_TARGET, sg)[0]
        assert wf.steps[0].status is WorkflowStepStatus.pending
        for step in wf.steps[1:]:
            assert step.status is WorkflowStepStatus.blocked

    def test_second_step_unlocked_only_after_first_completes(self) -> None:
        sg = _subgraph(_host_node(), _unclassified_service_node(), _access_state_node())
        # access_state alone does NOT satisfy discover_login (no auth_flow,
        # no access_validate_* capability derivable from this minimal
        # fixture) — validate_credentials must stay blocked until
        # discover_login completes, proving the dependency gate is real.
        wf = next(w for w in derive_workflows_from_subgraph(_TARGET, sg) if w.key == "credential_to_privesc")
        assert wf.steps[0].status is WorkflowStepStatus.pending
        assert wf.steps[1].status is WorkflowStepStatus.blocked

    def test_full_chain_progresses_in_order(self) -> None:
        sg = _subgraph(
            _host_node(), _service_node(), _access_state_node(), _priv_esc_opportunity_node(),
        )
        wf = derive_workflows_from_subgraph(_TARGET, sg)[0]
        # discover_login completes via the access_validate_ssh capability
        # derived from the service node.
        assert wf.steps[0].status is WorkflowStepStatus.completed
        assert wf.steps[1].status is WorkflowStepStatus.completed  # validate_credentials
        assert wf.steps[2].status is WorkflowStepStatus.completed  # enumerate_privilege
        assert wf.steps[3].status is WorkflowStepStatus.completed  # generate_recommendations
        assert wf.status is WorkflowStatus.completed

    def test_web_chain_dependency_ordering(self) -> None:
        sg = _subgraph(_host_node(), _endpoint_node(f"http://{_TARGET}"), _web_opportunity_node())
        # identify_opportunity node exists, but discover_form/inspect_technology
        # do not — identify_opportunity must stay blocked regardless.
        wf = next(w for w in derive_workflows_from_subgraph(_TARGET, sg) if w.key == "web_discovery_to_opportunity")
        assert wf.steps[0].status is WorkflowStepStatus.pending  # discover_form
        assert wf.steps[1].status is WorkflowStepStatus.blocked  # inspect_technology
        assert wf.steps[2].status is WorkflowStepStatus.blocked  # identify_opportunity


# ---------------------------------------------------------------------------
# 3. Blocked chains (failed prerequisite)
# ---------------------------------------------------------------------------

class TestBlockedChains:
    def test_failed_credential_attempt_blocks_workflow(self) -> None:
        sg = _subgraph(_host_node(), _service_node(), _credential_node())
        wf = derive_workflows_from_subgraph(_TARGET, sg)[0]
        assert wf.steps[1].status is WorkflowStepStatus.failed
        assert wf.steps[2].status is WorkflowStepStatus.blocked
        assert wf.steps[3].status is WorkflowStepStatus.blocked
        assert wf.status is WorkflowStatus.blocked
        assert "validate_credentials" in wf.failed_steps
        assert wf.next_candidate == ""

    def test_blocked_workflow_recommendation_mentions_failed_step(self) -> None:
        sg = _subgraph(_host_node(), _service_node(), _credential_node())
        wf = derive_workflows_from_subgraph(_TARGET, sg)[0]
        text = workflow_recommendation_text(wf)
        assert "blocked" in text.lower()
        assert "validate_credentials" in text


# ---------------------------------------------------------------------------
# 4. Resumed chains — never restart a completed/in-progress chain
# ---------------------------------------------------------------------------

class TestResumedChains:
    def test_adding_evidence_progresses_without_resetting(self) -> None:
        sg1 = _subgraph(_host_node(), _service_node(), _access_state_node())
        wf1 = derive_workflows_from_subgraph(_TARGET, sg1)[0]
        assert wf1.steps[1].status is WorkflowStepStatus.completed
        assert wf1.steps[2].status is WorkflowStepStatus.pending

        sg2 = _subgraph(_host_node(), _service_node(), _access_state_node(), _priv_esc_opportunity_node())
        wf2 = derive_workflows_from_subgraph(_TARGET, sg2)[0]
        # Step 1 (validate_credentials) is still completed — never reset —
        # and step 2 (enumerate_privilege) has now progressed to completed.
        assert wf2.steps[1].status is WorkflowStepStatus.completed
        assert wf2.steps[2].status is WorkflowStepStatus.completed

    def test_completed_workflow_stays_completed_on_rederivation(self) -> None:
        sg = _subgraph(_host_node(), _service_node(), _access_state_node(), _priv_esc_opportunity_node())
        wf1 = derive_workflows_from_subgraph(_TARGET, sg)[0]
        wf2 = derive_workflows_from_subgraph(_TARGET, sg)[0]
        assert wf1.status is wf2.status is WorkflowStatus.completed


# ---------------------------------------------------------------------------
# 5. Sessions — planning objects only
# ---------------------------------------------------------------------------

class TestSessionTracking:
    def test_no_evidence_no_sessions(self) -> None:
        assert derive_sessions_from_subgraph(_TARGET, _subgraph(_host_node())) == []

    def test_browser_session_inactive_without_browsed_page(self) -> None:
        sg = _subgraph(_host_node(), _endpoint_node(f"http://{_TARGET}", browsed=False))
        sessions = derive_sessions_from_subgraph(_TARGET, sg)
        browser = next(s for s in sessions if s.kind is SessionKind.browser)
        assert browser.status is SessionStatus.inactive

    def test_browser_session_active_with_browsed_page(self) -> None:
        sg = _subgraph(_host_node(), _endpoint_node(f"http://{_TARGET}", browsed=True))
        sessions = derive_sessions_from_subgraph(_TARGET, sg)
        browser = next(s for s in sessions if s.kind is SessionKind.browser)
        assert browser.status is SessionStatus.active

    def test_ssh_session_active_with_validated_access_state(self) -> None:
        sg = _subgraph(_host_node(), _access_state_node(protocol="ssh"))
        sessions = derive_sessions_from_subgraph(_TARGET, sg)
        ssh = next(s for s in sessions if s.kind is SessionKind.ssh)
        assert ssh.status is SessionStatus.active

    def test_ftp_session_attempted_when_credential_only(self) -> None:
        sg = _subgraph(_host_node(), _credential_node(protocol="ftp"))
        sessions = derive_sessions_from_subgraph(_TARGET, sg)
        ftp = next(s for s in sessions if s.kind is SessionKind.ftp)
        assert ftp.status is SessionStatus.attempted

    def test_telnet_session_matches_legacy_no_protocol_tag(self) -> None:
        from apex_host.graph_ids import access_state_id
        legacy_access = _node(
            access_state_id(_TARGET, "root"), "access_state",
            {"level": "user", "username": "root", "target": _TARGET, "service": "telnet"},
        )
        sg = _subgraph(_host_node(), legacy_access)
        sessions = derive_sessions_from_subgraph(_TARGET, sg)
        telnet = next(s for s in sessions if s.kind is SessionKind.telnet)
        assert telnet.status is SessionStatus.active

    def test_credential_session_aggregates_all_protocols(self) -> None:
        sg = _subgraph(_host_node(), _credential_node(protocol="ssh"), _credential_node(username="anon", protocol="ftp"))
        sessions = derive_sessions_from_subgraph(_TARGET, sg)
        cred = next(s for s in sessions if s.kind is SessionKind.credential)
        assert "ssh" in cred.detail
        assert "ftp" in cred.detail

    def test_no_secret_in_session_detail(self) -> None:
        sg = _subgraph(_host_node(), _access_state_node())
        sessions = derive_sessions_from_subgraph(_TARGET, sg)
        for s in sessions:
            assert "hunter2" not in s.detail

    def test_sessions_ranked_deterministically(self) -> None:
        sg = _subgraph(
            _host_node(), _access_state_node(protocol="ssh"),
            _credential_node(username="anon", protocol="ftp"),
            _endpoint_node(f"http://{_TARGET}", browsed=True),
        )
        s1 = [s.id for s in rank_sessions(derive_sessions_from_subgraph(_TARGET, sg))]
        s2 = [s.id for s in rank_sessions(derive_sessions_from_subgraph(_TARGET, sg))]
        assert s1 == s2


# ---------------------------------------------------------------------------
# 6. Ranking / deterministic execution / template ordering
# ---------------------------------------------------------------------------

class TestDeterministicOrdering:
    def test_workflow_templates_fixed_order(self) -> None:
        keys = [w.key for w in WORKFLOW_TEMPLATES]
        assert keys == ["credential_to_privesc", "web_discovery_to_opportunity"]

    def test_derive_workflows_deterministic_across_calls(self) -> None:
        sg = _subgraph(_host_node(), _service_node(), _endpoint_node(f"http://{_TARGET}"))
        r1 = [w.key for w in derive_workflows_from_subgraph(_TARGET, sg)]
        r2 = [w.key for w in derive_workflows_from_subgraph(_TARGET, sg)]
        assert r1 == r2

    def test_rank_workflows_running_before_completed(self) -> None:
        sg_running = _subgraph(_host_node(), _service_node())
        sg_completed = _subgraph(_host_node(), _service_node(), _access_state_node(), _priv_esc_opportunity_node())
        running_wf = derive_workflows_from_subgraph(_TARGET, sg_running)[0]
        completed_wf = derive_workflows_from_subgraph(_TARGET, sg_completed)[0]
        ranked = rank_workflows([completed_wf, running_wf])
        assert ranked[0].status is WorkflowStatus.running

    def test_rank_workflows_never_random(self) -> None:
        sg = _subgraph(_host_node(), _service_node(), _endpoint_node(f"http://{_TARGET}"))
        workflows = derive_workflows_from_subgraph(_TARGET, sg)
        assert [w.id for w in rank_workflows(workflows)] == [w.id for w in rank_workflows(list(reversed(workflows)))]


# ---------------------------------------------------------------------------
# 7. MemoryAPI integration — graph links, dedup, transaction rollback
# ---------------------------------------------------------------------------

async def _seed_host_and_ssh_service(api: MemoryAPI) -> str:
    """Seed a host + SSH service node WITH the exposes edge linking them —
    without this edge the service node is an orphan, invisible to
    get_subgraph()'s bounded traversal (the exact class of bug Phase
    13/14 each hit for their own new node types)."""
    ts = now()
    h_id = host_id(_TARGET)
    svc_id = f"service:{_TARGET}:22/tcp"
    await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))
    await api.upsert_node(Node(
        id=svc_id, type="service",
        props={"port": "22", "proto": "tcp", "service": "ssh", "state": "open", "version": ""},
        confidence=0.9, source="t", first_seen=ts, last_seen=ts,
    ))
    await api.upsert_edge(Edge(
        id=f"exposes:{h_id}:{svc_id}", from_id=h_id, to_id=svc_id, type="exposes",
        props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts,
    ))
    return h_id


class TestMemoryApiIntegration:
    @pytest.mark.asyncio
    async def test_full_chain_persisted_and_linked(self) -> None:
        api = _make_api()
        h_id = await _seed_host_and_ssh_service(api)

        subgraph = await api.get_subgraph(h_id, depth=10)
        workflows = derive_workflows_from_subgraph(_TARGET, subgraph)
        sessions = derive_sessions_from_subgraph(_TARGET, subgraph)
        nodes, edges = build_workflow_graph_deltas(_TARGET, workflows, sessions)
        await api.apply_deltas(nodes=nodes, edges=edges)

        subgraph2 = await api.get_subgraph(h_id, depth=10)
        types = {n.type for n in subgraph2.nodes}
        assert {"workflow", "workflow_step", "workflow_recommendation"}.issubset(types)
        edge_types = {e.type for e in subgraph2.edges}
        assert {"indicates", "contains", "recommends"}.issubset(edge_types)

    @pytest.mark.asyncio
    async def test_reapplying_same_state_upserts_not_duplicates(self) -> None:
        api = _make_api()
        h_id = await _seed_host_and_ssh_service(api)

        for _ in range(2):
            subgraph = await api.get_subgraph(h_id, depth=10)
            workflows = derive_workflows_from_subgraph(_TARGET, subgraph)
            sessions = derive_sessions_from_subgraph(_TARGET, subgraph)
            nodes, edges = build_workflow_graph_deltas(_TARGET, workflows, sessions)
            await api.apply_deltas(nodes=nodes, edges=edges)

        final_subgraph = await api.get_subgraph(h_id, depth=10)
        workflow_nodes = [n for n in final_subgraph.nodes if n.type == "workflow"]
        assert len(workflow_nodes) == 1

    @pytest.mark.asyncio
    async def test_transaction_rollback_on_dangling_edge(self) -> None:
        api = _make_api()
        h_id = await _seed_host_and_ssh_service(api)
        ts = now()
        subgraph = await api.get_subgraph(h_id, depth=10)
        workflows = derive_workflows_from_subgraph(_TARGET, subgraph)
        sessions = derive_sessions_from_subgraph(_TARGET, subgraph)
        nodes, edges = build_workflow_graph_deltas(_TARGET, workflows, sessions)
        assert nodes  # sanity: prerequisites were met, so there IS something to roll back

        bad_edge = Edge(
            id="indicates:bogus:missing", from_id="host:does-not-exist", to_id=nodes[0].id,
            type="indicates", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts,
        )
        with pytest.raises(ValueError):
            await api.apply_deltas(nodes=nodes, edges=[*edges, bad_edge])

        final_subgraph = await api.get_subgraph(h_id, depth=10)
        assert not any(n.type == "workflow" for n in final_subgraph.nodes)

    @pytest.mark.asyncio
    async def test_workflow_summary_fields_returns_expected_keys(self) -> None:
        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))
        subgraph = await api.get_subgraph(h_id, depth=10)
        fields = workflow_summary_fields(_TARGET, subgraph)
        assert "workflow_summary" in fields
        for key in ("workflow_count", "status_counts", "active_session_count"):
            assert key in fields["workflow_summary"]


# ---------------------------------------------------------------------------
# 8. Report — Workflow Summary
# ---------------------------------------------------------------------------

def _base_config() -> ApexConfig:
    return ApexConfig(target=_TARGET, dry_run=True, max_turns=5)


def _final_state(*, completed: bool = True, planner_decisions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "target": _TARGET, "phase": "done", "completed": completed, "turn_count": 1,
        "last_error": None, "findings": [], "error_episodes": [],
        "planner_decisions": planner_decisions or [],
        "policy_decisions": [], "duplicate_actions": [], "credential_validation_log": [],
        "execution_backend_log": [], "outcome": "validated_access",
        "termination_reason": "", "termination_phase": "done", "stall_reason": "",
        "privilege_state": "", "enumeration_complete": False, "web_session_state": {},
        "workflow_summary": {},
    }


class TestReportWorkflowSummary:
    def test_no_prerequisites_no_section(self) -> None:
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=_subgraph(_host_node()))
        assert report.workflow_count == 0
        assert "Workflow Summary" not in format_text(report)

    def test_running_workflow_counted(self) -> None:
        sg = _subgraph(_host_node(), _service_node())
        report = build_report(config=_base_config(), final_state=_final_state(completed=False), subgraph=sg)
        assert report.workflow_count == 1
        assert report.workflows_running == 1

    def test_completed_workflow_counted(self) -> None:
        sg = _subgraph(_host_node(), _service_node(), _access_state_node(), _priv_esc_opportunity_node())
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=sg)
        assert report.workflows_completed == 1
        assert report.workflow_completion_percentage == 100.0

    def test_blocked_workflow_counted(self) -> None:
        sg = _subgraph(_host_node(), _service_node(), _credential_node())
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=sg)
        assert report.workflows_blocked == 1

    def test_abandoned_workflow_when_engagement_completed_without_progress(self) -> None:
        sg = _subgraph(_host_node(), _service_node())
        state = _final_state(completed=True)
        state["outcome"] = "max_turns_exhausted"
        report = build_report(config=_base_config(), final_state=state, subgraph=sg)
        assert report.workflows_abandoned == 1

    def test_active_sessions_reflected(self) -> None:
        sg = _subgraph(_host_node(), _access_state_node(protocol="ssh"))
        report = build_report(config=_base_config(), final_state=_final_state(), subgraph=sg)
        assert any(s["kind"] == "ssh" and s["status"] == "active" for s in report.active_sessions)

    def test_reasoning_chains_include_step_status(self) -> None:
        sg = _subgraph(_host_node(), _service_node())
        report = build_report(config=_base_config(), final_state=_final_state(completed=False), subgraph=sg)
        chain = next(c for c in report.reasoning_chains if c["workflow"] == "credential_to_privesc")
        assert chain["steps"][0]["name"] == "discover_login"

    def test_planner_decisions_counted_in_text(self) -> None:
        sg = _subgraph(_host_node(), _service_node())
        decisions = [
            {"planner_model": "deterministic", "confidence": 1.0, "selected_task_count": 1, "rejected_task_count": 0,
             "reasoning_summary": "x", "fallback_used": True, "timestamp": now(), "phase": "recon"},
            {"planner_model": "llm", "confidence": 0.8, "selected_task_count": 1, "rejected_task_count": 0,
             "reasoning_summary": "y", "fallback_used": False, "timestamp": now(), "phase": "recon"},
        ]
        report = build_report(
            config=_base_config(), final_state=_final_state(completed=False, planner_decisions=decisions), subgraph=sg,
        )
        text = format_text(report)
        assert "Planner decisions" in text
        assert "deterministic=1" in text
        assert "llm=1" in text

    def test_format_text_includes_section_fields(self) -> None:
        sg = _subgraph(_host_node(), _service_node())
        report = build_report(config=_base_config(), final_state=_final_state(completed=False), subgraph=sg)
        text = format_text(report)
        assert "Workflow Summary" in text
        assert "Workflows" in text
        assert "Completion" in text
        assert "Reasoning chains" in text

    def test_json_dict_includes_workflow_orchestration_block(self) -> None:
        sg = _subgraph(_host_node(), _service_node())
        report = build_report(config=_base_config(), final_state=_final_state(completed=False), subgraph=sg)
        d = to_json_dict(report)
        assert "workflow_orchestration" in d
        assert d["workflow_orchestration"]["workflow_count"] == 1


# ---------------------------------------------------------------------------
# 9. No-exploitation invariants
# ---------------------------------------------------------------------------

class TestNoExploitationInvariants:
    def test_no_exploit_or_metasploit_or_reverse_shell_references(self) -> None:
        import pathlib
        root = pathlib.Path(__file__).parent.parent.parent / "apex_host"
        f = root / "planners" / "workflow_orchestration.py"
        forbidden = (
            "msfconsole", "msfvenom", "meterpreter", "reverse_shell",
            "exec_payload", "sqlmap", "<script>alert",
        )
        text = _code_only(f.read_text()).lower()
        for term in forbidden:
            assert term not in text, f"{f} must not reference {term!r}"

    def test_no_subprocess_or_network_calls_in_workflow_orchestration(self) -> None:
        import pathlib
        root = pathlib.Path(__file__).parent.parent.parent / "apex_host"
        source = _code_only((root / "planners" / "workflow_orchestration.py").read_text())
        for term in ("subprocess", "asyncio.create_subprocess", "socket.", "requests.", "playwright"):
            assert term not in source.lower()

    def test_recommendation_text_never_contains_shell_metacharacters(self) -> None:
        sg = _subgraph(_host_node(), _service_node(), _credential_node())
        wf = derive_workflows_from_subgraph(_TARGET, sg)[0]
        text = workflow_recommendation_text(wf)
        for meta in ("&&", "||", "|", "$(", "`"):
            assert meta not in text

    def test_no_secret_leakage_in_persisted_workflow_nodes(self) -> None:
        sg = _subgraph(_host_node(), _service_node(), _access_state_node())
        workflows = derive_workflows_from_subgraph(_TARGET, sg)
        sessions = derive_sessions_from_subgraph(_TARGET, sg)
        nodes, _edges = build_workflow_graph_deltas(_TARGET, workflows, sessions)
        for n in nodes:
            assert "hunter2" not in str(n.props)

    def test_workflow_recommendations_view_matches_text_function(self) -> None:
        sg = _subgraph(_host_node(), _service_node())
        workflows = rank_workflows(derive_workflows_from_subgraph(_TARGET, sg))
        recs = workflow_recommendations_from_workflows(workflows)
        assert recs[0].text == workflow_recommendation_text(workflows[0])
        assert recs[0].workflow_id == workflows[0].id
