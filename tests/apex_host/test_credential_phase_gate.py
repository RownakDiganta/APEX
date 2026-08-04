# test_credential_phase_gate.py
# Tests that credential-phase entry requires an actionable credential hypothesis (never merely a credential-validation capability), that web discovery must produce meaningful evidence before it is complete, and that the workflow accounting blocks (not stalls) a validation step with no hypothesis. Synthetic only — no real network or LLM calls.
"""Regression tests for the credential-evidence phase gate.

Covers ``apex_host.planners.phase_gates`` (the pure credential-hypothesis and
web-evidence gates), the authoritative phase-transition path
(``GlobalPlanner.decide_phase``), the compiled graph's behavior for a
capability-without-hypothesis target, and the workflow blocked-vs-stalled
accounting. RFC 5737 documentation address; every config is ``dry_run=True``;
no real command, network, or LLM call is made.
"""
from __future__ import annotations

from typing import Any

import pytest

from apex_host.config import ApexConfig
from apex_host.planners import phase_gates as pg
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.planners.phase_gates import credential_hypothesis, web_evidence_status
from apex_host.planners.workflow_orchestration import derive_workflows_from_subgraph
from apex_host.types import ApexPhase
from memfabric.ids import now
from memfabric.types import Node, SubgraphView

_HOST = "192.0.2.10"
_ANCHOR = f"host:{_HOST}"


def _node(node_type: str, props: dict[str, Any], node_id: str = "") -> Node:
    ts = now()
    return Node(
        id=node_id or f"{node_type}:{_HOST}:x", type=node_type, props=props,
        confidence=0.8, source="test", first_seen=ts, last_seen=ts,
    )


def _subgraph(*nodes: Node) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=[], depth=2)


# ---------------------------------------------------------------------------
# credential_hypothesis — the four sources + the typed no-hypothesis reason
# ---------------------------------------------------------------------------

class TestCredentialHypothesis:
    def test_operator_credentials(self) -> None:
        h = credential_hypothesis(_subgraph(), has_operator_credentials=True)
        assert h.available is True and h.source == pg.CREDENTIAL_SOURCE_OPERATOR

    def test_discovered_credential_evidence(self) -> None:
        sg = _subgraph(_node("credential", {"username": "svc", "source": "discovered"}))
        h = credential_hypothesis(sg, has_operator_credentials=False)
        assert h.available is True and h.source == pg.CREDENTIAL_SOURCE_DISCOVERED

    def test_discovered_flag_marker(self) -> None:
        sg = _subgraph(_node("credential", {"username": "svc", "discovered": True}))
        assert credential_hypothesis(sg, has_operator_credentials=False).available is True

    def test_policy_default_hypothesis(self) -> None:
        h = credential_hypothesis(_subgraph(), has_operator_credentials=False, allow_default_credentials=True)
        assert h.available is True and h.source == pg.CREDENTIAL_SOURCE_POLICY_DEFAULT

    def test_auth_bypass_opportunity(self) -> None:
        sg = _subgraph(_node("web_opportunity", {"category": "auth_bypass"}))
        h = credential_hypothesis(sg, has_operator_credentials=False)
        assert h.available is True and h.source == pg.CREDENTIAL_SOURCE_AUTH_BYPASS

    def test_no_hypothesis_typed_reason(self) -> None:
        h = credential_hypothesis(_subgraph(), has_operator_credentials=False)
        assert h.available is False
        assert h.reason == pg.MISSING_CREDENTIAL_HYPOTHESIS
        assert h.source == pg.CREDENTIAL_SOURCE_NONE

    def test_capability_and_login_form_are_not_a_hypothesis(self) -> None:
        # A credential-validation CAPABILITY (an ssh service) and a discovered
        # login form (auth_flow, or an authentication_portal opportunity) are
        # auth SURFACES — not actionable hypotheses.
        sg = _subgraph(
            _node("service", {"port": "22", "service": "ssh", "state": "open"}),
            _node("auth_flow", {"url": f"http://{_HOST}/login"}),
            _node("web_opportunity", {"category": "authentication_portal"}),
        )
        assert credential_hypothesis(sg, has_operator_credentials=False).available is False

    def test_prior_attempt_credential_node_is_not_discovered(self) -> None:
        # A normal attempt-record credential node (redacted secret, parser
        # source) must never be mistaken for discovered credential evidence.
        sg = _subgraph(_node("credential", {"username": "root", "secret_hint": "[redacted]", "source": "access_parser"}))
        assert credential_hypothesis(sg, has_operator_credentials=False).available is False


# ---------------------------------------------------------------------------
# web_evidence_status — meaningful evidence vs mere attempts
# ---------------------------------------------------------------------------

class TestWebEvidence:
    def test_no_content_is_incomplete(self) -> None:
        # A discovered-but-unfetched endpoint (a link) is not meaningful content.
        sg = _subgraph(_node("endpoint", {"url": f"http://{_HOST}/", "browsed": False}))
        assert web_evidence_status(sg).complete is False

    def test_fetched_page_status_is_complete(self) -> None:
        sg = _subgraph(_node("endpoint", {"url": f"http://{_HOST}/", "status": "200"}))
        assert web_evidence_status(sg).complete is True
        assert web_evidence_status(sg).reason == pg.WEB_EVIDENCE_CONTENT

    def test_browsed_page_is_complete(self) -> None:
        sg = _subgraph(_node("endpoint", {"url": f"http://{_HOST}/", "browsed": True}))
        assert web_evidence_status(sg).complete is True

    def test_fetched_endpoint_is_complete(self) -> None:
        # A successful curl GET marks its endpoint fetched=True even though the
        # body carries no status line — a live, fetched HTTP endpoint is web
        # content per §28.6 (the fix for a fetched endpoint being ignored).
        sg = _subgraph(_node("endpoint", {"url": f"http://{_HOST}/", "fetched": True}))
        assert web_evidence_status(sg).complete is True
        assert web_evidence_status(sg).reason == pg.WEB_EVIDENCE_CONTENT

    def test_bare_endpoint_no_marker_is_not_content(self) -> None:
        # An endpoint with neither status, browsed, nor fetched (a
        # discovered-but-unfetched link) is not meaningful content.
        sg = _subgraph(_node("endpoint", {"url": f"http://{_HOST}/x"}))
        assert web_evidence_status(sg).complete is False

    def test_form_and_opportunity_are_complete(self) -> None:
        for t in ("form", "web_opportunity"):
            assert web_evidence_status(_subgraph(_node(t, {}))).complete is True

    def test_vhost_node_alone_is_not_web_complete(self) -> None:
        # §28.8 (corrected) — discovering a vhost is progress that REQUIRES a
        # Host-aware follow-up fetch, NOT completion. A vhost node on its own
        # must NOT mark the web phase complete (else the phase moves on without
        # ever fetching the real app behind the vhost).
        sg = _subgraph(_node("vhost", {"hostname": "app.htb", "ip": _HOST}))
        assert web_evidence_status(sg).complete is False

    def test_redirect_stub_endpoint_plus_vhost_is_not_complete(self) -> None:
        # The bare-IP endpoint's only observation is a 3xx redirect to the
        # vhost — a stub. It must NOT satisfy the web phase; the vhost fetch is
        # the required next step.
        sg = _subgraph(
            _node("vhost", {"hostname": "app.htb", "ip": _HOST}),
            _node("endpoint", {"url": f"http://{_HOST}/", "status": "301", "fetched": True}),
        )
        assert web_evidence_status(sg).complete is False

    def test_vhost_url_fetch_completes_web(self) -> None:
        # Once the vhost itself is fetched (an endpoint whose URL host is the
        # vhost), web discovery is complete.
        sg = _subgraph(
            _node("vhost", {"hostname": "app.htb", "ip": _HOST}),
            _node("endpoint", {"url": f"http://{_HOST}/", "status": "301", "fetched": True}),
            _node("endpoint", {"url": "http://app.htb/", "status": "200", "fetched": True}),
        )
        assert web_evidence_status(sg).complete is True

    def test_redirect_status_endpoint_alone_is_not_complete(self) -> None:
        # A 3xx-status endpoint is a redirect stub even with no vhost node yet.
        sg = _subgraph(_node("endpoint", {"url": f"http://{_HOST}/", "status": "302"}))
        assert web_evidence_status(sg).complete is False

    def test_bare_tech_node_is_not_web_content(self) -> None:
        # A bare `tech` node with no endpoint is produced by nmap version
        # detection (service+tech), not web fetching — it must NOT mark web
        # discovery complete (else the web phase is skipped on any versioned
        # HTTP service). CLAUDE.md §26.3/§28.
        assert web_evidence_status(_subgraph(_node("tech", {}))).complete is False

    def test_tech_with_endpoint_is_web_content(self) -> None:
        # Web fingerprinting (curl/browser) produces an endpoint AND a tech
        # node together — that tech node legitimately counts.
        sg = _subgraph(
            _node("endpoint", {"url": f"http://{_HOST}/"}),
            _node("tech", {"name": "Apache"}),
        )
        assert web_evidence_status(sg).complete is True

    def test_no_web_capability_is_trivially_complete(self) -> None:
        assert web_evidence_status(_subgraph(), has_web_capability=False).complete is True

    def test_policy_blocked_request_produces_no_content(self) -> None:
        # A policy-blocked/failed web request creates no endpoint node, so the
        # web evidence gate stays incomplete (never counts as success).
        sg = _subgraph(_node("service", {"port": "80", "service": "http", "state": "open"}))
        assert web_evidence_status(sg).complete is False


# ---------------------------------------------------------------------------
# decide_phase — the authoritative gate
# ---------------------------------------------------------------------------

class TestDecidePhaseGate:
    def _gp(self) -> GlobalPlanner:
        return GlobalPlanner(max_turns=20)

    def test_curl_only_service_avoids_no_services_termination(self) -> None:
        # Recon budget exhausted with a live HTTP endpoint+service proven by
        # curl (zero nmap services) must NOT die "no services discovered" — the
        # service node counts as progress. Contrast the endpoint-only case,
        # which correctly still terminates.
        gp = GlobalPlanner(max_turns=20, phase_budgets={"recon": 1})
        gp.record_turn(ApexPhase.recon)  # exhaust recon budget
        assert gp.budget_remaining(ApexPhase.recon) == 0

        # A curl-only web target: host + fetched endpoint + recorded service.
        phase = gp.decide_phase(
            node_types_seen={"host", "endpoint", "service"},
            turn_count=2, current_phase=ApexPhase.recon.value,
            has_web_capability=True, has_credential_hypothesis=False,
            web_evidence_complete=False,
        )
        assert phase != ApexPhase.done
        assert phase == ApexPhase.web

    def test_endpoint_only_no_service_still_terminates(self) -> None:
        # Guard: an endpoint with NO service node (pre-fix curl behavior) still
        # terminates "no services discovered" once recon is exhausted, so the
        # fix is specifically the curl-records-a-service change, not a
        # weakening of the termination.
        gp = GlobalPlanner(max_turns=20, phase_budgets={"recon": 1})
        gp.record_turn(ApexPhase.recon)
        phase = gp.decide_phase(
            node_types_seen={"host", "endpoint"},
            turn_count=2, current_phase=ApexPhase.recon.value,
            has_web_capability=True, has_credential_hypothesis=False,
            web_evidence_complete=False,
        )
        assert phase == ApexPhase.done

    def test_http_no_content_no_creds_stays_web(self) -> None:
        # Open HTTP port, no fetched page, no credentials → remain in web
        # (prefer unfinished web discovery over credential validation).
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "endpoint"},
            turn_count=1, has_web_capability=True,
            has_credential_hypothesis=False, web_evidence_complete=False,
        )
        assert phase == ApexPhase.web

    def test_operator_creds_makes_credential_actionable(self) -> None:
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "endpoint"},
            turn_count=1, has_web_capability=True,
            has_credential_hypothesis=True, web_evidence_complete=True,
        )
        assert phase == ApexPhase.credential

    def test_web_complete_no_hypothesis_terminates(self) -> None:
        # Web done, no access, no credential hypothesis → nothing actionable.
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "endpoint"},
            turn_count=1, has_web_capability=True,
            has_credential_hypothesis=False, web_evidence_complete=True,
        )
        assert phase == ApexPhase.done

    def test_ssh_capability_no_hypothesis_terminates(self) -> None:
        # A pure-ssh target (credential-validation capability) with no
        # hypothesis never enters credential — it terminates truthfully.
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service"},
            turn_count=1, has_web_capability=False,
            has_credential_hypothesis=False,
        )
        assert phase == ApexPhase.done

    def test_ssh_capability_with_operator_creds_enters_credential(self) -> None:
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service"},
            turn_count=1, has_web_capability=False,
            has_credential_hypothesis=True,
        )
        assert phase == ApexPhase.credential

    def test_backward_compatible_default_enters_credential(self) -> None:
        # Callers that don't pass the new signals keep the pre-fix behavior.
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "endpoint"}, turn_count=1,
        )
        assert phase == ApexPhase.credential


# ---------------------------------------------------------------------------
# Compiled-graph integration — no repeated no-action credential turns, no
# fabricated findings (requirements 7 & 8). Dry-run, no real network/LLM.
# ---------------------------------------------------------------------------

class TestGraphNoActionLoopRemoved:
    @pytest.mark.asyncio
    async def test_ssh_capability_no_creds_no_credential_turns_no_fabrication(self) -> None:
        from apex_host.runtime import build_runtime
        from memfabric.types import Edge

        config = ApexConfig(target=_HOST, dry_run=True, max_turns=8)
        runtime = build_runtime(config)
        api = runtime.api
        ts = now()
        await api.upsert_node(_node("host", {"ip": _HOST}, node_id=_ANCHOR))
        svc_id = f"service:{_HOST}:22/tcp"
        await api.upsert_node(_node("service", {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"}, node_id=svc_id))
        await api.upsert_edge(Edge(
            id=f"exposes:{_ANCHOR}:{svc_id}", from_id=_ANCHOR, to_id=svc_id, type="exposes",
            props={}, confidence=0.9, source="test", first_seen=ts, last_seen=ts,
        ))

        # runtime.run() builds the initial state + compiled graph internally
        # and runs it (dry-run — no real network/LLM). Our seeded ssh service
        # is already in the api, so the first turn's global_plan sees it.
        final_state = await runtime.run()

        phase_seq = [d.get("phase") for d in final_state["planner_decisions"] if d.get("phase")]
        assert ApexPhase.credential.value not in phase_seq, phase_seq
        assert ApexPhase.objective.value not in phase_seq, phase_seq
        assert final_state["completed"] is True
        assert final_state["outcome"] != "user_flag_verified"
        # No fabricated credential/access evidence.
        sg = await api.get_subgraph(_ANCHOR, depth=3)
        types_seen = {n.type for n in sg.nodes}
        assert "credential" not in types_seen and "access_state" not in types_seen
        # The phase-selection reason surfaces the typed missing-hypothesis reason.
        assert final_state["phase_selection"].get("credential_reason") == pg.MISSING_CREDENTIAL_HYPOTHESIS
        await runtime.aclose()


# ---------------------------------------------------------------------------
# Workflow accounting — blocked (not stalled), completion percentage
# ---------------------------------------------------------------------------

class TestWorkflowAccounting:
    def _cred_workflow(self, subgraph: SubgraphView, *, hypothesis: bool, outcome: str = ""):
        wfs = derive_workflows_from_subgraph(
            _HOST, subgraph, engagement_completed=True, engagement_outcome=outcome,
            credential_hypothesis_available=hypothesis,
        )
        return next(w for w in wfs if w.key == "credential_to_privesc")

    def test_validate_step_blocked_when_no_hypothesis(self) -> None:
        # Login mechanism present (ssh), no hypothesis → validate_credentials
        # is BLOCKED (not pending), and the workflow is BLOCKED (not stalled)
        # even when the engagement outcome was a stall value.
        sg = _subgraph(
            _node("host", {"ip": _HOST}),
            _node("service", {"port": "22", "service": "ssh", "state": "open"}),
        )
        wf = self._cred_workflow(sg, hypothesis=False, outcome="no_actionable_task")
        steps = {s.name: s.status.value for s in wf.steps}
        assert steps["discover_login"] == "completed"
        assert steps["validate_credentials"] == "blocked"
        assert wf.status.value == "blocked", wf.status.value

    def test_validate_step_pending_when_hypothesis_available(self) -> None:
        sg = _subgraph(
            _node("host", {"ip": _HOST}),
            _node("service", {"port": "22", "service": "ssh", "state": "open"}),
        )
        wf = self._cred_workflow(sg, hypothesis=True)
        steps = {s.name: s.status.value for s in wf.steps}
        assert steps["validate_credentials"] == "pending"

    def test_completion_percentage_reflects_completed_steps(self) -> None:
        sg = _subgraph(
            _node("host", {"ip": _HOST}),
            _node("service", {"port": "22", "service": "ssh", "state": "open"}),
        )
        wf = self._cred_workflow(sg, hypothesis=False)
        # Only discover_login (1 of 4 steps) is completed.
        completed = sum(1 for s in wf.steps if s.status.value == "completed")
        assert completed == 1
        assert wf.completion_percentage == pytest.approx(25.0)

    def test_web_form_step_blocked_until_page_acquired(self) -> None:
        # Endpoint discovered (workflow prereq met) but not fetched → the
        # form step is BLOCKED until a page is actually acquired.
        sg = _subgraph(
            _node("host", {"ip": _HOST}),
            _node("endpoint", {"url": f"http://{_HOST}/", "browsed": False}),
        )
        wfs = derive_workflows_from_subgraph(_HOST, sg)
        web_wf = next(w for w in wfs if w.key == "web_discovery_to_opportunity")
        assert {s.name: s.status.value for s in web_wf.steps}["discover_form"] == "blocked"

    def test_web_form_step_actionable_after_page_fetched(self) -> None:
        sg = _subgraph(
            _node("host", {"ip": _HOST}),
            _node("endpoint", {"url": f"http://{_HOST}/", "status": "200"}),
        )
        wfs = derive_workflows_from_subgraph(_HOST, sg)
        web_wf = next(w for w in wfs if w.key == "web_discovery_to_opportunity")
        # A fetched page (status) makes form discovery actionable (pending),
        # not blocked.
        assert {s.name: s.status.value for s in web_wf.steps}["discover_form"] == "pending"
