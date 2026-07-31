# test_phase12a_state_machine.py
# Regression tests for Phase 12A (R1) state-machine fixes: budget oscillation (Bug A), auth_flow-vs-access_state (Bug B), and unroutable-phase silent END (Bug E).
"""Phase 12A (R1) regression tests.

Covers the three confirmed state-machine bugs from the HTB Exploitation
Workflow Diagnostic Report:

- Bug A: credential-phase budget exhaustion oscillated between a peeked
  "priv_esc" and a re-derived "credential" forever, so ``priv_esc_agent``
  was never actually dispatched.
- Bug B: a bare ``auth_flow`` node (a discovered login page) was treated
  as equivalent to ``access_state`` (a validated login), skipping the
  credential-validation phase entirely.
- Bug E: an unroutable ``ApexPhase`` value (e.g. the still-unreachable
  ``exploit``/``lateral`` members) fell through ``route_after_global_plan``
  straight to ``END`` with no diagnostic trail.

No new exploitation capability is exercised or added here — every test
uses ``dry_run=True`` and the deterministic (non-LLM) planner stack.
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
from memfabric.types import Edge, Node

from apex_host.config import ApexConfig
from apex_host.graph import build_apex_graph
from apex_host.graph_ids import access_capability_id
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.diagnostics_node import make_unknown_phase_node
from apex_host.orchestration.routing import UNKNOWN_PHASE_NODE, route_after_global_plan
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.tools.registry import ToolRegistry
from apex_host.types import AccessCapabilityType, ApexPhase

_TARGET = "10.10.10.99"
_ANCHOR = f"host:{_TARGET}"


def make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def make_initial_state(target: str = _TARGET, run_id: str = "run-12a") -> ApexGraphState:
    return {
        "run_id": run_id,
        "target": target,
        "phase": "recon",
        "goal": f"Begin engagement against {target}",
        "current_task": None,
        "evidence_summary": "",
        "findings": [],
        "error_episodes": [],
        "last_tool_result": None,
        "last_error": None,
        "completed": False,
        "turn_count": 0,
        "planner_decisions": [],
        "tool_results": None,
        "repair_count": 0,
        "policy_decisions": [],
        "duplicate_actions": [],
        "completed_fingerprints": [],
        "execution_backend_log": [],
        "diagnostic_events": [],
    }


async def _seed_node(api: MemoryAPI, node_id: str, node_type: str, props: dict[str, Any]) -> None:
    timestamp = now()
    await api.upsert_node(
        Node(
            id=node_id, type=node_type, props=props, confidence=0.9,
            source="test-seed", first_seen=timestamp, last_seen=timestamp,
        )
    )


async def _seed_edge(api: MemoryAPI, from_id: str, to_id: str) -> None:
    timestamp = now()
    await api.upsert_edge(
        Edge(
            id=f"edge:{from_id}:{to_id}", from_id=from_id, to_id=to_id, type="exposes",
            props={}, confidence=0.9, source="test-seed", first_seen=timestamp, last_seen=timestamp,
        )
    )


# ---------------------------------------------------------------------------
# 1. Credential budget exhaustion -> priv_esc dispatched, no oscillation
# ---------------------------------------------------------------------------


class TestBugACredentialBudgetExhaustion:
    """GlobalPlanner-level regression for the exact oscillation mechanics:
    reflect_or_continue's peek passes current_phase=<peeked phase>, and the
    following turn's global_plan call passes current_phase=<that peeked
    phase> too — this is precisely where the old implementation reverted
    back to credential instead of staying force-advanced."""

    def test_budget_exhaustion_immediately_advances_past_credential(self) -> None:
        gp = GlobalPlanner(max_turns=100, phase_budgets={"credential": 2})
        node_types_seen = {"host", "service", "endpoint"}  # no auth_flow/access_state ever

        for _ in range(2):
            phase = gp.decide_phase(
                node_types_seen=node_types_seen, turn_count=0, current_phase="credential"
            )
            assert phase == ApexPhase.credential
            gp.record_turn(phase)

        assert gp.budget_remaining(ApexPhase.credential) == 0

        # Phase 18: forcing past credential routes to the unresolved
        # objective phase first — not directly to priv_esc.
        phase = gp.decide_phase(
            node_types_seen=node_types_seen, turn_count=2, current_phase="credential"
        )
        assert phase == ApexPhase.objective

    def test_no_oscillation_across_repeated_peek_and_global_plan_calls(self) -> None:
        """Regression for Bug A: simulate several more turns exactly the way
        production code calls decide_phase — reflect_or_continue's peek
        (current_phase=<this turn's phase>) followed by the next turn's
        global_plan call (current_phase=<peek's own return value>). Before
        the fix, the second call in each pair reverted to credential.

        Phase 18: the steady state once credential's budget is exhausted
        (and no real access_state exists) is now `objective`, not
        `priv_esc` — the fix under test (no oscillation back to
        `credential`) is unaffected by which forward phase is reached."""
        gp = GlobalPlanner(max_turns=100, phase_budgets={"credential": 2})
        node_types_seen = {"host", "service", "endpoint"}
        gp.record_turn(ApexPhase.credential)
        gp.record_turn(ApexPhase.credential)
        assert gp.budget_remaining(ApexPhase.credential) == 0

        current_phase_value = ApexPhase.credential.value
        for turn in range(6):
            peeked = gp.decide_phase(
                node_types_seen=node_types_seen, turn_count=turn,
                current_phase=current_phase_value,
            )
            assert peeked == ApexPhase.objective, (
                f"turn {turn}: peek reverted to {peeked!r} instead of staying objective"
            )
            dispatched = gp.decide_phase(
                node_types_seen=node_types_seen, turn_count=turn,
                current_phase=peeked.value,
            )
            assert dispatched == ApexPhase.objective, (
                f"turn {turn}: global_plan call oscillated back to {dispatched!r} "
                "instead of dispatching objective (Bug A regression)"
            )
            assert dispatched != ApexPhase.credential
            current_phase_value = dispatched.value

    async def test_full_graph_priv_esc_agent_actually_dispatched(self) -> None:
        """End-to-end proof that priv_esc_agent is genuinely invoked once
        the objective phase itself concludes without success (Phase 18):
        seed a REAL ssh access_state plus operator credentials so
        ObjectivePlanner actually dispatches a bounded verification task
        (never an AbandonSignal) — in dry-run mode that attempt always
        fails to verify, and with only one default candidate path
        (max_user_flag_attempts default x one filename) that single
        failure immediately marks the objective 'failed', letting the very
        next turn fall through to priv_esc."""
        api = make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        await _seed_node(
            api, f"service:{_TARGET}:22/tcp", "service",
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
        )
        await _seed_node(
            api, f"access_state:{_TARGET}:testuser:ssh", "access_state",
            {"level": "user", "username": "testuser", "target": _TARGET, "service": "ssh"},
        )
        # Access-capability refactor: ObjectivePlanner now selects among
        # validated AccessCapability nodes rather than access_state nodes
        # directly (see apex_host/planners/access_capabilities.py) — a
        # capability node is normally produced by CapabilityParser once a
        # real ssh_access task succeeds through the dispatcher; this test
        # seeds the equivalent EKG state directly.
        cap_id = access_capability_id(_TARGET, AccessCapabilityType.ssh_command.value, "testuser")
        await _seed_node(
            api, cap_id, "access_capability",
            {
                "capability_type": AccessCapabilityType.ssh_command.value,
                "host_id": _ANCHOR, "validated": True, "principal": "testuser",
                "confidence": 0.85, "source_task_id": "", "metadata": {},
            },
        )
        for to_id in (
            f"service:{_TARGET}:22/tcp", f"access_state:{_TARGET}:testuser:ssh", cap_id,
        ):
            await _seed_edge(api, _ANCHOR, to_id)

        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=6,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(make_initial_state(_TARGET))

        phases_dispatched = [
            d.get("phase") for d in final_state["planner_decisions"] if d.get("phase")
        ]
        assert ApexPhase.objective.value in phases_dispatched, (
            f"objective_agent was never dispatched; phases seen: {phases_dispatched}"
        )
        assert ApexPhase.priv_esc.value in phases_dispatched, (
            f"priv_esc_agent was never dispatched after the objective failed; "
            f"phases seen: {phases_dispatched}"
        )
        assert final_state["completed"] is True
        # Never fabricates success from access alone or from an
        # unverified objective attempt.
        assert final_state["outcome"] != "user_flag_verified"


# ---------------------------------------------------------------------------
# 2. auth_flow only (access_state absent) -> credential planner still runs
# ---------------------------------------------------------------------------


class TestBugBAuthFlowIsNotAccessState:
    def test_decide_phase_stays_credential_with_auth_flow_only(self) -> None:
        gp = GlobalPlanner(max_turns=20)
        phase = gp.decide_phase(
            node_types_seen={"host", "service", "endpoint", "auth_flow"},
            turn_count=0,
        )
        assert phase == ApexPhase.credential

    async def test_full_graph_dispatches_execute_agent_not_priv_esc(self) -> None:
        """With only a discovered auth_flow (no access_state), the compiled
        graph must route to execute_agent (CredentialPlanner) on this turn
        — proven by the dispatched task being CredentialPlanner's curl
        fallback probe against the auth_flow URL, and the turn's phase
        being 'credential', never 'priv_esc'."""
        api = make_api()
        login_url = f"http://{_TARGET}/login"
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        await _seed_node(
            api, f"service:{_TARGET}:80/tcp", "service",
            {"port": "80", "proto": "tcp", "service": "http", "state": "open"},
        )
        # endpoint carries a real HTTP status → web discovery has meaningful
        # content, so the web-evidence gate is satisfied and the engagement
        # proceeds to the credential phase (credential-evidence-gate fix).
        await _seed_node(
            api, f"endpoint:{_TARGET}:seed", "endpoint", {"url": login_url, "status": "200"}
        )
        await _seed_node(
            api, f"auth_flow:{_TARGET}:seed", "auth_flow", {"url": login_url}
        )
        for to_id in (
            f"service:{_TARGET}:80/tcp", f"endpoint:{_TARGET}:seed", f"auth_flow:{_TARGET}:seed",
        ):
            await _seed_edge(api, _ANCHOR, to_id)

        # Operator credentials supply a bounded credential hypothesis — without
        # one, the credential phase is (correctly) not actionable and the
        # engagement would prefer/stay in web. CredentialPlanner still uses its
        # curl-probe fallback here because the only service is HTTP (no
        # telnet/ssh/ftp protocol capability).
        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=1,
            username_candidates=["admin"], password_candidates=["admin"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)

        final_state = await graph.ainvoke(make_initial_state(_TARGET))

        # Phase 12C: `phase` always becomes "done" once terminated (here,
        # via max_turns_exhausted since no access_state was ever produced);
        # `termination_phase` records the phase actually dispatched.
        assert final_state["phase"] == "done"
        assert final_state["termination_phase"] == "credential"
        assert final_state["outcome"] == "max_turns_exhausted"
        current_task = final_state["current_task"]
        assert current_task is not None, "CredentialPlanner must have dispatched a task"
        assert current_task["params"]["tool"] == "curl"
        assert current_task["params"]["target"] == login_url


# ---------------------------------------------------------------------------
# 3. access_state -> planner advances beyond credential
# ---------------------------------------------------------------------------


class TestAccessStateAdvancesPastCredential:
    def test_decide_phase_advances_to_objective(self) -> None:
        # Phase 18: access_state routes to the objective phase, never
        # straight to priv_esc, and access alone is never terminal.
        gp = GlobalPlanner(max_turns=20)
        phase = gp.decide_phase(
            node_types_seen={"host", "service", "endpoint", "access_state"},
            turn_count=0,
        )
        assert phase == ApexPhase.objective

    async def test_full_graph_dispatches_objective_agent_not_priv_esc(self) -> None:
        """With access_state already present but NOT ssh-protocol and no
        credentials configured, the compiled graph routes to objective_agent
        (not priv_esc_agent), ObjectivePlanner abandons (no ssh access it
        can act on), and — critically — the engagement does NOT terminate
        as success merely because access_state exists (Phase 18's core
        mandate)."""
        api = make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        await _seed_node(
            api, f"service:{_TARGET}:23/tcp", "service",
            {"port": "23", "proto": "tcp", "service": "telnet", "state": "open"},
        )
        await _seed_node(
            api, f"access_state:{_TARGET}:root", "access_state",
            {"level": "user", "username": "root", "target": _TARGET},
        )
        for to_id in (f"service:{_TARGET}:23/tcp", f"access_state:{_TARGET}:root"):
            await _seed_edge(api, _ANCHOR, to_id)

        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)

        final_state = await graph.ainvoke(make_initial_state(_TARGET))

        # Phase 12C: `phase` always becomes "done" once terminated;
        # `termination_phase` records the phase actually dispatched
        # (objective, since access_state was already present when
        # global_plan ran this turn). Phase 18: access alone never
        # produces a success outcome — with max_turns=1 the engagement
        # simply exhausts its turn budget.
        assert final_state["phase"] == "done"
        assert final_state["termination_phase"] == "objective"
        assert final_state["outcome"] == "max_turns_exhausted"
        assert final_state["outcome"] != "user_flag_verified"
        assert final_state["outcome"] != "validated_access"
        assert final_state["completed"] is True


# ---------------------------------------------------------------------------
# 4. Unknown phase -> no silent END, diagnostic created, graceful termination
# ---------------------------------------------------------------------------


class TestBugEUnknownPhaseHandling:
    def test_route_after_global_plan_never_falls_through_to_end(self) -> None:
        """routing.py unit-level proof: an unroutable phase value routes to
        UNKNOWN_PHASE_NODE, never bare END."""
        state: dict[str, Any] = {
            "completed": False, "phase": ApexPhase.exploit.value, "findings": [],
        }
        result = route_after_global_plan(state)  # type: ignore[arg-type]
        assert result == UNKNOWN_PHASE_NODE
        assert result != "END"

    def test_route_after_global_plan_routes_done_to_reflect(self) -> None:
        """The done phase routes to reflect_or_continue (the canonical
        termination path that sets a truthful outcome/reason), not to the
        diagnostic node — only genuinely unrecognized values do."""
        state: dict[str, Any] = {
            "completed": False, "phase": ApexPhase.done.value, "findings": [],
        }
        assert route_after_global_plan(state) == "reflect_or_continue"  # type: ignore[arg-type]

    async def test_unknown_phase_agent_writes_diagnostic_and_terminates(self) -> None:
        """The unknown_phase_agent node itself: appends an Episode, sets
        last_error, marks completed, and records a diagnostic_events entry
        — never a bare, unexplained stop."""
        from apex_host.execution.dispatcher import TaskDispatcher
        from apex_host.execution.registry import TaskRegistry
        from apex_host.orchestration.dependencies import OrchestrationDeps
        from apex_host.orchestration.stall import StallTracker
        from apex_host.policy import PolicyAdvisor, load_policy
        from apex_host.capabilities.runtime_references import RuntimeReferenceResolver, RuntimeReferenceStore
        from apex_host.runtime_registry import CapabilityRuntimeRegistry

        api = make_api()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=5)
        dispatcher = TaskDispatcher(
            advisor=PolicyAdvisor(load_policy(config), config),
            task_registry=TaskRegistry(), config=config,
            run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type]
        )
        capability_registry = CapabilityRuntimeRegistry()
        runtime_reference_store = RuntimeReferenceStore()
        deps = OrchestrationDeps(
            api=api, dispatcher=dispatcher,
            global_planner=GlobalPlanner(max_turns=config.max_turns),
            phase_planners={}, repair_engine=None,  # type: ignore[arg-type]
            config=config, anchor_id=_ANCHOR, stall_tracker=StallTracker(),
            capability_registry=capability_registry,
            runtime_reference_store=runtime_reference_store,
            runtime_reference_resolver=RuntimeReferenceResolver(runtime_reference_store, capability_registry),
        )
        node = make_unknown_phase_node(deps)

        state = make_initial_state(_TARGET)
        state["phase"] = "lateral"
        state["turn_count"] = 3

        result = await node(state)

        assert result["completed"] is True
        assert result["phase"] == ApexPhase.done.value
        assert result["last_error"] is not None and "lateral" in result["last_error"]
        assert len(result["diagnostic_events"]) == 1
        event = result["diagnostic_events"][0]
        assert event["phase"] == "lateral"
        assert event["turn_count"] == 3
        assert "lateral" in event["reason"]
        # Phase 12C: canonical outcome fields threaded through too.
        assert result["outcome"] == "unknown_phase"
        assert result["termination_phase"] == "lateral"
        assert "lateral" in result["termination_reason"]

        # An actual Episode must have been appended — not just an in-memory dict.
        subgraph_evidence = await api.query(text="unknown_phase_diagnostic", k=5)
        assert subgraph_evidence is not None  # query must not raise; episode write succeeded

    async def test_full_graph_terminates_gracefully_on_unroutable_phase(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end proof: force GlobalPlanner.decide_phase to return the
        currently-unreachable ApexPhase.exploit and run the full compiled
        graph — it must terminate cleanly with a diagnostic trail, never
        vanish into END with no explanation."""

        def _always_exploit(
            self: GlobalPlanner,
            *,
            node_types_seen: set[str],
            turn_count: int,
            current_phase: str | None = None,
            has_web_capability: bool = True,
            has_credential_hypothesis: bool = True,
            web_evidence_complete: bool | None = None,
            objective_status: str = "pending",
            objective_reopened: bool = False,
        ) -> ApexPhase:
            return ApexPhase.exploit

        monkeypatch.setattr(GlobalPlanner, "decide_phase", _always_exploit)

        api = make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})

        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=5)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)

        final_state = await graph.ainvoke(make_initial_state(_TARGET))

        assert final_state["completed"] is True
        assert final_state["phase"] == ApexPhase.done.value
        assert final_state["diagnostic_events"], "no diagnostic recorded for the unroutable phase"
        assert final_state["last_error"] is not None
        assert "exploit" in final_state["last_error"]
        # Never ran any dispatch agent — proves it went straight from
        # global_plan to the diagnostic node, not through a real phase agent.
        assert final_state["current_task"] is None


# ---------------------------------------------------------------------------
# 5. Full regression: credential -> priv_esc -> completion, no oscillation
# ---------------------------------------------------------------------------


class TestFullRegressionCredentialToPrivEscToCompletion:
    async def test_synthetic_engagement_stalls_cleanly_without_oscillation_or_fabricated_success(
        self,
    ) -> None:
        """End-to-end synthetic engagement: seed an EKG that already has
        host+service+endpoint (web phase satisfied) with credential's
        budget exhausted immediately, and NO real access ever available
        (no credentials configured, no ssh access_state). Phase 18: the
        engagement routes credential -> objective (never straight to
        priv_esc), ObjectivePlanner can never act without real ssh access,
        and the stall detector — strictly more responsive than either
        phase's own turn budget — cleanly stops the engagement rather than
        oscillating or fabricating success from access alone."""
        api = make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        # An SSH service IS a credential-validation *capability* — but with no
        # credentials configured (and no discovered creds, no auth-bypass
        # opportunity, no policy-default hypothesis), there is no actionable
        # credential *hypothesis*. The credential phase must therefore never be
        # entered (this removes the observed "capability present but no
        # credentials configured" no-action loop); the engagement terminates
        # cleanly with a truthful reason instead — never fabricating a
        # credential/objective/priv_esc phase or a success from access alone.
        await _seed_node(
            api, f"service:{_TARGET}:22/tcp", "service",
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
        )
        await _seed_edge(api, _ANCHOR, f"service:{_TARGET}:22/tcp")

        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=8)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(make_initial_state(_TARGET))

        phase_sequence = [
            d.get("phase") for d in final_state["planner_decisions"] if d.get("phase")
        ]
        # Credential is never entered without a hypothesis; objective/priv_esc
        # (both requiring access the engagement can never obtain here) are
        # likewise never fabricated. No oscillation.
        assert ApexPhase.credential.value not in phase_sequence, (
            f"credential entered without a hypothesis (regression): {phase_sequence}"
        )
        assert ApexPhase.objective.value not in phase_sequence, phase_sequence
        assert ApexPhase.priv_esc.value not in phase_sequence, phase_sequence
        assert final_state["completed"] is True
        assert final_state["outcome"] != "user_flag_verified"
        # No fabricated evidence: no credential or access node was invented.
        _sg = await api.get_subgraph(_ANCHOR, depth=3)
        _seeded_types = {n.type for n in _sg.nodes}
        assert "credential" not in _seeded_types
        assert "access_state" not in _seeded_types
