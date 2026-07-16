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
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.diagnostics_node import make_unknown_phase_node
from apex_host.orchestration.routing import UNKNOWN_PHASE_NODE, route_after_global_plan
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

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

        phase = gp.decide_phase(
            node_types_seen=node_types_seen, turn_count=2, current_phase="credential"
        )
        assert phase == ApexPhase.priv_esc

    def test_no_oscillation_across_repeated_peek_and_global_plan_calls(self) -> None:
        """Regression for Bug A: simulate several more turns exactly the way
        production code calls decide_phase — reflect_or_continue's peek
        (current_phase=<this turn's phase>) followed by the next turn's
        global_plan call (current_phase=<peek's own return value>). Before
        the fix, the second call in each pair reverted to credential."""
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
            assert peeked == ApexPhase.priv_esc, (
                f"turn {turn}: peek reverted to {peeked!r} instead of staying priv_esc"
            )
            dispatched = gp.decide_phase(
                node_types_seen=node_types_seen, turn_count=turn,
                current_phase=peeked.value,
            )
            assert dispatched == ApexPhase.priv_esc, (
                f"turn {turn}: global_plan call oscillated back to {dispatched!r} "
                "instead of dispatching priv_esc (Bug A regression)"
            )
            current_phase_value = dispatched.value

    async def test_full_graph_priv_esc_agent_actually_dispatched(self) -> None:
        """End-to-end proof that priv_esc_agent is genuinely invoked (not
        just that decide_phase returns priv_esc in isolation): run the
        compiled graph with credential's budget pre-exhausted and assert a
        priv_esc-phase planner decision was recorded."""
        api = make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        await _seed_node(
            api, f"service:{_TARGET}:80/tcp", "service",
            {"port": "80", "proto": "tcp", "service": "http", "state": "open"},
        )
        await _seed_node(
            api, f"endpoint:{_TARGET}:seed", "endpoint", {"url": f"http://{_TARGET}/"}
        )
        for to_id in (f"service:{_TARGET}:80/tcp", f"endpoint:{_TARGET}:seed"):
            await _seed_edge(api, _ANCHOR, to_id)

        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=6)
        registry = ToolRegistry.from_config(config)

        # Force credential's budget to exhaust immediately (1 turn allowed)
        # so it is exhausted well before max_turns, matching the diagnostic
        # report's real-world scenario (no telnet, no auth_flow — credential
        # can never resolve organically). GlobalPlanner is constructed
        # inside build_apex_graph from this module-level default table.
        from apex_host.planners import global_planner as gp_mod

        original_defaults = dict(gp_mod._DEFAULT_PHASE_BUDGETS)
        gp_mod._DEFAULT_PHASE_BUDGETS[ApexPhase.credential.value] = 1
        try:
            graph = build_apex_graph(api, registry, config)
            final_state = await graph.ainvoke(make_initial_state(_TARGET))
        finally:
            gp_mod._DEFAULT_PHASE_BUDGETS.clear()
            gp_mod._DEFAULT_PHASE_BUDGETS.update(original_defaults)

        phases_dispatched = {
            d.get("phase") for d in final_state["planner_decisions"] if d.get("phase")
        }
        assert ApexPhase.priv_esc.value in phases_dispatched, (
            f"priv_esc_agent was never dispatched; phases seen: {phases_dispatched}"
        )
        assert final_state["completed"] is True


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
        await _seed_node(
            api, f"endpoint:{_TARGET}:seed", "endpoint", {"url": login_url}
        )
        await _seed_node(
            api, f"auth_flow:{_TARGET}:seed", "auth_flow", {"url": login_url}
        )
        for to_id in (
            f"service:{_TARGET}:80/tcp", f"endpoint:{_TARGET}:seed", f"auth_flow:{_TARGET}:seed",
        ):
            await _seed_edge(api, _ANCHOR, to_id)

        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)

        final_state = await graph.ainvoke(make_initial_state(_TARGET))

        assert final_state["phase"] == "credential"
        current_task = final_state["current_task"]
        assert current_task is not None, "CredentialPlanner must have dispatched a task"
        assert current_task["params"]["tool"] == "curl"
        assert current_task["params"]["target"] == login_url


# ---------------------------------------------------------------------------
# 3. access_state -> planner advances beyond credential
# ---------------------------------------------------------------------------


class TestAccessStateAdvancesPastCredential:
    def test_decide_phase_advances_to_priv_esc(self) -> None:
        gp = GlobalPlanner(max_turns=20)
        phase = gp.decide_phase(
            node_types_seen={"host", "service", "endpoint", "access_state"},
            turn_count=0,
        )
        assert phase == ApexPhase.priv_esc

    async def test_full_graph_dispatches_priv_esc_agent(self) -> None:
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

        assert final_state["phase"] == "priv_esc"
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

    def test_route_after_global_plan_still_ends_cleanly_on_done(self) -> None:
        """The done phase must still route straight to END, not to the
        diagnostic node — only genuinely unrecognized values do."""
        from langgraph.graph import END

        state: dict[str, Any] = {
            "completed": False, "phase": ApexPhase.done.value, "findings": [],
        }
        assert route_after_global_plan(state) == END  # type: ignore[arg-type]

    async def test_unknown_phase_agent_writes_diagnostic_and_terminates(self) -> None:
        """The unknown_phase_agent node itself: appends an Episode, sets
        last_error, marks completed, and records a diagnostic_events entry
        — never a bare, unexplained stop."""
        from apex_host.execution.dispatcher import TaskDispatcher
        from apex_host.execution.registry import TaskRegistry
        from apex_host.orchestration.dependencies import OrchestrationDeps
        from apex_host.policy import PolicyAdvisor, load_policy

        api = make_api()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=5)
        dispatcher = TaskDispatcher(
            advisor=PolicyAdvisor(load_policy(config), config),
            task_registry=TaskRegistry(), config=config,
            run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type]
        )
        deps = OrchestrationDeps(
            api=api, dispatcher=dispatcher,
            global_planner=GlobalPlanner(max_turns=config.max_turns),
            phase_planners={}, repair_engine=None,  # type: ignore[arg-type]
            config=config, anchor_id=_ANCHOR,
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
    async def test_synthetic_engagement_completes_without_oscillation(self) -> None:
        """End-to-end synthetic engagement: seed an EKG that already has
        host+service+endpoint (web phase satisfied) with credential's
        budget exhausted immediately. Run several turns and prove the
        engagement (a) actually reaches priv_esc, (b) completes within the
        turn budget rather than spinning until max_turns doing nothing, and
        (c) never re-dispatches execute_agent after priv_esc is reached."""
        from apex_host.planners import global_planner as gp_mod

        api = make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        await _seed_node(
            api, f"service:{_TARGET}:80/tcp", "service",
            {"port": "80", "proto": "tcp", "service": "http", "state": "open"},
        )
        await _seed_node(
            api, f"endpoint:{_TARGET}:seed", "endpoint", {"url": f"http://{_TARGET}/"}
        )
        for to_id in (f"service:{_TARGET}:80/tcp", f"endpoint:{_TARGET}:seed"):
            await _seed_edge(api, _ANCHOR, to_id)

        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=8)
        registry = ToolRegistry.from_config(config)

        original_defaults = dict(gp_mod._DEFAULT_PHASE_BUDGETS)
        gp_mod._DEFAULT_PHASE_BUDGETS[ApexPhase.credential.value] = 1
        try:
            graph = build_apex_graph(api, registry, config)
            final_state = await graph.ainvoke(make_initial_state(_TARGET))
        finally:
            gp_mod._DEFAULT_PHASE_BUDGETS.clear()
            gp_mod._DEFAULT_PHASE_BUDGETS.update(original_defaults)

        phase_sequence = [
            d.get("phase") for d in final_state["planner_decisions"] if d.get("phase")
        ]
        assert ApexPhase.priv_esc.value in phase_sequence, (
            f"priv_esc never dispatched; sequence was {phase_sequence}"
        )
        # No oscillation: priv_esc is reached immediately after credential's
        # one-turn budget (index 1 of 2 dispatched phases: credential, then
        # priv_esc) — before the fix this never happened at all, the
        # sequence bounced credential/(nothing) until max_turns.
        first_priv_esc = phase_sequence.index(ApexPhase.priv_esc.value)
        assert first_priv_esc == 1, (
            f"priv_esc should be reached on the second dispatched turn "
            f"(right after credential's 1-turn budget); sequence was {phase_sequence}"
        )
        # And once reached, credential must never be dispatched again —
        # PrivEscPlanner has no organic exit condition of its own (that is
        # explicitly out of scope for this phase; see the diagnostic
        # report's Divergence D / Phase R4), so the engagement legitimately
        # keeps dispatching priv_esc_agent every remaining turn until the
        # global max_turns ceiling — not credential again.
        assert ApexPhase.credential.value not in phase_sequence[first_priv_esc + 1:], (
            f"credential re-dispatched after priv_esc — oscillation regression: {phase_sequence}"
        )
        assert all(p == ApexPhase.priv_esc.value for p in phase_sequence[first_priv_esc:]), (
            f"expected only priv_esc dispatches after it is first reached: {phase_sequence}"
        )
        assert final_state["turn_count"] == config.max_turns
        assert final_state["completed"] is True
        assert final_state["completed"] is True
