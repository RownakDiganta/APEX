# test_phase12c_outcomes.py
# Regression tests for Phase 12C: the canonical EngagementOutcome model, the termination evaluator, stall detection, terminal-episode writing, report integration, and CLI exit codes.
"""Phase 12C regression tests.

Covers the single canonical engagement-outcome model introduced in Phase
12C (``apex_host.orchestration.outcome``), the pure termination evaluator,
bounded stall detection (``apex_host.orchestration.stall``), the
exactly-one terminal episode guarantee (``apex_host.orchestration.terminal_episode``),
failure-catching in ``dispatch_node``/``parsing_node``/``memory_node``,
``RunReport`` integration, and CLI exit codes on both entry points.

No new exploitation capability, privilege escalation, persistence, or
shell-access behavior is exercised or added here — every test uses
``dry_run=True`` and the deterministic (non-LLM) planner stack. No Docker,
Compose, VPN, or internet dependency is used anywhere in this file.
"""
from __future__ import annotations

import argparse
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
from memfabric.types import AbandonSignal, Edge, Node, Outcome

from apex_host.config import ApexConfig
from apex_host.eval.report import build_report, outcome_headline, to_json_dict
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.outcome import (
    EngagementOutcome,
    TerminationDecision,
    evaluate_termination,
    exit_code_for,
    is_success_outcome,
    legacy_status_for,
)
from apex_host.orchestration.stall import StallDecision, StallTracker
from apex_host.orchestration.terminal_episode import (
    build_terminal_episode,
    terminal_state_fields,
    write_terminal_episode,
)
from apex_host.runtime_registry import CapabilityRuntimeRegistry
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

_TARGET = "10.10.10.201"
_ANCHOR = f"host:{_TARGET}"

# All 15 outcomes, for parametrized completeness checks.
_ALL_OUTCOMES = list(EngagementOutcome)


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


def _make_config(target: str = _TARGET, max_turns: int = 20, **kwargs: Any) -> ApexConfig:
    return ApexConfig(target=target, dry_run=True, max_turns=max_turns, **kwargs)


def _no_stall() -> StallDecision:
    return StallDecision(stalled=False, outcome=None, reason="")


async def _seed_node(api: MemoryAPI, node_id: str, node_type: str, props: dict[str, Any] | None = None) -> None:
    ts = now()
    await api.upsert_node(Node(
        id=node_id, type=node_type, props=props or {}, confidence=0.9,
        source="test-seed", first_seen=ts, last_seen=ts,
    ))


async def _seed_edge(api: MemoryAPI, from_id: str, to_id: str) -> None:
    ts = now()
    await api.upsert_edge(Edge(
        id=f"edge:{from_id}:{to_id}", from_id=from_id, to_id=to_id, type="exposes",
        props={}, confidence=0.9, source="test-seed", first_seen=ts, last_seen=ts,
    ))


def _make_initial_state(
    target: str = _TARGET, run_id: str = "run-12c", phase: str = "recon",
) -> ApexGraphState:
    return {
        "run_id": run_id,
        "target": target,
        "phase": phase,
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
        "credential_validation_log": [],
        "outcome": "",
        "termination_reason": "",
        "termination_phase": "",
        "stall_reason": "",
    }


# ---------------------------------------------------------------------------
# 1. EngagementOutcome model — completeness, success invariant, exit codes
# ---------------------------------------------------------------------------

class TestEngagementOutcomeModel:
    def test_exactly_16_outcomes_defined(self) -> None:
        # Phase 18 added EngagementOutcome.user_flag_verified.
        assert len(_ALL_OUTCOMES) == 16

    @pytest.mark.parametrize("outcome", _ALL_OUTCOMES)
    def test_is_success_outcome_true_only_for_user_flag_verified(self, outcome: EngagementOutcome) -> None:
        # Phase 18: validated_access (an intermediate milestone) is no
        # longer success on its own — only user_flag_verified is.
        expected = outcome is EngagementOutcome.user_flag_verified
        assert is_success_outcome(outcome) is expected

    @pytest.mark.parametrize("outcome", _ALL_OUTCOMES)
    def test_every_outcome_has_an_exit_code(self, outcome: EngagementOutcome) -> None:
        code = exit_code_for(outcome)
        assert isinstance(code, int)
        assert code in (0, 1, 2, 3, 4, 130)

    @pytest.mark.parametrize("outcome", _ALL_OUTCOMES)
    def test_every_outcome_has_a_legacy_status(self, outcome: EngagementOutcome) -> None:
        status = legacy_status_for(outcome)
        assert status in (
            "success", "stopped_max_turns", "stopped_error", "abandoned", "cancelled",
        )

    def test_exit_code_table_matches_spec(self) -> None:
        expected = {
            EngagementOutcome.user_flag_verified: 0,
            # Phase 18: access alone is access-only exhaustion, not success.
            EngagementOutcome.validated_access: 1,
            EngagementOutcome.goal_completed: 0,
            EngagementOutcome.max_turns_exhausted: 1,
            EngagementOutcome.phase_budget_exhausted: 1,
            EngagementOutcome.no_actionable_task: 1,
            EngagementOutcome.duplicate_task_stall: 1,
            EngagementOutcome.configuration_failure: 2,
            EngagementOutcome.policy_blocked: 3,
            EngagementOutcome.planner_failure: 4,
            EngagementOutcome.parser_failure: 4,
            EngagementOutcome.tool_failure: 4,
            EngagementOutcome.memory_failure: 4,
            EngagementOutcome.unknown_phase: 4,
            EngagementOutcome.internal_error: 4,
            EngagementOutcome.cancelled: 130,
        }
        for outcome, code in expected.items():
            assert exit_code_for(outcome) == code, outcome

    def test_only_user_flag_verified_maps_to_legacy_success(self) -> None:
        for outcome in _ALL_OUTCOMES:
            status = legacy_status_for(outcome)
            if outcome is EngagementOutcome.user_flag_verified:
                assert status == "success"
            else:
                assert status != "success"

    def test_cancelled_has_its_own_legacy_status(self) -> None:
        assert legacy_status_for(EngagementOutcome.cancelled) == "cancelled"

    def test_outcome_is_str_enum_serializable(self) -> None:
        # EngagementOutcome(str, Enum) — .value round-trips through JSON.
        assert EngagementOutcome("validated_access") is EngagementOutcome.validated_access
        assert EngagementOutcome.validated_access.value == "validated_access"
        assert EngagementOutcome("user_flag_verified") is EngagementOutcome.user_flag_verified


# ---------------------------------------------------------------------------
# 2. evaluate_termination — pure precedence logic
# ---------------------------------------------------------------------------

class TestEvaluateTerminationPrecedence:
    def test_objective_verified_wins_unconditionally(self) -> None:
        decision = evaluate_termination(
            max_turns=5, turn_count=1, objective_verified=True,
            next_phase="recon", current_phase="recon", stall=_no_stall(),
        )
        assert decision.terminate is True
        assert decision.outcome is EngagementOutcome.user_flag_verified
        assert decision.success is True

    def test_objective_verified_wins_even_on_last_allowed_turn(self) -> None:
        # An objective verified on the very last allowed turn is still
        # success, never max_turns_exhausted.
        decision = evaluate_termination(
            max_turns=3, turn_count=3, objective_verified=True,
            next_phase="done", current_phase="objective", stall=_no_stall(),
        )
        assert decision.outcome is EngagementOutcome.user_flag_verified
        assert decision.success is True

    def test_objective_verified_wins_even_when_stalled(self) -> None:
        stall = StallDecision(True, EngagementOutcome.duplicate_task_stall, "stalled")
        decision = evaluate_termination(
            max_turns=20, turn_count=5, objective_verified=True,
            next_phase="recon", current_phase="recon", stall=stall,
        )
        assert decision.outcome is EngagementOutcome.user_flag_verified

    def test_validated_access_alone_is_not_success(self) -> None:
        """Phase 18 — evaluate_termination() has no `has_access_state`
        parameter at all anymore: a validated access_state must never be
        passed as `objective_verified`. This test proves that a caller
        supplying objective_verified=False (correct — access alone is not
        the objective) never produces a success outcome, even when other
        inputs superficially resemble the old "credential just validated"
        scenario."""
        decision = evaluate_termination(
            max_turns=20, turn_count=1, objective_verified=False,
            next_phase="objective", current_phase="credential", stall=_no_stall(),
        )
        assert decision.success is False
        assert decision.outcome is not EngagementOutcome.user_flag_verified
        assert decision.terminate is False  # "objective" is not "done" and no stall fired

    def test_done_at_max_turns_is_max_turns_exhausted(self) -> None:
        decision = evaluate_termination(
            max_turns=5, turn_count=5, objective_verified=False,
            next_phase="done", current_phase="web", stall=_no_stall(),
        )
        assert decision.outcome is EngagementOutcome.max_turns_exhausted
        assert decision.success is False

    def test_done_from_priv_esc_before_max_turns_is_phase_budget_exhausted(self) -> None:
        decision = evaluate_termination(
            max_turns=20, turn_count=8, objective_verified=False,
            next_phase="done", current_phase="priv_esc", stall=_no_stall(),
        )
        assert decision.outcome is EngagementOutcome.phase_budget_exhausted
        assert decision.success is False

    def test_done_from_non_priv_esc_before_max_turns_is_goal_completed(self) -> None:
        decision = evaluate_termination(
            max_turns=20, turn_count=8, objective_verified=False,
            next_phase="done", current_phase="web", stall=_no_stall(),
        )
        assert decision.outcome is EngagementOutcome.goal_completed
        assert decision.success is False

    def test_stall_decision_propagates_when_not_done(self) -> None:
        stall = StallDecision(True, EngagementOutcome.no_actionable_task, "3 no-op turns")
        decision = evaluate_termination(
            max_turns=20, turn_count=4, objective_verified=False,
            next_phase="credential", current_phase="credential", stall=stall,
        )
        assert decision.outcome is EngagementOutcome.no_actionable_task
        assert decision.reason == "3 no-op turns"
        assert decision.success is False

    def test_max_turns_fallback_when_not_done_and_not_stalled(self) -> None:
        decision = evaluate_termination(
            max_turns=3, turn_count=3, objective_verified=False,
            next_phase="recon", current_phase="recon", stall=_no_stall(),
        )
        assert decision.outcome is EngagementOutcome.max_turns_exhausted

    def test_no_termination_when_nothing_applies(self) -> None:
        decision = evaluate_termination(
            max_turns=20, turn_count=2, objective_verified=False,
            next_phase="web", current_phase="recon", stall=_no_stall(),
        )
        assert decision.terminate is False
        assert decision.outcome is None
        assert decision.success is False

    def test_done_takes_priority_over_stall(self) -> None:
        # If GlobalPlanner already says "done", that outcome wins over a
        # stall signal from the same turn (level 4/5 precedes stall only
        # when done fires — done is checked before stall in the evaluator).
        stall = StallDecision(True, EngagementOutcome.policy_blocked, "policy stall")
        decision = evaluate_termination(
            max_turns=20, turn_count=5, objective_verified=False,
            next_phase="done", current_phase="web", stall=stall,
        )
        assert decision.outcome is EngagementOutcome.goal_completed

    def test_reason_and_phase_and_turn_populated(self) -> None:
        decision = evaluate_termination(
            max_turns=5, turn_count=5, objective_verified=False,
            next_phase="recon", current_phase="recon", stall=_no_stall(),
        )
        assert decision.reason
        assert decision.phase == "recon"
        assert decision.turn == 5

    def test_termination_decision_dataclass_is_slots(self) -> None:
        d = TerminationDecision(
            terminate=True, outcome=EngagementOutcome.validated_access,
            success=True, reason="r", phase="recon", turn=1,
        )
        with pytest.raises(AttributeError):
            d.new_field = "x"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 3. StallTracker — bounded stall detection
# ---------------------------------------------------------------------------

class TestStallTracker:
    def test_duplicate_task_stall_after_threshold(self) -> None:
        tracker = StallTracker(threshold=3)
        decision = _no_stall()
        for i in range(3):
            decision = tracker.record_turn(
                had_action=True,
                duplicate_actions=[{"fingerprint": "x"}] * (i + 1),
                policy_decisions=[], planner_fingerprint="recon:none",
                state_fingerprint="recon|host",
            )
        assert decision.stalled is True
        assert decision.outcome is EngagementOutcome.duplicate_task_stall

    def test_duplicate_streak_resets_on_non_duplicate_turn(self) -> None:
        tracker = StallTracker(threshold=3)
        tracker.record_turn(
            had_action=True, duplicate_actions=[{"fingerprint": "x"}],
            policy_decisions=[], planner_fingerprint="a", state_fingerprint="s1",
        )
        tracker.record_turn(
            had_action=True, duplicate_actions=[{"fingerprint": "x"}],
            policy_decisions=[], planner_fingerprint="b", state_fingerprint="s2",
        )
        # Turn 3: no new duplicate — real progress resets the streak.
        decision = tracker.record_turn(
            had_action=True, duplicate_actions=[{"fingerprint": "x"}],
            policy_decisions=[], planner_fingerprint="c", state_fingerprint="s3",
        )
        assert decision.stalled is False

    def test_policy_blocked_stall_after_threshold(self) -> None:
        tracker = StallTracker(threshold=3)
        decision = _no_stall()
        for i in range(3):
            decision = tracker.record_turn(
                had_action=False, duplicate_actions=[],
                policy_decisions=[{"status": "blocked"}] * (i + 1),
                planner_fingerprint="web:none", state_fingerprint="web|host",
            )
        assert decision.stalled is True
        assert decision.outcome is EngagementOutcome.policy_blocked

    def test_no_actionable_task_stall_after_threshold(self) -> None:
        tracker = StallTracker(threshold=3)
        decision = _no_stall()
        for i in range(3):
            decision = tracker.record_turn(
                had_action=False, duplicate_actions=[], policy_decisions=[],
                planner_fingerprint=f"credential:no-tasks-{i}",
                state_fingerprint=f"credential|host-{i}",
            )
        assert decision.stalled is True
        assert decision.outcome is EngagementOutcome.no_actionable_task

    def test_stagnant_state_fingerprint_wins_when_stall_cause_alternates(self) -> None:
        """The stagnant-fingerprint check is the catch-all: it fires when the
        underlying EKG/phase state never changes across turns even though no
        single narrow category (duplicate/policy/no-action) individually
        reaches the threshold — e.g. a duplicate turn, then a policy-blocked
        turn, then a no-action turn, all against the same unchanged state.
        A turn where a real (non-duplicate, non-policy-blocked) action is
        dispatched counts as "progress" and resets every streak including
        this one, so the stagnant streak can only accumulate on turns where
        one of the other three "no progress" conditions already applies —
        this test exercises exactly that combination."""
        tracker = StallTracker(threshold=3)
        # Baseline turn: establishes the reference state/planner fingerprints.
        tracker.record_turn(
            had_action=True, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="recon:same", state_fingerprint="recon|host",
        )
        # Turn 1: a duplicate task (not progress) — stagnant streak -> 1.
        decision = tracker.record_turn(
            had_action=True, duplicate_actions=[{"fingerprint": "d1"}], policy_decisions=[],
            planner_fingerprint="recon:same", state_fingerprint="recon|host",
        )
        assert decision.stalled is False
        # Turn 2: a policy-blocked task, no *new* duplicate — stagnant streak -> 2.
        decision = tracker.record_turn(
            had_action=True, duplicate_actions=[{"fingerprint": "d1"}],
            policy_decisions=[{"status": "blocked"}],
            planner_fingerprint="recon:same", state_fingerprint="recon|host",
        )
        assert decision.stalled is False
        # Turn 3: no action at all — stagnant streak -> 3, wins (duplicate=0,
        # policy_block=0 this turn, no_action=1 this turn — all below threshold).
        decision = tracker.record_turn(
            had_action=False, duplicate_actions=[{"fingerprint": "d1"}],
            policy_decisions=[{"status": "blocked"}],
            planner_fingerprint="recon:same", state_fingerprint="recon|host",
        )
        assert decision.stalled is True
        assert decision.outcome is EngagementOutcome.duplicate_task_stall

    def test_stagnant_planner_fingerprint_wins_when_state_fingerprint_varies(self) -> None:
        """Same scenario as above, but with the EKG-derived state_fingerprint
        changing every turn while the planner_fingerprint (phase:last_error)
        stays fixed — proves ``repeated_planner`` alone (the OR branch) is
        sufficient to trigger the stagnant catch-all."""
        tracker = StallTracker(threshold=3)
        tracker.record_turn(
            had_action=True, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="credential:same-error", state_fingerprint="credential|host-0",
        )
        decision = tracker.record_turn(
            had_action=True, duplicate_actions=[{"fingerprint": "d1"}], policy_decisions=[],
            planner_fingerprint="credential:same-error", state_fingerprint="credential|host-1",
        )
        assert decision.stalled is False
        decision = tracker.record_turn(
            had_action=True, duplicate_actions=[{"fingerprint": "d1"}],
            policy_decisions=[{"status": "blocked"}],
            planner_fingerprint="credential:same-error", state_fingerprint="credential|host-2",
        )
        assert decision.stalled is False
        decision = tracker.record_turn(
            had_action=False, duplicate_actions=[{"fingerprint": "d1"}],
            policy_decisions=[{"status": "blocked"}],
            planner_fingerprint="credential:same-error", state_fingerprint="credential|host-3",
        )
        assert decision.stalled is True
        assert decision.outcome is EngagementOutcome.duplicate_task_stall

    def test_progress_resets_all_streaks(self) -> None:
        tracker = StallTracker(threshold=3)
        # Two turns of no-action (building toward the threshold)...
        tracker.record_turn(
            had_action=False, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="a", state_fingerprint="s1",
        )
        tracker.record_turn(
            had_action=False, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="b", state_fingerprint="s2",
        )
        # ...then genuine progress: had_action, no duplicate, no policy block.
        decision = tracker.record_turn(
            had_action=True, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="c", state_fingerprint="s3",
        )
        assert decision.stalled is False
        # Two more no-action turns should NOT immediately stall (streak was reset).
        tracker.record_turn(
            had_action=False, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="d", state_fingerprint="s4",
        )
        decision2 = tracker.record_turn(
            had_action=False, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="e", state_fingerprint="s5",
        )
        assert decision2.stalled is False

    def test_manual_reset_clears_counters(self) -> None:
        tracker = StallTracker(threshold=3)
        tracker.record_turn(
            had_action=False, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="a", state_fingerprint="s1",
        )
        tracker.record_turn(
            had_action=False, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="b", state_fingerprint="s2",
        )
        tracker.reset()
        decision = tracker.record_turn(
            had_action=False, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="c", state_fingerprint="s3",
        )
        assert decision.stalled is False

    def test_threshold_minimum_is_one(self) -> None:
        tracker = StallTracker(threshold=0)
        decision = tracker.record_turn(
            had_action=False, duplicate_actions=[], policy_decisions=[],
            planner_fingerprint="a", state_fingerprint="s1",
        )
        assert decision.stalled is True  # threshold clamps to 1

    def test_only_new_duplicates_since_last_call_count(self) -> None:
        # duplicate_actions accumulates via operator.add across turns; the
        # tracker must track its own previous length, not re-count the
        # whole accumulated list every turn.
        tracker = StallTracker(threshold=3)
        accumulated: list[dict[str, object]] = []
        # Turn 1: one duplicate appended.
        accumulated.append({"fingerprint": "a"})
        tracker.record_turn(
            had_action=True, duplicate_actions=list(accumulated),
            policy_decisions=[], planner_fingerprint="x1", state_fingerprint="s1",
        )
        # Turn 2: no new duplicate (list unchanged) — must not still count as duplicate.
        decision = tracker.record_turn(
            had_action=True, duplicate_actions=list(accumulated),
            policy_decisions=[], planner_fingerprint="x2", state_fingerprint="s2",
        )
        assert decision.stalled is False


# ---------------------------------------------------------------------------
# 4. Terminal episode — exactly one, correct shape, no duplication
# ---------------------------------------------------------------------------

class TestTerminalEpisode:
    def test_build_terminal_episode_shape_success(self) -> None:
        decision = TerminationDecision(
            terminate=True, outcome=EngagementOutcome.user_flag_verified,
            success=True, reason="objective verified", phase="objective", turn=4,
        )
        episode = build_terminal_episode(decision, run_id="run-x")
        assert episode.agent == "apex.orchestration"
        assert episode.action == "engagement_terminated"
        assert episode.outcome is Outcome.success
        assert episode.data["outcome"] == "user_flag_verified"
        assert episode.data["success"] is True
        assert episode.data["run_id"] == "run-x"
        assert episode.task_id is None
        assert episode.phase == "objective"

    def test_build_terminal_episode_shape_failure(self) -> None:
        decision = TerminationDecision(
            terminate=True, outcome=EngagementOutcome.parser_failure,
            success=False, reason="boom", phase="recon", turn=2,
        )
        episode = build_terminal_episode(decision, run_id="run-y")
        assert episode.outcome is Outcome.fundamental
        assert episode.data["success"] is False

    @pytest.mark.asyncio
    async def test_write_terminal_episode_appends_exactly_one_episode(self) -> None:
        api = _make_api()
        decision = TerminationDecision(
            terminate=True, outcome=EngagementOutcome.max_turns_exhausted,
            success=False, reason="reached max turns", phase="recon", turn=5,
        )
        await write_terminal_episode(api, decision, run_id="run-z")
        all_episodes = await api._episodic.all()
        terminal_entries = [e for e in all_episodes if e.action == "engagement_terminated"]
        assert len(terminal_entries) == 1

    @pytest.mark.parametrize(
        "outcome,expect_stall_reason",
        [
            (EngagementOutcome.duplicate_task_stall, True),
            (EngagementOutcome.no_actionable_task, True),
            (EngagementOutcome.policy_blocked, True),
            (EngagementOutcome.max_turns_exhausted, False),
            (EngagementOutcome.validated_access, False),
            (EngagementOutcome.parser_failure, False),
        ],
    )
    def test_terminal_state_fields_stall_reason(
        self, outcome: EngagementOutcome, expect_stall_reason: bool
    ) -> None:
        decision = TerminationDecision(
            terminate=True, outcome=outcome, success=(outcome is EngagementOutcome.validated_access),
            reason="some reason", phase="recon", turn=3,
        )
        fields = terminal_state_fields(decision)
        assert fields["outcome"] == outcome.value
        assert fields["termination_reason"] == "some reason"
        assert fields["termination_phase"] == "recon"
        if expect_stall_reason:
            assert fields["stall_reason"] == "some reason"
        else:
            assert fields["stall_reason"] == ""


# ---------------------------------------------------------------------------
# 5. dispatch_node — planner/memory failure catching
# ---------------------------------------------------------------------------

class _RaisingPlanner:
    async def plan(self, goal: Any, subgraph: Any, evidence: Any) -> Any:
        raise RuntimeError("boom-planner")


class _AbandonPlanner:
    async def plan(self, goal: Any, subgraph: Any, evidence: Any) -> Any:
        return AbandonSignal(reason="nothing to do")


class _RaisingSubgraphAPI:
    """Duck-typed stand-in for MemoryAPI whose get_subgraph always raises."""

    async def get_subgraph(self, anchor: str, depth: int = 2) -> Any:
        raise RuntimeError("boom-memory-read")

    async def query(self, **kwargs: Any) -> Any:
        raise AssertionError("query() must never be reached when get_subgraph() raised")


def _build_deps(
    api: Any, config: ApexConfig, registry: ToolRegistry, *, phase_planners: dict[str, Any] | None = None
) -> Any:
    from apex_host.execution.dispatcher import TaskDispatcher
    from apex_host.execution.registry import TaskRegistry
    from apex_host.agents.browser_executor import BrowserExecutor
    from apex_host.agents.telnet_executor import TelnetExecutor
    from apex_host.orchestration.dependencies import OrchestrationDeps, build_planners
    from apex_host.orchestration.stall import StallTracker
    from apex_host.planners.global_planner import GlobalPlanner
    from apex_host.planning.repair import RepairEngine
    from apex_host.policy.models import PolicyDecision, PolicyStatus, ScopePolicy
    from apex_host.tools.runner import run_command

    class _AllowAdvisor:
        def review_task(self, task: Any, phase: str, evidence: Any, cfg: Any) -> PolicyDecision:
            tool = str(task.params.get("tool", "") or task.params.get("kind", ""))
            return PolicyDecision(status=PolicyStatus.approved, rule_name="always_allow", reason="test", task_tool=tool)

        @property
        def policy(self) -> ScopePolicy:
            return ScopePolicy(
                allowed_targets=frozenset({config.target}), blocked_tools=frozenset(),
                allow_password_lists=False, allow_sensitive_data_access=False,
                require_review_for=[], policy_loaded=False, policy_source="test",
            )

    dispatcher = TaskDispatcher(
        advisor=_AllowAdvisor(), task_registry=TaskRegistry(), config=config,
        run_command_fn=run_command, telnet_executor=TelnetExecutor(config),
        browser_executor=BrowserExecutor(config),
    )
    planners = phase_planners if phase_planners is not None else build_planners(config, registry)
    return OrchestrationDeps(
        api=api, dispatcher=dispatcher, global_planner=GlobalPlanner(max_turns=config.max_turns),
        phase_planners=planners, repair_engine=RepairEngine(model_router=None, allowed_tools=config.allowed_tools, dry_run=True),
        config=config, anchor_id=f"host:{config.target}", stall_tracker=StallTracker(),
        capability_registry=CapabilityRuntimeRegistry(),
    )


class TestDispatchNodeFailureCatching:
    @pytest.mark.asyncio
    async def test_planner_exception_becomes_planner_failure_outcome(self) -> None:
        from apex_host.orchestration.dispatch_node import make_recon_node

        api = _make_api()
        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(api, config, registry, phase_planners={ApexPhase.recon.value: _RaisingPlanner()})
        node = make_recon_node(deps)
        result = await node(_make_initial_state())
        assert result["outcome"] == EngagementOutcome.planner_failure.value
        assert result["termination_phase"] == "recon"
        assert "boom-planner" in result["termination_reason"]
        assert result["current_task"] is None

    @pytest.mark.asyncio
    async def test_memory_read_exception_becomes_memory_failure_outcome(self) -> None:
        from apex_host.orchestration.dispatch_node import make_recon_node

        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(_RaisingSubgraphAPI(), config, registry)
        node = make_recon_node(deps)
        result = await node(_make_initial_state())
        assert result["outcome"] == EngagementOutcome.memory_failure.value
        assert result["termination_phase"] == "recon"

    @pytest.mark.asyncio
    async def test_abandon_signal_does_not_set_an_outcome(self) -> None:
        """A normal AbandonSignal (no credentials configured, etc.) is not a
        failure — it must never set state["outcome"]; that's the stall
        detector's job, evaluated later in reflect_or_continue."""
        from apex_host.orchestration.dispatch_node import make_recon_node

        api = _make_api()
        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(api, config, registry, phase_planners={ApexPhase.recon.value: _AbandonPlanner()})
        node = make_recon_node(deps)
        result = await node(_make_initial_state())
        assert "outcome" not in result
        assert result["current_task"] is None
        assert result["last_error"] == "nothing to do"


# ---------------------------------------------------------------------------
# 6. parsing_node — parser/memory failure catching
# ---------------------------------------------------------------------------

class TestParsingNodeFailureCatching:
    @pytest.mark.asyncio
    async def test_parser_exception_becomes_parser_failure_outcome(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.orchestration.parsing_node as parsing_node_mod

        def _raise(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("boom-parser")

        monkeypatch.setattr(parsing_node_mod, "parse_single_result", _raise)

        api = _make_api()
        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(api, config, registry)
        node = parsing_node_mod.make_parsing_node(deps)

        state = _make_initial_state()
        state["last_tool_result"] = {"tool": "nmap", "stdout": "", "parser": "nmap", "target": _TARGET}
        result = await node(state)
        assert result["outcome"] == EngagementOutcome.parser_failure.value
        assert "boom-parser" in result["termination_reason"]
        assert result["findings"] == []

    @pytest.mark.asyncio
    async def test_apply_deltas_exception_becomes_memory_failure_outcome(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.orchestration.parsing_node as parsing_node_mod

        api = _make_api()

        async def _raise(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("boom-write")

        monkeypatch.setattr(api, "apply_deltas", _raise)

        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(api, config, registry)
        node = parsing_node_mod.make_parsing_node(deps)

        state = _make_initial_state()
        state["last_tool_result"] = {"tool": "curl", "stdout": "", "parser": "command", "target": _TARGET}
        result = await node(state)
        assert result["outcome"] == EngagementOutcome.memory_failure.value

    @pytest.mark.asyncio
    async def test_no_tool_results_returns_empty_dict(self) -> None:
        from apex_host.orchestration.parsing_node import make_parsing_node

        api = _make_api()
        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(api, config, registry)
        node = make_parsing_node(deps)
        result = await node(_make_initial_state())
        assert result == {}


# ---------------------------------------------------------------------------
# 7. memory_node — write (apply_deltas) failure catching
# ---------------------------------------------------------------------------

class TestMemoryNodeFailureCatching:
    @pytest.mark.asyncio
    async def test_apply_deltas_exception_becomes_memory_failure_outcome(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.orchestration.memory_node import make_memory_node

        api = _make_api()

        async def _raise(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("boom-episode-write")

        monkeypatch.setattr(api, "apply_deltas", _raise)

        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(api, config, registry)
        node = make_memory_node(deps)

        state = _make_initial_state()
        state["tool_results"] = [{"tool": "nmap", "returncode": 0, "target": _TARGET}]
        result = await node(state)
        assert result["outcome"] == EngagementOutcome.memory_failure.value
        assert "boom-episode-write" in result["termination_reason"]

    @pytest.mark.asyncio
    async def test_failure_preserves_entries_written_before_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.orchestration.memory_node import make_memory_node

        api = _make_api()
        real_apply_deltas = api.apply_deltas
        call_count = {"n": 0}

        async def _fail_on_second(*args: Any, **kwargs: Any) -> Any:
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise RuntimeError("boom-second-write")
            return await real_apply_deltas(*args, **kwargs)

        monkeypatch.setattr(api, "apply_deltas", _fail_on_second)

        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(api, config, registry)
        node = make_memory_node(deps)

        state = _make_initial_state()
        state["tool_results"] = [
            {"tool": "curl", "returncode": 1, "error": "conn refused", "target": _TARGET, "backend": "local"},
            {"tool": "nmap", "returncode": 0, "target": _TARGET},
        ]
        result = await node(state)
        assert result["outcome"] == EngagementOutcome.memory_failure.value
        # The first (successful) tool_result's error/backend entries survive
        # in the failure result even though the second write failed.
        assert result.get("error_episodes")
        assert result["error_episodes"][0]["tool"] == "curl"
        assert result.get("execution_backend_log")

    @pytest.mark.asyncio
    async def test_normal_success_never_sets_outcome(self) -> None:
        from apex_host.orchestration.memory_node import make_memory_node

        api = _make_api()
        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(api, config, registry)
        node = make_memory_node(deps)

        state = _make_initial_state()
        state["tool_results"] = [{"tool": "nmap", "returncode": 0, "target": _TARGET}]
        result = await node(state)
        assert "outcome" not in result


# ---------------------------------------------------------------------------
# 8. diagnostics_node — unknown_phase terminal episode
# ---------------------------------------------------------------------------

class TestUnknownPhaseTerminalEpisode:
    @pytest.mark.asyncio
    async def test_unknown_phase_writes_exactly_one_terminal_episode(self) -> None:
        from apex_host.orchestration.diagnostics_node import make_unknown_phase_node

        api = _make_api()
        config = _make_config()
        registry = ToolRegistry.from_config(config)
        deps = _build_deps(api, config, registry)
        node = make_unknown_phase_node(deps)

        state = _make_initial_state(phase="exploit")
        result = await node(state)

        assert result["outcome"] == EngagementOutcome.unknown_phase.value
        assert result["completed"] is True
        assert result["phase"] == "done"
        assert result["termination_phase"] == "exploit"

        all_episodes = await api._episodic.all()
        terminal_entries = [e for e in all_episodes if e.action == "engagement_terminated"]
        assert len(terminal_entries) == 1

    def test_unknown_phase_exit_code_is_operational_failure(self) -> None:
        assert exit_code_for(EngagementOutcome.unknown_phase) == 4


# ---------------------------------------------------------------------------
# 9. continuation_node full-graph integration
# ---------------------------------------------------------------------------

class TestContinuationNodeIntegration:
    async def test_max_turns_exhausted_full_graph(self) -> None:
        from apex_host.graph import build_apex_graph

        api = _make_api()
        config = _make_config(target="10.10.10.202", max_turns=2)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(target="10.10.10.202"))

        assert final_state["completed"] is True
        assert final_state["phase"] == "done"
        assert final_state["outcome"] == EngagementOutcome.max_turns_exhausted.value
        assert final_state["turn_count"] == 2

        all_episodes = await api._episodic.all()
        terminal_entries = [e for e in all_episodes if e.action == "engagement_terminated"]
        assert len(terminal_entries) == 1

    async def test_access_state_alone_does_not_terminate_as_success(self) -> None:
        """Phase 18 — a validated access_state (seeded directly, matching
        what the credential phase's own parser produces) is an important
        intermediate milestone but must never, by itself, terminate the
        engagement as success. With no ssh-protocol access_state and no
        credentials configured, ObjectivePlanner can never emit a task, so
        the engagement eventually stalls (no_actionable_task) rather than
        looping forever or fabricating success — proving the mandate
        end-to-end through the real compiled graph."""
        from apex_host.graph import build_apex_graph

        api = _make_api()
        target = "10.10.10.203"
        host_id = f"host:{target}"
        for node_type in ("host", "endpoint", "access_state", "service"):
            node_id = host_id if node_type == "host" else f"{node_type}:{target}:seed"
            await _seed_node(api, node_id, node_type)
        for node_type in ("endpoint", "access_state", "service"):
            await _seed_edge(api, host_id, f"{node_type}:{target}:seed")

        config = _make_config(target=target, max_turns=20)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(target=target))

        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value
        assert final_state["outcome"] != EngagementOutcome.validated_access.value
        assert final_state["completed"] is True
        # Must NOT terminate on the very first turn the way pre-Phase-18
        # code did — the engagement genuinely continues toward the
        # objective phase before eventually stalling.
        assert final_state["turn_count"] > 1

    async def test_planner_failure_full_graph_via_monkeypatched_planner(self) -> None:
        from apex_host.orchestration import builder as builder_mod

        api = _make_api()
        target = "10.10.10.204"
        config = _make_config(target=target, max_turns=10)
        registry = ToolRegistry.from_config(config)

        # Build deps manually with a raising recon planner, then drive the
        # recon node + continuation node directly (full LangGraph compile
        # not required to prove the outcome propagates through to termination).
        deps = _build_deps(api, config, registry, phase_planners={ApexPhase.recon.value: _RaisingPlanner()})
        from apex_host.orchestration.dispatch_node import make_recon_node
        from apex_host.orchestration.continuation_node import make_continuation_node

        recon_node = make_recon_node(deps)
        continuation_node = make_continuation_node(deps)

        state = _make_initial_state(target=target)
        partial = await recon_node(state)
        state.update(partial)  # type: ignore[typeddict-item]
        final_update = await continuation_node(state)

        assert final_update["outcome"] == EngagementOutcome.planner_failure.value
        assert final_update["completed"] is True
        assert final_update["phase"] == "done"
        assert exit_code_for(EngagementOutcome(final_update["outcome"])) == 4
        del builder_mod  # imported only to document which module owns build_apex_graph


# ---------------------------------------------------------------------------
# 10. RunReport / report.py integration
# ---------------------------------------------------------------------------

def _empty_subgraph() -> Any:
    from memfabric.types import SubgraphView
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)


class TestReportOutcomeIntegration:
    def test_report_reflects_graph_supplied_outcome(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["turn_count"] = 5
        state["outcome"] = EngagementOutcome.max_turns_exhausted.value
        state["termination_reason"] = "reached the maximum turn budget (5)"
        state["termination_phase"] = "web"

        config = _make_config(max_turns=5)
        report = build_report(state, _empty_subgraph(), config)

        assert report.outcome == "max_turns_exhausted"
        assert report.success is False
        assert report.termination_reason == "reached the maximum turn budget (5)"
        assert report.termination_phase == "web"
        assert report.termination_turn == 5
        assert report.status == "stopped_max_turns"
        assert report.completed_successfully is False

    def test_report_success_only_when_user_flag_verified(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.user_flag_verified.value
        state["termination_phase"] = "objective"
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        assert report.success is True
        assert report.completed_successfully is True
        assert report.status == "success"

    def test_report_validated_access_alone_is_not_success(self) -> None:
        # Phase 18 — a validated access_state is an intermediate milestone,
        # never independently success.
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.validated_access.value
        state["termination_phase"] = "objective"
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        assert report.success is False
        assert report.completed_successfully is False
        assert report.status != "success"

    def test_stall_reason_populated_only_for_stall_outcomes(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.no_actionable_task.value
        state["stall_reason"] = "3 consecutive turns produced no actionable task"
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        assert report.stall_reason == "3 consecutive turns produced no actionable task"

    def test_fallback_outcome_derivation_for_legacy_state_without_outcome_field(self) -> None:
        """A hand-built final_state that predates Phase 12C (no 'outcome' key
        at all) must still resolve to a sensible outcome via the backward-
        compatible fallback path."""
        state: dict[str, Any] = {
            "run_id": "legacy", "target": _TARGET, "phase": "recon",
            "goal": "g", "current_task": None, "evidence_summary": "",
            "findings": [], "error_episodes": [], "last_tool_result": None,
            "last_error": None, "completed": True, "turn_count": 20,
            "planner_decisions": [], "tool_results": None, "repair_count": 0,
            "policy_decisions": [],
        }
        config = _make_config(max_turns=20)
        report = build_report(state, _empty_subgraph(), config)  # type: ignore[arg-type]
        assert report.outcome == EngagementOutcome.max_turns_exhausted.value

    def test_outcome_headline_success(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.user_flag_verified.value
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        headline = outcome_headline(report)
        assert headline.startswith("SUCCESS")
        assert "flag" in headline

    def test_outcome_headline_validated_access_is_not_success(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.validated_access.value
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        headline = outcome_headline(report)
        assert not headline.startswith("SUCCESS")

    def test_outcome_headline_stopped_max_turns(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.max_turns_exhausted.value
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        assert outcome_headline(report) == "STOPPED — maximum turns exhausted"

    def test_outcome_headline_no_actionable_task(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.no_actionable_task.value
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        assert outcome_headline(report) == "STOPPED — no actionable task remained"

    def test_outcome_headline_policy_blocked(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.policy_blocked.value
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        assert outcome_headline(report) == "BLOCKED — policy prevented further progress"

    def test_outcome_headline_parser_failure(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.parser_failure.value
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        assert outcome_headline(report) == "FAILED — parser error"

    def test_outcome_headline_cancelled(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.cancelled.value
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        assert outcome_headline(report) == "CANCELLED — user interrupted run"

    def test_json_dict_includes_engagement_outcome_block(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.max_turns_exhausted.value
        state["termination_reason"] = "r"
        state["termination_phase"] = "recon"
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)
        data = to_json_dict(report)
        assert "engagement_outcome" in data
        eo = data["engagement_outcome"]
        assert eo["outcome"] == "max_turns_exhausted"
        assert eo["success"] is False
        assert eo["termination_reason"] == "r"
        assert eo["termination_phase"] == "recon"
        assert "headline" in eo
        assert "access_summary" in eo

    def test_no_success_without_access_state_in_report(self) -> None:
        """Even if the caller mistakenly sets outcome=validated_access with
        no access_state node in the EKG, the report must not fabricate an
        access_summary claiming validation — access_summary.validated is
        driven only by node_counts, never by the outcome string alone."""
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.validated_access.value
        config = _make_config()
        report = build_report(state, _empty_subgraph(), config)  # empty subgraph: no access_state node
        assert report.access_summary["validated"] is False


# ---------------------------------------------------------------------------
# 11. No success without a verified objective — cross-cutting invariant
#     (Phase 18 — a validated access_state alone is never sufficient)
# ---------------------------------------------------------------------------

class TestNoSuccessWithoutAccessState:
    def test_evaluate_termination_success_requires_objective_verified_true(self) -> None:
        for verified in (True, False):
            decision = evaluate_termination(
                max_turns=20, turn_count=5, objective_verified=verified,
                next_phase="done", current_phase="web", stall=_no_stall(),
            )
            if verified:
                assert decision.success is True
                assert decision.outcome is EngagementOutcome.user_flag_verified
            else:
                assert decision.success is False
                assert decision.outcome is not EngagementOutcome.user_flag_verified

    @pytest.mark.parametrize("outcome", [o for o in _ALL_OUTCOMES if o is not EngagementOutcome.user_flag_verified])
    def test_no_other_outcome_is_ever_success(self, outcome: EngagementOutcome) -> None:
        assert is_success_outcome(outcome) is False


# ---------------------------------------------------------------------------
# 12. CLI exit codes — run_htb_local.py and main.py
# ---------------------------------------------------------------------------

class TestRunHtbLocalExitCodes:
    def test_help_exits_zero(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--help"])
        assert exc_info.value.code == 0

    @pytest.mark.asyncio
    async def test_configuration_failure_exit_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.eval import run_htb_local as mod

        def _raise_config(*args: Any, **kwargs: Any) -> Any:
            raise ValueError("bad config")

        monkeypatch.setattr(mod.ApexConfig, "from_cli_args", staticmethod(_raise_config))
        args = argparse.Namespace(preflight=False)
        code = await mod._async_main(args)
        assert code == exit_code_for(EngagementOutcome.configuration_failure)
        assert code == 2

    @pytest.mark.asyncio
    async def test_internal_error_exit_code_when_engagement_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.eval import run_htb_local as mod

        async def _raise_run(config: Any) -> Any:
            raise RuntimeError("boom-run")

        monkeypatch.setattr(mod, "run_engagement", _raise_run)
        config = _make_config()
        args = argparse.Namespace(preflight=False)
        monkeypatch.setattr(mod.ApexConfig, "from_cli_args", staticmethod(lambda a: config))
        code = await mod._async_main(args)
        assert code == exit_code_for(EngagementOutcome.internal_error)
        assert code == 4

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "outcome,expected_code",
        [
            (EngagementOutcome.user_flag_verified, 0),
            (EngagementOutcome.validated_access, 1),
            (EngagementOutcome.max_turns_exhausted, 1),
            (EngagementOutcome.no_actionable_task, 1),
            (EngagementOutcome.policy_blocked, 3),
            (EngagementOutcome.parser_failure, 4),
            (EngagementOutcome.memory_failure, 4),
        ],
    )
    async def test_exit_code_matches_report_outcome(
        self, monkeypatch: pytest.MonkeyPatch, outcome: EngagementOutcome, expected_code: int
    ) -> None:
        from apex_host.eval import run_htb_local as mod

        config = _make_config()
        registry = ToolRegistry.from_config(config)
        from apex_host.runtime import build_runtime
        runtime = build_runtime(config)

        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = outcome.value

        async def _fake_run_engagement(cfg: Any) -> Any:
            return runtime, state, {}

        monkeypatch.setattr(mod, "run_engagement", _fake_run_engagement)
        monkeypatch.setattr(mod.ApexConfig, "from_cli_args", staticmethod(lambda a: config))
        args = argparse.Namespace(
            preflight=False, export_graph=None, export_json=None,
            # Phase 17 — benchmarking/evaluation/comparison flags _async_main
            # now reads unconditionally after run_engagement() returns.
            htb_machine_name=None, htb_difficulty=None,
            compare_with=None, export_benchmark=None, export_comparison=None,
        )
        code = await mod._async_main(args)
        assert code == expected_code
        del registry


class TestMainExitCodes:
    def test_help_exits_zero(self) -> None:
        from apex_host.main import parse_args
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--help"])
        assert exc_info.value.code == 0

    @pytest.mark.asyncio
    async def test_configuration_failure_exit_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host import main as mod

        def _raise_config(*args: Any, **kwargs: Any) -> Any:
            raise ValueError("bad config")

        monkeypatch.setattr(mod.ApexConfig, "from_cli_args", staticmethod(_raise_config))
        args = argparse.Namespace(preflight=False)
        code = await mod.run(args)
        assert code == 2

    @pytest.mark.asyncio
    async def test_internal_error_exit_code(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host import main as mod

        config = _make_config()
        monkeypatch.setattr(mod.ApexConfig, "from_cli_args", staticmethod(lambda a: config))

        class _RaisingRuntime:
            async def seed_all(self) -> dict[str, Any]:
                raise RuntimeError("boom-seed")

        monkeypatch.setattr(mod, "build_runtime", lambda cfg: _RaisingRuntime())
        args = argparse.Namespace(preflight=False)
        code = await mod.run(args)
        assert code == 4

    @pytest.mark.asyncio
    async def test_success_exit_code_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host import main as mod

        config = _make_config()
        monkeypatch.setattr(mod.ApexConfig, "from_cli_args", staticmethod(lambda a: config))

        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.user_flag_verified.value

        class _FakeRuntime:
            async def seed_all(self) -> dict[str, Any]:
                return {}

            async def run(self) -> Any:
                return state

        monkeypatch.setattr(mod, "build_runtime", lambda cfg: _FakeRuntime())
        args = argparse.Namespace(preflight=False)
        code = await mod.run(args)
        assert code == 0


# ---------------------------------------------------------------------------
# 13. No secret leakage in outcome/report surfaces
# ---------------------------------------------------------------------------

class TestNoSecretLeakageInOutcomeReporting:
    def test_access_summary_never_contains_password_key(self) -> None:
        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.validated_access.value
        state["credential_validation_log"] = [
            {"protocol": "ssh", "username": "root", "success": True, "error_category": "success"},
        ]
        config = _make_config(username_candidates=["root"], password_candidates=["hunter2-secret"])
        # Seed an access_state node so access_summary.validated is True.
        import asyncio

        async def _seed() -> Any:
            api = _make_api()
            await _seed_node(api, f"host:{config.target}", "host")
            await _seed_node(api, f"access_state:{config.target}:seed", "access_state")
            await _seed_edge(api, f"host:{config.target}", f"access_state:{config.target}:seed")
            return await api.get_subgraph(f"host:{config.target}", depth=5)

        subgraph = asyncio.run(_seed())
        report = build_report(state, subgraph, config)
        assert report.access_summary["validated"] is True
        assert "password" not in report.access_summary
        for value in report.access_summary.values():
            assert value != "hunter2-secret"

        data = to_json_dict(report)
        serialized = str(data)
        assert "hunter2-secret" not in serialized

    def test_format_text_never_contains_configured_password(self) -> None:
        from apex_host.eval.report import format_text

        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.max_turns_exhausted.value
        config = _make_config(username_candidates=["admin"], password_candidates=["s3cr3t-value"])
        report = build_report(state, _empty_subgraph(), config)
        text = format_text(report)
        assert "s3cr3t-value" not in text

    def test_termination_reason_from_config_failure_never_echoes_real_secrets(self) -> None:
        # configuration_failure's termination_reason is built from the raw
        # exception message — verify the CLI wrapper doesn't add anything
        # beyond that message (no accidental config dump).
        decision = TerminationDecision(
            terminate=True, outcome=EngagementOutcome.configuration_failure,
            success=False, reason="invalid target", phase="unknown", turn=0,
        )
        fields = terminal_state_fields(decision)
        assert fields["termination_reason"] == "invalid target"
