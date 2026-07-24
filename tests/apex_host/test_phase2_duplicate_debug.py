# test_phase2_duplicate_debug.py
# Regression tests for Phase 2 of 4 post-live-test debugging phases: canonical action fingerprinting, bounded retry/repair rules, and capability-gated phase transitions.
"""Phase 2 (post-live-test debugging) regression tests.

Covers the fixes made in response to the second authorized HTB live
test's findings:

1. The same Nmap action executed six times — the execution fingerprint
   was repeated, but ``duplicate_actions.total_skipped`` stayed zero,
   because ``TaskDispatcher`` assigned ``TaskStatus.FAILED_RETRYABLE``
   (which does not suppress resubmission) to EVERY ``EXECUTED_FAILURE``
   disposition, regardless of what ``classify_retry()`` actually decided
   about that specific error.
2. The engagement force-advanced into the credential phase on a
   host-only graph merely because recon's turn budget was exhausted,
   producing a string of "no action" turns rather than a precise,
   immediate stop.

No real OpenAI/OpenRouter API is ever contacted. No live HTB engagement
is run — the "six-Nmap-repeat" simulation test uses an in-process fake
``ToolBackend`` that returns a synthetic raw-socket-permission failure,
never a real subprocess or network call. No new exploitation,
privilege-escalation, or shell-access capability is exercised here.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.config import ApexConfig
from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispatcher import TaskDispatcher
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.execution.registry import TaskRegistry, TaskStatus
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.builder import build_apex_graph
from apex_host.orchestration.outcome import EngagementOutcome, evaluate_termination
from apex_host.orchestration.stall import StallDecision
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.planners.recon_planner import ReconPlanner
from apex_host.planning.fingerprint import task_fingerprint
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase, ToolCommand, ToolResult

_TARGET = "10.10.10.14"
_ANCHOR = f"host:{_TARGET}"

_RAW_SOCKET_STDERR = (
    "Couldn't open a raw socket. Error: (1) Operation not permitted\n"
    "Couldn't open a raw socket or eth handle.\nQUITTING!"
)


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


def _make_subgraph() -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=2)


def _make_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=_make_subgraph(), tiers_queried=[])


def _make_task(
    tool: str = "nmap",
    args: list[str] | None = None,
    target: str = _TARGET,
    parser: str = "nmap",
    executor_domain: str = "recon",
) -> TaskSpec:
    return TaskSpec(
        id=new_id(), goal_id=new_id(), executor_domain=executor_domain,
        params={"tool": tool, "args": args if args is not None else ["-sV", target], "target": target, "parser": parser},
        subgraph_anchor=_ANCHOR, phase="recon",
    )


def _make_ctx(phase: str = "recon", dry_run: bool = False) -> ExecutionContext:
    return ExecutionContext(
        run_id="run-2", phase=phase, turn_number=1, evidence_version=None,
        subgraph=_make_subgraph(), evidence=_make_evidence(), dry_run=dry_run,
    )


class _AllowAdvisor:
    def review_task(self, task: Any, phase: Any, evidence: Any, config: Any) -> Any:
        from unittest.mock import MagicMock
        decision = MagicMock()
        decision.is_approved = True
        decision.status = MagicMock()
        decision.status.value = "approved"
        decision.rule_name = "default_allow"
        decision.reason = ""
        return decision


@dataclass
class _TestConfig:
    target: str = _TARGET
    dry_run: bool = False
    max_command_seconds: int = 30
    tool_backend: str = "local"
    tool_backend_raw_socket_capable: bool | None = None
    max_fingerprint_retries: int = 1


def _make_dispatcher(run_command_fn: Any, config: Any | None = None, registry: TaskRegistry | None = None) -> TaskDispatcher:
    return TaskDispatcher(
        advisor=_AllowAdvisor(), task_registry=registry or TaskRegistry(),
        config=config or _TestConfig(), run_command_fn=run_command_fn,
    )


def _make_initial_state(target: str = _TARGET, run_id: str = "run-phase2") -> ApexGraphState:
    return {
        "run_id": run_id, "target": target, "phase": "recon",
        "goal": f"Begin engagement against {target}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "", "privilege_state": "", "privilege_summary": {},
        "opportunity_ids": [], "attempted_opportunities": [],
        "enumeration_complete": False, "web_session_state": {},
        "workflow_summary": {}, "learning_summary": {}, "task_latency_log": [],
        "objective_status": "", "objective_summary": {},
        "direct_file_read_log": [], "bounded_command_log": [],
        "capability_discovery_log": [],
    }


class _RawSocketFailBackend:
    """Fake ToolBackend: nmap always fails with a raw-socket permission
    error; every other tool "succeeds" trivially. Never a real subprocess
    or network call — purely in-process synthetic data."""

    name = "fake-remote"

    def __init__(self) -> None:
        self.call_count = 0
        self.calls: list[tuple[str, list[str]]] = []

    async def execute(
        self, tool: str, arguments: list[str], *, timeout_seconds: float | None = None, stdin: str | None = None,
    ) -> ToolResult:
        self.call_count += 1
        self.calls.append((tool, list(arguments)))
        cmd = ToolCommand(tool=tool, args=arguments, timeout_seconds=timeout_seconds or 30.0)
        if tool == "nmap":
            return ToolResult(
                command=cmd, stdout="", stderr=_RAW_SOCKET_STDERR,
                returncode=1, duration_seconds=0.001, dry_run=False, backend="remote",
            )
        return ToolResult(
            command=cmd, stdout="ok", stderr="", returncode=0,
            duration_seconds=0.001, dry_run=False, backend="remote",
        )


# ---------------------------------------------------------------------------
# 1 & 3. Canonical fingerprint stability + safe-formatting normalization
# ---------------------------------------------------------------------------


class TestCanonicalFingerprintStability:
    def test_same_action_same_fingerprint(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", ["-sT", "-sV", "-T4", _TARGET], _TARGET, parser="nmap", executor_domain="recon")
        fp2 = task_fingerprint("recon", "nmap", ["-sT", "-sV", "-T4", _TARGET], _TARGET, parser="nmap", executor_domain="recon")
        assert fp1 == fp2

    def test_equivalent_whitespace_formatting_normalizes(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", [" -sT ", "-sV", " -T4"], _TARGET)
        fp2 = task_fingerprint("recon", "nmap", ["-sT", "-sV", "-T4"], _TARGET)
        assert fp1 == fp2

    def test_target_case_normalizes(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", ["-sV"], "TARGET.local")
        fp2 = task_fingerprint("recon", "nmap", ["-sV"], "target.local")
        assert fp1 == fp2


# ---------------------------------------------------------------------------
# 2. Different task IDs do not change the fingerprint
# ---------------------------------------------------------------------------


class TestTaskIdNeverAffectsFingerprint:
    @pytest.mark.asyncio
    async def test_two_dispatches_different_ids_same_fingerprint(self) -> None:
        """Two TaskSpecs with different .id but identical semantic action
        fields produce the SAME dispatcher fingerprint — "Do not allow
        task UUID changes to bypass duplicate suppression."""
        reg = TaskRegistry()
        dispatcher = _make_dispatcher(run_command_fn=None, registry=reg)

        async def _run(cmd: Any, cfg: Any) -> ToolResult:
            return ToolResult(command=cmd, stdout="", stderr="", returncode=0, duration_seconds=0.0)

        dispatcher = _make_dispatcher(run_command_fn=_run, registry=reg)
        task1 = _make_task()
        task2 = _make_task()
        assert task1.id != task2.id

        dr1 = await dispatcher.dispatch(task1, _make_ctx())
        dr2_ctx = _make_ctx()
        dr2 = await dispatcher.dispatch(task2, dr2_ctx)
        assert dr1.fingerprint == dr2.fingerprint


# ---------------------------------------------------------------------------
# 4. Meaningfully changed arguments produce a new fingerprint
# ---------------------------------------------------------------------------


class TestMeaningfullyChangedArgsNewFingerprint:
    def test_reordered_flag_value_pairs_differ(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", ["-p", "80", "--exclude", "443"], _TARGET)
        fp2 = task_fingerprint("recon", "nmap", ["-p", "443", "--exclude", "80"], _TARGET)
        assert fp1 != fp2

    def test_added_sT_flag_differs(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", ["-sV", "-T4", _TARGET], _TARGET)
        fp2 = task_fingerprint("recon", "nmap", ["-sT", "-sV", "-T4", _TARGET], _TARGET)
        assert fp1 != fp2


# ---------------------------------------------------------------------------
# 5. Identical completed (non-retryable) failure is skipped
# ---------------------------------------------------------------------------


class TestIdenticalNonRetryableFailureSkipped:
    @pytest.mark.asyncio
    async def test_second_identical_nmap_raw_socket_failure_is_skipped(self) -> None:
        backend = _RawSocketFailBackend()

        async def _run(cmd: ToolCommand, cfg: Any) -> ToolResult:
            result = await backend.execute(cmd.tool, cmd.args)
            return result

        reg = TaskRegistry()
        dispatcher = _make_dispatcher(run_command_fn=_run, registry=reg)
        task1 = _make_task()
        task2 = _make_task()  # different task.id, identical action

        dr1 = await dispatcher.dispatch(task1, _make_ctx())
        assert dr1.disposition is ExecutionDisposition.EXECUTED_FAILURE
        record = reg.get(dr1.fingerprint)
        assert record is not None
        assert record.status is TaskStatus.FAILED_TERMINAL

        dr2 = await dispatcher.dispatch(task2, _make_ctx())
        assert dr2.disposition is ExecutionDisposition.SKIPPED_DUPLICATE
        assert backend.call_count == 1  # nmap only ever actually ran once


# ---------------------------------------------------------------------------
# 6 & 7. Bounded transient retry vs non-retryable no-retry
# ---------------------------------------------------------------------------


class TestBoundedRetryPolicy:
    @pytest.mark.asyncio
    async def test_transient_failure_permits_one_bounded_retry(self) -> None:
        """max_fingerprint_retries=1 (default): first attempt fails
        transiently -> FAILED_RETRYABLE (resubmission allowed); second
        (bounded) attempt also fails transiently -> forced FAILED_TERMINAL
        (resubmission now suppressed) — "one bounded retry", not
        unbounded."""
        call_count = {"n": 0}

        async def _run(cmd: ToolCommand, cfg: Any) -> ToolResult:
            call_count["n"] += 1
            return ToolResult(
                command=cmd, stdout="", stderr="connection refused",
                returncode=1, duration_seconds=0.0, error="connection refused",
            )

        reg = TaskRegistry()
        dispatcher = _make_dispatcher(run_command_fn=_run, registry=reg, config=_TestConfig(max_fingerprint_retries=1))

        dr1 = await dispatcher.dispatch(_make_task(), _make_ctx())
        assert reg.get(dr1.fingerprint).status is TaskStatus.FAILED_RETRYABLE  # type: ignore[union-attr]

        dr2 = await dispatcher.dispatch(_make_task(), _make_ctx())
        assert dr2.disposition is ExecutionDisposition.EXECUTED_FAILURE  # bounded retry permitted
        assert reg.get(dr2.fingerprint).status is TaskStatus.FAILED_TERMINAL  # type: ignore[union-attr]
        assert reg.get(dr2.fingerprint).disposition == "executed_failure"  # type: ignore[union-attr]

        dr3 = await dispatcher.dispatch(_make_task(), _make_ctx())
        assert dr3.disposition is ExecutionDisposition.SKIPPED_DUPLICATE  # bound exhausted, now suppressed
        assert call_count["n"] == 2  # only two real attempts ever made

    @pytest.mark.asyncio
    async def test_non_retryable_failure_is_not_retried(self) -> None:
        """A raw-socket permission failure is classified may_retry=False by
        classify_retry() on the FIRST attempt — never gets FAILED_RETRYABLE
        at all, regardless of the retry bound."""
        backend = _RawSocketFailBackend()

        async def _run(cmd: ToolCommand, cfg: Any) -> ToolResult:
            return await backend.execute(cmd.tool, cmd.args)

        reg = TaskRegistry()
        dispatcher = _make_dispatcher(run_command_fn=_run, registry=reg, config=_TestConfig(max_fingerprint_retries=5))
        dr1 = await dispatcher.dispatch(_make_task(), _make_ctx())
        assert dr1.retryable is False
        assert reg.get(dr1.fingerprint).status is TaskStatus.FAILED_TERMINAL  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# 8 & 9. Repair changed vs repair_no_change
# ---------------------------------------------------------------------------


class TestRepairChangeDetection:
    @pytest.mark.asyncio
    async def test_repaired_action_with_changed_args_may_execute(self) -> None:
        from apex_host.orchestration.repair_node import make_repair_node
        from apex_host.planning.repair import RepairRequest

        api = _make_api()
        config = _TestConfig()

        class _StubRepairEngine:
            async def repair(self, **kwargs: Any) -> Any:
                return RepairRequest(
                    original_task_id="t-1",
                    repaired_task=TaskSpec(
                        id="t-2", goal_id="g", executor_domain="recon",
                        params={"tool": "nmap", "args": ["-sT", "-sV", _TARGET], "target": _TARGET, "parser": "nmap"},
                        subgraph_anchor=_ANCHOR, phase="recon",
                    ),
                    repair_attempt=0, failure_reason="raw socket permission denied", phase="recon", target=_TARGET,
                )

        dispatched: list[TaskSpec] = []

        class _StubDispatchResult:
            def __init__(self) -> None:
                self.disposition = ExecutionDisposition.EXECUTED_SUCCESS
                self.tool_result_dict = {
                    "tool": "nmap", "target": _TARGET, "parser": "nmap",
                    "returncode": 0, "stdout": "", "error": None, "task_id": "t-2",
                }
                self.audit_metadata: dict[str, Any] = {}

        class _StubDispatcher:
            def __init__(self) -> None:
                self.task_registry = TaskRegistry()

            async def dispatch(self, task: TaskSpec, ctx: Any) -> Any:
                dispatched.append(task)
                return _StubDispatchResult()

        deps = _build_deps(api, config, repair_engine=_StubRepairEngine(), dispatcher=_StubDispatcher())
        node = make_repair_node(deps)
        state = _make_initial_state()
        state["last_tool_result"] = {"tool": "nmap", "error": "raw socket permission denied", "task_id": "t-1", "returncode": 1}
        state["current_task"] = {
            "params": {"tool": "nmap", "args": ["-sV", _TARGET], "target": _TARGET, "parser": "nmap"},
            "executor_domain": "recon",
        }

        result = await node(state)
        assert len(dispatched) == 1  # the repaired (changed) task WAS dispatched
        assert not result.get("duplicate_actions")  # no repair_no_change entry
        assert result["last_tool_result"]["tool"] == "nmap"

    @pytest.mark.asyncio
    async def test_repair_producing_no_change_is_rejected_before_dispatch(self) -> None:
        from apex_host.orchestration.repair_node import make_repair_node
        from apex_host.planning.repair import RepairRequest

        api = _make_api()
        config = _TestConfig()

        class _StubRepairEngine:
            async def repair(self, **kwargs: Any) -> Any:
                return RepairRequest(
                    original_task_id="t-1",
                    repaired_task=TaskSpec(
                        # Identical tool/args/target/parser/executor_domain
                        # to the failed task below — no real change.
                        id="t-2", goal_id="g", executor_domain="recon",
                        params={"tool": "nmap", "args": ["-sV", _TARGET], "target": _TARGET, "parser": "nmap"},
                        subgraph_anchor=_ANCHOR, phase="recon",
                    ),
                    repair_attempt=0, failure_reason="raw socket permission denied", phase="recon", target=_TARGET,
                )

        dispatched: list[TaskSpec] = []

        class _StubDispatcher:
            def __init__(self) -> None:
                self.task_registry = TaskRegistry()

            async def dispatch(self, task: TaskSpec, ctx: Any) -> Any:
                dispatched.append(task)
                raise AssertionError("repair_no_change must never reach dispatch()")

        deps = _build_deps(api, config, repair_engine=_StubRepairEngine(), dispatcher=_StubDispatcher())
        node = make_repair_node(deps)
        state = _make_initial_state()
        state["last_tool_result"] = {"tool": "nmap", "error": "raw socket permission denied", "task_id": "t-1", "returncode": 1}
        state["current_task"] = {
            "params": {"tool": "nmap", "args": ["-sV", _TARGET], "target": _TARGET, "parser": "nmap"},
            "executor_domain": "recon",
        }

        result = await node(state)
        assert dispatched == []
        assert result["duplicate_actions"][0]["disposition"] == "repair_no_change"
        assert result["duplicate_actions"][0]["repair_changed_action"] is False
        assert result["repair_count"] == 1
        # repair_no_change must not consume another execution turn — no new
        # last_tool_result/current_task written this call.
        assert "last_tool_result" not in result


def _build_deps(api: MemoryAPI, config: Any, *, repair_engine: Any, dispatcher: Any) -> Any:
    from apex_host.orchestration.dependencies import OrchestrationDeps
    from apex_host.orchestration.stall import StallTracker as _ST
    from apex_host.capabilities.runtime_references import RuntimeReferenceResolver, RuntimeReferenceStore
    from apex_host.runtime_registry import CapabilityRuntimeRegistry
    from apex_host.planners.global_planner import GlobalPlanner as _GP

    capability_registry = CapabilityRuntimeRegistry()
    runtime_reference_store = RuntimeReferenceStore()
    return OrchestrationDeps(
        api=api, dispatcher=dispatcher, global_planner=_GP(max_turns=20),
        phase_planners={}, repair_engine=repair_engine, config=config,
        anchor_id=_ANCHOR, stall_tracker=_ST(),
        capability_registry=capability_registry,
        runtime_reference_store=runtime_reference_store,
        runtime_reference_resolver=RuntimeReferenceResolver(runtime_reference_store, capability_registry),
    )


# ---------------------------------------------------------------------------
# 10. Deterministic fallback cannot re-dispatch an unchanged failed action
# ---------------------------------------------------------------------------


class TestDeterministicFallbackCannotReDispatch:
    @pytest.mark.asyncio
    async def test_recon_planner_proposes_same_task_dispatcher_suppresses_it(self) -> None:
        """ReconPlanner is stateless and will keep proposing the identical
        nmap task every turn (no service ever appears) — the DISPATCHER,
        not the planner, is what must reject the unchanged action."""
        backend = _RawSocketFailBackend()

        async def _run(cmd: ToolCommand, cfg: Any) -> ToolResult:
            return await backend.execute(cmd.tool, cmd.args)

        registry = ToolRegistry(allowed_tools=["nmap"])
        planner = ReconPlanner(_TARGET, registry, raw_socket_capable=False)
        reg = TaskRegistry()
        dispatcher = _make_dispatcher(run_command_fn=_run, registry=reg)

        goal = Goal(id=new_id(), description="recon", phase="recon", anchor_node=_ANCHOR)
        for _ in range(3):
            plan_result = await planner.plan(goal, _make_subgraph(), _make_evidence())
            assert not isinstance(plan_result, AbandonSignal)
            task = list(plan_result)[0]
            await dispatcher.dispatch(task, _make_ctx())

        # nmap's fixed, unchanged, non-retryable failure only ever actually
        # executed once — every subsequent identical proposal was
        # suppressed before reaching the backend.
        assert backend.call_count == 1


# ---------------------------------------------------------------------------
# 11 & 12. Report metrics + no execution episode for skipped duplicates
# ---------------------------------------------------------------------------


class TestReportAndEpisodeBehavior:
    @pytest.mark.asyncio
    async def test_duplicate_skip_appears_in_report_metrics(self) -> None:
        from apex_host.eval.report import build_report

        backend = _RawSocketFailBackend()

        async def _run(cmd: ToolCommand, cfg: Any) -> ToolResult:
            return await backend.execute(cmd.tool, cmd.args)

        reg = TaskRegistry()
        dispatcher = _make_dispatcher(run_command_fn=_run, registry=reg)
        task1, task2 = _make_task(), _make_task()
        await dispatcher.dispatch(task1, _make_ctx())
        dr2 = await dispatcher.dispatch(task2, _make_ctx())
        assert dr2.disposition is ExecutionDisposition.SKIPPED_DUPLICATE

        from apex_host.orchestration.dispatch_node import _dup_entry
        entry = _dup_entry(task2, dr2.fingerprint, "recon", _TARGET, dr2.tool_result_dict)

        state = _make_initial_state()
        state["duplicate_actions"] = [entry]
        report = build_report(state, subgraph=_make_subgraph(), config=ApexConfig(target=_TARGET))
        assert report.duplicate_action_count == 1
        assert report.duplicate_action_entries[0]["previous_status"] == "failed_terminal"

    @pytest.mark.asyncio
    async def test_skipped_duplicate_creates_no_episode(self) -> None:
        from apex_host.orchestration.memory_node import make_memory_node

        api = _make_api()
        config = _TestConfig()
        deps = _build_deps(api, config, repair_engine=None, dispatcher=None)
        node = make_memory_node(deps)

        state = _make_initial_state()
        state["tool_results"] = [{
            "tool": "nmap", "target": _TARGET, "parser": "nmap", "task_id": "t-2",
            "returncode": 0, "error": None, "stdout": "", "stderr": "",
            "skipped_duplicate": True, "duplicate_fingerprint": "abc123",
        }]
        await node(state)

        # No episode was appended for the skipped-duplicate result — the
        # episodic store stays empty (F13: skipped duplicates are recorded
        # separately via duplicate_actions, never as an execution episode).
        all_episodes = await api._episodic.all()  # type: ignore[attr-defined]
        assert all_episodes == []


# ---------------------------------------------------------------------------
# 13 & 14. Host-only graph / precise stall reasons
# ---------------------------------------------------------------------------


class TestPhaseTransitionEvidenceGating:
    def test_host_only_graph_does_not_enter_credential(self) -> None:
        gp = GlobalPlanner(max_turns=100, phase_budgets={ApexPhase.recon.value: 2})
        gp.record_turn(ApexPhase.recon)
        gp.record_turn(ApexPhase.recon)
        assert gp.budget_remaining(ApexPhase.recon.value) == 0

        phase = gp.decide_phase(node_types_seen={"host"}, turn_count=2, current_phase="recon")
        assert phase == ApexPhase.done
        assert phase != ApexPhase.credential

    def test_missing_service_capability_produces_precise_stall_reason(self) -> None:
        decision = evaluate_termination(
            max_turns=100, turn_count=2, objective_verified=False,
            next_phase="done", current_phase="recon",
            stall=StallDecision(stalled=False, outcome=None, reason=""),
        )
        assert decision.terminate is True
        assert decision.outcome is EngagementOutcome.phase_budget_exhausted
        assert "no services discovered" in decision.reason.lower()


# ---------------------------------------------------------------------------
# 15. The run terminates earlier than the prior six-repeat scenario
# ---------------------------------------------------------------------------


class TestSixNmapRepeatScenarioTerminatesEarlier:
    @pytest.mark.asyncio
    async def test_full_graph_stops_well_before_six_real_executions(self) -> None:
        """End-to-end simulation of the exact live-test scenario: nmap
        always fails with a raw-socket permission error (a fake, in-process
        ToolBackend — never a real subprocess/network call). Before this
        phase's fix, this would execute nmap six times (once per turn,
        duplicate_actions.total_skipped staying zero) before cascading
        through several empty "no action" phases. After the fix, nmap
        executes at most once for real and the engagement terminates within
        a handful of turns via the stall detector's duplicate-streak
        signal, never advancing into a capability-dependent phase."""
        backend = _RawSocketFailBackend()

        async def _run_command_fn(cmd: Any, cfg: Any) -> Any:
            raise AssertionError("must not be reached — fake tool_backend intercepts all execution")

        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=20,
            allowed_tools=["nmap"], tool_backend="remote",
            tool_service_url="http://fake-kali.invalid",
        )
        registry = ToolRegistry(allowed_tools=["nmap"])
        api = _make_api()

        graph = build_apex_graph(api, registry, config, tool_backend=backend)  # type: ignore[arg-type]

        initial_state = _make_initial_state(run_id="run-six-repeat")
        final_state = await graph.ainvoke(
            initial_state,
            config={"configurable": {"thread_id": "run-six-repeat"}, "recursion_limit": 200},
        )

        assert final_state["completed"] is True
        # The core proof: nmap never executed six times for real.
        assert backend.call_count <= 2, f"nmap executed {backend.call_count} times — duplicate suppression failed"
        # Never fabricated its way into credential/objective/priv_esc —
        # the engagement's outcome reflects a bounded, precise stop.
        assert final_state["outcome"] in (
            EngagementOutcome.duplicate_task_stall.value,
            EngagementOutcome.phase_budget_exhausted.value,
            EngagementOutcome.no_actionable_task.value,
        )
        # Terminates in a small, bounded number of turns — nowhere near
        # the prior six-repeat-plus-cascading-abandon-turns scenario.
        assert final_state["turn_count"] < 10


# ---------------------------------------------------------------------------
# 16, 17, 18. Concurrency / reservation regressions (extended for failures)
# ---------------------------------------------------------------------------


class TestConcurrencyAndReservationRegressions:
    @pytest.mark.asyncio
    async def test_concurrent_identical_failing_tasks_only_one_executes(self) -> None:
        """Extends the existing SUCCESS-only concurrency race test to the
        FAILURE path — in-flight suppression must remain race-safe even
        when the winning attempt is destined to fail terminally."""
        backend = _RawSocketFailBackend()

        async def _run(cmd: ToolCommand, cfg: Any) -> ToolResult:
            await asyncio.sleep(0)  # yield, maximize race window
            return await backend.execute(cmd.tool, cmd.args)

        reg = TaskRegistry()
        dispatcher = _make_dispatcher(run_command_fn=_run, registry=reg)
        task1, task2 = _make_task(), _make_task()
        results = await asyncio.gather(
            dispatcher.dispatch(task1, _make_ctx()),
            dispatcher.dispatch(task2, _make_ctx()),
        )
        assert backend.call_count == 1
        skipped = sum(1 for dr in results if dr.disposition is ExecutionDisposition.SKIPPED_DUPLICATE)
        assert skipped == 1

    @pytest.mark.asyncio
    async def test_reservation_released_after_cancellation_allows_retry(self) -> None:
        reg = TaskRegistry()
        fp = "cancel-fp-1"
        await reg.reserve(fingerprint=fp, task_id="t1", run_id="r1", phase="recon")
        await reg.update_status(fp, TaskStatus.CANCELLED)
        ok, _ = await reg.reserve(fingerprint=fp, task_id="t2", run_id="r1", phase="recon")
        assert ok is True

    @pytest.mark.asyncio
    async def test_reservation_released_after_completion_blocks_retry(self) -> None:
        reg = TaskRegistry()
        fp = "complete-fp-1"
        await reg.reserve(fingerprint=fp, task_id="t1", run_id="r1", phase="recon")
        await reg.update_status(fp, TaskStatus.COMPLETED)
        ok, _ = await reg.reserve(fingerprint=fp, task_id="t2", run_id="r1", phase="recon")
        assert ok is False

    def test_superseded_status_suppresses_resubmission(self) -> None:
        assert TaskStatus.SUPERSEDED.suppresses_new_submission is True

    def test_timed_out_status_does_not_suppress(self) -> None:
        assert TaskStatus.TIMED_OUT.suppresses_new_submission is False

    def test_attempt_count_tracks_across_reservations(self) -> None:
        reg = TaskRegistry()
        assert reg.attempt_count("fp") == 0

        async def _run() -> None:
            await reg.reserve(fingerprint="fp", task_id="t1", run_id="r1", phase="recon")
            await reg.update_status("fp", TaskStatus.FAILED_RETRYABLE)
            await reg.reserve(fingerprint="fp", task_id="t2", run_id="r1", phase="recon")

        asyncio.run(_run())
        assert reg.attempt_count("fp") == 2
