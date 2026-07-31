# test_bounded_repair_dedup.py
# Focused tests for bounded repair, terminal-failure suppression, semantic duplicate identity, and the bounded-repair report summary (CLAUDE.md §27).
"""Bounded-repair / semantic-duplicate-suppression regression tests.

Proves the behaviors required after the live finding where APEX recognized a
fundamental nmap failure yet re-executed the same failing strategy while
duplicate avoidance stayed zero:

- a fundamental (raw-socket) failure is recorded FAILED_TERMINAL and is never
  retried unchanged;
- a retryable transport timeout follows the existing bounded fingerprint-retry
  limit;
- semantically equivalent nmap commands (harmless flag reordering) and
  equivalent URL forms normalize to ONE canonical action identity, while
  opposite flag/value pairs stay distinct;
- a deterministic raw-socket ``-sT`` repair is a DISTINCT action from the
  original privileged strategy, runs once, and consumes NO LLM budget;
- policy-blocked tasks are neither retried nor repaired (no loop);
- a missing credential prerequisite never routes into the credential phase
  (no repeated no-action turns);
- the report's duplicate/suppression/repair/terminal/no-action/stall metrics
  increment correctly and never fabricate a finding or force a phase.

Every test uses in-process fake planners/runners — no real subprocess, no
network, no LLM, no live HTB engagement.
"""
from __future__ import annotations

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
from memfabric.types import EvidenceBundle, Node, SubgraphView, TaskSpec

from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispatcher import TaskDispatcher
from apex_host.execution.dispositions import (
    ExecutionDisposition,
    classify_retry,
)
from apex_host.execution.registry import TaskRegistry, TaskStatus
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.planners.phase_gates import credential_hypothesis
from apex_host.planning.fingerprint import task_fingerprint
from apex_host.tools.nmap_command import plan_raw_socket_repair
from apex_host.types import ApexPhase, ToolCommand, ToolResult

# RFC 5737 documentation IP — never a live HTB address.
_TARGET = "192.0.2.10"
_ANCHOR = f"host:{_TARGET}"

_RAW_SOCKET_STDERR = (
    "Couldn't open a raw socket. Error: (1) Operation not permitted\nQUITTING!"
)


# ---------------------------------------------------------------------------
# Shared minimal fakes
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


def _make_subgraph(nodes: list[Node] | None = None) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=nodes or [], edges=[], depth=2)


def _make_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=_make_subgraph(), tiers_queried=[])


def _make_task(tool: str = "nmap", args: list[str] | None = None, target: str = _TARGET,
               parser: str = "nmap", executor_domain: str = "recon") -> TaskSpec:
    return TaskSpec(
        id=new_id(), goal_id=new_id(), executor_domain=executor_domain,
        params={"tool": tool, "args": args if args is not None else ["-sV", target],
                "target": target, "parser": parser},
        subgraph_anchor=_ANCHOR, phase="recon",
    )


def _make_ctx(phase: str = "recon", dry_run: bool = False) -> ExecutionContext:
    return ExecutionContext(
        run_id="run-brd", phase=phase, turn_number=1, evidence_version=None,
        subgraph=_make_subgraph(), evidence=_make_evidence(), dry_run=dry_run,
    )


class _Advisor:
    """Minimal PolicyAdvisor fake — approves or blocks every task."""

    def __init__(self, approve: bool = True) -> None:
        self._approve = approve

    def review_task(self, task: Any, phase: Any, evidence: Any, config: Any) -> Any:
        from unittest.mock import MagicMock
        d = MagicMock()
        d.is_approved = self._approve
        d.status = MagicMock()
        d.status.value = "approved" if self._approve else "blocked"
        d.rule_name = "default_allow" if self._approve else "no_destructive_command"
        d.reason = "" if self._approve else "out of scope"
        return d


class _Config:
    target = _TARGET
    dry_run = False
    max_command_seconds = 30
    tool_backend = "local"
    tool_backend_raw_socket_capable: bool | None = None
    max_fingerprint_retries = 1


def _make_dispatcher(run_command_fn: Any, *, approve: bool = True,
                     registry: TaskRegistry | None = None,
                     config: Any | None = None) -> TaskDispatcher:
    return TaskDispatcher(
        advisor=_Advisor(approve=approve), task_registry=registry or TaskRegistry(),
        config=config or _Config(), run_command_fn=run_command_fn,
    )


class _Backend:
    """Fake ToolBackend returning a fixed result per tool — no subprocess."""

    def __init__(self, *, returncode: int = 0, stderr: str = "",
                 error: str | None = None) -> None:
        self.call_count = 0
        self.calls: list[tuple[str, list[str]]] = []
        self._rc = returncode
        self._stderr = stderr
        self._error = error

    async def run(self, cmd: ToolCommand, cfg: Any) -> ToolResult:
        self.call_count += 1
        self.calls.append((cmd.tool, list(cmd.args)))
        return ToolResult(
            command=cmd, stdout="" if self._rc else "ok", stderr=self._stderr,
            returncode=self._rc, duration_seconds=0.001, dry_run=False,
            backend="remote", error=self._error,
        )


# ===========================================================================
# 1. Semantic duplicate identity (pure fingerprint)
# ===========================================================================


class TestSemanticIdentity:
    def test_semantically_equivalent_nmap_commands_deduplicate(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", ["-sV", "-T4", _TARGET], _TARGET,
                               parser="nmap", executor_domain="recon")
        fp2 = task_fingerprint("recon", "nmap", ["-T4", "-sV", _TARGET], _TARGET,
                               parser="nmap", executor_domain="recon")
        assert fp1 == fp2

    def test_opposite_flag_value_pairs_stay_distinct(self) -> None:
        fp1 = task_fingerprint("recon", "nmap", ["-p", "80", "--exclude", "443"], _TARGET)
        fp2 = task_fingerprint("recon", "nmap", ["-p", "443", "--exclude", "80"], _TARGET)
        assert fp1 != fp2

    def test_equivalent_url_forms_normalize_to_one_identity(self) -> None:
        a = task_fingerprint("web", "curl", ["-s", "-I", "http://host/"], "http://host/")
        b = task_fingerprint("web", "curl", ["-s", "-I", "http://host"], "http://host")
        c = task_fingerprint("web", "curl", ["-s", "-I", "http://HOST:80/"], "http://HOST:80")
        assert a == b == c

    def test_distinct_url_paths_remain_distinct(self) -> None:
        a = task_fingerprint("web", "curl", ["-s", "http://host/a"], "http://host/a")
        b = task_fingerprint("web", "curl", ["-s", "http://host/b"], "http://host/b")
        assert a != b

    def test_generic_tool_argument_order_is_preserved(self) -> None:
        # A non-nmap tool's positional order can be semantically meaningful and
        # must never be reordered away.
        a = task_fingerprint("web", "curl", ["-a", "-b"], _TARGET)
        b = task_fingerprint("web", "curl", ["-b", "-a"], _TARGET)
        assert a != b

    @pytest.mark.asyncio
    async def test_reordered_nmap_second_dispatch_is_suppressed(self) -> None:
        backend = _Backend(returncode=0)  # succeeds
        reg = TaskRegistry()
        dispatcher = _make_dispatcher(backend.run, registry=reg)
        dr1 = await dispatcher.dispatch(_make_task(args=["-sV", "-T4", _TARGET]), _make_ctx())
        dr2 = await dispatcher.dispatch(_make_task(args=["-T4", "-sV", _TARGET]), _make_ctx())
        assert dr1.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert dr2.disposition is ExecutionDisposition.SKIPPED_DUPLICATE
        assert backend.call_count == 1  # the reordered duplicate never ran


# ===========================================================================
# 2. Terminal failure is not retried unchanged
# ===========================================================================


class TestTerminalNotRetried:
    @pytest.mark.asyncio
    async def test_fundamental_failure_not_retried_unchanged(self) -> None:
        backend = _Backend(returncode=1, stderr=_RAW_SOCKET_STDERR, error=_RAW_SOCKET_STDERR)
        reg = TaskRegistry()
        dispatcher = _make_dispatcher(backend.run, registry=reg)
        dr1 = await dispatcher.dispatch(_make_task(), _make_ctx())
        dr2 = await dispatcher.dispatch(_make_task(), _make_ctx())
        assert dr1.disposition is ExecutionDisposition.EXECUTED_FAILURE
        assert dr1.retryable is False
        rec = reg.get(dr1.fingerprint)
        assert rec is not None and rec.status is TaskStatus.FAILED_TERMINAL
        assert dr2.disposition is ExecutionDisposition.SKIPPED_DUPLICATE
        assert backend.call_count == 1

    def test_classify_retry_marks_raw_socket_non_retryable(self) -> None:
        decision = classify_retry(ExecutionDisposition.EXECUTED_FAILURE, _RAW_SOCKET_STDERR)
        assert decision.may_retry is False

    def test_terminal_classifier_not_overridden_by_shape(self) -> None:
        # A disposition whose SHAPE is retryable-looking must still be governed
        # by the specific classify_retry decision on the actual error.
        assert ExecutionDisposition.EXECUTED_FAILURE.is_retryable is True  # shape only
        assert classify_retry(
            ExecutionDisposition.EXECUTED_FAILURE, _RAW_SOCKET_STDERR
        ).may_retry is False


# ===========================================================================
# 3. Retryable transport timeout follows bounded retry limit
# ===========================================================================


class TestBoundedTimeoutRetry:
    @pytest.mark.asyncio
    async def test_transient_timeout_is_bounded(self) -> None:
        backend = _Backend(returncode=1, error="connection timed out")
        reg = TaskRegistry()
        # max_fingerprint_retries=1 → one bounded resubmission, then terminal.
        dispatcher = _make_dispatcher(backend.run, registry=reg, config=_Config())
        dr1 = await dispatcher.dispatch(_make_task(), _make_ctx())
        assert dr1.retryable is True
        rec1 = reg.get(dr1.fingerprint)
        assert rec1 is not None and rec1.status is TaskStatus.FAILED_RETRYABLE
        dr2 = await dispatcher.dispatch(_make_task(), _make_ctx())  # bounded retry
        rec2 = reg.get(dr2.fingerprint)
        assert rec2 is not None and rec2.status is TaskStatus.FAILED_TERMINAL
        dr3 = await dispatcher.dispatch(_make_task(), _make_ctx())  # now suppressed
        assert dr3.disposition is ExecutionDisposition.SKIPPED_DUPLICATE
        assert backend.call_count == 2  # exactly two real attempts


# ===========================================================================
# 4. Policy-blocked tasks do not loop
# ===========================================================================


class TestPolicyNoLoop:
    @pytest.mark.asyncio
    async def test_policy_blocked_task_is_not_retried_or_repaired(self) -> None:
        backend = _Backend(returncode=0)
        dispatcher = _make_dispatcher(backend.run, approve=False)
        dr = await dispatcher.dispatch(_make_task(), _make_ctx())
        assert dr.disposition is ExecutionDisposition.BLOCKED_POLICY
        assert dr.retryable is False
        assert dr.repairable is False
        assert backend.call_count == 0  # never executed

    def test_classify_retry_never_retries_a_policy_block(self) -> None:
        d = classify_retry(ExecutionDisposition.BLOCKED_POLICY, "out of scope")
        assert d.may_retry is False and d.may_repair is False


# ===========================================================================
# 5. Deterministic repair: distinct -sT, runs once, no LLM budget
# ===========================================================================


def _build_deps(api: MemoryAPI, config: Any, *, repair_engine: Any, dispatcher: Any) -> Any:
    from apex_host.capabilities.runtime_references import (
        RuntimeReferenceResolver,
        RuntimeReferenceStore,
    )
    from apex_host.orchestration.dependencies import OrchestrationDeps
    from apex_host.orchestration.stall import StallTracker
    from apex_host.runtime_registry import CapabilityRuntimeRegistry

    reg = CapabilityRuntimeRegistry()
    store = RuntimeReferenceStore()
    return OrchestrationDeps(
        api=api, dispatcher=dispatcher, global_planner=GlobalPlanner(max_turns=20),
        phase_planners={}, repair_engine=repair_engine, config=config,
        anchor_id=_ANCHOR, stall_tracker=StallTracker(),
        capability_registry=reg, runtime_reference_store=store,
        runtime_reference_resolver=RuntimeReferenceResolver(store, reg),
    )


def _initial_state() -> dict[str, Any]:
    return {
        "run_id": "run-brd", "target": _TARGET, "phase": "recon",
        "goal": "recon", "current_task": None, "evidence_summary": "",
        "findings": [], "error_episodes": [], "last_tool_result": None,
        "last_error": None, "completed": False, "turn_count": 0,
        "planner_decisions": [], "tool_results": None, "repair_count": 0,
        "policy_decisions": [], "duplicate_actions": [], "repair_log": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "",
    }


class _SpyRepairEngine:
    """Records whether the LLM repair engine was ever consulted."""

    def __init__(self) -> None:
        self.called = False

    async def repair(self, **kwargs: Any) -> Any:
        self.called = True
        raise AssertionError("deterministic repair must not consult the LLM engine")


class _StubDispatcher:
    def __init__(self) -> None:
        self.task_registry = TaskRegistry()
        self.dispatched: list[TaskSpec] = []

    async def dispatch(self, task: TaskSpec, ctx: Any) -> Any:
        self.dispatched.append(task)

        class _R:
            disposition = ExecutionDisposition.EXECUTED_SUCCESS
            tool_result_dict = {
                "tool": "nmap", "target": _TARGET, "parser": "nmap",
                "returncode": 0, "stdout": "", "error": None, "task_id": task.id,
            }
            audit_metadata: dict[str, Any] = {}
        return _R()


class TestDeterministicRepair:
    @pytest.mark.asyncio
    async def test_raw_socket_repair_runs_sT_once_distinct_and_no_llm(self) -> None:
        from apex_host.orchestration.repair_node import make_repair_node

        api = _make_api()
        spy = _SpyRepairEngine()
        disp = _StubDispatcher()
        deps = _build_deps(api, _Config(), repair_engine=spy, dispatcher=disp)
        node = make_repair_node(deps)

        state = _initial_state()
        state["last_tool_result"] = {
            "tool": "nmap", "error": _RAW_SOCKET_STDERR, "task_id": "t-1",
            "returncode": 1, "error_category": "raw_socket_permission_denied",
        }
        state["current_task"] = {
            "params": {"tool": "nmap", "args": ["-sV", _TARGET], "target": _TARGET, "parser": "nmap"},
            "executor_domain": "recon",
        }
        result = await node(state)

        # Deterministic repair ran exactly one action, an -sT scan, distinct
        # from the original privileged strategy — and never touched the LLM.
        assert spy.called is False
        assert len(disp.dispatched) == 1
        repaired_args = list(disp.dispatched[0].params.get("args", []))
        assert "-sT" in repaired_args
        original_fp = task_fingerprint("recon", "nmap", ["-sV", _TARGET], _TARGET,
                                       parser="nmap", executor_domain="recon")
        repaired_fp = task_fingerprint("recon", "nmap", repaired_args, _TARGET,
                                       parser="nmap", executor_domain="recon")
        assert original_fp != repaired_fp
        assert result["repair_log"][0]["outcome"] == "succeeded"
        assert result["repair_log"][0]["kind"] == "raw_socket_to_tcp_connect"

    def test_raw_socket_repair_is_terminal_when_already_tcp_connect(self) -> None:
        plan = plan_raw_socket_repair(["-sT", "-sV", _TARGET], _TARGET)
        assert plan.terminal is True
        assert plan.repaired_args is None


# ===========================================================================
# 6. Missing credential prerequisite → no credential phase / no-action loop
# ===========================================================================


class TestMissingCredentialPrereq:
    def test_no_hypothesis_does_not_enter_credential_phase(self) -> None:
        # A service-only graph with NO operator credentials, no discovered
        # credential, and no auth-bypass opportunity: credential validation is
        # an unavailable prerequisite, so the router must NOT enter credential.
        sub = _make_subgraph([
            Node(id=_ANCHOR, type="host", props={"ip": _TARGET}, confidence=0.9,
                 source="t", first_seen="", last_seen=""),
            Node(id=f"service:{_TARGET}:22", type="service",
                 props={"port": "22", "service": "ssh"}, confidence=0.8,
                 source="t", first_seen="", last_seen=""),
        ])
        hyp = credential_hypothesis(sub, has_operator_credentials=False)
        assert hyp.available is False
        assert hyp.reason == "missing_credential_hypothesis"

        gp = GlobalPlanner(max_turns=20)
        phase = gp.decide_phase(
            node_types_seen={"host", "service"}, turn_count=1,
            has_web_capability=False, has_credential_hypothesis=False,
            web_evidence_complete=None, current_phase="recon",
        )
        assert phase != ApexPhase.credential
        assert phase is ApexPhase.done

    def test_operator_credentials_make_the_hypothesis_available(self) -> None:
        sub = _make_subgraph([
            Node(id=_ANCHOR, type="host", props={"ip": _TARGET}, confidence=0.9,
                 source="t", first_seen="", last_seen=""),
        ])
        hyp = credential_hypothesis(sub, has_operator_credentials=True)
        assert hyp.available is True
        assert hyp.source == "operator_supplied"


# ===========================================================================
# 7. Report metrics
# ===========================================================================


def _build_report(final_state: dict[str, Any]) -> Any:
    from apex_host.config import ApexConfig
    from apex_host.eval.report import build_report

    config = ApexConfig(target=_TARGET, dry_run=True)
    return build_report(final_state, _make_subgraph(), config)  # type: ignore[arg-type]


class TestReportMetrics:
    def test_duplicate_avoidance_metrics_increment(self) -> None:
        state = _initial_state()
        state["duplicate_actions"] = [
            {"fingerprint": "aa", "tool": "nmap", "target": _TARGET,
             "phase": "recon", "disposition": "skipped_duplicate"},
            {"fingerprint": "aa", "tool": "nmap", "target": _TARGET,
             "phase": "recon", "disposition": "skipped_duplicate"},
        ]
        report = _build_report(state)
        assert report.duplicate_action_count == 2
        assert report.executions_suppressed == 2
        assert report.terminal_strategies_recorded == 0

    def test_repair_and_terminal_summary_counts(self) -> None:
        state = _initial_state()
        state["duplicate_actions"] = [
            {"fingerprint": "t1", "tool": "nmap", "target": _TARGET,
             "phase": "recon", "disposition": "raw_socket_terminal"},
        ]
        state["repair_log"] = [
            {"kind": "raw_socket_to_tcp_connect", "tool": "nmap", "target": _TARGET,
             "phase": "recon", "outcome": "succeeded", "changed_action": True},
            {"kind": "llm", "tool": "curl", "target": _TARGET, "phase": "web",
             "outcome": "failed", "changed_action": True},
            {"kind": "raw_socket_to_tcp_connect", "tool": "nmap", "target": _TARGET,
             "phase": "recon", "outcome": "terminal", "changed_action": False},
        ]
        report = _build_report(state)
        assert report.terminal_strategies_recorded == 1
        assert report.repairs_attempted == 3
        assert report.repairs_succeeded == 1
        assert report.repairs_failed == 1
        assert report.repairs_terminal == 1

    def test_stall_reason_in_report_matches_actual_cause(self) -> None:
        from apex_host.eval.report import to_json_dict
        from apex_host.orchestration.outcome import EngagementOutcome
        from apex_host.orchestration.stall import StallTracker

        # The tracker attributes a genuine duplicate streak to the duplicate
        # cause, not a generic stall.
        tracker = StallTracker(threshold=2)
        d1 = tracker.record_turn(
            had_action=False, duplicate_actions=[{"x": 1}], policy_decisions=[],
            planner_fingerprint="recon:", state_fingerprint="recon|host",
        )
        assert d1.stalled is False
        d2 = tracker.record_turn(
            had_action=False, duplicate_actions=[{"x": 1}, {"x": 2}], policy_decisions=[],
            planner_fingerprint="recon:", state_fingerprint="recon|host",
        )
        assert d2.stalled is True
        assert d2.outcome is EngagementOutcome.duplicate_task_stall

        state = _initial_state()
        state["stall_reason"] = d2.reason
        report = _build_report(state)
        assert report.stall_reason == d2.reason
        js = to_json_dict(report)
        assert js["bounded_repair"]["dominant_stall_reason"] == d2.reason

    def test_no_fake_findings_or_forced_completion_on_terminal_failure(self) -> None:
        # A run that only ever produced a terminal nmap failure must not
        # fabricate a finding nor report a success outcome.
        state = _initial_state()
        state["duplicate_actions"] = [
            {"fingerprint": "t1", "tool": "nmap", "target": _TARGET,
             "phase": "recon", "disposition": "raw_socket_terminal"},
        ]
        state["repair_log"] = [
            {"kind": "raw_socket_to_tcp_connect", "tool": "nmap", "target": _TARGET,
             "phase": "recon", "outcome": "terminal", "changed_action": False},
        ]
        report = _build_report(state)
        assert report.findings == []
        assert report.success is False
        assert report.terminal_strategies_recorded == 1

    def test_no_action_reason_counts_distinguish_causes(self) -> None:
        state = _initial_state()
        state["duplicate_actions"] = [
            {"disposition": "skipped_duplicate", "phase": "recon"},
            {"disposition": "raw_socket_terminal", "phase": "recon"},
        ]
        state["policy_decisions"] = [{"status": "blocked"}]
        report = _build_report(state)
        counts = report.no_action_reason_counts
        assert counts.get("skipped_duplicate") == 1
        assert counts.get("raw_socket_terminal") == 1
        assert counts.get("policy_blocked") == 1
