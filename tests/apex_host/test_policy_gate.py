# test_policy_gate.py
# Integration tests for the execution-time PolicyAdvisor gate wired into graph.py.
"""Tests for the execution-time policy gate in the APEX LangGraph.

Acceptance criteria:
  - Approved tasks reach runner.py (run_command is called).
  - Blocked tasks NEVER reach runner.py.
  - Blocked credential tasks NEVER reach TelnetExecutor.run().
  - Blocked tasks appear in state["policy_decisions"] and in the run report.
  - Blocked browser tasks NEVER reach BrowserExecutor.run().
  - Repaired tasks are also gated by policy.

All tests use dry_run=True (the default) and inject a _FakeAdvisor so the
policy gate behaviour is deterministic regardless of real policy-file state.
No real commands or network connections are made.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

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
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.graph import build_apex_graph
from apex_host.graph_state import ApexGraphState
from apex_host.policy.models import PolicyDecision, PolicyStatus, ScopePolicy
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ToolCommand, ToolResult


# ---------------------------------------------------------------------------
# Helpers
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


def _make_initial_state(target: str, run_id: str = "run-gate-test") -> ApexGraphState:
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
    }


def _fake_tool_result(*, stdout: str = "", returncode: int = 0) -> ToolResult:
    """Construct a minimal valid ToolResult for use in monkeypatches."""
    return ToolResult(
        command=ToolCommand(tool="nmap", args=[], timeout_seconds=30),
        stdout=stdout,
        stderr="",
        returncode=returncode,
        duration_seconds=0.0,
        dry_run=True,
        error=None,
    )


class _FakeAdvisor:
    """Test double for PolicyAdvisor with a fixed always-block or always-allow mode."""

    def __init__(self, *, always_blocked: bool = False, block_tool: str | None = None) -> None:
        self._always_blocked = always_blocked
        self._block_tool = block_tool

    def review_task(
        self, task: Any, phase: str, evidence: Any, config: Any
    ) -> PolicyDecision:
        tool = str(task.params.get("tool", "") or task.params.get("kind", ""))
        if self._always_blocked or (
            self._block_tool is not None and tool == self._block_tool
        ):
            return PolicyDecision(
                status=PolicyStatus.blocked,
                rule_name="test_block",
                reason=f"test policy block for tool={tool!r}",
                task_tool=tool,
            )
        return PolicyDecision(
            status=PolicyStatus.approved,
            rule_name="test_allow",
            reason="test policy allow",
            task_tool=tool,
        )

    @property
    def policy(self) -> ScopePolicy:
        return ScopePolicy(
            allowed_targets=frozenset({"127.0.0.1"}),
            blocked_tools=frozenset(),
            allow_password_lists=False,
            allow_sensitive_data_access=False,
            require_review_for=[],
            policy_loaded=False,
            policy_source="test_fake",
        )


class _FakeSubgraph:
    def __init__(self) -> None:
        self.nodes: list[Any] = []
        self.edges: list[Any] = []


async def _seed_host_telnet(api: MemoryAPI, target: str) -> None:
    """Seed host + telnet service nodes so GlobalPlanner routes to credential."""
    ts = now()
    await api.upsert_node(Node(
        id=f"host:{target}", type="host",
        props={"ip": target}, confidence=0.9, source="test",
        first_seen=ts, last_seen=ts,
    ))
    await api.upsert_node(Node(
        id=f"service:{target}:23", type="service",
        props={"port": "23", "service": "telnet", "proto": "tcp"},
        confidence=0.9, source="test", first_seen=ts, last_seen=ts,
    ))
    await api.upsert_edge(Edge(
        id=f"edge:exposes:{target}:23",
        from_id=f"host:{target}",
        to_id=f"service:{target}:23",
        type="exposes", props={}, confidence=0.9, source="test",
        first_seen=ts, last_seen=ts,
    ))


async def _seed_host_http(api: MemoryAPI, target: str) -> None:
    """Seed host + HTTP service (no endpoint) so GlobalPlanner picks web phase.

    GlobalPlanner decides web when: host + service present BUT no endpoint yet.
    With a prior web finding in state["findings"], route_after_global_plan then
    selects browser_agent (the second-visit web flow).
    """
    ts = now()
    await api.upsert_node(Node(
        id=f"host:{target}", type="host",
        props={"ip": target}, confidence=0.9, source="test",
        first_seen=ts, last_seen=ts,
    ))
    await api.upsert_node(Node(
        id=f"service:{target}:80", type="service",
        props={"port": "80", "service": "http", "proto": "tcp"},
        confidence=0.9, source="test", first_seen=ts, last_seen=ts,
    ))
    await api.upsert_edge(Edge(
        id=f"edge:exposes:{target}:80",
        from_id=f"host:{target}",
        to_id=f"service:{target}:80",
        type="exposes", props={}, confidence=0.9, source="test",
        first_seen=ts, last_seen=ts,
    ))


# ---------------------------------------------------------------------------
# Test: Approved tasks reach runner (dry-run path — no real subprocess)
# ---------------------------------------------------------------------------

class TestApprovedReachesRunner:
    async def test_approved_task_completes_without_blocking(self) -> None:
        """With an always-approved advisor, the graph completes with no blocked decisions."""
        advisor = _FakeAdvisor(always_blocked=False)

        target = "127.0.0.1"
        api = _make_api()
        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        final_state = await graph.ainvoke(_make_initial_state(target))

        pd_list = final_state.get("policy_decisions", [])
        blocked = [d for d in pd_list if d.get("status") == "blocked"]
        assert len(blocked) == 0, (
            f"No tasks should be blocked with an always-approved advisor; got: {blocked}"
        )

    async def test_approved_policy_decisions_recorded_in_state(self) -> None:
        """Policy decisions for approved tasks are recorded in state."""
        advisor = _FakeAdvisor(always_blocked=False)

        target = "127.0.0.1"
        api = _make_api()
        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        final_state = await graph.ainvoke(_make_initial_state(target))

        pd_list = final_state.get("policy_decisions", [])
        assert any(d.get("status") == "approved" for d in pd_list), (
            "Expected at least one approved policy decision entry"
        )

    async def test_approved_run_command_is_called(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With an approved advisor, run_command is invoked (gate opens)."""
        advisor = _FakeAdvisor(always_blocked=False)
        run_calls: list[Any] = []

        async def _spy_run_command(cmd: Any, cfg: Any) -> ToolResult:
            run_calls.append(cmd)
            return _fake_tool_result(stdout=f"[dry-run] {cmd.tool}")

        monkeypatch.setattr("apex_host.tools.runner.run_command", _spy_run_command)

        target = "127.0.0.1"
        api = _make_api()
        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        await graph.ainvoke(_make_initial_state(target))

        assert len(run_calls) > 0, (
            "run_command should have been called at least once for an approved task"
        )


# ---------------------------------------------------------------------------
# Test: Blocked tasks never reach runner
# ---------------------------------------------------------------------------

class TestBlockedNeverReachesRunner:
    async def test_blocked_task_run_command_not_called(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With an always-blocked advisor, run_command must NEVER be called."""
        advisor = _FakeAdvisor(always_blocked=True)
        run_calls: list[Any] = []

        async def _forbidden_run_command(cmd: Any, cfg: Any) -> ToolResult:
            run_calls.append(cmd)
            raise AssertionError(
                f"run_command must not be called when task is blocked; called with {cmd}"
            )

        monkeypatch.setattr("apex_host.tools.runner.run_command", _forbidden_run_command)

        target = "127.0.0.1"
        api = _make_api()
        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        await graph.ainvoke(_make_initial_state(target))

        assert len(run_calls) == 0, (
            f"run_command must not be called when all tasks are blocked; got {run_calls}"
        )

    async def test_blocked_task_in_policy_decisions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Blocked tasks are recorded in state['policy_decisions']."""
        advisor = _FakeAdvisor(always_blocked=True)
        monkeypatch.setattr(
            "apex_host.tools.runner.run_command",
            AsyncMock(return_value=_fake_tool_result()),
        )

        target = "127.0.0.1"
        api = _make_api()
        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        final_state = await graph.ainvoke(_make_initial_state(target))

        pd_list = final_state.get("policy_decisions", [])
        assert len(pd_list) > 0, "policy_decisions should be non-empty after a blocked turn"
        blocked = [d for d in pd_list if d.get("status") == "blocked"]
        assert len(blocked) > 0, "at least one blocked decision expected"

    async def test_blocked_tool_result_has_policy_blocked_flag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The tool_result for a blocked task must carry policy_blocked=True."""
        advisor = _FakeAdvisor(always_blocked=True)
        monkeypatch.setattr(
            "apex_host.tools.runner.run_command",
            AsyncMock(return_value=_fake_tool_result()),
        )

        target = "127.0.0.1"
        api = _make_api()
        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        final_state = await graph.ainvoke(_make_initial_state(target))

        last_tr = final_state.get("last_tool_result") or {}
        assert last_tr.get("policy_blocked") is True, (
            "last_tool_result.policy_blocked must be True for a blocked task"
        )

    async def test_blocked_error_contains_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The error field in a blocked result contains the policy reason."""
        advisor = _FakeAdvisor(always_blocked=True)
        monkeypatch.setattr(
            "apex_host.tools.runner.run_command",
            AsyncMock(return_value=_fake_tool_result()),
        )

        target = "127.0.0.1"
        api = _make_api()
        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        final_state = await graph.ainvoke(_make_initial_state(target))

        last_tr = final_state.get("last_tool_result") or {}
        assert "policy_blocked" in str(last_tr.get("error", "")), (
            "error field should contain 'policy_blocked'"
        )


# ---------------------------------------------------------------------------
# Test: Blocked credential tasks never reach TelnetExecutor
# ---------------------------------------------------------------------------

class TestBlockedCredentialNeverReachesTelnet:
    async def test_blocked_telnet_access_skips_executor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With advisor blocking telnet_access, TelnetExecutor.run must not be called."""
        advisor = _FakeAdvisor(block_tool="telnet_access")
        telnet_calls: list[Any] = []

        async def _forbidden_telnet_run(self_ex: Any, task: Any, evidence: Any) -> Any:
            telnet_calls.append(task)
            raise AssertionError("TelnetExecutor.run must not be called when task is blocked")

        monkeypatch.setattr(
            "apex_host.agents.telnet_executor.TelnetExecutor.run", _forbidden_telnet_run
        )
        monkeypatch.setattr(
            "apex_host.tools.runner.run_command",
            AsyncMock(return_value=_fake_tool_result()),
        )

        target = "127.0.0.1"
        api = _make_api()
        await _seed_host_telnet(api, target)

        config = ApexConfig(
            target=target,
            dry_run=True,
            max_turns=1,
            username_candidates=["root"],
            password_candidates=[""],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        await graph.ainvoke(_make_initial_state(target))

        assert len(telnet_calls) == 0, (
            "TelnetExecutor.run must not be called when the task is blocked"
        )

    async def test_blocked_credential_records_policy_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Blocked credential task appears in policy_decisions."""
        advisor = _FakeAdvisor(block_tool="telnet_access")
        monkeypatch.setattr(
            "apex_host.tools.runner.run_command",
            AsyncMock(return_value=_fake_tool_result()),
        )

        target = "127.0.0.1"
        api = _make_api()
        await _seed_host_telnet(api, target)

        config = ApexConfig(
            target=target, dry_run=True, max_turns=1,
            username_candidates=["root"], password_candidates=[""],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        final_state = await graph.ainvoke(_make_initial_state(target))

        pd_list = final_state.get("policy_decisions", [])
        blocked_telnet = [
            d for d in pd_list
            if d.get("tool") == "telnet_access" and d.get("status") == "blocked"
        ]
        assert len(blocked_telnet) > 0, (
            "policy_decisions must contain a blocked entry for telnet_access; "
            f"got: {pd_list}"
        )


# ---------------------------------------------------------------------------
# Test: Blocked tasks appear in run report
# ---------------------------------------------------------------------------

class TestBlockedAppearsInReport:
    def test_blocked_count_in_run_report(self) -> None:
        """build_report reflects blocked policy decisions from state."""
        state: ApexGraphState = {
            "run_id": "r1",
            "target": "127.0.0.1",
            "phase": "recon",
            "goal": "test",
            "current_task": None,
            "evidence_summary": "",
            "findings": [],
            "error_episodes": [],
            "last_tool_result": None,
            "last_error": None,
            "completed": True,
            "turn_count": 1,
            "planner_decisions": [],
            "tool_results": None,
            "repair_count": 0,
            "policy_decisions": [
                {"tool": "nmap", "target": "127.0.0.1", "phase": "recon",
                 "status": "approved", "rule_name": "safe_recon_allowed", "reason": "ok"},
                {"tool": "rm", "target": "127.0.0.1", "phase": "recon",
                 "status": "blocked", "rule_name": "no_destructive_command",
                 "reason": "rm is blocked"},
                {"tool": "hydra", "target": "127.0.0.1", "phase": "credential",
                 "status": "blocked", "rule_name": "no_destructive_command",
                 "reason": "hydra is blocked"},
            ],
        }
        config = ApexConfig(target="127.0.0.1", dry_run=True)
        subgraph = _FakeSubgraph()

        report = build_report(state, subgraph, config)  # type: ignore[arg-type]

        assert report.policy_approved_count == 1
        assert report.policy_blocked_count == 2
        assert report.policy_needs_review_count == 0
        assert len(report.last_blocked_reasons) == 2

    def test_needs_review_count_in_run_report(self) -> None:
        """needs_human_review decisions are counted correctly."""
        state: ApexGraphState = {
            "run_id": "r2",
            "target": "127.0.0.1",
            "phase": "web",
            "goal": "test",
            "current_task": None,
            "evidence_summary": "",
            "findings": [],
            "error_episodes": [],
            "last_tool_result": None,
            "last_error": None,
            "completed": True,
            "turn_count": 1,
            "planner_decisions": [],
            "tool_results": None,
            "repair_count": 0,
            "policy_decisions": [
                {"tool": "gobuster", "target": "127.0.0.1", "phase": "web",
                 "status": "needs_human_review", "rule_name": "require_review",
                 "reason": "gobuster needs human approval"},
            ],
        }
        config = ApexConfig(target="127.0.0.1", dry_run=True)
        subgraph = _FakeSubgraph()

        report = build_report(state, subgraph, config)  # type: ignore[arg-type]

        assert report.policy_needs_review_count == 1
        assert len(report.last_blocked_reasons) == 1
        assert "gobuster" in report.last_blocked_reasons[0]

    def test_format_text_contains_policy_gate_section(self) -> None:
        """format_text renders a 'Policy Gate' section with counts."""
        state: ApexGraphState = {
            "run_id": "r3",
            "target": "127.0.0.1",
            "phase": "recon",
            "goal": "test",
            "current_task": None,
            "evidence_summary": "",
            "findings": [],
            "error_episodes": [],
            "last_tool_result": None,
            "last_error": None,
            "completed": True,
            "turn_count": 2,
            "planner_decisions": [],
            "tool_results": None,
            "repair_count": 0,
            "policy_decisions": [
                {"tool": "nmap", "target": "127.0.0.1", "phase": "recon",
                 "status": "approved", "rule_name": "safe_recon_allowed", "reason": "ok"},
                {"tool": "rm", "target": "127.0.0.1", "phase": "recon",
                 "status": "blocked", "rule_name": "no_destructive_command",
                 "reason": "rm is blocked"},
            ],
        }
        config = ApexConfig(target="127.0.0.1", dry_run=True)
        subgraph = _FakeSubgraph()

        report = build_report(state, subgraph, config)  # type: ignore[arg-type]
        text = format_text(report)

        assert "Policy Gate" in text
        assert "Approved" in text
        assert "Blocked" in text

    def test_to_json_dict_includes_policy_gate_and_decisions(self) -> None:
        """to_json_dict must include both 'policy_gate' and 'policy_decisions'."""
        state: ApexGraphState = {
            "run_id": "r4",
            "target": "127.0.0.1",
            "phase": "recon",
            "goal": "test",
            "current_task": None,
            "evidence_summary": "",
            "findings": [],
            "error_episodes": [],
            "last_tool_result": None,
            "last_error": None,
            "completed": True,
            "turn_count": 1,
            "planner_decisions": [],
            "tool_results": None,
            "repair_count": 0,
            "policy_decisions": [
                {"tool": "nc", "target": "127.0.0.1", "phase": "recon",
                 "status": "approved", "rule_name": "safe_recon_allowed", "reason": "ok"},
            ],
        }
        config = ApexConfig(target="127.0.0.1", dry_run=True)
        subgraph = _FakeSubgraph()

        report = build_report(state, subgraph, config)  # type: ignore[arg-type]
        data = to_json_dict(report)

        assert "policy_gate" in data
        assert "policy_decisions" in data
        assert data["policy_gate"]["approved"] == 1
        assert data["policy_gate"]["blocked"] == 0
        assert len(data["policy_decisions"]) == 1

    def test_empty_policy_decisions_reports_zero_counts(self) -> None:
        """When no policy_decisions in state, all counts are 0."""
        state: ApexGraphState = {
            "run_id": "r5",
            "target": "127.0.0.1",
            "phase": "recon",
            "goal": "test",
            "current_task": None,
            "evidence_summary": "",
            "findings": [],
            "error_episodes": [],
            "last_tool_result": None,
            "last_error": None,
            "completed": True,
            "turn_count": 0,
            "planner_decisions": [],
            "tool_results": None,
            "repair_count": 0,
            "policy_decisions": [],
        }
        config = ApexConfig(target="127.0.0.1", dry_run=True)
        subgraph = _FakeSubgraph()

        report = build_report(state, subgraph, config)  # type: ignore[arg-type]

        assert report.policy_approved_count == 0
        assert report.policy_blocked_count == 0
        assert report.policy_needs_review_count == 0
        assert report.last_blocked_reasons == []


# ---------------------------------------------------------------------------
# Test: Blocked browser tasks never reach BrowserExecutor
# ---------------------------------------------------------------------------

class TestBlockedBrowserNeverReachesExecutor:
    async def test_blocked_browser_skips_executor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With advisor blocking 'browser', BrowserExecutor.run must not be called."""
        advisor = _FakeAdvisor(block_tool="browser")
        browser_calls: list[Any] = []

        async def _forbidden_browser_run(self_ex: Any, task: Any, evidence: Any) -> Any:
            browser_calls.append(task)
            raise AssertionError("BrowserExecutor.run must not be called for blocked tasks")

        monkeypatch.setattr(
            "apex_host.agents.browser_executor.BrowserExecutor.run", _forbidden_browser_run
        )
        monkeypatch.setattr(
            "apex_host.tools.runner.run_command",
            AsyncMock(return_value=_fake_tool_result()),
        )

        target = "127.0.0.1"
        api = _make_api()
        await _seed_host_http(api, target)

        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        # Seed a prior web finding so the planner routes to browser_agent
        initial = _make_initial_state(target)
        initial["findings"] = [{"phase": "web", "title": "endpoint discovered",
                                 "id": "ep1", "confidence": 0.9,
                                 "source": "test", "detail": ""}]

        await graph.ainvoke(initial)

        assert len(browser_calls) == 0, (
            "BrowserExecutor.run must not be called for a blocked browser task"
        )

    async def test_blocked_browser_records_policy_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Blocked browser task produces a policy_decisions entry with tool='browser'."""
        advisor = _FakeAdvisor(block_tool="browser")
        monkeypatch.setattr(
            "apex_host.tools.runner.run_command",
            AsyncMock(return_value=_fake_tool_result()),
        )

        target = "127.0.0.1"
        api = _make_api()
        await _seed_host_http(api, target)

        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config, advisor=advisor)

        initial = _make_initial_state(target)
        initial["findings"] = [{"phase": "web", "title": "endpoint discovered",
                                 "id": "ep1", "confidence": 0.9,
                                 "source": "test", "detail": ""}]

        final_state = await graph.ainvoke(initial)

        pd_list = final_state.get("policy_decisions", [])
        browser_blocked = [
            d for d in pd_list
            if d.get("tool") == "browser" and d.get("status") == "blocked"
        ]
        assert len(browser_blocked) > 0, (
            "policy_decisions must contain a blocked entry for browser; "
            f"got: {pd_list}"
        )


# ---------------------------------------------------------------------------
# Test: ApexGraphState contains policy_decisions field
# ---------------------------------------------------------------------------

class TestPolicyDecisionsInState:
    def test_state_has_policy_decisions_field(self) -> None:
        from typing import get_type_hints
        hints = get_type_hints(ApexGraphState, include_extras=True)
        assert "policy_decisions" in hints, (
            "ApexGraphState must have a policy_decisions field"
        )

    def test_initial_state_has_empty_policy_decisions(self) -> None:
        state = _make_initial_state("127.0.0.1")
        assert "policy_decisions" in state
        assert state["policy_decisions"] == []
