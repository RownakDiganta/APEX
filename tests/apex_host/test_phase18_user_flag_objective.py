# test_phase18_user_flag_objective.py
# Regression tests for Phase 18: the user-flag objective and verification model — success redefinition, verifier, executor, parser, planner, GlobalPlanner routing, reporting, and CLI exit codes.
"""Phase 18 regression tests.

Covers Ali's confirmed benchmark success definition: for the selected HTB
benchmark, success means verified retrieval of the user flag — a validated
``access_state`` node is an important intermediate milestone, but never
independently benchmark success. See docs/user-flag-objective.md for the
full design.

No test requires a real HTB machine, Docker, VPN, internet access, a real
SSH server, or real credentials. ``paramiko.SSHClient`` is monkeypatched
with an in-process fake (mirroring ``tests/apex_host/test_ssh_executor.py``'s
established pattern) so the "verified success" path can be exercised
end-to-end without any real network I/O. Every test uses ``dry_run=True``
unless explicitly testing the monkeypatched live-mode path, and even then
no real command execution or network I/O ever occurs.
"""
from __future__ import annotations

import hashlib
import json
import re
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
from memfabric.types import AbandonSignal, Edge, EvidenceBundle, Goal, Node, SubgraphView, TaskSpec

from apex_host.config import ApexConfig
from apex_host.eval.evaluation import build_htb_evaluation
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.graph_ids import (
    access_capability_id,
    access_state_id,
    enables_edge_id,
    host_id,
    indicates_edge_id,
    objective_id,
    satisfied_by_edge_id,
    service_id,
)
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.outcome import EngagementOutcome, exit_code_for, is_success_outcome
from apex_host.parsers.capability_parser import CapabilityParser
from apex_host.parsers.objective_parser import ObjectiveParser
from apex_host.planners.objective import (
    find_objective_evidence_node,
    find_objective_node,
    objective_report_fields,
    objective_status_from_subgraph,
)
from apex_host.planners.objective_planner import ObjectivePlanner, _ObjectiveDeterministic
from apex_host.policy import PolicyAdvisor, load_policy
from apex_host.policy.rules import check_bounded_user_flag_verification
from apex_host.tools.registry import ToolRegistry
from apex_host.types import AccessCapabilityType
from apex_host.verification.user_flag import (
    DEFAULT_FLAG_FORMAT_REGEX,
    is_bounded_candidate_path,
    verify_user_flag,
)

_TARGET = "10.10.10.150"
_ANCHOR = host_id(_TARGET)
_FLAG_VALUE = "9f3a7c21b6e04d18"  # a plausible, well-formed synthetic token — never a real HTB flag


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


async def _seed_node(api: MemoryAPI, node_id: str, node_type: str, props: dict[str, Any] | None = None) -> None:
    ts = now()
    await api.upsert_node(Node(
        id=node_id, type=node_type, props=props or {}, confidence=0.9,
        source="test-seed", first_seen=ts, last_seen=ts,
    ))


async def _seed_edge(api: MemoryAPI, from_id: str, to_id: str, edge_type: str = "exposes") -> None:
    ts = now()
    await api.upsert_edge(Edge(
        id=f"edge:{edge_type}:{from_id}:{to_id}", from_id=from_id, to_id=to_id, type=edge_type,
        props={}, confidence=0.9, source="test-seed", first_seen=ts, last_seen=ts,
    ))


async def _seed_validated_ssh_access(api: MemoryAPI, target: str, username: str = "testuser") -> None:
    """Seed host + ssh service + a validated ssh access_state + the
    corresponding validated access_capability — the precondition
    ObjectivePlanner requires before it will ever emit a task since the
    access-capability refactor (ObjectivePlanner now selects among
    AccessCapability records, never access_state directly).

    Uses the real CapabilityParser.derive_ssh_capability() to build the
    capability node/edges — exactly what parsing_node.py produces after a
    genuine ssh_access success — rather than hand-rolling an equivalent
    shape that could drift from the real parser's output."""
    h_id = host_id(target)
    svc_id = service_id(target, "22", "tcp")
    acc_id = access_state_id(target, username, protocol="ssh")
    await _seed_node(api, h_id, "host", {"ip": target})
    await _seed_node(api, svc_id, "service", {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"})
    await _seed_node(api, acc_id, "access_state", {
        "level": "user", "username": username, "target": target, "service": "ssh",
    })
    await _seed_edge(api, h_id, svc_id)
    await _seed_edge(api, h_id, acc_id)

    cap_obs = CapabilityParser().derive_ssh_capability(target=target, username=username, source_task_id="")
    await api.apply_deltas(nodes=cap_obs.node_deltas, edges=cap_obs.edge_deltas)

    # Phase 20 — derive_ssh_capability() now starts a fresh capability at
    # runtime_available=False (no adapter registered yet at derivation
    # time — see that method's docstring). Full-graph tests exercise the
    # real registration step (apex_host.orchestration.dispatch_node
    # .make_objective_node) automatically; this helper is also used by
    # tests that construct _ObjectiveDeterministic/ObjectivePlanner
    # directly (bypassing that orchestration step entirely), so it marks
    # the capability available itself — simulating what registration would
    # have done — at a confidence BELOW MemoryAPI's conflict_confidence_floor
    # (0.5 < 0.8 default) to avoid colliding with the derivation's own
    # high-confidence write (mirrors the production fix in dispatch_node.py).
    ts = now()
    cap_id = access_capability_id(target, AccessCapabilityType.ssh_command.value, username)
    await api.upsert_node(Node(
        id=cap_id, type="access_capability", props={"runtime_available": True},
        confidence=0.5, source="test-seed", first_seen=ts, last_seen=ts,
    ))


def _make_initial_state(target: str = _TARGET, run_id: str = "run-18") -> ApexGraphState:
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
        "credential_validation_log": [],
        "outcome": "",
        "termination_reason": "",
        "termination_phase": "",
        "stall_reason": "",
        "privilege_state": "",
        "privilege_summary": {},
        "opportunity_ids": [],
        "attempted_opportunities": [],
        "enumeration_complete": False,
        "web_session_state": {},
        "workflow_summary": {},
        "learning_summary": {},
        "task_latency_log": [],
        "objective_status": "",
        "objective_summary": {},
    }


def _goal(target: str, phase: str = "objective") -> Goal:
    return Goal(id="goal-1", description="verify objective", phase=phase, anchor_node=host_id(target))


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


async def _subgraph(api: MemoryAPI, target: str) -> SubgraphView:
    return await api.get_subgraph(host_id(target), depth=10)


# ---------------------------------------------------------------------------
# Fake SSH backend — no real network I/O (mirrors test_ssh_executor.py)
# ---------------------------------------------------------------------------

class _FakeChannel:
    def __init__(self, exit_status: int) -> None:
        self._exit_status = exit_status

    def recv_exit_status(self) -> int:
        return self._exit_status


class _FakeChannelFile:
    def __init__(self, data: bytes, exit_status: int) -> None:
        self._data = data
        self.channel = _FakeChannel(exit_status)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._data
        return self._data[:size]


class _FakeSSHClient:
    def __init__(self, *, stdout: bytes, stderr: bytes, exit_status: int, connect_raises: Exception | None) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._exit_status = exit_status
        self._connect_raises = connect_raises
        self.commands_run: list[str] = []

    def set_missing_host_key_policy(self, policy: Any) -> None:
        pass

    def connect(self, **kwargs: Any) -> None:
        if self._connect_raises is not None:
            raise self._connect_raises

    def exec_command(self, command: str, timeout: float | None = None) -> Any:
        self.commands_run.append(command)
        return (
            None,
            _FakeChannelFile(self._stdout, self._exit_status),
            _FakeChannelFile(self._stderr, self._exit_status),
        )

    def close(self) -> None:
        pass


def _install_fake_ssh(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    exit_status: int = 0,
    connect_raises: Exception | None = None,
) -> list[_FakeSSHClient]:
    """Patch paramiko.SSHClient (as imported inside runtime_registry.py,
    where the SSH capability adapter now lives since the access-capability
    refactor) with an in-process fake — no real network I/O ever occurs.
    Returns the list of constructed fake-client instances for call-count
    assertions."""
    import apex_host.runtime_registry as registry_mod

    created: list[_FakeSSHClient] = []

    def _factory() -> _FakeSSHClient:
        client = _FakeSSHClient(stdout=stdout, stderr=stderr, exit_status=exit_status, connect_raises=connect_raises)
        created.append(client)
        return client

    monkeypatch.setattr(registry_mod.paramiko, "SSHClient", _factory)
    return created


# ---------------------------------------------------------------------------
# 1-3. Access/credentials/foothold alone are not success
# ---------------------------------------------------------------------------

class TestAccessAloneIsNotSuccess:
    def test_access_state_without_objective_evidence_is_not_success(self) -> None:
        state = {**_make_initial_state(), "completed": True, "outcome": "validated_access"}
        report = build_report(state, SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0), ApexConfig(target=_TARGET))
        assert report.success is False
        assert report.completed_successfully is False

    def test_valid_credentials_without_flag_verification_are_not_success(self) -> None:
        # A credential_validation_log entry proving a successful login is
        # not, by itself, ever the success signal.
        state = {
            **_make_initial_state(), "completed": True, "outcome": "validated_access",
            "credential_validation_log": [
                {"protocol": "ssh", "target": _TARGET, "port": "22", "username": "root",
                 "success": True, "authenticated": True, "error_category": "success",
                 "timed_out": False, "phase": "credential"},
            ],
        }
        report = build_report(state, SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0), ApexConfig(target=_TARGET))
        assert report.success is False
        assert report.credential_attempts_by_protocol.get("ssh") == 1  # real progress, still not success

    async def test_shell_foothold_without_flag_verification_is_not_success(self) -> None:
        """A full compiled-graph run that reaches a validated ssh
        access_state, but with dry_run=True (the executor never verifies
        anything for real), must never report user_flag_verified."""
        from apex_host.graph import build_apex_graph

        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=6,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] != "user_flag_verified"
        assert final_state["completed"] is True


# ---------------------------------------------------------------------------
# 4, 25, 26. Verified success end-to-end (fake backend) vs. dry-run never verifies
# ---------------------------------------------------------------------------

class TestEndToEndVerification:
    async def test_full_graph_verified_user_flag_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A well-formed flag value read through a fake (monkeypatched) SSH
        backend produces a verified objective and terminates the engagement
        as EngagementOutcome.user_flag_verified — the ONLY success outcome."""
        from apex_host.graph import build_apex_graph

        _install_fake_ssh(monkeypatch, stdout=f"{_FLAG_VALUE}\n".encode())

        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] == EngagementOutcome.user_flag_verified.value
        assert is_success_outcome(EngagementOutcome(final_state["outcome"])) is True
        assert final_state["completed"] is True
        assert final_state["turn_count"] == 1  # verified on the very first (only) objective turn

    async def test_dry_run_never_creates_verified_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Even with the fake SSH backend installed and configured to
        return a perfectly well-formed flag, dry_run=True must never reach
        it — UserFlagExecutor's own dry-run short-circuit fires first and
        returns a deliberately unremarkable, never-verifiable result."""
        from apex_host.graph import build_apex_graph

        fakes = _install_fake_ssh(monkeypatch, stdout=f"{_FLAG_VALUE}\n".encode())

        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=6,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] != "user_flag_verified"
        assert not fakes, "dry-run must never construct a real SSH client"


# ---------------------------------------------------------------------------
# 5-9. CLI exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:
    def test_user_flag_verified_exit_code_zero(self) -> None:
        assert exit_code_for(EngagementOutcome.user_flag_verified) == 0

    def test_access_only_exhaustion_exit_code_one(self) -> None:
        # validated_access (access-only, objective never verified) and the
        # realistic ways an access-only engagement actually exhausts.
        assert exit_code_for(EngagementOutcome.validated_access) == 1
        assert exit_code_for(EngagementOutcome.max_turns_exhausted) == 1
        assert exit_code_for(EngagementOutcome.phase_budget_exhausted) == 1
        assert exit_code_for(EngagementOutcome.no_actionable_task) == 1

    def test_policy_blocked_verification_exit_code_three(self) -> None:
        assert exit_code_for(EngagementOutcome.policy_blocked) == 3

    def test_operational_verification_failure_exit_code_four(self) -> None:
        assert exit_code_for(EngagementOutcome.tool_failure) == 4
        assert exit_code_for(EngagementOutcome.parser_failure) == 4
        assert exit_code_for(EngagementOutcome.memory_failure) == 4

    def test_cancellation_remains_130(self) -> None:
        assert exit_code_for(EngagementOutcome.cancelled) == 130

    @pytest.mark.asyncio
    async def test_cli_exit_code_end_to_end_for_verified_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.eval import run_htb_local as mod
        import argparse

        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        from apex_host.runtime import build_runtime
        runtime = build_runtime(config)

        state = _make_initial_state()
        state["completed"] = True
        state["outcome"] = EngagementOutcome.user_flag_verified.value

        async def _fake_run_engagement(cfg: Any) -> Any:
            return runtime, state, {}

        monkeypatch.setattr(mod, "run_engagement", _fake_run_engagement)
        monkeypatch.setattr(mod.ApexConfig, "from_cli_args", staticmethod(lambda a: config))
        args = argparse.Namespace(
            preflight=False, export_graph=None, export_json=None,
            htb_machine_name=None, htb_difficulty=None,
            compare_with=None, export_benchmark=None, export_comparison=None,
        )
        code = await mod._async_main(args)
        assert code == 0
        del registry


# ---------------------------------------------------------------------------
# 10-15. The one authoritative verifier
# ---------------------------------------------------------------------------

class TestVerifier:
    def test_rejects_empty_output(self) -> None:
        result = verify_user_flag("")
        assert result.verified is False
        assert result.digest == ""

    def test_rejects_multiline_output(self) -> None:
        result = verify_user_flag("abcd1234\nextra-garbage-line")
        assert result.verified is False
        assert "multiline" in result.reason

    def test_rejects_oversized_output(self) -> None:
        result = verify_user_flag("a" * 100, max_output_bytes=8)
        assert result.verified is False
        assert "oversized" in result.reason or "exceeds" in result.reason

    def test_rejects_malformed_values(self) -> None:
        for bad in ("!!!not-a-flag!!!", "has spaces in it", "x", "a" * 500):
            result = verify_user_flag(bad)
            assert result.verified is False, bad

    def test_rejects_command_error_markers(self) -> None:
        result = verify_user_flag("", raw_error="cat: /home/x/user.txt: No such file or directory")
        assert result.verified is False
        assert "command error" in result.reason

    def test_accepts_configured_plausible_benchmark_format_token(self) -> None:
        result = verify_user_flag(_FLAG_VALUE)
        assert result.verified is True
        assert result.reason == "verified"

    def test_accepts_with_harmless_whitespace_normalized(self) -> None:
        result = verify_user_flag(f"  {_FLAG_VALUE}\n\n")
        assert result.verified is True

    def test_computes_expected_sha256_digest(self) -> None:
        result = verify_user_flag(_FLAG_VALUE)
        assert result.verified is True
        assert result.digest == hashlib.sha256(_FLAG_VALUE.encode("utf-8")).hexdigest()

    def test_redacted_display_never_equals_raw_value(self) -> None:
        result = verify_user_flag(_FLAG_VALUE)
        assert result.redacted != _FLAG_VALUE
        assert _FLAG_VALUE not in result.redacted or len(result.redacted) < len(_FLAG_VALUE)

    def test_result_object_has_no_plaintext_field(self) -> None:
        import dataclasses
        from apex_host.verification.user_flag import FlagVerificationResult
        field_names = {f.name for f in dataclasses.fields(FlagVerificationResult)}
        assert "value" not in field_names
        assert "raw" not in field_names
        assert "plaintext" not in field_names

    def test_custom_format_regex_is_honored(self) -> None:
        result = verify_user_flag("HTB{abc-123}", format_regex=r"^HTB\{[a-z0-9\-]+\}$")
        assert result.verified is True
        result2 = verify_user_flag("HTB{abc-123}")  # default regex rejects braces-with-hyphen? still bounded charset includes {} and -
        assert isinstance(result2.verified, bool)

    def test_default_regex_is_conservative_bounded_token(self) -> None:
        assert re.match(DEFAULT_FLAG_FORMAT_REGEX, "short") is None  # < 8 chars

    def test_bounded_candidate_path_validation(self) -> None:
        allowed = frozenset({"user.txt"})
        assert is_bounded_candidate_path("/home/user/user.txt", allowed_filenames=allowed) is True
        assert is_bounded_candidate_path("/home/user/../../etc/passwd", allowed_filenames=allowed) is False
        assert is_bounded_candidate_path("/home/user/user.txt; rm -rf /", allowed_filenames=allowed) is False
        assert is_bounded_candidate_path("relative/path/user.txt", allowed_filenames=allowed) is False
        assert is_bounded_candidate_path("/home/user/root.txt", allowed_filenames=allowed) is False


# ---------------------------------------------------------------------------
# 16-18. Raw flag never leaks anywhere
# ---------------------------------------------------------------------------

class TestNoRawFlagLeakage:
    async def _run_verified(self, monkeypatch: pytest.MonkeyPatch) -> tuple[ApexGraphState, MemoryAPI, ApexConfig]:
        from apex_host.graph import build_apex_graph

        _install_fake_ssh(monkeypatch, stdout=f"{_FLAG_VALUE}\n".encode())
        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] == "user_flag_verified"
        return final_state, api, config

    async def test_raw_flag_absent_from_text_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        final_state, api, config = await self._run_verified(monkeypatch)
        subgraph = await _subgraph(api, _TARGET)
        report = build_report(final_state, subgraph, config)
        text = format_text(report)
        assert _FLAG_VALUE not in text
        assert report.objective_evidence_redacted != _FLAG_VALUE

    async def test_raw_flag_absent_from_json_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        final_state, api, config = await self._run_verified(monkeypatch)
        subgraph = await _subgraph(api, _TARGET)
        report = build_report(final_state, subgraph, config)
        data = to_json_dict(report)
        serialized = json.dumps(data, default=str)
        assert _FLAG_VALUE not in serialized
        assert data["objective"]["evidence_digest"] == hashlib.sha256(_FLAG_VALUE.encode()).hexdigest()

    async def test_raw_flag_absent_from_ekg_nodes_and_edges(self, monkeypatch: pytest.MonkeyPatch) -> None:
        final_state, api, config = await self._run_verified(monkeypatch)
        subgraph = await _subgraph(api, _TARGET)
        for node in subgraph.nodes:
            assert _FLAG_VALUE not in json.dumps(node.props, default=str)
        for edge in subgraph.edges:
            assert _FLAG_VALUE not in json.dumps(edge.props, default=str)

    async def test_raw_flag_absent_from_episodes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        final_state, api, config = await self._run_verified(monkeypatch)
        all_episodes = await api._episodic.all()
        for ep in all_episodes:
            assert _FLAG_VALUE not in json.dumps(ep.data, default=str)

    async def test_raw_flag_absent_from_planner_decisions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        final_state, api, config = await self._run_verified(monkeypatch)
        assert _FLAG_VALUE not in json.dumps(final_state["planner_decisions"], default=str)

    async def test_raw_flag_absent_from_workflow_and_experience_replay(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.planners.experience_replay import derive_experiences_from_engagement
        from apex_host.planners.workflow_orchestration import derive_workflows_from_subgraph

        final_state, api, config = await self._run_verified(monkeypatch)
        subgraph = await _subgraph(api, _TARGET)

        workflows = derive_workflows_from_subgraph(
            _TARGET, subgraph, engagement_completed=True, engagement_outcome="user_flag_verified",
        )
        for wf in workflows:
            assert _FLAG_VALUE not in json.dumps(
                {"objective": wf.objective, "steps": [s.description for s in wf.steps]}, default=str,
            )

        experiences = derive_experiences_from_engagement(_TARGET, subgraph, dict(final_state))
        for exp in experiences:
            assert _FLAG_VALUE not in exp.context
            assert _FLAG_VALUE not in exp.evidence_excerpt
            assert _FLAG_VALUE not in exp.recommendation

    def test_no_unsafe_raw_flag_export_mode_exists(self) -> None:
        """No test-only/operator "show me the raw flag" mode exists anywhere
        in the reporting surface — to_json_dict's signature accepts only a
        RunReport, with no flag to request unsafe/raw output."""
        import inspect
        sig = inspect.signature(to_json_dict)
        for name in sig.parameters:
            assert "raw" not in name.lower() and "unsafe" not in name.lower() and "plaintext" not in name.lower()


# ---------------------------------------------------------------------------
# 19-20. Objective/evidence linkage; failed attempts create no verified evidence
# ---------------------------------------------------------------------------

class TestObjectiveEvidenceLinkage:
    async def test_verified_result_links_objective_and_evidence_correctly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        _install_fake_ssh(monkeypatch, stdout=f"{_FLAG_VALUE}\n".encode())
        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        await graph.ainvoke(_make_initial_state(_TARGET))

        subgraph = await _subgraph(api, _TARGET)
        obj_node = find_objective_node(subgraph, _TARGET, "user_flag")
        assert obj_node is not None
        assert obj_node.props["status"] == "verified"

        ev_node = find_objective_evidence_node(subgraph, _TARGET, "user_flag")
        assert ev_node is not None
        assert ev_node.props["verified"] is True
        assert ev_node.props["value_digest"] == hashlib.sha256(_FLAG_VALUE.encode()).hexdigest()

        obj_id = objective_id(_TARGET, "user_flag")
        cap_id = access_capability_id(_TARGET, AccessCapabilityType.ssh_command.value, "testuser")
        edge_ids = {e.id for e in subgraph.edges}
        assert indicates_edge_id(_ANCHOR, obj_id) in edge_ids
        # Access-capability refactor: the semantic "enables" edge now runs
        # access_capability -> objective, not access_state -> objective.
        assert enables_edge_id(cap_id, obj_id) in edge_ids
        assert satisfied_by_edge_id(obj_id, ev_node.id) in edge_ids
        assert ev_node.props["capability_type"] == AccessCapabilityType.ssh_command.value
        assert ev_node.props["capability_id"] == cap_id

    async def test_failed_attempt_creates_no_verified_evidence(self) -> None:
        parser = ObjectiveParser()
        cap_id = access_capability_id(_TARGET, AccessCapabilityType.ssh_command.value, "testuser")
        parsed = parser.parse_user_flag_result(
            target=_TARGET, objective_type="user_flag", candidate_path="/home/testuser/user.txt",
            connected=True, verified=False, value_digest="", redacted_value="", verification_method="",
            capability_id=cap_id, capability_type=AccessCapabilityType.ssh_command.value, principal="testuser",
            attempted_paths=[], is_last_candidate=True,
        )
        node_types = {n.type for n in parsed.node_deltas}
        assert "objective_evidence" not in node_types
        assert "objective" in node_types
        obj_node = next(n for n in parsed.node_deltas if n.type == "objective")
        assert obj_node.props["status"] == "failed"

    async def test_connection_level_failure_produces_no_node_update(self) -> None:
        parser = ObjectiveParser()
        cap_id = access_capability_id(_TARGET, AccessCapabilityType.ssh_command.value, "testuser")
        parsed = parser.parse_user_flag_result(
            target=_TARGET, objective_type="user_flag", candidate_path="/home/testuser/user.txt",
            connected=False, verified=False, value_digest="", redacted_value="", verification_method="",
            capability_id=cap_id, capability_type=AccessCapabilityType.ssh_command.value, principal="testuser",
            attempted_paths=[], is_last_candidate=False,
        )
        assert parsed.node_deltas == []
        assert parsed.edge_deltas == []


# ---------------------------------------------------------------------------
# 21. Repeated continuation evaluation does not duplicate terminal episodes
# ---------------------------------------------------------------------------

class TestExactlyOneTerminalEpisode:
    async def test_verified_full_graph_writes_exactly_one_terminal_episode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        _install_fake_ssh(monkeypatch, stdout=f"{_FLAG_VALUE}\n".encode())
        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        await graph.ainvoke(_make_initial_state(_TARGET))

        all_episodes = await api._episodic.all()
        terminal_entries = [e for e in all_episodes if e.action == "engagement_terminated"]
        assert len(terminal_entries) == 1
        assert terminal_entries[0].data["outcome"] == "user_flag_verified"


# ---------------------------------------------------------------------------
# 22-24. ObjectivePlanner behavior
# ---------------------------------------------------------------------------

class TestObjectivePlanner:
    async def test_no_verification_work_without_validated_access(self) -> None:
        api = _make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "no validated access capability" in result.reason

    async def test_no_verification_work_for_an_unvalidated_capability(self) -> None:
        """Access-capability refactor: a capability node that exists but is
        not (yet) validated must never be selected — this replaces the
        pre-refactor "no credentials configured" check, which no longer
        exists at the planner level (the planner never sees credentials at
        all since the access-capability refactor; provisioning the runtime
        adapter with operator-supplied credentials is now an orchestration-
        layer concern — see apex_host.orchestration.dispatch_node
        ._register_capability_adapter)."""
        api = _make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        cap_id = access_capability_id(_TARGET, AccessCapabilityType.ssh_command.value, "testuser")
        await _seed_node(api, cap_id, "access_capability", {
            "capability_type": AccessCapabilityType.ssh_command.value, "host_id": _ANCHOR,
            "validated": False, "principal": "testuser", "confidence": 0.85,
            "source_task_id": "", "metadata": {},
        })
        await _seed_edge(api, _ANCHOR, cap_id, edge_type="has_capability")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "no validated access capability" in result.reason

    async def test_emits_verification_task_after_validated_access(self) -> None:
        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list)
        assert len(result) == 1
        task = result[0]
        assert task.params["tool"] == "user_flag_verify"
        # Access-capability refactor: the planner never touches a password
        # and never learns a raw SSH-specific field like "username"/"port"
        # — only the transport-independent capability reference.
        assert task.params["capability_id"] == access_capability_id(
            _TARGET, AccessCapabilityType.ssh_command.value, "testuser"
        )
        assert task.params["capability_type"] == AccessCapabilityType.ssh_command.value
        assert task.params["principal"] == "testuser"
        assert "password" not in task.params
        assert "username" not in task.params
        assert "port" not in task.params

    async def test_no_verification_work_when_already_verified(self) -> None:
        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        obj_id = objective_id(_TARGET, "user_flag")
        await _seed_node(api, obj_id, "objective", {
            "objective_type": "user_flag", "status": "verified", "target": _TARGET, "attempted_paths": ["/home/testuser/user.txt"],
        })
        await _seed_edge(api, _ANCHOR, obj_id, edge_type="indicates")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "already verified" in result.reason

    async def test_respects_bounded_attempt_budget_and_avoids_repeats(self) -> None:
        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        obj_id = objective_id(_TARGET, "user_flag")
        cap_id = access_capability_id(_TARGET, AccessCapabilityType.ssh_command.value, "testuser")
        # Phase 20 — exhaustion is now tracked per (capability_id,
        # candidate_path) pair, not by a flat attempted_paths list alone,
        # so that a failed attempt through one capability never blocks a
        # retry of the same path through a different, newly-available
        # capability. Global exhaustion requires every validated+available
        # capability's every candidate to already be in
        # attempted_capability_paths. Here only one SSH capability exists,
        # and its one default candidate has already been attempted via
        # THAT capability, so the planner must still report exhaustion.
        await _seed_node(api, obj_id, "objective", {
            "objective_type": "user_flag", "status": "in_progress", "target": _TARGET,
            "attempted_paths": ["/home/testuser/user.txt"],
            "attempted_capability_paths": [[cap_id, "/home/testuser/user.txt"]],
        })
        await _seed_edge(api, _ANCHOR, obj_id, edge_type="indicates")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(
            _TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)),
            max_attempts=1,
        )
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "exhausted" in result.reason

    async def test_prefers_higher_confidence_capability(self) -> None:
        """Access-capability refactor: with two validated capabilities for
        the same objective, the planner must pick the higher-confidence one
        (apex_host.planners.access_capabilities.rank_capabilities)."""
        api = _make_api()
        h_id = _ANCHOR
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        low_id = access_capability_id(_TARGET, AccessCapabilityType.ssh_command.value, "loweruser")
        high_id = access_capability_id(_TARGET, AccessCapabilityType.ssh_command.value, "higheruser")
        await _seed_node(api, low_id, "access_capability", {
            "capability_type": AccessCapabilityType.ssh_command.value, "host_id": h_id,
            "validated": True, "principal": "loweruser", "confidence": 0.5,
            "source_task_id": "", "metadata": {},
        })
        await _seed_node(api, high_id, "access_capability", {
            "capability_type": AccessCapabilityType.ssh_command.value, "host_id": h_id,
            "validated": True, "principal": "higheruser", "confidence": 0.95,
            "source_task_id": "", "metadata": {},
        })
        await _seed_edge(api, h_id, low_id, edge_type="has_capability")
        await _seed_edge(api, h_id, high_id, edge_type="has_capability")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["principal"] == "higheruser"

    async def test_wrapper_records_plan_decision(self) -> None:
        api = _make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        subgraph = await _subgraph(api, _TARGET)
        planner = ObjectivePlanner(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        assert planner.last_decision is None
        await planner.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert planner.last_decision is not None
        assert planner.last_decision.planner_model == "deterministic"


# ---------------------------------------------------------------------------
# 29. State remains fully serializable
# ---------------------------------------------------------------------------

class TestStateSerializable:
    async def test_final_state_is_json_serializable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        _install_fake_ssh(monkeypatch, stdout=f"{_FLAG_VALUE}\n".encode())
        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        serialized = json.dumps(final_state, default=str)
        assert isinstance(serialized, str)
        # New objective fields present and plain (str/dict).
        assert isinstance(final_state["objective_status"], str)
        assert isinstance(final_state["objective_summary"], dict)


# ---------------------------------------------------------------------------
# 30-32. Static architecture scans
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_KNOWN_HTB_MACHINE_NAMES = (
    "meow", "lame", "blue", "shoppy", "blog", "alert", "academy", "twomillion", "cap",
)
_NEW_PHASE18_FILES = (
    "apex_host/verification/user_flag.py",
    "apex_host/agents/user_flag_executor.py",
    "apex_host/parsers/objective_parser.py",
    "apex_host/planners/objective.py",
    "apex_host/planners/objective_planner.py",
    # Access-capability refactor.
    "apex_host/runtime_registry.py",
    "apex_host/parsers/capability_parser.py",
    "apex_host/planners/access_capabilities.py",
)


class TestArchitectureScans:
    def test_no_cybersecurity_terms_added_to_memfabric(self) -> None:
        memfabric_dir = _REPO_ROOT / "memfabric"
        forbidden = ("user_flag", "flag_verify", "objective_evidence", "htb", "ssh")
        offenders: list[str] = []
        for path in memfabric_dir.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            for term in forbidden:
                if term in text:
                    offenders.append(f"{path}: {term}")
        assert not offenders, f"Phase 18 terminology leaked into memfabric: {offenders}"

    def test_no_machine_specific_names_in_new_source_files(self) -> None:
        # Word-boundary matching — "cap" is a common English/code substring
        # (e.g. "escape", "capabilities") that would otherwise false-positive
        # against the HTB machine name "Cap".
        offenders: list[str] = []
        for rel in _NEW_PHASE18_FILES:
            text = (_REPO_ROOT / rel).read_text(encoding="utf-8").lower()
            for name in _KNOWN_HTB_MACHINE_NAMES:
                if re.search(rf"\b{re.escape(name)}\b", text):
                    offenders.append(f"{rel}: {name}")
        assert not offenders, f"machine-specific name(s) found: {offenders}"

    def test_no_expected_plaintext_flag_value_in_config_or_cli(self) -> None:
        config_text = (_REPO_ROOT / "apex_host/config.py").read_text(encoding="utf-8")
        assert "expected_flag" not in config_text
        assert "known_flag" not in config_text
        main_text = (_REPO_ROOT / "apex_host/main.py").read_text(encoding="utf-8")
        assert "--user-flag-value" not in main_text
        assert "--expected-flag" not in main_text

    def test_no_raw_subprocess_usage_in_new_files(self) -> None:
        offenders: list[str] = []
        for rel in _NEW_PHASE18_FILES:
            text = (_REPO_ROOT / rel).read_text(encoding="utf-8")
            if "subprocess" in text or "create_subprocess" in text:
                offenders.append(rel)
        assert not offenders, f"raw subprocess usage found: {offenders}"


# ---------------------------------------------------------------------------
# 33. Real operations pass through safety, policy, and authorization gates
# ---------------------------------------------------------------------------

class TestPolicyGating:
    def test_policy_approves_bounded_candidate_against_target(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "candidate_path": "/home/testuser/user.txt",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None
        assert decision.status.value == "approved"

    def test_policy_blocks_unbounded_candidate_path(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t2", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "candidate_path": "/etc/shadow",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None
        assert decision.status.value == "blocked"

    async def test_dispatcher_blocks_off_scope_target_before_executor_reached(self) -> None:
        from apex_host.execution.dispatcher import TaskDispatcher
        from apex_host.execution.registry import TaskRegistry

        config = ApexConfig(target=_TARGET, dry_run=False)
        advisor = PolicyAdvisor(load_policy(config), config)

        class _SpyExecutor:
            calls = 0

            async def run(self, task: Any, evidence: Any) -> Any:
                type(self).calls += 1
                raise AssertionError("executor must never be reached for an off-scope target")

        dispatcher = TaskDispatcher(
            advisor=advisor, task_registry=TaskRegistry(), config=config,
            run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type]
            user_flag_executor=_SpyExecutor(),  # type: ignore[arg-type]
        )
        task = TaskSpec(
            id="t3", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": "8.8.8.8",  # not the configured target
                "candidate_path": "/home/testuser/user.txt", "username": "testuser", "password": "pw",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        ctx = ExecutionContext(
            run_id="r1", phase="objective", turn_number=0, evidence_version=None,
            subgraph=None, evidence=_empty_evidence(), dry_run=False,  # type: ignore[arg-type]
        )
        result = await dispatcher.dispatch(task, ctx)
        assert result.disposition is ExecutionDisposition.BLOCKED_POLICY
        assert _SpyExecutor.calls == 0


# ---------------------------------------------------------------------------
# 34. Report distinguishes access from benchmark success
# ---------------------------------------------------------------------------

class TestReportDistinguishesAccessFromSuccess:
    def test_access_only_report_shows_no_flag_verified_no_benchmark_success(self) -> None:
        nodes = [
            Node(id=_ANCHOR, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=now(), last_seen=now()),
            Node(id=access_state_id(_TARGET, "root"), type="access_state",
                 props={"username": "root", "target": _TARGET}, confidence=0.9, source="t", first_seen=now(), last_seen=now()),
        ]
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=nodes, edges=[], depth=1)
        state = {**_make_initial_state(), "completed": True, "outcome": "validated_access"}
        report = build_report(state, subgraph, ApexConfig(target=_TARGET))

        assert report.access_summary["validated"] is True
        assert report.objective_verified is False
        assert report.success is False

        text = format_text(report)
        assert "Access obtained    : Yes" in text
        assert "Flag verified      : No" in text
        assert "Benchmark success  : No" in text

        data = to_json_dict(report)
        assert data["objective"]["access_obtained"] is True
        assert data["objective"]["verified"] is False
        assert data["objective"]["benchmark_success"] is False

    async def test_verified_report_shows_yes_for_all_three(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apex_host.graph import build_apex_graph

        _install_fake_ssh(monkeypatch, stdout=f"{_FLAG_VALUE}\n".encode())
        api = _make_api()
        await _seed_validated_ssh_access(api, _TARGET, username="testuser")
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5,
            username_candidates=["testuser"], password_candidates=["testpass"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        subgraph = await _subgraph(api, _TARGET)
        report = build_report(final_state, subgraph, config)

        text = format_text(report)
        assert "Access obtained    : Yes" in text
        assert "Flag verified      : Yes" in text
        assert "Benchmark success  : Yes" in text

        data = to_json_dict(report)
        assert data["objective"]["access_obtained"] is True
        assert data["objective"]["verified"] is True
        assert data["objective"]["benchmark_success"] is True


# ---------------------------------------------------------------------------
# 35. Benchmark metrics count only verified flags as solved machines
# ---------------------------------------------------------------------------

class TestBenchmarkCountsOnlyVerifiedFlags:
    def test_evaluation_success_false_for_access_only(self) -> None:
        nodes = [
            Node(id=_ANCHOR, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=now(), last_seen=now()),
            Node(id=access_state_id(_TARGET, "root"), type="access_state",
                 props={"username": "root", "target": _TARGET}, confidence=0.9, source="t", first_seen=now(), last_seen=now()),
        ]
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=nodes, edges=[], depth=1)
        state = {**_make_initial_state(), "completed": True, "outcome": "validated_access"}
        report = build_report(state, subgraph, ApexConfig(target=_TARGET))
        evaluation = build_htb_evaluation(report, machine_name="TestBox", difficulty="Easy")
        assert evaluation.success is False

    def test_evaluation_success_true_for_verified_flag(self) -> None:
        state = {**_make_initial_state(), "completed": True, "outcome": "user_flag_verified"}
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        report = build_report(state, subgraph, ApexConfig(target=_TARGET))
        evaluation = build_htb_evaluation(report, machine_name="TestBox", difficulty="Easy")
        assert evaluation.success is True


# ---------------------------------------------------------------------------
# GlobalPlanner routing regression (objective_type default)
# ---------------------------------------------------------------------------

class TestObjectiveConfigDefaults:
    def test_objective_type_defaults_to_user_flag(self) -> None:
        config = ApexConfig(target=_TARGET)
        assert config.objective_type == "user_flag"

    def test_objective_status_from_subgraph_defaults_pending(self) -> None:
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        assert objective_status_from_subgraph(subgraph, _TARGET, "user_flag") == "pending"

    def test_objective_report_fields_shape(self) -> None:
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        fields = objective_report_fields(subgraph, _TARGET, "user_flag")
        assert fields["objective_type"] == "user_flag"
        assert fields["objective_status"] == "pending"
        assert fields["objective_verified"] is False
        assert fields["objective_evidence_digest"] == ""

    def test_no_cli_flag_accepts_expected_plaintext_flag(self) -> None:
        from apex_host.main import parse_args
        args = parse_args(["--target", _TARGET])
        forbidden_attrs = ("expected_flag", "user_flag_value", "known_flag")
        for attr in forbidden_attrs:
            assert not hasattr(args, attr)
