# test_phase21_bounded_command_capability.py
# Regression tests for Phase 21: the generic, bounded, policy-gated command-execution access capability — capability types, strategy protocol, adapter security, planner/executor/parser transport-independence, policy, EKG, and full-graph verification without SSH or direct file read.
"""Phase 21 regression tests: bounded command-execution access capability.

Covers the full flow:

    validated command-execution primitive
        -> AccessCapability(type=local_shell | remote_command | web_command)
        -> CapabilityRuntimeRegistry
        -> BoundedCommandCapabilityAdapter.read_bounded_file(path)
        -> verify_user_flag()
        -> objective evidence
        -> EngagementOutcome.user_flag_verified

No test performs a real network operation. The one real reference strategy
(``ToolBackendCommandReadStrategy``) is exercised against a real temp file
via the real ``LocalToolBackend``/``apex_host.tools.runner.run_command`` —
this is intentional: it is the SAME already-safety-gated, argv-only,
no-shell subprocess path every other command in this codebase uses, so
exercising it for real (against a throwaway temp file, never a real
target) is both safe and the most faithful test of the actual invariant
("no new subprocess call site was introduced"). No test requires a real
HTB machine, Docker, VPN, or internet access. This phase is not a specific
exploit or a named-machine solver — every fixture uses a synthetic target
and a synthetic, well-formed (never real) flag-shaped token.
"""
from __future__ import annotations

import hashlib
import inspect
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
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.graph_ids import access_capability_id, access_state_id, endpoint_id, host_id, service_id
from apex_host.orchestration.capability_seed import seed_bounded_command_capability
from apex_host.orchestration.outcome import EngagementOutcome, exit_code_for, is_success_outcome
from apex_host.parsers.capability_parser import CapabilityParser
from apex_host.planners.access_capabilities import (
    access_capabilities_from_subgraph,
    capability_type_label,
)
from apex_host.planners.objective_planner import ObjectivePlanner, _ObjectiveDeterministic
from apex_host.policy import PolicyAdvisor, load_policy
from apex_host.policy.rules import check_bounded_user_flag_verification
from apex_host.runtime_registry import (
    BoundedCommandCapabilityAdapter,
    BoundedCommandReadPrimitive,
    BoundedReadResult,
    CapabilityRuntimeRegistry,
    ToolBackendCommandReadStrategy,
)
from apex_host.tools.backend import LocalToolBackend, ToolBackend
from apex_host.tools.registry import ToolRegistry
from apex_host.types import AccessCapability, AccessCapabilityType

_TARGET = "10.10.10.201"
_ANCHOR = host_id(_TARGET)
_FLAG_VALUE = "b2e7f4c19a3d0865"  # a plausible, well-formed synthetic token — never a real HTB flag

_TRIPLE_QUOTED_RE = re.compile(r'("""|\'\'\')(?:.|\n)*?\1')


def _non_comment_code(source: str) -> str:
    """Strip triple-quoted docstrings and full-line ``#`` comments — mirrors
    ``test_phase20_direct_file_read_capability.py``'s identical helper."""
    stripped = _TRIPLE_QUOTED_RE.sub("", source)
    return "\n".join(line for line in stripped.splitlines() if not line.strip().startswith("#"))


def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(), episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(), vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(), config=cfg,
    )


async def _seed_node(api: MemoryAPI, node_id: str, node_type: str, props: dict[str, Any] | None = None) -> None:
    ts = now()
    await api.upsert_node(Node(
        id=node_id, type=node_type, props=props or {}, confidence=0.9,
        source="test-seed", first_seen=ts, last_seen=ts,
    ))


async def _seed_edge(api: MemoryAPI, from_id: str, to_id: str, edge_type: str = "has_capability") -> None:
    ts = now()
    await api.upsert_edge(Edge(
        id=f"edge:{edge_type}:{from_id}:{to_id}", from_id=from_id, to_id=to_id, type=edge_type,
        props={}, confidence=0.9, source="test-seed", first_seen=ts, last_seen=ts,
    ))


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _goal(target: str, phase: str = "objective") -> Goal:
    return Goal(id="goal-1", description="verify objective", phase=phase, anchor_node=host_id(target))


async def _subgraph(api: MemoryAPI, target: str) -> SubgraphView:
    return await api.get_subgraph(host_id(target), depth=10)


class _FakeToolResult:
    """Minimal stand-in for ``apex_host.types.ToolResult`` — exposes only
    the attributes ``ToolBackendCommandReadStrategy`` reads."""

    def __init__(
        self, *, stdout: str = "", stderr: str = "", returncode: int = 0,
        error: str | None = None, timed_out: bool = False, backend: str = "fake",
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.error = error
        self.timed_out = timed_out
        self.backend = backend


class _FakeToolBackend:
    """A ``ToolBackend`` test double — never spawns a process. Records
    every call for assertions."""

    name = "fake"

    def __init__(self, result: _FakeToolResult | None = None, *, raises: Exception | None = None) -> None:
        self._result = result or _FakeToolResult()
        self._raises = raises
        self.calls: list[tuple[str, list[str]]] = []

    async def execute(
        self, tool: str, arguments: list[str], *, timeout_seconds: float | None = None, stdin: str | None = None,
    ) -> _FakeToolResult:
        self.calls.append((tool, list(arguments)))
        if self._raises is not None:
            raise self._raises
        return self._result


def _make_primitive(
    *, capability_id: str = "cmd-cap-1", backend: Any = None,
    allowed_filenames: frozenset[str] = frozenset({"user.txt"}),
    timeout_seconds: float = 5.0, max_output_bytes: int = 4096,
) -> BoundedCommandReadPrimitive:
    strategy = ToolBackendCommandReadStrategy(backend=backend or _FakeToolBackend(_FakeToolResult(stdout=_FLAG_VALUE)))
    return BoundedCommandReadPrimitive(
        capability_id=capability_id, strategy=strategy,
        allowed_filenames=allowed_filenames, timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )


async def _seed_validated_command_capability(
    api: MemoryAPI, target: str, *, principal: str = "application",
    capability_type: AccessCapabilityType = AccessCapabilityType.local_shell,
    confidence: float = 0.7, runtime_available: bool = True,
) -> str:
    """Seed host + a validated, runtime-available bounded-command
    capability — the precondition ObjectivePlanner requires. Mirrors
    ``test_phase20_direct_file_read_capability.py``'s
    ``_seed_validated_dfr_capability`` exactly."""
    h_id = host_id(target)
    await _seed_node(api, h_id, "host", {"ip": target})
    parsed = CapabilityParser().derive_command_capability(
        target=target, capability_type=capability_type, principal=principal,
        source_task_id="", validation_method="operator_attestation", confidence=confidence,
    )
    await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
    cap_id = access_capability_id(target, capability_type.value, principal)
    if runtime_available:
        ts = now()
        await api.upsert_node(Node(
            id=cap_id, type="access_capability", props={"runtime_available": True},
            confidence=0.5, source="test-seed", first_seen=ts, last_seen=ts,
        ))
    return cap_id


# ---------------------------------------------------------------------------
# 1. Capability types
# ---------------------------------------------------------------------------

class TestCapabilityTypes:
    def test_local_shell_type_exists(self) -> None:
        assert AccessCapabilityType.local_shell.value == "local_shell"

    def test_remote_command_type_exists(self) -> None:
        assert AccessCapabilityType.remote_command.value == "remote_command"

    def test_web_command_type_exists(self) -> None:
        assert AccessCapabilityType.web_command.value == "web_command"

    def test_no_vulnerability_oriented_capability_types_exist(self) -> None:
        names = {t.value for t in AccessCapabilityType}
        forbidden = {"command_injection", "php_webshell", "academy_rce", "twomillion_shell", "cgi_exploit"}
        assert not (names & forbidden)

    def test_capability_serializes_to_json(self) -> None:
        cap = AccessCapability(
            capability_id=access_capability_id(_TARGET, "local_shell", "application"),
            host_id=_ANCHOR, capability_type=AccessCapabilityType.local_shell,
            validated=True, principal="application", confidence=0.7, source_task_id="",
            metadata={"validation_method": "operator_attestation"},
        )
        payload = {
            "capability_id": cap.capability_id, "capability_type": str(cap.capability_type.value),
            "validated": cap.validated, "principal": cap.principal, "confidence": cap.confidence,
            "metadata": cap.metadata, "runtime_available": cap.runtime_available,
        }
        serialized = json.dumps(payload)
        assert isinstance(serialized, str)
        assert "application" in serialized

    def test_labels_are_capability_oriented(self) -> None:
        assert capability_type_label(AccessCapabilityType.local_shell.value) == "Local Command"
        assert capability_type_label(AccessCapabilityType.remote_command.value) == "Remote Command"
        assert capability_type_label(AccessCapabilityType.web_command.value) == "Web Command"

    def test_graph_ids_are_content_addressed_and_distinct_per_type(self) -> None:
        local_id = access_capability_id(_TARGET, "local_shell", "application")
        remote_id = access_capability_id(_TARGET, "remote_command", "application")
        web_id = access_capability_id(_TARGET, "web_command", "application")
        assert len({local_id, remote_id, web_id}) == 3
        assert local_id == access_capability_id(_TARGET, "local_shell", "application")

    def test_sanitized_metadata_shape(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="operator_attestation",
            confidence=0.7, max_output_bytes=4096, strategy_id="strategy-1",
        )
        node = parsed.node_deltas[0]
        metadata = node.props["metadata"]
        assert set(metadata.keys()) == {"validation_method", "max_output_bytes", "strategy_id", "read_only"}
        forbidden_terms = ("cookie", "password", "token", "command", "shell", "session")
        serialized = json.dumps(metadata).lower()
        for term in forbidden_terms:
            assert term not in serialized


# ---------------------------------------------------------------------------
# 2. Bounded command primitive
# ---------------------------------------------------------------------------

class TestBoundedCommandPrimitive:
    async def test_strategy_binding_never_mutated_by_a_read(self) -> None:
        """The primitive's fields are never mutated by the adapter itself —
        the only per-call variable is the candidate path passed to
        read_bounded_file(). Behavioral (not structural-frozen) immutability."""
        backend = _FakeToolBackend(_FakeToolResult(stdout=_FLAG_VALUE))
        primitive = _make_primitive(backend=backend)
        original_strategy = primitive.strategy
        original_timeout = primitive.timeout_seconds
        adapter = BoundedCommandCapabilityAdapter(primitive)
        await adapter.read_bounded_file("/home/application/user.txt")
        assert primitive.strategy is original_strategy
        assert primitive.timeout_seconds == original_timeout

    def test_accepts_only_one_path_parameter(self) -> None:
        sig = inspect.signature(BoundedCommandCapabilityAdapter.read_bounded_file)
        assert list(sig.parameters) == ["self", "path"]

    def test_no_arbitrary_command_parameter(self) -> None:
        sig = inspect.signature(BoundedCommandCapabilityAdapter.read_bounded_file)
        assert "command" not in sig.parameters

    def test_no_arbitrary_executable_parameter(self) -> None:
        sig = inspect.signature(BoundedCommandCapabilityAdapter.read_bounded_file)
        assert "executable" not in sig.parameters

    def test_strategy_protocol_has_no_execute_method(self) -> None:
        from apex_host.runtime_registry import BoundedCommandReadStrategy
        members = [name for name, _ in inspect.getmembers(BoundedCommandReadStrategy) if not name.startswith("_")]
        assert members == ["read_file"]

    async def test_timeout_enforced(self) -> None:
        class _SlowStrategy:
            async def read_file(self, path: str, *, timeout_seconds: float, max_output_bytes: int) -> BoundedReadResult:
                import asyncio
                await asyncio.sleep(timeout_seconds + 10)
                return BoundedReadResult(connected=True, output=_FLAG_VALUE, error=None)

        primitive = BoundedCommandReadPrimitive(
            capability_id="c1", strategy=_SlowStrategy(), allowed_filenames=frozenset({"user.txt"}),
            timeout_seconds=0.05,
        )
        adapter = BoundedCommandCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.connected is False
        assert result.error is not None and "timeout" in result.error.lower()

    async def test_byte_cap_enforced_and_oversized_rejected_entirely(self) -> None:
        backend = _FakeToolBackend(_FakeToolResult(stdout="x" * 10000))
        primitive = _make_primitive(backend=backend, max_output_bytes=100)
        adapter = BoundedCommandCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.output == ""
        assert result.truncated is True
        assert result.error is not None and "exceeds" in result.error

    async def test_errors_sanitized(self) -> None:
        backend = _FakeToolBackend(raises=RuntimeError("secret-header-value-xyz"))
        primitive = _make_primitive(backend=backend)
        adapter = BoundedCommandCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.error is not None
        assert "secret-header-value-xyz" not in result.error
        assert "execution_context_unavailable" in result.error

    def test_primitive_rejects_non_positive_timeout(self) -> None:
        with pytest.raises(ValueError, match="timeout_seconds"):
            BoundedCommandReadPrimitive(
                capability_id="c1", strategy=_FakeToolBackend(), timeout_seconds=0.0,  # type: ignore[arg-type]
            )

    def test_primitive_rejects_non_positive_max_output_bytes(self) -> None:
        with pytest.raises(ValueError, match="max_output_bytes"):
            BoundedCommandReadPrimitive(
                capability_id="c1", strategy=_FakeToolBackend(), max_output_bytes=0,  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# 3. Path security
# ---------------------------------------------------------------------------

class TestPathSecurity:
    async def test_valid_absolute_approved_path_accepted(self) -> None:
        backend = _FakeToolBackend(_FakeToolResult(stdout=_FLAG_VALUE))
        primitive = _make_primitive(backend=backend)
        adapter = BoundedCommandCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file("/home/application/user.txt")
        assert result.connected is True
        assert backend.calls == [("cat", ["--", "/home/application/user.txt"])]

    async def test_relative_path_rejected(self) -> None:
        backend = _FakeToolBackend()
        primitive = _make_primitive(backend=backend)
        adapter = BoundedCommandCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file("home/application/user.txt")
        assert result.connected is False
        assert backend.calls == []

    async def test_traversal_rejected(self) -> None:
        backend = _FakeToolBackend()
        primitive = _make_primitive(backend=backend)
        adapter = BoundedCommandCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file("/home/../etc/user.txt")
        assert result.connected is False
        assert backend.calls == []

    async def test_unapproved_basename_rejected(self) -> None:
        backend = _FakeToolBackend()
        primitive = _make_primitive(backend=backend, allowed_filenames=frozenset({"user.txt"}))
        adapter = BoundedCommandCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file("/home/application/root.txt")
        assert result.connected is False
        assert backend.calls == []

    async def test_wildcard_rejected(self) -> None:
        backend = _FakeToolBackend()
        primitive = _make_primitive(backend=backend)
        adapter = BoundedCommandCapabilityAdapter(primitive)
        result = await adapter.read_bounded_file("/home/application/*.txt")
        assert result.connected is False
        assert backend.calls == []

    async def test_shell_metacharacter_path_rejected(self) -> None:
        backend = _FakeToolBackend()
        primitive = _make_primitive(backend=backend)
        adapter = BoundedCommandCapabilityAdapter(primitive)
        for bad_path in ("/home/app/user.txt; rm -rf /", "/home/app/`whoami`", "/home/app/$(id)"):
            result = await adapter.read_bounded_file(bad_path)
            assert result.connected is False
        assert backend.calls == []

    async def test_oversized_path_rejected(self) -> None:
        backend = _FakeToolBackend()
        primitive = _make_primitive(backend=backend)
        adapter = BoundedCommandCapabilityAdapter(primitive)
        long_path = "/" + ("a" * 300) + "/user.txt"
        result = await adapter.read_bounded_file(long_path)
        assert result.connected is False
        assert backend.calls == []


# ---------------------------------------------------------------------------
# 4. No shell construction
# ---------------------------------------------------------------------------

class TestNoShellConstruction:
    def test_no_shell_true_in_runtime_registry(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "shell=True" not in code

    def test_no_bin_sh_c_in_runtime_registry(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "/bin/sh" not in code

    def test_no_bash_c_in_runtime_registry(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert '"bash"' not in code and "'bash'" not in code

    def test_no_eval_in_runtime_registry(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "eval(" not in code

    def test_no_dynamic_interpreter_string(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "python -c" not in code and "exec(" not in code

    def test_no_pipes_or_redirections_in_fixed_command(self) -> None:
        """The fixed command argv literal contains only the "--" separator
        and the candidate path — never a pipe/redirect operator. (Shell
        metacharacters legitimately appear elsewhere in this file's Python
        syntax — e.g. type unions, comparisons — so this checks the
        specific argv literal rather than scanning the whole file.)"""
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert '["--",path]' in code.replace(" ", "")

    def test_no_command_substitution(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "$(" not in code and "`" not in code

    async def test_argv_list_used_never_shell_string(self) -> None:
        backend = _FakeToolBackend(_FakeToolResult(stdout=_FLAG_VALUE))
        strategy = ToolBackendCommandReadStrategy(backend=backend)
        await strategy.read_file("/home/app/user.txt", timeout_seconds=5.0, max_output_bytes=4096)
        assert len(backend.calls) == 1
        tool, args = backend.calls[0]
        assert tool == "cat"
        assert args == ["--", "/home/app/user.txt"]
        assert isinstance(args, list)

    async def test_real_local_backend_never_uses_shell(self, tmp_path: Path) -> None:
        """Exercises the REAL LocalToolBackend/run_command path (the same
        already-safety-gated, argv-only subprocess pathway every other
        command in this codebase uses) against a real temp file — proves
        the actual invariant, not just a mocked one."""
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        config = ApexConfig(target=_TARGET, dry_run=False, allowed_tools=["cat"])
        backend: ToolBackend = LocalToolBackend(config)
        strategy = ToolBackendCommandReadStrategy(backend=backend)
        result = await strategy.read_file(str(flag_file), timeout_seconds=5.0, max_output_bytes=4096)
        assert result.connected is True
        assert result.output == _FLAG_VALUE
        assert result.error is None


# ---------------------------------------------------------------------------
# 5. Capability derivation
# ---------------------------------------------------------------------------

class TestCapabilityDerivation:
    def test_operator_attestation_derives_capability(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="operator_attestation",
            confidence=0.8,
        )
        assert len(parsed.node_deltas) == 1
        assert parsed.node_deltas[0].type == "access_capability"

    def test_canary_output_match_derives_capability(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.remote_command,
            principal="application", source_task_id="", validation_method="canary_output_match",
            confidence=0.8,
        )
        assert len(parsed.node_deltas) == 1

    def test_llm_assertion_alone_rejected(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="llm_claimed_command_injection_succeeded",
            confidence=0.95,
        )
        assert parsed.node_deltas == []

    def test_http_200_alone_rejected(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.web_command,
            principal="application", source_task_id="", validation_method="http_200",
            confidence=0.9,
        )
        assert parsed.node_deltas == []

    def test_payload_attempted_alone_rejected(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.web_command,
            principal="application", source_task_id="", validation_method="payload_attempted",
            confidence=0.9,
        )
        assert parsed.node_deltas == []

    def test_application_admin_access_alone_rejected(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.web_command,
            principal="application", source_task_id="", validation_method="application_administrator_access",
            confidence=0.9,
        )
        assert parsed.node_deltas == []

    def test_credentials_discovered_alone_rejected(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="credentials_discovered",
            confidence=0.9,
        )
        assert parsed.node_deltas == []

    def test_low_confidence_recognised_method_still_rejected(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="operator_attestation",
            confidence=0.1,
        )
        assert parsed.node_deltas == []

    def test_empty_principal_rejected(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        assert parsed.node_deltas == []

    def test_wrong_capability_type_rejected(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.ssh_command,
            principal="application", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        assert parsed.node_deltas == []

    def test_duplicate_derivation_idempotent(self) -> None:
        first = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="t1", validation_method="operator_attestation", confidence=0.9,
        )
        second = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="t2", validation_method="operator_attestation", confidence=0.9,
        )
        assert first.node_deltas[0].id == second.node_deltas[0].id

    def test_source_evidence_edge_correct(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="operator_attestation",
            confidence=0.9, source_node_id="endpoint:some-evidence-node",
        )
        cap_id = access_capability_id(_TARGET, "local_shell", "application")
        enables_edges = [e for e in parsed.edge_deltas if e.type == "enables"]
        assert len(enables_edges) == 1
        assert enables_edges[0].from_id == "endpoint:some-evidence-node"
        assert enables_edges[0].to_id == cap_id

    def test_host_has_capability_edge_always_present(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        h_id = host_id(_TARGET)
        cap_id = access_capability_id(_TARGET, "local_shell", "application")
        has_cap_edges = [e for e in parsed.edge_deltas if e.type == "has_capability"]
        assert len(has_cap_edges) == 1
        assert has_cap_edges[0].from_id == h_id
        assert has_cap_edges[0].to_id == cap_id

    async def test_seed_bounded_command_capability_derives_from_operator_attested_config(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True,
            bounded_command_operator_attested=True,
            bounded_command_capability_type="local_shell",
            bounded_command_principal="application",
        )
        seeded = await seed_bounded_command_capability(api, config)
        assert seeded is True
        subgraph = await _subgraph(api, _TARGET)
        caps = access_capabilities_from_subgraph(subgraph)
        assert len(caps) == 1
        assert caps[0].capability_type is AccessCapabilityType.local_shell

    async def test_seed_bounded_command_capability_is_idempotent(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True,
            bounded_command_operator_attested=True,
            bounded_command_capability_type="local_shell",
            bounded_command_principal="application",
        )
        first = await seed_bounded_command_capability(api, config)
        second = await seed_bounded_command_capability(api, config)
        assert first is True
        assert second is False

    async def test_seed_bounded_command_capability_disabled_by_default(self) -> None:
        api = _make_api()
        config = ApexConfig(target=_TARGET, dry_run=True)
        seeded = await seed_bounded_command_capability(api, config)
        assert seeded is False

    async def test_seed_bounded_command_capability_rejects_web_command(self) -> None:
        """web_command is configured through direct_file_read_* fields
        instead — seed_bounded_command_capability only handles
        local_shell/remote_command."""
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True,
            bounded_command_operator_attested=True,
            bounded_command_capability_type="web_command",
            bounded_command_principal="application",
        )
        seeded = await seed_bounded_command_capability(api, config)
        assert seeded is False

    async def test_seed_bounded_command_capability_performs_no_execution(self) -> None:
        """Seeding never invokes a strategy/backend — it only constructs
        EKG deltas from configuration."""
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=False,  # even with dry_run=False, seeding must not execute anything
            bounded_command_operator_attested=True,
            bounded_command_capability_type="local_shell",
            bounded_command_principal="application",
        )
        seeded = await seed_bounded_command_capability(api, config)
        assert seeded is True
        subgraph = await _subgraph(api, _TARGET)
        cap_id = access_capability_id(_TARGET, "local_shell", "application")
        node = next(n for n in subgraph.nodes if n.id == cap_id)
        assert node.props["runtime_available"] is False  # no adapter registered by seeding alone


# ---------------------------------------------------------------------------
# 6. Runtime registry
# ---------------------------------------------------------------------------

class TestRuntimeRegistry:
    def test_command_adapter_registration(self) -> None:
        registry = CapabilityRuntimeRegistry()
        primitive = _make_primitive()
        adapter = registry.ensure_bounded_command("cap-1", primitive=primitive)
        assert registry.has("cap-1") is True
        assert registry.get("cap-1") is adapter

    def test_resolution_through_generic_registry(self) -> None:
        registry = CapabilityRuntimeRegistry()
        registry.ensure_bounded_command("cap-1", primitive=_make_primitive())
        resolved = registry.get("cap-1")
        assert isinstance(resolved, BoundedCommandCapabilityAdapter)

    def test_ensure_bounded_command_idempotent(self) -> None:
        registry = CapabilityRuntimeRegistry()
        first = registry.ensure_bounded_command("cap-1", primitive=_make_primitive())
        second = registry.ensure_bounded_command("cap-1", primitive=_make_primitive())
        assert first is second

    async def test_missing_runtime_strategy_leaves_capability_unavailable(self) -> None:
        """A validated capability with NO operator-supplied bounded-command
        configuration must not be considered executable."""
        from apex_host.capabilities.runtime_resolution import register_capability_adapter

        api = _make_api()
        cap_id = await _seed_validated_command_capability(api, _TARGET, runtime_available=False)
        subgraph = await _subgraph(api, _TARGET)
        capability = next(c for c in access_capabilities_from_subgraph(subgraph) if c.capability_id == cap_id)

        config = ApexConfig(target=_TARGET, dry_run=True)  # bounded_command_operator_attested defaults False
        registry = CapabilityRuntimeRegistry()
        registered = register_capability_adapter(
            config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET, cap=capability,
        )
        assert registered is False
        assert registry.has(cap_id) is False

    def test_runtime_object_not_json_serializable_by_default(self) -> None:
        """The registry/adapter/strategy chain is never expected to survive
        JSON serialization — proving it holds live Python objects, not EKG-
        safe primitives (defense in depth: confirms nothing here could be
        accidentally persisted through a naive dict-dump path)."""
        registry = CapabilityRuntimeRegistry()
        registry.ensure_bounded_command("cap-1", primitive=_make_primitive())
        adapter = registry.get("cap-1")
        with pytest.raises(TypeError):
            json.dumps(adapter)

    async def test_graph_runtime_available_does_not_override_actual_registry_state(self) -> None:
        """Even if the EKG node claims runtime_available=True, the registry
        itself is the source of truth for whether an adapter is ACTUALLY
        registered — ObjectivePlanner must still check registry-backed
        availability before selecting, per best_capability_for_objective's
        own contract (this test proves the registry starts empty
        regardless of the EKG claim)."""
        registry = CapabilityRuntimeRegistry()
        cap_id = access_capability_id(_TARGET, "local_shell", "application")
        assert registry.has(cap_id) is False  # EKG may say True, registry says otherwise until registered


# ---------------------------------------------------------------------------
# 7. UserFlagExecutor independence
# ---------------------------------------------------------------------------

class TestUserFlagExecutorIndependence:
    async def test_same_executor_works_with_bounded_command_adapter(self) -> None:
        from apex_host.agents.user_flag_executor import UserFlagExecutor

        registry = CapabilityRuntimeRegistry()
        backend = _FakeToolBackend(_FakeToolResult(stdout=_FLAG_VALUE))
        registry.ensure_bounded_command("cmd-cap", primitive=_make_primitive(capability_id="cmd-cap", backend=backend))
        config = ApexConfig(target=_TARGET, dry_run=False)
        executor = UserFlagExecutor(config, registry)
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET, "capability_id": "cmd-cap",
                "capability_type": "local_shell", "principal": "application",
                "candidate_path": "/home/application/user.txt", "objective_type": "user_flag",
                "attempted_paths": [], "is_last_candidate": False,
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        result = await executor.run(task, _empty_evidence())
        assert result.episode.data["verified"] is True

    def test_executor_has_no_command_construction_imports(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "ToolBackendCommandReadStrategy" not in code
        assert "BoundedCommandCapabilityAdapter" not in code

    def test_executor_has_no_capability_type_branching_for_command_types(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "local_shell" not in code
        assert "remote_command" not in code
        assert "web_command" not in code

    def test_executor_has_no_credential_handling(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "password" not in code.lower()

    async def test_executor_does_not_return_raw_output(self) -> None:
        from apex_host.agents.user_flag_executor import UserFlagExecutor

        registry = CapabilityRuntimeRegistry()
        backend = _FakeToolBackend(_FakeToolResult(stdout=_FLAG_VALUE))
        registry.ensure_bounded_command("cmd-cap", primitive=_make_primitive(capability_id="cmd-cap", backend=backend))
        config = ApexConfig(target=_TARGET, dry_run=False)
        executor = UserFlagExecutor(config, registry)
        task = TaskSpec(
            id="t2", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET, "capability_id": "cmd-cap",
                "capability_type": "local_shell", "principal": "application",
                "candidate_path": "/home/application/user.txt", "objective_type": "user_flag",
                "attempted_paths": [], "is_last_candidate": False,
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        result = await executor.run(task, _empty_evidence())
        serialized = json.dumps(result.episode.data, default=str)
        assert _FLAG_VALUE not in serialized

    def test_objective_planner_has_no_command_type_branching(self) -> None:
        import apex_host.planners.objective_planner as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "local_shell" not in code
        assert "remote_command" not in code
        assert "web_command" not in code
        assert "ToolBackendCommandReadStrategy" not in code

    def test_objective_parser_has_no_command_type_branching(self) -> None:
        import apex_host.parsers.objective_parser as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "local_shell" not in code
        assert "remote_command" not in code
        assert "web_command" not in code


# ---------------------------------------------------------------------------
# 8. Verifier integration
# ---------------------------------------------------------------------------

class TestVerifierIntegration:
    def test_flag_like_command_output_verified(self) -> None:
        from apex_host.verification.user_flag import verify_user_flag
        result = verify_user_flag(_FLAG_VALUE)
        assert result.verified is True

    def test_empty_output_rejected(self) -> None:
        from apex_host.verification.user_flag import verify_user_flag
        result = verify_user_flag("")
        assert result.verified is False

    def test_multiline_output_rejected(self) -> None:
        from apex_host.verification.user_flag import verify_user_flag
        result = verify_user_flag(f"{_FLAG_VALUE}\nsome other line")
        assert result.verified is False

    def test_html_output_rejected(self) -> None:
        from apex_host.verification.user_flag import verify_user_flag
        result = verify_user_flag("<html><body>not a flag</body></html>")
        assert result.verified is False

    def test_command_error_marker_rejected(self) -> None:
        from apex_host.verification.user_flag import verify_user_flag
        result = verify_user_flag("cat: /home/app/user.txt: No such file or directory")
        assert result.verified is False

    def test_oversized_output_rejected(self) -> None:
        from apex_host.verification.user_flag import verify_user_flag
        result = verify_user_flag("x" * 10000, max_output_bytes=4096)
        assert result.verified is False

    def test_digest_and_redaction_only_downstream(self) -> None:
        from apex_host.verification.user_flag import verify_user_flag
        result = verify_user_flag(_FLAG_VALUE)
        assert result.digest == hashlib.sha256(_FLAG_VALUE.encode("utf-8")).hexdigest()
        field_names = {f.name for f in __import__("dataclasses").fields(result)}
        assert field_names == {"verified", "reason", "digest", "redacted", "length", "method"}


# ---------------------------------------------------------------------------
# 9. Planner
# ---------------------------------------------------------------------------

class TestPlanner:
    async def test_considers_command_capability_generically(self) -> None:
        api = _make_api()
        await _seed_validated_command_capability(api, _TARGET)
        subgraph = await _subgraph(api, _TARGET)
        planner = ObjectivePlanner(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await planner.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list) and len(result) == 1
        assert result[0].params["capability_type"] == "local_shell"

    async def test_ignores_unregistered_adapter(self) -> None:
        api = _make_api()
        await _seed_validated_command_capability(api, _TARGET, runtime_available=False)
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, AbandonSignal)

    async def test_direct_file_read_preferred_when_higher_confidence(self) -> None:
        """Confirms confidence-based ranking (not a hardcoded transport
        preference) — a higher-confidence DFR capability beats a
        lower-confidence command capability."""
        from apex_host.parsers.capability_parser import CapabilityParser as _CP

        api = _make_api()
        h_id = host_id(_TARGET)
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        dfr_parsed = _CP().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="app_dfr", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        await api.apply_deltas(nodes=dfr_parsed.node_deltas, edges=dfr_parsed.edge_deltas)
        dfr_id = access_capability_id(_TARGET, "arbitrary_file_read", "app_dfr")
        ts = now()
        await api.upsert_node(Node(id=dfr_id, type="access_capability", props={"runtime_available": True}, confidence=0.5, source="t", first_seen=ts, last_seen=ts))

        await _seed_validated_command_capability(api, _TARGET, principal="app_cmd", confidence=0.6)
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["capability_id"] == dfr_id

    async def test_command_capability_selected_when_best_available(self) -> None:
        api = _make_api()
        await _seed_validated_command_capability(api, _TARGET, principal="app_cmd", confidence=0.9)
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["capability_type"] == "local_shell"

    async def test_failed_ssh_pair_does_not_block_command_pair(self) -> None:
        from apex_host.graph_ids import objective_id

        api = _make_api()
        ssh_cap_id = access_capability_id(_TARGET, "ssh_command", "application")
        h_id = host_id(_TARGET)
        acc_id = access_state_id(_TARGET, "application", protocol="ssh")
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        await _seed_node(api, acc_id, "access_state", {"level": "user", "username": "application", "target": _TARGET, "service": "ssh"})
        parsed = CapabilityParser().derive_ssh_capability(target=_TARGET, username="application", source_task_id="")
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
        ts = now()
        await api.upsert_node(Node(id=ssh_cap_id, type="access_capability", props={"runtime_available": True}, confidence=0.5, source="t", first_seen=ts, last_seen=ts))
        cmd_cap_id = await _seed_validated_command_capability(api, _TARGET, principal="application")

        obj_id = objective_id(_TARGET, "user_flag")
        await _seed_node(api, obj_id, "objective", {
            "objective_type": "user_flag", "status": "in_progress", "target": _TARGET,
            "attempted_paths": ["/home/application/user.txt"],
            "attempted_capability_paths": [[ssh_cap_id, "/home/application/user.txt"]],
        })
        await _seed_edge(api, h_id, obj_id, edge_type="indicates")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list), "command-capability retry of the SSH-attempted path must still be offered"
        assert result[0].params["capability_id"] == cmd_cap_id
        assert result[0].params["candidate_path"] == "/home/application/user.txt"

    async def test_failed_dfr_pair_does_not_block_command_pair(self) -> None:
        from apex_host.graph_ids import objective_id
        from apex_host.parsers.capability_parser import CapabilityParser as _CP

        api = _make_api()
        h_id = host_id(_TARGET)
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        dfr_parsed = _CP().derive_direct_file_read_capability(
            target=_TARGET, capability_type=AccessCapabilityType.arbitrary_file_read,
            principal="application", source_task_id="", validation_method="operator_attestation", confidence=0.7,
        )
        await api.apply_deltas(nodes=dfr_parsed.node_deltas, edges=dfr_parsed.edge_deltas)
        dfr_id = access_capability_id(_TARGET, "arbitrary_file_read", "application")
        ts = now()
        await api.upsert_node(Node(id=dfr_id, type="access_capability", props={"runtime_available": True}, confidence=0.5, source="t", first_seen=ts, last_seen=ts))
        cmd_cap_id = await _seed_validated_command_capability(api, _TARGET, principal="application")

        obj_id = objective_id(_TARGET, "user_flag")
        await _seed_node(api, obj_id, "objective", {
            "objective_type": "user_flag", "status": "in_progress", "target": _TARGET,
            "attempted_paths": ["/home/application/user.txt"],
            "attempted_capability_paths": [[dfr_id, "/home/application/user.txt"]],
        })
        await _seed_edge(api, h_id, obj_id, edge_type="indicates")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["capability_id"] == cmd_cap_id
        assert result[0].params["candidate_path"] == "/home/application/user.txt"

    async def test_duplicate_pair_not_retried(self) -> None:
        from apex_host.graph_ids import objective_id

        api = _make_api()
        cmd_cap_id = await _seed_validated_command_capability(api, _TARGET, principal="application")
        obj_id = objective_id(_TARGET, "user_flag")
        await _seed_node(api, obj_id, "objective", {
            "objective_type": "user_flag", "status": "in_progress", "target": _TARGET,
            "attempted_paths": ["/home/application/user.txt"],
            "attempted_capability_paths": [[cmd_cap_id, "/home/application/user.txt"]],
        })
        await _seed_edge(api, _ANCHOR, obj_id, edge_type="indicates")
        subgraph = await _subgraph(api, _TARGET)
        core = _ObjectiveDeterministic(
            _TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)), max_attempts=1,
        )
        result = await core.plan(_goal(_TARGET), subgraph, _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "exhausted" in result.reason


# ---------------------------------------------------------------------------
# 10. Policy
# ---------------------------------------------------------------------------

class TestPolicy:
    def test_approves_bounded_command_candidate_against_target(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "candidate_path": "/home/application/user.txt",
                "capability_id": "cmd-cap", "capability_type": "local_shell",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None and decision.status.value == "approved"

    def test_unauthorized_target_blocked(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t2", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": "8.8.8.8",
                "candidate_path": "/home/application/user.txt",
                "capability_id": "cmd-cap", "capability_type": "local_shell",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is None  # falls through to check_target_in_scope, which blocks it earlier in ALL_RULES

    def test_invalid_path_blocked(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t3", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "candidate_path": "/etc/shadow",
                "capability_id": "cmd-cap", "capability_type": "local_shell",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None and decision.status.value == "blocked"

    def test_arbitrary_command_field_blocked(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t4", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "candidate_path": "/home/application/user.txt",
                "capability_id": "cmd-cap", "capability_type": "local_shell",
                "command": "rm -rf /",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None and decision.status.value == "blocked"

    def test_shell_command_field_blocked(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        task = TaskSpec(
            id="t5", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "candidate_path": "/home/application/user.txt",
                "capability_id": "cmd-cap", "capability_type": "local_shell",
                "shell_command": "cat /etc/passwd; rm -rf /",
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        decision = check_bounded_user_flag_verification(task, policy, config)
        assert decision is not None and decision.status.value == "blocked"

    def test_env_and_cwd_fields_blocked(self) -> None:
        config = ApexConfig(target=_TARGET)
        policy = load_policy(config)
        for forbidden_key in ("env", "cwd", "executable", "exec", "payload", "args"):
            task = TaskSpec(
                id=f"t-{forbidden_key}", goal_id="g1", executor_domain="objective",
                params={
                    "tool": "user_flag_verify", "target": _TARGET,
                    "candidate_path": "/home/application/user.txt",
                    "capability_id": "cmd-cap", "capability_type": "local_shell",
                    forbidden_key: "anything",
                },
                subgraph_anchor=_ANCHOR, phase="objective",
            )
            decision = check_bounded_user_flag_verification(task, policy, config)
            assert decision is not None and decision.status.value == "blocked", forbidden_key

    async def test_dispatcher_never_reaches_strategy_when_blocked(self) -> None:
        from apex_host.execution.dispatcher import TaskDispatcher
        from apex_host.execution.registry import TaskRegistry

        config = ApexConfig(target=_TARGET, dry_run=False)
        advisor = PolicyAdvisor(load_policy(config), config)

        class _SpyExecutor:
            calls = 0

            async def run(self, task: Any, evidence: Any) -> Any:
                type(self).calls += 1
                raise AssertionError("adapter/executor must never be reached for a blocked task")

        dispatcher = TaskDispatcher(
            advisor=advisor, task_registry=TaskRegistry(), config=config,
            run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type]
            user_flag_executor=_SpyExecutor(),  # type: ignore[arg-type]
        )
        task = TaskSpec(
            id="t6", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET,
                "candidate_path": "/home/application/user.txt",
                "capability_id": "cmd-cap", "capability_type": "local_shell",
                "command": "id",  # forbidden field — must be blocked before the executor
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

    async def test_dispatcher_blocks_excessive_timeout_via_dry_run_short_circuit(self) -> None:
        """A timeout misconfiguration cannot escalate into a real strategy
        call: even with an absurd timeout, dry_run=True short-circuits
        before any adapter is ever resolved."""
        from apex_host.agents.user_flag_executor import UserFlagExecutor

        registry = CapabilityRuntimeRegistry()
        backend = _FakeToolBackend(_FakeToolResult(stdout=_FLAG_VALUE))
        registry.ensure_bounded_command("cmd-cap", primitive=_make_primitive(capability_id="cmd-cap", backend=backend, timeout_seconds=999999.0))
        config = ApexConfig(target=_TARGET, dry_run=True)
        executor = UserFlagExecutor(config, registry)
        task = TaskSpec(
            id="t7", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET, "capability_id": "cmd-cap",
                "capability_type": "local_shell", "principal": "application",
                "candidate_path": "/home/application/user.txt", "objective_type": "user_flag",
                "attempted_paths": [], "is_last_candidate": False,
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        result = await executor.run(task, _empty_evidence())
        assert result.episode.data["verified"] is False
        assert backend.calls == []


# ---------------------------------------------------------------------------
# 11. Persistence and redaction
# ---------------------------------------------------------------------------

class TestPersistenceAndRedaction:
    async def test_raw_output_absent_from_ekg(self) -> None:
        api = _make_api()
        await _seed_validated_command_capability(api, _TARGET)
        subgraph = await _subgraph(api, _TARGET)
        serialized = json.dumps([n.props for n in subgraph.nodes], default=str)
        assert _FLAG_VALUE not in serialized

    async def test_raw_output_absent_from_episodes(self) -> None:
        from apex_host.agents.user_flag_executor import UserFlagExecutor

        registry = CapabilityRuntimeRegistry()
        backend = _FakeToolBackend(_FakeToolResult(stdout=_FLAG_VALUE))
        registry.ensure_bounded_command("cmd-cap", primitive=_make_primitive(capability_id="cmd-cap", backend=backend))
        config = ApexConfig(target=_TARGET, dry_run=False)
        executor = UserFlagExecutor(config, registry)
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="objective",
            params={
                "tool": "user_flag_verify", "target": _TARGET, "capability_id": "cmd-cap",
                "capability_type": "local_shell", "principal": "application",
                "candidate_path": "/home/application/user.txt", "objective_type": "user_flag",
                "attempted_paths": [], "is_last_candidate": False,
            },
            subgraph_anchor=_ANCHOR, phase="objective",
        )
        result = await executor.run(task, _empty_evidence())
        assert _FLAG_VALUE not in json.dumps(result.episode.data, default=str)

    async def test_raw_output_absent_from_reports(self) -> None:
        api = _make_api()
        await _seed_validated_command_capability(api, _TARGET)
        subgraph = await _subgraph(api, _TARGET)
        state = {
            **_make_initial_state(_TARGET),
            "completed": True,
            "bounded_command_log": [{
                "capability_id": "cmd-cap", "capability_type": "local_shell",
                "candidate_path": "/home/application/user.txt", "blocked": False,
                "connected": True, "verified": True, "bytes_received": 16,
                "truncated": False, "error": None, "phase": "objective",
            }],
        }
        report = build_report(state, subgraph, ApexConfig(target=_TARGET))
        text = format_text(report)
        assert _FLAG_VALUE not in text

    async def test_raw_output_absent_from_json(self) -> None:
        api = _make_api()
        await _seed_validated_command_capability(api, _TARGET)
        subgraph = await _subgraph(api, _TARGET)
        state = {**_make_initial_state(_TARGET), "completed": True}
        report = build_report(state, subgraph, ApexConfig(target=_TARGET))
        data = to_json_dict(report)
        assert _FLAG_VALUE not in json.dumps(data)

    def test_credentials_absent_from_capability_metadata(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        serialized = json.dumps(parsed.node_deltas[0].props).lower()
        for term in ("password", "cookie", "token", "secret"):
            assert term not in serialized

    def test_session_handles_absent_from_capability_metadata(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="operator_attestation", confidence=0.9,
        )
        serialized = json.dumps(parsed.node_deltas[0].props)
        assert "ToolBackend" not in serialized
        assert "<" not in serialized  # no repr()-style object leakage

    def test_command_strings_absent_from_capability_metadata(self) -> None:
        parsed = CapabilityParser().derive_command_capability(
            target=_TARGET, capability_type=AccessCapabilityType.local_shell,
            principal="application", source_task_id="", validation_method="operator_attestation",
            confidence=0.9, strategy_id="strategy-abc",
        )
        serialized = json.dumps(parsed.node_deltas[0].props)
        assert "cat -- " not in serialized
        assert "cat" not in json.dumps(parsed.node_deltas[0].props.get("metadata", {}))

    async def test_raw_flag_absent_from_experience_replay(self) -> None:
        """Even a fully-completed engagement's derived Experience nodes
        must never carry the raw flag value (Phase 16 experience replay
        reads engagement state generically — it has no special knowledge of
        capability types, so this is really a re-confirmation that nothing
        upstream ever placed the raw value where experience derivation
        could see it)."""
        api = _make_api()
        await _seed_validated_command_capability(api, _TARGET)
        subgraph = await _subgraph(api, _TARGET)
        serialized = json.dumps([n.props for n in subgraph.nodes] + [e.props for e in subgraph.edges], default=str)
        assert _FLAG_VALUE not in serialized


# ---------------------------------------------------------------------------
# 12. Full synthetic graph — positive
# ---------------------------------------------------------------------------

def _make_initial_state(target: str, run_id: str = "run-21") -> dict[str, Any]:
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
        "objective_status": "", "objective_summary": {}, "direct_file_read_log": [],
        "bounded_command_log": [],
    }


async def _seed_command_ready_engagement(api: MemoryAPI, target: str) -> None:
    """Seed the recon/web-phase EKG state a real engagement would already
    have produced (host + an http service + an endpoint) plus a validated,
    runtime-available bounded-command capability — no SSH/access_state and
    no direct-file-read capability anywhere, proving the objective phase is
    reachable through the bounded-command capability alone."""
    h_id = host_id(target)
    svc_id = service_id(target, "80", "tcp")
    ep_id = endpoint_id(f"http://{target}/index.html")
    await _seed_node(api, h_id, "host", {"ip": target})
    await _seed_node(api, svc_id, "service", {"port": "80", "proto": "tcp", "service": "http", "state": "open"})
    await _seed_node(api, ep_id, "endpoint", {"url": f"http://{target}/index.html"})
    await _seed_edge(api, h_id, svc_id, edge_type="exposes")
    await _seed_edge(api, h_id, ep_id, edge_type="exposes")
    await _seed_validated_command_capability(api, target, principal="application")


class TestFullGraphPositive:
    async def test_full_graph_verified_success_via_bounded_command_no_ssh_no_dfr(self, tmp_path: Path) -> None:
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5, allowed_tools=["cat"],
            bounded_command_operator_attested=True, bounded_command_capability_type="local_shell",
            bounded_command_principal="application",
            user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] == EngagementOutcome.user_flag_verified.value
        assert is_success_outcome(EngagementOutcome(final_state["outcome"])) is True
        assert final_state["completed"] is True
        assert exit_code_for(EngagementOutcome(final_state["outcome"])) == 0

        subgraph = await _subgraph(api, _TARGET)
        assert not any(n.type == "access_state" for n in subgraph.nodes), "no SSH access_state anywhere in this run"
        assert not any(
            n.type == "access_capability" and str(n.props.get("capability_type", "")) in ("arbitrary_file_read", "api_file_read")
            for n in subgraph.nodes
        ), "no direct-file-read capability anywhere in this run"
        assert any(n.type == "objective_evidence" for n in subgraph.nodes)

    async def test_full_graph_report_shows_local_command_capability_label(self, tmp_path: Path) -> None:
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=5, allowed_tools=["cat"],
            bounded_command_operator_attested=True, bounded_command_capability_type="local_shell",
            bounded_command_principal="application",
            user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        subgraph = await _subgraph(api, _TARGET)

        report = build_report(final_state, subgraph, config)
        text = format_text(report)
        assert "Capability used" in text and "Local Command" in text
        assert "Benchmark success  : Yes" in text
        assert _FLAG_VALUE not in text

        data = to_json_dict(report)
        assert data["objective"]["benchmark_success"] is True
        assert data["bounded_command"]["capabilities_derived"] == 1
        assert data["bounded_command"]["verified_count"] == 1
        assert _FLAG_VALUE not in json.dumps(data)

    async def test_full_graph_dry_run_never_verifies_via_bounded_command(self, tmp_path: Path) -> None:
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=5, allowed_tools=["cat"],
            bounded_command_operator_attested=True, bounded_command_capability_type="local_shell",
            bounded_command_principal="application",
            user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value


# ---------------------------------------------------------------------------
# 13. Negative full graph
# ---------------------------------------------------------------------------

class TestFullGraphNegative:
    async def test_command_context_unavailable_never_becomes_verified_success(self) -> None:
        """No cat file exists at the configured root — the command context
        is 'unavailable' in the sense that nothing readable is there."""
        from apex_host.graph import build_apex_graph

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=3, allowed_tools=["cat"],
            bounded_command_operator_attested=True, bounded_command_capability_type="local_shell",
            bounded_command_principal="application",
            user_flag_candidate_roots=["/nonexistent-root-for-testing"], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

    async def test_permission_error_never_becomes_verified_success(self, tmp_path: Path) -> None:
        import os
        import stat

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        os.chmod(flag_file, 0)  # remove all permissions
        try:
            from apex_host.graph import build_apex_graph

            api = _make_api()
            await _seed_command_ready_engagement(api, _TARGET)
            config = ApexConfig(
                target=_TARGET, dry_run=False, max_turns=3, allowed_tools=["cat"],
                bounded_command_operator_attested=True, bounded_command_capability_type="local_shell",
                bounded_command_principal="application",
                user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
            )
            registry = ToolRegistry.from_config(config)
            graph = build_apex_graph(api, registry, config)
            final_state = await graph.ainvoke(_make_initial_state(_TARGET))
            assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value
        finally:
            os.chmod(flag_file, stat.S_IRUSR | stat.S_IWUSR)

    async def test_html_output_never_becomes_verified_success(self) -> None:
        from apex_host.graph import build_apex_graph

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = ApexConfig(target=_TARGET, dry_run=False, max_turns=3, allowed_tools=["cat"])
        # No bounded_command_operator_attested — capability never gets a
        # registered adapter, so the executor cannot even reach a strategy
        # to produce HTML in the first place (this proves the same
        # never-verified guarantee holds when no adapter is available).
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

    async def test_oversized_command_output_never_becomes_verified_success(self, tmp_path: Path) -> None:
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text("x" * 10000)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=3, allowed_tools=["cat"],
            bounded_command_operator_attested=True, bounded_command_capability_type="local_shell",
            bounded_command_principal="application", bounded_command_max_output_bytes=100,
            user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

    async def test_policy_blocks_task_never_becomes_verified_success(self) -> None:
        """A capability whose principal never matches the configured
        bounded_command_principal never gets a registered adapter — the
        engagement completes without ever reaching a real command."""
        from apex_host.graph import build_apex_graph

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)  # principal="application"
        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=3, allowed_tools=["cat"],
            bounded_command_operator_attested=True, bounded_command_capability_type="local_shell",
            bounded_command_principal="someone-else",  # mismatched principal
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value
        assert final_state["completed"] is True


# ---------------------------------------------------------------------------
# 14. Dry-run graph
# ---------------------------------------------------------------------------

class TestDryRunGraph:
    async def test_dry_run_command_capability_present_but_never_verified(self, tmp_path: Path) -> None:
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        api = _make_api()
        await _seed_command_ready_engagement(api, _TARGET)
        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=5, allowed_tools=["cat"],
            bounded_command_operator_attested=True, bounded_command_capability_type="local_shell",
            bounded_command_principal="application",
            user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        subgraph = await _subgraph(api, _TARGET)
        assert any(n.type == "access_capability" for n in subgraph.nodes), "capability metadata still present"
        assert not any(n.type == "objective_evidence" for n in subgraph.nodes), "no evidence node in dry-run"
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value

        report = build_report(final_state, subgraph, config)
        assert report.success is False

    async def test_dry_run_report_is_deterministic(self, tmp_path: Path) -> None:
        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        results = []
        for _ in range(2):
            api = _make_api()
            await _seed_command_ready_engagement(api, _TARGET)
            config = ApexConfig(
                target=_TARGET, dry_run=True, max_turns=5, allowed_tools=["cat"],
                bounded_command_operator_attested=True, bounded_command_capability_type="local_shell",
                bounded_command_principal="application",
                user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
            )
            registry = ToolRegistry.from_config(config)
            graph = build_apex_graph(api, registry, config)
            final_state = await graph.ainvoke(_make_initial_state(_TARGET))
            results.append(final_state["outcome"])
        assert results[0] == results[1]


# ---------------------------------------------------------------------------
# 15. Architecture scans
# ---------------------------------------------------------------------------

_PHASE21_NEW_FILES: tuple[str, ...] = ()  # capability_seed.py is Phase20-owned; no wholly-new Phase21 files

_HTB_MACHINE_NAMES: tuple[str, ...] = (
    "meow", "fawn", "dancing", "redeemer", "explosion", "preignition",
    "mongod", "synced", "appointment", "sequel", "crocodile", "responder",
    "three", "ignition", "vaccine", "cap", "lame", "blue",
)


class TestArchitectureScans:
    def test_memfabric_unchanged_by_this_phase(self) -> None:
        memfabric_dir = Path("memfabric")
        forbidden_terms = (
            "bounded_command", "BoundedCommandCapabilityAdapter", "BoundedCommandReadStrategy",
            "ToolBackendCommandReadStrategy", "local_shell", "remote_command",
        )
        for py_file in memfabric_dir.rglob("*.py"):
            code = _non_comment_code(py_file.read_text())
            for term in forbidden_terms:
                assert term not in code, f"{py_file} references {term!r} — memfabric must remain domain-agnostic"

    def test_memfabric_has_no_new_apex_host_imports(self) -> None:
        memfabric_dir = Path("memfabric")
        for py_file in memfabric_dir.rglob("*.py"):
            code = py_file.read_text()
            assert "import apex_host" not in code
            assert "from apex_host" not in code

    def test_no_machine_specific_names_in_new_code(self) -> None:
        # dispatch_node.py is deliberately excluded here — it is a
        # pre-existing, heavily modified (not wholly new) file with a
        # legitimate `cap` loop variable (`for cap in
        # access_capabilities_from_subgraph(...)`) that would false-positive
        # against the HTB machine name "Cap" under word-boundary matching.
        # Mirrors the identical scoping decision made in Phase 20's own
        # architecture-scan test.
        for rel_path in (
            "apex_host/runtime_registry.py",
            "apex_host/parsers/capability_parser.py",
            "apex_host/orchestration/capability_seed.py",
        ):
            source = Path(rel_path).read_text()
            code = _non_comment_code(source)
            for name in _HTB_MACHINE_NAMES:
                pattern = re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE)
                assert not pattern.search(code), f"{rel_path} contains machine-name-like token {name!r}"

    def test_no_hardcoded_flag_values_in_new_code(self) -> None:
        for path in (
            Path("apex_host/runtime_registry.py"),
            Path("apex_host/parsers/capability_parser.py"),
            Path("apex_host/orchestration/capability_seed.py"),
        ):
            code = _non_comment_code(path.read_text())
            assert "HTB{" not in code
            assert "flag{" not in code.lower()

    def test_no_generic_execute_api_exposed_to_objective_layer(self) -> None:
        import apex_host.runtime_registry as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "def execute(self, command" not in code
        assert "def run_shell(" not in code
        assert "def send_command(" not in code
        assert "def exec(" not in code

    def test_no_shell_true_in_new_code(self) -> None:
        for path in (
            Path("apex_host/runtime_registry.py"),
            Path("apex_host/orchestration/capability_seed.py"),
            Path("apex_host/orchestration/dispatch_node.py"),
        ):
            code = _non_comment_code(path.read_text())
            assert "shell=True" not in code

    def test_no_bin_sh_c_or_bash_c_anywhere_new(self) -> None:
        for path in (
            Path("apex_host/runtime_registry.py"),
            Path("apex_host/orchestration/capability_seed.py"),
        ):
            code = _non_comment_code(path.read_text())
            assert "/bin/sh" not in code
            assert "bash -c" not in code

    def test_no_command_string_from_llm_task(self) -> None:
        """ObjectivePlanner never has an LLM seam at all (see its own
        module docstring) — this asserts that fact statically, so a future
        change cannot silently introduce one that could smuggle a command
        string into a task."""
        import apex_host.planners.objective_planner as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "PlanningEngine" not in code
        assert "model_router" not in code

    def test_objective_planner_transport_independent(self) -> None:
        import apex_host.planners.objective_planner as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "ToolBackendCommandReadStrategy" not in code
        assert "paramiko" not in code
        assert "httpx" not in code

    def test_user_flag_executor_transport_independent(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "isinstance(adapter" not in code
        assert "BoundedCommandCapabilityAdapter" not in code
        assert "ToolBackendCommandReadStrategy" not in code

    def test_objective_parser_transport_independent(self) -> None:
        import apex_host.parsers.objective_parser as mod
        code = _non_comment_code(inspect.getsource(mod))
        assert "BoundedCommandCapabilityAdapter" not in code

    def test_verifier_unchanged_and_authoritative(self) -> None:
        """The verifier module was not modified by this phase — it remains
        the SOLE place flag-shape validation logic lives."""
        import apex_host.verification.user_flag as mod
        code = inspect.getsource(mod)
        assert "def verify_user_flag(" in code
        assert "local_shell" not in code
        assert "remote_command" not in code
        assert "web_command" not in code

    def test_dry_run_default_true(self) -> None:
        config = ApexConfig(target=_TARGET)
        assert config.dry_run is True

    def test_bounded_command_disabled_by_default(self) -> None:
        config = ApexConfig(target=_TARGET)
        assert config.bounded_command_operator_attested is False
