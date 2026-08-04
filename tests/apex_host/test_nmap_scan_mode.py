# test_nmap_scan_mode.py
# Tests for unprivileged Nmap scan selection: the remote (non-raw-socket) backend must run -sT, never -sS or the privileged default; the LLM cannot inject raw scans/scripts/output paths/extra targets; UDP is never silently converted to TCP; and a raw-socket failure is repaired once to -sT (terminal if already -sT). Fake runner only — no real scans.
"""Unit + integration tests for the nmap raw-socket scan-mode fix.

Covers ``apex_host.tools.nmap_command`` (pure normalization + deterministic
repair), ``apex_host.tools.backend.backend_raw_socket_capability`` (three-state),
the dispatcher execution chokepoint (a remote/unprivileged backend receives
``-sT``; UDP is rejected as unsupported), and the deterministic raw-socket
repair in ``repair_agent``. RFC 5737 documentation address; no real network.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from apex_host.tools import nmap_command as nc
from apex_host.tools.backend import (
    RAW_SOCKET_CAPABILITY_RAW,
    RAW_SOCKET_CAPABILITY_UNKNOWN,
    RAW_SOCKET_CAPABILITY_UNPRIVILEGED,
    backend_raw_socket_capability,
)

_HOST = "192.0.2.10"


def _scan_flags(args: list[str]) -> list[str]:
    return [a for a in args if a in nc._SCAN_MODE_INTENT]


# ---------------------------------------------------------------------------
# normalize_nmap_command — pure
# ---------------------------------------------------------------------------

class TestNormalizeUnprivileged:
    def test_unprivileged_forces_sT(self) -> None:
        # A privileged default (no scan flag) on an unprivileged backend:
        # -sT is not enough on its own — nmap as uid 0 without CAP_NET_RAW
        # still attempts raw-socket host discovery — so --unprivileged and
        # -Pn are injected too.
        r = nc.normalize_nmap_command(["-sV", "-T4", "-Pn", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert r.args == ["-sT", "--unprivileged", "-Pn", "-sV", "-T4", _HOST]
        assert r.transport == nc.TRANSPORT_TCP_CONNECT
        assert r.unsupported is False

    def test_unprivileged_injects_unprivileged_and_pn(self) -> None:
        # The exact flags that resolve the demonstrated EPERM failure.
        r = nc.normalize_nmap_command(["-sV", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert "--unprivileged" in r.args and "-Pn" in r.args and "-sT" in r.args

    def test_unprivileged_no_duplicate_injected_flags(self) -> None:
        # A planner/LLM that already supplied --unprivileged/-Pn must not get
        # them doubled.
        r = nc.normalize_nmap_command(
            ["-sT", "--unprivileged", "-Pn", "-sV", _HOST], _HOST, capability=nc.UNPRIVILEGED,
        )
        assert r.args.count("--unprivileged") == 1
        assert r.args.count("-Pn") == 1
        assert _scan_flags(r.args) == ["-sT"]

    def test_unprivileged_rewrites_sS_to_sT(self) -> None:
        r = nc.normalize_nmap_command(["-sS", "-sV", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert "-sS" not in r.args and "-sT" in r.args
        assert "--unprivileged" in r.args and "-Pn" in r.args
        assert r.transport == nc.TRANSPORT_TCP_CONNECT

    def test_exactly_one_tcp_scan_mode(self) -> None:
        # Even given a contradictory pile of scan flags, exactly one survives.
        r = nc.normalize_nmap_command(["-sS", "-sT", "-sA", "-sV", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert _scan_flags(r.args) == ["-sT"]

    def test_equivalent_to_documented_command(self) -> None:
        r = nc.normalize_nmap_command(["-sV", "-Pn", "-T4", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        # Equivalent to `nmap -sT --unprivileged -Pn -sV -T4 <target>`
        # (scan mode + unprivileged flags prepended; kept flags follow; target trails).
        assert set(r.args) == {"-sT", "--unprivileged", "-sV", "-Pn", "-T4", _HOST}
        assert r.args[0] == "-sT" and r.args[-1] == _HOST

    def test_unknown_capability_defaults_to_sT(self) -> None:
        r = nc.normalize_nmap_command(["-sV", _HOST], _HOST, capability=nc.UNKNOWN)
        assert "-sT" in r.args and r.transport == nc.TRANSPORT_TCP_CONNECT

    def test_bogus_capability_string_defaults_safely(self) -> None:
        r = nc.normalize_nmap_command(["-sV", _HOST], _HOST, capability="nonsense")
        assert "-sT" in r.args


class TestNormalizeRawCapable:
    def test_raw_capable_preserves_privileged_default(self) -> None:
        r = nc.normalize_nmap_command(["-sV", "-T4", "-Pn", _HOST], _HOST, capability=nc.RAW_SOCKET)
        assert "-sT" not in r.args  # existing privileged strategy (SYN default)
        assert r.transport == nc.TRANSPORT_TCP_SYN
        assert r.args == ["-sV", "-T4", "-Pn", _HOST]

    def test_raw_capable_keeps_explicit_sS(self) -> None:
        r = nc.normalize_nmap_command(["-sS", "-sV", _HOST], _HOST, capability=nc.RAW_SOCKET)
        assert _scan_flags(r.args) == ["-sS"]
        assert r.transport == nc.TRANSPORT_TCP_SYN

    def test_raw_capable_honors_explicit_sT(self) -> None:
        r = nc.normalize_nmap_command(["-sT", "-sV", _HOST], _HOST, capability=nc.RAW_SOCKET)
        assert _scan_flags(r.args) == ["-sT"]


class TestNormalizeInjectionResistance:
    def test_drops_script_injection(self) -> None:
        r = nc.normalize_nmap_command(
            ["-sV", "--script", "http-shellshock", _HOST], _HOST, capability=nc.UNPRIVILEGED,
        )
        assert "--script" not in r.args and "http-shellshock" not in r.args
        assert "--script" in r.dropped

    def test_drops_output_file_flags(self) -> None:
        for out_flag in ("-oN", "-oX", "-oG", "-oA", "-oS"):
            r = nc.normalize_nmap_command(
                ["-sV", out_flag, "/tmp/loot", _HOST], _HOST, capability=nc.UNPRIVILEGED,
            )
            assert out_flag not in r.args and "/tmp/loot" not in r.args

    def test_drops_extra_target(self) -> None:
        r = nc.normalize_nmap_command(
            ["-sV", _HOST, "203.0.113.9"], _HOST, capability=nc.UNPRIVILEGED,
        )
        # Only the authorized target survives as a positional.
        assert "203.0.113.9" not in r.args
        assert [a for a in r.args if not a.startswith("-")] == [_HOST]

    def test_drops_input_list_flags(self) -> None:
        r = nc.normalize_nmap_command(["-sV", "-iL", "targets.txt", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert "-iL" not in r.args and "targets.txt" not in r.args

    def test_keeps_bounded_ports_and_timing(self) -> None:
        r = nc.normalize_nmap_command(
            ["-sV", "-p", "22,80,443", "-T4", _HOST], _HOST, capability=nc.UNPRIVILEGED,
        )
        assert "-p" in r.args and "22,80,443" in r.args and "-T4" in r.args

    def test_drops_malformed_port_value(self) -> None:
        r = nc.normalize_nmap_command(["-sV", "-p", "$(whoami)", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert "$(whoami)" not in r.args and "-p" not in r.args


class TestNormalizeUdp:
    def test_udp_unsupported_on_unprivileged(self) -> None:
        r = nc.normalize_nmap_command(["-sU", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert r.unsupported is True and r.args == []
        assert r.transport == nc.TRANSPORT_UDP
        assert "not converting" in r.reason.lower() or "raw-socket" in r.reason.lower()

    def test_udp_allowed_on_raw_capable(self) -> None:
        r = nc.normalize_nmap_command(["-sU", "-sV", _HOST], _HOST, capability=nc.RAW_SOCKET)
        assert r.unsupported is False and "-sU" in r.args

    def test_udp_never_silently_becomes_tcp_precheck(self) -> None:
        r = nc.normalize_nmap_command(["-sU", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert "-sT" not in r.args


class TestNormalizeRawOnlyFeatures:
    """-O and --traceroute need raw sockets and have no faithful unprivileged
    equivalent — they are refused truthfully, never silently dropped so a
    plain TCP scan is presented as if it ran them."""

    def test_os_detection_unsupported_on_unprivileged(self) -> None:
        r = nc.normalize_nmap_command(["-sV", "-O", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert r.unsupported is True and r.args == []
        assert "-O" in r.reason

    def test_traceroute_unsupported_on_unprivileged(self) -> None:
        r = nc.normalize_nmap_command(["-sV", "--traceroute", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert r.unsupported is True and r.args == []

    def test_os_detection_unsupported_on_unknown(self) -> None:
        r = nc.normalize_nmap_command(["-sV", "-O", _HOST], _HOST, capability=nc.UNKNOWN)
        assert r.unsupported is True

    def test_os_detection_not_silently_downgraded_to_tcp(self) -> None:
        # It must NOT come back as a plain -sT scan pretending to be OS detection.
        r = nc.normalize_nmap_command(["-sV", "-O", _HOST], _HOST, capability=nc.UNPRIVILEGED)
        assert "-sT" not in r.args and r.args == []

    def test_os_detection_allowed_on_raw_capable(self) -> None:
        # On a raw-capable backend the request is not refused (pre-existing
        # behavior: -O is not in the safe allowlist so it is dropped, but the
        # scan itself still runs — never an unsupported refusal).
        r = nc.normalize_nmap_command(["-sV", "-O", _HOST], _HOST, capability=nc.RAW_SOCKET)
        assert r.unsupported is False


# ---------------------------------------------------------------------------
# plan_raw_socket_repair — pure deterministic repair decision
# ---------------------------------------------------------------------------

class TestRepairPlan:
    def test_privileged_failure_rewrites_with_unprivileged_flags(self) -> None:
        plan = nc.plan_raw_socket_repair(["-sV", "-T4", "-Pn", _HOST], _HOST)
        assert plan.terminal is False
        assert plan.repaired_args is not None
        # The rewrite adds the flags that actually resolve the EPERM.
        assert "-sT" in plan.repaired_args
        assert "--unprivileged" in plan.repaired_args
        assert "-Pn" in plan.repaired_args
        assert plan.transport == nc.TRANSPORT_TCP_CONNECT

    def test_syn_failure_rewrites_to_sT(self) -> None:
        plan = nc.plan_raw_socket_repair(["-sS", "-sV", _HOST], _HOST)
        assert plan.terminal is False and "-sS" not in (plan.repaired_args or [])
        assert "-sT" in (plan.repaired_args or [])
        assert "--unprivileged" in (plan.repaired_args or [])

    def test_sT_without_unprivileged_is_repaired_not_terminal(self) -> None:
        # A bare -sT -Pn (no --unprivileged) that failed with EPERM is NOT
        # terminal — it is missing the flag that actually resolves the error.
        plan = nc.plan_raw_socket_repair(["-sT", "-sV", "-Pn", _HOST], _HOST)
        assert plan.terminal is False
        assert "--unprivileged" in (plan.repaired_args or [])

    def test_repaired_command_is_a_distinct_fingerprint(self) -> None:
        # The repair must produce a materially different action so it is not
        # dedup-suppressed as a repeat of the failed command.
        failed = ["-sT", "-sV", "-Pn", _HOST]
        plan = nc.plan_raw_socket_repair(failed, _HOST)
        assert plan.repaired_args is not None
        assert nc.canonical_fingerprint_args(plan.repaired_args, _HOST) != \
            nc.canonical_fingerprint_args(failed, _HOST)

    def test_terminal_only_when_unprivileged_flags_already_present(self) -> None:
        plan = nc.plan_raw_socket_repair(["-sT", "--unprivileged", "-Pn", "-sV", _HOST], _HOST)
        assert plan.terminal is True and plan.repaired_args is None
        assert "--unprivileged" in plan.reason

    def test_udp_failure_is_terminal(self) -> None:
        plan = nc.plan_raw_socket_repair(["-sU", _HOST], _HOST)
        assert plan.terminal is True


class TestIncompleteScanEscalation:
    _DISCOVERY = ["-sT", "--unprivileged", "-Pn", "-T4", "--top-ports", "100",
                  "--max-retries", "2", "--host-timeout", "80s", _HOST]

    def test_discovery_timeout_escalates_to_targeted_pV_scan(self) -> None:
        plan = nc.plan_incomplete_scan_escalation(self._DISCOVERY, _HOST)
        assert plan.terminal is False
        assert plan.repaired_args is not None
        assert "-sV" in plan.repaired_args
        assert "-p" in plan.repaired_args
        # A fixed common-port list, not the top-ports breadth.
        assert "--top-ports" not in plan.repaired_args
        assert "80" in " ".join(plan.repaired_args)  # a common port (80) present

    def test_escalated_scan_has_distinct_fingerprint(self) -> None:
        plan = nc.plan_incomplete_scan_escalation(self._DISCOVERY, _HOST)
        assert plan.repaired_args is not None
        assert nc.canonical_fingerprint_args(plan.repaired_args, _HOST) != \
            nc.canonical_fingerprint_args(self._DISCOVERY, _HOST)

    def test_already_targeted_scan_is_terminal(self) -> None:
        targeted = ["-sT", "--unprivileged", "-Pn", "-T4", "-p", "22,80", "-sV",
                    "--host-timeout", "80s", _HOST]
        plan = nc.plan_incomplete_scan_escalation(targeted, _HOST)
        assert plan.terminal is True and plan.repaired_args is None

    def test_escalation_preserves_host_timeout(self) -> None:
        plan = nc.plan_incomplete_scan_escalation(self._DISCOVERY, _HOST)
        assert plan.repaired_args is not None
        assert "--host-timeout" in plan.repaired_args
        assert "80s" in plan.repaired_args


# ---------------------------------------------------------------------------
# backend_raw_socket_capability — three-state
# ---------------------------------------------------------------------------

@dataclass
class _Cfg:
    tool_backend: str = "remote"
    tool_backend_raw_socket_capable: bool | None = None


class TestBackendCapability:
    def test_remote_is_unprivileged(self) -> None:
        assert backend_raw_socket_capability(_Cfg(tool_backend="remote")) == RAW_SOCKET_CAPABILITY_UNPRIVILEGED  # type: ignore[arg-type]

    def test_local_is_raw(self) -> None:
        assert backend_raw_socket_capability(_Cfg(tool_backend="local")) == RAW_SOCKET_CAPABILITY_RAW  # type: ignore[arg-type]

    def test_override_true_is_raw(self) -> None:
        cfg = _Cfg(tool_backend="remote", tool_backend_raw_socket_capable=True)
        assert backend_raw_socket_capability(cfg) == RAW_SOCKET_CAPABILITY_RAW  # type: ignore[arg-type]

    def test_override_false_is_unprivileged(self) -> None:
        cfg = _Cfg(tool_backend="local", tool_backend_raw_socket_capable=False)
        assert backend_raw_socket_capability(cfg) == RAW_SOCKET_CAPABILITY_UNPRIVILEGED  # type: ignore[arg-type]

    def test_unrecognized_backend_is_unknown(self) -> None:
        assert backend_raw_socket_capability(_Cfg(tool_backend="weird")) == RAW_SOCKET_CAPABILITY_UNKNOWN  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Dispatcher integration — the execution chokepoint (fake runner only)
# ---------------------------------------------------------------------------

from apex_host.config import ApexConfig  # noqa: E402
from apex_host.execution.context import ExecutionContext  # noqa: E402
from apex_host.execution.dispatcher import TaskDispatcher  # noqa: E402
from apex_host.execution.dispositions import ExecutionDisposition  # noqa: E402
from apex_host.execution.registry import TaskRegistry  # noqa: E402
from apex_host.policy import PolicyAdvisor  # noqa: E402
from apex_host.policy.policy_loader import load_policy  # noqa: E402
from apex_host.types import ToolResult  # noqa: E402
from memfabric.ids import new_id  # noqa: E402
from memfabric.types import TaskSpec  # noqa: E402


def _nmap_task(args: list[str], target: str = _HOST) -> TaskSpec:
    return TaskSpec(
        id=new_id(), goal_id=new_id(), executor_domain="recon",
        params={"tool": "nmap", "args": args, "target": target, "parser": "nmap"},
        subgraph_anchor=f"host:{target}", phase="recon",
    )


def _context() -> ExecutionContext:
    class _Ev:
        entries: list[Any] = []
        subgraph: Any = None
        blocked_fields: list[Any] = []
    return ExecutionContext(
        run_id="run-nmap", phase="recon", turn_number=1, evidence_version=None,
        subgraph=None, evidence=_Ev(), dry_run=False,
    )


def _dispatcher(tool_backend: str, calls: list[tuple[str, list[str]]]) -> TaskDispatcher:
    config = ApexConfig(target=_HOST, dry_run=False, tool_backend=tool_backend,
                        allowed_tools=["nmap", "curl", "nc"])

    async def _fake_run(cmd: Any, cfg: Any) -> ToolResult:
        calls.append((cmd.tool, list(cmd.args)))
        return ToolResult(
            command=cmd, stdout="", stderr="", returncode=0,
            duration_seconds=0.0, dry_run=False, backend=tool_backend,
        )

    return TaskDispatcher(
        advisor=PolicyAdvisor(load_policy(config), config),
        task_registry=TaskRegistry(), config=config, run_command_fn=_fake_run,
    )


def _timeout_dispatcher(calls: list[tuple[str, list[str]]]) -> TaskDispatcher:
    """A dispatcher whose fake nmap returns rc0 + a host-timeout stdout with
    0 open ports — the demonstrated 'executed_success but scanned nothing' case."""
    config = ApexConfig(target=_HOST, dry_run=False, tool_backend="remote",
                        allowed_tools=["nmap"])

    async def _fake_run(cmd: Any, cfg: Any) -> ToolResult:
        calls.append((cmd.tool, list(cmd.args)))
        return ToolResult(
            command=cmd,
            stdout=f"Nmap scan report for {_HOST}\nSkipping host {_HOST} due to host timeout\n",
            stderr="", returncode=0, duration_seconds=80.0, dry_run=False, backend="remote",
        )

    return TaskDispatcher(
        advisor=PolicyAdvisor(load_policy(config), config),
        task_registry=TaskRegistry(), config=config, run_command_fn=_fake_run,
    )


class TestDispatcherIncompleteScan:
    @pytest.mark.asyncio
    async def test_timed_out_zero_ports_is_repairable_failure_not_success(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        disp = _timeout_dispatcher(calls)
        result = await disp.dispatch(
            _nmap_task(["-sT", "--unprivileged", "-Pn", "-T4", "--top-ports", "100", _HOST]),
            _context(),
        )
        tr = result.tool_result_dict
        # Classified incomplete, NOT plain success.
        assert tr["error_category"] == "nmap_incomplete_host_timeout"
        assert result.disposition == ExecutionDisposition.EXECUTED_FAILURE
        # Error contains "timed out" so outcome_for() → fixable (repair-eligible).
        assert "timed out" in (tr.get("error") or "")
        from apex_host.orchestration.completion import outcome_for
        from memfabric.types import Outcome
        assert outcome_for(0, tr["error"]) is Outcome.fixable


class TestDispatcherIntegration:
    @pytest.mark.asyncio
    async def test_remote_backend_runs_sT_not_privileged(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        disp = _dispatcher("remote", calls)
        # A privileged default nmap (no scan flag) on the remote backend.
        await disp.dispatch(_nmap_task(["-sV", "-T4", "-Pn", _HOST]), _context())
        assert len(calls) == 1
        tool, args = calls[0]
        assert tool == "nmap"
        assert "-sT" in args, f"remote backend must run -sT, got {args}"
        assert "-sS" not in args
        assert _scan_flags(args) == ["-sT"], "exactly one TCP scan mode"
        # The flags that actually resolve the EPERM on a root-but-no-NET_RAW
        # backend must reach the runner, not just -sT.
        assert "--unprivileged" in args, f"remote backend must run --unprivileged, got {args}"
        assert "-Pn" in args, f"remote backend must run -Pn, got {args}"

    @pytest.mark.asyncio
    async def test_remote_backend_never_sends_sS(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        disp = _dispatcher("remote", calls)
        await disp.dispatch(_nmap_task(["-sS", "-sV", _HOST]), _context())
        assert calls and "-sS" not in calls[0][1] and "-sT" in calls[0][1]

    @pytest.mark.asyncio
    async def test_local_backend_may_keep_privileged(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        disp = _dispatcher("local", calls)
        await disp.dispatch(_nmap_task(["-sV", "-T4", "-Pn", _HOST]), _context())
        assert calls and "-sT" not in calls[0][1]  # privileged default preserved

    @pytest.mark.asyncio
    async def test_remote_udp_is_unsupported_and_never_runs(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        disp = _dispatcher("remote", calls)
        result = await disp.dispatch(_nmap_task(["-sU", _HOST]), _context())
        assert calls == [], "unsupported UDP scan must never reach the runner"
        assert result.disposition == ExecutionDisposition.INVALID_TASK
        assert result.tool_result_dict.get("error_category") == "unsupported_capability"

    @pytest.mark.asyncio
    async def test_remote_os_detection_is_unsupported_and_never_runs(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        disp = _dispatcher("remote", calls)
        result = await disp.dispatch(_nmap_task(["-sV", "-O", _HOST]), _context())
        assert calls == [], "OS detection must never reach the runner on an unprivileged backend"
        assert result.disposition == ExecutionDisposition.INVALID_TASK
        assert result.tool_result_dict.get("error_category") == "unsupported_capability"

    @pytest.mark.asyncio
    async def test_remote_strips_injection_before_running(self) -> None:
        # (An out-of-scope extra IP is separately blocked by the policy gate's
        # no_attacking_infrastructure rule before this point — see
        # test_policy_advisor; here we prove nmap normalization itself strips
        # scripts/output paths and keeps a single authorized-target positional.)
        calls: list[tuple[str, list[str]]] = []
        disp = _dispatcher("remote", calls)
        await disp.dispatch(
            _nmap_task(["-sV", "--script", "vuln", "-oN", "/tmp/x", _HOST]),
            _context(),
        )
        assert calls
        _tool, args = calls[0]
        assert "--script" not in args and "vuln" not in args
        assert "-oN" not in args and "/tmp/x" not in args
        assert [a for a in args if not a.startswith("-")] == [_HOST]
        assert _scan_flags(args) == ["-sT"]

    @pytest.mark.asyncio
    async def test_diagnostics_fields_present(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        disp = _dispatcher("remote", calls)
        result = await disp.dispatch(_nmap_task(["-sV", _HOST]), _context())
        tr = result.tool_result_dict
        assert tr["nmap_transport"] == "tcp_connect"
        assert tr["backend_raw_socket_capability"] == "unprivileged"
        assert tr["nmap_normalized"] is True

    @pytest.mark.asyncio
    async def test_execution_diagnostic_surfaces_nmap_fields(self) -> None:
        from apex_host.execution.diagnostics import build_execution_diagnostic
        calls: list[tuple[str, list[str]]] = []
        disp = _dispatcher("remote", calls)
        result = await disp.dispatch(_nmap_task(["-sV", _HOST]), _context())
        diag = build_execution_diagnostic(result.tool_result_dict, phase="recon")
        assert diag["nmap_transport"] == "tcp_connect"
        assert diag["backend_raw_socket_capability"] == "unprivileged"


# ---------------------------------------------------------------------------
# Deterministic raw-socket repair in repair_agent (fake runner only)
# ---------------------------------------------------------------------------

from apex_host.capabilities.runtime_references import (  # noqa: E402
    RuntimeReferenceResolver,
    RuntimeReferenceStore,
)
from apex_host.orchestration.dependencies import OrchestrationDeps  # noqa: E402
from apex_host.orchestration.repair_node import make_repair_node  # noqa: E402
from apex_host.orchestration.stall import StallTracker  # noqa: E402
from apex_host.planners.global_planner import GlobalPlanner  # noqa: E402
from apex_host.runtime_registry import CapabilityRuntimeRegistry  # noqa: E402
from memfabric.api import MemoryAPI  # noqa: E402
from memfabric.config import Config  # noqa: E402
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore  # noqa: E402
from memfabric.stores.graph_networkx import NetworkXGraphStore  # noqa: E402
from memfabric.stores.kv_memory import InMemoryKVStore  # noqa: E402
from memfabric.stores.lexical_bm25 import BM25LexicalIndex  # noqa: E402
from memfabric.stores.vector_faiss import FaissVectorIndex  # noqa: E402


class _NoopRepairEngine:
    async def repair(self, **kwargs: Any) -> None:  # pragma: no cover - never called on the raw-socket path
        return None


def _make_deps(calls: list[tuple[str, list[str]]]) -> OrchestrationDeps:
    mf = Config()
    api = MemoryAPI(
        graph=NetworkXGraphStore(), episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(), vector=FaissVectorIndex(dim=mf.vector_dim),
        kv=InMemoryKVStore(), config=mf,
    )
    config = ApexConfig(target=_HOST, dry_run=False, tool_backend="remote",
                        allowed_tools=["nmap"])

    async def _fake_run(cmd: Any, cfg: Any) -> ToolResult:
        calls.append((cmd.tool, list(cmd.args)))
        return ToolResult(command=cmd, stdout="", stderr="", returncode=0,
                          duration_seconds=0.0, dry_run=False, backend="remote")

    dispatcher = TaskDispatcher(
        advisor=PolicyAdvisor(load_policy(config), config),
        task_registry=TaskRegistry(), config=config, run_command_fn=_fake_run,
    )
    registry = CapabilityRuntimeRegistry()
    store = RuntimeReferenceStore()
    return OrchestrationDeps(
        api=api, dispatcher=dispatcher, global_planner=GlobalPlanner(max_turns=5),
        phase_planners={}, repair_engine=_NoopRepairEngine(), config=config,  # type: ignore[arg-type]
        anchor_id=f"host:{_HOST}", stall_tracker=StallTracker(),
        capability_registry=registry, runtime_reference_store=store,
        runtime_reference_resolver=RuntimeReferenceResolver(store, registry),
    )


def _raw_socket_state(args: list[str]) -> dict[str, Any]:
    return {
        "run_id": "r1", "target": _HOST, "phase": "recon", "goal": "scan",
        "turn_count": 1, "repair_count": 0,
        "current_task": {
            "params": {"tool": "nmap", "args": args, "target": _HOST, "parser": "nmap"},
            "executor_domain": "recon",
        },
        "last_tool_result": {
            "task_id": "failed-1", "tool": "nmap", "args": args, "target": _HOST,
            "parser": "nmap", "returncode": 1, "error": None,
            "stderr": "Couldn't open a raw socket. Error: (1) Operation not permitted",
            "error_category": "raw_socket_permission_denied", "phase": "recon",
        },
    }


def _incomplete_state(args: list[str]) -> dict[str, Any]:
    return {
        "run_id": "r1", "target": _HOST, "phase": "recon", "goal": "scan",
        "turn_count": 1, "repair_count": 0,
        "current_task": {
            "params": {"tool": "nmap", "args": args, "target": _HOST, "parser": "nmap"},
            "executor_domain": "recon",
        },
        "last_tool_result": {
            "task_id": "failed-1", "tool": "nmap", "args": args, "target": _HOST,
            "parser": "nmap", "returncode": 0,
            "error": "nmap discovery incomplete: host timed out before finishing with 0 open ports found",
            "stdout": f"Skipping host {_HOST} due to host timeout\n",
            "error_category": "nmap_incomplete_host_timeout", "phase": "recon",
        },
    }


class TestDeterministicRepair:
    @pytest.mark.asyncio
    async def test_privileged_failure_repaired_to_sT_once(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        deps = _make_deps(calls)
        repair_agent = make_repair_node(deps)
        result = await repair_agent(_raw_socket_state(["-sV", "-T4", "-Pn", _HOST]))  # type: ignore[arg-type]
        # Exactly one repaired execution reached the fake runner, and it was -sT.
        assert len(calls) == 1
        _tool, args = calls[0]
        assert "-sT" in args and _scan_flags(args) == ["-sT"]
        # The repaired result is marked as a deterministic raw-socket repair.
        assert result["last_tool_result"]["repaired"] is True
        assert result["last_tool_result"]["repair_kind"] == "raw_socket_to_tcp_connect"
        assert result["repair_count"] == 1

    @pytest.mark.asyncio
    async def test_privileged_command_not_executed_verbatim(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        deps = _make_deps(calls)
        repair_agent = make_repair_node(deps)
        await repair_agent(_raw_socket_state(["-sS", "-sV", _HOST]))  # type: ignore[arg-type]
        # The original privileged (-sS) command is never sent to the runner.
        assert calls and "-sS" not in calls[0][1]

    @pytest.mark.asyncio
    async def test_sT_without_unprivileged_is_repaired_not_terminal(self) -> None:
        # A bare -sT -Pn that failed with EPERM is missing --unprivileged, so
        # the repair adds it and re-executes exactly once (not terminal).
        calls: list[tuple[str, list[str]]] = []
        deps = _make_deps(calls)
        repair_agent = make_repair_node(deps)
        result = await repair_agent(_raw_socket_state(["-sT", "-sV", "-Pn", _HOST]))  # type: ignore[arg-type]
        assert len(calls) == 1
        _tool, args = calls[0]
        assert "--unprivileged" in args and "-sT" in args
        # It was NOT recorded as a terminal failure.
        assert not any(
            d.get("disposition") == "raw_socket_terminal"
            for d in (result.get("duplicate_actions") or [])
        )

    @pytest.mark.asyncio
    async def test_already_unprivileged_failure_is_terminal(self) -> None:
        calls: list[tuple[str, list[str]]] = []
        deps = _make_deps(calls)
        repair_agent = make_repair_node(deps)
        # Already had --unprivileged -Pn -sT and still failed → terminal.
        result = await repair_agent(
            _raw_socket_state(["-sT", "--unprivileged", "-Pn", "-sV", _HOST])  # type: ignore[arg-type]
        )
        # No re-execution — the unprivileged flags were already present.
        assert calls == []
        entries = result.get("duplicate_actions") or []
        assert entries and entries[0]["disposition"] == "raw_socket_terminal"

    @pytest.mark.asyncio
    async def test_incomplete_scan_escalates_to_targeted_pV(self) -> None:
        # A timed-out top-ports discovery scan escalates to a DIFFERENT bounded
        # -p <common> -sV scan (executed once), so the planner does not
        # re-propose the identical scan and dedup-stall.
        calls: list[tuple[str, list[str]]] = []
        deps = _make_deps(calls)
        repair_agent = make_repair_node(deps)
        result = await repair_agent(_incomplete_state(
            ["-sT", "--unprivileged", "-Pn", "-T4", "--top-ports", "100",
             "--max-retries", "2", "--host-timeout", "80s", _HOST]
        ))  # type: ignore[arg-type]
        assert len(calls) == 1
        _tool, args = calls[0]
        assert "-sV" in args and "-p" in args and "--top-ports" not in args
        assert result["last_tool_result"]["repaired"] is True
        assert result["last_tool_result"]["repair_kind"] == "nmap_incomplete_escalation"

    @pytest.mark.asyncio
    async def test_targeted_scan_incomplete_is_terminal(self) -> None:
        # The targeted -p <common> -sV scan also timed out with nothing → no
        # smaller bounded scan → terminal (honest), never a bare stall.
        calls: list[tuple[str, list[str]]] = []
        deps = _make_deps(calls)
        repair_agent = make_repair_node(deps)
        result = await repair_agent(_incomplete_state(
            ["-sT", "--unprivileged", "-Pn", "-T4", "-p", "22,80", "-sV",
             "--host-timeout", "80s", _HOST]
        ))  # type: ignore[arg-type]
        assert calls == []  # no re-execution
        entries = result.get("duplicate_actions") or []
        assert entries and entries[0]["disposition"] == "nmap_incomplete_terminal"
