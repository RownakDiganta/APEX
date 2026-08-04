# test_nmap_two_pass_timeout.py
# Tests for the nmap per-execution timeout field (separate from --tool-service-timeout, validated <= it) and the two-pass recon scan: a fast bounded first discovery pass without -sV, then a smaller -sV follow-up on only the open ports. Fakes only — no real subprocess or network.
"""Unit + integration tests for the nmap execution-timeout field and the
two-pass (discovery → version) recon scan (§25.6).

Covers: `ApexConfig.nmap_execution_timeout_seconds` / `nmap_top_ports` parsing
and validation (rejected when the nmap timeout exceeds the tool-service HTTP
timeout); the deterministic recon planner's bounded first scan (omits `-sV`,
carries `--top-ports` / `--max-retries` / `--host-timeout`) and separate
version follow-up on only the discovered ports; the normalizer preserving the
new bounding value flags; and the dispatcher passing the larger nmap timeout so
a scan that would have timed out at the general 30s cap now completes. RFC 5737
documentation address; no real network or subprocess.
"""
from __future__ import annotations

import argparse
from typing import Any

import pytest

from apex_host.config import ApexConfig
from apex_host.eval.check_config import validate_combinations
from apex_host.tools import nmap_command as nc

_HOST = "192.0.2.10"


def _scan_flags(args: list[str]) -> list[str]:
    return [a for a in args if a in nc._SCAN_MODE_INTENT]


# ---------------------------------------------------------------------------
# Config field: parsing, defaults, and validation
# ---------------------------------------------------------------------------

class TestNmapTimeoutConfig:
    def test_defaults(self) -> None:
        cfg = ApexConfig(target=_HOST)
        assert cfg.nmap_execution_timeout_seconds == 90.0
        assert cfg.nmap_top_ports == 1000
        # Independent of the tool-service HTTP budget.
        assert cfg.tool_service_timeout_seconds == 120.0

    def test_cli_flags_parsed(self) -> None:
        args = argparse.Namespace(target=_HOST, nmap_timeout=150.0, nmap_top_ports=500)
        cfg = ApexConfig.from_cli_args(args)
        assert cfg.nmap_execution_timeout_seconds == 150.0
        assert cfg.nmap_top_ports == 500

    def test_absent_flags_fall_back_to_defaults(self) -> None:
        args = argparse.Namespace(target=_HOST)  # neither flag supplied
        cfg = ApexConfig.from_cli_args(args)
        assert cfg.nmap_execution_timeout_seconds == 90.0
        assert cfg.nmap_top_ports == 1000

    def test_valid_when_below_tool_service_timeout(self) -> None:
        cfg = ApexConfig(target=_HOST, nmap_execution_timeout_seconds=90.0,
                         tool_service_timeout_seconds=120.0)
        assert [p for p in validate_combinations(cfg) if "nmap" in p] == []

    def test_valid_when_equal_to_tool_service_timeout(self) -> None:
        cfg = ApexConfig(target=_HOST, nmap_execution_timeout_seconds=120.0,
                         tool_service_timeout_seconds=120.0)
        assert [p for p in validate_combinations(cfg) if "nmap_execution" in p] == []

    def test_rejected_when_exceeds_tool_service_timeout(self) -> None:
        cfg = ApexConfig(target=_HOST, nmap_execution_timeout_seconds=200.0,
                         tool_service_timeout_seconds=120.0)
        problems = [p for p in validate_combinations(cfg) if "nmap_execution" in p]
        assert problems and "must not exceed" in problems[0]

    def test_rejected_when_non_positive(self) -> None:
        cfg = ApexConfig(target=_HOST, nmap_execution_timeout_seconds=0.0)
        assert any("must be positive" in p for p in validate_combinations(cfg))

    def test_top_ports_range_validated(self) -> None:
        assert any("nmap_top_ports" in p for p in
                   validate_combinations(ApexConfig(target=_HOST, nmap_top_ports=0)))
        assert any("nmap_top_ports" in p for p in
                   validate_combinations(ApexConfig(target=_HOST, nmap_top_ports=70000)))
        assert [p for p in validate_combinations(ApexConfig(target=_HOST, nmap_top_ports=1000))
                if "nmap_top_ports" in p] == []


# ---------------------------------------------------------------------------
# Normalizer preserves the bounding value flags
# ---------------------------------------------------------------------------

class TestNormalizerPreservesBounds:
    def test_host_timeout_and_max_retries_preserved(self) -> None:
        r = nc.normalize_nmap_command(
            ["-sT", "-Pn", "-T4", "--top-ports", "1000", "--max-retries", "2",
             "--host-timeout", "80s", _HOST],
            _HOST, capability=nc.UNPRIVILEGED,
        )
        assert "--top-ports" in r.args and "1000" in r.args
        assert "--max-retries" in r.args and "2" in r.args
        assert "--host-timeout" in r.args and "80s" in r.args

    def test_malformed_host_timeout_value_dropped(self) -> None:
        r = nc.normalize_nmap_command(
            ["-sV", "--host-timeout", "$(x)", _HOST], _HOST, capability=nc.UNPRIVILEGED,
        )
        assert "$(x)" not in r.args and "--host-timeout" not in r.args

    def test_bounding_flags_in_fingerprint(self) -> None:
        # A scan bounded by --host-timeout is a distinct identity from one without.
        a = nc.canonical_fingerprint_args(["-sT", "-Pn", "--host-timeout", "80s", _HOST], _HOST)
        b = nc.canonical_fingerprint_args(["-sT", "-Pn", _HOST], _HOST)
        assert a != b


# ---------------------------------------------------------------------------
# Two-pass recon planner (deterministic)
# ---------------------------------------------------------------------------

from apex_host.planners.recon_planner import _ReconDeterministic  # noqa: E402
from apex_host.tools.registry import ToolRegistry  # noqa: E402
from memfabric.types import (  # noqa: E402
    EvidenceBundle,
    Goal,
    SubgraphView,
)


def _core(raw_capable: bool = False) -> _ReconDeterministic:
    cfg = ApexConfig(target=_HOST, allowed_tools=["nmap", "nc"])
    reg = ToolRegistry.from_config(cfg)
    return _ReconDeterministic(
        _HOST, reg, raw_socket_capable=raw_capable, top_ports=1000,
        execution_timeout_seconds=90.0,
    )


def _goal() -> Goal:
    return Goal(id="g", description="d", phase="recon", anchor_node=f"host:{_HOST}")


def _sg(nodes: list[Any]) -> SubgraphView:
    return SubgraphView(nodes=nodes, edges=[], anchor=f"host:{_HOST}", depth=2)


class _Node:
    def __init__(self, node_id: str, ntype: str, props: dict[str, Any]) -> None:
        self.id = node_id
        self.type = ntype
        self.props = props
        self.confidence = 0.9


def _service(port: str, version: str = "") -> _Node:
    return _Node(f"service:{_HOST}:{port}", "service",
                 {"port": port, "proto": "tcp", "service": "unknown",
                  "version": version, "state": "open", "ip": _HOST})


class TestTwoPassRecon:
    @pytest.mark.asyncio
    async def test_first_pass_is_discovery_without_sV(self) -> None:
        core = _core()
        tasks = await core.plan(_goal(), _sg([]), EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]))
        assert isinstance(tasks, list) and len(tasks) == 1
        args = tasks[0].params["args"]
        assert "-sV" not in args, f"first discovery pass must omit -sV, got {args}"
        assert "--top-ports" in args and "1000" in args
        assert "--max-retries" in args and "2" in args
        assert "--host-timeout" in args and args[args.index("--host-timeout") + 1] == "80s"
        assert _scan_flags(args) == ["-sT"]

    @pytest.mark.asyncio
    async def test_second_pass_version_on_open_ports_only(self) -> None:
        core = _core()
        tasks = await core.plan(
            _goal(), _sg([_service("22"), _service("80")]),
            EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]),
        )
        assert isinstance(tasks, list) and len(tasks) == 1
        args = tasks[0].params["args"]
        assert "-sV" in args, "version pass must run -sV"
        assert "--top-ports" not in args, "version pass targets explicit ports, not top-ports"
        assert "-p" in args and args[args.index("-p") + 1] == "22,80"
        assert "--host-timeout" in args

    @pytest.mark.asyncio
    async def test_no_second_version_scan_once_versions_present(self) -> None:
        core = _core()
        # A service that already has a version → no more version scans; move on.
        tasks = await core.plan(
            _goal(), _sg([_service("22", version="OpenSSH 8.2")]),
            EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]),
        )
        # Either banner probes or a fallback — but NOT another version scan of
        # the already-versioned service (would be a -p 22 -sV repeat).
        if isinstance(tasks, list) and tasks and tasks[0].params.get("tool") == "nmap":
            assert "-sV" not in tasks[0].params["args"] or "-p" not in tasks[0].params["args"]


# ---------------------------------------------------------------------------
# Dispatcher passes the larger nmap timeout — a slow scan now completes
# ---------------------------------------------------------------------------

from apex_host.execution.context import ExecutionContext  # noqa: E402
from apex_host.execution.dispatcher import TaskDispatcher  # noqa: E402
from apex_host.execution.registry import TaskRegistry  # noqa: E402
from apex_host.policy import PolicyAdvisor  # noqa: E402
from apex_host.policy.policy_loader import load_policy  # noqa: E402
from apex_host.types import ToolResult  # noqa: E402
from memfabric.ids import new_id  # noqa: E402
from memfabric.types import TaskSpec  # noqa: E402

# The (fake) wall-clock a full scan needs — larger than the general 30s cap,
# smaller than the nmap execution timeout. No real time elapses in the test.
_SIMULATED_SCAN_SECONDS = 45.0


def _nmap_task(args: list[str]) -> TaskSpec:
    return TaskSpec(
        id=new_id(), goal_id=new_id(), executor_domain="recon",
        params={"tool": "nmap", "args": args, "target": _HOST, "parser": "nmap"},
        subgraph_anchor=f"host:{_HOST}", phase="recon",
    )


def _context() -> ExecutionContext:
    class _Ev:
        entries: list[Any] = []
        subgraph: Any = None
        blocked_fields: list[Any] = []
    return ExecutionContext(
        run_id="run-nmap-timeout", phase="recon", turn_number=1, evidence_version=None,
        subgraph=None, evidence=_Ev(), dry_run=False,
    )


def _timeout_aware_dispatcher(
    nmap_timeout: float, recorded: list[float],
) -> TaskDispatcher:
    """A dispatcher whose fake runner models a subprocess timeout: an nmap
    scan needs _SIMULATED_SCAN_SECONDS to finish, so a timeout budget below
    that produces a timed-out result, and one at/above it completes."""
    config = ApexConfig(
        target=_HOST, dry_run=False, tool_backend="remote",
        allowed_tools=["nmap"], nmap_execution_timeout_seconds=nmap_timeout,
        tool_service_timeout_seconds=120.0,
    )

    async def _fake_run(cmd: Any, cfg: Any) -> ToolResult:
        recorded.append(float(cmd.timeout_seconds))
        if cmd.tool == "nmap" and cmd.timeout_seconds < _SIMULATED_SCAN_SECONDS:
            return ToolResult(
                command=cmd, stdout="", stderr="", returncode=1,
                duration_seconds=float(cmd.timeout_seconds), dry_run=False,
                backend="remote", timed_out=True,
                error=f"command timed out after {cmd.timeout_seconds}s",
            )
        return ToolResult(
            command=cmd,
            stdout=f"Nmap scan report for {_HOST}\n22/tcp open ssh\n",
            stderr="", returncode=0, duration_seconds=_SIMULATED_SCAN_SECONDS,
            dry_run=False, backend="remote",
        )

    return TaskDispatcher(
        advisor=PolicyAdvisor(load_policy(config), config),
        task_registry=TaskRegistry(), config=config, run_command_fn=_fake_run,
    )


class TestDispatcherNmapTimeout:
    @pytest.mark.asyncio
    async def test_nmap_gets_execution_timeout_not_general_cap(self) -> None:
        recorded: list[float] = []
        disp = _timeout_aware_dispatcher(90.0, recorded)
        await disp.dispatch(_nmap_task(["-sT", "-Pn", "-T4", "--top-ports", "1000", _HOST]), _context())
        # The runner saw the nmap execution timeout (90), NOT max_command_seconds (30).
        assert recorded == [90.0]

    @pytest.mark.asyncio
    async def test_slow_scan_completes_under_configured_bound(self) -> None:
        recorded: list[float] = []
        disp = _timeout_aware_dispatcher(90.0, recorded)
        result = await disp.dispatch(_nmap_task(["-sT", "-Pn", "-T4", "--top-ports", "1000", _HOST]), _context())
        tr = result.tool_result_dict
        assert tr["returncode"] == 0 and not tr.get("timed_out"), \
            "a 45s scan must complete under the 90s nmap timeout"
        assert not tr.get("error")

    @pytest.mark.asyncio
    async def test_same_scan_would_time_out_at_the_old_30s_cap(self) -> None:
        # Proves the field is what governs it: a 20s budget cuts the 45s scan off.
        recorded: list[float] = []
        disp = _timeout_aware_dispatcher(20.0, recorded)
        result = await disp.dispatch(_nmap_task(["-sT", "-Pn", "-T4", "--top-ports", "1000", _HOST]), _context())
        tr = result.tool_result_dict
        assert tr.get("timed_out") is True
        assert recorded == [20.0]
