# test_recon.py
# Tests for ReconPlanner (two-phase nmap/nc logic) and ReconExecutor (parser dispatch, dry-run, statelessness).
from __future__ import annotations

from typing import Any

import pytest

from memfabric.ids import new_id, now
from memfabric.types import (
    AbandonSignal,
    EvidenceBundle,
    Goal,
    Node,
    Outcome,
    SubgraphView,
    TaskSpec,
)

from apex_host.config import ApexConfig
from apex_host.agents.recon_executor import ReconExecutor
from apex_host.planners.recon_planner import ReconPlanner, _MAX_BANNER_TASKS
from apex_host.tools.registry import ToolRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TARGET = "10.10.10.14"


def _make_goal(target: str = _TARGET) -> Goal:
    return Goal(
        id=new_id(),
        description=f"Recon {target}",
        phase="recon",
        anchor_node=f"host:{target}",
    )


def _empty_subgraph(target: str = _TARGET) -> SubgraphView:
    return SubgraphView(anchor=f"host:{target}", nodes=[], edges=[], depth=2)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="recon", entries=[], subgraph=None, tiers_queried=[])


def _service_subgraph(*services: dict[str, Any], target: str = _TARGET) -> SubgraphView:
    nodes = [
        Node(
            id=f"service:{target}:{svc['port']}/tcp",
            type="service",
            props=svc,
            confidence=0.9,
            source="nmap",
            first_seen=now(),
            last_seen=now(),
        )
        for svc in services
    ]
    return SubgraphView(anchor=f"host:{target}", nodes=nodes, edges=[], depth=2)


def _registry(*tools: str) -> ToolRegistry:
    return ToolRegistry(allowed_tools=list(tools))


# ---------------------------------------------------------------------------
# ReconPlanner — Phase 1: nmap when no services known
# ---------------------------------------------------------------------------

class TestReconPlannerNmapPhase:
    async def test_emits_nmap_when_no_services(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap"))
        result = await planner.plan(_make_goal(), _empty_subgraph(), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        tasks = list(result)
        assert len(tasks) == 1
        assert tasks[0].params["tool"] == "nmap"

    async def test_nmap_task_has_correct_args_including_target(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap"))
        result = await planner.plan(_make_goal(), _empty_subgraph(), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        task = list(result)[0]
        args = task.params["args"]
        assert _TARGET in args
        assert "-sV" in args
        assert "-T4" in args

    async def test_nmap_task_has_parser_nmap(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap"))
        result = await planner.plan(_make_goal(), _empty_subgraph(), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        assert list(result)[0].params["parser"] == "nmap"

    async def test_nmap_task_executor_domain_is_recon(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap"))
        result = await planner.plan(_make_goal(), _empty_subgraph(), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        assert list(result)[0].executor_domain == "recon"

    async def test_abandons_when_nmap_not_available(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("curl"))
        result = await planner.plan(_make_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, AbandonSignal)
        assert "nmap" in result.reason.lower()

    async def test_falls_back_to_nmap_when_no_nc_available(self) -> None:
        """Services exist but nc not in registry → fall back to nmap."""
        planner = ReconPlanner(_TARGET, _registry("nmap"))
        subgraph = _service_subgraph(
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        tasks = list(result)
        assert tasks[0].params["tool"] == "nmap"


# ---------------------------------------------------------------------------
# ReconPlanner — Phase 2: nc banner probes when services known
# ---------------------------------------------------------------------------

class TestReconPlannerBannerPhase:
    async def test_emits_nc_task_when_ssh_service_known(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap", "nc"))
        subgraph = _service_subgraph(
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        tasks = list(result)
        assert len(tasks) >= 1
        assert tasks[0].params["tool"] == "nc"

    async def test_nc_task_args_include_target_and_port(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap", "nc"))
        subgraph = _service_subgraph(
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        task = list(result)[0]
        assert _TARGET in task.params["args"]
        assert "22" in task.params["args"]

    async def test_nc_task_has_parser_banner(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap", "nc"))
        subgraph = _service_subgraph(
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        assert list(result)[0].params["parser"] == "banner"

    async def test_nc_task_port_in_params(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap", "nc"))
        subgraph = _service_subgraph(
            {"port": "21", "proto": "tcp", "service": "ftp", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        assert list(result)[0].params["port"] == "21"

    async def test_uses_netcat_when_nc_not_available(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap", "netcat"))
        subgraph = _service_subgraph(
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        assert list(result)[0].params["tool"] == "netcat"

    async def test_skips_udp_services(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap", "nc"))
        subgraph = _service_subgraph(
            {"port": "53", "proto": "udp", "service": "domain", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        # udp is not nc-probeable → falls back to nmap
        assert not isinstance(result, AbandonSignal)
        tasks = list(result)
        assert tasks[0].params["tool"] == "nmap"

    async def test_skips_services_outside_safe_set(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap", "nc"))
        subgraph = _service_subgraph(
            {"port": "445", "proto": "tcp", "service": "microsoft-ds", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        tasks = list(result)
        # SMB not in safe set, falls back to nmap
        assert tasks[0].params["tool"] == "nmap"

    async def test_caps_banner_tasks_at_max(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap", "nc"))
        subgraph = _service_subgraph(
            {"port": "21", "proto": "tcp", "service": "ftp", "state": "open"},
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
            {"port": "23", "proto": "tcp", "service": "telnet", "state": "open"},
            {"port": "25", "proto": "tcp", "service": "smtp", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        assert len(list(result)) <= _MAX_BANNER_TASKS

    async def test_no_duplicate_ports(self) -> None:
        planner = ReconPlanner(_TARGET, _registry("nmap", "nc"))
        subgraph = _service_subgraph(
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
            {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},  # dup
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        ports = [t.params["port"] for t in list(result)]
        assert len(ports) == len(set(ports))

    async def test_probes_by_port_number_when_service_name_unknown(self) -> None:
        """Port 6379 (Redis) without a service name should still be probed."""
        planner = ReconPlanner(_TARGET, _registry("nmap", "nc"))
        subgraph = _service_subgraph(
            {"port": "6379", "proto": "tcp", "service": "", "state": "open"},
        )
        result = await planner.plan(_make_goal(), subgraph, _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        tasks = list(result)
        assert tasks[0].params["tool"] == "nc"
        assert tasks[0].params["port"] == "6379"


# ---------------------------------------------------------------------------
# ReconExecutor — dry-run and parser dispatch
# ---------------------------------------------------------------------------

class TestReconExecutorDryRun:
    def _config(self, **kw: object) -> ApexConfig:
        defaults: dict[str, object] = {
            "target": _TARGET,
            "dry_run": True,
            "allowed_tools": ["nmap", "nc"],
        }
        defaults.update(kw)
        return ApexConfig(**defaults)  # type: ignore[arg-type]

    def _task(self, tool: str, args: list[str], parser: str, port: str = "") -> TaskSpec:
        return TaskSpec(
            id=new_id(),
            goal_id="goal-1",
            executor_domain="recon",
            params={
                "tool": tool,
                "args": args,
                "target": _TARGET,
                "parser": parser,
                "port": port,
            },
            phase="recon",
        )

    async def test_nmap_dry_run_returns_executor_result(self) -> None:
        executor = ReconExecutor(self._config())
        task = self._task("nmap", ["-sV", "-T4", _TARGET], "nmap")
        result = await executor.run(task, _empty_evidence())
        assert result.task_id == task.id
        assert result.episode.outcome in (Outcome.success, Outcome.fundamental, Outcome.script_error)

    async def test_nmap_dry_run_episode_is_success(self) -> None:
        executor = ReconExecutor(self._config())
        task = self._task("nmap", ["-sV", "-T4", _TARGET], "nmap")
        result = await executor.run(task, _empty_evidence())
        assert result.episode.outcome == Outcome.success
        assert result.episode.data.get("dry_run") is True

    async def test_nmap_dry_run_episode_agent_is_recon(self) -> None:
        executor = ReconExecutor(self._config())
        task = self._task("nmap", ["-sV", "-T4", _TARGET], "nmap")
        result = await executor.run(task, _empty_evidence())
        assert result.episode.agent == "recon"

    async def test_nc_dry_run_returns_executor_result(self) -> None:
        executor = ReconExecutor(self._config())
        task = self._task("nc", ["-nv", _TARGET, "22"], "banner", port="22")
        result = await executor.run(task, _empty_evidence())
        assert result.task_id == task.id
        assert result.episode.outcome == Outcome.success

    async def test_nc_dry_run_does_not_append_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """nc args are already complete; target must NOT be appended again."""
        import asyncio

        async def _fake_proc(*args: object, **kwargs: object) -> object:
            raise AssertionError("dry_run must not spawn a subprocess")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_proc)

        executor = ReconExecutor(self._config())
        task = self._task("nc", ["-nv", _TARGET, "22"], "banner", port="22")
        # Dry-run: no real subprocess → should not raise
        result = await executor.run(task, _empty_evidence())
        assert result.episode.outcome == Outcome.success

    async def test_safety_violation_returns_fundamental_outcome(self) -> None:
        """A disallowed tool raises ValueError → fundamental outcome, no crash."""
        config = self._config(allowed_tools=["nmap"])  # nc not allowed
        executor = ReconExecutor(config)
        task = self._task("nc", ["-nv", _TARGET, "22"], "banner", port="22")
        result = await executor.run(task, _empty_evidence())
        assert result.episode.outcome == Outcome.fundamental

    async def test_executor_is_stateless_across_calls(self) -> None:
        """Two successive calls must produce independent results."""
        executor = ReconExecutor(self._config())
        task1 = self._task("nmap", ["-sV", "-T4", _TARGET], "nmap")
        task2 = self._task("nc", ["-nv", _TARGET, "22"], "banner", port="22")
        r1 = await executor.run(task1, _empty_evidence())
        r2 = await executor.run(task2, _empty_evidence())
        assert r1.task_id != r2.task_id
        assert r1.episode.action != r2.episode.action

    async def test_unknown_tool_falls_back_to_command_parser(self) -> None:
        """An unknown tool with non-empty output → proposed_knowledge, no crash."""
        config = self._config(allowed_tools=["python3"])
        executor = ReconExecutor(config)
        task = self._task("python3", ["-c", "print('hello')"], "")
        result = await executor.run(task, _empty_evidence())
        assert result.episode.outcome == Outcome.success
        # dry-run output isn't real python3 output, but shouldn't crash
        assert result.task_id == task.id
