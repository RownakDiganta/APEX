# test_agent_factory.py
# Tests for the minimal dynamic-agent factory: registering types, building agents, the depth guard, and the per-agent allowlist gate.
from __future__ import annotations

from memfabric.types import EvidenceBundle, Outcome, TaskSpec

from apex_host.agents.factory import (
    AgentFactory,
    AgentRegistry,
    AgentSpec,
    spawn_task,
)
from apex_host.config import ApexConfig

_EMPTY_EVIDENCE = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _config() -> ApexConfig:
    # dry_run defaults to True; nmap/curl are in the default allowlist.
    return ApexConfig(target="10.10.10.1")


def _registry() -> AgentRegistry:
    reg = AgentRegistry()
    reg.register(
        AgentSpec(
            name="recon-specialist",
            allowed_tools=frozenset({"nmap", "nc"}),
            parser="nmap",
            max_depth=1,
            may_spawn=frozenset({"banner-specialist"}),
        )
    )
    reg.register(
        AgentSpec(
            name="banner-specialist",
            allowed_tools=frozenset({"nc"}),
            parser="banner",
            max_depth=2,
        )
    )
    return reg


def test_registry_registers_and_lists_types() -> None:
    reg = _registry()
    assert set(reg.names()) == {"recon-specialist", "banner-specialist"}
    assert reg.get("recon-specialist") is not None
    assert reg.get("nope") is None


def test_factory_creates_known_type() -> None:
    factory = AgentFactory(_registry(), _config())
    agent = factory.create("recon-specialist")
    assert agent is not None
    assert agent.domain == "recon-specialist"


def test_factory_rejects_unknown_type() -> None:
    factory = AgentFactory(_registry(), _config())
    assert factory.create("exploit-generator") is None


def test_factory_enforces_depth_ceiling() -> None:
    factory = AgentFactory(_registry(), _config())
    # recon-specialist has max_depth=1, so depth=2 must be refused.
    assert factory.create("recon-specialist", depth=1) is not None
    assert factory.create("recon-specialist", depth=2) is None


async def test_agent_runs_allowed_tool_in_dry_run() -> None:
    factory = AgentFactory(_registry(), _config())
    agent = factory.create("recon-specialist")
    assert agent is not None
    task = TaskSpec(
        id="t1",
        goal_id="g1",
        executor_domain="recon-specialist",
        params={"tool": "nmap", "args": ["-sV", "10.10.10.1"], "target": "10.10.10.1", "parser": "nmap"},
    )
    result = await agent.run(task, _EMPTY_EVIDENCE)
    assert result.episode.outcome == Outcome.success
    assert result.episode.data["dry_run"] is True


async def test_agent_rejects_tool_outside_its_spec() -> None:
    factory = AgentFactory(_registry(), _config())
    agent = factory.create("recon-specialist")
    assert agent is not None
    # curl is in the GLOBAL allowlist but not in this agent's spec.allowed_tools.
    task = TaskSpec(
        id="t2",
        goal_id="g1",
        executor_domain="recon-specialist",
        params={"tool": "curl", "args": ["-I", "http://10.10.10.1"], "target": "10.10.10.1"},
    )
    result = await agent.run(task, _EMPTY_EVIDENCE)
    assert result.episode.outcome == Outcome.fundamental
    assert "not permitted" in result.episode.data["error"]


def test_spawn_task_builds_child_and_honours_max_depth() -> None:
    child = spawn_task(
        "banner-specialist",
        tool="nc",
        args=["-nv", "10.10.10.1", "22"],
        target="10.10.10.1",
        goal_id="g1",
        parser="banner",
        parent_depth=0,
        max_depth=2,
    )
    assert child is not None
    assert child.executor_domain == "banner-specialist"
    assert child.params["depth"] == 1

    # A request that would exceed max_depth returns None (recursion guard).
    assert (
        spawn_task(
            "banner-specialist",
            tool="nc",
            args=[],
            target="10.10.10.1",
            goal_id="g1",
            parent_depth=2,
            max_depth=2,
        )
        is None
    )
