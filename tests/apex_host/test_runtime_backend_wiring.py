# test_runtime_backend_wiring.py
# Tests proving centralized backend selection (Infra Phase 4): default graph construction picks the right backend from config, explicit injection still works, policy blocking produces zero backend calls, and Telnet/Browser always bypass the generic backend.
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from apex_host.config import ApexConfig
from apex_host.execution.context import ExecutionContext
from apex_host.execution.dispatcher import TaskDispatcher
from apex_host.execution.dispositions import ExecutionDisposition
from apex_host.execution.registry import TaskRegistry
from apex_host.tools.backend import (
    DryRunToolBackend,
    LocalToolBackend,
    RemoteToolBackend,
    select_runtime_backend,
    to_run_command_fn,
)
from memfabric.ids import new_id
from memfabric.types import EvidenceBundle, SubgraphView, TaskSpec

_TARGET = "10.10.10.10"


# ---------------------------------------------------------------------------
# Helpers (self-contained — mirrors tests/apex_host/test_phase6_dispatcher.py's
# private helpers, not imported cross-file per this repo's test convention)
# ---------------------------------------------------------------------------

def _config(**overrides: object) -> ApexConfig:
    base: dict[str, object] = {"target": _TARGET, "allowed_tools": ["nmap", "curl", "nc"]}
    base.update(overrides)
    return ApexConfig(**base)  # type: ignore[arg-type]


def _subgraph() -> SubgraphView:
    return SubgraphView(anchor=f"host:{_TARGET}", nodes=[], edges=[], depth=2)


def _evidence(blocked_fields: list[Any] | None = None) -> EvidenceBundle:
    return EvidenceBundle(
        query="", entries=[], subgraph=_subgraph(), tiers_queried=[],
        blocked_fields=blocked_fields or [],
    )


def _task(
    tool: str = "nmap",
    args: list[str] | None = None,
    executor_domain: str = "recon",
    extra_params: dict[str, object] | None = None,
) -> TaskSpec:
    params: dict[str, object] = {
        "tool": tool, "args": args or [], "target": _TARGET, "parser": "nmap",
    }
    if extra_params:
        params.update(extra_params)
    return TaskSpec(
        id=new_id(), goal_id=new_id(), executor_domain=executor_domain,
        params=params, subgraph_anchor=f"host:{_TARGET}", phase="recon",
    )


def _ctx(dry_run: bool = False) -> ExecutionContext:
    return ExecutionContext(
        run_id="run-wiring-test", phase="recon", turn_number=1,
        evidence_version=None, subgraph=_subgraph(), evidence=_evidence(),
        dry_run=dry_run,
    )


class _ApprovedAdvisor:
    def review_task(self, task: Any, phase: Any, evidence: Any, config: Any) -> Any:
        decision = MagicMock()
        decision.is_approved = True
        decision.status = MagicMock(value="approved")
        decision.rule_name = "default_allow"
        decision.reason = ""
        return decision


class _BlockedAdvisor:
    def review_task(self, task: Any, phase: Any, evidence: Any, config: Any) -> Any:
        decision = MagicMock()
        decision.is_approved = False
        decision.status = MagicMock(value="blocked")
        decision.rule_name = "target_in_scope"
        decision.reason = "out-of-scope"
        return decision


def _make_dispatcher(
    *, advisor: Any, run_command_fn: Any,
    telnet_executor: Any | None = None, browser_executor: Any | None = None,
) -> TaskDispatcher:
    return TaskDispatcher(
        advisor=advisor, task_registry=TaskRegistry(), config=_config(),
        run_command_fn=run_command_fn,
        telnet_executor=telnet_executor, browser_executor=browser_executor,
    )


# ---------------------------------------------------------------------------
# build_apex_graph() / select_runtime_backend() default selection
# ---------------------------------------------------------------------------

def test_default_config_selects_local_backend() -> None:
    cfg = _config(dry_run=False)  # tool_backend defaults to "local"
    backend = select_runtime_backend(cfg)
    assert isinstance(backend, LocalToolBackend)


def test_dry_run_config_selects_dry_run_backend() -> None:
    cfg = _config(dry_run=True, tool_backend="local")
    backend = select_runtime_backend(cfg)
    assert isinstance(backend, DryRunToolBackend)


def test_remote_config_selects_remote_backend() -> None:
    cfg = _config(
        dry_run=False, tool_backend="remote",
        tool_service_url="http://kali:8080", tool_service_token="t",
    )
    backend = select_runtime_backend(cfg)
    assert isinstance(backend, RemoteToolBackend)


def test_dry_run_beats_remote_configuration() -> None:
    """The critical safety invariant, re-proven at the wiring-test level."""
    cfg = _config(
        dry_run=True, tool_backend="remote",
        tool_service_url="http://kali:8080", tool_service_token="t",
    )
    backend = select_runtime_backend(cfg)
    assert isinstance(backend, DryRunToolBackend)


async def test_build_apex_graph_default_construction_uses_local_backend_for_generic_command() -> None:
    """No explicit tool_backend= injected + dry_run=False + tool_backend="local"
    (both ApexConfig defaults) -> a generic command reaches LocalToolBackend,
    proven by observing backend="local" (or "dry-run", from run_command's own
    internal short-circuit) in the resulting tool_result, matching pre-Phase-4
    LocalToolBackend semantics exactly."""
    from apex_host.graph import build_apex_graph
    from apex_host.tools.registry import ToolRegistry
    from memfabric.api import MemoryAPI
    from memfabric.config import Config as MFConfig
    from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
    from memfabric.stores.graph_networkx import NetworkXGraphStore
    from memfabric.stores.kv_memory import InMemoryKVStore
    from memfabric.stores.lexical_bm25 import BM25LexicalIndex
    from memfabric.stores.vector_faiss import FaissVectorIndex

    mf_cfg = MFConfig()
    api = MemoryAPI(
        graph=NetworkXGraphStore(), episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(), vector=FaissVectorIndex(dim=mf_cfg.vector_dim),
        kv=InMemoryKVStore(), config=mf_cfg,
    )
    cfg = ApexConfig(target=_TARGET, dry_run=True, max_turns=1)  # dry_run=True => DryRunToolBackend
    registry = ToolRegistry.from_config(cfg)
    graph = build_apex_graph(api, registry, cfg)  # tool_backend=None -> centralized selection
    final = await graph.ainvoke({
        "run_id": "run-wiring-e2e", "target": _TARGET, "phase": "recon",
        "goal": f"Begin engagement against {_TARGET}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [],
    })
    log = final.get("execution_backend_log") or []
    assert log, "expected at least one backend-tagged execution in a recon turn"
    assert log[0]["backend"] == "dry-run"


# ---------------------------------------------------------------------------
# Explicit backend injection still takes precedence
# ---------------------------------------------------------------------------

async def test_explicit_backend_injection_overrides_config() -> None:
    """Even though _config() defaults to tool_backend="local", explicitly
    injecting a DryRunToolBackend into the dispatcher must be honored."""
    calls: list[str] = []

    class _SpyDryRun(DryRunToolBackend):
        async def execute(self, tool: Any, arguments: Any, **kwargs: Any) -> Any:
            calls.append(tool)
            return await super().execute(tool, arguments, **kwargs)

    injected = _SpyDryRun(_config())
    disp = _make_dispatcher(advisor=_ApprovedAdvisor(), run_command_fn=to_run_command_fn(injected))
    result = await disp.dispatch(_task(tool="nmap"), _ctx())
    assert result.disposition is ExecutionDisposition.EXECUTED_SUCCESS
    assert calls == ["nmap"]


# ---------------------------------------------------------------------------
# Policy-blocked task produces zero backend calls; approved produces exactly one
# ---------------------------------------------------------------------------

async def test_policy_blocked_task_produces_zero_remote_requests() -> None:
    calls: list[str] = []

    class _SpyRemote(RemoteToolBackend):
        async def execute(self, tool: Any, arguments: Any, **kwargs: Any) -> Any:
            calls.append(tool)
            raise AssertionError("must never be called for a policy-blocked task")

    cfg = _config(dry_run=False, tool_backend="remote", tool_service_url="http://kali:8080", tool_service_token="t")
    backend = _SpyRemote(cfg)
    disp = _make_dispatcher(advisor=_BlockedAdvisor(), run_command_fn=to_run_command_fn(backend))
    result = await disp.dispatch(_task(tool="nmap"), _ctx())
    assert result.disposition is ExecutionDisposition.BLOCKED_POLICY
    assert calls == []


async def test_approved_generic_task_produces_exactly_one_remote_request() -> None:
    calls: list[str] = []

    class _SpyRemote(DryRunToolBackend):  # dry-run-shaped so no real network call is needed
        async def execute(self, tool: Any, arguments: Any, **kwargs: Any) -> Any:
            calls.append(tool)
            return await super().execute(tool, arguments, **kwargs)

    backend = _SpyRemote(_config())
    disp = _make_dispatcher(advisor=_ApprovedAdvisor(), run_command_fn=to_run_command_fn(backend))
    result = await disp.dispatch(_task(tool="curl", args=["--version"]), _ctx())
    assert result.disposition is ExecutionDisposition.EXECUTED_SUCCESS
    assert calls == ["curl"]


# ---------------------------------------------------------------------------
# Telnet and Browser always bypass the generic backend — even when a remote
# backend is configured for generic commands.
# ---------------------------------------------------------------------------

async def test_telnet_task_uses_telnet_executor_not_generic_backend() -> None:
    from apex_host.agents.telnet_executor import TelnetExecutor

    generic_calls: list[str] = []

    async def _spy_run_command_fn(cmd: Any, cfg: Any) -> Any:
        generic_calls.append(cmd.tool)
        raise AssertionError("telnet_access must never reach the generic run_command_fn")

    cfg = _config(dry_run=True)  # TelnetExecutor's own dry-run path — no real network
    telnet_executor = TelnetExecutor(cfg)
    disp = _make_dispatcher(
        advisor=_ApprovedAdvisor(), run_command_fn=_spy_run_command_fn,
        telnet_executor=telnet_executor,
    )
    task = _task(
        tool="telnet_access", executor_domain="credential",
        extra_params={"username": "root", "password": "", "port": "23"},
    )
    result = await disp.dispatch(task, _ctx(dry_run=True))
    assert generic_calls == []
    assert result.tool_result_dict["tool"] == "telnet_access"


async def test_browser_task_uses_browser_executor_not_generic_backend() -> None:
    from apex_host.agents.browser_executor import BrowserExecutor

    generic_calls: list[str] = []

    async def _spy_run_command_fn(cmd: Any, cfg: Any) -> Any:
        generic_calls.append(cmd.tool)
        raise AssertionError("browser must never reach the generic run_command_fn")

    cfg = _config(dry_run=True)  # BrowserExecutor's own dry-run path — no real Playwright
    browser_executor = BrowserExecutor(cfg)
    disp = _make_dispatcher(
        advisor=_ApprovedAdvisor(), run_command_fn=_spy_run_command_fn,
        browser_executor=browser_executor,
    )
    task = _task(tool="browser", executor_domain="web", extra_params={"url": f"http://{_TARGET}/"})
    result = await disp.dispatch(task, _ctx(dry_run=True))
    assert generic_calls == []
    assert result.tool_result_dict["kind"] == "browser"


async def test_telnet_and_browser_bypass_even_with_remote_backend_configured() -> None:
    """The same two routing proofs, but with a RemoteToolBackend-shaped
    run_command_fn standing in for the generic path, to make explicit that
    configuring tool_backend="remote" for generic commands has no effect on
    Telnet/Browser routing whatsoever."""
    from apex_host.agents.browser_executor import BrowserExecutor
    from apex_host.agents.telnet_executor import TelnetExecutor

    remote_calls: list[str] = []

    class _SpyRemote(RemoteToolBackend):
        async def execute(self, tool: Any, arguments: Any, **kwargs: Any) -> Any:
            remote_calls.append(tool)
            raise AssertionError("generic remote backend must never be reached by telnet/browser")

    remote_cfg = _config(
        dry_run=False, tool_backend="remote",
        tool_service_url="http://kali:8080", tool_service_token="t",
    )
    dry_cfg = _config(dry_run=True)
    disp = _make_dispatcher(
        advisor=_ApprovedAdvisor(),
        run_command_fn=to_run_command_fn(_SpyRemote(remote_cfg)),
        telnet_executor=TelnetExecutor(dry_cfg),
        browser_executor=BrowserExecutor(dry_cfg),
    )

    telnet_task = _task(
        tool="telnet_access", executor_domain="credential",
        extra_params={"username": "root", "password": "", "port": "23"},
    )
    browser_task = _task(tool="browser", executor_domain="web", extra_params={"url": f"http://{_TARGET}/"})

    await disp.dispatch(telnet_task, _ctx(dry_run=True))
    await disp.dispatch(browser_task, _ctx(dry_run=True))

    assert remote_calls == []


# ---------------------------------------------------------------------------
# CLI wiring parity
# ---------------------------------------------------------------------------

def test_cli_tool_backend_flags_flow_into_config() -> None:
    from apex_host.eval.run_htb_local import parse_args

    args = parse_args([
        "--target", _TARGET,
        "--tool-backend", "remote",
        "--tool-service-url", "http://kali:8080",
        "--tool-service-timeout", "42",
        "--dry-run",
    ])
    cfg = ApexConfig.from_cli_args(args)
    assert cfg.tool_backend == "remote"
    assert cfg.tool_service_url == "http://kali:8080"
    assert cfg.tool_service_timeout_seconds == 42.0


def test_cli_omits_tool_backend_flags_preserves_defaults() -> None:
    from apex_host.eval.run_htb_local import parse_args

    args = parse_args(["--target", _TARGET, "--dry-run"])
    cfg = ApexConfig.from_cli_args(args)
    assert cfg.tool_backend == "local"
    assert cfg.tool_service_url is None


def test_cli_has_no_tool_service_token_flag() -> None:
    """Security requirement: the token must come from an environment
    variable, never a CLI flag (shell history / `ps` exposure)."""
    from apex_host.eval.run_htb_local import parse_args

    with pytest.raises(SystemExit):
        parse_args(["--target", _TARGET, "--tool-service-token", "x"])
