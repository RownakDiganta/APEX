# test_access_validation.py
# Tests for bounded access-validation: CredentialPlanner capability routing, AccessParser EKG deltas, and TelnetExecutor dry-run safety.
"""Acceptance tests for the bounded access-validation workflow.

Acceptance criteria:
1. CredentialPlanner abandons without credentials (telnet cap present).
2. CredentialPlanner emits exactly one bounded task with explicit credentials.
3. AccessParser correctly classifies success/failure from session text.
4. TelnetExecutor dry-run does not open any network connection.
"""
from __future__ import annotations

import asyncio

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

from apex_host.agents.telnet_executor import TelnetExecutor
from apex_host.config import ApexConfig
from apex_host.parsers.access_parser import AccessParser
from apex_host.planners.capabilities import Capability
from apex_host.planners.credential_planner import CredentialPlanner
from apex_host.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TARGET = "10.10.10.14"
_ANCHOR = f"host:{_TARGET}"


def _subgraph(*nodes: Node) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=[], depth=2)


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=2)


def _telnet_service_node() -> Node:
    return Node(
        id=f"service:{_TARGET}:23/tcp",
        type="service",
        props={"port": "23", "proto": "tcp", "service": "telnet", "state": "open"},
        confidence=0.9,
        source="nmap",
        first_seen=now(),
        last_seen=now(),
    )


def _auth_flow_node() -> Node:
    return Node(
        id=f"auth_flow:{_TARGET}",
        type="auth_flow",
        props={"url": f"http://{_TARGET}/login", "hint": "login form"},
        confidence=0.8,
        source="browser",
        first_seen=now(),
        last_seen=now(),
    )


def _goal() -> Goal:
    return Goal(
        id=new_id(),
        description=f"validate access to {_TARGET}",
        phase="credential",
        anchor_node=_ANCHOR,
    )


def _evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _planner(
    *,
    usernames: list[str] | None = None,
    passwords: list[str] | None = None,
    curl_available: bool = False,
) -> CredentialPlanner:
    tools: list[str] = ["nmap"]
    if curl_available:
        tools.append("curl")
    registry = ToolRegistry(allowed_tools=tools)
    return CredentialPlanner(
        _TARGET, registry,
        username_candidates=usernames,
        password_candidates=passwords,
    )


# ---------------------------------------------------------------------------
# CredentialPlanner — abandon paths
# ---------------------------------------------------------------------------

class TestCredentialPlannerAbandon:
    async def test_abandons_telnet_cap_present_no_credentials(self) -> None:
        planner = _planner()  # no credentials
        subgraph = _subgraph(_telnet_service_node())
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)
        assert "credentials" in result.reason.lower() or "username" in result.reason.lower()

    async def test_abandons_no_capability_no_auth_flow_no_curl(self) -> None:
        planner = _planner(usernames=["root"], passwords=[""])
        result = await planner.plan(_goal(), _empty_subgraph(), _evidence())
        assert isinstance(result, AbandonSignal)

    async def test_abandons_no_capability_no_auth_flow_with_curl(self) -> None:
        planner = _planner(usernames=["root"], passwords=[""], curl_available=True)
        result = await planner.plan(_goal(), _empty_subgraph(), _evidence())
        assert isinstance(result, AbandonSignal)
        assert "auth_flow" in result.reason.lower()

    async def test_abandon_reason_is_informative(self) -> None:
        planner = _planner()
        subgraph = _subgraph(_telnet_service_node())
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)
        assert "--username" in result.reason or "credentials" in result.reason.lower()


# ---------------------------------------------------------------------------
# CredentialPlanner — telnet task emission
# ---------------------------------------------------------------------------

class TestCredentialPlannerTelnetTask:
    async def test_emits_telnet_task_with_credentials(self) -> None:
        planner = _planner(usernames=["root"], passwords=[""])
        subgraph = _subgraph(_telnet_service_node())
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert len(result) == 1
        task = result[0]
        assert isinstance(task, TaskSpec)
        assert task.params["tool"] == "telnet_access"

    async def test_telnet_task_parser_is_access(self) -> None:
        planner = _planner(usernames=["admin"], passwords=["pass"])
        subgraph = _subgraph(_telnet_service_node())
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert result[0].params["parser"] == "access"

    async def test_telnet_task_uses_first_credential_pair_only(self) -> None:
        planner = _planner(usernames=["root", "admin", "user"], passwords=["", "password", "123"])
        subgraph = _subgraph(_telnet_service_node())
        result = await planner.plan(_goal(), subgraph, _evidence())
        # Must emit exactly ONE task — no looping over all credential pairs
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0].params["username"] == "root"
        assert result[0].params["password"] == ""

    async def test_telnet_task_contains_target_and_port(self) -> None:
        planner = _planner(usernames=["root"], passwords=[""])
        subgraph = _subgraph(_telnet_service_node())
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        task = result[0]
        assert task.params["target"] == _TARGET
        assert task.params["port"] == "23"

    async def test_fallback_curl_when_auth_flow_exists(self) -> None:
        planner = _planner(curl_available=True)  # no credentials
        subgraph = _subgraph(_auth_flow_node())  # auth_flow but no telnet
        result = await planner.plan(_goal(), subgraph, _evidence())
        # No telnet cap, curl available, auth_flow exists → curl HEAD task
        assert isinstance(result, list)
        assert result[0].params["tool"] == "curl"


# ---------------------------------------------------------------------------
# AccessParser — EKG delta production
# ---------------------------------------------------------------------------

class TestAccessParser:
    _PARSER = AccessParser()

    def test_empty_input_returns_empty(self) -> None:
        obs = self._PARSER.parse_text("", target=_TARGET, username="root")
        assert obs.node_deltas == []
        assert obs.edge_deltas == []

    def test_whitespace_only_returns_empty(self) -> None:
        obs = self._PARSER.parse_text("   \n  ", target=_TARGET, username="root")
        assert obs.node_deltas == []

    def test_success_creates_credential_node(self) -> None:
        stdout = "Target login: root\r\nPassword:\r\nroot@target:~$ "
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="root")
        cred_nodes = [n for n in obs.node_deltas if n.type == "credential"]
        assert len(cred_nodes) == 1
        assert cred_nodes[0].props["username"] == "root"

    def test_success_credential_node_has_redacted_secret(self) -> None:
        stdout = f"login: root\r\nPassword:\r\nroot@host:~$ "
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="root")
        cred_nodes = [n for n in obs.node_deltas if n.type == "credential"]
        assert cred_nodes[0].props["secret_hint"] == "[redacted]"

    def test_success_creates_access_state_node(self) -> None:
        stdout = "login: root\r\nPassword:\r\nroot@host:~$ "
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="root")
        access_nodes = [n for n in obs.node_deltas if n.type == "access_state"]
        assert len(access_nodes) == 1

    def test_success_creates_grants_edge(self) -> None:
        stdout = "login: root\r\nPassword:\r\nroot@host:~$ "
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="root")
        grants_edges = [e for e in obs.edge_deltas if e.type == "grants"]
        assert len(grants_edges) == 1

    def test_grants_edge_connects_credential_to_access_state(self) -> None:
        stdout = "login: root\r\nPassword:\r\nroot@host:~$ "
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="root")
        cred_id = next(n.id for n in obs.node_deltas if n.type == "credential")
        access_id = next(n.id for n in obs.node_deltas if n.type == "access_state")
        edge = obs.edge_deltas[0]
        assert edge.from_id == cred_id
        assert edge.to_id == access_id

    def test_failure_creates_credential_node_only(self) -> None:
        stdout = "Login incorrect\r\nlogin: "
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="root")
        types = {n.type for n in obs.node_deltas}
        assert "credential" in types
        assert "access_state" not in types
        assert obs.edge_deltas == []

    def test_authentication_failed_is_failure(self) -> None:
        stdout = "Authentication failed."
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="admin")
        assert not any(n.type == "access_state" for n in obs.node_deltas)

    def test_access_denied_is_failure(self) -> None:
        stdout = "Access denied"
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="root")
        assert not any(n.type == "access_state" for n in obs.node_deltas)

    def test_shell_prompt_hash_is_success(self) -> None:
        stdout = "root@server:/root# "
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="root")
        assert any(n.type == "access_state" for n in obs.node_deltas)

    def test_dollar_prompt_is_success(self) -> None:
        stdout = "user@host:~$ "
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="user")
        assert any(n.type == "access_state" for n in obs.node_deltas)

    def test_dry_run_stdout_has_no_prompt_no_access_state(self) -> None:
        stdout = "[dry-run] would connect telnet 10.10.10.14:23 as 'root' — no network activity"
        obs = self._PARSER.parse_text(stdout, target=_TARGET, username="root")
        assert not any(n.type == "access_state" for n in obs.node_deltas)
        # credential node is still emitted since username was tried
        assert any(n.type == "credential" for n in obs.node_deltas)


# ---------------------------------------------------------------------------
# TelnetExecutor — dry-run safety
# ---------------------------------------------------------------------------

class TestTelnetExecutorDryRun:
    def _make_task(self) -> TaskSpec:
        return TaskSpec(
            id=new_id(),
            goal_id=new_id(),
            executor_domain="credential",
            params={
                "tool": "telnet_access",
                "target": _TARGET,
                "port": "23",
                "username": "root",
                "password": "",
                "parser": "access",
            },
            subgraph_anchor=_ANCHOR,
            phase="credential",
        )

    async def test_dry_run_returns_success_outcome(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        executor = TelnetExecutor(config)
        result = await executor.run(self._make_task(), _evidence())
        assert result.episode.outcome == Outcome.success

    async def test_dry_run_result_has_dry_run_flag(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        executor = TelnetExecutor(config)
        result = await executor.run(self._make_task(), _evidence())
        assert result.episode.data.get("dry_run") is True

    async def test_dry_run_stdout_describes_what_would_happen(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        executor = TelnetExecutor(config)
        result = await executor.run(self._make_task(), _evidence())
        stdout = str(result.episode.data.get("stdout", ""))
        assert "dry-run" in stdout.lower() or "would" in stdout.lower()

    async def test_dry_run_does_not_open_network_connection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Monkeypatch asyncio.open_connection to prove it is never called in dry_run mode."""
        async def _should_not_be_called(*args: object, **kwargs: object) -> object:
            raise AssertionError("asyncio.open_connection was called in dry_run mode")

        monkeypatch.setattr(asyncio, "open_connection", _should_not_be_called)

        config = ApexConfig(target=_TARGET, dry_run=True)
        executor = TelnetExecutor(config)
        result = await executor.run(self._make_task(), _evidence())
        # If we reach here, open_connection was NOT called — the assertion above
        # would have fired.
        assert result.episode.outcome == Outcome.success
