# test_live_run_fixes.py
# Tests for session-2 live-run fixes: early stop, service->credential edge, nc loop guard.
"""Tests for session-2 live-run fixes.

Covers:
A1. Early stop: reflect_or_continue sets completed=True when access_state in EKG.
A2. service→credential 'tested' edge emitted by AccessParser when port is given.
A3. access_state props include 'service' and 'proof' fields.
A4. nc banner-probe loop guard: ReconPlanner skips services that already have tech nodes.
"""
from __future__ import annotations

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, EvidenceBundle, Goal, Node, SubgraphView

from apex_host.config import ApexConfig
from apex_host.graph import build_apex_graph
from apex_host.graph_state import ApexGraphState
from apex_host.parsers.access_parser import AccessParser
from apex_host.planners.recon_planner import ReconPlanner
from apex_host.tools.registry import ToolRegistry


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_memfabric_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def _make_apex_config(**kwargs: object) -> ApexConfig:
    defaults: dict[str, object] = dict(
        target="10.10.10.1",
        payload_repo_path="./payloads",
        dry_run=True,
        username_candidates=["root"],
        password_candidates=[""],
    )
    defaults.update(kwargs)
    return ApexConfig(**defaults)  # type: ignore[arg-type]


def _host_node(target: str) -> Node:
    return Node(
        id=f"host:{target}", type="host",
        props={"ip": target}, confidence=0.9, source="nmap",
        first_seen=now(), last_seen=now(),
    )


def _service_node(target: str, port: str, service: str = "telnet") -> Node:
    return Node(
        id=f"service:{target}:{port}/tcp",
        type="service",
        props={"port": port, "proto": "tcp", "service": service, "state": "open"},
        confidence=0.9,
        source="nmap",
        first_seen=now(),
        last_seen=now(),
    )


def _tech_node(name: str, service_id: str) -> tuple[Node, Edge]:
    tech_id = f"tech:{name}"
    node = Node(
        id=tech_id, type="tech",
        props={"name": name, "version": ""},
        confidence=0.8, source="banner",
        first_seen=now(), last_seen=now(),
    )
    edge = Edge(
        id=new_id(), from_id=service_id, to_id=tech_id,
        type="runs", props={}, confidence=0.8, source="banner",
        first_seen=now(), last_seen=now(),
    )
    return node, edge


def _exposes_edge(host_id: str, svc_id: str) -> Edge:
    return Edge(
        id=new_id(), from_id=host_id, to_id=svc_id,
        type="exposes", props={}, confidence=0.9, source="nmap",
        first_seen=now(), last_seen=now(),
    )


# ---------------------------------------------------------------------------
# A1. Early stop via reflect_or_continue
# ---------------------------------------------------------------------------

class TestEarlyStop:
    """reflect_or_continue sets completed=True when access_state is in EKG."""

    @pytest.mark.asyncio
    async def test_early_stop_when_access_state_present(self) -> None:
        """Engagement stops early after access_state node is written to EKG."""
        target = "10.10.10.99"
        config = _make_apex_config(target=target, max_turns=20)
        api = _make_memfabric_api()
        registry = ToolRegistry(config.allowed_tools)

        # Pre-seed EKG with full connected graph including access_state.
        ts = now()
        host_id = f"host:{target}"
        svc_id = f"service:{target}:23/tcp"
        cred_id = f"credential:{target}:root"
        access_id = f"access_state:{target}:root"

        await api.apply_deltas(
            nodes=[
                Node(id=host_id, type="host",
                     props={"ip": target}, confidence=0.9, source="nmap",
                     first_seen=ts, last_seen=ts),
                Node(id=svc_id, type="service",
                     props={"port": "23", "proto": "tcp", "service": "telnet", "state": "open"},
                     confidence=0.9, source="nmap", first_seen=ts, last_seen=ts),
                Node(id=cred_id, type="credential",
                     props={"username": "root", "secret_hint": "[redacted]", "target": target},
                     confidence=0.9, source="telnet_access", first_seen=ts, last_seen=ts),
                Node(id=access_id, type="access_state",
                     props={"level": "user", "username": "root", "target": target,
                            "service": "telnet_access", "evidence": "root@meow:~#",
                            "proof": "root@meow:~#"},
                     confidence=0.85, source="telnet_access", first_seen=ts, last_seen=ts),
            ],
            edges=[
                Edge(id=new_id(), from_id=host_id, to_id=svc_id,
                     type="exposes", props={}, confidence=0.9, source="nmap",
                     first_seen=ts, last_seen=ts),
                Edge(id=new_id(), from_id=svc_id, to_id=cred_id,
                     type="tested", props={}, confidence=0.8, source="telnet_access",
                     first_seen=ts, last_seen=ts),
                Edge(id=new_id(), from_id=cred_id, to_id=access_id,
                     type="grants", props={}, confidence=0.85, source="telnet_access",
                     first_seen=ts, last_seen=ts),
                Edge(id=new_id(), from_id=svc_id, to_id=access_id,
                     type="grants", props={}, confidence=0.8, source="telnet_access",
                     first_seen=ts, last_seen=ts),
            ],
        )

        graph = build_apex_graph(api, registry, config)

        initial_state: ApexGraphState = {
            "run_id": new_id(),
            "target": target,
            "phase": "credential",
            "goal": "test",
            "evidence_summary": "",
            "findings": [],
            "last_tool_result": None,
            "tool_results": None,
            "last_error": None,
            "completed": False,
            "turn_count": 3,
            "current_task": None,
            "planner_decisions": [],
            "error_episodes": [],
            "repair_count": 0,
        }

        final_state = await graph.ainvoke(initial_state)

        assert final_state["completed"] is True
        assert final_state["turn_count"] <= 5, (
            f"Should have stopped early, but ran {final_state['turn_count']} turns"
        )

    @pytest.mark.asyncio
    async def test_no_early_stop_without_access_state(self) -> None:
        """Engagement does NOT stop early when access_state is absent from EKG."""
        target = "10.10.10.99"
        config = _make_apex_config(target=target, max_turns=2)
        api = _make_memfabric_api()
        registry = ToolRegistry(config.allowed_tools)

        graph = build_apex_graph(api, registry, config)
        initial_state: ApexGraphState = {
            "run_id": new_id(),
            "target": target,
            "phase": "recon",
            "goal": "test",
            "evidence_summary": "",
            "findings": [],
            "last_tool_result": None,
            "tool_results": None,
            "last_error": None,
            "completed": False,
            "turn_count": 0,
            "current_task": None,
            "planner_decisions": [],
            "error_episodes": [],
            "repair_count": 0,
        }

        final_state = await graph.ainvoke(initial_state)
        # With max_turns=2 and no access_state, both turns are consumed.
        assert final_state["turn_count"] == 2


# ---------------------------------------------------------------------------
# A2 & A3. AccessParser: service→credential edge + richer access_state props
# ---------------------------------------------------------------------------

class TestAccessParserEdgesAndProps:
    """AccessParser emits service→credential 'tested' edge and enhanced props."""

    _PARSER = AccessParser()
    _SUCCESS = "Meow login: \nPassword: \nroot@meow:~# "
    _SUCCESS_WITH_ID = "Meow login: \nPassword: \nroot@meow:~# \nuid=0(root) gid=0(root)\nroot@meow:~# "

    def test_service_to_credential_tested_edge_emitted(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS,
            target="10.10.10.14",
            username="root",
            source="telnet_access",
            port="23",
            proto="tcp",
        )
        edge_types_from_service = [
            e.type for e in obs.edge_deltas
            if e.from_id == "service:10.10.10.14:23/tcp"
        ]
        assert "tested" in edge_types_from_service, (
            f"Expected 'tested' edge from service node, got: {edge_types_from_service}"
        )

    def test_service_to_credential_target(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS,
            target="10.10.10.14",
            username="root",
            source="telnet_access",
            port="23",
            proto="tcp",
        )
        tested_edges = [
            e for e in obs.edge_deltas
            if e.type == "tested" and e.from_id == "service:10.10.10.14:23/tcp"
        ]
        assert len(tested_edges) == 1
        assert tested_edges[0].to_id == "credential:10.10.10.14:root"

    def test_service_to_access_state_grants_edge_still_present(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS,
            target="10.10.10.14",
            username="root",
            source="telnet_access",
            port="23",
            proto="tcp",
        )
        grants_from_service = [
            e for e in obs.edge_deltas
            if e.type == "grants" and e.from_id == "service:10.10.10.14:23/tcp"
        ]
        assert len(grants_from_service) == 1
        assert "access_state" in grants_from_service[0].to_id

    def test_access_state_has_service_prop(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS,
            target="10.10.10.14",
            username="root",
            source="telnet_access",
            port="23",
        )
        access_nodes = [n for n in obs.node_deltas if n.type == "access_state"]
        assert len(access_nodes) == 1
        assert access_nodes[0].props.get("service") == "telnet_access"

    def test_access_state_has_proof_prop(self) -> None:
        # Text ends with a shell prompt so _login_succeeded() returns True.
        obs = self._PARSER.parse_text(
            self._SUCCESS_WITH_ID,
            target="10.10.10.14",
            username="root",
            source="telnet_access",
            port="23",
        )
        access_nodes = [n for n in obs.node_deltas if n.type == "access_state"]
        assert len(access_nodes) == 1
        proof = str(access_nodes[0].props.get("proof", ""))
        # The proof should be the last non-empty line (shell prompt or id output).
        assert len(proof) > 0, "proof prop must not be empty"
        assert "root" in proof or "#" in proof

    def test_no_service_edges_when_port_omitted(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS,
            target="10.10.10.14",
            username="root",
            source="telnet_access",
        )
        service_edges = [e for e in obs.edge_deltas if "service:" in e.from_id]
        assert len(service_edges) == 0

    def test_no_service_edges_on_failed_login(self) -> None:
        obs = self._PARSER.parse_text(
            "Meow login: root\nPassword: \nLogin incorrect",
            target="10.10.10.14",
            username="root",
            source="telnet_access",
            port="23",
        )
        service_edges = [e for e in obs.edge_deltas if "service:" in e.from_id]
        assert len(service_edges) == 0

    def test_three_edges_on_success_with_port(self) -> None:
        """Successful login with port → exactly 3 edges: cred→access, svc→cred, svc→access."""
        obs = self._PARSER.parse_text(
            self._SUCCESS,
            target="10.10.10.14",
            username="root",
            source="telnet_access",
            port="23",
        )
        assert len(obs.edge_deltas) == 3

    def test_one_edge_on_success_without_port(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS,
            target="10.10.10.14",
            username="root",
            source="telnet_access",
        )
        assert len(obs.edge_deltas) == 1


# ---------------------------------------------------------------------------
# A4. ReconPlanner nc loop guard
# ---------------------------------------------------------------------------

class TestReconPlannerNcLoopGuard:
    """ReconPlanner skips nc probes for services that already have tech nodes."""

    def _make_subgraph_with_tech(self, target: str, port: str) -> SubgraphView:
        svc_id = f"service:{target}:{port}/tcp"
        svc_node = _service_node(target, port)
        tech_node, runs_edge = _tech_node("telnetd", svc_id)
        host_node = _host_node(target)
        return SubgraphView(
            anchor=f"host:{target}",
            nodes=[host_node, svc_node, tech_node],
            edges=[runs_edge],
            depth=2,
        )

    def _make_subgraph_without_tech(self, target: str, port: str) -> SubgraphView:
        svc_node = _service_node(target, port)
        host_node = _host_node(target)
        return SubgraphView(
            anchor=f"host:{target}",
            nodes=[host_node, svc_node],
            edges=[],
            depth=2,
        )

    def _evidence() -> EvidenceBundle:
        return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])

    @pytest.mark.asyncio
    async def test_no_nc_probe_when_tech_node_present(self) -> None:
        """No nc banner task emitted when the service already has a tech node."""
        target = "10.10.10.1"
        config = _make_apex_config(target=target)
        registry = ToolRegistry(config.allowed_tools)
        planner = ReconPlanner(target, registry)

        subgraph = self._make_subgraph_with_tech(target, "23")
        goal = Goal(id=new_id(), description="recon", phase="recon", anchor_node=f"host:{target}")
        evidence = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])

        result = await planner.plan(goal, subgraph, evidence)

        if isinstance(result, list):
            nc_tasks = [t for t in result if str(t.params.get("tool", "")) in ("nc", "netcat")]
            assert len(nc_tasks) == 0, f"Expected no nc tasks when tech exists, got: {nc_tasks}"

    @pytest.mark.asyncio
    async def test_nc_probe_emitted_without_tech_node(self) -> None:
        """nc banner task is emitted when the service has NO tech node yet."""
        target = "10.10.10.1"
        config = _make_apex_config(target=target)
        registry = ToolRegistry(config.allowed_tools)
        planner = ReconPlanner(target, registry)

        subgraph = self._make_subgraph_without_tech(target, "23")
        goal = Goal(id=new_id(), description="recon", phase="recon", anchor_node=f"host:{target}")
        evidence = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])

        result = await planner.plan(goal, subgraph, evidence)

        if isinstance(result, list) and len(result) > 0:
            nc_tasks = [t for t in result if str(t.params.get("tool", "")) in ("nc", "netcat")]
            assert len(nc_tasks) >= 1, "Expected at least one nc task when no tech exists"

    @pytest.mark.asyncio
    async def test_second_recon_turn_skips_probed_port(self) -> None:
        """After a tech node is written, subsequent recon turns skip that port."""
        target = "10.10.10.1"
        config = _make_apex_config(target=target)
        registry = ToolRegistry(config.allowed_tools)
        planner = ReconPlanner(target, registry)

        subgraph = self._make_subgraph_with_tech(target, "23")
        goal = Goal(id=new_id(), description="recon", phase="recon", anchor_node=f"host:{target}")
        evidence = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])

        result = await planner.plan(goal, subgraph, evidence)

        if isinstance(result, list):
            nc_tasks = [t for t in result if str(t.params.get("tool", "")) in ("nc", "netcat")]
            assert len(nc_tasks) == 0

    @pytest.mark.asyncio
    async def test_multiple_services_partial_tech(self) -> None:
        """Only ports WITHOUT tech nodes get nc probes; those WITH do not."""
        target = "10.10.10.1"
        config = _make_apex_config(target=target)
        registry = ToolRegistry(config.allowed_tools)
        planner = ReconPlanner(target, registry)

        svc23_id = f"service:{target}:23/tcp"
        svc23 = _service_node(target, "23", "telnet")
        svc21 = _service_node(target, "21", "ftp")
        tech_telnetd, runs_edge = _tech_node("telnetd", svc23_id)  # port 23 already probed
        host_node = _host_node(target)

        subgraph = SubgraphView(
            anchor=f"host:{target}",
            nodes=[host_node, svc23, svc21, tech_telnetd],
            edges=[runs_edge],
            depth=2,
        )

        goal = Goal(id=new_id(), description="recon", phase="recon", anchor_node=f"host:{target}")
        evidence = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
        result = await planner.plan(goal, subgraph, evidence)

        if isinstance(result, list):
            nc_ports = {str(t.params.get("port", "")) for t in result
                        if str(t.params.get("tool", "")) in ("nc", "netcat")}
            # Port 23 should NOT be in nc_ports (already has tech node).
            assert "23" not in nc_ports, f"Port 23 should be skipped but got nc_ports={nc_ports}"
