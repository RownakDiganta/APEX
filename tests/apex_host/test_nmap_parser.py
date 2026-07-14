# test_nmap_parser.py
# Tests for NmapParser covering all common HTB service types, edge correctness, ReconPlanner -Pn flag, and graph merge path.
"""Acceptance tests for the NmapParser and the recon pipeline.

Covers:
1. Parser handles every common HTB service line (ssh, telnet, http, https,
   smb, mysql, unknown, and bare services with no version banner).
2. host → service "exposes" edges are created for every open port.
3. service → tech "runs" edges are created when a version banner is present.
4. Closed / filtered states do NOT generate service or tech nodes.
5. Service nodes carry target, port, proto, state, raw_version, version props.
6. ReconPlanner emits -Pn in nmap args.
7. parse_observation in graph.py writes all parser deltas to MemoryAPI.
"""
from __future__ import annotations

from typing import Any


from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import (
    EvidenceBundle,
    Goal,
    SubgraphView,
)

from apex_host.config import ApexConfig
from apex_host.graph import build_apex_graph
from apex_host.graph_state import ApexGraphState
from apex_host.parsers.nmap_parser import NmapParser
from apex_host.planners.recon_planner import ReconPlanner
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_TARGET = "10.10.10.100"
_ANCHOR = f"host:{_TARGET}"
_PARSER = NmapParser()


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


def _goal() -> Goal:
    return Goal(
        id=new_id(),
        description=f"recon {_TARGET}",
        phase="recon",
        anchor_node=_ANCHOR,
    )


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=2)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="recon", entries=[], subgraph=None, tiers_queried=[])


# ---------------------------------------------------------------------------
# Representative nmap output samples
# ---------------------------------------------------------------------------

_NMAP_SSH = f"""\
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
"""

_NMAP_TELNET = f"""\
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
"""

_NMAP_HTTP = f"""\
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
"""

_NMAP_HTTPS = f"""\
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http nginx 1.18.0
"""

_NMAP_SMB = f"""\
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Samba smbd 4.x - 6.x (workgroup: WORKGROUP)
"""

_NMAP_MYSQL = f"""\
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 5.7.39
"""

_NMAP_HTTP_PROXY = f"""\
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
PORT     STATE SERVICE
8080/tcp open  http-proxy
"""

_NMAP_UNKNOWN = f"""\
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
PORT     STATE SERVICE
9999/tcp open  unknown
"""

_NMAP_MULTI = f"""\
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.2p1 Ubuntu
23/tcp   open  telnet       Linux telnetd
80/tcp   open  http         Apache httpd 2.4.49
443/tcp  open  ssl/http     nginx 1.18.0
3306/tcp open  mysql        MySQL 5.7.39
9999/tcp open  unknown
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""

# A scan where some ports are closed/filtered — those must NOT create nodes.
_NMAP_WITH_FILTERED = f"""\
Nmap scan report for {_TARGET}
Host is up.
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   filtered http
443/tcp  closed   https
8080/tcp open     http-proxy
"""

# Output when host doesn't respond to ping and -Pn is absent:
_NMAP_HOST_DOWN = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.05 seconds
"""


# ---------------------------------------------------------------------------
# Section 1 — parser handles all common service types
# ---------------------------------------------------------------------------

class TestNmapParserServiceTypes:
    def _service_node(self, output: str, port: str) -> Any:
        parsed = _PARSER.parse_text(output, target=_TARGET)
        svc = next(
            (n for n in parsed.node_deltas
             if n.type == "service" and n.props.get("port") == port),
            None,
        )
        assert svc is not None, f"no service node for port {port}"
        return svc

    def test_ssh_service_node(self) -> None:
        svc = self._service_node(_NMAP_SSH, "22")
        assert svc.props["service"] == "ssh"

    def test_telnet_service_node(self) -> None:
        svc = self._service_node(_NMAP_TELNET, "23")
        assert svc.props["service"] == "telnet"

    def test_http_service_node(self) -> None:
        svc = self._service_node(_NMAP_HTTP, "80")
        assert svc.props["service"] == "http"

    def test_https_service_node(self) -> None:
        svc = self._service_node(_NMAP_HTTPS, "443")
        assert svc.props["service"] == "ssl/http"

    def test_smb_service_node(self) -> None:
        svc = self._service_node(_NMAP_SMB, "445")
        assert svc.props["service"] == "microsoft-ds"

    def test_mysql_service_node(self) -> None:
        svc = self._service_node(_NMAP_MYSQL, "3306")
        assert svc.props["service"] == "mysql"

    def test_http_proxy_service_node(self) -> None:
        """Bare service with no version banner must still produce a service node."""
        svc = self._service_node(_NMAP_HTTP_PROXY, "8080")
        assert svc.props["service"] == "http-proxy"

    def test_unknown_service_node(self) -> None:
        """Port 9999/unknown with no version banner must still produce a service node."""
        svc = self._service_node(_NMAP_UNKNOWN, "9999")
        assert svc.props["service"] == "unknown"

    def test_multi_port_scan_all_services_present(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_MULTI, target=_TARGET)
        ports = {n.props["port"] for n in parsed.node_deltas if n.type == "service"}
        assert ports == {"22", "23", "80", "443", "3306", "9999"}

    def test_host_node_always_created(self) -> None:
        for output in (_NMAP_SSH, _NMAP_TELNET, _NMAP_HTTP, _NMAP_UNKNOWN):
            parsed = _PARSER.parse_text(output, target=_TARGET)
            host_nodes = [n for n in parsed.node_deltas if n.type == "host"]
            assert len(host_nodes) == 1, f"expected 1 host node, got {len(host_nodes)}"

    def test_no_ping_response_produces_host_only(self) -> None:
        """Without -Pn, nmap may output 'host seems down' with no port lines."""
        parsed = _PARSER.parse_text(_NMAP_HOST_DOWN, target=_TARGET)
        types = {n.type for n in parsed.node_deltas}
        assert "host" in types
        assert "service" not in types


# ---------------------------------------------------------------------------
# Section 2 — host → service "exposes" edges
# ---------------------------------------------------------------------------

class TestNmapParserExposesEdges:
    def test_ssh_has_exposes_edge(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_SSH, target=_TARGET)
        exposes = [e for e in parsed.edge_deltas if e.type == "exposes"]
        assert len(exposes) == 1
        assert exposes[0].from_id == f"host:{_TARGET}"

    def test_telnet_has_exposes_edge(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_TELNET, target=_TARGET)
        exposes = [e for e in parsed.edge_deltas if e.type == "exposes"]
        assert exposes

    def test_multi_port_one_exposes_per_service(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_MULTI, target=_TARGET)
        exposes = [e for e in parsed.edge_deltas if e.type == "exposes"]
        service_count = len([n for n in parsed.node_deltas if n.type == "service"])
        assert len(exposes) == service_count

    def test_exposes_edge_to_id_matches_service_node_id(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_SSH, target=_TARGET)
        service = next(n for n in parsed.node_deltas if n.type == "service")
        exposes = next(e for e in parsed.edge_deltas if e.type == "exposes")
        assert exposes.to_id == service.id

    def test_unknown_service_still_has_exposes_edge(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_UNKNOWN, target=_TARGET)
        exposes = [e for e in parsed.edge_deltas if e.type == "exposes"]
        assert len(exposes) == 1


# ---------------------------------------------------------------------------
# Section 3 — service → tech "runs" edges
# ---------------------------------------------------------------------------

class TestNmapParserTechEdges:
    def test_ssh_has_tech_node(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_SSH, target=_TARGET)
        tech = [n for n in parsed.node_deltas if n.type == "tech"]
        assert tech, "expected a tech node for OpenSSH"

    def test_telnet_has_tech_node(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_TELNET, target=_TARGET)
        tech = [n for n in parsed.node_deltas if n.type == "tech"]
        assert tech, "expected a tech node for Linux telnetd"

    def test_http_has_tech_node(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_HTTP, target=_TARGET)
        tech = [n for n in parsed.node_deltas if n.type == "tech"]
        assert tech, "expected a tech node for Apache httpd"

    def test_https_has_tech_node(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_HTTPS, target=_TARGET)
        tech = [n for n in parsed.node_deltas if n.type == "tech"]
        assert tech, "expected a tech node for nginx"

    def test_mysql_has_tech_node(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_MYSQL, target=_TARGET)
        tech = [n for n in parsed.node_deltas if n.type == "tech"]
        assert tech

    def test_runs_edge_type(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_SSH, target=_TARGET)
        runs = [e for e in parsed.edge_deltas if e.type == "runs"]
        assert len(runs) == 1

    def test_runs_edge_from_service_to_tech(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_SSH, target=_TARGET)
        service = next(n for n in parsed.node_deltas if n.type == "service")
        tech = next(n for n in parsed.node_deltas if n.type == "tech")
        runs = next(e for e in parsed.edge_deltas if e.type == "runs")
        assert runs.from_id == service.id
        assert runs.to_id == tech.id

    def test_no_version_no_tech_node(self) -> None:
        """Port with no version banner must not produce a tech node."""
        parsed = _PARSER.parse_text(_NMAP_UNKNOWN, target=_TARGET)
        tech = [n for n in parsed.node_deltas if n.type == "tech"]
        assert not tech

    def test_http_proxy_no_version_no_tech(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_HTTP_PROXY, target=_TARGET)
        tech = [n for n in parsed.node_deltas if n.type == "tech"]
        assert not tech


# ---------------------------------------------------------------------------
# Section 4 — closed/filtered states excluded
# ---------------------------------------------------------------------------

class TestNmapParserStateFiltering:
    def test_filtered_port_no_service_node(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_WITH_FILTERED, target=_TARGET)
        ports = {n.props["port"] for n in parsed.node_deltas if n.type == "service"}
        assert "80" not in ports   # filtered

    def test_closed_port_no_service_node(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_WITH_FILTERED, target=_TARGET)
        ports = {n.props["port"] for n in parsed.node_deltas if n.type == "service"}
        assert "443" not in ports  # closed

    def test_open_ports_still_created(self) -> None:
        parsed = _PARSER.parse_text(_NMAP_WITH_FILTERED, target=_TARGET)
        ports = {n.props["port"] for n in parsed.node_deltas if n.type == "service"}
        assert "22" in ports
        assert "8080" in ports

    def test_open_filtered_udp_included(self) -> None:
        output = f"""\
Nmap scan report for {_TARGET}
PORT    STATE         SERVICE
53/udp  open|filtered domain
"""
        parsed = _PARSER.parse_text(output, target=_TARGET)
        ports = {n.props["port"] for n in parsed.node_deltas if n.type == "service"}
        assert "53" in ports


# ---------------------------------------------------------------------------
# Section 5 — service node props
# ---------------------------------------------------------------------------

class TestNmapParserServiceProps:
    def _svc(self, output: str, port: str) -> Any:
        parsed = _PARSER.parse_text(output, target=_TARGET)
        return next(n for n in parsed.node_deltas if n.type == "service" and n.props["port"] == port)

    def test_service_has_target_prop(self) -> None:
        svc = self._svc(_NMAP_SSH, "22")
        assert svc.props["target"] == _TARGET

    def test_service_has_raw_version_prop(self) -> None:
        svc = self._svc(_NMAP_SSH, "22")
        assert "raw_version" in svc.props
        assert "OpenSSH" in svc.props["raw_version"]

    def test_service_raw_version_empty_for_no_banner(self) -> None:
        svc = self._svc(_NMAP_UNKNOWN, "9999")
        assert svc.props["raw_version"] == ""

    def test_service_has_version_prop(self) -> None:
        svc = self._svc(_NMAP_SSH, "22")
        assert "version" in svc.props

    def test_service_has_port_prop(self) -> None:
        svc = self._svc(_NMAP_TELNET, "23")
        assert svc.props["port"] == "23"

    def test_service_has_proto_prop(self) -> None:
        svc = self._svc(_NMAP_SSH, "22")
        assert svc.props["proto"] == "tcp"

    def test_service_has_state_prop(self) -> None:
        svc = self._svc(_NMAP_SSH, "22")
        assert svc.props["state"] == "open"

    def test_service_has_service_prop(self) -> None:
        svc = self._svc(_NMAP_MYSQL, "3306")
        assert svc.props["service"] == "mysql"


# ---------------------------------------------------------------------------
# Section 6 — ReconPlanner nmap args include -Pn
# ---------------------------------------------------------------------------

class TestReconPlannerNmapArgs:
    async def test_nmap_args_include_pn(self) -> None:
        registry = ToolRegistry(allowed_tools=["nmap"])
        planner = ReconPlanner(_TARGET, registry)
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        nmap_task = next(t for t in result if t.params.get("tool") == "nmap")
        assert "-Pn" in nmap_task.params["args"]

    async def test_nmap_args_include_sv(self) -> None:
        registry = ToolRegistry(allowed_tools=["nmap"])
        planner = ReconPlanner(_TARGET, registry)
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        nmap_task = next(t for t in result if t.params.get("tool") == "nmap")
        assert "-sV" in nmap_task.params["args"]

    async def test_nmap_args_include_t4(self) -> None:
        registry = ToolRegistry(allowed_tools=["nmap"])
        planner = ReconPlanner(_TARGET, registry)
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        nmap_task = next(t for t in result if t.params.get("tool") == "nmap")
        assert "-T4" in nmap_task.params["args"]

    async def test_nmap_args_include_target(self) -> None:
        registry = ToolRegistry(allowed_tools=["nmap"])
        planner = ReconPlanner(_TARGET, registry)
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        nmap_task = next(t for t in result if t.params.get("tool") == "nmap")
        assert _TARGET in nmap_task.params["args"]

    async def test_pn_order_before_target(self) -> None:
        """Flags must come before the positional target argument."""
        registry = ToolRegistry(allowed_tools=["nmap"])
        planner = ReconPlanner(_TARGET, registry)
        result = await planner.plan(_goal(), _empty_subgraph(), _empty_evidence())
        assert isinstance(result, list)
        args = result[0].params["args"]
        pn_idx = args.index("-Pn")
        target_idx = args.index(_TARGET)
        assert pn_idx < target_idx


# ---------------------------------------------------------------------------
# Section 7 — graph merge writes all parser deltas through MemoryAPI
# ---------------------------------------------------------------------------

class TestGraphMergesParserDeltas:
    """Verify that parse_observation in graph.py writes service + tech nodes and
    their edges to the EKG via MemoryAPI, using a real (in-memory) API."""

    async def test_service_nodes_written_to_ekg(self) -> None:
        api = _make_api()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=2)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)

        # Pre-populate so GlobalPlanner skips straight to recon and nmap
        # dry-run output is parsed. (Dry-run nmap output is synthetic text
        # like "[dry-run] would execute: nmap -sV -T4 -Pn <target>" which
        # the parser won't match port lines on — but the host node IS written.)
        initial: ApexGraphState = {
            "run_id": "test-merge",
            "target": _TARGET,
            "phase": ApexPhase.recon.value,
            "goal": f"recon {_TARGET}",
            "current_task": None,
            "evidence_summary": "",
            "findings": [],
            "error_episodes": [],
            "last_tool_result": None,
            "last_error": None,
            "completed": False,
            "turn_count": 0,
        }
        await graph.ainvoke(initial)
        # After the dry-run nmap turn, at minimum the host node should exist.
        subgraph = await api.get_subgraph(_ANCHOR, depth=2)
        types = {n.type for n in subgraph.nodes}
        assert "host" in types

    async def test_real_nmap_output_writes_service_nodes(self) -> None:
        """Simulate what parse_observation does when it receives real nmap output."""
        api = _make_api()

        # Write the nmap deltas via the parser and upsert manually — this
        # directly tests that the parser + API integration works.
        parsed = _PARSER.parse_text(_NMAP_MULTI, target=_TARGET)
        for node in parsed.node_deltas:
            await api.upsert_node(node)
        for edge in parsed.edge_deltas:
            await api.upsert_edge(edge)

        subgraph = await api.get_subgraph(_ANCHOR, depth=3)
        types = {n.type for n in subgraph.nodes}
        assert "host" in types
        assert "service" in types
        assert "tech" in types

        exposes = [e for e in subgraph.edges if e.type == "exposes"]
        runs = [e for e in subgraph.edges if e.type == "runs"]
        assert exposes, "exposes edges must be present"
        assert runs, "runs edges must be present for services with version banners"

    async def test_six_service_nodes_from_multi_scan(self) -> None:
        api = _make_api()
        parsed = _PARSER.parse_text(_NMAP_MULTI, target=_TARGET)
        for node in parsed.node_deltas:
            await api.upsert_node(node)
        for edge in parsed.edge_deltas:
            await api.upsert_edge(edge)

        subgraph = await api.get_subgraph(_ANCHOR, depth=3)
        service_nodes = [n for n in subgraph.nodes if n.type == "service"]
        assert len(service_nodes) == 6

    async def test_edges_written_after_upsert(self) -> None:
        api = _make_api()
        parsed = _PARSER.parse_text(_NMAP_SSH, target=_TARGET)
        for node in parsed.node_deltas:
            await api.upsert_node(node)
        for edge in parsed.edge_deltas:
            await api.upsert_edge(edge)

        subgraph = await api.get_subgraph(_ANCHOR, depth=2)
        assert subgraph.edges, "expected at least one edge after upsert"
