# test_access_parser_structured.py
# Tests for AccessParser.parse_structured() (Phase 12B SSH/FTP) and full-graph advancement after a successful SSH/FTP access_state.
"""Tests for the Phase 12B additions to apex_host/parsers/access_parser.py,
plus full compiled-graph tests proving the engagement actually advances
beyond the credential phase after a real (dry-run-synthetic) SSH/FTP
success — not merely that the parser produces the right node shape in
isolation.
"""
from __future__ import annotations

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node

from apex_host.config import ApexConfig
from apex_host.graph import build_apex_graph
from apex_host.graph_state import ApexGraphState
from apex_host.parsers.access_parser import AccessParser
from apex_host.tools.registry import ToolRegistry

_TARGET = "10.10.10.62"
_ANCHOR = f"host:{_TARGET}"
_PARSER = AccessParser()


# ---------------------------------------------------------------------------
# 1 / 2. Successful SSH / FTP creates access_state
# ---------------------------------------------------------------------------

class TestSuccessCreatesAccessState:
    def test_ssh_success_creates_access_state(self) -> None:
        obs = _PARSER.parse_structured(
            protocol="ssh", target=_TARGET, username="root",
            success=True, authenticated=True, port="22",
            evidence_text="uid=0(root) gid=0(root)", proof_type="ssh_id",
        )
        assert any(n.type == "access_state" for n in obs.node_deltas)
        assert any(n.type == "credential" for n in obs.node_deltas)

    def test_ftp_success_creates_access_state(self) -> None:
        obs = _PARSER.parse_structured(
            protocol="ftp", target=_TARGET, username="anonymous",
            success=True, authenticated=True, port="21",
            evidence_text='"/" is the current directory', proof_type="ftp_pwd",
        )
        assert any(n.type == "access_state" for n in obs.node_deltas)
        assert any(n.type == "credential" for n in obs.node_deltas)


# ---------------------------------------------------------------------------
# 3 / 4. Failed SSH / FTP does not create access_state
# ---------------------------------------------------------------------------

class TestFailureNeverCreatesAccessState:
    def test_ssh_auth_rejected_no_access_state(self) -> None:
        obs = _PARSER.parse_structured(
            protocol="ssh", target=_TARGET, username="root",
            success=False, authenticated=False, port="22",
        )
        assert not any(n.type == "access_state" for n in obs.node_deltas)

    def test_ftp_auth_rejected_no_access_state(self) -> None:
        obs = _PARSER.parse_structured(
            protocol="ftp", target=_TARGET, username="anonymous",
            success=False, authenticated=False, port="21",
        )
        assert not any(n.type == "access_state" for n in obs.node_deltas)

    def test_ssh_authenticated_but_command_failed_no_access_state(self) -> None:
        """A successful login followed by a failed/timed-out harmless
        command must not be treated as a full success — no false-positive."""
        obs = _PARSER.parse_structured(
            protocol="ssh", target=_TARGET, username="root",
            success=False, authenticated=True, port="22",
            evidence_text="",
        )
        assert not any(n.type == "access_state" for n in obs.node_deltas)
        # A credential node IS still produced — the login itself succeeded.
        assert any(n.type == "credential" for n in obs.node_deltas)

    def test_pre_auth_connection_failure_produces_no_nodes_at_all(self) -> None:
        """A connection-level failure (never reached authentication) mirrors
        Telnet's own pre-Phase-12B behavior: no node at all, not even a
        credential node — an open port or banner alone was never enough."""
        obs = _PARSER.parse_structured(
            protocol="ssh", target=_TARGET, username="root",
            success=False, authenticated=False, port="22",
        )
        assert obs.node_deltas == []
        assert obs.edge_deltas == []


# ---------------------------------------------------------------------------
# 5. Protocol metadata is correct
# ---------------------------------------------------------------------------

class TestProtocolMetadata:
    def test_ssh_credential_node_protocol_prop(self) -> None:
        obs = _PARSER.parse_structured(
            protocol="ssh", target=_TARGET, username="root",
            success=True, authenticated=True, port="22", evidence_text="uid=0(root)",
        )
        cred = next(n for n in obs.node_deltas if n.type == "credential")
        assert cred.props["protocol"] == "ssh"
        assert cred.props["target"] == _TARGET
        assert cred.props["username"] == "root"

    def test_ftp_access_state_service_prop(self) -> None:
        obs = _PARSER.parse_structured(
            protocol="ftp", target=_TARGET, username="anonymous",
            success=True, authenticated=True, port="21", evidence_text="/",
        )
        access = next(n for n in obs.node_deltas if n.type == "access_state")
        assert access.props["service"] == "ftp"
        assert access.props["level"] == "user"

    def test_proof_type_recorded(self) -> None:
        obs = _PARSER.parse_structured(
            protocol="ssh", target=_TARGET, username="root",
            success=True, authenticated=True, port="22",
            evidence_text="uid=0(root)", proof_type="ssh_id",
        )
        access = next(n for n in obs.node_deltas if n.type == "access_state")
        assert access.props["proof_type"] == "ssh_id"

    def test_ssh_and_ftp_ids_are_isolated_from_each_other_and_telnet(self) -> None:
        ssh_obs = _PARSER.parse_structured(
            protocol="ssh", target=_TARGET, username="root",
            success=True, authenticated=True, port="22", evidence_text="x",
        )
        ftp_obs = _PARSER.parse_structured(
            protocol="ftp", target=_TARGET, username="root",
            success=True, authenticated=True, port="21", evidence_text="x",
        )
        telnet_obs = _PARSER.parse_text(
            "login: root\r\nPassword:\r\nroot@host:~# ", target=_TARGET, username="root",
        )
        ssh_cred_id = next(n.id for n in ssh_obs.node_deltas if n.type == "credential")
        ftp_cred_id = next(n.id for n in ftp_obs.node_deltas if n.type == "credential")
        telnet_cred_id = next(n.id for n in telnet_obs.node_deltas if n.type == "credential")
        assert len({ssh_cred_id, ftp_cred_id, telnet_cred_id}) == 3


# ---------------------------------------------------------------------------
# 6. Secrets absent
# ---------------------------------------------------------------------------

class TestSecretsAbsent:
    def test_password_never_in_output_even_if_passed(self) -> None:
        obs = _PARSER.parse_structured(
            protocol="ssh", target=_TARGET, username="root",
            success=True, authenticated=True, port="22",
            evidence_text="uid=0(root) gid=0(root)",
            passwords=["s3cr3t-value"],
        )
        for node in obs.node_deltas:
            assert "s3cr3t-value" not in str(node.props)

    def test_secret_hint_is_redacted_placeholder(self) -> None:
        obs = _PARSER.parse_structured(
            protocol="ssh", target=_TARGET, username="root",
            success=True, authenticated=True, port="22", evidence_text="uid=0(root)",
        )
        cred = next(n for n in obs.node_deltas if n.type == "credential")
        assert cred.props["secret_hint"] == "[redacted]"


# ---------------------------------------------------------------------------
# 7 / 8. Full graph advances after SSH / FTP access_state
# ---------------------------------------------------------------------------

def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(), episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(), vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(), config=cfg,
    )


async def _seed_service(api: MemoryAPI, port: str, service: str) -> None:
    timestamp = now()
    await api.upsert_node(
        Node(id=_ANCHOR, type="host", props={"ip": _TARGET}, confidence=0.9,
             source="test-seed", first_seen=timestamp, last_seen=timestamp)
    )
    svc_id = f"service:{_TARGET}:{port}/tcp"
    await api.upsert_node(
        Node(id=svc_id, type="service",
             props={"port": port, "proto": "tcp", "service": service, "state": "open"},
             confidence=0.9, source="test-seed", first_seen=timestamp, last_seen=timestamp)
    )
    await api.upsert_edge(
        Edge(id=f"edge:{svc_id}", from_id=_ANCHOR, to_id=svc_id, type="exposes",
             props={}, confidence=0.9, source="test-seed", first_seen=timestamp, last_seen=timestamp)
    )


def _initial_state(run_id: str) -> ApexGraphState:
    return {
        "run_id": run_id, "target": _TARGET, "phase": "recon",
        "goal": f"Begin engagement against {_TARGET}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [],
    }


class TestFullGraphAdvancesAfterAccessState:
    async def test_ssh_success_advances_engagement(self) -> None:
        api = _make_api()
        await _seed_service(api, "22", "ssh")
        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=3,
            username_candidates=["root"], password_candidates=["hunter2"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_initial_state("run-ssh-advance"))

        assert final_state["completed"] is True
        subgraph = await api.get_subgraph(_ANCHOR, depth=3)
        assert any(n.type == "access_state" for n in subgraph.nodes)
        access_nodes = [n for n in subgraph.nodes if n.type == "access_state"]
        assert access_nodes[0].props.get("service") == "ssh"
        # Credential log recorded the attempt with no password anywhere.
        cred_log = final_state.get("credential_validation_log") or []
        assert any(e.get("protocol") == "ssh" and e.get("success") for e in cred_log)
        assert "hunter2" not in str(final_state)

    async def test_ftp_success_advances_engagement(self) -> None:
        api = _make_api()
        await _seed_service(api, "21", "ftp")
        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=3,
            username_candidates=["anonymous"], password_candidates=["guest@"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_initial_state("run-ftp-advance"))

        assert final_state["completed"] is True
        subgraph = await api.get_subgraph(_ANCHOR, depth=3)
        assert any(n.type == "access_state" for n in subgraph.nodes)
        access_nodes = [n for n in subgraph.nodes if n.type == "access_state"]
        assert access_nodes[0].props.get("service") == "ftp"
        cred_log = final_state.get("credential_validation_log") or []
        assert any(e.get("protocol") == "ftp" and e.get("success") for e in cred_log)
        assert "guest@" not in str(final_state)
