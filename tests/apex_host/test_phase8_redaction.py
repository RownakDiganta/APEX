# test_phase8_redaction.py
# Phase 8 acceptance tests: secret redaction, graph identity, parallel-edge, schema versioning.
"""Phase 8 acceptance tests.

Groups (naming convention: test_<GROUP>_<NN>_<description>):
  REDACT  — redaction module unit tests (10 tests)
  CANARY  — canary artifact scanning: no secret survives into EKG/episodic (5 tests)
  BOUND   — secret-data boundary invariants (8 tests)
  GRAPH_ID — canonical ID function tests (10 tests)
  URL     — URL normalization tests (12 tests)
  PAR     — parallel-edge consistency via get_edges_for_node (5 tests)
  DANGLE  — dangling-edge rejection (5 tests)
  SCHEMA  — EKG schema version tests (4 tests)
  ARCH    — architecture scans for P8 invariants (10 tests)
  INT     — integration tests (11 tests)

Total: 80 named tests.
"""
from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from typing import Any

import pytest

# --- memfabric ---
from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, EvidenceBundle, Node, TaskSpec

# --- apex_host ---
from apex_host.agents.telnet_executor import TelnetExecutor
from apex_host.config import ApexConfig
from apex_host.eval.export_graph import export_ekg
from apex_host.graph_ids import (
    EKG_SCHEMA_VERSION,
    access_state_id,
    auth_flow_id,
    credential_id,
    endpoint_id,
    exposes_edge_id,
    form_id,
    grants_edge_id,
    host_id,
    normalize_url,
    runs_edge_id,
    service_id,
    tech_id,
    tech_slug,
    tested_edge_id as _canon_tested_edge_id,  # 'tested_*' prefix triggers pytest collection
    token_id,
)
from apex_host.parsers.access_parser import AccessParser
from apex_host.parsers.nmap_parser import NmapParser
from apex_host.security.redaction import (
    REDACTED_PLACEHOLDER,
    SESSION_REDACTED_PLACEHOLDER,
    redact_dict,
    redact_session_text,
    redact_value,
)

# ---------------------------------------------------------------------------
# Shared path constants
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).parent.parent.parent  # repo root
_APEX_ROOT = _ROOT / "apex_host"


def _all_apex_py() -> list[Path]:
    return list(_APEX_ROOT.rglob("*.py"))


def _all_parser_py() -> list[Path]:
    return list((_APEX_ROOT / "parsers").glob("*.py"))


# ---------------------------------------------------------------------------
# Minimal MemoryAPI factory
# ---------------------------------------------------------------------------

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


def _node(nid: str, ntype: str = "host", props: dict[str, Any] | None = None) -> Node:
    ts = now()
    return Node(id=nid, type=ntype, props=props or {}, confidence=0.8, source="test",
                first_seen=ts, last_seen=ts)


def _edge(eid: str, from_id: str, to_id: str, etype: str = "exposes") -> Edge:
    ts = now()
    return Edge(id=eid, from_id=from_id, to_id=to_id, type=etype, props={},
                confidence=0.8, source="test", first_seen=ts, last_seen=ts)


def _evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _task(tool: str = "telnet_access", target: str = "10.0.0.1",
          username: str = "root", password: str = "", port: str = "23") -> TaskSpec:
    return TaskSpec(
        id=new_id(), goal_id=new_id(), executor_domain="credential", phase="credential",
        params={"tool": tool, "target": target, "port": port,
                "username": username, "password": password},
    )


# ===========================================================================
# REDACT — redaction module unit tests
# ===========================================================================

class TestRedact:
    def test_redact_01_placeholder_constants_defined(self) -> None:
        assert REDACTED_PLACEHOLDER == "[redacted]"
        assert SESSION_REDACTED_PLACEHOLDER == "[session_redacted]"

    def test_redact_02_session_text_replaces_password(self) -> None:
        result = redact_session_text("password: secret123\n$", passwords=["secret123"])
        assert "secret123" not in result
        assert REDACTED_PLACEHOLDER in result

    def test_redact_03_empty_password_list_returns_unchanged(self) -> None:
        text = "hello world"
        out = redact_session_text(text, passwords=[])
        assert out == text

    def test_redact_04_empty_string_password_skipped(self) -> None:
        result = redact_session_text("hello", passwords=["", "world"])
        assert result == "hello"  # "" would corrupt; only non-empty "world" replaces

    def test_redact_05_multiple_passwords_all_replaced(self) -> None:
        text = "user=root secret=toor"
        result = redact_session_text(text, passwords=["root", "toor"])
        assert "root" not in result
        assert "toor" not in result

    def test_redact_06_redact_value_handles_str(self) -> None:
        result = redact_value("pass=abc", passwords=["abc"])
        assert "abc" not in result

    def test_redact_07_redact_value_handles_list(self) -> None:
        result = redact_value(["secret", "ok"], passwords=["secret"])
        assert result == [REDACTED_PLACEHOLDER, "ok"]

    def test_redact_08_redact_value_handles_dict(self) -> None:
        d = {"k": "password=foo", "num": 42}
        result = redact_value(d, passwords=["foo"])
        assert "foo" not in result["k"]
        assert result["num"] == 42

    def test_redact_09_redact_dict_convenience_wrapper(self) -> None:
        d = {"a": "x=secret", "b": "clean"}
        result = redact_dict(d, passwords=["secret"])
        assert "secret" not in result["a"]
        assert result["b"] == "clean"

    def test_redact_10_redact_value_non_string_passthrough(self) -> None:
        for val in (42, 3.14, None, True, False):
            assert redact_value(val, passwords=["secret"]) is val or redact_value(val, passwords=["secret"]) == val


# ===========================================================================
# CANARY — canary artifact scanning
# ===========================================================================

_CANARY_PASSWORD = "CANARY_SECRET_XK3P9"


class TestCanary:
    def test_canary_01_access_parser_evidence_redacted(self) -> None:
        """Password must not appear in access_state props after parsing."""
        session = f"login: root\r\nPassword: {_CANARY_PASSWORD}\r\nWelcome!\r\n# "
        parser = AccessParser()
        obs = parser.parse_text(session, target="10.0.0.1", username="root",
                                passwords=[_CANARY_PASSWORD])
        for node in obs.node_deltas:
            for v in node.props.values():
                assert _CANARY_PASSWORD not in str(v), (
                    f"Canary password found in node {node.id} prop: {v!r}"
                )

    def test_canary_02_access_parser_secret_hint_not_password(self) -> None:
        """secret_hint must be REDACTED_PLACEHOLDER, not the real password."""
        parser = AccessParser()
        obs = parser.parse_text("login: root\r\nPassword: \r\n# ", target="10.0.0.1",
                                username="root", passwords=[_CANARY_PASSWORD])
        cred_nodes = [n for n in obs.node_deltas if n.type == "credential"]
        assert cred_nodes, "Expected at least one credential node"
        for cn in cred_nodes:
            assert cn.props.get("secret_hint") == REDACTED_PLACEHOLDER
            assert _CANARY_PASSWORD not in cn.props.get("secret_hint", "")

    def test_canary_03_telnet_executor_dry_run_no_canary(self) -> None:
        """Dry-run episode stdout must not contain the canary password."""
        config = ApexConfig(target="10.0.0.1", dry_run=True,
                            password_candidates=[_CANARY_PASSWORD])
        executor = TelnetExecutor(config)
        task = _task(password=_CANARY_PASSWORD)
        result = asyncio.run(executor.run(task, _evidence()))
        assert _CANARY_PASSWORD not in str(result.episode.data.get("stdout", ""))

    def test_canary_04_live_episode_uses_session_redacted(self) -> None:
        """Patch _attempt_login to return a canary-containing session — verify redaction."""
        config = ApexConfig(target="10.0.0.1", dry_run=False,
                            password_candidates=[_CANARY_PASSWORD])
        executor = TelnetExecutor(config)
        canary_session = f"login:\r\nPassword: {_CANARY_PASSWORD}\r\n# "

        async def _fake_attempt(target: str, port: int, username: str, password: str) -> str:
            return canary_session

        executor._attempt_login = _fake_attempt  # type: ignore[assignment]
        task = _task(password=_CANARY_PASSWORD)
        result = asyncio.run(executor.run(task, _evidence()))
        ep_data = result.episode.data
        assert ep_data["stdout"] == SESSION_REDACTED_PLACEHOLDER
        assert _CANARY_PASSWORD not in str(ep_data)

    def test_canary_05_redact_value_deep_dict_no_password(self) -> None:
        """Verify canary password removed from arbitrarily nested dicts."""
        nested: dict[str, Any] = {
            "a": {"b": {"c": f"token={_CANARY_PASSWORD}&other=ok"}},
            "list": [f"x={_CANARY_PASSWORD}"],
        }
        result = redact_value(nested, passwords=[_CANARY_PASSWORD])
        assert _CANARY_PASSWORD not in str(result)


# ===========================================================================
# BOUND — secret-data boundary invariants
# ===========================================================================

class TestBound:
    def test_bound_01_credential_node_secret_hint_is_redacted_placeholder(self) -> None:
        parser = AccessParser()
        obs = parser.parse_text("login:\r\n# ", target="10.0.0.1", username="root")
        cred = next((n for n in obs.node_deltas if n.type == "credential"), None)
        assert cred is not None
        assert cred.props.get("secret_hint") == REDACTED_PLACEHOLDER

    def test_bound_02_telnet_executor_dry_run_has_dry_run_flag(self) -> None:
        """Dry-run episode must have dry_run=True in data."""
        config = ApexConfig(target="10.0.0.1", dry_run=True)
        executor = TelnetExecutor(config)
        result = asyncio.run(executor.run(_task(), _evidence()))
        assert result.episode.data.get("dry_run") is True

    def test_bound_03_live_episode_stdout_is_session_redacted_constant(self) -> None:
        """Live-mode episode must use SESSION_REDACTED_PLACEHOLDER, not raw session."""
        config = ApexConfig(target="10.0.0.1", dry_run=False)
        executor = TelnetExecutor(config)

        async def _fake(t: str, p: int, u: str, pw: str) -> str:
            return "login:\r\n# "

        executor._attempt_login = _fake  # type: ignore[assignment]
        result = asyncio.run(executor.run(_task(), _evidence()))
        assert result.episode.data["stdout"] == SESSION_REDACTED_PLACEHOLDER

    def test_bound_04_live_episode_preserves_stdout_length(self) -> None:
        """stdout_length in live episode must equal the original session length."""
        config = ApexConfig(target="10.0.0.1", dry_run=False)
        executor = TelnetExecutor(config)
        session_text = "login:\r\nPassword: \r\n$ "

        async def _fake(t: str, p: int, u: str, pw: str) -> str:
            return session_text

        executor._attempt_login = _fake  # type: ignore[assignment]
        result = asyncio.run(executor.run(_task(), _evidence()))
        assert result.episode.data.get("stdout_length") == len(session_text)

    def test_bound_05_access_parser_empty_returns_empty_obs(self) -> None:
        parser = AccessParser()
        obs = parser.parse_text("", target="10.0.0.1", username="root")
        assert obs.node_deltas == []
        assert obs.edge_deltas == []

    def test_bound_06_access_parser_failure_no_access_state(self) -> None:
        """Login incorrect → only credential node, no access_state."""
        parser = AccessParser()
        obs = parser.parse_text("login incorrect", target="10.0.0.1", username="root")
        types = {n.type for n in obs.node_deltas}
        assert "credential" in types
        assert "access_state" not in types

    def test_bound_07_access_parser_success_has_access_state(self) -> None:
        """Shell prompt → credential + access_state + grants edge."""
        parser = AccessParser()
        obs = parser.parse_text("login:\r\n# ", target="10.0.0.1", username="root")
        types = {n.type for n in obs.node_deltas}
        assert "credential" in types
        assert "access_state" in types
        assert any(e.type == "grants" for e in obs.edge_deltas)

    def test_bound_08_access_parser_evidence_passes_through_redaction(self) -> None:
        """evidence field must not contain the supplied password."""
        pw = "hunter2"
        session = f"login: root\r\nPassword: {pw}\r\nWelcome!\r\n# "
        parser = AccessParser()
        obs = parser.parse_text(session, target="10.0.0.1", username="root", passwords=[pw])
        access_nodes = [n for n in obs.node_deltas if n.type == "access_state"]
        for an in access_nodes:
            assert pw not in an.props.get("evidence", "")


# ===========================================================================
# GRAPH_ID — canonical ID function tests
# ===========================================================================

class TestGraphId:
    def test_graph_id_01_host_id_prefix(self) -> None:
        assert host_id("10.0.0.1") == "host:10.0.0.1"

    def test_graph_id_02_service_id_canonical_form(self) -> None:
        assert service_id("10.0.0.1", "23", "tcp") == "service:10.0.0.1:23/tcp"
        assert service_id("10.0.0.1", 22, "tcp") == "service:10.0.0.1:22/tcp"

    def test_graph_id_03_tech_id_host_scoped(self) -> None:
        t1 = tech_id("10.0.0.1", "OpenSSH")
        t2 = tech_id("10.0.0.2", "OpenSSH")
        assert t1 != t2
        assert t1.startswith("tech:10.0.0.1:")

    def test_graph_id_04_tech_slug_normalizes(self) -> None:
        slug = tech_slug("OpenSSH 8.2p1")
        assert " " not in slug
        assert slug == slug.lower()

    def test_graph_id_05_credential_id(self) -> None:
        assert credential_id("10.0.0.1", "root") == "credential:10.0.0.1:root"

    def test_graph_id_06_access_state_id(self) -> None:
        assert access_state_id("10.0.0.1", "root") == "access_state:10.0.0.1:root"

    def test_graph_id_07_exposes_edge_id(self) -> None:
        hid = host_id("10.0.0.1")
        sid = service_id("10.0.0.1", "22", "tcp")
        eid = exposes_edge_id(hid, sid)
        assert eid.startswith("exposes:")
        assert hid in eid and sid in eid

    def test_graph_id_08_runs_edge_id(self) -> None:
        sid = service_id("10.0.0.1", "22", "tcp")
        tid = tech_id("10.0.0.1", "OpenSSH")
        eid = runs_edge_id(sid, tid)
        assert eid.startswith("runs:")

    def test_graph_id_09_grants_edge_id(self) -> None:
        cid = credential_id("10.0.0.1", "root")
        aid = access_state_id("10.0.0.1", "root")
        eid = grants_edge_id(cid, aid)
        assert eid.startswith("grants:")

    def test_graph_id_10_canon_tested_edge_id(self) -> None:
        sid = service_id("10.0.0.1", "23", "tcp")
        cid = credential_id("10.0.0.1", "root")
        assert _canon_tested_edge_id(sid, cid).startswith("tested:")


# ===========================================================================
# URL — URL normalization tests
# ===========================================================================

class TestUrl:
    def test_url_01_strips_default_port_80(self) -> None:
        assert endpoint_id("http://host:80/") == "endpoint:http://host/"

    def test_url_02_strips_default_port_443(self) -> None:
        assert endpoint_id("https://host:443/") == "endpoint:https://host/"

    def test_url_03_keeps_non_default_port(self) -> None:
        assert endpoint_id("http://host:8080/") == "endpoint:http://host:8080/"

    def test_url_04_lowercases_scheme(self) -> None:
        assert endpoint_id("HTTP://host/") == "endpoint:http://host/"

    def test_url_05_lowercases_host(self) -> None:
        assert endpoint_id("http://HOST/") == "endpoint:http://host/"

    def test_url_06_trailing_slash_stripped_on_path(self) -> None:
        assert endpoint_id("http://host/path/") == "endpoint:http://host/path"

    def test_url_07_root_slash_kept(self) -> None:
        assert endpoint_id("http://host/") == "endpoint:http://host/"

    def test_url_08_collapses_double_slashes_in_path(self) -> None:
        result = normalize_url("http://host/a//b")
        assert "//" not in result.replace("://", "XX")

    def test_url_09_same_canonical_id_for_equivalent_urls(self) -> None:
        a = endpoint_id("http://HOST:80/path/")
        b = endpoint_id("http://host/path")
        assert a == b

    def test_url_10_auth_flow_id_url_normalized(self) -> None:
        assert auth_flow_id("http://host:80/login") == "auth_flow:http://host/login"

    def test_url_11_form_id_url_normalized(self) -> None:
        assert form_id("http://host:80/", 0) == "form:http://host/:0"

    def test_url_12_token_id_url_normalized(self) -> None:
        assert token_id("http://host:80/", "csrf") == "token:http://host/:csrf"


# ===========================================================================
# PAR — parallel-edge consistency via get_edges_for_node
# ===========================================================================

class TestParallelEdge:
    @pytest.mark.asyncio
    async def test_par_01_two_edges_same_endpoints_different_ids_both_visible(self) -> None:
        store = NetworkXGraphStore()
        ts = now()
        await store.put_node(Node("A", "host", {}, 0.9, "t", ts, ts))
        await store.put_node(Node("B", "service", {}, 0.9, "t", ts, ts))
        e1 = Edge("e1", "A", "B", "exposes", {}, 0.8, "t", ts, ts)
        e2 = Edge("e2", "A", "B", "runs", {}, 0.8, "t", ts, ts)
        await store.put_edge(e1)
        await store.put_edge(e2)
        edges = await store.get_edges_for_node("A")
        ids = {e.id for e in edges}
        assert "e1" in ids, "First parallel edge must be visible"
        assert "e2" in ids, "Second parallel edge must be visible"

    @pytest.mark.asyncio
    async def test_par_02_get_edges_for_node_reads_edges_dict(self) -> None:
        store = NetworkXGraphStore()
        ts = now()
        await store.put_node(Node("X", "host", {}, 0.9, "t", ts, ts))
        await store.put_node(Node("Y", "service", {}, 0.9, "t", ts, ts))
        await store.put_node(Node("Z", "tech", {}, 0.9, "t", ts, ts))
        await store.put_edge(Edge("e1", "X", "Y", "exposes", {}, 0.8, "t", ts, ts))
        await store.put_edge(Edge("e2", "X", "Z", "runs", {}, 0.8, "t", ts, ts))
        edges = await store.get_edges_for_node("X")
        assert len(edges) == 2

    @pytest.mark.asyncio
    async def test_par_03_delete_one_parallel_edge_keeps_other(self) -> None:
        store = NetworkXGraphStore()
        ts = now()
        await store.put_node(Node("A", "host", {}, 0.9, "t", ts, ts))
        await store.put_node(Node("B", "service", {}, 0.9, "t", ts, ts))
        await store.put_edge(Edge("e1", "A", "B", "exposes", {}, 0.8, "t", ts, ts))
        await store.put_edge(Edge("e2", "A", "B", "runs", {}, 0.8, "t", ts, ts))
        await store.delete_edge("e1")
        edges = await store.get_edges_for_node("A")
        ids = {e.id for e in edges}
        assert "e1" not in ids
        assert "e2" in ids

    @pytest.mark.asyncio
    async def test_par_04_all_edges_consistent_with_get_edges_for_node(self) -> None:
        store = NetworkXGraphStore()
        ts = now()
        await store.put_node(Node("A", "host", {}, 0.9, "t", ts, ts))
        await store.put_node(Node("B", "service", {}, 0.9, "t", ts, ts))
        await store.put_edge(Edge("e1", "A", "B", "exposes", {}, 0.8, "t", ts, ts))
        await store.put_edge(Edge("e2", "A", "B", "runs", {}, 0.8, "t", ts, ts))
        all_e = {e.id for e in await store.all_edges()}
        node_e = {e.id for e in await store.get_edges_for_node("A")}
        assert all_e == node_e

    @pytest.mark.asyncio
    async def test_par_05_in_edges_also_returned(self) -> None:
        store = NetworkXGraphStore()
        ts = now()
        await store.put_node(Node("A", "host", {}, 0.9, "t", ts, ts))
        await store.put_node(Node("B", "service", {}, 0.9, "t", ts, ts))
        await store.put_edge(Edge("e1", "A", "B", "exposes", {}, 0.8, "t", ts, ts))
        edges_b = await store.get_edges_for_node("B")
        assert any(e.id == "e1" for e in edges_b)


# ===========================================================================
# DANGLE — dangling-edge rejection
# ===========================================================================

class TestDangle:
    @pytest.mark.asyncio
    async def test_dangle_01_put_edge_missing_from_node_raises(self) -> None:
        store = NetworkXGraphStore()
        ts = now()
        await store.put_node(Node("B", "service", {}, 0.9, "t", ts, ts))
        with pytest.raises(ValueError, match="from_id"):
            await store.put_edge(Edge("e1", "MISSING", "B", "exposes", {}, 0.8, "t", ts, ts))

    @pytest.mark.asyncio
    async def test_dangle_02_put_edge_missing_to_node_raises(self) -> None:
        store = NetworkXGraphStore()
        ts = now()
        await store.put_node(Node("A", "host", {}, 0.9, "t", ts, ts))
        with pytest.raises(ValueError, match="to_id"):
            await store.put_edge(Edge("e1", "A", "MISSING", "exposes", {}, 0.8, "t", ts, ts))

    @pytest.mark.asyncio
    async def test_dangle_03_put_edge_both_nodes_present_succeeds(self) -> None:
        store = NetworkXGraphStore()
        ts = now()
        await store.put_node(Node("A", "host", {}, 0.9, "t", ts, ts))
        await store.put_node(Node("B", "service", {}, 0.9, "t", ts, ts))
        eid = await store.put_edge(Edge("e1", "A", "B", "exposes", {}, 0.8, "t", ts, ts))
        assert eid == "e1"

    @pytest.mark.asyncio
    async def test_dangle_04_api_upsert_edge_missing_node_raises(self) -> None:
        api = _make_api()
        await api.upsert_node(_node("A"))
        with pytest.raises(ValueError):
            await api.upsert_edge(_edge("e1", "A", "B_MISSING"))

    @pytest.mark.asyncio
    async def test_dangle_05_api_apply_deltas_nodes_before_edges_succeeds(self) -> None:
        api = _make_api()
        await api.apply_deltas(nodes=[_node("A"), _node("B")], edges=[_edge("e1", "A", "B")])
        stored_e = await api._graph.get_edge("e1")
        assert stored_e is not None


# ===========================================================================
# SCHEMA — EKG schema version tests
# ===========================================================================

class TestSchema:
    def test_schema_01_ekg_schema_version_string(self) -> None:
        assert isinstance(EKG_SCHEMA_VERSION, str)
        assert len(EKG_SCHEMA_VERSION) >= 1

    def test_schema_02_schema_version_is_one(self) -> None:
        assert EKG_SCHEMA_VERSION == "1"

    @pytest.mark.asyncio
    async def test_schema_03_export_ekg_includes_schema_version(self) -> None:
        api = _make_api()
        ts = now()
        await api.upsert_node(Node("host:10.0.0.1", "host", {"ip": "10.0.0.1"}, 0.9, "t", ts, ts))
        result = await export_ekg(api, anchor="host:10.0.0.1", depth=1)
        assert "schema_version" in result
        assert result["schema_version"] == EKG_SCHEMA_VERSION

    @pytest.mark.asyncio
    async def test_schema_04_export_ekg_schema_version_is_string(self) -> None:
        api = _make_api()
        ts = now()
        await api.upsert_node(Node("host:10.0.0.1", "host", {}, 0.9, "t", ts, ts))
        result = await export_ekg(api, anchor="host:10.0.0.1", depth=1)
        assert isinstance(result["schema_version"], str)


# ===========================================================================
# ARCH — architecture scan tests
# ===========================================================================

class TestArch:
    def test_arch_01_redaction_module_is_sole_source_of_redacted_strings(self) -> None:
        """No apex_host source file (except redaction.py and this test) may contain
        the string '[redacted]' or '[session_redacted]' as a code string literal
        (docstrings are excluded from the scan)."""
        allowed = {"redaction.py", "test_phase8_redaction.py"}
        violations: list[str] = []
        for py in _all_apex_py():
            if py.name in allowed:
                continue
            try:
                src = py.read_text(encoding="utf-8")
                tree = ast.parse(src)
            except Exception:
                continue
            docstring_ids: set[int] = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.ClassDef, ast.Module)):
                    if (node.body and isinstance(node.body[0], ast.Expr)
                            and isinstance(node.body[0].value, ast.Constant)
                            and isinstance(node.body[0].value.value, str)):
                        docstring_ids.add(id(node.body[0].value))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if id(node) in docstring_ids:
                        continue
                    if "[redacted]" in node.value or "[session_redacted]" in node.value:
                        violations.append(f"{py.name}:{getattr(node, 'lineno', '?')}")
        assert not violations, (
            "Literal '[redacted]' code strings outside redaction.py: "
            + ", ".join(violations)
        )

    def test_arch_02_no_inline_host_id_fstrings_in_parsers(self) -> None:
        violations: list[str] = []
        for py in _all_parser_py():
            try:
                src = py.read_text(encoding="utf-8")
            except Exception:
                continue
            if 'f"host:' in src or "f'host:" in src:
                violations.append(py.name)
        assert not violations, f"Inline host: f-strings in parsers: {violations}"

    def test_arch_03_no_inline_credential_id_fstrings_in_parsers(self) -> None:
        for py in _all_parser_py():
            src = py.read_text(encoding="utf-8", errors="ignore")
            assert 'f"credential:' not in src and "f'credential:" not in src, (
                f"Inline credential: f-string in {py.name}"
            )

    def test_arch_04_no_inline_access_state_fstrings_in_parsers(self) -> None:
        for py in _all_parser_py():
            src = py.read_text(encoding="utf-8", errors="ignore")
            assert 'f"access_state:' not in src and "f'access_state:" not in src, (
                f"Inline access_state: f-string in {py.name}"
            )

    def test_arch_05_no_inline_tech_id_fstrings_in_parsers(self) -> None:
        for py in _all_parser_py():
            src = py.read_text(encoding="utf-8", errors="ignore")
            assert 'f"tech:' not in src and "f'tech:" not in src, (
                f"Inline tech: f-string in {py.name}"
            )

    def test_arch_06_graph_ids_exports_all_required_builders(self) -> None:
        """Every canonical ID builder must be importable from apex_host.graph_ids."""
        from apex_host import graph_ids as _gids  # noqa: PLC0415
        required = [
            "host_id", "service_id", "tech_id", "credential_id", "access_state_id",
            "endpoint_id", "auth_flow_id", "form_id", "token_id",
            "exposes_edge_id", "runs_edge_id", "grants_edge_id",
            "tested_edge_id", "contains_edge_id", "requires_edge_id",
            "EKG_SCHEMA_VERSION", "normalize_url",
        ]
        for name in required:
            assert hasattr(_gids, name), f"graph_ids missing {name}"

    def test_arch_07_security_package_exports_redaction_api(self) -> None:
        """apex_host.security must export redact_dict, redact_session_text, redact_value."""
        import apex_host.security as _sec  # noqa: PLC0415
        for attr in ("redact_dict", "redact_session_text", "redact_value"):
            assert hasattr(_sec, attr), f"apex_host.security missing {attr}"

    def test_arch_08_telnet_executor_imports_session_redacted_placeholder(self) -> None:
        src = (_APEX_ROOT / "agents" / "telnet_executor.py").read_text()
        assert "SESSION_REDACTED_PLACEHOLDER" in src
        assert "apex_host.security.redaction" in src

    def test_arch_09_access_parser_imports_redact_session_text(self) -> None:
        src = (_APEX_ROOT / "parsers" / "access_parser.py").read_text()
        assert "redact_session_text" in src
        assert "REDACTED_PLACEHOLDER" in src

    def test_arch_10_export_ekg_imports_ekg_schema_version(self) -> None:
        src = (_APEX_ROOT / "eval" / "export_graph.py").read_text()
        assert "EKG_SCHEMA_VERSION" in src
        assert "schema_version" in src


# ===========================================================================
# INT — integration tests
# ===========================================================================

_NMAP_OUTPUT = """\
Nmap scan report for 10.10.10.14
Host is up (0.012s latency).
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
"""


class TestInt:
    @pytest.mark.asyncio
    async def test_int_01_nmap_parser_creates_host_node(self) -> None:
        parser = NmapParser()
        obs = parser.parse_text(_NMAP_OUTPUT, target="10.10.10.14")
        host_nodes = [n for n in obs.node_deltas if n.type == "host"]
        assert len(host_nodes) == 1
        assert host_nodes[0].id == host_id("10.10.10.14")

    @pytest.mark.asyncio
    async def test_int_02_nmap_parser_creates_service_nodes(self) -> None:
        parser = NmapParser()
        obs = parser.parse_text(_NMAP_OUTPUT, target="10.10.10.14")
        service_nodes = [n for n in obs.node_deltas if n.type == "service"]
        assert len(service_nodes) == 2

    @pytest.mark.asyncio
    async def test_int_03_nmap_parser_service_ids_canonical(self) -> None:
        parser = NmapParser()
        obs = parser.parse_text(_NMAP_OUTPUT, target="10.10.10.14")
        svc_ids = {n.id for n in obs.node_deltas if n.type == "service"}
        assert service_id("10.10.10.14", "23", "tcp") in svc_ids
        assert service_id("10.10.10.14", "22", "tcp") in svc_ids

    @pytest.mark.asyncio
    async def test_int_04_nmap_parser_exposes_edges_canonical(self) -> None:
        parser = NmapParser()
        obs = parser.parse_text(_NMAP_OUTPUT, target="10.10.10.14")
        h_id = host_id("10.10.10.14")
        s_id = service_id("10.10.10.14", "23", "tcp")
        edge_ids = {e.id for e in obs.edge_deltas}
        assert exposes_edge_id(h_id, s_id) in edge_ids

    @pytest.mark.asyncio
    async def test_int_05_nmap_parser_tech_id_canonical(self) -> None:
        parser = NmapParser()
        obs = parser.parse_text(_NMAP_OUTPUT, target="10.10.10.14")
        tech_nodes = [n for n in obs.node_deltas if n.type == "tech"]
        assert any(n.id == tech_id("10.10.10.14", "OpenSSH") for n in tech_nodes)

    @pytest.mark.asyncio
    async def test_int_06_access_parser_credential_id_canonical(self) -> None:
        parser = AccessParser()
        obs = parser.parse_text("login:\r\n# ", target="10.10.10.14", username="root")
        cred = next((n for n in obs.node_deltas if n.type == "credential"), None)
        assert cred is not None
        assert cred.id == credential_id("10.10.10.14", "root")

    @pytest.mark.asyncio
    async def test_int_07_access_parser_access_state_id_canonical(self) -> None:
        parser = AccessParser()
        obs = parser.parse_text("login:\r\n# ", target="10.10.10.14", username="root")
        acc = next((n for n in obs.node_deltas if n.type == "access_state"), None)
        assert acc is not None
        assert acc.id == access_state_id("10.10.10.14", "root")

    @pytest.mark.asyncio
    async def test_int_08_access_parser_grants_edge_canonical(self) -> None:
        parser = AccessParser()
        obs = parser.parse_text("login:\r\n# ", target="10.10.10.14", username="root")
        cid = credential_id("10.10.10.14", "root")
        aid = access_state_id("10.10.10.14", "root")
        edge_ids = {e.id for e in obs.edge_deltas}
        assert grants_edge_id(cid, aid) in edge_ids

    @pytest.mark.asyncio
    async def test_int_09_full_ekg_pipeline_no_dangling_edges(self) -> None:
        """Verify that the full nmap+access parse→upsert cycle leaves no dangling edges."""
        api = _make_api()
        parser_n = NmapParser()
        obs_n = parser_n.parse_text(_NMAP_OUTPUT, target="10.10.10.14")
        await api.apply_deltas(nodes=obs_n.node_deltas, edges=obs_n.edge_deltas)

        parser_a = AccessParser()
        obs_a = parser_a.parse_text("login:\r\n# ", target="10.10.10.14", username="root")
        await api.apply_deltas(nodes=obs_a.node_deltas, edges=obs_a.edge_deltas)

        all_edges = await api._graph.all_edges()
        all_nodes = await api._graph.all_nodes()
        node_ids = {n.id for n in all_nodes}
        for edge in all_edges:
            assert edge.from_id in node_ids, f"Dangling from_id on edge {edge.id}"
            assert edge.to_id in node_ids, f"Dangling to_id on edge {edge.id}"

    @pytest.mark.asyncio
    async def test_int_10_ekg_export_has_schema_version(self) -> None:
        api = _make_api()
        ts = now()
        await api.upsert_node(Node("host:10.10.10.14", "host", {}, 0.9, "t", ts, ts))
        result = await export_ekg(api, anchor="host:10.10.10.14")
        assert result["schema_version"] == "1"

    @pytest.mark.asyncio
    async def test_int_11_url_normalization_deduplicates_endpoint_ids(self) -> None:
        """http://host:80/path/ and http://host/path must produce the same endpoint ID."""
        from apex_host.parsers.command_parser import CommandParser  # noqa: PLC0415
        from memfabric.types import RawObservation  # noqa: PLC0415
        parser = CommandParser()
        raw1 = RawObservation(
            raw="HTTP/1.1 200 OK\r\nServer: nginx/1.18\r\n",
            metadata={"source": "curl", "target": "http://10.0.0.1:80/"},
        )
        raw2 = RawObservation(
            raw="HTTP/1.1 200 OK\r\nServer: nginx/1.18\r\n",
            metadata={"source": "curl", "target": "http://10.0.0.1/"},
        )
        obs1 = parser.parse(raw1)
        obs2 = parser.parse(raw2)
        ids1 = {n.id for n in obs1.node_deltas if n.type == "endpoint"}
        ids2 = {n.id for n in obs2.node_deltas if n.type == "endpoint"}
        assert ids1 == ids2, "Equivalent URLs must produce the same endpoint IDs"
