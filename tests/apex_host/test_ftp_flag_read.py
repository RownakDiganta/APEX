# test_ftp_flag_read.py
# §28.17 — a validated FTP access_state becomes an ftp_file_read access_capability
# the ObjectivePlanner acts on; the flag is RETR'd over the tool-service (Kali/VPN
# side), verified by verify_user_flag (SHA-256 only, raw never stored). Fakes only.
from __future__ import annotations

import ftplib
from typing import Any

import httpx
import pytest

from apex_host.capabilities.discovery import (
    CapabilityDiscoveryContext,
    CapabilityDiscoveryEngine,
)
from apex_host.capabilities.evidence import validate_evidence
from apex_host.config import ApexConfig
from apex_host.graph_ids import access_capability_id, access_state_id, host_id
from apex_host.orchestration.parsing_node import ftp_capability_evidence_for_result
from apex_host.parsers.capability_parser import CapabilityParser
from apex_host.planners.objective_planner import _ObjectiveDeterministic
from apex_host.runtime_registry import CapabilityRuntimeRegistry, FtpFileReadCapabilityAdapter
from apex_host.tools.registry import ToolRegistry
from apex_host.types import AccessCapabilityType
from apex_host.verification.user_flag import is_bounded_candidate_path, verify_user_flag
from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import EvidenceBundle, Goal, Node, SubgraphView

_TARGET = "10.129.44.139"
_TOKEN = "tok-not-a-real-secret"
_SECRET = "hunter2-not-a-real-secret"
_FLAG = "d41d8cd98f00b204e9800998ecf8427e"  # a well-formed, synthetic (never real) flag


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


async def _seed_validated_ftp_capability(
    api: MemoryAPI, target: str, *, principal: str = "anonymous", runtime_available: bool = True,
) -> str:
    ts = now()
    await api.upsert_node(Node(id=host_id(target), type="host", props={"ip": target},
                               confidence=0.9, source="s", first_seen=ts, last_seen=ts))
    asid = access_state_id(target, principal, protocol="ftp")
    await api.upsert_node(Node(id=asid, type="access_state",
                               props={"level": "user", "service": "ftp"},
                               confidence=0.9, source="s", first_seen=ts, last_seen=ts))
    parsed = CapabilityParser().derive_ftp_capability(target=target, username=principal, source_task_id="")
    await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
    cap_id = access_capability_id(target, AccessCapabilityType.ftp_file_read.value, principal)
    if runtime_available:
        await api.upsert_node(Node(id=cap_id, type="access_capability",
                                   props={"runtime_available": True}, confidence=0.5,
                                   source="test-seed", first_seen=now(), last_seen=now()))
    return cap_id


# ---------------------------------------------------------------------------
# Derivation: validated FTP access -> ftp_file_read access_capability
# ---------------------------------------------------------------------------
class TestFtpCapabilityDerivation:
    def test_ftp_file_read_type_exists(self) -> None:
        assert AccessCapabilityType.ftp_file_read.value == "ftp_file_read"

    def test_derive_ftp_capability_builds_node_and_edges(self) -> None:
        parsed = CapabilityParser().derive_ftp_capability(
            target=_TARGET, username="anonymous", source_task_id="t1",
        )
        caps = [n for n in parsed.node_deltas if n.type == "access_capability"]
        assert len(caps) == 1
        assert caps[0].props["capability_type"] == "ftp_file_read"
        assert caps[0].props["validated"] is True and caps[0].props["principal"] == "anonymous"
        # host --has_capability--> cap AND access_state --enables--> cap
        assert {e.type for e in parsed.edge_deltas} == {"has_capability", "enables"}

    def test_evidence_only_for_successful_ftp_access(self) -> None:
        assert ftp_capability_evidence_for_result({"tool": "ssh_access", "success": True}, target=_TARGET) is None
        assert ftp_capability_evidence_for_result({"tool": "ftp_access", "success": False}, target=_TARGET) is None
        ev = ftp_capability_evidence_for_result(
            {"tool": "ftp_access", "success": True, "username": "anonymous", "port": "21"}, target=_TARGET,
        )
        assert ev is not None and ev.evidence_type.value == "ftp_file_read_validated"
        assert validate_evidence(ev) is None  # passes the central gate (None == accepted)

    async def test_discovery_produces_ftp_capability_node(self) -> None:
        api = _make_api()
        ts = now()
        await api.upsert_node(Node(id=host_id(_TARGET), type="host", props={"ip": _TARGET},
                                   confidence=0.9, source="s", first_seen=ts, last_seen=ts))
        asid = access_state_id(_TARGET, "anonymous", protocol="ftp")
        await api.upsert_node(Node(id=asid, type="access_state", props={"service": "ftp"},
                                   confidence=0.9, source="s", first_seen=ts, last_seen=ts))
        ev = ftp_capability_evidence_for_result(
            {"tool": "ftp_access", "success": True, "username": "anonymous", "port": "21", "task_id": ""},
            target=_TARGET,
        )
        sub = await api.get_subgraph(host_id(_TARGET), depth=4)
        from apex_host.runtime_registry import CapabilityRuntimeRegistry as _Reg
        ctx = CapabilityDiscoveryContext(
            api=api, config=ApexConfig(target=_TARGET), capability_registry=_Reg(),
            subgraph=sub, target=_TARGET, attempt_runtime_registration=False,
        )
        await CapabilityDiscoveryEngine().discover([ev], context=ctx)
        sub2 = await api.get_subgraph(host_id(_TARGET), depth=5)
        caps = [n for n in sub2.nodes if n.type == "access_capability"
                and n.props.get("capability_type") == "ftp_file_read"]
        assert len(caps) == 1 and caps[0].props["validated"] is True


# ---------------------------------------------------------------------------
# Registration + ObjectivePlanner selection (planner UNCHANGED)
# ---------------------------------------------------------------------------
class TestRegistrationAndObjectivePlanner:
    def test_register_ftp_adapter(self) -> None:
        from apex_host.capabilities.runtime_resolution import register_capability_adapter
        from apex_host.planners.access_capabilities import access_capabilities_from_subgraph

        parsed = CapabilityParser().derive_ftp_capability(target=_TARGET, username="anonymous", source_task_id="")
        sub = SubgraphView(nodes=parsed.node_deltas, edges=parsed.edge_deltas,
                           anchor=host_id(_TARGET), depth=3)
        cap = access_capabilities_from_subgraph(sub)[0]
        reg = CapabilityRuntimeRegistry()
        config = ApexConfig(target=_TARGET, username_candidates=["anonymous"], password_candidates=[_SECRET])
        ok = register_capability_adapter(
            config=config, capability_registry=reg, subgraph=sub, target=_TARGET, cap=cap,
        )
        assert ok is True
        assert isinstance(reg.get(cap.capability_id), FtpFileReadCapabilityAdapter)

    async def test_objective_planner_emits_bounded_flag_read(self) -> None:
        api = _make_api()
        await _seed_validated_ftp_capability(api, _TARGET)
        sub = await api.get_subgraph(host_id(_TARGET), depth=6)
        core = _ObjectiveDeterministic(_TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)))
        goal = Goal(id="g", description="objective", phase="objective", anchor_node=host_id(_TARGET))
        result = await core.plan(goal, sub, EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[]))
        assert isinstance(result, list) and len(result) == 1
        t = result[0]
        assert t.params["tool"] == "user_flag_verify"
        assert isinstance(t.params["candidate_path"], str) and t.params["candidate_path"]
        assert t.params["capability_type"] == "ftp_file_read"


# ---------------------------------------------------------------------------
# Adapter: RETR the flag on the Kali/VPN side (tool-service), verify it.
# ---------------------------------------------------------------------------
class _LiveSock:
    def settimeout(self, v: float) -> None: ...
    def sendall(self, d: bytes) -> None: ...


class _ServerFakeFTP:
    def __init__(self) -> None:
        self.encoding = "utf-8"
        self.sock: _LiveSock | None = None
    def connect(self, host: str = "", port: int = 0, timeout: float = -1, source_address: object = None) -> str:
        self.sock = _LiveSock()
        return "220"
    def set_pasv(self, v: bool) -> None: ...
    def login(self, user: str = "", passwd: str = "", acct: str = "") -> str:
        return "230"
    def retrbinary(self, cmd: str, cb: Any, blocksize: int = 8192) -> str:
        assert cmd.startswith("RETR ")
        cb((_FLAG + "\n").encode())
        return "226"
    def quit(self) -> str:
        self.sock.sendall(b"Q")  # type: ignore[union-attr]
        return "221"
    def close(self) -> None:
        self.sock = None


def _wire_tool_service(monkeypatch: pytest.MonkeyPatch) -> None:
    from apex_tool_service.app import create_app
    from apex_tool_service.settings import ServiceSettings
    import apex_host.tools.remote_backend as rb

    monkeypatch.setattr(ftplib, "FTP", _ServerFakeFTP)
    app = create_app(ServiceSettings(token=_TOKEN, authorized_cidrs=("10.129.0.0/16",)))
    transport = httpx.ASGITransport(app=app)
    real = httpx.AsyncClient
    monkeypatch.setattr(rb.httpx, "AsyncClient", lambda *a, **k: real(transport=transport))


def _remote_config() -> ApexConfig:
    return ApexConfig(
        target=_TARGET, dry_run=False, tool_backend="remote",
        tool_service_url="http://svc", tool_service_token=_TOKEN,
        user_flag_max_output_bytes=4096,
    )


# ---------------------------------------------------------------------------
# §28.18 — candidate paths reach the FTP root (/flag.txt), not only /home/*.
# ---------------------------------------------------------------------------
class TestCandidatePathsReachFtpRoot:
    def test_config_defaults_include_flag_txt_and_root(self) -> None:
        cfg = ApexConfig(target=_TARGET)
        assert "flag.txt" in cfg.user_flag_candidate_filenames
        assert "/" in cfg.user_flag_candidate_roots
        assert cfg.max_user_flag_attempts >= 4  # enough to reach the root-level /flag.txt

    def test_candidate_paths_produce_absolute_ftp_root_flag(self) -> None:
        core = _ObjectiveDeterministic(
            _TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)),
            candidate_filenames=["user.txt", "flag.txt"], candidate_roots=["/home/{username}", "/"],
            max_attempts=6,
        )
        paths = core._candidate_paths("anonymous")
        assert "/flag.txt" in paths  # the Fawn layout
        assert "/user.txt" in paths
        assert "/home/anonymous/user.txt" in paths
        # every candidate is absolute and passes the bounded-path validator
        allowed = frozenset(["user.txt", "flag.txt"])
        for p in paths:
            assert p.startswith("/")
            assert is_bounded_candidate_path(p, allowed_filenames=allowed)

    def test_root_only_candidate_when_username_unsafe(self) -> None:
        # A principal that fails the POSIX-username check must not build a
        # templated /home/{username} path, but the filesystem-root "/" candidates
        # (which have no {username}) must still be produced.
        core = _ObjectiveDeterministic(
            _TARGET, ToolRegistry.from_config(ApexConfig(target=_TARGET)),
            candidate_filenames=["flag.txt"], candidate_roots=["/home/{username}", "/"], max_attempts=6,
        )
        paths = core._candidate_paths("../evil")
        assert paths == ["/flag.txt"]

    async def test_default_config_planner_reaches_ftp_root_flag(self) -> None:
        # End-to-end through the REAL default-config ObjectivePlanner: with a
        # validated FTP capability, the planner (over turns) emits a
        # candidate_path of "/flag.txt". Uses the same default candidate set a
        # live engagement would.
        api = _make_api()
        cap_id = await _seed_validated_ftp_capability(api, _TARGET, principal="anonymous")
        _ = cap_id
        reg = CapabilityRuntimeRegistry()
        config = ApexConfig(target=_TARGET, username_candidates=["anonymous"], password_candidates=["anonymous"])
        from apex_host.planners.objective_planner import ObjectivePlanner
        from apex_host.parsers.objective_parser import ObjectiveParser
        from memfabric.types import AbandonSignal
        planner = ObjectivePlanner(_TARGET, reg, config=config)
        parser = ObjectiveParser()
        goal = Goal(id="g", description="obj", phase="objective", anchor_node=host_id(_TARGET))
        eb = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
        seen_paths: list[str] = []
        for _ in range(8):
            sub = await api.get_subgraph(host_id(_TARGET), depth=6)
            plan = await planner.plan(goal, sub, eb)
            if isinstance(plan, AbandonSignal) or not plan:
                break
            path = str(plan[0].params["candidate_path"])
            seen_paths.append(path)
            # Simulate a connected miss so the planner advances to the next
            # candidate (the parser persists the attempted (cap, path) pair).
            parsed = parser.parse_user_flag_result(
                target=_TARGET, objective_type="user_flag", candidate_path=path,
                connected=True, verified=False, value_digest="", redacted_value="",
                verification_method="", capability_id=str(plan[0].params["capability_id"]),
                capability_type="ftp_file_read", principal="anonymous",
                attempted_paths=list(plan[0].params.get("attempted_paths", [])),
                attempted_capability_paths=list(plan[0].params.get("attempted_capability_paths", [])),
                is_last_candidate=bool(plan[0].params.get("is_last_candidate", False)),
            )
            await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
        assert "/flag.txt" in seen_paths  # the planner reaches the FTP root


class TestFtpAdapterReadsFlag:
    async def test_adapter_retrieves_flag_via_tool_service(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire_tool_service(monkeypatch)
        adapter = FtpFileReadCapabilityAdapter(
            target=_TARGET, port="21", username="anonymous", password=_SECRET, config=_remote_config(),
        )
        result = await adapter.read_bounded_file("/user.txt")
        assert result.connected is True
        assert _FLAG in result.output
        # verify_user_flag accepts it; only a digest survives, raw never stored.
        v = verify_user_flag(result.output, max_output_bytes=4096)
        assert v.verified is True
        assert v.digest and v.digest != _FLAG  # SHA-256 digest, not the raw value
        assert _FLAG not in v.digest and _FLAG not in v.redacted

    async def test_adapter_never_reads_in_process_when_remote(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.runtime_registry as rr

        def _boom(*a: Any, **k: Any) -> None:
            raise AssertionError("in-process ftplib RETR ran despite tool_backend=remote")

        monkeypatch.setattr(rr, "_read_ftp_file_sync", _boom)
        _wire_tool_service(monkeypatch)
        adapter = FtpFileReadCapabilityAdapter(
            target=_TARGET, port="21", username="anonymous", password=_SECRET, config=_remote_config(),
        )
        result = await adapter.read_bounded_file("/user.txt")
        assert _FLAG in result.output  # went through the tool-service

    async def test_password_never_in_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire_tool_service(monkeypatch)
        adapter = FtpFileReadCapabilityAdapter(
            target=_TARGET, port="21", username="anonymous", password=_SECRET, config=_remote_config(),
        )
        result = await adapter.read_bounded_file("/user.txt")
        assert _SECRET not in str(result.__dict__ if hasattr(result, "__dict__") else result)

    async def test_local_backend_reads_in_process(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ftplib, "FTP", _ServerFakeFTP)
        config = ApexConfig(target=_TARGET, dry_run=False, tool_backend="local", user_flag_max_output_bytes=4096)
        adapter = FtpFileReadCapabilityAdapter(
            target=_TARGET, port="21", username="anonymous", password=_SECRET, config=config,
        )
        result = await adapter.read_bounded_file("/user.txt")
        assert result.connected is True and _FLAG in result.output
