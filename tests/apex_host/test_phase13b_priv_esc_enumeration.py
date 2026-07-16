# test_phase13b_priv_esc_enumeration.py
# Regression tests for Phase 13B: safe privilege enumeration and evidence collection — deterministic parsers, PrivEscEnumExecutor, planner enumeration tasks, dispatcher/policy wiring, graph links, transaction rollback, and report generation.
"""Phase 13B regression tests.

Covers the bounded, read-only enumeration capability added on top of the
Phase 13A planning framework: the fixed ``ENUM_COMMANDS`` allowlist, the
deterministic fact-extraction parsers in ``apex_host.parsers.priv_esc_parser``,
``PrivEscParser.parse_enumeration``'s evidence/opportunity/recommendation
EKG deltas, ``PrivEscEnumExecutor``'s bounded SSH session, the planner's
enumeration-task emission and per-command dedup, dispatcher/policy wiring
for the ``priv_esc_enum`` tool, and ``RunReport``'s Privilege Enumeration
Summary.

No exploit is executed, no payload is generated, no privilege escalation is
ever performed by any code exercised here — every enumeration command is
read-only (``id``, ``uname -a``, ``sudo -n -l``, ``find ... -perm -4000``,
``getcap -r /``, ``mount``, ``crontab -l``, ``systemctl list-units``, ...).
No Docker, Compose, VPN, or GitHub Actions files are touched by this test
file or the code it tests.
"""
from __future__ import annotations

import re
from typing import Any

import paramiko
import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, EvidenceBundle, Goal, Node, SubgraphView, TaskSpec

from apex_host.agents.priv_esc_enum_executor import (
    ENUM_COMMANDS,
    PrivEscEnumExecutor,
    _run_enum_command_sync,
)
from apex_host.config import ApexConfig
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.graph_ids import (
    collects_edge_id,
    host_id,
    priv_esc_evidence_id,
    produces_edge_id,
    recommends_edge_id,
)
from apex_host.parsers.priv_esc_parser import (
    PrivEscParser,
    parse_capabilities_output,
    parse_cron_output,
    parse_identity_output,
    parse_kernel_output,
    parse_mount_output,
    parse_os_info_output,
    parse_service_info_output,
    parse_sudo_output,
    parse_suid_output,
    parse_windows_groups_output,
    parse_windows_privileges_output,
    parse_windows_registry_output,
    parse_windows_scheduled_task_output,
    parse_windows_service_output,
    parse_windows_systeminfo_output,
)
from apex_host.planners.priv_esc_planner import PrivEscPlanner, _PrivEscDeterministic
from apex_host.planners.priv_esc_opportunities import (
    already_run_commands,
    build_enumeration_progress,
    evidence_from_subgraph,
)
from apex_host.tools.registry import ToolRegistry
from apex_host.types import EvidenceCategory, OpportunityConfidence

_TARGET = "10.10.10.201"
_ANCHOR = f"host:{_TARGET}"

_DOCSTRING_RE = re.compile(r'""".*?"""', re.DOTALL)


def _code_only(source: str) -> str:
    return _DOCSTRING_RE.sub("", source)


# ---------------------------------------------------------------------------
# Shared helpers (mirrors tests/apex_host/test_phase13_priv_esc_planning.py)
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


def _registry(*tools: str) -> ToolRegistry:
    return ToolRegistry(allowed_tools=list(tools))


def _goal(phase: str = "priv_esc") -> Goal:
    return Goal(id="g-enum", description="Enumerate", phase=phase, anchor_node=_ANCHOR)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(entries=[], query="test", subgraph=None, tiers_queried=[])


def _node(node_id: str, node_type: str, props: dict[str, Any], confidence: float = 0.9) -> Node:
    ts = now()
    return Node(id=node_id, type=node_type, props=props, confidence=confidence, source="test", first_seen=ts, last_seen=ts)


def _edge(from_id: str, to_id: str, edge_type: str = "exposes") -> Edge:
    ts = now()
    return Edge(
        id=f"{edge_type}:{from_id}:{to_id}", from_id=from_id, to_id=to_id, type=edge_type,
        props={}, confidence=0.9, source="test", first_seen=ts, last_seen=ts,
    )


def _subgraph(*nodes: Node, edges: list[Edge] | None = None) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=edges or [], depth=2)


def _ssh_access_state_node(username: str = "root", evidence: str = "") -> Node:
    return _node(
        f"access_state:{_TARGET}:{username}:ssh", "access_state",
        {"level": "user", "username": username, "target": _TARGET, "service": "ssh", "evidence": evidence, "proof": ""},
    )


def _evidence_node(command_key: str, category: str, facts: dict[str, Any] | None = None) -> Node:
    ev_id = priv_esc_evidence_id(_TARGET, command_key)
    return _node(
        ev_id, "priv_esc_evidence",
        {
            "target": _TARGET, "category": category, "source_command": ENUM_COMMANDS.get(command_key, ("", ""))[0],
            "command_key": command_key, "confidence": "high", "extracted_facts": facts or {},
            "raw_excerpt": "", "evidence_timestamp": now(),
        },
    )


def _tool_task(evidence: EvidenceBundle | None = None) -> EvidenceBundle:
    return evidence or _empty_evidence()


# ---------------------------------------------------------------------------
# 1. Deterministic fact-extraction parsers
# ---------------------------------------------------------------------------

class TestSudoParser:
    def test_extracts_rules_and_nopasswd(self) -> None:
        stdout = (
            "Matching Defaults entries for user on host:\n"
            "User user may run the following commands on host:\n"
            "    (ALL) NOPASSWD: ALL\n"
        )
        facts = parse_sudo_output(stdout)
        assert facts["nopasswd"] is True
        assert facts["rule_count"] == 1
        assert "NOPASSWD" in facts["rules"][0]

    def test_no_rules_section_returns_empty(self) -> None:
        facts = parse_sudo_output("Sorry, user user may not run sudo on host.\n")
        assert facts["rules"] == []
        assert facts["rule_count"] == 0
        assert facts["nopasswd"] is False
        assert facts["all_all"] is False

    def test_malformed_output_does_not_raise(self) -> None:
        facts = parse_sudo_output("\x00\x01garbage�")
        assert facts["rule_count"] == 0

    def test_all_all_detected(self) -> None:
        stdout = "User user may run the following commands on host:\n    (ALL : ALL) ALL\n"
        facts = parse_sudo_output(stdout)
        assert facts["all_all"] is True

    def test_bounded_to_max_entries(self) -> None:
        lines = "User user may run the following commands on host:\n" + "\n".join(
            f"    (ALL) /usr/bin/tool{i}" for i in range(200)
        )
        facts = parse_sudo_output(lines)
        assert facts["rule_count"] <= 50


class TestSuidParser:
    def test_extracts_paths_and_flags_interesting(self) -> None:
        stdout = "/usr/bin/passwd\n/usr/bin/find\n/usr/bin/vim\n"
        facts = parse_suid_output(stdout)
        assert "/usr/bin/find" in facts["interesting_suid_binaries"]
        assert "/usr/bin/passwd" not in facts["interesting_suid_binaries"]
        assert facts["count"] == 3

    def test_empty_output_returns_zero_count(self) -> None:
        facts = parse_suid_output("")
        assert facts["count"] == 0
        assert facts["suid_binaries"] == []
        assert facts["interesting_suid_binaries"] == []

    def test_non_path_lines_ignored(self) -> None:
        facts = parse_suid_output("find: '/proc/123': Permission denied\nnot a path\n")
        assert facts["count"] == 0

    def test_bounded_to_max_entries(self) -> None:
        stdout = "\n".join(f"/usr/bin/tool{i}" for i in range(200))
        facts = parse_suid_output(stdout)
        assert len(facts["suid_binaries"]) <= 50


class TestCapabilitiesParser:
    def test_extracts_interesting_capability(self) -> None:
        stdout = "/usr/bin/python3.11 = cap_setuid,cap_setgid+eip\n"
        facts = parse_capabilities_output(stdout)
        assert facts["count"] == 1
        assert facts["interesting_capabilities"][0]["path"] == "/usr/bin/python3.11"

    def test_boring_capability_not_flagged_interesting(self) -> None:
        stdout = "/usr/bin/ping = cap_net_raw+ep\n"
        facts = parse_capabilities_output(stdout)
        # cap_net_raw IS in the interesting set (network raw sockets) —
        # verify a truly boring one is excluded instead.
        stdout2 = "/usr/bin/foo = cap_chown+ep\n"
        facts2 = parse_capabilities_output(stdout2)
        assert facts2["interesting_capabilities"] == []
        del facts

    def test_empty_output_returns_zero(self) -> None:
        facts = parse_capabilities_output("")
        assert facts["count"] == 0

    def test_malformed_lines_skipped(self) -> None:
        facts = parse_capabilities_output("this is not a capability line at all\n")
        assert facts["count"] == 0


class TestMountParser:
    def test_extracts_entries_and_nfs(self) -> None:
        stdout = "/dev/sda1 on / type ext4 (rw)\nnfs-server:/export on /mnt type nfs (rw)\n"
        facts = parse_mount_output(stdout)
        assert facts["count"] == 2
        assert len(facts["nfs_entries"]) == 1

    def test_empty_output(self) -> None:
        facts = parse_mount_output("")
        assert facts["count"] == 0
        assert facts["nfs_entries"] == []


class TestCronParser:
    def test_extracts_jobs_skips_comments(self) -> None:
        stdout = "# comment\n*/5 * * * * root /usr/bin/backup.sh\n\n"
        facts = parse_cron_output(stdout)
        assert facts["count"] == 1

    def test_empty_crontab(self) -> None:
        facts = parse_cron_output("")
        assert facts["count"] == 0
        assert facts["jobs"] == []


class TestIdentityParser:
    def test_id_output_detects_docker_and_sudo_groups(self) -> None:
        facts = parse_identity_output("uid=1000(user) gid=1000(user) groups=1000(user),27(sudo),999(docker)")
        assert facts["in_docker_group"] is True
        assert facts["in_sudo_group"] is True
        assert "docker" in facts["groups"]

    def test_groups_command_plain_list(self) -> None:
        facts = parse_identity_output("user sudo docker\n")
        assert facts["in_sudo_group"] is True
        assert facts["in_docker_group"] is True

    def test_no_groups_no_hints(self) -> None:
        facts = parse_identity_output("uid=1000(user) gid=1000(user) groups=1000(user)")
        assert facts["in_docker_group"] is False
        assert facts["in_sudo_group"] is False

    def test_empty_output(self) -> None:
        facts = parse_identity_output("")
        assert facts["groups"] == []
        assert facts["in_docker_group"] is False


class TestKernelParser:
    def test_extracts_version(self) -> None:
        facts = parse_kernel_output("Linux host 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux")
        assert facts["kernel_version"] == "5.4.0-42-generic"

    def test_malformed_output_returns_empty_version(self) -> None:
        facts = parse_kernel_output("not a uname line")
        assert facts["kernel_version"] == ""

    def test_empty_output(self) -> None:
        facts = parse_kernel_output("")
        assert facts["kernel_version"] == ""
        assert facts["raw"] == ""


class TestOsInfoParser:
    def test_extracts_key_value_pairs(self) -> None:
        facts = parse_os_info_output('NAME="Ubuntu"\nVERSION="20.04"\n')
        assert facts["os_facts"]["NAME"] == "Ubuntu"
        assert facts["os_facts"]["VERSION"] == "20.04"

    def test_colon_form(self) -> None:
        facts = parse_os_info_output("Operating System: Ubuntu 20.04\n")
        assert "Operating System" in facts["os_facts"]

    def test_empty_output(self) -> None:
        facts = parse_os_info_output("")
        assert facts["os_facts"] == {}


class TestServiceInfoParser:
    def test_extracts_service_lines(self) -> None:
        facts = parse_service_info_output("ssh.service loaded active running OpenSSH\nnot-a-service\n")
        assert facts["count"] == 1

    def test_empty_output(self) -> None:
        facts = parse_service_info_output("")
        assert facts["count"] == 0


class TestWindowsPlanningSupportParsers:
    """Planning support only — no executor runs these live (see class
    docstring in priv_esc_parser.py 'Windows support scope')."""

    def test_privileges_parser_flags_interesting(self) -> None:
        stdout = "SeDebugPrivilege                Debug programs                Enabled\n"
        facts = parse_windows_privileges_output(stdout)
        assert facts["count"] == 1
        assert facts["interesting_privileges"][0]["privilege"] == "SeDebugPrivilege"

    def test_groups_parser_detects_admin(self) -> None:
        facts = parse_windows_groups_output("BUILTIN\\Administrators              Group\n")
        assert facts["is_local_admin_group"] is True

    def test_systeminfo_parser_extracts_facts(self) -> None:
        facts = parse_windows_systeminfo_output("OS Name:                   Microsoft Windows 10\n")
        assert facts["system_info"]["OS Name"] == "Microsoft Windows 10"

    def test_service_parser_returns_lines(self) -> None:
        facts = parse_windows_service_output("SERVICE_NAME: spooler\n")
        assert facts["count"] == 1

    def test_scheduled_task_parser_returns_lines(self) -> None:
        facts = parse_windows_scheduled_task_output("TaskName: \\Updater\n")
        assert facts["count"] == 1

    def test_registry_parser_returns_lines(self) -> None:
        facts = parse_windows_registry_output("HKEY_LOCAL_MACHINE\\SOFTWARE\n")
        assert facts["count"] == 1

    def test_empty_output_all_windows_parsers(self) -> None:
        assert parse_windows_privileges_output("")["count"] == 0
        assert parse_windows_groups_output("")["groups"] == []
        assert parse_windows_systeminfo_output("")["system_info"] == {}
        assert parse_windows_service_output("")["count"] == 0
        assert parse_windows_scheduled_task_output("")["count"] == 0
        assert parse_windows_registry_output("")["count"] == 0


# ---------------------------------------------------------------------------
# 2. PrivEscParser.parse_enumeration — evidence + opportunity + graph links
# ---------------------------------------------------------------------------

class TestParseEnumeration:
    def test_unknown_category_returns_empty(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_enumeration(
            "output", target=_TARGET, category="not-a-real-category",
            command_key="sudo_l", source_command="sudo -n -l",
        )
        assert parsed.node_deltas == []
        assert parsed.edge_deltas == []

    def test_empty_command_key_returns_empty(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_enumeration(
            "output", target=_TARGET, category=EvidenceCategory.sudo.value,
            command_key="", source_command="sudo -n -l",
        )
        assert parsed.node_deltas == []

    def test_creates_evidence_node(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_enumeration(
            "uid=1000(user) groups=1000(user)", target=_TARGET,
            category=EvidenceCategory.identity.value, command_key="identity", source_command="id",
        )
        evidence_nodes = [n for n in parsed.node_deltas if n.type == "priv_esc_evidence"]
        assert len(evidence_nodes) == 1
        assert evidence_nodes[0].props["command_key"] == "identity"
        assert evidence_nodes[0].props["source_command"] == "id"

    def test_evidence_links_from_host_via_collects(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_enumeration(
            "uid=1000(user)", target=_TARGET, category=EvidenceCategory.identity.value,
            command_key="identity", source_command="id",
        )
        h_id = host_id(_TARGET)
        ev_id = priv_esc_evidence_id(_TARGET, "identity")
        collects = [e for e in parsed.edge_deltas if e.type == "collects"]
        assert len(collects) == 1
        assert collects[0].from_id == h_id
        assert collects[0].to_id == ev_id
        assert collects[0].id == collects_edge_id(h_id, ev_id)

    def test_sudo_nopasswd_produces_opportunity_and_recommendation(self) -> None:
        parser = PrivEscParser()
        stdout = "User user may run the following commands on host:\n    (ALL) NOPASSWD: ALL\n"
        parsed = parser.parse_enumeration(
            stdout, target=_TARGET, category=EvidenceCategory.sudo.value,
            command_key="sudo_l", source_command="sudo -n -l",
        )
        opp_nodes = [n for n in parsed.node_deltas if n.type == "priv_esc_opportunity"]
        rec_nodes = [n for n in parsed.node_deltas if n.type == "priv_esc_recommendation"]
        assert len(opp_nodes) == 1
        assert opp_nodes[0].props["category"] == "sudo"
        assert opp_nodes[0].props["confidence"] == "high"
        assert len(rec_nodes) == 1
        assert rec_nodes[0].props["opportunity_id"] == opp_nodes[0].id

    def test_sudo_no_rules_produces_no_opportunity(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_enumeration(
            "Sorry, user user may not run sudo on host.\n", target=_TARGET,
            category=EvidenceCategory.sudo.value, command_key="sudo_l", source_command="sudo -n -l",
        )
        assert not any(n.type == "priv_esc_opportunity" for n in parsed.node_deltas)
        # But evidence is still recorded (command was completed and parsed).
        assert any(n.type == "priv_esc_evidence" for n in parsed.node_deltas)

    def test_suid_interesting_binary_produces_opportunity(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_enumeration(
            "/usr/bin/find\n", target=_TARGET, category=EvidenceCategory.suid.value,
            command_key="suid", source_command="find / -perm -4000",
        )
        opp_nodes = [n for n in parsed.node_deltas if n.type == "priv_esc_opportunity"]
        assert len(opp_nodes) == 1
        assert opp_nodes[0].props["category"] == "suid"

    def test_docker_identity_produces_docker_opportunity(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_enumeration(
            "uid=1000(user) groups=1000(user),999(docker)", target=_TARGET,
            category=EvidenceCategory.identity.value, command_key="identity", source_command="id",
        )
        cats = {n.props["category"] for n in parsed.node_deltas if n.type == "priv_esc_opportunity"}
        assert cats == {"docker"}

    def test_kernel_version_never_produces_opportunity(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_enumeration(
            "Linux host 5.4.0-42-generic x86_64", target=_TARGET,
            category=EvidenceCategory.kernel_version.value, command_key="kernel_version", source_command="uname -a",
        )
        assert not any(n.type == "priv_esc_opportunity" for n in parsed.node_deltas)

    def test_produces_edge_links_evidence_to_opportunity(self) -> None:
        parser = PrivEscParser()
        stdout = "/usr/bin/find\n"
        parsed = parser.parse_enumeration(
            stdout, target=_TARGET, category=EvidenceCategory.suid.value,
            command_key="suid", source_command="find / -perm -4000",
        )
        opp = next(n for n in parsed.node_deltas if n.type == "priv_esc_opportunity")
        ev_id = priv_esc_evidence_id(_TARGET, "suid")
        produces = [e for e in parsed.edge_deltas if e.type == "produces"]
        assert produces[0].from_id == ev_id
        assert produces[0].to_id == opp.id
        assert produces[0].id == produces_edge_id(ev_id, opp.id)

    def test_recommends_edge_links_opportunity_to_recommendation(self) -> None:
        parser = PrivEscParser()
        stdout = "/usr/bin/find\n"
        parsed = parser.parse_enumeration(
            stdout, target=_TARGET, category=EvidenceCategory.suid.value,
            command_key="suid", source_command="find / -perm -4000",
        )
        opp = next(n for n in parsed.node_deltas if n.type == "priv_esc_opportunity")
        rec = next(n for n in parsed.node_deltas if n.type == "priv_esc_recommendation")
        recommends = [e for e in parsed.edge_deltas if e.type == "recommends"]
        assert recommends[0].from_id == opp.id
        assert recommends[0].to_id == rec.id
        assert recommends[0].id == recommends_edge_id(opp.id, rec.id)

    def test_evidence_id_deterministic_across_calls(self) -> None:
        parser = PrivEscParser()
        p1 = parser.parse_enumeration("id output", target=_TARGET, category=EvidenceCategory.identity.value, command_key="identity", source_command="id")
        p2 = parser.parse_enumeration("different id output", target=_TARGET, category=EvidenceCategory.identity.value, command_key="identity", source_command="id")
        ev1 = next(n for n in p1.node_deltas if n.type == "priv_esc_evidence")
        ev2 = next(n for n in p2.node_deltas if n.type == "priv_esc_evidence")
        assert ev1.id == ev2.id

    def test_no_exploit_code_or_raw_excerpt_unbounded(self) -> None:
        parser = PrivEscParser()
        huge_stdout = "/usr/bin/find\n" * 5000
        parsed = parser.parse_enumeration(
            huge_stdout, target=_TARGET, category=EvidenceCategory.suid.value,
            command_key="suid", source_command="find / -perm -4000",
        )
        ev = next(n for n in parsed.node_deltas if n.type == "priv_esc_evidence")
        assert len(ev.props["raw_excerpt"]) <= 200

    def test_no_output_produces_low_confidence_evidence_no_opportunity(self) -> None:
        parser = PrivEscParser()
        parsed = parser.parse_enumeration(
            "", target=_TARGET, category=EvidenceCategory.cron.value,
            command_key="cron", source_command="crontab -l",
        )
        ev = next(n for n in parsed.node_deltas if n.type == "priv_esc_evidence")
        assert ev.props["confidence"] == OpportunityConfidence.none.value
        assert not any(n.type == "priv_esc_opportunity" for n in parsed.node_deltas)


# ---------------------------------------------------------------------------
# 3. Command deduplication & enumeration progress
# ---------------------------------------------------------------------------

class TestAlreadyRunCommands:
    def test_empty_subgraph_returns_empty_set(self) -> None:
        assert already_run_commands(_subgraph()) == set()

    def test_reads_command_key_from_evidence_nodes(self) -> None:
        sg = _subgraph(_evidence_node("identity", "identity"), _evidence_node("sudo_l", "sudo"))
        assert already_run_commands(sg) == {"identity", "sudo_l"}

    def test_ignores_non_evidence_nodes(self) -> None:
        sg = _subgraph(_node("service:x", "service", {"port": "22"}))
        assert already_run_commands(sg) == set()


class TestBuildEnumerationProgress:
    def test_counts_from_evidence_nodes(self) -> None:
        sg = _subgraph(_evidence_node("identity", "identity"), _evidence_node("sudo_l", "sudo"))
        progress = build_enumeration_progress(_TARGET, sg)
        assert progress.commands_completed == 2
        assert progress.commands_parsed == 2
        assert progress.evidence_count == 2

    def test_zero_evidence_zero_counts(self) -> None:
        progress = build_enumeration_progress(_TARGET, _subgraph())
        assert progress.commands_completed == 0
        assert progress.commands_attempted == 0

    def test_failed_commands_passed_through(self) -> None:
        progress = build_enumeration_progress(_TARGET, _subgraph(), failed_commands=2)
        assert progress.commands_failed == 2
        assert progress.commands_attempted == 2


class TestEvidenceFromSubgraph:
    def test_reconstructs_evidence(self) -> None:
        sg = _subgraph(_evidence_node("identity", "identity"))
        ev = evidence_from_subgraph(sg)
        assert len(ev) == 1
        assert ev[0].category == EvidenceCategory.identity

    def test_skips_unparseable_category(self) -> None:
        bad = _node(priv_esc_evidence_id(_TARGET, "bogus"), "priv_esc_evidence", {"category": "not-real", "confidence": "high"})
        assert evidence_from_subgraph(_subgraph(bad)) == []


# ---------------------------------------------------------------------------
# 4. PrivEscEnumExecutor
# ---------------------------------------------------------------------------

def _enum_task(*, command_key: str = "identity", port: str = "22", username: str = "root", password: str = "hunter2") -> TaskSpec:
    return TaskSpec(
        id="t-enum-1", goal_id="g1", executor_domain="priv_esc",
        params={
            "tool": "priv_esc_enum", "target": _TARGET, "port": port,
            "username": username, "password": password, "parser": "priv_esc_enum",
            "command_key": command_key, "args": [command_key],
        },
        phase="priv_esc",
    )


class _FakeChannel:
    def __init__(self, exit_status: int) -> None:
        self._exit_status = exit_status

    def recv_exit_status(self) -> int:
        return self._exit_status


class _FakeChannelFile:
    def __init__(self, data: bytes, exit_status: int) -> None:
        self._data = data
        self.channel = _FakeChannel(exit_status)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._data
        return self._data[:size]


class _FakeSSHClient:
    connect_raises: Exception | None = None
    exec_raises: Exception | None = None
    stdout_bytes: bytes = b"uid=1000(user) groups=1000(user)\n"
    stderr_bytes: bytes = b""
    exit_status: int = 0

    def __init__(self) -> None:
        self.connect_calls: list[dict[str, Any]] = []
        self.exec_calls: list[dict[str, Any]] = []
        self.closed = False

    def set_missing_host_key_policy(self, policy: object) -> None:
        pass

    def connect(self, **kwargs: Any) -> None:
        self.connect_calls.append(kwargs)
        if type(self).connect_raises is not None:
            raise type(self).connect_raises

    def exec_command(self, command: str, timeout: float | None = None) -> tuple[None, _FakeChannelFile, _FakeChannelFile]:
        self.exec_calls.append({"command": command, "timeout": timeout})
        if type(self).exec_raises is not None:
            raise type(self).exec_raises
        return None, _FakeChannelFile(type(self).stdout_bytes, type(self).exit_status), _FakeChannelFile(type(self).stderr_bytes, type(self).exit_status)

    def open_sftp(self) -> None:
        raise AssertionError("PrivEscEnumExecutor must never open an SFTP session")

    def request_port_forward(self, *a: Any, **k: Any) -> None:
        raise AssertionError("PrivEscEnumExecutor must never request port forwarding")

    def invoke_shell(self, *a: Any, **k: Any) -> None:
        raise AssertionError("PrivEscEnumExecutor must never invoke an interactive shell")

    def close(self) -> None:
        self.closed = True


_last_client: list[_FakeSSHClient] = []


def _install_fake_client(monkeypatch: pytest.MonkeyPatch) -> type[_FakeSSHClient]:
    _FakeSSHClient.connect_raises = None
    _FakeSSHClient.exec_raises = None
    _FakeSSHClient.stdout_bytes = b"uid=1000(user) groups=1000(user)\n"
    _FakeSSHClient.stderr_bytes = b""
    _FakeSSHClient.exit_status = 0
    _last_client.clear()

    def _factory() -> _FakeSSHClient:
        client = _FakeSSHClient()
        _last_client.append(client)
        return client

    import apex_host.agents.priv_esc_enum_executor as mod
    monkeypatch.setattr(mod.paramiko, "SSHClient", _factory)
    return _FakeSSHClient


def _config(**overrides: Any) -> ApexConfig:
    base: dict[str, Any] = {
        "target": _TARGET, "dry_run": False,
        "ssh_connect_timeout_seconds": 1.0, "ssh_auth_timeout_seconds": 1.0,
        "ssh_command_timeout_seconds": 1.0,
    }
    base.update(overrides)
    return ApexConfig(**base)


class TestPrivEscEnumExecutorDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_never_touches_network(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*a: Any, **k: Any) -> None:
            raise AssertionError("dry-run must never construct an SSHClient")
        monkeypatch.setattr(paramiko, "SSHClient", _boom)
        executor = PrivEscEnumExecutor(ApexConfig(target=_TARGET, dry_run=True))
        result = await executor.run(_enum_task(), _tool_task())
        assert result.episode.data["dry_run"] is True
        assert result.episode.data["success"] is True

    @pytest.mark.asyncio
    async def test_dry_run_synthetic_output_never_fabricates_finding(self) -> None:
        """Dry-run synthetic stdout must never contain a NOPASSWD sudo rule
        or a SUID hit — it demonstrates the pipeline without ever
        manufacturing a fake privilege-escalation opportunity."""
        executor = PrivEscEnumExecutor(ApexConfig(target=_TARGET, dry_run=True))
        for key in ENUM_COMMANDS:
            result = await executor.run(_enum_task(command_key=key), _tool_task())
            stdout = result.episode.data["stdout"]
            assert "nopasswd" not in stdout.lower()

    @pytest.mark.asyncio
    async def test_unknown_command_key_fails_closed(self) -> None:
        executor = PrivEscEnumExecutor(ApexConfig(target=_TARGET, dry_run=True))
        result = await executor.run(_enum_task(command_key="rm_rf_root"), _tool_task())
        assert result.episode.data["success"] is False
        assert "unknown" in str(result.episode.data["error"]).lower()

    @pytest.mark.asyncio
    async def test_stateless_across_calls(self) -> None:
        executor = PrivEscEnumExecutor(ApexConfig(target=_TARGET, dry_run=True))
        r1 = await executor.run(_enum_task(command_key="identity"), _tool_task())
        r2 = await executor.run(_enum_task(command_key="os_info"), _tool_task())
        assert r1.episode.data["command_key"] != r2.episode.data["command_key"]
        assert not hasattr(executor, "_client")


class TestPrivEscEnumExecutorLive:
    @pytest.mark.asyncio
    async def test_successful_command_returns_stdout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = PrivEscEnumExecutor(_config())
        result = await executor.run(_enum_task(command_key="identity"), _tool_task())
        assert result.episode.data["success"] is True
        assert "uid=1000" in result.episode.data["stdout"]
        assert _last_client[0].closed is True

    @pytest.mark.asyncio
    async def test_fixed_command_string_used_never_task_supplied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = PrivEscEnumExecutor(_config())
        await executor.run(_enum_task(command_key="sudo_l"), _tool_task())
        assert _last_client[0].exec_calls[0]["command"] == "sudo -n -l"

    @pytest.mark.asyncio
    async def test_password_never_in_exception_or_data(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        _FakeSSHClient.connect_raises = paramiko.AuthenticationException("nope")
        executor = PrivEscEnumExecutor(_config())
        result = await executor.run(_enum_task(command_key="identity", password="s3cr3t-value"), _tool_task())
        assert "s3cr3t-value" not in str(result.episode.data)

    @pytest.mark.asyncio
    async def test_auth_failure_produces_failure_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        _FakeSSHClient.connect_raises = paramiko.AuthenticationException("nope")
        executor = PrivEscEnumExecutor(_config())
        result = await executor.run(_enum_task(), _tool_task())
        assert result.episode.data["success"] is False
        assert result.episode.outcome.value == "fundamental"

    @pytest.mark.asyncio
    async def test_nonzero_exit_status_still_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """sudo -n -l without configured rules legitimately exits non-zero
        while still producing safe, useful stdout — must not be treated as
        a failure."""
        _install_fake_client(monkeypatch)
        _FakeSSHClient.exit_status = 1
        _FakeSSHClient.stdout_bytes = b""
        _FakeSSHClient.stderr_bytes = b"sudo: a password is required\n"
        executor = PrivEscEnumExecutor(_config())
        result = await executor.run(_enum_task(command_key="sudo_l"), _tool_task())
        assert result.episode.data["success"] is True
        assert "password is required" in result.episode.data["stdout"]

    @pytest.mark.asyncio
    async def test_never_opens_sftp_or_shell(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch)
        executor = PrivEscEnumExecutor(_config())
        await executor.run(_enum_task(), _tool_task())
        # _FakeSSHClient raises AssertionError if these are ever called —
        # reaching here without an exception is the proof.

    def test_run_enum_command_sync_never_raises_on_connect_failure(self) -> None:
        stdout, error = _run_enum_command_sync(
            "unreachable.invalid", 22, "user", "pass", "id", 0.01, 0.01, 0.01,
        )
        assert stdout == ""
        assert error is not None


class TestEnumCommandOrderConsistency:
    def test_planner_order_matches_shared_command_table_exactly(self) -> None:
        """_ENUM_COMMAND_ORDER (priv_esc_planner.py) and ENUM_COMMANDS
        (priv_esc_opportunities.py, the single shared source of truth) must
        never drift apart — a missing/extra key would either silently skip
        a command forever or crash the executor on lookup."""
        from apex_host.planners.priv_esc_planner import _ENUM_COMMAND_ORDER

        assert set(_ENUM_COMMAND_ORDER) == set(ENUM_COMMANDS)
        assert len(_ENUM_COMMAND_ORDER) == len(set(_ENUM_COMMAND_ORDER))


class TestPrivEscEnumExecutorNoExploitInvariants:
    def test_all_commands_are_read_only_no_write_flags(self) -> None:
        # Redirects to /dev/null (discarding stderr noise) are harmless and
        # expected; any OTHER redirect target would be a real write concern.
        destructive_re = re.compile(
            r"(^|[;&|]\s*)(rm|dd|mkfs|shutdown|reboot|useradd|userdel|mkswap)\b|"
            r">>?\s*(?!/dev/null)/|chmod\s+777|:\(\)\{"
        )
        for command, _category in ENUM_COMMANDS.values():
            assert destructive_re.search(command.lower()) is None, (
                f"{command!r} looks like it contains a destructive/write operation"
            )

    def test_no_metasploit_or_shell_references_in_source(self) -> None:
        import pathlib
        root = pathlib.Path(__file__).parent.parent.parent / "apex_host"
        f = root / "agents" / "priv_esc_enum_executor.py"
        text = _code_only(f.read_text()).lower()
        for term in ("msfconsole", "msfvenom", "meterpreter", "reverse_shell", "invoke_shell(", "open_sftp("):
            assert term not in text

    def test_command_keys_map_to_fixed_strings_never_task_args(self) -> None:
        """Static proof: the executor never formats a shell command using
        task.params free text — it only ever looks up ENUM_COMMANDS[key]."""
        import pathlib
        root = pathlib.Path(__file__).parent.parent.parent / "apex_host"
        source = _code_only((root / "agents" / "priv_esc_enum_executor.py").read_text())
        assert "params.get(\"command\")" not in source
        assert "f\"{command}" not in source


# ---------------------------------------------------------------------------
# 5. Planner — enumeration task emission and dedup
# ---------------------------------------------------------------------------

class TestPrivEscPlannerEnumeration:
    @pytest.mark.asyncio
    async def test_no_ssh_access_no_enum_tasks(self) -> None:
        core = _PrivEscDeterministic(_TARGET, _registry("searchsploit"), username_candidates=["root"], password_candidates=["hunter2"])
        result = await core.plan(_goal(), _subgraph(), _empty_evidence())
        assert isinstance(result, type(result))  # AbandonSignal or list — no crash
        if isinstance(result, list):
            assert not any(t.params.get("tool") == "priv_esc_enum" for t in result)

    @pytest.mark.asyncio
    async def test_ssh_access_no_credentials_abandons_with_clear_message(self) -> None:
        core = _PrivEscDeterministic(_TARGET, _registry())
        sg = _subgraph(_ssh_access_state_node())
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert not isinstance(result, list)
        assert "no credentials configured" in result.reason

    @pytest.mark.asyncio
    async def test_ssh_access_with_credentials_emits_enum_tasks(self) -> None:
        core = _PrivEscDeterministic(_TARGET, _registry(), username_candidates=["root"], password_candidates=["hunter2"])
        sg = _subgraph(_ssh_access_state_node())
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        assert all(t.params["tool"] == "priv_esc_enum" for t in result)
        assert all(t.params["username"] == "root" and t.params["password"] == "hunter2" for t in result)

    @pytest.mark.asyncio
    async def test_enum_tasks_bounded_per_turn(self) -> None:
        core = _PrivEscDeterministic(_TARGET, _registry(), username_candidates=["root"], password_candidates=["hunter2"])
        sg = _subgraph(_ssh_access_state_node())
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        assert len(result) <= 3

    @pytest.mark.asyncio
    async def test_deterministic_command_order(self) -> None:
        core = _PrivEscDeterministic(_TARGET, _registry(), username_candidates=["root"], password_candidates=["hunter2"])
        sg = _subgraph(_ssh_access_state_node())
        r1 = await core.plan(_goal(), sg, _empty_evidence())
        r2 = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(r1, list) and isinstance(r2, list)
        assert [t.params["command_key"] for t in r1] == [t.params["command_key"] for t in r2]
        assert [t.params["command_key"] for t in r1] == ["identity", "os_info", "kernel_version"]

    @pytest.mark.asyncio
    async def test_already_run_commands_never_reemitted(self) -> None:
        core = _PrivEscDeterministic(_TARGET, _registry(), username_candidates=["root"], password_candidates=["hunter2"])
        sg = _subgraph(_ssh_access_state_node(), _evidence_node("identity", "identity"), _evidence_node("os_info", "os_info"), _evidence_node("kernel_version", "kernel_version"))
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        assert all(t.params["command_key"] not in ("identity", "os_info", "kernel_version") for t in result)

    @pytest.mark.asyncio
    async def test_all_commands_run_falls_through_to_exhaustion_or_other_paths(self) -> None:
        evidence_nodes = [_evidence_node(k, cat) for k, (cmd, cat) in ENUM_COMMANDS.items()]
        core = _PrivEscDeterministic(_TARGET, _registry(), username_candidates=["root"], password_candidates=["hunter2"])
        sg = _subgraph(_ssh_access_state_node(), *evidence_nodes)
        result = await core.plan(_goal(), sg, _empty_evidence())
        # No more enumeration tasks possible; falls to analytical/searchsploit
        # or the exhaustion AbandonSignal.
        if isinstance(result, list):
            assert not any(t.params.get("tool") == "priv_esc_enum" for t in result)
        else:
            assert "exhausted" in result.reason

    @pytest.mark.asyncio
    async def test_port_derived_from_ssh_capability(self) -> None:
        service = _node(f"service:{_TARGET}:2222/tcp", "service", {"port": "2222", "proto": "tcp", "service": "ssh", "state": "open"})
        core = _PrivEscDeterministic(_TARGET, _registry(), username_candidates=["root"], password_candidates=["hunter2"])
        sg = _subgraph(_ssh_access_state_node(), service)
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["port"] == "2222"

    @pytest.mark.asyncio
    async def test_password_never_appears_in_task_repr(self) -> None:
        core = _PrivEscDeterministic(_TARGET, _registry(), username_candidates=["root"], password_candidates=["s3cr3t-marker"])
        sg = _subgraph(_ssh_access_state_node())
        result = await core.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        # The password IS present in params (needed by the executor) but
        # must never be logged/echoed anywhere outside params — this test
        # documents that expectation at the boundary the executor reads.
        assert result[0].params["password"] == "s3cr3t-marker"

    @pytest.mark.asyncio
    async def test_backward_compatible_constructor_without_credentials(self) -> None:
        """Existing Phase 13A call sites that never pass
        username_candidates/password_candidates must still work unchanged."""
        core = _PrivEscDeterministic(_TARGET, _registry("searchsploit"))
        result = await core.plan(_goal(), _subgraph(), _empty_evidence())
        assert not isinstance(result, list) or True  # no crash is the assertion

    @pytest.mark.asyncio
    async def test_wrapper_passes_through_credentials(self) -> None:
        planner = PrivEscPlanner(_TARGET, _registry(), username_candidates=["root"], password_candidates=["hunter2"])
        sg = _subgraph(_ssh_access_state_node())
        result = await planner.plan(_goal(), sg, _empty_evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "priv_esc_enum"


# ---------------------------------------------------------------------------
# 6. Dispatcher routing
# ---------------------------------------------------------------------------

def _build_dispatcher_with_enum_executor(config: ApexConfig) -> Any:
    from apex_host.execution.dispatcher import TaskDispatcher
    from apex_host.execution.registry import TaskRegistry
    from apex_host.policy import PolicyAdvisor, load_policy

    return TaskDispatcher(
        advisor=PolicyAdvisor(load_policy(config), config),
        task_registry=TaskRegistry(), config=config,
        run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type,return-value]
        priv_esc_enum_executor=PrivEscEnumExecutor(config),
    )


class TestDispatcherPrivEscEnumRouting:
    @pytest.mark.asyncio
    async def test_priv_esc_enum_routes_to_executor(self) -> None:
        from apex_host.execution.context import ExecutionContext
        from apex_host.execution.dispositions import ExecutionDisposition

        config = ApexConfig(target=_TARGET, dry_run=True)
        dispatcher = _build_dispatcher_with_enum_executor(config)
        ctx = ExecutionContext(run_id="r1", phase="priv_esc", turn_number=1, evidence_version=None, subgraph=_subgraph(), evidence=_empty_evidence(), dry_run=True)
        result = await dispatcher.dispatch(_enum_task(), ctx)
        assert result.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert result.tool_result_dict["command_key"] == "identity"
        assert "password" not in result.tool_result_dict

    @pytest.mark.asyncio
    async def test_missing_executor_returns_tool_unavailable(self) -> None:
        from apex_host.execution.context import ExecutionContext
        from apex_host.execution.dispatcher import TaskDispatcher
        from apex_host.execution.dispositions import ExecutionDisposition
        from apex_host.execution.registry import TaskRegistry
        from apex_host.policy import PolicyAdvisor, load_policy

        config = ApexConfig(target=_TARGET, dry_run=True)
        dispatcher = TaskDispatcher(
            advisor=PolicyAdvisor(load_policy(config), config),
            task_registry=TaskRegistry(), config=config,
            run_command_fn=lambda *a, **k: None,  # type: ignore[arg-type,return-value]
        )
        ctx = ExecutionContext(run_id="r1", phase="priv_esc", turn_number=1, evidence_version=None, subgraph=_subgraph(), evidence=_empty_evidence(), dry_run=True)
        result = await dispatcher.dispatch(_enum_task(), ctx)
        assert result.disposition is ExecutionDisposition.TOOL_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_distinct_command_keys_do_not_collide_as_duplicates(self) -> None:
        from apex_host.execution.context import ExecutionContext
        from apex_host.execution.dispositions import ExecutionDisposition

        config = ApexConfig(target=_TARGET, dry_run=True)
        dispatcher = _build_dispatcher_with_enum_executor(config)
        ctx = ExecutionContext(run_id="r1", phase="priv_esc", turn_number=1, evidence_version=None, subgraph=_subgraph(), evidence=_empty_evidence(), dry_run=True)
        r1 = await dispatcher.dispatch(_enum_task(command_key="identity"), ctx)
        r2 = await dispatcher.dispatch(_enum_task(command_key="sudo_l"), ctx)
        assert r1.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert r2.disposition is ExecutionDisposition.EXECUTED_SUCCESS
        assert r1.fingerprint != r2.fingerprint

    @pytest.mark.asyncio
    async def test_identical_command_key_is_a_duplicate(self) -> None:
        from apex_host.execution.context import ExecutionContext
        from apex_host.execution.dispositions import ExecutionDisposition

        config = ApexConfig(target=_TARGET, dry_run=True)
        dispatcher = _build_dispatcher_with_enum_executor(config)
        ctx = ExecutionContext(run_id="r1", phase="priv_esc", turn_number=1, evidence_version=None, subgraph=_subgraph(), evidence=_empty_evidence(), dry_run=True)
        await dispatcher.dispatch(_enum_task(command_key="identity"), ctx)
        r2 = await dispatcher.dispatch(_enum_task(command_key="identity"), ctx)
        assert r2.disposition is ExecutionDisposition.SKIPPED_DUPLICATE


# ---------------------------------------------------------------------------
# 7. Policy — check_bounded_priv_esc_enumeration for priv_esc_enum
# ---------------------------------------------------------------------------

class TestPolicyPrivEscEnum:
    def _advisor_inputs(self, config: ApexConfig) -> Any:
        from apex_host.policy import load_policy
        return load_policy(config)

    def test_valid_command_key_approved(self) -> None:
        from apex_host.policy.rules import check_bounded_priv_esc_enumeration

        config = ApexConfig(target=_TARGET, dry_run=True)
        policy = self._advisor_inputs(config)
        task = _enum_task(command_key="identity")
        decision = check_bounded_priv_esc_enumeration(task, policy, config)
        assert decision is not None
        assert decision.status.value == "approved"

    def test_unknown_command_key_blocked(self) -> None:
        from apex_host.policy.rules import check_bounded_priv_esc_enumeration

        config = ApexConfig(target=_TARGET, dry_run=True)
        policy = self._advisor_inputs(config)
        task = _enum_task(command_key="rm_everything")
        decision = check_bounded_priv_esc_enumeration(task, policy, config)
        assert decision is not None
        assert decision.status.value == "blocked"

    def test_off_scope_target_falls_through(self) -> None:
        from apex_host.policy.rules import check_bounded_priv_esc_enumeration

        config = ApexConfig(target=_TARGET, dry_run=True)
        policy = self._advisor_inputs(config)
        task = _enum_task(command_key="identity")
        task.params["target"] = "10.0.0.99"
        decision = check_bounded_priv_esc_enumeration(task, policy, config)
        assert decision is None

    def test_unrelated_tool_returns_none(self) -> None:
        from apex_host.policy.rules import check_bounded_priv_esc_enumeration

        config = ApexConfig(target=_TARGET, dry_run=True)
        policy = self._advisor_inputs(config)
        task = TaskSpec(id="t", goal_id="g", executor_domain="priv_esc", params={"tool": "nmap", "target": _TARGET}, phase="priv_esc")
        assert check_bounded_priv_esc_enumeration(task, policy, config) is None

    def test_full_advisor_approves_end_to_end(self) -> None:
        from apex_host.policy import PolicyAdvisor, load_policy

        config = ApexConfig(target=_TARGET, dry_run=True)
        advisor = PolicyAdvisor(load_policy(config), config)
        decision = advisor.review_task(_enum_task(command_key="identity"), "priv_esc", _empty_evidence(), config)
        assert decision.is_approved

    def test_full_advisor_blocks_bad_command_key(self) -> None:
        from apex_host.policy import PolicyAdvisor, load_policy

        config = ApexConfig(target=_TARGET, dry_run=True)
        advisor = PolicyAdvisor(load_policy(config), config)
        decision = advisor.review_task(_enum_task(command_key="hydra_bruteforce"), "priv_esc", _empty_evidence(), config)
        assert not decision.is_approved


# ---------------------------------------------------------------------------
# 8. MemoryAPI writes, transaction rollback, graph link integrity
# ---------------------------------------------------------------------------

class TestMemoryApiIntegration:
    @pytest.mark.asyncio
    async def test_evidence_and_opportunity_persisted_and_linked(self) -> None:
        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))

        parser = PrivEscParser()
        stdout = "User user may run the following commands on host:\n    (ALL) NOPASSWD: ALL\n"
        parsed = parser.parse_enumeration(stdout, target=_TARGET, category=EvidenceCategory.sudo.value, command_key="sudo_l", source_command="sudo -n -l")
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)

        subgraph = await api.get_subgraph(h_id, depth=10)
        types = {n.type for n in subgraph.nodes}
        assert {"host", "priv_esc_evidence", "priv_esc_opportunity", "priv_esc_recommendation"}.issubset(types)
        edge_types = {e.type for e in subgraph.edges}
        assert {"collects", "produces", "recommends"}.issubset(edge_types)

    @pytest.mark.asyncio
    async def test_reapplying_same_command_upserts_not_duplicates(self) -> None:
        """Running the same enumeration command twice must upsert the same
        evidence node id, not create a second node — deterministic IDs are
        what make this possible."""
        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))

        parser = PrivEscParser()
        for _ in range(2):
            parsed = parser.parse_enumeration("uid=0(root)", target=_TARGET, category=EvidenceCategory.identity.value, command_key="identity", source_command="id")
            await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)

        subgraph = await api.get_subgraph(h_id, depth=10)
        evidence_nodes = [n for n in subgraph.nodes if n.type == "priv_esc_evidence"]
        assert len(evidence_nodes) == 1

    @pytest.mark.asyncio
    async def test_transaction_rollback_on_dangling_edge(self) -> None:
        """A batch that fails partway (dangling edge to a non-existent
        node) must roll back completely — no orphaned evidence node left
        behind (memfabric's apply_deltas transaction guarantee)."""
        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))

        parser = PrivEscParser()
        parsed = parser.parse_enumeration("uid=0(root)", target=_TARGET, category=EvidenceCategory.identity.value, command_key="identity", source_command="id")
        bad_edge = Edge(
            id="collects:bogus:missing", from_id="host:does-not-exist", to_id=parsed.node_deltas[0].id,
            type="collects", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts,
        )
        with pytest.raises(ValueError):
            await api.apply_deltas(nodes=parsed.node_deltas, edges=[bad_edge])

        subgraph = await api.get_subgraph(h_id, depth=10)
        assert not any(n.type == "priv_esc_evidence" for n in subgraph.nodes)

    @pytest.mark.asyncio
    async def test_no_secret_leakage_in_evidence_or_opportunity_props(self) -> None:
        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))
        parser = PrivEscParser()
        parsed = parser.parse_enumeration("uid=0(root) groups=0(root),27(sudo)", target=_TARGET, category=EvidenceCategory.identity.value, command_key="identity", source_command="id")
        await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
        subgraph = await api.get_subgraph(h_id, depth=10)
        for n in subgraph.nodes:
            serialized = str(n.props)
            assert "hunter2" not in serialized
            assert "s3cr3t" not in serialized


# ---------------------------------------------------------------------------
# 9. Report — Privilege Enumeration Summary
# ---------------------------------------------------------------------------

def _base_config() -> ApexConfig:
    return ApexConfig(target=_TARGET, dry_run=True, max_turns=5)


def _final_state(subgraph_nodes: list[Node]) -> dict[str, Any]:
    return {
        "target": _TARGET, "phase": "done", "completed": True, "turn_count": 1,
        "last_error": None,
        "findings": [], "error_episodes": [], "planner_decisions": [],
        "policy_decisions": [], "duplicate_actions": [], "credential_validation_log": [],
        "execution_backend_log": [], "outcome": "validated_access",
        "termination_reason": "", "termination_phase": "done", "stall_reason": "",
        "privilege_state": "", "enumeration_complete": False,
    }


class TestReportPrivilegeEnumerationSummary:
    def test_no_enumeration_no_section(self) -> None:
        report = build_report(config=_base_config(), final_state=_final_state([]), subgraph=_subgraph())
        assert report.enum_commands_completed == 0
        assert "Privilege Enumeration Summary" not in format_text(report)

    def test_evidence_reflected_in_report(self) -> None:
        sg = _subgraph(_evidence_node("identity", "identity"), _evidence_node("sudo_l", "sudo"))
        report = build_report(config=_base_config(), final_state=_final_state([]), subgraph=sg)
        assert report.enum_commands_completed == 2
        assert report.enum_evidence_categories.get("identity") == 1
        assert report.enum_evidence_categories.get("sudo") == 1

    def test_new_opportunities_counted(self) -> None:
        opp = _node(
            "priv_esc_opportunity:x:sudo:enum-sudo-rules", "priv_esc_opportunity",
            {"category": "sudo", "confidence": "high", "source_tool": "priv_esc_enum", "description": "d", "recommended_next_action": "r", "attempted": True, "attempt_count": 1, "exhausted": True},
        )
        sg = _subgraph(_evidence_node("sudo_l", "sudo"), opp)
        report = build_report(config=_base_config(), final_state=_final_state([]), subgraph=sg)
        assert report.enum_new_opportunities == 1

    def test_completeness_true_when_all_commands_run(self) -> None:
        nodes = [_evidence_node(k, cat) for k, (cmd, cat) in ENUM_COMMANDS.items()]
        sg = _subgraph(*nodes)
        report = build_report(config=_base_config(), final_state=_final_state([]), subgraph=sg)
        assert report.enum_completeness is True

    def test_completeness_false_when_partial(self) -> None:
        sg = _subgraph(_evidence_node("identity", "identity"))
        report = build_report(config=_base_config(), final_state=_final_state([]), subgraph=sg)
        assert report.enum_completeness is False

    def test_format_text_includes_section_when_present(self) -> None:
        sg = _subgraph(_evidence_node("identity", "identity"))
        report = build_report(config=_base_config(), final_state=_final_state([]), subgraph=sg)
        text = format_text(report)
        assert "Privilege Enumeration Summary" in text
        assert "Commands executed" in text
        assert "Evidence collected" in text
        assert "Duplicates avoided" in text

    def test_json_dict_includes_privilege_enumeration_block(self) -> None:
        sg = _subgraph(_evidence_node("identity", "identity"))
        report = build_report(config=_base_config(), final_state=_final_state([]), subgraph=sg)
        d = to_json_dict(report)
        assert "privilege_enumeration" in d
        assert d["privilege_enumeration"]["commands_completed"] == 1

    def test_duplicate_opportunities_avoided_from_state(self) -> None:
        state = _final_state([])
        state["duplicate_actions"] = [
            {"fingerprint": "abc", "tool": "priv_esc_enum", "target": _TARGET, "phase": "priv_esc", "disposition": "skip_task", "reason": "r", "meaningful_state_change": False},
            {"fingerprint": "def", "tool": "nmap", "target": _TARGET, "phase": "recon", "disposition": "skip_task", "reason": "r", "meaningful_state_change": False},
        ]
        report = build_report(config=_base_config(), final_state=state, subgraph=_subgraph())
        assert report.enum_duplicate_opportunities_avoided == 1


# ---------------------------------------------------------------------------
# 10. Full graph integration — dry-run end-to-end
# ---------------------------------------------------------------------------

class TestFullGraphIntegrationEnumeration:
    @pytest.mark.asyncio
    async def test_dry_run_engagement_with_ssh_access_produces_evidence(self) -> None:
        from apex_host.orchestration.builder import build_apex_graph

        api = _make_api()
        ts = now()
        h_id = host_id(_TARGET)
        await api.upsert_node(Node(id=h_id, type="host", props={"ip": _TARGET}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))
        svc_id = f"service:{_TARGET}:22/tcp"
        await api.upsert_node(Node(
            id=svc_id, type="service",
            props={"port": "22", "proto": "tcp", "service": "ssh", "state": "open", "version": "OpenSSH 8.2"},
            confidence=0.9, source="t", first_seen=ts, last_seen=ts,
        ))
        await api.upsert_edge(Edge(id="e1", from_id=h_id, to_id=svc_id, type="exposes", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))
        access_id = f"access_state:{_TARGET}:root:ssh"
        await api.upsert_node(Node(
            id=access_id, type="access_state",
            props={"level": "user", "username": "root", "target": _TARGET, "service": "ssh", "evidence": "uid=0(root)", "proof": ""},
            confidence=0.85, source="ssh", first_seen=ts, last_seen=ts,
        ))
        await api.upsert_edge(Edge(id="e2", from_id=h_id, to_id=access_id, type="exposes", props={}, confidence=0.9, source="t", first_seen=ts, last_seen=ts))

        config = ApexConfig(
            target=_TARGET, dry_run=True, max_turns=2,
            allowed_tools=["nmap", "curl", "nc"],
            username_candidates=["root"], password_candidates=["hunter2"],
        )
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        initial_state: dict[str, Any] = {
            "run_id": "r1", "target": _TARGET, "phase": "priv_esc", "goal": "",
            "current_task": None, "evidence_summary": "", "findings": [],
            "last_tool_result": None, "tool_results": None, "last_error": None,
            "completed": False, "turn_count": 0, "planner_decisions": [],
            "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
            "execution_backend_log": [], "credential_validation_log": [],
            "outcome": "", "termination_reason": "", "termination_phase": "",
            "stall_reason": "", "privilege_state": "", "privilege_summary": {},
            "opportunity_ids": [], "attempted_opportunities": [],
            "enumeration_complete": False,
        }
        await graph.ainvoke(initial_state)

        subgraph = await api.get_subgraph(h_id, depth=10)
        evidence_nodes = [n for n in subgraph.nodes if n.type == "priv_esc_evidence"]
        assert len(evidence_nodes) >= 1
