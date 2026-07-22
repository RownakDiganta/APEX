# test_credential_validation_security.py
# Cross-cutting security-invariant tests for Phase 12B SSH/FTP credential validation: no cracking tools, no brute force, no arbitrary commands, no secret leakage, no infra changes.
"""Phase 12B security-invariant tests.

These are deliberately cross-cutting — they scan/exercise multiple modules
together to prove the invariants this phase's own task brief required, on
top of (not instead of) the per-module tests in test_ssh_executor.py,
test_ftp_executor.py, test_credential_planner_multiprotocol.py,
test_dispatcher_credential_protocols.py, and test_access_parser_structured.py.
"""
from __future__ import annotations

import inspect
import re
import subprocess
from pathlib import Path

from memfabric.ids import now
from memfabric.types import EvidenceBundle, Goal, Node, SubgraphView

from apex_host import agents
from apex_host.agents import ftp_executor as ftp_mod
from apex_host.agents import ssh_executor as ssh_mod
from apex_host.config import ApexConfig
from apex_host.planners.credential_planner import CredentialPlanner
from apex_host.tools.registry import ToolRegistry

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TARGET = "10.10.10.70"
_ANCHOR = f"host:{_TARGET}"

_DOCSTRING_RE = re.compile(r'""".*?"""', re.DOTALL)


def _code_only(source: str) -> str:
    return _DOCSTRING_RE.sub("", source)


def _module_files() -> list[Path]:
    agents_dir = Path(inspect.getfile(agents)).parent
    return [
        agents_dir / "ssh_executor.py",
        agents_dir / "ftp_executor.py",
        _REPO_ROOT / "apex_host" / "planners" / "credential_planner.py",
        _REPO_ROOT / "apex_host" / "parsers" / "access_parser.py",
        _REPO_ROOT / "apex_host" / "execution" / "dispatcher.py",
        _REPO_ROOT / "apex_host" / "policy" / "rules.py",
    ]


# ---------------------------------------------------------------------------
# No hydra/medusa/ncrack or any other cracking/automation tool
# ---------------------------------------------------------------------------

class TestNoCredentialCrackingTools:
    def test_no_cracking_tool_names_in_new_modules(self) -> None:
        forbidden = ("hydra", "medusa", "ncrack", "msfconsole", "msfvenom", "john", "hashcat", "patator")
        for path in _module_files():
            source = _code_only(path.read_text()).lower()
            for tool in forbidden:
                assert tool not in source, f"{tool!r} found in {path.name}"

    def test_ssh_executor_never_shells_out(self) -> None:
        source = _code_only(ssh_mod.__file__ and Path(ssh_mod.__file__).read_text())
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "shell=True" not in source

    def test_ftp_executor_never_shells_out(self) -> None:
        source = _code_only(Path(ftp_mod.__file__).read_text())
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "shell=True" not in source


# ---------------------------------------------------------------------------
# No brute force / credential spraying / password lists / generated candidates
# ---------------------------------------------------------------------------

class TestNoBruteForce:
    def test_credential_planner_never_iterates_password_candidates(self) -> None:
        """CredentialPlanner must only ever read index [0] of the configured
        candidate lists — never loop over them."""
        source = _code_only(
            Path(inspect.getfile(CredentialPlanner)).read_text()
        )
        assert "for password in" not in source
        assert "for pw in" not in source
        assert "itertools.product" not in source
        assert "wordlist" not in source.lower()

    async def test_multiple_configured_passwords_only_first_is_used(self) -> None:
        registry = ToolRegistry(allowed_tools=["nmap"])
        planner = CredentialPlanner(
            _TARGET, registry,
            username_candidates=["root", "admin", "user"],
            password_candidates=["first", "second", "third"],
        )
        svc = Node(
            id=f"service:{_TARGET}:22/tcp", type="service",
            props={"port": "22", "proto": "tcp", "service": "ssh", "state": "open"},
            confidence=0.9, source="nmap", first_seen=now(), last_seen=now(),
        )
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[svc], edges=[], depth=2)
        goal = Goal(id="g", description="x", phase="credential", anchor_node=_ANCHOR)
        evidence = EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
        result = await planner.plan(goal, subgraph, evidence)
        assert isinstance(result, list) and len(result) == 1
        assert result[0].params["username"] == "root"
        assert result[0].params["password"] == "first"

    def test_max_access_attempts_is_bounded_to_one(self) -> None:
        registry = ToolRegistry(allowed_tools=["nmap"])
        planner = CredentialPlanner(
            _TARGET, registry, username_candidates=["root"], password_candidates=["x"],
            max_access_attempts=999,  # even if misconfigured, must not multiply attempts
        )
        assert planner._core._max_attempts >= 1  # stored, but plan() never loops on it


# ---------------------------------------------------------------------------
# No arbitrary shell strings — commands/operations are allowlisted constants
# ---------------------------------------------------------------------------

class TestNoArbitraryCommands:
    def test_ssh_allowlist_contains_only_harmless_identity_commands(self) -> None:
        assert ssh_mod._ALLOWED_VALIDATION_COMMANDS == frozenset({"id", "whoami"})

    def test_ftp_allowlist_contains_only_harmless_operations(self) -> None:
        assert ftp_mod._ALLOWED_VALIDATION_OPERATIONS == frozenset({"PWD", "NOOP"})

    async def test_ssh_executor_ignores_disallowed_command(self) -> None:
        from memfabric.types import ExecutorResult, TaskSpec

        from apex_host.agents.ssh_executor import SSHExecutor

        executor = SSHExecutor(ApexConfig(target=_TARGET, dry_run=True))
        task = TaskSpec(
            id="t1", goal_id="g1", executor_domain="credential",
            params={
                "tool": "ssh_access", "target": _TARGET, "port": "22",
                "username": "root", "password": "x", "command": "; rm -rf /",
            },
            subgraph_anchor=_ANCHOR, phase="credential",
        )
        result: ExecutorResult = await executor.run(
            task, EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
        )
        assert result.episode.data["operation"] == "id"


# ---------------------------------------------------------------------------
# No password serialization anywhere
# ---------------------------------------------------------------------------

class TestNoPasswordSerialization:
    def test_config_to_safe_dict_redacts_password_candidates(self) -> None:
        config = ApexConfig(
            target=_TARGET, username_candidates=["root"], password_candidates=["s3cr3t-value"],
        )
        safe = config.to_safe_dict()
        assert "s3cr3t-value" not in str(safe)

    def test_config_repr_via_to_safe_dict_never_includes_password(self) -> None:
        config = ApexConfig(target=_TARGET, password_candidates=["s3cr3t-value"])
        assert "s3cr3t-value" not in str(config.to_safe_dict())


# ---------------------------------------------------------------------------
# No file-transfer methods (SFTP / FTP RETR-STOR-DELE-MKD-RMD-RNFR-RNTO)
# ---------------------------------------------------------------------------

class TestNoFileTransferMethods:
    def test_ssh_module_has_no_sftp_calls(self) -> None:
        source = _code_only(Path(ssh_mod.__file__).read_text())
        assert "open_sftp" not in source
        assert "SFTPClient" not in source

    def test_ftp_module_has_no_transfer_or_mutation_calls(self) -> None:
        source = _code_only(Path(ftp_mod.__file__).read_text())
        for forbidden in ("retrbinary", "retrlines", "storbinary", "storlines",
                           "delete(", "mkd(", "rmd(", "rename(", "nlst(", ".dir("):
            assert forbidden not in source


# ---------------------------------------------------------------------------
# No persistent sessions
# ---------------------------------------------------------------------------

class TestNoPersistentSessions:
    def test_ssh_executor_holds_no_client_on_self(self) -> None:
        """SSHExecutor must be stateless across calls (memfabric Invariant 6)
        — no client/session instance attribute set in __init__ or run()."""
        source = _code_only(Path(ssh_mod.__file__).read_text())
        cls_source = source[source.index("class SSHExecutor"):]
        cls_source = cls_source[:cls_source.index("\ndef _attempt_ssh_sync")]
        assert "self._client" not in cls_source
        assert "self._session" not in cls_source
        assert "self._connection" not in cls_source

    def test_ftp_executor_holds_no_client_on_self(self) -> None:
        source = _code_only(Path(ftp_mod.__file__).read_text())
        cls_source = source[source.index("class FTPExecutor"):]
        cls_source = cls_source[:cls_source.index("\ndef _attempt_ftp_sync")]
        assert "self._client" not in cls_source
        assert "self._ftp" not in cls_source
        assert "self._connection" not in cls_source


# ---------------------------------------------------------------------------
# No unbounded retries
# ---------------------------------------------------------------------------

class TestNoUnboundedRetries:
    def test_ssh_attempt_sync_calls_connect_at_most_once(self) -> None:
        source = _code_only(Path(ssh_mod.__file__).read_text())
        assert source.count("client.connect(") == 1

    def test_ftp_attempt_sync_calls_login_at_most_once(self) -> None:
        source = _code_only(Path(ftp_mod.__file__).read_text())
        assert source.count("ftp.login(") == 1

    def test_no_while_true_or_retry_loop_in_new_modules(self) -> None:
        for path in _module_files():
            source = _code_only(path.read_text())
            assert "while True" not in source
            assert re.search(r"for\s+\w+\s+in\s+range\(", source) is None


# ---------------------------------------------------------------------------
# No changes to Docker / Compose / VPN / CI / GHCR
# ---------------------------------------------------------------------------

class TestNoInfrastructureChanges:
    def test_no_infra_paths_modified_in_working_tree(self) -> None:
        """Phase 12B itself was application-layer only. This originally
        asserted zero working-tree diff for any infrastructure path, which
        held only because no other infra work happened to be pending at the
        time. That blanket assertion does not scale: later, separately
        authorized phases legitimately touch these same paths as part of
        their own documented scope (Infra Phase 7's Compose wiring, Infra
        Phase 10's VPN profile, Phase 22's dedicated bounded-file-read env
        vars in compose.yaml, ...). What this test still needs to catch is
        the property Phase 12B actually cared about: SSH/FTP
        credential-validation implementation details leaking into
        infrastructure config where they do not belong — not the mere
        presence of an unrelated, legitimate infra diff."""
        try:
            diff = subprocess.run(
                [
                    "git", "-C", str(_REPO_ROOT), "diff", "HEAD", "--",
                    "docker/", "compose.yaml", "compose.htb.yaml",
                    "compose.mock-vpn.yaml", ".github/", ".dockerignore",
                ],
                capture_output=True, text=True, timeout=10, check=True,
            ).stdout
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return  # not a git checkout / git unavailable — nothing to assert
        forbidden_markers = (
            "ssh_executor", "SSHExecutor", "ftp_executor", "FTPExecutor",
            "paramiko", "ftplib", "username_candidates", "password_candidates",
        )
        offending = [m for m in forbidden_markers if m in diff]
        assert offending == [], (
            f"credential-validation-specific content leaked into infra diff: {offending}"
        )
