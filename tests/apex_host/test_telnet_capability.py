# test_telnet_capability.py
# Tests the telnet passwordless-shell classification fix and the telnet FlagReadCapability adapter.
"""Covers the two APEX telnet fixes:

1. ``TelnetExecutor``/``telnet_transport`` classify a passwordless-root
   shell (no password prompt) as a success and emit a structured result.
2. ``TelnetCapabilityAdapter`` reads a bounded file over telnet and returns
   CLEAN content (session echo/prompt stripped via sentinel markers), so
   ``verify_user_flag`` can accept it.

Plus unit coverage for the capability-pipeline additions
(``derive_telnet_capability``, ``evidence_from_telnet_validation``,
``TelnetCapabilityProvider``).

Uses a local ``asyncio`` server mimicking an HTB Starting-Point telnetd
(IAC negotiation, ``login:`` prompt, passwordless root shell, command
echo). No real network, no real target.
"""
from __future__ import annotations

import asyncio

import pytest

from apex_host.agents.telnet_transport import telnet_session
from apex_host.config import ApexConfig
from apex_host.parsers.capability_parser import CapabilityParser
from apex_host.types import AccessCapabilityType, CredentialValidationResult

pytestmark = pytest.mark.asyncio

_FLAG = "b40abdfe23665f766f9c61ecba8a4c19"


class _FakeTelnetd:
    """Passwordless-root telnetd: IAC DO ECHO, ``Meow login:``, then a
    ``#`` shell that echoes each command line and answers marked reads."""

    def __init__(self) -> None:
        self._server: asyncio.AbstractServer | None = None
        self.host = "127.0.0.1"
        self.port = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # IAC DO ECHO negotiation + banner + login prompt (no newline after).
            writer.write(bytes([255, 253, 1]) + b"\r\n  Meow  \r\nMeow login: ")
            await writer.drain()
            await reader.readline()  # username line (may be prefixed with client's IAC reply)
            # Passwordless: go straight to a root shell prompt.
            writer.write(b"\r\nWelcome to Ubuntu\r\nroot@Meow:~# ")
            await writer.drain()
            while True:
                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode("utf-8", errors="replace")
                # Real telnetd echoes the input line back (markers inline here).
                writer.write(line)
                if "__APEX_READ_START__" in cmd:
                    payload = _FLAG if "cat" in cmd else "uid=0(root) gid=0(root) groups=0(root)"
                    writer.write(
                        b"\r\n__APEX_READ_START__\r\n"
                        + payload.encode()
                        + b"\r\n__APEX_READ_END__\r\nroot@Meow:~# "
                    )
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
            except OSError:
                pass


async def _server():
    srv = _FakeTelnetd()
    await srv.start()
    return srv


async def test_passwordless_login_classified_as_authenticated() -> None:
    srv = await _server()
    try:
        result = await telnet_session(
            target=srv.host, port=srv.port, username="root", password="",
            command="id", login_timeout=5.0, read_timeout=1.0, max_seconds=8.0, max_bytes=4096,
        )
    finally:
        await srv.stop()
    assert result.connected is True
    assert result.authenticated is True
    assert "uid=0(root)" in result.command_output


async def test_bounded_read_returns_clean_flag_no_echo_noise() -> None:
    srv = await _server()
    try:
        result = await telnet_session(
            target=srv.host, port=srv.port, username="root", password="",
            command="cat -- /root/flag.txt", login_timeout=5.0, read_timeout=1.0,
            max_seconds=8.0, max_bytes=4096,
        )
    finally:
        await srv.stop()
    # The extracted content is exactly the flag — no command echo, no prompt,
    # no markers (so verify_user_flag's single-line check will accept it).
    assert result.command_output == _FLAG
    assert "\n" not in result.command_output
    assert "__APEX_READ" not in result.command_output


async def test_telnet_executor_emits_structured_success() -> None:
    from apex_host.agents.telnet_executor import TelnetExecutor
    from memfabric.types import EvidenceBundle, TaskSpec

    srv = await _server()
    try:
        config = ApexConfig(target=srv.host, dry_run=False, telnet_read_timeout_seconds=1.0)
        executor = TelnetExecutor(config)
        task = TaskSpec(
            id="task-telnet-1", goal_id="g", executor_domain="credential", phase="credential",
            params={"target": srv.host, "port": str(srv.port), "username": "root", "password": ""},
        )
        result = await executor.run(
            task, EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])
        )
    finally:
        await srv.stop()
    data = result.episode.data
    assert data["protocol"] == "telnet"
    assert data["success"] is True
    assert data["authenticated"] is True
    assert data["error_category"] == "success"
    # The raw session is never stored — only a redacted placeholder.
    assert data["stdout"] == "[session_redacted]"


async def test_telnet_adapter_reads_flag() -> None:
    from apex_host.runtime_registry import TelnetCapabilityAdapter

    srv = await _server()
    try:
        config = ApexConfig(target=srv.host, dry_run=False, telnet_read_timeout_seconds=1.0)
        adapter = TelnetCapabilityAdapter(
            target=srv.host, port=str(srv.port), username="root", password="", config=config,
        )
        r = await adapter.read_bounded_file("/root/flag.txt")
    finally:
        await srv.stop()
    assert r.connected is True
    assert r.output == _FLAG
    assert r.method == "telnet_cat"


def test_derive_telnet_capability_shape() -> None:
    parsed = CapabilityParser().derive_telnet_capability(
        target="10.129.1.17", username="root", source_task_id="t1",
    )
    caps = [n for n in parsed.node_deltas if n.type == "access_capability"]
    assert len(caps) == 1
    node = caps[0]
    assert node.props["capability_type"] == AccessCapabilityType.telnet_command.value
    assert node.props["validated"] is True
    assert node.props["principal"] == "root"
    assert node.props["runtime_available"] is False
    edge_types = {e.type for e in parsed.edge_deltas}
    assert "has_capability" in edge_types and "enables" in edge_types


def test_evidence_from_telnet_validation_accepts_and_rejects() -> None:
    from apex_host.capabilities.emission import evidence_from_telnet_validation

    ok = CredentialValidationResult(
        protocol="telnet", target="10.129.1.17", port="23", username="root",
        success=True, authenticated=True, operation="id", response_summary="",
        error_category="success", error_detail="", duration_seconds=0.1,
        timed_out=False, executor="telnet",
    )
    ev = evidence_from_telnet_validation(ok, task_id="t1", target="10.129.1.17")
    assert ev is not None
    assert ev.capability_family is AccessCapabilityType.telnet_command

    failed = CredentialValidationResult(
        protocol="telnet", target="10.129.1.17", port="23", username="root",
        success=False, authenticated=False, operation="id", response_summary="",
        error_category="auth_rejected", error_detail="", duration_seconds=0.1,
        timed_out=False, executor="telnet",
    )
    assert evidence_from_telnet_validation(failed, task_id="t1", target="10.129.1.17") is None
    # Wrong protocol never yields telnet evidence.
    ssh_like = CredentialValidationResult(
        protocol="ssh", target="10.129.1.17", port="22", username="root",
        success=True, authenticated=True, operation="id", response_summary="",
        error_category="success", error_detail="", duration_seconds=0.1,
        timed_out=False, executor="ssh",
    )
    assert evidence_from_telnet_validation(ssh_like, task_id="t1", target="10.129.1.17") is None


def test_telnet_provider_accepts_valid_evidence() -> None:
    from apex_host.capabilities.emission import evidence_from_telnet_validation
    from apex_host.capabilities.providers import TelnetCapabilityProvider
    from apex_host.capabilities.decisions import CapabilityDerivationStatus

    class _Ctx:
        # Minimal read-only context: no existing capability nodes.
        class _SG:
            nodes: list = []
        subgraph = _SG()

    ok = CredentialValidationResult(
        protocol="telnet", target="10.129.1.17", port="23", username="root",
        success=True, authenticated=True, operation="id", response_summary="",
        error_category="success", error_detail="", duration_seconds=0.1,
        timed_out=False, executor="telnet",
    )
    ev = evidence_from_telnet_validation(ok, task_id="t1", target="10.129.1.17")
    assert ev is not None
    decision = TelnetCapabilityProvider().evaluate(ev, _Ctx())  # type: ignore[arg-type]
    assert decision.status is CapabilityDerivationStatus.accepted
    assert decision.capability_type is AccessCapabilityType.telnet_command
    assert decision.capability_id
