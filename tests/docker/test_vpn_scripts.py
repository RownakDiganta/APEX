# test_vpn_scripts.py
# Unit tests for docker/vpn/route_check.py, docker/vpn/tunnel_status.py, docker/vpn/connect_check.py, and docker/vpn/readiness_server.py — dynamically imported since these are standalone, dependency-free scripts (not an installed Python package). Does not require a Docker daemon or the `ip` binary.
"""Unit tests for the VPN container's support scripts.

These files are copied into the minimal VPN image standalone (see
``docker/vpn/Dockerfile``) and deliberately have zero dependency on
``apex_host``/``memfabric`` — they are not part of this project's
installed package, so this test file imports them directly from disk via
``importlib.util.spec_from_file_location``.

Covers: CIDR parsing, interface/route-table parsing (pure functions, no
subprocess), route-check IP validation, route-check success/failure/
timeout/missing-binary handling (subprocess mocked via monkeypatch — no
real `ip` binary required, so these tests pass on macOS/CI too), connect-
check port validation and outcome classification (real loopback sockets
for the deterministic connected/refused cases, monkeypatched sockets for
timeout/unreachable), and a real, local-only HTTP round trip against the
readiness server (loopback only, no packet leaves the test process).
"""
from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import threading
import types
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

_VPN_DIR = pathlib.Path(__file__).parent.parent.parent / "docker" / "vpn"


def _load_module(name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, _VPN_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # readiness_server imports route_check/tunnel_status by bare name
    spec.loader.exec_module(module)
    return module


route_check = _load_module("route_check")
tunnel_status = _load_module("tunnel_status")
connect_check = _load_module("connect_check")
readiness_server = _load_module("readiness_server")


# ---------------------------------------------------------------------------
# route_check.py — IP validation
# ---------------------------------------------------------------------------

class TestValidateTargetIp:
    def test_valid_ipv4(self) -> None:
        assert route_check.validate_target_ip("10.129.5.5") == "10.129.5.5"

    def test_valid_ipv6(self) -> None:
        assert route_check.validate_target_ip("::1") == "::1"

    def test_strips_whitespace(self) -> None:
        assert route_check.validate_target_ip("  10.129.5.5  ") == "10.129.5.5"

    def test_blank_rejected(self) -> None:
        with pytest.raises(route_check.InvalidTargetError):
            route_check.validate_target_ip("")

    def test_hostname_rejected(self) -> None:
        with pytest.raises(route_check.InvalidTargetError):
            route_check.validate_target_ip("example.com")

    def test_cidr_notation_rejected(self) -> None:
        with pytest.raises(route_check.InvalidTargetError):
            route_check.validate_target_ip("10.129.0.0/16")

    def test_shell_metacharacters_rejected(self) -> None:
        with pytest.raises(route_check.InvalidTargetError):
            route_check.validate_target_ip("10.129.5.5; rm -rf /")

    def test_command_substitution_rejected(self) -> None:
        with pytest.raises(route_check.InvalidTargetError):
            route_check.validate_target_ip("$(whoami)")

    def test_invalid_target_error_is_a_value_error(self) -> None:
        assert issubclass(route_check.InvalidTargetError, ValueError)


# ---------------------------------------------------------------------------
# route_check.py — output parsing (pure)
# ---------------------------------------------------------------------------

class TestParseRouteGetOutput:
    def test_with_gateway(self) -> None:
        out = "10.129.5.5 via 10.129.0.1 dev tun0 src 10.10.14.5 uid 1000"
        device, gateway = route_check._parse_route_get_output(out)
        assert device == "tun0"
        assert gateway == "10.129.0.1"

    def test_without_gateway(self) -> None:
        out = "10.129.5.5 dev tun0 src 10.129.0.5 uid 1000"
        device, gateway = route_check._parse_route_get_output(out)
        assert device == "tun0"
        assert gateway is None

    def test_empty_output(self) -> None:
        device, gateway = route_check._parse_route_get_output("")
        assert device is None
        assert gateway is None


class TestDeviceIsTunnelShaped:
    @pytest.mark.parametrize("device", ["tun0", "tun1", "tap0", "ppp0"])
    def test_tunnel_shaped(self, device: str) -> None:
        assert route_check._device_is_tunnel_shaped(device) is True

    @pytest.mark.parametrize("device", ["eth0", "wlan0", "docker0", None])
    def test_not_tunnel_shaped(self, device: str | None) -> None:
        assert route_check._device_is_tunnel_shaped(device) is False


# ---------------------------------------------------------------------------
# route_check.py — run_route_get (subprocess mocked, no real `ip` needed)
# ---------------------------------------------------------------------------

class TestRunRouteGet:
    def test_invalid_target_never_calls_subprocess(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called = {"n": 0}

        def _fake_run(*a: object, **kw: object) -> object:
            called["n"] += 1
            raise AssertionError("must not be called for an invalid target")

        monkeypatch.setattr(route_check.subprocess, "run", _fake_run)
        result = route_check.run_route_get("not-an-ip")
        assert result.ok is False
        assert "not a valid" in (result.error or "")
        assert called["n"] == 0

    def test_success_via_tunnel(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
            assert argv == ["ip", "route", "get", "10.129.5.5"]
            return subprocess.CompletedProcess(
                argv, 0, stdout="10.129.5.5 dev tun0 src 10.129.0.5\n", stderr="",
            )

        monkeypatch.setattr(route_check.subprocess, "run", _fake_run)
        result = route_check.run_route_get("10.129.5.5")
        assert result.ok is True
        assert result.would_use_route is True
        assert result.device == "tun0"

    def test_success_not_via_tunnel(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                argv, 0, stdout="8.8.8.8 via 172.17.0.1 dev eth0 src 172.17.0.5\n", stderr="",
            )

        monkeypatch.setattr(route_check.subprocess, "run", _fake_run)
        result = route_check.run_route_get("8.8.8.8")
        assert result.ok is True
        assert result.would_use_route is False
        assert result.device == "eth0"

    def test_nonzero_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 2, stdout="", stderr="Network is unreachable")

        monkeypatch.setattr(route_check.subprocess, "run", _fake_run)
        result = route_check.run_route_get("10.129.5.5")
        assert result.ok is False
        assert "unreachable" in (result.error or "")

    def test_missing_ip_binary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*a: object, **kw: object) -> object:
            raise FileNotFoundError()

        monkeypatch.setattr(route_check.subprocess, "run", _fake_run)
        result = route_check.run_route_get("10.129.5.5")
        assert result.ok is False
        assert "not found" in (result.error or "")

    def test_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*a: object, **kw: object) -> object:
            raise subprocess.TimeoutExpired(cmd="ip", timeout=5.0)

        monkeypatch.setattr(route_check.subprocess, "run", _fake_run)
        result = route_check.run_route_get("10.129.5.5")
        assert result.ok is False
        assert "timed out" in (result.error or "")

    def test_result_to_dict_has_all_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 0, stdout="10.129.5.5 dev tun0\n", stderr="")

        monkeypatch.setattr(route_check.subprocess, "run", _fake_run)
        result = route_check.run_route_get("10.129.5.5")
        d = result.to_dict()
        assert set(d.keys()) == {"target", "ok", "would_use_route", "device", "gateway", "raw_output", "error"}

    def test_never_uses_shell(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
            captured["shell"] = kw.get("shell")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(route_check.subprocess, "run", _fake_run)
        route_check.run_route_get("10.129.5.5")
        assert captured["shell"] is False


# ---------------------------------------------------------------------------
# connect_check.py — port validation
# ---------------------------------------------------------------------------

class TestValidatePort:
    def test_valid_port(self) -> None:
        assert connect_check.validate_port("23") == 23
        assert connect_check.validate_port(23) == 23

    def test_min_and_max_boundaries(self) -> None:
        assert connect_check.validate_port(1) == 1
        assert connect_check.validate_port(65535) == 65535

    def test_zero_rejected(self) -> None:
        with pytest.raises(connect_check.InvalidPortError):
            connect_check.validate_port(0)

    def test_out_of_range_rejected(self) -> None:
        with pytest.raises(connect_check.InvalidPortError):
            connect_check.validate_port(65536)

    def test_non_numeric_rejected(self) -> None:
        with pytest.raises(connect_check.InvalidPortError):
            connect_check.validate_port("not-a-port")

    def test_error_is_value_error(self) -> None:
        assert issubclass(connect_check.InvalidPortError, ValueError)


# ---------------------------------------------------------------------------
# connect_check.py — run_connect_check (real loopback sockets for the
# deterministic connected/refused cases; monkeypatched sockets for
# timeout/unreachable, which are not reliably reproducible in a sandboxed
# test environment without a real network path).
# ---------------------------------------------------------------------------

class TestRunConnectCheck:
    def test_invalid_target_never_opens_a_socket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_socket(*a: object, **kw: object) -> object:
            raise AssertionError("must not open a socket for an invalid target")

        monkeypatch.setattr(connect_check.socket, "socket", _fake_socket)
        result = connect_check.run_connect_check("not-an-ip", 23)
        assert result.ok is False
        assert result.outcome == "invalid_target"

    def test_invalid_port_never_opens_a_socket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_socket(*a: object, **kw: object) -> object:
            raise AssertionError("must not open a socket for an invalid port")

        monkeypatch.setattr(connect_check.socket, "socket", _fake_socket)
        result = connect_check.run_connect_check("10.129.5.5", 99999)
        assert result.ok is False
        assert result.outcome == "invalid_port"

    def test_connected_via_real_loopback_listener(self) -> None:
        import socket as socket_module

        listener = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            result = connect_check.run_connect_check("127.0.0.1", port, timeout_seconds=2.0)
            assert result.ok is True
            assert result.outcome == "connected"
            assert result.errno is None
        finally:
            listener.close()

    def test_refused_via_real_closed_loopback_port(self) -> None:
        import socket as socket_module

        # Bind to get a genuinely free ephemeral port, then close it
        # immediately so nothing is listening — a connect attempt to it
        # reliably yields ECONNREFUSED on both Linux and macOS.
        probe = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        result = connect_check.run_connect_check("127.0.0.1", port, timeout_seconds=2.0)
        assert result.ok is False
        assert result.outcome == "refused"
        assert result.errno_name == "ECONNREFUSED"

    def test_timeout_outcome_classification(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import socket as socket_module

        class _FakeSocket:
            def settimeout(self, value: float) -> None:
                pass

            def connect(self, addr: tuple[str, int]) -> None:
                raise socket_module.timeout("timed out")

            def close(self) -> None:
                pass

        monkeypatch.setattr(connect_check.socket, "socket", lambda *a, **kw: _FakeSocket())
        result = connect_check.run_connect_check("10.129.156.9", 23, timeout_seconds=0.1)
        assert result.ok is False
        assert result.outcome == "timeout"
        assert result.errno is None

    def test_unreachable_outcome_classification(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regression test for the reported repository investigation: a
        route that resolves in the routing table can still fail to
        connect with EHOSTUNREACH ('No route to host') — the connect
        diagnostic must classify this distinctly from a timeout."""
        import errno as errno_module

        class _FakeSocket:
            def settimeout(self, value: float) -> None:
                pass

            def connect(self, addr: tuple[str, int]) -> None:
                raise OSError(errno_module.EHOSTUNREACH, "No route to host")

            def close(self) -> None:
                pass

        monkeypatch.setattr(connect_check.socket, "socket", lambda *a, **kw: _FakeSocket())
        result = connect_check.run_connect_check("10.129.156.9", 23)
        assert result.ok is False
        assert result.outcome == "unreachable"
        assert result.errno_name == "EHOSTUNREACH"

    def test_network_unreachable_also_classified_as_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import errno as errno_module

        class _FakeSocket:
            def settimeout(self, value: float) -> None:
                pass

            def connect(self, addr: tuple[str, int]) -> None:
                raise OSError(errno_module.ENETUNREACH, "Network is unreachable")

            def close(self) -> None:
                pass

        monkeypatch.setattr(connect_check.socket, "socket", lambda *a, **kw: _FakeSocket())
        result = connect_check.run_connect_check("10.129.156.9", 23)
        assert result.outcome == "unreachable"

    def test_unrecognized_errno_classified_as_error(self, monkeypatch: pytest.MonkeyPatch) -> None:

        class _FakeSocket:
            def settimeout(self, value: float) -> None:
                pass

            def connect(self, addr: tuple[str, int]) -> None:
                raise OSError(9999, "some unusual failure")

            def close(self) -> None:
                pass

        monkeypatch.setattr(connect_check.socket, "socket", lambda *a, **kw: _FakeSocket())
        result = connect_check.run_connect_check("10.129.156.9", 23)
        assert result.outcome == "error"

    def test_result_to_dict_has_all_fields(self) -> None:
        result = connect_check.run_connect_check("not-an-ip", 23)
        d = result.to_dict()
        assert set(d.keys()) == {
            "target", "port", "ok", "outcome", "errno", "errno_name", "elapsed_seconds", "detail",
        }

    def test_socket_always_closed_even_on_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        closed = {"n": 0}

        class _FakeSocket:
            def settimeout(self, value: float) -> None:
                pass

            def connect(self, addr: tuple[str, int]) -> None:
                raise OSError(1, "boom")

            def close(self) -> None:
                closed["n"] += 1

        monkeypatch.setattr(connect_check.socket, "socket", lambda *a, **kw: _FakeSocket())
        connect_check.run_connect_check("10.129.156.9", 23)
        assert closed["n"] == 1


# ---------------------------------------------------------------------------
# tunnel_status.py — CIDR validation
# ---------------------------------------------------------------------------

class TestValidateCidr:
    def test_valid(self) -> None:
        assert tunnel_status.validate_cidr("10.129.0.0/16") == "10.129.0.0/16"

    def test_malformed_raises(self) -> None:
        with pytest.raises(tunnel_status.CidrValidationError):
            tunnel_status.validate_cidr("not-a-cidr")

    def test_bare_ip_no_prefix_is_treated_as_host_route(self) -> None:
        # ipaddress.ip_network accepts a bare IP as a /32 (or /128) network
        # — legitimate, not an error; a caller wanting a range should pass
        # an explicit prefix.
        assert tunnel_status.validate_cidr("10.129.5.5") == "10.129.5.5/32"

    def test_out_of_range_prefix_raises(self) -> None:
        with pytest.raises(tunnel_status.CidrValidationError):
            tunnel_status.validate_cidr("10.129.0.0/99")

    def test_error_is_value_error(self) -> None:
        assert issubclass(tunnel_status.CidrValidationError, ValueError)


# ---------------------------------------------------------------------------
# tunnel_status.py — pure parsing functions
# ---------------------------------------------------------------------------

class TestFindTunnelInterface:
    def test_finds_up_tun_interface(self) -> None:
        out = "3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 100"
        assert tunnel_status.find_tunnel_interface(out) == "tun0"

    def test_ignores_down_tun_interface(self) -> None:
        out = "3: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 100"
        assert tunnel_status.find_tunnel_interface(out) is None

    def test_ignores_non_tunnel_interfaces(self) -> None:
        out = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000"
        assert tunnel_status.find_tunnel_interface(out) is None

    def test_finds_tap_interface(self) -> None:
        out = "4: tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 100"
        assert tunnel_status.find_tunnel_interface(out) == "tap0"

    def test_no_interfaces_at_all(self) -> None:
        assert tunnel_status.find_tunnel_interface("") is None

    def test_multiple_interfaces_finds_first_up_tunnel(self) -> None:
        out = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\n"
            "3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 100"
        )
        assert tunnel_status.find_tunnel_interface(out) == "tun0"

    def test_real_world_tun0_with_operstate_unknown_is_still_found(self) -> None:
        """Regression test for the Infra Phase 10 readiness bug: a real,
        fully-working OpenVPN tun0 commonly reports `state UNKNOWN` (the
        Linux kernel's operstate is unreliable for NOARP point-to-point
        interfaces — see find_tunnel_interface's own docstring) even
        though the interface is administratively UP and passing traffic.
        A version of this function that required `state == "UP"` exactly
        never matched this real-world shape and reported every genuinely
        ready tunnel as not-ready."""
        out = "4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500"
        assert tunnel_status.find_tunnel_interface(out) == "tun0"

    def test_administratively_down_tunnel_with_unknown_state_is_excluded(self) -> None:
        """A tun interface that is NOT administratively up (no UP flag in
        the brackets) must still be excluded, regardless of what the
        trailing state token says — proves the fix checks the flags
        bracket, not merely "any state token other than DOWN"."""
        out = "4: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc noop state UNKNOWN group default qlen 500"
        assert tunnel_status.find_tunnel_interface(out) is None

    def test_nonzero_unit_number_and_alternate_dev_name(self) -> None:
        """A profile specifying `dev tap5` or a non-default unit number
        must still be detected — the literal name `tun0` is never assumed."""
        out = "5: tap5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 100"
        assert tunnel_status.find_tunnel_interface(out) == "tap5"


class TestRouteMatchesCidr:
    def test_exact_match(self) -> None:
        out = "10.129.0.0/16 dev tun0 proto kernel scope link src 10.10.14.5"
        assert tunnel_status.route_matches_cidr(out, "10.129.0.0/16") is True

    def test_narrower_subnet_matches(self) -> None:
        out = "10.129.5.0/24 dev tun0 proto kernel scope link src 10.10.14.5"
        assert tunnel_status.route_matches_cidr(out, "10.129.0.0/16") is True

    def test_unrelated_route_does_not_match(self) -> None:
        out = "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.5"
        assert tunnel_status.route_matches_cidr(out, "10.129.0.0/16") is False

    def test_default_route_ignored(self) -> None:
        out = "default via 10.10.14.1 dev eth0"
        assert tunnel_status.route_matches_cidr(out, "10.129.0.0/16") is False

    def test_empty_output(self) -> None:
        assert tunnel_status.route_matches_cidr("", "10.129.0.0/16") is False

    def test_malformed_cidr_returns_false_not_raise(self) -> None:
        out = "10.129.0.0/16 dev tun0"
        assert tunnel_status.route_matches_cidr(out, "not-a-cidr") is False

    def test_malformed_route_line_skipped(self) -> None:
        out = "garbage-not-a-route-line\n10.129.0.0/16 dev tun0"
        assert tunnel_status.route_matches_cidr(out, "10.129.0.0/16") is True


# ---------------------------------------------------------------------------
# tunnel_status.py — check_tunnel_status (subprocess mocked)
# ---------------------------------------------------------------------------

class TestCheckTunnelStatus:
    def test_ready_when_both_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
            if "link" in argv:
                return subprocess.CompletedProcess(
                    argv, 0,
                    stdout="3: tun0: <POINTOPOINT,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 100",
                    stderr="",
                )
            return subprocess.CompletedProcess(argv, 0, stdout="10.129.0.0/16 dev tun0", stderr="")

        monkeypatch.setattr(tunnel_status.subprocess, "run", _fake_run)
        status = tunnel_status.check_tunnel_status("10.129.0.0/16")
        assert status.ready is True
        assert status.tunnel_interface_name == "tun0"

    def test_not_ready_when_no_interface(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
            if "link" in argv:
                return subprocess.CompletedProcess(argv, 0, stdout="1: lo: <LOOPBACK> state UNKNOWN", stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="default via 10.10.14.1 dev eth0", stderr="")

        monkeypatch.setattr(tunnel_status.subprocess, "run", _fake_run)
        status = tunnel_status.check_tunnel_status("10.129.0.0/16")
        assert status.ready is False

    def test_ready_with_real_world_operstate_unknown_tunnel(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end regression test for the Infra Phase 10 readiness bug
        report: a real OpenVPN session with 'Initialization Sequence
        Completed', a tun0 interface administratively UP but reporting
        `state UNKNOWN` (the common, real-world Linux operstate for NOARP
        point-to-point devices), and the expected HTB route present, must
        report `ready is True` — not `degraded`."""
        def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
            if "link" in argv:
                return subprocess.CompletedProcess(
                    argv, 0,
                    stdout=(
                        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\n"
                        "4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(
                argv, 0,
                stdout=(
                    "10.129.0.0/16 dev tun0 proto kernel scope link src 10.10.14.23\n"
                    "default via 172.17.0.1 dev eth0"
                ),
                stderr="",
            )

        monkeypatch.setattr(tunnel_status.subprocess, "run", _fake_run)
        status = tunnel_status.check_tunnel_status("10.129.0.0/16")
        assert status.tunnel_interface_present is True
        assert status.tunnel_interface_name == "tun0"
        assert status.route_present is True
        assert status.ready is True

    def test_malformed_cidr_never_calls_subprocess(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*a: object, **kw: object) -> object:
            raise AssertionError("must not be called for a malformed CIDR")

        monkeypatch.setattr(tunnel_status.subprocess, "run", _fake_run)
        status = tunnel_status.check_tunnel_status("not-a-cidr")
        assert status.ready is False
        assert status.error is not None

    def test_missing_ip_binary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(*a: object, **kw: object) -> object:
            raise FileNotFoundError()

        monkeypatch.setattr(tunnel_status.subprocess, "run", _fake_run)
        status = tunnel_status.check_tunnel_status("10.129.0.0/16")
        assert status.ready is False
        assert "not found" in (status.error or "")

    def test_to_dict_has_all_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(tunnel_status.subprocess, "run", _fake_run)
        status = tunnel_status.check_tunnel_status("10.129.0.0/16")
        d = status.to_dict()
        assert set(d.keys()) == {
            "tunnel_interface_present", "tunnel_interface_name",
            "route_present", "route_cidr", "ready", "error",
        }


# ---------------------------------------------------------------------------
# readiness_server.py — real local-only HTTP round trip (loopback only)
# ---------------------------------------------------------------------------

@pytest.fixture()
def _running_server(monkeypatch: pytest.MonkeyPatch):
    """Start the real readiness_server.ReadinessHandler on an ephemeral
    loopback port, with tunnel_status/route_check's subprocess calls
    mocked so no real `ip` binary is required."""
    def _fake_ip_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        if "link" in argv:
            # Deliberately `state UNKNOWN`, not `state UP` — the real-world
            # shape a working OpenVPN tun0 actually reports (Linux's
            # operstate is unreliable for NOARP point-to-point interfaces;
            # see tunnel_status.find_tunnel_interface's own docstring and
            # the Infra Phase 10 readiness bug this fixture regression-tests).
            # Readiness must be derived from the administrative UP flag in
            # the brackets, which this line does set.
            return subprocess.CompletedProcess(
                argv, 0,
                stdout="3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500",
                stderr="",
            )
        if "route" in argv and "get" not in argv:
            return subprocess.CompletedProcess(argv, 0, stdout="10.129.0.0/16 dev tun0", stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="10.129.5.5 dev tun0 src 10.129.0.5", stderr="")

    monkeypatch.setattr(tunnel_status.subprocess, "run", _fake_ip_run)
    monkeypatch.setattr(route_check.subprocess, "run", _fake_ip_run)
    monkeypatch.setenv(readiness_server.ENV_ROUTE_CIDR, "10.129.0.0/16")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), readiness_server.ReadinessHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


class TestReadinessServerHttp:
    def test_health_endpoint_returns_ok_when_ready(self, _running_server: str) -> None:
        import json

        with urllib.request.urlopen(f"{_running_server}/health", timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read())
        assert data["status"] == "ok"
        assert data["service"] == "apex-vpn-readiness"
        assert data["tunnel"] is True
        assert data["route_cidr"] == "10.129.0.0/16"

    def test_health_endpoint_never_exposes_extra_fields(self, _running_server: str) -> None:
        import json

        with urllib.request.urlopen(f"{_running_server}/health", timeout=5) as resp:
            data = json.loads(resp.read())
        assert set(data.keys()) == {"status", "service", "tunnel", "route_cidr"}

    def test_route_check_endpoint_valid_target(self, _running_server: str) -> None:
        import json

        with urllib.request.urlopen(f"{_running_server}/route-check?target=10.129.5.5", timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read())
        assert data["target"] == "10.129.5.5"
        assert data["ok"] is True
        assert data["would_use_route"] is True

    def test_route_check_endpoint_missing_target_is_400(self, _running_server: str) -> None:
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{_running_server}/route-check", timeout=5)
        assert exc_info.value.code == 400

    def test_route_check_endpoint_invalid_target_is_422(self, _running_server: str) -> None:
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{_running_server}/route-check?target=not-an-ip", timeout=5)
        assert exc_info.value.code == 422

    def test_unknown_path_is_404(self, _running_server: str) -> None:
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{_running_server}/unknown", timeout=5)
        assert exc_info.value.code == 404

    def test_no_post_method_supported(self, _running_server: str) -> None:
        """The readiness server is read-only — no POST handler exists at all."""
        assert not hasattr(readiness_server.ReadinessHandler, "do_POST")


# ---------------------------------------------------------------------------
# readiness_server.py — GET /diagnose (combined route + connect check)
# ---------------------------------------------------------------------------

class TestDiagnoseEndpoint:
    def test_missing_target_is_400(self, _running_server: str) -> None:
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{_running_server}/diagnose?port=23", timeout=5)
        assert exc_info.value.code == 400

    def test_missing_port_is_400(self, _running_server: str) -> None:
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{_running_server}/diagnose?target=10.129.156.9", timeout=5)
        assert exc_info.value.code == 400

    def test_combines_route_and_connect_results(
        self, _running_server: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The load-bearing shape test: /diagnose must return BOTH a route
        lookup and a connect result, and the two must be independently
        interpretable — this is what lets an operator see 'route resolves
        via tun0' AND 'connect got EHOSTUNREACH' in the same response,
        exactly the discrepancy reported in the repository investigation
        this endpoint was added to diagnose."""
        import json

        def _fake_connect_check(target: str, port: object, **kw: object) -> connect_check.ConnectCheckResult:
            return connect_check.ConnectCheckResult(
                target=target, port=int(port), ok=False, outcome="unreachable",
                errno=113, errno_name="EHOSTUNREACH", elapsed_seconds=3.34,
                detail="[Errno 113] No route to host",
            )

        monkeypatch.setattr(readiness_server, "run_connect_check", _fake_connect_check)
        with urllib.request.urlopen(
            f"{_running_server}/diagnose?target=10.129.156.9&port=23", timeout=5,
        ) as resp:
            assert resp.status == 200
            data = json.loads(resp.read())

        assert set(data.keys()) == {"route", "connect"}
        assert data["route"]["target"] == "10.129.156.9"
        assert data["route"]["would_use_route"] is True  # from the fixture's fake `ip route get`
        assert data["connect"]["outcome"] == "unreachable"
        assert data["connect"]["errno_name"] == "EHOSTUNREACH"
        assert data["connect"]["ok"] is False

    def test_connected_outcome_end_to_end(
        self, _running_server: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import json

        def _fake_connect_check(target: str, port: object, **kw: object) -> connect_check.ConnectCheckResult:
            return connect_check.ConnectCheckResult(
                target=target, port=int(port), ok=True, outcome="connected",
                errno=None, errno_name=None, elapsed_seconds=0.02, detail="connected",
            )

        monkeypatch.setattr(readiness_server, "run_connect_check", _fake_connect_check)
        with urllib.request.urlopen(
            f"{_running_server}/diagnose?target=10.129.156.9&port=22", timeout=5,
        ) as resp:
            data = json.loads(resp.read())
        assert data["connect"]["outcome"] == "connected"
        assert data["connect"]["ok"] is True

    def test_invalid_port_in_connect_never_crashes_endpoint(
        self, _running_server: str,
    ) -> None:
        """An out-of-range port must be handled as ordinary data by the
        real (unpatched) connect_check, not raise inside the handler."""
        import json

        with urllib.request.urlopen(
            f"{_running_server}/diagnose?target=10.129.156.9&port=99999", timeout=5,
        ) as resp:
            assert resp.status == 200
            data = json.loads(resp.read())
        assert data["connect"]["outcome"] == "invalid_port"
        assert data["connect"]["ok"] is False

    def test_diagnose_never_sends_bearer_token(
        self, _running_server: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unauthenticated by design, matching /health and /route-check —
        no Authorization header is ever required or checked. The connect
        step is patched so this test exercises only the auth-free routing
        of the endpoint, not a real network attempt (real connectivity is
        already covered by the loopback-socket tests in TestRunConnectCheck)."""
        import urllib.request as urllib_request

        def _fake_connect_check(target: str, port: object, **kw: object) -> connect_check.ConnectCheckResult:
            return connect_check.ConnectCheckResult(
                target=target, port=int(port), ok=True, outcome="connected",
                errno=None, errno_name=None, elapsed_seconds=0.01, detail="connected",
            )

        monkeypatch.setattr(readiness_server, "run_connect_check", _fake_connect_check)
        req = urllib_request.Request(f"{_running_server}/diagnose?target=10.129.156.9&port=23")
        with urllib_request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
