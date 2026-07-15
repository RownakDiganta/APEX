# test_vpn_scripts.py
# Unit tests for docker/vpn/route_check.py, docker/vpn/tunnel_status.py, and docker/vpn/readiness_server.py — dynamically imported since these are standalone, dependency-free scripts (not an installed Python package). Does not require a Docker daemon or the `ip` binary.
"""Unit tests for the VPN container's support scripts.

These three files are copied into the minimal VPN image standalone (see
``docker/vpn/Dockerfile``) and deliberately have zero dependency on
``apex_host``/``memfabric`` — they are not part of this project's
installed package, so this test file imports them directly from disk via
``importlib.util.spec_from_file_location``.

Covers: CIDR parsing, interface/route-table parsing (pure functions, no
subprocess), route-check IP validation, route-check success/failure/
timeout/missing-binary handling (subprocess mocked via monkeypatch — no
real `ip` binary required, so these tests pass on macOS/CI too), and a
real, local-only HTTP round trip against the readiness server (loopback
only, no packet leaves the test process).
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
            return subprocess.CompletedProcess(
                argv, 0,
                stdout="3: tun0: <POINTOPOINT,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 100",
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
