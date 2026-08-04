# test_vpn_route_readiness.py
# Regression tests for the HTB VPN routing bug where the container reported healthy (readiness HTTP 200) while target traffic still routed through Docker eth0 — verifies the layered tunnel-readiness (openvpn process / tunnel up / HTB route installed / route egresses via the tunnel) and that the Docker healthcheck now gates on the body's readiness, not merely HTTP 200.
"""Regression tests for the HTB VPN route-readiness fix.

The reported failure: the VPN container reported *healthy*, but
``ip route get <HTB_TARGET>`` inside the VPN namespace still resolved
through Docker ``eth0`` instead of the OpenVPN ``tun0`` tunnel. Root cause:
the Docker ``HEALTHCHECK`` gated on ``GET /health`` returning HTTP 200, but
``/health`` returns 200 unconditionally (tunnel state lives in the JSON
body) — so "healthy" meant only "the readiness HTTP sidecar is listening",
not "HTB traffic is routed through the tunnel". ``check_tunnel_status`` also
never verified the OpenVPN process was alive nor that the matching HTB route
egressed via the tunnel device.

These tests pin the corrected, layered contract. They mock ``ip`` /
``/proc`` output — no Docker daemon, no real ``ip`` binary, no real VPN
profile, no packet. The current HTB target IP is never hard-coded (a static
scan asserts this).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import threading
import types
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_VPN_DIR = _REPO_ROOT / "docker" / "vpn"


def _load_module(name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, _VPN_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


route_check = _load_module("route_check")
tunnel_status = _load_module("tunnel_status")
connect_check = _load_module("connect_check")
readiness_server = _load_module("readiness_server")

_CIDR = "10.129.0.0/16"
# A realistic HTB-shaped target used only to exercise route lookups. NOT the
# reported production target (that must never be hard-coded — see
# TestNoHardcodedTarget). Any address in 10.129.0.0/16 is representative.
_SAMPLE_TARGET = "10.129.42.7"

_LINK_TUN_UP = "3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500"
_LINK_TUN_DOWN = "3: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc fq_codel state DOWN group default qlen 500"
_LINK_NO_TUN = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n"
    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP"
)
_ROUTE_VIA_TUN = "10.129.0.0/16 dev tun0 proto kernel scope link src 10.10.14.23\ndefault via 172.18.0.1 dev eth0"
_ROUTE_NO_HTB = "default via 172.18.0.1 dev eth0\n172.18.0.0/16 dev eth0 proto kernel scope link src 172.18.0.5"
# The exact failure shape: a route that matches the CIDR textually but exits
# via eth0 (would send target traffic OUTSIDE the tunnel).
_ROUTE_VIA_ETH0 = "10.129.0.0/16 via 172.18.0.1 dev eth0\ndefault via 172.18.0.1 dev eth0"


def _mock_ip(monkeypatch: pytest.MonkeyPatch, *, link: str, route: str) -> None:
    def _fake(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        if "link" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=link, stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout=route, stderr="")

    monkeypatch.setattr(tunnel_status.subprocess, "run", _fake)


# ===========================================================================
# Layered readiness — the container must NOT be healthy on the HTTP sidecar alone
# ===========================================================================


class TestLayeredReadiness:
    def test_readiness_server_alone_is_not_healthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Everything below OpenVPN is missing (no process, no tun, no route):
        # the HTTP server answers, but the tunnel is NOT ready.
        _mock_ip(monkeypatch, link=_LINK_NO_TUN, route=_ROUTE_NO_HTB)
        monkeypatch.setattr(tunnel_status, "openvpn_process_running", lambda *a, **k: False)
        status = tunnel_status.check_tunnel_status(_CIDR)
        assert status.ready is False

    def test_missing_openvpn_process_is_unhealthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_ip(monkeypatch, link=_LINK_TUN_UP, route=_ROUTE_VIA_TUN)
        monkeypatch.setattr(tunnel_status, "openvpn_process_running", lambda *a, **k: False)
        status = tunnel_status.check_tunnel_status(_CIDR)
        assert status.ready is False
        assert status.reason == "VPN process is not running"

    def test_missing_tunnel_device_is_unhealthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_ip(monkeypatch, link=_LINK_NO_TUN, route=_ROUTE_NO_HTB)
        monkeypatch.setattr(tunnel_status, "openvpn_process_running", lambda *a, **k: True)
        status = tunnel_status.check_tunnel_status(_CIDR)
        assert status.ready is False
        assert status.tunnel_interface_present is False
        assert "missing" in status.reason.lower()

    def test_tunnel_device_down_is_unhealthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_ip(monkeypatch, link=_LINK_TUN_DOWN, route=_ROUTE_VIA_TUN)
        monkeypatch.setattr(tunnel_status, "openvpn_process_running", lambda *a, **k: True)
        status = tunnel_status.check_tunnel_status(_CIDR)
        assert status.ready is False
        assert status.tunnel_interface_present is True
        assert status.tunnel_interface_up is False
        assert "down" in status.reason.lower()

    def test_tunnel_up_but_no_htb_route_is_unhealthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_ip(monkeypatch, link=_LINK_TUN_UP, route=_ROUTE_NO_HTB)
        monkeypatch.setattr(tunnel_status, "openvpn_process_running", lambda *a, **k: True)
        status = tunnel_status.check_tunnel_status(_CIDR)
        assert status.ready is False
        assert status.route_present is False
        assert "no htb route" in status.reason.lower()

    def test_htb_route_via_eth0_is_unhealthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The exact reported failure: a route matches the CIDR but egresses
        # via eth0 — target traffic would leave OUTSIDE the tunnel.
        _mock_ip(monkeypatch, link=_LINK_TUN_UP, route=_ROUTE_VIA_ETH0)
        monkeypatch.setattr(tunnel_status, "openvpn_process_running", lambda *a, **k: True)
        status = tunnel_status.check_tunnel_status(_CIDR)
        assert status.route_present is True
        assert status.route_via_tunnel is False
        assert status.route_device == "eth0"
        assert status.ready is False
        assert "egresses via" in status.reason.lower()

    def test_all_layers_present_is_healthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_ip(monkeypatch, link=_LINK_TUN_UP, route=_ROUTE_VIA_TUN)
        monkeypatch.setattr(tunnel_status, "openvpn_process_running", lambda *a, **k: True)
        status = tunnel_status.check_tunnel_status(_CIDR)
        assert status.ready is True
        assert status.route_via_tunnel is True
        assert status.route_device == "tun0"
        assert status.reason == "tunnel ready"


# ===========================================================================
# route lookup device classification (would_use_route)
# ===========================================================================


class TestRouteLookupDevice:
    def test_target_via_eth0_would_not_use_route(self, monkeypatch: pytest.MonkeyPatch) -> None:
        out = f"{_SAMPLE_TARGET} via 172.18.0.1 dev eth0 src 172.18.0.5 uid 1000"
        monkeypatch.setattr(
            route_check.subprocess, "run",
            lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout=out, stderr=""),
        )
        result = route_check.run_route_get(_SAMPLE_TARGET)
        assert result.ok is True
        assert result.would_use_route is False
        assert result.device == "eth0"

    def test_target_via_tun0_would_use_route(self, monkeypatch: pytest.MonkeyPatch) -> None:
        out = f"{_SAMPLE_TARGET} via 10.10.14.1 dev tun0 src 10.10.14.23 uid 1000"
        monkeypatch.setattr(
            route_check.subprocess, "run",
            lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout=out, stderr=""),
        )
        result = route_check.run_route_get(_SAMPLE_TARGET)
        assert result.ok is True
        assert result.would_use_route is True
        assert result.device == "tun0"

    def test_parses_realistic_direct_route_get_output(self) -> None:
        # No 'via' gateway (on-link) form.
        device, gateway = route_check._parse_route_get_output(
            f"{_SAMPLE_TARGET} dev tun0 src 10.129.0.5 uid 1000 \n    cache"
        )
        assert device == "tun0"
        assert gateway is None


# ===========================================================================
# find_htb_route — device extraction + policy-routing / multi-table tolerance
# ===========================================================================


class TestFindHtbRoute:
    def test_exact_cidr_via_tunnel(self) -> None:
        present, device = tunnel_status.find_htb_route("10.129.0.0/16 dev tun0", _CIDR)
        assert present is True and device == "tun0"

    def test_cidr_via_eth0_reports_device(self) -> None:
        present, device = tunnel_status.find_htb_route("10.129.0.0/16 via 172.18.0.1 dev eth0", _CIDR)
        assert present is True and device == "eth0"

    def test_narrower_subnet_via_tunnel(self) -> None:
        present, device = tunnel_status.find_htb_route("10.129.42.0/24 dev tun0", _CIDR)
        assert present is True and device == "tun0"

    def test_no_matching_route(self) -> None:
        present, device = tunnel_status.find_htb_route(_ROUTE_NO_HTB, _CIDR)
        assert present is False and device is None

    def test_policy_routing_table_all_output_is_handled(self) -> None:
        # `ip route show table all` interleaves multiple tables; the HTB route
        # (in whichever table) must still be found with its device.
        table_all = (
            "default via 172.18.0.1 dev eth0 table main\n"
            "local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1\n"
            "10.129.0.0/16 dev tun0 table 200 proto static scope link\n"
            "broadcast 172.18.0.0 dev eth0 table local proto kernel scope link src 172.18.0.5"
        )
        present, device = tunnel_status.find_htb_route(table_all, _CIDR)
        assert present is True and device == "tun0"


# ===========================================================================
# openvpn_process_running — /proc scan (fake proc root, no real processes)
# ===========================================================================


class TestOpenvpnProcessScan:
    def test_detects_openvpn(self, tmp_path: pathlib.Path) -> None:
        pid = tmp_path / "1234"
        pid.mkdir()
        (pid / "comm").write_text("openvpn\n")
        assert tunnel_status.openvpn_process_running(str(tmp_path)) is True

    def test_no_openvpn(self, tmp_path: pathlib.Path) -> None:
        pid = tmp_path / "1234"
        pid.mkdir()
        (pid / "comm").write_text("python3\n")
        assert tunnel_status.openvpn_process_running(str(tmp_path)) is False

    def test_missing_proc_root_returns_false(self, tmp_path: pathlib.Path) -> None:
        assert tunnel_status.openvpn_process_running(str(tmp_path / "does-not-exist")) is False

    def test_non_pid_and_unreadable_entries_skipped(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "not-a-pid").mkdir()  # skipped (non-numeric)
        (tmp_path / "999").mkdir()        # no comm file -> skipped, no crash
        assert tunnel_status.openvpn_process_running(str(tmp_path)) is False


# ===========================================================================
# The Docker healthcheck now gates on the body, not merely HTTP 200
# ===========================================================================


@pytest.fixture()
def _degraded_server(monkeypatch: pytest.MonkeyPatch):
    """A running readiness server whose tunnel is NOT ready (no openvpn, no
    tun, no route) — /health still returns HTTP 200 with tunnel=false."""
    _mock_ip(monkeypatch, link=_LINK_NO_TUN, route=_ROUTE_NO_HTB)
    monkeypatch.setattr(tunnel_status, "openvpn_process_running", lambda *a, **k: False)
    monkeypatch.setenv(readiness_server.ENV_ROUTE_CIDR, _CIDR)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), readiness_server.ReadinessHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


class TestHealthcheckGatesOnBody:
    def test_degraded_tunnel_still_returns_http_200(self, _degraded_server: str) -> None:
        # HTTP 200 so preflight can read the body — the service IS reachable.
        with urllib.request.urlopen(f"{_degraded_server}/health", timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read())
        assert data["tunnel"] is False
        assert data["status"] == "degraded"
        assert data["openvpn_running"] is False

    def test_healthcheck_logic_rejects_degraded_body(self, _degraded_server: str) -> None:
        # Mirror the exact Dockerfile HEALTHCHECK logic: gate on body.tunnel,
        # NOT on the HTTP status. A degraded tunnel must be treated unhealthy.
        with urllib.request.urlopen(f"{_degraded_server}/health", timeout=5) as resp:
            body = json.loads(resp.read())
        healthcheck_exit = 0 if body.get("tunnel") is True else 1
        assert healthcheck_exit == 1

    def test_http_200_alone_would_have_falsely_passed_old_check(self, _degraded_server: str) -> None:
        # Demonstrates the ROOT CAUSE: the old healthcheck (status == 200)
        # would have reported this degraded container healthy.
        with urllib.request.urlopen(f"{_degraded_server}/health", timeout=5) as resp:
            old_check_exit = 0 if resp.status == 200 else 1
        assert old_check_exit == 0  # old check falsely healthy
        # ...while the new body-gated check correctly fails (asserted above).


# ===========================================================================
# Secret-safety, no hard-coded target, Dockerfile healthcheck contract
# ===========================================================================


class TestSecretSafetyAndContract:
    def test_reason_never_contains_secret_shaped_content(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The reason/diagnostic must never echo profile content, keys, or env.
        _mock_ip(monkeypatch, link=_LINK_TUN_UP, route=_ROUTE_VIA_ETH0)
        monkeypatch.setattr(tunnel_status, "openvpn_process_running", lambda *a, **k: True)
        status = tunnel_status.check_tunnel_status(_CIDR)
        blob = json.dumps(status.to_dict())
        for marker in ("BEGIN", "PRIVATE KEY", "CERTIFICATE", "password", "auth-user-pass", ".ovpn", "/vpn/"):
            assert marker not in blob

    def test_current_target_ip_not_hardcoded_in_vpn_sources(self) -> None:
        # The reported production target must not appear anywhere in the VPN
        # scripts, the route-check module, or preflight.
        forbidden = "10.129.229.66"
        for path in (
            _VPN_DIR / "tunnel_status.py",
            _VPN_DIR / "readiness_server.py",
            _VPN_DIR / "route_check.py",
            _VPN_DIR / "entrypoint.py",
            _REPO_ROOT / "apex_host" / "eval" / "vpn_route_check.py",
            _REPO_ROOT / "apex_host" / "eval" / "preflight.py",
        ):
            assert forbidden not in path.read_text(), f"{forbidden} hard-coded in {path}"

    def test_dockerfile_healthcheck_gates_on_body_not_status(self) -> None:
        dockerfile = (_VPN_DIR / "Dockerfile").read_text()
        # Strip full-line comments so the negative assertion below inspects
        # the actual instructions, not the explanatory prose (which
        # deliberately mentions the old `.status == 200` bug).
        instructions = "\n".join(
            line for line in dockerfile.splitlines() if not line.lstrip().startswith("#")
        )
        assert "HEALTHCHECK" in instructions
        # The healthcheck CMD must parse the body and gate on tunnel readiness.
        assert "b.get('tunnel')" in instructions
        # The old, root-cause check (HTTP status only) must be gone from the CMD.
        assert ".status == 200" not in instructions
