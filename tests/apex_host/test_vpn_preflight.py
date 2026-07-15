# test_vpn_preflight.py
# Tests for Infra Phase 10's VPN preflight checks in apex_host/eval/preflight.py — check_htb_profile_configured, check_vpn_readiness, run_vpn_checks, and their wiring into run_local_checks/run_smoke_checks.
"""Infra Phase 10 VPN preflight tests.

Mirrors the established pattern in `tests/apex_host/test_eval_preflight.py`
(Infra Phase 9): `httpx.MockTransport`-backed clients for HTTP-touching
checks, `tmp_path` for filesystem-touching checks. Every test here asserts
that the *default* (no VPN configured) path remains completely inert —
zero network calls, zero blocking checks — since that is the invariant
this whole section of the codebase must never violate.
"""
from __future__ import annotations

import httpx
import pytest

from apex_host.config import ApexConfig
from apex_host.eval.preflight import (
    PreflightCheck,
    check_htb_profile_configured,
    check_vpn_readiness,
    run_local_checks,
    run_smoke_checks,
    run_vpn_checks,
)


def _vpn_client(handler) -> httpx.AsyncClient:  # type: ignore[no-untyped-def]
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _health_payload(*, status: str = "ok", tunnel: bool = True, route_cidr: str = "10.129.0.0/16") -> dict[str, object]:
    return {"status": status, "service": "apex-vpn-readiness", "tunnel": tunnel, "route_cidr": route_cidr}


# ---------------------------------------------------------------------------
# check_htb_profile_configured
# ---------------------------------------------------------------------------

class TestCheckHtbProfileConfigured:
    def test_unconfigured_is_soft_pass_by_default(self) -> None:
        check = check_htb_profile_configured(None)
        assert check.passed is True
        assert check.required is False

    def test_unconfigured_is_hard_fail_when_required(self) -> None:
        check = check_htb_profile_configured(None, required=True)
        assert check.passed is False
        assert check.required is True

    def test_configured_missing_file_is_hard_fail_regardless_of_required(self) -> None:
        check = check_htb_profile_configured("/nonexistent/path/htb.ovpn", required=False)
        assert check.passed is False
        assert check.required is True

    def test_configured_valid_file_passes(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        profile = tmp_path / "htb.ovpn"
        profile.write_text("client\ndev tun\n")
        check = check_htb_profile_configured(str(profile))
        assert check.passed is True
        assert check.required is True

    def test_configured_unreadable_file_fails(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        import os
        import stat

        profile = tmp_path / "htb.ovpn"
        profile.write_text("client\n")
        profile.chmod(0)
        try:
            if os.access(profile, os.R_OK):
                pytest.skip("running as a user that bypasses file permissions (e.g. root)")
            check = check_htb_profile_configured(str(profile))
            assert check.passed is False
        finally:
            profile.chmod(stat.S_IRWXU)

    def test_never_reads_file_content(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """Even a file containing what looks like credential material must
        never appear in the check's own detail message."""
        profile = tmp_path / "htb.ovpn"
        profile.write_text("<ca>\nSUPER-SECRET-CERT-MATERIAL\n</ca>\n")
        check = check_htb_profile_configured(str(profile))
        assert "SUPER-SECRET-CERT-MATERIAL" not in check.detail

    def test_detail_never_contains_full_path_only_basename(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        profile = tmp_path / "htb.ovpn"
        profile.write_text("client\n")
        check = check_htb_profile_configured(str(profile))
        assert str(tmp_path) not in check.detail
        assert "htb.ovpn" in check.detail


# ---------------------------------------------------------------------------
# check_vpn_readiness
# ---------------------------------------------------------------------------

class TestCheckVpnReadiness:
    @pytest.mark.asyncio
    async def test_none_url_returns_empty_list_no_network_call(self) -> None:
        called = {"n": 0}

        async def handler(request: httpx.Request) -> httpx.Response:
            called["n"] += 1
            return httpx.Response(200, json=_health_payload())

        async with _vpn_client(handler) as client:
            checks = await check_vpn_readiness(None, client=client)
        assert checks == []
        assert called["n"] == 0

    @pytest.mark.asyncio
    async def test_malformed_url_fails_without_network_call(self) -> None:
        called = {"n": 0}

        async def handler(request: httpx.Request) -> httpx.Response:
            called["n"] += 1
            return httpx.Response(200, json=_health_payload())

        async with _vpn_client(handler) as client:
            checks = await check_vpn_readiness("not-a-url", client=client)
        assert len(checks) == 1
        assert checks[0].passed is False
        assert called["n"] == 0

    @pytest.mark.asyncio
    async def test_ready_tunnel_produces_two_passing_checks(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_health_payload(tunnel=True, route_cidr="10.129.0.0/16"))

        async with _vpn_client(handler) as client:
            checks = await check_vpn_readiness(
                "http://vpn:8090", expected_route_cidr="10.129.0.0/16", client=client,
            )
        assert len(checks) == 2
        assert all(c.passed for c in checks)
        names = {c.name for c in checks}
        assert names == {"VPN service reachable", "VPN tunnel/route ready"}

    @pytest.mark.asyncio
    async def test_tunnel_not_ready_fails_second_check_only(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_health_payload(status="degraded", tunnel=False))

        async with _vpn_client(handler) as client:
            checks = await check_vpn_readiness("http://vpn:8090", client=client)
        assert len(checks) == 2
        service_check, tunnel_check = checks
        assert service_check.passed is True
        assert tunnel_check.passed is False

    @pytest.mark.asyncio
    async def test_cidr_mismatch_fails_tunnel_check(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_health_payload(tunnel=True, route_cidr="172.16.0.0/12"))

        async with _vpn_client(handler) as client:
            checks = await check_vpn_readiness(
                "http://vpn:8090", expected_route_cidr="10.129.0.0/16", client=client,
            )
        tunnel_check = checks[1]
        assert tunnel_check.passed is False
        assert "172.16.0.0/12" in tunnel_check.detail

    @pytest.mark.asyncio
    async def test_unreachable_service_fails(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        async with _vpn_client(handler) as client:
            checks = await check_vpn_readiness("http://vpn:8090", client=client)
        assert len(checks) == 1
        assert checks[0].passed is False
        assert checks[0].name == "VPN service reachable"

    @pytest.mark.asyncio
    async def test_non_200_status_fails(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, json={"detail": "unavailable"})

        async with _vpn_client(handler) as client:
            checks = await check_vpn_readiness("http://vpn:8090", client=client)
        assert len(checks) == 1
        assert checks[0].passed is False

    @pytest.mark.asyncio
    async def test_non_json_body_fails(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not json")

        async with _vpn_client(handler) as client:
            checks = await check_vpn_readiness("http://vpn:8090", client=client)
        assert len(checks) == 1
        assert checks[0].passed is False

    @pytest.mark.asyncio
    async def test_wrong_service_name_fails(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": "ok", "service": "some-other-service", "tunnel": True, "route_cidr": "x"})

        async with _vpn_client(handler) as client:
            checks = await check_vpn_readiness("http://vpn:8090", client=client)
        assert len(checks) == 1
        assert checks[0].passed is False

    @pytest.mark.asyncio
    async def test_never_sends_bearer_token(self) -> None:
        """The VPN readiness endpoint is unauthenticated by design — no
        Authorization header should ever be sent."""
        captured: dict[str, object] = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            captured["auth_header"] = request.headers.get("authorization")
            return httpx.Response(200, json=_health_payload())

        async with _vpn_client(handler) as client:
            await check_vpn_readiness("http://vpn:8090", client=client)
        assert captured["auth_header"] is None

    @pytest.mark.asyncio
    async def test_never_calls_route_check_endpoint(self) -> None:
        """Automatic preflight must never call /route-check — that
        endpoint is manual-only (apex_host/eval/vpn_route_check.py)."""
        paths_hit: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            paths_hit.append(request.url.path)
            return httpx.Response(200, json=_health_payload())

        async with _vpn_client(handler) as client:
            await check_vpn_readiness("http://vpn:8090", client=client)
        assert paths_hit == ["/health"]


# ---------------------------------------------------------------------------
# run_vpn_checks — config-driven wrapper
# ---------------------------------------------------------------------------

class TestRunVpnChecks:
    @pytest.mark.asyncio
    async def test_default_config_produces_no_checks(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        checks = await run_vpn_checks(config)
        assert checks == []

    @pytest.mark.asyncio
    async def test_configured_url_triggers_real_shaped_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.eval.preflight as preflight_mod

        captured: dict[str, object] = {}

        async def _fake_check_vpn_readiness(url, **kwargs):  # type: ignore[no-untyped-def]
            captured["url"] = url
            captured["expected_route_cidr"] = kwargs.get("expected_route_cidr")
            captured["timeout_seconds"] = kwargs.get("timeout_seconds")
            return [PreflightCheck(name="VPN service reachable", passed=True, detail="ok")]

        monkeypatch.setattr(preflight_mod, "check_vpn_readiness", _fake_check_vpn_readiness)
        config = ApexConfig(
            target="10.0.0.1", vpn_service_url="http://vpn:8090",
            htb_route_cidr="10.129.0.0/16", vpn_health_timeout_seconds=7.0,
        )
        checks = await run_vpn_checks(config)
        assert len(checks) == 1
        assert captured["url"] == "http://vpn:8090"
        assert captured["expected_route_cidr"] == "10.129.0.0/16"
        assert captured["timeout_seconds"] == 7.0


# ---------------------------------------------------------------------------
# Wiring: run_local_checks includes check_htb_profile_configured;
# run_smoke_checks includes VPN readiness only when configured.
# ---------------------------------------------------------------------------

class TestWiringIntoAggregateRunners:
    def test_run_local_checks_includes_htb_profile_check(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        config = ApexConfig(target="10.0.0.1")
        checks = run_local_checks(config, default_report_dir=str(tmp_path))
        names = [c.name for c in checks]
        assert "HTB profile configured" in names

    @pytest.mark.asyncio
    async def test_run_smoke_checks_default_config_has_no_vpn_checks(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
        """The default (no vpn_service_url) smoke pass must not include
        any VPN-named check — proving run_smoke_checks' behavior is
        byte-for-byte unaffected by this phase's additions when VPN is
        not configured."""
        import apex_host.eval.preflight as preflight_mod

        async def _fake_health(*a, **kw):  # type: ignore[no-untyped-def]
            return PreflightCheck(name="Kali health", passed=True, detail="ok")

        async def _fake_smoke(*a, **kw):  # type: ignore[no-untyped-def]
            return PreflightCheck(name="remote tool smoke", passed=True, detail="ok")

        monkeypatch.setattr(preflight_mod, "check_tool_service_health", _fake_health)
        monkeypatch.setattr(preflight_mod, "check_remote_smoke", _fake_smoke)

        config = ApexConfig(target="10.0.0.1", tool_backend="remote", tool_service_url="http://kali:8080")
        result = await run_smoke_checks(config, default_report_dir=str(tmp_path))
        names = [c.name for c in result.checks]
        assert not any("VPN" in n for n in names)

    @pytest.mark.asyncio
    async def test_run_smoke_checks_with_vpn_configured_includes_vpn_checks(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
        import apex_host.eval.preflight as preflight_mod

        async def _fake_health(*a, **kw):  # type: ignore[no-untyped-def]
            return PreflightCheck(name="Kali health", passed=True, detail="ok")

        async def _fake_smoke(*a, **kw):  # type: ignore[no-untyped-def]
            return PreflightCheck(name="remote tool smoke", passed=True, detail="ok")

        async def _fake_vpn_readiness(url, **kw):  # type: ignore[no-untyped-def]
            return [PreflightCheck(name="VPN service reachable", passed=True, detail="ok")]

        monkeypatch.setattr(preflight_mod, "check_tool_service_health", _fake_health)
        monkeypatch.setattr(preflight_mod, "check_remote_smoke", _fake_smoke)
        monkeypatch.setattr(preflight_mod, "check_vpn_readiness", _fake_vpn_readiness)

        config = ApexConfig(
            target="10.0.0.1", tool_backend="remote", tool_service_url="http://vpn:8080",
            vpn_service_url="http://vpn:8090",
        )
        result = await run_smoke_checks(config, default_report_dir=str(tmp_path))
        names = [c.name for c in result.checks]
        assert "VPN service reachable" in names
