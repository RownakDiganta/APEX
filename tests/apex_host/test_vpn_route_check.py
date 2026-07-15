# test_vpn_route_check.py
# Tests for the manual, operator-invoked apex_host/eval/vpn_route_check.py utility — IP validation, exit codes, and confirmation that it is never wired into any automatic preflight path.
"""Tests for the manual VPN route-lookup utility.

This tool is deliberately excluded from every automatic preflight path
(`apex_host/eval/preflight.py::run_vpn_checks` never calls it — see
`tests/apex_host/test_vpn_preflight.py::test_never_calls_route_check_endpoint`)
and from `apex_host/container_entrypoint.py`'s every mode. These tests
verify its own standalone behavior: strict client-side IP validation
before any HTTP call, and clear exit codes.
"""
from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout

import pytest

from apex_host.eval.vpn_route_check import (
    InvalidTargetError,
    _async_main,
    validate_target_ip,
)


class TestValidateTargetIp:
    def test_valid_ipv4(self) -> None:
        assert validate_target_ip("10.129.5.5") == "10.129.5.5"

    def test_valid_ipv6(self) -> None:
        assert validate_target_ip("::1") == "::1"

    def test_blank_rejected(self) -> None:
        with pytest.raises(InvalidTargetError):
            validate_target_ip("")

    def test_hostname_rejected(self) -> None:
        with pytest.raises(InvalidTargetError):
            validate_target_ip("target.htb")

    def test_cidr_rejected(self) -> None:
        with pytest.raises(InvalidTargetError):
            validate_target_ip("10.129.0.0/16")

    def test_shell_metacharacters_rejected(self) -> None:
        with pytest.raises(InvalidTargetError):
            validate_target_ip("10.129.5.5 && curl evil.com")

    def test_error_is_value_error(self) -> None:
        assert issubclass(InvalidTargetError, ValueError)


class TestAsyncMain:
    @pytest.mark.asyncio
    async def test_invalid_target_exits_2_no_network_attempted(self) -> None:
        """An invalid --target must fail before any HTTP call is even
        constructed — exit code 2, matching this project's convention for
        a malformed-invocation error (distinct from a request failure)."""
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = await _async_main(["--vpn-service-url", "http://vpn:8090", "--target", "not-an-ip"])
        assert code == 2
        assert "not a valid" in err.getvalue()

    @pytest.mark.asyncio
    async def test_unreachable_service_exits_1(self) -> None:
        """A syntactically valid target against an unreachable service
        fails cleanly (bounded, short timeout) with exit code 1 — never a
        raw traceback."""
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = await _async_main([
                "--vpn-service-url", "http://127.0.0.1:1",
                "--target", "10.129.5.5",
                "--timeout", "2",
            ])
        assert code == 1
        assert "could not reach" in err.getvalue()

    @pytest.mark.asyncio
    async def test_missing_required_args_exits_2(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            await _async_main([])
        assert exc_info.value.code == 2

    @pytest.mark.asyncio
    async def test_never_sends_a_request_for_invalid_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.eval.vpn_route_check as module

        async def _boom(*a: object, **kw: object) -> dict[str, object]:
            raise AssertionError("must not query the route-check endpoint for an invalid target")

        monkeypatch.setattr(module, "_query_route_check", _boom)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = await _async_main(["--vpn-service-url", "http://vpn:8090", "--target", "garbage"])
        assert code == 2

    @pytest.mark.asyncio
    async def test_json_output_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.eval.vpn_route_check as module

        async def _fake_query(url: str, target: str, timeout: float) -> dict[str, object]:
            return {
                "target": target, "ok": True, "would_use_route": True,
                "device": "tun0", "gateway": None, "raw_output": "...", "error": None,
            }

        monkeypatch.setattr(module, "_query_route_check", _fake_query)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = await _async_main([
                "--vpn-service-url", "http://vpn:8090", "--target", "10.129.5.5", "--json",
            ])
        assert code == 0
        assert '"would_use_route": true' in out.getvalue()

    @pytest.mark.asyncio
    async def test_text_output_includes_no_packet_disclaimer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.eval.vpn_route_check as module

        async def _fake_query(url: str, target: str, timeout: float) -> dict[str, object]:
            return {
                "target": target, "ok": True, "would_use_route": False,
                "device": "eth0", "gateway": None, "raw_output": "...", "error": None,
            }

        monkeypatch.setattr(module, "_query_route_check", _fake_query)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            await _async_main(["--vpn-service-url", "http://vpn:8090", "--target", "8.8.8.8"])
        assert "does NOT prove" in out.getvalue() or "No packet was sent" in out.getvalue()
