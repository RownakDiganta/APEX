# test_validation.py
# Tests for request validation: unknown tool, raw command field, non-list arguments, size limits, shell metacharacters, control characters, timeout bounds.
from __future__ import annotations

import pytest

from apex_tool_service.app import create_app
from apex_tool_service.settings import ServiceSettings
from apex_tool_service.validation import (
    RequestValidationError,
    resolve_and_validate_tool,
    resolve_timeout,
    validate_arguments,
    validate_stdin,
)
from tests.apex_tool_service._support import auth_headers, client_for, make_settings

_LIMITS = make_settings(
    max_arguments=4, max_argument_length=16, max_total_argument_bytes=48,
    max_stdin_bytes=32, min_timeout_seconds=2.0, max_timeout_seconds=10.0,
)


# ---------------------------------------------------------------------------
# HTTP-level: POST /v1/execute
# ---------------------------------------------------------------------------

async def test_unknown_tool_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "wget", "arguments": []}, headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_raw_command_field_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"command": "nmap -sV 10.0.0.1"}, headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_command_field_alongside_valid_fields_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute",
            json={"tool": "curl", "arguments": [], "command": "curl && rm -rf /"},
            headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_arguments_must_be_a_list() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "curl", "arguments": "not-a-list"}, headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_malformed_json_body_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", content=b"{not valid json", headers={**auth_headers(), "Content-Type": "application/json"},
        )
    assert r.status_code == 400


async def test_too_many_arguments_rejected() -> None:
    app = create_app(_LIMITS)
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute",
            json={"tool": "curl", "arguments": ["a", "b", "c", "d", "e"]},  # 5 > max_arguments=4
            headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_argument_too_long_rejected() -> None:
    app = create_app(_LIMITS)
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute",
            json={"tool": "curl", "arguments": ["x" * 17]},  # 17 > max_argument_length=16
            headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_total_argument_size_limit_enforced() -> None:
    app = create_app(_LIMITS)
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute",
            # 4 args * 12 chars = 48 bytes total, but individually under 16 chars each — should
            # still trip max_total_argument_bytes=48 boundary when pushed slightly over.
            json={"tool": "curl", "arguments": ["x" * 13, "x" * 13, "x" * 13, "x" * 13]},
            headers=auth_headers(),
        )
    assert r.status_code == 400


@pytest.mark.parametrize("op", [";", "&&", "||", "|", ">>", ">", "<", "$(", "`"])
async def test_shell_metacharacter_rejected(op: str) -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "curl", "arguments": [f"safe{op}unsafe"]}, headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_newline_in_argument_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "curl", "arguments": ["line1\nline2"]}, headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_carriage_return_in_argument_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "curl", "arguments": ["a\rb"]}, headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_null_byte_in_argument_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "curl", "arguments": ["a\x00b"]}, headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_excessive_stdin_rejected() -> None:
    app = create_app(_LIMITS)
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute",
            json={"tool": "curl", "arguments": [], "stdin": "x" * 33},  # 33 > max_stdin_bytes=32
            headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_timeout_below_minimum_rejected() -> None:
    app = create_app(_LIMITS)
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute",
            json={"tool": "curl", "arguments": [], "timeout_seconds": 0.5},  # < min 2.0
            headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_timeout_above_maximum_rejected() -> None:
    app = create_app(_LIMITS)
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute",
            json={"tool": "curl", "arguments": [], "timeout_seconds": 999},  # > max 10.0
            headers=auth_headers(),
        )
    assert r.status_code == 400


async def test_validation_error_does_not_leak_internal_details() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json={"tool": "wget", "arguments": []}, headers=auth_headers(),
        )
    body = r.text
    assert "Traceback" not in body
    assert "asyncio" not in body
    assert __file__ not in body


# ---------------------------------------------------------------------------
# Unit tests: validation.py functions directly
# ---------------------------------------------------------------------------

def test_resolve_and_validate_tool_rejects_unknown() -> None:
    with pytest.raises(RequestValidationError, match="not in the server allowlist"):
        resolve_and_validate_tool("wget")


def test_resolve_and_validate_tool_returns_binary_for_allowed() -> None:
    assert resolve_and_validate_tool("curl") == "curl"


def test_validate_arguments_accepts_within_limits() -> None:
    validate_arguments(["-T4", "127.0.0.1"], make_settings())  # must not raise


def test_validate_stdin_none_is_valid() -> None:
    validate_stdin(None, make_settings())  # must not raise


def test_resolve_timeout_uses_default_when_omitted() -> None:
    settings = ServiceSettings(token="t", default_timeout_seconds=42.0)
    assert resolve_timeout(None, settings) == 42.0


def test_resolve_timeout_rejects_bool() -> None:
    with pytest.raises(RequestValidationError):
        resolve_timeout(True, make_settings())  # type: ignore[arg-type]
