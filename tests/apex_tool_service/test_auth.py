# test_auth.py
# Tests for POST /v1/execute bearer-token authentication: missing/malformed/wrong/correct token, fail-closed when unconfigured, token never leaked.
from __future__ import annotations

import logging

import pytest

from apex_tool_service.app import create_app
from apex_tool_service.auth import AuthStatus, check_bearer_token
from tests.apex_tool_service._support import TEST_TOKEN, client_for, make_settings

_BODY = {"tool": "curl", "arguments": ["--version"]}


async def test_no_bearer_token_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post("/v1/execute", json=_BODY)
    assert r.status_code == 401


async def test_malformed_header_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json=_BODY, headers={"Authorization": TEST_TOKEN},  # missing "Bearer " prefix
        )
    assert r.status_code == 401


async def test_malformed_header_empty_bearer_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json=_BODY, headers={"Authorization": "Bearer "},
        )
    assert r.status_code == 401


async def test_incorrect_token_rejected() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json=_BODY, headers={"Authorization": "Bearer wrong-token"},
        )
    assert r.status_code == 401


async def test_correct_token_accepted() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json=_BODY, headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        )
    assert r.status_code == 200


async def test_missing_server_token_configuration_fails_closed() -> None:
    """No token configured server-side → every request rejected, regardless of client credential."""
    app = create_app(make_settings(token=None))
    async with client_for(app) as client:
        r_no_creds = await client.post("/v1/execute", json=_BODY)
        r_any_creds = await client.post(
            "/v1/execute", json=_BODY, headers={"Authorization": "Bearer anything-at-all"},
        )
    assert r_no_creds.status_code == 503
    assert r_any_creds.status_code == 503


async def test_missing_server_token_health_still_works() -> None:
    """Fail-closed applies only to /v1/execute — /health must remain reachable."""
    app = create_app(make_settings(token=None))
    async with client_for(app) as client:
        r = await client.get("/health")
    assert r.status_code == 200


async def test_token_never_appears_in_success_response() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json=_BODY, headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        )
    assert TEST_TOKEN not in r.text


async def test_token_never_appears_in_failure_response() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.post(
            "/v1/execute", json=_BODY, headers={"Authorization": "Bearer wrong-token"},
        )
    assert TEST_TOKEN not in r.text
    assert "wrong-token" not in r.text


async def test_token_never_logged_on_failure(caplog: pytest.LogCaptureFixture) -> None:
    app = create_app(make_settings())
    with caplog.at_level(logging.DEBUG):
        async with client_for(app) as client:
            await client.post(
                "/v1/execute", json=_BODY, headers={"Authorization": "Bearer super-secret-wrong-value"},
            )
    assert "super-secret-wrong-value" not in caplog.text


async def test_token_never_logged_on_success(caplog: pytest.LogCaptureFixture) -> None:
    app = create_app(make_settings())
    with caplog.at_level(logging.DEBUG):
        async with client_for(app) as client:
            await client.post(
                "/v1/execute", json=_BODY, headers={"Authorization": f"Bearer {TEST_TOKEN}"},
            )
    assert TEST_TOKEN not in caplog.text


# ---------------------------------------------------------------------------
# check_bearer_token unit tests (auth.py directly — timing-safe comparison,
# every AuthStatus branch)
# ---------------------------------------------------------------------------

def test_check_bearer_token_ok() -> None:
    settings = make_settings()
    result = check_bearer_token(f"Bearer {TEST_TOKEN}", settings)
    assert result.status is AuthStatus.ok
    assert result.is_authenticated is True


def test_check_bearer_token_missing_header() -> None:
    result = check_bearer_token(None, make_settings())
    assert result.status is AuthStatus.missing_header


def test_check_bearer_token_malformed() -> None:
    result = check_bearer_token("Basic abc123", make_settings())
    assert result.status is AuthStatus.malformed_header


def test_check_bearer_token_invalid() -> None:
    result = check_bearer_token("Bearer nope", make_settings())
    assert result.status is AuthStatus.invalid_token


def test_check_bearer_token_service_misconfigured() -> None:
    result = check_bearer_token(f"Bearer {TEST_TOKEN}", make_settings(token=None))
    assert result.status is AuthStatus.service_misconfigured
    assert result.is_authenticated is False
