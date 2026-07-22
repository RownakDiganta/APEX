# test_health.py
# Tests for GET /health: succeeds unauthenticated, reports tool availability accurately, exposes no secrets.
from __future__ import annotations

import pytest

from apex_tool_service import allowlist
from apex_tool_service.app import create_app
from tests.apex_tool_service._support import TEST_TOKEN, client_for, make_settings


async def test_health_succeeds_without_authentication() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.get("/health")
    assert r.status_code == 200


async def test_health_reports_service_name_and_status() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.get("/health")
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "apex-tool-service"


async def test_health_accurately_reports_available_test_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(allowlist.ALLOWED_TOOLS, "test-available-tool", "python3")
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.get("/health")
    assert r.json()["tools"]["test-available-tool"] is True


async def test_health_accurately_reports_missing_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        allowlist.ALLOWED_TOOLS,
        "test-missing-tool",
        "_apex_tool_service_definitely_nonexistent_binary_xyz",
    )
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.get("/health")
    assert r.json()["tools"]["test-missing-tool"] is False


async def test_health_does_not_expose_service_token() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.get("/health")
    raw = r.text
    assert TEST_TOKEN not in raw


async def test_health_does_not_expose_env_or_internal_paths() -> None:
    app = create_app(make_settings())
    async with client_for(app) as client:
        r = await client.get("/health")
    body = r.json()
    # Phase 22 — "bounded_file_read" is a static capability flag only (the
    # endpoint exists); it never reads a file, validates a path, or exposes
    # allowed paths/basenames/executables.
    assert set(body.keys()) == {"status", "service", "tools", "bounded_file_read"}
    assert isinstance(body["bounded_file_read"], bool)
    for value in body["tools"].values():
        assert isinstance(value, bool)
