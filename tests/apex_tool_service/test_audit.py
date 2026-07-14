# test_audit.py
# Tests for audit logging: correlation IDs, bounded argument previews, and that stdin/token are never logged.
from __future__ import annotations

import logging

import pytest

from apex_tool_service.app import create_app
from apex_tool_service.audit import new_correlation_id, preview_arguments
from tests.apex_tool_service._support import auth_headers, client_for, make_settings


def test_new_correlation_id_is_unique() -> None:
    a, b = new_correlation_id(), new_correlation_id()
    assert a != b
    assert len(a) > 0


def test_preview_arguments_truncates_long_single_argument() -> None:
    preview = preview_arguments(["x" * 1000])
    assert len(preview) < 1000


def test_preview_arguments_truncates_many_arguments() -> None:
    preview = preview_arguments(["arg"] * 500)
    assert len(preview) <= 210  # bounded total + ellipsis margin


def test_preview_arguments_short_list_unmodified_content() -> None:
    preview = preview_arguments(["-T4", "127.0.0.1"])
    assert "-T4" in preview
    assert "127.0.0.1" in preview


async def test_full_stdin_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    secret_marker = "STDIN-PAYLOAD-MARKER-should-not-be-logged-in-full-xyz"
    app = create_app(make_settings())
    with caplog.at_level(logging.DEBUG):
        async with client_for(app) as client:
            await client.post(
                "/v1/execute",
                json={"tool": "curl", "arguments": ["--version"], "stdin": secret_marker},
                headers=auth_headers(),
            )
    assert secret_marker not in caplog.text


async def test_execution_audit_log_emitted(caplog: pytest.LogCaptureFixture) -> None:
    app = create_app(make_settings())
    with caplog.at_level(logging.INFO, logger="apex_tool_service.audit"):
        async with client_for(app) as client:
            await client.post(
                "/v1/execute", json={"tool": "curl", "arguments": ["--version"]}, headers=auth_headers(),
            )
    assert "execution_complete" in caplog.text
    assert "execution_accepted" in caplog.text
