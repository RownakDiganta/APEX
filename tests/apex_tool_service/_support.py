# _support.py
# Shared test helpers for apex_tool_service tests: settings factories and an in-process ASGI HTTP client.
"""Shared helpers for apex_tool_service tests.

Uses ``httpx.AsyncClient`` with ``httpx.ASGITransport`` to drive the FastAPI
app in-process — no real socket, no real server process, no Docker, no
network access. This is the "local HTTP smoke test using an in-process test
client" approach this phase's task brief asks for.
"""
from __future__ import annotations

import contextlib
from typing import AsyncIterator

import httpx
from fastapi import FastAPI

from apex_tool_service.settings import ServiceSettings

# Obvious test-only value — never a real credential, never used outside tests.
TEST_TOKEN = "test-only-token-not-a-real-secret"


def make_settings(**overrides: object) -> ServiceSettings:
    base: dict[str, object] = {"token": TEST_TOKEN}
    base.update(overrides)
    return ServiceSettings(**base)  # type: ignore[arg-type]


@contextlib.asynccontextmanager
async def client_for(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


def auth_headers(token: str = TEST_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
