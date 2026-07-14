# app.py
# FastAPI application factory: GET /health (unauthenticated, no secrets) and POST /v1/execute (bearer-authenticated, allowlisted, argv-only execution).
"""apex_tool_service HTTP application.

Endpoint order of operations for ``POST /v1/execute`` deliberately matches
``docs/kali-tool-service.md`` / this phase's task brief exactly:

    1. Validate authentication.
    2. Validate request structure.
    3. Check the tool allowlist.
    4. Check executable availability. (inside ``executor.execute_tool``)
    5. Validate all arguments.
    6. Enforce timeout bounds.
    7. Execute with argument arrays and shell=False.

To guarantee step 1 happens strictly before step 2 (rather than relying on
FastAPI's automatic body-parameter injection, whose internal ordering
versus header-derived parameters is not a contract this module wants to
depend on), the request body is read and validated *manually*, after the
auth check, using the raw Starlette ``Request`` rather than an
automatically-injected Pydantic parameter.
"""
from __future__ import annotations

import logging

import pydantic
from fastapi import FastAPI, Header, HTTPException, Request

from apex_tool_service.allowlist import tool_availability
from apex_tool_service.audit import (
    log_auth_failure,
    log_execution_result,
    log_request_accepted,
    log_validation_rejected,
    new_correlation_id,
)
from apex_tool_service.auth import AuthStatus, check_bearer_token
from apex_tool_service.executor import execute_tool
from apex_tool_service.models import ExecuteRequest, ExecuteResponse, HealthResponse
from apex_tool_service.settings import ServiceSettings
from apex_tool_service.validation import (
    RequestValidationError,
    resolve_and_validate_tool,
    resolve_timeout,
    validate_arguments,
    validate_stdin,
)

logger = logging.getLogger("apex_tool_service.app")

SERVICE_NAME = "apex-tool-service"


def _format_schema_errors(exc: pydantic.ValidationError) -> list[dict[str, object]]:
    """Bounded, client-safe summary of a Pydantic validation error.

    Includes only field location and message — never Python internals or
    file paths (Pydantic's own ``errors()`` output does not include those,
    but we still project down to a fixed, minimal shape rather than
    forwarding the raw error objects).
    """
    return [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]


def create_app(settings: ServiceSettings | None = None) -> FastAPI:
    """Build the FastAPI application. Pass *settings* explicitly in tests."""
    if settings is None:
        settings = ServiceSettings.from_env()

    app = FastAPI(
        title="APEX Tool Service",
        description="Restricted, allowlisted tool-execution boundary. Not a general remote shell.",
        version="0.1.0",
    )
    app.state.settings = settings

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="ok", service=SERVICE_NAME, tools=tool_availability())

    @app.post("/v1/execute", response_model=ExecuteResponse)
    async def execute(raw_request: Request, authorization: str | None = Header(default=None)) -> ExecuteResponse:
        correlation_id = new_correlation_id()

        # ── 1. Authentication (before touching the body at all) ──────────
        auth_result = check_bearer_token(authorization, settings)
        if auth_result.status is AuthStatus.service_misconfigured:
            logger.warning("execute rejected: no server token configured id=%s", correlation_id)
            raise HTTPException(
                status_code=503,
                detail="tool service is not configured with an authentication token",
            )
        if not auth_result.is_authenticated:
            log_auth_failure(correlation_id, auth_result.status.value)
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")

        # ── 2. Request structure ──────────────────────────────────────────
        try:
            raw_body = await raw_request.json()
        except Exception:  # noqa: BLE001 - any body-decoding failure is a 400, not a 500
            raise HTTPException(status_code=400, detail="request body must be valid JSON") from None
        try:
            req = ExecuteRequest.model_validate(raw_body)
        except pydantic.ValidationError as exc:
            log_validation_rejected(correlation_id, "schema validation failed")
            raise HTTPException(
                status_code=400,
                detail={"message": "invalid request schema", "errors": _format_schema_errors(exc)},
            ) from None

        # ── 3. Allowlist, 5. Arguments, 6. Timeout bounds ─────────────────
        try:
            binary = resolve_and_validate_tool(req.tool)
            validate_arguments(req.arguments, settings)
            validate_stdin(req.stdin, settings)
            timeout = resolve_timeout(req.timeout_seconds, settings)
        except RequestValidationError as exc:
            log_validation_rejected(correlation_id, exc.detail)
            raise HTTPException(status_code=400, detail=exc.detail) from None

        # ── 4. Executable availability + 7. Execution ─────────────────────
        log_request_accepted(correlation_id, req.tool, len(req.arguments), timeout)
        result = await execute_tool(
            tool=req.tool, binary=binary, arguments=req.arguments,
            timeout_seconds=timeout, stdin=req.stdin, settings=settings,
        )
        log_execution_result(correlation_id, req.tool, req.arguments, result)
        return result

    return app


# Alternative standalone-run entrypoint: `uv run uvicorn apex_tool_service.app:app`.
# The primary documented entrypoint is `uv run python -m apex_tool_service`
# (see apex_tool_service/__main__.py) — both construct settings the same way.
app = create_app()
