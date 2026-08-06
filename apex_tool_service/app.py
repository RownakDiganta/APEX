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
    log_bounded_read_accepted,
    log_bounded_read_result,
    log_execution_result,
    log_ftp_read_accepted,
    log_ftp_read_result,
    log_ftp_validate_accepted,
    log_ftp_validate_result,
    log_request_accepted,
    log_validation_rejected,
    new_correlation_id,
)
from apex_tool_service.auth import AuthStatus, check_bearer_token
from apex_tool_service.executor import (
    execute_bounded_file_read,
    execute_ftp_read,
    execute_ftp_validate,
    execute_tool,
)
from apex_tool_service.models import (
    ExecuteRequest,
    ExecuteResponse,
    FtpReadRequest,
    FtpReadResponse,
    FtpValidateRequest,
    FtpValidateResponse,
    HealthResponse,
    ReadBoundedFileRequest,
    ReadBoundedFileResponse,
)
from apex_tool_service.settings import ServiceSettings
from apex_tool_service.validation import (
    RequestValidationError,
    resolve_and_validate_tool,
    resolve_bounded_read_limits,
    resolve_ftp_read_max_bytes,
    resolve_ftp_validate_timeout,
    resolve_timeout,
    validate_arguments,
    validate_bounded_path,
    validate_ftp_credentials,
    validate_ftp_operation,
    validate_ftp_port,
    validate_stdin,
    validate_target_authorized,
)

logger = logging.getLogger("apex_tool_service.app")

SERVICE_NAME = "apex-tool-service"

#: Phase 22 — fixed, generic, sanitized messages per bounded-file-read
#: error category. Never derived from raw stderr/exception text — always
#: one of these fixed phrases, so a caller can never receive anything
#: beyond a stable, non-sensitive category description.
_ERROR_CODE_MESSAGES: dict[str, str] = {
    "backend_unavailable": "the bounded-read executable is unavailable on this host",
    "timeout": "the bounded read did not complete within the allotted timeout",
    "oversized_output": "the file content exceeds the maximum bounded output size",
    "file_not_found": "the requested path does not exist",
    "permission_denied": "the requested path could not be read (permission denied)",
    "invalid_path": "the requested path is not a readable regular file",
    "process_failed": "the bounded read could not be completed",
    "dry_run": "dry-run: no process launched",
}

#: §28.16 — fixed, generic, sanitized messages per FTP-validate error category.
#: Never derived from raw exception text (the one exception is the redacted
#: auth-rejected server response, which is set as ``sanitized_error`` directly).
_FTP_ERROR_CODE_MESSAGES: dict[str, str] = {
    "connect_timeout": "the FTP connection did not complete within the timeout",
    "connection_failed": "the FTP connection could not be established",
    "auth_rejected": "the FTP server rejected the credentials",
    "auth_timeout": "the FTP login did not complete within the timeout",
    "protocol_error": "an FTP protocol error occurred during login",
    "command_timeout": "the FTP validation operation timed out",
    "command_failed": "the FTP validation operation failed",
    "file_not_found": "the requested file does not exist or is not readable",
    "oversized_output": "the file exceeds the maximum bounded read size",
    "dry_run": "dry-run: no login attempted",
    "success": "",
}


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
        # Static capability flag only — never reads a file, validates a
        # path, or exposes allowed paths/basenames.
        return HealthResponse(
            status="ok", service=SERVICE_NAME, tools=tool_availability(),
            bounded_file_read=True, ftp_validate=True, ftp_read=True,
        )

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

    @app.post("/v1/bounded-file-read", response_model=ReadBoundedFileResponse)
    async def read_bounded_file(
        raw_request: Request, authorization: str | None = Header(default=None),
    ) -> ReadBoundedFileResponse:
        """Dedicated, structured bounded-file-read operation (Phase 22).

        Deliberately NOT a generalisation of ``/v1/execute`` — it never
        consults ``ALLOWED_TOOLS``, never accepts a ``tool``/``arguments``/
        ``command`` field, and internally constructs the one fixed
        ``cat -- <path>`` argv itself (see
        ``apex_tool_service/executor.py::execute_bounded_file_read``). Order
        of operations mirrors ``/v1/execute`` exactly: authenticate, parse,
        validate (schema, then target authorization, then path, then
        limits), execute, audit, respond.
        """
        correlation_id = new_correlation_id()

        # ── 1. Authentication ──────────────────────────────────────────────
        auth_result = check_bearer_token(authorization, settings)
        if auth_result.status is AuthStatus.service_misconfigured:
            logger.warning("bounded_read rejected: no server token configured id=%s", correlation_id)
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
            req = ReadBoundedFileRequest.model_validate(raw_body)
        except pydantic.ValidationError as exc:
            log_validation_rejected(correlation_id, "schema validation failed")
            raise HTTPException(
                status_code=400,
                detail={"message": "invalid request schema", "errors": _format_schema_errors(exc)},
            ) from None

        # ── 3. Target authorization, path validation, limit resolution ────
        try:
            validate_target_authorized(req.target, authorized_cidrs=settings.authorized_cidrs)
            validate_bounded_path(req.path, allowed_basenames=settings.allowed_flag_basenames)
            timeout_seconds, max_output_bytes = resolve_bounded_read_limits(
                req.timeout_seconds, req.max_output_bytes, settings,
            )
        except RequestValidationError as exc:
            log_validation_rejected(correlation_id, exc.detail)
            raise HTTPException(status_code=400, detail=exc.detail) from None

        basename = req.path.rsplit("/", 1)[-1]

        # ── 4. Dry-run short-circuit (defense in depth) ────────────────────
        if req.dry_run:
            log_bounded_read_accepted(correlation_id, req.target, basename, timeout_seconds, max_output_bytes)
            logger.info("bounded_read_dry_run id=%s target=%s basename=%s", correlation_id, req.target, basename)
            return ReadBoundedFileResponse(
                ok=False, error_code="dry_run", sanitized_error=_ERROR_CODE_MESSAGES["dry_run"],
            )

        # ── 5. Execution ───────────────────────────────────────────────────
        log_bounded_read_accepted(correlation_id, req.target, basename, timeout_seconds, max_output_bytes)
        result = await execute_bounded_file_read(
            path=req.path, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
        )
        log_bounded_read_result(correlation_id, req.target, basename, result)

        return ReadBoundedFileResponse(
            ok=result.ok,
            output=result.output,
            error_code=result.error_code,
            sanitized_error=_ERROR_CODE_MESSAGES.get(result.error_code, result.error_code) if result.error_code else None,
            return_code=result.return_code,
            bytes_received=result.bytes_received,
            oversized=result.oversized,
            timed_out=result.timed_out,
            duration_ms=result.duration_seconds * 1000.0,
        )

    @app.post("/v1/ftp-validate", response_model=FtpValidateResponse)
    async def ftp_validate(
        raw_request: Request, authorization: str | None = Header(default=None),
    ) -> FtpValidateResponse:
        """Dedicated, structured bounded FTP credential-validation (§28.16).

        Runs on the Kali/VPN side where the target is reachable (apex has no VPN
        route). Deliberately NOT ``/v1/execute``: no ``tool``/``arguments``, no
        binary allowlist consulted — the service alone runs ONE ftplib login +
        one harmless PWD/NOOP + close. Order of operations mirrors
        ``/v1/bounded-file-read`` exactly: authenticate, parse, validate (target,
        port, credentials, operation, timeouts), dry-run short-circuit, execute,
        audit, respond. The password is used only for the single login attempt
        and is NEVER logged or returned.
        """
        correlation_id = new_correlation_id()

        auth_result = check_bearer_token(authorization, settings)
        if auth_result.status is AuthStatus.service_misconfigured:
            logger.warning("ftp_validate rejected: no server token configured id=%s", correlation_id)
            raise HTTPException(status_code=503, detail="tool service is not configured with an authentication token")
        if not auth_result.is_authenticated:
            log_auth_failure(correlation_id, auth_result.status.value)
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")

        try:
            raw_body = await raw_request.json()
        except Exception:  # noqa: BLE001 - any body-decoding failure is a 400, not a 500
            raise HTTPException(status_code=400, detail="request body must be valid JSON") from None
        try:
            req = FtpValidateRequest.model_validate(raw_body)
        except pydantic.ValidationError as exc:
            log_validation_rejected(correlation_id, "schema validation failed")
            raise HTTPException(
                status_code=400,
                detail={"message": "invalid request schema", "errors": _format_schema_errors(exc)},
            ) from None

        try:
            validate_target_authorized(req.target, authorized_cidrs=settings.authorized_cidrs)
            port = validate_ftp_port(req.port)
            validate_ftp_credentials(
                req.username, req.password, max_bytes=settings.ftp_validate_max_credential_bytes,
            )
            operation = validate_ftp_operation(req.operation)
            connect_timeout = resolve_ftp_validate_timeout(req.connect_timeout_seconds, settings)
            login_timeout = resolve_ftp_validate_timeout(req.login_timeout_seconds, settings)
            command_timeout = resolve_ftp_validate_timeout(req.command_timeout_seconds, settings)
        except RequestValidationError as exc:
            log_validation_rejected(correlation_id, exc.detail)
            raise HTTPException(status_code=400, detail=exc.detail) from None

        if req.dry_run:
            log_ftp_validate_accepted(correlation_id, req.target, port, req.username, operation)
            return FtpValidateResponse(
                ok=False, error_code="dry_run", sanitized_error="dry-run: no login attempted",
            )

        log_ftp_validate_accepted(correlation_id, req.target, port, req.username, operation)
        result = await execute_ftp_validate(
            target=req.target, port=port, username=req.username, password=req.password,
            operation=operation, connect_timeout=connect_timeout,
            login_timeout=login_timeout, command_timeout=command_timeout,
        )
        log_ftp_validate_result(correlation_id, req.target, req.username, result)

        return FtpValidateResponse(
            ok=result.ok,
            authenticated=result.authenticated,
            operation=result.operation,
            response_summary=result.response_summary,
            error_code=result.error_code,
            sanitized_error=result.sanitized_error
            or (_FTP_ERROR_CODE_MESSAGES.get(result.error_code, result.error_code) if result.error_code else None),
            timed_out=result.timed_out,
            duration_ms=result.duration_seconds * 1000.0,
        )

    @app.post("/v1/ftp-read", response_model=FtpReadResponse)
    async def ftp_read(
        raw_request: Request, authorization: str | None = Header(default=None),
    ) -> FtpReadResponse:
        """Dedicated, structured bounded FTP file-read (§28.17): connect → login
        → RETR one approved candidate path (bounded) → close, on the Kali/VPN
        side. Same order of operations and safety model as ``/v1/ftp-validate``
        and ``/v1/bounded-file-read``; the path is validated against the same
        basename allowlist as bounded-file-read. The password is used only for
        the single login and is never logged; the retrieved content appears only
        in the response ``output`` (bounded), never in a log.
        """
        correlation_id = new_correlation_id()

        auth_result = check_bearer_token(authorization, settings)
        if auth_result.status is AuthStatus.service_misconfigured:
            logger.warning("ftp_read rejected: no server token configured id=%s", correlation_id)
            raise HTTPException(status_code=503, detail="tool service is not configured with an authentication token")
        if not auth_result.is_authenticated:
            log_auth_failure(correlation_id, auth_result.status.value)
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")

        try:
            raw_body = await raw_request.json()
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=400, detail="request body must be valid JSON") from None
        try:
            req = FtpReadRequest.model_validate(raw_body)
        except pydantic.ValidationError as exc:
            log_validation_rejected(correlation_id, "schema validation failed")
            raise HTTPException(
                status_code=400,
                detail={"message": "invalid request schema", "errors": _format_schema_errors(exc)},
            ) from None

        try:
            validate_target_authorized(req.target, authorized_cidrs=settings.authorized_cidrs)
            port = validate_ftp_port(req.port)
            validate_ftp_credentials(
                req.username, req.password, max_bytes=settings.ftp_validate_max_credential_bytes,
            )
            validate_bounded_path(req.path, allowed_basenames=settings.allowed_flag_basenames)
            max_output_bytes = resolve_ftp_read_max_bytes(req.max_output_bytes, settings)
            connect_timeout = resolve_ftp_validate_timeout(req.connect_timeout_seconds, settings)
            login_timeout = resolve_ftp_validate_timeout(req.login_timeout_seconds, settings)
            command_timeout = resolve_ftp_validate_timeout(req.command_timeout_seconds, settings)
        except RequestValidationError as exc:
            log_validation_rejected(correlation_id, exc.detail)
            raise HTTPException(status_code=400, detail=exc.detail) from None

        basename = req.path.rsplit("/", 1)[-1]
        if req.dry_run:
            log_ftp_read_accepted(correlation_id, req.target, port, req.username, basename)
            return FtpReadResponse(ok=False, error_code="dry_run", sanitized_error="dry-run: no read attempted")

        log_ftp_read_accepted(correlation_id, req.target, port, req.username, basename)
        result = await execute_ftp_read(
            target=req.target, port=port, username=req.username, password=req.password,
            path=req.path, max_output_bytes=max_output_bytes, connect_timeout=connect_timeout,
            login_timeout=login_timeout, command_timeout=command_timeout,
        )
        log_ftp_read_result(correlation_id, req.target, req.username, result)

        return FtpReadResponse(
            ok=result.ok,
            output=result.output,
            error_code=result.error_code,
            sanitized_error=result.sanitized_error
            or (_FTP_ERROR_CODE_MESSAGES.get(result.error_code, result.error_code) if result.error_code else None),
            bytes_received=result.bytes_received,
            oversized=result.oversized,
            timed_out=result.timed_out,
            duration_ms=result.duration_seconds * 1000.0,
        )

    return app


# Alternative standalone-run entrypoint: `uv run uvicorn apex_tool_service.app:app`.
# The primary documented entrypoint is `uv run python -m apex_tool_service`
# (see apex_tool_service/__main__.py) — both construct settings the same way.
app = create_app()
