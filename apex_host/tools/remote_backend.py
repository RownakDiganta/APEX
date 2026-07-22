# remote_backend.py
# RemoteToolBackend: the real async HTTP client that calls a Phase 3 apex_tool_service instance, implementing the docs/tool-execution-architecture.md §10 contract.
"""``RemoteToolBackend`` — the APEX-side HTTP client for ``apex_tool_service``.

Split out of ``apex_host/tools/backend.py`` (which still re-exports
``RemoteToolBackend`` for backward compatibility) because this
implementation is substantially larger than the other two backends: it
owns an ``httpx.AsyncClient``, maps nine-plus distinct failure modes to
structured ``ToolResult`` objects, and validates configuration eagerly.

Design summary (full detail in ``docs/tool-execution-architecture.md`` and
``docs/kali-tool-service.md``):

- **Constructed from ``ApexConfig``**, never from bare positional args and
  never by reading environment variables for anything except the bearer
  token fallback (mirrors ``apex_host/llm/router.py::OpenAIModelRouter``'s
  ``OPENAI_API_KEY``/``OPENAI_BASE_URL`` precedent — explicit config field
  wins, ``APEX_TOOL_SERVICE_TOKEN`` env var is the fallback, never the
  other way around).
- **Defense in depth against ``dry_run``:** even if this class is
  constructed and injected explicitly while ``config.dry_run is True``,
  ``execute()`` never makes a network call — it delegates to
  ``DryRunToolBackend`` instead. This closes the gap ``LocalToolBackend``
  gets "for free" via ``run_command``'s own internal dry-run check, which
  ``RemoteToolBackend`` has no equivalent of on the server side.
- **Lazy client:** the ``httpx.AsyncClient`` is created on first real
  (non-dry-run) ``execute()`` call, not in ``__init__`` — so merely
  constructing and never executing a ``RemoteToolBackend`` (e.g. because
  ``dry_run=True`` shadowed it) never opens a socket and never triggers an
  "unclosed client" warning.
- **Every ordinary failure becomes a structured ``ToolResult``.** HTTP
  error statuses, malformed/missing/wrong-typed response fields, and
  transport failures (connection refused, DNS failure, connect/read
  timeout) are all caught here and mapped to a ``ToolResult`` with
  ``error`` set — none of them propagate as a raw ``httpx`` exception into
  ``TaskDispatcher``. The only exceptions this class raises are
  configuration/programming errors that make continuing unsafe: a
  malformed constructor (bad URL scheme, missing URL/token) raises
  immediately in ``__init__`` (fail fast, before any task is ever
  dispatched), and the safety-gate ``ValueError`` from
  ``apex_host.tools.safety.check_command`` (the same contract every other
  ``ToolBackend`` honors) still propagates from ``execute()``.
"""
from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

from apex_host.runtime_registry import BoundedReadResult
from apex_host.tools.safety import check_command
from apex_host.types import ToolCommand, ToolResult

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

_EXECUTE_PATH = "/v1/execute"
# Phase 22 — the dedicated bounded-file-read operation's own endpoint,
# entirely separate from the generic /v1/execute path above. This is NOT
# "run 'cat' through the generic tool endpoint" — it is a structurally
# different, narrower request/response contract (see
# apex_tool_service/models.py::ReadBoundedFileRequest/Response) that never
# touches apex_tool_service's ALLOWED_TOOLS allowlist at all.
_READ_BOUNDED_FILE_PATH = "/v1/bounded-file-read"
_ENV_TOKEN = "APEX_TOOL_SERVICE_TOKEN"

_REQUIRED_BOUNDED_READ_RESPONSE_FIELDS: dict[str, type | tuple[type, ...]] = {
    "ok": bool,
    "output": str,
    "bytes_received": int,
    "oversized": bool,
    "timed_out": bool,
}
# How much longer than the requested remote timeout the *client* waits before
# giving up — generous enough that the service's own SIGTERM-then-grace
# timeout handling (docs/kali-tool-service.md §8) can produce a structured
# timed_out=true response before our own client-side timeout would fire.
_CLIENT_TIMEOUT_MARGIN_SECONDS = 10.0

_REQUIRED_RESPONSE_FIELDS: dict[str, type | tuple[type, ...]] = {
    "tool": str,
    "arguments": list,
    "stdout": str,
    "stderr": str,
    "returncode": int,
    "duration_seconds": (int, float),
    "timed_out": bool,
}


def _safe_exc_text(exc: BaseException) -> str:
    """A client-safe, bounded string for an httpx exception.

    httpx transport exceptions do not include request headers/bearer tokens
    in their string representation, but this helper still bounds length and
    strips the object's memory-address repr noise defensively.
    """
    text = str(exc) or exc.__class__.__name__
    return text[:300]


class RemoteToolBackend:
    """Async HTTP client for a restricted ``apex_tool_service`` instance.

    Constructed from an ``ApexConfig``. Raises ``ValueError`` immediately
    (a configuration error, not a runtime condition) if
    ``config.tool_service_url`` is empty, is not ``http``/``https``, or if
    no bearer token is available from either ``config.tool_service_token``
    or the ``APEX_TOOL_SERVICE_TOKEN`` environment variable.
    """

    name = "remote"

    def __init__(self, config: "ApexConfig", *, client: httpx.AsyncClient | None = None) -> None:
        service_url = (config.tool_service_url or "").strip()
        if not service_url:
            raise ValueError(
                "RemoteToolBackend requires a non-empty service_url "
                "(ApexConfig.tool_service_url)"
            )
        parsed = urlsplit(service_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"RemoteToolBackend service_url must use http or https, "
                f"got scheme {parsed.scheme!r} in {service_url!r}"
            )
        if not parsed.netloc:
            raise ValueError(f"RemoteToolBackend service_url is not a valid URL: {service_url!r}")

        # Explicit config field wins; APEX_TOOL_SERVICE_TOKEN is the fallback.
        # Mirrors apex_host/llm/router.py::OpenAIModelRouter's precedent for
        # OPENAI_API_KEY/OPENAI_BASE_URL — secrets are read from the
        # environment at the point of use, never inside apex_host/config.py.
        token = config.tool_service_token or os.environ.get(_ENV_TOKEN) or ""
        if not token:
            raise ValueError(
                "RemoteToolBackend requires a non-empty bearer token — set "
                "ApexConfig.tool_service_token or the "
                f"{_ENV_TOKEN} environment variable"
            )

        self._config = config
        self._base_url = service_url.rstrip("/")
        self._token = token
        self._default_timeout_seconds = float(config.tool_service_timeout_seconds)
        self._client = client
        self._owns_client = client is None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self._client

    async def aclose(self) -> None:
        """Close the owned ``httpx.AsyncClient``, if this backend created one.

        A no-op when a client was injected (the injector owns its lifecycle)
        or when no client was ever created (e.g. every call this run was
        shadowed by ``dry_run``). Idempotent.
        """
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def execute(
        self,
        tool: str,
        arguments: list[str],
        *,
        timeout_seconds: float | None = None,
        stdin: str | None = None,
    ) -> ToolResult:
        cmd = ToolCommand(
            tool=tool,
            args=list(arguments),
            timeout_seconds=int(timeout_seconds or self._default_timeout_seconds),
            stdin=stdin,
        )

        # Defense in depth (docs/tool-execution-architecture.md §19 / this
        # phase's completion criteria): dry_run=True must NEVER contact the
        # tool service, even if a RemoteToolBackend was explicitly injected.
        if self._config.dry_run:
            from apex_host.tools.backend import DryRunToolBackend

            return await DryRunToolBackend(self._config).execute(
                tool, arguments, timeout_seconds=timeout_seconds, stdin=stdin
            )

        # Client-side safety gate — defense in depth. The server remains
        # authoritative (docs/kali-tool-service.md §6); this is early
        # rejection using the same allowlist/shell-metacharacter logic every
        # other backend already applies, so an unsupported/dangerous
        # request never leaves this process at all.
        check_command(cmd, self._config)

        effective_timeout = float(timeout_seconds) if timeout_seconds is not None else self._default_timeout_seconds
        client_timeout = effective_timeout + _CLIENT_TIMEOUT_MARGIN_SECONDS

        body = {
            "tool": tool,
            "arguments": list(arguments),
            "timeout_seconds": effective_timeout,
            "stdin": stdin,
        }
        headers = {"Authorization": f"Bearer {self._token}"}
        url = f"{self._base_url}{_EXECUTE_PATH}"

        client = self._get_client()
        start = time.monotonic()
        try:
            response = await client.post(url, json=body, headers=headers, timeout=client_timeout)
        except httpx.ConnectTimeout:
            return self._transport_failure(cmd, start, "connection to tool service timed out", timed_out=False)
        except httpx.ReadTimeout:
            return self._transport_failure(
                cmd, start, "tool service did not respond within the client timeout", timed_out=True,
            )
        except httpx.ConnectError as exc:
            return self._transport_failure(
                cmd, start, f"could not connect to tool service: {_safe_exc_text(exc)}",
            )
        except httpx.TimeoutException as exc:
            return self._transport_failure(cmd, start, f"tool service request timed out: {_safe_exc_text(exc)}")
        except httpx.RequestError as exc:
            return self._transport_failure(cmd, start, f"tool service request failed: {_safe_exc_text(exc)}")

        return self._map_response(cmd, response, start)

    # ------------------------------------------------------------------
    # Phase 22 — dedicated bounded-file-read operation
    # ------------------------------------------------------------------

    async def read_bounded_file(
        self, target: str, path: str, *, timeout_seconds: float, max_output_bytes: int,
    ) -> BoundedReadResult:
        """Call the tool service's dedicated ``POST /v1/bounded-file-read``
        operation — never the generic ``/v1/execute`` endpoint, and never
        represented as ``execute("cat", ["--", path])``. The fixed
        ``cat -- <path>`` argv is constructed entirely inside
        ``apex_tool_service`` (see ``apex_tool_service/executor.py
        ::execute_bounded_file_read``) — this client sends only the
        structured ``{target, path, timeout_seconds, max_output_bytes}``
        fields, never a command/argv/executable field.

        Same dry-run defense in depth as ``execute()``: ``config.dry_run``
        is checked first and, if true, delegates to
        ``DryRunToolBackend.read_bounded_file()`` without ever touching the
        network.
        """
        if self._config.dry_run:
            from apex_host.tools.backend import DryRunToolBackend

            return await DryRunToolBackend(self._config).read_bounded_file(
                target, path, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
            )

        client_timeout = float(timeout_seconds) + _CLIENT_TIMEOUT_MARGIN_SECONDS
        body = {
            "target": target,
            "path": path,
            "timeout_seconds": float(timeout_seconds),
            "max_output_bytes": int(max_output_bytes),
        }
        headers = {"Authorization": f"Bearer {self._token}"}
        url = f"{self._base_url}{_READ_BOUNDED_FILE_PATH}"

        client = self._get_client()
        try:
            response = await client.post(url, json=body, headers=headers, timeout=client_timeout)
        except httpx.ConnectTimeout:
            return self._bounded_read_transport_failure("connection to tool service timed out")
        except httpx.ReadTimeout:
            return self._bounded_read_transport_failure(
                "tool service did not respond within the client timeout", timed_out=True,
            )
        except httpx.ConnectError as exc:
            return self._bounded_read_transport_failure(
                f"could not connect to tool service: {_safe_exc_text(exc)}"
            )
        except httpx.TimeoutException as exc:
            return self._bounded_read_transport_failure(f"tool service request timed out: {_safe_exc_text(exc)}")
        except httpx.RequestError as exc:
            return self._bounded_read_transport_failure(f"tool service request failed: {_safe_exc_text(exc)}")

        return self._map_bounded_read_response(response)

    def _bounded_read_transport_failure(self, message: str, *, timed_out: bool = False) -> BoundedReadResult:
        logger.warning("remote bounded-file-read transport failure: %s", message)
        # Never log/echo the target or path here beyond what the caller's
        # own audit logging already handles — this message is a fixed,
        # bounded transport-failure description only.
        return BoundedReadResult(connected=False, output="", error=message, timed_out=timed_out, method="remote")

    def _map_bounded_read_response(self, response: httpx.Response) -> BoundedReadResult:
        if response.status_code != 200:
            detail = self._extract_detail(response)
            message = f"tool service returned HTTP {response.status_code}"
            if detail:
                message = f"{message}: {detail}"
            logger.warning("remote bounded-file-read HTTP error: status=%s", response.status_code)
            return BoundedReadResult(connected=False, output="", error=message[:500], method="remote")

        try:
            data = response.json()
        except ValueError:
            return self._malformed_bounded_read_result("response body is not valid JSON")
        if not isinstance(data, dict):
            return self._malformed_bounded_read_result("response body is not a JSON object")

        missing = [f for f in _REQUIRED_BOUNDED_READ_RESPONSE_FIELDS if f not in data]
        if missing:
            return self._malformed_bounded_read_result(
                f"response missing required field(s): {', '.join(sorted(missing))}"
            )
        wrong_type = [
            f for f, expected in _REQUIRED_BOUNDED_READ_RESPONSE_FIELDS.items()
            if not isinstance(data.get(f), expected)
        ]
        if wrong_type:
            return self._malformed_bounded_read_result(
                f"response field(s) have unexpected type: {', '.join(sorted(wrong_type))}"
            )

        error_code = data.get("error_code")
        sanitized_error = data.get("sanitized_error")
        error = str(sanitized_error) if sanitized_error else (str(error_code) if error_code else None)
        # "backend_unavailable" is the one error_code that means the service
        # could not even attempt the read (the fixed executable is missing
        # on its own host) — every other outcome (including a failed read
        # such as file_not_found/permission_denied/oversized_output) means
        # the service DID engage with the request, mirroring
        # ToolBackendCommandReadStrategy's own "connected unless the
        # mechanism itself never engaged" convention.
        connected = str(error_code or "") != "backend_unavailable"
        return BoundedReadResult(
            connected=connected,
            output=str(data["output"]),
            error=error,
            return_code=data.get("return_code"),
            bytes_received=int(data["bytes_received"]),
            truncated=bool(data["oversized"]),
            method=str(data.get("method") or "bounded_file_read"),
            timed_out=bool(data["timed_out"]),
        )

    def _malformed_bounded_read_result(self, message: str) -> BoundedReadResult:
        logger.warning("remote bounded-file-read returned a malformed response: %s", message)
        return BoundedReadResult(connected=False, output="", error=message, method="remote")

    # ------------------------------------------------------------------
    # Response mapping
    # ------------------------------------------------------------------

    def _transport_failure(
        self, cmd: ToolCommand, start: float, message: str, *, timed_out: bool = False,
    ) -> ToolResult:
        logger.warning("remote tool service transport failure: %s", message)
        return ToolResult(
            command=cmd, stdout="", stderr="", returncode=-1,
            duration_seconds=time.monotonic() - start,
            dry_run=False, timed_out=timed_out, backend="remote", error=message,
        )

    def _http_error_result(self, cmd: ToolCommand, start: float, response: httpx.Response) -> ToolResult:
        detail = self._extract_detail(response)
        message = f"tool service returned HTTP {response.status_code}"
        if detail:
            message = f"{message}: {detail}"
        logger.warning(
            "remote tool service HTTP error: status=%s detail_present=%s",
            response.status_code, bool(detail),
        )
        return ToolResult(
            command=cmd, stdout="", stderr="", returncode=-1,
            duration_seconds=time.monotonic() - start,
            dry_run=False, timed_out=False, backend="remote", error=message[:500],
        )

    @staticmethod
    def _extract_detail(response: httpx.Response) -> str:
        """Best-effort extraction of a client-safe detail string from an
        error response body. Never raises; never returns request headers."""
        try:
            data = response.json()
        except ValueError:
            text = response.text
            return text[:200] if text else ""
        if isinstance(data, dict):
            detail = data.get("detail")
            if isinstance(detail, str):
                return detail[:200]
            if detail is not None:
                return str(detail)[:200]
        return str(data)[:200]

    def _map_response(self, cmd: ToolCommand, response: httpx.Response, start: float) -> ToolResult:
        if response.status_code != 200:
            return self._http_error_result(cmd, start, response)

        try:
            data = response.json()
        except ValueError:
            return self._malformed_response_result(cmd, start, "response body is not valid JSON")

        if not isinstance(data, dict):
            return self._malformed_response_result(cmd, start, "response body is not a JSON object")

        missing = [f for f in _REQUIRED_RESPONSE_FIELDS if f not in data]
        if missing:
            return self._malformed_response_result(
                cmd, start, f"response missing required field(s): {', '.join(sorted(missing))}",
            )

        wrong_type = [
            f for f, expected in _REQUIRED_RESPONSE_FIELDS.items()
            if not isinstance(data.get(f), expected)
        ]
        if wrong_type:
            return self._malformed_response_result(
                cmd, start, f"response field(s) have unexpected type: {', '.join(sorted(wrong_type))}",
            )

        error = data.get("error")
        if error is not None and not isinstance(error, str):
            error = str(error)

        return ToolResult(
            command=cmd,
            stdout=str(data["stdout"]),
            stderr=str(data["stderr"]),
            returncode=int(data["returncode"]),
            duration_seconds=float(data["duration_seconds"]),
            dry_run=False,
            timed_out=bool(data["timed_out"]),
            backend=str(data.get("backend") or "remote"),
            error=error,
        )

    def _malformed_response_result(self, cmd: ToolCommand, start: float, message: str) -> ToolResult:
        logger.warning("remote tool service returned a malformed response: %s", message)
        return ToolResult(
            command=cmd, stdout="", stderr="", returncode=-1,
            duration_seconds=time.monotonic() - start,
            dry_run=False, timed_out=False, backend="remote", error=message,
        )
