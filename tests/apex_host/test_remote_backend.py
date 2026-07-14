# test_remote_backend.py
# Tests for apex_host/tools/remote_backend.py::RemoteToolBackend — request construction, response mapping, HTTP/transport failure handling, configuration validation, and lifecycle.
from __future__ import annotations

import json
import logging

import httpx
import pytest

from apex_host.config import ApexConfig
from apex_host.tools.remote_backend import RemoteToolBackend

_TOKEN = "test-only-remote-token"


def _config(**overrides: object) -> ApexConfig:
    base: dict[str, object] = {
        "target": "127.0.0.1",
        "allowed_tools": ["nmap", "curl", "nc"],
        "dry_run": False,
        "tool_backend": "remote",
        "tool_service_url": "http://kali.internal:8080",
        "tool_service_token": _TOKEN,
    }
    base.update(overrides)
    return ApexConfig(**base)  # type: ignore[arg-type]


def _capturing_client(
    status_code: int = 200,
    json_body: object | None = None,
    text_body: str | None = None,
) -> tuple[httpx.AsyncClient, list[httpx.Request]]:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if text_body is not None:
            return httpx.Response(status_code, text=text_body, request=request)
        return httpx.Response(status_code, json=json_body, request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client, captured


def _ok_body(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "tool": "nmap",
        "arguments": ["-Pn", "-n", "-p", "23", "10.129.0.1"],
        "stdout": "some output",
        "stderr": "",
        "returncode": 0,
        "duration_seconds": 0.42,
        "timed_out": False,
        "backend": "kali-service",
        "error": None,
    }
    base.update(overrides)
    return base


class _RaisingTransport(httpx.AsyncBaseTransport):
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise self._exc


def _raising_client(exc: Exception) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=_RaisingTransport(exc))


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------

async def test_request_uses_correct_endpoint_url() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    await backend.execute("nmap", ["-Pn"])
    assert str(captured[0].url) == "http://kali.internal:8080/v1/execute"


async def test_request_url_avoids_duplicate_slashes_when_base_url_has_trailing_slash() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(tool_service_url="http://kali.internal:8080/"), client=client)
    await backend.execute("nmap", ["-Pn"])
    assert str(captured[0].url) == "http://kali.internal:8080/v1/execute"


async def test_request_uses_bearer_header() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    await backend.execute("nmap", ["-Pn"])
    assert captured[0].headers["authorization"] == f"Bearer {_TOKEN}"


async def test_request_json_body_shape() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    await backend.execute("nmap", ["-Pn", "-n"], timeout_seconds=45)
    body = json.loads(captured[0].content)
    assert body == {"tool": "nmap", "arguments": ["-Pn", "-n"], "timeout_seconds": 45.0, "stdin": None}


async def test_request_never_sends_raw_command_string() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    await backend.execute("nmap", ["-Pn", "-n"])
    body = json.loads(captured[0].content)
    assert "command" not in body


async def test_argument_list_preserved_in_request() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    args = ["-Pn", "-n", "-p", "23", "10.129.0.1"]
    await backend.execute("nmap", args)
    assert json.loads(captured[0].content)["arguments"] == args


async def test_stdin_preserved_when_supplied() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    await backend.execute("nc", ["-nv", "10.0.0.1", "22"], stdin="hello\n")
    assert json.loads(captured[0].content)["stdin"] == "hello\n"


async def test_requested_timeout_preserved_in_body() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    await backend.execute("nmap", ["-Pn"], timeout_seconds=17.5)
    assert json.loads(captured[0].content)["timeout_seconds"] == 17.5


async def test_omitted_timeout_uses_config_default() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(tool_service_timeout_seconds=99.0), client=client)
    await backend.execute("nmap", ["-Pn"])
    assert json.loads(captured[0].content)["timeout_seconds"] == 99.0


async def test_token_absent_from_request_body() -> None:
    client, captured = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    await backend.execute("nmap", ["-Pn"])
    assert _TOKEN not in captured[0].content.decode()


async def test_token_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    client, _ = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    with caplog.at_level(logging.DEBUG):
        await backend.execute("nmap", ["-Pn"])
    assert _TOKEN not in caplog.text


# ---------------------------------------------------------------------------
# Successful responses
# ---------------------------------------------------------------------------

async def test_stdout_preserved_from_response() -> None:
    client, _ = _capturing_client(200, _ok_body(stdout="hello stdout"))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.stdout == "hello stdout"


async def test_stderr_preserved_from_response() -> None:
    client, _ = _capturing_client(200, _ok_body(stderr="hello stderr"))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.stderr == "hello stderr"


async def test_nonzero_return_code_preserved_from_response() -> None:
    client, _ = _capturing_client(200, _ok_body(returncode=7))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.returncode == 7


async def test_duration_preserved_from_response() -> None:
    client, _ = _capturing_client(200, _ok_body(duration_seconds=4.25))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.duration_seconds == 4.25


async def test_timed_out_state_preserved_from_response() -> None:
    client, _ = _capturing_client(200, _ok_body(timed_out=True, error="command timed out"))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.timed_out is True


async def test_backend_identifier_preserved_from_response() -> None:
    client, _ = _capturing_client(200, _ok_body(backend="kali-service"))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.backend == "kali-service"


async def test_returned_command_reconstructed_correctly() -> None:
    client, _ = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn", "-n"])
    assert result.command.tool == "nmap"
    assert result.command.args == ["-Pn", "-n"]


async def test_successful_response_dry_run_field_is_false() -> None:
    client, _ = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.dry_run is False


# ---------------------------------------------------------------------------
# HTTP failures — all produce a structured ToolResult, never a raised exception
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [400, 401, 404, 422, 500, 503])
async def test_http_error_status_produces_structured_result(status: int) -> None:
    client, _ = _capturing_client(status, {"detail": f"error {status}"})
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None
    assert str(status) in result.error
    assert result.returncode != 0
    assert result.backend == "remote"


async def test_http_error_detail_included_without_token() -> None:
    client, _ = _capturing_client(401, {"detail": "invalid or missing bearer token"})
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert "invalid or missing bearer token" in (result.error or "")
    assert _TOKEN not in (result.error or "")


async def test_malformed_json_response_produces_structured_result() -> None:
    client, _ = _capturing_client(200, text_body="{not valid json")
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None
    assert "JSON" in result.error
    assert result.returncode != 0


async def test_valid_json_missing_required_fields_produces_structured_result() -> None:
    client, _ = _capturing_client(200, {"tool": "nmap"})  # missing everything else
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None
    assert "missing" in result.error.lower()


async def test_valid_json_wrong_field_types_produces_structured_result() -> None:
    body = _ok_body(returncode="not-an-int")  # wrong type
    client, _ = _capturing_client(200, body)
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None
    assert "type" in result.error.lower()


async def test_json_response_not_an_object_produces_structured_result() -> None:
    client, _ = _capturing_client(200, [1, 2, 3])
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None


# ---------------------------------------------------------------------------
# Transport failures
# ---------------------------------------------------------------------------

async def test_connect_error_produces_structured_result() -> None:
    client = _raising_client(httpx.ConnectError("connection refused"))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None
    assert "connect" in result.error.lower()
    assert result.returncode == -1


async def test_connect_timeout_produces_structured_result_not_timed_out() -> None:
    """A connect timeout means we never reached the server at all — the
    remote process never started, so timed_out=False (distinct from a read
    timeout, where the server accepted the request)."""
    client = _raising_client(httpx.ConnectTimeout("connect timed out"))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None
    assert result.timed_out is False


async def test_read_timeout_produces_structured_result_timed_out_true() -> None:
    client = _raising_client(httpx.ReadTimeout("read timed out"))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None
    assert result.timed_out is True


async def test_dns_style_failure_produces_structured_result() -> None:
    """DNS resolution failures surface through httpx as ConnectError."""
    client = _raising_client(httpx.ConnectError("[Errno 8] nodename nor servname provided"))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None
    assert result.returncode == -1


async def test_generic_request_error_produces_structured_result() -> None:
    client = _raising_client(httpx.RequestError("generic transport failure"))
    backend = RemoteToolBackend(_config(), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.error is not None


async def test_transport_failure_error_excludes_token(caplog: pytest.LogCaptureFixture) -> None:
    client = _raising_client(httpx.ConnectError("connection refused"))
    backend = RemoteToolBackend(_config(), client=client)
    with caplog.at_level(logging.DEBUG):
        result = await backend.execute("nmap", ["-Pn"])
    assert _TOKEN not in (result.error or "")
    assert _TOKEN not in caplog.text


async def test_client_timeout_is_greater_than_requested_command_timeout() -> None:
    """The client-side httpx timeout passed per-request must exceed the
    requested remote process timeout, so the service's own structured
    timeout response has a chance to arrive first."""
    captured_timeouts: list[object] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok_body())

    class _TimeoutCapturingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return handler(request)

    client = httpx.AsyncClient(transport=_TimeoutCapturingTransport())
    orig_post = client.post

    async def _spy_post(url: str, **kwargs: object) -> httpx.Response:
        captured_timeouts.append(kwargs.get("timeout"))
        return await orig_post(url, **kwargs)  # type: ignore[arg-type]

    client.post = _spy_post  # type: ignore[method-assign]
    backend = RemoteToolBackend(_config(), client=client)
    await backend.execute("nmap", ["-Pn"], timeout_seconds=30.0)
    assert captured_timeouts[0] is not None
    assert float(captured_timeouts[0]) > 30.0  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------

def test_remote_without_url_rejected() -> None:
    with pytest.raises(ValueError, match="service_url"):
        RemoteToolBackend(_config(tool_service_url=None))


def test_remote_without_token_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APEX_TOOL_SERVICE_TOKEN", raising=False)
    with pytest.raises(ValueError, match="token"):
        RemoteToolBackend(_config(tool_service_token=""))


def test_remote_token_falls_back_to_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "env-token-value")
    backend = RemoteToolBackend(_config(tool_service_token=""))
    assert backend is not None  # must not raise


def test_explicit_config_token_wins_over_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "env-token-value")
    backend = RemoteToolBackend(_config(tool_service_token="config-token-value"))
    assert backend._token == "config-token-value"  # noqa: SLF001


@pytest.mark.parametrize("scheme_url", ["ftp://kali:8080", "ws://kali:8080", "kali:8080", "not-a-url"])
def test_invalid_url_scheme_rejected(scheme_url: str) -> None:
    with pytest.raises(ValueError, match="http"):
        RemoteToolBackend(_config(tool_service_url=scheme_url))


def test_https_scheme_accepted() -> None:
    RemoteToolBackend(_config(tool_service_url="https://kali.internal:8443"))  # must not raise


def test_token_redacted_in_config_safe_dict() -> None:
    cfg = _config(tool_service_token="super-secret-value")
    safe = cfg.to_safe_dict()
    assert "super-secret-value" not in str(safe)


# ---------------------------------------------------------------------------
# dry_run defense in depth
# ---------------------------------------------------------------------------

async def test_dry_run_true_never_contacts_network_even_when_explicitly_injected() -> None:
    async def _fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("RemoteToolBackend must never contact the network when dry_run=True")

    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(AssertionError("no network"))))
    backend = RemoteToolBackend(_config(dry_run=True), client=client)
    result = await backend.execute("nmap", ["-Pn"])
    assert result.dry_run is True
    assert result.backend == "dry-run"


async def test_dry_run_true_returns_synthetic_result() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(AssertionError("no network"))))
    backend = RemoteToolBackend(_config(dry_run=True), client=client)
    result = await backend.execute("nmap", ["-Pn", "-n"])
    assert "nmap" in result.stdout
    assert result.returncode == 0


# ---------------------------------------------------------------------------
# select_runtime_backend — default local behavior preserved
# ---------------------------------------------------------------------------

def test_select_runtime_backend_default_config_is_local() -> None:
    from apex_host.tools.backend import LocalToolBackend, select_runtime_backend

    cfg = ApexConfig(target="127.0.0.1", dry_run=False)  # tool_backend defaults to "local"
    backend = select_runtime_backend(cfg)
    assert isinstance(backend, LocalToolBackend)


# ---------------------------------------------------------------------------
# Client lifecycle
# ---------------------------------------------------------------------------

async def test_aclose_closes_owned_client() -> None:
    backend = RemoteToolBackend(_config())
    client = backend._get_client()  # noqa: SLF001 - force lazy creation
    assert client.is_closed is False
    await backend.aclose()
    assert client.is_closed is True


async def test_aclose_does_not_close_injected_client() -> None:
    client, _ = _capturing_client(200, _ok_body())
    backend = RemoteToolBackend(_config(), client=client)
    await backend.execute("nmap", ["-Pn"])
    await backend.aclose()
    assert client.is_closed is False
    await client.aclose()


async def test_aclose_is_idempotent() -> None:
    backend = RemoteToolBackend(_config())
    backend._get_client()  # noqa: SLF001
    await backend.aclose()
    await backend.aclose()  # must not raise


async def test_lazy_client_never_created_when_dry_run_shadows_it() -> None:
    """No client (and therefore no socket) is ever created if every call this
    backend's lifetime is shadowed by dry_run — nothing to close, no warning."""
    backend = RemoteToolBackend(_config(dry_run=True))
    await backend.execute("nmap", ["-Pn"])
    assert backend._client is None  # noqa: SLF001


# ---------------------------------------------------------------------------
# Contract-integration test — the REAL Phase 3 apex_tool_service FastAPI app,
# mounted in-process via httpx.ASGITransport (no MockTransport, no real
# socket, no Docker/Kali/HTB/internet access). Proves the full path:
#   RemoteToolBackend -> POST /v1/execute -> apex_tool_service -> ToolResult
# ---------------------------------------------------------------------------

async def test_contract_integration_real_apex_tool_service_app() -> None:
    from apex_tool_service.app import create_app
    from apex_tool_service.settings import ServiceSettings

    shared_token = "contract-integration-shared-token"
    service_settings = ServiceSettings(token=shared_token)
    app = create_app(service_settings)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://kali-contract-test")

    apex_config = _config(
        tool_service_url="http://kali-contract-test",
        tool_service_token=shared_token,
    )
    backend = RemoteToolBackend(apex_config, client=client)
    try:
        result = await backend.execute("curl", ["--version"])
    finally:
        await client.aclose()

    assert result.error is None
    assert result.returncode == 0
    assert "curl" in result.stdout.lower()
    assert result.backend == "kali-service"
    assert result.timed_out is False
    assert result.duration_seconds >= 0.0


async def test_contract_integration_wrong_token_rejected() -> None:
    from apex_tool_service.app import create_app
    from apex_tool_service.settings import ServiceSettings

    service_settings = ServiceSettings(token="the-real-service-token")
    app = create_app(service_settings)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://kali-contract-test")

    apex_config = _config(
        tool_service_url="http://kali-contract-test",
        tool_service_token="a-completely-different-token",
    )
    backend = RemoteToolBackend(apex_config, client=client)
    try:
        result = await backend.execute("curl", ["--version"])
    finally:
        await client.aclose()

    assert result.error is not None
    assert "401" in result.error
    assert "the-real-service-token" not in result.error


async def test_contract_integration_unknown_tool_rejected_by_real_service() -> None:
    from apex_tool_service.app import create_app
    from apex_tool_service.settings import ServiceSettings

    shared_token = "contract-integration-shared-token-2"
    service_settings = ServiceSettings(token=shared_token)
    app = create_app(service_settings)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://kali-contract-test")

    apex_config = _config(
        tool_service_url="http://kali-contract-test",
        tool_service_token=shared_token,
        allowed_tools=["wget"],  # bypass the APEX-side client allowlist check
    )
    backend = RemoteToolBackend(apex_config, client=client)
    try:
        result = await backend.execute("wget", ["http://example.com"])
    finally:
        await client.aclose()

    assert result.error is not None
    assert "400" in result.error
