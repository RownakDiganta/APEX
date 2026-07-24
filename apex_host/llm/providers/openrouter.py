# openrouter.py
# Optional OpenRouter provider adapter — retained as its own distinct provider identity, never as "openai + a custom base URL".
"""Optional OpenRouter provider adapter (Phase 5).

OpenRouter's own HTTP API is OpenAI-Chat-Completions-compatible, so this
adapter reuses the official ``openai`` Python SDK's client machinery
(pointed at OpenRouter's own endpoint) — the SAME SDK class, but this is
still its OWN, clearly-identified provider:

- ``name = "openrouter"`` (never ``"openai"``) — reports/diagnostics
  truthfully show OpenRouter processed the request, never OpenAI.
- Its own credential: ``OPENROUTER_API_KEY`` — never ``OPENAI_API_KEY``
  (no fallback between the two; see ``docs/llm-providers.md`` "Credential
  resolution").
- Its own default endpoint: ``https://openrouter.ai/api/v1`` — never
  inherited from, or blended with, the OpenAI provider's own base URL
  resolution.
- Router-style (vendor-prefixed) model identifiers such as
  ``"openai/gpt-4o"``/``"anthropic/claude-3.5-sonnet"`` are its NORMAL,
  expected shape — ``apex_host.llm.errors.detect_provider_model_mismatch``
  never flags this provider (see that function's docstring).

This is retained (not removed) because it was already a supported,
documented configuration path before this phase (``OPENAI_BASE_URL``
pointed at OpenRouter) — see ``docs/llm-providers.md`` "OpenRouter
retention" for the full evidence review. After this phase it is its own
provider identity, never expressed as ``provider=openai`` plus a custom
base URL.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from apex_host.llm.errors import base_url_host, classify_llm_exception, endpoint_kind
from apex_host.llm.providers.base import EmptyResponseError, MissingCredentialError, read_credential
from apex_host.llm.types import CREDENTIAL_ENV_VAR, OFFICIAL_BASE_URL, ProviderReadiness

if TYPE_CHECKING:
    from apex_host.llm.types import LLMRequest, LLMResponse

_CREDENTIAL_ENV_VAR = CREDENTIAL_ENV_VAR["openrouter"]
_DEFAULT_BASE_URL = OFFICIAL_BASE_URL["openrouter"]


class OpenRouterProvider:
    """Adapter for the optional OpenRouter aggregator, via the OpenAI SDK's
    client shape pointed at OpenRouter's own endpoint. See module
    docstring — this is a distinct provider identity, not "openai with a
    different base URL"."""

    name = "openrouter"

    def __init__(self, *, base_url: str | None = None, timeout_seconds: float | None = None) -> None:
        self._base_url = base_url or _DEFAULT_BASE_URL
        self._timeout = timeout_seconds

    def _api_key(self) -> str | None:
        return read_credential(_CREDENTIAL_ENV_VAR)

    async def generate(self, request: "LLMRequest") -> "LLMResponse":
        from apex_host.llm.types import LLMResponse

        if not request.model:
            from apex_host.llm.providers.base import ProviderModelMismatchError

            raise ProviderModelMismatchError(
                "provider='openrouter' requires an explicit model identifier — "
                "none was configured (ApexConfig.planner_model/executor_model/"
                "parser_model is empty)"
            )

        api_key = self._api_key()
        if not api_key:
            raise MissingCredentialError(_CREDENTIAL_ENV_VAR)

        from openai import AsyncOpenAI

        timeout = request.timeout_seconds if request.timeout_seconds is not None else self._timeout
        client_kwargs: dict[str, Any] = {"api_key": api_key, "base_url": self._base_url}
        if timeout is not None:
            client_kwargs["timeout"] = float(timeout)
        client = AsyncOpenAI(**client_kwargs)

        create_kwargs: dict[str, Any] = {"model": request.model, "messages": request.messages}
        if request.max_output_tokens is not None:
            create_kwargs["max_tokens"] = request.max_output_tokens

        t0 = time.monotonic()
        try:
            response = await client.chat.completions.create(**create_kwargs)
        finally:
            await client.close()
        elapsed = time.monotonic() - t0

        if not response.choices:
            raise EmptyResponseError("OpenRouter response contained no choices")
        choice = response.choices[0]
        text = choice.message.content if choice.message is not None else None
        if not text:
            raise EmptyResponseError("OpenRouter response choice contained no text content")

        usage = getattr(response, "usage", None)
        return LLMResponse(
            provider=self.name,
            requested_model=request.model,
            text=text,
            actual_model=getattr(response, "model", "") or "",
            finish_reason=getattr(choice, "finish_reason", "") or "",
            input_tokens=getattr(usage, "prompt_tokens", None) if usage is not None else None,
            output_tokens=getattr(usage, "completion_tokens", None) if usage is not None else None,
            request_id=getattr(response, "id", "") or "",
            latency_seconds=elapsed,
        )

    async def check_readiness(self, *, network_check: bool = False) -> ProviderReadiness:
        api_key = self._api_key()
        readiness = ProviderReadiness(
            provider=self.name,
            requested_model="",
            endpoint_kind=endpoint_kind(self.name, self._base_url),
            credential_variable=_CREDENTIAL_ENV_VAR,
            credential_present=bool(api_key),
        )
        if not api_key:
            readiness.error_category = "missing_key"
            readiness.error_reason = f"Missing required environment variable {_CREDENTIAL_ENV_VAR}"
            readiness.permanent = True
            return readiness
        readiness.configuration_valid = True
        if not network_check:
            return readiness

        readiness.network_checked = True
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=api_key, base_url=self._base_url, timeout=self._timeout or 10.0)
        try:
            await client.models.list()
            readiness.reachable = True
        except Exception as exc:  # noqa: BLE001 — classified below, never re-raised
            category = classify_llm_exception(exc)
            readiness.reachable = False
            readiness.error_category = category.value
            readiness.error_reason = (
                f"{category.value}: GET /models at {base_url_host(self._base_url)!r} failed"
            )
            from apex_host.llm.errors import PERMANENT_LLM_ERROR_CATEGORIES

            readiness.permanent = category in PERMANENT_LLM_ERROR_CATEGORIES
            readiness.retryable = not readiness.permanent
        finally:
            await client.close()
        return readiness
