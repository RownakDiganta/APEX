# openai.py
# Native OpenAI provider adapter — the only module (besides its own tests) permitted to import the openai SDK.
"""Native OpenAI provider adapter (Phase 5).

Uses the official ``openai`` Python SDK's async client (``AsyncOpenAI``)
directly against the real OpenAI Chat Completions API. No LangChain, no
OpenAI-compatibility shim for a different provider. The configured model
identifier is passed to the API EXACTLY as given — never rewritten,
never stripped of a prefix, never silently converted.

Official default endpoint: the SDK's own built-in default
(``https://api.openai.com/v1``) is used whenever no custom base URL is
configured — this adapter never hardcodes that URL itself; passing no
``base_url`` kwarg to ``AsyncOpenAI`` is what lets the SDK apply its own
official default, which stays correct even if OpenAI changes it in a
future SDK release.

Credential: ``OPENAI_API_KEY``, read directly from the environment (never
via ``apex_host.config_env``'s generic merge — CLI args are visible in
shell history and `ps`, environment variables set via `export` are not;
same rationale as every other credential in this codebase).
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from apex_host.llm.errors import (
    base_url_host,
    classify_llm_exception,
    detect_base_url_provider_mismatch,
    detect_provider_model_mismatch,
    endpoint_kind,
)
from apex_host.llm.providers.base import (
    EmptyResponseError,
    MissingCredentialError,
    ProviderModelMismatchError,
    read_credential,
)
from apex_host.llm.types import CREDENTIAL_ENV_VAR, ProviderReadiness

if TYPE_CHECKING:
    from apex_host.llm.types import LLMRequest, LLMResponse

_CREDENTIAL_ENV_VAR = CREDENTIAL_ENV_VAR["openai"]


class OpenAIProvider:
    """Native adapter for the official OpenAI API.

    ``base_url``: ``None`` (the default) means "use the SDK's own official
    default endpoint" — never a hardcoded URL string here. A caller that
    supplies a custom value is opting into a non-default endpoint
    explicitly (e.g. Azure OpenAI, a self-hosted proxy) — see
    ``docs/llm-providers.md`` "Base URL behavior" for the documented
    compatibility caveat.
    """

    name = "openai"

    def __init__(self, *, base_url: str | None = None, timeout_seconds: float | None = None) -> None:
        self._base_url = base_url
        self._timeout = timeout_seconds

    def _api_key(self) -> str | None:
        return read_credential(_CREDENTIAL_ENV_VAR)

    async def generate(self, request: "LLMRequest") -> "LLMResponse":
        from apex_host.llm.types import LLMResponse

        mismatch = detect_provider_model_mismatch(self.name, request.model)
        if mismatch:
            raise ProviderModelMismatchError(mismatch)
        base_mismatch = detect_base_url_provider_mismatch(self.name, self._base_url)
        if base_mismatch:
            raise ProviderModelMismatchError(base_mismatch)
        if not request.model:
            raise ProviderModelMismatchError(
                "provider='openai' requires an explicit model identifier — "
                "none was configured (ApexConfig.planner_model/executor_model/"
                "parser_model is empty)"
            )

        api_key = self._api_key()
        if not api_key:
            raise MissingCredentialError(_CREDENTIAL_ENV_VAR)

        from openai import AsyncOpenAI

        client_kwargs: dict[str, Any] = {"api_key": api_key}
        if self._base_url:
            client_kwargs["base_url"] = self._base_url
        timeout = request.timeout_seconds if request.timeout_seconds is not None else self._timeout
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
            raise EmptyResponseError("OpenAI response contained no choices")
        choice = response.choices[0]
        text = choice.message.content if choice.message is not None else None
        if not text:
            raise EmptyResponseError("OpenAI response choice contained no text content")

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
            requested_model="",  # filled in by the caller (router knows the role's model)
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

        client_kwargs: dict[str, Any] = {"api_key": api_key}
        if self._base_url:
            client_kwargs["base_url"] = self._base_url
        client = AsyncOpenAI(**client_kwargs, timeout=self._timeout or 10.0)
        try:
            await client.models.list()
            readiness.reachable = True
        except Exception as exc:  # noqa: BLE001 — classified below, never re-raised
            category = classify_llm_exception(exc)
            readiness.reachable = False
            readiness.error_category = category.value
            readiness.error_reason = (
                f"{category.value}: GET /models at "
                f"{base_url_host(self._base_url) or 'api.openai.com'!r} failed"
            )
            from apex_host.llm.errors import PERMANENT_LLM_ERROR_CATEGORIES

            readiness.permanent = category in PERMANENT_LLM_ERROR_CATEGORIES
            readiness.retryable = not readiness.permanent
        finally:
            await client.close()
        return readiness
