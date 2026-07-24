# anthropic.py
# Native Anthropic provider adapter — the only module (besides its own tests) permitted to import the anthropic SDK.
"""Native Anthropic provider adapter (Phase 5).

Uses the official ``anthropic`` Python SDK's async client
(``AsyncAnthropic``) directly against the real Anthropic Messages API —
never an OpenAI-compatibility endpoint, never LangChain. The configured
Claude model identifier is passed to the API EXACTLY as given.

System-instruction handling: unlike the OpenAI Chat Completions shape
(where a system instruction is just another message with
``role="system"``), Anthropic's Messages API takes system instructions as
a SEPARATE, top-level ``system=`` request parameter — the ``messages``
list may contain only ``user``/``assistant`` turns. This adapter extracts
any ``role="system"`` entries from the normalized request's message list
and joins them into the ``system=`` parameter, rather than pretending the
request is OpenAI-shaped (CLAUDE.md's non-negotiable "use the native
Messages API structure" rule).

Content-block safety: an Anthropic response's ``content`` is a LIST of
typed blocks (``text``, ``tool_use``, ``thinking``, ...) — this adapter
never assumes the first (or only) block is plain text; it concatenates
every ``type="text"`` block and raises :class:`EmptyResponseError` if none
exist, rather than raising an unhandled ``AttributeError`` on a non-text
block.

Credential: ``ANTHROPIC_API_KEY``, read directly from the environment
(same rationale as ``OPENAI_API_KEY`` — see
``apex_host/llm/providers/openai.py``'s module docstring).
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

_CREDENTIAL_ENV_VAR = CREDENTIAL_ENV_VAR["anthropic"]

#: Anthropic's ``max_tokens`` is a REQUIRED request parameter (unlike
#: OpenAI's optional ``max_tokens``) — this is the fallback used only when
#: ``LLMRequest.max_output_tokens`` is not set. Conservative and bounded,
#: never unlimited.
_DEFAULT_MAX_TOKENS = 4096

#: The Anthropic API version this adapter was written against and tests
#: against — a required header on every request. Bumping this is a
#: deliberate, tested decision (docs/llm-providers.md "Adding another
#: provider" §), never silently auto-updated.
_ANTHROPIC_VERSION = "2023-06-01"


def _split_system_messages(messages: list[dict[str, str]]) -> tuple[str, list[dict[str, str]]]:
    """Return (joined_system_text, remaining_user/assistant_messages).

    Anthropic's Messages API takes system instructions as a separate
    top-level parameter, never as a message with role="system" — this is
    the single place that translation happens, so the rest of this
    adapter (and every caller building an ``LLMRequest``) never needs to
    know Anthropic's request shape is different from OpenAI's.
    """
    system_parts: list[str] = []
    remaining: list[dict[str, str]] = []
    for msg in messages:
        if msg.get("role") == "system":
            content = msg.get("content", "")
            if content:
                system_parts.append(content)
        else:
            remaining.append(msg)
    return "\n\n".join(system_parts), remaining


def _extract_text(content_blocks: Any) -> str:
    """Concatenate only text-type content blocks. Never assumes every
    block is plain text (tool_use/thinking blocks are safely skipped)."""
    parts: list[str] = []
    for block in content_blocks or []:
        block_type = getattr(block, "type", None)
        if block_type == "text":
            text = getattr(block, "text", "")
            if text:
                parts.append(text)
    return "".join(parts)


class AnthropicProvider:
    """Native adapter for the official Anthropic Messages API.

    ``base_url``: ``None`` (the default) means "use the SDK's own official
    default endpoint" (``https://api.anthropic.com``) — never hardcoded
    here beyond what the SDK itself applies when no override is given.
    """

    name = "anthropic"

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
                "provider='anthropic' requires an explicit model identifier — "
                "none was configured (ApexConfig.planner_model/executor_model/"
                "parser_model is empty)"
            )

        api_key = self._api_key()
        if not api_key:
            raise MissingCredentialError(_CREDENTIAL_ENV_VAR)

        from anthropic import AsyncAnthropic

        client_kwargs: dict[str, Any] = {"api_key": api_key}
        if self._base_url:
            client_kwargs["base_url"] = self._base_url
        timeout = request.timeout_seconds if request.timeout_seconds is not None else self._timeout
        if timeout is not None:
            client_kwargs["timeout"] = float(timeout)
        client = AsyncAnthropic(**client_kwargs)

        system_text, chat_messages = _split_system_messages(request.messages)
        create_kwargs: dict[str, Any] = {
            "model": request.model,
            "messages": chat_messages,
            "max_tokens": request.max_output_tokens or _DEFAULT_MAX_TOKENS,
        }
        if system_text:
            create_kwargs["system"] = system_text

        t0 = time.monotonic()
        try:
            response = await client.messages.create(**create_kwargs)
        finally:
            await client.close()
        elapsed = time.monotonic() - t0

        text = _extract_text(getattr(response, "content", None))
        if not text:
            raise EmptyResponseError(
                "Anthropic response contained no text content block "
                "(response may have consisted entirely of non-text blocks)"
            )

        usage = getattr(response, "usage", None)
        return LLMResponse(
            provider=self.name,
            requested_model=request.model,
            text=text,
            actual_model=getattr(response, "model", "") or "",
            finish_reason=getattr(response, "stop_reason", "") or "",
            input_tokens=getattr(usage, "input_tokens", None) if usage is not None else None,
            output_tokens=getattr(usage, "output_tokens", None) if usage is not None else None,
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
        from anthropic import AsyncAnthropic

        client_kwargs: dict[str, Any] = {"api_key": api_key}
        if self._base_url:
            client_kwargs["base_url"] = self._base_url
        client = AsyncAnthropic(**client_kwargs, timeout=self._timeout or 10.0)
        try:
            await client.models.list()
            readiness.reachable = True
        except Exception as exc:  # noqa: BLE001 — classified below, never re-raised
            category = classify_llm_exception(exc)
            readiness.reachable = False
            readiness.error_category = category.value
            readiness.error_reason = (
                f"{category.value}: GET /models at "
                f"{base_url_host(self._base_url) or 'api.anthropic.com'!r} failed"
            )
            from apex_host.llm.errors import PERMANENT_LLM_ERROR_CATEGORIES

            readiness.permanent = category in PERMANENT_LLM_ERROR_CATEGORIES
            readiness.retryable = not readiness.permanent
        finally:
            await client.close()
        return readiness
