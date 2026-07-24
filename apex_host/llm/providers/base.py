# base.py
# LLMProvider Protocol, shared exceptions, and the sync/async bridging helper every native provider adapter uses — no provider SDK is imported here.
"""Shared provider-adapter contract (Phase 5 — native OpenAI/Anthropic providers).

``LLMProvider`` is the ONE protocol every provider adapter
(``apex_host/llm/providers/{openai,anthropic,openrouter}.py``) implements.
It exposes only the two normalized operations APEX needs:

- ``generate(request: LLMRequest) -> LLMResponse`` — one bounded model
  call, normalized request in, normalized response out. Never raises for
  an ordinary provider failure in the sense of returning a degraded
  result — genuine failures ARE raised as exceptions (missing credential,
  provider/model mismatch, or whatever the SDK itself raised), and
  ``apex_host.llm.errors.classify_llm_exception`` is the single place
  that turns any such exception into a structured
  ``LLMErrorCategory`` — this module never classifies, it only raises.
- ``check_readiness(network_check=False) -> ProviderReadiness`` — pure
  configuration validation when ``network_check=False`` (no I/O at all);
  one minimal, bounded provider request when ``True``.

No planner, executor, agent, or graph node may import this module or any
concrete provider adapter directly — the ONLY consumers are
``apex_host.llm.router`` (constructs adapters) and
``apex_host.eval.preflight``/``apex_host.eval.check_config`` (readiness
only, never ``generate()``). This is enforced by a static architecture
test (``tests/apex_host/test_llm_providers.py``).

Backward-compatible sync bridge
--------------------------------
``apex_host.llm.gateway.LLMGateway`` — unchanged by this phase — invokes
whatever the ``ModelRouter`` role method (e.g. ``planner_llm``) returns via a SYNCHRONOUS
``.invoke(messages) -> object-with-.content`` call, made from inside a
worker thread (``asyncio.to_thread``). Every concrete provider adapter
therefore also implements ``invoke()`` as a thin synchronous facade over
its own ``async def generate()`` — safe specifically because ``invoke()``
only ever runs inside a thread that has no asyncio event loop of its own
(``asyncio.run()`` inside a plain OS thread is the standard, correct way
to bridge into async code from a genuinely synchronous caller). See
``_run_coroutine_sync`` below and ``docs/llm-providers.md`` "Architecture"
for the full rationale — this is what lets APEX both (a) present the
clean, explicitly-async ``LLMProvider`` protocol the rest of this
module's docstring describes, and (b) require zero changes to
``LLMGateway``'s existing, heavily-tested invocation pipeline (budget
reservation, prompt/output guard, timeout, audit log).
"""
from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from apex_host.llm.types import LLMRequest, LLMResponse, ProviderReadiness

__all__ = [
    "LLMProvider",
    "MissingCredentialError",
    "ProviderModelMismatchError",
    "EmptyResponseError",
    "InvokeResult",
    "RoleBoundProvider",
    "run_coroutine_sync",
    "read_credential",
]


# ---------------------------------------------------------------------------
# Shared exceptions
# ---------------------------------------------------------------------------

class MissingCredentialError(RuntimeError):
    """Raised by a provider adapter when its required credential env var is
    unset/empty. Message names the variable — NEVER a value, since none is
    held. Classified by ``apex_host.llm.errors.classify_llm_exception`` as
    ``LLMErrorCategory.missing_key`` (checked by exact exception type
    name, before any status-code/message heuristic)."""

    def __init__(self, env_var: str) -> None:
        super().__init__(f"Missing required environment variable {env_var}")
        self.env_var = env_var


class ProviderModelMismatchError(ValueError):
    """Raised when ``apex_host.llm.errors.detect_provider_model_mismatch``
    or ``detect_base_url_provider_mismatch`` detects an unambiguous
    provider/model or provider/base-URL namespace mistake. Raised BEFORE
    any network call. Classified as
    ``LLMErrorCategory.provider_model_mismatch`` (permanent — never
    retried)."""


class EmptyResponseError(ValueError):
    """Raised when a provider's response contains no usable text content
    (e.g. an empty ``choices`` list, or every content block was a non-text
    block type). Classified as ``LLMErrorCategory.malformed_response``."""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def read_credential(env_var: str) -> str | None:
    """Read *env_var* from the environment. Returns ``None`` for an unset
    OR blank value (never distinguishes the two — both mean "no usable
    credential"). Never logs, never caches beyond the caller's own
    lifetime."""
    value = os.environ.get(env_var)
    if value is None or not value.strip():
        return None
    return value


def run_coroutine_sync(coro: Any) -> Any:
    """Run an async coroutine to completion from synchronous code.

    Used ONLY by each provider adapter's ``invoke()`` facade, which is
    itself always invoked from inside a worker thread with no running
    event loop of its own (``apex_host.llm.gateway.LLMGateway`` calls
    ``chat_llm.invoke`` via ``asyncio.to_thread``) — ``asyncio.run()`` is
    therefore always safe here (it creates a fresh event loop for this
    thread and tears it down afterward) and would raise
    ``RuntimeError: asyncio.run() cannot be called from a running event
    loop`` if this assumption were ever violated, which is exactly the
    fail-loud behavior wanted if a future caller invokes ``.invoke()``
    from an async context by mistake.
    """
    return asyncio.run(coro)


class InvokeResult:
    """Thin, ``_LLMChatModel``-compatible wrapper around an
    :class:`~apex_host.llm.types.LLMResponse`.

    Exposes ``.content`` (what ``apex_host.llm.gateway.LLMGateway``'s
    existing extraction code reads via
    ``getattr(raw_response, "content", raw_response)``) plus a
    ``usage_metadata`` dict in the SAME shape the gateway already knows
    how to read (``input_tokens``/``output_tokens``), so the gateway's
    pre-existing token-extraction code requires zero changes. Additional
    normalized fields (``provider``, ``requested_model``, ``actual_model``,
    ``finish_reason``, ``request_id``, ``latency_seconds``) are exposed as
    plain attributes for the gateway's ADDITIVE extraction (Phase 5) that
    feeds the run report — see ``apex_host.llm.gateway``'s own docstring.
    """

    __slots__ = ("_response",)

    def __init__(self, response: "LLMResponse") -> None:
        self._response = response

    @property
    def content(self) -> str:
        return self._response.text

    @property
    def usage_metadata(self) -> dict[str, int]:
        meta: dict[str, int] = {}
        if self._response.input_tokens is not None:
            meta["input_tokens"] = self._response.input_tokens
        if self._response.output_tokens is not None:
            meta["output_tokens"] = self._response.output_tokens
        return meta

    @property
    def provider(self) -> str:
        return self._response.provider

    @property
    def requested_model(self) -> str:
        return self._response.requested_model

    @property
    def actual_model(self) -> str:
        return self._response.actual_model

    @property
    def finish_reason(self) -> str:
        return self._response.finish_reason

    @property
    def request_id(self) -> str:
        return self._response.request_id

    @property
    def latency_seconds(self) -> float:
        return self._response.latency_seconds


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------

class RoleBoundProvider:
    """Binds an :class:`LLMProvider` to one specific model name (the
    "role" — planner/executor/parser/reflector each have their own
    configured model string) and exposes the SYNCHRONOUS ``invoke()``
    facade ``apex_host.llm.gateway.LLMGateway`` and
    ``apex_host.planning.engine.PlanningEngine``'s legacy direct path both
    call. Constructed by ``apex_host.llm.router.ModelRouter``
    implementations — never by a planner directly.
    """

    def __init__(
        self, provider: "LLMProvider", model: str, *, timeout_seconds: float | None = None
    ) -> None:
        self._provider = provider
        self._model = model
        self._timeout = timeout_seconds

    def invoke(self, messages: list[dict[str, str]]) -> object:
        """Synchronous facade — see ``run_coroutine_sync``'s docstring for
        why this is safe only when called from a thread with no running
        event loop (exactly how ``LLMGateway`` calls it)."""
        from apex_host.llm.types import LLMRequest

        request = LLMRequest(messages=messages, model=self._model, timeout_seconds=self._timeout)
        response = run_coroutine_sync(self._provider.generate(request))
        return InvokeResult(response)

    async def generate_async(self, messages: list[dict[str, str]]) -> "LLMResponse":
        """Native async path — used by anything that already runs inside
        the event loop and does not need the sync ``.invoke()`` bridge."""
        from apex_host.llm.types import LLMRequest

        request = LLMRequest(messages=messages, model=self._model, timeout_seconds=self._timeout)
        return await self._provider.generate(request)


@runtime_checkable
class LLMProvider(Protocol):
    """The one protocol every native provider adapter implements.

    ``name`` is the provider identity string (``"openai"``/``"anthropic"``/
    ``"openrouter"``) — used by reports/diagnostics to truthfully record
    which service actually processed a request, never inferred from the
    model name.
    """

    name: str

    async def generate(self, request: "LLMRequest") -> "LLMResponse":
        """Perform one bounded model call. Raises on failure — never
        returns a degraded/partial result silently. See module docstring
        for the exception taxonomy every implementation must raise."""
        ...

    async def check_readiness(self, *, network_check: bool = False) -> "ProviderReadiness":
        """Validate configuration (no I/O) or, when ``network_check=True``,
        perform one minimal bounded request to confirm reachability.
        Never raises — a failure is reported IN the returned
        ``ProviderReadiness``, not as an exception."""
        ...
