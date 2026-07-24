# router.py
# Model routing seam: ModelRouter Protocol, FakeModelRouter for tests/dry-run, and per-provider routers backed by native provider adapters (Phase 5).
"""Model routing seam for LLM-backed planning/parsing.

``ModelRouter`` is the seam ``apex_host.llm.gateway.LLMGateway`` and the
legacy direct path in ``apex_host.planning.engine.PlanningEngine`` consume.
``FakeModelRouter`` is what tests and the dry-run CLI path use so no
network calls or API keys are required to exercise the graph end-to-end —
every role returns ``None``, which callers treat as "no LLM configured".

Phase 5 (native OpenAI/Anthropic providers) replaced the single
OpenAI-only, LangChain-backed router with one router class PER provider
(``OpenAIModelRouter``, ``AnthropicModelRouter``, ``OpenRouterModelRouter``),
each backed by its own native adapter in ``apex_host.llm.providers``.
:func:`build_model_router` is the single factory that inspects
``ApexConfig.use_llm``/``llm_provider`` and constructs the right one —
this is the ONLY place in ``apex_host`` that decides which provider
router to build; ``apex_host.runtime.ApexRuntime.run()`` calls it instead
of hardcoding a specific provider class.

Every real router's four role methods (``planner_llm``, ``executor_llm``,
``parser_llm``, ``reflector_llm``) each return a
``apex_host.llm.providers.base.RoleBoundProvider`` (or ``None`` when the
corresponding model string is empty) — a small object exposing the same
synchronous ``invoke(messages) -> object-with-.content`` shape
``LLMGateway`` has always called, now backed by a genuine native SDK call
instead of a LangChain ``ChatOpenAI`` object. See
``apex_host/llm/providers/base.py``'s module docstring for the full
sync/async bridging rationale.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Protocol

from apex_host.llm.providers.base import RoleBoundProvider
from apex_host.llm.types import normalize_llm_provider

if TYPE_CHECKING:
    from apex_host.config import ApexConfig
    from apex_host.llm.providers.base import LLMProvider


class ModelRouter(Protocol):
    """Returns a role-bound, ``invoke()``-capable object per role, or ``None``."""

    def planner_llm(self) -> object: ...
    def executor_llm(self) -> object: ...
    def parser_llm(self) -> object: ...
    def reflector_llm(self) -> object: ...


class FakeModelRouter:
    """Deterministic stand-in. Every role returns None — callers must treat
    a None model as "no LLM configured" and fall back to rule-based logic."""

    def planner_llm(self) -> object:
        return None

    def executor_llm(self) -> object:
        return None

    def parser_llm(self) -> object:
        return None

    def reflector_llm(self) -> object:
        return None


class _NativeProviderRouter:
    """Shared implementation for every real (non-fake) provider router.

    Subclasses only need to construct ``self._provider`` (an
    ``LLMProvider`` instance) in their own ``__init__``; role binding and
    the four ``ModelRouter`` methods are identical across providers.
    """

    _provider: "LLMProvider"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    def _bind(self, model: str) -> object:
        if not model:
            return None
        timeout = getattr(self._config, "llm_request_timeout_seconds", None)
        return RoleBoundProvider(self._provider, model, timeout_seconds=timeout)

    def planner_llm(self) -> object:
        return self._bind(self._config.planner_model)

    def executor_llm(self) -> object:
        return self._bind(self._config.executor_model)

    def parser_llm(self) -> object:
        return self._bind(self._config.parser_model)

    def reflector_llm(self) -> object:
        return self._bind(self._config.planner_model)


#: Provider -> the SDK-recognized environment variable name it also reads
#: for a base URL override, if none is explicitly configured. Used only
#: by :func:`resolve_base_url_for_provider` — never read directly by
#: anything else.
_SDK_BASE_URL_ENV_VAR: dict[str, str] = {
    "openai": "OPENAI_BASE_URL",
    "anthropic": "ANTHROPIC_BASE_URL",
    "openrouter": "OPENROUTER_BASE_URL",
}


def resolve_base_url_for_provider(config: "ApexConfig", provider: str) -> str | None:
    """Return the effective base URL override for *provider*, or ``None``
    to mean "use that provider's own official SDK default".

    Precedence (shared by every ``_NativeProviderRouter`` subclass's
    ``__init__`` AND ``apex_host.eval.preflight``'s no-network readiness
    check — a single implementation so the two can never disagree):
    provider-specific config field > legacy generic ``config.llm_base_url``
    (applies only because *provider* is the one currently selected) >
    the provider's own SDK-recognized environment variable > ``None``.
    """
    specific = getattr(config, f"llm_{provider}_base_url", None)
    if specific:
        return str(specific)
    generic = getattr(config, "llm_base_url", None)
    if generic:
        return str(generic)
    env_var = _SDK_BASE_URL_ENV_VAR.get(provider)
    if env_var:
        return os.environ.get(env_var)
    return None


class OpenAIModelRouter(_NativeProviderRouter):
    """Router backed by the native OpenAI adapter
    (``apex_host.llm.providers.openai.OpenAIProvider``).

    Base URL precedence: ``config.llm_openai_base_url`` (explicit,
    provider-specific) > ``config.llm_base_url`` (legacy generic override —
    only ever applied here because this router was selected FOR provider
    ``"openai"``, never carried over from a different provider) >
    ``$OPENAI_BASE_URL`` (the OpenAI SDK's own recognized env var) >
    the SDK's own official default (``None`` passed through, meaning
    "use ``https://api.openai.com/v1``").
    """

    def __init__(self, config: "ApexConfig") -> None:
        super().__init__(config)
        from apex_host.llm.providers.openai import OpenAIProvider

        base_url = resolve_base_url_for_provider(config, "openai")
        self._base_url = base_url
        self._provider = OpenAIProvider(
            base_url=base_url,
            timeout_seconds=getattr(config, "llm_request_timeout_seconds", None),
        )


class AnthropicModelRouter(_NativeProviderRouter):
    """Router backed by the native Anthropic adapter
    (``apex_host.llm.providers.anthropic.AnthropicProvider``).

    Base URL precedence: ``config.llm_anthropic_base_url`` >
    ``config.llm_base_url`` (legacy generic override, active-provider-only)
    > ``$ANTHROPIC_BASE_URL`` > the SDK's own official default.
    """

    def __init__(self, config: "ApexConfig") -> None:
        super().__init__(config)
        from apex_host.llm.providers.anthropic import AnthropicProvider

        base_url = resolve_base_url_for_provider(config, "anthropic")
        self._base_url = base_url
        self._provider = AnthropicProvider(
            base_url=base_url,
            timeout_seconds=getattr(config, "llm_request_timeout_seconds", None),
        )


class OpenRouterModelRouter(_NativeProviderRouter):
    """Router backed by the optional OpenRouter adapter
    (``apex_host.llm.providers.openrouter.OpenRouterProvider``). See that
    module's docstring for why this is a distinct provider identity, not
    ``provider=openai`` plus a custom base URL.

    Base URL precedence: ``config.llm_openrouter_base_url`` >
    ``config.llm_base_url`` (legacy generic override, active-provider-only)
    > ``$OPENROUTER_BASE_URL`` > OpenRouter's own well-known default
    (``https://openrouter.ai/api/v1``).
    """

    def __init__(self, config: "ApexConfig") -> None:
        super().__init__(config)
        from apex_host.llm.providers.openrouter import OpenRouterProvider

        base_url = resolve_base_url_for_provider(config, "openrouter")
        self._base_url = base_url
        self._provider = OpenRouterProvider(
            base_url=base_url,
            timeout_seconds=getattr(config, "llm_request_timeout_seconds", None),
        )


_PROVIDER_ROUTERS: dict[str, type[_NativeProviderRouter]] = {
    "openai": OpenAIModelRouter,
    "anthropic": AnthropicModelRouter,
    "openrouter": OpenRouterModelRouter,
}


def build_model_router(config: "ApexConfig") -> ModelRouter:
    """Construct the correct ``ModelRouter`` for *config*.

    The single place ``apex_host.runtime.ApexRuntime.run()`` (and any
    other production caller) delegates to — never hardcodes a specific
    provider class. ``use_llm=False`` or ``llm_provider in ("fake", "")``
    always returns ``FakeModelRouter()`` (the safe default: no network, no
    credential required). An unrecognized provider name raises
    ``ValueError`` rather than silently falling back to a different
    provider — provider selection is never silently changed. In normal
    operation this should never be reached: ``apex_host.config_env``'s
    environment-variable merge already validates ``llm_provider`` against
    :data:`apex_host.llm.types.VALID_LLM_PROVIDERS` before an ``ApexConfig``
    is even constructed from CLI/env input; this is a defense-in-depth
    check for callers that construct ``ApexConfig`` directly.
    """
    if not config.use_llm:
        return FakeModelRouter()
    provider = normalize_llm_provider(config.llm_provider)
    if provider in ("fake", ""):
        return FakeModelRouter()
    router_cls = _PROVIDER_ROUTERS.get(provider)
    if router_cls is None:
        from apex_host.llm.types import VALID_LLM_PROVIDERS

        raise ValueError(
            f"unrecognized llm_provider {config.llm_provider!r} — expected one of: "
            f"{', '.join(sorted(VALID_LLM_PROVIDERS))}"
        )
    return router_cls(config)
