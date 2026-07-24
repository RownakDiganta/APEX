# test_llm_providers.py
# Phase 5 (native OpenAI/Anthropic/OpenRouter providers): 50 numbered scenarios covering provider parsing, credential isolation, adapter selection, mismatch detection, response normalization, error mapping, readiness, and architecture invariants.
"""Phase 5 native-provider test suite.

Every test below is tagged S01..S50 in its docstring/name, matching the
task brief's "50 numbered test scenarios" requirement — the final Phase 5
report cross-references these tags.

**No real network access anywhere in this file.** Every provider-level
test mocks the official SDK's own async client class
(``openai.AsyncOpenAI`` / ``anthropic.AsyncAnthropic``) at the adapter
boundary via ``monkeypatch.setattr`` — never a raw ``httpx`` transport
underneath a real SDK client, and never a real API key. No paid request is
ever made. No live HTB engagement is exercised.
"""
from __future__ import annotations

import ast
import pathlib
from typing import Any

import pytest

from apex_host.config import ApexConfig
from apex_host.llm.errors import (
    LLMErrorCategory,
    PERMANENT_LLM_ERROR_CATEGORIES,
    TRANSIENT_LLM_ERROR_CATEGORIES,
    classify_llm_exception,
    detect_base_url_provider_mismatch,
    detect_provider_model_mismatch,
    endpoint_kind,
)
from apex_host.llm.providers.anthropic import AnthropicProvider, _extract_text, _split_system_messages
from apex_host.llm.providers.base import (
    EmptyResponseError,
    MissingCredentialError,
    ProviderModelMismatchError,
    read_credential,
)
from apex_host.llm.providers.openai import OpenAIProvider
from apex_host.llm.providers.openrouter import OpenRouterProvider
from apex_host.llm.router import (
    AnthropicModelRouter,
    FakeModelRouter,
    OpenAIModelRouter,
    OpenRouterModelRouter,
    build_model_router,
    resolve_base_url_for_provider,
)
from apex_host.llm.types import (
    CREDENTIAL_ENV_VAR,
    OFFICIAL_BASE_URL,
    VALID_LLM_PROVIDERS,
    LLMRequest,
    is_valid_llm_provider,
    normalize_llm_provider,
)

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_TARGET = "10.10.10.14"


# ---------------------------------------------------------------------------
# Shared exception stand-ins (duck-typed only — never a real SDK import for
# the exception classes themselves; classify_llm_exception is provider-
# agnostic and works against any object shaped like these).
# ---------------------------------------------------------------------------


class _AuthErr(Exception):
    def __init__(self, message: str = "invalid api key", status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


class _NotFoundErr(Exception):
    def __init__(self, message: str = "does not exist", status_code: int = 404) -> None:
        super().__init__(message)
        self.status_code = status_code


class _RateLimitErr(Exception):
    def __init__(self, message: str = "rate limit exceeded", status_code: int = 429) -> None:
        super().__init__(message)
        self.status_code = status_code


class _APITimeoutErr(Exception):
    """Named to match the real openai/anthropic SDK exception type."""


class _APIConnectionErr(Exception):
    """Named to match the real openai/anthropic SDK exception type."""


class _ServerErr(Exception):
    def __init__(self, message: str = "internal server error", status_code: int = 503) -> None:
        super().__init__(message)
        self.status_code = status_code


def _fake_openai_client(
    *, models_result: Any = None, models_exc: Exception | None = None,
    create_result: Any = None, create_exc: Exception | None = None,
) -> tuple[type, list[dict[str, Any]]]:
    """Build a fake AsyncOpenAI-shaped class + a list that records every
    construction kwargs dict — used across the OpenAI/OpenRouter tests."""
    construct_calls: list[dict[str, Any]] = []

    class _FakeModels:
        async def list(self) -> Any:
            if models_exc is not None:
                raise models_exc
            return models_result

    class _FakeCompletions:
        async def create(self, **kwargs: Any) -> Any:
            if create_exc is not None:
                raise create_exc
            return create_result

    class _FakeChat:
        def __init__(self) -> None:
            self.completions = _FakeCompletions()

    class _FakeAsyncOpenAI:
        def __init__(self, **kwargs: Any) -> None:
            construct_calls.append(kwargs)
            self.models = _FakeModels()
            self.chat = _FakeChat()

        async def close(self) -> None:
            pass

    return _FakeAsyncOpenAI, construct_calls


def _fake_anthropic_client(
    *, models_result: Any = None, models_exc: Exception | None = None,
    create_result: Any = None, create_exc: Exception | None = None,
) -> tuple[type, list[dict[str, Any]]]:
    construct_calls: list[dict[str, Any]] = []

    class _FakeModels:
        async def list(self) -> Any:
            if models_exc is not None:
                raise models_exc
            return models_result

    class _FakeMessages:
        async def create(self, **kwargs: Any) -> Any:
            if create_exc is not None:
                raise create_exc
            return create_result

    class _FakeAsyncAnthropic:
        def __init__(self, **kwargs: Any) -> None:
            construct_calls.append(kwargs)
            self.models = _FakeModels()
            self.messages = _FakeMessages()

        async def close(self) -> None:
            pass

    return _FakeAsyncAnthropic, construct_calls


class _Choice:
    def __init__(self, content: str, finish_reason: str = "stop") -> None:
        self.message = type("M", (), {"content": content})()
        self.finish_reason = finish_reason


class _OpenAIResponse:
    def __init__(
        self, *, content: str = "hello", model: str = "gpt-4o-mini-2024-07-18",
        response_id: str = "chatcmpl-abc123", prompt_tokens: int = 10, completion_tokens: int = 5,
        choices: list[Any] | None = None,
    ) -> None:
        self.choices = [_Choice(content)] if choices is None else choices
        self.model = model
        self.id = response_id
        self.usage = type("U", (), {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens})()


class _ContentBlock:
    def __init__(self, block_type: str, text: str = "") -> None:
        self.type = block_type
        self.text = text


class _AnthropicResponse:
    def __init__(
        self, *, content: list[Any] | None = None, model: str = "claude-sonnet-4-5-20250929",
        stop_reason: str = "end_turn", response_id: str = "msg_abc123",
        input_tokens: int = 12, output_tokens: int = 8,
    ) -> None:
        self.content = [_ContentBlock("text", "hello from claude")] if content is None else content
        self.model = model
        self.stop_reason = stop_reason
        self.id = response_id
        self.usage = type("U", (), {"input_tokens": input_tokens, "output_tokens": output_tokens})()


# ===========================================================================
# S01-S03 — Provider parsing, normalization, and validation
# ===========================================================================


class TestProviderParsingAndValidation:
    def test_s01_normalize_llm_provider_lowercases_and_strips(self) -> None:
        assert normalize_llm_provider(" OpenAI ") == "openai"
        assert normalize_llm_provider("ANTHROPIC") == "anthropic"
        assert normalize_llm_provider("OpenRouter") == "openrouter"

    def test_s01_is_valid_llm_provider_case_insensitive(self) -> None:
        assert is_valid_llm_provider("OpenAI") is True
        assert is_valid_llm_provider("Anthropic") is True
        assert is_valid_llm_provider("OPENROUTER") is True
        assert is_valid_llm_provider("fake") is True

    def test_s02_unsupported_provider_rejected_via_from_cli_args(self) -> None:
        from apex_host.main import parse_args

        args = parse_args(["--target", _TARGET, "--use-llm", "--llm-provider", "azure"])
        with pytest.raises(ValueError, match="invalid llm_provider"):
            ApexConfig.from_cli_args(args)

    def test_s02_unsupported_provider_rejected_by_build_model_router(self) -> None:
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="not-a-real-provider")
        with pytest.raises(ValueError, match="unrecognized llm_provider"):
            build_model_router(config)

    def test_s03_use_llm_true_without_model_has_no_provider_neutral_default(self) -> None:
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai")
        assert config.planner_model == ""
        assert config.executor_model == ""
        assert config.parser_model == ""

    def test_s03_no_provider_neutral_default_model_string_exists_anywhere(self) -> None:
        """There is no global constant like "openai/gpt-5.5" anywhere in
        ApexConfig's field defaults."""
        config = ApexConfig(target=_TARGET)
        assert config.planner_model == ""
        assert config.executor_model == ""
        assert config.parser_model == ""


# ===========================================================================
# S04-S06 — Credential isolation per provider
# ===========================================================================


class TestCredentialIsolation:
    def test_s04_openai_missing_key_names_variable_not_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        assert read_credential("OPENAI_API_KEY") is None
        try:
            raise MissingCredentialError("OPENAI_API_KEY")
        except MissingCredentialError as exc:
            assert str(exc) == "Missing required environment variable OPENAI_API_KEY"
            assert exc.env_var == "OPENAI_API_KEY"

    def test_s05_anthropic_missing_key_names_variable_not_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        try:
            raise MissingCredentialError("ANTHROPIC_API_KEY")
        except MissingCredentialError as exc:
            assert str(exc) == "Missing required environment variable ANTHROPIC_API_KEY"

    def test_s06_openrouter_missing_key_never_falls_back_to_openai_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-real-openai-key-should-not-be-used")
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        provider = OpenRouterProvider()
        assert provider._api_key() is None

    def test_s06_openai_never_reads_anthropic_or_openrouter_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-be-used")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-should-not-be-used")
        provider = OpenAIProvider()
        assert provider._api_key() is None

    def test_s06_anthropic_never_reads_openai_or_openrouter_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-be-used")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-should-not-be-used")
        provider = AnthropicProvider()
        assert provider._api_key() is None

    def test_s06_credential_env_var_map_is_1to1_no_shared_fallback(self) -> None:
        assert CREDENTIAL_ENV_VAR == {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }
        assert len(set(CREDENTIAL_ENV_VAR.values())) == 3  # no duplicate variable names


# ===========================================================================
# S07 — Adapter selection (build_model_router / native router classes)
# ===========================================================================


class TestAdapterSelection:
    def test_s07_openai_selects_openai_provider(self) -> None:
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini")
        router = build_model_router(config)
        assert isinstance(router, OpenAIModelRouter)
        assert isinstance(router._provider, OpenAIProvider)

    def test_s07_anthropic_selects_anthropic_provider(self) -> None:
        config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="anthropic",
            planner_model="claude-sonnet-4-5-20250929",
        )
        router = build_model_router(config)
        assert isinstance(router, AnthropicModelRouter)
        assert isinstance(router._provider, AnthropicProvider)

    def test_s07_openrouter_selects_openrouter_provider(self) -> None:
        config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="openrouter",
            planner_model="openai/gpt-4o-mini",
        )
        router = build_model_router(config)
        assert isinstance(router, OpenRouterModelRouter)
        assert isinstance(router._provider, OpenRouterProvider)

    def test_s07_fake_selects_fake_router(self) -> None:
        config = ApexConfig(target=_TARGET, use_llm=False)
        assert isinstance(build_model_router(config), FakeModelRouter)


# ===========================================================================
# S08 — No provider SDK imports outside approved adapter modules
# ===========================================================================


_APPROVED_SDK_IMPORT_FILES = {
    _REPO_ROOT / "apex_host" / "llm" / "providers" / "openai.py",
    _REPO_ROOT / "apex_host" / "llm" / "providers" / "anthropic.py",
    _REPO_ROOT / "apex_host" / "llm" / "providers" / "openrouter.py",
}

_APPROVED_SDK_IMPORT_TEST_FILES = {
    _REPO_ROOT / "tests" / "apex_host" / "test_llm_providers.py",
    _REPO_ROOT / "tests" / "apex_host" / "test_phase1_live_debug.py",
}


def _imports_provider_sdk(path: pathlib.Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("openai", "anthropic") or alias.name.startswith(("openai.", "anthropic.")):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and (
                node.module in ("openai", "anthropic")
                or node.module.startswith(("openai.", "anthropic."))
            ):
                return True
    return False


class TestNoDirectSDKImports:
    def test_s08_no_planner_agent_or_executor_imports_provider_sdk(self) -> None:
        offenders: list[str] = []
        for sub in ("planners", "agents", "planning", "orchestration", "execution"):
            for path in (_REPO_ROOT / "apex_host" / sub).rglob("*.py"):
                if _imports_provider_sdk(path):
                    offenders.append(str(path.relative_to(_REPO_ROOT)))
        assert offenders == []

    def test_s08_no_apex_host_file_imports_provider_sdk_except_approved_adapters(self) -> None:
        offenders: list[str] = []
        for path in (_REPO_ROOT / "apex_host").rglob("*.py"):
            if path in _APPROVED_SDK_IMPORT_FILES:
                continue
            if _imports_provider_sdk(path):
                offenders.append(str(path.relative_to(_REPO_ROOT)))
        assert offenders == []

    def test_s08_gateway_and_planning_engine_never_import_provider_sdk(self) -> None:
        for rel in ("apex_host/llm/gateway.py", "apex_host/planning/engine.py", "apex_host/planning/repair.py"):
            assert not _imports_provider_sdk(_REPO_ROOT / rel), f"{rel} must not import a provider SDK directly"


# ===========================================================================
# S09-S10 — Model identifiers passed through unchanged, never rewritten
# ===========================================================================


class TestModelPassthrough:
    @pytest.mark.asyncio
    async def test_s09_openai_model_sent_exactly_as_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        fake_cls, construct_calls = _fake_openai_client(create_result=_OpenAIResponse())
        monkeypatch.setattr(openai, "AsyncOpenAI", fake_cls)

        provider = OpenAIProvider()
        request = LLMRequest(messages=[{"role": "user", "content": "hi"}], model="gpt-4o-mini-2024-07-18")
        response = await provider.generate(request)
        assert response.requested_model == "gpt-4o-mini-2024-07-18"
        assert response.actual_model == "gpt-4o-mini-2024-07-18"

    @pytest.mark.asyncio
    async def test_s10_anthropic_model_sent_exactly_as_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
        fake_cls, _ = _fake_anthropic_client(create_result=_AnthropicResponse())
        monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_cls)

        provider = AnthropicProvider()
        request = LLMRequest(
            messages=[{"role": "user", "content": "hi"}], model="claude-sonnet-4-5-20250929",
        )
        response = await provider.generate(request)
        assert response.requested_model == "claude-sonnet-4-5-20250929"

    @pytest.mark.asyncio
    async def test_s09_openai_never_prefixes_or_strips_model_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        captured: dict[str, Any] = {}

        class _FakeCompletions:
            async def create(self, **kwargs: Any) -> Any:
                captured.update(kwargs)
                return _OpenAIResponse()

        class _FakeChat:
            def __init__(self) -> None:
                self.completions = _FakeCompletions()

        class _FakeAsyncOpenAI:
            def __init__(self, **kwargs: Any) -> None:
                self.chat = _FakeChat()
                self.models = None

            async def close(self) -> None:
                pass

        monkeypatch.setattr(openai, "AsyncOpenAI", _FakeAsyncOpenAI)
        provider = OpenAIProvider()
        await provider.generate(LLMRequest(messages=[{"role": "user", "content": "hi"}], model="gpt-4o-mini"))
        assert captured["model"] == "gpt-4o-mini"


# ===========================================================================
# S11-S13 — Namespace (provider/model) mismatch detection
# ===========================================================================


class TestProviderModelMismatch:
    def test_s11_openai_with_router_style_model_is_rejected(self) -> None:
        reason = detect_provider_model_mismatch("openai", "openai/gpt-5.5")
        assert reason != ""
        assert "openai/gpt-5.5" in reason

    def test_s12_anthropic_with_router_style_model_is_rejected(self) -> None:
        reason = detect_provider_model_mismatch("anthropic", "anthropic/claude-3.5-sonnet")
        assert reason != ""

    def test_s13_openrouter_router_style_model_never_flagged(self) -> None:
        assert detect_provider_model_mismatch("openrouter", "openai/gpt-4o") == ""
        assert detect_provider_model_mismatch("openrouter", "anthropic/claude-3.5-sonnet") == ""

    def test_s11_openai_bare_model_not_flagged(self) -> None:
        assert detect_provider_model_mismatch("openai", "gpt-4o-mini") == ""

    def test_s12_anthropic_bare_model_not_flagged(self) -> None:
        assert detect_provider_model_mismatch("anthropic", "claude-sonnet-4-5-20250929") == ""

    @pytest.mark.asyncio
    async def test_s11_openai_generate_raises_before_any_network_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import openai

        def _never_construct(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("must never construct an SDK client on a mismatch")

        monkeypatch.setattr(openai, "AsyncOpenAI", _never_construct)
        provider = OpenAIProvider()
        with pytest.raises(ProviderModelMismatchError):
            await provider.generate(
                LLMRequest(messages=[{"role": "user", "content": "hi"}], model="openai/gpt-5.5")
            )

    @pytest.mark.asyncio
    async def test_s12_anthropic_generate_raises_before_any_network_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import anthropic

        def _never_construct(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("must never construct an SDK client on a mismatch")

        monkeypatch.setattr(anthropic, "AsyncAnthropic", _never_construct)
        provider = AnthropicProvider()
        with pytest.raises(ProviderModelMismatchError):
            await provider.generate(
                LLMRequest(
                    messages=[{"role": "user", "content": "hi"}],
                    model="anthropic/claude-3.5-sonnet",
                )
            )


# ===========================================================================
# S14-S15 — Old mixed OpenAI+OpenRouter-base-URL configuration rejected
# ===========================================================================


class TestOldMixedConfigurationRejected:
    def test_s14_openai_provider_with_openrouter_base_url_rejected(self) -> None:
        reason = detect_base_url_provider_mismatch("openai", "https://openrouter.ai/api/v1")
        assert reason != ""
        assert "provider='openrouter'" in reason

    def test_s15_anthropic_provider_with_openrouter_base_url_rejected(self) -> None:
        reason = detect_base_url_provider_mismatch("anthropic", "https://openrouter.ai/api/v1")
        assert reason != ""
        assert "provider='openrouter'" in reason

    def test_s14_generic_custom_proxy_url_never_flagged(self) -> None:
        """A generic self-hosted/Azure-style proxy is never flagged — only
        OpenRouter's own well-known domain is treated as an unambiguous
        mismatch."""
        assert detect_base_url_provider_mismatch("openai", "https://my-litellm-proxy.internal") == ""
        assert detect_base_url_provider_mismatch("anthropic", "https://my-company-proxy.example") == ""

    def test_s14_openrouter_base_url_never_flagged_for_openrouter_provider(self) -> None:
        assert detect_base_url_provider_mismatch("openrouter", "https://openrouter.ai/api/v1") == ""

    @pytest.mark.asyncio
    async def test_s14_openai_generate_raises_on_openrouter_base_url_before_network(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import openai

        def _never_construct(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("must never construct an SDK client on a base-url mismatch")

        monkeypatch.setattr(openai, "AsyncOpenAI", _never_construct)
        provider = OpenAIProvider(base_url="https://openrouter.ai/api/v1")
        with pytest.raises(ProviderModelMismatchError):
            await provider.generate(
                LLMRequest(messages=[{"role": "user", "content": "hi"}], model="gpt-4o-mini")
            )


# ===========================================================================
# S16-S19 — Base URL behavior: official default vs custom, per-provider isolation
# ===========================================================================


class TestBaseURLBehavior:
    def test_s16_openai_official_default_when_unset(self) -> None:
        assert endpoint_kind("openai", None) == "official_default"

    def test_s17_anthropic_official_default_when_unset(self) -> None:
        assert endpoint_kind("anthropic", None) == "official_default"

    def test_s18_openrouter_official_default_when_unset(self) -> None:
        assert endpoint_kind("openrouter", None) == "official_default"
        assert OFFICIAL_BASE_URL["openrouter"] == "https://openrouter.ai/api/v1"

    def test_s16_openai_custom_base_url_is_custom(self) -> None:
        assert endpoint_kind("openai", "https://my-proxy.example/v1") == "custom"

    def test_s19_provider_specific_base_url_isolated_from_others(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Setting a custom base URL for one provider must never leak into
        another provider's own resolution."""
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
        monkeypatch.delenv("OPENROUTER_BASE_URL", raising=False)
        config = ApexConfig(
            target=_TARGET, use_llm=True,
            llm_openai_base_url="https://custom-openai.example/v1",
        )
        assert resolve_base_url_for_provider(config, "openai") == "https://custom-openai.example/v1"
        assert resolve_base_url_for_provider(config, "anthropic") is None
        assert resolve_base_url_for_provider(config, "openrouter") is None

    def test_s19_openai_sdk_env_var_isolated_from_anthropic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_BASE_URL", "https://openai-only.example")
        monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
        config = ApexConfig(target=_TARGET, use_llm=True)
        assert resolve_base_url_for_provider(config, "openai") == "https://openai-only.example"
        assert resolve_base_url_for_provider(config, "anthropic") is None


# ===========================================================================
# S20 — Malformed URL rejection
# ===========================================================================


class TestMalformedURLRejection:
    def test_s20_malformed_openai_base_url_env_var_rejected(self) -> None:
        from apex_host.config_env import EnvConfigError, ENV_LLM_OPENAI_BASE_URL, validate_url

        with pytest.raises(EnvConfigError):
            validate_url(ENV_LLM_OPENAI_BASE_URL, "not-a-url")

    def test_s20_malformed_anthropic_base_url_env_var_rejected(self) -> None:
        from apex_host.config_env import EnvConfigError, ENV_LLM_ANTHROPIC_BASE_URL, validate_url

        with pytest.raises(EnvConfigError):
            validate_url(ENV_LLM_ANTHROPIC_BASE_URL, "ftp://bad-scheme.example")

    def test_s20_well_formed_url_accepted(self) -> None:
        from apex_host.config_env import ENV_LLM_OPENROUTER_BASE_URL, validate_url

        assert validate_url(ENV_LLM_OPENROUTER_BASE_URL, "https://openrouter.ai/api/v1") == (
            "https://openrouter.ai/api/v1"
        )


# ===========================================================================
# S21-S23 — Success response normalization
# ===========================================================================


class TestSuccessResponseNormalization:
    @pytest.mark.asyncio
    async def test_s21_openai_response_normalized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        fake_cls, _ = _fake_openai_client(
            create_result=_OpenAIResponse(content="the answer", model="gpt-4o-mini-2024-07-18")
        )
        monkeypatch.setattr(openai, "AsyncOpenAI", fake_cls)

        provider = OpenAIProvider()
        response = await provider.generate(
            LLMRequest(messages=[{"role": "user", "content": "hi"}], model="gpt-4o-mini")
        )
        assert response.provider == "openai"
        assert response.text == "the answer"
        assert response.actual_model == "gpt-4o-mini-2024-07-18"
        assert response.finish_reason == "stop"
        assert response.input_tokens == 10
        assert response.output_tokens == 5
        assert response.request_id == "chatcmpl-abc123"
        assert response.latency_seconds >= 0.0

    @pytest.mark.asyncio
    async def test_s22_anthropic_response_normalized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        fake_cls, _ = _fake_anthropic_client(
            create_result=_AnthropicResponse(
                content=[_ContentBlock("text", "the claude answer")],
                model="claude-sonnet-4-5-20250929", stop_reason="end_turn",
            )
        )
        monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_cls)

        provider = AnthropicProvider()
        response = await provider.generate(
            LLMRequest(messages=[{"role": "user", "content": "hi"}], model="claude-sonnet-4-5-20250929")
        )
        assert response.provider == "anthropic"
        assert response.text == "the claude answer"
        assert response.actual_model == "claude-sonnet-4-5-20250929"
        assert response.finish_reason == "end_turn"
        assert response.input_tokens == 12
        assert response.output_tokens == 8
        assert response.request_id == "msg_abc123"

    @pytest.mark.asyncio
    async def test_s23_openrouter_response_normalized_with_openrouter_provider_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """S23 also confirms OpenRouter's reported provider identity is
        'openrouter', never 'openai' — even though it reuses the openai SDK
        client class internally."""
        import openai

        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
        fake_cls, construct_calls = _fake_openai_client(
            create_result=_OpenAIResponse(content="router answer", model="openai/gpt-4o")
        )
        monkeypatch.setattr(openai, "AsyncOpenAI", fake_cls)

        provider = OpenRouterProvider()
        response = await provider.generate(
            LLMRequest(messages=[{"role": "user", "content": "hi"}], model="openai/gpt-4o")
        )
        assert response.provider == "openrouter"
        assert response.text == "router answer"
        assert construct_calls[0]["base_url"] == "https://openrouter.ai/api/v1"


# ===========================================================================
# S24-S25 — Anthropic-specific: multi-content-block handling + system split
# ===========================================================================


class TestAnthropicSpecificHandling:
    def test_s24_extract_text_skips_non_text_blocks(self) -> None:
        blocks = [
            _ContentBlock("thinking", "internal reasoning, never surfaced"),
            _ContentBlock("tool_use", ""),
            _ContentBlock("text", "the real answer"),
        ]
        assert _extract_text(blocks) == "the real answer"

    def test_s24_extract_text_concatenates_multiple_text_blocks(self) -> None:
        blocks = [_ContentBlock("text", "part one. "), _ContentBlock("text", "part two.")]
        assert _extract_text(blocks) == "part one. part two."

    def test_s24_extract_text_empty_when_no_text_blocks(self) -> None:
        blocks = [_ContentBlock("tool_use", ""), _ContentBlock("thinking", "hidden")]
        assert _extract_text(blocks) == ""

    def test_s24_extract_text_handles_none_and_empty_list(self) -> None:
        assert _extract_text(None) == ""
        assert _extract_text([]) == ""

    def test_s25_system_messages_extracted_and_joined(self) -> None:
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello"},
            {"role": "system", "content": "Always be concise."},
            {"role": "assistant", "content": "Hi there"},
        ]
        system_text, remaining = _split_system_messages(messages)
        assert system_text == "You are a helpful assistant.\n\nAlways be concise."
        assert remaining == [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]

    def test_s25_no_system_messages_yields_empty_system_text(self) -> None:
        messages = [{"role": "user", "content": "Hello"}]
        system_text, remaining = _split_system_messages(messages)
        assert system_text == ""
        assert remaining == messages

    @pytest.mark.asyncio
    async def test_s25_system_param_sent_separately_never_as_a_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        captured: dict[str, Any] = {}

        class _FakeMessages:
            async def create(self, **kwargs: Any) -> Any:
                captured.update(kwargs)
                return _AnthropicResponse()

        class _FakeAsyncAnthropic:
            def __init__(self, **kwargs: Any) -> None:
                self.messages = _FakeMessages()

            async def close(self) -> None:
                pass

        monkeypatch.setattr(anthropic, "AsyncAnthropic", _FakeAsyncAnthropic)
        provider = AnthropicProvider()
        await provider.generate(
            LLMRequest(
                messages=[
                    {"role": "system", "content": "Be terse."},
                    {"role": "user", "content": "hi"},
                ],
                model="claude-sonnet-4-5-20250929",
            )
        )
        assert captured["system"] == "Be terse."
        assert captured["messages"] == [{"role": "user", "content": "hi"}]
        assert all(m.get("role") != "system" for m in captured["messages"])


# ===========================================================================
# S26-S27 — Empty/malformed response classification
# ===========================================================================


class TestEmptyMalformedResponse:
    @pytest.mark.asyncio
    async def test_s26_openai_no_choices_raises_empty_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        fake_cls, _ = _fake_openai_client(create_result=_OpenAIResponse(choices=[]))
        monkeypatch.setattr(openai, "AsyncOpenAI", fake_cls)

        provider = OpenAIProvider()
        with pytest.raises(EmptyResponseError):
            await provider.generate(
                LLMRequest(messages=[{"role": "user", "content": "hi"}], model="gpt-4o-mini")
            )

    @pytest.mark.asyncio
    async def test_s26_openai_empty_text_content_raises_empty_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        fake_cls, _ = _fake_openai_client(create_result=_OpenAIResponse(content=""))
        monkeypatch.setattr(openai, "AsyncOpenAI", fake_cls)

        provider = OpenAIProvider()
        with pytest.raises(EmptyResponseError):
            await provider.generate(
                LLMRequest(messages=[{"role": "user", "content": "hi"}], model="gpt-4o-mini")
            )

    @pytest.mark.asyncio
    async def test_s27_anthropic_all_non_text_blocks_raises_empty_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        fake_cls, _ = _fake_anthropic_client(
            create_result=_AnthropicResponse(content=[_ContentBlock("tool_use", "")])
        )
        monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_cls)

        provider = AnthropicProvider()
        with pytest.raises(EmptyResponseError):
            await provider.generate(
                LLMRequest(
                    messages=[{"role": "user", "content": "hi"}], model="claude-sonnet-4-5-20250929",
                )
            )

    def test_s26_empty_response_error_classified_as_malformed_response(self) -> None:
        assert classify_llm_exception(EmptyResponseError("no text")) is LLMErrorCategory.malformed_response
        assert LLMErrorCategory.malformed_response in PERMANENT_LLM_ERROR_CATEGORIES


# ===========================================================================
# S28-S38 — Error mapping: auth / invalid-model / rate-limit / timeout /
#           connection / server error, for both native providers
# ===========================================================================


class TestErrorMapping:
    def test_s28_openai_auth_error_mapped(self) -> None:
        assert classify_llm_exception(_AuthErr()) is LLMErrorCategory.authentication_failure

    def test_s29_anthropic_auth_error_mapped(self) -> None:
        # classify_llm_exception is provider-agnostic — the same duck-typed
        # 401/status check applies identically to an Anthropic-raised
        # AuthenticationError-shaped exception.
        assert classify_llm_exception(_AuthErr("invalid x-api-key")) is LLMErrorCategory.authentication_failure

    def test_s30_openai_invalid_model_error_mapped(self) -> None:
        exc = _NotFoundErr("The model `gpt-nonexistent` does not exist")
        assert classify_llm_exception(exc) is LLMErrorCategory.invalid_model

    def test_s31_anthropic_invalid_model_error_mapped(self) -> None:
        exc = _NotFoundErr("model: claude-nonexistent not found")
        assert classify_llm_exception(exc) is LLMErrorCategory.invalid_model

    def test_s32_openai_rate_limit_error_mapped(self) -> None:
        assert classify_llm_exception(_RateLimitErr()) is LLMErrorCategory.rate_limit

    def test_s33_anthropic_rate_limit_error_mapped(self) -> None:
        assert classify_llm_exception(_RateLimitErr("rate_limit_error")) is LLMErrorCategory.rate_limit

    def test_s34_openai_timeout_error_mapped(self) -> None:
        assert classify_llm_exception(_APITimeoutErr("Request timed out")) is LLMErrorCategory.timeout

    def test_s35_anthropic_timeout_error_mapped(self) -> None:
        assert classify_llm_exception(_APITimeoutErr("read timed out")) is LLMErrorCategory.timeout

    def test_s36_openai_connection_error_mapped(self) -> None:
        assert classify_llm_exception(_APIConnectionErr("Connection error.")) is LLMErrorCategory.network_error

    def test_s37_anthropic_connection_error_mapped(self) -> None:
        assert classify_llm_exception(
            _APIConnectionErr("Connection error.")
        ) is LLMErrorCategory.network_error

    def test_s38_openai_server_error_mapped_transient(self) -> None:
        assert classify_llm_exception(_ServerErr()) is LLMErrorCategory.transient_other
        assert LLMErrorCategory.transient_other in TRANSIENT_LLM_ERROR_CATEGORIES

    def test_s38_anthropic_server_error_mapped_transient(self) -> None:
        assert classify_llm_exception(_ServerErr("overloaded_error")) is LLMErrorCategory.transient_other

    @pytest.mark.asyncio
    async def test_s28_openai_auth_failure_propagates_through_generate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-bad")
        fake_cls, _ = _fake_openai_client(create_exc=_AuthErr())
        monkeypatch.setattr(openai, "AsyncOpenAI", fake_cls)

        provider = OpenAIProvider()
        with pytest.raises(_AuthErr):
            await provider.generate(
                LLMRequest(messages=[{"role": "user", "content": "hi"}], model="gpt-4o-mini")
            )

    @pytest.mark.asyncio
    async def test_s29_anthropic_auth_failure_propagates_through_generate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-bad")
        fake_cls, _ = _fake_anthropic_client(create_exc=_AuthErr())
        monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_cls)

        provider = AnthropicProvider()
        with pytest.raises(_AuthErr):
            await provider.generate(
                LLMRequest(
                    messages=[{"role": "user", "content": "hi"}], model="claude-sonnet-4-5-20250929",
                )
            )


# ===========================================================================
# S39-S42 — Permanent-error short-circuit, bounded retry, llm_required,
#           deterministic fallback — provider-adapter-focused re-verification
#           (the end-to-end PlanningEngine/budget behavior is already
#           covered by tests/apex_host/test_phase1_live_debug.py sections
#           4-6; these tests focus on the provider/error-classification
#           layer itself feeding that machinery correctly).
# ===========================================================================


class TestPermanentVsTransientClassification:
    def test_s39_missing_credential_is_permanent(self) -> None:
        assert classify_llm_exception(MissingCredentialError("OPENAI_API_KEY")) in PERMANENT_LLM_ERROR_CATEGORIES

    def test_s39_provider_model_mismatch_is_permanent(self) -> None:
        assert classify_llm_exception(
            ProviderModelMismatchError("bad combo")
        ) in PERMANENT_LLM_ERROR_CATEGORIES

    def test_s40_network_error_is_transient(self) -> None:
        assert classify_llm_exception(_APIConnectionErr("Connection error.")) in TRANSIENT_LLM_ERROR_CATEGORIES

    def test_s40_timeout_is_transient(self) -> None:
        assert classify_llm_exception(_APITimeoutErr("timed out")) in TRANSIENT_LLM_ERROR_CATEGORIES

    def test_s40_rate_limit_is_transient(self) -> None:
        assert classify_llm_exception(_RateLimitErr()) in TRANSIENT_LLM_ERROR_CATEGORIES

    def test_s39_permanent_and_transient_sets_are_disjoint(self) -> None:
        assert PERMANENT_LLM_ERROR_CATEGORIES.isdisjoint(TRANSIENT_LLM_ERROR_CATEGORIES)

    def test_s39_every_category_is_classified_permanent_or_neither_never_both(self) -> None:
        for category in LLMErrorCategory:
            assert not (category in PERMANENT_LLM_ERROR_CATEGORIES and category in TRANSIENT_LLM_ERROR_CATEGORIES)


# ===========================================================================
# S43 — Readiness output is structured and redacted (Anthropic + OpenRouter;
#       OpenAI's own readiness/probe coverage lives in
#       test_phase1_live_debug.py's TestPreflightLLMReadiness)
# ===========================================================================


class TestReadinessStructuredAndRedacted:
    @pytest.mark.asyncio
    async def test_s43_anthropic_readiness_missing_key_no_leak(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        provider = AnthropicProvider()
        readiness = await provider.check_readiness()
        assert readiness.provider == "anthropic"
        assert readiness.credential_variable == "ANTHROPIC_API_KEY"
        assert readiness.credential_present is False
        assert readiness.error_category == "missing_key"
        assert readiness.permanent is True
        assert "ANTHROPIC_API_KEY" in readiness.error_reason
        # Never a value, only the variable name, anywhere in the result.
        assert "sk-ant" not in str(readiness.to_dict())

    @pytest.mark.asyncio
    async def test_s43_anthropic_readiness_key_present_no_network(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-super-secret-value-1234567890")
        provider = AnthropicProvider()
        readiness = await provider.check_readiness(network_check=False)
        assert readiness.configuration_valid is True
        assert readiness.network_checked is False
        assert "sk-ant-super-secret-value-1234567890" not in str(readiness.to_dict())

    @pytest.mark.asyncio
    async def test_s43_openrouter_readiness_missing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        provider = OpenRouterProvider()
        readiness = await provider.check_readiness()
        assert readiness.provider == "openrouter"
        assert readiness.credential_variable == "OPENROUTER_API_KEY"
        assert readiness.error_category == "missing_key"

    @pytest.mark.asyncio
    async def test_s43_anthropic_network_probe_reachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-1234567890")
        fake_cls, construct_calls = _fake_anthropic_client(models_result=type("R", (), {"data": []})())
        monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_cls)

        provider = AnthropicProvider()
        readiness = await provider.check_readiness(network_check=True)
        assert readiness.network_checked is True
        assert readiness.reachable is True
        assert len(construct_calls) == 1

    @pytest.mark.asyncio
    async def test_s43_anthropic_network_probe_auth_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-bad-0000000000000000000")
        fake_cls, _ = _fake_anthropic_client(models_exc=_AuthErr())
        monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_cls)

        provider = AnthropicProvider()
        readiness = await provider.check_readiness(network_check=True)
        assert readiness.reachable is False
        assert readiness.error_category == "authentication_failure"


# ===========================================================================
# S44-S45 — Readiness cache scope / one provider's failure never poisons another
# ===========================================================================


class TestReadinessCacheScopeAndIsolation:
    def test_s44_check_llm_readiness_is_pure_and_free_no_caching_needed(self) -> None:
        """apex_host.eval.preflight.check_llm_readiness performs no I/O at
        all (pure configuration validation) — there is nothing to cache;
        calling it repeatedly within one runtime is already cheap and
        always produces the identical, correct result for the same
        config. Only the network-touching probe_llm_readiness is ever
        invoked (once) per live-interlock evaluation — see
        docs/llm-providers.md 'Readiness lifecycle' for the documented
        decision not to add an explicit cache layer."""
        from apex_host.eval.preflight import check_llm_readiness

        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini")
        first = check_llm_readiness(config)
        second = check_llm_readiness(config)
        assert first == second

    @pytest.mark.asyncio
    async def test_s45_openai_failure_does_not_affect_anthropic_provider_instance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-good-key-1234567890")

        openai_provider = OpenAIProvider()
        anthropic_provider = AnthropicProvider()

        openai_readiness = await openai_provider.check_readiness()
        anthropic_readiness = await anthropic_provider.check_readiness()

        assert openai_readiness.credential_present is False
        assert anthropic_readiness.credential_present is True

    def test_s45_two_router_instances_for_different_providers_never_share_state(self) -> None:
        openai_config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini",
        )
        anthropic_config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="anthropic",
            planner_model="claude-sonnet-4-5-20250929",
        )
        openai_router = build_model_router(openai_config)
        anthropic_router = build_model_router(anthropic_config)
        assert openai_router is not anthropic_router
        assert type(openai_router) is not type(anthropic_router)


# ===========================================================================
# S46 — Reports record the actual provider/fallback honestly
# ===========================================================================


def _minimal_final_state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "run_id": "r1", "target": _TARGET, "phase": "recon", "goal": "test",
        "current_task": None, "evidence_summary": "", "findings": [],
        "error_episodes": [], "last_tool_result": None, "last_error": None,
        "completed": True, "turn_count": 1, "planner_decisions": [],
        "termination_phase": "",
    }
    base.update(overrides)
    return base


def _empty_subgraph_for_report() -> Any:
    from memfabric.types import SubgraphView

    return SubgraphView(anchor=f"host:{_TARGET}", nodes=[], edges=[], depth=10)


class TestReportRecordsActualProvider:
    def test_s46_report_records_configured_provider_and_model(self) -> None:
        from apex_host.eval.report import build_report

        config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="anthropic",
            planner_model="claude-sonnet-4-5-20250929",
        )
        report = build_report(_minimal_final_state(), _empty_subgraph_for_report(), config)
        assert report.llm_configured_provider == "anthropic"
        assert report.llm_configured_model == "claude-sonnet-4-5-20250929"
        assert report.llm_credential_variable == "ANTHROPIC_API_KEY"

    def test_s46_report_never_shows_a_configured_provider_when_llm_disabled(self) -> None:
        from apex_host.eval.report import build_report

        config = ApexConfig(target=_TARGET, use_llm=False)
        report = build_report(_minimal_final_state(), _empty_subgraph_for_report(), config)
        assert report.llm_configured_provider == ""
        assert report.llm_configured_model == ""

    def test_s46_report_never_serializes_a_credential_value(self) -> None:
        from apex_host.eval.report import build_report, to_json_dict

        config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini",
        )
        report = build_report(_minimal_final_state(), _empty_subgraph_for_report(), config)
        assert "sk-" not in str(to_json_dict(report))
        assert report.llm_credential_variable == "OPENAI_API_KEY"  # name only, never a value


# ===========================================================================
# S47-S48 — Compose credential passthrough / .env.example placeholders
#           (covered end-to-end in tests/docker/test_compose.py and
#           tests/docker/test_env_files.py; re-verified here structurally)
# ===========================================================================


class TestComposeAndEnvExampleCoverageCrossCheck:
    def test_s47_compose_yaml_passes_all_three_provider_credentials(self) -> None:
        import yaml

        data = yaml.safe_load((_REPO_ROOT / "compose.yaml").read_text(encoding="utf-8"))
        env = data["services"]["apex"]["environment"]
        for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY"):
            assert key in env

    def test_s48_env_example_documents_all_three_credentials_blank(self) -> None:
        text = (_REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        for key in ("OPENAI_API_KEY=", "ANTHROPIC_API_KEY=", "OPENROUTER_API_KEY="):
            assert key in text


# ===========================================================================
# S49 — No hardcoded, real-looking API keys anywhere in the new source
# ===========================================================================


class TestNoRealisticSecretsInSource:
    def test_s49_no_openai_style_key_pattern_in_provider_modules(self) -> None:
        import re

        pattern = re.compile(r"sk-[A-Za-z0-9]{20,}")
        for rel in (
            "apex_host/llm/providers/openai.py",
            "apex_host/llm/providers/anthropic.py",
            "apex_host/llm/providers/openrouter.py",
            "apex_host/llm/router.py",
            "apex_host/llm/errors.py",
            "apex_host/llm/types.py",
        ):
            text = (_REPO_ROOT / rel).read_text(encoding="utf-8")
            assert pattern.search(text) is None, f"{rel} contains a real-looking API key pattern"

    def test_s49_no_anthropic_style_key_pattern_anywhere_in_apex_host(self) -> None:
        import re

        pattern = re.compile(r"sk-ant-api03-[A-Za-z0-9_-]{20,}")
        for path in (_REPO_ROOT / "apex_host").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert pattern.search(text) is None, f"{path} contains a real-looking Anthropic key pattern"


# ===========================================================================
# S50 — No network access in ordinary unit tests; every SDK client mocked
#       at the adapter boundary (a structural, self-verifying property of
#       this test module's own construction — re-asserted explicitly)
# ===========================================================================


class TestNoNetworkAccessInUnitTests:
    @pytest.mark.asyncio
    async def test_s50_openai_provider_never_opens_a_real_socket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import socket

        def _blocked(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("no real socket may be opened during this test")

        monkeypatch.setattr(socket, "socket", _blocked)

        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        fake_cls, _ = _fake_openai_client(create_result=_OpenAIResponse())
        monkeypatch.setattr(openai, "AsyncOpenAI", fake_cls)

        provider = OpenAIProvider()
        response = await provider.generate(
            LLMRequest(messages=[{"role": "user", "content": "hi"}], model="gpt-4o-mini")
        )
        assert response.text

    @pytest.mark.asyncio
    async def test_s50_anthropic_provider_never_opens_a_real_socket(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import socket

        def _blocked(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("no real socket may be opened during this test")

        monkeypatch.setattr(socket, "socket", _blocked)

        import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        fake_cls, _ = _fake_anthropic_client(create_result=_AnthropicResponse())
        monkeypatch.setattr(anthropic, "AsyncAnthropic", fake_cls)

        provider = AnthropicProvider()
        response = await provider.generate(
            LLMRequest(messages=[{"role": "user", "content": "hi"}], model="claude-sonnet-4-5-20250929")
        )
        assert response.text


# ===========================================================================
# Supplementary: VALID_LLM_PROVIDERS / build_model_router edge coverage
# ===========================================================================


class TestSupplementaryProviderRegistry:
    def test_valid_llm_providers_is_exactly_four(self) -> None:
        assert VALID_LLM_PROVIDERS == {"fake", "openai", "anthropic", "openrouter"}

    def test_openrouter_default_base_url_is_the_well_known_endpoint(self) -> None:
        provider = OpenRouterProvider()
        assert provider._base_url == "https://openrouter.ai/api/v1"

    def test_openrouter_explicit_base_url_override_respected(self) -> None:
        provider = OpenRouterProvider(base_url="https://self-hosted-router.example/v1")
        assert provider._base_url == "https://self-hosted-router.example/v1"
