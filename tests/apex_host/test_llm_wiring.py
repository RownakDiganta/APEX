# test_llm_wiring.py
# Tests for LLM wiring: CLI flag parsing, ApexConfig fields, ModelRouter construction, and fallback behavior.
"""Tests for the LLM wiring layer (Phase 6), updated for Phase 5's native
OpenAI/Anthropic/OpenRouter provider architecture.

Covers:
- ApexConfig carries use_llm, llm_provider, llm_base_url with safe defaults.
- planner_model/executor_model/parser_model default to "" (no provider-neutral
  default model exists anywhere in this codebase — Phase 5).
- Both CLI entry points (main.py and run_htb_local.py) expose --use-llm,
  --llm-provider, --llm-model, --llm-base-url (plus the three new
  --llm-{openai,anthropic,openrouter}-base-url flags) and wire them into
  ApexConfig.
- build_model_router() (the Phase 5 factory) selects FakeModelRouter for
  use_llm=False / provider=fake, and the correct native router class
  (OpenAIModelRouter / AnthropicModelRouter / OpenRouterModelRouter)
  otherwise — this is the ONE place apex_host.runtime delegates to; it no
  longer hardcodes a specific provider class or imports FakeModelRouter/
  OpenAIModelRouter directly by name.
- FakeModelRouter always returns None (safe default for tests and dry-run).
- ApexRuntime.run() calls build_model_router() exactly once per run().
- PlanningEngine receives the router and falls back to deterministic when LLM
  returns invalid output.
- dry_run=True engagement completes with no real subprocess calls regardless
  of use_llm setting.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from apex_host.config import ApexConfig
from apex_host.llm.router import (
    AnthropicModelRouter,
    FakeModelRouter,
    ModelRouter,
    OpenAIModelRouter,
    OpenRouterModelRouter,
    build_model_router,
    resolve_base_url_for_provider,
)


# ---------------------------------------------------------------------------
# ApexConfig new fields
# ---------------------------------------------------------------------------

class TestApexConfigLLMFields:
    def test_use_llm_defaults_false(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.use_llm is False

    def test_llm_provider_defaults_fake(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.llm_provider == "fake"

    def test_llm_base_url_defaults_none(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.llm_base_url is None

    def test_can_set_use_llm_true(self) -> None:
        config = ApexConfig(target="10.0.0.1", use_llm=True)
        assert config.use_llm is True

    def test_can_set_llm_provider(self) -> None:
        config = ApexConfig(target="10.0.0.1", llm_provider="openai")
        assert config.llm_provider == "openai"

    def test_can_set_llm_base_url(self) -> None:
        config = ApexConfig(target="10.0.0.1", llm_base_url="https://openrouter.ai/api/v1")
        assert config.llm_base_url == "https://openrouter.ai/api/v1"

    def test_provider_specific_base_url_fields_default_none(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.llm_openai_base_url is None
        assert config.llm_anthropic_base_url is None
        assert config.llm_openrouter_base_url is None

    def test_can_set_provider_specific_base_url_fields(self) -> None:
        config = ApexConfig(
            target="10.0.0.1",
            llm_openai_base_url="https://openai.example",
            llm_anthropic_base_url="https://anthropic.example",
            llm_openrouter_base_url="https://openrouter.example",
        )
        assert config.llm_openai_base_url == "https://openai.example"
        assert config.llm_anthropic_base_url == "https://anthropic.example"
        assert config.llm_openrouter_base_url == "https://openrouter.example"


class TestApexConfigModelNames:
    """Phase 5: there is no provider-neutral default model. Every model
    field defaults to the empty string — use_llm=True requires an explicit
    model for the selected provider, or readiness/config validation fails
    fast with a provider_model_mismatch-style diagnostic."""

    def test_planner_model_default_is_empty(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.planner_model == ""

    def test_executor_model_default_is_empty(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.executor_model == ""

    def test_parser_model_default_is_empty(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.parser_model == ""

    def test_can_set_native_openai_model(self) -> None:
        config = ApexConfig(target="10.0.0.1", planner_model="gpt-4o-mini")
        assert config.planner_model == "gpt-4o-mini"

    def test_can_set_native_anthropic_model(self) -> None:
        config = ApexConfig(target="10.0.0.1", planner_model="claude-sonnet-4-5-20250929")
        assert config.planner_model == "claude-sonnet-4-5-20250929"


# ---------------------------------------------------------------------------
# FakeModelRouter behaviour
# ---------------------------------------------------------------------------

class TestFakeModelRouter:
    def test_planner_llm_returns_none(self) -> None:
        assert FakeModelRouter().planner_llm() is None

    def test_executor_llm_returns_none(self) -> None:
        assert FakeModelRouter().executor_llm() is None

    def test_parser_llm_returns_none(self) -> None:
        assert FakeModelRouter().parser_llm() is None

    def test_reflector_llm_returns_none(self) -> None:
        assert FakeModelRouter().reflector_llm() is None


# ---------------------------------------------------------------------------
# build_model_router() — the Phase 5 provider-selection factory
# ---------------------------------------------------------------------------

class TestBuildModelRouter:
    def test_use_llm_false_returns_fake(self) -> None:
        config = ApexConfig(target="10.0.0.1", use_llm=False, llm_provider="openai")
        assert isinstance(build_model_router(config), FakeModelRouter)

    def test_use_llm_true_provider_fake_returns_fake(self) -> None:
        config = ApexConfig(target="10.0.0.1", use_llm=True, llm_provider="fake")
        assert isinstance(build_model_router(config), FakeModelRouter)

    def test_provider_openai_returns_openai_router(self) -> None:
        config = ApexConfig(
            target="10.0.0.1", use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini",
        )
        assert isinstance(build_model_router(config), OpenAIModelRouter)

    def test_provider_anthropic_returns_anthropic_router(self) -> None:
        config = ApexConfig(
            target="10.0.0.1", use_llm=True, llm_provider="anthropic",
            planner_model="claude-sonnet-4-5-20250929",
        )
        assert isinstance(build_model_router(config), AnthropicModelRouter)

    def test_provider_openrouter_returns_openrouter_router(self) -> None:
        config = ApexConfig(
            target="10.0.0.1", use_llm=True, llm_provider="openrouter",
            planner_model="openai/gpt-4o-mini",
        )
        assert isinstance(build_model_router(config), OpenRouterModelRouter)

    def test_unrecognized_provider_raises(self) -> None:
        # Defense-in-depth only — apex_host.config_env already validates
        # llm_provider before an ApexConfig with use_llm=True is normally
        # constructed. Direct construction bypasses that, so build_model_router
        # itself must still refuse rather than silently falling back.
        config = ApexConfig(target="10.0.0.1", use_llm=True, llm_provider="not-a-real-provider")
        with pytest.raises(ValueError, match="unrecognized llm_provider"):
            build_model_router(config)


# ---------------------------------------------------------------------------
# Native provider router base-URL precedence
# ---------------------------------------------------------------------------

class TestNativeRouterBaseURL:
    def test_openai_config_base_url_takes_precedence_over_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_BASE_URL", "https://env-base")
        config = ApexConfig(
            target="10.0.0.1", use_llm=True, llm_provider="openai",
            llm_openai_base_url="https://specific-base",
            llm_base_url="https://legacy-base",
        )
        assert resolve_base_url_for_provider(config, "openai") == "https://specific-base"

    def test_openai_legacy_base_url_wins_over_env_when_specific_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_BASE_URL", "https://env-base")
        config = ApexConfig(target="10.0.0.1", use_llm=True, llm_base_url="https://legacy-base")
        assert resolve_base_url_for_provider(config, "openai") == "https://legacy-base"

    def test_openai_env_base_url_used_when_config_is_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_BASE_URL", "https://env-base")
        config = ApexConfig(target="10.0.0.1", use_llm=True, llm_base_url=None)
        assert resolve_base_url_for_provider(config, "openai") == "https://env-base"

    def test_openai_none_falls_back_to_sdk_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        config = ApexConfig(target="10.0.0.1", use_llm=True, llm_base_url=None)
        assert resolve_base_url_for_provider(config, "openai") is None

    def test_anthropic_base_url_isolated_from_openai(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_BASE_URL", "https://openai-env-base")
        monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
        config = ApexConfig(target="10.0.0.1", use_llm=True, llm_provider="anthropic")
        assert resolve_base_url_for_provider(config, "anthropic") is None

    def test_openai_router_stores_resolved_base_url(self) -> None:
        config = ApexConfig(
            target="10.0.0.1", use_llm=True, llm_provider="openai",
            llm_openai_base_url="https://custom.example/v1", planner_model="gpt-4o-mini",
        )
        router = OpenAIModelRouter(config)
        assert router._base_url == "https://custom.example/v1"

    def test_anthropic_router_stores_resolved_base_url(self) -> None:
        config = ApexConfig(
            target="10.0.0.1", use_llm=True, llm_provider="anthropic",
            llm_anthropic_base_url="https://custom-anthropic.example",
            planner_model="claude-sonnet-4-5-20250929",
        )
        router = AnthropicModelRouter(config)
        assert router._base_url == "https://custom-anthropic.example"

    def test_planner_model_used_in_build(self) -> None:
        config = ApexConfig(
            target="10.0.0.1", use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini",
        )
        router = OpenAIModelRouter(config)
        # Constructing the router never contacts the network or requires a
        # real API key — the SDK client itself is only constructed inside
        # generate()/check_readiness(). We only verify the model is stored.
        assert router._config.planner_model == "gpt-4o-mini"


# ---------------------------------------------------------------------------
# main.py CLI flag parsing
# ---------------------------------------------------------------------------

class TestMainParseCLI:
    def test_default_no_llm(self) -> None:
        # Infra Phase 8: --use-llm's raw argparse default is None (not False)
        # so apex_host.config_env.merge_env_into_args can distinguish "not
        # passed" from "explicitly disabled" when filling in $APEX_USE_LLM.
        # The fully-resolved ApexConfig still defaults use_llm to False.
        from apex_host.config import ApexConfig
        from apex_host.main import parse_args
        args = parse_args(["--target", "10.0.0.1"])
        assert args.use_llm is None
        assert ApexConfig.from_cli_args(args).use_llm is False

    def test_use_llm_flag(self) -> None:
        from apex_host.main import parse_args
        args = parse_args(["--target", "10.0.0.1", "--use-llm"])
        assert args.use_llm is True

    def test_llm_provider_flag(self) -> None:
        from apex_host.main import parse_args
        args = parse_args(["--target", "10.0.0.1", "--llm-provider", "openai"])
        assert args.llm_provider == "openai"

    def test_llm_model_flag(self) -> None:
        from apex_host.main import parse_args
        args = parse_args(["--target", "10.0.0.1", "--llm-model", "gpt-4o-mini"])
        assert args.llm_model == "gpt-4o-mini"

    def test_llm_base_url_flag(self) -> None:
        from apex_host.main import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--llm-base-url", "https://custom.example/v1",
        ])
        assert args.llm_base_url == "https://custom.example/v1"

    def test_llm_openai_base_url_flag(self) -> None:
        from apex_host.main import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--llm-openai-base-url", "https://custom-openai.example/v1",
        ])
        assert args.llm_openai_base_url == "https://custom-openai.example/v1"

    def test_llm_anthropic_base_url_flag(self) -> None:
        from apex_host.main import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--llm-anthropic-base-url", "https://custom-anthropic.example",
        ])
        assert args.llm_anthropic_base_url == "https://custom-anthropic.example"

    def test_llm_openrouter_base_url_flag(self) -> None:
        from apex_host.main import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--llm-openrouter-base-url", "https://custom-openrouter.example/api/v1",
        ])
        assert args.llm_openrouter_base_url == "https://custom-openrouter.example/api/v1"

    def test_all_llm_flags_together(self) -> None:
        from apex_host.main import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--use-llm",
            "--llm-provider", "anthropic",
            "--llm-model", "claude-sonnet-4-5-20250929",
            "--llm-anthropic-base-url", "https://custom-anthropic.example",
        ])
        assert args.use_llm is True
        assert args.llm_provider == "anthropic"
        assert args.llm_model == "claude-sonnet-4-5-20250929"
        assert args.llm_anthropic_base_url == "https://custom-anthropic.example"

    def test_llm_model_none_by_default(self) -> None:
        from apex_host.main import parse_args
        args = parse_args(["--target", "10.0.0.1"])
        assert args.llm_model is None

    def test_provider_specific_base_url_flags_none_by_default(self) -> None:
        from apex_host.main import parse_args
        args = parse_args(["--target", "10.0.0.1"])
        assert args.llm_openai_base_url is None
        assert args.llm_anthropic_base_url is None
        assert args.llm_openrouter_base_url is None


# ---------------------------------------------------------------------------
# run_htb_local.py CLI flag parsing
# ---------------------------------------------------------------------------

class TestRunHTBLocalParseCLI:
    def test_default_no_llm(self) -> None:
        # Infra Phase 8: see TestMainParseCLI.test_default_no_llm's comment —
        # same None-by-default raw-parse contract applies here.
        from apex_host.config import ApexConfig
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args(["--target", "10.0.0.1"])
        assert args.use_llm is None
        assert ApexConfig.from_cli_args(args).use_llm is False

    def test_use_llm_flag(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args(["--target", "10.0.0.1", "--use-llm"])
        assert args.use_llm is True

    def test_llm_provider_flag(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args(["--target", "10.0.0.1", "--llm-provider", "anthropic"])
        assert args.llm_provider == "anthropic"

    def test_llm_model_flag(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args(["--target", "10.0.0.1", "--llm-model", "claude-sonnet-4-5-20250929"])
        assert args.llm_model == "claude-sonnet-4-5-20250929"

    def test_llm_base_url_flag(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--llm-base-url", "https://custom.example/v1",
        ])
        assert args.llm_base_url == "https://custom.example/v1"

    def test_llm_openrouter_base_url_flag(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--llm-openrouter-base-url", "https://custom-openrouter.example/api/v1",
        ])
        assert args.llm_openrouter_base_url == "https://custom-openrouter.example/api/v1"

    def test_all_llm_flags_together(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--use-llm",
            "--llm-provider", "openai",
            "--llm-model", "gpt-4o-mini",
            "--llm-openai-base-url", "https://custom-openai.example/v1",
        ])
        assert args.use_llm is True
        assert args.llm_provider == "openai"
        assert args.llm_model == "gpt-4o-mini"
        assert args.llm_openai_base_url == "https://custom-openai.example/v1"


# ---------------------------------------------------------------------------
# Config construction from CLI args (model override) — via the canonical
# ApexConfig.from_cli_args() factory, not manual dict construction.
# ---------------------------------------------------------------------------

class TestConfigFromCLIArgs:
    def test_llm_model_sets_all_model_fields(self) -> None:
        """--llm-model sets planner_model, executor_model, and parser_model."""
        from apex_host.main import parse_args

        args = parse_args(["--target", "10.0.0.1", "--llm-model", "gpt-4o-mini"])
        config = ApexConfig.from_cli_args(args)

        assert config.planner_model == "gpt-4o-mini"
        assert config.executor_model == "gpt-4o-mini"
        assert config.parser_model == "gpt-4o-mini"

    def test_no_llm_model_keeps_empty_default(self) -> None:
        """Without --llm-model, planner_model stays the empty-string default
        — there is no provider-neutral default model (Phase 5)."""
        from apex_host.main import parse_args

        args = parse_args(["--target", "10.0.0.1"])
        config = ApexConfig.from_cli_args(args)

        assert config.planner_model == ""

    def test_provider_normalized_case_insensitively(self) -> None:
        from apex_host.main import parse_args

        args = parse_args(["--target", "10.0.0.1", "--llm-provider", "OpenAI"])
        config = ApexConfig.from_cli_args(args)
        assert config.llm_provider == "openai"

    def test_invalid_provider_with_use_llm_raises(self) -> None:
        from apex_host.main import parse_args

        args = parse_args([
            "--target", "10.0.0.1", "--use-llm", "--llm-provider", "not-a-real-provider",
        ])
        with pytest.raises(ValueError, match="invalid llm_provider|unrecognized"):
            ApexConfig.from_cli_args(args)


# ---------------------------------------------------------------------------
# Runtime wiring: apex_host.runtime delegates to build_model_router() —
# the ONE factory function, never a hardcoded provider class by name.
# ---------------------------------------------------------------------------

class TestRuntimeRouterWiring:
    async def test_build_model_router_called_once_per_run(self) -> None:
        """apex_host.runtime.ApexRuntime.run() calls build_model_router(config)
        exactly once, and uses whatever it returns (never constructs a
        specific provider router class directly)."""
        from apex_host.runtime import build_runtime

        config = ApexConfig(target="127.0.0.1", dry_run=True, max_turns=1)
        runtime = build_runtime(config)

        calls: list[ApexConfig] = []
        real_build = build_model_router

        def spy(cfg: ApexConfig) -> ModelRouter:
            calls.append(cfg)
            return real_build(cfg)

        with patch("apex_host.runtime.build_model_router", spy):
            await runtime.run()

        assert calls == [config]

    def test_fake_router_returned_when_use_llm_false(self) -> None:
        config = ApexConfig(target="127.0.0.1", use_llm=False)
        assert isinstance(build_model_router(config), FakeModelRouter)

    def test_fake_router_returned_when_provider_fake_even_with_use_llm_true(self) -> None:
        config = ApexConfig(target="127.0.0.1", use_llm=True, llm_provider="fake")
        assert isinstance(build_model_router(config), FakeModelRouter)

    async def test_dry_run_engagement_completes_with_fake_router(self) -> None:
        """use_llm=False (default) -> FakeModelRouter -> no LLM calls,
        engagement still completes end-to-end in dry-run mode."""
        from apex_host.runtime import build_runtime

        config = ApexConfig(target="127.0.0.1", dry_run=True, max_turns=1)
        runtime = build_runtime(config)
        final = await runtime.run()
        assert final["completed"] is True

    async def test_one_providers_failure_does_not_affect_a_differently_configured_runtime(
        self,
    ) -> None:
        """Constructing a router for one provider must not leave any shared,
        process-global state that a subsequent, differently-configured
        runtime could inherit — each build_model_router() call is
        independent."""
        openai_config = ApexConfig(
            target="127.0.0.1", use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini",
        )
        anthropic_config = ApexConfig(
            target="127.0.0.1", use_llm=True, llm_provider="anthropic",
            planner_model="claude-sonnet-4-5-20250929",
        )

        openai_router = build_model_router(openai_config)
        anthropic_router = build_model_router(anthropic_config)

        assert isinstance(openai_router, OpenAIModelRouter)
        assert isinstance(anthropic_router, AnthropicModelRouter)
        assert openai_router._config.llm_provider == "openai"
        assert anthropic_router._config.llm_provider == "anthropic"


# ---------------------------------------------------------------------------
# PlanningEngine receives router and falls back deterministically on bad LLM
# ---------------------------------------------------------------------------

class _BadLLM:
    """LLM that always returns malformed JSON — should trigger fallback."""

    def invoke(self, messages: list[dict[str, str]]) -> object:
        response = type("R", (), {"content": "not valid json {{{"})()
        return response


class _BadRouter:
    def planner_llm(self) -> object:
        return _BadLLM()

    def executor_llm(self) -> object:
        return None

    def parser_llm(self) -> object:
        return None

    def reflector_llm(self) -> object:
        return None


class TestPlanningEngineFallback:
    async def test_bad_llm_output_falls_back_to_deterministic(self) -> None:
        """When LLM returns unparseable output, PlanningEngine falls back and
        the engagement still completes without error."""
        from memfabric.api import MemoryAPI
        from memfabric.config import Config
        from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
        from memfabric.stores.graph_networkx import NetworkXGraphStore
        from memfabric.stores.kv_memory import InMemoryKVStore
        from memfabric.stores.lexical_bm25 import BM25LexicalIndex
        from memfabric.stores.vector_faiss import FaissVectorIndex

        from apex_host.graph import build_apex_graph
        from apex_host.tools.registry import ToolRegistry

        cfg = Config()
        api = MemoryAPI(
            graph=NetworkXGraphStore(),
            episodic=JSONLEpisodicStore(path=None),
            lexical=BM25LexicalIndex(),
            vector=FaissVectorIndex(dim=cfg.vector_dim),
            kv=InMemoryKVStore(),
            config=cfg,
        )
        config = ApexConfig(target="127.0.0.1", dry_run=True, max_turns=2)
        registry = ToolRegistry.from_config(config)

        graph = build_apex_graph(api, registry, config, model_router=_BadRouter())

        initial: dict[str, Any] = {
            "run_id": "test-run",
            "target": "127.0.0.1",
            "phase": "recon",
            "goal": "test",
            "current_task": None,
            "evidence_summary": "",
            "findings": [],
            "error_episodes": [],
            "last_tool_result": None,
            "last_error": None,
            "completed": False,
            "turn_count": 0,
            "planner_decisions": [],
            "tool_results": None,
            "repair_count": 0,
        }

        final = await graph.ainvoke(initial)
        assert final["completed"] is True
        # PlanningEngine fell back → decisions should show fallback_used=True
        decisions = final.get("planner_decisions", [])
        assert len(decisions) >= 1
        assert all(d.get("fallback_used") is True for d in decisions)

    async def test_engagement_dry_run_no_llm_always_completes(self) -> None:
        """Baseline: dry_run=True, use_llm=False → engagement always completes."""
        from apex_host.runtime import build_runtime

        config = ApexConfig(target="127.0.0.1", dry_run=True, max_turns=3)
        runtime = build_runtime(config)
        final = await runtime.run()
        assert final["completed"] is True
        assert final["turn_count"] == 3
