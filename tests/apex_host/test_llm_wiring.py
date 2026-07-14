# test_llm_wiring.py
# Tests for LLM wiring: CLI flag parsing, ApexConfig fields, ModelRouter construction, and fallback behavior.
"""Tests for the LLM wiring layer added in Phase 6.

Covers:
- ApexConfig carries use_llm, llm_provider, llm_base_url with safe defaults.
- Model names updated to openai/gpt-5.5.
- Both CLI entry points (main.py and run_htb_local.py) expose --use-llm,
  --llm-provider, --llm-model, --llm-base-url and wire them into ApexConfig.
- OpenAIModelRouter respects config.llm_base_url over OPENAI_BASE_URL env var.
- FakeModelRouter always returns None (safe default for tests and dry-run).
- ApexRuntime.run() uses FakeModelRouter when use_llm=False (default).
- ApexRuntime.run() constructs OpenAIModelRouter when use_llm=True and
  llm_provider != "fake".
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
from apex_host.llm.router import FakeModelRouter, OpenAIModelRouter


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


class TestApexConfigModelNames:
    def test_planner_model_default(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.planner_model == "openai/gpt-5.5"

    def test_executor_model_default(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.executor_model == "openai/gpt-5.5"

    def test_parser_model_default(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.parser_model == "openai/gpt-5.5"


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
# OpenAIModelRouter base-URL precedence
# ---------------------------------------------------------------------------

class TestOpenAIModelRouterBaseURL:
    def test_config_base_url_takes_precedence_over_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_BASE_URL", "https://env-base")
        config = ApexConfig(
            target="10.0.0.1", use_llm=True, llm_base_url="https://config-base"
        )
        router = OpenAIModelRouter(config)
        assert router._base_url == "https://config-base"

    def test_env_base_url_used_when_config_is_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_BASE_URL", "https://env-base")
        config = ApexConfig(target="10.0.0.1", use_llm=True, llm_base_url=None)
        router = OpenAIModelRouter(config)
        assert router._base_url == "https://env-base"

    def test_empty_base_url_falls_back_to_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        config = ApexConfig(target="10.0.0.1", use_llm=True, llm_base_url=None)
        router = OpenAIModelRouter(config)
        assert router._base_url is None

    def test_planner_model_used_in_build(self) -> None:
        config = ApexConfig(
            target="10.0.0.1", use_llm=True, planner_model="openai/gpt-5.5"
        )
        router = OpenAIModelRouter(config)
        # Access the _config to confirm model is stored correctly; _build would
        # need langchain_openai installed, so we only test the routing layer here.
        assert router._config.planner_model == "openai/gpt-5.5"


# ---------------------------------------------------------------------------
# main.py CLI flag parsing
# ---------------------------------------------------------------------------

class TestMainParseCLI:
    def test_default_no_llm(self) -> None:
        from apex_host.main import parse_args
        args = parse_args(["--target", "10.0.0.1"])
        assert args.use_llm is False

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
        args = parse_args(["--target", "10.0.0.1", "--llm-model", "openai/gpt-5.5"])
        assert args.llm_model == "openai/gpt-5.5"

    def test_llm_base_url_flag(self) -> None:
        from apex_host.main import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--llm-base-url", "https://openrouter.ai/api/v1",
        ])
        assert args.llm_base_url == "https://openrouter.ai/api/v1"

    def test_all_llm_flags_together(self) -> None:
        from apex_host.main import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--use-llm",
            "--llm-provider", "openai",
            "--llm-model", "openai/gpt-5.5",
            "--llm-base-url", "https://openrouter.ai/api/v1",
        ])
        assert args.use_llm is True
        assert args.llm_provider == "openai"
        assert args.llm_model == "openai/gpt-5.5"
        assert args.llm_base_url == "https://openrouter.ai/api/v1"

    def test_llm_model_none_by_default(self) -> None:
        from apex_host.main import parse_args
        args = parse_args(["--target", "10.0.0.1"])
        assert args.llm_model is None


# ---------------------------------------------------------------------------
# run_htb_local.py CLI flag parsing
# ---------------------------------------------------------------------------

class TestRunHTBLocalParseCLI:
    def test_default_no_llm(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args(["--target", "10.0.0.1"])
        assert args.use_llm is False

    def test_use_llm_flag(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args(["--target", "10.0.0.1", "--use-llm"])
        assert args.use_llm is True

    def test_llm_provider_flag(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args(["--target", "10.0.0.1", "--llm-provider", "openai"])
        assert args.llm_provider == "openai"

    def test_llm_model_flag(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args(["--target", "10.0.0.1", "--llm-model", "openai/gpt-5.5"])
        assert args.llm_model == "openai/gpt-5.5"

    def test_llm_base_url_flag(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--llm-base-url", "https://openrouter.ai/api/v1",
        ])
        assert args.llm_base_url == "https://openrouter.ai/api/v1"

    def test_all_llm_flags_together(self) -> None:
        from apex_host.eval.run_htb_local import parse_args
        args = parse_args([
            "--target", "10.0.0.1",
            "--use-llm",
            "--llm-provider", "openai",
            "--llm-model", "openai/gpt-5.5",
            "--llm-base-url", "https://openrouter.ai/api/v1",
        ])
        assert args.use_llm is True
        assert args.llm_provider == "openai"
        assert args.llm_model == "openai/gpt-5.5"
        assert args.llm_base_url == "https://openrouter.ai/api/v1"


# ---------------------------------------------------------------------------
# Config construction from CLI args (model override)
# ---------------------------------------------------------------------------

class TestConfigFromCLIArgs:
    def test_llm_model_sets_all_model_fields(self) -> None:
        """--llm-model sets planner_model, executor_model, and parser_model."""
        from apex_host.main import parse_args

        args = parse_args(["--target", "10.0.0.1", "--llm-model", "openai/gpt-5.5"])
        config_kwargs: dict[str, object] = dict(
            target=args.target,
            use_llm=args.use_llm,
            llm_provider=args.llm_provider,
            llm_base_url=args.llm_base_url,
        )
        if args.llm_model:
            config_kwargs["planner_model"] = args.llm_model
            config_kwargs["executor_model"] = args.llm_model
            config_kwargs["parser_model"] = args.llm_model
        config = ApexConfig(**config_kwargs)  # type: ignore[arg-type]

        assert config.planner_model == "openai/gpt-5.5"
        assert config.executor_model == "openai/gpt-5.5"
        assert config.parser_model == "openai/gpt-5.5"

    def test_no_llm_model_keeps_default(self) -> None:
        """Without --llm-model, planner_model is the default "openai/gpt-5.5"."""
        from apex_host.main import parse_args

        args = parse_args(["--target", "10.0.0.1"])
        config_kwargs: dict[str, object] = dict(
            target=args.target,
            use_llm=args.use_llm,
            llm_provider=args.llm_provider,
            llm_base_url=args.llm_base_url,
        )
        config = ApexConfig(**config_kwargs)  # type: ignore[arg-type]

        assert config.planner_model == "openai/gpt-5.5"


# ---------------------------------------------------------------------------
# Runtime wiring: router selected based on use_llm
# ---------------------------------------------------------------------------

class TestRuntimeRouterWiring:
    async def test_fake_router_used_by_default(self) -> None:
        """use_llm=False (default) → FakeModelRouter → no LLM calls during run."""
        from apex_host.runtime import build_runtime

        config = ApexConfig(target="127.0.0.1", dry_run=True, max_turns=1)
        runtime = build_runtime(config)

        routers_constructed: list[str] = []

        _real_fake = FakeModelRouter
        _real_openai = OpenAIModelRouter

        def fake_fake() -> FakeModelRouter:
            routers_constructed.append("fake")
            return _real_fake()

        def fake_openai(cfg: ApexConfig) -> OpenAIModelRouter:
            routers_constructed.append("openai")
            return _real_openai(cfg)

        with (
            patch("apex_host.runtime.FakeModelRouter", fake_fake),
            patch("apex_host.runtime.OpenAIModelRouter", fake_openai),
        ):
            await runtime.run()

        assert "fake" in routers_constructed
        assert "openai" not in routers_constructed

    async def test_openai_router_used_when_use_llm_and_provider_openai(self) -> None:
        """use_llm=True + llm_provider='openai' → OpenAIModelRouter constructed.

        We intercept the constructor call and return a FakeModelRouter so no
        real API key or network is needed — we only verify the constructor was
        reached, not that a live LLM call succeeded.
        """
        from apex_host.runtime import build_runtime

        config = ApexConfig(
            target="127.0.0.1",
            dry_run=True,
            max_turns=1,
            use_llm=True,
            llm_provider="openai",
        )
        runtime = build_runtime(config)

        routers_constructed: list[str] = []

        def fake_openai(cfg: ApexConfig) -> FakeModelRouter:
            routers_constructed.append("openai")
            return FakeModelRouter()  # safe stand-in; avoids API key requirement

        with patch("apex_host.runtime.OpenAIModelRouter", fake_openai):
            await runtime.run()

        assert "openai" in routers_constructed

    async def test_fake_router_when_use_llm_but_provider_fake(self) -> None:
        """use_llm=True + llm_provider='fake' still uses FakeModelRouter."""
        from apex_host.runtime import build_runtime

        config = ApexConfig(
            target="127.0.0.1",
            dry_run=True,
            max_turns=1,
            use_llm=True,
            llm_provider="fake",
        )
        runtime = build_runtime(config)

        openai_constructed = False

        _real_openai = OpenAIModelRouter

        def fake_openai(cfg: ApexConfig) -> OpenAIModelRouter:
            nonlocal openai_constructed
            openai_constructed = True
            return _real_openai(cfg)

        with patch("apex_host.runtime.OpenAIModelRouter", fake_openai):
            await runtime.run()

        assert not openai_constructed


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
