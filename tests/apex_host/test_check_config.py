# test_check_config.py
# Tests for apex_host/eval/check_config.py — the safe, network-free-by-default configuration validation command.
"""Infra Phase 8 tests for the config-check command.

Covers: valid/invalid configuration exit codes, redacted output (token
never printed), no network call by default, target not required, and each
documented validation rule (invalid backend, remote backend missing
URL/token, malformed URL, negative timeout, LLM enabled without a
provider/key requirement only when actually required).
"""
from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout

import pytest

from apex_host.eval.check_config import _async_main, _parse_args, validate_combinations
from apex_host.config_env import load_apex_config_from_env


async def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = await _async_main(argv)
    return code, out.getvalue(), err.getvalue()


class TestSafeDefault:
    @pytest.mark.asyncio
    async def test_default_config_is_valid_and_exits_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("APEX_TOOL_SERVICE_TOKEN", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        code, out, _ = await _run([])
        assert code == 0
        assert "Configuration is valid." in out

    @pytest.mark.asyncio
    async def test_no_target_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("APEX_TARGET", raising=False)
        code, out, _ = await _run([])
        assert code == 0
        assert "config-check" in out

    @pytest.mark.asyncio
    async def test_default_makes_no_network_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--check-connectivity is not passed, so _check_connectivity must
        never be invoked, proven by monkeypatching it to raise if called."""
        import apex_host.eval.check_config as mod

        async def _boom(url: str) -> tuple[bool, str]:
            raise AssertionError("network call attempted without --check-connectivity")

        monkeypatch.setattr(mod, "_check_connectivity", _boom)
        code, _, _ = await _run(["--tool-backend", "remote", "--tool-service-url", "http://kali:8080"])
        # Still invalid (no token), but crucially never attempted a network call.
        assert code in (0, 1)


class TestRedaction:
    @pytest.mark.asyncio
    async def test_token_never_in_stdout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "totally-secret-value-123")
        code, out, err = await _run(["--tool-backend", "remote", "--tool-service-url", "http://kali:8080", "--no-dry-run"])
        assert code == 0
        assert "totally-secret-value-123" not in out
        assert "totally-secret-value-123" not in err
        assert "present" in out  # token state shown as present/absent only

    @pytest.mark.asyncio
    async def test_openai_key_never_in_stdout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-totallysecretkeyvalue1234567890")
        code, out, _ = await _run([])
        assert "sk-totallysecretkeyvalue1234567890" not in out


class TestValidationRules:
    @pytest.mark.asyncio
    async def test_invalid_backend_rejected_by_argparse(self) -> None:
        with pytest.raises(SystemExit):
            _parse_args(["--tool-backend", "bogus"])

    @pytest.mark.asyncio
    async def test_remote_backend_without_url_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "x")
        code, out, _ = await _run(["--tool-backend", "remote", "--no-dry-run"])
        assert code == 1
        assert "requires --tool-service-url" in out

    @pytest.mark.asyncio
    async def test_remote_backend_without_token_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("APEX_TOOL_SERVICE_TOKEN", raising=False)
        code, out, _ = await _run(
            ["--tool-backend", "remote", "--tool-service-url", "http://kali:8080", "--no-dry-run"],
        )
        assert code == 1
        assert "requires a bearer token" in out

    @pytest.mark.asyncio
    async def test_remote_backend_with_url_and_token_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "x")
        code, out, _ = await _run(
            ["--tool-backend", "remote", "--tool-service-url", "http://kali:8080", "--no-dry-run"],
        )
        assert code == 0
        assert "Configuration is valid." in out

    @pytest.mark.asyncio
    async def test_dry_run_remote_backend_skips_url_token_requirement(self) -> None:
        """dry_run=True means the backend never actually contacts anything
        (select_runtime_backend always yields DryRunToolBackend), so a
        remote-backend-with-no-url-or-token combination is not an error
        while dry_run is in effect."""
        code, out, _ = await _run(["--tool-backend", "remote", "--dry-run"])
        assert code == 0
        assert "Configuration is valid." in out

    @pytest.mark.asyncio
    async def test_malformed_url_from_env_rejected_at_merge_time(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An env-sourced malformed URL fails even earlier and more clearly
        than a combination-level problem — apex_host.config_env.validate_url
        raises EnvConfigError immediately during the merge, before
        validate_combinations ever runs."""
        monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "x")
        code, _, err = await _run(["--tool-backend", "remote", "--no-dry-run"])
        # No malformed URL yet — sanity check this specific combination is
        # merely "missing", not malformed.
        assert code == 1

        monkeypatch.setenv("APEX_TOOL_SERVICE_URL", "not-a-url")
        code, _, err = await _run(["--tool-backend", "remote", "--no-dry-run"])
        assert code == 1
        assert "APEX_TOOL_SERVICE_URL" in err
        assert "must use http or https" in err

    @pytest.mark.asyncio
    async def test_malformed_cli_url_rejected_by_combination_check(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A CLI-supplied --tool-service-url is not shape-validated by
        argparse itself, so the combination-level check in
        validate_combinations is what catches it."""
        monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "x")
        ns = _parse_args(["--tool-backend", "remote", "--tool-service-url", "not-a-url", "--no-dry-run"])
        config = load_apex_config_from_env(ns, {}, require_target=False)
        problems = validate_combinations(config)
        assert any("not a valid http(s) URL" in p for p in problems)

    @pytest.mark.asyncio
    async def test_negative_timeout_rejected(self) -> None:
        code, out, _ = await _run(["--tool-service-timeout", "-5"])
        assert code == 1
        assert "must not be negative" in out

    @pytest.mark.asyncio
    async def test_max_turns_below_one_rejected(self) -> None:
        code, out, _ = await _run(["--max-turns", "0"])
        assert code == 1
        assert "must be at least 1" in out

    @pytest.mark.asyncio
    async def test_llm_enabled_with_fake_provider_never_requires_key(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        code, out, _ = await _run(["--use-llm", "--llm-provider", "fake"])
        assert code == 0

    @pytest.mark.asyncio
    async def test_llm_disabled_never_requires_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        code, out, _ = await _run(["--llm-provider", "openai"])  # use_llm not set
        assert code == 0

    @pytest.mark.asyncio
    async def test_llm_enabled_with_real_provider_requires_key(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        code, out, _ = await _run(["--use-llm", "--llm-provider", "openai"])
        assert code == 1
        assert "OPENAI_API_KEY" in out

    @pytest.mark.asyncio
    async def test_llm_enabled_with_real_provider_and_key_valid(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Phase 5: use_llm=True with a real provider also requires an
        # explicit native model — there is no provider-neutral default.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-abc")
        code, _, _ = await _run([
            "--use-llm", "--llm-provider", "openai", "--llm-model", "gpt-4o-mini",
        ])
        assert code == 0

    @pytest.mark.asyncio
    async def test_llm_enabled_with_real_provider_and_key_but_no_model_fails(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Phase 5: a valid credential alone is not sufficient — an
        explicit model is also required, since no provider-neutral default
        model exists anywhere in this codebase."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-abc")
        code, out, _ = await _run(["--use-llm", "--llm-provider", "openai"])
        assert code == 1
        assert "model" in out.lower()

    @pytest.mark.asyncio
    async def test_llm_enabled_openai_with_router_style_model_fails_as_mismatch(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Phase 5: the exact old root-cause configuration — provider=openai
        with a router-style ("vendor/model") model identifier — is rejected
        as a provider_model_mismatch, not silently accepted."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-abc")
        code, out, _ = await _run([
            "--use-llm", "--llm-provider", "openai", "--llm-model", "openai/gpt-5.5",
        ])
        assert code == 1
        assert "provider_model_mismatch" in out

    @pytest.mark.asyncio
    async def test_llm_enabled_anthropic_requires_anthropic_key_not_openai_key(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Phase 5: credential isolation — an OPENAI_API_KEY present does
        not satisfy provider='anthropic'; only ANTHROPIC_API_KEY does."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-abc-not-for-anthropic")
        code, out, _ = await _run([
            "--use-llm", "--llm-provider", "anthropic", "--llm-model", "claude-sonnet-4-5-20250929",
        ])
        assert code == 1
        assert "ANTHROPIC_API_KEY" in out

    @pytest.mark.asyncio
    async def test_llm_enabled_anthropic_with_key_and_model_valid(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-abc")
        code, _, _ = await _run([
            "--use-llm", "--llm-provider", "anthropic",
            "--llm-model", "claude-sonnet-4-5-20250929",
        ])
        assert code == 0

    @pytest.mark.asyncio
    async def test_invalid_env_value_fails_clearly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APEX_MAX_TURNS", "notanumber")
        code, _, err = await _run([])
        assert code == 1
        assert "APEX_MAX_TURNS" in err

    @pytest.mark.asyncio
    async def test_env_dry_run_false_without_flag_fails_clearly(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("APEX_DRY_RUN", "false")
        code, _, err = await _run([])
        assert code == 1
        assert "--no-dry-run" in err
