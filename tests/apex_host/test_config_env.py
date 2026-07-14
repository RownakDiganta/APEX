# test_config_env.py
# Tests for apex_host/config_env.py — strict environment parsing, CLI/environment/default precedence, target and dry_run resolution rules, and dotenv-file loading.
"""Infra Phase 8 tests for the centralized environment-variable loader.

Covers: strict boolean/int/float parsing, blank-secret-to-absent
normalization, backend/log-level/URL validation, target resolution (at
least one of --target/APEX_TARGET required; blank counts as absent;
CLI wins), dry_run's asymmetric safety rule (APEX_DRY_RUN can only ever
reinforce the safe default, never enable real execution by itself),
generic CLI>env>default merging via an injected mapping (never patching
real os.environ), and explicit dotenv-file loading (never automatic).
"""
from __future__ import annotations

import argparse

import pytest

from apex_host.config_env import (
    CONFIG_CHECK_TARGET_PLACEHOLDER,
    EnvConfigError,
    load_apex_config_from_env,
    load_env_file,
    merge_env_into_args,
    merge_log_level,
    parse_bool_strict,
    parse_float_strict,
    parse_int_strict,
    resolve_dry_run,
    resolve_target,
    validate_log_level,
    validate_tool_backend,
    validate_url,
)

# ---------------------------------------------------------------------------
# Strict scalar parsing
# ---------------------------------------------------------------------------


class TestParseBoolStrict:
    @pytest.mark.parametrize("raw", ["true", "True", "TRUE", "1", "yes", "on", "  true  "])
    def test_true_values(self, raw: str) -> None:
        assert parse_bool_strict("X", raw) is True

    @pytest.mark.parametrize("raw", ["false", "False", "FALSE", "0", "no", "off"])
    def test_false_values(self, raw: str) -> None:
        assert parse_bool_strict("X", raw) is False

    @pytest.mark.parametrize("raw", ["yeah", "nope", "2", "-1", "", "truee", "TrueFalse"])
    def test_invalid_values_rejected(self, raw: str) -> None:
        with pytest.raises(EnvConfigError, match="X"):
            parse_bool_strict("X", raw)


class TestParseIntStrict:
    def test_valid_int(self) -> None:
        assert parse_int_strict("X", "42") == 42

    def test_whitespace_tolerated(self) -> None:
        assert parse_int_strict("X", "  7  ") == 7

    def test_invalid_int_rejected(self) -> None:
        with pytest.raises(EnvConfigError, match="X"):
            parse_int_strict("X", "notanumber")

    def test_float_string_rejected_as_int(self) -> None:
        with pytest.raises(EnvConfigError):
            parse_int_strict("X", "3.5")

    def test_minimum_enforced(self) -> None:
        with pytest.raises(EnvConfigError, match="below the minimum"):
            parse_int_strict("X", "0", minimum=1)

    def test_minimum_boundary_accepted(self) -> None:
        assert parse_int_strict("X", "1", minimum=1) == 1


class TestParseFloatStrict:
    def test_valid_float(self) -> None:
        assert parse_float_strict("X", "3.5") == 3.5

    def test_valid_int_as_float(self) -> None:
        assert parse_float_strict("X", "120") == 120.0

    def test_invalid_float_rejected(self) -> None:
        with pytest.raises(EnvConfigError, match="X"):
            parse_float_strict("X", "notanumber")

    def test_negative_rejected_with_minimum(self) -> None:
        with pytest.raises(EnvConfigError, match="below the minimum"):
            parse_float_strict("X", "-5", minimum=0.0)

    def test_negative_allowed_without_minimum(self) -> None:
        assert parse_float_strict("X", "-5") == -5.0


class TestValidateToolBackend:
    @pytest.mark.parametrize("raw", ["dry-run", "local", "remote", "REMOTE", "  Local  "])
    def test_valid_backends_normalized(self, raw: str) -> None:
        result = validate_tool_backend("X", raw)
        assert result in ("dry-run", "local", "remote")

    def test_invalid_backend_rejected(self) -> None:
        with pytest.raises(EnvConfigError, match="invalid tool backend"):
            validate_tool_backend("X", "bogus")


class TestValidateLogLevel:
    @pytest.mark.parametrize("raw", ["DEBUG", "info", "Warning", "ERROR", "critical"])
    def test_valid_levels(self, raw: str) -> None:
        assert validate_log_level("X", raw) == raw.strip().upper()

    def test_invalid_level_rejected(self) -> None:
        with pytest.raises(EnvConfigError, match="invalid log level"):
            validate_log_level("X", "VERBOSE")


class TestValidateUrl:
    def test_valid_http(self) -> None:
        assert validate_url("X", "http://kali:8080") == "http://kali:8080"

    def test_valid_https(self) -> None:
        assert validate_url("X", "https://example.com") == "https://example.com"

    def test_missing_scheme_rejected(self) -> None:
        with pytest.raises(EnvConfigError, match="must use http or https"):
            validate_url("X", "kali:8080")

    def test_ftp_scheme_rejected(self) -> None:
        with pytest.raises(EnvConfigError, match="must use http or https"):
            validate_url("X", "ftp://kali:8080")

    def test_no_netloc_rejected(self) -> None:
        with pytest.raises(EnvConfigError, match="not a valid URL"):
            validate_url("X", "http://")


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------


class TestResolveTarget:
    def test_cli_target_wins(self) -> None:
        assert resolve_target("10.0.0.1", {"APEX_TARGET": "10.0.0.2"}) == "10.0.0.1"

    def test_env_target_used_when_cli_absent(self) -> None:
        assert resolve_target(None, {"APEX_TARGET": "10.0.0.2"}) == "10.0.0.2"

    def test_blank_env_target_counts_as_absent(self) -> None:
        with pytest.raises(EnvConfigError, match="no target provided"):
            resolve_target(None, {"APEX_TARGET": "   "})

    def test_both_absent_raises_when_required(self) -> None:
        with pytest.raises(EnvConfigError, match="no target provided"):
            resolve_target(None, {})

    def test_both_absent_returns_placeholder_when_not_required(self) -> None:
        assert resolve_target(None, {}, required=False) == CONFIG_CHECK_TARGET_PLACEHOLDER

    def test_env_wins_over_placeholder_when_not_required(self) -> None:
        assert resolve_target(None, {"APEX_TARGET": "10.0.0.9"}, required=False) == "10.0.0.9"

    def test_blank_cli_target_falls_through_to_env(self) -> None:
        assert resolve_target("   ", {"APEX_TARGET": "10.0.0.3"}) == "10.0.0.3"

    def test_defaults_to_real_os_environ_when_env_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APEX_TARGET", "10.0.0.5")
        assert resolve_target(None, None) == "10.0.0.5"


# ---------------------------------------------------------------------------
# dry_run — the asymmetric safety rule
# ---------------------------------------------------------------------------


class TestResolveDryRun:
    def test_explicit_cli_true_wins(self) -> None:
        assert resolve_dry_run(True, {"APEX_DRY_RUN": "false"}) is True

    def test_explicit_cli_false_wins_regardless_of_env(self) -> None:
        assert resolve_dry_run(False, {"APEX_DRY_RUN": "true"}) is False

    def test_explicit_cli_false_wins_with_no_env(self) -> None:
        assert resolve_dry_run(False, {}) is False

    def test_absent_cli_and_env_defaults_true(self) -> None:
        assert resolve_dry_run(None, {}) is True

    def test_absent_cli_env_true_stays_true(self) -> None:
        assert resolve_dry_run(None, {"APEX_DRY_RUN": "true"}) is True

    def test_absent_cli_env_false_raises(self) -> None:
        """The core safety invariant: an environment variable alone can
        never enable real execution — CLAUDE.md §13.5."""
        with pytest.raises(EnvConfigError, match="--no-dry-run was not passed"):
            resolve_dry_run(None, {"APEX_DRY_RUN": "false"})

    def test_blank_env_dry_run_treated_as_absent(self) -> None:
        assert resolve_dry_run(None, {"APEX_DRY_RUN": "  "}) is True

    def test_invalid_env_dry_run_value_raises(self) -> None:
        with pytest.raises(EnvConfigError, match="invalid boolean"):
            resolve_dry_run(None, {"APEX_DRY_RUN": "maybe"})


# ---------------------------------------------------------------------------
# Generic CLI > env > default merge
# ---------------------------------------------------------------------------


class TestMergeEnvIntoArgs:
    def test_absent_variables_preserve_none(self) -> None:
        ns = argparse.Namespace(max_turns=None, tool_backend=None)
        merged = merge_env_into_args(ns, {})
        assert merged.max_turns is None
        assert merged.tool_backend is None

    def test_env_fills_none_cli_value(self) -> None:
        ns = argparse.Namespace(max_turns=None, target="10.0.0.1", dry_run=None)
        merged = merge_env_into_args(ns, {"APEX_MAX_TURNS": "15"})
        assert merged.max_turns == 15

    def test_explicit_cli_value_never_overwritten(self) -> None:
        ns = argparse.Namespace(max_turns=5, target="10.0.0.1", dry_run=None)
        merged = merge_env_into_args(ns, {"APEX_MAX_TURNS": "15"})
        assert merged.max_turns == 5

    def test_original_namespace_not_mutated(self) -> None:
        ns = argparse.Namespace(max_turns=None, target="10.0.0.1", dry_run=None)
        merge_env_into_args(ns, {"APEX_MAX_TURNS": "15"})
        assert ns.max_turns is None

    def test_missing_attribute_silently_skipped(self) -> None:
        ns = argparse.Namespace(target="10.0.0.1", dry_run=None)  # no max_turns at all
        merged = merge_env_into_args(ns, {"APEX_MAX_TURNS": "15"})
        assert not hasattr(merged, "max_turns")

    def test_tool_backend_normalized_from_env(self) -> None:
        ns = argparse.Namespace(tool_backend=None, target="10.0.0.1", dry_run=None)
        merged = merge_env_into_args(ns, {"APEX_TOOL_BACKEND": "REMOTE"})
        assert merged.tool_backend == "remote"

    def test_invalid_env_value_raises_env_config_error(self) -> None:
        ns = argparse.Namespace(max_turns=None, target="10.0.0.1", dry_run=None)
        with pytest.raises(EnvConfigError):
            merge_env_into_args(ns, {"APEX_MAX_TURNS": "not-a-number"})

    def test_tool_service_url_validated(self) -> None:
        ns = argparse.Namespace(tool_service_url=None, target="10.0.0.1", dry_run=None)
        with pytest.raises(EnvConfigError, match="must use http or https"):
            merge_env_into_args(ns, {"APEX_TOOL_SERVICE_URL": "not-a-url"})

    def test_export_json_and_export_graph_fillable(self) -> None:
        ns = argparse.Namespace(
            export_json=None, export_graph=None, target="10.0.0.1", dry_run=None,
        )
        merged = merge_env_into_args(
            ns, {"APEX_REPORT_PATH": "/tmp/r.json", "APEX_GRAPH_PATH": "/tmp/g.json"},
        )
        assert merged.export_json == "/tmp/r.json"
        assert merged.export_graph == "/tmp/g.json"

    def test_use_llm_boolean_merge(self) -> None:
        ns = argparse.Namespace(use_llm=None, target="10.0.0.1", dry_run=None)
        merged = merge_env_into_args(ns, {"APEX_USE_LLM": "true"})
        assert merged.use_llm is True

    def test_require_target_false_uses_placeholder(self) -> None:
        ns = argparse.Namespace(target=None, dry_run=None)
        merged = merge_env_into_args(ns, {}, require_target=False)
        assert merged.target == CONFIG_CHECK_TARGET_PLACEHOLDER

    def test_dry_run_and_target_always_resolved(self) -> None:
        ns = argparse.Namespace(target="10.0.0.1", dry_run=None)
        merged = merge_env_into_args(ns, {})
        assert merged.dry_run is True
        assert merged.target == "10.0.0.1"

    def test_injected_mapping_used_not_real_os_environ(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A completely empty injected mapping must not silently fall back
        to the real process environment — proves tests never need to touch
        global os.environ state."""
        monkeypatch.setenv("APEX_MAX_TURNS", "99")
        ns = argparse.Namespace(max_turns=None, target="10.0.0.1", dry_run=None)
        merged = merge_env_into_args(ns, {})  # explicit empty mapping, not None
        assert merged.max_turns is None


# ---------------------------------------------------------------------------
# Log level merge
# ---------------------------------------------------------------------------


class TestMergeLogLevel:
    def test_verbose_always_debug(self) -> None:
        assert merge_log_level(True, {"APEX_LOG_LEVEL": "ERROR"}) == "DEBUG"

    def test_env_used_when_not_verbose(self) -> None:
        assert merge_log_level(False, {"APEX_LOG_LEVEL": "WARNING"}) == "WARNING"

    def test_absent_returns_empty_string(self) -> None:
        assert merge_log_level(False, {}) == ""

    def test_invalid_env_log_level_raises(self) -> None:
        with pytest.raises(EnvConfigError, match="invalid log level"):
            merge_log_level(False, {"APEX_LOG_LEVEL": "NOISY"})


# ---------------------------------------------------------------------------
# load_apex_config_from_env — top-level convenience
# ---------------------------------------------------------------------------


class TestLoadApexConfigFromEnv:
    def test_builds_valid_config(self) -> None:
        ns = argparse.Namespace(target="10.0.0.1", dry_run=None, max_turns=None)
        config = load_apex_config_from_env(ns, {})
        assert config.target == "10.0.0.1"
        assert config.dry_run is True
        assert config.max_turns == 20

    def test_env_overrides_flow_through(self) -> None:
        ns = argparse.Namespace(target=None, dry_run=None, max_turns=None)
        config = load_apex_config_from_env(ns, {"APEX_TARGET": "10.0.0.9", "APEX_MAX_TURNS": "3"})
        assert config.target == "10.0.0.9"
        assert config.max_turns == 3

    def test_no_target_required_false(self) -> None:
        ns = argparse.Namespace(target=None, dry_run=None)
        config = load_apex_config_from_env(ns, {}, require_target=False)
        assert config.target == CONFIG_CHECK_TARGET_PLACEHOLDER

    def test_token_redacted_in_safe_dict(self) -> None:
        ns = argparse.Namespace(target="10.0.0.1", dry_run=None)
        config = load_apex_config_from_env(ns, {})
        config.tool_service_token = "super-secret"
        safe = config.to_safe_dict()
        assert safe["tool_service_token"] != "super-secret"
        assert "super-secret" not in str(safe)


# ---------------------------------------------------------------------------
# load_env_file — explicit, opt-in dotenv loading
# ---------------------------------------------------------------------------


class TestLoadEnvFile:
    def test_loads_simple_file(self, tmp_path: "object") -> None:
        path = tmp_path / ".env"  # type: ignore[operator]
        path.write_text("APEX_TARGET=10.0.0.7\nAPEX_MAX_TURNS=9\n")
        values = load_env_file(str(path))
        assert values["APEX_TARGET"] == "10.0.0.7"
        assert values["APEX_MAX_TURNS"] == "9"

    def test_missing_file_raises_env_config_error(self, tmp_path: "object") -> None:
        missing = tmp_path / "does-not-exist.env"  # type: ignore[operator]
        with pytest.raises(EnvConfigError, match="does not exist"):
            load_env_file(str(missing))

    def test_does_not_mutate_real_os_environ(self, tmp_path: "object", monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("APEX_TARGET", raising=False)
        path = tmp_path / ".env"  # type: ignore[operator]
        path.write_text("APEX_TARGET=10.0.0.7\n")
        load_env_file(str(path))
        import os

        assert "APEX_TARGET" not in os.environ

    def test_comments_and_blank_lines_ignored(self, tmp_path: "object") -> None:
        path = tmp_path / ".env"  # type: ignore[operator]
        path.write_text("# a comment\n\nAPEX_TARGET=10.0.0.7\n")
        values = load_env_file(str(path))
        assert values == {"APEX_TARGET": "10.0.0.7"}
