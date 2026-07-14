# test_settings.py
# Tests for ServiceSettings.from_env(): defaults, env-var overrides via an injected mapping (never real os.environ), and safe-dict redaction.
from __future__ import annotations

from apex_tool_service.settings import ServiceSettings


def test_from_env_empty_mapping_uses_safe_defaults() -> None:
    settings = ServiceSettings.from_env({})
    assert settings.token is None
    assert settings.host == "127.0.0.1"
    assert settings.port == 8080
    assert settings.max_timeout_seconds > settings.min_timeout_seconds


def test_from_env_reads_token() -> None:
    settings = ServiceSettings.from_env({"APEX_TOOL_SERVICE_TOKEN": "abc123"})
    assert settings.token == "abc123"


def test_from_env_empty_string_token_treated_as_unset() -> None:
    settings = ServiceSettings.from_env({"APEX_TOOL_SERVICE_TOKEN": ""})
    assert settings.token is None


def test_from_env_overrides_host_and_port() -> None:
    settings = ServiceSettings.from_env(
        {"APEX_TOOL_SERVICE_HOST": "0.0.0.0", "APEX_TOOL_SERVICE_PORT": "9090"}
    )
    assert settings.host == "0.0.0.0"
    assert settings.port == 9090


def test_from_env_overrides_all_limits() -> None:
    env = {
        "APEX_TOOL_SERVICE_DEFAULT_TIMEOUT_SECONDS": "5",
        "APEX_TOOL_SERVICE_MAX_TIMEOUT_SECONDS": "60",
        "APEX_TOOL_SERVICE_MIN_TIMEOUT_SECONDS": "2",
        "APEX_TOOL_SERVICE_MAX_ARGUMENTS": "10",
        "APEX_TOOL_SERVICE_MAX_ARGUMENT_LENGTH": "100",
        "APEX_TOOL_SERVICE_MAX_TOTAL_ARGUMENT_BYTES": "1000",
        "APEX_TOOL_SERVICE_MAX_STDIN_BYTES": "2000",
        "APEX_TOOL_SERVICE_MAX_STDOUT_BYTES": "3000",
        "APEX_TOOL_SERVICE_MAX_STDERR_BYTES": "4000",
    }
    settings = ServiceSettings.from_env(env)
    assert settings.default_timeout_seconds == 5.0
    assert settings.max_timeout_seconds == 60.0
    assert settings.min_timeout_seconds == 2.0
    assert settings.max_arguments == 10
    assert settings.max_argument_length == 100
    assert settings.max_total_argument_bytes == 1000
    assert settings.max_stdin_bytes == 2000
    assert settings.max_stdout_bytes == 3000
    assert settings.max_stderr_bytes == 4000


def test_no_secret_default_token() -> None:
    """Constructing settings with no explicit token must never yield a real-looking default."""
    settings = ServiceSettings(token=None)
    assert settings.token is None


def test_to_safe_dict_never_includes_token_field_value() -> None:
    settings = ServiceSettings(token="super-secret-value")
    safe = settings.to_safe_dict()
    assert "token" not in safe
    assert "super-secret-value" not in str(safe)


def test_to_safe_dict_reports_token_configured_boolean() -> None:
    assert ServiceSettings(token="x").to_safe_dict()["token_configured"] is True
    assert ServiceSettings(token=None).to_safe_dict()["token_configured"] is False
