# settings.py
# Centralized ServiceSettings: the sole place apex_tool_service reads environment variables or defines its limit constants.
"""Centralized configuration for apex_tool_service.

Unlike ``apex_host/config.py`` (which deliberately never reads environment
variables — see its own ``test_arch_08_config_py_has_no_env_access``
architecture test), this module is the intentional, sole place
``apex_tool_service`` reads environment variables. This service is a
separate, standalone process/container from ``apex_host``, so centralizing
its own environment reads here (rather than scattering ``os.environ`` calls
across ``app.py``/``auth.py``/``executor.py``) is the equivalent discipline
applied to a different process boundary.

No field here has a secret default. ``token`` defaults to ``None``, which
``auth.py`` treats as "the execution endpoint must fail closed" — see
``require_bearer_token`` in that module.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

# Env var names (documented here, matching docs/kali-tool-service.md and
# docs/tool-execution-architecture.md §9).
ENV_TOKEN = "APEX_TOOL_SERVICE_TOKEN"
ENV_HOST = "APEX_TOOL_SERVICE_HOST"
ENV_PORT = "APEX_TOOL_SERVICE_PORT"
ENV_DEFAULT_TIMEOUT_SECONDS = "APEX_TOOL_SERVICE_DEFAULT_TIMEOUT_SECONDS"
ENV_MAX_TIMEOUT_SECONDS = "APEX_TOOL_SERVICE_MAX_TIMEOUT_SECONDS"
ENV_MIN_TIMEOUT_SECONDS = "APEX_TOOL_SERVICE_MIN_TIMEOUT_SECONDS"
ENV_MAX_ARGUMENTS = "APEX_TOOL_SERVICE_MAX_ARGUMENTS"
ENV_MAX_ARGUMENT_LENGTH = "APEX_TOOL_SERVICE_MAX_ARGUMENT_LENGTH"
ENV_MAX_TOTAL_ARGUMENT_BYTES = "APEX_TOOL_SERVICE_MAX_TOTAL_ARGUMENT_BYTES"
ENV_MAX_STDIN_BYTES = "APEX_TOOL_SERVICE_MAX_STDIN_BYTES"
ENV_MAX_STDOUT_BYTES = "APEX_TOOL_SERVICE_MAX_STDOUT_BYTES"
ENV_MAX_STDERR_BYTES = "APEX_TOOL_SERVICE_MAX_STDERR_BYTES"

# Phase 22 — dedicated bounded-file-read operation (POST /v1/bounded-file-read).
# Deliberately separate from the generic-tool limits above: this operation
# has its own, narrower ceilings and its own target-authorization/basename
# allowlists, since it is a structurally different (and more restrictive)
# capability than the generic allowlisted-tool endpoint.
ENV_BOUNDED_READ_MAX_BYTES = "APEX_TOOL_SERVICE_BOUNDED_READ_MAX_BYTES"
ENV_BOUNDED_READ_TIMEOUT = "APEX_TOOL_SERVICE_BOUNDED_READ_TIMEOUT"
ENV_ALLOWED_FLAG_BASENAMES = "APEX_TOOL_SERVICE_ALLOWED_FLAG_BASENAMES"
ENV_AUTHORIZED_CIDRS = "APEX_TOOL_SERVICE_AUTHORIZED_CIDRS"

# Safe, non-secret defaults. Every limit here is a ceiling/floor chosen to be
# generous enough for the allowlisted tools (apex_tool_service/allowlist.py)
# while bounding worst-case resource use. None of these are secrets.
_DEFAULT_HOST = "127.0.0.1"  # never 0.0.0.0 by default — explicit opt-in to expose beyond localhost
_DEFAULT_PORT = 8080
_DEFAULT_TIMEOUT_SECONDS = 30.0
_DEFAULT_MAX_TIMEOUT_SECONDS = 120.0
_DEFAULT_MIN_TIMEOUT_SECONDS = 1.0
_DEFAULT_MAX_ARGUMENTS = 32
_DEFAULT_MAX_ARGUMENT_LENGTH = 512
_DEFAULT_MAX_TOTAL_ARGUMENT_BYTES = 4096
_DEFAULT_MAX_STDIN_BYTES = 65_536
_DEFAULT_MAX_STDOUT_BYTES = 1_048_576
_DEFAULT_MAX_STDERR_BYTES = 1_048_576

# Phase 22 defaults — deliberately narrow. `_DEFAULT_BOUNDED_READ_MAX_BYTES`
# and `_DEFAULT_BOUNDED_READ_TIMEOUT_SECONDS` are the service-side HARD
# ceilings — a caller-requested value is always clamped to
# min(requested, this ceiling), never the other way around.
# `_DEFAULT_ALLOWED_FLAG_BASENAMES` intentionally contains only "user.txt" —
# do not widen this default to arbitrary filenames or system paths.
# `_DEFAULT_AUTHORIZED_CIDRS` mirrors `ApexConfig.htb_route_cidr`'s own
# established default (the standard HTB lab network range) — not a single
# hardcoded machine IP, and always operator-overridable.
_DEFAULT_BOUNDED_READ_MAX_BYTES = 4096
_DEFAULT_BOUNDED_READ_TIMEOUT_SECONDS = 10.0
_DEFAULT_ALLOWED_FLAG_BASENAMES: tuple[str, ...] = ("user.txt",)
_DEFAULT_AUTHORIZED_CIDRS: tuple[str, ...] = ("10.129.0.0/16",)


def _parse_csv(raw: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    """Parse a comma-separated env var into a tuple of stripped, non-empty
    entries. ``None``/empty -> *default* (never an empty tuple silently
    disabling a required allowlist)."""
    if not raw or not raw.strip():
        return default
    entries = tuple(part.strip() for part in raw.split(",") if part.strip())
    return entries or default


@dataclass(slots=True, frozen=True)
class ServiceSettings:
    """Immutable service configuration. Construct via ``ServiceSettings.from_env()``."""

    token: str | None
    host: str = _DEFAULT_HOST
    port: int = _DEFAULT_PORT
    default_timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    max_timeout_seconds: float = _DEFAULT_MAX_TIMEOUT_SECONDS
    min_timeout_seconds: float = _DEFAULT_MIN_TIMEOUT_SECONDS
    max_arguments: int = _DEFAULT_MAX_ARGUMENTS
    max_argument_length: int = _DEFAULT_MAX_ARGUMENT_LENGTH
    max_total_argument_bytes: int = _DEFAULT_MAX_TOTAL_ARGUMENT_BYTES
    max_stdin_bytes: int = _DEFAULT_MAX_STDIN_BYTES
    max_stdout_bytes: int = _DEFAULT_MAX_STDOUT_BYTES
    max_stderr_bytes: int = _DEFAULT_MAX_STDERR_BYTES
    bounded_read_max_bytes: int = _DEFAULT_BOUNDED_READ_MAX_BYTES
    bounded_read_timeout_seconds: float = _DEFAULT_BOUNDED_READ_TIMEOUT_SECONDS
    allowed_flag_basenames: tuple[str, ...] = _DEFAULT_ALLOWED_FLAG_BASENAMES
    authorized_cidrs: tuple[str, ...] = _DEFAULT_AUTHORIZED_CIDRS

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ServiceSettings":
        """Build settings from environment variables (or an injected mapping for tests).

        ``env=None`` reads the real process environment (``os.environ``) —
        the only place in this package that happens. Tests should pass an
        explicit ``dict`` instead of mutating real env vars.
        """
        e = env if env is not None else os.environ
        token = e.get(ENV_TOKEN) or None
        return cls(
            token=token,
            host=e.get(ENV_HOST, _DEFAULT_HOST),
            port=int(e.get(ENV_PORT, _DEFAULT_PORT)),
            default_timeout_seconds=float(
                e.get(ENV_DEFAULT_TIMEOUT_SECONDS, _DEFAULT_TIMEOUT_SECONDS)
            ),
            max_timeout_seconds=float(e.get(ENV_MAX_TIMEOUT_SECONDS, _DEFAULT_MAX_TIMEOUT_SECONDS)),
            min_timeout_seconds=float(e.get(ENV_MIN_TIMEOUT_SECONDS, _DEFAULT_MIN_TIMEOUT_SECONDS)),
            max_arguments=int(e.get(ENV_MAX_ARGUMENTS, _DEFAULT_MAX_ARGUMENTS)),
            max_argument_length=int(e.get(ENV_MAX_ARGUMENT_LENGTH, _DEFAULT_MAX_ARGUMENT_LENGTH)),
            max_total_argument_bytes=int(
                e.get(ENV_MAX_TOTAL_ARGUMENT_BYTES, _DEFAULT_MAX_TOTAL_ARGUMENT_BYTES)
            ),
            max_stdin_bytes=int(e.get(ENV_MAX_STDIN_BYTES, _DEFAULT_MAX_STDIN_BYTES)),
            max_stdout_bytes=int(e.get(ENV_MAX_STDOUT_BYTES, _DEFAULT_MAX_STDOUT_BYTES)),
            max_stderr_bytes=int(e.get(ENV_MAX_STDERR_BYTES, _DEFAULT_MAX_STDERR_BYTES)),
            bounded_read_max_bytes=int(
                e.get(ENV_BOUNDED_READ_MAX_BYTES, _DEFAULT_BOUNDED_READ_MAX_BYTES)
            ),
            bounded_read_timeout_seconds=float(
                e.get(ENV_BOUNDED_READ_TIMEOUT, _DEFAULT_BOUNDED_READ_TIMEOUT_SECONDS)
            ),
            allowed_flag_basenames=_parse_csv(
                e.get(ENV_ALLOWED_FLAG_BASENAMES), _DEFAULT_ALLOWED_FLAG_BASENAMES
            ),
            authorized_cidrs=_parse_csv(e.get(ENV_AUTHORIZED_CIDRS), _DEFAULT_AUTHORIZED_CIDRS),
        )

    def to_safe_dict(self) -> dict[str, object]:
        """All fields except ``token`` — never include the token in diagnostics."""
        return {
            "host": self.host,
            "port": self.port,
            "default_timeout_seconds": self.default_timeout_seconds,
            "max_timeout_seconds": self.max_timeout_seconds,
            "min_timeout_seconds": self.min_timeout_seconds,
            "max_arguments": self.max_arguments,
            "max_argument_length": self.max_argument_length,
            "max_total_argument_bytes": self.max_total_argument_bytes,
            "max_stdin_bytes": self.max_stdin_bytes,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
            "bounded_read_max_bytes": self.bounded_read_max_bytes,
            "bounded_read_timeout_seconds": self.bounded_read_timeout_seconds,
            "allowed_flag_basenames": list(self.allowed_flag_basenames),
            "authorized_cidrs": list(self.authorized_cidrs),
            "token_configured": self.token is not None,
        }
