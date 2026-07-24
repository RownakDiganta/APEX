# config_env.py
# Centralized, explicit environment-variable loading for ApexConfig — the sole place apex_host reads APEX_*-prefixed application-level environment variables.
"""Centralized environment-variable configuration for ``apex_host``.

``apex_host/config.py`` itself never reads environment variables — enforced
by ``test_arch_08_config_py_has_no_env_access``. That invariant is
preserved unchanged by this phase. This module is the **one** place
outside of it where the application-level ``APEX_*`` environment variables
documented in ``.env.example`` are read and parsed, and it does so
explicitly: nothing is read merely by importing this module. Every read
happens inside the functions below, which default to ``os.environ`` only
when no mapping is injected — every function also accepts an explicit
``Mapping[str, str]`` so tests never need to patch global process state.

Two narrow, deliberate exceptions are **not** handled here, by design:

- ``APEX_TOOL_SERVICE_TOKEN`` continues to be read directly by
  ``apex_host.tools.remote_backend.RemoteToolBackend.__init__`` (Infra
  Phase 4, unchanged) as a fallback when ``ApexConfig.tool_service_token``
  is empty. Duplicating that read here would create two independent
  sources of truth for the same secret; this module leaves
  ``tool_service_token`` alone entirely.
- ``OPENAI_API_KEY`` / ``OPENAI_BASE_URL`` continue to be read directly by
  ``apex_host.llm.router.OpenAIModelRouter`` (pre-existing, unchanged).
  Both are already documented in ``.env.example`` for operator convenience,
  but this module does not re-read or re-validate them — that would be
  scattering the same read across two places for no benefit.

Everything else this module supports maps onto an existing
``ApexConfig``/CLI attribute name and is merged into an
``argparse.Namespace`` *before* that namespace is passed to
``ApexConfig.from_cli_args()`` — the sole approved, tested CLI→config
construction path (``test_arch_10_apex_config_construction_only_in_approved_files``).
This module never calls the ``ApexConfig`` constructor directly.

Precedence (binding, tested): **explicit CLI argument > environment value
> existing safe default.** A CLI flag only participates in this merge when
its ``argparse`` declaration uses ``default=None`` — an explicit
non-``None`` CLI default would silently mask the environment value, which
is exactly the failure mode this module's task brief warned against.
"""
from __future__ import annotations

import argparse
import copy
import os
import pathlib
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

# ---------------------------------------------------------------------------
# Environment variable names — the single source of truth for spelling.
# Mirrors apex_tool_service/settings.py's own ENV_* naming convention.
# ---------------------------------------------------------------------------

ENV_DRY_RUN = "APEX_DRY_RUN"
ENV_LOG_LEVEL = "APEX_LOG_LEVEL"
ENV_MAX_TURNS = "APEX_MAX_TURNS"
ENV_TARGET = "APEX_TARGET"
ENV_KNOWLEDGE_ROOT = "APEX_KNOWLEDGE_ROOT"
ENV_KNOWLEDGE_CACHE_PATH = "APEX_KNOWLEDGE_CACHE_PATH"
ENV_KNOWLEDGE_CACHE_LOCK_TIMEOUT_SECONDS = "APEX_KNOWLEDGE_CACHE_LOCK_TIMEOUT_SECONDS"
ENV_POLICY_FILE = "APEX_POLICY_FILE"
ENV_REPORT_PATH = "APEX_REPORT_PATH"
ENV_GRAPH_PATH = "APEX_GRAPH_PATH"
ENV_TOOL_BACKEND = "APEX_TOOL_BACKEND"
ENV_TOOL_SERVICE_URL = "APEX_TOOL_SERVICE_URL"
ENV_TOOL_SERVICE_TIMEOUT_SECONDS = "APEX_TOOL_SERVICE_TIMEOUT_SECONDS"
ENV_USE_LLM = "APEX_USE_LLM"
ENV_LLM_PROVIDER = "APEX_LLM_PROVIDER"
ENV_LLM_MODEL = "APEX_LLM_MODEL"

# Infra Phase 10 — HTB VPN readiness configuration. See
# docs/htb-vpn-container.md and apex_host/eval/preflight.py.
ENV_VPN_SERVICE_URL = "APEX_VPN_SERVICE_URL"
ENV_VPN_HEALTH_TIMEOUT_SECONDS = "APEX_VPN_HEALTH_TIMEOUT_SECONDS"
ENV_HTB_ROUTE_CIDR = "APEX_HTB_ROUTE_CIDR"
# ENV_HTB_OVPN_PATH is a HOST filesystem path, not a credential — read
# directly (never a secret-style env-var-only convention like the token
# below); still not wired into any --xxx CLI flag on apex_host.main or
# apex_host.eval.run_htb_local, since the profile is a Compose/VPN-container
# concern (compose.htb.yaml), not something those two entry points act on.
ENV_HTB_OVPN_PATH = "APEX_HTB_OVPN_PATH"

# Deliberately NOT read by this module — see the module docstring.
ENV_TOOL_SERVICE_TOKEN = "APEX_TOOL_SERVICE_TOKEN"

_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_VALID_TOOL_BACKENDS = frozenset({"dry-run", "local", "remote"})


class EnvConfigError(ValueError):
    """Raised for a malformed or inconsistent environment-derived configuration value.

    The message is always client-safe: it names the offending variable and
    describes the shape problem, never the secret value itself (only
    ``APEX_TOOL_SERVICE_TOKEN`` is secret, and it is never read by this
    module in the first place — see the module docstring).
    """


def load_env_file(path: str) -> dict[str, str]:
    """Explicitly, opt-in read a dotenv-format file into a plain dict.

    This is the **only** place ``apex_host`` reads a ``.env``-format file
    directly — and it does so only when a caller explicitly asks it to (a
    CLI-supplied ``--env-file PATH``, never an implicit/automatic scan of
    the current working directory). Docker Compose has its own, entirely
    separate, built-in ``.env`` reading (it substitutes ``${VAR}`` before
    the container ever starts — see ``compose.yaml`` and
    ``docs/docker-compose.md``); this function exists for the *direct host
    CLI* use case only, per this phase's own "prefer explicit, predictable
    behavior" instruction.

    Uses ``dotenv_values`` (not ``load_dotenv``) so the real process
    environment is never mutated as a side effect — the returned mapping is
    handed to ``merge_env_into_args(..., env=combined)`` by the caller,
    which conventionally combines it as
    ``{**load_env_file(path), **os.environ}`` so a real, already-exported
    shell variable still wins over the same name found in the file.

    Raises ``EnvConfigError`` if *path* does not exist or cannot be parsed
    — a typo'd ``--env-file`` path fails clearly rather than silently
    producing an empty mapping.
    """
    from dotenv import dotenv_values  # lazy: only imported when --env-file is actually used

    if not pathlib.Path(path).is_file():
        raise EnvConfigError(f"--env-file {path!r} does not exist or is not a file")
    try:
        values = dotenv_values(path)
    except Exception as exc:  # noqa: BLE001 - dotenv's own parse errors vary by version
        raise EnvConfigError(f"--env-file {path!r} could not be parsed: {exc}") from exc
    return {k: v for k, v in values.items() if v is not None}


# ---------------------------------------------------------------------------
# Strict scalar parsing — every parser raises EnvConfigError with a message
# naming the variable, never silently coerces or guesses.
# ---------------------------------------------------------------------------

def _blank_to_none(raw: str | None) -> str | None:
    """Treat a blank/whitespace-only string as absent — required for every
    secret-shaped or optional value (CLAUDE.md-style "blank means unset")."""
    if raw is None:
        return None
    stripped = raw.strip()
    return stripped if stripped else None


def parse_bool_strict(name: str, raw: str) -> bool:
    """Parse a strict boolean. Accepts only a fixed, documented token set —
    never truthy-string heuristics like ``bool("false")`` (which is ``True``
    in Python and exactly the kind of silent footgun this function exists
    to prevent)."""
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise EnvConfigError(
        f"{name}: invalid boolean value {raw!r} "
        "(expected one of: true, false, 1, 0, yes, no, on, off)"
    )


def parse_int_strict(name: str, raw: str, *, minimum: int | None = None) -> int:
    try:
        value = int(raw.strip())
    except ValueError:
        raise EnvConfigError(f"{name}: invalid integer value {raw!r}") from None
    if minimum is not None and value < minimum:
        raise EnvConfigError(f"{name}: value {value} is below the minimum allowed ({minimum})")
    return value


def parse_float_strict(name: str, raw: str, *, minimum: float | None = None) -> float:
    try:
        value = float(raw.strip())
    except ValueError:
        raise EnvConfigError(f"{name}: invalid numeric value {raw!r}") from None
    if minimum is not None and value < minimum:
        raise EnvConfigError(f"{name}: value {value} is below the minimum allowed ({minimum})")
    return value


def normalize_backend_name(raw: str) -> str:
    return raw.strip().lower()


def validate_tool_backend(name: str, raw: str) -> str:
    normalized = normalize_backend_name(raw)
    if normalized not in _VALID_TOOL_BACKENDS:
        raise EnvConfigError(
            f"{name}: invalid tool backend {raw!r} (expected one of: "
            f"{', '.join(sorted(_VALID_TOOL_BACKENDS))})"
        )
    return normalized


def validate_log_level(name: str, raw: str) -> str:
    normalized = raw.strip().upper()
    if normalized not in _VALID_LOG_LEVELS:
        raise EnvConfigError(
            f"{name}: invalid log level {raw!r} (expected one of: "
            f"{', '.join(sorted(_VALID_LOG_LEVELS))})"
        )
    return normalized


def validate_url(name: str, raw: str) -> str:
    """Validate an ``http``/``https`` URL shape. Does not attempt to
    resolve or contact it — purely a structural check, the same class of
    validation ``RemoteToolBackend.__init__`` already performs for a
    CLI-supplied URL (docs/remote-tool-backend.md §2.1); this function
    gives the same clear failure for an env-sourced URL, at parse time,
    before any backend is ever constructed."""
    stripped = raw.strip()
    parsed = urlsplit(stripped)
    if parsed.scheme not in ("http", "https"):
        raise EnvConfigError(
            f"{name}: URL must use http or https, got scheme {parsed.scheme!r} in {raw!r}"
        )
    if not parsed.netloc:
        raise EnvConfigError(f"{name}: not a valid URL: {raw!r}")
    return stripped


def validate_cidr(name: str, raw: str) -> str:
    """Validate *raw* as a well-formed CIDR network (e.g. ``10.129.0.0/16``).

    Uses ``ipaddress.ip_network`` (stdlib) — the same validation approach
    ``docker/vpn/tunnel_status.py::validate_cidr`` uses inside the VPN
    container itself; kept as an independent implementation here rather
    than an import, since ``apex_host`` must not depend on anything under
    ``docker/vpn/`` (that directory is copied into a *different*,
    dependency-free image — see ``docker/vpn/Dockerfile``).
    """
    import ipaddress

    stripped = raw.strip()
    try:
        network = ipaddress.ip_network(stripped, strict=False)
    except ValueError as exc:
        raise EnvConfigError(f"{name}: {raw!r} is not a valid CIDR network") from exc
    return str(network)


# ---------------------------------------------------------------------------
# Target resolution — the one field with a documented, non-generic rule.
# ---------------------------------------------------------------------------

CONFIG_CHECK_TARGET_PLACEHOLDER = "config-check"


def resolve_target(
    cli_target: str | None,
    env: Mapping[str, str] | None = None,
    *,
    required: bool = True,
) -> str:
    """Resolve the engagement target.

    Rule (binding, per this phase's task brief): explicit ``--target`` always
    wins; ``APEX_TARGET`` is an alternative when ``--target`` was not
    passed; a blank/whitespace-only ``APEX_TARGET`` counts as absent, the
    same as an unset one; at least one of the two must resolve to a
    non-blank value when ``required=True`` (the default, used by
    ``apex_host.main`` and ``apex_host.eval.run_htb_local`` — both perform
    real engagement work that always needs a real target), or this raises
    ``EnvConfigError``.

    ``required=False`` is for configuration-validation-only callers (e.g.
    ``apex_host.eval.check_config`` — CLAUDE.md's task brief for this phase
    is explicit: "Do not require a target for Compose smoke mode or
    config-only validation"). In that mode, a clearly-synthetic placeholder
    (``CONFIG_CHECK_TARGET_PLACEHOLDER``) is returned instead of raising —
    it is never treated as a real address by anything downstream of a pure
    config check.
    """
    if cli_target and cli_target.strip():
        return cli_target
    e = env if env is not None else os.environ
    from_env = _blank_to_none(e.get(ENV_TARGET))
    if from_env:
        return from_env
    if not required:
        return CONFIG_CHECK_TARGET_PLACEHOLDER
    raise EnvConfigError(
        "no target provided: pass --target explicitly or set APEX_TARGET "
        "(a blank APEX_TARGET counts as unset — no default target exists)"
    )


# ---------------------------------------------------------------------------
# dry_run resolution — the one safety-critical field with an asymmetric rule.
# ---------------------------------------------------------------------------

def resolve_dry_run(cli_dry_run: bool | None, env: Mapping[str, str] | None = None) -> bool:
    """Resolve ``dry_run`` with dry-run's safety invariant preserved exactly.

    CLAUDE.md §13.5 is unconditional: real execution (``dry_run=False``)
    must always require an explicit CLI flag (``--no-dry-run``) on every
    invocation — never an implicit default, and (this module's own
    extension of that rule) never an environment variable alone either.

    - ``cli_dry_run`` not ``None`` (an explicit ``--dry-run``/``--no-dry-run``
      was passed) → that value wins outright, regardless of the environment.
    - ``cli_dry_run is None`` and ``APEX_DRY_RUN`` parses to ``True`` →
      ``True`` (this only ever *reinforces* the already-safe default; never
      a behavior change).
    - ``cli_dry_run is None`` and ``APEX_DRY_RUN`` parses to ``False`` →
      raises ``EnvConfigError``. Loading a ``.env`` file (or otherwise
      exporting ``APEX_DRY_RUN=false``) can never, by itself, enable real
      command execution — the operator must still pass ``--no-dry-run``
      explicitly on the command line to confirm that intent, exactly as
      CLAUDE.md §13.5 and this phase's philosophy rule 10 ("No automatic
      live engagement may start from loading .env") both require.
    - ``cli_dry_run is None`` and ``APEX_DRY_RUN`` is absent/blank →
      ``True`` (the unchanged, hardcoded safe default).
    """
    if cli_dry_run is not None:
        return cli_dry_run
    e = env if env is not None else os.environ
    raw = _blank_to_none(e.get(ENV_DRY_RUN))
    if raw is None:
        return True
    parsed = parse_bool_strict(ENV_DRY_RUN, raw)
    if parsed:
        return True
    raise EnvConfigError(
        f"{ENV_DRY_RUN}=false was set but --no-dry-run was not passed on the "
        "command line. Real command execution always requires the explicit "
        "--no-dry-run CLI flag (CLAUDE.md §13.5) — an environment variable "
        "alone can never enable it. Pass --no-dry-run explicitly to confirm."
    )


# ---------------------------------------------------------------------------
# Generic merge: fills CLI attributes that are still None with a validated
# environment value, when present. Never overwrites an explicit CLI value.
# ---------------------------------------------------------------------------

def merge_env_into_args(
    args: argparse.Namespace,
    env: Mapping[str, str] | None = None,
    *,
    require_target: bool = True,
) -> argparse.Namespace:
    """Return a copy of *args* with ``None``-valued attributes filled in from
    the environment, per the CLI > environment > default precedence rule.

    Only attributes that are present on *args* **and** currently ``None``
    are eligible — a CLI flag that was actually passed (or whose argparse
    declaration still uses a non-``None`` default, which this module's
    callers are responsible for not doing) is never touched. Attributes not
    present on *args* at all are silently skipped, so this function is safe
    to call with a minimal, purpose-built namespace (e.g.
    ``apex_host.eval.compose_smoke``'s or ``apex_host.eval.check_config``'s
    own namespaces, which do not declare every possible attribute).

    ``require_target=False`` (used only by ``apex_host.eval.check_config``)
    disables ``resolve_target``'s "at least one of --target/APEX_TARGET"
    requirement, substituting ``CONFIG_CHECK_TARGET_PLACEHOLDER`` instead of
    raising — see ``resolve_target``'s own docstring.

    Raises ``EnvConfigError`` (never a bare ``ValueError`` from a stdlib
    parse call) for any malformed environment value it encounters, naming
    the offending variable.
    """
    e = env if env is not None else os.environ
    merged = copy.copy(args)

    def _fill(attr: str, env_name: str, parser: Callable[[str, str], object]) -> None:
        if not hasattr(merged, attr) or getattr(merged, attr) is not None:
            return
        raw = _blank_to_none(e.get(env_name))
        if raw is None:
            return
        setattr(merged, attr, parser(env_name, raw))

    _fill("max_turns", ENV_MAX_TURNS, lambda n, r: parse_int_strict(n, r, minimum=1))
    _fill("knowledge_root", ENV_KNOWLEDGE_ROOT, lambda n, r: r)
    _fill("knowledge_cache_path", ENV_KNOWLEDGE_CACHE_PATH, lambda n, r: r)
    _fill(
        "knowledge_cache_lock_timeout_seconds", ENV_KNOWLEDGE_CACHE_LOCK_TIMEOUT_SECONDS,
        lambda n, r: parse_float_strict(n, r, minimum=0.0),
    )
    _fill("policy_file", ENV_POLICY_FILE, lambda n, r: r)
    _fill("tool_backend", ENV_TOOL_BACKEND, validate_tool_backend)
    _fill("tool_service_url", ENV_TOOL_SERVICE_URL, validate_url)
    _fill(
        "tool_service_timeout", ENV_TOOL_SERVICE_TIMEOUT_SECONDS,
        lambda n, r: parse_float_strict(n, r, minimum=0.0),
    )
    _fill("use_llm", ENV_USE_LLM, parse_bool_strict)
    _fill("llm_provider", ENV_LLM_PROVIDER, lambda n, r: normalize_backend_name(r))
    _fill("llm_model", ENV_LLM_MODEL, lambda n, r: r)
    # export_json / export_graph: only present on run_htb_local's namespace,
    # not main.py's (which has no report-export flags at all) — silently
    # skipped there via the hasattr() guard above.
    _fill("export_json", ENV_REPORT_PATH, lambda n, r: r)
    _fill("export_graph", ENV_GRAPH_PATH, lambda n, r: r)
    # Infra Phase 10 — HTB VPN readiness configuration. Only present on
    # apex_host.container_entrypoint's namespaces (check/smoke/dry-run/run
    # all declare these flags) — silently skipped elsewhere via the
    # hasattr() guard above.
    _fill("vpn_service_url", ENV_VPN_SERVICE_URL, validate_url)
    _fill(
        "vpn_health_timeout", ENV_VPN_HEALTH_TIMEOUT_SECONDS,
        lambda n, r: parse_float_strict(n, r, minimum=0.0),
    )
    _fill("htb_route_cidr", ENV_HTB_ROUTE_CIDR, validate_cidr)
    _fill("htb_ovpn_path", ENV_HTB_OVPN_PATH, lambda n, r: r)

    # dry_run and target use their own dedicated resolution rules (above) —
    # both are *always* resolved (never left None), unlike the generic
    # fields, so they are handled here unconditionally rather than through
    # the None-only `_fill` helper.
    if hasattr(merged, "dry_run"):
        merged.dry_run = resolve_dry_run(getattr(args, "dry_run", None), e)
    if hasattr(merged, "target"):
        merged.target = resolve_target(getattr(args, "target", None), e, required=require_target)

    return merged


def merge_log_level(cli_verbose: bool, env: Mapping[str, str] | None = None) -> str:
    """Resolve the effective logging level name.

    ``-v``/``--verbose`` (an explicit CLI flag) always wins and means
    ``DEBUG``, matching every entry point's existing, unchanged behavior.
    Otherwise ``APEX_LOG_LEVEL`` is honored if present and valid; absent
    entirely, the caller's own pre-existing default applies (this function
    returns ``None`` in that case so the caller's own default is
    untouched — it never invents a new default itself).
    """
    if cli_verbose:
        return "DEBUG"
    e = env if env is not None else os.environ
    raw = _blank_to_none(e.get(ENV_LOG_LEVEL))
    if raw is None:
        return ""
    return validate_log_level(ENV_LOG_LEVEL, raw)


# ---------------------------------------------------------------------------
# Top-level convenience: merge + construct, still going through the sole
# approved ApexConfig.from_cli_args() construction path.
# ---------------------------------------------------------------------------

def load_apex_config_from_env(
    args: argparse.Namespace,
    env: Mapping[str, str] | None = None,
    *,
    require_target: bool = True,
) -> "ApexConfig":
    """Merge *args* with environment-derived overrides and build an
    ``ApexConfig`` via the existing, approved ``ApexConfig.from_cli_args()``
    classmethod.

    This is the single, explicit, opt-in entry point ``apex_host.main`` and
    ``apex_host.eval.run_htb_local`` call instead of
    ``ApexConfig.from_cli_args(args)`` directly. Nothing is read from the
    environment merely by importing this module or ``apex_host.config`` —
    only by calling this function (or one of the narrower functions above).
    ``require_target=False`` is for ``apex_host.eval.check_config`` only —
    see ``merge_env_into_args``.
    """
    from apex_host.config import ApexConfig  # local import: config.py must not import this module

    merged = merge_env_into_args(args, env, require_target=require_target)
    return ApexConfig.from_cli_args(merged)
