# check_config.py
# Safe, network-free (by default) configuration validation command — parses configuration, prints a redacted summary, never contacts a target.
"""Configuration validation command.

    uv run python -m apex_host.eval.check_config
    uv run python -m apex_host.eval.check_config --tool-backend remote --tool-service-url http://kali:8080

This command parses configuration (CLI flags merged with the ``APEX_*``
environment variables documented in ``.env.example`` — see
``apex_host/config_env.py``), validates required combinations, prints a
redacted summary, and exits non-zero for invalid configuration. It never
contacts a real target, and by default never makes any network call at
all — the optional ``--check-connectivity`` flag is the sole, explicit way
to make this command touch the network, and even then it only ever issues
an unauthenticated ``GET /health`` against the configured tool-service URL
(never ``POST /v1/execute`` — no tool is ever run).

**No target is required.** Unlike ``apex_host.main`` and
``apex_host.eval.run_htb_local`` (which always need a real engagement
target), this command's whole purpose is validating *configuration shape*,
not preparing a real engagement — ``--target``/``APEX_TARGET`` are both
optional here; a fixed, clearly-synthetic placeholder
(``apex_host.config_env.CONFIG_CHECK_TARGET_PLACEHOLDER``) is used when
neither is supplied.

This command is designed to work identically on the host and inside the
``apex`` container (it has no container-specific behavior) — see
``docs/environment-configuration.md`` "Config validation command".
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from urllib.parse import urlsplit

import httpx

from apex_host.config import ApexConfig
from apex_host.config_env import (
    EnvConfigError,
    ENV_TOOL_SERVICE_TOKEN,
    load_apex_config_from_env,
    load_env_file,
    merge_log_level,
)

_CONNECTIVITY_TIMEOUT_SECONDS = 5.0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="apex_host.eval.check_config",
        description=(
            "Parse and validate APEX configuration (CLI flags + APEX_* "
            "environment variables), print a redacted summary, and exit "
            "non-zero on any invalid combination. Never contacts a real "
            "target; never calls the tool service unless --check-connectivity "
            "is explicitly passed (and even then, only GET /health)."
        ),
    )
    parser.add_argument(
        "--target", default=None,
        help="Optional. Falls back to $APEX_TARGET, then a synthetic placeholder — never required here.",
    )
    dry = parser.add_mutually_exclusive_group()
    dry.add_argument("--dry-run", dest="dry_run", action="store_true", default=None)
    dry.add_argument("--no-dry-run", dest="dry_run", action="store_false")
    parser.add_argument("--max-turns", dest="max_turns", type=int, default=None)
    parser.add_argument("--knowledge-root", dest="knowledge_root", default=None, metavar="DIR")
    parser.add_argument("--policy-file", dest="policy_file", default=None, metavar="PATH")
    parser.add_argument(
        "--tool-backend", dest="tool_backend", default=None,
        choices=["dry-run", "local", "remote"], metavar="{dry-run,local,remote}",
    )
    parser.add_argument("--tool-service-url", dest="tool_service_url", default=None, metavar="URL")
    parser.add_argument(
        "--tool-service-timeout", dest="tool_service_timeout", type=float, default=None, metavar="SECS",
    )
    use_llm = parser.add_mutually_exclusive_group()
    use_llm.add_argument("--use-llm", dest="use_llm", action="store_true", default=None)
    use_llm.add_argument("--no-use-llm", dest="use_llm", action="store_false")
    parser.add_argument("--llm-provider", dest="llm_provider", default=None, metavar="PROVIDER")
    parser.add_argument("--llm-model", dest="llm_model", default=None, metavar="MODEL")
    parser.add_argument(
        "--check-connectivity", dest="check_connectivity", action="store_true", default=False,
        help=(
            "Opt-in only: when the resolved backend is 'remote' and dry_run "
            "is False, issue a bounded, unauthenticated GET /health against "
            "the configured tool-service URL. Never POSTs to /v1/execute. "
            "Off by default — the default invocation makes no network call."
        ),
    )
    parser.add_argument(
        "--env-file", dest="env_file", default=None, metavar="PATH",
        help=(
            "Explicitly load a dotenv-format file (e.g. .env) before "
            "resolving environment-derived values. Never loaded implicitly "
            "or automatically — omit this flag to use only real, exported "
            "environment variables (the default, predictable behavior)."
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", default=False)
    return parser.parse_args(argv)


def _validate_combinations(config: ApexConfig) -> list[str]:
    """Return a list of human-readable problems with *config* as a whole.
    Empty list means the configuration is valid. Never raises."""
    problems: list[str] = []

    if config.tool_backend == "remote" and not config.dry_run:
        if not config.tool_service_url:
            problems.append(
                "tool_backend='remote' requires --tool-service-url or $APEX_TOOL_SERVICE_URL "
                "(remote backend has no default URL)"
            )
        else:
            parsed = urlsplit(config.tool_service_url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                problems.append(f"tool_service_url {config.tool_service_url!r} is not a valid http(s) URL")

        token_present = bool(config.tool_service_token) or bool(os.environ.get(ENV_TOOL_SERVICE_TOKEN))
        if not token_present:
            problems.append(
                f"tool_backend='remote' requires a bearer token via ${ENV_TOOL_SERVICE_TOKEN} "
                "(there is deliberately no CLI flag for this — see docs/remote-tool-backend.md §3.2)"
            )

    if config.use_llm and config.llm_provider not in ("fake", ""):
        if not os.environ.get("OPENAI_API_KEY"):
            problems.append(
                f"use_llm=True with llm_provider={config.llm_provider!r} requires $OPENAI_API_KEY "
                "to be set (not required when llm_provider is 'fake' or --use-llm is not set)"
            )

    if config.max_turns < 1:
        problems.append(f"max_turns={config.max_turns} must be at least 1")

    if config.tool_service_timeout_seconds < 0:
        problems.append(
            f"tool_service_timeout_seconds={config.tool_service_timeout_seconds} must not be negative"
        )

    return problems


async def _check_connectivity(url: str) -> tuple[bool, str]:
    """Bounded, unauthenticated GET /health only — never POST /v1/execute,
    never a tool invocation. Returns (reachable, detail)."""
    try:
        async with httpx.AsyncClient(timeout=_CONNECTIVITY_TIMEOUT_SECONDS) as client:
            response = await client.get(f"{url.rstrip('/')}/health")
        if response.status_code == 200:
            return True, f"GET {url.rstrip('/')}/health -> 200 OK"
        return False, f"GET {url.rstrip('/')}/health -> HTTP {response.status_code}"
    except httpx.RequestError as exc:
        return False, f"GET {url.rstrip('/')}/health -> connection failed: {exc.__class__.__name__}"


def _print_summary(config: ApexConfig, problems: list[str]) -> None:
    safe = config.to_safe_dict()
    print("APEX configuration summary (redacted):")
    for key in (
        "target", "dry_run", "max_turns", "tool_backend", "tool_service_url",
        "tool_service_timeout_seconds", "use_llm", "llm_provider", "planner_model",
        "knowledge_root", "policy_file", "config_schema_version",
    ):
        print(f"  {key}: {safe[key]!r}")

    token_state = "present" if os.environ.get(ENV_TOOL_SERVICE_TOKEN) or config.tool_service_token else "absent"
    openai_key_state = "present" if os.environ.get("OPENAI_API_KEY") else "absent"
    print(f"  tool_service_token: {token_state} (never displayed)")
    print(f"  OPENAI_API_KEY: {openai_key_state} (never displayed)")

    if problems:
        print("\nINVALID configuration:")
        for problem in problems:
            print(f"  - {problem}")
    else:
        print("\nConfiguration is valid.")


async def _async_main(argv: list[str] | None) -> int:
    args = _parse_args(argv)
    try:
        env = None
        if args.env_file:
            # Explicit opt-in only (never automatic) — see load_env_file's
            # own docstring. Real, already-exported environment variables
            # still win over the same name found in the file.
            env = {**load_env_file(args.env_file), **os.environ}
        config = load_apex_config_from_env(args, env, require_target=False)
    except EnvConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    log_level_name = merge_log_level(args.verbose)
    if log_level_name:
        logging.basicConfig(level=getattr(logging, log_level_name))

    problems = _validate_combinations(config)
    _print_summary(config, problems)

    if args.check_connectivity and config.tool_backend == "remote" and config.tool_service_url:
        reachable, detail = await _check_connectivity(config.tool_service_url)
        print(f"\nConnectivity check: {detail}")
        if not reachable:
            problems.append(f"connectivity check failed: {detail}")

    return 1 if problems else 0


def main(argv: list[str] | None = None) -> None:
    sys.exit(asyncio.run(_async_main(argv)))


if __name__ == "__main__":
    main()
