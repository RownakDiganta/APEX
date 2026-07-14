# main.py
# CLI entry point for the APEX host application, wiring config and runtime then running the engagement graph to completion.
"""CLI entry point.

    python -m apex_host.main --target 127.0.0.1 --payload-repo ./payloads --dry-run

``--dry-run`` (default True) threads through ApexConfig.dry_run -> runtime.py
-> graph.py -> tools/runner.py, guaranteeing no real command execution unless
the host explicitly passes ``--no-dry-run``. ``APEX_TARGET``/``APEX_DRY_RUN``/
other ``APEX_*`` environment variables are an alternative to their CLI-flag
equivalents (see ``apex_host/config_env.py`` and
``docs/environment-configuration.md``) — an explicit CLI flag always wins,
and ``APEX_DRY_RUN=false`` alone can never enable real execution without the
explicit ``--no-dry-run`` flag also being passed.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import pprint
import sys

from apex_host.config import ApexConfig
from apex_host.config_env import EnvConfigError, load_env_file, merge_env_into_args, merge_log_level
from apex_host.runtime import build_runtime

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="apex_host", description="APEX cybersecurity host application")
    parser.add_argument(
        "--target", required=False, default=None,
        help=(
            "Engagement target (host or URL). May be omitted if APEX_TARGET "
            "is set (a blank APEX_TARGET counts as unset) — explicit "
            "--target always wins. At least one of the two is required."
        ),
    )
    parser.add_argument("--payload-repo", default="./payloads", help="Path to the payload repo (RAG seed corpus)")
    parser.add_argument(
        "--max-turns", type=int, default=None,
        help="Maximum engagement turns (default: 20, or $APEX_MAX_TURNS)",
    )
    dry_run_group = parser.add_mutually_exclusive_group()
    dry_run_group.add_argument(
        "--dry-run", dest="dry_run", action="store_true", default=None,
        help=(
            "Simulate tool execution; perform no real commands (default — "
            "matches $APEX_DRY_RUN when true; $APEX_DRY_RUN=false alone can "
            "never enable real execution)"
        ),
    )
    dry_run_group.add_argument(
        "--no-dry-run", dest="dry_run", action="store_false",
        help="Allow real, safety-gated command execution",
    )
    parser.add_argument(
        "--username", dest="username", action="append", default=[],
        metavar="USER",
        help="Username candidate for bounded access validation (may be specified multiple times)",
    )
    parser.add_argument(
        "--password", dest="password", action="append", default=[],
        metavar="PASS",
        help="Password candidate for bounded access validation (may be specified multiple times)",
    )
    parser.add_argument(
        "--web-wordlist", dest="web_wordlist", default=None, metavar="PATH",
        help="Wordlist file for ffuf/gobuster directory discovery (omit to skip wordlist-based fuzzing)",
    )
    parser.add_argument(
        "--max-web-paths", type=int, default=50,
        help="Maximum number of web paths to discover per turn (default: 50)",
    )
    parser.add_argument(
        "--max-access-attempts", type=int, default=1,
        help="Maximum access validation attempts per run (default: 1; never brute-forces)",
    )
    parser.add_argument(
        "--use-llm", dest="use_llm", action="store_true", default=None,
        help=(
            "Enable LLM-backed planning (default: fully deterministic, no API "
            "calls; also settable via $APEX_USE_LLM)"
        ),
    )
    parser.add_argument(
        "--llm-provider", dest="llm_provider", default=None, metavar="PROVIDER",
        help="LLM provider when --use-llm is set (default: fake/deterministic; use 'openai' for real LLM)",
    )
    parser.add_argument(
        "--llm-model", dest="llm_model", default=None, metavar="MODEL",
        help="Model for LLM planning (e.g. openai/gpt-5.5); sets planner/executor/parser models",
    )
    parser.add_argument(
        "--llm-base-url", dest="llm_base_url", default=None, metavar="URL",
        help="Override LLM API base URL (e.g. https://openrouter.ai/api/v1)",
    )
    parser.add_argument(
        "--knowledge-root", dest="knowledge_root", default=None, metavar="DIR",
        help=(
            "Root of the compiled knowledge directory (e.g. ./knowledge). "
            "Sub-directories (intel_db, methodology_db, payload_db, policy_db) "
            "are loaded from <knowledge_root>/<family>/compiled/. "
            "Families whose compiled/ directory is absent are skipped gracefully."
        ),
    )
    parser.add_argument(
        "--policy-file", dest="policy_file", default=None, metavar="PATH",
        help=(
            "Explicit path to the policy YAML file. "
            "Overrides automatic discovery through --knowledge-root and the "
            "conventional local-development path. "
            "Precedence: --policy-file > --knowledge-root discovery > "
            "conservative default."
        ),
    )
    # Infra Phase 4 — tool-execution backend selection.
    # No --tool-service-token flag exists on purpose: CLI arguments are
    # visible in shell history and `ps` output. Set the bearer token via the
    # APEX_TOOL_SERVICE_TOKEN environment variable instead.
    parser.add_argument(
        "--tool-backend", dest="tool_backend", default=None,
        choices=["dry-run", "local", "remote"], metavar="{dry-run,local,remote}",
        help=(
            "Tool-execution backend for generic (non-Telnet, non-browser) commands "
            "(default: local). Ignored whenever --dry-run is in effect. "
            "See docs/remote-tool-backend.md."
        ),
    )
    parser.add_argument(
        "--tool-service-url", dest="tool_service_url", default=None, metavar="URL",
        help="Base URL of a Phase 3 apex_tool_service instance (required when --tool-backend remote).",
    )
    parser.add_argument(
        "--tool-service-timeout", dest="tool_service_timeout", type=float, default=None, metavar="SECS",
        help="Overall request timeout budget in seconds for the remote tool backend (default: 120.0).",
    )
    # LLM call budget flags — only relevant when --use-llm is set.
    parser.add_argument(
        "--max-llm-calls", dest="max_llm_calls", type=int, default=None, metavar="N",
        help="Maximum real LLM calls for the entire run (default: 5).",
    )
    parser.add_argument(
        "--max-llm-calls-per-phase", dest="max_llm_calls_per_phase",
        type=int, default=None, metavar="N",
        help="Maximum LLM calls per phase (default: 2).",
    )
    parser.add_argument(
        "--llm-timeout", dest="llm_timeout", type=float, default=None, metavar="SECS",
        help="Per-call LLM request timeout in seconds (default: 60.0).",
    )
    llm_repeat = parser.add_mutually_exclusive_group()
    llm_repeat.add_argument(
        "--llm-stop-on-repeated-plan", dest="llm_stop_on_repeated_plan",
        action="store_true", default=True,
        help="Skip LLM call when context is unchanged since last call for the same phase (default).",
    )
    llm_repeat.add_argument(
        "--no-llm-stop-on-repeated-plan", dest="llm_stop_on_repeated_plan",
        action="store_false",
        help="Always call LLM even when context is unchanged.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--http-debug", dest="http_debug", action="store_true", default=False,
        help=(
            "Enable raw HTTP transport debug logs from openai/httpx/httpcore. "
            "Only use when diagnosing API connectivity issues. Requires -v."
        ),
    )
    parser.add_argument(
        "--preflight", action="store_true",
        help="Check which allowed tools are available in PATH then exit",
    )
    parser.add_argument(
        "--trace-records", dest="trace_records", action="store_true", default=False,
        help=(
            "Show per-record Reflector promotion logs when -v is set. "
            "Without this flag, -v shows only interval summaries and the final "
            "count. Only useful when diagnosing knowledge-seeding issues."
        ),
    )
    parser.add_argument(
        "--env-file", dest="env_file", default=None, metavar="PATH",
        help=(
            "Explicitly load a dotenv-format file (e.g. .env) before "
            "resolving $APEX_* environment values. Never loaded implicitly — "
            "omit this flag to use only real, exported environment variables."
        ),
    )
    return parser.parse_args(argv)


async def run(args: argparse.Namespace) -> None:
    config = ApexConfig.from_cli_args(args)

    if args.preflight:
        from apex_host.tools.preflight import check_local_tools
        availability = check_local_tools(config)
        print(f"Preflight tool check for target={config.target!r}:")
        for tool, present in availability.items():
            status = "OK     " if present else "MISSING"
            print(f"  [{status}] {tool}")
        missing = [t for t, ok in availability.items() if not ok]
        if missing:
            print(f"\n{len(missing)} tool(s) missing — install or remove from allowed_tools.")
            sys.exit(1)
        print("\nAll allowed tools found.")
        sys.exit(0)

    runtime = build_runtime(config)

    seed_results = await runtime.seed_all()
    logger.info("seeded knowledge: %s", seed_results)

    final_state = await runtime.run()

    print(f"\nAPEX engagement complete: target={config.target} dry_run={config.dry_run}")
    print(f"turns={final_state['turn_count']} final_phase={final_state['phase']}")
    print(f"findings ({len(final_state['findings'])}):")
    pprint.pprint(final_state["findings"])


def main(argv: list[str] | None = None) -> None:
    raw_args = parse_args(argv)
    # Single, explicit merge point: environment values fill in whichever CLI
    # flags were left at their argparse `default=None` (i.e. not passed). An
    # explicit CLI flag always wins — see apex_host/config_env.py.
    try:
        env = None
        if raw_args.env_file:
            env = {**load_env_file(raw_args.env_file), **os.environ}
        args = merge_env_into_args(raw_args, env)
    except EnvConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    log_level_name = merge_log_level(args.verbose)
    effective_level = getattr(logging, log_level_name) if log_level_name else logging.INFO
    logging.basicConfig(level=effective_level)
    # Suppress chatty HTTP transport libs when -v is set but --http-debug is not.
    if args.verbose and not getattr(args, "http_debug", False):
        for _noisy in ("openai", "openai._base_client", "httpx", "httpcore"):
            logging.getLogger(_noisy).setLevel(logging.WARNING)
    # Suppress per-record reflector DEBUG logs unless --trace-records is set.
    if args.verbose and not getattr(args, "trace_records", False):
        logging.getLogger("memfabric.reflector.worker").setLevel(logging.INFO)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
