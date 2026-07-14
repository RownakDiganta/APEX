# main.py
# CLI entry point for the APEX host application, wiring config and runtime then running the engagement graph to completion.
"""CLI entry point.

    python -m apex_host.main --target 127.0.0.1 --payload-repo ./payloads --dry-run

``--dry-run`` (default True) threads through ApexConfig.dry_run -> runtime.py
-> graph.py -> tools/runner.py, guaranteeing no real command execution unless
the host explicitly passes ``--no-dry-run``.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import pprint

from apex_host.config import ApexConfig
from apex_host.runtime import build_runtime

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="apex_host", description="APEX cybersecurity host application")
    parser.add_argument("--target", required=True, help="Engagement target (host or URL)")
    parser.add_argument("--payload-repo", default="./payloads", help="Path to the payload repo (RAG seed corpus)")
    parser.add_argument("--max-turns", type=int, default=20, help="Maximum engagement turns")
    dry_run_group = parser.add_mutually_exclusive_group()
    dry_run_group.add_argument(
        "--dry-run", dest="dry_run", action="store_true", default=True,
        help="Simulate tool execution; perform no real commands (default)",
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
        "--use-llm", dest="use_llm", action="store_true", default=False,
        help="Enable LLM-backed planning (default: fully deterministic, no API calls)",
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
    return parser.parse_args(argv)


async def run(args: argparse.Namespace) -> None:
    import sys

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
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
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
