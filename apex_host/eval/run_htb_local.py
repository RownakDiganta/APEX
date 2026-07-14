# run_htb_local.py
# Runs the APEX-Nexus prototype against an authorized HTB target from a local machine.
"""General local runner for authorized HTB Easy/Medium machines.

Usage examples
--------------
Dry-run (safe, no real commands):
    python -m apex_host.eval.run_htb_local \\
        --target <HTB_TARGET_IP> --payload-repo ./payloads --dry-run

Live authorized run (HTB VPN required):
    python -m apex_host.eval.run_htb_local \\
        --target <HTB_TARGET_IP> --payload-repo ./payloads \\
        --no-dry-run --username <USER> --password <PASS>

Preflight tool check:
    python -m apex_host.eval.run_htb_local --target <IP> --preflight

The runner prints a phase-by-phase summary, full findings table, EKG
node/edge breakdown, and episode count after the engagement completes.
Live mode requires ``--no-dry-run`` to be passed explicitly — the default
is always safe dry-run mode.

All target details (IP, credentials, payload repo) are supplied through CLI
flags.  No machine-specific profiles, expected credential paths, or
target-specific defaults exist in this module or anywhere in the codebase.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from memfabric.types import SubgraphView

from apex_host.config import ApexConfig
from apex_host.eval.export_graph import export_ekg
from apex_host.eval.report import (
    RunReport,
    build_report,
    format_text,
    to_json_dict,
    write_report_json,
)
from apex_host.graph_state import ApexGraphState
from apex_host.runtime import ApexRuntime, build_runtime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core engagement runner (importable for tests)
# ---------------------------------------------------------------------------

async def run_engagement(
    config: ApexConfig,
) -> tuple[ApexRuntime, ApexGraphState, dict[str, object]]:
    """Build runtime, seed all knowledge sources, and run the engagement graph.

    Returns a triple of:
    - ``ApexRuntime`` (api still accessible after return)
    - completed ``ApexGraphState``
    - seed_results dict from ``seed_all()`` (includes ``"_promotion"`` key when
      compiled knowledge was loaded)

    ``seed_all()`` loads both the raw payload repo (``--payload-repo``) and any
    compiled knowledge families configured via ``--knowledge-root``.  When
    neither is configured it is a no-op for the compiled families.
    """
    runtime = build_runtime(config)
    seed_results = await runtime.seed_all()
    logger.info("seeded knowledge: %s", {k: v for k, v in seed_results.items() if k != "_promotion"})
    final_state = await runtime.run()
    return runtime, final_state, dict(seed_results)


# ---------------------------------------------------------------------------
# Report formatting — delegates to apex_host.eval.report
# ---------------------------------------------------------------------------

def format_report(
    final_state: ApexGraphState,
    *,
    subgraph: SubgraphView,
    config: ApexConfig,
) -> str:
    """Render a human-readable engagement report as a string.

    Backward-compatible wrapper: existing callers and tests that import
    ``format_report`` from this module continue to work unchanged.
    """
    return format_text(build_report(final_state, subgraph, config))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="apex_host.eval.run_htb_local",
        description=(
            "APEX-Nexus local HTB runner. "
            "Any authorized HTB Easy/Medium machine reachable over the HTB VPN "
            "is a valid target. All target details are supplied through CLI flags."
        ),
    )
    parser.add_argument("--target", required=True, help="HTB target IP/hostname")
    parser.add_argument(
        "--payload-repo", default="./payloads",
        help="Path to the payload repo (RAG seed corpus)",
    )
    parser.add_argument("--max-turns", type=int, default=20, help="Maximum engagement turns")
    dry = parser.add_mutually_exclusive_group()
    dry.add_argument(
        "--dry-run", dest="dry_run", action="store_true", default=True,
        help="Simulate tool execution; no real commands (default)",
    )
    dry.add_argument(
        "--no-dry-run", dest="dry_run", action="store_false",
        help="Allow real, safety-gated execution (requires HTB VPN for live targets)",
    )
    parser.add_argument(
        "--username", dest="username", action="append", default=[], metavar="USER",
        help="Username for bounded access validation (repeatable)",
    )
    parser.add_argument(
        "--password", dest="password", action="append", default=[], metavar="PASS",
        help="Password for bounded access validation (repeatable)",
    )
    parser.add_argument(
        "--max-access-attempts", type=int, default=1,
        help="Maximum access-validation attempts (default: 1)",
    )
    parser.add_argument(
        "--web-wordlist", dest="web_wordlist", default=None, metavar="PATH",
        help="Wordlist for ffuf/gobuster directory discovery (omit to use curl-only web probing)",
    )
    parser.add_argument(
        "--max-web-paths", type=int, default=50,
        help="Maximum web paths to discover per turn (default: 50)",
    )
    parser.add_argument(
        "--export-graph", metavar="PATH",
        help="After the run, write EKG nodes+edges JSON to this file",
    )
    parser.add_argument(
        "--export-json", dest="export_json", metavar="PATH",
        help="After the run, write a full structured run-report JSON to this file",
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
            "Explicit path to the policy YAML file (e.g. "
            "./knowledge/policy_db/compiled/hackthebox_lab.yaml). "
            "Overrides automatic discovery through --knowledge-root and the "
            "conventional local-development path. "
            "If the path does not exist, the conservative built-in fallback is "
            "used and a warning is emitted. "
            "Precedence: --policy-file > --knowledge-root discovery > "
            "conservative default."
        ),
    )
    # LLM call budget flags — only relevant when --use-llm is set.
    parser.add_argument(
        "--max-llm-calls", dest="max_llm_calls", type=int, default=None, metavar="N",
        help=(
            "Maximum real LLM calls for the entire run (default: 5). "
            "When exhausted, the deterministic fallback planner is used for "
            "all remaining turns."
        ),
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
    parser.add_argument(
        "--preflight", action="store_true",
        help="Check which allowed tools are in PATH then exit",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    parser.add_argument(
        "--http-debug", dest="http_debug", action="store_true", default=False,
        help=(
            "Enable raw HTTP transport debug logs from openai/httpx/httpcore. "
            "Only use when diagnosing API connectivity issues — these logs are "
            "very verbose and may expose request headers (never API keys). "
            "Requires -v to be set."
        ),
    )
    parser.add_argument(
        "--trace-records", dest="trace_records", action="store_true", default=False,
        help=(
            "Show per-record Reflector promotion logs when -v is set. "
            "Without this flag, -v shows only interval summaries and the final "
            "count — not one line per promoted record. "
            "Only useful when diagnosing knowledge-seeding issues."
        ),
    )
    return parser.parse_args(argv)


async def _async_main(args: argparse.Namespace) -> None:
    config = ApexConfig.from_cli_args(args)

    if args.preflight:
        from apex_host.tools.preflight import check_local_tools
        availability = check_local_tools(config)
        print(f"Preflight tool check — target={config.target!r}:")
        for tool, present in availability.items():
            print(f"  [{'OK    ' if present else 'MISSING'}] {tool}")
        missing = [t for t, ok in availability.items() if not ok]
        if missing:
            print(f"\n{len(missing)} tool(s) missing.")
            sys.exit(1)
        print("\nAll allowed tools found.")
        sys.exit(0)

    runtime, final_state, seed_results = await run_engagement(config)
    subgraph = await runtime.api.get_subgraph(f"host:{config.target}", depth=10)

    # Derive policy_source for the report (read from the loaded policy).
    try:
        from apex_host.policy.policy_loader import load_policy
        policy = load_policy(config)
        policy_source = policy.policy_source
    except Exception:  # noqa: BLE001
        policy_source = "unknown"

    llm_budget = runtime.last_budget.to_dict() if runtime.last_budget is not None else None
    report = build_report(
        final_state, subgraph, config,
        seed_results=seed_results,
        policy_source=policy_source,
        llm_budget=llm_budget,
    )
    print(format_text(report))

    if args.export_graph:
        from apex_host.eval.export_graph import write_json
        ekg_data = await export_ekg(runtime.api, f"host:{config.target}")
        write_json(ekg_data, args.export_graph)
        print(f"EKG exported to {args.export_graph}")

    if args.export_json:
        write_report_json(report, args.export_json)
        print(f"Run report exported to {args.export_json}")


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)
    # Suppress chatty HTTP transport libs when -v is set but --http-debug is not.
    # Without this, openai/_base_client and httpx flood the terminal with per-header
    # DEBUG lines that bury APEX-level planning/execution summaries.
    if args.verbose and not getattr(args, "http_debug", False):
        for _noisy in ("openai", "openai._base_client", "httpx", "httpcore"):
            logging.getLogger(_noisy).setLevel(logging.WARNING)
    # Suppress per-record reflector DEBUG logs unless --trace-records is set.
    # Without this, -v with large knowledge corpora floods the terminal with one
    # line per promoted record (63 000+ lines for a full knowledge build).
    # The interval-progress and final-summary INFO lines remain visible.
    if args.verbose and not getattr(args, "trace_records", False):
        logging.getLogger("memfabric.reflector.worker").setLevel(logging.INFO)
    asyncio.run(_async_main(args))


if __name__ == "__main__":
    main()
