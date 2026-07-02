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

async def run_engagement(config: ApexConfig) -> tuple[ApexRuntime, ApexGraphState]:
    """Build runtime, seed payload repo, and run the engagement graph.

    Returns the live ``ApexRuntime`` (with its ``api`` still accessible) and
    the completed ``ApexGraphState``.  The caller can query the api further
    after this call returns.
    """
    runtime = build_runtime(config)
    seeded = await runtime.seed()
    logger.info("seeded %d payload-repo chunks", seeded)
    final_state = await runtime.run()
    return runtime, final_state


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
        "--preflight", action="store_true",
        help="Check which allowed tools are in PATH then exit",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return parser.parse_args(argv)


async def _async_main(args: argparse.Namespace) -> None:
    config = ApexConfig(
        target=args.target,
        payload_repo_path=args.payload_repo,
        max_turns=args.max_turns,
        dry_run=args.dry_run,
        web_wordlist_path=args.web_wordlist,
        max_web_paths=args.max_web_paths,
        username_candidates=list(args.username),
        password_candidates=list(args.password),
        max_access_attempts=args.max_access_attempts,
    )

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

    runtime, final_state = await run_engagement(config)
    subgraph = await runtime.api.get_subgraph(f"host:{config.target}", depth=10)

    report = build_report(final_state, subgraph, config)
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
    asyncio.run(_async_main(args))


if __name__ == "__main__":
    main()
