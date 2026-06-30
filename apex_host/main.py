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
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args(argv)


async def run(args: argparse.Namespace) -> None:
    config = ApexConfig(
        target=args.target,
        payload_repo_path=args.payload_repo,
        max_turns=args.max_turns,
        dry_run=args.dry_run,
    )
    runtime = build_runtime(config)

    seeded = await runtime.seed()
    logger.info("seeded %d payload-repo knowledge chunks", seeded)

    final_state = await runtime.run()

    print(f"\nAPEX engagement complete: target={config.target} dry_run={config.dry_run}")
    print(f"turns={final_state['turn_count']} final_phase={final_state['phase']}")
    print(f"findings ({len(final_state['findings'])}):")
    pprint.pprint(final_state["findings"])


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
