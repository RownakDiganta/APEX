# compose_smoke.py
# Infrastructure connectivity smoke test for the APEX/Kali Compose environment — proves backend wiring works; not an engagement execution path.
"""Compose connectivity smoke test.

This module exercises the ``ToolBackend`` abstraction
(``apex_host.tools.backend.select_runtime_backend``) directly with one
harmless, version-only command (``curl --version`` by default). It proves
that the APEX container can reach a configured tool-execution backend —
in the Compose environment (``compose.yaml``, Infra Phase 7), that backend
is the ``kali`` service reached over the internal ``apex-internal``
network at ``http://kali:8080``.

**This is NOT an engagement execution path.** It never constructs a
``TaskSpec``, never calls ``TaskDispatcher``/``PolicyAdvisor``, never
touches ``MemoryAPI``, and never targets a real host — ``ApexConfig.target``
is set to the fixed placeholder string ``"compose-smoke-test"``, used only
because ``ApexConfig`` requires a ``target`` field; it is never passed to
anything that would treat it as a real address. See
``docs/docker-compose.md`` "Connectivity smoke test" for the full design
rationale and every documented invocation.

**Safety invariant preserved (CLAUDE.md §13.5):** exactly like every other
APEX entry point, ``--dry-run`` is the default and real backend contact
requires the explicit ``--no-dry-run`` flag. Compose's own default
``command:`` for the ``apex`` service passes no flags at all, so
``docker compose up`` never contacts the ``kali`` service by default —
only an explicit ``docker compose run --rm apex python -m
apex_host.eval.compose_smoke --no-dry-run`` (or an equivalent override)
performs a real HTTP call.

**No secret logging.** Only ``tool_service_url`` (a plain address, not a
credential) and non-secret ``ToolResult`` fields are ever printed. The
bearer token is never read, held, or logged by this module — it flows
directly from the ``APEX_TOOL_SERVICE_TOKEN`` environment variable into
``RemoteToolBackend.__init__`` (see ``docs/remote-tool-backend.md`` §3.2),
exactly as it does for every other caller of that class.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Any

from apex_host.config import ApexConfig
from apex_host.tools.backend import select_runtime_backend


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="apex_host.eval.compose_smoke",
        description=(
            "Infrastructure connectivity smoke test: proves the APEX container "
            "can reach a configured tool-execution backend (dry-run, local, or "
            "a remote apex_tool_service instance such as the Compose 'kali' "
            "service) and execute one harmless, version-only command. This is "
            "NOT an engagement execution path — it never routes through "
            "TaskDispatcher, PolicyAdvisor, or MemoryAPI, and it never "
            "targets a real host."
        ),
    )
    dry = parser.add_mutually_exclusive_group()
    dry.add_argument(
        "--dry-run", dest="dry_run", action="store_true", default=True,
        help=(
            "Never contact any backend; prove configuration is valid with "
            "zero network I/O (default — matches every other APEX entry "
            "point's safe default)."
        ),
    )
    dry.add_argument(
        "--no-dry-run", dest="dry_run", action="store_false",
        help="Actually contact the configured tool backend (e.g. the Compose 'kali' service).",
    )
    parser.add_argument(
        "--tool-backend", dest="tool_backend",
        default=os.environ.get("APEX_TOOL_BACKEND", "remote"),
        choices=["dry-run", "local", "remote"],
        help="Backend to exercise (default: $APEX_TOOL_BACKEND or 'remote').",
    )
    parser.add_argument(
        "--tool-service-url", dest="tool_service_url",
        default=os.environ.get("APEX_TOOL_SERVICE_URL"),
        metavar="URL",
        help="Base URL of the tool service (default: $APEX_TOOL_SERVICE_URL).",
    )
    parser.add_argument(
        "--tool", default="curl", metavar="TOOL",
        help="Allowlisted tool to invoke (default: curl).",
    )
    parser.add_argument(
        "--tool-arg", dest="tool_args", action="append", default=None, metavar="ARG",
        help="Argument to pass to --tool (repeatable; default: a single '--version').",
    )
    parser.add_argument(
        "--report-path", dest="report_path", default=None, metavar="PATH",
        help=(
            "If set, write a small, clearly-marked smoke-test JSON artifact "
            "to this path (e.g. /app/run_reports/compose_smoke.json). Never "
            "written unless explicitly requested."
        ),
    )
    return parser.parse_args(argv)


def _build_config(args: argparse.Namespace) -> ApexConfig:
    """Build an ``ApexConfig`` via the canonical ``from_cli_args`` factory.

    A minimal synthetic ``argparse.Namespace`` is constructed here — this
    module deliberately does not call the dataclass constructor directly,
    since the architecture scan restricting that construction path to
    ``apex_host/config.py`` and ``apex_host/eval/run_synthetic_machine.py``
    means every other entry point, this one included, must go through
    ``from_cli_args`` like ``main.py`` and ``run_htb_local.py`` already do.
    """
    ns = argparse.Namespace(
        target="compose-smoke-test",
        dry_run=args.dry_run,
        tool_backend=args.tool_backend,
        tool_service_url=args.tool_service_url,
    )
    return ApexConfig.from_cli_args(ns)


def _write_report(path: str, *, config: ApexConfig, result: Any, ok: bool, elapsed: float) -> None:
    payload = {
        "smoke_test": True,
        "smoke_test_module": "apex_host.eval.compose_smoke",
        "note": "Synthetic infrastructure connectivity check — not a real engagement report.",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dry_run": config.dry_run,
        "tool_backend": config.tool_backend,
        "tool_service_url": config.tool_service_url,
        "backend_used": result.backend,
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "error": result.error,
        "elapsed_seconds": round(elapsed, 3),
        "ok": ok,
    }
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"compose_smoke: report written to {path}")


async def run_smoke(args: argparse.Namespace) -> int:
    config = _build_config(args)
    tool = args.tool
    tool_args = args.tool_args if args.tool_args is not None else ["--version"]

    print(
        f"compose_smoke: dry_run={config.dry_run} tool_backend={config.tool_backend!r} "
        f"tool_service_url={config.tool_service_url!r} tool={tool!r} args={tool_args}"
    )

    backend = select_runtime_backend(config)
    start = time.monotonic()
    try:
        result = await backend.execute(tool, tool_args)
    finally:
        aclose = getattr(backend, "aclose", None)
        if aclose is not None:
            await aclose()
    elapsed = time.monotonic() - start

    print(
        f"compose_smoke: backend_used={result.backend!r} returncode={result.returncode} "
        f"timed_out={result.timed_out} dry_run={result.dry_run} error={result.error!r} "
        f"elapsed_seconds={elapsed:.3f}"
    )

    ok = result.returncode == 0 and not result.timed_out and result.error is None
    if not config.dry_run:
        ok = ok and bool(result.stdout.strip() or result.stderr.strip())

    if args.report_path:
        _write_report(args.report_path, config=config, result=result, ok=ok, elapsed=elapsed)

    if not ok:
        print("compose_smoke: FAILED", file=sys.stderr)
        return 1
    print("compose_smoke: OK")
    return 0


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    exit_code = asyncio.run(run_smoke(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
