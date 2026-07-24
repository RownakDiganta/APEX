# container_entrypoint.py
# The APEX container's ENTRYPOINT — parses mode/configuration, runs preflight, and only then dispatches to the selected safe or (explicitly confirmed) live command.
"""APEX container entrypoint.

    python -m apex_host.container_entrypoint check
    python -m apex_host.container_entrypoint smoke
    python -m apex_host.container_entrypoint dry-run --target 10.10.10.14
    python -m apex_host.container_entrypoint run --target 10.10.10.14 --no-dry-run --confirm-live
    python -m apex_host.container_entrypoint exec -- python -m apex_host.main --help

Startup sequence (every mode except ``exec``, which bypasses all of this by
design — see its own section below):

    parse environment + CLI configuration
        -> print redacted configuration summary
        -> verify report directory
        -> verify compiled knowledge (when configured)
        -> verify policy file (when configured, or required by mode)
        -> [smoke/run only] verify Kali tool-service health
        -> [smoke/run only] one harmless remote-tool smoke command
        -> only on success: execute the selected command

This module never imports or constructs the engagement graph
(``apex_host.graph``/``apex_host.orchestration``) for ``check``/``smoke`` —
those two modes only ever import ``apex_host.eval.preflight`` and
``apex_host.tools.backend``. ``dry-run``/``run`` import
``apex_host.eval.run_htb_local.run_engagement`` lazily, inside their own
handler functions, so a plain ``check``/``smoke`` invocation never pays the
cost (or risk) of loading the full orchestration stack.

**Safety invariants preserved exactly, not reimplemented:**

- ``dry_run`` still defaults to ``True`` and still can never be flipped to
  ``False`` by an environment variable alone (CLAUDE.md §13.5,
  ``apex_host.config_env.resolve_dry_run``) — this module never bypasses
  that resolution.
- ``run`` mode additionally requires the explicit ``--confirm-live`` CLI
  flag (never an environment-variable equivalent — see
  ``check_live_confirmation``'s own docstring for why) on top of
  ``dry_run=False`` already being resolved through the normal precedence.
- No mode has a default target; ``check``/``smoke`` never require one at
  all (``apex_host.config_env.CONFIG_CHECK_TARGET_PLACEHOLDER``).
- No secret is ever printed — every mode's configuration summary goes
  through the same ``ApexConfig.to_safe_dict()``/presence-only redaction
  ``apex_host.eval.check_config`` already uses.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from typing import Any, Coroutine

from apex_host.config import ApexConfig
from apex_host.config_env import (
    EnvConfigError,
    load_apex_config_from_env,
    load_env_file,
    merge_log_level,
)
from apex_host.eval.live_interlock import evaluate_live_interlock
from apex_host.eval.preflight import (
    PreflightResult,
    run_local_checks,
    run_smoke_checks,
)

_DEFAULT_REPORT_DIR = "/app/run_reports"


# ---------------------------------------------------------------------------
# Shared argument groups
# ---------------------------------------------------------------------------

def _add_common_config_flags(parser: argparse.ArgumentParser) -> None:
    """Flags shared by every mode except ``exec``. All use ``default=None``
    so ``apex_host.config_env.merge_env_into_args`` can fill them from the
    environment without a concrete CLI default masking it."""
    parser.add_argument("--knowledge-root", dest="knowledge_root", default=None, metavar="DIR")
    # Phase 4 (post-live-test debugging) — persistent, incremental
    # knowledge-initialization cache. --knowledge-cache-path should point at
    # the mounted apex-knowledge-cache volume (/app/knowledge_cache in the
    # apex image — see compose.yaml) so cache state survives container
    # recreation. default=None lets APEX_KNOWLEDGE_CACHE_PATH fill it via
    # merge_env_into_args, matching every other flag in this function.
    parser.add_argument("--knowledge-cache-path", dest="knowledge_cache_path", default=None, metavar="DIR")
    parser.add_argument(
        "--no-knowledge-cache", dest="no_knowledge_cache", action="store_true", default=False,
    )
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
    parser.add_argument("--max-turns", dest="max_turns", type=int, default=None, metavar="N")
    parser.add_argument("--export-json", dest="export_json", default=None, metavar="PATH")
    parser.add_argument("--export-graph", dest="export_graph", default=None, metavar="PATH")
    parser.add_argument(
        "--report-dir", dest="report_dir", default=_DEFAULT_REPORT_DIR, metavar="DIR",
        help=f"Default report output directory to verify writable (default: {_DEFAULT_REPORT_DIR}).",
    )
    parser.add_argument(
        "--env-file", dest="env_file", default=None, metavar="PATH",
        help="Explicitly load a dotenv-format file before resolving environment values (never automatic).",
    )
    # Infra Phase 10 — HTB VPN readiness. All default=None so the generic
    # env merge (apex_host.config_env.merge_env_into_args) can fill them;
    # every mode is unaffected when none of these are set (the default,
    # non-htb-profile case) — see apex_host/eval/preflight.py::run_vpn_checks.
    parser.add_argument(
        "--vpn-service-url", dest="vpn_service_url", default=None, metavar="URL",
        help="Base URL of the VPN container's readiness server, e.g. http://vpn:8090 (htb Compose profile only).",
    )
    parser.add_argument(
        "--vpn-health-timeout", dest="vpn_health_timeout", type=float, default=None, metavar="SECS",
    )
    parser.add_argument(
        "--htb-route-cidr", dest="htb_route_cidr", default=None, metavar="CIDR",
        help="Expected HTB private route (default: 10.129.0.0/16) — compared against what the VPN service reports.",
    )
    parser.add_argument(
        "--htb-ovpn-path", dest="htb_ovpn_path", default=None, metavar="PATH",
        help="Host-side visibility only — path to the .ovpn profile (existence/readability checked, never opened for content).",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", default=False)
    parser.add_argument("-v", "--verbose", action="store_true", default=False)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apex_host.container_entrypoint",
        description=(
            "APEX container entrypoint: verifies environment/configuration/"
            "knowledge/policy/connectivity before running any operational "
            "command. Never starts a live engagement by default."
        ),
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    check_p = sub.add_parser("check", help="Local-only configuration/knowledge/policy validation. No target, no network.")
    check_p.add_argument("--target", default=None, help="Optional — falls back to $APEX_TARGET, then a synthetic placeholder.")
    _add_common_config_flags(check_p)

    smoke_p = sub.add_parser("smoke", help="Everything in 'check', plus Kali health + one harmless remote-tool command.")
    smoke_p.add_argument("--target", default=None)
    _add_common_config_flags(smoke_p)

    dry_p = sub.add_parser("dry-run", help="Run a full dry-run engagement (forces dry_run=True; never contacts Kali).")
    dry_p.add_argument("--target", default=None, help="Required (or $APEX_TARGET).")
    dry_p.add_argument("--payload-repo", dest="payload_repo", default="./payloads")
    dry_p.add_argument("--username", dest="username", action="append", default=[])
    dry_p.add_argument("--password", dest="password", action="append", default=[])
    _add_common_config_flags(dry_p)

    run_p = sub.add_parser("run", help="Live engagement. Requires --no-dry-run and --confirm-live.")
    run_p.add_argument("--target", default=None, help="Required (or $APEX_TARGET).")
    run_p.add_argument("--payload-repo", dest="payload_repo", default="./payloads")
    run_p.add_argument("--username", dest="username", action="append", default=[])
    run_p.add_argument("--password", dest="password", action="append", default=[])
    live_dry = run_p.add_mutually_exclusive_group()
    live_dry.add_argument("--dry-run", dest="dry_run", action="store_true", default=None)
    live_dry.add_argument("--no-dry-run", dest="dry_run", action="store_false")
    run_p.add_argument(
        "--confirm-live", dest="confirm_live", action="store_true", default=False,
        help="Required. Cannot be satisfied by any environment variable — must be passed explicitly on every invocation.",
    )
    _add_common_config_flags(run_p)

    exec_p = sub.add_parser(
        "exec",
        help="Advanced: run an arbitrary command after basic setup, via argv-list os.execvp (no shell).",
    )
    exec_p.add_argument("command", nargs=argparse.REMAINDER, help="Command and arguments to exec, e.g. -- python -m apex_host.main --help")

    return parser


# ---------------------------------------------------------------------------
# Configuration construction
# ---------------------------------------------------------------------------

def _resolve_env(args: argparse.Namespace) -> dict[str, str] | None:
    if not getattr(args, "env_file", None):
        return None
    return {**load_env_file(args.env_file), **os.environ}


def _build_config(args: argparse.Namespace, *, require_target: bool, force_dry_run: bool | None = None) -> ApexConfig:
    if force_dry_run is not None:
        args.dry_run = force_dry_run
    env = _resolve_env(args)
    return load_apex_config_from_env(args, env, require_target=require_target)


def _print_config_summary(config: ApexConfig) -> None:
    safe = config.to_safe_dict()
    print("APEX configuration summary (redacted):")
    for key in (
        "target", "dry_run", "max_turns", "tool_backend", "tool_service_url",
        "tool_service_timeout_seconds", "use_llm", "llm_provider",
        "knowledge_root", "policy_file",
    ):
        print(f"  {key}: {safe[key]!r}")
    token_state = "present" if config.tool_service_token or os.environ.get("APEX_TOOL_SERVICE_TOKEN") else "absent"
    openai_state = "present" if os.environ.get("OPENAI_API_KEY") else "absent"
    print(f"  tool_service_token: {token_state} (never displayed)")
    print(f"  OPENAI_API_KEY: {openai_state} (never displayed)")


def _emit_result(result: PreflightResult, *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(result.format_text())


# ---------------------------------------------------------------------------
# Mode handlers
# ---------------------------------------------------------------------------

async def _handle_check(args: argparse.Namespace) -> int:
    try:
        config = _build_config(args, require_target=False)
    except EnvConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_config_summary(config)
    checks = run_local_checks(
        config, default_report_dir=args.report_dir,
        report_path=args.export_json, graph_path=args.export_graph,
    )
    result = PreflightResult(checks)
    _emit_result(result, json_output=args.json_output)
    return 0 if result.passed else 1


async def _handle_smoke(args: argparse.Namespace) -> int:
    """``smoke`` always attempts a real connectivity check — unlike the
    engagement-facing modes, ``dry_run`` is forced ``False`` unconditionally
    here (no CLI flag, no ``APEX_DRY_RUN`` involvement) rather than left to
    the normal CLI>env>default resolution.

    This does **not** weaken CLAUDE.md §13.5's dry-run safety invariant:
    that invariant protects against *arbitrary, target-directed engagement
    command execution*. Smoke mode has no target, no user/environment-
    controllable tool or arguments — it always runs exactly one hardcoded,
    harmless, allowlisted command (``curl --version``, see
    ``apex_host/eval/preflight.py::check_remote_smoke``'s own defaults),
    the same command Infra Phase 7/8's own ``apex_host.eval.compose_smoke
    --no-dry-run`` was already established as safe to run by default in
    this exact role. See ``docs/container-entrypoint.md`` "Smoke mode" for
    the full rationale.
    """
    try:
        config = _build_config(args, require_target=False, force_dry_run=False)
    except EnvConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_config_summary(config)
    result = await run_smoke_checks(
        config, default_report_dir=args.report_dir,
        report_path=args.export_json, graph_path=args.export_graph,
    )
    _emit_result(result, json_output=args.json_output)
    return 0 if result.passed else 1


async def _run_engagement_and_report(config: ApexConfig, args: argparse.Namespace) -> int:
    """Shared dispatch for ``dry-run`` and ``run`` — both are just an
    ``ApexConfig`` with a different ``dry_run``/confirmation gate; the
    actual engagement pipeline is identical, and lives entirely in
    ``apex_host.eval.run_htb_local`` (imported lazily here, never for
    ``check``/``smoke``, per this module's own docstring)."""
    from apex_host.eval.export_graph import export_ekg, write_json
    from apex_host.eval.report import build_report, format_text, write_report_json
    from apex_host.eval.run_htb_local import run_engagement
    from apex_host.policy.policy_loader import load_policy

    runtime, final_state, seed_results = await run_engagement(config)
    subgraph = await runtime.api.get_subgraph(f"host:{config.target}", depth=10)
    try:
        policy_source = load_policy(config).policy_source
    except Exception:  # noqa: BLE001 - report generation must never crash on this
        policy_source = "unknown"
    llm_budget = runtime.last_budget.to_dict() if runtime.last_budget is not None else None
    report = build_report(
        final_state, subgraph, config,
        seed_results=seed_results, policy_source=policy_source, llm_budget=llm_budget,
    )
    print(format_text(report))

    if args.export_graph:
        ekg_data = await export_ekg(runtime.api, f"host:{config.target}")
        write_json(ekg_data, args.export_graph)
        print(f"EKG exported to {args.export_graph}")
    if args.export_json:
        write_report_json(report, args.export_json)
        print(f"Run report exported to {args.export_json}")
    return 0


async def _handle_dry_run(args: argparse.Namespace) -> int:
    try:
        config = _build_config(args, require_target=True, force_dry_run=True)
    except EnvConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_config_summary(config)
    checks = run_local_checks(
        config, default_report_dir=args.report_dir,
        report_path=args.export_json, graph_path=args.export_graph,
    )
    result = PreflightResult(checks)
    _emit_result(result, json_output=args.json_output)
    if not result.passed:
        return 1
    return await _run_engagement_and_report(config, args)


async def _handle_run(args: argparse.Namespace) -> int:
    """Phase 25: dispatches through the ONE centralized live-run safety
    interlock (``apex_host.eval.live_interlock.evaluate_live_interlock``)
    rather than this function's own ad-hoc confirmation + preflight
    sequence — ``apex_host.eval.run_htb_local``'s live-mode gate uses the
    exact same function, so the two entrypoints can never drift apart on
    what "may a live engagement start?" means.
    """
    try:
        config = _build_config(args, require_target=True)
    except EnvConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_config_summary(config)

    interlock = await evaluate_live_interlock(
        config, confirmed=args.confirm_live, default_report_dir=args.report_dir,
        report_path=args.export_json, graph_path=args.export_graph,
    )
    if args.json_output:
        print(json.dumps(interlock.to_dict(), indent=2, sort_keys=True))
    else:
        print(interlock.format_text())
    if not interlock.permitted:
        return 1
    return await _run_engagement_and_report(config, args)


def _handle_exec(args: argparse.Namespace) -> int:
    """Run an arbitrary command via argv-list ``os.execvp`` — process
    replacement, never a shell, never a reinterpreted string. This
    intentionally bypasses the APEX engagement workflow (no preflight, no
    configuration parsing) but not container OS permissions: the exec'd
    process still runs as the container's own non-root user, with the same
    filesystem/network access any other process in this container has.

    ``os.execvp`` replaces the current process image entirely, so signals
    sent to this container's PID 1 are delivered directly to the new
    program — no forwarding logic is needed or possible once this call
    succeeds (there is no Python process left to forward anything).
    """
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("error: exec requires a command, e.g. -- python -m apex_host.main --help", file=sys.stderr)
        return 2
    os.execvp(command[0], command)  # noqa: S606 - argv-list, no shell, documented intentional use
    return 127  # unreachable if execvp succeeds; kept for type-checker completeness


# ---------------------------------------------------------------------------
# Signal-aware async dispatch (check/smoke/dry-run/run)
# ---------------------------------------------------------------------------

async def _run_with_signal_handling(coro: "Coroutine[Any, Any, int]") -> int:
    """Run *coro* to completion, cancelling it cleanly if SIGTERM arrives —
    the container orchestrator's normal stop signal — rather than leaving
    the default disposition (which would kill the interpreter mid-await
    with no chance for the tool backend's own ``aclose()`` cleanup to run).
    """
    loop = asyncio.get_running_loop()
    task: "asyncio.Task[int]" = asyncio.ensure_future(coro)

    def _on_sigterm() -> None:
        task.cancel()

    try:
        loop.add_signal_handler(signal.SIGTERM, _on_sigterm)
    except NotImplementedError:
        pass  # platforms without add_signal_handler (e.g. some non-POSIX) — best effort only

    try:
        return await task
    except asyncio.CancelledError:
        print("entrypoint: terminated by signal", file=sys.stderr)
        return 143  # 128 + SIGTERM(15), the conventional shell exit code


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_MODE_HANDLERS = {
    "check": _handle_check,
    "smoke": _handle_smoke,
    "dry-run": _handle_dry_run,
    "run": _handle_run,
}


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    if args.mode == "exec":
        sys.exit(_handle_exec(args))

    log_level_name = merge_log_level(getattr(args, "verbose", False))
    effective_level = getattr(logging, log_level_name) if log_level_name else logging.WARNING
    logging.basicConfig(level=effective_level)

    handler = _MODE_HANDLERS[args.mode]
    exit_code = asyncio.run(_run_with_signal_handling(handler(args)))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
