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
flags or the equivalent environment variables (APEX_TARGET, APEX_MAX_TURNS,
APEX_DRY_RUN, ... — see docs/environment-configuration.md).  An explicit CLI
flag always overrides its environment-variable equivalent; no machine-specific
profiles, expected credential paths, or target-specific defaults exist in
this module or anywhere in the codebase.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time

from memfabric.types import SubgraphView

from apex_host.config import ApexConfig
from apex_host.config_env import EnvConfigError, load_env_file, merge_env_into_args, merge_log_level
from apex_host.eval.comparison import (
    comparison_input_from_json_export,
    comparison_input_from_report,
    compare_reports,
    comparison_to_json_dict,
    format_comparison_text,
)
from apex_host.eval.export_graph import export_ekg
from apex_host.eval.report import (
    build_report,
    format_text,
    write_report_json,
)
from apex_host.graph_state import ApexGraphState
from apex_host.orchestration.outcome import EngagementOutcome, exit_code_for
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
    parser.add_argument(
        "--target", required=False, default=None,
        help=(
            "HTB target IP/hostname. May be omitted if APEX_TARGET is set in "
            "the environment (a blank APEX_TARGET counts as unset) — an "
            "explicit --target always wins over APEX_TARGET. At least one "
            "of the two is required; neither has a default target."
        ),
    )
    parser.add_argument(
        "--payload-repo", default="./payloads",
        help="Path to the payload repo (RAG seed corpus)",
    )
    parser.add_argument(
        "--max-turns", type=int, default=None,
        help="Maximum engagement turns (default: 20, or $APEX_MAX_TURNS)",
    )
    dry = parser.add_mutually_exclusive_group()
    dry.add_argument(
        "--dry-run", dest="dry_run", action="store_true", default=None,
        help=(
            "Simulate tool execution; no real commands (default — matches "
            "$APEX_DRY_RUN when set to true; $APEX_DRY_RUN=false alone can "
            "never enable real execution, see docs/environment-configuration.md)"
        ),
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
        help="After the run, write EKG nodes+edges JSON to this file (default: $APEX_GRAPH_PATH)",
    )
    parser.add_argument(
        "--export-json", dest="export_json", metavar="PATH",
        help="After the run, write a full structured run-report JSON to this file (default: $APEX_REPORT_PATH)",
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
    # Infra Phase 4 — tool-execution backend selection.
    # No --tool-service-token flag exists on purpose: CLI arguments are
    # visible in shell history and `ps` output. Set the bearer token via the
    # APEX_TOOL_SERVICE_TOKEN environment variable instead, e.g.:
    #   export APEX_TOOL_SERVICE_TOKEN=... && python -m apex_host.eval.run_htb_local --tool-backend remote ...
    parser.add_argument(
        "--tool-backend", dest="tool_backend", default=None,
        choices=["dry-run", "local", "remote"], metavar="{dry-run,local,remote}",
        help=(
            "Tool-execution backend for generic (non-Telnet, non-browser) commands "
            "(default: local). Ignored whenever --dry-run is in effect: dry-run "
            "always uses the dry-run backend regardless of this flag. "
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
    raw_socket_group = parser.add_mutually_exclusive_group()
    raw_socket_group.add_argument(
        "--tool-backend-raw-socket-capable", dest="tool_backend_raw_socket_capable",
        action="store_true", default=None,
        help=(
            "Override the automatic backend-capability seam: force nmap to assume "
            "raw-socket privilege is available (default: auto-derived from --tool-backend; "
            "'remote' is assumed non-root, 'local'/'dry-run' are assumed raw-socket-capable)."
        ),
    )
    raw_socket_group.add_argument(
        "--no-tool-backend-raw-socket-capable", dest="tool_backend_raw_socket_capable",
        action="store_false",
        help=(
            "Override the automatic backend-capability seam: force nmap into TCP-connect "
            "mode (-sT) regardless of the selected --tool-backend."
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
        "--llm-required", dest="llm_required", action="store_true", default=None,
        help=(
            "Phase 1 (post-live-test debugging): when set together with --use-llm, "
            "a CONFIRMED PERMANENT LLM provider failure (missing key, invalid model, "
            "authentication failure, unsupported endpoint, malformed response) "
            "terminates the engagement immediately with outcome=llm_unavailable "
            "instead of silently continuing in deterministic-fallback mode for the "
            "rest of the run. Transient failures (timeout, rate limit, network "
            "error) never trigger this. Default: off — existing silent-fallback "
            "behavior is unchanged unless this flag is explicitly passed."
        ),
    )
    parser.add_argument(
        "--preflight", action="store_true",
        help="Check which allowed tools are in PATH then exit",
    )
    parser.add_argument(
        "--preflight-only", dest="preflight_only", action="store_true", default=False,
        help=(
            "Phase 25: run the full environment/policy/service readiness preflight "
            "(apex_host.eval.preflight — configuration, report directory, compiled "
            "knowledge, policy, LLM readiness, HTB profile, and — when tool_backend="
            "'remote' or a VPN service is configured — Kali health, one harmless "
            "smoke command, and VPN readiness) and exit. Never runs the engagement, "
            "never attempts exploitation, never submits a payload, never retrieves "
            "a flag. Distinct from --preflight (local allowed-tool binary check only)."
        ),
    )
    parser.add_argument(
        "--confirm-live", dest="confirm_live", action="store_true", default=False,
        help=(
            "Phase 25: required (in addition to --no-dry-run) to run a real, "
            "target-directed engagement. Cannot be satisfied by any environment "
            "variable — must be passed explicitly on every live invocation. Has no "
            "effect when dry_run is True (the default)."
        ),
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
    parser.add_argument(
        "--env-file", dest="env_file", default=None, metavar="PATH",
        help=(
            "Explicitly load a dotenv-format file (e.g. .env) before "
            "resolving $APEX_* environment values. Never loaded implicitly — "
            "omit this flag to use only real, exported environment variables."
        ),
    )
    # Phase 17 — benchmarking, HTB evaluation mode, and run comparison.
    # All three are purely additive reporting features: none of them change
    # engagement behavior, planner decisions, or task execution.
    parser.add_argument(
        "--htb-machine-name", dest="htb_machine_name", default=None, metavar="NAME",
        help=(
            "Operator-supplied HTB machine name. When set together with "
            "--htb-difficulty, the report gains an Evaluation Summary "
            "section. Never inferred from the target or EKG content."
        ),
    )
    parser.add_argument(
        "--htb-difficulty", dest="htb_difficulty", default=None, metavar="LEVEL",
        help="Operator-supplied HTB difficulty label (e.g. Easy, Medium).",
    )
    parser.add_argument(
        "--compare-with", dest="compare_with", default=None, metavar="PATH",
        help=(
            "Path to a previously-exported run-report JSON file "
            "(--export-json output from an earlier run) to deterministically "
            "compare this run against. Prints a Comparison Summary; use "
            "--export-comparison to also write it as JSON."
        ),
    )
    parser.add_argument(
        "--export-benchmark", dest="export_benchmark", metavar="PATH",
        help="After the run, write the standalone benchmark JSON to this file.",
    )
    parser.add_argument(
        "--export-comparison", dest="export_comparison", metavar="PATH",
        help="With --compare-with, write the comparison JSON to this file.",
    )
    # Phase 18 — user-flag objective and bounded verification. There is
    # deliberately NO flag that accepts an expected plaintext flag value.
    parser.add_argument(
        "--objective-type", dest="objective_type", default=None, metavar="TYPE",
        help=(
            "Engagement benchmark-success objective (default: user_flag — "
            "the only implemented objective, and the HTB benchmark default). "
            "A validated access_state alone is never treated as success; "
            "see docs/user-flag-objective.md."
        ),
    )
    parser.add_argument(
        "--user-flag-candidate-filename", dest="user_flag_candidate_filenames",
        action="append", default=[], metavar="NAME",
        help="Candidate user-flag filename (repeatable; default: user.txt).",
    )
    parser.add_argument(
        "--user-flag-candidate-root", dest="user_flag_candidate_roots",
        action="append", default=[], metavar="TEMPLATE",
        help=(
            "Candidate root directory template; '{username}' is substituted "
            "with the already-authenticated SSH username (repeatable; "
            "default: /home/{username})."
        ),
    )
    parser.add_argument(
        "--max-user-flag-attempts", dest="max_user_flag_attempts",
        type=int, default=None, metavar="N",
        help="Maximum bounded candidate paths attempted per engagement (default: 3).",
    )
    parser.add_argument(
        "--user-flag-max-output-bytes", dest="user_flag_max_output_bytes",
        type=int, default=None, metavar="N",
        help="Maximum bytes read per candidate before the verifier rejects it as oversized (default: 4096).",
    )
    parser.add_argument(
        "--user-flag-format-regex", dest="user_flag_verification_regex",
        default=None, metavar="REGEX",
        help=(
            "Override the verifier's expected flag-format regex (shape only "
            "— never a specific known flag value). Default: a generic "
            "bounded-token pattern."
        ),
    )
    parser.add_argument(
        "--user-flag-read-timeout", dest="user_flag_read_timeout_seconds",
        type=float, default=None, metavar="SECONDS",
        help=(
            "Outer defensive timeout ceiling (seconds) for one bounded "
            "user-flag candidate read, independent of the resolved access "
            "capability's own internal timeouts (default: 35.0)."
        ),
    )
    # Phase 20 — direct file-read access capability. Every field below
    # describes a FULLY FIXED, operator-supplied HTTP request shape for a
    # pre-validated file-read primitive that the operator has ALREADY
    # manually confirmed through authorized testing (an arbitrary file
    # read, an LFI, a path-traversal primitive, an authenticated
    # file-download endpoint, an XSS-assisted workflow that resolves to a
    # bounded file read, ...) — mirrors --username/--password's own trust
    # boundary exactly. None of these fields have any effect unless
    # --direct-file-read-attested is also passed.
    parser.add_argument(
        "--direct-file-read-attested", dest="direct_file_read_operator_attested",
        action="store_true", default=None,
        help=(
            "Explicit opt-in: the operator has already manually confirmed "
            "(through authorized testing) that the configured request shape "
            "reads files. Required for any of the other --direct-file-read-* "
            "flags to have any effect (default: False)."
        ),
    )
    parser.add_argument(
        "--direct-file-read-capability-type", dest="direct_file_read_capability_type",
        default=None, metavar="TYPE",
        choices=["arbitrary_file_read", "api_file_read", "web_command"],
        help=(
            "Capability classification: 'arbitrary_file_read', 'api_file_read', "
            "or 'web_command' (Phase 21 — same fixed request shape, but records "
            "that the endpoint executes a command rather than serving a file "
            "directly) (default: arbitrary_file_read)."
        ),
    )
    parser.add_argument(
        "--direct-file-read-origin", dest="direct_file_read_origin",
        default=None, metavar="SCHEME://HOST[:PORT]",
        help="Fixed, authorized origin — no path, no query, no userinfo.",
    )
    parser.add_argument(
        "--direct-file-read-endpoint-template", dest="direct_file_read_endpoint_template",
        default=None, metavar="TEMPLATE",
        help="Fixed path+query template with exactly one {path} placeholder, e.g. '/download.php?file={path}'.",
    )
    parser.add_argument(
        "--direct-file-read-method", dest="direct_file_read_method",
        default=None, metavar="METHOD", choices=["GET", "POST"],
        help="Fixed HTTP method for the request shape (default: GET).",
    )
    parser.add_argument(
        "--direct-file-read-header", dest="direct_file_read_header",
        action="append", default=None, metavar="NAME:VALUE",
        help="Fixed request header (repeatable), e.g. 'Cookie:session=abc123'. Never logged or persisted.",
    )
    parser.add_argument(
        "--direct-file-read-principal", dest="direct_file_read_principal",
        default=None, metavar="LABEL",
        help="Identity label this capability is attributed to (e.g. an application username).",
    )
    parser.add_argument(
        "--direct-file-read-max-bytes", dest="direct_file_read_max_response_bytes",
        type=int, default=None, metavar="N",
        help="Maximum bounded response size in bytes (default: 4096).",
    )
    parser.add_argument(
        "--direct-file-read-timeout", dest="direct_file_read_timeout_seconds",
        type=float, default=None, metavar="SECONDS",
        help="Bounded request timeout in seconds (default: 15.0).",
    )
    parser.add_argument(
        "--direct-file-read-allow-redirects", dest="direct_file_read_allow_redirects",
        action="store_true", default=None,
        help="Follow at most one same-origin redirect (default: disabled — be extremely conservative with redirects).",
    )
    parser.add_argument(
        "--bounded-command-attested", dest="bounded_command_operator_attested",
        action="store_true", default=None,
        help=(
            "Enable the bounded command-execution access capability (Phase 21). "
            "Asserts an already-established, operator-confirmed command-execution "
            "context (a local shell/session, or a non-web remote session) works. "
            "No flag anywhere accepts a command string, shell syntax, or payload — "
            "the one fixed command ever run is 'cat -- <candidate_path>'."
        ),
    )
    parser.add_argument(
        "--bounded-command-capability-type", dest="bounded_command_capability_type",
        default=None, metavar="TYPE", choices=["local_shell", "remote_command"],
        help=(
            "Capability classification: 'local_shell' or 'remote_command' "
            "(default: local_shell). 'web_command' is configured through "
            "--direct-file-read-* instead."
        ),
    )
    parser.add_argument(
        "--bounded-command-principal", dest="bounded_command_principal",
        default=None, metavar="LABEL",
        help="Identity label this capability is attributed to.",
    )
    parser.add_argument(
        "--bounded-command-timeout", dest="bounded_command_timeout_seconds",
        type=float, default=None, metavar="SECONDS",
        help="Bounded command-read timeout in seconds (default: 15.0).",
    )
    parser.add_argument(
        "--bounded-command-max-bytes", dest="bounded_command_max_output_bytes",
        type=int, default=None, metavar="N",
        help="Maximum bounded command output size in bytes (default: 4096).",
    )
    return parser.parse_args(argv)


async def _async_main(args: argparse.Namespace) -> int:
    """Run the engagement (or preflight) and return a deterministic CLI exit
    code (Phase 12C — see docs/engagement-outcomes.md "CLI exit codes").

    ``--preflight`` remains a distinct utility mode (not an engagement) and
    keeps its own plain 0/1 exit codes, unrelated to the outcome taxonomy.
    """
    try:
        config = ApexConfig.from_cli_args(args)
    except Exception as exc:  # noqa: BLE001 - any construction failure is a config error
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return exit_code_for(EngagementOutcome.configuration_failure)

    if args.preflight:
        from apex_host.tools.preflight import check_local_tools
        availability = check_local_tools(config)
        print(f"Preflight tool check — target={config.target!r}:")
        for tool, present in availability.items():
            print(f"  [{'OK    ' if present else 'MISSING'}] {tool}")
        missing = [t for t, ok in availability.items() if not ok]
        if missing:
            print(f"\n{len(missing)} tool(s) missing.")
            return 1
        print("\nAll allowed tools found.")
        return 0

    if getattr(args, "preflight_only", False):
        # Phase 25: the richer environment/policy/service readiness preflight
        # (apex_host.eval.preflight), distinct from --preflight above (local
        # allowed-tool binary check only). Never runs the engagement — this
        # branch always returns before run_engagement() is ever imported.
        from apex_host.eval.preflight import PreflightResult, run_local_checks, run_vpn_checks

        checks = run_local_checks(
            config, default_report_dir=(os.path.dirname(args.export_json) if args.export_json else None) or ".",
            report_path=args.export_json, graph_path=args.export_graph,
            policy_required=not config.dry_run,
        )
        if config.tool_backend == "remote":
            from apex_host.eval.preflight import check_remote_smoke, check_tool_service_health
            checks.append(await check_tool_service_health(config.tool_service_url))
            checks.append(await check_remote_smoke(config))
        checks.extend(await run_vpn_checks(config))
        result = PreflightResult(checks)
        print(result.format_text())
        return 0 if result.passed else 1

    if not config.dry_run:
        # Phase 25: the ONE centralized live-run safety interlock — see
        # apex_host.eval.live_interlock's own module docstring. Live
        # execution must never be reachable from this entrypoint without
        # every one of its independent confirmations passing. Never
        # consulted for dry_run=True (the default) — dry-run behavior is
        # completely unaffected by this block's existence.
        from apex_host.eval.live_interlock import evaluate_live_interlock

        interlock = await evaluate_live_interlock(
            config, confirmed=getattr(args, "confirm_live", False),
            default_report_dir=(os.path.dirname(args.export_json) if args.export_json else None) or ".",
            report_path=args.export_json, graph_path=args.export_graph,
        )
        print(interlock.format_text())
        if not interlock.permitted:
            return exit_code_for(EngagementOutcome.configuration_failure)

    # Phase 17: wall-clock runtime measurement — the ONLY way to know how
    # long an engagement actually took (ApexGraphState tracks turn counts,
    # never real elapsed time — see apex_host/eval/benchmark.py module
    # docstring "Why timing is an external input").
    engagement_start = time.monotonic()
    try:
        runtime, final_state, seed_results = await run_engagement(config)
    except Exception as exc:  # noqa: BLE001 - surface as a deterministic operational-failure exit code
        logger.error("engagement failed to run: %s", exc)
        print(f"error: engagement failed: {exc}", file=sys.stderr)
        return exit_code_for(EngagementOutcome.internal_error)
    total_runtime_seconds = time.monotonic() - engagement_start

    try:
        subgraph = await runtime.api.get_subgraph(f"host:{config.target}", depth=10)

        # Derive policy_source for the report (read from the loaded policy).
        try:
            from apex_host.policy.policy_loader import load_policy
            policy = load_policy(config)
            policy_source = policy.policy_source
        except Exception:  # noqa: BLE001
            policy_source = "unknown"

        llm_budget = runtime.last_budget.to_dict() if runtime.last_budget is not None else None
        # Phase 17: measure report-build+format time on a throwaway first pass,
        # then rebuild once more so the printed/exported report itself reports
        # an accurate report_generation_seconds. Both build_report() calls are
        # pure (no I/O, no engagement re-run) — the cost of the extra pass is
        # negligible relative to the engagement itself.
        report_start = time.monotonic()
        _timing_report = build_report(
            final_state, subgraph, config,
            seed_results=seed_results,
            policy_source=policy_source,
            llm_budget=llm_budget,
            total_runtime_seconds=total_runtime_seconds,
            htb_machine_name=args.htb_machine_name,
            htb_difficulty=args.htb_difficulty,
        )
        format_text(_timing_report)
        report_generation_seconds = time.monotonic() - report_start

        report = build_report(
            final_state, subgraph, config,
            seed_results=seed_results,
            policy_source=policy_source,
            llm_budget=llm_budget,
            total_runtime_seconds=total_runtime_seconds,
            report_generation_seconds=report_generation_seconds,
            htb_machine_name=args.htb_machine_name,
            htb_difficulty=args.htb_difficulty,
        )
        print(format_text(report))

        if args.compare_with:
            try:
                with open(args.compare_with, encoding="utf-8") as fh:
                    baseline_json = json.load(fh)
                baseline_input = comparison_input_from_json_export(baseline_json)
                candidate_input = comparison_input_from_report(report)
                comparison = compare_reports(baseline_input, candidate_input)
                print("\n" + format_comparison_text(comparison))
                if args.export_comparison:
                    with open(args.export_comparison, "w", encoding="utf-8") as fh:
                        json.dump(comparison_to_json_dict(comparison), fh, indent=2, default=str)
                    print(f"Comparison exported to {args.export_comparison}")
            except Exception as exc:  # noqa: BLE001 - comparison is advisory, never fatal
                logger.warning("run comparison failed (non-fatal): %s", exc)
                print(f"warning: could not compare with {args.compare_with!r}: {exc}", file=sys.stderr)

        if args.export_benchmark:
            from apex_host.eval.benchmark import benchmark_to_json_dict, compute_benchmark
            bench = compute_benchmark(
                report,
                total_runtime_seconds=report.benchmark_total_runtime_seconds,
                report_generation_seconds=report.benchmark_report_generation_seconds,
                task_latency_log=report.task_latency_log,
            )
            with open(args.export_benchmark, "w", encoding="utf-8") as fh:
                json.dump(benchmark_to_json_dict(bench), fh, indent=2, default=str)
            print(f"Benchmark exported to {args.export_benchmark}")

        if args.export_graph:
            from apex_host.eval.export_graph import write_json
            ekg_data = await export_ekg(runtime.api, f"host:{config.target}")
            write_json(ekg_data, args.export_graph)
            print(f"EKG exported to {args.export_graph}")

        if args.export_json:
            write_report_json(report, args.export_json)
            print(f"Run report exported to {args.export_json}")

        try:
            resolved_outcome = EngagementOutcome(report.outcome) if report.outcome else EngagementOutcome.internal_error
        except ValueError:
            resolved_outcome = EngagementOutcome.internal_error
        return exit_code_for(resolved_outcome)
    finally:
        await runtime.aclose()


def main(argv: list[str] | None = None) -> None:
    raw_args = parse_args(argv)
    # Single, explicit merge point: environment values fill in whichever CLI
    # flags were left at their argparse `default=None` (i.e. not passed).
    # An explicit CLI flag always wins; see apex_host/config_env.py's own
    # docstring for the full precedence contract, including the dry_run and
    # target special cases.
    try:
        env = None
        if raw_args.env_file:
            env = {**load_env_file(raw_args.env_file), **os.environ}
        args = merge_env_into_args(raw_args, env)
    except EnvConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(exit_code_for(EngagementOutcome.configuration_failure))

    log_level_name = merge_log_level(args.verbose)
    effective_level = getattr(logging, log_level_name) if log_level_name else logging.WARNING
    logging.basicConfig(level=effective_level)
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
    try:
        exit_code = asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        print("\nengagement cancelled", file=sys.stderr)
        sys.exit(exit_code_for(EngagementOutcome.cancelled))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
