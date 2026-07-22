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
from apex_host.orchestration.outcome import EngagementOutcome, exit_code_for
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
    # Phase 18 — user-flag objective and bounded verification. There is
    # deliberately NO flag that accepts an expected plaintext flag value.
    parser.add_argument(
        "--objective-type", dest="objective_type", default=None, metavar="TYPE",
        help=(
            "Engagement benchmark-success objective (default: user_flag — "
            "the only implemented objective). A validated access_state "
            "alone is never treated as success; see docs/user-flag-objective.md."
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


async def run(args: argparse.Namespace) -> int:
    """Run the engagement (or preflight) and return a deterministic CLI exit
    code (Phase 12C — see docs/engagement-outcomes.md "CLI exit codes")."""
    try:
        config = ApexConfig.from_cli_args(args)
    except Exception as exc:  # noqa: BLE001 - any construction failure is a config error
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return exit_code_for(EngagementOutcome.configuration_failure)

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
            return 1
        print("\nAll allowed tools found.")
        return 0

    runtime = build_runtime(config)

    try:
        seed_results = await runtime.seed_all()
        logger.info("seeded knowledge: %s", seed_results)

        final_state = await runtime.run()
    except Exception as exc:  # noqa: BLE001 - surface as a deterministic operational-failure exit code
        logger.error("engagement failed to run: %s", exc)
        print(f"error: engagement failed: {exc}", file=sys.stderr)
        return exit_code_for(EngagementOutcome.internal_error)

    print(f"\nAPEX engagement complete: target={config.target} dry_run={config.dry_run}")
    print(f"turns={final_state['turn_count']} final_phase={final_state['phase']}")
    print(f"outcome={final_state.get('outcome') or 'unknown'} termination_phase={final_state.get('termination_phase') or ''}")
    print(f"findings ({len(final_state['findings'])}):")
    pprint.pprint(final_state["findings"])

    try:
        raw_outcome = final_state.get("outcome")
        resolved_outcome = EngagementOutcome(raw_outcome) if raw_outcome else EngagementOutcome.internal_error
    except ValueError:
        resolved_outcome = EngagementOutcome.internal_error
    return exit_code_for(resolved_outcome)


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
        sys.exit(exit_code_for(EngagementOutcome.configuration_failure))

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
    try:
        exit_code = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nengagement cancelled", file=sys.stderr)
        sys.exit(exit_code_for(EngagementOutcome.cancelled))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
