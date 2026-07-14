# config.py
# Typed configuration dataclass for the APEX host application, including target, allowed tools, dry-run flag, and turn limits.
"""Typed configuration for the APEX host application."""
from __future__ import annotations

from dataclasses import dataclass, field, fields as _dc_fields

from apex_host.security.redaction import REDACTED_PLACEHOLDER as _REDACTED


@dataclass(slots=True)
class ApexConfig:
    target: str
    payload_repo_path: str = "./payloads"
    max_command_seconds: int = 30
    allowed_tools: list[str] = field(
        default_factory=lambda: ["nmap", "curl", "python3", "nc"]
    )
    # Mac-native tools: nmap (Homebrew), curl (built-in), python3 (built-in), nc (built-in).
    # Optional tools (ffuf, gobuster, searchsploit, netcat) must be installed separately
    # and added to this list explicitly.
    planner_model: str = "openai/gpt-5.5"
    executor_model: str = "openai/gpt-5.5"
    parser_model: str = "openai/gpt-5.5"
    dry_run: bool = True
    """Safety default. Real command execution requires the host to set this
    to False explicitly — see apex_host/tools/runner.py."""
    max_turns: int = 20
    max_concurrency: int = 2
    max_retries: int = 1
    # Safe web probing — wordlist-based discovery is opt-in.
    # Set web_wordlist_path to enable ffuf/gobuster directory discovery.
    # Without a wordlist, WebPlanner emits only bounded curl probes (HEAD + body).
    web_wordlist_path: str | None = None
    max_web_paths: int = 50
    # Bounded access validation — explicit credentials only, no looping.
    # Empty by default: no login attempts are made unless the operator
    # supplies credentials via --username / --password CLI flags.
    username_candidates: list[str] = field(default_factory=list)
    password_candidates: list[str] = field(default_factory=list)
    max_access_attempts: int = 1
    # Slot-extraction patterns for the Reflector's skill generalizer.
    # These are the cybersecurity-specific patterns that belong in the host app,
    # NOT in memfabric's substrate.  Supplied to Config.slot_patterns when
    # constructing the memfabric Config for this engagement.
    slot_patterns: list[str] = field(
        default_factory=lambda: [
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # IPv4 address
            r"\d{4,6}",                                  # port / numeric service ID
        ]
    )
    # LLM planning layer — confidence gate and retry policy.
    # PlanningEngine falls back to the deterministic planner when the LLM
    # reports confidence below this threshold or after max_planning_retries
    # failed/rejected attempts.
    planning_confidence_threshold: float = 0.4
    max_planning_retries: int = 1
    # Repair layer — how many times a failed task may be repaired per turn.
    # RepairEngine is a no-op when dry_run=True (the default) or when no LLM
    # is configured (FakeModelRouter), so this counter is only relevant in
    # live mode with a real model router.
    max_repair_attempts: int = 1
    # LLM runtime wiring — controlled by --use-llm CLI flag.
    # When use_llm=False (the default), FakeModelRouter is used and all planners
    # run in fully-deterministic mode with no API calls or network traffic.
    # When use_llm=True, OpenAIModelRouter is constructed; llm_provider selects
    # the implementation ("openai" is the only real provider today).
    # llm_base_url overrides OPENAI_BASE_URL env var (useful for OpenRouter).
    use_llm: bool = False
    llm_provider: str = "fake"
    llm_base_url: str | None = None
    # External knowledge base root and per-family overrides.
    # When knowledge_root is set, each family defaults to <knowledge_root>/<family>.
    # Per-family overrides take precedence over the derived default.
    # Set these via --knowledge-root / --policy-db-path / etc. CLI flags.
    # None means the corresponding knowledge family is not loaded at startup.
    knowledge_root: str | None = None
    policy_db_path: str | None = None
    methodology_db_path: str | None = None
    intel_db_path: str | None = None
    payload_db_path: str | None = None
    # PolicyAdvisor scope enforcement.
    # policy_enabled=True (the default) means every task is reviewed before
    # execution.  Disable only in integration tests that exercise the task
    # routing machinery without any policy checking.
    # policy_file is an optional explicit path to the policy YAML; when None
    # the loader searches the conventional locations (see policy_loader.py).
    # allow_password_lists and allow_sensitive_data_access default to False;
    # the operator must explicitly set them to True (e.g. via CLI flags).
    # require_policy_approval_for lists tool names that always trigger a
    # needs_human_review decision regardless of other rules.
    policy_enabled: bool = True
    policy_file: str | None = None
    allow_sensitive_data_access: bool = False
    allow_password_lists: bool = False
    require_policy_approval_for: list[str] = field(default_factory=list)
    # LLM call budget — controls how many real LLM calls are allowed per run.
    # FakeModelRouter (the default when use_llm=False) returns None for all
    # roles so these limits are never consulted in deterministic mode.
    # max_llm_calls_per_run: hard cap on total LLM calls across the entire run.
    # max_llm_calls_per_phase: hard cap per phase (recon, web, credential, …).
    # llm_request_timeout_seconds: per-call timeout forwarded to ChatOpenAI.
    # llm_stop_on_repeated_plan: skip LLM when context is unchanged since last
    #   call for the same phase (saves one API call per identical turn).
    max_llm_calls_per_run: int = 5
    max_llm_calls_per_phase: int = 2
    llm_request_timeout_seconds: float = 60.0
    llm_stop_on_repeated_plan: bool = True
    # Knowledge promotion strategy — controls how many Reflector passes are
    # run after the compiled knowledge corpus is staged at startup.
    #
    # "until_stable" (default): loop run_once() until no staged records remain
    #     or until safety limits are reached.  Required when the corpus is
    #     larger than reflector_max_promotions_per_run (100 by default).
    # "single_pass": one run_once() call only — legacy behaviour; leaves large
    #     corpora partially promoted.
    # "disabled": skip promotion entirely (test fixtures that don't need
    #     retrieval to work).
    knowledge_promotion_mode: str = "until_stable"
    # Maximum number of Reflector passes during the startup promotion loop.
    # At 100 records/pass, 1000 passes → up to 100,000 records.  Increase
    # only if your corpus is larger than knowledge_promotion_max_passes × 100.
    knowledge_promotion_max_passes: int = 1000
    # Optional hard cap on total records promoted during startup.  None = no
    # cap (promote everything that clears the quality gate).
    knowledge_promotion_max_records: int | None = None
    # Optional wall-clock timeout in seconds for the promotion loop.  None =
    # no timeout (loop until stable or max_passes reached).
    knowledge_promotion_timeout_seconds: float | None = None
    # Duplicate action detection — catches repeated identical fallback tasks.
    # When enabled, any task whose fingerprint (phase+tool+args+target) has been
    # seen >= duplicate_action_max_repeats times within the most recent
    # duplicate_action_window executions is skipped and logged to duplicate_actions.
    # Set duplicate_action_detection_enabled=False to disable entirely.
    duplicate_action_detection_enabled: bool = True
    duplicate_action_window: int = 5
    duplicate_action_max_repeats: int = 1
    # Promotion logging verbosity for -v runs.
    # False (default): per-record reflector DEBUG logs are suppressed even with -v;
    #   only interval progress summaries and the final count are shown.
    # True (--trace-records): per-record DEBUG logs are visible with -v, showing
    #   each promoted record ID.
    trace_knowledge_records: bool = False
    # ---------------------------------------------------------------------------
    # Phase 7 — Async timeout fields (P7-I03, P7-I05, P7-I10)
    # ---------------------------------------------------------------------------
    # subprocess_sigterm_grace_seconds: time to wait after SIGTERM before
    #   escalating to SIGKILL on command timeout or cancellation (A07/A08 fix).
    subprocess_sigterm_grace_seconds: float = 5.0
    # browser_launch_timeout_seconds: maximum time allowed for
    #   playwright.chromium.launch() before raising TimeoutError (A09 fix).
    browser_launch_timeout_seconds: float = 30.0
    # telnet_read_timeout_seconds: per-read timeout inside TelnetExecutor's
    #   banner-read loop.  The outer asyncio.wait_for still applies.
    telnet_read_timeout_seconds: float = 10.0
    # retrieval_channel_timeout_seconds: maximum time for a single retrieval
    #   channel (BM25, vector, graph) before it is skipped and an empty result
    #   is returned for that channel.
    retrieval_channel_timeout_seconds: float = 5.0
    # parser_timeout_seconds: maximum wall-clock time for a parser call.
    parser_timeout_seconds: float = 10.0
    # ---------------------------------------------------------------------------
    # Infra Phase 2/4 — tool-execution backend selection
    # (docs/tool-execution-architecture.md; docs/remote-tool-backend.md;
    #  apex_host/tools/backend.py; apex_host/tools/remote_backend.py)
    # ---------------------------------------------------------------------------
    # tool_backend selects which ToolBackend apex_host.tools.backend.select_tool_backend()
    # constructs; values are normalized (case/whitespace) at the point of
    # interpretation, not here.  As of Infra Phase 4, this field IS consumed
    # by the default construction path: apex_host.runtime.ApexRuntime.run()
    # and apex_host.orchestration.builder.build_apex_graph() (when no
    # explicit tool_backend= is injected) both call
    # apex_host.tools.backend.select_runtime_backend(config), which applies
    # one binding safety invariant on top of this field:
    #   dry_run=True  → ALWAYS DryRunToolBackend, regardless of this field.
    #   dry_run=False → the backend named by this field, exactly:
    #     "dry-run": DryRunToolBackend — never executes a process.
    #     "local":   LocalToolBackend — the trusted local-subprocess pathway
    #                (apex_host/tools/runner.py); still honors dry_run
    #                internally as a second, redundant safety layer.
    #     "remote":  RemoteToolBackend — a real async HTTP client for a
    #                Phase 3 apex_tool_service instance. Also refuses to
    #                contact the network if dry_run=True (defense in depth,
    #                in case this class is ever constructed and injected
    #                directly, bypassing select_runtime_backend).
    # "local" remains the default because it is what build_apex_graph() has
    # always used — this field's default does not change default runtime
    # behavior.  CLI: --tool-backend (apex_host/main.py, eval/run_htb_local.py).
    tool_backend: str = "local"
    # tool_service_url configures RemoteToolBackend's target. CLI:
    # --tool-service-url. No default (None) — RemoteToolBackend.__init__
    # raises ValueError if tool_backend="remote" is selected without one.
    tool_service_url: str | None = None
    # tool_service_token: NO CLI flag exists for this on purpose (CLI args
    # are visible in shell history and `ps`).  RemoteToolBackend reads this
    # field first, falling back to the APEX_TOOL_SERVICE_TOKEN environment
    # variable if empty — mirrors apex_host/llm/router.py::OpenAIModelRouter's
    # OPENAI_API_KEY precedent.  This field's own default ("") is never a
    # real credential.  This module (config.py) never reads environment
    # variables itself — enforced by test_arch_08_config_py_has_no_env_access.
    tool_service_token: str = ""
    # tool_service_timeout_seconds: overall request timeout budget for
    # RemoteToolBackend. CLI: --tool-service-timeout.
    tool_service_timeout_seconds: float = 120.0
    # Configuration schema version — increment when the config format changes in a
    # backward-incompatible way (new required fields, renamed fields, type changes).
    # Exposed via to_safe_dict() so consumers can detect incompatible changes.
    config_schema_version: str = "1"

    # ------------------------------------------------------------------
    # Safe serialisation and canonical CLI→config construction
    # ------------------------------------------------------------------

    def to_safe_dict(self) -> dict[str, object]:
        """Return all fields as a JSON-serialisable dict with sensitive values redacted.

        ``password_candidates`` entries are replaced with ``"[redacted]"``.
        ``tool_service_token`` is replaced with ``"[redacted]"`` when non-empty
        (RemoteToolBackend authentication token — contract only in this phase,
        but redacted defensively since it is credential-shaped).
        All other fields are returned verbatim — no other field stores a plaintext secret.
        """
        d: dict[str, object] = {f.name: getattr(self, f.name) for f in _dc_fields(self)}
        if self.password_candidates:
            d["password_candidates"] = [_REDACTED] * len(self.password_candidates)
        if self.tool_service_token:
            d["tool_service_token"] = _REDACTED
        return d

    @classmethod
    def from_cli_args(cls, args: object) -> "ApexConfig":
        """Canonical CLI→config factory used by main.py and eval/run_htb_local.py.

        Accepts an ``argparse.Namespace`` (or any attribute-holder).  This is the
        single place that maps CLI argument names to ``ApexConfig`` field names so
        that both entry points stay in sync without duplicating logic.

        Key invariant: when ``--llm-provider`` is absent (``args.llm_provider`` is
        ``None``), the ``ApexConfig`` field default of ``"fake"`` is preserved.
        The CLI must register that flag with ``default=None``, not ``"openai"``.
        """
        def _g(attr: str, default: object) -> object:
            v = getattr(args, attr, None)
            return default if v is None else v

        kwargs: dict[str, object] = {
            "target": getattr(args, "target"),
            "payload_repo_path": _g("payload_repo", "./payloads"),
            "max_turns": _g("max_turns", 20),
            "dry_run": bool(_g("dry_run", True)),
            "web_wordlist_path": _g("web_wordlist", None),
            "max_web_paths": _g("max_web_paths", 50),
            "username_candidates": list(getattr(args, "username", None) or []),
            "password_candidates": list(getattr(args, "password", None) or []),
            "max_access_attempts": _g("max_access_attempts", 1),
            "use_llm": bool(_g("use_llm", False)),
            # llm_provider: CLI None → field default "fake".
            # The CLI flag must use default=None (not "openai") so this fallback fires.
            "llm_provider": _g("llm_provider", "fake"),
            "llm_base_url": _g("llm_base_url", None),
            "knowledge_root": _g("knowledge_root", None),
            "policy_file": _g("policy_file", None),
            "llm_stop_on_repeated_plan": bool(_g("llm_stop_on_repeated_plan", True)),
            # Infra Phase 4 — tool-execution backend selection. Note there is
            # deliberately NO --tool-service-token CLI flag: the bearer token
            # is read from the APEX_TOOL_SERVICE_TOKEN environment variable
            # at the point RemoteToolBackend is constructed (never here —
            # this file has no environment-variable access, enforced by
            # test_arch_08_config_py_has_no_env_access), because CLI
            # arguments are visible in shell history and process listings
            # (`ps`) while environment variables set via `export` are not.
            "tool_backend": _g("tool_backend", "local"),
            "tool_service_url": _g("tool_service_url", None),
        }
        if getattr(args, "max_llm_calls", None) is not None:
            kwargs["max_llm_calls_per_run"] = int(getattr(args, "max_llm_calls"))
        if getattr(args, "max_llm_calls_per_phase", None) is not None:
            kwargs["max_llm_calls_per_phase"] = int(getattr(args, "max_llm_calls_per_phase"))
        if getattr(args, "llm_timeout", None) is not None:
            kwargs["llm_request_timeout_seconds"] = float(getattr(args, "llm_timeout"))
        if getattr(args, "tool_service_timeout", None) is not None:
            kwargs["tool_service_timeout_seconds"] = float(getattr(args, "tool_service_timeout"))
        llm_model = getattr(args, "llm_model", None)
        if llm_model:
            kwargs["planner_model"] = str(llm_model)
            kwargs["executor_model"] = str(llm_model)
            kwargs["parser_model"] = str(llm_model)
        if getattr(args, "trace_records", False):
            kwargs["trace_knowledge_records"] = True
        return cls(**kwargs)  # type: ignore[arg-type]
