# config.py
# Typed configuration dataclass for the APEX host application, including target, allowed tools, dry-run flag, and turn limits.
"""Typed configuration for the APEX host application."""
from __future__ import annotations

from dataclasses import dataclass, field


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
