# config.py
# Typed configuration dataclass for the APEX host application, including target, allowed tools, dry-run flag, and turn limits.
"""Typed configuration for the APEX host application."""
from __future__ import annotations

from dataclasses import dataclass, field, fields as _dc_fields
from os.path import basename as _basename

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
    # Phase 2 (post-live-test debugging) — canonical action fingerprint /
    # bounded-retry model. A task whose specific failure is classified as
    # retryable (apex_host.execution.dispositions.classify_retry — e.g. a
    # transient network error) may be resubmitted under the SAME action
    # fingerprint at most this many additional times before
    # TaskDispatcher forces it to TaskStatus.FAILED_TERMINAL (suppressing
    # further resubmission) regardless of the per-error retry
    # classification. Default 1 means "one bounded retry": the first
    # attempt plus one retry, then stop. Non-retryable failures (e.g. an
    # nmap raw-socket permission error) are never subject to this bound —
    # they are terminal on the FIRST attempt. See
    # apex_host/execution/registry.py::TaskRegistry.attempt_count and
    # docs/action-fingerprint.md.
    max_fingerprint_retries: int = 1
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
    # Phase 1 (post-live-test debugging) — explicit, configurable live-run
    # policy for COMPLETE provider failure. Defaults to False so existing
    # behavior (always fall back to deterministic planning, silently, on
    # any LLM issue) is completely unchanged unless an operator opts in.
    # When True AND use_llm is True: once a CONFIRMED PERMANENT provider
    # misconfiguration is observed (missing key, invalid model,
    # authentication failure, unsupported endpoint, malformed response —
    # apex_host.llm.errors.PERMANENT_LLM_ERROR_CATEGORIES), the engagement
    # terminates immediately with EngagementOutcome.llm_unavailable rather
    # than silently completing the rest of the run in deterministic
    # fallback mode while still claiming to be "LLM-guided". Transient
    # failures (timeout, rate limit, network error) never trigger this —
    # only a confirmed, non-retriable configuration problem does. Has no
    # effect when use_llm=False or llm_provider="fake" (no real provider
    # is ever contacted in either case, so no provider failure can occur).
    llm_required: bool = False
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
    # Phase 12B — bounded SSH/FTP credential-validation timeouts
    # (apex_host/agents/ssh_executor.py, apex_host/agents/ftp_executor.py;
    #  docs/credential-validation.md "Timeout behavior")
    # ---------------------------------------------------------------------------
    # Each pair bounds one phase of the single bounded login attempt: the
    # TCP connect, the authentication exchange, and the one fixed harmless
    # validation command/operation run afterward. All three are summed (plus
    # a small fixed margin) into one outer asyncio.wait_for ceiling inside
    # the executor as a second, independent safety net.
    ssh_connect_timeout_seconds: float = 10.0
    ssh_auth_timeout_seconds: float = 10.0
    ssh_command_timeout_seconds: float = 10.0
    ftp_connect_timeout_seconds: float = 10.0
    ftp_login_timeout_seconds: float = 10.0
    ftp_command_timeout_seconds: float = 10.0
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
    # tool_backend_raw_socket_capable: explicit override for
    # apex_host.tools.backend.backend_supports_raw_sockets() — the
    # capability seam ReconPlanner consults to decide whether nmap may use
    # a raw-socket scan mode (plain "-sV", implicitly SYN-scan) or must be
    # restricted to TCP-connect mode ("-sT"). None (the default) means
    # "derive automatically from tool_backend": tool_backend="remote"
    # (the Kali tool-service container, documented to run as a non-root
    # user with zero added Linux capabilities — docs/kali-container.md
    # §5/§14) derives to False; every other backend derives to True,
    # preserving the pre-existing scan behavior for "local"/"dry-run".
    # Set explicitly only when a specific deployment's real privilege
    # differs from that default assumption (e.g. a remote backend granted
    # NET_RAW, or a sandboxed local backend that is not root). CLI:
    # --tool-backend-raw-socket-capable / --no-tool-backend-raw-socket-capable.
    tool_backend_raw_socket_capable: bool | None = None
    # ---------------------------------------------------------------------------
    # Infra Phase 10 — HTB VPN readiness configuration
    # (docs/htb-vpn-container.md; docker/vpn/; apex_host/eval/preflight.py)
    # ---------------------------------------------------------------------------
    # vpn_service_url: base URL of the VPN container's own readiness HTTP
    # server (docker/vpn/readiness_server.py — GET /health, GET
    # /route-check). None (unset) means VPN preflight checks are skipped
    # entirely — the safe default for every non-HTB-profile invocation.
    # CLI: --vpn-service-url. Env: APEX_VPN_SERVICE_URL.
    vpn_service_url: str | None = None
    # vpn_health_timeout_seconds: bounded timeout for the GET /health call
    # above. CLI: --vpn-health-timeout. Env: APEX_VPN_HEALTH_TIMEOUT_SECONDS.
    vpn_health_timeout_seconds: float = 10.0
    # htb_route_cidr: the private route APEX expects the VPN tunnel to
    # install once connected — used only to compare against what the VPN
    # container's own readiness server reports (docker/vpn/tunnel_status.py);
    # never used to construct or inject a route directive anywhere.
    # HTB machine labs commonly use 10.129.0.0/16, but this is configurable
    # since not every HTB profile/region is guaranteed to match that exact
    # range. CLI: --htb-route-cidr. Env: APEX_HTB_ROUTE_CIDR.
    htb_route_cidr: str = "10.129.0.0/16"
    # htb_ovpn_path: the HOST filesystem path to the .ovpn profile — this
    # field exists purely for host-side, PRE-Compose visibility/validation
    # (apex_host/eval/preflight.py::check_htb_profile_configured checks
    # only that the file exists and is readable; it is NEVER opened for
    # its content). The apex container itself never reads this path at
    # runtime — the profile is mounted directly into the *vpn* container
    # by compose.htb.yaml, never into apex. Sensitive operational
    # configuration, not a credential — to_safe_dict() below shows only
    # the basename, never the full host path. Env: APEX_HTB_OVPN_PATH.
    # No CLI flag (mirrors tool_service_token's own "env-var only for a
    # sensitive path" precedent, though this is not itself a secret).
    htb_ovpn_path: str | None = None
    # ---------------------------------------------------------------------------
    # Phase 18 — user-flag objective and bounded verification
    # (apex_host/verification/user_flag.py; apex_host/agents/user_flag_executor.py;
    #  docs/user-flag-objective.md)
    # ---------------------------------------------------------------------------
    # objective_type selects the engagement's benchmark success condition.
    # "user_flag" is the only implemented objective and is the default for
    # BOTH the general library/runtime and the HTB benchmark runner — Ali's
    # confirmed benchmark success definition ("success means verified
    # retrieval of the user flag") applies by default, not only when an
    # operator opts in. A validated access_state node is never independently
    # treated as success; see apex_host/orchestration/outcome.py.
    objective_type: str = "user_flag"
    # Small, documented, overrideable list of generic HTB user-flag filename
    # candidates. Never a machine-specific value (CLAUDE.md §13.8/§13.9).
    user_flag_candidate_filenames: list[str] = field(default_factory=lambda: ["user.txt"])
    # Bounded candidate root templates. "{username}" is substituted with the
    # already-authenticated SSH username (validated against a conservative
    # POSIX-username charset before substitution — see
    # apex_host/planners/objective_planner.py); a root containing
    # "{username}" is skipped defensively if the username fails that check.
    user_flag_candidate_roots: list[str] = field(default_factory=lambda: ["/home/{username}"])
    # Hard cap on distinct candidate paths attempted per engagement — bounds
    # the discovery surface; never an unrestricted recursive filesystem search.
    max_user_flag_attempts: int = 3
    # Per-read output cap in bytes — the verifier also independently rejects
    # oversized/multiline/malformed content regardless of this cap.
    user_flag_max_output_bytes: int = 4096
    # Optional override for the verifier's expected flag-format regex. None
    # (the default) uses apex_host.verification.user_flag.DEFAULT_FLAG_FORMAT_REGEX
    # — a generic, conservative bounded-token pattern, never a specific
    # machine's known flag value (CLAUDE.md §13.8/§13.9 — no exact expected
    # flag value may ever appear in source or configuration).
    user_flag_verification_regex: str | None = None
    # Access-capability refactor — outer defensive timeout ceiling for one
    # UserFlagExecutor.run() call, independent of whatever transport-
    # specific timeouts the resolved capability adapter applies internally
    # (e.g. SSHCapabilityAdapter's own ssh_connect_timeout_seconds /
    # ssh_auth_timeout_seconds / ssh_command_timeout_seconds). Belt-and-
    # suspenders only — never the primary bound.
    user_flag_read_timeout_seconds: float = 35.0

    # ---------------------------------------------------------------------------
    # Phase 20 — direct file-read access capability
    # (apex_host/runtime_registry.py::DirectFileReadCapabilityAdapter;
    #  apex_host/parsers/capability_parser.py::derive_direct_file_read_capability;
    #  docs/user-flag-objective.md §17)
    # ---------------------------------------------------------------------------
    # Every field below describes a FULLY FIXED, operator-supplied HTTP
    # request shape for a pre-validated file-read primitive (an arbitrary
    # file read, an LFI, a path-traversal primitive, an authenticated
    # file-download endpoint, ...) — mirrors --username/--password's own
    # trust boundary exactly: the operator asserts, out of band, that this
    # exact request shape already works; APEX never discovers, probes for,
    # or autonomously exploits it. NONE of these fields are ever
    # LLM-controlled, planner-controlled, or task-controlled — only the ONE
    # bounded candidate path substituted per read varies.
    #
    # `direct_file_read_operator_attested` is the explicit opt-in gate: with
    # the default `False`, none of the fields below have any effect — no
    # `access_capability` node is ever derived from them. This mirrors
    # `policy_enabled`'s own "safe unless explicitly configured" precedent.
    direct_file_read_operator_attested: bool = False
    # "arbitrary_file_read", "api_file_read", or "web_command" (Phase 21) —
    # all three are behaviorally identical at runtime (same adapter),
    # differing only in this metadata classification of the underlying
    # primitive (see AccessCapabilityType). "web_command" additionally
    # routes derivation through CapabilityParser.derive_command_capability
    # (command-evidence vocabulary) instead of
    # derive_direct_file_read_capability (file-read-evidence vocabulary) —
    # see apex_host/orchestration/capability_seed.py.
    direct_file_read_capability_type: str = "arbitrary_file_read"
    # scheme://host[:port] ONLY — no path, no query, no userinfo. Every
    # request (and every followed redirect) must resolve to exactly this
    # origin or it is rejected — see DirectFileReadCapabilityAdapter.
    direct_file_read_origin: str | None = None
    # A path+query template containing exactly one "{path}" placeholder,
    # e.g. "/download.php?file={path}" or "/files/{path}".
    direct_file_read_endpoint_template: str | None = None
    # "GET" or "POST" only — validated at adapter construction time.
    direct_file_read_method: str = "GET"
    # Fixed, operator-supplied headers (e.g. a pre-obtained session cookie
    # or bearer token VALUE) — runtime-only; never written to the EKG,
    # never included in any report, episode, or log line.
    direct_file_read_headers: dict[str, str] = field(default_factory=dict)
    # A label identifying who/what this capability is attributed to (e.g.
    # an application username, or a fixed operator-chosen tag like
    # "application" when no specific principal applies). Required —
    # mirrors derive_ssh_capability's own "no username, no node" guard.
    direct_file_read_principal: str = ""
    # Bounded response-size cap in bytes — enforced independently by the
    # adapter itself (never trusts the verifier's own cap alone).
    direct_file_read_max_response_bytes: int = 4096
    direct_file_read_timeout_seconds: float = 15.0
    # Default False — "be extremely conservative with redirects." When
    # True, at most one same-origin redirect is followed (see
    # DirectFileReadPrimitive.max_redirect_hops).
    direct_file_read_allow_redirects: bool = False
    # Confidence recorded on the derived access_capability node. Fixed and
    # conservative — never a specific known-flag value, never inferred from
    # the target or EKG content (CLAUDE.md §13.8/§13.9).
    direct_file_read_confidence: float = 0.7

    # ---------------------------------------------------------------------------
    # Phase 21 — bounded command-execution access capability
    # (apex_host/runtime_registry.py::BoundedCommandCapabilityAdapter;
    #  apex_host/parsers/capability_parser.py::derive_command_capability;
    #  docs/user-flag-objective.md §18)
    # ---------------------------------------------------------------------------
    # Mirrors --username/--password's and direct_file_read_*'s own trust
    # boundary exactly: the operator asserts, out of band, that a specific,
    # already-established command-execution context (a local shell/session,
    # a non-web remote session, ...) already works; APEX never discovers,
    # probes for, or autonomously establishes it. Deliberately NOT a
    # `--command`/`--exec`/`--shell-command`/`--payload` style field — there
    # is no field anywhere in this config that accepts a command string,
    # shell syntax, or payload. The one fixed, non-configurable command this
    # capability ever runs is `cat -- <candidate_path>` via an argv list,
    # issued through the SAME already-safety-gated
    # `apex_host.tools.backend.ToolBackend` seam every other command in this
    # codebase uses (see `apex_host/runtime_registry.py
    # ::ToolBackendCommandReadStrategy`).
    #
    # `bounded_command_operator_attested` is the explicit opt-in gate: with
    # the default `False`, none of the fields below have any effect.
    bounded_command_operator_attested: bool = False
    # "local_shell" or "remote_command" only. "web_command" is configured
    # through the direct_file_read_* fields above instead (it shares
    # DirectFileReadCapabilityAdapter — see
    # apex_host/orchestration/dispatch_node.py::_register_capability_adapter).
    bounded_command_capability_type: str = "local_shell"
    # A label identifying who/what this capability is attributed to —
    # required, mirrors direct_file_read_principal's own guard.
    bounded_command_principal: str = ""
    # Confidence recorded on the derived access_capability node. Fixed and
    # conservative — never inferred from the target or EKG content.
    bounded_command_confidence: float = 0.7
    bounded_command_timeout_seconds: float = 15.0
    # Bounded output-size cap in bytes — enforced independently by the
    # adapter itself (never trusts the verifier's own cap alone).
    bounded_command_max_output_bytes: int = 4096

    # Phase 23 — deterministic, structured capability-derivation pipeline
    # (see apex_host/capabilities/ and docs/user-flag-objective.md §20).
    # `capability_discovery_enabled` defaults True: discovery only ever
    # processes already-validated structured evidence (never executes a
    # command, opens a connection, or calls an LLM itself — see
    # apex_host.capabilities.discovery's module docstring), so it is safe
    # to leave on by default, unlike every *_operator_attested flag above
    # (which gate a specific, sensitive capability from being seeded at
    # all). Set False only to fully disable automatic derivation (e.g. for
    # a test fixture that wants to assert operator-seeding-only behavior).
    capability_discovery_enabled: bool = True
    # 0.0 (the default) disables evidence-age expiry entirely — no current
    # evidence source in this codebase produces stale evidence worth
    # rejecting on age alone (every live evidence item is emitted and
    # consumed within the same turn). Set to a positive value to reject
    # evidence older than this many seconds at validation time (see
    # apex_host.capabilities.evidence.validate_evidence).
    capability_evidence_ttl_seconds: float = 0.0
    # Hard per-turn ceiling on how many CapabilityEvidence items one
    # discovery cycle processes — bounds worst-case turn latency
    # regardless of how many tool_results a single turn produced.
    capability_discovery_max_evidence_per_cycle: int = 50

    # Phase 24 — 0.0 (the default) disables runtime-reference expiry
    # entirely: a minted RuntimeReference never expires on its own (it is
    # still invalidated by generation supersession, explicit revocation,
    # target change, or process shutdown — see
    # apex_host.capabilities.runtime_references). Set to a positive value
    # to bound how long a runtime reference remains resolvable before it
    # must be re-minted, independent of whether anything else invalidated
    # it. Conservative by default: no engagement in this codebase today
    # needs reference expiry, since every reference's lifetime is already
    # naturally bounded by the engagement's own process lifetime.
    capability_runtime_reference_ttl_seconds: float = 0.0

    # ---------------------------------------------------------------------------
    # Phase 4 (post-live-test debugging) — persistent, incremental knowledge
    # initialization cache (apex_host/knowledge/init_cache.py;
    # docs/knowledge-initialization.md). Fixes a live-test finding where
    # ~1,758 of ~1,785 total startup seconds were spent re-staging and
    # re-Reflector-promoting a 63,783-record compiled knowledge corpus on
    # EVERY run, even when the compiled files had not changed.
    # ---------------------------------------------------------------------------
    # knowledge_cache_path: a durable directory (surviving disposable
    # container restarts — see compose.yaml's apex-knowledge-cache named
    # volume) where the small init_state.json bookkeeping file and one
    # family_<name>.json payload file per compiled-knowledge family are
    # persisted. None (the default) means NO cross-run persistence — every
    # startup performs a full (but now fast — see
    # apex_host.execution.error_classifier's sibling fix in
    # memfabric.api.MemoryAPI.select_unpromoted_knowledge_ids) re-stage.
    # CLI: --knowledge-cache-path. Env: APEX_KNOWLEDGE_CACHE_PATH.
    knowledge_cache_path: str | None = None
    # knowledge_cache_enabled: explicit kill switch — when False, behaves
    # exactly as if knowledge_cache_path were None, even if a path is
    # configured (useful for a --no-knowledge-cache override without
    # having to unset the path). CLI: --no-knowledge-cache.
    knowledge_cache_enabled: bool = True
    # knowledge_cache_lock_timeout_seconds: how long a process will wait to
    # acquire the cross-process cache-directory lock before degrading to an
    # uncached (correct, bounded, but non-persistent) initialization for
    # this run only. CLI: --knowledge-cache-lock-timeout.
    knowledge_cache_lock_timeout_seconds: float = 30.0
    # knowledge_cache_stale_lock_seconds: a lock file older than this is
    # treated as abandoned (its holder crashed without releasing it) and
    # reclaimed by the next waiter — see apex_host/knowledge/init_lock.py.
    knowledge_cache_stale_lock_seconds: float = 300.0

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
        ``htb_ovpn_path`` (Infra Phase 10), when set, is replaced with just its
        ``os.path.basename`` — the VPN profile path is sensitive operational
        configuration (it can reveal host directory structure/username) but
        not itself a credential, so the filename alone is shown rather than
        a full "[redacted]" — this lets an operator confirm *which* profile
        is configured without exposing the full host path.
        ``direct_file_read_headers`` (Phase 20) values are replaced with
        ``"[redacted]"`` — a fixed header may carry a session cookie or
        bearer token value; header NAMES are kept (so an operator can
        confirm which headers are configured) but never the values.
        All other fields are returned verbatim — no other field stores a plaintext secret.
        """
        d: dict[str, object] = {f.name: getattr(self, f.name) for f in _dc_fields(self)}
        if self.password_candidates:
            d["password_candidates"] = [_REDACTED] * len(self.password_candidates)
        if self.tool_service_token:
            d["tool_service_token"] = _REDACTED
        if self.htb_ovpn_path:
            d["htb_ovpn_path"] = _basename(self.htb_ovpn_path)
        if self.direct_file_read_headers:
            d["direct_file_read_headers"] = {k: _REDACTED for k in self.direct_file_read_headers}
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
            "llm_required": bool(_g("llm_required", False)),
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
            # None (unset) means "derive automatically from tool_backend" —
            # see apex_host.tools.backend.backend_supports_raw_sockets().
            "tool_backend_raw_socket_capable": _g("tool_backend_raw_socket_capable", None),
            # Infra Phase 10 — HTB VPN readiness configuration. All three
            # are None/safe-default unless a caller (container_entrypoint.py
            # for the first two; config_env.py's env merge for all three)
            # explicitly sets them — no VPN behavior is enabled by default.
            "vpn_service_url": _g("vpn_service_url", None),
            "htb_route_cidr": _g("htb_route_cidr", "10.129.0.0/16"),
            "htb_ovpn_path": _g("htb_ovpn_path", None),
            # Phase 18 — user-flag objective configuration. Never a CLI
            # option accepts an expected plaintext flag value.
            "objective_type": _g("objective_type", "user_flag"),
            "max_user_flag_attempts": _g("max_user_flag_attempts", 3),
            "user_flag_max_output_bytes": _g("user_flag_max_output_bytes", 4096),
            "user_flag_verification_regex": _g("user_flag_verification_regex", None),
            "user_flag_read_timeout_seconds": _g("user_flag_read_timeout_seconds", 35.0),
            # Phase 20 — direct file-read access capability. Never enabled
            # unless the operator explicitly passes --direct-file-read-attested.
            "direct_file_read_operator_attested": bool(_g("direct_file_read_operator_attested", False)),
            "direct_file_read_capability_type": _g("direct_file_read_capability_type", "arbitrary_file_read"),
            "direct_file_read_origin": _g("direct_file_read_origin", None),
            "direct_file_read_endpoint_template": _g("direct_file_read_endpoint_template", None),
            "direct_file_read_method": _g("direct_file_read_method", "GET"),
            "direct_file_read_principal": _g("direct_file_read_principal", ""),
            "direct_file_read_max_response_bytes": _g("direct_file_read_max_response_bytes", 4096),
            "direct_file_read_timeout_seconds": _g("direct_file_read_timeout_seconds", 15.0),
            "direct_file_read_allow_redirects": bool(_g("direct_file_read_allow_redirects", False)),
            "direct_file_read_confidence": _g("direct_file_read_confidence", 0.7),
            # Phase 21 — bounded command-execution access capability. Never
            # enabled unless the operator explicitly passes
            # --bounded-command-attested. No flag anywhere accepts a
            # command string, shell syntax, or payload.
            "bounded_command_operator_attested": bool(_g("bounded_command_operator_attested", False)),
            "bounded_command_capability_type": _g("bounded_command_capability_type", "local_shell"),
            "bounded_command_principal": _g("bounded_command_principal", ""),
            "bounded_command_confidence": _g("bounded_command_confidence", 0.7),
            "bounded_command_timeout_seconds": _g("bounded_command_timeout_seconds", 15.0),
            "bounded_command_max_output_bytes": _g("bounded_command_max_output_bytes", 4096),
            "capability_discovery_enabled": bool(_g("capability_discovery_enabled", True)),
            "capability_evidence_ttl_seconds": _g("capability_evidence_ttl_seconds", 0.0),
            "capability_discovery_max_evidence_per_cycle": _g("capability_discovery_max_evidence_per_cycle", 50),
            "capability_runtime_reference_ttl_seconds": _g("capability_runtime_reference_ttl_seconds", 0.0),
            # Phase 4 — knowledge-initialization cache. None means "no
            # persistence" (the safe, pre-existing default behavior).
            "knowledge_cache_path": _g("knowledge_cache_path", None),
            "knowledge_cache_enabled": bool(_g("knowledge_cache_enabled", True)),
            "knowledge_cache_lock_timeout_seconds": _g("knowledge_cache_lock_timeout_seconds", 30.0),
            "knowledge_cache_stale_lock_seconds": _g("knowledge_cache_stale_lock_seconds", 300.0),
        }
        if getattr(args, "no_knowledge_cache", False):
            kwargs["knowledge_cache_enabled"] = False
        user_flag_filenames = getattr(args, "user_flag_candidate_filenames", None)
        if user_flag_filenames:
            kwargs["user_flag_candidate_filenames"] = list(user_flag_filenames)
        user_flag_roots = getattr(args, "user_flag_candidate_roots", None)
        if user_flag_roots:
            kwargs["user_flag_candidate_roots"] = list(user_flag_roots)
        direct_file_read_headers = getattr(args, "direct_file_read_header", None)
        if direct_file_read_headers:
            headers: dict[str, str] = {}
            for entry in direct_file_read_headers:
                name, sep, value = str(entry).partition(":")
                if sep:
                    headers[name.strip()] = value.strip()
            kwargs["direct_file_read_headers"] = headers
        if getattr(args, "vpn_health_timeout", None) is not None:
            kwargs["vpn_health_timeout_seconds"] = float(getattr(args, "vpn_health_timeout"))
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
