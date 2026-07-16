# types.py
# Core APEX-specific data shapes — ApexPhase, ApexFinding, ToolCommand, ToolResult, BrowserObservation, and ApexRunConfig — that feed into memfabric types via parsers.
"""Core data shapes for the APEX cybersecurity host application.

These types are APEX-specific (unlike memfabric/types.py, which is
domain-agnostic). They describe phases, tool commands/results, browser
observations, and findings — all of which eventually become memfabric
Node/Edge/Episode/KnowledgeEntry objects via the parsers in apex_host/parsers/.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ApexPhase(str, Enum):
    recon = "recon"
    web = "web"
    exploit = "exploit"
    priv_esc = "priv_esc"
    credential = "credential"
    lateral = "lateral"
    done = "done"


@dataclass(slots=True)
class ApexFinding:
    """A simplified, serializable security observation."""
    id: str
    phase: ApexPhase
    title: str
    detail: str
    confidence: float
    source: str
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ToolCommand:
    """A single allowlisted-tool invocation, pre-safety-check."""
    tool: str
    args: list[str]
    timeout_seconds: int = 30
    metadata: dict[str, Any] = field(default_factory=dict)
    # Optional stdin payload for controlled interactive adapters (e.g. a future
    # ToolBackend that pipes input to a tool expecting stdin). Not yet wired
    # into apex_host/tools/runner.py's subprocess invocation — see
    # docs/tool-execution-architecture.md ("Open risks and deferred questions").
    stdin: str | None = None


@dataclass(slots=True)
class ToolResult:
    """Outcome of running (or dry-running) a ToolCommand."""
    command: ToolCommand
    stdout: str
    stderr: str
    returncode: int
    duration_seconds: float
    dry_run: bool = False
    error: str | None = None
    # Backend-abstraction fields (Infra Phase 2 — docs/tool-execution-architecture.md).
    # timed_out: True only when the command was terminated because it exceeded
    #   its timeout (as opposed to a normal non-zero exit or an OSError).
    timed_out: bool = False
    # backend: identifies which execution mode actually produced this result —
    #   "dry-run" (no process was spawned) or "local" (a real local subprocess
    #   ran). A future "remote" value will identify results produced by
    #   RemoteToolBackend once its transport is implemented. Note this reflects
    #   the *execution mode*, not necessarily which ToolBackend class was
    #   invoked: LocalToolBackend still honors ApexConfig.dry_run internally
    #   (defense in depth) and will itself report backend="dry-run" when it does.
    backend: str = ""


@dataclass(slots=True)
class BrowserObservation:
    """A snapshot of what BrowserExecutor saw on a page.

    In dry_run mode this is synthesised, never produced by a real browser.

    Phase 14 additions (all additive — existing callers that only ever set
    the original seven fields are unaffected): ``status``/``headers``
    support deterministic technology detection (see
    ``apex_host/parsers/tech_detector.py``); ``cookies`` is deliberately
    name/flag-only — **never** a cookie value, mirroring this project's
    "no secret leakage" discipline (see ``apex_host.security.redaction`` and
    Phase 12B's credential handling); ``final_url`` is set only when a live
    fetch followed a redirect chain that landed somewhere different from
    ``url`` (``url`` always stays the originally requested address, so
    session/visited-URL dedup logic never has to reconcile two identities
    for the same request); ``favicon_present`` is a bare observational flag,
    not an opportunity.
    """
    url: str
    html_snippet: str
    title: str = ""
    forms: list[dict[str, Any]] = field(default_factory=list)
    auth_hints: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    status: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    # Each entry: {"name": str, "http_only": bool, "secure": bool} — never a
    # cookie value.
    cookies: list[dict[str, Any]] = field(default_factory=list)
    final_url: str = ""
    favicon_present: bool = False


# ---------------------------------------------------------------------------
# Web exploitation planning model (Phase 14)
# ---------------------------------------------------------------------------
#
# These types back a PLANNING/REASONING framework only — organizing browser
# observations, detecting technology and form structure deterministically,
# and surfacing structured, non-executable opportunities for a human
# operator. Nothing here executes an exploit, submits a form, uploads a
# payload, or performs SQL injection / XSS / CSRF of any kind. See
# docs/web-planning.md.


class WebOpportunityCategory(str, Enum):
    """Planning labels only — never an executable action.

    Mirrors ``OpportunityCategory`` (privilege-escalation planning, Phase
    13) in spirit: every member is a *classification* a human operator
    would use to decide what to investigate next, never something APEX
    itself acts on.
    """
    authentication_portal = "authentication_portal"
    admin_panel = "admin_panel"
    upload_functionality = "upload_functionality"
    search_functionality = "search_functionality"
    directory_listing = "directory_listing"
    api_endpoint = "api_endpoint"
    robots_entry = "robots_entry"
    backup_file = "backup_file"
    default_page = "default_page"
    # Reserved for a future capability if this taxonomy is ever extended by
    # a category with no reliable deterministic detector yet — mirrors
    # OpportunityCategory.none's "searched, nothing found" precedent.
    none = "none"


@dataclass(slots=True)
class WebOpportunityEvidence:
    """Bounded, secret-free evidence backing one ``WebOpportunity``.

    ``excerpt`` is deliberately short (<=200 chars, enforced by producers)
    and holds only titles/labels/short markers (e.g. a matched HTML
    fragment or header value) — never full page content, never a payload,
    never a cookie/session value.
    """
    source: str  # e.g. "form" | "header" | "html" | "url" | "robots_txt"
    excerpt: str = ""
    timestamp: str = ""


@dataclass(slots=True)
class WebOpportunity:
    """One structured, non-executable web-exploitation planning record.

    Stored in the EKG as a ``web_opportunity`` node (see
    ``apex_host/graph_ids.py::web_opportunity_id`` and
    ``apex_host/parsers/browser_parser.py``) — this dataclass is the
    in-planner/report view reconstructed from that node's props, never a
    second, independent storage format (memfabric Invariant 1).
    """
    id: str
    category: WebOpportunityCategory
    confidence: "OpportunityConfidence"
    evidence: WebOpportunityEvidence
    description: str
    recommended_next_action: str
    first_seen: str
    last_seen: str


@dataclass(slots=True)
class WebSessionState:
    """A snapshot view over browser session/reasoning state for one target —
    built fresh from the EKG each turn, never itself the source of truth.

    ``login_state`` is derived from the SAME success signal every other
    phase uses (an ``access_state`` node) — never a second, independent
    notion of "logged in".
    """
    target: str
    pages_visited: int = 0
    forms_discovered: int = 0
    technologies_detected: int = 0
    opportunities: tuple["WebOpportunity", ...] = ()
    login_state: str = "anonymous"  # "anonymous" | "authenticated"

    @property
    def opportunity_count(self) -> int:
        return len(self.opportunities)

    @property
    def categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for o in self.opportunities:
            counts[o.category.value] = counts.get(o.category.value, 0) + 1
        return counts


@dataclass(slots=True)
class ApexRunConfig:
    """Identifies one engagement run for episode/finding correlation."""
    run_id: str
    target: str
    start_phase: ApexPhase = ApexPhase.recon
    max_turns: int = 20


class CredentialErrorCategory(str, Enum):
    """Distinguishes why a bounded SSH/FTP credential-validation attempt did
    or did not succeed (Phase 12B).

    Used by ``apex_host/agents/ssh_executor.py`` and ``ftp_executor.py`` to
    classify their result before it becomes episode data. TelnetExecutor
    predates this taxonomy and is intentionally left unchanged (Phase 12A/
    12B invariant: existing Telnet behavior must remain compatible) — it
    folds every non-success case into ``Outcome.fundamental``/``fixable``
    without this finer breakdown.
    """
    success = "success"
    auth_rejected = "auth_rejected"
    connection_failed = "connection_failed"
    connect_timeout = "connect_timeout"
    auth_timeout = "auth_timeout"
    command_timeout = "command_timeout"
    protocol_error = "protocol_error"
    command_failed = "command_failed"


@dataclass(slots=True)
class CredentialValidationResult:
    """Structured, secret-free outcome of one bounded SSH/FTP credential
    validation attempt (Phase 12B).

    Built entirely inside the executor's synchronous worker function and
    never crosses a boundary that could accidentally attach the plaintext
    password — no field here is ever the credential itself, only whether it
    worked and why. ``response_summary`` is the bounded, already-truncated
    harmless-command output (e.g. ``id``'s stdout, or FTP's ``PWD``
    response) — never raw session/protocol transcript data beyond what the
    fixed validation operation itself produced.
    """
    protocol: str            # "ssh" | "ftp"
    target: str
    port: str
    username: str
    success: bool             # True only on a fully successful validation
    authenticated: bool       # True once login succeeded, even if the
                               # follow-up harmless command itself then failed
    operation: str             # the fixed harmless validation command/operation run
    response_summary: str      # bounded, truncated stdout/response text — no secrets
    error_category: str        # a CredentialErrorCategory value
    error_detail: str          # human-readable detail — never includes the password
    duration_seconds: float
    timed_out: bool
    executor: str               # "ssh" | "ftp" — identifies which executor produced this


# ---------------------------------------------------------------------------
# Privilege-escalation planning model (Phase 13)
# ---------------------------------------------------------------------------
#
# These types back a PLANNING framework only — organizing enumeration,
# reasoning about opportunities, avoiding duplicate work, and reporting
# findings. Nothing here executes an exploit, escalates privileges, or
# generates payload content. See docs/privilege-escalation-planning.md.


class OpportunityCategory(str, Enum):
    """Planning labels only — never an executable action.

    Every member here is a *classification* a human operator (or a future,
    out-of-scope capability) would use to decide what to investigate next.
    Phase 13's own opportunity producers (see
    ``apex_host/planners/priv_esc_opportunities.py``) only ever populate
    ``vulnerable_service``, ``docker``, and ``sudo`` — the remaining members
    are defined so the taxonomy, ranking, deduplication, and reporting layers
    are complete and forward-compatible with future enumeration sources,
    exactly as CLAUDE.md's convention for "documented but not yet reachable"
    members (see ``EngagementOutcome.goal_completed``, Phase 12C).
    """
    sudo = "sudo"
    suid = "suid"
    capabilities = "capabilities"
    cron = "cron"
    writable_service = "writable_service"
    path_issue = "path_issue"
    kernel_version = "kernel_version"
    docker = "docker"
    mounted_filesystem = "mounted_filesystem"
    credentials = "credentials"
    scheduled_task = "scheduled_task"
    windows_service = "windows_service"
    registry = "registry"
    startup_item = "startup_item"
    # A known-vulnerable service/version combination (searchsploit-sourced).
    # Not in the brief's suggested list but needed for the one live research
    # task this planner already performs safely (a local exploit-db lookup,
    # zero target interaction).
    vulnerable_service = "vulnerable_service"
    # Search/enumeration was performed and found nothing — recorded so the
    # planner never repeats it, not a "finding" for the operator to act on.
    none = "none"


class OpportunityConfidence(str, Enum):
    """Discrete confidence bucket — deliberately not a raw float.

    Matches this project's preference for small, testable, serializable
    enums over unconstrained floats for planner-facing classifications
    (compare ``CredentialErrorCategory`` above). ``as_float()``/``from_score()``
    provide the numeric mapping used for deterministic ranking.
    """
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"

    def as_float(self) -> float:
        return {
            OpportunityConfidence.none: 0.0,
            OpportunityConfidence.low: 0.3,
            OpportunityConfidence.medium: 0.6,
            OpportunityConfidence.high: 0.9,
        }[self]

    @classmethod
    def from_score(cls, score: float) -> "OpportunityConfidence":
        if score >= 0.85:
            return cls.high
        if score >= 0.5:
            return cls.medium
        if score > 0.0:
            return cls.low
        return cls.none


class PrivilegeEnumerationStatus(str, Enum):
    """Where the priv-esc enumeration process currently stands for one target.

    ``elevated_access_validated`` is a **future capability** — no code in
    this phase ever produces it (mirrors ``EngagementOutcome.goal_completed``'s
    documented-but-unreachable precedent, Phase 12C). Reaching it would
    require APEX to itself validate an elevated shell, which is explicitly
    out of scope: this phase is a planning framework, not privilege
    escalation.
    """
    not_started = "not_started"
    running = "running"
    opportunities_found = "opportunities_found"
    exhausted = "exhausted"
    elevated_access_validated = "elevated_access_validated"


@dataclass(slots=True)
class PrivilegeOpportunityEvidence:
    """Bounded, secret-free evidence backing one ``PrivilegeOpportunity``.

    ``excerpt`` is deliberately short and title/label-only — for
    searchsploit-sourced opportunities this is exploit-db *titles*, never
    proof-of-concept code; for analytically-derived opportunities it is a
    redacted snippet of already-stored, already-redacted EKG text (e.g. an
    ``access_state`` node's ``evidence``/``proof`` props). No opportunity
    producer in this codebase may put payload or exploit code here.
    """
    source: str                          # e.g. "searchsploit" | "id_groups"
    supporting_node_ids: tuple[str, ...] = ()
    excerpt: str = ""                    # bounded (<=200 chars enforced by producers)
    timestamp: str = ""


@dataclass(slots=True)
class PrivilegeOpportunity:
    """One structured, non-executable privilege-escalation planning record.

    Stored in the EKG as a ``priv_esc_opportunity`` node (see
    ``apex_host/graph_ids.py::priv_esc_opportunity_id`` and
    ``apex_host/parsers/priv_esc_parser.py``) — this dataclass is the
    in-planner/report view reconstructed from that node's props, never a
    second, independent storage format (memfabric Invariant 1).
    """
    id: str
    category: OpportunityCategory
    confidence: OpportunityConfidence
    evidence: PrivilegeOpportunityEvidence
    description: str
    recommended_next_action: str
    attempted: bool
    attempt_count: int
    exhausted: bool
    first_seen: str
    last_seen: str

    @property
    def supporting_node_ids(self) -> tuple[str, ...]:
        return self.evidence.supporting_node_ids


@dataclass(slots=True)
class PrivilegeEscalationState:
    """A snapshot view over all ``PrivilegeOpportunity`` records for one
    target — built fresh from the EKG each turn, never itself the source of
    truth (the EKG nodes are)."""
    target: str
    status: PrivilegeEnumerationStatus
    opportunities: tuple[PrivilegeOpportunity, ...] = ()

    @property
    def opportunity_count(self) -> int:
        return len(self.opportunities)

    @property
    def attempted_count(self) -> int:
        return sum(1 for o in self.opportunities if o.attempted)

    @property
    def exhausted_count(self) -> int:
        return sum(1 for o in self.opportunities if o.exhausted)

    @property
    def remaining_count(self) -> int:
        return sum(1 for o in self.opportunities if not o.exhausted)

    @property
    def categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for o in self.opportunities:
            counts[o.category.value] = counts.get(o.category.value, 0) + 1
        return counts

    @property
    def enumeration_complete(self) -> bool:
        return self.status is PrivilegeEnumerationStatus.exhausted


# ---------------------------------------------------------------------------
# Safe privilege enumeration & evidence collection (Phase 13B)
# ---------------------------------------------------------------------------
#
# Extends the Phase 13A planning framework with structured EVIDENCE — the
# output of harmless, read-only enumeration commands, parsed deterministically
# (never by an LLM) into typed facts that in turn generate PrivilegeOpportunity
# records. Nothing here executes an exploit, escalates privileges, or
# performs any command beyond the fixed, read-only allowlist enforced by
# apex_host/agents/priv_esc_enum_executor.py. See docs/privilege-enumeration.md.


class EvidenceCategory(str, Enum):
    """Classification for one parsed enumeration command's output.

    Overlaps deliberately with ``OpportunityCategory`` for the categories
    that can directly imply an opportunity (``sudo``, ``suid``,
    ``capabilities``, ``cron``, ``docker``, ``kernel_version``,
    ``mounted_filesystem``) — evidence is the raw, parsed fact; an
    opportunity is the actionable escalation vector a human should look at.
    Not every piece of evidence produces an opportunity (e.g. ``identity``/
    ``os_info``/``service_info`` are informational only).

    The ``windows_*`` members are **planning support only** — their parsers
    exist and are fully tested, but no code path in this codebase ever
    executes a Windows enumeration command live (no WinRM/PSRemoting
    executor exists here). See docs/privilege-enumeration.md "Windows
    support scope".
    """
    identity = "identity"
    kernel_version = "kernel_version"
    os_info = "os_info"
    sudo = "sudo"
    suid = "suid"
    capabilities = "capabilities"
    mounted_filesystem = "mounted_filesystem"
    cron = "cron"
    docker = "docker"
    service_info = "service_info"
    # Windows — planning support only (see class docstring).
    windows_privileges = "windows_privileges"
    windows_groups = "windows_groups"
    windows_system_info = "windows_system_info"
    windows_service = "windows_service"
    windows_scheduled_task = "windows_scheduled_task"
    windows_registry = "windows_registry"


@dataclass(slots=True)
class PrivilegeEvidence:
    """One structured, non-executable record of a parsed enumeration
    command's output.

    Stored in the EKG as a ``priv_esc_evidence`` node (see
    ``apex_host/graph_ids.py::priv_esc_evidence_id`` and
    ``apex_host/parsers/priv_esc_parser.py``). ``extracted_facts`` is a
    plain, JSON-serialisable dict of deterministically-parsed values (e.g.
    ``{"suid_binaries": ["/usr/bin/find", ...]}``) — never raw exploit code,
    never a payload, never a secret. ``raw_excerpt`` is bounded and mirrors
    the same "titles/labels only" discipline as
    ``PrivilegeOpportunityEvidence.excerpt`` from Phase 13A.
    """
    id: str
    category: EvidenceCategory
    source_command: str
    confidence: OpportunityConfidence
    extracted_facts: dict[str, Any]
    supporting_node_ids: tuple[str, ...]
    raw_excerpt: str
    timestamp: str


@dataclass(slots=True)
class PrivilegeEnumerationProgress:
    """A snapshot view over enumeration command execution for one target —
    built fresh from the EKG each turn (evidence nodes + a completed/failed
    command ledger), never itself the source of truth."""
    target: str
    commands_completed: int = 0
    commands_failed: int = 0
    commands_parsed: int = 0
    evidence_count: int = 0
    opportunities_created: int = 0
    duplicate_commands_avoided: int = 0

    @property
    def commands_attempted(self) -> int:
        return self.commands_completed + self.commands_failed


# ---------------------------------------------------------------------------
# Multi-step exploitation orchestration model (Phase 15)
# ---------------------------------------------------------------------------
#
# These types back a REASONING AND COORDINATION framework only — reifying
# the dependency ordering GlobalPlanner already enforces (recon -> web ->
# credential -> priv_esc) into an explicit, inspectable, reportable
# "Workflow" model, tracking which planning-object "sessions" exist, and
# synthesizing advisory recommendations. Nothing here executes an exploit,
# uploads a payload, generates a reverse shell, uses Metasploit, establishes
# persistence, or captures a flag. See docs/workflow-orchestration.md.


class WorkflowStepStatus(str, Enum):
    """One step's status within a Workflow — derived purely from EKG
    evidence, never from imperative/remembered history (see
    ``apex_host.planners.workflow_orchestration`` module docstring for why
    this makes "resuming" and "never restarting a completed chain"
    automatic rather than something that needs its own tracking logic)."""
    pending = "pending"      # not yet reached, or reached but not yet satisfied
    completed = "completed"  # satisfied by existing EKG evidence
    blocked = "blocked"      # a prerequisite step failed, or hasn't completed yet
    failed = "failed"        # attempted (evidence of the attempt exists) and did not succeed


class WorkflowStatus(str, Enum):
    """A workflow's overall status — see
    ``apex_host.planners.workflow_orchestration.derive_workflows_from_subgraph``
    for the exact precedence rules."""
    running = "running"
    blocked = "blocked"
    completed = "completed"
    abandoned = "abandoned"
    stalled = "stalled"


class SessionKind(str, Enum):
    """Which planning-object "session" this record describes. These are
    NEVER live, executable sessions APEX holds open — they are derived,
    read-only reconstructions of what earlier phases already recorded
    (browser page visits, SSH/FTP/Telnet credential validation results)."""
    browser = "browser"
    credential = "credential"
    ssh = "ssh"
    ftp = "ftp"
    telnet = "telnet"


class SessionStatus(str, Enum):
    """A session's status — ``active`` means validated/confirmed evidence
    exists (e.g. an ``access_state`` node); ``attempted`` means an attempt
    was recorded but not confirmed (e.g. a ``credential`` node with no
    matching ``access_state``); ``inactive`` means no evidence of any kind."""
    active = "active"
    attempted = "attempted"
    inactive = "inactive"


@dataclass(slots=True)
class WorkflowStep:
    """One step in a ``Workflow`` — a named, ordered unit of reasoning
    progress, never an executable action APEX performs on its own."""
    name: str
    status: WorkflowStepStatus
    description: str


@dataclass(slots=True)
class Workflow:
    """One structured, non-executable multi-step reasoning chain.

    Stored in the EKG as a ``workflow`` node with one ``workflow_step``
    node per step (see ``apex_host/graph_ids.py`` and
    ``apex_host/planners/workflow_orchestration.py``) — this dataclass is
    the in-planner/report view reconstructed from those nodes, never a
    second, independent store (memfabric Invariant 1).
    """
    id: str
    key: str
    objective: str
    prerequisites: tuple[str, ...]
    steps: tuple[WorkflowStep, ...]
    status: WorkflowStatus
    confidence: OpportunityConfidence
    first_seen: str
    last_seen: str

    @property
    def completed_steps(self) -> list[str]:
        return [s.name for s in self.steps if s.status is WorkflowStepStatus.completed]

    @property
    def blocked_steps(self) -> list[str]:
        return [s.name for s in self.steps if s.status is WorkflowStepStatus.blocked]

    @property
    def failed_steps(self) -> list[str]:
        return [s.name for s in self.steps if s.status is WorkflowStepStatus.failed]

    @property
    def pending_steps(self) -> list[str]:
        return [s.name for s in self.steps if s.status is WorkflowStepStatus.pending]

    @property
    def current_step(self) -> str:
        """The first non-completed step — "" once every step is completed."""
        for s in self.steps:
            if s.status is not WorkflowStepStatus.completed:
                return s.name
        return ""

    @property
    def next_candidate(self) -> str:
        """The single actionable next step — the first ``pending`` step.

        "" when nothing is actionable right now (either the workflow is
        fully ``completed``, or it is ``blocked`` on a ``failed`` step with
        nothing left to attempt automatically)."""
        pending = self.pending_steps
        return pending[0] if pending else ""

    @property
    def completion_percentage(self) -> float:
        if not self.steps:
            return 0.0
        return round(100.0 * len(self.completed_steps) / len(self.steps), 1)


@dataclass(slots=True)
class Session:
    """A planning-object view of one credential/browser session — never a
    live, executable session APEX holds open. Stored in the EKG as a
    ``session`` node."""
    id: str
    kind: SessionKind
    target: str
    status: SessionStatus
    detail: str
    first_seen: str
    last_seen: str


@dataclass(slots=True)
class WorkflowRecommendation:
    """Advisory text for a human operator summarizing one workflow's
    current state — never a command or payload APEX itself would run.
    Stored in the EKG as a ``workflow_recommendation`` node."""
    id: str
    workflow_id: str
    text: str
    category: str
    priority: OpportunityConfidence
