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
    """
    url: str
    html_snippet: str
    title: str = ""
    forms: list[dict[str, Any]] = field(default_factory=list)
    auth_hints: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


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
