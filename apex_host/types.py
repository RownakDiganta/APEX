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
