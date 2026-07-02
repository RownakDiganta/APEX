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
    planner_model: str = "gpt-4o-mini"
    executor_model: str = "gpt-4o-mini"
    parser_model: str = "gpt-4o-mini"
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
