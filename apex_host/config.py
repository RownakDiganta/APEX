"""Typed configuration for the APEX host application."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ApexConfig:
    target: str
    payload_repo_path: str = "./payloads"
    max_command_seconds: int = 30
    allowed_tools: list[str] = field(
        default_factory=lambda: ["nmap", "ffuf", "gobuster", "curl", "python3", "searchsploit"]
    )
    planner_model: str = "gpt-4o-mini"
    executor_model: str = "gpt-4o-mini"
    parser_model: str = "gpt-4o-mini"
    dry_run: bool = True
    """Safety default. Real command execution requires the host to set this
    to False explicitly — see apex_host/tools/runner.py."""
    max_turns: int = 20
    max_concurrency: int = 2
    max_retries: int = 1
