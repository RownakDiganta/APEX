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
