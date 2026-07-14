# allowlist.py
# Explicit, minimal server-side tool allowlist — the sole source of which binaries apex_tool_service will ever execute.
"""Explicit tool allowlist for apex_tool_service.

Each entry maps an API-facing tool name to the exact binary name passed to
``asyncio.create_subprocess_exec`` (never resolved through a shell). An
unknown ``tool`` value is rejected before any process creation — see
``apex_tool_service/validation.py``.

Selection rationale (see ``docs/kali-tool-service.md`` "Tool allowlist" for
the full writeup):

- ``nmap``, ``curl``, ``nc``/``netcat`` — APEX has direct evidence of using
  these (``apex_host/tools/registry.py``, ``ReconPlanner``, ``WebPlanner``,
  ``NmapParser``, ``BannerParser``, ``CommandParser``).
- ``ping`` — no direct APEX usage evidence today, but included per this
  phase's own task brief as a safe, read-only network diagnostic with the
  same risk profile as the tools above.
- ``telnet`` — no direct APEX usage evidence as a *subprocess* (APEX's own
  ``TelnetExecutor`` speaks the protocol itself over ``asyncio.open_connection``,
  never shelling out to a ``telnet`` binary); included because this phase's
  own task brief names it explicitly in the required ``/health`` response
  shape, and its risk profile is the same as ``nc``.

Deliberately EXCLUDED even though APEX has usage evidence:

- ``ffuf``, ``gobuster`` — wordlist-driven fuzzers. APEX's own policy layer
  (``apex_host/policy/rules.py::check_no_password_list``) already treats
  ``-w``/``--wordlist`` usage as opt-in and blocked by default
  (``allow_password_lists=False``). Adding them here would need matching
  wordlist-path validation logic this phase does not design. Deferred.
- ``searchsploit`` — a local exploit-database search tool, not a network
  execution primitive; a different risk shape than the tools above (reads
  a local database rather than acting on a network target). Deferred.
- ``python3`` — APEX's own local ``allowed_tools`` default includes it, but
  this phase's task brief explicitly forbids general-purpose interpreters
  in this service's allowlist. The explicit prohibition overrides local
  usage evidence.

Never include, regardless of evidence: shells (``sh``, ``bash``, ``zsh``),
other interpreters (``perl``, ``ruby``, ``php``, ``node``, ``python``/``python3``),
``env`` (can be used to invoke an arbitrary binary), privilege-escalation
tools (``sudo``, ``su``), or container/orchestration control planes
(``docker``, ``kubectl``).
"""
from __future__ import annotations

import shutil

# tool name (API-facing) -> exact binary name (never shell-resolved; passed
# as argv[0] to asyncio.create_subprocess_exec).
ALLOWED_TOOLS: dict[str, str] = {
    "nmap": "nmap",
    "curl": "curl",
    "nc": "nc",
    "netcat": "netcat",
    "ping": "ping",
    "telnet": "telnet",
}

# Tool names that must NEVER be allowlisted, even by a future configuration
# change — a defense-in-depth constant independent of ALLOWED_TOOLS above,
# checked explicitly by a security-invariant test so a careless edit to
# ALLOWED_TOOLS cannot silently reintroduce one of these.
NEVER_ALLOWED: frozenset[str] = frozenset(
    {
        "sh", "bash", "zsh", "csh", "ksh", "fish",
        "python", "python3", "perl", "ruby", "php", "node",
        "env", "sudo", "su", "doas",
        "docker", "kubectl", "podman", "containerd",
        "rm", "mkfs", "dd", "shutdown", "reboot", "halt", "poweroff",
    }
)


def is_allowed(tool: str) -> bool:
    """True only for an exact, case-sensitive match in ``ALLOWED_TOOLS``."""
    return tool in ALLOWED_TOOLS and tool not in NEVER_ALLOWED


def resolve_binary(tool: str) -> str | None:
    """Return the binary name for an allowed *tool*, or ``None`` if disallowed."""
    if not is_allowed(tool):
        return None
    return ALLOWED_TOOLS[tool]


def tool_availability() -> dict[str, bool]:
    """Map every allowlisted tool name to whether its binary is on PATH.

    Mirrors ``apex_host/tools/preflight.py::check_local_tools`` — never
    raises merely because an optional tool's binary is absent.
    """
    return {name: shutil.which(binary) is not None for name, binary in ALLOWED_TOOLS.items()}
