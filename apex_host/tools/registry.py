"""Catalogue of recognised tools, filtered down to ApexConfig.allowed_tools."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apex_host.config import ApexConfig


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    default_args: list[str] = field(default_factory=list)


_KNOWN_TOOLS: dict[str, ToolSpec] = {
    "nmap": ToolSpec("nmap", "Network mapper for host/service discovery", ["-T4"]),
    "ffuf": ToolSpec("ffuf", "Web fuzzer for endpoint/directory discovery", ["-c"]),
    "gobuster": ToolSpec("gobuster", "Directory and DNS busting tool", ["dir"]),
    "curl": ToolSpec("curl", "HTTP client for web interaction", ["-s"]),
    "python3": ToolSpec("python3", "Python interpreter for bounded scripting", []),
    "searchsploit": ToolSpec("searchsploit", "Local exploit-database search", ["--json"]),
}


class ToolRegistry:
    """Exposes only the tools allowlisted in ApexConfig.allowed_tools."""

    def __init__(self, allowed_tools: list[str]) -> None:
        self._available: dict[str, ToolSpec] = {
            name: spec for name, spec in _KNOWN_TOOLS.items() if name in allowed_tools
        }

    def get(self, name: str) -> ToolSpec | None:
        return self._available.get(name)

    def available(self) -> list[str]:
        return list(self._available.keys())

    @classmethod
    def from_config(cls, config: "ApexConfig") -> "ToolRegistry":
        return cls(allowed_tools=config.allowed_tools)
