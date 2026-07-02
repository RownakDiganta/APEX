# preflight.py
# Checks which allowed local tools are available in PATH before a run.
from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apex_host.config import ApexConfig


def check_local_tools(config: "ApexConfig") -> dict[str, bool]:
    """Return a mapping of tool name → whether it is found in PATH."""
    return {tool: shutil.which(tool) is not None for tool in config.allowed_tools}
