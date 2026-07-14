# models.py
# Pydantic v2 request/response schemas for apex_tool_service's HTTP contract.
"""Request/response models for apex_tool_service.

``ExecuteRequest``/``ExecuteResponse`` implement the contract specified in
``docs/tool-execution-architecture.md`` §10 and finalized in
``docs/kali-tool-service.md``. ``ExecuteRequest`` uses
``model_config = ConfigDict(extra="forbid")`` specifically so that a client
sending ``{"command": "nmap ... && ..."}`` (a raw shell-string field this
contract never accepts) is rejected by schema validation alone, before any
of this package's own validation logic runs.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ExecuteRequest(BaseModel):
    """A single allowlisted-tool invocation request.

    ``arguments`` is always a JSON array of strings — one argv token each.
    There is no ``command`` field and none is accepted (``extra="forbid"``).
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    arguments: list[str] = Field(default_factory=list)
    timeout_seconds: float | None = None
    stdin: str | None = None


class ExecuteResponse(BaseModel):
    """Structured execution result — mirrors ``apex_host.types.ToolResult``.

    Field names intentionally match ``ToolResult`` (``tool``/``arguments``
    here correspond to ``ToolCommand.tool``/``.args``) so a future
    ``RemoteToolBackend`` in ``apex_host`` can map this response onto
    ``ToolResult`` with minimal translation.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    arguments: list[str]
    stdout: str
    stderr: str
    returncode: int
    duration_seconds: float
    timed_out: bool = False
    backend: str = "kali-service"
    error: str | None = None


class HealthResponse(BaseModel):
    """``/health`` response — availability only, never secrets or paths."""

    model_config = ConfigDict(extra="forbid")

    status: str
    service: str
    tools: dict[str, bool]
