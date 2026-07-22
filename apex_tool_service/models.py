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


class ReadBoundedFileRequest(BaseModel):
    """One dedicated, structured bounded-file-read request (Phase 22).

    Deliberately NOT a generalisation of ``ExecuteRequest`` — there is no
    ``tool``/``arguments``/``stdin`` field here, and none is accepted
    (``extra="forbid"``). The caller supplies only *what* to read and the
    authorization/bounding context; the service alone decides *how*
    (constructing a fixed ``["cat", "--", path]`` argv internally — see
    ``apex_tool_service/executor.py::execute_bounded_file_read``). There is
    no field here, and there must never be one added, for an executable,
    command string, shell, argv, environment, or working directory.
    """

    model_config = ConfigDict(extra="forbid")

    target: str
    path: str
    timeout_seconds: float | None = None
    max_output_bytes: int | None = None
    #: Defense-in-depth mirror of ``ApexConfig.dry_run`` — when true, the
    #: service must not launch a process at all and returns a synthetic,
    #: never-executed response. The primary dry-run enforcement is on the
    #: apex_host side (``UserFlagExecutor`` never even reaches this client
    #: call when ``config.dry_run`` is true); this field exists so the
    #: service itself independently refuses execution too.
    dry_run: bool = False


class ReadBoundedFileResponse(BaseModel):
    """Structured, sanitized result of one bounded-file-read request.

    ``output`` is populated only on a genuine, in-bound, successful read —
    it is never a truncated prefix of an oversized read (see
    ``execute_bounded_file_read``'s "reject oversized output completely"
    contract). This is the ONLY field that may ever carry file content;
    every other field is a bounded, non-sensitive status/metadata value
    safe to log, report, or include in a metrics label.
    """

    model_config = ConfigDict(extra="forbid")

    ok: bool
    output: str = ""
    error_code: str | None = None
    sanitized_error: str | None = None
    return_code: int | None = None
    bytes_received: int = 0
    oversized: bool = False
    timed_out: bool = False
    duration_ms: float = 0.0
    method: str = "bounded_file_read"


class HealthResponse(BaseModel):
    """``/health`` response — availability only, never secrets or paths."""

    model_config = ConfigDict(extra="forbid")

    status: str
    service: str
    tools: dict[str, bool]
    #: Phase 22 — a static capability flag only. This endpoint never reads
    #: a file, validates a path, or exposes allowed paths/basenames —
    #: it simply reports that the dedicated bounded-file-read route exists.
    bounded_file_read: bool = True
