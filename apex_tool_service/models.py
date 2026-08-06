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


class FtpValidateRequest(BaseModel):
    """One dedicated, structured bounded FTP credential-validation request
    (§28.16). Deliberately NOT a generalisation of ``ExecuteRequest`` — there
    is no ``tool``/``arguments``/``command`` field and none is accepted
    (``extra="forbid"``). The service runs exactly ONE ftplib login attempt
    (passive mode) followed by exactly one harmless ``PWD``/``NOOP`` and closes
    — no file transfer, no brute force. The password is used only to attempt the
    single login; it is never logged, and never appears in the response."""

    model_config = ConfigDict(extra="forbid")

    target: str
    port: int = 21
    username: str
    password: str
    operation: str = "PWD"
    connect_timeout_seconds: float | None = None
    login_timeout_seconds: float | None = None
    command_timeout_seconds: float | None = None
    #: Defense-in-depth mirror of ``ApexConfig.dry_run`` — the primary dry-run
    #: enforcement is apex-side (FTPExecutor returns a synthetic result and never
    #: reaches this endpoint); this field lets the service refuse too.
    dry_run: bool = False


class FtpValidateResponse(BaseModel):
    """Structured, sanitized result of one FTP validation. Carries NO password
    and NO file content — only bounded status/metadata safe to log or report."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    authenticated: bool = False
    operation: str = "PWD"
    #: The harmless PWD/NOOP response text (e.g. '"/" is the current directory')
    #: — bounded and password-redacted server-side; never the password itself.
    response_summary: str = ""
    error_code: str | None = None
    sanitized_error: str | None = None
    timed_out: bool = False
    duration_ms: float = 0.0
    method: str = "ftp_validate"


class FtpReadRequest(BaseModel):
    """One dedicated, structured bounded FTP file-read request (§28.17): connect
    -> login -> RETR one approved candidate ``path`` (bounded) -> close. No
    ``tool``/``arguments``/``command`` field and none accepted
    (``extra="forbid"``). The password is used only for the single login; it is
    never logged, and neither it nor the retrieved content appears anywhere but
    the caller's own bounded response ``output``."""

    model_config = ConfigDict(extra="forbid")

    target: str
    port: int = 21
    username: str
    password: str
    path: str
    max_output_bytes: int | None = None
    connect_timeout_seconds: float | None = None
    login_timeout_seconds: float | None = None
    command_timeout_seconds: float | None = None
    dry_run: bool = False


class FtpReadResponse(BaseModel):
    """Structured result of one bounded FTP RETR. ``output`` is populated ONLY on
    a genuine, in-bound success — never a truncated prefix of an oversized read
    (mirrors ``ReadBoundedFileResponse``). It is the only field that may carry
    file content; every other field is bounded status/metadata."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    output: str = ""
    error_code: str | None = None
    sanitized_error: str | None = None
    bytes_received: int = 0
    oversized: bool = False
    timed_out: bool = False
    duration_ms: float = 0.0
    method: str = "ftp_read"


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
    #: §28.16 — static capability flag: the dedicated bounded FTP-validate
    #: route exists. Never exposes a credential, target, or result.
    ftp_validate: bool = True
    #: §28.17 — static capability flag: the dedicated bounded FTP-read route
    #: exists. Never exposes a credential, path, target, or content.
    ftp_read: bool = True
