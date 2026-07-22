# runtime_registry.py
# Runtime-only (never persisted to MemoryAPI/EKG) registry mapping capability_id to a bounded-read adapter, plus the SSH and direct-file-read adapter implementations.
"""Runtime-only capability registry and adapters (capability refactor;
extended in Phase 20 with a generic direct-file-read adapter; extended in
Phase 21 with a generic bounded command-execution adapter).

This module is the ONE place a live/reusable access mechanism (an SSH
connection's parameters, a pre-validated HTTP file-read request shape, a
future Telnet/API session's parameters, ...) may be held in memory for the
duration of an engagement. It is deliberately **not** part of ``memfabric``
and is never written through ``MemoryAPI`` — ``CapabilityRuntimeRegistry``
lives only inside ``apex_host.orchestration.dependencies.OrchestrationDeps``,
constructed fresh per engagement, exactly like ``apex_host.orchestration.stall
.StallTracker`` and ``apex_host.planners.global_planner.GlobalPlanner``'s
own ``_spent`` counters (memfabric Invariant 1: the graph is never a place
to stash live session/credential state).

Never stored here (or anywhere): passwords, cookies, bearer tokens, CSRF
tokens, authenticated request objects, SSH session objects, shell objects,
or sockets held open across calls. Each adapter documented below is
stateless *per read* — it stores only the connection PARAMETERS (or, for
HTTP, a pre-validated, fully fixed request-shape descriptor) needed to
issue a fresh, bounded read for each ``read_bounded_file()`` call (mirroring
``SSHExecutor``'s/``PrivEscEnumExecutor``'s pre-existing "no live session
held" discipline, memfabric Invariant 6 — executors, and by extension these
adapters, are stateless). The registry does not make anything *more*
persistent than before this refactor; it only gives the previously-inline
connection parameters a name (``capability_id``) so the objective layer
never needs to know which transport that name resolves to.

Phase 20 — ``DirectFileReadCapabilityAdapter`` is deliberately NOT a generic
HTTP client. It is constructed from a ``DirectFileReadPrimitive`` — a fully
fixed, pre-validated request shape (origin, endpoint template, method,
headers) that the operator supplies out of band (mirroring how
``--username``/``--password`` are operator-supplied, already-known-good
credentials for ``CredentialPlanner``/``SSHExecutor``, never autonomously
discovered by APEX). The ONLY thing that ever varies per call is the
bounded candidate path substituted into the template's ``{path}``
placeholder — the adapter structurally cannot be asked for a different
host, port, scheme, method, header set, or body. See the adapter's own
docstring for the full defense-in-depth request-shape enforcement.
"""
from __future__ import annotations

import asyncio
import logging
import shlex
import socket
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import httpx
import paramiko

from apex_host.verification.user_flag import is_bounded_candidate_path

if TYPE_CHECKING:
    from apex_host.config import ApexConfig
    from apex_host.tools.backend import ToolBackend

logger = logging.getLogger(__name__)

#: Schemes a direct-file-read primitive's origin may ever use. Deliberately
#: excludes "file", "ftp", "gopher", etc. — this is an HTTP(S)-only adapter,
#: never a generic URL fetcher.
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
#: HTTP methods a direct-file-read primitive may ever use. The operator's
#: configured method is validated against this allowlist at construction
#: time — never LLM- or planner-controlled.
_ALLOWED_METHODS: frozenset[str] = frozenset({"GET", "POST"})


@dataclass(slots=True)
class BoundedReadResult:
    """Transport-neutral result of one ``FlagReadCapability.read_bounded_file()``
    call.

    Deliberately NOT persisted directly — ``UserFlagExecutor`` consumes it,
    calls ``verify_user_flag()`` on ``.output``, and discards the raw value;
    only the verifier's own secret-free result fields (``verified``/
    ``value_digest``/``redacted_value``) ever leave the executor. ``output``
    must never be logged or written to the episodic log verbatim.

    Fields
    ------
    connected:
        True once the underlying access mechanism was successfully
        established (SSH auth succeeded / the HTTP request was sent and a
        response was received) — False means nothing was learned about the
        candidate path at all (a connection/auth/network-level failure), so
        the caller must not count the candidate as attempted.
    output:
        The raw (already byte-capped) read content. Only meaningful when
        ``connected`` is True.
    error:
        ``None`` on a fully successful read; otherwise a human-readable,
        secret-free description of what went wrong (connection failure,
        "no such file", a timeout, an HTTP status code, a rejected
        cross-origin redirect, ...). Never contains a header value, cookie,
        or full URL with query parameters.
    status_code:
        HTTP status code, when the transport is HTTP. ``None`` for
        non-HTTP transports (e.g. SSH).
    return_code:
        Process/command exit code, when the transport is a command
        execution (e.g. SSH's ``cat`` exit status). ``None`` for HTTP.
    bytes_received:
        Number of bytes actually read (bounded — never exceeds the
        configured maximum by more than one byte, used only to detect
        truncation).
    truncated:
        True when more data was available than the configured bound
        allowed the adapter to read.
    method:
        A short, transport-identifying string for audit/metrics purposes
        only (e.g. ``"ssh_cat"``, ``"http_get"``) — never used by any
        caller to branch on transport type.
    timed_out:
        True when the read did not complete within the configured
        timeout (Phase 22) — a distinct, structured signal from a remote
        service's own timeout detection, kept separate from ``error`` so
        callers never need to substring-match error text to detect a
        timeout. Defaults ``False`` for backward compatibility with
        adapters (SSH, Direct File Read) that only ever encoded timeout
        information in ``error`` text.
    """

    connected: bool
    output: str
    error: str | None
    status_code: int | None = None
    return_code: int | None = None
    bytes_received: int = 0
    truncated: bool = False
    method: str = ""
    timed_out: bool = False


class FlagReadCapability(Protocol):
    """The ONLY operation any capability adapter may expose.

    The objective layer (``apex_host/agents/user_flag_executor.py``) never
    calls anything beyond this — no arbitrary command execution, no
    interactive shell, no file listing, no arbitrary URL/method/header
    construction. A future adapter (Telnet, a local shell, ...) implements
    exactly this one method and nothing else is required to plug it into
    the existing planner/verifier/parser/report pipeline unchanged.
    """

    async def read_bounded_file(self, path: str) -> BoundedReadResult:
        """Attempt one bounded read of *path*. See ``BoundedReadResult``."""
        ...


class CapabilityRuntimeRegistry:
    """Runtime-only, in-process, per-engagement map of
    ``capability_id -> FlagReadCapability``.

    Never persisted to ``MemoryAPI``/the EKG — see module docstring. One
    instance lives in ``OrchestrationDeps``, constructed fresh per
    engagement (mirrors ``StallTracker``'s lifecycle exactly), and is
    populated by the orchestration layer (``apex_host.orchestration
    .dispatch_node.make_objective_node``) immediately before each objective
    turn, from whatever validated ``AccessCapability`` records the live EKG
    currently has — never by a planner (planners stay pure over
    subgraph/evidence data only, memfabric Invariant 7) and never by the
    executor (which only ever *looks up* an already-registered adapter).
    """

    def __init__(self) -> None:
        self._adapters: dict[str, FlagReadCapability] = {}

    def register(self, capability_id: str, adapter: FlagReadCapability) -> None:
        self._adapters[capability_id] = adapter

    def get(self, capability_id: str) -> FlagReadCapability | None:
        return self._adapters.get(capability_id)

    def has(self, capability_id: str) -> bool:
        return capability_id in self._adapters

    def ensure_ssh(
        self,
        capability_id: str,
        *,
        target: str,
        port: str,
        username: str,
        password: str,
        config: "ApexConfig",
    ) -> FlagReadCapability:
        """Idempotently register (and return) an ``SSHCapabilityAdapter`` for
        *capability_id*. A second call with the same ``capability_id``
        returns the existing adapter unchanged — registration never
        overwrites live state with a possibly-stale re-derivation mid-turn.
        """
        existing = self._adapters.get(capability_id)
        if existing is not None:
            return existing
        adapter: FlagReadCapability = SSHCapabilityAdapter(
            target=target, port=port, username=username, password=password, config=config,
        )
        self._adapters[capability_id] = adapter
        return adapter

    def ensure_direct_file_read(
        self, capability_id: str, *, primitive: "DirectFileReadPrimitive",
    ) -> FlagReadCapability:
        """Idempotently register (and return) a
        ``DirectFileReadCapabilityAdapter`` for *capability_id*, built from a
        already-constructed, already-validated ``DirectFileReadPrimitive``.

        Mirrors ``ensure_ssh``'s idempotency exactly — a second call with the
        same ``capability_id`` returns the existing adapter unchanged.
        Constructing the adapter performs NO network I/O — it is safe to
        call unconditionally once a validated capability node is known.
        """
        existing = self._adapters.get(capability_id)
        if existing is not None:
            return existing
        adapter: FlagReadCapability = DirectFileReadCapabilityAdapter(primitive)
        self._adapters[capability_id] = adapter
        return adapter

    def ensure_bounded_command(
        self, capability_id: str, *, primitive: "BoundedCommandReadPrimitive",
    ) -> FlagReadCapability:
        """Idempotently register (and return) a
        ``BoundedCommandCapabilityAdapter`` for *capability_id* (Phase 21),
        built from an already-constructed ``BoundedCommandReadPrimitive``.

        Mirrors ``ensure_ssh``/``ensure_direct_file_read``'s idempotency
        exactly. Constructing the adapter performs no execution — the
        underlying strategy is only ever invoked from
        ``read_bounded_file()``, once per verification attempt.
        """
        existing = self._adapters.get(capability_id)
        if existing is not None:
            return existing
        adapter: FlagReadCapability = BoundedCommandCapabilityAdapter(primitive)
        self._adapters[capability_id] = adapter
        return adapter


# ---------------------------------------------------------------------------
# SSH adapter — the original concrete adapter (Phase 18 / access-capability
# refactor).
#
# Behavior is unchanged from the pre-refactor UserFlagExecutor: one fresh
# paramiko.SSHClient() per read_bounded_file() call, closed in a finally
# block, allow_agent=False, look_for_keys=False, no SFTP/port-forwarding.
# The password is held only as a plain constructor argument (an in-memory
# Python string, exactly as it was already held by the pre-refactor
# executor's task.params) — never logged, never returned from
# read_bounded_file(), never written anywhere the EKG or a report could see.
# ---------------------------------------------------------------------------

class SSHCapabilityAdapter:
    """``FlagReadCapability`` adapter backed by SSH (Paramiko).

    Stateless per read: holds only connection parameters, never a live
    ``SSHClient``/socket across calls (memfabric Invariant 6).
    """

    def __init__(
        self, *, target: str, port: str, username: str, password: str, config: "ApexConfig",
    ) -> None:
        self._target = target
        self._port = port
        self._username = username
        self._password = password
        self._connect_timeout = float(getattr(config, "ssh_connect_timeout_seconds", 10.0))
        self._auth_timeout = float(getattr(config, "ssh_auth_timeout_seconds", 10.0))
        self._command_timeout = float(getattr(config, "ssh_command_timeout_seconds", 10.0))
        self._max_bytes = int(getattr(config, "user_flag_max_output_bytes", 4096) or 4096)

    async def read_bounded_file(self, path: str) -> BoundedReadResult:
        try:
            port = int(self._port)
        except ValueError:
            port = 22
        connected, stdout, error = await asyncio.to_thread(
            _read_ssh_file_sync,
            self._target, port, self._username, self._password, path,
            self._connect_timeout, self._auth_timeout, self._command_timeout, self._max_bytes,
        )
        return BoundedReadResult(
            connected=connected, output=stdout, error=error,
            return_code=None, bytes_received=len(stdout.encode("utf-8", errors="replace")),
            truncated=False, method="ssh_cat",
        )


def _read_ssh_file_sync(
    target: str,
    port: int,
    username: str,
    password: str,
    path: str,
    connect_timeout: float,
    auth_timeout: float,
    command_timeout: float,
    max_bytes: int,
) -> tuple[bool, str, str | None]:
    """Synchronous Paramiko session — run via ``asyncio.to_thread`` only.

    Byte-for-byte the same behavior as the pre-refactor
    ``UserFlagExecutor._read_candidate_sync`` (renamed/relocated, not
    changed): exactly one ``connect()`` and, on success, exactly one
    ``exec_command("cat -- <path>")`` call. The client is always closed.
    Never raises — every Paramiko/socket exception is caught here and
    converted into an error string. Never returns or logs the password.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            client.connect(
                hostname=target,
                port=port,
                username=username,
                password=password,
                timeout=connect_timeout,
                banner_timeout=connect_timeout,
                auth_timeout=auth_timeout,
                allow_agent=False,
                look_for_keys=False,
                pkey=None,
                key_filename=None,
            )
        except paramiko.AuthenticationException:
            return False, "", "ssh authentication rejected"
        except socket.timeout:
            return False, "", "ssh connect/auth timed out"
        except (OSError, paramiko.SSHException) as exc:
            return False, "", f"ssh connection failed: {type(exc).__name__}"

        command = "cat -- " + shlex.quote(path)
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=command_timeout)
            out_bytes = stdout.read(max_bytes)
            err_bytes = stderr.read(max_bytes)
            exit_status = stdout.channel.recv_exit_status()
        except socket.timeout:
            return True, "", "user-flag read command timed out"
        except paramiko.SSHException as exc:
            return True, "", f"ssh protocol error running read command: {type(exc).__name__}"

        out_text = out_bytes.decode("utf-8", errors="replace")
        err_text = err_bytes.decode("utf-8", errors="replace").strip()
        if exit_status != 0:
            return True, "", (err_text or f"read command exited {exit_status}")
        return True, out_text, None
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Direct file-read adapter (Phase 20) — the second concrete adapter.
#
# NOT a generic HTTP client / SSRF executor. Every request this adapter ever
# issues has a request shape (origin, endpoint template, method, headers)
# that was fixed at construction time from an operator-supplied
# ``DirectFileReadPrimitive`` — never from a planner, an LLM, or the
# objective task itself. The ONLY thing that varies per call is the bounded
# candidate path substituted into the template's one ``{path}`` placeholder.
# See docs/user-flag-objective.md §17 for the full design rationale.
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class DirectFileReadPrimitive:
    """A fully fixed, pre-validated HTTP file-read request shape.

    Represents "an operator has already manually confirmed (through
    authorized testing — an arbitrary file read, an LFI, a path-traversal
    primitive, an authenticated file-download endpoint, an XSS-assisted
    workflow that resolves to a bounded file read, ...) that requesting
    this exact origin/endpoint/method/headers with a substituted path
    returns that file's content." APEX never discovers, probes for, or
    autonomously exploits this primitive — it only re-issues the ALREADY
    -validated request shape, once per read, with the ONE bounded variable
    (the candidate path) substituted in.

    Fields
    ------
    capability_id:
        The ``access_capability`` EKG node ID this primitive backs — used
        only for logging/audit correlation, never for control flow.
    target_origin:
        ``scheme://host[:port]`` ONLY — no path, no query, no userinfo.
        Every request (and every followed redirect, if any) must resolve to
        exactly this origin or it is rejected.
    endpoint_template:
        A path+query template containing exactly one ``{path}``
        placeholder (e.g. ``"/download.php?file={path}"`` or
        ``"/files/{path}"``). Nothing else about the request is ever
        templated or substitutable.
    method:
        ``"GET"`` or ``"POST"`` only (validated in ``__post_init__``).
    headers:
        A fixed, operator-supplied header mapping (e.g. a pre-obtained
        session cookie or bearer token VALUE) — runtime-only, never
        written to the EKG, never included in any report or episode.
    timeout_seconds / max_response_bytes:
        Bounded read limits, mirroring ``SSHCapabilityAdapter``'s own
        timeout/output-size-bounding discipline.
    allow_redirects:
        Default ``False`` — "be extremely conservative with redirects."
        When ``True``, at most ``max_redirect_hops`` same-origin redirects
        are followed (never a scheme/host/port change, never
        loopback/metadata/private-infrastructure hosts unless that exact
        origin IS the authorized target).
    max_redirect_hops:
        Hard ceiling on redirects ever followed in one call. Defaults to 0
        (no redirects followed at all) unless ``allow_redirects`` is set,
        in which case it defaults to 1.
    allowed_filenames:
        The SAME operator-configured allowlist
        (``ApexConfig.user_flag_candidate_filenames``) the policy layer and
        ``is_bounded_candidate_path()`` already enforce — the adapter
        re-validates independently rather than trusting the caller.
    """

    capability_id: str
    target_origin: str
    endpoint_template: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 15.0
    max_response_bytes: int = 4096
    allow_redirects: bool = False
    max_redirect_hops: int = 0
    allowed_filenames: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        method = self.method.upper().strip()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"unsupported direct-file-read method {self.method!r}")
        self.method = method
        origin_parts = urlsplit(self.target_origin)
        if origin_parts.scheme not in _ALLOWED_SCHEMES:
            raise ValueError(f"unsupported direct-file-read scheme {origin_parts.scheme!r}")
        if origin_parts.username or origin_parts.password:
            raise ValueError("direct-file-read target_origin must not contain userinfo")
        if origin_parts.path or origin_parts.query or origin_parts.fragment:
            raise ValueError("direct-file-read target_origin must be scheme://host[:port] only")
        if "{path}" not in self.endpoint_template:
            raise ValueError("direct-file-read endpoint_template must contain exactly one {path} placeholder")
        if self.allow_redirects and self.max_redirect_hops <= 0:
            self.max_redirect_hops = 1


def _same_origin(a: str, b: str) -> bool:
    """True when *a* and *b* share scheme+host+port exactly (case-insensitive
    scheme/host). Used to enforce "every redirect must remain on the exact
    authorized origin" — never a scheme, host, or port change."""
    pa, pb = urlsplit(a), urlsplit(b)
    return (
        pa.scheme.lower() == pb.scheme.lower()
        and (pa.hostname or "").lower() == (pb.hostname or "").lower()
        and pa.port == pb.port
    )


class DirectFileReadCapabilityAdapter:
    """``FlagReadCapability`` adapter backed by one pre-validated,
    application-layer HTTP file-read primitive.

    Satisfies the ``FlagReadCapability`` protocol's ONE method only —
    ``ObjectivePlanner``/``UserFlagExecutor`` never gain any generic
    request-execution capability through this adapter. Every safety check
    below runs on EVERY call, independent of whatever validation already
    happened at capability-derivation time (defense in depth — "the adapter
    must reject on its own, never relying on the caller having already
    validated," mirroring ``is_bounded_candidate_path()``'s own convention).
    """

    def __init__(
        self, primitive: DirectFileReadPrimitive, *, transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._primitive = primitive
        # Test-only seam: a real engagement never supplies `transport` (the
        # default `None` uses httpx's real network transport). Tests inject
        # `httpx.MockTransport` here — the SAME dependency-injection pattern
        # already used throughout this codebase (e.g. `apex_tool_service`'s
        # own httpx-based tests) — never a production code path.
        self._transport = transport

    async def read_bounded_file(self, path: str) -> BoundedReadResult:
        primitive = self._primitive
        if not is_bounded_candidate_path(path, allowed_filenames=primitive.allowed_filenames):
            return BoundedReadResult(
                connected=False, output="", error="candidate path failed bounded-path validation",
                method="http_get" if primitive.method == "GET" else "http_post",
            )

        url = _substitute_path(primitive.endpoint_template, primitive.target_origin, path)
        if url is None:
            return BoundedReadResult(
                connected=False, output="",
                error="request-shape construction rejected (path substitution produced an unsafe URL)",
                method="http_get" if primitive.method == "GET" else "http_post",
            )

        method_label = "http_get" if primitive.method == "GET" else "http_post"
        timeout = httpx.Timeout(primitive.timeout_seconds)
        try:
            async with httpx.AsyncClient(
                follow_redirects=False, timeout=timeout, transport=self._transport,
            ) as client:
                hops_remaining = primitive.max_redirect_hops if primitive.allow_redirects else 0
                current_url = url
                while True:
                    request = client.build_request(primitive.method, current_url, headers=primitive.headers)
                    response = await client.send(request, stream=True)
                    try:
                        if response.is_redirect and hops_remaining > 0:
                            location = response.headers.get("location", "")
                            next_url = _resolve_redirect(current_url, location, primitive.target_origin)
                            if next_url is None:
                                return BoundedReadResult(
                                    connected=True, output="",
                                    error="redirect target outside the authorized origin was rejected",
                                    status_code=response.status_code, method=method_label,
                                )
                            hops_remaining -= 1
                            current_url = next_url
                            continue
                        if response.is_redirect:
                            return BoundedReadResult(
                                connected=True, output="",
                                error="redirect received but redirects are disabled for this capability",
                                status_code=response.status_code, method=method_label,
                            )

                        output, truncated = await _read_bounded_body(response, primitive.max_response_bytes)
                        if truncated:
                            # Oversized responses are an unambiguous rejection,
                            # never a truncated candidate — a truncated prefix
                            # could coincidentally resemble a plausible (but
                            # WRONG) flag-shaped token to the verifier. This
                            # also bounds memory: _read_bounded_body itself
                            # never reads past max_response_bytes + 1.
                            return BoundedReadResult(
                                connected=True, output="",
                                error="response exceeds the maximum bounded size",
                                status_code=response.status_code,
                                bytes_received=len(output.encode("utf-8", errors="replace")),
                                truncated=True, method=method_label,
                            )
                        error = None if response.status_code < 400 else f"http status {response.status_code}"
                        return BoundedReadResult(
                            connected=True, output=output, error=error,
                            status_code=response.status_code,
                            bytes_received=len(output.encode("utf-8", errors="replace")),
                            truncated=False, method=method_label,
                        )
                    finally:
                        await response.aclose()
        except httpx.TimeoutException:
            return BoundedReadResult(
                connected=False, output="", error="direct file-read request timed out", method=method_label,
            )
        except httpx.HTTPError as exc:
            return BoundedReadResult(
                connected=False, output="",
                error=f"direct file-read request failed: {type(exc).__name__}", method=method_label,
            )


def _substitute_path(endpoint_template: str, target_origin: str, path: str) -> str | None:
    """Substitute *path* into the template's ``{path}`` placeholder and
    return the resulting absolute URL, or ``None`` if the result would not
    resolve to *target_origin* exactly (defense in depth — the upstream
    charset restriction on *path* already excludes URL-breaking characters
    like ``@``/``:``/whitespace, but this never trusts that alone)."""
    encoded = quote(path, safe="/")
    endpoint = endpoint_template.replace("{path}", encoded)
    candidate = target_origin.rstrip("/") + endpoint
    if not _same_origin(candidate, target_origin):
        return None
    parts = urlsplit(candidate)
    if parts.username or parts.password:
        return None
    return urlunsplit(parts)


def _resolve_redirect(current_url: str, location: str, target_origin: str) -> str | None:
    """Resolve a ``Location`` header against *current_url* and return the
    absolute URL only if it remains on *target_origin* exactly — rejects
    any scheme/host/port change, any userinfo, and any non-http(s) scheme."""
    if not location:
        return None
    resolved = urljoin(current_url, location)
    parts = urlsplit(resolved)
    if parts.scheme not in _ALLOWED_SCHEMES:
        return None
    if parts.username or parts.password:
        return None
    if not _same_origin(resolved, target_origin):
        return None
    return resolved


async def _read_bounded_body(response: "object", max_bytes: int) -> tuple[str, bool]:
    """Read up to ``max_bytes + 1`` decoded bytes from *response* (an
    ``httpx.Response`` opened with ``stream=True``), never more — bounds
    both wire size and decompressed size, since httpx decodes
    gzip/deflate/br lazily as ``aiter_bytes()`` is iterated. Returns
    ``(text, truncated)``; ``truncated=True`` means more data was available
    than the bound allowed reading."""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    async for chunk in response.aiter_bytes():  # type: ignore[attr-defined]
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            truncated = True
            break
    raw = b"".join(chunks)[: max_bytes + 1]
    return raw.decode("utf-8", errors="replace"), truncated


# ---------------------------------------------------------------------------
# Bounded command-execution adapter (Phase 21).
#
# Unlike DirectFileReadCapabilityAdapter (a fixed HTTP request shape),
# BoundedCommandCapabilityAdapter delegates the actual "how do I read a
# file" mechanism to an injected, narrow BoundedCommandReadStrategy — this
# lets a single adapter class service `local_shell` and `remote_command`
# capabilities alike (they differ only in which strategy/backend was
# constructed for them, never in the adapter's own logic). The strategy
# Protocol exposes exactly one operation, read_file(path, ...) — never a
# generic execute()/run_shell()/exec() — so no arbitrary command string can
# ever cross from the objective layer into a real execution context.
#
# CLAUDE.md §13.6 ("No raw child-process spawning outside
# apex_host/tools/runner.py") is honored by construction: the one
# reference strategy shipped here, ToolBackendCommandReadStrategy, never
# launches a process itself — it delegates to an injected
# `apex_host.tools.backend.ToolBackend` (the SAME already-safety-gated,
# already-dry-run-aware execution seam every other command in this
# codebase goes through), issuing a single FIXED argv command
# (`cat -- <path>`) — never a shell string, never operator- or
# LLM-controlled beyond the one bounded candidate path.
# ---------------------------------------------------------------------------


class BoundedCommandReadStrategy(Protocol):
    """The ONLY operation a command-execution runtime strategy may expose
    to ``BoundedCommandCapabilityAdapter``.

    Deliberately narrower than ``FlagReadCapability`` is wide: there is no
    ``execute()``/``run_shell()``/``send_command()`` here, and there never
    may be one. A strategy implementation may internally hold a reference
    to a much broader execution backend (a ``ToolBackend``, an existing
    authenticated web/remote session, ...), but it must expose only this
    one bounded, path-scoped method to the capability layer — the broader
    backend object itself is never stored in ``BoundedCommandReadPrimitive``
    or returned from any method here.
    """

    async def read_file(
        self, path: str, *, timeout_seconds: float, max_output_bytes: int,
    ) -> BoundedReadResult:
        """Attempt one bounded, read-only command execution against *path*.

        *path* is the only variable input — the concrete command shape
        (executable, fixed flags, working directory, environment) is
        entirely the strategy implementation's own fixed configuration,
        never supplied by the caller."""
        ...


@dataclass(slots=True)
class BoundedCommandReadPrimitive:
    """A fixed, pre-validated command-read strategy binding for one
    ``access_capability`` (Phase 21) — the command-execution analogue of
    ``DirectFileReadPrimitive``.

    ``strategy`` is a runtime-only object (never JSON-serializable, never
    persisted to the EKG or any checkpoint) — it is constructed fresh, per
    engagement, by the orchestration layer
    (``apex_host.orchestration.dispatch_node._register_bounded_command_adapter``)
    and held only inside this primitive, which itself lives only inside the
    in-process ``CapabilityRuntimeRegistry``.

    Immutable after construction (``__post_init__`` validates and never
    mutates); the only per-call variable is the candidate path passed to
    ``BoundedCommandCapabilityAdapter.read_bounded_file()``.
    """

    capability_id: str
    strategy: BoundedCommandReadStrategy
    allowed_filenames: frozenset[str] = field(default_factory=frozenset)
    timeout_seconds: float = 15.0
    max_output_bytes: int = 4096

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("BoundedCommandReadPrimitive.timeout_seconds must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("BoundedCommandReadPrimitive.max_output_bytes must be positive")


class BoundedCommandCapabilityAdapter:
    """``FlagReadCapability`` adapter backed by a narrow, injected
    ``BoundedCommandReadStrategy`` (Phase 21).

    Its only objective-facing public method is ``read_bounded_file(path)``
    — there is no second method, and it never exposes the underlying
    strategy or any broader execution backend to a caller. On every call:

    1. Re-validates *path* via ``is_bounded_candidate_path()`` — defense in
       depth on top of whatever validation the caller (``UserFlagExecutor``,
       the policy layer) already performed; the adapter never trusts a
       caller to have already validated.
    2. Invokes ``self._primitive.strategy.read_file(path, ...)`` under an
       outer ``asyncio.wait_for`` timeout (belt-and-suspenders on top of
       whatever internal timeout the strategy itself applies).
    3. Re-enforces the maximum output size on the strategy's own returned output —
       an oversized result is rejected outright (``output=""``, a bounded
       ``truncated=True`` result), mirroring
       ``DirectFileReadCapabilityAdapter``'s identical "never partially
       accept a truncated prefix" invariant, never partially accepted.
    4. Never logs, returns, or persists the raw output beyond the
       ``BoundedReadResult`` handed back to ``UserFlagExecutor`` — same
       lifecycle as every other adapter in this module.

    Exceptions raised by the strategy (a safety-gate ``ValueError``, a
    backend-unavailable error, ...) are caught and mapped to a bounded,
    sanitized error category — the adapter never raises.
    """

    def __init__(self, primitive: BoundedCommandReadPrimitive) -> None:
        self._primitive = primitive

    async def read_bounded_file(self, path: str) -> BoundedReadResult:
        if not is_bounded_candidate_path(path, allowed_filenames=self._primitive.allowed_filenames):
            return BoundedReadResult(
                connected=False, output="", error="candidate path failed bounded-path validation",
            )

        try:
            result = await asyncio.wait_for(
                self._primitive.strategy.read_file(
                    path,
                    timeout_seconds=self._primitive.timeout_seconds,
                    max_output_bytes=self._primitive.max_output_bytes,
                ),
                timeout=self._primitive.timeout_seconds + 5.0,
            )
        except asyncio.TimeoutError:
            return BoundedReadResult(connected=False, output="", error="timeout: bounded command read timed out")
        except ValueError as exc:
            # The one exception type command-execution safety gates (e.g.
            # apex_host.tools.safety.check_command) are expected to raise —
            # never let it propagate past this boundary.
            return BoundedReadResult(
                connected=False, output="",
                error=f"execution_context_unavailable: {type(exc).__name__}",
            )
        except Exception as exc:  # noqa: BLE001 - adapters never raise past this boundary
            logger.debug("bounded command strategy raised %s", type(exc).__name__)
            return BoundedReadResult(
                connected=False, output="",
                error=f"execution_context_unavailable: {type(exc).__name__}",
            )

        if len(result.output.encode("utf-8", errors="replace")) > self._primitive.max_output_bytes:
            return BoundedReadResult(
                connected=result.connected, output="",
                error="oversized_output: response exceeds the maximum bounded size",
                return_code=result.return_code, truncated=True, method=result.method,
            )
        return result


class ToolBackendCommandReadStrategy:
    """The one concrete, real ``BoundedCommandReadStrategy`` reference
    implementation (Phase 21; refactored in Phase 22 to prefer a dedicated
    bounded-read backend method) — wraps an existing, already-safety-gated
    ``apex_host.tools.backend.ToolBackend`` (local or remote) rather than
    launching a child process directly, so this file never becomes a
    second command-execution entry point (CLAUDE.md §13.6).

    Phase 22 — the PREFERRED path: when the injected *backend* implements
    ``apex_host.tools.backend.BoundedFileReadBackend`` (checked via a real,
    checked ``isinstance()`` test against a ``@runtime_checkable`` Protocol,
    never blind duck-typing), this strategy calls
    ``backend.read_bounded_file(target, path, ...)`` directly — it no
    longer submits ``cat -- <path>`` through the backend's generic
    ``execute()`` method at all in this case. The fixed argv construction
    now lives inside each backend's own ``read_bounded_file()``
    implementation (``LocalToolBackend``: still ``cat -- <path>`` via its
    own trusted ``execute()`` call; ``RemoteToolBackend``: the tool
    service's dedicated ``POST /v1/bounded-file-read`` operation, which
    constructs the fixed argv server-side — see
    ``apex_tool_service/executor.py::execute_bounded_file_read``).

    FALLBACK path (preserved for backward compatibility with test doubles
    that implement only ``execute()``, e.g. a minimal fake ``ToolBackend``
    used in unit tests): when *backend* does NOT implement
    ``BoundedFileReadBackend``, this strategy falls back to its original
    Phase 21 behavior — ``backend.execute("cat", ["--", path], ...)`` —
    unchanged. This is the ONLY place ``cat`` is still submitted through a
    generic ``execute()`` call from this strategy; every real backend
    shipped in this codebase (``DryRunToolBackend``, ``LocalToolBackend``,
    ``RemoteToolBackend``) implements the preferred path.

    Dry-run is honored transitively and redundantly: ``UserFlagExecutor``
    already short-circuits before ever resolving an adapter when
    ``config.dry_run`` is True, and separately, whichever ``ToolBackend``
    the caller injected here (via ``apex_host.tools.backend
    .select_runtime_backend(config)``) is *itself* guaranteed to be a
    ``DryRunToolBackend`` whenever ``config.dry_run`` is True — so even a
    hypothetical future caller that bypassed the executor's own dry-run
    gate could not reach a real command execution through this strategy.
    """

    _FIXED_TOOL: str = "cat"

    def __init__(self, *, backend: "ToolBackend", target: str = "") -> None:
        self._backend = backend
        self._target = target

    async def read_file(
        self, path: str, *, timeout_seconds: float, max_output_bytes: int,
    ) -> BoundedReadResult:
        from apex_host.tools.backend import BoundedFileReadBackend

        if isinstance(self._backend, BoundedFileReadBackend):
            return await self._backend.read_bounded_file(
                self._target, path, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
            )
        return await self._read_file_via_generic_execute(
            path, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
        )

    async def _read_file_via_generic_execute(
        self, path: str, *, timeout_seconds: float, max_output_bytes: int,
    ) -> BoundedReadResult:
        """FALLBACK path (Phase 21 behavior, unchanged) — used only when
        *backend* does not implement ``BoundedFileReadBackend`` (e.g. a
        minimal test double implementing only ``execute()``)."""
        result = await self._backend.execute(self._FIXED_TOOL, ["--", path], timeout_seconds=timeout_seconds)
        success = result.returncode == 0 and not result.timed_out
        output = result.stdout if success else ""
        error: str | None = None
        if result.timed_out:
            error = "timeout: bounded command read timed out"
        elif not success:
            # cat's own stderr for a missing/unreadable file (e.g. "No such
            # file or directory", "Permission denied") is not sensitive —
            # it never contains anything beyond the fixed error phrase and
            # the already-known candidate path — and is exactly the kind
            # of content verify_user_flag()'s own error-marker check
            # already knows how to reject. Bounded defensively regardless.
            error = (result.error or result.stderr or "non-zero exit")[:200]
        return BoundedReadResult(
            connected=not result.timed_out,
            output=output,
            error=error,
            return_code=result.returncode,
            bytes_received=len(output.encode("utf-8", errors="replace")),
            truncated=False,
            method=f"cmd_{result.backend or 'local'}",
        )
