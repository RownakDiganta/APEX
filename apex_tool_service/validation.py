# validation.py
# Mechanical request validation: allowlist check, argument/stdin size limits, shell-metacharacter and control-character rejection, timeout bounds.
"""Request validation for apex_tool_service.

This module intentionally duplicates (rather than imports) the small,
stable shell-metacharacter list also enforced by
``apex_host/tools/safety.py::check_command`` — the two packages are kept
independently deployable (``docs/tool-execution-architecture.md`` "Keep the
tool service separated from the APEX orchestration logic"), so this is a
deliberate, documented duplication of a handful of literal characters, not
a shared dependency.

Every check here runs *before* any subprocess is created
(``apex_tool_service/executor.py``). ``RequestValidationError`` carries a
client-safe ``detail`` message only — never an internal traceback, path, or
stack detail.
"""
from __future__ import annotations

import ipaddress
import math
import re

from apex_tool_service.allowlist import is_allowed, resolve_binary
from apex_tool_service.settings import ServiceSettings

# Matches apex_host/tools/safety.py::_SHELL_OPERATORS (duplicated on purpose — see module docstring).
_SHELL_OPERATORS: tuple[str, ...] = (";", "&&", "||", "|", ">>", ">", "<", "$(", "`")
_CONTROL_CHARS: tuple[str, ...] = ("\n", "\r", "\x00")

# Phase 22 — mirrors (duplicated on purpose, same rationale as
# `_SHELL_OPERATORS` above: this package never imports `apex_host`)
# `apex_host.verification.user_flag._PATH_CHAR_RE` / `is_bounded_candidate_path`
# EXACTLY: absolute path, conservative charset, bounded length. A dedicated
# parity test (`tests/apex_tool_service/test_bounded_file_read.py`) proves
# the two validators agree on the same set of inputs — keep this regex in
# sync with `apex_host/verification/user_flag.py` if that one ever changes.
_BOUNDED_PATH_RE = re.compile(r"^/[A-Za-z0-9_./\-]{1,254}$")


class RequestValidationError(Exception):
    """Raised for any mechanical validation failure. ``detail`` is client-safe."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _check_token_safety(token: str, *, label: str) -> None:
    for op in _SHELL_OPERATORS:
        if op in token:
            raise RequestValidationError(
                f"{label} contains shell operator {op!r}; arguments are passed as "
                "argv lists, not shell strings"
            )
    for ch in _CONTROL_CHARS:
        if ch in token:
            name = {"\n": "newline", "\r": "carriage return", "\x00": "null byte"}[ch]
            raise RequestValidationError(f"{label} contains a disallowed {name}")


def resolve_and_validate_tool(tool: str) -> str:
    """Return the resolved binary name for *tool*, or raise ``RequestValidationError``."""
    if not tool or not isinstance(tool, str):
        raise RequestValidationError("'tool' must be a non-empty string")
    _check_token_safety(tool, label="'tool'")
    if not is_allowed(tool):
        raise RequestValidationError(f"tool {tool!r} is not in the server allowlist")
    binary = resolve_binary(tool)
    assert binary is not None  # is_allowed() already guarantees this
    return binary


def validate_arguments(arguments: list[str], settings: ServiceSettings) -> None:
    if not isinstance(arguments, list):
        raise RequestValidationError("'arguments' must be a list of strings")
    if len(arguments) > settings.max_arguments:
        raise RequestValidationError(
            f"too many arguments: {len(arguments)} > max_arguments={settings.max_arguments}"
        )
    total_bytes = 0
    for i, arg in enumerate(arguments):
        if not isinstance(arg, str):
            raise RequestValidationError(f"argument[{i}] must be a string")
        arg_bytes = len(arg.encode("utf-8", errors="surrogatepass"))
        if len(arg) > settings.max_argument_length:
            raise RequestValidationError(
                f"argument[{i}] length {len(arg)} exceeds "
                f"max_argument_length={settings.max_argument_length}"
            )
        _check_token_safety(arg, label=f"argument[{i}]")
        total_bytes += arg_bytes
    if total_bytes > settings.max_total_argument_bytes:
        raise RequestValidationError(
            f"total argument size {total_bytes} bytes exceeds "
            f"max_total_argument_bytes={settings.max_total_argument_bytes}"
        )


def validate_stdin(stdin: str | None, settings: ServiceSettings) -> None:
    if stdin is None:
        return
    if not isinstance(stdin, str):
        raise RequestValidationError("'stdin' must be a string or null")
    size = len(stdin.encode("utf-8", errors="surrogatepass"))
    if size > settings.max_stdin_bytes:
        raise RequestValidationError(
            f"stdin size {size} bytes exceeds max_stdin_bytes={settings.max_stdin_bytes}"
        )


def resolve_timeout(timeout_seconds: float | None, settings: ServiceSettings) -> float:
    """Return the effective timeout, or raise if an explicit value is out of bounds.

    An omitted (``None``) timeout uses ``settings.default_timeout_seconds`` and
    is never rejected. An *explicit* out-of-bounds value is rejected rather
    than silently clamped — the caller should be told, not guessed for.
    """
    if timeout_seconds is None:
        return settings.default_timeout_seconds
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
        raise RequestValidationError("'timeout_seconds' must be a number")
    if timeout_seconds < settings.min_timeout_seconds:
        raise RequestValidationError(
            f"timeout_seconds={timeout_seconds} is below "
            f"min_timeout_seconds={settings.min_timeout_seconds}"
        )
    if timeout_seconds > settings.max_timeout_seconds:
        raise RequestValidationError(
            f"timeout_seconds={timeout_seconds} exceeds "
            f"max_timeout_seconds={settings.max_timeout_seconds}"
        )
    return float(timeout_seconds)


# ---------------------------------------------------------------------------
# Phase 22 — dedicated bounded-file-read validation (POST /v1/bounded-file-read).
#
# Independent of everything above: this operation does not go through
# `resolve_and_validate_tool`/`ALLOWED_TOOLS` at all — it is a structurally
# different, narrower capability with its own validation surface.
# ---------------------------------------------------------------------------


def validate_bounded_path(path: str, *, allowed_basenames: tuple[str, ...]) -> str:
    """Validate *path* as a bounded candidate file-read target.

    Mirrors ``apex_host.verification.user_flag.is_bounded_candidate_path``'s
    invariants exactly (absolute POSIX path, conservative charset, no ``..``
    traversal segment, approved basename) — this service performs this
    check independently rather than trusting apex_host's own validation,
    since a caller must never be trusted to have already validated (defense
    in depth). Returns the validated path unchanged, or raises
    ``RequestValidationError``.
    """
    if not path or not isinstance(path, str):
        raise RequestValidationError("'path' must be a non-empty string")
    if _BOUNDED_PATH_RE.match(path) is None:
        raise RequestValidationError(
            "'path' must be an absolute POSIX path using only a conservative "
            "character set, bounded to 254 characters"
        )
    if ".." in path.split("/"):
        raise RequestValidationError("'path' must not contain a '..' traversal segment")
    basename = path.rsplit("/", 1)[-1]
    if not basename or basename not in allowed_basenames:
        raise RequestValidationError(
            f"basename {basename!r} is not in the server's allowed_flag_basenames"
        )
    return path


def validate_target_authorized(target: str, *, authorized_cidrs: tuple[str, ...]) -> str:
    """Validate that *target* is a well-formed IP address falling within at
    least one of *authorized_cidrs*.

    Rejects: missing/empty target, a malformed (non-IP, hostname, URL-like)
    target, and any syntactically valid IP that does not fall within a
    configured CIDR — this naturally rejects loopback, link-local, cloud
    metadata endpoints (``169.254.169.254``), and unrelated private/public
    networks by default, since none of them fall within the default
    ``10.129.0.0/16`` HTB lab range unless an operator has explicitly
    reconfigured ``authorized_cidrs`` to include them (e.g. for local
    testing) — there is no separate hardcoded blocklist to bypass or
    maintain.
    """
    if not target or not isinstance(target, str):
        raise RequestValidationError("'target' must be a non-empty string")
    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError:
        raise RequestValidationError(f"'target' {target!r} is not a well-formed IP address") from None
    for cidr in authorized_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue  # a malformed configured CIDR is skipped, never crashes the request
        if address in network:
            return target
    raise RequestValidationError(
        f"'target' {target!r} is not within any authorized CIDR {list(authorized_cidrs)!r}"
    )


def resolve_bounded_read_limits(
    requested_timeout_seconds: float | None,
    requested_max_output_bytes: int | None,
    settings: ServiceSettings,
) -> tuple[float, int]:
    """Return the effective ``(timeout_seconds, max_output_bytes)`` for a
    bounded-file-read request: ``min(requested, service_hard_limit)`` for
    each, never the other way around. Rejects malformed requested values
    (zero, negative, NaN, infinity, non-integer byte cap) rather than
    silently coercing them.
    """
    if requested_timeout_seconds is None:
        timeout_seconds = settings.bounded_read_timeout_seconds
    else:
        if not isinstance(requested_timeout_seconds, (int, float)) or isinstance(
            requested_timeout_seconds, bool
        ):
            raise RequestValidationError("'timeout_seconds' must be a number")
        if math.isnan(requested_timeout_seconds) or math.isinf(requested_timeout_seconds):
            raise RequestValidationError("'timeout_seconds' must be finite")
        if requested_timeout_seconds <= 0:
            raise RequestValidationError("'timeout_seconds' must be positive")
        timeout_seconds = min(float(requested_timeout_seconds), settings.bounded_read_timeout_seconds)

    if requested_max_output_bytes is None:
        max_output_bytes = settings.bounded_read_max_bytes
    else:
        if not isinstance(requested_max_output_bytes, int) or isinstance(requested_max_output_bytes, bool):
            raise RequestValidationError("'max_output_bytes' must be an integer")
        if requested_max_output_bytes <= 0:
            raise RequestValidationError("'max_output_bytes' must be positive")
        max_output_bytes = min(requested_max_output_bytes, settings.bounded_read_max_bytes)

    return timeout_seconds, max_output_bytes
