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

from apex_tool_service.allowlist import is_allowed, resolve_binary
from apex_tool_service.settings import ServiceSettings

# Matches apex_host/tools/safety.py::_SHELL_OPERATORS (duplicated on purpose — see module docstring).
_SHELL_OPERATORS: tuple[str, ...] = (";", "&&", "||", "|", ">>", ">", "<", "$(", "`")
_CONTROL_CHARS: tuple[str, ...] = ("\n", "\r", "\x00")


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
