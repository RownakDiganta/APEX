# auth.py
# Bearer-token authentication for POST /v1/execute — timing-safe comparison, fail-closed when no server token is configured, never logs the supplied token.
"""Bearer-token authentication for ``POST /v1/execute``.

``/health`` is intentionally unauthenticated (see
``docs/kali-tool-service.md`` "Authentication" for the documented decision)
— it exposes only tool-name-availability booleans, no secrets, no paths, no
environment variables.

Fail-closed rule: if the server has no token configured
(``ServiceSettings.token is None``), every call to ``require_bearer_token``
raises ``AuthResult(status=AuthStatus.SERVICE_MISCONFIGURED, ...)``
regardless of what the client sends — there is no valid credential to
compare against, so "no token configured" must never be treated as "accept
anything."

The supplied token is never logged, in either the success or failure path.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import Enum

from apex_tool_service.settings import ServiceSettings

_BEARER_PREFIX = "Bearer "


class AuthStatus(str, Enum):
    ok = "ok"
    missing_header = "missing_header"
    malformed_header = "malformed_header"
    invalid_token = "invalid_token"
    service_misconfigured = "service_misconfigured"


@dataclass(slots=True, frozen=True)
class AuthResult:
    status: AuthStatus

    @property
    def is_authenticated(self) -> bool:
        return self.status is AuthStatus.ok


def check_bearer_token(authorization: str | None, settings: ServiceSettings) -> AuthResult:
    """Evaluate an ``Authorization`` header against *settings*.

    Never raises. Never includes the supplied or configured token in the
    returned ``AuthResult`` — callers must not log ``authorization`` either.
    """
    if not settings.token:
        # Fail closed: no valid credential exists to compare against.
        return AuthResult(AuthStatus.service_misconfigured)
    if not authorization:
        return AuthResult(AuthStatus.missing_header)
    if not authorization.startswith(_BEARER_PREFIX):
        return AuthResult(AuthStatus.malformed_header)
    supplied = authorization[len(_BEARER_PREFIX):]
    if not supplied:
        return AuthResult(AuthStatus.malformed_header)
    # Timing-safe comparison — never a plain `==`.
    if not hmac.compare_digest(supplied, settings.token):
        return AuthResult(AuthStatus.invalid_token)
    return AuthResult(AuthStatus.ok)
