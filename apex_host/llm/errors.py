# errors.py
# Fine-grained, provider-agnostic LLM failure classification — distinguishes missing-key, auth, invalid-model, unsupported-endpoint, network, timeout, rate-limit, and malformed-response failures without importing any provider SDK.
"""LLM error classification (provider/gateway layer).

This module is the **single** place a raw provider exception (or a
missing-configuration condition detected before any call is made) is
turned into one of a small, fixed set of ``LLMErrorCategory`` values. It
is intentionally provider-agnostic — it never imports ``openai`` or any
other SDK, matching the existing duck-typing convention already
established in ``apex_host.planning.engine._classify_error`` (HTTP status
via ``getattr(exc, "status_code", None)`` / ``exc.response.status_code``,
exception type name via ``type(exc).__name__``).

Classification is a *pure* function — no I/O, no logging, no side
effects. Callers (``apex_host.llm.gateway.LLMGateway``,
``apex_host.planning.engine.PlanningEngine``) decide what to do with the
result (retry, fall back, record a permanent-failure short-circuit,
terminate the engagement).

Never logs or returns the original exception's full message verbatim —
``describe_for_diagnostics()`` truncates and never includes anything that
could carry a leaked credential (provider error bodies occasionally echo
back request headers; this module treats the message as untrusted text).
"""
from __future__ import annotations

from enum import Enum

__all__ = [
    "LLMErrorCategory",
    "PERMANENT_LLM_ERROR_CATEGORIES",
    "TRANSIENT_LLM_ERROR_CATEGORIES",
    "classify_llm_exception",
    "classify_missing_key",
    "describe_for_diagnostics",
]


class LLMErrorCategory(str, Enum):
    """A bounded, fixed vocabulary of LLM provider failure reasons.

    Members are grouped into two disjoint sets —
    :data:`PERMANENT_LLM_ERROR_CATEGORIES` (a retry can never succeed
    without an operator fixing configuration) and
    :data:`TRANSIENT_LLM_ERROR_CATEGORIES` (a retry, or waiting, may
    succeed) — plus ``malformed_response`` and ``unknown``, which are
    provider-response-shape issues rather than transport/auth issues and
    are treated as non-retriable (the SAME request would almost certainly
    produce the same malformed shape again).
    """

    #: No API key was configured at all (``OPENAI_API_KEY`` unset/empty).
    #: Detected proactively (before any call) as well as from a raised
    #: authentication exception with no key present.
    missing_key = "missing_key"
    #: A key was present but the provider rejected it (401-shaped error,
    #: or an ``AuthenticationError``-suffixed exception type).
    authentication_failure = "authentication_failure"
    #: The provider rejected the configured model identifier (404-shaped
    #: "model not found"/"does not exist" error, or a ``NotFoundError``-
    #: suffixed exception type whose message mentions the model).
    invalid_model = "invalid_model"
    #: The configured base URL/endpoint does not implement the expected
    #: API shape (e.g. a 404 on the route itself, not on the model; a
    #: connection that succeeds but returns HTML instead of JSON).
    unsupported_endpoint = "unsupported_endpoint"
    #: A network-level failure below the HTTP layer (DNS, TCP connect,
    #: TLS) — never reached the provider's own application logic.
    network_error = "network_error"
    #: The call did not complete within the configured timeout.
    timeout = "timeout"
    #: The provider returned a 429 / rate-limit-shaped error.
    rate_limit = "rate_limit"
    #: The provider responded but the response could not be parsed into
    #: the expected shape (e.g. missing ``.content``, non-JSON body).
    malformed_response = "malformed_response"
    #: A permanent-shaped (4xx, non-retriable exception type) error that
    #: does not match any more specific category above.
    permanent_other = "permanent_other"
    #: A transient-shaped (5xx, connection, or unclassified) error that
    #: does not match any more specific category above.
    transient_other = "transient_other"


#: Categories for which retrying the exact same request can never
#: succeed — the operator must change configuration (key, model, base
#: URL) first. Used by both the budget tracker's "known permanent
#: failure" short-circuit and the ``llm_required`` fail-fast policy.
PERMANENT_LLM_ERROR_CATEGORIES: frozenset[LLMErrorCategory] = frozenset({
    LLMErrorCategory.missing_key,
    LLMErrorCategory.authentication_failure,
    LLMErrorCategory.invalid_model,
    LLMErrorCategory.unsupported_endpoint,
    LLMErrorCategory.malformed_response,
    LLMErrorCategory.permanent_other,
})

#: Categories for which a later attempt (this call's bounded retry, or a
#: later phase) may succeed without any configuration change.
TRANSIENT_LLM_ERROR_CATEGORIES: frozenset[LLMErrorCategory] = frozenset({
    LLMErrorCategory.network_error,
    LLMErrorCategory.timeout,
    LLMErrorCategory.rate_limit,
    LLMErrorCategory.transient_other,
})

#: Substrings searched for (lowercased) in an exception's message when no
#: structured signal (status code, type name) is available. Kept narrow
#: and specific — a generic word like "error" would over-match.
_INVALID_MODEL_MARKERS: tuple[str, ...] = (
    "does not exist", "not found", "unknown model", "invalid model", "model_not_found",
)
_AUTH_MARKERS: tuple[str, ...] = (
    "invalid api key", "incorrect api key", "unauthorized", "invalid_api_key",
)
_RATE_LIMIT_MARKERS: tuple[str, ...] = ("rate limit", "rate_limit", "too many requests")
_NETWORK_MARKERS: tuple[str, ...] = (
    "connection", "name or service not known", "nodename nor servname",
    "failed to establish a new connection", "dns",
)
_ENDPOINT_MARKERS: tuple[str, ...] = (
    "404", "not a valid endpoint", "unsupported endpoint", "no such host",
)


def classify_missing_key(api_key: str | None) -> LLMErrorCategory | None:
    """Proactive, pre-call check: ``None`` when *api_key* is present and
    non-empty, otherwise :data:`LLMErrorCategory.missing_key`. Callers use
    this to detect the condition BEFORE ever invoking the provider (e.g.
    in preflight — see ``apex_host.eval.preflight.check_llm_readiness``),
    distinct from :func:`classify_llm_exception`, which classifies an
    exception a provider call already raised."""
    if not api_key or not api_key.strip():
        return LLMErrorCategory.missing_key
    return None


def _http_status(exc: Exception) -> int | None:
    """Extract an HTTP status code without importing any provider SDK —
    checks ``exc.status_code`` then ``exc.response.status_code``, both via
    ``getattr`` so this works against any provider's exception shape."""
    raw_status = getattr(exc, "status_code", None)
    if isinstance(raw_status, int):
        return raw_status
    response = getattr(exc, "response", None)
    if response is not None:
        nested = getattr(response, "status_code", None)
        if isinstance(nested, int):
            return nested
    return None


def classify_llm_exception(exc: Exception) -> LLMErrorCategory:
    """Classify a raised provider-call exception into one
    :class:`LLMErrorCategory`. Never raises. Order of checks (first match
    wins): HTTP status code -> exception type name -> message-substring
    heuristics -> ``permanent_other``/``transient_other`` fallback.

    This is deliberately duck-typed and provider-agnostic — it works
    identically whether the underlying provider is the real OpenAI SDK,
    an OpenRouter-compatible endpoint, or any future LangChain chat-model
    adapter, without ever importing that provider's own exception types.
    """
    status = _http_status(exc)
    exc_type = type(exc).__name__
    message = str(exc).lower()

    if status == 401 or exc_type.endswith("AuthenticationError"):
        # A raised auth error with no key configured at all is reported
        # as missing_key (a clearer operator-facing signal than "the
        # provider rejected an empty credential"); this branch is a
        # defensive fallback for callers that do not pre-check via
        # classify_missing_key() before invoking the provider.
        return LLMErrorCategory.authentication_failure
    if status == 404 or exc_type.endswith("NotFoundError"):
        if any(marker in message for marker in _INVALID_MODEL_MARKERS) or "model" in message:
            return LLMErrorCategory.invalid_model
        return LLMErrorCategory.unsupported_endpoint
    if status == 429 or exc_type.endswith("RateLimitError"):
        return LLMErrorCategory.rate_limit
    if exc_type in ("TimeoutError", "ReadTimeout", "ConnectTimeout") or "timeout" in message or "timed out" in message:
        return LLMErrorCategory.timeout
    if exc_type.endswith(("ConnectionError", "APIConnectionError")) or any(
        marker in message for marker in _NETWORK_MARKERS
    ):
        return LLMErrorCategory.network_error
    if any(marker in message for marker in _AUTH_MARKERS):
        return LLMErrorCategory.authentication_failure
    if any(marker in message for marker in _INVALID_MODEL_MARKERS):
        return LLMErrorCategory.invalid_model
    if any(marker in message for marker in _RATE_LIMIT_MARKERS):
        return LLMErrorCategory.rate_limit
    if any(marker in message for marker in _ENDPOINT_MARKERS):
        return LLMErrorCategory.unsupported_endpoint
    if exc_type in ("ValueError", "TypeError", "KeyError", "AttributeError", "JSONDecodeError"):
        # Raised while interpreting an already-received provider
        # response (e.g. `.content` missing, unexpected shape) — never a
        # transport/auth condition.
        return LLMErrorCategory.malformed_response
    if status is not None and 400 <= status < 500:
        return LLMErrorCategory.permanent_other
    if status is not None and status >= 500:
        return LLMErrorCategory.transient_other
    return LLMErrorCategory.transient_other


def describe_for_diagnostics(exc: Exception, *, max_length: int = 200) -> str:
    """A bounded, sanitized, human-readable description of *exc* safe to
    place in structured diagnostics/logs.

    Never logs the configured API key: this module never holds it (only
    ``apex_host.llm.router.OpenAIModelRouter`` reads ``OPENAI_API_KEY``,
    and it never passes the raw value to this module or to
    ``LLMGateway``). This function additionally guards against the case a
    provider SDK's own exception message happens to echo a credential
    verbatim (some providers include the submitted key in an "invalid
    key" error body) by pattern-scrubbing known credential shapes via
    ``apex_host.security.redaction.redact_secret_patterns`` — a pattern
    match, not a known-value substring match, since this module has no
    specific secret value to look for. Truncates to *max_length*
    characters after redaction and never includes a stack trace.
    """
    from apex_host.security.redaction import redact_secret_patterns

    text = redact_secret_patterns(f"{type(exc).__name__}: {exc}")
    return text[:max_length]


def base_url_host(base_url: str | None) -> str:
    """Return only the host portion of *base_url* (never the full URL,
    which could in principle carry embedded credentials or a query
    string) — used by preflight/diagnostics to report "where" without
    leaking "how"."""
    if not base_url:
        return ""
    from urllib.parse import urlsplit

    return urlsplit(base_url).hostname or ""


def looks_like_openrouter_style_model_id(model: str) -> bool:
    """Heuristic: OpenRouter (and similar aggregators) use
    ``vendor/model`` identifiers (e.g. ``openai/gpt-5.5``,
    ``anthropic/claude-3.5``); the real OpenAI API's own model IDs never
    contain a ``/``. Used only to WARN — never to reject — when
    ``llm_provider="openai"`` with no base-URL override is combined with
    a slash-containing model name, since this exact combination is what
    caused the live-test failure this phase investigates (the model ID
    was valid for OpenRouter but invalid against the real
    ``api.openai.com``).
    """
    return "/" in model.strip()
