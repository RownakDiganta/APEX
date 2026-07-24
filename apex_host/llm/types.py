# types.py
# Provider-neutral configuration shapes and normalized request/response types shared by every LLM provider adapter.
"""Provider enumeration, normalization, credential mapping, and normalized
request/response types for the native-provider LLM architecture (Phase 5).

This module is the single source of truth for three configuration-shape
concerns that were previously entangled with a single OpenAI-only router:

1. **Which provider names are valid** (:data:`VALID_LLM_PROVIDERS`) and how
   a raw, possibly mixed-case CLI/env string is normalized
   (:func:`normalize_llm_provider`).
2. **Which environment variable holds each provider's credential**
   (:data:`CREDENTIAL_ENV_VAR`) — used both by the provider adapters
   themselves (to read the key) and by preflight/diagnostics (to NAME the
   variable in a missing-key message without ever reading or printing its
   value from here).
3. **The normalized request/response shape** every provider adapter speaks
   (:class:`LLMRequest`, :class:`LLMResponse`) — planners and the planning
   engine never see a raw OpenAI/Anthropic SDK object; they see (indirectly,
   through ``apex_host.llm.gateway.LLMGateway``) only these two dataclasses
   or their existing ``LLMCallResult`` projection.

No provider SDK (``openai``, ``anthropic``) is imported here — this module
is purely configuration/data shape, imported by ``apex_host.llm.errors``,
``apex_host.llm.router``, ``apex_host.eval.preflight``,
``apex_host.eval.check_config``, and ``apex_host.config_env`` alike.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Provider enumeration
# ---------------------------------------------------------------------------

#: The complete, fixed set of recognized provider names. "fake" is the
#: deterministic no-network test/default provider (``FakeModelRouter``);
#: every other value selects a real native (or, for openrouter, router-
#: style) adapter. Adding a new provider means adding its name here, its
#: credential variable below, and a new ``apex_host/llm/providers/<name>.py``
#: module — never editing a planner or the gateway.
VALID_LLM_PROVIDERS: frozenset[str] = frozenset({"fake", "openai", "anthropic", "openrouter"})

#: Real (non-"fake") providers — the ones that construct an actual native
#: adapter and require a credential.
REAL_LLM_PROVIDERS: frozenset[str] = frozenset({"openai", "anthropic", "openrouter"})

#: Provider -> required credential environment variable. Deliberately a
#: 1:1 mapping with NO shared fallback between providers (e.g. OpenRouter
#: never falls back to ``OPENAI_API_KEY`` — see docs/llm-providers.md
#: "Credential resolution"). Read directly from ``os.environ`` by each
#: provider adapter's own ``__init__``/``generate()`` — never routed
#: through ``apex_host.config_env``'s generic merge (same rationale as the
#: pre-existing ``OPENAI_API_KEY`` handling: CLI args are visible in shell
#: history and `ps`; environment variables set via `export` are not).
CREDENTIAL_ENV_VAR: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}

#: Provider -> official default base URL (used when no custom base URL is
#: configured for that provider). Purely informational/diagnostic here —
#: each provider adapter's own SDK client already knows its own official
#: default and is never told to use these constants directly unless a
#: custom override is absent; kept here so preflight/diagnostics can report
#: "official_default" vs "custom" without constructing a provider instance.
OFFICIAL_BASE_URL: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "openrouter": "https://openrouter.ai/api/v1",
}


def normalize_llm_provider(raw: str) -> str:
    """Lowercase + strip a provider name. Never validates membership —
    see :func:`is_valid_llm_provider` for that. Pure, no I/O."""
    return raw.strip().lower()


def is_valid_llm_provider(raw: str) -> bool:
    """True if *raw*, once normalized, is a recognized provider name."""
    return normalize_llm_provider(raw) in VALID_LLM_PROVIDERS


# ---------------------------------------------------------------------------
# Normalized request / response
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class LLMRequest:
    """Provider-neutral request — what every :class:`~apex_host.llm.providers
    .base.LLMProvider` adapter's ``generate()`` accepts.

    ``messages`` keeps the existing ``list[dict[str, str]]`` shape
    (``{"role": ..., "content": ...}``) already used throughout
    ``apex_host.planning`` — no new message type was introduced, since the
    existing shape already covers what every provider needs (each adapter
    translates it into its own SDK's native format, e.g. splitting out a
    ``system`` message for Anthropic's separate ``system=`` parameter).
    """

    messages: list[dict[str, str]]
    model: str
    timeout_seconds: float | None = None
    max_output_tokens: int | None = None


@dataclass(slots=True)
class LLMResponse:
    """Provider-neutral, normalized response — never a raw SDK object.

    Every field beyond ``provider``/``requested_model``/``text`` is
    best-effort: providers that do not return a given piece of information
    leave it at its safe default rather than the adapter fabricating a
    value. ``latency_seconds`` is measured by the adapter itself (wall
    clock around the SDK call), matching this codebase's existing
    ``elapsed_seconds`` convention in ``apex_host.llm.gateway``'s audit log.
    """

    provider: str
    requested_model: str
    text: str
    actual_model: str = ""
    finish_reason: str = ""
    input_tokens: int | None = None
    output_tokens: int | None = None
    request_id: str = ""
    latency_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable projection — never includes anything beyond
        these named fields (no raw SDK response, no headers)."""
        return {
            "provider": self.provider,
            "requested_model": self.requested_model,
            "actual_model": self.actual_model,
            "text_len": len(self.text),
            "finish_reason": self.finish_reason,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "request_id": self.request_id,
            "latency_seconds": round(self.latency_seconds, 3),
        }


@dataclass(slots=True)
class ProviderReadiness:
    """Structured readiness/preflight result for one provider configuration.

    Distinguishes **configuration validation** (no I/O — provider
    recognized, credential env var present, model non-empty, no syntactic
    provider/model or base-URL mismatch) from **network/API validation**
    (``network_checked=True`` — an actual bounded request was attempted).

    Never carries the credential value — only ``credential_present``
    (bool) and ``credential_variable`` (the env var NAME).
    """

    provider: str
    requested_model: str
    endpoint_kind: str = "official_default"  # "official_default" | "custom"
    credential_variable: str = ""
    credential_present: bool = False
    configuration_valid: bool = False
    network_checked: bool = False
    reachable: bool | None = None
    error_category: str = ""
    error_reason: str = ""
    retryable: bool = False
    permanent: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "requested_model": self.requested_model,
            "endpoint_kind": self.endpoint_kind,
            "credential_variable": self.credential_variable,
            "credential_present": self.credential_present,
            "configuration_valid": self.configuration_valid,
            "network_checked": self.network_checked,
            "reachable": self.reachable,
            "error_category": self.error_category,
            "error_reason": self.error_reason,
            "retryable": self.retryable,
            "permanent": self.permanent,
        }
