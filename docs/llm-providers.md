# LLM Provider Architecture (Phase 5)

Native OpenAI and Anthropic support, plus an optional OpenRouter adapter,
replacing the earlier OpenAI-only, LangChain-backed router. This document
is authoritative for the LLM provider layer; `CLAUDE.md` §25 and the
README's "Provider configuration" section summarize it.

## 1. Why this phase exists

The previous architecture allowed `provider=openai` with
`model=openai/gpt-5.5` — a router-style (vendor-prefixed) model
identifier — to be sent directly to the real OpenAI API, which rejected it
as an invalid model. All four LLM calls in the first authorized live HTB
test failed this way, and APEX silently continued in deterministic
fallback mode with no operator-visible signal (a generic `provider_error`
category, indistinguishable from a real transient failure).

The deeper problem was that **provider selection, endpoint selection,
credential selection, and model naming were not sufficiently isolated.**
A single `OpenAIModelRouter` conflated "the OpenAI SDK" with "the OpenAI
service" — pointing its base URL at OpenRouter was the only way to reach
OpenRouter, which meant OpenRouter-shaped model IDs and OpenAI-shaped model
IDs were both "valid" through the same code path, with no way to detect
the mismatch until the real API rejected it.

## 2. Architecture

```
                      ApexConfig.use_llm / llm_provider
                                  │
                                  ▼
                  apex_host.llm.router.build_model_router(config)
                                  │
              ┌───────────────────┼───────────────────┬─────────────┐
              ▼                   ▼                   ▼             ▼
     FakeModelRouter    OpenAIModelRouter   AnthropicModelRouter  OpenRouterModelRouter
     (use_llm=False /        │                      │                    │
      provider=fake)         ▼                      ▼                    ▼
                       OpenAIProvider        AnthropicProvider    OpenRouterProvider
                       (providers/openai.py) (providers/anthropic.py) (providers/openrouter.py)
                              │                      │                    │
                              ▼                      ▼                    ▼
                     openai.AsyncOpenAI      anthropic.AsyncAnthropic  openai.AsyncOpenAI
                     api.openai.com          api.anthropic.com         openrouter.ai/api/v1
                     (official default)      (official default)        (its own default)
```

Every native adapter implements one Protocol, `apex_host.llm.providers.base
.LLMProvider`:

```python
class LLMProvider(Protocol):
    name: str
    async def generate(self, request: LLMRequest) -> LLMResponse: ...
    async def check_readiness(self, *, network_check: bool = False) -> ProviderReadiness: ...
```

`LLMRequest`/`LLMResponse`/`ProviderReadiness` (`apex_host/llm/types.py`)
are the only shapes a planner, executor, or the gateway ever sees — **no
planner or agent ever sees a raw OpenAI/Anthropic SDK response object**,
and no planner, executor, agent, or workflow node may import the `openai`
or `anthropic` SDK directly (enforced by a static architecture test, §14).

### 2.1 The sync/async bridge (why `LLMGateway` needed zero changes)

`apex_host.llm.gateway.LLMGateway` — unchanged since before this phase —
calls whatever a `ModelRouter` role method (`planner_llm()`, etc.) returns
via a **synchronous** `.invoke(messages) -> object-with-.content`, from
inside a worker thread (`asyncio.to_thread`). Every native adapter's role
method returns a `RoleBoundProvider` (`apex_host/llm/providers/base.py`),
which exposes exactly that synchronous `.invoke()` facade as a thin wrapper
around its own `async def generate()`:

```python
def invoke(self, messages: list[dict[str, str]]) -> object:
    request = LLMRequest(messages=messages, model=self._model, timeout_seconds=self._timeout)
    response = run_coroutine_sync(self._provider.generate(request))   # asyncio.run()
    return InvokeResult(response)                                     # exposes .content, .usage_metadata, ...
```

`run_coroutine_sync` is `asyncio.run()` — safe specifically because
`LLMGateway` always invokes `.invoke()` from a worker thread with **no
running event loop of its own**. This is what let Phase 5 introduce a
cleanly async-first provider protocol without touching `LLMGateway`'s
existing, heavily-tested pipeline (budget reservation, prompt/output
guard, timeout, audit log) at all — only additive field extraction
(`provider`, `actual_model`, `finish_reason`, `request_id`) was added.

## 3. Provider enumeration and configuration

`apex_host.llm.types.VALID_LLM_PROVIDERS = frozenset({"fake", "openai", "anthropic", "openrouter"})`.
Validated case-insensitively at the CLI/env boundary
(`apex_host.config_env.validate_llm_provider`, `apex_host.config._normalize_and_validate_llm_provider`),
normalized internally (always lowercase).

| Field | Default | Notes |
|---|---|---|
| `ApexConfig.use_llm` | `False` | Safe default — no API calls, no key required |
| `ApexConfig.llm_provider` | `"fake"` | `FakeModelRouter`; validated only when `use_llm=True` |
| `ApexConfig.planner_model` / `executor_model` / `parser_model` | `""` | **No provider-neutral default exists.** `--llm-model` sets all three simultaneously |
| `ApexConfig.llm_openai_base_url` | `None` | OpenAI's own official default when unset |
| `ApexConfig.llm_anthropic_base_url` | `None` | Anthropic's own official default when unset |
| `ApexConfig.llm_openrouter_base_url` | `None` | `https://openrouter.ai/api/v1` when unset |
| `ApexConfig.llm_base_url` | `None` | **Legacy**, generic, CLI-only override — applies only to whichever provider is currently selected; provider-specific fields above always win |
| `ApexConfig.llm_required` | `False` | Fail-fast on a confirmed permanent LLM error |

`use_llm=True` requires an explicit, valid `llm_provider` and an explicit
model for that provider — there is no hardcoded exhaustive model
allowlist, and APEX never silently strips a prefix or converts a model ID
between providers.

## 4. Credential resolution

Strict 1:1 mapping, no shared fallback (`apex_host.llm.types.CREDENTIAL_ENV_VAR`):

| Provider | Environment variable |
|---|---|
| `openai` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `openrouter` | `OPENROUTER_API_KEY` |

Each is read directly by that provider's own adapter
(`apex_host.llm.providers.base.read_credential`) — **never** through
`apex_host.config_env`'s generic CLI/env merge (the same rationale as the
pre-existing `APEX_TOOL_SERVICE_TOKEN`/`OPENAI_API_KEY` handling: CLI
arguments are visible in shell history and `ps`; environment variables set
via `export` are not). `OPENAI_API_KEY` is never used to satisfy
`anthropic` or `openrouter`, and vice versa — there is no fallback path
between providers anywhere in the codebase.

A missing-key diagnostic always names the variable, never its value:

```
Missing required environment variable OPENAI_API_KEY
```

## 5. Base URL behavior

Resolution order (`apex_host.llm.router.resolve_base_url_for_provider` —
the single implementation shared by every native router **and** by
`apex_host.eval.preflight`, so the two can never disagree):

1. The provider-specific field (`llm_openai_base_url` / `llm_anthropic_base_url` / `llm_openrouter_base_url`)
2. The legacy generic `llm_base_url` (applies only because this provider is the one currently selected)
3. That provider's own SDK-recognized environment variable (`OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` / `OPENROUTER_BASE_URL`)
4. `None` → the provider's own official SDK default (`api.openai.com`, `api.anthropic.com`, `openrouter.ai/api/v1`)

`apex_host.llm.errors.endpoint_kind(provider, base_url)` classifies the
resolved value as `"official_default"` or `"custom"` for readiness/report
diagnostics — the full URL is reported elsewhere only as a hostname
(`base_url_host()`), never with embedded credentials or query strings.

**Provider/base-URL mismatch detection**
(`apex_host.llm.errors.detect_base_url_provider_mismatch`) flags exactly
one unambiguous case: `provider in ("openai", "anthropic")` combined with
a base URL whose hostname contains `"openrouter"`. A generic self-hosted
proxy, Azure OpenAI endpoint, or LiteLLM gateway is never flagged — only
OpenRouter's own well-known domain, since that is the one case APEX can
identify with certainty.

## 6. Model/provider mismatch detection

`apex_host.llm.errors.detect_provider_model_mismatch(provider, model)`
flags exactly one unambiguous case: `provider in ("openai", "anthropic")`
combined with a model string containing `/`. OpenRouter's own model
catalog is entirely `vendor/model`-shaped, so `provider="openrouter"` is
never flagged. Neither OpenAI's nor Anthropic's real model catalog has
ever used `/` in a model identifier (both use dash/dot-separated names —
`gpt-4o-mini`, `claude-opus-4-1-20250805`), so this is conservative: an
unambiguous namespace mistake, not a general punctuation ban.

Both `detect_provider_model_mismatch` and
`detect_base_url_provider_mismatch` are checked **before any network
call** — a provider adapter's `generate()` raises
`ProviderModelMismatchError` (classified as
`LLMErrorCategory.provider_model_mismatch`, always permanent) at the very
top of the method, before constructing an SDK client.

## 7. Error classification (`apex_host/llm/errors.py`)

`classify_llm_exception(exc) -> LLMErrorCategory` is provider-agnostic and
duck-typed — it works identically against a real `openai`/`anthropic` SDK
exception, an `httpx` exception, or any object shaped like one (checked in
order: our own raised exception type name → HTTP status code → exception
type-name suffix → message substring → generic 4xx/5xx fallback).

| Category | Permanent? | Detected from |
|---|---|---|
| `missing_key` | Yes | No credential present (proactive check, or `MissingCredentialError`) |
| `authentication_failure` | Yes | HTTP 401, or an `*AuthenticationError`-named exception |
| `invalid_model` | Yes | HTTP 404 whose message mentions the model, or a `*NotFoundError` with a model marker |
| `unsupported_endpoint` | Yes | HTTP 404 with no model marker |
| `malformed_response` | Yes | `EmptyResponseError`, or a `ValueError`/`TypeError`/`KeyError`/`AttributeError` interpreting an already-received response |
| `permanent_other` | Yes | Any other 4xx |
| `provider_model_mismatch` | Yes | `ProviderModelMismatchError` (Phase 5 — pre-call, syntactic) |
| `network_error` | No | `*ConnectionError`/`*APIConnectionError`, or a connection-shaped message |
| `timeout` | No | `TimeoutError`/`ReadTimeout`/`ConnectTimeout`/`APITimeoutError`, or a timeout-shaped message |
| `rate_limit` | No | HTTP 429, or a `*RateLimitError` |
| `transient_other` | No | Any other 5xx, or unclassified |

`PERMANENT_LLM_ERROR_CATEGORIES` and `TRANSIENT_LLM_ERROR_CATEGORIES` are
disjoint frozensets consumed by `LLMBudgetTracker` (permanent-error
short-circuit — a second phase never re-spends a budget slot rediscovering
the identical misconfiguration) and by the `--llm-required` fail-fast
policy (`apex_host.orchestration.outcome.EngagementOutcome.llm_unavailable`,
exit code `4`).

`describe_for_diagnostics(exc)` returns a bounded (200 char), pattern-
scrubbed description (`apex_host.security.redaction.redact_secret_patterns`
strips `sk-...`/`AKIA...`/`Bearer ...`/`ghp_...`/private-key-header
shapes) — used only for logs/diagnostics, never for classification logic.

## 8. Readiness lifecycle

Three layers, each progressively more expensive:

1. **`check_llm_readiness(config)`** (`apex_host.eval.preflight`) — pure,
   no I/O. Validates: provider recognized; model configured (a hard
   failure if not — there is no default); provider/model syntactic
   mismatch (hard failure, Phase 5 — previously a warning); base-URL/
   provider syntactic mismatch (hard failure); credential environment
   variable present. Reports provider, model, endpoint kind, base-URL
   host, and the credential variable *name* — never a value.
2. **`check_llm_model_compatibility(config)`** — kept for backward
   compatibility with existing callers of this name; always
   `required=False` (informational only) and never duplicates a failure
   `check_llm_readiness` would already report as a hard blocker.
3. **`probe_llm_readiness(config)`** — the one network-touching check.
   Constructs the selected provider's own real adapter
   (`_provider_readiness()`) and calls its `check_readiness(network_check
   =True)`, which issues exactly one minimal, official model-access
   request (`GET /models` — zero completion tokens, never a chat/
   completion call). Never run automatically as part of every preflight
   pass; `apex_host.eval.live_interlock.evaluate_live_interlock()` adds it
   to the required checks only when `config.llm_required=True`.

`ProviderReadiness` (`apex_host/llm/types.py`) distinguishes configuration
validation (`configuration_valid`) from network validation
(`network_checked`, `reachable`) explicitly — never conflates the two.

**No explicit readiness cache exists.** `check_llm_readiness` is pure and
free (no I/O), so repeated calls within one runtime cost nothing to begin
with; `probe_llm_readiness` is only ever invoked once per live-interlock
evaluation, not per turn or per LLM call. Adding a cache layer would add
complexity with no measurable benefit — this is a deliberate decision, not
an oversight.

**One provider's failure never poisons another.** Every `ProviderReadiness`/
`LLMErrorCategory` result is scoped to the single provider adapter
instance that produced it; `build_model_router(config)` constructs a
fresh, independent adapter per `ApexConfig`, and nothing about a failed
OpenAI configuration is retained anywhere that a subsequently-constructed
Anthropic (or a second, differently-configured OpenAI) adapter could read.

## 9. Runtime and reporting

`apex_host.eval.report.RunReport` gained (all additive, safe defaults):

| Field | Meaning |
|---|---|
| `llm_configured_provider` | The resolved provider name (`""` when `use_llm=False`) |
| `llm_configured_model` | The resolved model string |
| `llm_endpoint_kind` | `"official_default"` or `"custom"` |
| `llm_credential_variable` | The credential env var *name* (never its value) |
| `llm_readiness` | The last readiness/probe result dict, if supplied |
| `llm_attempts` / `llm_successes` / `llm_failures` | Derived from `planner_decisions` |
| `llm_fallback_used` / `llm_fallback_reason` | Whether/why the deterministic fallback fired |
| `llm_required_terminated` | Whether the engagement ended via `llm_unavailable` |

`format_text()` renders an "LLM Provider" section (shown whenever a real
provider is configured); `to_json_dict()` exposes an `"llm_provider"`
block with the same fields. **No report field, log line, or exception ever
includes an API key value** — only variable names and boolean presence
flags.

`report_schema_version` was **not** bumped for this phase — every new
field is purely additive with a safe default (`""`/`0`/`False`/`{}`),
consistent with this project's established policy that additive optional
report fields do not require a version bump.

## 10. OpenRouter retention

**Retained**, as its own distinct provider identity — not removed, and
never expressed as `provider=openai` plus a custom base URL after this
phase. Evidence reviewed before this decision: OpenRouter was already a
documented, supported configuration path (`OPENAI_BASE_URL` pointed at
`openrouter.ai`); nothing in the codebase's tests, docs, or CLI examples
depended on removing it; and OpenRouter's own HTTP API is genuinely
OpenAI-Chat-Completions-compatible, so reusing the `openai` SDK's client
machinery (pointed at a different endpoint, under its own provider name
and credential) is the correct, low-risk implementation — not a reason to
drop the provider.

`OpenRouterProvider` (`apex_host/llm/providers/openrouter.py`) is a
structurally separate adapter: `name = "openrouter"` (never `"openai"` —
reports/diagnostics truthfully show which service processed a request),
its own credential (`OPENROUTER_API_KEY`, no fallback to `OPENAI_API_KEY`),
its own default endpoint (`https://openrouter.ai/api/v1`), and it is the
one provider `detect_provider_model_mismatch` never flags for a
router-style model ID (that is its normal, expected shape).

## 11. Migration from the old mixed configuration

**Old (broken) configuration:**

```bash
export APEX_LLM_PROVIDER=openai
export APEX_LLM_MODEL=openai/gpt-5.5
```

Sent directly to the real OpenAI API, rejected as an invalid model. Now
rejected at startup/readiness time with:

```
provider_model_mismatch: provider 'openai' requires a native openai model
identifier. The configured value 'openai/gpt-5.5' appears to be a
router-style (vendor-prefixed) model identifier. Select provider='openrouter'
for router-style model names, or provide a native openai model identifier
(verify the exact spelling with your provider account — APEX never assumes
or hardcodes a specific model name).
```

**Old (also broken) configuration:**

```bash
export APEX_LLM_PROVIDER=openai
export OPENAI_BASE_URL=https://openrouter.ai/api/v1
```

Now rejected with:

```
provider_model_mismatch: provider 'openai' is configured with a base URL
pointing at OpenRouter ('openrouter.ai'). Select provider='openrouter'
instead — do not combine provider='openai' with an OpenRouter base URL;
APEX will not silently route a native provider's requests through a
different service.
```

**Corrected configuration** (either):

```bash
# Use the real, native OpenAI API directly
export APEX_LLM_PROVIDER=openai
export APEX_LLM_MODEL=<VALID_NATIVE_OPENAI_MODEL_ID>
export OPENAI_API_KEY=sk-...

# Or use OpenRouter, as its own provider identity
export APEX_LLM_PROVIDER=openrouter
export APEX_LLM_MODEL=<VALID_OPENROUTER_ROUTE_ID>
export OPENROUTER_API_KEY=sk-or-...
```

## 12. Environment variable matrix

| Variable | Read by | Purpose |
|---|---|---|
| `APEX_USE_LLM` | `apex_host.config_env` | Enable/disable the LLM layer |
| `APEX_LLM_PROVIDER` | `apex_host.config_env` | `fake` / `openai` / `anthropic` / `openrouter` |
| `APEX_LLM_MODEL` | `apex_host.config_env` | Model for the selected provider (sets all three role fields) |
| `APEX_LLM_OPENAI_BASE_URL` | `apex_host.config_env` | OpenAI-only base URL override |
| `APEX_LLM_ANTHROPIC_BASE_URL` | `apex_host.config_env` | Anthropic-only base URL override |
| `APEX_LLM_OPENROUTER_BASE_URL` | `apex_host.config_env` | OpenRouter-only base URL override |
| `OPENAI_API_KEY` | `apex_host.llm.providers.openai` (via `providers/base.py::read_credential`) | OpenAI credential |
| `ANTHROPIC_API_KEY` | `apex_host.llm.providers.anthropic` | Anthropic credential |
| `OPENROUTER_API_KEY` | `apex_host.llm.providers.openrouter` | OpenRouter credential |
| `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` / `OPENROUTER_BASE_URL` | `apex_host.llm.router::resolve_base_url_for_provider` | Each SDK's own recognized env-var fallback, below the provider-specific field above |

None of the three credential variables is read by `apex_host/config.py`
itself (unchanged architectural invariant — see
`test_arch_08_config_py_has_no_env_access`) or by
`apex_host.config_env`'s generic merge.

## 13. Security and redaction guarantees

- No API key is ever stored on `ApexConfig`, passed as a CLI flag, logged,
  or included in a report/JSON export — only presence booleans and
  variable *names*.
- `ApexConfig.to_safe_dict()` never includes a raw credential — it was
  never stored there to begin with.
- `describe_for_diagnostics()` pattern-scrubs credential-shaped substrings
  from a raised exception's message, in case a provider's own error body
  happens to echo a submitted key back.
- `.env.example` documents all three credential variables, always blank,
  with placeholder model IDs only (`<VALID_NATIVE_OPENAI_MODEL_ID>`, etc.)
  — never a guaranteed-current real model name.
- `compose.yaml` passes all three credentials through to the `apex`
  service via `${VAR:-}` interpolation — blank by default, never baked in.
- No unit test ever makes a real network call: every native-provider test
  mocks the official SDK's own async client class (`openai.AsyncOpenAI` /
  `anthropic.AsyncAnthropic`) directly via `monkeypatch.setattr`, at the
  adapter boundary — never a raw `httpx` transport underneath a real SDK
  client, and never a real API key.

## 14. Adding another provider (without touching a planner)

1. Add the provider name to `apex_host.llm.types.VALID_LLM_PROVIDERS` and
   `REAL_LLM_PROVIDERS`.
2. Add its credential variable to `CREDENTIAL_ENV_VAR` and its official
   default to `OFFICIAL_BASE_URL`.
3. Create `apex_host/llm/providers/<name>.py` implementing `LLMProvider`
   (`generate()` + `check_readiness()`), following the same
   mismatch-check-before-network-call, credential-isolation, and
   response-normalization pattern the three existing adapters use.
4. Add a `<Name>ModelRouter(_NativeProviderRouter)` class to
   `apex_host/llm/router.py` and register it in `_PROVIDER_ROUTERS`.
5. Add a construction branch to `apex_host.eval.preflight._provider_readiness`.
6. Add tests to `tests/apex_host/test_llm_providers.py` following the
   existing per-provider test groups (mock the SDK client, never make a
   real network call).
7. Never touch `apex_host/planning/engine.py`, `apex_host/llm/gateway.py`,
   or any planner — the provider seam is entirely below `ModelRouter`.

This is enforced by a static architecture test
(`tests/apex_host/test_llm_providers.py::TestNoDirectSDKImports`) that
fails if any `apex_host` file outside the three approved adapter modules
imports `openai` or `anthropic` directly.
