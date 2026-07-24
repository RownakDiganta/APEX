# preflight.py
# Reusable, structured preflight checks (configuration, report directory, compiled knowledge, policy, tool-service health, remote smoke, LLM readiness) shared by the container entrypoint and any future automation.
"""Structured preflight checks for the APEX container entrypoint.

This module defines the individual, independently-testable checks the
container entrypoint (``apex_host/container_entrypoint.py``) composes per
mode. None of these functions import or start the engagement graph
(``apex_host.graph``/``apex_host.orchestration``) — configuration-only
checks stay configuration-only, per this phase's own instruction to avoid
importing the entire orchestration graph for a preflight pass.

Every check function returns a ``PreflightCheck`` and never raises for an
*ordinary* failure (a missing file, an unreachable service, an invalid
value) — exceptions are reserved for genuine programming errors, matching
the same "ordinary failure is data" discipline
``apex_host.tools.backend``/``apex_host.tools.remote_backend`` already use
for tool execution.

**Never prints or serializes a secret.** No check function accepts or
returns a token/API-key value — only ``bool`` presence flags, exactly like
``apex_host.eval.check_config``'s own redaction discipline.
"""
from __future__ import annotations

import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from apex_host.config import ApexConfig
from apex_host.eval.check_config import validate_combinations
from apex_host.knowledge.compiler.verify_compiled import verify_compiled
from apex_host.llm.errors import (
    base_url_host,
    detect_base_url_provider_mismatch,
    detect_provider_model_mismatch,
    endpoint_kind as _endpoint_kind,
)
from apex_host.llm.types import CREDENTIAL_ENV_VAR, VALID_LLM_PROVIDERS, ProviderReadiness
from apex_host.policy.policy_loader import _resolve_policy_path
from apex_host.tools.backend import select_runtime_backend

_HEALTH_TIMEOUT_SECONDS = 5.0
_DEFAULT_SMOKE_TOOL = "curl"
_DEFAULT_SMOKE_ARGS = ["--version"]


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PreflightCheck:
    """One structured, human- and machine-readable preflight result.

    ``required=True`` (the default) means this check must pass for the
    overall preflight to succeed. ``required=False`` marks an optional/
    informational check (e.g. "no policy configured, conservative default
    in effect") whose failure is surfaced as a warning, not a blocker.
    """

    name: str
    passed: bool
    detail: str
    required: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "required": self.required,
        }


@dataclass(frozen=True, slots=True)
class PreflightResult:
    """The aggregate outcome of a full preflight pass (one mode's worth of
    ``PreflightCheck`` results, in the order they were run)."""

    checks: list[PreflightCheck] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks if c.required)

    @property
    def failed_required(self) -> list[PreflightCheck]:
        return [c for c in self.checks if c.required and not c.passed]

    @property
    def warnings(self) -> list[PreflightCheck]:
        return [c for c in self.checks if not c.required and not c.passed]

    @property
    def required_count(self) -> int:
        return sum(1 for c in self.checks if c.required)

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "required_count": self.required_count,
            "failed_required_count": len(self.failed_required),
            "warning_count": len(self.warnings),
            "checks": [c.to_dict() for c in self.checks],
        }

    def format_text(self) -> str:
        lines: list[str] = []
        for c in self.checks:
            tag = "PASS" if c.passed else ("WARN" if not c.required else "FAIL")
            lines.append(f"[{tag}] {c.name}")
            if not c.passed:
                lines.append(f"       {c.detail}")
        lines.append("")
        if self.passed:
            lines.append(f"Preflight passed: {self.required_count} required check(s)")
        else:
            names = ", ".join(c.name for c in self.failed_required)
            lines.append(f"Preflight FAILED: {len(self.failed_required)} required check(s) failed ({names})")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------

def check_configuration(config: ApexConfig) -> PreflightCheck:
    """Validate required field combinations via the same
    ``apex_host.eval.check_config.validate_combinations`` used by the
    standalone config-check command — one implementation, two callers,
    never duplicated."""
    problems = validate_combinations(config)
    if problems:
        return PreflightCheck(
            name="configuration", passed=False,
            detail="; ".join(problems),
        )
    return PreflightCheck(name="configuration", passed=True, detail="valid")


def check_remote_backend_selected(config: ApexConfig) -> PreflightCheck:
    """Smoke mode's own explicit requirement (this phase's task brief:
    "require remote backend configuration") — a bare, actionable failure
    rather than letting an unrelated check (health/smoke) fail confusingly
    when the operator simply forgot ``--tool-backend remote`` or
    ``APEX_TOOL_BACKEND=remote``. In the Compose environment this always
    resolves to ``remote`` already (``compose.yaml``'s own default,
    unchanged since Infra Phase 7) — this check matters primarily for
    host-side/non-Compose smoke invocations.
    """
    if config.tool_backend != "remote":
        return PreflightCheck(
            name="remote backend selected", passed=False,
            detail=(
                f"tool_backend={config.tool_backend!r} — smoke mode requires "
                "'remote' (set --tool-backend remote or $APEX_TOOL_BACKEND=remote)"
            ),
        )
    return PreflightCheck(name="remote backend selected", passed=True, detail="tool_backend=remote")


# ---------------------------------------------------------------------------
# 2. Report directory
# ---------------------------------------------------------------------------

def check_report_directory(
    *,
    default_dir: str,
    report_path: str | None = None,
    graph_path: str | None = None,
) -> PreflightCheck:
    """Verify the report output directory (and any explicitly requested
    report/graph file's parent directory) exists or can be created, and is
    writable by the current (non-root) user.

    Never deletes or overwrites an existing file — writability is proven
    with a uniquely-named, immediately-removed marker file, never a real
    report filename. Never recursively changes ownership/permissions.
    """
    candidates = {Path(default_dir)}
    for p in (report_path, graph_path):
        if p:
            candidates.add(Path(p).parent)

    for directory in candidates:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return PreflightCheck(
                name="report directory", passed=False,
                detail=f"cannot create {directory}: {exc}",
            )
        marker = directory / f".apex_preflight_write_test_{os.getpid()}_{int(time.time() * 1000)}"
        try:
            marker.write_text("preflight write test\n", encoding="utf-8")
            marker.unlink()
        except OSError as exc:
            return PreflightCheck(
                name="report directory", passed=False,
                detail=f"{directory} exists but is not writable: {exc}",
            )
    return PreflightCheck(
        name="report directory", passed=True,
        detail=f"writable: {', '.join(str(c) for c in sorted(candidates))}",
    )


# ---------------------------------------------------------------------------
# 3. Compiled knowledge
# ---------------------------------------------------------------------------

def check_compiled_knowledge(knowledge_root: str | None) -> PreflightCheck:
    """Verify compiled knowledge via the existing
    ``apex_host.knowledge.compiler.verify_compiled.verify_compiled()`` —
    never re-implements the nine-file spec or record-count minimums here.

    ``knowledge_root=None`` (not configured) is a **pass**, not a failure —
    knowledge is optional application configuration
    (``docs/environment-configuration.md`` §13); this check only runs the
    real verifier when a root is actually configured, and never recompiles
    or silently accepts a corrupted compiled tree.
    """
    if not knowledge_root:
        return PreflightCheck(
            name="compiled knowledge", passed=True,
            detail="not configured (APEX_KNOWLEDGE_ROOT unset) — skipped",
            required=False,
        )
    result = verify_compiled(knowledge_root)
    if not result.passed:
        failing = [fr for fr in result.file_results if not fr.ok]
        detail = "; ".join(
            f"{fr.relative_path}: {'; '.join(fr.problems)}" for fr in failing
        )
        return PreflightCheck(name="compiled knowledge", passed=False, detail=detail)
    total = sum(r.record_count for r in result.file_results)
    return PreflightCheck(
        name="compiled knowledge", passed=True,
        detail=f"all {len(result.file_results)} required outputs verified ({total:,} records)",
    )


# ---------------------------------------------------------------------------
# 4. Policy
# ---------------------------------------------------------------------------

def check_policy(config: ApexConfig, *, required: bool = False) -> PreflightCheck:
    """Verify the resolved policy YAML (if any) exists and parses.

    Reuses ``apex_host.policy.policy_loader``'s own path-resolution order
    (explicit ``config.policy_file`` > ``knowledge_root``-derived >
    conventional local path) rather than re-implementing it — "no
    overly broad policy substitution" (this phase's own instruction) means
    this check must agree exactly with what ``load_policy()`` would
    actually resolve at runtime.

    A **configured** policy path that is missing or malformed is always a
    failure, regardless of ``required`` — an operator who pointed at a
    specific file clearly intended to use it. When no path resolves at
    all, the outcome depends on ``required`` (``True`` only for live "run"
    mode; ``False``, an informational pass, for every other mode — the
    conservative default that ``load_policy()`` already falls back to is a
    legitimate, safe outcome for check/smoke/dry-run).

    Never mutates, regenerates, or substitutes the policy file.
    """
    policy_path = _resolve_policy_path(config)
    if policy_path is None:
        if required:
            return PreflightCheck(
                name="policy", passed=False, required=True,
                detail=(
                    "no policy file configured (set --policy-file or "
                    "--knowledge-root) — a policy file is required for live runs"
                ),
            )
        return PreflightCheck(
            name="policy", passed=True, required=False,
            detail="no policy configured — conservative built-in default in effect",
        )

    if not policy_path.exists():
        return PreflightCheck(
            name="policy", passed=False, required=True,
            detail=f"file not found: {policy_path}",
        )
    try:
        import yaml

        raw = policy_path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(raw)
    except (OSError, UnicodeDecodeError) as exc:
        return PreflightCheck(
            name="policy", passed=False, required=True,
            detail=f"could not read {policy_path}: {exc}",
        )
    except Exception as exc:  # noqa: BLE001 - yaml.YAMLError subclasses vary
        return PreflightCheck(
            name="policy", passed=False, required=True,
            detail=f"could not parse {policy_path}: {exc}",
        )
    if not isinstance(parsed, dict) or not parsed:
        return PreflightCheck(
            name="policy", passed=False, required=True,
            detail=f"{policy_path} parsed but is not a non-empty mapping",
        )
    return PreflightCheck(
        name="policy", passed=True, required=True,
        detail=f"valid: {policy_path}",
    )


# ---------------------------------------------------------------------------
# 5. Tool-service health
# ---------------------------------------------------------------------------

async def check_tool_service_health(
    tool_service_url: str | None,
    *,
    required_tools: Sequence[str] = ("curl",),
    timeout_seconds: float = _HEALTH_TIMEOUT_SECONDS,
    client: httpx.AsyncClient | None = None,
) -> PreflightCheck:
    """Bounded ``GET /health`` — no bearer token sent (the endpoint is
    intentionally public, ``docs/kali-tool-service.md`` §4), no token
    logged, never ``POST /v1/execute``. Verifies service identity, status,
    and that every tool in *required_tools* reports available.

    *client* is injectable for tests (an ``httpx.AsyncClient`` backed by
    ``httpx.MockTransport``, matching the convention already established in
    ``tests/apex_host/test_remote_backend.py``) — when ``None`` (the
    default), a real, short-lived client is created and closed internally.
    An injected client's lifecycle belongs to the caller and is never
    closed here.
    """
    if not tool_service_url:
        return PreflightCheck(
            name="Kali health", passed=False,
            detail="no tool_service_url configured",
        )
    parsed = urlsplit(tool_service_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return PreflightCheck(
            name="Kali health", passed=False,
            detail=f"tool_service_url {tool_service_url!r} is not a valid http(s) URL",
        )

    url = f"{tool_service_url.rstrip('/')}/health"
    try:
        if client is not None:
            response = await client.get(url, timeout=timeout_seconds)
        else:
            async with httpx.AsyncClient(timeout=timeout_seconds) as owned_client:
                response = await owned_client.get(url)
    except httpx.RequestError as exc:
        return PreflightCheck(
            name="Kali health", passed=False,
            detail=f"GET {url} failed: {exc.__class__.__name__}",
        )

    if response.status_code != 200:
        return PreflightCheck(
            name="Kali health", passed=False,
            detail=f"GET {url} -> HTTP {response.status_code}",
        )
    try:
        data: Any = response.json()
    except ValueError:
        return PreflightCheck(
            name="Kali health", passed=False,
            detail=f"GET {url} returned a non-JSON body",
        )
    if not isinstance(data, dict):
        return PreflightCheck(
            name="Kali health", passed=False,
            detail=f"GET {url} returned a non-object JSON body",
        )
    if data.get("status") != "ok" or data.get("service") != "apex-tool-service":
        return PreflightCheck(
            name="Kali health", passed=False,
            detail=f"unexpected health payload: status={data.get('status')!r} service={data.get('service')!r}",
        )
    tools = data.get("tools")
    if not isinstance(tools, dict):
        return PreflightCheck(
            name="Kali health", passed=False,
            detail="health payload missing a 'tools' object",
        )
    missing = [t for t in required_tools if not tools.get(t)]
    if missing:
        return PreflightCheck(
            name="Kali health", passed=False,
            detail=f"required tool(s) unavailable on the service: {', '.join(missing)}",
        )
    return PreflightCheck(
        name="Kali health", passed=True,
        detail=f"{url} -> ok, required tool(s) available: {', '.join(required_tools)}",
    )


# ---------------------------------------------------------------------------
# 6. Harmless remote smoke
# ---------------------------------------------------------------------------

async def check_remote_smoke(
    config: ApexConfig,
    *,
    tool: str = _DEFAULT_SMOKE_TOOL,
    args: Sequence[str] | None = None,
) -> PreflightCheck:
    """Execute exactly one deterministic, harmless, allowlisted command
    (``curl --version`` by default) through the real
    ``apex_host.tools.backend.select_runtime_backend`` — never a scan,
    never an externally-reachable target, since ``curl --version`` makes
    no network call at all. Client is always closed, even on failure.

    ``select_runtime_backend()``/``RemoteToolBackend.__init__`` fail fast
    with ``ValueError`` for a configuration problem (missing token, bad
    URL) rather than raising once ``execute()`` is called
    (``docs/remote-tool-backend.md`` §2.1) — that ``ValueError`` is caught
    here and turned into an ordinary failed ``PreflightCheck`` (never sends
    a request), exactly like every other check in this module: an
    *ordinary* failure is data, never an unhandled exception reaching the
    entrypoint's caller.
    """
    tool_args = list(args) if args is not None else list(_DEFAULT_SMOKE_ARGS)
    try:
        backend = select_runtime_backend(config)
    except ValueError as exc:
        return PreflightCheck(
            name="remote tool smoke", passed=False,
            detail=f"could not construct backend: {exc}",
        )
    try:
        result = await backend.execute(tool, tool_args)
    finally:
        aclose = getattr(backend, "aclose", None)
        if aclose is not None:
            await aclose()

    if result.backend == "dry-run":
        return PreflightCheck(
            name="remote tool smoke", passed=False,
            detail="backend resolved to dry-run — expected a real remote/local execution",
        )
    if result.timed_out:
        return PreflightCheck(
            name="remote tool smoke", passed=False,
            detail=f"{tool} {' '.join(tool_args)} timed out",
        )
    if result.returncode != 0:
        return PreflightCheck(
            name="remote tool smoke", passed=False,
            detail=f"{tool} {' '.join(tool_args)} exited {result.returncode}: {result.error or result.stderr[:200]}",
        )
    if not (result.stdout.strip() or result.stderr.strip()):
        return PreflightCheck(
            name="remote tool smoke", passed=False,
            detail=f"{tool} {' '.join(tool_args)} produced no output",
        )
    return PreflightCheck(
        name="remote tool smoke", passed=True,
        detail=f"backend={result.backend} {tool} {' '.join(tool_args)} -> returncode=0",
    )


# ---------------------------------------------------------------------------
# 7. LLM readiness
# ---------------------------------------------------------------------------

def check_llm_readiness(config: ApexConfig) -> PreflightCheck:
    """When ``use_llm=False`` (the default), this is a trivial pass — no
    credential, no contact. When enabled with a real provider, this is a
    purely local **configuration validation** — never makes an external
    model request itself; that remains a separate, explicit connectivity
    concern performed only by :func:`probe_llm_readiness`.

    Validates, in order: the provider name is recognized; a model is
    configured (there is no provider-neutral default — see
    ``ApexConfig.planner_model``'s own docstring); the provider/model
    combination has no unambiguous namespace mismatch (Phase 5 —
    upgraded from a warning to a hard failure, since the check is now
    narrowly scoped to the one unambiguous case —
    ``apex_host.llm.errors.detect_provider_model_mismatch``); the
    configured base URL (if any) does not point at a different provider's
    known endpoint (``detect_base_url_provider_mismatch``); and the
    provider's own credential environment variable is present.

    The ``detail`` string always reports, for operator visibility, the
    resolved provider, the configured model identifier, the credential
    variable NAME (never its value), and whether the endpoint is the
    provider's official default or a custom override.
    """
    if not config.use_llm:
        return PreflightCheck(
            name="LLM readiness", passed=True,
            detail="use_llm=False — no credentials required", required=False,
        )
    provider = config.llm_provider
    if provider in ("fake", ""):
        return PreflightCheck(
            name="LLM readiness", passed=True,
            detail=f"llm_provider={provider!r} — no credentials required",
        )
    if provider not in VALID_LLM_PROVIDERS:
        return PreflightCheck(
            name="LLM readiness", passed=False,
            detail=(
                f"invalid llm_provider={provider!r} — expected one of: "
                f"{', '.join(sorted(VALID_LLM_PROVIDERS))}"
            ),
        )

    from apex_host.llm.router import resolve_base_url_for_provider

    base_url = resolve_base_url_for_provider(config, provider)
    host = base_url_host(base_url) or "(official default)"
    kind = _endpoint_kind(provider, base_url)
    model = config.planner_model

    if not model:
        return PreflightCheck(
            name="LLM readiness", passed=False,
            detail=(
                f"provider_model_mismatch: use_llm=True with llm_provider={provider!r} "
                "requires an explicit model (--llm-model / $APEX_LLM_MODEL) — there is "
                "no provider-neutral default"
            ),
        )

    model_mismatch = detect_provider_model_mismatch(provider, model)
    if model_mismatch:
        return PreflightCheck(
            name="LLM readiness", passed=False,
            detail=f"provider_model_mismatch: {model_mismatch}",
        )

    base_mismatch = detect_base_url_provider_mismatch(provider, base_url)
    if base_mismatch:
        return PreflightCheck(
            name="LLM readiness", passed=False,
            detail=f"provider_model_mismatch: {base_mismatch}",
        )

    env_var = CREDENTIAL_ENV_VAR[provider]
    key_present = bool(os.environ.get(env_var))
    if not key_present:
        return PreflightCheck(
            name="LLM readiness", passed=False,
            detail=(
                f"missing_key: use_llm=True with llm_provider={provider!r} "
                f"(model={model!r}, endpoint={kind}, base_url_host={host!r}) requires "
                f"${env_var}"
            ),
        )
    return PreflightCheck(
        name="LLM readiness", passed=True,
        detail=(
            f"llm_provider={provider!r}, model={model!r}, endpoint={kind}, "
            f"base_url_host={host!r}, credential_variable={env_var!r}, credential present"
        ),
    )


def check_llm_model_compatibility(config: ApexConfig) -> PreflightCheck:
    """Secondary, more detailed provider/model/base-URL compatibility
    report — kept for backward compatibility with existing callers of
    this function name. ``check_llm_readiness`` (above) already performs
    the same detection as a HARD failure (Phase 5 — upgraded from a
    warning, now that the check is narrowly scoped to the one unambiguous
    namespace-mismatch case); this function remains ``required=False``
    (informational) and never duplicates a failure the required check
    above would already have reported, so a passing ``check_llm_readiness``
    always implies this one only ever adds detail, never a new blocker.
    """
    if not config.use_llm or config.llm_provider in ("fake", ""):
        return PreflightCheck(
            name="LLM model/provider compatibility", passed=True,
            detail="use_llm=False or llm_provider='fake' — no compatibility check needed",
            required=False,
        )
    provider = config.llm_provider
    if provider not in VALID_LLM_PROVIDERS or not config.planner_model:
        return PreflightCheck(
            name="LLM model/provider compatibility", passed=True,
            detail="invalid provider or missing model — already reported by LLM readiness",
            required=False,
        )

    from apex_host.llm.router import resolve_base_url_for_provider

    base_url = resolve_base_url_for_provider(config, provider)
    host = base_url_host(base_url) or "(official default)"
    model = config.planner_model
    model_mismatch = detect_provider_model_mismatch(provider, model)
    base_mismatch = detect_base_url_provider_mismatch(provider, base_url)
    if model_mismatch or base_mismatch:
        return PreflightCheck(
            name="LLM model/provider compatibility", passed=False,
            detail=model_mismatch or base_mismatch,
            required=False,
        )
    return PreflightCheck(
        name="LLM model/provider compatibility", passed=True,
        detail=f"provider={provider!r}, model={model!r} and base_url_host={host!r} — no known mismatch",
        required=False,
    )


async def probe_llm_readiness(
    config: ApexConfig,
    *,
    timeout_seconds: float = _HEALTH_TIMEOUT_SECONDS,
    client: httpx.AsyncClient | None = None,
) -> PreflightCheck:
    """Bounded, low-token LLM provider readiness probe: exactly one
    minimal, official model-access request through the SELECTED
    provider's own adapter (``apex_host.llm.providers.*.check_readiness
    (network_check=True)``) — never a chat/completion call, costing zero
    completion tokens. Never performed automatically as part of every
    preflight pass — unlike :func:`check_llm_readiness` (a purely local,
    no-network check), this makes a real network call and depends on
    external provider availability, so callers opt in explicitly
    (:func:`apex_host.eval.live_interlock.evaluate_live_interlock` adds it
    only when ``config.llm_required`` is set).

    Distinguishes, via the response, the same failure categories
    :mod:`apex_host.llm.errors` classifies at call time: missing key
    (checked locally, no request made), authentication failure,
    unsupported endpoint, rate limit, network error, and timeout.

    The API key is read from the environment and is **never** included in
    any request URL, header value logged, or returned detail string.

    *client* is accepted for backward compatibility with existing callers
    but is currently unused — each native provider adapter constructs its
    own official SDK client internally rather than a raw ``httpx``
    client. Tests inject failures by monkeypatching the provider's own
    SDK client construction (see ``tests/apex_host/test_llm_providers.py``)
    rather than an injected ``httpx.AsyncClient`` — this function itself
    never reaches the real OpenAI/Anthropic/OpenRouter API in a unit test.
    """
    if not config.use_llm or config.llm_provider in ("fake", ""):
        return PreflightCheck(
            name="LLM provider probe", passed=True,
            detail="use_llm=False or llm_provider='fake' — no probe performed", required=False,
        )
    provider = config.llm_provider
    if provider not in VALID_LLM_PROVIDERS or not config.planner_model:
        return PreflightCheck(
            name="LLM provider probe", passed=False,
            detail="invalid provider or missing model — see LLM readiness check",
        )

    readiness = await _provider_readiness(config, provider, network_check=True, timeout_seconds=timeout_seconds)
    if not readiness.configuration_valid:
        return PreflightCheck(
            name="LLM provider probe", passed=False,
            detail=f"{readiness.error_category}: {readiness.error_reason}",
        )
    if readiness.reachable is False:
        return PreflightCheck(
            name="LLM provider probe", passed=False,
            detail=f"{readiness.error_category}: {readiness.error_reason}",
        )
    return PreflightCheck(
        name="LLM provider probe", passed=True,
        detail=(
            f"provider={readiness.provider!r} reachable and authenticated "
            f"(endpoint={readiness.endpoint_kind})"
        ),
    )


async def _provider_readiness(
    config: ApexConfig, provider: str, *, network_check: bool, timeout_seconds: float
) -> "ProviderReadiness":
    """Construct the right native provider adapter for *provider* and
    return its own ``check_readiness()`` result. The one place preflight
    constructs a real provider adapter — never called for ``network_check
    =False`` (``check_llm_readiness`` computes that purely from config,
    with no provider object at all)."""
    from apex_host.llm.router import resolve_base_url_for_provider

    base_url = resolve_base_url_for_provider(config, provider)
    if provider == "openai":
        from apex_host.llm.providers.openai import OpenAIProvider

        adapter = OpenAIProvider(base_url=base_url, timeout_seconds=timeout_seconds)
    elif provider == "anthropic":
        from apex_host.llm.providers.anthropic import AnthropicProvider

        adapter = AnthropicProvider(base_url=base_url, timeout_seconds=timeout_seconds)  # type: ignore[assignment]
    else:
        from apex_host.llm.providers.openrouter import OpenRouterProvider

        adapter = OpenRouterProvider(base_url=base_url, timeout_seconds=timeout_seconds)  # type: ignore[assignment]
    result = await adapter.check_readiness(network_check=network_check)
    result.requested_model = config.planner_model
    return result


# ---------------------------------------------------------------------------
# 8. HTB VPN readiness (Infra Phase 10)
# ---------------------------------------------------------------------------
#
# All VPN checks in this section are inert (never fire, never contact a
# network) unless the caller explicitly configures a VPN service URL —
# the same "safe by omission" pattern ``check_tool_service_health``/
# ``check_remote_smoke`` already establish for the Kali tool service.
# None of these checks import or start the engagement graph, mount the
# Docker socket, or inspect another container directly — they only ever
# speak plain, bounded HTTP to the VPN container's own first-party
# readiness server (``docker/vpn/readiness_server.py``).

_VPN_HEALTH_TIMEOUT_SECONDS = 10.0
_VPN_READINESS_SERVICE_NAME = "apex-vpn-readiness"


def check_htb_profile_configured(htb_ovpn_path: str | None, *, required: bool = False) -> PreflightCheck:
    """Host-side visibility check: does the configured ``.ovpn`` profile
    path exist and is it readable? Never opens or reads the file's
    *content* — only ``Path.exists()``/``os.access(..., os.R_OK)``, so no
    credential material is ever touched by this check, only its
    filesystem metadata.

    This is a *host*-side convenience check — the apex container itself
    never mounts or reads the profile at runtime (only the ``vpn``
    container does, via ``compose.htb.yaml``); this check exists so an
    operator can validate their local ``.env``/``secrets/`` setup with
    ``apex_host.eval.check_config`` or ``container_entrypoint.py check``
    *before* running ``docker compose --profile htb up``.

    ``htb_ovpn_path=None`` (not configured) is a soft, informational pass
    when ``required=False`` (every mode except a future explicit
    "preparing for HTB" check) — matching the ``check_policy`` pattern:
    an unconfigured VPN profile is a legitimate, safe state for
    ``check``/``smoke``/``dry-run``. A *configured* path that does not
    exist or is not readable is always a hard failure, regardless of
    ``required`` — an operator who set the variable clearly intended to
    use it.
    """
    if not htb_ovpn_path:
        if required:
            return PreflightCheck(
                name="HTB profile configured", passed=False, required=True,
                detail="APEX_HTB_OVPN_PATH is not set — required to use the htb Compose profile",
            )
        return PreflightCheck(
            name="HTB profile configured", passed=True, required=False,
            detail="APEX_HTB_OVPN_PATH not set — VPN/htb mode not in use",
        )
    path = Path(htb_ovpn_path)
    if not path.exists():
        return PreflightCheck(
            name="HTB profile configured", passed=False, required=True,
            detail=f"configured profile not found: {path.name} (path exists check failed)",
        )
    if not os.access(path, os.R_OK):
        return PreflightCheck(
            name="HTB profile configured", passed=False, required=True,
            detail=f"configured profile {path.name} exists but is not readable",
        )
    return PreflightCheck(
        name="HTB profile configured", passed=True, required=True,
        detail=f"profile found and readable: {path.name}",
    )


async def check_vpn_readiness(
    vpn_service_url: str | None,
    *,
    expected_route_cidr: str = "10.129.0.0/16",
    timeout_seconds: float = _VPN_HEALTH_TIMEOUT_SECONDS,
    client: httpx.AsyncClient | None = None,
) -> list[PreflightCheck]:
    """Query the VPN container's own readiness HTTP server
    (``docker/vpn/readiness_server.py``, ``GET /health``) and produce two
    checks from the single response: "VPN service reachable" and "VPN
    tunnel/route ready". One HTTP round trip, not two.

    ``vpn_service_url=None`` (the default everywhere outside the ``htb``
    Compose profile) returns an empty list — no checks, no network call.
    This is what keeps every non-HTB invocation of
    ``run_local_checks``/``run_smoke_checks`` byte-for-byte unaffected by
    this section's existence.

    Never inspects another container directly and never mounts the Docker
    socket — this function only ever speaks HTTP to *vpn_service_url*.
    Never pings, scans, or contacts an HTB target — the readiness
    server's own ``/health`` endpoint performs only local ``ip link
    show``/``ip route show`` inspection (see
    ``docker/vpn/tunnel_status.py``), never a route lookup or the
    ``/route-check`` endpoint (that one is deliberately excluded from
    this automatic preflight path — see
    ``apex_host/eval/vpn_route_check.py``'s own module docstring for why
    it remains a manual-only tool).

    *client* is injectable for tests, matching
    ``check_tool_service_health``'s own convention.
    """
    if not vpn_service_url:
        return []

    parsed = urlsplit(vpn_service_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return [
            PreflightCheck(
                name="VPN service reachable", passed=False,
                detail=f"vpn_service_url {vpn_service_url!r} is not a valid http(s) URL",
            ),
        ]

    url = f"{vpn_service_url.rstrip('/')}/health"
    try:
        if client is not None:
            response = await client.get(url, timeout=timeout_seconds)
        else:
            async with httpx.AsyncClient(timeout=timeout_seconds) as owned_client:
                response = await owned_client.get(url)
    except httpx.RequestError as exc:
        return [
            PreflightCheck(
                name="VPN service reachable", passed=False,
                detail=f"GET {url} failed: {exc.__class__.__name__}",
            ),
        ]

    if response.status_code != 200:
        return [
            PreflightCheck(
                name="VPN service reachable", passed=False,
                detail=f"GET {url} -> HTTP {response.status_code}",
            ),
        ]
    try:
        data: Any = response.json()
    except ValueError:
        return [
            PreflightCheck(
                name="VPN service reachable", passed=False,
                detail=f"GET {url} returned a non-JSON body",
            ),
        ]
    if not isinstance(data, dict) or data.get("service") != _VPN_READINESS_SERVICE_NAME:
        return [
            PreflightCheck(
                name="VPN service reachable", passed=False,
                detail=f"unexpected readiness payload from {url}: {data!r}",
            ),
        ]

    service_check = PreflightCheck(
        name="VPN service reachable", passed=True,
        detail=f"{url} -> ok (service={_VPN_READINESS_SERVICE_NAME})",
    )

    tunnel_ready = bool(data.get("tunnel"))
    reported_cidr = data.get("route_cidr")
    if tunnel_ready and reported_cidr == expected_route_cidr:
        tunnel_check = PreflightCheck(
            name="VPN tunnel/route ready", passed=True,
            detail=f"tunnel up, route {reported_cidr} present",
        )
    elif tunnel_ready:
        tunnel_check = PreflightCheck(
            name="VPN tunnel/route ready", passed=False,
            detail=(
                f"tunnel up but reported route_cidr={reported_cidr!r} does not "
                f"match expected {expected_route_cidr!r} — see APEX_HTB_ROUTE_CIDR"
            ),
        )
    else:
        tunnel_check = PreflightCheck(
            name="VPN tunnel/route ready", passed=False,
            detail=f"VPN service reports status={data.get('status')!r} — tunnel not yet ready",
        )
    return [service_check, tunnel_check]


# ---------------------------------------------------------------------------
# 9. Live confirmation (run mode only)
# ---------------------------------------------------------------------------

def check_live_confirmation(*, confirmed: bool, dry_run: bool) -> PreflightCheck:
    """The live-run safeguard: requires both an explicit ``--confirm-live``
    CLI flag (never an environment variable — "prefer an explicit CLI flag
    because environment values can be stale") and ``dry_run=False`` already
    resolved through the normal, unmodified CLI>env>default precedence
    (``apex_host.config_env.resolve_dry_run`` — this function does not
    bypass or duplicate that safety logic, only checks its outcome)."""
    if dry_run:
        return PreflightCheck(
            name="live confirmation", passed=False,
            detail="dry_run is still True — pass --no-dry-run to enable real execution",
        )
    if not confirmed:
        return PreflightCheck(
            name="live confirmation", passed=False,
            detail="--confirm-live was not passed — live mode refuses to run without explicit confirmation",
        )
    return PreflightCheck(name="live confirmation", passed=True, detail="confirmed")


# ---------------------------------------------------------------------------
# Mode-level aggregate runners
# ---------------------------------------------------------------------------

def run_local_checks(
    config: ApexConfig,
    *,
    default_report_dir: str,
    report_path: str | None = None,
    graph_path: str | None = None,
    policy_required: bool = False,
    htb_profile_required: bool = False,
) -> list[PreflightCheck]:
    """The checks common to every mode: configuration, report directory,
    compiled knowledge, policy, LLM readiness, HTB profile visibility.
    Never contacts a network — ``check_htb_profile_configured`` only
    inspects local filesystem metadata (never the VPN service itself;
    that is ``run_vpn_checks``, below, called separately since it is
    async and network-touching)."""
    return [
        check_configuration(config),
        check_report_directory(
            default_dir=default_report_dir, report_path=report_path, graph_path=graph_path,
        ),
        check_compiled_knowledge(config.knowledge_root),
        check_policy(config, required=policy_required),
        check_llm_readiness(config),
        check_llm_model_compatibility(config),
        check_htb_profile_configured(config.htb_ovpn_path, required=htb_profile_required),
    ]


async def run_vpn_checks(config: ApexConfig) -> list[PreflightCheck]:
    """VPN readiness checks (Infra Phase 10) — a thin wrapper around
    ``check_vpn_readiness`` that reads its parameters from *config*.
    Returns an empty list (no network call at all) when
    ``config.vpn_service_url`` is unset — the default for every
    non-``htb``-profile invocation, which is what keeps
    ``run_smoke_checks``'s behavior byte-for-byte unchanged for the
    default (non-VPN) Compose workflow.
    """
    return await check_vpn_readiness(
        config.vpn_service_url,
        expected_route_cidr=config.htb_route_cidr,
        timeout_seconds=config.vpn_health_timeout_seconds,
    )


async def run_smoke_checks(
    config: ApexConfig,
    *,
    default_report_dir: str,
    report_path: str | None = None,
    graph_path: str | None = None,
) -> PreflightResult:
    """``check`` mode's local checks, plus Kali health and one harmless
    remote-tool execution — used by the entrypoint's ``smoke`` mode.
    Also includes VPN readiness checks (Infra Phase 10) when
    ``config.vpn_service_url`` is configured — inert otherwise (§ above)."""
    checks = run_local_checks(
        config, default_report_dir=default_report_dir,
        report_path=report_path, graph_path=graph_path,
    )
    checks.append(check_remote_backend_selected(config))
    checks.append(await check_tool_service_health(config.tool_service_url))
    checks.append(await check_remote_smoke(config))
    checks.extend(await run_vpn_checks(config))
    return PreflightResult(checks)
