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
    credential, no contact. When enabled with a real provider, verifies
    ``OPENAI_API_KEY`` is present (never its value) — never makes an
    external model request itself; that remains a separate, explicit
    connectivity concern this function does not perform.
    """
    if not config.use_llm:
        return PreflightCheck(
            name="LLM readiness", passed=True,
            detail="use_llm=False — no credentials required", required=False,
        )
    if config.llm_provider in ("fake", ""):
        return PreflightCheck(
            name="LLM readiness", passed=True,
            detail=f"llm_provider={config.llm_provider!r} — no credentials required",
        )
    if not os.environ.get("OPENAI_API_KEY"):
        return PreflightCheck(
            name="LLM readiness", passed=False,
            detail=f"use_llm=True with llm_provider={config.llm_provider!r} requires $OPENAI_API_KEY",
        )
    return PreflightCheck(
        name="LLM readiness", passed=True,
        detail=f"llm_provider={config.llm_provider!r}, credential present",
    )


# ---------------------------------------------------------------------------
# 8. Live confirmation (run mode only)
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
) -> list[PreflightCheck]:
    """The checks common to every mode: configuration, report directory,
    compiled knowledge, policy, LLM readiness. Never contacts a network."""
    return [
        check_configuration(config),
        check_report_directory(
            default_dir=default_report_dir, report_path=report_path, graph_path=graph_path,
        ),
        check_compiled_knowledge(config.knowledge_root),
        check_policy(config, required=policy_required),
        check_llm_readiness(config),
    ]


async def run_smoke_checks(
    config: ApexConfig,
    *,
    default_report_dir: str,
    report_path: str | None = None,
    graph_path: str | None = None,
) -> PreflightResult:
    """``check`` mode's local checks, plus Kali health and one harmless
    remote-tool execution — used by the entrypoint's ``smoke`` mode."""
    checks = run_local_checks(
        config, default_report_dir=default_report_dir,
        report_path=report_path, graph_path=graph_path,
    )
    checks.append(check_remote_backend_selected(config))
    checks.append(await check_tool_service_health(config.tool_service_url))
    checks.append(await check_remote_smoke(config))
    return PreflightResult(checks)
