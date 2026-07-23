# live_interlock.py
# The one centralized live-run safety interlock — requires multiple independent positive confirmations before any real, target-directed engagement action may begin.
"""Centralized live-run safety interlock (Phase 25).

Before this module, the "may a real, target-directed engagement start?"
decision was implemented twice, ad-hoc, in two different places:
``apex_host.container_entrypoint._handle_run`` (Docker-only) had a full
interlock; ``apex_host.eval.run_htb_local`` (the primary, documented
host-side entrypoint) had none at all beyond resolving ``dry_run``. This
module is the single, reusable implementation both entrypoints now call —
never duplicated, never bypassed.

``evaluate_live_interlock()`` requires **all** of the following independent
positive confirmations before permitting a live engagement:

1. ``dry_run_disabled`` — ``config.dry_run`` resolved to ``False`` through
   the normal, unmodified CLI>env>default precedence
   (``apex_host.config_env.resolve_dry_run``) — this module never bypasses
   or duplicates that resolution, only reads its outcome.
2. ``live_confirmed`` — an explicit, caller-supplied confirmation flag
   (e.g. a CLI ``--confirm-live`` flag). **Never** satisfiable by an
   environment variable alone — a stale exported variable must not be able
   to authorize a live run days after the operator intended it once.
3. ``target_supplied`` — a real target was explicitly provided (not the
   config-check synthetic placeholder, not empty).
4. ``target_in_scope`` — the target is within ``PolicyAdvisor``'s resolved
   scope (``ScopePolicy.allowed_targets``, via ``load_policy(config)``) —
   this is the SAME scope policy every tool-execution call is already
   gated against; the interlock does not invent a second scope concept.
5. ``preflight_passed`` — the full preflight (``apex_host.eval.preflight
   .run_local_checks`` with ``policy_required=True``, plus Kali/remote-
   backend health and VPN readiness when applicable) passes with no
   required-check failures.

Any single missing confirmation blocks the interlock — this is
deliberately NOT a single boolean flag (CLAUDE.md-style "at least two
independent positive confirmations", generalized here to five). No
destructive or exploitative request is ever made while evaluating this
interlock — every confirmation is either a pure config/policy read or one
of the existing, already-conservative preflight checks (bounded ``GET
/health`` calls, a fixed harmless ``curl --version`` smoke command).

This module never itself starts, imports, or references the engagement
graph (``apex_host.graph``/``apex_host.orchestration``) — it is a pure
gate a caller consults before deciding to import and run that graph.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from apex_host.config_env import CONFIG_CHECK_TARGET_PLACEHOLDER
from apex_host.eval.preflight import PreflightResult, run_local_checks, run_vpn_checks

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

__all__ = ["LiveInterlockResult", "evaluate_live_interlock"]


@dataclass(frozen=True, slots=True)
class LiveInterlockResult:
    """The outcome of one interlock evaluation — five named confirmations
    plus the full underlying preflight detail, all safe to log or export
    as-is (no secret, no raw command output beyond what
    ``PreflightCheck``/``PreflightResult`` already sanitize)."""

    confirmations: dict[str, bool]
    reasons: dict[str, str]
    preflight: PreflightResult = field(default_factory=lambda: PreflightResult([]))

    @property
    def permitted(self) -> bool:
        """True only when every confirmation is True. A live engagement
        may proceed to target-directed action if and only if this is True."""
        return all(self.confirmations.values())

    @property
    def failed_confirmations(self) -> list[str]:
        return [name for name, ok in self.confirmations.items() if not ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "permitted": self.permitted,
            "confirmations": dict(self.confirmations),
            "reasons": dict(self.reasons),
            "preflight": self.preflight.to_dict(),
        }

    def format_text(self) -> str:
        lines = ["Live-run safety interlock:"]
        for name, ok in self.confirmations.items():
            tag = "PASS" if ok else "FAIL"
            lines.append(f"  [{tag}] {name}")
            if not ok and self.reasons.get(name):
                lines.append(f"         {self.reasons[name]}")
        if self.preflight.checks:
            lines.append("")
            lines.append(self.preflight.format_text())
        lines.append("")
        if self.permitted:
            lines.append("Live interlock: PERMITTED — all confirmations satisfied.")
        else:
            lines.append(
                f"Live interlock: BLOCKED — failed confirmation(s): "
                f"{', '.join(self.failed_confirmations)}"
            )
        return "\n".join(lines)


def _target_in_scope(config: "ApexConfig") -> tuple[bool, str]:
    """Reads the SAME ``PolicyAdvisor``/``ScopePolicy`` scope every tool
    execution is already gated against (``apex_host.policy.policy_loader
    .load_policy``) — never a second, invented scope concept. A policy
    load failure is treated as out-of-scope (fail closed), never
    permissive."""
    try:
        from apex_host.policy.policy_loader import load_policy

        policy = load_policy(config)
    except Exception as exc:  # noqa: BLE001 - a policy load failure must fail closed
        return False, f"could not load policy for scope check: {type(exc).__name__}"
    if config.target not in policy.allowed_targets:
        return False, (
            f"target {config.target!r} is not in the resolved policy scope "
            f"{sorted(policy.allowed_targets)}"
        )
    return True, f"target in scope (allowed_targets={sorted(policy.allowed_targets)})"


async def evaluate_live_interlock(
    config: "ApexConfig",
    *,
    confirmed: bool,
    default_report_dir: str,
    report_path: str | None = None,
    graph_path: str | None = None,
) -> LiveInterlockResult:
    """Evaluate every confirmation required before a live, target-directed
    engagement may start. Never mutates *config*, never contacts the
    engagement target itself — only ``config.target``'s scope membership
    and the existing, already-conservative preflight checks (Kali health,
    one harmless smoke command, VPN readiness) are consulted.

    Returns a :class:`LiveInterlockResult` whose ``.permitted`` property is
    the single boolean callers should act on. Callers must not start
    ``run_engagement()``/``run_apex_graph`` unless ``.permitted`` is
    ``True`` — this function performs the evaluation only, it does not
    itself raise or exit the process.
    """
    confirmations: dict[str, bool] = {}
    reasons: dict[str, str] = {}

    confirmations["dry_run_disabled"] = not config.dry_run
    if config.dry_run:
        reasons["dry_run_disabled"] = "dry_run is still True — pass --no-dry-run to enable real execution"

    confirmations["live_confirmed"] = bool(confirmed)
    if not confirmed:
        reasons["live_confirmed"] = (
            "--confirm-live was not passed — live mode refuses to run without explicit confirmation"
        )

    target_supplied = bool(config.target) and config.target != CONFIG_CHECK_TARGET_PLACEHOLDER
    confirmations["target_supplied"] = target_supplied
    if not target_supplied:
        reasons["target_supplied"] = "no real target configured (--target / $APEX_TARGET)"

    if target_supplied:
        in_scope, scope_reason = _target_in_scope(config)
    else:
        in_scope, scope_reason = False, "cannot evaluate scope without a real target"
    confirmations["target_in_scope"] = in_scope
    reasons["target_in_scope"] = scope_reason

    if not all((confirmations["dry_run_disabled"], confirmations["live_confirmed"], target_supplied, in_scope)):
        # Fail fast: skip the full (network-touching) preflight entirely
        # when a cheap, purely local confirmation has already failed —
        # "terminate before target execution" applies to unnecessary Kali/
        # VPN health calls too, not only to the target itself. An empty
        # PreflightResult here reports honestly as "not evaluated", never
        # as a false pass.
        confirmations["preflight_passed"] = False
        reasons["preflight_passed"] = "not evaluated — an earlier confirmation already failed"
        return LiveInterlockResult(confirmations=confirmations, reasons=reasons, preflight=PreflightResult([]))

    preflight = PreflightResult(run_local_checks(
        config, default_report_dir=default_report_dir,
        report_path=report_path, graph_path=graph_path, policy_required=True,
    ))
    if config.tool_backend == "remote":
        from apex_host.eval.preflight import check_remote_smoke, check_tool_service_health

        preflight = PreflightResult([
            *preflight.checks,
            await check_tool_service_health(config.tool_service_url),
            await check_remote_smoke(config),
        ])
    if config.llm_required:
        # config.llm_required means the operator has declared this live
        # run must be LLM-guided — the cheap, no-network
        # check_llm_readiness() (already in run_local_checks) only proves
        # a key is present, not that the provider/model actually work.
        # Add the real, bounded, low-token network probe here so a
        # misconfigured model/provider (e.g. the OpenRouter-style model
        # id against the real OpenAI API that caused the first live
        # test's failure) blocks the interlock instead of silently
        # falling back to deterministic planning after burning turns.
        from apex_host.eval.preflight import probe_llm_readiness

        preflight = PreflightResult([*preflight.checks, await probe_llm_readiness(config)])
    preflight = PreflightResult([*preflight.checks, *await run_vpn_checks(config)])

    confirmations["preflight_passed"] = preflight.passed
    if not preflight.passed:
        names = ", ".join(c.name for c in preflight.failed_required)
        reasons["preflight_passed"] = f"required preflight check(s) failed: {names}"

    return LiveInterlockResult(confirmations=confirmations, reasons=reasons, preflight=preflight)
