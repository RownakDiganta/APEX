# advisor.py
# PolicyAdvisor: deterministic, LLM-free scope and policy checker for APEX engagements.
"""Policy advisor for the APEX host application.

``PolicyAdvisor`` is the single public entry point for scope/policy checking.
It is deterministic and requires no LLM.  A missing policy file makes the
advisor *more* restrictive, not less — the conservative default blocks
everything outside the assigned target.

Usage::

    from apex_host.policy import PolicyAdvisor, load_policy

    policy = load_policy(config)
    advisor = PolicyAdvisor(policy, config)

    decision = advisor.review_task(task, phase="recon", evidence=bundle, config=config)
    if decision.is_blocked:
        logger.warning("Task blocked by policy: %s", decision.reason)
    elif decision.needs_review:
        raise RuntimeError(f"Human approval required: {decision.reason}")
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable

from apex_host.policy.models import PolicyDecision, PolicyStatus
from apex_host.policy.rules import ALL_RULES

if TYPE_CHECKING:
    from apex_host.config import ApexConfig
    from apex_host.policy.models import ScopePolicy
    from memfabric.types import EvidenceBundle, TaskSpec

logger = logging.getLogger(__name__)

# Type alias for a rule function.
_RuleFn = Callable[["TaskSpec", "ScopePolicy", "ApexConfig"], PolicyDecision | None]

# Sentinel decision returned when policy_enabled=False.
_POLICY_DISABLED = PolicyDecision(
    status=PolicyStatus.approved,
    rule_name="policy_disabled",
    reason="PolicyAdvisor is disabled via config.policy_enabled=False",
)

# Sentinel decision returned when all rules pass without an explicit result.
_DEFAULT_APPROVED = PolicyDecision(
    status=PolicyStatus.approved,
    rule_name="default_allow",
    reason="Task passed all policy rules",
)


class PolicyAdvisor:
    """Deterministic scope and policy checker.

    Constructed once per engagement.  Thread-safe and stateless between calls
    (consistent with memfabric Invariant 6 for executors — advisors follow the
    same principle).

    Parameters
    ----------
    policy:
        Loaded ``ScopePolicy`` (from ``policy_loader.load_policy``).
    config:
        ``ApexConfig`` captured at construction time.  ``review_task`` also
        accepts a ``config`` parameter so callers can supply a fresher copy —
        the call-site config takes precedence when provided.
    """

    def __init__(self, policy: "ScopePolicy", config: "ApexConfig") -> None:
        self._policy = policy
        self._config = config
        logger.info(
            "PolicyAdvisor initialised: policy_loaded=%s source=%r "
            "allow_password_lists=%s allow_sensitive_data=%s",
            policy.policy_loaded,
            policy.policy_source,
            policy.allow_password_lists,
            policy.allow_sensitive_data_access,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def review_task(
        self,
        task: "TaskSpec",
        phase: str,
        evidence: "EvidenceBundle",
        config: "ApexConfig",
    ) -> PolicyDecision:
        """Apply all policy rules to *task* and return the binding decision.

        The call-site *config* takes precedence over the constructor config so
        that per-turn config changes (e.g. mid-run flag changes) are honoured.

        Rules are evaluated in the order defined in ``rules.ALL_RULES``.  The
        first rule that returns a non-None ``PolicyDecision`` wins.  If no rule
        fires, the task is ``approved`` via the default-allow sentinel.

        This method is synchronous and requires no LLM, no I/O, and no
        MemoryAPI access.

        Parameters
        ----------
        task:
            The ``TaskSpec`` to evaluate.
        phase:
            Current engagement phase (e.g. ``"recon"``, ``"web"``).
            Reserved for future phase-specific rules; not used by current rules.
        evidence:
            The current ``EvidenceBundle``.  Reserved for future evidence-aware
            rules; not used by current rules.
        config:
            Active ``ApexConfig``.  Overrides the constructor config for this
            call.

        Returns
        -------
        PolicyDecision
            Always returns a decision — never raises.
        """
        effective_config = config

        if not effective_config.policy_enabled:
            return _POLICY_DISABLED

        tool = str(task.params.get("tool", ""))
        target = str(task.params.get("target", ""))

        for rule_fn in ALL_RULES:
            try:
                decision = rule_fn(task, self._policy, effective_config)
            except Exception as exc:  # noqa: BLE001 — rules must never crash the advisor
                logger.warning(
                    "PolicyAdvisor: rule %r raised unexpectedly for tool=%r target=%r: %s",
                    getattr(rule_fn, "__name__", str(rule_fn)),
                    tool,
                    target,
                    exc,
                )
                continue

            if decision is not None:
                _log_decision(decision, phase, tool, target)
                return decision

        _log_decision(_DEFAULT_APPROVED, phase, tool, target)
        return _DEFAULT_APPROVED

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def policy(self) -> "ScopePolicy":
        """The active ScopePolicy (read-only view)."""
        return self._policy


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _log_decision(decision: PolicyDecision, phase: str, tool: str, target: str) -> None:
    if decision.is_blocked:
        logger.warning(
            "PolicyAdvisor [%s] BLOCKED tool=%r target=%r — rule=%r reason=%r",
            phase, tool, target, decision.rule_name, decision.reason,
        )
    elif decision.needs_review:
        logger.warning(
            "PolicyAdvisor [%s] NEEDS_REVIEW tool=%r target=%r — rule=%r reason=%r",
            phase, tool, target, decision.rule_name, decision.reason,
        )
    else:
        logger.debug(
            "PolicyAdvisor [%s] approved tool=%r target=%r — rule=%r",
            phase, tool, target, decision.rule_name,
        )
