# models.py
# Data shapes for policy decisions: PolicyStatus, PolicyDecision, PolicyRule, and ScopePolicy.
from __future__ import annotations

import enum
from dataclasses import dataclass


class PolicyStatus(str, enum.Enum):
    """Outcome of a single policy review."""
    approved = "approved"
    blocked = "blocked"
    needs_human_review = "needs_human_review"


@dataclass(slots=True)
class PolicyDecision:
    """The result of PolicyAdvisor.review_task()."""
    status: PolicyStatus
    rule_name: str
    reason: str
    task_tool: str = ""
    task_target: str = ""

    @property
    def is_approved(self) -> bool:
        return self.status == PolicyStatus.approved

    @property
    def is_blocked(self) -> bool:
        return self.status == PolicyStatus.blocked

    @property
    def needs_review(self) -> bool:
        return self.status == PolicyStatus.needs_human_review


@dataclass(slots=True)
class PolicyRule:
    """Metadata about a named policy rule.

    The actual check logic lives as a module-level function in rules.py.
    This dataclass is used for registration, documentation, and enabling/
    disabling rules at runtime.
    """
    name: str
    description: str
    enabled: bool = True


@dataclass(slots=True)
class ScopePolicy:
    """The active engagement scope policy, built from config + optional YAML.

    ``allowed_targets`` is normally a single-element frozenset containing
    ``config.target``.  All tools that produce output touching an IP outside
    this set are blocked.

    ``blocked_tools`` are blocked unconditionally regardless of what appears
    in ``ApexConfig.allowed_tools``.  This is additive to the safety.py gate
    — even tools on the allowed list are blocked here if they appear in this
    set.

    ``policy_loaded`` is True when the policy YAML file was found and parsed
    successfully.  False means the conservative default is in effect.
    """
    allowed_targets: frozenset[str]
    blocked_tools: frozenset[str]
    allow_password_lists: bool
    allow_sensitive_data_access: bool
    require_review_for: list[str]
    policy_loaded: bool
    policy_source: str
