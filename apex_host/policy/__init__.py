# __init__.py
# Public exports for the apex_host.policy package: PolicyAdvisor, LLMPolicyGuard, models, and load_policy.
"""Policy package for the APEX host application.

Public surface::

    from apex_host.policy import PolicyAdvisor, PolicyDecision, PolicyStatus
    from apex_host.policy import load_policy, ScopePolicy, PolicyRule
    from apex_host.policy import LLMPolicyGuard

Quick-start::

    from apex_host.policy import PolicyAdvisor, LLMPolicyGuard, load_policy

    policy = load_policy(config)          # loads YAML or falls back to conservative default
    advisor = PolicyAdvisor(policy, config)
    decision = advisor.review_task(task, phase, evidence, config)

    guard = LLMPolicyGuard(config)        # pre/post LLM call content checks
"""
from __future__ import annotations

from apex_host.policy.advisor import PolicyAdvisor
from apex_host.policy.llm_guard import LLMPolicyGuard
from apex_host.policy.models import (
    PolicyDecision,
    PolicyRule,
    PolicyStatus,
    ScopePolicy,
)
from apex_host.policy.policy_loader import load_policy

__all__ = [
    "LLMPolicyGuard",
    "PolicyAdvisor",
    "PolicyDecision",
    "PolicyRule",
    "PolicyStatus",
    "ScopePolicy",
    "load_policy",
]
