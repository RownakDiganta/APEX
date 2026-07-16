# models.py
# Lightweight orchestration-local type aliases and helper record builders.
"""Lightweight types used within the orchestration package.

These are not exported as part of the public apex_host API — they exist to
give the orchestration modules a shared vocabulary without pulling in heavy
external dependencies.
"""
from __future__ import annotations

from typing import Any

from apex_host.policy.models import PolicyDecision
from apex_host.security.redaction import REDACTED_PLACEHOLDER


def make_pd_entry(
    tool: str, target: str, phase: str, decision: PolicyDecision
) -> dict[str, Any]:
    """Build a policy-decision record for ``state['policy_decisions']``."""
    return {
        "tool": tool,
        "target": target,
        "phase": phase,
        "status": decision.status.value,
        "rule_name": decision.rule_name,
        "reason": decision.reason,
    }


def task_info(task: Any) -> dict[str, Any] | None:
    """Convert a TaskSpec to the minimal dict stored in state['current_task'].

    Phase 12B: ``state['current_task']`` is public, checkpoint-persisted
    ``ApexGraphState`` — CredentialPlanner's telnet/ssh/ftp TaskSpecs
    necessarily carry the plaintext password in ``task.params["password"]``
    (the executor needs it to authenticate), but that value must never
    reach serialized state. The ``params`` dict is copied and any
    ``"password"`` key is masked by name — a simple, bulletproof
    key-based guard, not a duplicate of the substring-based redaction
    logic ``apex_host.security.redaction`` centralizes (P8-S06).
    """
    if task is None:
        return None
    params = dict(task.params)
    if "password" in params:
        params["password"] = REDACTED_PLACEHOLDER
    return {
        "id": task.id,
        "executor_domain": task.executor_domain,
        "params": params,
    }
