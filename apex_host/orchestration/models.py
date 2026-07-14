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
    """Convert a TaskSpec to the minimal dict stored in state['current_task']."""
    if task is None:
        return None
    return {
        "id": task.id,
        "executor_domain": task.executor_domain,
        "params": task.params,
    }
