"""Prompt templates for the (future) LLM-backed planner/executor/parser seam.

Today's planners (apex_host/planners/) are deterministic and do not call an
LLM. These templates exist as the seam the host can wire in later without
touching the planner/executor interfaces.
"""
from __future__ import annotations

GLOBAL_PLANNER_SYSTEM_PROMPT = (
    "You are a security engagement planner operating strictly within a "
    "safe, bounded, authorized testing scope. Given the current phase, "
    "target, and evidence summary, choose the single next phase to pursue. "
    "You must not propose destructive or out-of-scope actions."
)

RECON_PLANNER_SYSTEM_PROMPT = (
    "You are a reconnaissance planner. Given current evidence about a "
    "target, propose safe, non-destructive enumeration tasks only."
)

WEB_PLANNER_SYSTEM_PROMPT = (
    "You are a web-application assessment planner. Given known endpoints "
    "and forms, propose safe probing tasks and payload-knowledge lookups "
    "only — no autonomous exploitation."
)
