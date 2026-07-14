# graph.py
# Thin re-export wrapper: build_apex_graph now lives in apex_host/orchestration/builder.py.
"""APEX engagement LangGraph — public API surface.

The implementation was decomposed from this file into the
``apex_host/orchestration/`` package (Phase 10).  This module re-exports
``build_apex_graph`` and the module-level helpers that external callers or
tests may reference so that all existing imports remain unbroken.

Graph topology (unchanged)::

    START → load_context → global_plan → route_phase
          → [recon_agent | web_agent | browser_agent | execute_agent | priv_esc_agent]
          → parse_observation → write_memory
          → route_after_write → repair_agent (optional)
          → reflect_or_continue → END  (or loop back to load_context)

See ``apex_host/orchestration/`` for the decomposed node implementations and
``CLAUDE.md §11.3`` for design rationale.
"""
from __future__ import annotations

# Public surface — unchanged API
from apex_host.orchestration.builder import build_apex_graph as build_apex_graph  # noqa: F401
# Re-export helpers used directly in tests
from apex_host.orchestration.completion import outcome_for as _outcome_for  # noqa: F401
from apex_host.orchestration.parsing_node import parse_single_result as _parse_single_result  # noqa: F401
from apex_host.orchestration.routing import PHASE_NODE as _PHASE_NODE  # noqa: F401

__all__ = ["build_apex_graph"]
