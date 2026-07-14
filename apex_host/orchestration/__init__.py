# __init__.py
# Public re-exports for the apex_host orchestration package.
"""Orchestration package for the APEX engagement loop.

This package decomposes ``apex_host/graph.py``'s monolithic
``build_apex_graph`` function into focused, independently-testable modules.
The public surface is unchanged — import ``build_apex_graph`` from here or
from ``apex_host.graph`` (which re-exports it).
"""
from __future__ import annotations

from apex_host.orchestration.builder import build_apex_graph as build_apex_graph
from apex_host.orchestration.dependencies import OrchestrationDeps as OrchestrationDeps

__all__ = ["build_apex_graph", "OrchestrationDeps"]
