# context_node.py
# Factory for the load_context LangGraph node: queries MemoryAPI for current evidence.
"""Context-loading node factory for the APEX orchestration layer.

``make_context_node`` returns the ``load_context`` async function that is
registered as the first LangGraph node in every engagement turn.  It queries
``MemoryAPI`` for current evidence scoped to the engagement anchor and places
a compact summary into state.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memfabric.types import EvidenceBundle

from apex_host.graph_state import ApexGraphState

if TYPE_CHECKING:
    from apex_host.orchestration.dependencies import OrchestrationDeps


def _evidence_summary(evidence: EvidenceBundle) -> str:
    """Return a compact one-line string of the top-5 evidence entries."""
    if not evidence.entries:
        return ""
    top = sorted(evidence.entries, key=lambda e: e.score, reverse=True)[:5]
    return " | ".join(f"[{e.tier}:{e.source}] {e.text[:120]}" for e in top)


def make_context_node(
    deps: "OrchestrationDeps",
) -> Any:
    """Return the ``load_context`` async node function bound to *deps*."""

    async def load_context(state: "ApexGraphState") -> dict[str, Any]:
        evidence = await deps.api.query(
            text=state["goal"] or deps.config.target,
            subgraph_anchor=deps.anchor_id,
        )
        return {"evidence_summary": _evidence_summary(evidence)}

    return load_context
