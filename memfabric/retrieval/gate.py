# gate.py
# Pure, stateless low-confidence gate function plus a GateDecision record for diagnostics.
"""Low-confidence gate.

Decides whether the expensive retrieval channels (dense vector, graph matcher)
should fire for a given query.  The gate is intentionally pure / stateless so
it is trivially unit-testable.

Gate logic (Option A+ — backward-compatible):

  When ``embedder_configured`` is True (real embedder available):
    → Dense channel always fires; Graph channel fires whenever Tier.working is
      requested.  The BM25-score gate is bypassed.

  When ``embedder_configured`` is False (StubEmbedder, the default):
    → Legacy BM25-score gate: if the maximum BM25 score from the lexical channel
      is below *tau*, the lexical channel has low confidence → open the gate →
      fire dense + graph.  Otherwise BM25 is strong enough → keep gate closed.

This design preserves backward compatibility for all existing tests (which use
StubEmbedder) while fixing the channel-starvation problem for real-embedder
deployments where dense should always run.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class GateDecision:
    """Result of a single gate evaluation — observable and testable.

    ``open`` is True when expensive channels (dense, graph) should fire.
    ``reasons`` is a list of human-readable explanations that can be attached
    to ``RetrievalDiagnostics.gate_reasons`` for debugging.
    """
    open: bool
    reasons: list[str] = field(default_factory=list)


def gate_is_open(bm25_scores: list[float], tau: float) -> bool:
    """Return True when expensive channels should fire (legacy BM25-score gate).

    Parameters
    ----------
    bm25_scores:
        BM25 scores from the lexical channel (may be empty).
    tau:
        Low-confidence threshold from ``Config.low_confidence_tau``.
    """
    if not bm25_scores:
        return True   # no lexical results → definitely fire expensive channels
    return max(bm25_scores) < tau


def decide_gate(
    bm25_scores: list[float],
    tau: float,
    *,
    embedder_configured: bool = False,
) -> GateDecision:
    """Evaluate the retrieval gate and return a ``GateDecision`` with reasons.

    Parameters
    ----------
    bm25_scores:
        Raw BM25 scores from the lexical channel (before tier filtering).
        May be empty if the index is empty or no results were found.
    tau:
        Low-confidence threshold from ``Config.low_confidence_tau``.
    embedder_configured:
        True when a real embedder is available (``embedder.is_configured``).
        When True, the expensive channels always fire regardless of BM25 scores
        (Option A+ policy).  When False, the legacy BM25-score gate is used.
    """
    if embedder_configured:
        return GateDecision(
            open=True,
            reasons=["embedder_configured: dense channel always fires"],
        )

    # Legacy path: BM25-score gate
    if not bm25_scores:
        return GateDecision(
            open=True,
            reasons=["no_bm25_results: no lexical evidence → open gate"],
        )

    max_score = max(bm25_scores)
    if max_score < tau:
        return GateDecision(
            open=True,
            reasons=[f"bm25_max_score={max_score:.4f} < tau={tau}: low lexical confidence"],
        )

    return GateDecision(
        open=False,
        reasons=[f"bm25_max_score={max_score:.4f} >= tau={tau}: strong lexical match; gate closed"],
    )
