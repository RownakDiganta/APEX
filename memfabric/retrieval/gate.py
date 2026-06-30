"""Low-confidence gate.

Decides whether the expensive retrieval channels (dense vector, graph matcher)
should fire for a given query.  The gate is intentionally pure / stateless so
it is trivially unit-testable.

Gate logic:
    If the maximum BM25 score from the lexical channel is below *tau*, the
    lexical channel has low confidence → open the gate → fire dense + graph.
    Otherwise BM25 is strong enough on its own → keep the gate closed.
"""
from __future__ import annotations


def gate_is_open(bm25_scores: list[float], tau: float) -> bool:
    """Return True when expensive channels should fire.

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
