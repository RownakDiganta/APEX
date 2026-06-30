"""Reciprocal-Rank Fusion (RRF).

Standard RRF with per-channel weights:
    rrf_score(d) = Σ_i  weight_i / (k + rank_i(d))

where rank_i(d) is the 1-based rank of document d in channel i's result list.
Documents not present in a channel contribute 0 from that channel.

Reference: Cormack, Clarke & Buettcher, SIGIR 2009.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Sequence


def fuse_rrf(
    channel_rankings: Sequence[Sequence[tuple[str, float, dict[str, Any]]]],
    *,
    k: int = 60,
    weights: Sequence[float] | None = None,
    top_n: int | None = None,
) -> list[tuple[str, float, dict[str, Any]]]:
    """Fuse multiple ranked lists into one using RRF.

    Parameters
    ----------
    channel_rankings:
        Each element is a ranked list of ``(id, score, metadata)`` triples,
        ordered best-first.  An empty list is legal (that channel contributed
        nothing).
    k:
        The RRF constant (default 60).
    weights:
        Per-channel weight multiplier.  Defaults to uniform 1.0.
    top_n:
        Truncate the fused list to the top-n entries.  ``None`` returns all.

    Returns
    -------
    list of ``(id, fused_score, metadata)`` triples, ordered best-first.
    """
    if weights is None:
        weights = [1.0] * len(channel_rankings)
    if len(weights) != len(channel_rankings):
        raise ValueError("weights length must match number of channels")

    fused_scores: dict[str, float] = defaultdict(float)
    # Keep the first-seen metadata per doc id (for the result)
    first_meta: dict[str, dict[str, Any]] = {}

    for channel, weight in zip(channel_rankings, weights):
        for rank_0, (doc_id, _score, meta) in enumerate(channel):
            rank_1 = rank_0 + 1
            fused_scores[doc_id] += weight / (k + rank_1)
            if doc_id not in first_meta:
                first_meta[doc_id] = meta

    ranked = sorted(fused_scores.items(), key=lambda kv: kv[1], reverse=True)
    result = [(doc_id, score, first_meta[doc_id]) for doc_id, score in ranked]

    if top_n is not None:
        result = result[:top_n]
    return result
