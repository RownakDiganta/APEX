# query_filters.py
# Provides source_family filter dicts for MemoryAPI.query() and ScoredEntry post-filter helpers.
"""Filter helpers for compiled knowledge retrieval by source_family.

Usage
-----
    from apex_host.knowledge.query_filters import POLICY_FILTER, PAYLOAD_FILTER

    # Filter at query time (passed to MemoryAPI.query()):
    bundle = await api.query(text="SQL injection", filters=POLICY_FILTER)

    # Or filter an existing result list:
    from apex_host.knowledge.query_filters import filter_by_source_family
    policy_hits = filter_by_source_family(bundle.entries, "policy_db")

Filter dicts are applied as metadata post-filters in HybridRetriever.search().
Only entries whose metadata contains ALL the specified key-value pairs are returned.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from memfabric.types import ScoredEntry

# ---------------------------------------------------------------------------
# Pre-built filter dicts — pass to MemoryAPI.query(filters=...).
# ---------------------------------------------------------------------------

POLICY_FILTER: dict[str, str] = {"source_family": "policy_db"}
PAYLOAD_FILTER: dict[str, str] = {"source_family": "payload_db"}
INTEL_FILTER: dict[str, str] = {"source_family": "intel_db"}
METHODOLOGY_FILTER: dict[str, str] = {"source_family": "methodology_db"}

# Convenience aliases for restricted wordlist manifests.
WORDLIST_MANIFEST_FILTER: dict[str, str] = {
    "source_family": "payload_db",
    "source_type": "wordlist_manifest",
}


def source_family_filter(family: str) -> dict[str, str]:
    """Return a filter dict that selects entries from *family*.

    Parameters
    ----------
    family:
        One of ``"policy_db"``, ``"methodology_db"``, ``"intel_db"``,
        ``"payload_db"``.

    Returns
    -------
    dict[str, str]
        Filter dict suitable for ``MemoryAPI.query(filters=...)``.
    """
    return {"source_family": family}


def source_type_filter(source_type: str) -> dict[str, str]:
    """Return a filter dict that selects entries of *source_type*.

    Example: ``source_type_filter("cve")`` narrows results to CVE records only.
    """
    return {"source_type": source_type}


def combined_filter(*filters: dict[str, str]) -> dict[str, str]:
    """Merge multiple filter dicts into a single AND-filter.

    All conditions must match; later dicts override earlier ones for duplicate keys.

    Example::

        combined_filter(PAYLOAD_FILTER, source_type_filter("wordlist_manifest"))
        # → {"source_family": "payload_db", "source_type": "wordlist_manifest"}
    """
    merged: dict[str, str] = {}
    for f in filters:
        merged.update(f)
    return merged


# ---------------------------------------------------------------------------
# Post-filter helpers (apply to an existing ScoredEntry list).
# ---------------------------------------------------------------------------

def filter_by_source_family(
    entries: "list[ScoredEntry]",
    family: str,
) -> "list[ScoredEntry]":
    """Keep only entries whose metadata source_family matches *family*."""
    return [e for e in entries if e.metadata.get("source_family") == family]


def filter_by_source_type(
    entries: "list[ScoredEntry]",
    source_type: str,
) -> "list[ScoredEntry]":
    """Keep only entries whose metadata source_type matches *source_type*."""
    return [e for e in entries if e.metadata.get("source_type") == source_type]


def filter_by_metadata(
    entries: "list[ScoredEntry]",
    **kwargs: object,
) -> "list[ScoredEntry]":
    """Keep entries where metadata matches every supplied keyword argument.

    Example::

        filter_by_metadata(entries, source_family="intel_db", source_type="cve")
    """
    return [
        e for e in entries
        if all(e.metadata.get(k) == v for k, v in kwargs.items())
    ]
