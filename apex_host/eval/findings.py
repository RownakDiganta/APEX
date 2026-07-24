# findings.py
# Deduplicates raw per-turn finding observations into unique, semantically-identified findings for RunReport (Phase 3).
"""Finding deduplication (Phase 3, post-live-test debugging track).

``state["findings"]`` (``ApexGraphState``, ``operator.add``) is an
append-only OBSERVATION log — one entry per EKG node delta a parser
produced, once per turn, regardless of whether that node already existed.
A host discovered by six separate (even six IDENTICAL, six FAILED) Nmap
executions produces six observation entries with the same ``id`` (the
node ID is the finding's stable semantic identity — see
``apex_host.orchestration.parsing_node.findings_from_parsed``). This is
correct and intentional for the observation log itself — memfabric
Invariant 2 (episodic history is append-only) extends by convention to
this state field too, and this module never mutates or truncates it.

What was missing before this phase: ``RunReport.findings`` used the RAW,
undeduplicated observation list directly, so a report could show "six
identical host findings" even though the EKG (and ``export_ekg``) only
ever had one host node. ``deduplicate_findings()`` is the one place that
gap is closed — it produces the UNIQUE-entity view a report should show,
while the raw observation list remains fully intact and inspectable
(``RunReport.observation_count`` — see ``apex_host/eval/report.py``).

Deduplication key: the observation's ``id`` field — the EKG node ID
(e.g. ``"host:10.10.10.14"``), already a stable, content-addressed
semantic identity assigned by the parser/graph-ID layer
(``apex_host.graph_ids``), never re-derived here.

Confidence merge rule: MAXIMUM observed confidence wins — a later,
lower-confidence re-observation of the same entity must never make an
already-established higher-confidence finding look weaker in the report.
This mirrors (without duplicating) memfabric's own per-field
last-writer-wins-with-provenance discipline: this module operates on
report-level display data, not EKG field state, so it picks the simpler,
equally defensible "max confidence, documented explicitly" rule named in
this phase's own requirements.
"""
from __future__ import annotations

from typing import Any


def deduplicate_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse *raw_findings* (the raw, append-only observation log) into
    one entry per unique ``id``, preserving:

    - ``first_seen``: the earliest ``timestamp`` observed for this ``id``.
    - ``last_seen``: the latest ``timestamp`` observed for this ``id``.
    - ``observation_count``: how many raw observations shared this ``id``.
    - ``sources``: the sorted, deduplicated set of every ``source`` value
      seen for this ``id``.
    - ``confidence``: the MAXIMUM confidence observed for this ``id``
      (documented merge rule — see module docstring).
    - ``title``/``detail``/``phase``: taken from the LATEST observation
      (by ``timestamp``; ties broken by list order) — the most current
      parse of that entity. Never a blend of multiple observations'
      text, which could produce a nonsensical hybrid string.

    Never mutates *raw_findings*. Order of the returned list matches each
    unique ``id``'s FIRST appearance in *raw_findings* (stable, deterministic
    — never alphabetical, never confidence-sorted) so a report's finding
    order tracks the engagement's own discovery order.
    """
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for entry in raw_findings:
        fid = str(entry.get("id", ""))
        if not fid:
            # No stable identity to dedupe on — keep as its own entry,
            # keyed by a synthetic, order-based id so it is never silently
            # dropped or accidentally merged with an unrelated entry.
            fid = f"__unidentified__:{len(order)}"

        timestamp = str(entry.get("timestamp", ""))
        confidence = float(entry.get("confidence", 0.0) or 0.0)
        source = str(entry.get("source", ""))

        if fid not in merged:
            order.append(fid)
            merged[fid] = {
                "id": str(entry.get("id", fid)),
                "phase": entry.get("phase", "unknown"),
                "title": entry.get("title", ""),
                "detail": entry.get("detail", ""),
                "confidence": confidence,
                "source": source,
                "timestamp": timestamp,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "observation_count": 1,
                "sources": [source] if source else [],
            }
            continue

        existing = merged[fid]
        existing["observation_count"] = int(existing["observation_count"]) + 1
        if source and source not in existing["sources"]:
            existing["sources"] = sorted({*existing["sources"], source})
        if confidence > float(existing["confidence"]):
            existing["confidence"] = confidence
        # first_seen/last_seen: string ISO-8601 timestamps sort correctly
        # lexicographically; empty strings are excluded from the comparison
        # so a malformed/missing timestamp never displaces a real one.
        if timestamp and (not existing["first_seen"] or timestamp < existing["first_seen"]):
            existing["first_seen"] = timestamp
        if timestamp and (not existing["last_seen"] or timestamp >= existing["last_seen"]):
            existing["last_seen"] = timestamp
            # The latest observation's own text/phase/source supersedes —
            # the most current parse of this entity.
            existing["title"] = entry.get("title", existing["title"])
            existing["detail"] = entry.get("detail", existing["detail"])
            existing["phase"] = entry.get("phase", existing["phase"])
            existing["source"] = source or existing["source"]
            existing["timestamp"] = timestamp

    return [merged[fid] for fid in order]
