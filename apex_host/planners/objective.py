# objective.py
# Pure, no-IO helpers for deriving user-flag-objective status, live-state summaries, and report fields from EKG subgraph data.
"""Objective reasoning helpers (Phase 18).

Everything here is pure — no I/O, no MemoryAPI calls, no tool execution —
consistent with the blackboard model (memfabric Invariant 7): planners only
ever read the ``SubgraphView``/``EvidenceBundle`` they are handed and
return ``TaskSpec``s; all persistence happens later through the standard
parse_observation -> MemoryAPI.apply_deltas path.

This module mirrors ``apex_host/planners/priv_esc_opportunities.py``'s
separation: pure derivation helpers live here; the planner class itself
(``ObjectivePlanner``) lives in ``apex_host/planners/objective_planner.py``
and imports from this module.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from apex_host.graph_ids import objective_id

if TYPE_CHECKING:
    from memfabric.types import Node, SubgraphView


def find_objective_node(subgraph: "SubgraphView", target: str, objective_type: str) -> "Node | None":
    """The ``objective`` EKG node for *target*/*objective_type*, or ``None``
    if it has never been created (the implicit "pending" state)."""
    oid = objective_id(target, objective_type)
    for n in subgraph.nodes:
        if n.id == oid:
            return n
    return None


def objective_status_from_subgraph(subgraph: "SubgraphView", target: str, objective_type: str) -> str:
    """The current ``ObjectiveStatus`` value for *target*/*objective_type*.

    ``"pending"`` (never persisted as a node prop — mirrors
    ``PrivilegeEnumerationStatus.not_started``'s precedent) is the implicit
    status when no ``objective`` node exists yet.
    """
    node = find_objective_node(subgraph, target, objective_type)
    if node is None:
        return "pending"
    return str(node.props.get("status") or "pending")


def objective_attempted_paths(subgraph: "SubgraphView", target: str, objective_type: str) -> list[str]:
    node = find_objective_node(subgraph, target, objective_type)
    if node is None:
        return []
    return list(node.props.get("attempted_paths", []))


def objective_attempted_capability_pairs(
    subgraph: "SubgraphView", target: str, objective_type: str,
) -> list[tuple[str, str]]:
    """The list of ``(capability_id, candidate_path)`` pairs already
    attempted for *target*/*objective_type* — the authoritative,
    capability-scoped attempt record (Phase 20).

    Distinct from ``objective_attempted_paths`` (a flat union of every path
    ever attempted, across every capability, kept for backward-compatible
    display/reporting): a path already attempted through ONE capability
    (e.g. SSH) must not block a DIFFERENT, newly-available capability (e.g.
    a direct-file-read primitive) from attempting that SAME path — see
    ``apex_host/planners/objective_planner.py``'s ``_select_capability``,
    which is the sole consumer of this pair list for exhaustion/dedup
    decisions.

    Stored on the ``objective`` node as ``attempted_capability_paths``: a
    list of ``[capability_id, candidate_path]`` 2-element lists (JSON-safe
    — a bare tuple is not directly JSON-serialisable). Missing/malformed
    entries are skipped defensively rather than raising.
    """
    node = find_objective_node(subgraph, target, objective_type)
    if node is None:
        return []
    raw = node.props.get("attempted_capability_paths", [])
    pairs: list[tuple[str, str]] = []
    for entry in raw:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            pairs.append((str(entry[0]), str(entry[1])))
    return pairs


def find_objective_evidence_node(subgraph: "SubgraphView", target: str, objective_type: str) -> "Node | None":
    """The verified ``objective_evidence`` node for *target*/*objective_type*.

    At most one such node ever exists per engagement: only a VERIFIED
    result creates an ``objective_evidence`` node (see
    ``apex_host/parsers/objective_parser.py``), and verification is
    terminal — no further attempts occur once ``status == "verified"``.
    """
    prefix = f"objective_evidence:{target}:{objective_type}:"
    for n in subgraph.nodes:
        if n.type == "objective_evidence" and n.id.startswith(prefix):
            return n
    return None


def objective_state_fields(subgraph: "SubgraphView", target: str, objective_type: str) -> dict[str, Any]:
    """Build the ``ApexGraphState`` partial-update dict for one objective turn.

    Pure derivation from the subgraph. Called only from
    ``apex_host.orchestration.dispatch_node.make_objective_node`` so this
    state summary is refreshed exactly on objective turns; every other node
    simply omits these keys (mirrors ``privilege_state_fields``/
    ``web_session_state_fields``).
    """
    status = objective_status_from_subgraph(subgraph, target, objective_type)
    attempted = objective_attempted_paths(subgraph, target, objective_type)
    return {
        "objective_status": status,
        "objective_summary": {
            "objective_type": objective_type,
            "status": status,
            "attempts": len(attempted),
        },
    }


def objective_report_fields(subgraph: "SubgraphView", target: str, objective_type: str) -> dict[str, Any]:
    """Build the ``RunReport`` field dict for the final report — always
    derived directly from the FINAL subgraph, never from the possibly
    one-turn-stale live state snapshot (same convention as every other
    Phase 13-17 report section)."""
    status = objective_status_from_subgraph(subgraph, target, objective_type)
    attempted = objective_attempted_paths(subgraph, target, objective_type)
    evidence = find_objective_evidence_node(subgraph, target, objective_type)
    fields: dict[str, Any] = {
        "objective_type": objective_type,
        "objective_status": status,
        "objective_verified": status == "verified",
        "objective_attempts": len(attempted),
        "objective_evidence_digest": "",
        "objective_evidence_redacted": "",
        "objective_evidence_source_path": "",
        "objective_evidence_access_identity": "",
        "objective_verification_timestamp": "",
        "objective_evidence_capability_type": "",
    }
    if evidence is not None:
        fields["objective_evidence_digest"] = str(evidence.props.get("value_digest", ""))
        fields["objective_evidence_redacted"] = str(evidence.props.get("redacted_value", ""))
        fields["objective_evidence_source_path"] = str(evidence.props.get("source_path", ""))
        fields["objective_evidence_access_identity"] = str(evidence.props.get("access_identity", ""))
        fields["objective_verification_timestamp"] = str(evidence.props.get("evidence_timestamp", ""))
        # Transport-independent display signal only — never branch report
        # logic on this beyond a label lookup (see
        # apex_host.planners.access_capabilities.capability_type_label).
        fields["objective_evidence_capability_type"] = str(evidence.props.get("capability_type", ""))
    return fields
