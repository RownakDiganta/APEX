# objective_parser.py
# Converts one bounded user-flag candidate-read result into objective/objective_evidence EKG deltas from an already-computed verification result — never touches the verifier or the plaintext flag value itself.
"""Parser for user-flag objective verification output (Phase 18; made
capability-generic in the access-capability refactor).

Stateless — no IO, no stored state, no MemoryAPI access; all writes go
through ``MemoryAPI.apply_deltas`` when the caller (``apex_host.orchestration
.parsing_node``) upserts the returned deltas (memfabric Invariant 1).

Since the access-capability refactor, this parser no longer calls
``apex_host.verification.user_flag.verify_user_flag()`` itself — that ONE
authoritative verifier call now lives in
``apex_host.agents.user_flag_executor.UserFlagExecutor``, so the raw
candidate value never needs to travel any further than that executor's own
stack frame (see that module's docstring, "Why verification now happens
HERE"). This parser only ever receives the verifier's already-computed,
already-secret-free result fields (``verified``, ``value_digest``,
``redacted_value``, ``verification_method``) and builds EKG nodes from them.
It never re-implements, second-guesses, or re-runs verification.

This parser is also transport-independent: it takes ``capability_id`` /
``capability_type`` / ``principal`` (whatever produced the read) rather than
an SSH-specific ``username`` — see ``apex_host/types.py``'s
``AccessCapability``. It builds the semantic edge
``access_capability --enables--> objective`` (previously
``access_state --enables--> objective``) — the capability is now the thing
that "enables" the objective, one level more general than the raw
credential validation that produced it.

EKG output
----------
Always (when the underlying capability's read actually connected — see
``connected``):
    an ``objective`` node, upserted with the accumulated
    ``attempted_paths`` list and a status of ``"in_progress"`` (more
    candidates remain), ``"failed"`` (this was the last bounded candidate
    and it did not verify), or ``"verified"``.
On success only:
    an ``objective_evidence`` node — SHA-256 digest + redacted display
    only, never the plaintext value — linked ``objective --satisfied_by-->
    objective_evidence``, and tagged with ``capability_type``/
    ``capability_id`` so a report can show which transport produced it.

Edges: ``host --indicates--> objective`` (reachability, matching the
"don't fragment the graph" discipline every prior phase's opportunity/
workflow/experience node established) and
``access_capability --enables--> objective`` (the semantic relationship
this phase's design requires, now transport-generic).

A connection-level failure (``connected=False`` — the capability's
underlying session never connected, so nothing was learned about this
specific candidate) produces NO node update at all — the planner will
legitimately retry the same candidate on a later turn once the underlying
session issue is resolved, mirroring how ``AccessParser``/
``PrivEscEnumExecutor`` treat a connection-level failure as "no signal"
rather than "this candidate is now known to be wrong."
"""
from __future__ import annotations

from typing import Any

from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation

from apex_host.graph_ids import (
    enables_edge_id,
    host_id,
    indicates_edge_id,
    objective_evidence_id,
    objective_id,
    satisfied_by_edge_id,
)

_MAX_PATH_CHARS = 256


class ObjectiveParser:
    """Stateless parser: user_flag_verify tool_result -> EKG objective deltas."""

    def parse_user_flag_result(
        self,
        *,
        target: str,
        objective_type: str,
        candidate_path: str,
        connected: bool,
        verified: bool,
        value_digest: str,
        redacted_value: str,
        verification_method: str,
        capability_id: str,
        capability_type: str,
        principal: str,
        attempted_paths: list[str],
        is_last_candidate: bool,
        attempted_capability_paths: list[list[str]] | None = None,
    ) -> ParsedObservation:
        if not connected or not candidate_path:
            return ParsedObservation()

        timestamp = now()
        obj_id = objective_id(target, objective_type)
        # Preserve order, de-duplicate — the planner already computed this
        # list from prior subgraph state and appended this turn's candidate;
        # this defensive de-dup guards against a caller passing a
        # already-included path twice.
        new_attempted = list(dict.fromkeys([*attempted_paths, candidate_path]))
        # Phase 20 — capability-scoped attempt record: a path already
        # attempted through a DIFFERENT capability must never block a newly
        # -available capability from trying that same path. Stored as
        # [capability_id, candidate_path] 2-element lists (JSON-safe).
        new_attempted_pairs = list(attempted_capability_paths or [])
        this_pair = [capability_id, candidate_path]
        if this_pair not in new_attempted_pairs:
            new_attempted_pairs.append(this_pair)

        if verified:
            status = "verified"
        elif is_last_candidate:
            status = "failed"
        else:
            status = "in_progress"

        nodes: list[Node] = []
        edges: list[Edge] = []

        obj_confidence = 0.9 if verified else 0.5
        obj_node = Node(
            id=obj_id,
            type="objective",
            props={
                "objective_type": objective_type,
                "status": status,
                "target": target,
                "attempted_paths": new_attempted,
                "attempt_count": len(new_attempted),
                "attempted_capability_paths": new_attempted_pairs,
            },
            confidence=obj_confidence,
            source="objective_parser",
            first_seen=timestamp,
            last_seen=timestamp,
        )
        nodes.append(obj_node)

        h_id = host_id(target)
        edges.append(
            Edge(
                id=indicates_edge_id(h_id, obj_id),
                from_id=h_id, to_id=obj_id, type="indicates", props={},
                confidence=obj_confidence, source="objective_parser",
                first_seen=timestamp, last_seen=timestamp,
            )
        )

        if capability_id:
            edges.append(
                Edge(
                    id=enables_edge_id(capability_id, obj_id),
                    from_id=capability_id, to_id=obj_id, type="enables", props={},
                    confidence=obj_confidence, source="objective_parser",
                    first_seen=timestamp, last_seen=timestamp,
                )
            )

        if verified:
            ev_id = objective_evidence_id(target, objective_type, candidate_path)
            ev_props: dict[str, Any] = {
                "evidence_type": objective_type,
                "verified": True,
                "value_digest": value_digest,
                "redacted_value": redacted_value,
                "source_tool": "user_flag_verify",
                "source_path": candidate_path[:_MAX_PATH_CHARS],
                "access_identity": principal,
                "verification_method": verification_method,
                "confidence": "high",
                "evidence_timestamp": timestamp,
                "capability_type": capability_type,
                "capability_id": capability_id,
            }
            ev_node = Node(
                id=ev_id, type="objective_evidence", props=ev_props,
                confidence=0.95, source="user_flag_verify",
                first_seen=timestamp, last_seen=timestamp,
            )
            nodes.append(ev_node)
            edges.append(
                Edge(
                    id=satisfied_by_edge_id(obj_id, ev_id),
                    from_id=obj_id, to_id=ev_id, type="satisfied_by", props={},
                    confidence=0.95, source="user_flag_verify",
                    first_seen=timestamp, last_seen=timestamp,
                )
            )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
