# invite_parser.py
# Parses an auto-invite-flow result into a REDACTED credential node + a
# once-per-engagement attempt marker (§28.35).
"""Invite-flow result → EKG deltas (§28.35).

Always writes a single ``invite_attempt`` MARKER node (host-anchored, §28.35)
recording that the opt-in auto-invite-flow was attempted and its outcome — so it
is attempted at most once per engagement and a FAILED/misconfigured flow no
longer re-emits every turn (which caused a ``duplicate_task_stall``). On success
also writes a ``credential`` node with ``secret_hint="[redacted]"`` (P8-I03 — the
plaintext password is held ONLY in the runtime registry, never here). Reads only
non-secret fields from the result dict; the password is never present in it. Any
failure ``error`` stored on the marker is bounded and secret-pattern-redacted.
"""
from __future__ import annotations

from typing import Any

from apex_host.graph_ids import (
    bare_host,
    credential_id,
    host_id,
    indicates_edge_id,
    invite_attempt_id,
)
from apex_host.security.redaction import REDACTED_PLACEHOLDER, redact_secret_patterns
from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation


class InviteFlowParser:
    """Stateless: invite-flow result dict → ParsedObservation."""

    def parse_result(self, tool_result: dict[str, Any], *, target: str) -> ParsedObservation:
        # A dry-run produced no real attempt — nothing to record.
        if tool_result.get("dry_run"):
            return ParsedObservation()
        ts = now()
        nodes: list[Node] = []
        edges: list[Edge] = []

        succeeded = bool(tool_result.get("credentials_stored"))
        # §28.35 — a single, host-anchored attempt marker (success OR failure) so
        # the planner emits the invite flow at most once (no duplicate re-emit /
        # duplicate_task_stall). Carries the bounded, redacted outcome for report
        # visibility.
        marker_id = invite_attempt_id(target)
        h_id = host_id(bare_host(target))
        outcome = "success" if succeeded else "failed"
        err = redact_secret_patterns(str(tool_result.get("error", "") or ""))[:200]
        urls_tried = [str(u) for u in (tool_result.get("register_urls_tried") or [])][:8]
        nodes.append(Node(
            id=marker_id, type="invite_attempt",
            props={"target": target, "outcome": outcome, "error": err,
                   "register_urls_tried": urls_tried,
                   "auto_generated": bool(tool_result.get("credentials_auto_generated"))},
            confidence=0.9, source="invite_flow", first_seen=ts, last_seen=ts,
        ))
        # host --indicates--> invite_attempt (reachable in the depth-bounded
        # planner subgraph so build_invite_flow_task sees it).
        edges.append(Edge(
            id=indicates_edge_id(h_id, marker_id), from_id=h_id, to_id=marker_id,
            type="indicates", props={}, confidence=0.9, source="invite_flow",
            first_seen=ts, last_seen=ts,
        ))

        username = str(tool_result.get("invite_username", "")).strip()
        if succeeded and username:
            nodes.append(Node(
                id=credential_id(target, username),
                type="credential",
                props={
                    "username": username,
                    # Plaintext lives only in the runtime registry (amended P8-I03).
                    "secret_hint": REDACTED_PLACEHOLDER,
                    "target": target,
                    "protocol": "",
                    "source": "auto_registration",
                    "auto_generated": bool(tool_result.get("credentials_auto_generated")),
                    "validated": False,
                },
                confidence=0.9, source="auto_registration",
                first_seen=ts, last_seen=ts,
            ))
        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
