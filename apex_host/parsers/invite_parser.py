# invite_parser.py
# Parses an auto-invite-flow result into a REDACTED credential node (§28.35).
"""Invite-flow result → EKG deltas (§28.35).

Creates a ``credential`` node with ``secret_hint="[redacted]"`` (P8-I03 — the
plaintext password is held ONLY in the runtime registry, never here) when the
opt-in auto-invite-flow captured credentials. Reads only the non-secret
``invite_username`` field from the result dict; the password is never present in
that dict. Nothing is created when no credentials were stored (e.g. dry-run,
fail-closed block, or a failed flow).
"""
from __future__ import annotations

from typing import Any

from apex_host.graph_ids import credential_id
from apex_host.security.redaction import REDACTED_PLACEHOLDER
from memfabric.ids import now
from memfabric.types import Node, ParsedObservation


class InviteFlowParser:
    """Stateless: invite-flow result dict → ParsedObservation."""

    def parse_result(self, tool_result: dict[str, Any], *, target: str) -> ParsedObservation:
        if not tool_result.get("credentials_stored"):
            return ParsedObservation()
        username = str(tool_result.get("invite_username", "")).strip()
        if not username:
            return ParsedObservation()
        ts = now()
        cred = Node(
            id=credential_id(target, username),
            type="credential",
            props={
                "username": username,
                # Plaintext lives only in the runtime registry (amended P8-I03).
                "secret_hint": REDACTED_PLACEHOLDER,
                "target": target,
                "protocol": "",
                "source": "auto_registration",
                "validated": False,
            },
            confidence=0.9,
            source="auto_registration",
            first_seen=ts,
            last_seen=ts,
        )
        return ParsedObservation(node_deltas=[cred])
