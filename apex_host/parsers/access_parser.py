# access_parser.py
# Parses bounded login validation output into credential and access_state EKG deltas.
"""Parser for bounded telnet/access login session output.

Stateless — receives raw session text and returns a ParsedObservation
with EKG node/edge deltas. No IO. No stored state. All writes go through
MemoryAPI (memfabric Invariant 1) when the caller upserts the returned
deltas.

EKG output:
  Always:  credential node (username + ``secret_hint="[redacted]"``)
  On success only:
           access_state node (level="user", evidence snippet)
           grants edge credential → access_state

Secret material is never stored in the EKG. The ``secret_hint`` field
signals that a credential was tested without preserving the plaintext.
The ``evidence`` field in access_state is run through redact_session_text
with any caller-supplied passwords before storage (P8-S04).
"""
from __future__ import annotations

import re

from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation
from apex_host.security.redaction import REDACTED_PLACEHOLDER, redact_session_text
from apex_host.graph_ids import (
    credential_id,
    access_state_id,
    grants_edge_id,
    service_id,
    tested_edge_id,
)

_SHELL_PROMPT_RE = re.compile(r"[$#>]\s*$", re.MULTILINE)
_FAILURE_RE = re.compile(
    r"(login\s+incorrect|authentication\s+failed|access\s+denied"
    r"|invalid\s+password|permission\s+denied|login\s+failed)",
    re.IGNORECASE,
)


def _login_succeeded(text: str) -> bool:
    if _FAILURE_RE.search(text) is not None:
        return False
    return _SHELL_PROMPT_RE.search(text) is not None


class AccessParser:
    """Stateless parser: access session text -> EKG credential/access_state deltas."""

    def parse_text(
        self,
        text: str,
        *,
        target: str,
        username: str,
        source: str = "telnet",
        port: str = "",
        proto: str = "tcp",
        passwords: list[str] | None = None,
    ) -> ParsedObservation:
        if not text.strip():
            return ParsedObservation()

        _passwords: list[str] = passwords or []
        timestamp = now()
        nodes: list[Node] = []
        edges: list[Edge] = []

        cred_id = credential_id(target, username)
        nodes.append(
            Node(
                id=cred_id,
                type="credential",
                props={
                    "username": username,
                    "secret_hint": REDACTED_PLACEHOLDER,
                    "target": target,
                    "protocol": source,
                },
                confidence=0.9,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )

        if _login_succeeded(text):
            # Extract a short proof snippet from the last non-empty line of output
            # (typically the shell prompt or id/whoami command output).
            proof_lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            proof_snippet = proof_lines[-1][:120] if proof_lines else ""

            # P8-S04: redact passwords from evidence before storing in EKG.
            safe_evidence = redact_session_text(text[:200], passwords=_passwords)

            access_id = access_state_id(target, username)
            nodes.append(
                Node(
                    id=access_id,
                    type="access_state",
                    props={
                        "level": "user",
                        "username": username,
                        "target": target,
                        "service": source,
                        "evidence": safe_evidence,
                        "proof": proof_snippet,
                    },
                    confidence=0.85,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=grants_edge_id(cred_id, access_id),
                    from_id=cred_id,
                    to_id=access_id,
                    type="grants",
                    props={},
                    confidence=0.85,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            if port:
                svc_id = service_id(target, port, proto)
                # service → credential: the service received this credential test
                edges.append(
                    Edge(
                        id=tested_edge_id(svc_id, cred_id),
                        from_id=svc_id,
                        to_id=cred_id,
                        type="tested",
                        props={},
                        confidence=0.8,
                        source=source,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )
                # service → access_state: the service granted this access level
                edges.append(
                    Edge(
                        id=grants_edge_id(svc_id, access_id),
                        from_id=svc_id,
                        to_id=access_id,
                        type="grants",
                        props={},
                        confidence=0.8,
                        source=source,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
