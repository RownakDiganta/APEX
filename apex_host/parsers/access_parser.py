# access_parser.py
# Parses bounded login validation output into credential and access_state EKG deltas.
"""Parser for bounded telnet/SSH/FTP access login validation output.

Stateless — receives raw session text (or, for SSH/FTP, an already-classified
structured result) and returns a ParsedObservation with EKG node/edge deltas.
No IO. No stored state. All writes go through MemoryAPI (memfabric Invariant 1)
when the caller upserts the returned deltas.

Two entry points, one shared node/edge shape:

``parse_text`` (unchanged since Phase 12A — Telnet only):
    Classifies success/failure itself via a shell-prompt/failure-phrase text
    heuristic (``_login_succeeded``). Appropriate for Telnet's raw
    interactive session transcript. Left untouched for Phase 12B per the
    "existing Telnet behavior must remain compatible" invariant.

``parse_structured`` (Phase 12B — SSH/FTP):
    Takes an explicit ``success: bool`` instead of running text heuristics
    over the output. SSH (Paramiko) and FTP (ftplib) both determine success
    or failure definitively via typed exceptions/response codes inside their
    own executor — there is no shell prompt or failure phrase to pattern-match
    for either protocol, so reusing ``_login_succeeded`` would be both
    unnecessary and unreliable (e.g. a non-interactive ``exec_command('id')``
    over SSH never produces a shell prompt at all).

EKG output (both entry points):
  Always:  credential node (username + ``secret_hint="[redacted]"``)
  On success only:
           access_state node (level="user", evidence snippet)
           grants edge credential → access_state

Secret material is never stored in the EKG. The ``secret_hint`` field
signals that a credential was tested without preserving the plaintext.
The ``evidence`` field in access_state is run through redact_session_text
with any caller-supplied passwords before storage (P8-S04).

Node-ID isolation across protocols (Phase 12B): ``parse_structured`` always
passes an explicit ``protocol`` to ``credential_id``/``access_state_id``
(e.g. ``protocol="ssh"``), so a failed SSH attempt's credential/access_state
nodes never share an ID with, and can never be mistaken for, an unrelated
FTP or Telnet attempt against the same target/username — see
``apex_host/graph_ids.py`` and ``docs/credential-validation.md``
"Planner integration" for why this matters (CredentialPlanner's per-protocol
duplicate guard depends on it).
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

    def parse_structured(
        self,
        *,
        protocol: str,
        target: str,
        username: str,
        success: bool,
        authenticated: bool,
        port: str = "",
        proto: str = "tcp",
        evidence_text: str = "",
        proof_type: str = "",
        passwords: list[str] | None = None,
    ) -> ParsedObservation:
        """Build credential/access_state deltas from an already-classified
        SSH or FTP validation result (Phase 12B).

        Unlike ``parse_text``, this never runs a text heuristic — ``success``
        and ``authenticated`` are supplied by the caller (the executor, which
        determined them definitively via a typed exception or protocol
        response code; see ``apex_host/agents/ssh_executor.py`` /
        ``ftp_executor.py``).

        A credential node is emitted only when authentication was actually
        attempted (``authenticated`` is True, or the attempt reached and was
        rejected by the remote auth exchange) — a pre-authentication failure
        (connection refused, connect timeout, protocol error before login)
        produces no node at all, mirroring ``parse_text``'s existing
        behavior for Telnet connection-level failures (empty ``text`` ->
        no node). An open port or banner alone was never sufficient to
        create a credential node before Phase 12B, and it still is not.

        An access_state node is emitted only when ``success`` is True — full
        success requires both a successful login AND a successful run of the
        fixed harmless validation command/operation. Authenticating but then
        having the harmless command itself time out or fail produces a
        credential node (the login itself is real signal) but never an
        access_state node, so the engagement can never advance on
        incomplete evidence.
        """
        if not (authenticated or success):
            return ParsedObservation()

        _passwords: list[str] = passwords or []
        timestamp = now()
        nodes: list[Node] = []
        edges: list[Edge] = []

        cred_id = credential_id(target, username, protocol=protocol)
        nodes.append(
            Node(
                id=cred_id,
                type="credential",
                props={
                    "username": username,
                    "secret_hint": REDACTED_PLACEHOLDER,
                    "target": target,
                    "protocol": protocol,
                },
                confidence=0.9,
                source=protocol,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )

        if success:
            safe_evidence = redact_session_text(evidence_text[:200], passwords=_passwords)
            proof_snippet = evidence_text.strip()[:120]

            access_id = access_state_id(target, username, protocol=protocol)
            access_props: dict[str, object] = {
                "level": "user",
                "username": username,
                "target": target,
                "service": protocol,
                "evidence": safe_evidence,
                "proof": proof_snippet,
            }
            if proof_type:
                access_props["proof_type"] = proof_type
            nodes.append(
                Node(
                    id=access_id,
                    type="access_state",
                    props=access_props,
                    confidence=0.85,
                    source=protocol,
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
                    source=protocol,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            if port:
                svc_id = service_id(target, port, proto)
                edges.append(
                    Edge(
                        id=tested_edge_id(svc_id, cred_id),
                        from_id=svc_id,
                        to_id=cred_id,
                        type="tested",
                        props={},
                        confidence=0.8,
                        source=protocol,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )
                edges.append(
                    Edge(
                        id=grants_edge_id(svc_id, access_id),
                        from_id=svc_id,
                        to_id=access_id,
                        type="grants",
                        props={},
                        confidence=0.8,
                        source=protocol,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
