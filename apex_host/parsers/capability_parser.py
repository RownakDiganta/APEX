# capability_parser.py
# Converts a validated protocol-access result (or, since Phase 20, a validated direct-file-read primitive) into an access_capability EKG delta — the sole place a raw validation becomes a generic, transport-tagged AccessCapability record.
"""Parser for the generic access-capability abstraction (capability refactor;
extended in Phase 20 with a generic direct-file-read derivation method).

Stateless — no IO, no stored state, no MemoryAPI access; all writes go
through ``MemoryAPI.apply_deltas`` when the caller (``apex_host.orchestration
.parsing_node`` / ``apex_host.orchestration.capability_seed``) upserts the
returned deltas (memfabric Invariant 1).

This is deliberately a SEPARATE parser from ``AccessParser``
(``apex_host/parsers/access_parser.py``, unchanged by this refactor —
still the sole producer of ``credential``/``access_state`` nodes from a raw
protocol validation). ``CapabilityParser`` runs immediately after, deriving
a generic, transport-tagged ``access_capability`` record from an already
-validated result — it never re-validates anything itself and never
duplicates ``AccessParser``'s own logic.

Two capability types are implemented: ``derive_ssh_capability`` (Phase 18 /
access-capability refactor) and ``derive_direct_file_read_capability``
(Phase 20 — covers both ``arbitrary_file_read`` and ``api_file_read``,
which are behaviorally identical at runtime and so share this one
derivation method, differing only in the ``capability_type`` metadata
value passed in). Adding a third capability type later means adding one
more ``derive_*`` method here (and one more registration branch in
``apex_host.orchestration.dispatch_node``) — never touching
``ObjectivePlanner``, ``UserFlagExecutor``, ``ObjectiveParser``, or the
report generator.
"""
from __future__ import annotations

from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation

from apex_host.graph_ids import (
    access_capability_id,
    access_state_id,
    enables_edge_id,
    has_capability_edge_id,
    host_id,
)
from apex_host.types import AccessCapabilityType

#: Confidence assigned to a freshly-derived SSH capability — high but not
#: absolute, mirroring AccessParser's own access_state confidence (0.85).
_SSH_CAPABILITY_CONFIDENCE = 0.85

#: The only capability types `derive_direct_file_read_capability` may ever
#: produce — "arbitrary file read" and "API file read" are behaviorally
#: identical at runtime (same adapter) but recorded as distinct metadata
#: types, per the operator's own classification of the underlying primitive.
_DIRECT_FILE_READ_TYPES: frozenset[AccessCapabilityType] = frozenset({
    AccessCapabilityType.arbitrary_file_read, AccessCapabilityType.api_file_read,
})

#: The ONLY validation methods `derive_direct_file_read_capability` accepts
#: as "positive evidence demonstrating bounded controlled file retrieval."
#: An HTTP 200, an LLM's own assertion, or "a payload was attempted" are
#: deliberately NOT in this set — the caller must have already performed
#: (or the operator must already have manually confirmed, out of band) one
#: of these specific, structured checks before this function will ever
#: derive a capability.
_ACCEPTED_VALIDATION_METHODS: frozenset[str] = frozenset({
    # An operator has manually, out-of-band confirmed (through authorized
    # testing) that this exact request shape reads files — the same trust
    # boundary already established for --username/--password.
    "operator_attestation",
    # A harmless, operator-approved canary file was retrieved through the
    # fixed request shape and its content matched what was expected.
    "canary_file_match",
    # The same fixed request shape was probed with two or more distinct
    # candidate paths and produced distinguishable, path-dependent content
    # (never a fixed/static response regardless of path).
    "path_dependent_content",
    # A dedicated parser inspected the response and classified it as a
    # genuine file read (e.g. matched a known file's structural signature)
    # above its own minimum confidence threshold.
    "structural_signature_match",
})

#: Below this confidence, `derive_direct_file_read_capability` refuses to
#: derive a capability regardless of `validation_method` — "require positive
#: evidence," not just a recognised method name.
_MIN_DIRECT_FILE_READ_CONFIDENCE = 0.6

#: Confidence assigned to a freshly-derived direct-file-read capability when
#: the caller does not supply an explicit, evidence-appropriate value.
_DEFAULT_DIRECT_FILE_READ_CONFIDENCE = 0.7


class CapabilityParser:
    """Stateless parser: validated access result -> access_capability EKG delta."""

    def derive_ssh_capability(
        self, *, target: str, username: str, source_task_id: str,
    ) -> ParsedObservation:
        """Build the ``access_capability`` node + edges for a validated SSH
        login (mirrors ``AccessParser.parse_structured``'s own "only on
        success" discipline — the caller must only invoke this once an SSH
        ``access_state`` was actually created this turn).

        Edges: ``host --has_capability--> access_capability`` (reachability)
        and ``access_state --enables--> access_capability`` (the semantic
        chain: validated access enables the capability).

        ``runtime_available`` starts ``False`` — no runtime adapter has been
        registered yet at the moment this node is created; the
        orchestration layer (``apex_host.orchestration.dispatch_node
        ._register_capability_adapter``) flips it to ``True`` once it
        successfully constructs and registers a real adapter for it.
        """
        if not username:
            return ParsedObservation()

        timestamp = now()
        cap_id = access_capability_id(target, AccessCapabilityType.ssh_command.value, username)
        h_id = host_id(target)
        cap_node = Node(
            id=cap_id,
            type="access_capability",
            props={
                "capability_type": AccessCapabilityType.ssh_command.value,
                "host_id": h_id,
                "validated": True,
                "principal": username,
                "confidence": _SSH_CAPABILITY_CONFIDENCE,
                "source_task_id": source_task_id,
                "metadata": {},
                "runtime_available": False,
            },
            confidence=_SSH_CAPABILITY_CONFIDENCE,
            source="capability_parser",
            first_seen=timestamp,
            last_seen=timestamp,
        )

        acc_id = access_state_id(target, username, protocol="ssh")
        edges = [
            Edge(
                id=has_capability_edge_id(h_id, cap_id),
                from_id=h_id, to_id=cap_id, type="has_capability", props={},
                confidence=_SSH_CAPABILITY_CONFIDENCE, source="capability_parser",
                first_seen=timestamp, last_seen=timestamp,
            ),
            Edge(
                id=enables_edge_id(acc_id, cap_id),
                from_id=acc_id, to_id=cap_id, type="enables", props={},
                confidence=_SSH_CAPABILITY_CONFIDENCE, source="capability_parser",
                first_seen=timestamp, last_seen=timestamp,
            ),
        ]
        return ParsedObservation(node_deltas=[cap_node], edge_deltas=edges)

    def derive_direct_file_read_capability(
        self,
        *,
        target: str,
        capability_type: AccessCapabilityType,
        principal: str,
        source_task_id: str,
        validation_method: str,
        confidence: float = _DEFAULT_DIRECT_FILE_READ_CONFIDENCE,
        source_node_id: str = "",
        requires_auth: bool = False,
        max_response_bytes: int = 4096,
        request_shape_id: str = "",
    ) -> ParsedObservation:
        """Build the ``access_capability`` node + edges for a validated
        direct-file-read primitive (``arbitrary_file_read`` or
        ``api_file_read`` — behaviorally identical at runtime, sharing this
        one derivation method; the two types are distinguished purely by
        the operator's own classification of the underlying primitive, e.g.
        "this is a raw LFI" vs. "this is an authenticated file-download API").

        Requires structured, positive evidence — refuses to derive a
        capability when:

        - ``validation_method`` is not one of the recognised
          ``_ACCEPTED_VALIDATION_METHODS`` (an HTTP 200 alone, an LLM's own
          assertion, or "a payload was attempted" are NOT acceptable
          evidence — see module docstring);
        - ``confidence`` is below ``_MIN_DIRECT_FILE_READ_CONFIDENCE``;
        - ``capability_type`` is not one of ``arbitrary_file_read`` /
          ``api_file_read``;
        - ``principal`` is empty (mirrors ``derive_ssh_capability``'s own
          "no username, no node" guard — a capability must be attributable
          to *something*, even if only a fixed operator-supplied label like
          ``"application"``).

        On acceptance, the node's ``metadata`` prop records
        ``requires_auth``/``max_response_bytes``/``request_shape_id`` (all
        sanitized, non-secret classification fields — never a header value,
        cookie, token, or raw request/response body). Edges:
        ``host --has_capability--> access_capability`` (always) and, when
        *source_node_id* is supplied (the EKG node ID of whatever evidence
        the caller already has — an endpoint, a web_opportunity, an
        access_state, ...), ``source_node_id --enables--> access_capability``
        (the same semantic relationship ``derive_ssh_capability`` uses,
        generalized to any source-evidence node rather than only
        ``access_state``).

        ``runtime_available`` starts ``False`` for the same reason as
        ``derive_ssh_capability`` — no adapter is registered until the
        orchestration layer successfully constructs one.
        """
        if validation_method not in _ACCEPTED_VALIDATION_METHODS:
            return ParsedObservation()
        if confidence < _MIN_DIRECT_FILE_READ_CONFIDENCE:
            return ParsedObservation()
        if capability_type not in _DIRECT_FILE_READ_TYPES:
            return ParsedObservation()
        if not principal:
            return ParsedObservation()

        timestamp = now()
        cap_id = access_capability_id(target, capability_type.value, principal)
        h_id = host_id(target)
        cap_node = Node(
            id=cap_id,
            type="access_capability",
            props={
                "capability_type": capability_type.value,
                "host_id": h_id,
                "validated": True,
                "principal": principal,
                "confidence": confidence,
                "source_task_id": source_task_id,
                "metadata": {
                    "validation_method": validation_method,
                    "requires_auth": requires_auth,
                    "max_response_bytes": max_response_bytes,
                    "request_shape_id": request_shape_id,
                },
                "runtime_available": False,
            },
            confidence=confidence,
            source="capability_parser",
            first_seen=timestamp,
            last_seen=timestamp,
        )

        edges = [
            Edge(
                id=has_capability_edge_id(h_id, cap_id),
                from_id=h_id, to_id=cap_id, type="has_capability", props={},
                confidence=confidence, source="capability_parser",
                first_seen=timestamp, last_seen=timestamp,
            ),
        ]
        if source_node_id:
            edges.append(
                Edge(
                    id=enables_edge_id(source_node_id, cap_id),
                    from_id=source_node_id, to_id=cap_id, type="enables", props={},
                    confidence=confidence, source="capability_parser",
                    first_seen=timestamp, last_seen=timestamp,
                )
            )
        return ParsedObservation(node_deltas=[cap_node], edge_deltas=edges)
