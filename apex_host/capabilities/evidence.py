# evidence.py
# CapabilityEvidence — immutable, secret-free structured proof that a capability exists — plus its bounded evidence-type vocabulary and central validator.
"""The capability-evidence model (Phase 23).

Three deliberately distinct terms are used throughout this package (never
interchangeably — see ``docs/user-flag-objective.md`` §20 "Terminology"):

``CapabilityObservation``
    Something was merely observed (an open port, an HTTP 200, a discovered
    credential). May be weak or incomplete. Cannot itself create a
    capability. This package has no dataclass for it — it is whatever
    upstream signal a caller chooses NOT to turn into evidence.

``CapabilityEvidence`` (this module)
    Structured, validated proof. Has an accepted ``evidence_type``. May be
    evaluated by a :class:`~apex_host.capabilities.providers.CapabilityProvider`.

``CapabilityDerivationDecision``
    (``apex_host.capabilities.decisions``) — a deterministic provider
    result: accepted, rejected, duplicate, or runtime-unavailable.

``AccessCapability`` (``apex_host.types``)
    Persistent, sanitized capability metadata — the thing this whole
    pipeline ultimately writes to the EKG via ``CapabilityParser``.

Evidence never carries a secret. It may carry a ``credential_reference_id``
(an opaque label) but never a password, private key, bearer token, or
cookie value; it may carry ``response_digest``/``canary_match`` but never
the raw canary or response content. :func:`validate_evidence` is the single
place these rules — and every other acceptance rule — are enforced; no
provider re-implements validation.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from apex_host.types import AccessCapabilityType

#: Fields that, if present as a *key* inside ``sanitized_attributes``, would
#: indicate a raw secret or raw output leaked into evidence — checked by
#: :func:`validate_evidence` regardless of what value is stored there.
_FORBIDDEN_ATTRIBUTE_KEYS: frozenset[str] = frozenset({
    "password", "passwd", "secret", "token", "bearer_token", "cookie", "cookies",
    "private_key", "ssh_key", "api_key", "raw_output", "raw_response", "raw_stdout",
    "raw_stderr", "session", "session_id", "flag", "flag_value", "raw_flag",
})

#: Regexes are deliberately not used here — a simple substring/keyword check
#: on dict *keys* (never values) is sufficient and avoids false rejections
#: on legitimate values that happen to contain a word like "token" as part
#: of a sanitized label (e.g. ``"strategy_id": "token-bound-read"``).


class CapabilityEvidenceType(str, Enum):
    """A bounded vocabulary of accepted evidence shapes.

    Every member describes WHAT KIND OF PROOF was produced, never HOW a
    vulnerability was found and never a machine/target name. Adding a new
    evidence type requires updating this enum, a matching provider in
    ``apex_host.capabilities.providers``, and nothing else.
    """

    #: A successful, authenticated SSH operation — harmless command
    #: execution or bounded read confirmed, with a runtime session/backend
    #: reference available (i.e. the orchestration layer can actually
    #: reconnect this turn).
    SSH_AUTHENTICATED_COMMAND = "ssh_authenticated_command"
    #: Path-dependent HTTP response content validated via an accepted
    #: direct-file-read validation method, with a fixed primitive
    #: available.
    DIRECT_FILE_READ_VALIDATED = "direct_file_read_validated"
    #: A deterministic, benign LOCAL command result validated, with a safe
    #: bounded-read strategy available.
    LOCAL_COMMAND_VALIDATED = "local_command_validated"
    #: A deterministic, benign REMOTE command result validated, with a
    #: safe bounded-read backend/session available.
    REMOTE_COMMAND_VALIDATED = "remote_command_validated"
    #: A fixed, validated web-command mechanism available, with a safe
    #: bounded objective adapter registrable.
    WEB_COMMAND_VALIDATED = "web_command_validated"
    #: An existing backend confirms an already-validated session handle —
    #: must be paired with an accepted capability family and proof type by
    #: the evidence's own ``capability_family``/``validation_method``.
    RUNTIME_SESSION_CONFIRMED = "runtime_session_confirmed"
    #: The pre-existing operator-attestation trust boundary
    #: (``--username``/``--password``-equivalent: the operator has already
    #: manually confirmed, out of band, that a capability works).
    OPERATOR_ATTESTED = "operator_attested"


#: Evidence types that map 1:1 onto exactly one ``AccessCapabilityType`` —
#: used by :func:`validate_evidence` to reject an evidence/family mismatch
#: (e.g. SSH evidence claiming ``capability_family="local_shell"``).
_EVIDENCE_TYPE_TO_FAMILY: dict[CapabilityEvidenceType, AccessCapabilityType] = {
    CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND: AccessCapabilityType.ssh_command,
    CapabilityEvidenceType.LOCAL_COMMAND_VALIDATED: AccessCapabilityType.local_shell,
    CapabilityEvidenceType.REMOTE_COMMAND_VALIDATED: AccessCapabilityType.remote_command,
    CapabilityEvidenceType.WEB_COMMAND_VALIDATED: AccessCapabilityType.web_command,
    # DIRECT_FILE_READ_VALIDATED maps to either arbitrary_file_read or
    # api_file_read (the operator's own classification) — both accepted,
    # so it is intentionally absent from this 1:1 table and checked
    # separately in validate_evidence.
}

#: Minimum confidence accepted for ANY evidence, regardless of family —
#: family-specific thresholds (mirroring ``CapabilityParser``'s own
#: existing constants) are applied additionally by each provider.
_MIN_EVIDENCE_CONFIDENCE = 0.6

#: Validation methods that unconditionally prove nothing about capability
#: (an HTTP-200-alone/LLM-claim/credentials-alone/admin-access-alone/
#: payload-attempted-alone signal) — rejected centrally so no provider
#: needs to re-implement this list. Mirrors the rejection vocabulary
#: already documented in ``apex_host/parsers/capability_parser.py``.
_REJECTED_VALIDATION_METHODS: frozenset[str] = frozenset({
    "http_200", "http_status_only", "llm_claim", "llm_assertion",
    "credentials_found", "credentials_only", "admin_access", "application_admin",
    "payload_attempted", "payload_only", "banner_only", "port_open",
})


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    """Immutable, secret-free structured proof that a capability exists.

    Never contains: a password, private key, bearer token, cookie value,
    raw command/HTTP output, or a raw flag-like value. ``sanitized_attributes``
    is the one open-ended field, and :func:`validate_evidence` scans its
    KEYS (never values — a value legitimately containing the substring
    "token" as part of an opaque label is fine) against
    ``_FORBIDDEN_ATTRIBUTE_KEYS`` before any provider ever sees it.

    Fields
    ------
    evidence_id:
        Caller-supplied identifier for this specific evidence instance
        (audit/dedup correlation only — NOT the capability's own identity,
        which ``CapabilityParser``/``access_capability_id`` compute
        separately from target+capability_type+principal).
    evidence_type:
        One of :class:`CapabilityEvidenceType`.
    capability_family:
        The ``AccessCapabilityType`` value this evidence claims to prove.
    target_host_id:
        The EKG ``host:<ip>`` node ID (or bare target string — both
        accepted; validated for non-emptiness only).
    source_task_id:
        The ``TaskSpec.id`` that produced this evidence, if any — "" for
        operator-attested evidence (there is no task).
    source_observation_id:
        Opaque correlation ID for whatever raw executor result produced
        this evidence (e.g. an ``ExecutorResult``/episode ID) — never the
        result content itself.
    principal:
        Who/what this capability is attributed to (mirrors
        ``AccessCapability.principal``).
    validation_method:
        A string drawn from the accepted vocabulary each provider defines
        (e.g. ``"operator_attestation"``, ``"canary_file_match"``,
        ``"nonce_bound_execution"``) — never free text describing a
        vulnerability.
    confidence:
        0.0-1.0. Below ``_MIN_EVIDENCE_CONFIDENCE`` is rejected centrally;
        each provider may enforce a stricter family-specific floor.
    timestamp:
        ISO-8601 UTC (``memfabric.ids.now()`` format) — used for TTL
        expiry when ``ApexConfig.capability_evidence_ttl_seconds`` is
        non-zero.
    authorization_scope_id:
        Opaque label for the authorization/engagement context this
        evidence was produced under — "" is treated as "current
        engagement" (the common case; every existing call site in this
        codebase has exactly one engagement/authorization context).
    runtime_reference_id:
        An OPAQUE, non-secret, process-local identifier a
        :class:`~apex_host.capabilities.discovery.RuntimeReferenceResolver`
        can use to reconstruct a runtime adapter THIS turn. Never a
        memory address, object repr, URL with a token, cookie, credential,
        or SSH private key — see that Protocol's own docstring for the
        full "what may/may not be a reference ID" discipline. "" means
        "no runtime reference available yet" — the resulting capability
        will be persisted as metadata-only (``runtime_available=False``).
    runtime_generation:
        A monotonic integer tag for "which construction of the runtime
        material this reference belongs to" — a stale generation (e.g.
        from a resumed/replayed checkpoint) is rejected by the resolver,
        never silently reused.
    sanitized_attributes:
        Free-form but secret-free classification metadata (mirrors what
        ``CapabilityParser.derive_*`` already stores in a capability
        node's own ``metadata`` prop) — e.g.
        ``{"requires_auth": False, "max_response_bytes": 4096}``.
    replay_safe:
        True (the default) when re-processing this exact evidence object
        a second time is guaranteed idempotent (no side effect beyond a
        confidence-merge/no-op) — every evidence type in this codebase is
        replay-safe by construction, so this defaults True; kept as an
        explicit field for forward compatibility with a future evidence
        source that might not be.
    expires_at:
        ISO-8601 UTC, or "" for "does not expire" (the default — TTL is
        opt-in via ``ApexConfig.capability_evidence_ttl_seconds``, see
        :func:`validate_evidence`).
    provenance_digest:
        A short, non-reversible correlation tag (e.g. a truncated hash of
        ``source_task_id``+``timestamp``) for audit trails — never a hash
        of secret material.
    """

    evidence_id: str
    evidence_type: CapabilityEvidenceType
    capability_family: AccessCapabilityType
    target_host_id: str
    source_task_id: str
    principal: str
    validation_method: str
    confidence: float
    timestamp: str
    source_observation_id: str = ""
    authorization_scope_id: str = ""
    runtime_reference_id: str = ""
    runtime_generation: int = 0
    sanitized_attributes: dict[str, Any] = field(default_factory=dict)
    replay_safe: bool = True
    expires_at: str = ""
    provenance_digest: str = ""
    #: Set by the caller when the underlying operation ran under
    #: ``dry_run=True`` — validated centrally so a dry-run result can never
    #: derive a live capability (see :func:`validate_evidence`).
    is_dry_run: bool = False


@dataclass(frozen=True, slots=True)
class EvidenceRejection:
    """A sanitized, structured rejection reason from :func:`validate_evidence`.

    ``reason`` is always one of a fixed vocabulary (never raw evidence
    content) — see the ``reason`` values documented on
    :func:`validate_evidence` itself.
    """

    reason: str
    detail: str = ""


def _is_finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def validate_evidence(
    evidence: CapabilityEvidence,
    *,
    known_task_ids: frozenset[str] = frozenset(),
    require_known_task: bool = False,
    evidence_ttl_seconds: float = 0.0,
    now_iso: str = "",
) -> EvidenceRejection | None:
    """Central evidence validator. Returns ``None`` when *evidence* passes
    every structural check (a provider may still reject it on its own,
    family-specific grounds); returns an :class:`EvidenceRejection` with a
    sanitized reason otherwise.

    This is the ONE place the following are enforced, so no provider
    re-implements any of them:

    - missing target (``rejection reason="missing_target"``)
    - unsupported/malformed evidence type or capability family
      (``"unsupported_evidence"``)
    - confidence below the universal floor (``"confidence_below_threshold"``)
    - a rejected validation method — HTTP-200-alone, an LLM claim,
      credentials-alone, admin-access-alone, a payload-attempt record, a
      banner, or an open port (``"invalid_validation_method"``)
    - a raw secret/output/flag field smuggled into
      ``sanitized_attributes`` (``"secret_field_detected"``)
    - dry-run evidence claiming a live validated capability
      (``"dry_run_evidence"``)
    - an evidence/family mismatch for the 1:1-mapped evidence types
      (``"unsupported_evidence"``)
    - a malformed ``runtime_generation``/``runtime_reference_id`` pairing
      (a non-empty reference with a negative generation —
      ``"missing_runtime_reference"``)
    - a *required* source task that does not exist in *known_task_ids*
      (``"unsupported_evidence"`` — only enforced when
      *require_known_task* is True; most callers pass evidence they just
      produced this turn and have no separate task ledger to check against)
    - expiry, when *evidence_ttl_seconds* is non-zero
      (``"expired_evidence"``)
    """
    if not evidence.target_host_id.strip():
        return EvidenceRejection("target_mismatch", "missing target_host_id")

    if evidence.is_dry_run:
        return EvidenceRejection("dry_run_evidence", "evidence produced under dry_run=True")

    if not _is_finite_number(evidence.confidence) or not (0.0 <= evidence.confidence <= 1.0):
        return EvidenceRejection("confidence_below_threshold", "confidence out of [0,1] range")
    if evidence.confidence < _MIN_EVIDENCE_CONFIDENCE:
        return EvidenceRejection("confidence_below_threshold", "below universal evidence floor")

    method = evidence.validation_method.strip().lower()
    if not method or method in _REJECTED_VALIDATION_METHODS:
        return EvidenceRejection("invalid_validation_method", "method carries no positive evidence")

    expected_family = _EVIDENCE_TYPE_TO_FAMILY.get(evidence.evidence_type)
    if expected_family is not None and evidence.capability_family is not expected_family:
        return EvidenceRejection("unsupported_evidence", "evidence_type/capability_family mismatch")
    if evidence.evidence_type is CapabilityEvidenceType.DIRECT_FILE_READ_VALIDATED and evidence.capability_family not in (
        AccessCapabilityType.arbitrary_file_read, AccessCapabilityType.api_file_read,
    ):
        return EvidenceRejection("unsupported_evidence", "direct-file-read evidence requires a file-read family")

    if evidence.runtime_reference_id and evidence.runtime_generation < 0:
        return EvidenceRejection("missing_runtime_reference", "negative runtime_generation")

    forbidden = _FORBIDDEN_ATTRIBUTE_KEYS.intersection(
        k.lower() for k in evidence.sanitized_attributes.keys()
    )
    if forbidden:
        return EvidenceRejection("secret_field_detected", "forbidden attribute key present")

    if require_known_task and evidence.source_task_id and evidence.source_task_id not in known_task_ids:
        return EvidenceRejection("unsupported_evidence", "source_task_id not found among known tasks")

    if evidence_ttl_seconds > 0 and now_iso and evidence.timestamp:
        if _evidence_expired(evidence.timestamp, now_iso, evidence_ttl_seconds):
            return EvidenceRejection("expired_evidence", "evidence exceeded configured TTL")

    if evidence.expires_at and now_iso and now_iso > evidence.expires_at:
        return EvidenceRejection("expired_evidence", "evidence past its own expires_at")

    return None


def _evidence_expired(evidence_ts: str, now_iso: str, ttl_seconds: float) -> bool:
    """Best-effort TTL check using stdlib ``datetime`` parsing of two
    ISO-8601 UTC strings. Never raises — a malformed timestamp is treated
    as "not expired" (fail open on this specific, non-security-critical
    bookkeeping check; the underlying capability's own validity is
    governed by ``runtime_available``/authorization, not evidence age)."""
    from datetime import datetime

    try:
        t_ev = datetime.fromisoformat(evidence_ts.replace("Z", "+00:00"))
        t_now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (t_now - t_ev).total_seconds() > ttl_seconds
