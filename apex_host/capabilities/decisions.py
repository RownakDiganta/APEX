# decisions.py
# CapabilityDerivationDecision — the immutable, structured result a CapabilityProvider returns; never a graph write, never a runtime registration.
"""Deterministic provider decision model (Phase 23).

A :class:`CapabilityDerivationDecision` is what a
:class:`~apex_host.capabilities.providers.CapabilityProvider` returns —
never a graph write (that is ``CapabilityParser``'s job, called only by
:class:`~apex_host.capabilities.discovery.CapabilityDiscoveryEngine`) and
never a runtime registration (that is
``apex_host.capabilities.runtime_resolution``'s job, likewise only called by
the engine). Providers are pure functions from evidence to decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from apex_host.types import AccessCapabilityType


class CapabilityDerivationStatus(str, Enum):
    """The outcome of one provider's evaluation of one piece of evidence."""

    #: Evidence accepted; a new (or confidence-updated) capability should
    #: be materialized.
    accepted = "accepted"
    #: Evidence did not meet this provider's own acceptance criteria.
    rejected = "rejected"
    #: An identical (capability_id, evidence content) pair was already
    #: processed — no new write, no confidence change.
    duplicate = "duplicate"
    #: A capability already exists for this identity; this evidence
    #: updates it (e.g. reinforces confidence per the monotonic merge
    #: rule) rather than creating a new node.
    updated = "updated"
    #: A newer capability generation supersedes an older one at the same
    #: identity — reserved for forward compatibility (see
    #: ``docs/user-flag-objective.md`` §20 "Capability lifecycle"); no
    #: current provider produces this status.
    superseded = "superseded"
    #: Evidence accepted on its own merits, but no runtime adapter could be
    #: resolved this turn — the capability is persisted as
    #: metadata-only (``runtime_available=False``).
    runtime_unavailable = "runtime_unavailable"
    #: Evidence failed central or provider-specific TTL/expiry validation.
    expired = "expired"
    #: Evidence or its target capability has been explicitly revoked —
    #: reserved for forward compatibility; no current code path produces
    #: this (mirrors this codebase's own established "documented but not
    #: yet reachable" convention, e.g. ``EngagementOutcome.goal_completed``).
    revoked = "revoked"


@dataclass(frozen=True, slots=True)
class CapabilityDerivationDecision:
    """Immutable, secret-free result of one provider evaluating one
    :class:`~apex_host.capabilities.evidence.CapabilityEvidence`.

    Fields
    ------
    status:
        See :class:`CapabilityDerivationStatus`.
    provider_name:
        The concrete provider class name that produced this decision
        (audit/metrics correlation only).
    evidence_id:
        Echoes ``CapabilityEvidence.evidence_id`` (correlation only).
    capability_type:
        The ``AccessCapabilityType`` this decision concerns.
    capability_id:
        The deterministic ``access_capability_id(...)`` this decision
        would materialize/update — computed by the provider (pure,
        content-addressed — see ``apex_host.graph_ids.access_capability_id``)
        so the engine never needs a second identity computation.
    accepted:
        Convenience boolean mirroring ``status in (accepted, updated,
        runtime_unavailable)`` — the three statuses that still result in
        a ``CapabilityParser`` materialization call.
    confidence:
        The confidence value to record on the capability (already
        merged per the monotonic ``max(existing, new)`` rule when this
        decision represents an ``updated`` status — see
        ``apex_host.capabilities.discovery`` "Confidence merge").
    validation_method:
        Echoes the evidence's own field, for audit.
    sanitized_reason:
        Human-readable, secret-free explanation — never raw evidence
        content (mirrors every other sanitized-reason convention in this
        codebase, e.g. ``apex_tool_service``'s own error categories).
    target_host_id / principal:
        Echoed from the evidence, for the engine's materialization call.
    runtime_reference_id:
        Echoed from the evidence — the engine passes this to the runtime
        resolver.
    runtime_available:
        Whether THIS decision already knows a runtime adapter is
        resolvable (set by the provider only when it can determine this
        without performing any I/O itself — in practice, providers never
        set this True; the engine determines it after calling the
        resolver, then rebuilds the decision's status accordingly for
        reporting).
    metadata:
        Sanitized, non-secret classification fields to record on the
        capability node's own ``metadata`` prop (mirrors what
        ``CapabilityParser.derive_*`` already accepts).
    supersedes_capability_id:
        "" unless this decision represents a newer generation replacing
        an older capability identity (reserved; unused today).
    expiry:
        "" unless the resulting capability should itself carry an expiry
        (reserved; unused today — capabilities do not currently expire).
    provenance_digest:
        Echoed from the evidence, for audit correlation.
    """

    status: CapabilityDerivationStatus
    provider_name: str
    evidence_id: str
    capability_type: AccessCapabilityType
    capability_id: str
    confidence: float
    validation_method: str
    sanitized_reason: str
    target_host_id: str
    principal: str
    source_task_id: str = ""
    runtime_reference_id: str = ""
    runtime_available: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    supersedes_capability_id: str = ""
    expiry: str = ""
    provenance_digest: str = ""

    @property
    def accepted(self) -> bool:
        return self.status in (
            CapabilityDerivationStatus.accepted,
            CapabilityDerivationStatus.updated,
            CapabilityDerivationStatus.runtime_unavailable,
        )

    def to_dict(self) -> dict[str, Any]:
        """Sanitized dict for audit logging/reporting — safe to log or
        persist as-is (no secret, no raw output, no runtime object)."""
        return {
            "status": self.status.value,
            "provider_name": self.provider_name,
            "evidence_id": self.evidence_id,
            "capability_type": self.capability_type.value,
            "capability_id": self.capability_id,
            "confidence": self.confidence,
            "validation_method": self.validation_method,
            "sanitized_reason": self.sanitized_reason,
            "accepted": self.accepted,
            "runtime_available": self.runtime_available,
        }
