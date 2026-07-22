# providers.py
# CapabilityProvider Protocol + one concrete, deterministic provider per currently-supported capability family — pure functions from evidence to decision, never a graph/registry write.
"""Deterministic capability providers (Phase 23).

Every provider here is a pure function: given a
:class:`~apex_host.capabilities.evidence.CapabilityEvidence` and a
read-only :class:`~apex_host.capabilities.discovery.CapabilityDiscoveryContext`,
return exactly one
:class:`~apex_host.capabilities.decisions.CapabilityDerivationDecision`.
Providers **never** write ``MemoryAPI``, **never** mutate
``CapabilityRuntimeRegistry``, **never** open a network connection, **never**
invoke a tool, and **never** call an LLM — enforced both by construction
(no such object is reachable from the narrow arguments a provider receives)
and by a static architecture-scan test
(``tests/apex_host/test_phase23_capability_discovery.py``) that greps this
file's source for any of those forbidden calls.

Acceptance thresholds/vocabularies are REUSED from
``apex_host.parsers.capability_parser`` (the existing, already-tested
authority for "what counts as positive evidence" per family) rather than
redefined here — this phase adds automatic derivation on top of that
existing acceptance logic, it does not relax or duplicate it.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from apex_host.capabilities.decisions import CapabilityDerivationDecision, CapabilityDerivationStatus
from apex_host.capabilities.evidence import CapabilityEvidence, CapabilityEvidenceType
from apex_host.graph_ids import access_capability_id
from apex_host.parsers.capability_parser import (
    _ACCEPTED_COMMAND_VALIDATION_METHODS,
    _ACCEPTED_VALIDATION_METHODS,
    _MIN_COMMAND_CAPABILITY_CONFIDENCE,
    _MIN_DIRECT_FILE_READ_CONFIDENCE,
    _SSH_CAPABILITY_CONFIDENCE,
)
from apex_host.types import AccessCapabilityType

if TYPE_CHECKING:
    from apex_host.capabilities.discovery import CapabilityDiscoveryContext

#: Below this, SSH evidence is refused regardless of evidence_type/method —
#: mirrors ``CapabilityParser``'s own fixed ``_SSH_CAPABILITY_CONFIDENCE``
#: derivation value (SSH has no caller-supplied confidence today; the
#: provider enforces the SAME floor for automatically-derived evidence so a
#: weaker signal can never masquerade as a real validated login).
_MIN_SSH_CONFIDENCE = _SSH_CAPABILITY_CONFIDENCE


def _existing_capability_confidence(context: "CapabilityDiscoveryContext", capability_id: str) -> float | None:
    """Read-only lookup against the already-fetched subgraph — reading
    passed-in data is not "writing MemoryAPI directly"; every planner in
    this codebase does exactly this (e.g.
    ``access_capabilities_from_subgraph``)."""
    for node in context.subgraph.nodes:
        if node.id == capability_id and node.type == "access_capability":
            try:
                return float(node.props.get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                return 0.0
    return None


def _evidence_provenance(context: "CapabilityDiscoveryContext", capability_id: str) -> tuple[str, ...]:
    for node in context.subgraph.nodes:
        if node.id == capability_id and node.type == "access_capability":
            metadata = node.props.get("metadata") or {}
            return tuple(str(e) for e in metadata.get("evidence_provenance", []))
    return ()


def _base_decision(
    evidence: CapabilityEvidence,
    *,
    provider_name: str,
    status: CapabilityDerivationStatus,
    capability_id: str,
    confidence: float,
    sanitized_reason: str,
    metadata: dict[str, object] | None = None,
) -> CapabilityDerivationDecision:
    return CapabilityDerivationDecision(
        status=status,
        provider_name=provider_name,
        evidence_id=evidence.evidence_id,
        capability_type=evidence.capability_family,
        capability_id=capability_id,
        confidence=confidence,
        validation_method=evidence.validation_method,
        sanitized_reason=sanitized_reason,
        target_host_id=evidence.target_host_id,
        principal=evidence.principal,
        source_task_id=evidence.source_task_id,
        runtime_reference_id=evidence.runtime_reference_id,
        metadata=dict(metadata or {}),
        provenance_digest=evidence.provenance_digest,
    )


def _evidence_type_accepted(evidence: CapabilityEvidence, supported: frozenset[CapabilityEvidenceType]) -> bool:
    """True when *evidence*'s type is one of *supported*, OR it is the
    universal ``OPERATOR_ATTESTED`` type (Phase 23's operator-seed
    migration routes through every provider's own family-matching logic
    below via this shared entry point — see
    ``apex_host.orchestration.capability_seed``). The family itself is
    still separately checked by each provider afterward — ``OPERATOR_ATTESTED``
    alone is never sufficient on its own."""
    return evidence.evidence_type in supported or evidence.evidence_type is CapabilityEvidenceType.OPERATOR_ATTESTED


def _classify_against_existing(
    evidence: CapabilityEvidence,
    context: "CapabilityDiscoveryContext",
    *,
    capability_id: str,
) -> tuple[CapabilityDerivationStatus, float]:
    """Shared duplicate/update/accept classification for every provider —
    see module docstring "Identity and deduplication" for the rule:
    duplicate replay of the same ``evidence_id`` never changes confidence;
    new, different evidence for an already-known capability raises
    confidence monotonically (never lowers it); brand-new identity is a
    plain accept."""
    existing_confidence = _existing_capability_confidence(context, capability_id)
    if existing_confidence is None:
        return CapabilityDerivationStatus.accepted, evidence.confidence
    provenance = _evidence_provenance(context, capability_id)
    if evidence.evidence_id and evidence.evidence_id in provenance:
        return CapabilityDerivationStatus.duplicate, existing_confidence
    return CapabilityDerivationStatus.updated, max(existing_confidence, evidence.confidence)


class CapabilityProvider(Protocol):
    """The ONLY interface a provider may implement."""

    @property
    def supported_evidence_types(self) -> frozenset[CapabilityEvidenceType]: ...

    @property
    def accepted_capability_families(self) -> frozenset[AccessCapabilityType]:
        """The ``AccessCapabilityType`` value(s) this provider owns — used
        by the discovery engine to route ``OPERATOR_ATTESTED`` evidence
        (which carries no evidence-type-implied family) to the correct
        provider by ``capability_family`` alone (Phase 23's operator-seed
        migration — see ``apex_host.orchestration.capability_seed``)."""
        ...

    def evaluate(
        self, evidence: CapabilityEvidence, context: "CapabilityDiscoveryContext",
    ) -> CapabilityDerivationDecision: ...


class SSHCapabilityProvider:
    """Accepts only evidence proving an authenticated SSH operation with a
    runtime reference available. Rejects: discovered-but-untested
    credentials, an open port 22, an SSH banner, a failed login, dry-run
    evidence (rejected centrally by :func:`validate_evidence` before any
    provider runs), or an LLM assertion (never an accepted
    ``validation_method`` value in the first place)."""

    supported_evidence_types = frozenset({CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND})
    accepted_capability_families = frozenset({AccessCapabilityType.ssh_command})

    def evaluate(
        self, evidence: CapabilityEvidence, context: "CapabilityDiscoveryContext",
    ) -> CapabilityDerivationDecision:
        name = type(self).__name__
        if not _evidence_type_accepted(evidence, self.supported_evidence_types):
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="unsupported_evidence",
            )
        if evidence.capability_family is not AccessCapabilityType.ssh_command:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="unsupported_evidence",
            )
        if not evidence.principal:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="target_mismatch",
            )
        if evidence.confidence < _MIN_SSH_CONFIDENCE:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="confidence_below_threshold",
            )
        capability_id = access_capability_id(
            evidence.target_host_id.removeprefix("host:"), AccessCapabilityType.ssh_command.value, evidence.principal,
        )
        status, confidence = _classify_against_existing(evidence, context, capability_id=capability_id)
        return _base_decision(
            evidence, provider_name=name, status=status, capability_id=capability_id,
            confidence=confidence, sanitized_reason="authenticated ssh operation validated",
        )


class DirectFileReadCapabilityProvider:
    """Accepts only evidence proving path-dependent content behavior via
    an accepted direct-file-read validation method. Rejects: an HTTP 200
    alone, an identical response for every path, generic authenticated web
    access, an LLM claim, or an unvalidated URL template (all of which are
    already excluded from ``_ACCEPTED_VALIDATION_METHODS``)."""

    supported_evidence_types = frozenset({CapabilityEvidenceType.DIRECT_FILE_READ_VALIDATED})
    accepted_capability_families = frozenset({
        AccessCapabilityType.arbitrary_file_read, AccessCapabilityType.api_file_read,
    })

    def evaluate(
        self, evidence: CapabilityEvidence, context: "CapabilityDiscoveryContext",
    ) -> CapabilityDerivationDecision:
        name = type(self).__name__
        if not _evidence_type_accepted(evidence, self.supported_evidence_types):
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="unsupported_evidence",
            )
        if evidence.capability_family not in (
            AccessCapabilityType.arbitrary_file_read, AccessCapabilityType.api_file_read,
        ):
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="unsupported_evidence",
            )
        if not evidence.principal:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="target_mismatch",
            )
        if evidence.validation_method not in _ACCEPTED_VALIDATION_METHODS:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="invalid_validation_method",
            )
        if evidence.confidence < _MIN_DIRECT_FILE_READ_CONFIDENCE:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="confidence_below_threshold",
            )
        capability_id = access_capability_id(
            evidence.target_host_id.removeprefix("host:"), evidence.capability_family.value, evidence.principal,
        )
        status, confidence = _classify_against_existing(evidence, context, capability_id=capability_id)
        return _base_decision(
            evidence, provider_name=name, status=status, capability_id=capability_id,
            confidence=confidence, sanitized_reason="path-dependent direct-file-read evidence validated",
            metadata=dict(evidence.sanitized_attributes),
        )


class _BoundedCommandProviderBase:
    """Shared evaluation logic for ``LocalCommandCapabilityProvider`` and
    ``RemoteCommandCapabilityProvider`` — the acceptance rules are
    identical (both are serviced by the same
    ``BoundedCommandCapabilityAdapter`` at the runtime layer); only the
    accepted ``evidence_type``/``capability_family`` differ."""

    _evidence_type: CapabilityEvidenceType
    _capability_family: AccessCapabilityType
    supported_evidence_types: frozenset[CapabilityEvidenceType]

    @property
    def accepted_capability_families(self) -> frozenset[AccessCapabilityType]:
        return frozenset({self._capability_family})

    def evaluate(
        self, evidence: CapabilityEvidence, context: "CapabilityDiscoveryContext",
    ) -> CapabilityDerivationDecision:
        name = type(self).__name__
        if not _evidence_type_accepted(evidence, self.supported_evidence_types):
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="unsupported_evidence",
            )
        if evidence.capability_family is not self._capability_family:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="unsupported_evidence",
            )
        if not evidence.principal:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="target_mismatch",
            )
        if evidence.validation_method not in _ACCEPTED_COMMAND_VALIDATION_METHODS:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="invalid_validation_method",
            )
        if evidence.confidence < _MIN_COMMAND_CAPABILITY_CONFIDENCE:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="confidence_below_threshold",
            )
        capability_id = access_capability_id(
            evidence.target_host_id.removeprefix("host:"), self._capability_family.value, evidence.principal,
        )
        status, confidence = _classify_against_existing(evidence, context, capability_id=capability_id)
        return _base_decision(
            evidence, provider_name=name, status=status, capability_id=capability_id,
            confidence=confidence, sanitized_reason="bounded command-execution evidence validated",
            metadata={**dict(evidence.sanitized_attributes), "read_only": True},
        )


class LocalCommandCapabilityProvider(_BoundedCommandProviderBase):
    """Accepts only a deterministic, benign LOCAL command result validated
    with a safe bounded-read strategy available. Rejects: arbitrary
    textual output alone, a dry-run result (rejected centrally), or an
    unaccepted validation method."""

    _evidence_type = CapabilityEvidenceType.LOCAL_COMMAND_VALIDATED
    _capability_family = AccessCapabilityType.local_shell
    supported_evidence_types = frozenset({CapabilityEvidenceType.LOCAL_COMMAND_VALIDATED})


class RemoteCommandCapabilityProvider(_BoundedCommandProviderBase):
    """Accepts only a deterministic, benign REMOTE command result
    validated with a safe bounded-read backend/session reference
    available. Rejects: a generic "command executed" claim with no
    accepted validation method, or a runtime-target mismatch (checked by
    the discovery engine before registration, not here — see
    ``apex_host.capabilities.discovery``)."""

    _evidence_type = CapabilityEvidenceType.REMOTE_COMMAND_VALIDATED
    _capability_family = AccessCapabilityType.remote_command
    supported_evidence_types = frozenset({CapabilityEvidenceType.REMOTE_COMMAND_VALIDATED})


class WebCommandCapabilityProvider:
    """Accepts only evidence proving a fixed, validated web-command
    mechanism with a safe bounded objective adapter registrable. Shares
    ``DirectFileReadCapabilityAdapter`` at the runtime layer (see
    ``apex_host/parsers/capability_parser.py`` module docstring) but uses
    the COMMAND validation vocabulary, not the file-read vocabulary —
    mirroring ``derive_command_capability``'s own existing distinction.

    Rejects: a generic admin-portal-access claim, an HTTP 200 alone, or a
    token/cookie value (which would never legitimately appear in
    ``sanitized_attributes`` at all — rejected centrally by
    :func:`~apex_host.capabilities.evidence.validate_evidence` if it did).
    """

    supported_evidence_types = frozenset({CapabilityEvidenceType.WEB_COMMAND_VALIDATED})
    accepted_capability_families = frozenset({AccessCapabilityType.web_command})

    def evaluate(
        self, evidence: CapabilityEvidence, context: "CapabilityDiscoveryContext",
    ) -> CapabilityDerivationDecision:
        name = type(self).__name__
        if not _evidence_type_accepted(evidence, self.supported_evidence_types):
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="unsupported_evidence",
            )
        if evidence.capability_family is not AccessCapabilityType.web_command:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="unsupported_evidence",
            )
        if not evidence.principal:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="target_mismatch",
            )
        if evidence.validation_method not in _ACCEPTED_COMMAND_VALIDATION_METHODS:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="invalid_validation_method",
            )
        if evidence.confidence < _MIN_COMMAND_CAPABILITY_CONFIDENCE:
            return _base_decision(
                evidence, provider_name=name, status=CapabilityDerivationStatus.rejected,
                capability_id="", confidence=0.0, sanitized_reason="confidence_below_threshold",
            )
        # No known current mechanism activates a web_command runtime adapter
        # from automatically-produced evidence alone (its adapter requires
        # an operator-fixed HTTP request shape — origin/endpoint/headers —
        # that no executor in this codebase derives autonomously). Metadata
        # derivation is still permitted (a future operator-attested seed, or
        # a future request-shape-supplying executor, can use it); runtime
        # activation is explicitly reported as unavailable rather than
        # faked. See docs/user-flag-objective.md §20 "Known limitations".
        capability_id = access_capability_id(
            evidence.target_host_id.removeprefix("host:"), AccessCapabilityType.web_command.value, evidence.principal,
        )
        status, confidence = _classify_against_existing(evidence, context, capability_id=capability_id)
        if status is CapabilityDerivationStatus.accepted and not evidence.runtime_reference_id:
            status = CapabilityDerivationStatus.runtime_unavailable
        return _base_decision(
            evidence, provider_name=name, status=status, capability_id=capability_id,
            confidence=confidence, sanitized_reason="web-command evidence validated; requires operator-fixed request shape",
            metadata={**dict(evidence.sanitized_attributes), "read_only": True},
        )


#: The complete, ordered set of providers the discovery engine dispatches
#: to — stable order (never a set/dict-iteration-order dependency), one
#: instance per family. Adding a new provider means adding one entry here.
DEFAULT_PROVIDERS: tuple[CapabilityProvider, ...] = (
    SSHCapabilityProvider(),
    DirectFileReadCapabilityProvider(),
    LocalCommandCapabilityProvider(),
    RemoteCommandCapabilityProvider(),
    WebCommandCapabilityProvider(),
)
