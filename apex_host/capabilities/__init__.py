# __init__.py
# apex_host.capabilities — deterministic capability-evidence discovery pipeline (Phase 23).
"""Structured automatic capability derivation (Phase 23).

Converts already-validated execution evidence into ``AccessCapability``
metadata and runtime-adapter registration without requiring the operator to
manually seed every supported capability. This is **not** autonomous
vulnerability discovery — it never discovers SQL injection, XSS, command
injection, or arbitrary file read from scratch. It closes one narrower
architectural gap: a validated execution result already proves a capability
exists; this package makes that fact deterministically flow into the same
``AccessCapability`` records ``ObjectivePlanner`` already consumes.

Public surface: :class:`~apex_host.capabilities.evidence.CapabilityEvidence`,
:class:`~apex_host.capabilities.evidence.CapabilityEvidenceType`,
:func:`~apex_host.capabilities.evidence.validate_evidence`,
:class:`~apex_host.capabilities.decisions.CapabilityDerivationDecision`,
:class:`~apex_host.capabilities.discovery.CapabilityDiscoveryEngine`, and
:func:`~apex_host.capabilities.discovery.run_capability_discovery` (the
orchestration-facing entry point).

See ``docs/user-flag-objective.md`` §20 for the full design.
"""
from __future__ import annotations

from apex_host.capabilities.decisions import CapabilityDerivationDecision, CapabilityDerivationStatus
from apex_host.capabilities.discovery import (
    CapabilityDiscoveryContext,
    CapabilityDiscoveryEngine,
    CapabilityDiscoveryResult,
    run_capability_discovery,
)
from apex_host.capabilities.evidence import CapabilityEvidence, CapabilityEvidenceType, validate_evidence
from apex_host.capabilities.lifecycle import CapabilityLifecycleState, capability_lifecycle_state

__all__ = [
    "CapabilityDerivationDecision",
    "CapabilityDerivationStatus",
    "CapabilityDiscoveryContext",
    "CapabilityDiscoveryEngine",
    "CapabilityDiscoveryResult",
    "CapabilityEvidence",
    "CapabilityEvidenceType",
    "CapabilityLifecycleState",
    "capability_lifecycle_state",
    "run_capability_discovery",
    "validate_evidence",
]
