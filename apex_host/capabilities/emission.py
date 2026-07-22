# emission.py
# Typed-result-only organic capability-evidence emitters — one function per supported evidence family, each accepting a specific, already-existing (or minimal, purpose-built) typed result dataclass, never a generic untrusted dict.
"""Organic evidence emission (Phase 24).

Every function here follows the same shape: given a **typed** validation
result object (never a free-form ``dict``, never raw tool stdout), return
a :class:`~apex_host.capabilities.evidence.CapabilityEvidence` or ``None``
when the result does not qualify. This is deliberately narrower than
accepting "whatever a caller happens to have" — a future executor that
wants automatic capability derivation must construct one of these typed
result objects from its own already-validated fields, never hand this
module a raw stdout blob to interpret.

Only ``evidence_from_ssh_validation`` has a real, live producer today
(``apex_host.agents.ssh_executor.SSHExecutor`` -> ``CredentialValidationResult``,
already threaded through ``apex_host.execution.dispatcher`` into a tr-dict
that ``apex_host.orchestration.parsing_node`` reads). The other four
(direct-file-read, local-command, remote-command, web-command) have **no
live validating executor anywhere in this codebase** (see
``docs/user-flag-objective.md`` §20/§21 "Known limitations" — DFR/local/
remote/web capabilities are activated exclusively through operator
attestation today). Per Phase 24's own explicit scope boundary, this
module adds only the minimal typed result model and emission seam for
those four — never a fabricated discovery mechanism. A future phase that
builds a real DFR/local/remote/web validation executor should construct
the corresponding ``*ValidationResult`` from its own typed output and call
the matching ``evidence_from_*`` function; nothing else in
``apex_host.capabilities`` needs to change.

``web_command`` in particular is documented, not silently deferred:
``apex_host.capabilities.providers.WebCommandCapabilityProvider`` already
explains why no current mechanism activates it automatically (its runtime
adapter requires an operator-fixed HTTP request shape that no executor in
this codebase derives autonomously) — that reasoning is unchanged by this
phase. ``evidence_from_web_command_validation`` exists for forward
compatibility only, exactly like the other three stubs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from memfabric.ids import new_id, now

from apex_host.capabilities.evidence import CapabilityEvidence, CapabilityEvidenceType
from apex_host.parsers.capability_parser import (
    _ACCEPTED_COMMAND_VALIDATION_METHODS,
    _ACCEPTED_VALIDATION_METHODS,
    _MIN_COMMAND_CAPABILITY_CONFIDENCE,
    _MIN_DIRECT_FILE_READ_CONFIDENCE,
    _SSH_CAPABILITY_CONFIDENCE,
)
from apex_host.types import AccessCapabilityType

if TYPE_CHECKING:
    from apex_host.types import CredentialValidationResult

__all__ = [
    "DirectFileReadValidationResult",
    "LocalCommandValidationResult",
    "RemoteCommandValidationResult",
    "WebCommandValidationResult",
    "evidence_from_direct_file_read_validation",
    "evidence_from_local_command_validation",
    "evidence_from_remote_command_validation",
    "evidence_from_ssh_validation",
    "evidence_from_web_command_validation",
]


def evidence_from_ssh_validation(
    result: "CredentialValidationResult", *, task_id: str, target: str, is_dry_run: bool = False,
) -> CapabilityEvidence | None:
    """Build ``SSH_AUTHENTICATED_COMMAND`` evidence from a typed
    ``CredentialValidationResult`` (the real, existing SSH executor result
    type — ``apex_host/types.py``). The ONE evidence family with a real,
    live producer today.

    Rejects: ``result.protocol != "ssh"``, a failed/unauthenticated result,
    or a missing username. Mirrors
    ``apex_host.orchestration.parsing_node.ssh_capability_evidence_for_result``
    exactly (that function is now a thin dict-unpacking wrapper around this
    one — see its docstring).
    """
    if result.protocol != "ssh" or not result.success or not result.username:
        return None
    return CapabilityEvidence(
        evidence_id=new_id(),
        evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
        capability_family=AccessCapabilityType.ssh_command,
        target_host_id=f"host:{target}",
        source_task_id=task_id,
        principal=result.username,
        validation_method="deterministic_benign_command",
        confidence=_SSH_CAPABILITY_CONFIDENCE,
        timestamp=now(),
        is_dry_run=is_dry_run,
    )


@dataclass(frozen=True, slots=True)
class DirectFileReadValidationResult:
    """Minimal typed result shape for a future direct-file-read validation
    executor — NOT produced by any executor in this codebase today (see
    module docstring). Mirrors the fields
    ``CapabilityParser.derive_direct_file_read_capability`` already accepts."""

    target: str
    principal: str
    validation_method: str
    confidence: float
    source_task_id: str = ""
    requires_auth: bool = False
    max_response_bytes: int = 4096
    request_shape_id: str = ""
    is_dry_run: bool = False


def evidence_from_direct_file_read_validation(
    result: DirectFileReadValidationResult,
) -> CapabilityEvidence | None:
    """Build ``DIRECT_FILE_READ_VALIDATED`` evidence from a typed
    :class:`DirectFileReadValidationResult`. No current call site produces
    one (see module docstring) — this is the emission seam a future
    executor would use.

    Rejects: an empty ``principal``, or a ``validation_method`` outside
    ``CapabilityParser``'s own accepted vocabulary (reused, never
    duplicated — see ``apex_host.parsers.capability_parser``).
    """
    if not result.principal or result.validation_method not in _ACCEPTED_VALIDATION_METHODS:
        return None
    if result.confidence < _MIN_DIRECT_FILE_READ_CONFIDENCE:
        return None
    return CapabilityEvidence(
        evidence_id=new_id(),
        evidence_type=CapabilityEvidenceType.DIRECT_FILE_READ_VALIDATED,
        capability_family=AccessCapabilityType.arbitrary_file_read,
        target_host_id=f"host:{result.target}",
        source_task_id=result.source_task_id,
        principal=result.principal,
        validation_method=result.validation_method,
        confidence=result.confidence,
        timestamp=now(),
        sanitized_attributes={
            "requires_auth": result.requires_auth,
            "max_response_bytes": result.max_response_bytes,
            "request_shape_id": result.request_shape_id,
        },
        is_dry_run=result.is_dry_run,
    )


@dataclass(frozen=True, slots=True)
class LocalCommandValidationResult:
    """Minimal typed result shape for a future local bounded-command
    validation executor — NOT produced by any executor in this codebase
    today (see module docstring)."""

    target: str
    principal: str
    validation_method: str
    confidence: float
    source_task_id: str = ""
    max_output_bytes: int = 4096
    strategy_id: str = ""
    is_dry_run: bool = False


def evidence_from_local_command_validation(
    result: LocalCommandValidationResult,
) -> CapabilityEvidence | None:
    """Build ``LOCAL_COMMAND_VALIDATED`` evidence from a typed
    :class:`LocalCommandValidationResult`. No current call site produces
    one (see module docstring)."""
    if not result.principal or result.validation_method not in _ACCEPTED_COMMAND_VALIDATION_METHODS:
        return None
    if result.confidence < _MIN_COMMAND_CAPABILITY_CONFIDENCE:
        return None
    return CapabilityEvidence(
        evidence_id=new_id(),
        evidence_type=CapabilityEvidenceType.LOCAL_COMMAND_VALIDATED,
        capability_family=AccessCapabilityType.local_shell,
        target_host_id=f"host:{result.target}",
        source_task_id=result.source_task_id,
        principal=result.principal,
        validation_method=result.validation_method,
        confidence=result.confidence,
        timestamp=now(),
        sanitized_attributes={"max_output_bytes": result.max_output_bytes, "strategy_id": result.strategy_id},
        is_dry_run=result.is_dry_run,
    )


@dataclass(frozen=True, slots=True)
class RemoteCommandValidationResult:
    """Minimal typed result shape for a future remote bounded-command
    validation executor — NOT produced by any executor in this codebase
    today (see module docstring)."""

    target: str
    principal: str
    validation_method: str
    confidence: float
    source_task_id: str = ""
    max_output_bytes: int = 4096
    strategy_id: str = ""
    is_dry_run: bool = False


def evidence_from_remote_command_validation(
    result: RemoteCommandValidationResult,
) -> CapabilityEvidence | None:
    """Build ``REMOTE_COMMAND_VALIDATED`` evidence from a typed
    :class:`RemoteCommandValidationResult`. No current call site produces
    one (see module docstring)."""
    if not result.principal or result.validation_method not in _ACCEPTED_COMMAND_VALIDATION_METHODS:
        return None
    if result.confidence < _MIN_COMMAND_CAPABILITY_CONFIDENCE:
        return None
    return CapabilityEvidence(
        evidence_id=new_id(),
        evidence_type=CapabilityEvidenceType.REMOTE_COMMAND_VALIDATED,
        capability_family=AccessCapabilityType.remote_command,
        target_host_id=f"host:{result.target}",
        source_task_id=result.source_task_id,
        principal=result.principal,
        validation_method=result.validation_method,
        confidence=result.confidence,
        timestamp=now(),
        sanitized_attributes={"max_output_bytes": result.max_output_bytes, "strategy_id": result.strategy_id},
        is_dry_run=result.is_dry_run,
    )


@dataclass(frozen=True, slots=True)
class WebCommandValidationResult:
    """Minimal typed result shape for a future web-command validation
    executor — NOT produced by any executor in this codebase today, and
    (unlike the other three stubs) not expected to be in the near future
    either — see ``apex_host.capabilities.providers.WebCommandCapabilityProvider``
    and module docstring "web_command in particular"."""

    target: str
    principal: str
    validation_method: str
    confidence: float
    source_task_id: str = ""
    max_output_bytes: int = 4096
    strategy_id: str = ""
    is_dry_run: bool = False


def evidence_from_web_command_validation(
    result: WebCommandValidationResult,
) -> CapabilityEvidence | None:
    """Build ``WEB_COMMAND_VALIDATED`` evidence from a typed
    :class:`WebCommandValidationResult`. No current call site produces one
    — kept for forward-compatible symmetry with the other three stubs
    only; ``WebCommandCapabilityProvider`` will still report
    ``runtime_unavailable`` for this evidence unless a
    ``runtime_reference_id`` is separately supplied, since no current
    registration path can activate a ``web_command`` adapter from evidence
    alone (it requires an operator-fixed HTTP request shape)."""
    if not result.principal or result.validation_method not in _ACCEPTED_COMMAND_VALIDATION_METHODS:
        return None
    if result.confidence < _MIN_COMMAND_CAPABILITY_CONFIDENCE:
        return None
    return CapabilityEvidence(
        evidence_id=new_id(),
        evidence_type=CapabilityEvidenceType.WEB_COMMAND_VALIDATED,
        capability_family=AccessCapabilityType.web_command,
        target_host_id=f"host:{result.target}",
        source_task_id=result.source_task_id,
        principal=result.principal,
        validation_method=result.validation_method,
        confidence=result.confidence,
        timestamp=now(),
        sanitized_attributes={"max_output_bytes": result.max_output_bytes, "strategy_id": result.strategy_id},
        is_dry_run=result.is_dry_run,
    )
