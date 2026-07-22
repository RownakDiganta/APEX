# lifecycle.py
# CapabilityLifecycleState — a pure, derived (never separately stored) view over an AccessCapability's existing validated/runtime_available fields.
"""Capability lifecycle (Phase 23).

A compact lifecycle derived ENTIRELY from fields ``AccessCapability``
already has (``validated``, ``runtime_available``) — no new persisted
"lifecycle_state" field was added to the EKG node or the dataclass. This
mirrors this codebase's own established convention of deriving a status
view rather than storing a second, redundant source of truth (see e.g.
``apex_host.planners.objective.objective_status_from_subgraph``,
``apex_host.planners.priv_esc_opportunities`` "opportunity_count" family of
derived properties).

Only three states are currently reachable: ``candidate``, ``active``,
``unavailable``. ``validated`` (a hypothetical intermediate state between
"derivation succeeded" and "we know whether a runtime adapter exists") is
never actually distinguishable in this codebase's data model — every
``CapabilityParser.derive_*`` call already sets ``validated=True`` at
creation time, and the orchestration layer's registration step runs every
objective turn, so a capability is only ever observed as either
``active`` or ``unavailable``, never in a separate "validated, runtime
status unknown" limbo. ``validated`` is kept as a reserved member (see
below) rather than removed, matching this module's own "reserved for
forward compatibility" convention for the other unreachable members.
``expired``/``revoked``/``superseded`` are likewise
defined for forward compatibility (matching this codebase's own repeated
"documented but not yet produced" pattern — see
``apex_host.types.PrivilegeEnumerationStatus.elevated_access_validated``,
``apex_host.orchestration.outcome.EngagementOutcome.goal_completed``) but no
current code path ever assigns them: nothing in this phase revokes a
capability or expires one after creation (``ApexConfig
.capability_evidence_ttl_seconds`` governs EVIDENCE staleness at validation
time, before a capability is ever created — it does not retroactively
expire an already-materialized capability).

``CapabilityRuntimeRegistry`` remains the authoritative source of truth for
"is a runtime adapter available RIGHT NOW" — ``AccessCapability
.runtime_available`` (and therefore this lifecycle view) is a re-derived,
advisory snapshot of that fact as of the last time
``apex_host.capabilities.runtime_resolution`` ran, not a live query against
the registry itself (see that module's docstring for why: the registry is
runtime-only and never available to a pure planning-time reader).
"""
from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apex_host.types import AccessCapability


class CapabilityLifecycleState(str, Enum):
    """See module docstring for which states are actually reachable."""

    candidate = "candidate"
    active = "active"
    unavailable = "unavailable"
    validated = "validated"   # reserved — not currently distinguishable/produced
    expired = "expired"       # reserved — not currently produced
    revoked = "revoked"       # reserved — not currently produced
    superseded = "superseded"  # reserved — not currently produced


def capability_lifecycle_state(capability: "AccessCapability") -> CapabilityLifecycleState:
    """Pure derivation — never reads the runtime registry, never performs
    I/O. See module docstring for the exact semantics of each reachable
    state:

    - ``candidate``: not yet validated (no current provider ever leaves a
      materialized capability in this state — it exists for forward
      compatibility with a future "evidence exists but derivation
      requirements not yet satisfied" intermediate write, which this
      phase's providers do not produce, since ``CapabilityParser`` only
      ever materializes already-validated=True nodes).
    - ``active``: validated AND a runtime adapter is currently registered.
    - ``unavailable``: validated metadata exists but no runtime adapter is
      currently registered for it.
    """
    if not capability.validated:
        return CapabilityLifecycleState.candidate
    if capability.runtime_available:
        return CapabilityLifecycleState.active
    return CapabilityLifecycleState.unavailable
