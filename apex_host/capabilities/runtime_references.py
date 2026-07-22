# runtime_references.py
# RuntimeReference model, RuntimeReferenceStore, and RuntimeReferenceResolver — the process-local, never-persisted opaque-handle layer binding a capability_id to a live runtime adapter for exactly one target/type/generation/scope, with explicit invalidation hooks.
"""Runtime-reference resolution layer (Phase 24).

Phase 23 scaffolded ``CapabilityEvidence.runtime_reference_id``/
``runtime_generation`` and ``CapabilityDerivationDecision.runtime_reference_id``
but nothing ever minted or resolved a real value — every emitter left them
at their defaults (``""``/``0``). This module makes the concept real:

``RuntimeReference``
    Immutable, opaque, non-secret metadata binding ONE runtime-adapter
    registration to a target/capability_type/generation/authorization
    scope. Never holds, exposes, or serializes the underlying adapter
    object itself — see its own docstring.

``RuntimeReferenceStore``
    Process-local, in-memory-only bookkeeping of ``RuntimeReference``
    metadata, keyed by an opaque, cryptographically-random
    ``reference_id`` (``secrets.token_urlsafe`` — explicitly NOT a Python
    object id/``id()`` value, which is reused across garbage-collected
    objects and observable via ``repr()``, and NOT derived from any
    secret material). One instance per engagement, constructed fresh in
    ``apex_host.orchestration.builder.build_apex_graph`` exactly like
    ``apex_host.runtime_registry.CapabilityRuntimeRegistry`` and
    ``apex_host.orchestration.stall.StallTracker`` — never written through
    ``MemoryAPI``, never present in ``ApexGraphState``, never touched by
    the LangGraph checkpointer. A ``reference_id`` minted by one instance
    is meaningless to another instance (including one built after a
    process restart) — there is no reconstruction path from persisted EKG
    metadata alone (memfabric Invariant 1 is not violated by this store
    precisely because it never IS the state; it is a runtime-only cache
    over state ``CapabilityRuntimeRegistry`` already independently holds).

``RuntimeReferenceResolver``
    Validates a ``reference_id`` (target match, capability-type match,
    optional generation match, expiry, revocation) against a
    ``RuntimeReferenceStore`` and, only when every check passes, resolves
    the live adapter from a ``CapabilityRuntimeRegistry`` by
    ``capability_id`` — it never falls back to a "global"/default adapter
    for a mismatched target, and never reconstructs an adapter from
    persisted metadata alone; the adapter always comes from the live,
    in-process registry, so a stale or replayed reference can, at most,
    resolve to whatever the CURRENT registry actually holds for that
    capability_id (or nothing, if unregistered).

``runtime_generation`` semantics (the "meaningful" requirement)
-----------------------------------------------------------------
A generation number increments **only** when
``CapabilityRuntimeRegistry.replace()`` is called to install a materially
new adapter for an already-registered ``capability_id`` (e.g. because the
session was invalidated and a fresh one was constructed, credentials
changed, or the underlying request/strategy shape changed) — never on a
mere re-derivation of identical evidence, never on an idempotent
``ensure_*`` call that returns the existing adapter unchanged, and never
on a checkpoint replay (there is no checkpoint for this data at all — see
"Persistence and replay" below). Capability-node IDENTITY itself
(``access_capability_id(target, capability_type, principal)``) never
changes across generations — this deliberately does not introduce
versioned capability nodes; "which construction of the runtime material
this is" lives entirely in the runtime-reference/registry-replacement
concept, not in the EKG's own content-addressed identity scheme.

Invalidation triggers (see ``RuntimeReferenceStore`` methods and
``RuntimeReferenceError`` below)
-----------------------------------------------------------------
- Process shutdown -> ``invalidate_all()`` (wired from
  ``apex_host.runtime.ApexRuntime.aclose()``).
- Explicit operator/engagement-level revocation -> ``invalidate()``.
- Authorization/target change -> ``invalidate_for_target()``.
- A backend-disconnected / session-invalid read outcome observed by the
  orchestration layer -> ``invalidate_for_capability()`` (wired from
  ``apex_host.orchestration.dispatch_node.make_objective_node`` — see that
  module).
- Natural expiry (``ttl_seconds`` at mint time) and generation
  supersession (a fresh ``mint()`` for the same ``capability_id``
  automatically revokes the prior reference) are both handled without any
  external caller needing to do anything.

Persistence and replay
-----------------------
Neither this module's objects nor ``CapabilityRuntimeRegistry`` ever
appear in ``ApexGraphState`` or any LangGraph checkpoint payload — proven
by a static architecture-scan test
(``tests/apex_host/test_phase24_runtime_reference_activation.py``). A
resumed/replayed engagement therefore always starts with an EMPTY store
and registry: every previously-"active" capability is
``runtime_available=False`` again in the live registry sense (its EKG
node still records ``runtime_available=True`` from before the restart —
that is stale metadata, not live state) until the orchestration layer
re-registers it fresh on the next objective turn. This is intentional,
not a bug: runtime material (an SSH password held in memory, an HTTP
primitive's headers) must never be reconstructed from anything persisted.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

from memfabric.ids import now

if TYPE_CHECKING:
    from apex_host.runtime_registry import CapabilityRuntimeRegistry, FlagReadCapability
    from apex_host.types import AccessCapabilityType

__all__ = [
    "RuntimeReference",
    "RuntimeReferenceError",
    "RuntimeReferenceResolver",
    "RuntimeReferenceStore",
]


class RuntimeReferenceError(str, Enum):
    """Bounded, sanitized vocabulary serving two roles: (1) the reason
    :meth:`RuntimeReferenceResolver.resolve` failed to return an adapter,
    and (2) the ``revocation_reason`` recorded on a revoked
    :class:`RuntimeReference` (a store-level invalidation call passes one
    of these values as its ``reason``). Never derived from raw
    adapter/exception content — always one of exactly these 13 fixed
    members.
    """

    #: No reference exists for the supplied id (never minted, or the
    #: store was reset — e.g. a fresh instance after a process restart).
    not_found = "not_found"
    #: The reference was explicitly revoked (see the four invalidation
    #: triggers in the module docstring) — the underlying cause is in
    #: ``RuntimeReference.revocation_reason``.
    revoked = "revoked"
    #: The reference's own ``ttl_seconds``-derived expiry has passed.
    expired = "expired"
    #: The caller's ``target`` does not match the reference's bound target
    #: — never resolved regardless of any other field matching (this is
    #: the "never falls back to a global adapter for a mismatched target"
    #: guarantee).
    target_mismatch = "target_mismatch"
    #: The caller's ``capability_type`` does not match the reference's
    #: bound type.
    type_mismatch = "type_mismatch"
    #: The caller supplied an ``expected_generation`` that does not match
    #: the reference's current generation (a stale caller holding an old
    #: generation number).
    generation_mismatch = "generation_mismatch"
    #: Reserved for a future multi-authorization-scope deployment; no
    #: current caller supplies a scope that could mismatch (mirrors this
    #: codebase's own "documented but not yet reachable" convention, e.g.
    #: ``memfabric``'s ``ConflictStatus`` reserved members).
    scope_mismatch = "scope_mismatch"
    #: Reserved: the registry holds an object for this capability_id that
    #: does not satisfy ``FlagReadCapability`` — not reachable today since
    #: every registration path constructs a conforming adapter.
    adapter_unavailable = "adapter_unavailable"
    #: The registry has no adapter registered for the reference's
    #: capability_id (it was never registered, or was unregistered — see
    #: ``CapabilityRuntimeRegistry.unregister``).
    capability_unregistered = "capability_unregistered"
    #: Revocation reason: an underlying backend/session was observed to be
    #: disconnected (e.g. a bounded read returned ``connected=False``).
    backend_disconnected = "backend_disconnected"
    #: Revocation reason: the operator/engagement's authorization for this
    #: capability was explicitly withdrawn.
    authorization_revoked = "authorization_revoked"
    #: Revocation reason: a session-shaped adapter (SSH, a bounded command
    #: strategy) reported its underlying session/connection as no longer
    #: valid.
    session_invalid = "session_invalid"
    #: Reserved defensive catch-all for an unexpected internal failure
    #: during resolution — never raised by current code paths (resolution
    #: is a pure dict/attribute lookup that cannot itself fail).
    internal_error = "internal_error"


@dataclass(frozen=True, slots=True)
class RuntimeReference:
    """Immutable, opaque, non-secret metadata binding one runtime-adapter
    registration to a target/capability_type/generation/authorization scope.

    Never exposes or serializes the underlying adapter object — there is
    no field here that could hold one, and :meth:`to_dict`/``__repr__``
    both surface only a truncated digest of ``reference_id``, never the
    full value (kept minimal on principle, mirroring this codebase's other
    sanitized-repr conventions, even though the id itself is not secret).
    """

    reference_id: str
    capability_id: str
    target: str
    capability_type: "AccessCapabilityType"
    generation: int
    authorization_scope_id: str = ""
    created_at: str = ""
    expires_at: str = ""
    revoked: bool = False
    revocation_reason: str = ""

    def is_expired(self, now_iso: str) -> bool:
        """True when *now_iso* is past this reference's ``expires_at``.
        A reference with no ``expires_at`` (the default — TTL is opt-in)
        never expires."""
        if not self.expires_at:
            return False
        return now_iso > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Sanitized audit view — a truncated digest only, never the full
        opaque ``reference_id``."""
        return {
            "reference_digest": self.reference_id[:8],
            "capability_id": self.capability_id,
            "target": self.target,
            "capability_type": self.capability_type.value,
            "generation": self.generation,
            "revoked": self.revoked,
            "revocation_reason": self.revocation_reason,
        }

    def __repr__(self) -> str:
        return (
            f"RuntimeReference(digest={self.reference_id[:8]}..., "
            f"capability_id={self.capability_id!r}, generation={self.generation}, "
            f"revoked={self.revoked})"
        )


class RuntimeReferenceStore:
    """Process-local, in-memory-only registry of :class:`RuntimeReference`
    metadata. See module docstring for the full lifecycle/persistence
    discussion."""

    def __init__(self) -> None:
        self._references: dict[str, RuntimeReference] = {}
        #: capability_id -> the reference_id of its current (non-superseded)
        #: reference. A fresh mint() for the same capability_id replaces
        #: this mapping and revokes the prior entry.
        self._current_for_capability: dict[str, str] = {}

    def mint(
        self,
        *,
        capability_id: str,
        target: str,
        capability_type: "AccessCapabilityType",
        generation: int,
        authorization_scope_id: str = "",
        ttl_seconds: float = 0.0,
    ) -> RuntimeReference:
        """Create and store a new, opaque :class:`RuntimeReference`.

        Superseding: minting a new reference for a ``capability_id`` that
        already has a live reference automatically revokes the prior one
        (``revocation_reason="superseded_by_new_generation"``) — at most
        one live reference per capability at a time. This is the one place
        ``generation`` becomes observable outside the registry itself;
        callers are expected to pass ``CapabilityRuntimeRegistry
        .generation_for(capability_id)`` so the reference's generation
        always reflects the registry's own authoritative counter.
        """
        reference_id = secrets.token_urlsafe(32)
        created = now()
        expires_at = ""
        if ttl_seconds > 0:
            try:
                expires_at = (
                    datetime.fromisoformat(created.replace("Z", "+00:00"))
                    + timedelta(seconds=ttl_seconds)
                ).isoformat()
            except ValueError:
                expires_at = ""
        ref = RuntimeReference(
            reference_id=reference_id,
            capability_id=capability_id,
            target=target,
            capability_type=capability_type,
            generation=generation,
            authorization_scope_id=authorization_scope_id,
            created_at=created,
            expires_at=expires_at,
        )
        self.invalidate_for_capability(capability_id, reason="superseded_by_new_generation")
        self._references[reference_id] = ref
        self._current_for_capability[capability_id] = reference_id
        return ref

    def get(self, reference_id: str) -> RuntimeReference | None:
        return self._references.get(reference_id)

    def current_reference_for(self, capability_id: str) -> RuntimeReference | None:
        """The current (possibly revoked/expired — callers must still
        check) reference for *capability_id*, or ``None`` if none was ever
        minted."""
        ref_id = self._current_for_capability.get(capability_id)
        if ref_id is None:
            return None
        return self._references.get(ref_id)

    def invalidate(self, reference_id: str, *, reason: str = RuntimeReferenceError.authorization_revoked.value) -> bool:
        """Explicitly revoke one reference by id. Idempotent — revoking an
        already-revoked reference is a harmless no-op that still returns
        ``True`` (the reference IS revoked, regardless of who did it
        first)."""
        ref = self._references.get(reference_id)
        if ref is None:
            return False
        self._references[reference_id] = replace(ref, revoked=True, revocation_reason=reason)
        return True

    def invalidate_for_capability(
        self, capability_id: str, *, reason: str = RuntimeReferenceError.authorization_revoked.value,
    ) -> bool:
        """Revoke the current reference for *capability_id*, if any."""
        ref_id = self._current_for_capability.get(capability_id)
        if ref_id is None:
            return False
        return self.invalidate(ref_id, reason=reason)

    def invalidate_for_target(self, target: str, *, reason: str = "target_changed") -> int:
        """Revoke every non-revoked reference bound to *target* — the
        authorization/target-change invalidation trigger. Returns the
        count actually revoked."""
        count = 0
        for ref_id, ref in list(self._references.items()):
            if ref.target == target and not ref.revoked:
                self._references[ref_id] = replace(ref, revoked=True, revocation_reason=reason)
                count += 1
        return count

    def invalidate_all(self, *, reason: str = "shutdown") -> int:
        """Revoke every non-revoked reference — the process-shutdown
        invalidation trigger (wired from ``ApexRuntime.aclose()``). Returns
        the count actually revoked."""
        count = 0
        for ref_id, ref in list(self._references.items()):
            if not ref.revoked:
                self._references[ref_id] = replace(ref, revoked=True, revocation_reason=reason)
                count += 1
        return count


class RuntimeReferenceResolver:
    """Validates a ``reference_id`` against a :class:`RuntimeReferenceStore`
    and, only when every check passes, resolves the live adapter from a
    :class:`~apex_host.runtime_registry.CapabilityRuntimeRegistry` by
    ``capability_id``.

    Never falls back to a "global"/default adapter for a mismatched
    target — a ``target_mismatch`` is always a hard rejection, even if the
    resolver happens to have some other adapter available. Never
    reconstructs an adapter from ``RuntimeReference``'s own persisted
    fields alone — the adapter object always comes from the live,
    in-process registry lookup at the very end of :meth:`resolve`.
    """

    def __init__(self, store: RuntimeReferenceStore, registry: "CapabilityRuntimeRegistry") -> None:
        self._store = store
        self._registry = registry

    def resolve(
        self,
        reference_id: str,
        *,
        target: str,
        capability_type: "AccessCapabilityType",
        now_iso: str = "",
        expected_generation: int | None = None,
    ) -> tuple["FlagReadCapability | None", RuntimeReferenceError | None]:
        """Return ``(adapter, None)`` on success or ``(None, error)`` on
        any validation failure. Order of checks (first failure wins):
        existence -> revocation -> expiry -> target -> capability_type ->
        generation (only when *expected_generation* is supplied) ->
        registry lookup."""
        if not reference_id:
            return None, RuntimeReferenceError.not_found
        ref = self._store.get(reference_id)
        if ref is None:
            return None, RuntimeReferenceError.not_found
        if ref.revoked:
            return None, RuntimeReferenceError.revoked
        if now_iso and ref.is_expired(now_iso):
            return None, RuntimeReferenceError.expired
        if ref.target != target:
            return None, RuntimeReferenceError.target_mismatch
        if ref.capability_type is not capability_type:
            return None, RuntimeReferenceError.type_mismatch
        if expected_generation is not None and ref.generation != expected_generation:
            return None, RuntimeReferenceError.generation_mismatch
        adapter = self._registry.get(ref.capability_id)
        if adapter is None:
            return None, RuntimeReferenceError.capability_unregistered
        return adapter, None
