# access_capabilities.py
# Pure, no-IO helpers for reconstructing and ranking AccessCapability records from EKG subgraph data — the sole place ObjectivePlanner looks for validated access, transport-independently.
"""Access-capability reasoning helpers (capability refactor; ranking
extended in Phase 20 with runtime-adapter-availability and directness).

Everything here is pure — no I/O, no MemoryAPI calls, no tool execution —
consistent with the blackboard model (memfabric Invariant 7): planners only
ever read the ``SubgraphView`` they are handed and return ``TaskSpec``s.
Mirrors ``apex_host/planners/priv_esc_opportunities.py``'s/``objective.py``'s
separation: pure derivation/ranking helpers live here; graph-delta
construction lives in ``apex_host/parsers/capability_parser.py``; the
runtime (non-EKG) adapter registry lives in
``apex_host/runtime_registry.py``.

This module is the ONE place ``ObjectivePlanner`` (and any future
capability-consuming planner) looks for validated access — it never
searches for ``access_state`` nodes, a specific ``service`` prop value, or
any other transport-specific signal directly. Adding a new
``AccessCapabilityType`` adapter later never requires touching this file's
public functions' call sites, only ``capability_parser.py`` (to derive the
new capability type from its own validation signal) and
``apex_host/runtime_registry.py`` (to add the adapter).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from apex_host.types import AccessCapability, AccessCapabilityType

if TYPE_CHECKING:
    from memfabric.types import Node, SubgraphView

#: Human-readable label per capability type — used by the report generator
#: ("Capability used: SSH Command" / "Capability used: Direct File Read")
#: so a future adapter needs only to add one entry here, never touch
#: report.py's rendering logic. Note: "Direct File Read" is the shared
#: display label the report deliberately uses for BOTH arbitrary_file_read
#: and api_file_read specific labels below — see `capability_type_label`.
#: "Local Command" (Phase 21) is a deliberate rename of the enum member's
#: own name (`local_shell`) to the more capability-oriented, human-facing
#: label the report should show — the SAME rename pattern already applied
#: to `arbitrary_file_read` -> "Direct File Read" in Phase 20.
CAPABILITY_TYPE_LABELS: dict[str, str] = {
    AccessCapabilityType.ssh_command.value: "SSH Command",
    AccessCapabilityType.telnet_command.value: "Telnet Command",
    AccessCapabilityType.web_command.value: "Web Command",
    AccessCapabilityType.local_shell.value: "Local Command",
    AccessCapabilityType.arbitrary_file_read.value: "Direct File Read",
    AccessCapabilityType.api_file_read.value: "API File Read",
    AccessCapabilityType.remote_command.value: "Remote Command",
}

#: Directness tie-break table (Phase 20; extended Phase 21) — used ONLY to
#: break ties between capabilities of otherwise-equal
#: validated/available/confidence standing, never to override confidence
#: itself. Lower rank sorts first. Roughly: a direct, bounded file read is
#: the most surgical/least-invasive access mechanism; a local/SSH/generic
#: remote command channel is a step more general; a protocol mediated
#: through telnet or a fixed web request shape is the least direct. An
#: unrecognised or future capability type sorts last (forward-compatible,
#: never crashes).
_DIRECTNESS_RANK: dict[str, int] = {
    AccessCapabilityType.arbitrary_file_read.value: 0,
    AccessCapabilityType.api_file_read.value: 0,
    AccessCapabilityType.local_shell.value: 1,
    AccessCapabilityType.ssh_command.value: 1,
    AccessCapabilityType.remote_command.value: 1,
    AccessCapabilityType.telnet_command.value: 2,
    AccessCapabilityType.web_command.value: 2,
}


def capability_type_label(capability_type: str) -> str:
    """Human-readable display label for *capability_type*, falling back to
    the raw value for a forward-compatible/unknown type."""
    return CAPABILITY_TYPE_LABELS.get(capability_type, capability_type)


def _node_to_capability(node: "Node") -> AccessCapability | None:
    props = node.props
    try:
        capability_type = AccessCapabilityType(str(props.get("capability_type", "")))
    except ValueError:
        return None
    try:
        confidence = float(props.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return AccessCapability(
        capability_id=node.id,
        host_id=str(props.get("host_id", "")),
        capability_type=capability_type,
        validated=bool(props.get("validated", False)),
        principal=str(props.get("principal", "")),
        confidence=confidence,
        source_task_id=str(props.get("source_task_id", "")),
        metadata=dict(props.get("metadata") or {}),
        # Phase 20 — missing prop defaults to True (backward compatible with
        # capability nodes predating this field and with direct unit-test
        # construction); the orchestration layer explicitly writes this
        # field once it knows for certain whether an adapter is registered.
        runtime_available=bool(props.get("runtime_available", True)),
    )


def access_capabilities_from_subgraph(subgraph: "SubgraphView") -> list[AccessCapability]:
    """Reconstruct every recorded ``AccessCapability`` from the subgraph.

    A node whose ``capability_type`` no longer parses as a known
    ``AccessCapabilityType`` member is skipped (forward-compatibility —
    mirrors every other ``*_from_subgraph`` reconstructor in this
    codebase, e.g. ``opportunities_from_subgraph``).
    """
    out: list[AccessCapability] = []
    for node in subgraph.nodes:
        if node.type != "access_capability":
            continue
        capability = _node_to_capability(node)
        if capability is not None:
            out.append(capability)
    return out


def rank_capabilities(capabilities: list[AccessCapability]) -> list[AccessCapability]:
    """Deterministic ranking: validated first, then runtime-adapter
    availability, then confidence descending, then a fixed directness
    tie-break, then ``capability_id`` ascending as the final stable
    tie-break.

    Confidence remains the primary per-instance ranking signal — directness
    is deliberately a LOW-priority tie-break only (never overrides
    confidence), since "prefer a direct file read over a remote shell" is a
    soft, general preference, not a hard rule that should override a
    genuinely more-confident alternative. Never random, never
    insertion-order-dependent — matches
    ``priv_esc_opportunities.rank_opportunities``'s convention exactly.
    """
    return sorted(
        capabilities,
        key=lambda c: (
            0 if c.validated else 1,
            0 if c.runtime_available else 1,
            -c.confidence,
            _DIRECTNESS_RANK.get(c.capability_type.value, 99),
            c.capability_id,
        ),
    )


def best_capability_for_objective(
    subgraph: "SubgraphView",
    *,
    exclude_capability_ids: frozenset[str] = frozenset(),
) -> AccessCapability | None:
    """The single best VALIDATED, runtime-AVAILABLE capability to use next
    for a bounded objective read, or ``None`` if none exists.

    A capability that is validated but has no registered runtime adapter
    (``runtime_available=False`` — e.g. a direct-file-read primitive the
    operator has not supplied runtime material for) is never selected for
    immediate execution; its metadata remains recorded and visible (see
    ``AccessCapability.runtime_available``'s docstring), it is simply
    skipped here exactly like an unvalidated capability.

    ``exclude_capability_ids`` lets a caller skip a capability that has
    already exhausted every bounded candidate path available to it (see
    ``ObjectivePlanner`` — capability-level exhaustion bookkeeping), so a
    second, still-untried validated+available capability can be preferred
    over one that has nothing left to attempt.
    """
    ranked = rank_capabilities(access_capabilities_from_subgraph(subgraph))
    for capability in ranked:
        if not capability.validated:
            continue
        if not capability.runtime_available:
            continue
        if capability.capability_id in exclude_capability_ids:
            continue
        return capability
    return None
