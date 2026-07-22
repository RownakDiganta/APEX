# capability_seed.py
# One-time, startup-only derivation of an operator-attested direct-file-read or bounded-command AccessCapability from ApexConfig — never a live network operation or command execution.
"""Startup-only direct-file-read capability seeding (Phase 20; extended in
Phase 21 with bounded command-execution capability seeding; Phase 23:
routed through the same ``CapabilityDiscoveryEngine`` every automatically
-derived capability now goes through, rather than calling
``CapabilityParser`` directly).

Mirrors ``--username``/``--password``'s own trust boundary: the operator
has ALREADY manually confirmed (through authorized testing — an arbitrary
file read, an LFI, a path-traversal primitive, an authenticated
file-download endpoint, an XSS-assisted workflow that resolves to a bounded
file read, ...) that a specific, fixed HTTP request shape reads files. This
function turns that operator ATTESTATION into an ``access_capability`` EKG
node — the SAME ``CapabilityParser.derive_direct_file_read_capability()``
any other caller (a future planner, a future web-exploitation validation
step) would use, with ``validation_method="operator_attestation"``.

Called exactly ONCE, at engagement startup (``apex_host.runtime.ApexRuntime
.run()``), before the graph starts running — so a ``host`` node already
exists by the time ``GlobalPlanner`` first evaluates the phase ladder (a
DFR-only engagement, with no SSH access ever attempted, must still be able
to reach the ``objective`` phase — see ``apex_host/planners/global_planner
.py``'s updated ``_select_phase`` gate).

This function performs **NO live network operation of any kind** — it only
constructs a ``CapabilityEvidence(evidence_type=OPERATOR_ATTESTED, ...)``
object and runs it through ``run_capability_discovery()``, which itself
performs no network I/O either (materialization is a graph write via
``CapabilityParser``; runtime registration merely constructs Python
objects from config — see ``apex_host.capabilities.discovery``/
``apex_host.capabilities.runtime_resolution``). The ONE real network
operation in the entire direct-file-read flow is the bounded, policy-gated
``user_flag_verify`` task itself, dispatched later through the normal
``TaskDispatcher.dispatch()`` pipeline exactly like every other live
operation in this codebase.

Idempotent: a second call (e.g. a future checkpoint-resume path) is a
no-op once the capability node already exists for this target/type/
principal (content-addressed ID — see ``apex_host/graph_ids.py
::access_capability_id``).

Two independent capability-creation paths temporarily existed side by
side after the access-capability refactor introduced this seeding module
(Phase 20/21) and before Phase 23 unified them: seeding called
``CapabilityParser.derive_*`` directly, while a validated SSH login (in
``apex_host.orchestration.parsing_node``) already went through a similar
direct-call pattern. Phase 23 collapses BOTH onto the single
``CapabilityEvidence -> CapabilityDiscoveryEngine -> CapabilityParser``
pipeline — this module no longer imports ``CapabilityParser`` at all.
``tests/apex_host/test_phase23_capability_discovery.py`` proves the
resulting EKG node metadata is identical (modulo the new, additive
``evidence_provenance``/``runtime_generation`` bookkeeping keys) to what
the pre-Phase-23 direct-call path produced.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from memfabric.ids import new_id, now
from memfabric.types import Node

from apex_host.capabilities.discovery import CapabilityDiscoveryContext, run_capability_discovery
from apex_host.capabilities.evidence import CapabilityEvidence, CapabilityEvidenceType
from apex_host.graph_ids import access_capability_id, host_id
from apex_host.runtime_registry import CapabilityRuntimeRegistry
from apex_host.types import AccessCapabilityType

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI

    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)


async def seed_direct_file_read_capability(api: "MemoryAPI", config: "ApexConfig") -> bool:
    """Derive an operator-attested direct-file-read (or ``web_command``,
    Phase 21 — see below) ``access_capability`` node from *config*, if
    fully configured and not already present.

    Returns ``True`` when a capability was newly derived this call,
    ``False`` otherwise (not configured, already present, or the origin
    failed the authorized-target check).

    Phase 21 — ``config.direct_file_read_capability_type`` may also be
    ``"web_command"``: the underlying fixed HTTP request shape is
    identical to a direct-file-read primitive (and is registered by the
    SAME ``_register_direct_file_read_adapter`` at runtime — see
    ``apex_host/orchestration/dispatch_node.py``), but ``web_command``
    represents "a command executes and its response happens to contain the
    read output," a different evidentiary claim than "this endpoint serves
    a file directly." Its derivation is therefore routed to
    ``CapabilityParser.derive_command_capability`` (command-evidence
    vocabulary) rather than ``derive_direct_file_read_capability``
    (file-read-evidence vocabulary), while still validating and reusing the
    exact same ``direct_file_read_origin``/``endpoint_template``/etc.
    configuration.
    """
    if not config.direct_file_read_operator_attested:
        return False
    if not config.direct_file_read_origin or not config.direct_file_read_endpoint_template:
        logger.debug(
            "seed_direct_file_read_capability: operator_attested=True but "
            "origin/endpoint_template not fully configured; skipping"
        )
        return False
    if not config.direct_file_read_principal:
        logger.debug("seed_direct_file_read_capability: no direct_file_read_principal configured; skipping")
        return False

    try:
        capability_type = AccessCapabilityType(config.direct_file_read_capability_type)
    except ValueError:
        logger.warning(
            "seed_direct_file_read_capability: unrecognised capability_type %r; skipping",
            config.direct_file_read_capability_type,
        )
        return False

    if not _origin_belongs_to_target(config.direct_file_read_origin, config.target):
        logger.warning(
            "seed_direct_file_read_capability: configured origin %r does not "
            "match the authorized target %r; refusing to derive a capability",
            config.direct_file_read_origin, config.target,
        )
        return False

    target = config.target
    cap_id = access_capability_id(target, capability_type.value, config.direct_file_read_principal)
    h_id = host_id(target)

    existing_subgraph = await api.get_subgraph(h_id, depth=1)
    if any(n.id == cap_id for n in existing_subgraph.nodes):
        logger.debug("seed_direct_file_read_capability: capability %s already present; skipping", cap_id)
        return False

    if not any(n.id == h_id for n in existing_subgraph.nodes):
        timestamp = now()
        await api.upsert_node(Node(
            id=h_id, type="host", props={"ip": target}, confidence=0.5,
            source="capability_seed", first_seen=timestamp, last_seen=timestamp,
        ))

    if capability_type is AccessCapabilityType.web_command:
        sanitized_attributes = {
            "max_output_bytes": config.direct_file_read_max_response_bytes,
            "strategy_id": cap_id,
        }
    else:
        sanitized_attributes = {
            "requires_auth": bool(config.direct_file_read_headers),
            "max_response_bytes": config.direct_file_read_max_response_bytes,
            "request_shape_id": cap_id,
        }
    evidence = CapabilityEvidence(
        evidence_id=new_id(),
        evidence_type=CapabilityEvidenceType.OPERATOR_ATTESTED,
        capability_family=capability_type,
        target_host_id=h_id,
        source_task_id="",
        principal=config.direct_file_read_principal,
        validation_method="operator_attestation",
        confidence=config.direct_file_read_confidence,
        timestamp=now(),
        sanitized_attributes=sanitized_attributes,
    )
    discovery_result = await run_capability_discovery(
        [evidence],
        context=CapabilityDiscoveryContext(
            api=api, config=config, capability_registry=CapabilityRuntimeRegistry(),
            subgraph=existing_subgraph, target=target, now_iso=now(),
            attempt_runtime_registration=False,
        ),
    )
    if discovery_result.capabilities_derived < 1:
        logger.warning("seed_direct_file_read_capability: derivation rejected the supplied evidence")
        return False

    logger.info(
        "seed_direct_file_read_capability: derived %s capability_id=%s principal=%s",
        capability_type.value, cap_id, config.direct_file_read_principal,
    )
    return True


async def seed_bounded_command_capability(api: "MemoryAPI", config: "ApexConfig") -> bool:
    """Derive an operator-attested ``local_shell``/``remote_command``
    ``access_capability`` node from *config*, if fully configured and not
    already present (Phase 21).

    Mirrors ``seed_direct_file_read_capability`` exactly in shape and
    safety properties: performs NO live command execution — it only
    constructs and applies a fixed set of EKG deltas from already-known,
    already-supplied configuration. The ONE real command execution in the
    entire bounded-command flow is the bounded, policy-gated
    ``user_flag_verify`` task itself, dispatched later through the normal
    ``TaskDispatcher.dispatch()`` pipeline. Idempotent (content-addressed
    capability ID).

    Returns ``True`` when a capability was newly derived this call,
    ``False`` otherwise (not configured, already present, or an
    unrecognised capability type).
    """
    if not config.bounded_command_operator_attested:
        return False
    if not config.bounded_command_principal:
        logger.debug("seed_bounded_command_capability: no bounded_command_principal configured; skipping")
        return False

    try:
        capability_type = AccessCapabilityType(config.bounded_command_capability_type)
    except ValueError:
        logger.warning(
            "seed_bounded_command_capability: unrecognised capability_type %r; skipping",
            config.bounded_command_capability_type,
        )
        return False
    if capability_type not in (AccessCapabilityType.local_shell, AccessCapabilityType.remote_command):
        logger.warning(
            "seed_bounded_command_capability: capability_type %r is not local_shell/"
            "remote_command (use direct_file_read_capability_type='web_command' instead); skipping",
            config.bounded_command_capability_type,
        )
        return False

    target = config.target
    cap_id = access_capability_id(target, capability_type.value, config.bounded_command_principal)
    h_id = host_id(target)

    existing_subgraph = await api.get_subgraph(h_id, depth=1)
    if any(n.id == cap_id for n in existing_subgraph.nodes):
        logger.debug("seed_bounded_command_capability: capability %s already present; skipping", cap_id)
        return False

    if not any(n.id == h_id for n in existing_subgraph.nodes):
        timestamp = now()
        await api.upsert_node(Node(
            id=h_id, type="host", props={"ip": target}, confidence=0.5,
            source="capability_seed", first_seen=timestamp, last_seen=timestamp,
        ))

    evidence = CapabilityEvidence(
        evidence_id=new_id(),
        evidence_type=CapabilityEvidenceType.OPERATOR_ATTESTED,
        capability_family=capability_type,
        target_host_id=h_id,
        source_task_id="",
        principal=config.bounded_command_principal,
        validation_method="operator_attestation",
        confidence=config.bounded_command_confidence,
        timestamp=now(),
        sanitized_attributes={
            "max_output_bytes": config.bounded_command_max_output_bytes,
            "strategy_id": cap_id,
        },
    )
    discovery_result = await run_capability_discovery(
        [evidence],
        context=CapabilityDiscoveryContext(
            api=api, config=config, capability_registry=CapabilityRuntimeRegistry(),
            subgraph=existing_subgraph, target=target, now_iso=now(),
            attempt_runtime_registration=False,
        ),
    )
    if discovery_result.capabilities_derived < 1:
        logger.warning("seed_bounded_command_capability: derivation rejected the supplied evidence")
        return False

    logger.info(
        "seed_bounded_command_capability: derived %s capability_id=%s principal=%s",
        capability_type.value, cap_id, config.bounded_command_principal,
    )
    return True


def _origin_belongs_to_target(origin: str, target: str) -> bool:
    """Best-effort check that *origin*'s host matches the authorized
    *target* — defense in depth on top of the adapter's own per-request
    origin enforcement (``DirectFileReadCapabilityAdapter``). Accepts an
    exact hostname match or the target appearing as the origin's hostname
    (covers ``http://<target>:<port>`` and ``http://<target>``)."""
    parts = urlsplit(origin)
    hostname = (parts.hostname or "").lower()
    return hostname == target.strip().lower()
