# capability_seed.py
# One-time, startup-only derivation of an operator-attested direct-file-read AccessCapability from ApexConfig — never a live network operation.
"""Startup-only direct-file-read capability seeding (Phase 20).

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
constructs and applies a fixed set of EKG deltas from already-known,
already-supplied configuration. The ONE real network operation in the
entire direct-file-read flow is the bounded, policy-gated
``user_flag_verify`` task itself, dispatched later through the normal
``TaskDispatcher.dispatch()`` pipeline exactly like every other live
operation in this codebase.

Idempotent: a second call (e.g. a future checkpoint-resume path) is a
no-op once the capability node already exists for this target/type/
principal (content-addressed ID — see ``apex_host/graph_ids.py
::access_capability_id``).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from memfabric.ids import now
from memfabric.types import Node

from apex_host.graph_ids import access_capability_id, host_id
from apex_host.parsers.capability_parser import CapabilityParser
from apex_host.types import AccessCapabilityType

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI

    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)


async def seed_direct_file_read_capability(api: "MemoryAPI", config: "ApexConfig") -> bool:
    """Derive an operator-attested direct-file-read ``access_capability``
    node from *config*, if fully configured and not already present.

    Returns ``True`` when a capability was newly derived this call,
    ``False`` otherwise (not configured, already present, or the origin
    failed the authorized-target check).
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

    parsed = CapabilityParser().derive_direct_file_read_capability(
        target=target,
        capability_type=capability_type,
        principal=config.direct_file_read_principal,
        source_task_id="",
        validation_method="operator_attestation",
        confidence=config.direct_file_read_confidence,
        requires_auth=bool(config.direct_file_read_headers),
        max_response_bytes=config.direct_file_read_max_response_bytes,
        request_shape_id=cap_id,
    )
    if not parsed.node_deltas:
        logger.warning("seed_direct_file_read_capability: derivation rejected the supplied evidence")
        return False

    await api.apply_deltas(nodes=parsed.node_deltas, edges=parsed.edge_deltas)
    logger.info(
        "seed_direct_file_read_capability: derived %s capability_id=%s principal=%s",
        capability_type.value, cap_id, config.direct_file_read_principal,
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
