# runtime_resolution.py
# The one implementation of "construct + register a runtime adapter for a validated AccessCapability" — shared by the pre-existing per-turn objective-turn registration loop and the new discovery engine.
"""Runtime-reference resolution (Phase 23; relocated from
``apex_host.orchestration.dispatch_node``, behavior unchanged).

Before this phase, ``apex_host/orchestration/dispatch_node.py`` contained
the only implementation of "given a validated ``AccessCapability``,
construct and register a real runtime adapter in
``CapabilityRuntimeRegistry``" — used exclusively by
``make_objective_node``'s per-turn registration loop. This phase's
discovery engine needs the IDENTICAL logic (the spec's own "Runtime
registration occurs only when... adapter satisfies FlagReadCapability..."
requirement is this exact function), so rather than duplicating it, these
functions were moved here and ``dispatch_node.py`` now imports them from
this module — one implementation, two callers, matching this codebase's
own "single authoritative writer" discipline (mirrors ``CapabilityParser``
being the sole capability-metadata writer).

Orchestration-layer-only concern, never a planner or provider concern
(memfabric Invariant 7 — planners/providers stay pure over subgraph/
evidence data only). Every function here takes plain, explicit parameters
(``config``, ``capability_registry``, ``target``, ``subgraph``, ``cap``)
rather than the whole ``OrchestrationDeps`` object, specifically so this
module has no dependency on ``apex_host.orchestration`` — the dependency
direction is orchestration -> capabilities, never the reverse.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.types import AccessCapabilityType

if TYPE_CHECKING:
    from memfabric.types import SubgraphView

    from apex_host.config import ApexConfig
    from apex_host.runtime_registry import CapabilityRuntimeRegistry
    from apex_host.types import AccessCapability


def ssh_port_for_capability(subgraph: "SubgraphView") -> str:
    """Lowest-port ``access_validate_ssh`` capability's port, or the SSH
    default. (Relocated verbatim from ``dispatch_node._ssh_port_for_capability``.)"""
    caps = [c for c in capabilities_from_subgraph(subgraph) if c.name == "access_validate_ssh"]
    if not caps:
        return "22"
    return sorted(caps, key=lambda c: int(c.port) if c.port.isdigit() else 22)[0].port or "22"


def register_capability_adapter(
    *,
    config: "ApexConfig",
    capability_registry: "CapabilityRuntimeRegistry",
    subgraph: "SubgraphView",
    target: str,
    cap: "AccessCapability",
) -> bool:
    """Register a runtime adapter for one validated ``AccessCapability`` so
    ``UserFlagExecutor`` can resolve ``capability_id -> adapter`` this turn.
    Returns ``True`` iff an adapter was successfully constructed and
    registered.

    (Relocated verbatim from
    ``dispatch_node._register_capability_adapter`` — same dispatch table,
    same per-type registration functions below.)
    """
    if cap.capability_type is AccessCapabilityType.ssh_command:
        return _register_ssh_adapter(config, capability_registry, subgraph, target, cap)
    if cap.capability_type in (
        AccessCapabilityType.arbitrary_file_read,
        AccessCapabilityType.api_file_read,
        AccessCapabilityType.web_command,
    ):
        return _register_direct_file_read_adapter(config, capability_registry, target, cap)
    if cap.capability_type in (AccessCapabilityType.local_shell, AccessCapabilityType.remote_command):
        return _register_bounded_command_adapter(config, capability_registry, target, cap)
    return False


def _register_ssh_adapter(
    config: "ApexConfig",
    capability_registry: "CapabilityRuntimeRegistry",
    subgraph: "SubgraphView",
    target: str,
    cap: "AccessCapability",
) -> bool:
    usernames = list(getattr(config, "username_candidates", None) or [])
    passwords = list(getattr(config, "password_candidates", None) or [])
    if not usernames or not passwords or cap.principal != usernames[0]:
        return False
    capability_registry.ensure_ssh(
        cap.capability_id,
        target=target,
        port=ssh_port_for_capability(subgraph),
        username=cap.principal,
        password=passwords[0],
        config=config,
    )
    return True


def _register_direct_file_read_adapter(
    config: "ApexConfig",
    capability_registry: "CapabilityRuntimeRegistry",
    target: str,
    cap: "AccessCapability",
) -> bool:
    from apex_host.runtime_registry import DirectFileReadPrimitive

    if not config.direct_file_read_origin or not config.direct_file_read_endpoint_template:
        return False
    if cap.principal != config.direct_file_read_principal:
        return False
    allowed_filenames = frozenset(getattr(config, "user_flag_candidate_filenames", None) or [])
    try:
        primitive = DirectFileReadPrimitive(
            capability_id=cap.capability_id,
            target_origin=config.direct_file_read_origin,
            endpoint_template=config.direct_file_read_endpoint_template,
            method=config.direct_file_read_method,
            headers=dict(config.direct_file_read_headers),
            timeout_seconds=config.direct_file_read_timeout_seconds,
            max_response_bytes=config.direct_file_read_max_response_bytes,
            allow_redirects=config.direct_file_read_allow_redirects,
            allowed_filenames=allowed_filenames,
        )
    except ValueError:
        return False
    capability_registry.ensure_direct_file_read(cap.capability_id, primitive=primitive)
    return True


def _register_bounded_command_adapter(
    config: "ApexConfig",
    capability_registry: "CapabilityRuntimeRegistry",
    target: str,
    cap: "AccessCapability",
) -> bool:
    from apex_host.runtime_registry import BoundedCommandReadPrimitive, ToolBackendCommandReadStrategy
    from apex_host.tools.backend import select_runtime_backend

    if not config.bounded_command_operator_attested:
        return False
    if cap.principal != config.bounded_command_principal:
        return False
    allowed_filenames = frozenset(getattr(config, "user_flag_candidate_filenames", None) or [])
    try:
        backend = select_runtime_backend(config)
        strategy = ToolBackendCommandReadStrategy(backend=backend, target=target)
        primitive = BoundedCommandReadPrimitive(
            capability_id=cap.capability_id,
            strategy=strategy,
            allowed_filenames=allowed_filenames,
            timeout_seconds=config.bounded_command_timeout_seconds,
            max_output_bytes=config.bounded_command_max_output_bytes,
        )
    except ValueError:
        return False
    capability_registry.ensure_bounded_command(cap.capability_id, primitive=primitive)
    return True
