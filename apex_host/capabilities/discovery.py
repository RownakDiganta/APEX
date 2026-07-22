# discovery.py
# CapabilityDiscoveryEngine — validate, dispatch to providers, materialize accepted decisions through CapabilityParser, register runtime adapters, and report structured, sanitized results.
"""The capability-discovery engine (Phase 23).

``run_capability_discovery()`` is the orchestration-facing entry point
(called once per turn from ``apex_host.orchestration.parsing_node`` after
that turn's normal parsing/apply_deltas loop, and from
``apex_host.orchestration.capability_seed`` for operator-attested
evidence). It never executes an exploit, makes a network request, invokes
a tool, or calls an LLM — the engine's own source is scanned by a static
architecture test for exactly these things being absent.

Pipeline (per the required flow):

    evidence -> validate -> select provider(s) -> evaluate (pure)
             -> collect decisions -> resolve duplicates
             -> CapabilityParser.derive_* (materialize accepted decisions)
             -> MemoryAPI.apply_deltas (the only graph write in this module)
             -> runtime_resolution.register_capability_adapter
             -> structured, sanitized CapabilityDiscoveryResult

``CapabilityParser`` remains the sole authoritative metadata writer (this
module never constructs a raw ``Node``/``Edge`` for an ``access_capability``
itself — it always goes through ``CapabilityParser.derive_*``).
``CapabilityRuntimeRegistry`` remains the sole runtime source of truth —
``AccessCapability.runtime_available`` is written back only as an advisory
mirror of what the registry actually holds, exactly like the pre-existing
``dispatch_node.make_objective_node`` per-turn loop already did (this
module now shares that same underlying
``apex_host.capabilities.runtime_resolution.register_capability_adapter``
call).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Sequence

from memfabric.ids import now
from memfabric.types import ConflictStatus, Node

from apex_host.capabilities.decisions import CapabilityDerivationDecision, CapabilityDerivationStatus
from apex_host.capabilities.evidence import CapabilityEvidence, CapabilityEvidenceType, validate_evidence
from apex_host.capabilities.providers import DEFAULT_PROVIDERS, CapabilityProvider
from apex_host.capabilities.runtime_resolution import register_capability_adapter
from apex_host.graph_ids import host_id
from apex_host.parsers.capability_parser import CapabilityParser
from apex_host.types import AccessCapability, AccessCapabilityType

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI
    from memfabric.types import SubgraphView

    from apex_host.config import ApexConfig
    from apex_host.runtime_registry import CapabilityRuntimeRegistry

logger = logging.getLogger(__name__)

#: Hard ceiling on how many evidence entries a single provenance list keeps
#: — bounds EKG node prop size regardless of how long an engagement runs.
_MAX_PROVENANCE_ENTRIES = 20

#: Default per-cycle evidence ceiling — mirrors this codebase's own
#: established "bounded batch" convention (e.g.
#: ``ReconPlanner._MAX_BANNER_TASKS``, ``PrivEscPlanner``'s per-turn task
#: cap). Configurable via ``ApexConfig.capability_discovery_max_evidence_per_cycle``.
_DEFAULT_MAX_EVIDENCE_PER_CYCLE = 50


@dataclass(slots=True)
class CapabilityDiscoveryContext:
    """Read-only-by-convention context passed to every provider and used by
    the engine to materialize/register accepted decisions.

    Providers may read ``subgraph``/``target`` (the same read-only pattern
    every planner in this codebase already uses) but must never call
    ``api``/``capability_registry`` methods themselves — enforced by a
    static architecture-scan test, not by a type-level restriction (see
    ``apex_host.capabilities.providers`` module docstring).
    """

    api: "MemoryAPI"
    config: "ApexConfig"
    capability_registry: "CapabilityRuntimeRegistry"
    subgraph: "SubgraphView"
    target: str
    now_iso: str = ""
    evidence_ttl_seconds: float = 0.0
    max_evidence_per_cycle: int = _DEFAULT_MAX_EVIDENCE_PER_CYCLE
    providers: tuple[CapabilityProvider, ...] = field(default_factory=lambda: DEFAULT_PROVIDERS)
    #: When ``False``, materialize accepted decisions (write the
    #: ``access_capability`` node) but skip the runtime-registration
    #: attempt entirely, leaving ``runtime_available=False`` exactly as
    #: ``CapabilityParser.derive_*`` already defaults it. Used ONLY by
    #: ``apex_host.orchestration.capability_seed`` — startup-time seeding
    #: runs before the engagement's real ``CapabilityRuntimeRegistry``
    #: exists (it is constructed later, inside ``build_apex_graph``), so
    #: attempting registration against a throwaway registry instance would
    #: write a misleading ``runtime_available=True`` that the real registry
    #: does not back. The pre-existing per-turn
    #: ``apex_host.orchestration.dispatch_node.make_objective_node`` loop
    #: performs the real registration on the first objective turn
    #: regardless, exactly as it already did before Phase 23.
    attempt_runtime_registration: bool = True


@dataclass(slots=True)
class CapabilityDiscoveryResult:
    """Structured, sanitized result of one ``discover()`` call — safe to
    log, report, or export as-is (no secret, no raw output, no runtime
    object)."""

    decisions: list[CapabilityDerivationDecision] = field(default_factory=list)
    rejections: list[dict[str, str]] = field(default_factory=list)
    capabilities_derived: int = 0
    capabilities_updated: int = 0
    adapters_registered: int = 0
    duplicate_count: int = 0
    runtime_unavailable_count: int = 0
    provider_failures: int = 0

    @property
    def evidence_evaluated(self) -> int:
        return len(self.decisions) + len(self.rejections)

    @property
    def evidence_accepted(self) -> int:
        return sum(1 for d in self.decisions if d.accepted)

    @property
    def evidence_rejected(self) -> int:
        return len(self.rejections) + sum(
            1 for d in self.decisions if d.status is CapabilityDerivationStatus.rejected
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_evaluated": self.evidence_evaluated,
            "evidence_accepted": self.evidence_accepted,
            "evidence_rejected": self.evidence_rejected,
            "duplicate_evidence": self.duplicate_count,
            "capabilities_derived": self.capabilities_derived,
            "capabilities_updated": self.capabilities_updated,
            "runtime_adapters_registered": self.adapters_registered,
            "validated_but_unavailable": self.runtime_unavailable_count,
            "provider_failures": self.provider_failures,
        }


def _select_provider(
    evidence: CapabilityEvidence, providers: Sequence[CapabilityProvider],
) -> CapabilityProvider | None:
    """``OPERATOR_ATTESTED`` evidence carries no evidence-type-implied
    family (unlike e.g. ``SSH_AUTHENTICATED_COMMAND``, which only ever
    means ``ssh_command``) — it is routed by ``capability_family`` alone,
    via each provider's ``accepted_capability_families``. Every other
    evidence type is routed by its own specific, 1:1-mapped
    ``supported_evidence_types`` set."""
    if evidence.evidence_type is CapabilityEvidenceType.OPERATOR_ATTESTED:
        for provider in providers:
            if evidence.capability_family in provider.accepted_capability_families:
                return provider
        return None
    for provider in providers:
        if evidence.evidence_type in provider.supported_evidence_types:
            return provider
    return None


def _existing_node(subgraph: "SubgraphView", capability_id: str) -> Node | None:
    for node in subgraph.nodes:
        if node.id == capability_id and node.type == "access_capability":
            return node
    return None


class CapabilityDiscoveryEngine:
    """Coordinates validation, provider dispatch, materialization, and
    runtime registration. Stateless — safe to construct fresh per call, or
    reuse across an engagement (holds no engagement-specific state)."""

    def __init__(self, providers: Sequence[CapabilityProvider] = DEFAULT_PROVIDERS) -> None:
        self._providers = tuple(providers)
        self._parser = CapabilityParser()

    async def discover(
        self, evidence: Sequence[CapabilityEvidence], *, context: CapabilityDiscoveryContext,
    ) -> CapabilityDiscoveryResult:
        result = CapabilityDiscoveryResult()
        bounded = list(evidence)[: context.max_evidence_per_cycle]

        node_batch: list[Node] = []
        edge_batch: list[Any] = []
        # (capability_id, cap, was_new, decision) — counters/decisions for
        # these are only finalized into `result` AFTER the batch write
        # below actually succeeds (see the loop at the bottom of this
        # method) — never incremented speculatively before the write is
        # known to have landed, so a rolled-back batch is correctly
        # reported as zero derived/updated capabilities, not a phantom
        # success.
        pending: list[tuple[str, AccessCapability, bool, CapabilityDerivationDecision]] = []

        for item in bounded:
            rejection = validate_evidence(
                item, evidence_ttl_seconds=context.evidence_ttl_seconds, now_iso=context.now_iso,
            )
            if rejection is not None:
                result.rejections.append({"evidence_id": item.evidence_id, "reason": rejection.reason})
                continue

            provider = _select_provider(item, self._providers)
            if provider is None:
                result.rejections.append({"evidence_id": item.evidence_id, "reason": "unsupported_evidence"})
                continue

            try:
                decision = provider.evaluate(item, context)
            except Exception as exc:  # noqa: BLE001 - provider failures must never crash discovery
                logger.warning("capability provider %s raised: %s", type(provider).__name__, type(exc).__name__)
                result.provider_failures += 1
                result.rejections.append({"evidence_id": item.evidence_id, "reason": "provider_error"})
                continue

            if decision.status is CapabilityDerivationStatus.duplicate:
                # Checked BEFORE the generic `not decision.accepted` branch
                # below — `duplicate` is deliberately excluded from
                # `CapabilityDerivationDecision.accepted` (it is not a
                # rejection either), so it needs its own counter, not the
                # generic "rejected" bucket.
                result.decisions.append(decision)
                result.duplicate_count += 1
                continue

            if not decision.accepted:
                result.decisions.append(decision)
                continue

            existing = _existing_node(context.subgraph, decision.capability_id)
            existing_generation = int((existing.props.get("metadata") or {}).get("runtime_generation", 0)) if existing else 0
            if item.runtime_generation and item.runtime_generation < existing_generation:
                result.rejections.append({"evidence_id": item.evidence_id, "reason": "expired_evidence"})
                continue

            try:
                nodes, edges = self._materialize(item, decision, existing=existing)
            except Exception as exc:  # noqa: BLE001 - parser failures must never crash discovery
                logger.warning("capability materialization failed: %s", type(exc).__name__)
                result.rejections.append({"evidence_id": item.evidence_id, "reason": "parser_error"})
                continue

            node_batch.extend(nodes)
            edge_batch.extend(edges)
            was_new = existing is None
            cap = AccessCapability(
                capability_id=decision.capability_id,
                host_id=item.target_host_id,
                capability_type=decision.capability_type,
                validated=True,
                principal=decision.principal,
                confidence=decision.confidence,
                source_task_id=decision.source_task_id,
                metadata=decision.metadata,
                runtime_available=False,
            )
            pending.append((decision.capability_id, cap, was_new, decision))

        if node_batch or edge_batch:
            try:
                await self._ensure_host_node(context)
                await context.api.apply_deltas(nodes=node_batch, edges=edge_batch)
            except Exception as exc:  # noqa: BLE001 - a batch write failure must not crash the turn
                logger.error("capability discovery apply_deltas failed: %s", type(exc).__name__)
                for capability_id, _cap, _was_new, _decision in pending:
                    result.rejections.append({"evidence_id": capability_id, "reason": "registry_error"})
                return result

            # A capability whose `confidence`/`metadata` differs from an
            # already-recorded high-confidence value legitimately raises an
            # open Conflict (memfabric's own epistemic-conflict invariant —
            # two high-confidence claims that disagree are never silently
            # overwritten by a bare upsert). Rather than fighting that
            # invariant, immediately auto-resolve it via the substrate's own
            # documented default policy ("higher confidence wins, tie ->
            # higher logical_version") — this is precisely the monotonic
            # max(existing, new) merge rule this module documents, achieved
            # through the correct, substrate-endorsed mechanism instead of
            # a second, competing merge implementation.
            for capability_id, _cap, _was_new, _decision in pending:
                try:
                    open_conflicts = await context.api.get_conflicts(
                        node_id=capability_id, status=ConflictStatus.open,
                    )
                    for conflict in open_conflicts:
                        await context.api.auto_resolve_conflict(conflict.id)
                except Exception as exc:  # noqa: BLE001 - never crash discovery on conflict bookkeeping
                    logger.debug("conflict auto-resolution failed for %s: %s", capability_id, exc)

        # The batch write succeeded (or there was nothing to write) — only
        # now do accepted decisions/counters become part of the result.
        registration_targets: list[tuple[str, AccessCapability, bool]] = []
        for capability_id, cap, was_new, decision in pending:
            result.decisions.append(decision)
            if was_new:
                result.capabilities_derived += 1
            else:
                result.capabilities_updated += 1
            registration_targets.append((capability_id, cap, was_new))

        for capability_id, cap, _was_new in registration_targets:
            if not context.attempt_runtime_registration:
                continue
            try:
                registered = register_capability_adapter(
                    config=context.config, capability_registry=context.capability_registry,
                    subgraph=context.subgraph, target=context.target, cap=cap,
                )
            except Exception as exc:  # noqa: BLE001 - registration failures must never crash discovery
                logger.warning("runtime registration failed for %s: %s", capability_id, type(exc).__name__)
                registered = False

            if registered:
                result.adapters_registered += 1
            else:
                result.runtime_unavailable_count += 1

            try:
                timestamp = now()
                await context.api.upsert_node(Node(
                    id=capability_id, type="access_capability",
                    props={"runtime_available": registered},
                    confidence=0.5, source="capability_discovery",
                    first_seen=timestamp, last_seen=timestamp,
                ))
            except Exception as exc:  # noqa: BLE001 - never crash discovery on a bookkeeping write
                logger.debug("runtime_available write-back failed for %s: %s", capability_id, exc)

        return result

    async def _ensure_host_node(self, context: CapabilityDiscoveryContext) -> None:
        """Defensively upsert a ``host`` node for *context.target* if the
        already-fetched ``context.subgraph`` shows none exists — mirrors
        ``apex_host.orchestration.capability_seed``'s identical defensive
        pattern. Without this, the first-ever capability derived for a
        target whose ``host`` node has not yet been created by an earlier
        recon step (or in a test that constructs an empty subgraph
        directly) would produce a dangling ``has_capability`` edge, which
        ``MemoryAPI.put_edge`` correctly rejects (P8-I05), rolling back the
        entire batch. Reuses the subgraph already fetched by the caller —
        no extra ``MemoryAPI`` read."""
        h_id = host_id(context.target)
        if any(n.id == h_id for n in context.subgraph.nodes):
            return
        timestamp = now()
        await context.api.upsert_node(Node(
            id=h_id, type="host", props={"ip": context.target}, confidence=0.5,
            source="capability_discovery", first_seen=timestamp, last_seen=timestamp,
        ))

    def _materialize(
        self, evidence: CapabilityEvidence, decision: CapabilityDerivationDecision, *, existing: Node | None,
    ) -> tuple[list[Node], list[Any]]:
        """Call the appropriate ``CapabilityParser.derive_*`` method,
        appending provenance/runtime_generation bookkeeping to the
        resulting node's metadata. Never writes directly — the caller
        (``discover``) is the only place ``apply_deltas`` is invoked."""
        existing_metadata = dict((existing.props.get("metadata") or {})) if existing else {}
        provenance = list(existing_metadata.get("evidence_provenance", []))
        if evidence.evidence_id and evidence.evidence_id not in provenance:
            provenance.append(evidence.evidence_id)
        provenance = provenance[-_MAX_PROVENANCE_ENTRIES:]

        capability_type = decision.capability_type
        target = evidence.target_host_id.removeprefix("host:")

        if capability_type is AccessCapabilityType.ssh_command:
            parsed = self._parser.derive_ssh_capability(
                target=target, username=decision.principal, source_task_id=decision.source_task_id,
                confidence=decision.confidence,
            )
        elif capability_type in (AccessCapabilityType.arbitrary_file_read, AccessCapabilityType.api_file_read):
            parsed = self._parser.derive_direct_file_read_capability(
                target=target, capability_type=capability_type, principal=decision.principal,
                source_task_id=decision.source_task_id, validation_method=decision.validation_method,
                confidence=decision.confidence,
                requires_auth=bool(evidence.sanitized_attributes.get("requires_auth", False)),
                max_response_bytes=int(evidence.sanitized_attributes.get("max_response_bytes", 4096)),
                request_shape_id=str(evidence.sanitized_attributes.get("request_shape_id", "")),
            )
        else:
            parsed = self._parser.derive_command_capability(
                target=target, capability_type=capability_type, principal=decision.principal,
                source_task_id=decision.source_task_id, validation_method=decision.validation_method,
                confidence=decision.confidence,
                max_output_bytes=int(evidence.sanitized_attributes.get("max_output_bytes", 4096)),
                strategy_id=str(evidence.sanitized_attributes.get("strategy_id", "")),
            )

        nodes = list(parsed.node_deltas)
        for n in nodes:
            if n.id == decision.capability_id:
                merged_metadata = dict(n.props.get("metadata") or {})
                merged_metadata["evidence_provenance"] = provenance
                merged_metadata["runtime_generation"] = max(
                    evidence.runtime_generation, int(existing_metadata.get("runtime_generation", 0)),
                )
                n.props["metadata"] = merged_metadata
        return nodes, list(parsed.edge_deltas)


async def run_capability_discovery(
    evidence: Sequence[CapabilityEvidence], *, context: CapabilityDiscoveryContext,
) -> CapabilityDiscoveryResult:
    """Convenience module-level entry point — constructs a default-provider
    engine and calls ``discover()``. This is what orchestration call sites
    (``parsing_node.py``, ``capability_seed.py``) actually import; a
    dedicated engine instance is only needed by callers that inject custom
    providers (tests)."""
    if not evidence:
        return CapabilityDiscoveryResult()
    engine = CapabilityDiscoveryEngine(providers=context.providers)
    return await engine.discover(evidence, context=context)
