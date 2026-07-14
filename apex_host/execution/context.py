# context.py
# ExecutionContext and DispatchResult dataclasses for the APEX task dispatcher.
"""Execution context and dispatch result types for the APEX task dispatcher."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from apex_host.execution.dispositions import ExecutionDisposition

if TYPE_CHECKING:
    from memfabric.types import EvidenceBundle, SubgraphView
    from apex_host.policy.models import PolicyDecision
    from apex_host.execution.errors import ExecutionError


@dataclass(slots=True, frozen=True)
class ExecutionContext:
    """Immutable per-dispatch context passed to the dispatcher and executors.

    Not stored in ``ApexGraphState`` — infrastructure objects are captured
    via closures (CLAUDE.md §11.3 and memfabric Invariant 7).
    """

    run_id: str
    phase: str
    turn_number: int
    evidence_version: str | None
    subgraph: "SubgraphView"
    evidence: "EvidenceBundle"
    dry_run: bool
    # Repair and retry metadata — zero for initial attempts.
    repair_attempt: int = 0
    is_repair: bool = False
    retry_count: int = 0
    original_task_id: str | None = None


@dataclass(slots=True)
class DispatchResult:
    """Complete outcome of one ``TaskDispatcher.dispatch()`` call.

    Callers use ``disposition`` and ``tool_result_dict`` (the backward-compatible
    tool-result dict) to drive downstream routing, audit episodes, and parser
    invocation.  The raw ``error`` and ``policy_decision`` fields are available
    for detailed reporting.
    """

    disposition: ExecutionDisposition
    task_id: str
    fingerprint: str
    # Backward-compatible tool-result dict for parse_observation / write_memory.
    # Always set; populated with appropriate empty/blocked content when the
    # executor was not called.
    tool_result_dict: dict[str, Any]
    # Structured metadata for audit and reporting.
    policy_decision: "PolicyDecision | None" = None
    duplicate_of: str | None = None
    retryable: bool = False
    repairable: bool = False
    error: "ExecutionError | None" = None
    audit_metadata: dict[str, Any] = field(default_factory=dict)

    # Convenience forwarders
    @property
    def is_executed(self) -> bool:
        return self.disposition.counts_as_execution

    @property
    def is_blocked(self) -> bool:
        return self.disposition.is_blocked

    @property
    def is_skipped(self) -> bool:
        return self.disposition.is_skipped

    @property
    def is_success(self) -> bool:
        return self.disposition.is_success
