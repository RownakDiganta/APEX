# types.py
# Core domain-agnostic data shapes for the memory fabric — Node, Edge, Episode, KnowledgeEntry, Skill, EvidenceBundle, Conflict, TaskSpec, ExecutorResult, Goal, and related enums.
"""Core data shapes for the memory fabric.

All records are @dataclass(slots=True) for memory efficiency and
attribute safety.  These types are domain-agnostic — they carry no
task-specific knowledge.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Tier enum
# ---------------------------------------------------------------------------

class Tier(str, Enum):
    """Logical retrieval tier.

    **Physical reality:** `working` and `episodic` each have a dedicated physical
    store (``GraphStore`` and ``EpisodicStore``).  ``semantic`` and ``procedural``
    do NOT — they are **metadata-distinguished entries in the shared BM25 and
    vector indexes**.  After Reflector promotion, a ``KnowledgeEntry`` or ``Skill``
    is indexed into the same ``LexicalIndex``/``VectorIndex`` that serves working
    and episodic entries, but with a different ``"tier"`` value in the metadata
    dict.  Retrieval tier filtering (the ``tiers`` parameter on
    ``MemoryAPI.query()``) works by post-filtering on that metadata field — not by
    routing to a separate physical store.

    Physical backend separation per tier is possible by injecting different
    ``LexicalIndex`` / ``VectorIndex`` implementations through the Protocol seams
    in ``stores/protocols.py``.  It is **not the default** and the substrate does
    not require it.

    Summary:
      working:    dedicated GraphStore + shared LexicalIndex (``tier=working``)
      episodic:   dedicated EpisodicStore + shared LexicalIndex (``tier=episodic``)
      semantic:   logical tier only — shared LexicalIndex/VectorIndex (``tier=semantic``)
      procedural: logical tier only — shared LexicalIndex/VectorIndex (``tier=procedural``)
      staged:     debug view of un-promoted proposals; never indexed in live stores
    """

    working = "working"
    episodic = "episodic"
    semantic = "semantic"     # logical tier: promoted KnowledgeEntry objects
    procedural = "procedural" # logical tier: promoted Skill objects
    staged = "staged"         # debug: view un-promoted proposals


ALL_TIERS: tuple[Tier, ...] = (
    Tier.working, Tier.episodic, Tier.semantic, Tier.procedural
)


# ---------------------------------------------------------------------------
# Outcome enum
# ---------------------------------------------------------------------------

class Outcome(str, Enum):
    success = "success"
    fixable = "fixable"
    script_error = "script_error"
    fundamental = "fundamental"


# ---------------------------------------------------------------------------
# Skill outcome disposition (for lifecycle tracking)
# ---------------------------------------------------------------------------

class SkillOutcomeDisposition(str, Enum):
    """Disposition of a skill following task execution.

    Used by ``MemoryAPI.record_skill_execution()`` to update wins/losses.

    ``WIN``: the task succeeded (``Outcome.success``).
    ``LOSS``: the task failed with a fundamental error (``Outcome.fundamental``).
    ``NEUTRAL``: the task failed transiently (``script_error``, ``fixable``); the
      outcome does not count against the skill.
    ``NOT_EXECUTED``: the task was blocked before execution (policy block, conflict
      block, or duplicate skip); wins/losses are not updated.
    """

    WIN = "win"
    LOSS = "loss"
    NEUTRAL = "neutral"
    NOT_EXECUTED = "not_executed"


# ---------------------------------------------------------------------------
# Working-memory graph types
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Node:
    """A node in the episodic knowledge graph (EKG)."""
    id: str
    type: str
    props: dict[str, Any]
    confidence: float
    source: str
    first_seen: str
    last_seen: str
    # Per-field provenance: field_name → {value, source, timestamp, confidence}
    _provenance: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)


@dataclass(slots=True)
class Edge:
    """A directed edge in the EKG."""
    id: str
    from_id: str
    to_id: str
    type: str
    props: dict[str, Any]
    confidence: float
    source: str
    first_seen: str
    last_seen: str


# ---------------------------------------------------------------------------
# Episodic memory
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Episode:
    """A single immutable event appended to the episodic log."""
    agent: str
    action: str
    outcome: Outcome
    data: dict[str, Any]
    id: str = ""
    timestamp: str = ""
    task_id: str | None = None
    phase: str | None = None
    # chain_id groups a sequence of episodes into one sub-chain
    chain_id: str | None = None


# ---------------------------------------------------------------------------
# Semantic & procedural knowledge (staging + live)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class KnowledgeEntry:
    """A factual claim staged for Reflector promotion."""
    text: str
    source: str
    confidence: float
    id: str = ""
    timestamp: str = ""
    embedding: list[float] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    promoted: bool = False


@dataclass(slots=True)
class Skill:
    """A procedural template generalised from episode chains."""
    name: str
    description: str
    # Templated action with typed slot references
    template: dict[str, Any]
    preconditions: dict[str, Any]
    source_episodes: list[str]
    confidence: float
    wins: int = 0
    losses: int = 0
    # Legacy run-counter for decay (kept for backward compatibility).
    # New code should prefer last_used_run_number (set by MemoryAPI lifecycle
    # methods).  should_decay() uses last_used_run_number when set.
    last_used_run: int = 0
    quarantined: bool = False
    promoted: bool = False
    id: str = ""
    timestamp: str = ""
    embedding: list[float] | None = None
    evidence_count: int = 0
    # --- Phase 3 lifecycle fields (all optional for backward compatibility) ---
    # Monotonic run-number fields — set by MemoryAPI lifecycle methods.
    # These use the global _completed_run_number from MemoryAPI, not local counters.
    created_run_number: int = 0
    promoted_run_number: int | None = None
    last_retrieved_run_number: int | None = None
    last_selected_run_number: int | None = None
    last_executed_run_number: int | None = None
    # Primary "last used" field for decay logic (set on any retrieve/select/execute).
    # When set, should_decay() uses this instead of last_used_run.
    last_used_run_number: int | None = None
    # Tracks idempotence: decay_skill() skips if last_decay_run_number == current_run.
    last_decay_run_number: int | None = None
    quarantined_run_number: int | None = None
    # Wall-clock timestamps for each lifecycle event (ISO-8601 UTC)
    last_retrieved_at: str | None = None
    last_selected_at: str | None = None
    last_executed_at: str | None = None
    # Event counters (separate from wins/losses which track outcomes)
    retrieval_count: int = 0
    selection_count: int = 0
    execution_count: int = 0
    # Quarantine metadata
    quarantine_reason: str | None = None
    quarantined_at: str | None = None


# ---------------------------------------------------------------------------
# Retrieval output
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ScoredEntry:
    """A single retrieval result with provenance and score."""
    id: str
    score: float
    text: str
    source: str
    tier: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RetrievalDiagnostics:
    """Observable diagnostics attached to every HybridRetriever result bundle.

    Serializable and testable.  All numeric counts are 0 when the corresponding
    channel did not run.  ``channels_attempted`` lists the channels that were
    invoked; ``channels_skipped`` lists channels that were configured but not
    invoked (e.g. dense skipped because StubEmbedder and gate closed).
    """
    cache_hit: bool
    channels_attempted: list[str]
    channels_skipped: list[str]
    lexical_top_score: float         # max raw BM25 score before tier filter (0.0 if none)
    lexical_candidate_count: int     # BM25 results after tier filter
    dense_candidate_count: int
    graph_candidate_count: int
    regex_candidate_count: int
    fused_candidate_count: int       # after RRF
    reranked_candidate_count: int    # after reranker (may equal fused if reranker is no-op)
    gate_open: bool                  # True if the BM25-score gate opened (for StubEmbedder path)
    gate_reasons: list[str]          # human-readable reasons the gate opened or closed
    index_generation: int            # MemoryAPI._index_generation at query time
    channel_weights: dict[str, float]  # {"bm25": 1.0, "regex": 0.5, "dense": 1.0, "graph": 0.5}


class RetrievalError(Exception):
    """Raised when a required retrieval channel (BM25) fails hard.

    Soft channel failures (dense, graph, regex) degrade gracefully and are
    recorded in ``RetrievalDiagnostics`` without raising.  BM25 failure is a
    hard error because it is the baseline channel and there is no fallback.
    """


@dataclass(slots=True)
class BlockedClaim:
    """A specific node field contested by an open Conflict.

    When ``SubgraphView.open_conflicts`` or ``EvidenceBundle.blocked_fields``
    contains a ``BlockedClaim``, any component that would derive an action from
    the contested field MUST treat that field as absent until the conflict is
    resolved.

    Produced centrally by ``MemoryAPI.get_subgraph()`` and ``MemoryAPI.query()``
    so that planners and executors receive pre-annotated context.  They never
    need to call ``dependents_blocked_by()`` directly — the annotation travels
    in the bundle.
    """
    node_id: str
    field_name: str
    conflict_id: str
    node_type: str


@dataclass(slots=True, frozen=True)
class ClaimDependency:
    """A specific node field that a TaskSpec depends on being undisputed.

    When a planner creates a task that reads a node field — target IP, port,
    service name, URL, protocol, version, credential, access level — it records
    that dependency here.

    The central conflict guard in ``MemoryAPI``/``apex_host/graph.py`` compares
    these dependencies against ``EvidenceBundle.blocked_fields`` and
    ``EvidenceBundle.quarantined_fields`` **before** any executor is invoked.
    A task is blocked only when one of its declared dependencies is contested;
    unrelated conflicts on other nodes do NOT block this task.

    ``expected_value`` is optional.  When set, the guard may additionally verify
    the field holds the expected value before permitting execution.
    """
    node_id: str
    field_name: str
    expected_value: object | None = None


@dataclass(slots=True)
class SubgraphView:
    """A bounded neighbourhood of the EKG."""
    anchor: str
    nodes: list[Node]
    edges: list[Edge]
    depth: int
    # Open conflicts on nodes in this subgraph — set by MemoryAPI.get_subgraph().
    # Components that derive actions from node field values must skip any field
    # that appears here.  Empty list means no contested fields in this subgraph.
    open_conflicts: list[BlockedClaim] = field(default_factory=list)
    # Quarantined fields on nodes in this subgraph — these are NOT open conflicts
    # (they do not block as "contested") but must be treated as ABSENT, not
    # trusted.  A capability that depends on a quarantined field must not be
    # emitted until the field is reestablished by a verified write.
    quarantined_fields: list[BlockedClaim] = field(default_factory=list)


@dataclass(slots=True)
class EvidenceBundle:
    """The scoped context delivered to planners and executors."""
    query: str
    entries: list[ScoredEntry]
    subgraph: SubgraphView | None
    tiers_queried: list[str]
    # Contested fields from the subgraph — propagated from SubgraphView.open_conflicts
    # by MemoryAPI.query().  Any action that reads a blocked field must not proceed
    # until the conflict is resolved.
    blocked_fields: list[BlockedClaim] = field(default_factory=list)
    # Quarantined fields — contested fields whose conflict was quarantined.
    # Not blocking (not "open"), but also not trusted — treat as absent.
    quarantined_fields: list[BlockedClaim] = field(default_factory=list)
    # Retrieval diagnostics — populated by HybridRetriever.search() and forwarded
    # here so callers can observe which channels fired, cache state, and gate decisions.
    # None when the retriever was not invoked (e.g. text=None query, or no retriever set).
    diagnostics: RetrievalDiagnostics | None = field(default=None)


# ---------------------------------------------------------------------------
# Conflict record
# ---------------------------------------------------------------------------

class ConflictStatus(str, Enum):
    """Lifecycle status of a Conflict record.

    Statuses:
      open        — created, awaiting resolution; **blocks dependents**.
      resolved    — winner chosen by policy or orchestrator; dependents may proceed.
      superseded  — a later write on the same field made this conflict moot
                    (e.g. both claimants were overwritten by a third authoritative
                    source); kept for audit but does not block.
      quarantined — the contested field has been quarantined by the Reflector
                    because neither claim could be validated; dependents must treat
                    the field as absent.
    """
    open = "open"
    resolved = "resolved"
    superseded = "superseded"
    quarantined = "quarantined"


@dataclass(slots=True)
class Conflict:
    """Records a contradiction between two high-confidence field writes.

    Lifecycle (see ``ConflictStatus``):
    - All conflicts start as ``open`` and block any component that depends on
      the contested field.
    - ``resolved`` after the default policy (or an explicit orchestrator call)
      picks a winner; ``winning_value`` is set.
    - ``superseded`` when a later high-confidence write makes both claims moot.
    - ``quarantined`` when the Reflector marks the field as untrusted.

    Provenance: ``history`` is an append-only list of audit entries so every
    status transition can be traced.  ``claim_a`` and ``claim_b`` are never
    mutated; they record the exact state of the two competing provenance dicts
    at the moment the conflict was detected.
    """
    id: str
    node_id: str
    field_name: str
    claim_a: dict[str, Any]   # {value, confidence, source, timestamp, logical_version}
    claim_b: dict[str, Any]
    timestamp: str            # wall-clock time the conflict was detected
    # Lifecycle
    status: ConflictStatus = ConflictStatus.open
    winning_value: Any = None
    resolution: str | None = None
    # Audit trail — each entry: {event, timestamp, detail}
    history: list[dict[str, Any]] = field(default_factory=list)
    # Legacy compat: True iff status is not open (derived, kept for old callers)
    resolved: bool = False


# ---------------------------------------------------------------------------
# Coordination types
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class TaskSpec:
    """A unit of work dispatched to an Executor."""
    id: str
    goal_id: str
    executor_domain: str
    params: dict[str, Any]
    subgraph_anchor: str | None = None
    phase: str | None = None
    retries: int = 0
    # Fields this task reads and therefore requires to be undisputed.
    # Populated by the planner at task-creation time so the central conflict
    # guard can perform dependency-specific blocking rather than tool-name
    # blocking.  An empty tuple means "no declared dependencies" — the task
    # either has none, or was created by a planner that has not yet been
    # updated.  The guard falls through to the legacy tool-name check when
    # this is empty.
    claim_dependencies: tuple[ClaimDependency, ...] = ()
    # Optional semantic purpose tag.  "conflict_verification" marks a task
    # whose goal is to re-probe an undisputed view of a contested field.
    # Verification tasks must declare only undisputed fields as dependencies
    # so the guard allows them through even when a conflict is open.
    purpose: str | None = None
    # Skill that was selected to produce this task.  Set by the planner when
    # a procedural skill is retrieved and chosen as the execution template.
    # Used by MemoryAPI.record_skill_execution() to attribute the outcome.
    origin_skill_id: str | None = None


@dataclass(slots=True)
class ExecutorResult:
    """What an Executor returns after completing a TaskSpec."""
    task_id: str
    episode: Episode
    node_deltas: list[Node] = field(default_factory=list)
    edge_deltas: list[Edge] = field(default_factory=list)
    proposed_knowledge: list[KnowledgeEntry] = field(default_factory=list)
    proposed_skills: list[Skill] = field(default_factory=list)
    # Clue for re-trying a fixable failure
    clue: str | None = None


@dataclass(slots=True)
class AbandonSignal:
    """Planner signals that the goal branch should be abandoned."""
    reason: str


@dataclass(slots=True)
class Goal:
    """A high-level objective handed to a sub-planner."""
    id: str
    description: str
    phase: str
    anchor_node: str | None = None
    priority: float = 1.0


@dataclass(slots=True)
class RawObservation:
    """Unstructured output from an external tool or executor."""
    raw: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedObservation:
    """Structured EKG deltas derived from a RawObservation."""
    node_deltas: list[Node] = field(default_factory=list)
    edge_deltas: list[Edge] = field(default_factory=list)
    proposed_knowledge: list[KnowledgeEntry] = field(default_factory=list)


@dataclass(slots=True)
class OpenTask:
    """A node that represents an unresolved actionable item."""
    node_id: str
    node_type: str
    props: dict[str, Any]
    created: str


# ---------------------------------------------------------------------------
# Transaction exceptions
# ---------------------------------------------------------------------------

class TransactionCapabilityError(Exception):
    """Raised when a batch operation requires a store capability that is absent.

    Example: ``apply_deltas(episodes=[...])`` requires the episodic store to
    expose ``_pop_episodes`` for rollback support.  If the store lacks this
    method, the batch is rejected *before* any writes begin so the all-or-nothing
    invariant is preserved.

    Attributes
    ----------
    store_type:  The class name of the store that lacks the capability.
    missing_cap: The name of the missing method or capability.
    reason:      Human-readable explanation.
    """

    def __init__(self, store_type: str, missing_cap: str, reason: str) -> None:
        super().__init__(reason)
        self.store_type = store_type
        self.missing_cap = missing_cap
        self.reason = reason

    def __str__(self) -> str:
        return (
            f"TransactionCapabilityError: store '{self.store_type}' lacks "
            f"'{self.missing_cap}': {self.reason}"
        )


class TransactionIntegrityError(Exception):
    """Raised when a transaction rollback itself fails, leaving state undefined.

    If ``apply_deltas`` or ``_apply_conflict_resolution_locked`` encounters an
    error during the write phase AND the subsequent rollback also encounters one
    or more errors, the system is in an **undefined** state.  The caller must
    treat all data written in the failed batch as suspect and either reinitialise
    the store or replay from the last known-good checkpoint.

    Attributes
    ----------
    original_error:   The exception that triggered the rollback attempt.
    rollback_errors:  List of exceptions raised during rollback.
    affected_ids:     IDs of nodes, edges, episodes, etc. written before failure.
    stage:            Name of the stage where the primary write failed.
    conflict_id:      The conflict ID when this error arose from resolution rollback.
    node_id:          The node ID of the contested field (conflict resolution context).
    field_name:       The field name of the contested field (conflict resolution context).
    """

    def __init__(
        self,
        original_error: Exception,
        rollback_errors: list[Exception],
        affected_ids: list[str],
        stage: str,
        conflict_id: str | None = None,
        node_id: str | None = None,
        field_name: str | None = None,
    ) -> None:
        super().__init__(
            f"Rollback failed after transaction error; store state is undefined. "
            f"Original: {original_error!r}; rollback errors: {rollback_errors!r}"
        )
        self.original_error = original_error
        self.rollback_errors = rollback_errors
        self.affected_ids = affected_ids
        self.stage = stage
        self.conflict_id = conflict_id
        self.node_id = node_id
        self.field_name = field_name

    def __str__(self) -> str:
        ctx = (
            f", conflict_id={self.conflict_id!r}"
            f", node_id={self.node_id!r}"
            f", field_name={self.field_name!r}"
            if self.conflict_id else ""
        )
        return (
            f"TransactionIntegrityError(stage={self.stage!r}{ctx}, "
            f"original={self.original_error!r}, "
            f"rollback_errors={self.rollback_errors!r}, "
            f"affected_ids={self.affected_ids!r})"
        )
