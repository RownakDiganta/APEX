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
    last_used_run: int = 0
    quarantined: bool = False
    promoted: bool = False
    id: str = ""
    timestamp: str = ""
    embedding: list[float] | None = None
    evidence_count: int = 0


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
class SubgraphView:
    """A bounded neighbourhood of the EKG."""
    anchor: str
    nodes: list[Node]
    edges: list[Edge]
    depth: int


@dataclass(slots=True)
class EvidenceBundle:
    """The scoped context delivered to planners and executors."""
    query: str
    entries: list[ScoredEntry]
    subgraph: SubgraphView | None
    tiers_queried: list[str]


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
