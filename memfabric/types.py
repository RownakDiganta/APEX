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
    working = "working"       # EKG graph (nodes + edges)
    episodic = "episodic"     # append-only episode log
    semantic = "semantic"     # promoted knowledge entries
    procedural = "procedural" # promoted skills
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

@dataclass(slots=True)
class Conflict:
    """Records a contradiction between two high-confidence field writes."""
    id: str
    node_id: str
    field_name: str
    claim_a: dict[str, Any]   # {value, confidence, source, timestamp}
    claim_b: dict[str, Any]
    timestamp: str
    resolved: bool = False
    resolution: str | None = None


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
