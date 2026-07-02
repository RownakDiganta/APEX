# api.py
# The unified Memory API — the only surface through which any component reads or writes state.
"""MemoryAPI — the ONLY surface through which any component touches state.

Design invariants enforced here:
1. Every read and write goes through this class.
2. Episodic memory is append-only; episodes are immutable once written.
3. Working memory (EKG) uses per-field LWW upsert with provenance.
4. Contradictory high-confidence field writes create a Conflict; they do NOT
   silently overwrite.
5. propose_* writes to staging; query() never reads staging unless Tier.staged
   is explicitly requested.
6. open_tasks() is derived live from the graph; there is no stored task list.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from memfabric.ids import new_id, now
from memfabric.types import (
    ALL_TIERS,
    Conflict,
    Edge,
    Episode,
    EvidenceBundle,
    KnowledgeEntry,
    Node,
    OpenTask,
    ScoredEntry,
    Skill,
    SubgraphView,
    Tier,
)

if TYPE_CHECKING:
    from memfabric.config import Config
    from memfabric.retrieval.engine import HybridRetriever
    from memfabric.stores.protocols import (
        EpisodicStore,
        GraphStore,
        KVStore,
        LexicalIndex,
        VectorIndex,
    )

logger = logging.getLogger(__name__)


def _node_text(node: Node) -> str:
    """Flat text representation of a node used for lexical/vector indexing."""
    parts = [f"node type={node.type}"]
    for k, v in node.props.items():
        parts.append(f"{k}={v}")
    return " ".join(parts)


def _episode_text(ep: Episode) -> str:
    parts = [f"episode agent={ep.agent} action={ep.action} outcome={ep.outcome.value}"]
    for k, v in ep.data.items():
        parts.append(f"{k}={v}")
    return " ".join(parts)


def _knowledge_text(ke: KnowledgeEntry) -> str:
    return ke.text


def _skill_text(sk: Skill) -> str:
    return f"skill name={sk.name} {sk.description}"


class MemoryAPI:
    """The unified memory fabric API.

    Parameters
    ----------
    graph:      GraphStore implementation
    episodic:   EpisodicStore implementation
    lexical:    LexicalIndex for keyword search
    vector:     VectorIndex for semantic search
    kv:         KVStore for retrieval caching
    retriever:  HybridRetriever (injected after construction to avoid circular dep)
    config:     Config dataclass
    """

    def __init__(
        self,
        graph: GraphStore,
        episodic: EpisodicStore,
        lexical: LexicalIndex,
        vector: VectorIndex,
        kv: KVStore,
        *,
        config: Config,
    ) -> None:
        self._graph = graph
        self._episodic = episodic
        self._lexical = lexical
        self._vector = vector
        self._kv = kv
        self._config = config

        # Retriever is set after construction (avoids circular init)
        self._retriever: HybridRetriever | None = None

        # Staging areas — only the Reflector worker may promote these
        self._staged_knowledge: dict[str, KnowledgeEntry] = {}
        self._staged_skills: dict[str, Skill] = {}

        # Conflict log — conflicts are accumulated here
        self._conflicts: dict[str, Conflict] = {}

        self._staging_lock = asyncio.Lock()

    def set_retriever(self, retriever: HybridRetriever) -> None:
        self._retriever = retriever

    # ------------------------------------------------------------------
    # READ
    # ------------------------------------------------------------------

    async def query(
        self,
        *,
        text: str | None = None,
        subgraph_anchor: str | None = None,
        tiers: Sequence[Tier] = ALL_TIERS,
        k: int = 8,
        filters: Mapping[str, object] | None = None,
    ) -> EvidenceBundle:
        """Retrieve evidence from the requested tiers and fuse into a bundle.

        Staged entries are NOT included unless ``Tier.staged`` is in *tiers*.
        """
        entries: list[ScoredEntry] = []

        if self._retriever is not None and text:
            entries = await self._retriever.search(
                text=text,
                k=k,
                tiers=list(tiers),
                filters=dict(filters) if filters else None,
            )

        # If staged tier explicitly requested, append staged entries directly
        if Tier.staged in tiers:
            staged: list[KnowledgeEntry | Skill] = (
                list(self._staged_knowledge.values())
                + list(self._staged_skills.values())
            )
            for item in staged:
                if isinstance(item, KnowledgeEntry):
                    t = _knowledge_text(item)
                elif isinstance(item, Skill):
                    t = _skill_text(item)
                else:
                    continue
                entries.append(
                    ScoredEntry(
                        id=item.id,
                        score=0.0,
                        text=t,
                        source=item.source if isinstance(item, KnowledgeEntry) else "reflector",
                        tier=Tier.staged.value,
                    )
                )

        subgraph: SubgraphView | None = None
        if subgraph_anchor:
            subgraph = await self._graph.get_subgraph(subgraph_anchor, depth=2)

        return EvidenceBundle(
            query=text or "",
            entries=entries,
            subgraph=subgraph,
            tiers_queried=[t.value for t in tiers],
        )

    async def get_subgraph(
        self,
        anchor_node: str,
        depth: int,
        edge_types: Sequence[str] | None = None,
    ) -> SubgraphView:
        return await self._graph.get_subgraph(anchor_node, depth, edge_types)

    # ------------------------------------------------------------------
    # WRITE: working memory (upsert, per-field LWW + provenance)
    # ------------------------------------------------------------------

    async def upsert_node(self, node: Node) -> str:
        """Merge *node* field-by-field into any existing node.

        - For each prop field, last-writer-wins based on ``node.last_seen``.
        - Provenance is recorded per field in ``_provenance``.
        - Contradictory high-confidence field writes produce a Conflict.
        """
        existing = await self._graph.get_node(node.id)

        if existing is None:
            # First write: populate provenance for every prop field
            prov: dict[str, dict[str, Any]] = {}
            for field_name, value in node.props.items():
                prov[field_name] = {
                    "value": value,
                    "source": node.source,
                    "timestamp": node.last_seen,
                    "confidence": node.confidence,
                }
            node._provenance = prov
            await self._graph.put_node(node)
            # Index for retrieval — _text stored in metadata so search can return it
            _t = _node_text(node)
            await self._lexical.add(
                node.id,
                _t,
                {"tier": Tier.working.value, "type": node.type, "_text": _t},
            )
            logger.debug("upsert_node (new) id=%s", node.id)
            return node.id

        # Merge onto existing node
        merged_props = dict(existing.props)
        merged_prov = dict(existing._provenance)

        for field_name, new_value in node.props.items():
            old_prov = merged_prov.get(field_name)

            if old_prov is None:
                # New field — write unconditionally
                merged_props[field_name] = new_value
                merged_prov[field_name] = {
                    "value": new_value,
                    "source": node.source,
                    "timestamp": node.last_seen,
                    "confidence": node.confidence,
                }
                continue

            old_value = old_prov["value"]
            old_confidence: float = float(old_prov.get("confidence", 0.0))
            floor = self._config.conflict_confidence_floor

            # Conflict detection: both high-confidence and values differ
            if (
                old_confidence >= floor
                and node.confidence >= floor
                and old_value != new_value
            ):
                conflict = Conflict(
                    id=new_id(),
                    node_id=node.id,
                    field_name=field_name,
                    claim_a=dict(old_prov),
                    claim_b={
                        "value": new_value,
                        "source": node.source,
                        "timestamp": node.last_seen,
                        "confidence": node.confidence,
                    },
                    timestamp=now(),
                )
                self._conflicts[conflict.id] = conflict
                logger.warning(
                    "conflict node=%s field=%s old=%r new=%r",
                    node.id, field_name, old_value, new_value,
                )
                # Do NOT silently overwrite — leave the existing value
                continue

            # LWW: newer timestamp wins
            if node.last_seen >= old_prov.get("timestamp", ""):
                merged_props[field_name] = new_value
                merged_prov[field_name] = {
                    "value": new_value,
                    "source": node.source,
                    "timestamp": node.last_seen,
                    "confidence": node.confidence,
                }

        # Build the merged node
        merged = Node(
            id=existing.id,
            type=existing.type,
            props=merged_props,
            confidence=max(existing.confidence, node.confidence),
            source=node.source,
            first_seen=existing.first_seen,
            last_seen=max(existing.last_seen, node.last_seen),
            _provenance=merged_prov,
        )
        merged._provenance = merged_prov

        await self._graph.put_node(merged)
        _mt = _node_text(merged)
        await self._lexical.add(
            merged.id,
            _mt,
            {"tier": Tier.working.value, "type": merged.type, "_text": _mt},
        )
        logger.debug("upsert_node (merge) id=%s", node.id)
        return node.id

    async def upsert_edge(self, edge: Edge) -> str:
        """Insert or replace an edge (LWW — edges have no sub-field merging)."""
        existing = await self._graph.get_edge(edge.id)
        if existing is not None and edge.last_seen < existing.last_seen:
            return existing.id  # older write loses
        await self._graph.put_edge(edge)
        return edge.id

    # ------------------------------------------------------------------
    # WRITE: episodic (append-only, immutable)
    # ------------------------------------------------------------------

    async def append_episode(self, episode: Episode) -> str:
        """Append an episode to the immutable log.

        Assigns id + timestamp if not already set.  Also indexes for retrieval.
        """
        eid = await self._episodic.append(episode)
        # Index episode for lexical search
        _et = _episode_text(episode)
        await self._lexical.add(
            episode.id,
            _et,
            {"tier": Tier.episodic.value, "outcome": episode.outcome.value, "_text": _et},
        )
        logger.debug("append_episode id=%s outcome=%s", eid, episode.outcome.value)
        return eid

    # ------------------------------------------------------------------
    # WRITE: staged proposals (NOT yet retrievable via normal query)
    # ------------------------------------------------------------------

    async def propose_knowledge(self, entry: KnowledgeEntry) -> str:
        """Stage a knowledge entry.  NOT retrievable until Reflector promotes it."""
        async with self._staging_lock:
            if not entry.id:
                entry.id = new_id()
            if not entry.timestamp:
                entry.timestamp = now()
            self._staged_knowledge[entry.id] = entry
        logger.debug("propose_knowledge id=%s", entry.id)
        return entry.id

    async def propose_skill(self, skill: Skill) -> str:
        """Stage a skill.  NOT retrievable until Reflector promotes it."""
        async with self._staging_lock:
            if not skill.id:
                skill.id = new_id()
            if not skill.timestamp:
                skill.timestamp = now()
            self._staged_skills[skill.id] = skill
        logger.debug("propose_skill id=%s name=%s", skill.id, skill.name)
        return skill.id

    # ------------------------------------------------------------------
    # Reflector promotion paths (only the Reflector worker calls these)
    # ------------------------------------------------------------------

    async def promote_knowledge(self, entry_id: str) -> bool:
        """Move a staged knowledge entry into the live lexical/vector indexes."""
        async with self._staging_lock:
            entry = self._staged_knowledge.get(entry_id)
            if entry is None:
                return False
            entry.promoted = True

        _kt = _knowledge_text(entry)
        await self._lexical.add(
            entry.id,
            _kt,
            {"tier": Tier.semantic.value, "source": entry.source, "_text": _kt},
        )
        if entry.embedding:
            await self._vector.add(
                entry.id,
                entry.embedding,
                {"tier": Tier.semantic.value, "source": entry.source},
            )
        logger.info("promoted knowledge id=%s", entry_id)
        return True

    async def promote_skill(self, skill_id: str) -> bool:
        """Move a staged skill into the live lexical/vector indexes."""
        async with self._staging_lock:
            skill = self._staged_skills.get(skill_id)
            if skill is None:
                return False
            skill.promoted = True

        _st = _skill_text(skill)
        await self._lexical.add(
            skill.id,
            _st,
            {"tier": Tier.procedural.value, "name": skill.name, "_text": _st},
        )
        if skill.embedding:
            await self._vector.add(
                skill.id,
                skill.embedding,
                {"tier": Tier.procedural.value, "name": skill.name},
            )
        logger.info("promoted skill id=%s name=%s", skill_id, skill.name)
        return True

    async def decay_skill(self, skill_id: str, factor: float) -> bool:
        """Reduce skill confidence by *factor* (Reflector decay)."""
        async with self._staging_lock:
            skill = self._staged_skills.get(skill_id)
            if skill is None:
                return False
            skill.confidence = max(0.0, skill.confidence * factor)
        return True

    async def quarantine_skill(self, skill_id: str) -> bool:
        """Mark a skill as quarantined (removed from retrieval)."""
        async with self._staging_lock:
            skill = self._staged_skills.get(skill_id)
            if skill is None:
                return False
            skill.quarantined = True

        # Remove from lexical/vector indexes
        await self._lexical.remove(skill_id)
        await self._vector.remove(skill_id)
        logger.info("quarantined skill id=%s", skill_id)
        return True

    async def update_skill_result(self, skill_id: str, *, won: bool) -> bool:
        """Record a win or loss for a skill (Reflector tracking)."""
        async with self._staging_lock:
            skill = self._staged_skills.get(skill_id)
            if skill is None:
                return False
            if won:
                skill.wins += 1
            else:
                skill.losses += 1
        return True

    # ------------------------------------------------------------------
    # Staging read access (for Reflector)
    # ------------------------------------------------------------------

    async def get_staged_knowledge(self) -> list[KnowledgeEntry]:
        async with self._staging_lock:
            return list(self._staged_knowledge.values())

    async def get_staged_skills(self) -> list[Skill]:
        async with self._staging_lock:
            return list(self._staged_skills.values())

    # ------------------------------------------------------------------
    # Conflict access
    # ------------------------------------------------------------------

    async def get_conflicts(self, node_id: str | None = None) -> list[Conflict]:
        if node_id is None:
            return list(self._conflicts.values())
        return [c for c in self._conflicts.values() if c.node_id == node_id]

    async def resolve_conflict(self, conflict_id: str, resolution: str) -> bool:
        c = self._conflicts.get(conflict_id)
        if c is None:
            return False
        c.resolved = True
        c.resolution = resolution
        return True

    # ------------------------------------------------------------------
    # DERIVED STATE: open tasks (never stored; computed live from graph)
    # ------------------------------------------------------------------

    async def open_tasks(self) -> list[OpenTask]:
        """Return actionable nodes that have no terminal-outcome edge.

        This is a VIEW derived live from the graph.  No separate task list is
        maintained — mutating the graph immediately changes this view.
        """
        terminal_types = set(self._config.terminal_edge_types)
        actionable_types = set(self._config.actionable_node_types)

        tasks: list[OpenTask] = []
        for node_type in actionable_types:
            candidates = await self._graph.get_nodes_by_type(node_type)
            for node in candidates:
                edges = await self._graph.get_edges_for_node(node.id)
                outgoing_types = {
                    e.type for e in edges if e.from_id == node.id
                }
                if not outgoing_types.intersection(terminal_types):
                    tasks.append(
                        OpenTask(
                            node_id=node.id,
                            node_type=node.type,
                            props=node.props,
                            created=node.first_seen,
                        )
                    )
        return tasks
