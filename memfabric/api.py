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

Physical storage note (important for accuracy):
  The ``working`` and ``episodic`` tiers have dedicated physical backends
  (``GraphStore`` and ``EpisodicStore``).  The ``semantic`` and ``procedural``
  tiers do NOT have their own physical stores — they are **logical tiers**
  implemented as metadata-distinguished entries in the shared ``LexicalIndex``
  and ``VectorIndex``.  When ``promote_knowledge`` or ``promote_skill`` is
  called, the entry is added to the SAME BM25/vector indexes as working and
  episodic content, with ``"tier": "semantic"`` or ``"tier": "procedural"``
  in the metadata dict.  Retrieval tier filtering works by post-filtering on
  that field, not by routing to a separate store.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Mapping, Sequence

# _EPISODIC_ROLLBACK_METHOD is the name of the private rollback method that
# in-memory EpisodicStore implementations may expose.  When present, apply_deltas
# calls it on failure to undo any episodes appended during the failed batch.
_EPISODIC_ROLLBACK_METHOD = "_pop_episodes"

from memfabric.coordination.conflict import (
    make_conflict,
    mark_quarantined,
    mark_superseded,
    resolve_by_policy,
)
from memfabric.ids import new_id, now
from memfabric.types import (
    ALL_TIERS,
    Conflict,
    ConflictStatus,
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
    from memfabric.retrieval.protocols import Embedder
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


def _edge_text(edge: Edge) -> str:
    """Flat text representation of an edge for lexical/vector indexing."""
    parts = [f"edge type={edge.type} from={edge.from_id} to={edge.to_id}"]
    for k, v in edge.props.items():
        parts.append(f"{k}={v}")
    return " ".join(parts)


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
    embedder:   Optional Embedder for dense-channel freshness.  When supplied,
                ``upsert_node`` and ``upsert_edge`` also update the vector index
                synchronously so the dense channel sees fresh working-tier state.
                When None (default), only the lexical index is updated.
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
        embedder: Embedder | None = None,
    ) -> None:
        self._graph = graph
        self._episodic = episodic
        self._lexical = lexical
        self._vector = vector
        self._kv = kv
        self._config = config
        # Optional embedder: when set, node/edge writes also update the vector
        # index synchronously so the dense retrieval channel sees fresh state.
        self._embedder: Embedder | None = embedder

        # Retriever is set after construction (avoids circular init)
        self._retriever: HybridRetriever | None = None

        # Staging areas — only the Reflector worker may promote these
        self._staged_knowledge: dict[str, KnowledgeEntry] = {}
        self._staged_skills: dict[str, Skill] = {}

        # Conflict log — conflicts are accumulated here
        self._conflicts: dict[str, Conflict] = {}

        self._staging_lock = asyncio.Lock()

        # Monotonic write clock — incremented on every graph write (upsert_node,
        # upsert_edge).  Stored in per-field provenance as "logical_version".
        # LWW ordering uses this counter as the primary key; wall-clock
        # timestamps are only a tie-breaker when logical_version is equal.
        # This prevents clock-skew on the caller's last_seen field from
        # silently winning over a logically later write.
        self._write_clock: int = 0
        # Per-edge write version: edge_id → logical_version of last accepted write.
        self._edge_write_lv: dict[str, int] = {}

    def set_retriever(self, retriever: HybridRetriever) -> None:
        self._retriever = retriever

    async def _refresh_working_indexes(
        self, entry_id: str, text: str, entry_type: str
    ) -> None:
        """Update lexical (and optionally vector) index and bust retrieval cache.

        Called synchronously from ``upsert_node`` and ``upsert_edge`` so that
        the next ``query()`` call sees the current graph state.

        Cache invalidation strategy: delete all keys with prefix ``"retrieval:"``
        from the KVStore.  This forces a fresh channel search on the next query.
        The cache TTL cannot be relied on for correctness here because a node/edge
        write may change what a cached query should return.
        """
        meta: dict[str, Any] = {
            "tier": Tier.working.value,
            "type": entry_type,
            "_text": text,
        }
        # 1. Lexical index (always): updates in-place if id already exists,
        #    so no stale duplicate text is ever returned.
        await self._lexical.add(entry_id, text, meta)

        # 2. Vector index (when embedder is configured): embed the latest text
        #    so the dense channel sees fresh working-tier state when the gate opens.
        if self._embedder is not None:
            vecs = await self._embedder.embed([text])
            await self._vector.add(entry_id, vecs[0], meta)

        # 3. Bust retrieval cache: delete all cached query results so the next
        #    query is re-executed against the updated indexes.
        await self._kv.delete_prefix("retrieval:")

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

        LWW ordering:
          1. ``logical_version`` (primary) — the MemoryAPI write-clock value at
             the moment this call was received.  Higher version always wins.
          2. ``node.last_seen`` (tie-breaker) — used only when two writes share
             the same logical_version, which should not occur in normal operation
             but can happen if the clock is reset.

        Wall-clock timestamps (``last_seen``) are treated as **observational
        metadata** only — they must never be the sole ordering authority, because
        callers may supply skewed or back-dated timestamps.  The ``logical_version``
        assigned by MemoryAPI is the authoritative causal ordering.

        Provenance per field records: ``value``, ``source``, ``timestamp``,
        ``confidence``, and ``logical_version``.

        Contradictory high-confidence field writes produce a Conflict regardless
        of logical_version ordering (conflict detection is epistemic, not temporal).
        """
        # Assign a monotonically increasing version to this write call.
        self._write_clock += 1
        write_lv: int = self._write_clock

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
                    "logical_version": write_lv,
                }
            node._provenance = prov
            await self._graph.put_node(node)
            # Synchronously refresh retrieval indexes so the next query() call
            # sees this write without waiting for Reflector or cache TTL expiry.
            _t = _node_text(node)
            await self._refresh_working_indexes(node.id, _t, node.type)
            logger.debug("upsert_node (new) id=%s lv=%d", node.id, write_lv)
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
                    "logical_version": write_lv,
                }
                continue

            old_value = old_prov["value"]
            old_confidence: float = float(old_prov.get("confidence", 0.0))
            floor = self._config.conflict_confidence_floor

            # Conflict detection: both high-confidence and values differ.
            # This check is epistemic (do two authoritative sources disagree?)
            # and is independent of logical_version — a logically-later write
            # that contradicts a high-confidence existing value still creates a
            # Conflict rather than silently overwriting.
            if (
                old_confidence >= floor
                and node.confidence >= floor
                and old_value != new_value
            ):
                conflict = make_conflict(
                    node_id=node.id,
                    field_name=field_name,
                    claim_a=dict(old_prov),
                    claim_b={
                        "value": new_value,
                        "source": node.source,
                        "timestamp": node.last_seen,
                        "confidence": node.confidence,
                        "logical_version": write_lv,
                    },
                )
                self._conflicts[conflict.id] = conflict
                logger.warning(
                    "conflict node=%s field=%s old=%r new=%r lv=%d",
                    node.id, field_name, old_value, new_value, write_lv,
                )
                # Do NOT silently overwrite — leave the existing value
                continue

            # LWW: logical_version primary, timestamp tie-breaker.
            old_lv: int = int(old_prov.get("logical_version", 0))
            if write_lv > old_lv or (
                write_lv == old_lv and node.last_seen >= old_prov.get("timestamp", "")
            ):
                merged_props[field_name] = new_value
                merged_prov[field_name] = {
                    "value": new_value,
                    "source": node.source,
                    "timestamp": node.last_seen,
                    "confidence": node.confidence,
                    "logical_version": write_lv,
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
        # Synchronously refresh retrieval indexes with the latest merged text.
        _mt = _node_text(merged)
        await self._refresh_working_indexes(merged.id, _mt, merged.type)
        logger.debug("upsert_node (merge) id=%s lv=%d", node.id, write_lv)
        return node.id

    async def upsert_edge(self, edge: Edge) -> str:
        """Insert or replace an edge (whole-edge LWW — no per-field merging).

        LWW ordering uses the same logical_version policy as ``upsert_node``:
          1. The write-clock value at the moment of this call (primary).
          2. ``edge.last_seen`` as a tie-breaker only when versions are equal.

        Wall-clock timestamps on the edge object are observational metadata and
        are NOT the sole ordering authority.  A caller supplying a back-dated
        ``last_seen`` does NOT cause the earlier write to win.
        """
        self._write_clock += 1
        write_lv: int = self._write_clock

        existing = await self._graph.get_edge(edge.id)
        if existing is not None:
            old_lv = self._edge_write_lv.get(edge.id, 0)
            # Reject if this call is somehow older (should not happen in sequential
            # async execution, but guards against any future concurrency).
            if write_lv < old_lv:
                return existing.id
            # Tie on logical_version — use timestamp as tie-breaker
            if write_lv == old_lv and edge.last_seen < existing.last_seen:
                return existing.id

        self._edge_write_lv[edge.id] = write_lv
        await self._graph.put_edge(edge)
        # Synchronously refresh retrieval indexes for the written edge.
        _et = _edge_text(edge)
        await self._refresh_working_indexes(edge.id, _et, edge.type)
        logger.debug("upsert_edge id=%s lv=%d", edge.id, write_lv)
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
    # WRITE: transactional batch (apply_deltas)
    # ------------------------------------------------------------------

    async def apply_deltas(
        self,
        *,
        nodes: Sequence[Node] = (),
        edges: Sequence[Edge] = (),
        episodes: Sequence[Episode] = (),
        knowledge: Sequence[KnowledgeEntry] = (),
        skills: Sequence[Skill] = (),
    ) -> None:
        """Apply a batch of memory writes atomically.

        All writes within the batch succeed together or are fully rolled back —
        no partial state is ever visible to future ``query()`` calls.

        Write order within the batch: nodes → edges → episodes →
        knowledge proposals → skill proposals.  A failure at any step rolls
        back everything committed earlier in the same batch.

        Rollback strategy (in-memory reference stores):
          - Nodes / edges: pre-write snapshots are captured before the batch
            starts.  On rollback, existing entries are restored to their
            pre-batch state via ``put_node`` / ``put_edge``; newly created
            entries are deleted via ``delete_node`` / ``delete_edge``.
          - Lexical and vector indexes are restored to match the rolled-back
            graph state.
          - Episodes: if the ``EpisodicStore`` exposes a private
            ``_pop_episodes`` method (as ``JSONLEpisodicStore`` does), it is
            called to remove any episodes appended during the failed batch.
            Durable stores without this method will log a warning.
          - Knowledge / skill proposals: removed from the staging dicts.
          - Retrieval cache: invalidated after rollback via ``delete_prefix``.

        Raises the original exception after rollback is complete.
        """
        # --- Phase 1: snapshot pre-write state (reads only, no mutations) ---
        pre_nodes: dict[str, Node | None] = {}
        pre_edges: dict[str, Edge | None] = {}
        for n in nodes:
            pre_nodes[n.id] = await self._graph.get_node(n.id)
        for e in edges:
            pre_edges[e.id] = await self._graph.get_edge(e.id)

        # Snapshot edge LWW clock entries for affected edge ids
        pre_edge_write_lv: dict[str, int] = {
            e.id: self._edge_write_lv[e.id]
            for e in edges
            if e.id in self._edge_write_lv
        }

        # --- Phase 2: write; rollback everything on any exception ---
        committed_node_ids: list[str] = []
        committed_edge_ids: list[str] = []
        appended_episode_ids: list[str] = []
        staged_knowledge_ids: list[str] = []
        staged_skill_ids: list[str] = []

        try:
            for node in nodes:
                await self.upsert_node(node)
                committed_node_ids.append(node.id)
            for edge in edges:
                await self.upsert_edge(edge)
                committed_edge_ids.append(edge.id)
            for ep in episodes:
                eid = await self.append_episode(ep)
                appended_episode_ids.append(eid)
            for ke in knowledge:
                kid = await self.propose_knowledge(ke)
                staged_knowledge_ids.append(kid)
            for sk in skills:
                sid = await self.propose_skill(sk)
                staged_skill_ids.append(sid)
        except Exception:
            await self._rollback_apply(
                committed_node_ids=committed_node_ids,
                committed_edge_ids=committed_edge_ids,
                appended_episode_ids=appended_episode_ids,
                staged_knowledge_ids=staged_knowledge_ids,
                staged_skill_ids=staged_skill_ids,
                pre_nodes=pre_nodes,
                pre_edges=pre_edges,
                pre_edge_write_lv=pre_edge_write_lv,
            )
            raise

    async def _rollback_apply(
        self,
        *,
        committed_node_ids: list[str],
        committed_edge_ids: list[str],
        appended_episode_ids: list[str],
        staged_knowledge_ids: list[str],
        staged_skill_ids: list[str],
        pre_nodes: dict[str, Node | None],
        pre_edges: dict[str, Edge | None],
        pre_edge_write_lv: dict[str, int],
    ) -> None:
        """Undo all writes committed so far in a failed apply_deltas batch."""
        logger.warning(
            "apply_deltas rollback: nodes=%d edges=%d episodes=%d knowledge=%d skills=%d",
            len(committed_node_ids), len(committed_edge_ids),
            len(appended_episode_ids), len(staged_knowledge_ids),
            len(staged_skill_ids),
        )

        # Rollback skills (reverse write order)
        for sid in reversed(staged_skill_ids):
            async with self._staging_lock:
                self._staged_skills.pop(sid, None)

        # Rollback knowledge proposals
        for kid in reversed(staged_knowledge_ids):
            async with self._staging_lock:
                self._staged_knowledge.pop(kid, None)

        # Rollback episodes via the store's private rollback method (if available)
        if appended_episode_ids:
            rollback_fn = getattr(self._episodic, _EPISODIC_ROLLBACK_METHOD, None)
            if rollback_fn is not None:
                await rollback_fn(appended_episode_ids)
                for eid in appended_episode_ids:
                    await self._lexical.remove(eid)
            else:
                logger.warning(
                    "apply_deltas rollback: EpisodicStore %r has no %r method; "
                    "%d episode(s) cannot be rolled back",
                    type(self._episodic).__name__,
                    _EPISODIC_ROLLBACK_METHOD,
                    len(appended_episode_ids),
                )

        # Rollback edges (reverse write order)
        for eid in reversed(committed_edge_ids):
            pre = pre_edges.get(eid)
            if pre is None:
                # Edge was newly created — delete it and restore LWW clock state
                await self._graph.delete_edge(eid)
                await self._lexical.remove(eid)
                if self._embedder is not None:
                    await self._vector.remove(eid)
                self._edge_write_lv.pop(eid, None)
            else:
                # Edge was updated — restore old state
                await self._graph.put_edge(pre)
                old_et = _edge_text(pre)
                old_emeta: dict[str, Any] = {
                    "tier": Tier.working.value, "type": pre.type, "_text": old_et
                }
                await self._lexical.add(eid, old_et, old_emeta)
                if self._embedder is not None:
                    vecs = await self._embedder.embed([old_et])
                    await self._vector.add(eid, vecs[0], old_emeta)
                # Restore the pre-batch LWW clock entry
                if eid in pre_edge_write_lv:
                    self._edge_write_lv[eid] = pre_edge_write_lv[eid]

        # Rollback nodes (reverse write order)
        for nid in reversed(committed_node_ids):
            pre_node = pre_nodes.get(nid)
            if pre_node is None:
                # Node was newly created — delete it
                await self._graph.delete_node(nid)
                await self._lexical.remove(nid)
                if self._embedder is not None:
                    await self._vector.remove(nid)
            else:
                # Node was updated — restore old state
                await self._graph.put_node(pre_node)
                old_nt = _node_text(pre_node)
                old_nmeta: dict[str, Any] = {
                    "tier": Tier.working.value, "type": pre_node.type, "_text": old_nt
                }
                await self._lexical.add(nid, old_nt, old_nmeta)
                if self._embedder is not None:
                    vecs = await self._embedder.embed([old_nt])
                    await self._vector.add(nid, vecs[0], old_nmeta)

        # Bust retrieval cache: rolled-back entries must not be cached
        await self._kv.delete_prefix("retrieval:")

    # ------------------------------------------------------------------
    # Reflector promotion paths (only the Reflector worker calls these)
    # ------------------------------------------------------------------

    async def promote_knowledge(self, entry_id: str) -> bool:
        """Index a staged knowledge entry into the shared BM25/vector indexes with tier=semantic.

        There is no separate physical store for the semantic tier.  This call adds
        the entry to the same ``LexicalIndex`` and ``VectorIndex`` used by all
        tiers, tagged with ``"tier": Tier.semantic.value`` in the metadata so that
        retrieval can filter by tier.
        """
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
        logger.debug("promoted knowledge id=%s", entry_id)
        return True

    async def promote_skill(self, skill_id: str) -> bool:
        """Index a staged skill into the shared BM25/vector indexes with tier=procedural.

        There is no separate physical store for the procedural tier.  This call adds
        the skill to the same ``LexicalIndex`` and ``VectorIndex`` used by all tiers,
        tagged with ``"tier": Tier.procedural.value`` in the metadata so that
        retrieval can filter by tier.
        """
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
        logger.debug("promoted skill id=%s name=%s", skill_id, skill.name)
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
    # Conflict access and lifecycle management
    # ------------------------------------------------------------------

    async def get_conflicts(
        self,
        node_id: str | None = None,
        status: ConflictStatus | None = None,
    ) -> list[Conflict]:
        """Return conflict records, optionally filtered by node_id and/or status."""
        results = self._conflicts.values()
        if node_id is not None:
            results = (c for c in results if c.node_id == node_id)  # type: ignore[assignment]
        if status is not None:
            results = (c for c in results if c.status == status)  # type: ignore[assignment]
        return list(results)

    async def resolve_conflict(
        self, conflict_id: str, resolution: str | None = None
    ) -> bool:
        """Resolve a conflict explicitly (orchestrator override).

        If *resolution* is provided it is recorded as the human-readable
        description.  If omitted, the default policy
        (``resolve_by_policy``) is applied automatically.

        Returns ``True`` if the conflict is now resolved, ``False`` if the
        default policy could not determine a winner (tie on both confidence
        and logical_version) and no explicit *resolution* string was given.
        """
        c = self._conflicts.get(conflict_id)
        if c is None:
            return False
        if c.status != ConflictStatus.open:
            # Already settled — idempotent success
            return c.status in (ConflictStatus.resolved, ConflictStatus.superseded)
        if resolution is not None:
            # Explicit orchestrator override — accept as-is
            ts = now()
            c.status = ConflictStatus.resolved
            c.resolved = True
            c.resolution = resolution
            c.history.append({
                "event": "resolved_override",
                "timestamp": ts,
                "detail": resolution,
            })
            return True
        # Apply default policy
        return resolve_by_policy(c)

    async def auto_resolve_conflict(self, conflict_id: str) -> bool:
        """Apply the default resolution policy to an open conflict.

        Returns ``True`` if resolved, ``False`` if the conflict remains open
        (confidence and logical_version are tied — human intervention needed).
        """
        c = self._conflicts.get(conflict_id)
        if c is None:
            return False
        return resolve_by_policy(c)

    async def supersede_conflict(self, conflict_id: str, reason: str = "") -> bool:
        """Mark a conflict superseded (a later write made both claims moot)."""
        c = self._conflicts.get(conflict_id)
        if c is None:
            return False
        mark_superseded(c, reason)
        return True

    async def quarantine_conflict(self, conflict_id: str, reason: str = "") -> bool:
        """Quarantine a conflict — mark the contested field as untrusted."""
        c = self._conflicts.get(conflict_id)
        if c is None:
            return False
        mark_quarantined(c, reason)
        return True

    async def dependents_blocked_by(self, node_id: str, field_name: str) -> bool:
        """Return True if any open conflict blocks use of node_id.field_name."""
        for c in self._conflicts.values():
            if c.node_id == node_id and c.field_name == field_name:
                if c.status == ConflictStatus.open:
                    return True
        return False

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
