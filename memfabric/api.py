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

Transaction safety:
  ``_graph_lock`` is the single transaction boundary for all graph mutations.
  Every ``upsert_node``, ``upsert_edge``, and ``apply_deltas`` acquires this
  lock for the full read-modify-write cycle so no concurrent writer can
  interleave between a graph read and its paired write.

  Internal helpers ``_upsert_node_locked`` and ``_upsert_edge_locked`` contain
  the merge logic and require the caller to hold ``_graph_lock``.  The public
  ``upsert_node`` / ``upsert_edge`` acquire the lock then delegate.
  ``apply_deltas`` acquires the lock once for the entire batch.

  Never hold ``_graph_lock`` while performing I/O outside the graph store
  (tool execution, LLM calls, browser automation, embedding large batches,
  reranking, generating reports, or unrelated filesystem work).  The reference
  implementation's in-memory stores perform no such I/O, so holding the lock
  during ``_refresh_working_indexes`` is safe for the reference case.

  For multi-process deployments, replace ``asyncio.Lock`` with a distributed
  advisory lock backed by the same durable store that hosts the graph.

  ``_write_clock`` is always restored to its pre-batch value when
  ``_rollback_locked`` runs, so a failed batch leaves no version-sequence gaps
  that could cause a subsequent write's logical_version to skip ahead (F02/F19).

Reader isolation:
  ``get_subgraph()``, ``open_tasks()``, and the subgraph-attachment path in
  ``query()`` each acquire ``_graph_lock`` for the duration of their graph
  reads.  This guarantees they always see a complete committed batch state —
  no partial ``apply_deltas`` write can interleave.  Callers that already hold
  ``_graph_lock`` must call ``self._graph.*`` methods directly to avoid
  deadlock (``asyncio.Lock`` is NOT reentrant).

Public deletion:
  ``delete_node`` and ``delete_edge`` acquire ``_graph_lock`` and delegate to
  the ``_delete_node_locked`` / ``_delete_edge_locked`` helpers, which remove
  entries from the graph, lexical index, and optional vector index.  Callers
  handle the retrieval cache bust explicitly after the last deletion in a batch.
"""
from __future__ import annotations

import asyncio
import copy
import logging
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence

from memfabric.coordination.conflict import (
    choose_conflict_winner,
    make_conflict,
    mark_quarantined,
    mark_superseded,
)
from memfabric.ids import new_id, now
from memfabric.types import (
    ALL_TIERS,
    BlockedClaim,
    Conflict,
    ConflictStatus,
    Edge,
    Episode,
    EvidenceBundle,
    KnowledgeEntry,
    Node,
    OpenTask,
    RetrievalDiagnostics,
    ScoredEntry,
    Skill,
    SkillOutcomeDisposition,
    SubgraphView,
    Tier,
    TransactionCapabilityError,
    TransactionIntegrityError,
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

# _EPISODIC_ROLLBACK_METHOD is the name of the private rollback method that
# in-memory EpisodicStore implementations may expose.  When present, apply_deltas
# calls it on failure to undo any episodes appended during the failed batch.
_EPISODIC_ROLLBACK_METHOD = "_pop_episodes"


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

        # Auxiliary "still pending" index sets (Phase 4 knowledge-init
        # performance fix). Mirrors of the staging dicts' own promotion
        # state, maintained incrementally by propose_knowledge/
        # promote_knowledge/propose_skill/promote_skill/quarantine_skill
        # (and unwound on apply_deltas rollback) so that
        # get_staged_knowledge(promoted=False) / get_staged_skills(
        # promoted=False, quarantined=False) — the exact filter the
        # Reflector's promotion gate and the startup promotion loop use on
        # every pass — can look up "what's left to do" in O(remaining)
        # instead of scanning every entry in the staging dict (including
        # already-promoted ones) on every call. This is what makes a large
        # bounded-pass promotion loop O(total staged) overall rather than
        # O(total staged × passes). Never the ordering/write authority for
        # anything — purely a derived index of the two staging dicts above,
        # kept in lockstep with them under the same _staging_lock.
        self._unpromoted_knowledge_ids: set[str] = set()
        self._unpromoted_active_skill_ids: set[str] = set()  # not promoted, not quarantined

        # Conflict log — conflicts are accumulated here
        self._conflicts: dict[str, Conflict] = {}

        self._staging_lock = asyncio.Lock()

        # Single transaction boundary for all graph mutations.
        # All upsert_node / upsert_edge / apply_deltas calls acquire this lock
        # for the entire read-modify-write cycle so concurrent writers cannot
        # interleave between a graph read and its paired write.
        # Lock nesting order (always outermost → innermost):
        #   _graph_lock → _staging_lock → GraphStore._lock
        # Never acquire in reverse order; _staging_lock is never held while
        # waiting for _graph_lock anywhere in this file.
        self._graph_lock = asyncio.Lock()

        # Monotonic write clock — incremented on every graph write (upsert_node,
        # upsert_edge).  Stored in per-field provenance as "logical_version".
        # LWW ordering uses this counter as the primary key; wall-clock
        # timestamps are only a tie-breaker when logical_version is equal.
        # This prevents clock-skew on the caller's last_seen field from
        # silently winning over a logically later write.
        self._write_clock: int = 0
        # Per-edge write version: edge_id → logical_version of last accepted write.
        self._edge_write_lv: dict[str, int] = {}

        # Monotonic run counter — incremented by advance_run_number() at the
        # start of each ReflectorWorker.run_once() call.  Used as the primary
        # ordering key for skill lifecycle events (retrieval, selection, execution,
        # decay, quarantine).  Skill fields store this value so that decay logic
        # can compare against a stable global clock rather than per-worker local
        # counters.
        self._completed_run_number: int = 0

        # Index generation counter — incremented by _advance_index_generation()
        # on every retrieval-affecting mutation (graph writes, promote_knowledge,
        # promote_skill, quarantine_skill).  Passed to HybridRetriever.search()
        # and included in the cache key so a post-mutation query always produces
        # a different key and gets a cache miss, even if delete_prefix were to
        # miss an entry.  Belt-and-suspenders with delete_prefix("retrieval:").
        self._index_generation: int = 0

    def set_retriever(self, retriever: HybridRetriever) -> None:
        self._retriever = retriever

    def _advance_index_generation(self) -> None:
        """Increment the index generation counter.

        Called on every retrieval-affecting mutation so that the next query()
        call uses a different cache key and gets a cache miss.  Works in
        conjunction with ``kv.delete_prefix("retrieval:")`` — both are called
        together to provide belt-and-suspenders cache invalidation:

        - ``delete_prefix`` immediately evicts all current cache entries.
        - ``_advance_index_generation`` ensures that any cache entry that
          survived deletion (e.g. in a different KVStore shard) produces a
          key mismatch on the next query.
        """
        self._index_generation += 1

    async def _refresh_working_indexes(
        self, entry_id: str, text: str, entry_type: str
    ) -> None:
        """Update lexical (and optionally vector) index and bust retrieval cache.

        Called synchronously from ``_upsert_node_locked`` and
        ``_upsert_edge_locked`` (inside ``_graph_lock``) so that the next
        ``query()`` call sees the current graph state.

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
        #    query is re-executed against the updated indexes.  Also advance
        #    the index generation so the new cache key differs from any entry
        #    that survived deletion (belt-and-suspenders).
        await self._kv.delete_prefix("retrieval:")
        self._advance_index_generation()

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

        **Query snapshot consistency — Option C (explicit narrow guarantee):**

        This method provides *two independent* consistency guarantees:

        1. **Graph-subgraph snapshot consistency**: when ``subgraph_anchor`` is
           supplied, the subgraph is fetched under ``_graph_lock`` and always
           reflects a single, complete, committed graph version.  A concurrent
           ``apply_deltas`` batch cannot produce a partial subgraph view.

        2. **Lexical / vector channel freshness**: the ``retriever.search()``
           call runs *outside* ``_graph_lock`` and reads the BM25/vector indexes
           at the committed state that exists when each channel fires.  In the
           typical sequential case (no concurrent writers), both channels see the
           same committed version.  A **mixed-version result** is possible when a
           concurrent writer commits between the ``retriever.search()`` return and
           the subgraph fetch under the lock.  In that case the lexical/vector
           evidence reflects version N while the subgraph reflects version N+1.

        **Rationale for Option C**: the BM25 index (``rank_bm25``) does not
        expose an immutable-snapshot read path, so holding ``_graph_lock``
        during the full retrieval search would violate the documented rule
        "never hold ``_graph_lock`` while performing I/O outside the graph
        store."  Option C (explicit narrow guarantee) is the correct documented
        contract for the reference implementation.

        **Callers that require full cross-channel snapshot consistency** should
        use ``get_subgraph()`` (always consistent) and call ``MemoryAPI.query()``
        without a concurrent writer, or use a single-writer pattern.
        """
        entries: list[ScoredEntry] = []
        diagnostics: RetrievalDiagnostics | None = None

        if self._retriever is not None and text:
            entries, diagnostics = await self._retriever.search(
                text=text,
                k=k,
                tiers=list(tiers),
                filters=dict(filters) if filters else None,
                index_generation=self._index_generation,
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
            # Acquire _graph_lock so the subgraph read sees a complete committed
            # batch state — no partial apply_deltas write can interleave here.
            async with self._graph_lock:
                subgraph = await self._graph.get_subgraph(subgraph_anchor, depth=2)

        blocked: list[BlockedClaim] = (
            self._collect_open_conflicts(subgraph) if subgraph is not None else []
        )
        quarantined: list[BlockedClaim] = (
            self._collect_quarantined_fields(subgraph) if subgraph is not None else []
        )
        if subgraph is not None:
            subgraph.open_conflicts = blocked
            subgraph.quarantined_fields = quarantined
        return EvidenceBundle(
            query=text or "",
            entries=entries,
            subgraph=subgraph,
            tiers_queried=[t.value for t in tiers],
            blocked_fields=blocked,
            quarantined_fields=quarantined,
            diagnostics=diagnostics,
        )

    async def get_subgraph(
        self,
        anchor_node: str,
        depth: int,
        edge_types: Sequence[str] | None = None,
    ) -> SubgraphView:
        """Return a defensive-copy subgraph rooted at *anchor_node*.

        Acquires ``_graph_lock`` so the caller always sees a complete,
        committed batch state — a concurrent ``apply_deltas`` cannot produce
        a partial view.  Callers that already hold ``_graph_lock`` must call
        ``self._graph.get_subgraph()`` directly to avoid a deadlock
        (``asyncio.Lock`` is NOT reentrant).

        The returned ``SubgraphView.open_conflicts`` is populated with all
        open ``Conflict`` records whose ``node_id`` is in the subgraph.
        Planners and capability extractors must skip any field listed there.
        """
        async with self._graph_lock:
            subgraph = await self._graph.get_subgraph(anchor_node, depth, edge_types)
        subgraph.open_conflicts = self._collect_open_conflicts(subgraph)
        subgraph.quarantined_fields = self._collect_quarantined_fields(subgraph)
        return subgraph

    def _collect_open_conflicts(self, subgraph: SubgraphView) -> list[BlockedClaim]:
        """Return BlockedClaim records for all open conflicts on nodes in *subgraph*.

        Only ``open`` conflicts block — resolved, superseded, and quarantined
        conflicts are excluded.  Scans ``_conflicts`` once; O(C) where C is the
        total number of recorded conflict records.
        """
        node_ids = {n.id for n in subgraph.nodes}
        node_type_map = {n.id: n.type for n in subgraph.nodes}
        blocked: list[BlockedClaim] = []
        for c in self._conflicts.values():
            if c.status == ConflictStatus.open and c.node_id in node_ids:
                blocked.append(
                    BlockedClaim(
                        node_id=c.node_id,
                        field_name=c.field_name,
                        conflict_id=c.id,
                        node_type=node_type_map.get(c.node_id, ""),
                    )
                )
        return blocked

    def _collect_quarantined_fields(self, subgraph: SubgraphView) -> list[BlockedClaim]:
        """Return BlockedClaim records for quarantined conflicts on nodes in *subgraph*.

        Quarantined conflicts do NOT block execution (they are not ``open``), but
        the contested field must be treated as **absent** — not as a trusted value.
        Planners and capability extractors that see a field in this list must skip
        that field exactly as they skip an open-conflict field.
        """
        node_ids = {n.id for n in subgraph.nodes}
        node_type_map = {n.id: n.type for n in subgraph.nodes}
        quarantined: list[BlockedClaim] = []
        for c in self._conflicts.values():
            if c.status == ConflictStatus.quarantined and c.node_id in node_ids:
                quarantined.append(
                    BlockedClaim(
                        node_id=c.node_id,
                        field_name=c.field_name,
                        conflict_id=c.id,
                        node_type=node_type_map.get(c.node_id, ""),
                    )
                )
        return quarantined

    # ------------------------------------------------------------------
    # WRITE: working memory deletions (public, lock-serialised)
    # ------------------------------------------------------------------

    async def _delete_node_locked(self, node_id: str) -> None:
        """Remove a node from the graph and lexical/vector indexes.

        Caller MUST hold ``self._graph_lock`` before calling this method.
        Does NOT bust the retrieval cache — callers are responsible for calling
        ``kv.delete_prefix("retrieval:")`` after all deletions in a batch.
        """
        await self._graph.delete_node(node_id)
        await self._lexical.remove(node_id)
        if self._embedder is not None:
            await self._vector.remove(node_id)

    async def _delete_edge_locked(self, edge_id: str) -> None:
        """Remove an edge from the graph and lexical/vector indexes.

        Caller MUST hold ``self._graph_lock`` before calling this method.
        Also removes the edge's LWW clock entry from ``_edge_write_lv``.
        Does NOT bust the retrieval cache — callers handle that after the batch.
        """
        self._edge_write_lv.pop(edge_id, None)
        await self._graph.delete_edge(edge_id)
        await self._lexical.remove(edge_id)
        if self._embedder is not None:
            await self._vector.remove(edge_id)

    async def delete_node(self, node_id: str) -> None:
        """Remove a node and keep all indexes coherent.

        Intended for parsers that need to retract an incorrectly-written node.
        Acquires ``_graph_lock``, removes from graph + lexical + vector, and
        busts the retrieval cache.
        """
        async with self._graph_lock:
            await self._delete_node_locked(node_id)
            await self._kv.delete_prefix("retrieval:")
        logger.debug("delete_node id=%s", node_id)

    async def delete_edge(self, edge_id: str) -> None:
        """Remove an edge and keep all indexes coherent.

        Acquires ``_graph_lock``, removes from graph + lexical + vector (and
        ``_edge_write_lv``), and busts the retrieval cache.
        """
        async with self._graph_lock:
            await self._delete_edge_locked(edge_id)
            await self._kv.delete_prefix("retrieval:")
        logger.debug("delete_edge id=%s", edge_id)

    # ------------------------------------------------------------------
    # WRITE: working memory (upsert, per-field LWW + provenance)
    # ------------------------------------------------------------------

    async def _upsert_node_locked(self, node: Node) -> str:
        """Merge *node* field-by-field into any existing node.

        Caller MUST hold ``self._graph_lock`` before calling this method.
        Use the public ``upsert_node`` for external callers.

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

    async def upsert_node(self, node: Node) -> str:
        """Acquire the graph transaction lock and merge *node* into the EKG.

        The lock serialises this call's read-modify-write cycle with all other
        concurrent graph writers.  Two callers updating disjoint fields on the
        same node both survive: the second writer reads the first writer's
        committed state and merges on top of it rather than overwriting it.
        """
        async with self._graph_lock:
            return await self._upsert_node_locked(node)

    async def _upsert_edge_locked(self, edge: Edge) -> str:
        """Insert or replace an edge (whole-edge LWW — no per-field merging).

        Caller MUST hold ``self._graph_lock`` before calling this method.
        Use the public ``upsert_edge`` for external callers.

        LWW ordering uses the same logical_version policy as ``_upsert_node_locked``:
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

    async def upsert_edge(self, edge: Edge) -> str:
        """Acquire the graph transaction lock and insert/replace *edge*.

        The lock serialises this call's read-modify-write cycle with all other
        concurrent graph writers so the LWW decision is always based on an
        authoritative ``_write_clock`` snapshot.
        """
        async with self._graph_lock:
            return await self._upsert_edge_locked(edge)

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
            # Keep the pending-index in sync: a (re-)proposed entry starts
            # (or resets to) whatever promoted state it carries. Re-staging
            # an id that was previously promoted with a fresh, unpromoted
            # entry correctly re-adds it to the pending set.
            if entry.promoted:
                self._unpromoted_knowledge_ids.discard(entry.id)
            else:
                self._unpromoted_knowledge_ids.add(entry.id)
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
            if skill.promoted or skill.quarantined:
                self._unpromoted_active_skill_ids.discard(skill.id)
            else:
                self._unpromoted_active_skill_ids.add(skill.id)
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

        The entire graph portion of the batch (nodes + edges) executes under
        ``_graph_lock``.  This serialises the batch with concurrent single-item
        writers and prevents partial state from being observed by readers.

        Write order within the batch: nodes → edges → episodes →
        knowledge proposals → skill proposals.  A failure at any step rolls
        back everything committed earlier in the same batch.

        Rollback strategy (in-memory reference stores):
          - Nodes / edges: pre-write snapshots are captured before the batch
            starts.  On rollback, existing entries are restored to their
            pre-batch state via ``put_node`` / ``put_edge``; newly created
            entries are deleted via ``delete_node`` / ``delete_edge``.
          - ``_write_clock`` is restored to its pre-batch value so version
            sequence gaps cannot accumulate across failed batches (F02/F19).
          - Lexical and vector indexes are restored to match the rolled-back
            graph state.
          - Episodes: if the ``EpisodicStore`` exposes a private
            ``_pop_episodes`` method (as ``JSONLEpisodicStore`` does), it is
            called to remove any episodes appended during the failed batch.
            Durable stores without this method will log a warning.
          - Knowledge / skill proposals: removed from the staging dicts.
          - Retrieval cache: invalidated after rollback via ``delete_prefix``.

        Raises the original exception after rollback is complete, or
        ``TransactionIntegrityError`` if rollback itself fails.

        **Episode capability pre-check:**
        If *episodes* is non-empty, the episodic store must expose
        ``_pop_episodes`` for rollback support.  If it does not, a
        ``TransactionCapabilityError`` is raised **before any writes begin**,
        preserving the all-or-nothing invariant.  Callers that use an episodic
        store without rollback support must either supply ``episodes=()`` or
        use ``append_episode()`` directly (which has no rollback guarantee).
        """
        # --- Episode capability pre-check (before acquiring any lock) ---
        if episodes:
            _pop_fn = getattr(self._episodic, _EPISODIC_ROLLBACK_METHOD, None)
            if _pop_fn is None:
                raise TransactionCapabilityError(
                    store_type=type(self._episodic).__name__,
                    missing_cap=_EPISODIC_ROLLBACK_METHOD,
                    reason=(
                        f"apply_deltas with episodes requires the episodic store to "
                        f"expose '{_EPISODIC_ROLLBACK_METHOD}' for rollback support. "
                        f"Use append_episode() directly if rollback is not needed, "
                        f"or supply episodes=()."
                    ),
                )

        async with self._graph_lock:
            # Snapshot pre-batch write clock so rollback can restore it (F02/F19).
            pre_clock: int = self._write_clock

            # --- Phase 1: snapshot pre-write state (reads; no mutations yet) ---
            # ALL affected node and edge snapshots are captured here, before the
            # FIRST store mutation.  A failure during Phase 1 leaves the graph
            # unchanged (no writes have started yet).
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
                    # Use the locked variant: _graph_lock is already held.
                    # Calling the public upsert_node would deadlock (re-acquire).
                    await self._upsert_node_locked(node)
                    committed_node_ids.append(node.id)
                for edge in edges:
                    await self._upsert_edge_locked(edge)
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
            except Exception as _tx_err:
                await self._rollback_locked(
                    original_error=_tx_err,
                    pre_clock=pre_clock,
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

    async def _rollback_locked(
        self,
        *,
        original_error: Exception,
        pre_clock: int,
        committed_node_ids: list[str],
        committed_edge_ids: list[str],
        appended_episode_ids: list[str],
        staged_knowledge_ids: list[str],
        staged_skill_ids: list[str],
        pre_nodes: dict[str, Node | None],
        pre_edges: dict[str, Edge | None],
        pre_edge_write_lv: dict[str, int],
    ) -> None:
        """Undo all writes committed so far in a failed apply_deltas batch.

        Caller MUST hold ``self._graph_lock``.

        Restores ``_write_clock`` to *pre_clock* so that subsequent writes
        receive the same logical_version sequence as if the failed batch had
        never run (F02/F19 fix).  The version integers consumed during the
        failed batch are discarded; they will never appear in provenance.

        **Rollback failure handling:**
        If any step in the rollback procedure itself raises an exception, the
        rollback continues attempting subsequent steps (best-effort), then
        raises ``TransactionIntegrityError`` with:
        - ``original_error``: the exception that triggered rollback
        - ``rollback_errors``: all exceptions raised during rollback
        - ``affected_ids``: the IDs of nodes/edges/episodes partially committed
        - ``stage``: the name of the rollback stage where the first error occurred

        When ``TransactionIntegrityError`` is raised, the store state is
        **undefined**.  The caller must reinitialise the store or replay from
        the last known-good checkpoint.
        """
        logger.warning(
            "apply_deltas rollback: nodes=%d edges=%d episodes=%d knowledge=%d skills=%d",
            len(committed_node_ids), len(committed_edge_ids),
            len(appended_episode_ids), len(staged_knowledge_ids),
            len(staged_skill_ids),
        )

        rollback_errors: list[Exception] = []
        first_error_stage: str = ""
        affected_ids: list[str] = (
            committed_node_ids
            + committed_edge_ids
            + appended_episode_ids
            + staged_knowledge_ids
            + staged_skill_ids
        )

        def _record(stage: str, exc: Exception) -> None:
            nonlocal first_error_stage
            if not first_error_stage:
                first_error_stage = stage
            rollback_errors.append(exc)
            logger.error("rollback step failed [%s]: %r", stage, exc)

        # Restore the write clock FIRST so any code that reads _write_clock
        # after this rollback sees a consistent value (F02/F19).
        self._write_clock = pre_clock

        # Rollback skills (reverse write order)
        for sid in reversed(staged_skill_ids):
            try:
                async with self._staging_lock:
                    self._staged_skills.pop(sid, None)
                    # Pending-index (Phase 4): the entry is gone entirely,
                    # so it can no longer be "pending" either.
                    self._unpromoted_active_skill_ids.discard(sid)
            except Exception as exc:
                _record("skill_rollback", exc)

        # Rollback knowledge proposals
        for kid in reversed(staged_knowledge_ids):
            try:
                async with self._staging_lock:
                    self._staged_knowledge.pop(kid, None)
                    self._unpromoted_knowledge_ids.discard(kid)
            except Exception as exc:
                _record("knowledge_rollback", exc)

        # Rollback episodes via the store's private rollback method.
        # The capability pre-check in apply_deltas() guarantees this method
        # is present whenever appended_episode_ids is non-empty, but we guard
        # defensively here in case _rollback_locked is called from outside
        # apply_deltas.
        if appended_episode_ids:
            rollback_fn = getattr(self._episodic, _EPISODIC_ROLLBACK_METHOD, None)
            if rollback_fn is not None:
                try:
                    await rollback_fn(appended_episode_ids)
                    for ep_id in appended_episode_ids:
                        try:
                            await self._lexical.remove(ep_id)
                        except Exception as exc:
                            _record("episode_lexical_rollback", exc)
                except Exception as exc:
                    _record("episode_rollback", exc)
            else:
                # Should not reach here if the capability pre-check ran, but
                # log clearly in case _rollback_locked is called standalone.
                msg = (
                    f"EpisodicStore {type(self._episodic).__name__!r} has no "
                    f"'{_EPISODIC_ROLLBACK_METHOD}' method; "
                    f"{len(appended_episode_ids)} episode(s) cannot be rolled back"
                )
                logger.error("rollback step failed [episode_capability]: %s", msg)
                rollback_errors.append(RuntimeError(msg))
                if not first_error_stage:
                    first_error_stage = "episode_capability"

        # Rollback edges (reverse write order)
        for eid in reversed(committed_edge_ids):
            try:
                pre = pre_edges.get(eid)
                if pre is None:
                    await self._delete_edge_locked(eid)
                else:
                    await self._graph.put_edge(pre)
                    old_et = _edge_text(pre)
                    old_emeta: dict[str, Any] = {
                        "tier": Tier.working.value, "type": pre.type, "_text": old_et
                    }
                    await self._lexical.add(eid, old_et, old_emeta)
                    if self._embedder is not None:
                        vecs = await self._embedder.embed([old_et])
                        await self._vector.add(eid, vecs[0], old_emeta)
                    if eid in pre_edge_write_lv:
                        self._edge_write_lv[eid] = pre_edge_write_lv[eid]
            except Exception as exc:
                _record(f"edge_rollback({eid})", exc)

        # Rollback nodes (reverse write order)
        for nid in reversed(committed_node_ids):
            try:
                pre_node = pre_nodes.get(nid)
                if pre_node is None:
                    await self._delete_node_locked(nid)
                else:
                    await self._graph.put_node(pre_node)
                    old_nt = _node_text(pre_node)
                    old_nmeta: dict[str, Any] = {
                        "tier": Tier.working.value, "type": pre_node.type, "_text": old_nt
                    }
                    await self._lexical.add(nid, old_nt, old_nmeta)
                    if self._embedder is not None:
                        vecs = await self._embedder.embed([old_nt])
                        await self._vector.add(nid, vecs[0], old_nmeta)
            except Exception as exc:
                _record(f"node_rollback({nid})", exc)

        # Bust retrieval cache: rolled-back entries must not be cached
        try:
            await self._kv.delete_prefix("retrieval:")
        except Exception as exc:
            _record("cache_bust", exc)

        if rollback_errors:
            raise TransactionIntegrityError(
                original_error=original_error,
                rollback_errors=rollback_errors,
                affected_ids=affected_ids,
                stage=first_error_stage,
            )

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
            self._unpromoted_knowledge_ids.discard(entry_id)

        _kt = _knowledge_text(entry)
        # Merge entry.metadata so host-supplied fields (e.g. source_family,
        # source_type) are available in retrieval results for filtering.
        # Core keys always win over user metadata to preserve tier integrity.
        _kmeta: dict[str, Any] = {**entry.metadata, "tier": Tier.semantic.value, "source": entry.source, "_text": _kt}
        await self._lexical.add(entry.id, _kt, _kmeta)
        if entry.embedding:
            _vmeta: dict[str, Any] = {**entry.metadata, "tier": Tier.semantic.value, "source": entry.source}
            await self._vector.add(entry.id, entry.embedding, _vmeta)
        # Bust retrieval cache so the newly promoted entry appears in the next query.
        await self._kv.delete_prefix("retrieval:")
        self._advance_index_generation()
        logger.debug("promoted knowledge id=%s", entry_id)
        return True

    async def promote_skill(self, skill_id: str) -> bool:
        """Index a staged skill into the shared BM25/vector indexes with tier=procedural.

        There is no separate physical store for the procedural tier.  This call adds
        the skill to the same ``LexicalIndex`` and ``VectorIndex`` used by all tiers,
        tagged with ``"tier": Tier.procedural.value`` in the metadata so that
        retrieval can filter by tier.

        Sets ``skill.promoted_run_number`` to the current ``_completed_run_number``
        so that the decay grace-period logic can suppress early decay.
        """
        async with self._staging_lock:
            skill = self._staged_skills.get(skill_id)
            if skill is None:
                return False
            skill.promoted = True
            skill.promoted_run_number = self._completed_run_number
            self._unpromoted_active_skill_ids.discard(skill_id)

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
        # Bust retrieval cache so the newly promoted skill appears in the next query.
        await self._kv.delete_prefix("retrieval:")
        self._advance_index_generation()
        logger.debug("promoted skill id=%s name=%s", skill_id, skill.name)
        return True

    async def decay_skill(
        self,
        skill_id: str,
        factor: float,
        *,
        current_run_number: int | None = None,
        confidence_floor: float = 0.0,
    ) -> bool:
        """Reduce skill confidence by *factor* (Reflector decay).

        Idempotence: if ``current_run_number`` is provided and equals
        ``skill.last_decay_run_number``, the decay is skipped.  This prevents
        the same skill from being decayed twice in a single Reflector pass.

        ``confidence_floor`` sets the minimum confidence after decay.  Default 0.0
        (matches legacy behaviour).
        """
        async with self._staging_lock:
            skill = self._staged_skills.get(skill_id)
            if skill is None:
                return False
            # Idempotence guard: skip if already decayed this run.
            if (
                current_run_number is not None
                and skill.last_decay_run_number == current_run_number
            ):
                return False
            skill.confidence = max(confidence_floor, skill.confidence * factor)
            if current_run_number is not None:
                skill.last_decay_run_number = current_run_number
        return True

    async def quarantine_skill(
        self,
        skill_id: str,
        *,
        reason: str = "",
        current_run_number: int | None = None,
    ) -> bool:
        """Mark a skill as quarantined (removed from retrieval).

        ``reason`` is stored in ``skill.quarantine_reason`` for audit purposes.
        Defaults to ``"winrate_below_floor"`` when empty.

        ``current_run_number`` is stored in ``skill.quarantined_run_number`` for
        provenance — which Reflector pass triggered the quarantine.
        """
        async with self._staging_lock:
            skill = self._staged_skills.get(skill_id)
            if skill is None:
                return False
            skill.quarantined = True
            skill.quarantine_reason = reason if reason else "winrate_below_floor"
            skill.quarantined_at = now()
            if current_run_number is not None:
                skill.quarantined_run_number = current_run_number
            self._unpromoted_active_skill_ids.discard(skill_id)

        # Remove from lexical/vector indexes and bust retrieval cache so the
        # quarantined skill is no longer returned by the next query.
        await self._lexical.remove(skill_id)
        await self._vector.remove(skill_id)
        await self._kv.delete_prefix("retrieval:")
        self._advance_index_generation()
        logger.info("quarantined skill id=%s reason=%s", skill_id, skill.quarantine_reason)
        return True

    async def update_skill_result(self, skill_id: str, *, won: bool) -> bool:
        """Record a win or loss for a skill (Reflector tracking).

        Legacy method kept for backward compatibility.  New code should prefer
        ``record_skill_execution()`` which also updates ``execution_count`` and
        lifecycle timestamps.
        """
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
    # Phase 3 lifecycle methods
    # ------------------------------------------------------------------

    async def advance_run_number(self) -> int:
        """Increment and return the monotonic completed-run counter.

        Called once at the start of each ``ReflectorWorker.run_once()`` pass.
        The returned value is stored in ``skill.last_*_run_number`` fields so
        that decay logic and usage tracking share a global ordering key rather
        than local per-worker counters.
        """
        self._completed_run_number += 1
        return self._completed_run_number

    async def record_skill_retrieved(
        self,
        skill_ids: list[str],
        *,
        run_number: int,
    ) -> None:
        """Record that one or more skills appeared in a retrieval result.

        Updates ``retrieval_count``, ``last_retrieved_run_number``,
        ``last_retrieved_at``, and ``last_used_run_number`` for each listed skill.
        Skills not found in the staging dict are silently skipped (they may have
        been quarantined or promoted to a different index).
        """
        _now = now()
        async with self._staging_lock:
            for sid in skill_ids:
                skill = self._staged_skills.get(sid)
                if skill is None:
                    continue
                skill.retrieval_count += 1
                skill.last_retrieved_run_number = run_number
                skill.last_retrieved_at = _now
                skill.last_used_run_number = run_number

    async def record_skill_selected(self, skill_id: str, *, run_number: int) -> None:
        """Record that a planner selected a skill as the execution template.

        Updates ``selection_count``, ``last_selected_run_number``,
        ``last_selected_at``, and ``last_used_run_number``.
        """
        _now = now()
        async with self._staging_lock:
            skill = self._staged_skills.get(skill_id)
            if skill is None:
                return
            skill.selection_count += 1
            skill.last_selected_run_number = run_number
            skill.last_selected_at = _now
            skill.last_used_run_number = run_number

    async def record_skill_execution(
        self,
        skill_id: str,
        *,
        run_number: int,
        disposition: SkillOutcomeDisposition,
    ) -> None:
        """Record the outcome of a skill execution.

        Always increments ``execution_count``, ``last_executed_run_number``,
        ``last_executed_at``, and ``last_used_run_number``.

        ``disposition`` controls win/loss accounting:
        - ``WIN`` → ``wins += 1``
        - ``LOSS`` → ``losses += 1``
        - ``NEUTRAL`` / ``NOT_EXECUTED`` → no change to wins/losses
        """
        _now = now()
        async with self._staging_lock:
            skill = self._staged_skills.get(skill_id)
            if skill is None:
                return
            skill.execution_count += 1
            skill.last_executed_run_number = run_number
            skill.last_executed_at = _now
            skill.last_used_run_number = run_number
            if disposition == SkillOutcomeDisposition.WIN:
                skill.wins += 1
            elif disposition == SkillOutcomeDisposition.LOSS:
                skill.losses += 1
            # NEUTRAL and NOT_EXECUTED leave wins/losses unchanged.

    async def merge_skill_candidate(
        self,
        existing_skill_id: str,
        *,
        run_number: int,
    ) -> bool:
        """Atomically record a successful merge into an existing skill.

        This is the F21 fix: the Reflector previously mutated Skill objects
        returned by ``get_staged_skills()`` directly.  Those mutations bypassed
        ``_staging_lock`` and violated Invariant 1 (MemoryAPI is the only state
        surface).

        Now ``ReflectorWorker._generalise_and_propose()`` calls this method
        when a candidate matches an existing skill, and this method performs
        all mutations under ``_staging_lock``.

        Fields updated: ``wins``, ``evidence_count``, ``confidence``
        (exponential moving average toward 1.0), and ``last_used_run_number``.

        Returns ``False`` if the skill no longer exists in the staging dict
        (quarantined or expired between the lookup and this call).
        """
        async with self._staging_lock:
            skill = self._staged_skills.get(existing_skill_id)
            if skill is None:
                return False
            skill.wins += 1
            skill.evidence_count += 1
            skill.confidence = min(
                1.0,
                skill.confidence + 0.05 * (1.0 - skill.confidence),
            )
            skill.last_used_run_number = run_number
        logger.debug(
            "merged into skill id=%s wins=%d conf=%.3f",
            existing_skill_id, skill.wins, skill.confidence,
        )
        return True

    # ------------------------------------------------------------------
    # Staging read access (for Reflector)
    # ------------------------------------------------------------------

    async def get_staged_knowledge(
        self, *, promoted: bool | None = None
    ) -> list[KnowledgeEntry]:
        """Return deep copies of staged knowledge entries.

        Callers may safely inspect returned objects; mutations are silently
        ignored — they do not affect the staging dict.

        ``promoted`` (Phase 4 knowledge-initialization performance fix):
        optional filter — ``None`` (default) returns every staged entry,
        exactly as before this parameter existed (fully backward
        compatible). ``promoted=False`` is the fast path: it looks up
        ``_unpromoted_knowledge_ids`` (an index maintained incrementally by
        ``propose_knowledge``/``promote_knowledge``, never rebuilt by
        scanning) instead of scanning every entry in ``_staged_knowledge``
        — O(remaining unpromoted), not O(total staged). ``promoted=True``
        still scans (less performance-critical; no caller in this codebase
        is on a hot loop for "give me only the promoted ones").
        """
        async with self._staging_lock:
            if promoted is None:
                return [copy.deepcopy(e) for e in self._staged_knowledge.values()]
            if promoted is False:
                return [
                    copy.deepcopy(self._staged_knowledge[i])
                    for i in self._unpromoted_knowledge_ids
                    if i in self._staged_knowledge
                ]
            return [
                copy.deepcopy(e)
                for e in self._staged_knowledge.values()
                if e.promoted == promoted
            ]

    async def get_staged_skills(
        self, *, promoted: bool | None = None, quarantined: bool | None = None
    ) -> list[Skill]:
        """Return deep copies of staged skills.

        Callers may safely inspect returned objects; mutations are silently
        ignored — they do not affect the staging dict.  This is the F21 fix:
        the previous implementation returned live references that allowed
        callers to bypass ``_staging_lock`` by mutating the returned objects.

        ``promoted`` / ``quarantined`` (Phase 4 performance fix): optional
        filters, same semantics and backward-compatibility guarantee as
        ``get_staged_knowledge``'s ``promoted`` parameter — ``None`` (the
        default for both) reproduces the exact prior unfiltered behavior.
        ``promoted=False, quarantined=False`` (the exact filter the
        Reflector's promotion gate and the startup promotion loop use) is
        the fast path: it looks up ``_unpromoted_active_skill_ids`` instead
        of scanning every staged skill.
        """
        async with self._staging_lock:
            if promoted is False and quarantined is False:
                return [
                    copy.deepcopy(self._staged_skills[i])
                    for i in self._unpromoted_active_skill_ids
                    if i in self._staged_skills
                ]
            skills: list[Skill] = list(self._staged_skills.values())
            if promoted is not None:
                skills = [s for s in skills if s.promoted == promoted]
            if quarantined is not None:
                skills = [s for s in skills if s.quarantined == quarantined]
            return [copy.deepcopy(s) for s in skills]

    async def count_staged_knowledge(self, *, promoted: bool | None = None) -> int:
        """Return the count of staged knowledge entries matching *promoted*, no copying.

        Phase 4 knowledge-initialization performance fix: a cheap O(N) scan
        (attribute read only, no ``copy.deepcopy``) for callers that only
        need a count — e.g. a startup promotion loop's before/after
        progress check. ``promoted=None`` counts every staged entry.
        """
        async with self._staging_lock:
            if promoted is None:
                return len(self._staged_knowledge)
            if promoted is False:
                return len(self._unpromoted_knowledge_ids)
            return sum(1 for e in self._staged_knowledge.values() if e.promoted == promoted)

    async def count_staged_skills(
        self, *, promoted: bool | None = None, quarantined: bool | None = None
    ) -> int:
        """Return the count of staged skills matching the given filters, no copying.

        Same rationale as ``count_staged_knowledge``. ``None`` for either
        filter means "do not filter on this field".
        """
        async with self._staging_lock:
            if promoted is False and quarantined is False:
                return len(self._unpromoted_active_skill_ids)
            count = 0
            for s in self._staged_skills.values():
                if promoted is not None and s.promoted != promoted:
                    continue
                if quarantined is not None and s.quarantined != quarantined:
                    continue
                count += 1
            return count

    async def select_unpromoted_knowledge_ids(
        self,
        predicate: Callable[[KnowledgeEntry], bool],
        *,
        limit: int | None = None,
    ) -> list[str]:
        """Return ids of unpromoted staged knowledge entries where predicate(entry) is True.

        Phase 4 knowledge-initialization performance fix. This is the
        genuinely bounded counterpart to ``get_staged_knowledge(promoted=
        False)``: that method still has to ``copy.deepcopy`` every entry it
        returns, so a caller (like the Reflector's promotion gate) that only
        needs to test a cheap, read-only condition and act on a handful of
        matching ids pays an unnecessary O(remaining unpromoted) deep-copy
        cost *every pass*, even when ``limit`` means only a few of those
        copies are ever used. That deep-copy — not the gate predicate
        itself — was the dominant remaining cost after the ``promoted=False``
        filtering fix (measured: ~85% of total promotion-loop wall time in a
        60k-record synthetic benchmark). This method evaluates *predicate*
        directly against the LIVE staged objects while ``_staging_lock`` is
        held and returns only their ids — no object ever leaves this method,
        so there is no risk of a caller mutating live staging state.

        *predicate* is caller-supplied (never imported by this module) so
        that ``MemoryAPI`` stays free of any promotion-policy knowledge
        (``memfabric.reflector.gates``'s pure functions remain the sole
        owner of promotion policy; this method is a generic "find ids
        matching a read-only condition, cheaply" primitive, analogous to
        ``count_staged_knowledge`` in spirit).

        Stops scanning as soon as ``limit`` matches have been found (when
        given); ``None`` scans every currently-unpromoted entry.
        """
        async with self._staging_lock:
            ids: list[str] = []
            for eid in self._unpromoted_knowledge_ids:
                entry = self._staged_knowledge.get(eid)
                if entry is not None and predicate(entry):
                    ids.append(eid)
                    if limit is not None and len(ids) >= limit:
                        break
            return ids

    async def select_unpromoted_active_skill_ids(
        self,
        predicate: Callable[[Skill], bool],
        *,
        limit: int | None = None,
    ) -> list[str]:
        """Return ids of unpromoted, non-quarantined staged skills where predicate(skill) is True.

        See ``select_unpromoted_knowledge_ids`` for the full rationale — same
        no-deep-copy, predicate-evaluated-on-live-objects design.
        """
        async with self._staging_lock:
            ids: list[str] = []
            for sid in self._unpromoted_active_skill_ids:
                skill = self._staged_skills.get(sid)
                if skill is not None and predicate(skill):
                    ids.append(sid)
                    if limit is not None and len(ids) >= limit:
                        break
            return ids

    # ------------------------------------------------------------------
    # Conflict access and lifecycle management
    # ------------------------------------------------------------------

    async def get_conflicts(
        self,
        node_id: str | None = None,
        status: ConflictStatus | None = None,
    ) -> list[Conflict]:
        """Return deep-copy conflict records, optionally filtered.

        Returns deep copies so callers cannot mutate stored ``claim_a``,
        ``claim_b``, ``history``, ``resolution``, or ``status``.  Mutation of
        returned objects is silently ignored — all lifecycle changes go through
        ``resolve_conflict``, ``auto_resolve_conflict``, ``supersede_conflict``,
        and ``quarantine_conflict``.
        """
        raw: list[Conflict] = [c for c in self._conflicts.values()]
        if node_id is not None:
            raw = [c for c in raw if c.node_id == node_id]
        if status is not None:
            raw = [c for c in raw if c.status == status]
        return [copy.deepcopy(c) for c in raw]

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
            # Explicit orchestrator override — accept as-is.
            # This path does not perform a graph write; the orchestrator is
            # asserting the resolution directly (e.g. human review outcome).
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
        # No explicit resolution — apply default policy atomically (graph write + index).
        async with self._graph_lock:
            return await self._apply_conflict_resolution_locked(conflict_id)

    async def auto_resolve_conflict(self, conflict_id: str) -> bool:
        """Apply the default resolution policy AND persist the winning value.

        The winning claim's value is written back to the graph field atomically
        under ``_graph_lock``.  If the graph write fails, the conflict is left
        open (rolled back to unresolved state).

        Returns ``True`` if the conflict was resolved and the graph was updated.
        Returns ``False`` if the conflict remains open (confidence and
        logical_version are tied, or the graph write failed).
        """
        async with self._graph_lock:
            return await self._apply_conflict_resolution_locked(conflict_id)

    async def _apply_conflict_resolution_locked(self, conflict_id: str) -> bool:
        """Resolve conflict and persist the winning value atomically.

        Caller MUST hold ``_graph_lock``.

        Contract (must not be violated):
          1. Pure winner selection via ``choose_conflict_winner`` — no mutation.
          2. Snapshot graph field, provenance, and complete conflict state.
          3. Write winning value to node in graph store.
          4. Refresh lexical (and optional vector) index.
          5. Invalidate retrieval cache.
          6. Append one ``resolved`` history entry.
          7. Set ``status``, ``resolved``, ``winning_value``, ``resolution``.

        If any stage 3-7 fails:
          - Restore graph field + provenance to pre-snapshot values.
          - Restore all conflict fields (status, resolved, winning_value,
            resolution) to pre-snapshot values.
          - Trim ``history`` back to pre-snapshot length.
          - Append a ``resolution_failed`` entry (non-terminal).
          - If the graph-restore write itself fails, raise
            ``TransactionIntegrityError`` — the store is in an unknown state.

        The conflict is NEVER marked resolved before all persistence succeeds.
        """
        c = self._conflicts.get(conflict_id)
        if c is None:
            return False
        if c.status != ConflictStatus.open:
            return True  # Already settled — idempotent success.

        # --- Stage 1: Pure winner selection (no mutation) ---
        decision = choose_conflict_winner(c)
        if decision is None:
            return True  # No longer open — shouldn't happen, but safe guard.

        if decision.winner == "tie":
            c.history.append({
                "event": "resolve_attempted",
                "timestamp": now(),
                "detail": decision.reason + "; remains open",
            })
            logger.info(
                "conflict unresolved (tied) node=%s field=%s id=%s",
                c.node_id, c.field_name, conflict_id,
            )
            return False

        # --- Stage 2: Look up node; supersede if deleted ---
        node = await self._graph.get_node(c.node_id)
        if node is None:
            mark_superseded(c, "node deleted before resolution could be applied")
            return True

        # --- Stage 3: Snapshot everything before any write ---
        pre_field_value = copy.deepcopy(node.props.get(c.field_name))
        pre_provenance = copy.deepcopy(node._provenance.get(c.field_name, {}))
        pre_status = c.status
        pre_resolved = c.resolved
        pre_winning_value = c.winning_value
        pre_resolution = c.resolution
        pre_history_len = len(c.history)

        # Prepare the winning provenance record (not written yet)
        resolution_str = (
            f"{decision.winner} wins — {decision.reason} "
            f"(value={decision.winning_value!r})"
        )
        prov_update = {
            "value": decision.winning_value,
            "resolution_conflict_id": conflict_id,
            "resolution_method": "auto_policy",
            "resolution_winner": decision.winner,
            "resolved_by": "MemoryAPI._apply_conflict_resolution_locked",
            "timestamp": now(),
        }

        # Mutate node in memory (not yet persisted)
        node.props[c.field_name] = decision.winning_value
        node._provenance[c.field_name] = {**pre_provenance, **prov_update}

        # --- Stages 4-7: Commit all stages with rollback on failure ---
        failed_stage = ""
        graph_write_succeeded = False
        rollback_errors: list[Exception] = []

        try:
            failed_stage = "graph_write"
            await self._graph.put_node(node)
            graph_write_succeeded = True

            failed_stage = "index_refresh"
            await self._refresh_working_indexes(
                node.id, _node_text(node), node.type
            )

            failed_stage = "history_append"
            c.history.append({
                "event": "resolved",
                "timestamp": now(),
                "detail": resolution_str,
            })

            failed_stage = "status_transition"
            c.status = ConflictStatus.resolved
            c.resolved = True
            c.winning_value = decision.winning_value
            c.resolution = resolution_str

            logger.info(
                "conflict resolved node=%s field=%s → %s id=%s",
                c.node_id, c.field_name, resolution_str, conflict_id,
            )
            return True

        except Exception as primary_exc:
            # --- Rollback ---
            # Restore node if the graph write succeeded.
            if graph_write_succeeded:
                node.props[c.field_name] = pre_field_value
                node._provenance[c.field_name] = pre_provenance
                try:
                    await self._graph.put_node(node)
                except Exception as re:
                    rollback_errors.append(re)
                try:
                    await self._refresh_working_indexes(
                        node.id, _node_text(node), node.type
                    )
                except Exception as re:
                    rollback_errors.append(re)

            # Restore conflict record.
            try:
                c.status = pre_status
                c.resolved = pre_resolved
                c.winning_value = pre_winning_value
                c.resolution = pre_resolution
                del c.history[pre_history_len:]
                c.history.append({
                    "event": "resolution_failed",
                    "timestamp": now(),
                    "detail": f"stage={failed_stage} error={primary_exc!r}",
                })
            except Exception as re:
                rollback_errors.append(re)

            if rollback_errors:
                raise TransactionIntegrityError(
                    original_error=primary_exc,
                    rollback_errors=rollback_errors,
                    affected_ids=[c.node_id, conflict_id],
                    stage=failed_stage,
                    conflict_id=conflict_id,
                    node_id=c.node_id,
                    field_name=c.field_name,
                )

            logger.error(
                "conflict resolution failed stage=%s node=%s field=%s id=%s: %r",
                failed_stage, c.node_id, c.field_name, conflict_id, primary_exc,
            )
            return False

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

        Acquires ``_graph_lock`` for the entire read so that all
        ``get_nodes_by_type`` and ``get_edges_for_node`` calls see the same
        committed graph snapshot.  A concurrent ``apply_deltas`` cannot produce
        a partial view between calls.
        """
        terminal_types = set(self._config.terminal_edge_types)
        actionable_types = set(self._config.actionable_node_types)

        tasks: list[OpenTask] = []
        async with self._graph_lock:
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
