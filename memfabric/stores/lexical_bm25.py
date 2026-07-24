# lexical_bm25.py
# BM25-based lexical index reference implementation with lazy rebuild, 2-char minimum tokenisation, zero-score filtering, dedup guard, and graceful empty-index degradation.
"""BM25-based lexical index reference implementation.

Design adapted from the predecessor pattern:
- Lazy build: index is rebuilt on first search after a dirty write.
- 2-character minimum tokenizer preserving short acronyms.
- Zero-score filtering: results with score == 0.0 are dropped.
- Dedup guard: no duplicate ids in a single result set.
- Graceful empty-index degradation: search on empty index returns [].

A single unified corpus is maintained; every document carries a ``metadata``
dict including a ``"tier"`` key so callers can post-filter by tier.

Phase 7 async invariants
------------------------
- ``search()`` and ``_rebuild_async()`` offload CPU-bound BM25 work to the
  thread pool via ``asyncio.to_thread``.  The event loop is released during
  scoring / index construction even though ``_lock`` is still held — other
  coroutines that do not need this lock can make progress normally.
- This is the correct pattern: ``asyncio.Lock`` held across
  ``await asyncio.to_thread(...)`` keeps mutual exclusion while allowing the
  event loop to serve unrelated coroutines.  Do not remove the lock.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Callable

from rank_bm25 import BM25Plus

logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"\w+")


def _tokenize(text: str) -> list[str]:
    """2-char minimum tokenizer that preserves short acronyms."""
    return [t.lower() for t in _TOKEN_RE.findall(text) if len(t) >= 2]


def _build_bm25(corpus: list[list[str]]) -> BM25Plus:
    """Build a BM25Plus index from a tokenized corpus.

    Pure function — safe to call from a thread pool.
    """
    return BM25Plus(corpus)


class BM25LexicalIndex:
    """LexicalIndex backed by BM25Plus over a unified corpus."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # (id, text, metadata) in insertion order
        self._docs: list[tuple[str, str, dict[str, Any]]] = []
        self._id_to_pos: dict[str, int] = {}  # id → index in _docs (for removal)
        self._index: BM25Plus | None = None
        self._dirty = False

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def add(self, id: str, text: str, metadata: dict[str, Any]) -> None:
        async with self._lock:
            if id in self._id_to_pos:
                # Update in-place: replace text/metadata, keep position
                pos = self._id_to_pos[id]
                self._docs[pos] = (id, text, metadata)
            else:
                self._id_to_pos[id] = len(self._docs)
                self._docs.append((id, text, metadata))
            self._dirty = True

    async def remove(self, id: str) -> None:
        async with self._lock:
            if id not in self._id_to_pos:
                return
            pos = self._id_to_pos.pop(id)
            self._docs[pos] = ("", "", {})   # tombstone — excluded in rebuild
            self._dirty = True

    async def rebuild(self) -> None:
        async with self._lock:
            await self._rebuild_async()

    # ------------------------------------------------------------------
    # Snapshot export/import (generic, domain-agnostic persistence support)
    # ------------------------------------------------------------------
    #
    # These two methods exist so that a HOST APPLICATION can give this
    # store durable, cross-process persistence (e.g. write the exported
    # documents to disk after a run and re-import them at the start of the
    # next one) WITHOUT memfabric knowing anything about files, manifests,
    # or any domain concept — the store only ever deals in the same
    # (id, text, metadata) triples that ``add()`` already accepts.
    #
    # ``import_documents`` calls the exact same ``add()`` path a live write
    # would use (same upsert-by-id semantics, same dirty-flag invalidation)
    # — there is no second, competing way for a document to enter this
    # index.  Re-importing a document a caller already legitimately wrote
    # via ``MemoryAPI.promote_knowledge()``/``promote_skill()`` in a prior
    # process is not a new write path; it is this same index resuming its
    # own prior state, exactly analogous to how the reference
    # ``JSONLEpisodicStore`` reference implementation reconstructs its
    # in-memory state by replaying its own file at construction.

    async def export_documents(
        self,
        predicate: Callable[[dict[str, Any]], bool] | None = None,
    ) -> list[dict[str, Any]]:
        """Return a JSON-serialisable snapshot of live (non-tombstoned) documents.

        Each entry is ``{"id": ..., "text": ..., "metadata": ...}``.  When
        *predicate* is given, only documents whose ``metadata`` dict passes
        ``predicate(metadata)`` are included — e.g. a caller may snapshot
        only documents tagged with a particular ``source_family``.
        """
        async with self._lock:
            out: list[dict[str, Any]] = []
            for id_, text, meta in self._docs:
                if not id_:
                    continue  # tombstone
                if predicate is not None and not predicate(meta):
                    continue
                out.append({"id": id_, "text": text, "metadata": dict(meta)})
            return out

    async def import_documents(self, documents: list[dict[str, Any]]) -> int:
        """Bulk-load previously-exported documents via the normal ``add()`` path.

        Returns the number of documents added. Safe to call on an index that
        already has documents — each entry is upserted by id, identical to
        calling ``add()`` once per document.
        """
        count = 0
        for doc in documents:
            doc_id = doc.get("id")
            if not doc_id:
                continue
            await self.add(str(doc_id), str(doc.get("text", "")), dict(doc.get("metadata") or {}))
            count += 1
        return count

    async def document_count(self) -> int:
        """Return the number of live (non-tombstoned) documents, no rebuild triggered."""
        async with self._lock:
            return len(self._id_to_pos)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def search(
        self, query: str, k: int
    ) -> list[tuple[str, float, dict[str, Any]]]:
        async with self._lock:
            live_docs = [(id_, text, meta) for id_, text, meta in self._docs if id_]
            if not live_docs:
                return []

            if self._dirty:
                # Offload CPU-bound index construction to a thread.
                # The lock is still held; the event loop is free to run other
                # coroutines that do not need this lock.
                await self._rebuild_async()

            assert self._index is not None
            tokens = _tokenize(query)
            if not tokens:
                return []

            # Offload CPU-bound BM25 scoring to a thread (P7-I01 / A01).
            # Capture current index reference before releasing; _rebuild_async
            # only replaces self._index after construction completes, so the
            # captured reference is stable for the duration of this thread call.
            current_index = self._index
            scores_array = await asyncio.to_thread(current_index.get_scores, tokens)

            # Pair scores with doc positions (only live docs)
            paired: list[tuple[float, str, dict[str, Any]]] = []
            live_pos = 0
            for id_, _, meta in self._docs:
                if not id_:
                    continue   # skip tombstones
                score = float(scores_array[live_pos])
                if score > 0.0:
                    paired.append((score, id_, meta))
                live_pos += 1

            paired.sort(key=lambda x: x[0], reverse=True)

            # Dedup + top-k
            seen: set[str] = set()
            results: list[tuple[str, float, dict[str, Any]]] = []
            for score, id_, meta in paired:
                if id_ in seen:
                    continue
                seen.add(id_)
                results.append((id_, score, meta))
                if len(results) >= k:
                    break

            return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _rebuild_async(self) -> None:
        """Rebuild the BM25Plus index, offloading construction to a thread (P7-I01 / A02).

        Caller must hold ``self._lock``.  The event loop is released during
        ``BM25Plus(corpus)`` construction without dropping the lock.
        """
        live_docs = [text for id_, text, _ in self._docs if id_]
        if not live_docs:
            self._index = None
            self._dirty = False
            return
        corpus = [_tokenize(t) for t in live_docs]
        # Offload the CPU-bound BM25Plus construction to a thread.
        self._index = await asyncio.to_thread(_build_bm25, corpus)
        self._dirty = False
        logger.debug("BM25 index rebuilt: %d docs", len(live_docs))

    def _rebuild_unlocked(self) -> None:
        """Synchronous rebuild — kept for backward compatibility.

        Prefer ``_rebuild_async`` in async contexts.  This method blocks the
        event loop and should only be called from a thread or from a
        synchronous (non-async) context such as tests that need the index
        to be ready immediately without an event loop.
        """
        live_docs = [text for id_, text, _ in self._docs if id_]
        if not live_docs:
            self._index = None
            self._dirty = False
            return
        corpus = [_tokenize(t) for t in live_docs]
        self._index = BM25Plus(corpus)
        self._dirty = False
        logger.debug("BM25 index rebuilt (sync): %d docs", len(live_docs))
