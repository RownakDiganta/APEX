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
from typing import Any

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
