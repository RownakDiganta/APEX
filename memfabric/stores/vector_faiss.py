"""Dense vector index reference implementation backed by faiss.

Uses IndexFlatIP (inner-product / cosine via pre-normalised vectors).
Dimension is fixed at construction; adding a vector of wrong dimension
raises ValueError.

Note: ``faiss`` is CPU-only here.  The host app can swap in a GPU index or
any other VectorIndex Protocol implementation.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import faiss
import numpy as np

logger = logging.getLogger(__name__)


class FaissVectorIndex:
    """VectorIndex backed by faiss.IndexIDMap wrapping IndexFlatIP."""

    def __init__(self, dim: int = 384) -> None:
        self._dim = dim
        self._lock = asyncio.Lock()
        self._flat = faiss.IndexFlatIP(dim)
        self._index: faiss.IndexIDMap = faiss.IndexIDMap(self._flat)
        # Map faiss int64 id → (original string id, metadata)
        self._id_map: dict[int, tuple[str, dict[str, Any]]] = {}
        self._str_to_int: dict[str, int] = {}
        self._next_int: int = 0
        self._removed: set[str] = set()   # logical deletes

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def add(self, id: str, vector: list[float], metadata: dict[str, Any]) -> None:
        async with self._lock:
            if len(vector) != self._dim:
                raise ValueError(
                    f"Vector dim {len(vector)} != configured dim {self._dim}"
                )
            if id in self._str_to_int:
                # faiss IndexFlatIP doesn't support update; treat as remove+add
                self._do_remove(id)

            vec = np.array([vector], dtype=np.float32)
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec /= norm

            int_id = self._next_int
            self._next_int += 1
            self._str_to_int[id] = int_id
            self._id_map[int_id] = (id, metadata)
            self._removed.discard(id)

            ids_arr = np.array([int_id], dtype=np.int64)
            self._index.add_with_ids(vec, ids_arr)
            logger.debug("vector add id=%s dim=%d", id, self._dim)

    async def remove(self, id: str) -> None:
        async with self._lock:
            self._do_remove(id)

    def _do_remove(self, id: str) -> None:
        if id not in self._str_to_int:
            return
        int_id = self._str_to_int.pop(id)
        self._id_map.pop(int_id, None)
        self._removed.add(id)
        ids_arr = np.array([int_id], dtype=np.int64)
        self._index.remove_ids(faiss.IDSelectorArray(1, faiss.swig_ptr(ids_arr)))

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def search(
        self, vector: list[float], k: int
    ) -> list[tuple[str, float, dict[str, Any]]]:
        async with self._lock:
            n_live = self._index.ntotal
            if n_live == 0:
                return []

            actual_k = min(k, n_live)
            vec = np.array([vector], dtype=np.float32)
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec /= norm

            scores, ids = self._index.search(vec, actual_k)

            results: list[tuple[str, float, dict[str, Any]]] = []
            for score, int_id in zip(scores[0], ids[0]):
                if int_id == -1:
                    continue
                entry = self._id_map.get(int(int_id))
                if entry is None:
                    continue
                str_id, meta = entry
                if str_id in self._removed:
                    continue
                results.append((str_id, float(score), meta))

            return results
