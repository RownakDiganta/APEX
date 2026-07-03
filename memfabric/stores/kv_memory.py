# kv_memory.py
# In-memory KVStore reference implementation backed by a plain dict with optional per-entry TTL and asyncio locking.
"""In-memory KVStore reference implementation with TTL support."""
from __future__ import annotations

import asyncio
import time
from typing import Any


class InMemoryKVStore:
    """KVStore backed by a plain dict.  Thread-safe via asyncio.Lock."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # key → (value, expires_at | None)
        self._data: dict[str, tuple[Any, float | None]] = {}

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            if key not in self._data:
                return None
            value, expires = self._data[key]
            if expires is not None and time.monotonic() > expires:
                del self._data[key]
                return None
            return value

    async def set(
        self, key: str, value: Any, ttl_seconds: float | None = None
    ) -> None:
        async with self._lock:
            expires = (
                time.monotonic() + ttl_seconds if ttl_seconds is not None else None
            )
            self._data[key] = (value, expires)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def delete_prefix(self, prefix: str) -> None:
        async with self._lock:
            to_remove = [k for k in self._data if k.startswith(prefix)]
            for k in to_remove:
                del self._data[k]
