"""Append-only JSONL episodic store reference implementation.

Invariants enforced here:
- An episode, once written, is never mutated or deleted.
- Concurrent appends are safe (protected by an asyncio.Lock).
- In-memory index mirrors the file; reads never re-scan the file.

For testing the store can be created with ``path=None`` which uses an
entirely in-memory list (no file I/O).
"""
from __future__ import annotations

import asyncio
import json
import logging
import pathlib
from typing import Any

from memfabric.ids import new_id, now
from memfabric.types import Episode, Outcome

logger = logging.getLogger(__name__)


def _episode_to_dict(ep: Episode) -> dict[str, Any]:
    return {
        "id": ep.id,
        "timestamp": ep.timestamp,
        "agent": ep.agent,
        "action": ep.action,
        "outcome": ep.outcome.value,
        "data": ep.data,
        "task_id": ep.task_id,
        "phase": ep.phase,
        "chain_id": ep.chain_id,
    }


def _dict_to_episode(d: dict[str, Any]) -> Episode:
    return Episode(
        id=d["id"],
        timestamp=d["timestamp"],
        agent=d["agent"],
        action=d["action"],
        outcome=Outcome(d["outcome"]),
        data=d["data"],
        task_id=d.get("task_id"),
        phase=d.get("phase"),
        chain_id=d.get("chain_id"),
    )


class JSONLEpisodicStore:
    """EpisodicStore backed by a JSONL file (or in-memory list for tests)."""

    def __init__(self, path: pathlib.Path | None = None) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._index: dict[str, Episode] = {}   # id → Episode
        self._order: list[str] = []            # insertion order

        if path is not None and path.exists():
            self._load_from_file()

    def _load_from_file(self) -> None:
        assert self._path is not None
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                ep = _dict_to_episode(json.loads(line))
                self._index[ep.id] = ep
                self._order.append(ep.id)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def append(self, episode: Episode) -> str:
        async with self._lock:
            if not episode.id:
                episode.id = new_id()
            if not episode.timestamp:
                episode.timestamp = now()

            if episode.id in self._index:
                raise ValueError(f"Episode {episode.id!r} already exists — episodic log is immutable")

            self._index[episode.id] = episode
            self._order.append(episode.id)

            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(_episode_to_dict(episode)) + "\n")

            logger.debug("append episode id=%s outcome=%s", episode.id, episode.outcome.value)
            return episode.id

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get(self, episode_id: str) -> Episode | None:
        return self._index.get(episode_id)

    async def tail(self, n: int = 100) -> list[Episode]:
        ids = self._order[-n:]
        return [self._index[eid] for eid in ids]

    async def since(self, cursor: str) -> list[Episode]:
        """Return episodes appended after *cursor* (exclusive, by insertion position)."""
        if cursor not in self._index:
            return list(self._index[eid] for eid in self._order)
        pos = self._order.index(cursor)
        return [self._index[eid] for eid in self._order[pos + 1 :]]

    async def all(self) -> list[Episode]:
        return [self._index[eid] for eid in self._order]
