# init_lock.py
# Cross-process advisory file lock guarding the knowledge-initialization cache directory, so two concurrently-starting APEX processes cannot corrupt each other's cache writes.
"""Cross-process advisory lock for the knowledge-initialization cache directory.

This is deliberately NOT a substitute for, or interaction with, memfabric's
own ``MemoryAPI._graph_lock`` / ``_staging_lock`` (``asyncio.Lock``
instances, single-process only, guarding in-memory transaction state). This
module solves a completely different problem: two independent OS
*processes* (e.g. two APEX containers racing to start against the same
mounted cache volume) both trying to read-decide-write the same small set
of cache files on disk. It never touches, imports, or blocks on anything
inside ``memfabric`` — pure filesystem coordination, entirely at the
``apex_host`` layer, exactly where "cyber-specific compiled knowledge
loading" is supposed to live.

Design
------
An exclusive lock is represented by a lock FILE (``<cache_dir>/.init.lock``)
created with ``os.O_CREAT | os.O_EXCL`` — this open mode is atomic at the
OS level: if two processes race to create the same path, exactly one
succeeds and the other gets ``FileExistsError``. This is the same primitive
this codebase already trusts for its "write-temp-then-rename" atomic-write
pattern (``apex_host/async_utils.py``), just applied to lock acquisition
instead of content publication.

The lock file's content is a small JSON blob (``pid``, ``acquired_at``) —
never used for correctness, only for the stale-lock diagnostic message.

Stale-lock recovery: if a lock file's own age exceeds
``stale_after_seconds`` (a process that crashed while holding the lock,
never running its ``finally`` cleanup), a waiter treats it as abandoned and
reclaims it. This trades a small window of theoretical risk (a
still-alive-but-very-slow holder being pre-empted) for the practical
requirement that a single crashed container must never permanently wedge
every future container's knowledge initialization — matching this
project's "graceful degradation over indefinite hang" convention used
throughout ``apex_host`` (e.g. ``apex_host/eval/preflight.py``'s bounded
timeouts).

Failure mode when the lock cannot be acquired within ``timeout_seconds``:
the caller (``apex_host.knowledge.init_cache``) degrades to an UNCACHED
cold initialization for this run rather than raising or hanging — safety
over speed, consistent with the "no durable storage configured → retain a
correct bounded fallback" requirement elsewhere in this feature.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import pathlib
import time
from dataclasses import dataclass
from typing import AsyncIterator

from apex_host.async_utils import run_io

logger = logging.getLogger(__name__)

_LOCK_FILENAME = ".init.lock"
_POLL_INTERVAL_SECONDS = 0.1


@dataclass(frozen=True, slots=True)
class LockAcquisition:
    """Result of attempting to acquire the cache directory lock."""

    acquired: bool
    reclaimed_stale: bool = False
    reason: str = ""


def _lock_path(cache_dir: pathlib.Path) -> pathlib.Path:
    return cache_dir / _LOCK_FILENAME


def _try_create_lock_sync(lock_path: pathlib.Path) -> bool:
    """Atomically create the lock file. Returns True if this call created it."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"pid": os.getpid(), "acquired_at": time.time()})
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)
    return True


def _lock_age_seconds_sync(lock_path: pathlib.Path) -> float | None:
    try:
        return time.time() - lock_path.stat().st_mtime
    except OSError:
        return None


def _remove_lock_sync(lock_path: pathlib.Path) -> None:
    with contextlib.suppress(OSError):
        lock_path.unlink()


@contextlib.asynccontextmanager
async def cache_directory_lock(
    cache_dir: pathlib.Path,
    *,
    timeout_seconds: float = 30.0,
    stale_after_seconds: float = 300.0,
) -> AsyncIterator[LockAcquisition]:
    """Acquire an exclusive advisory lock on *cache_dir* for the duration of the block.

    Always yields a ``LockAcquisition`` — never raises on contention or
    timeout. ``acquired=False`` means the caller must proceed WITHOUT the
    cache for this run (safe, bounded fallback) rather than block
    indefinitely or corrupt a concurrent writer's work. The lock file is
    only ever removed by the process that created it (or, after
    ``stale_after_seconds``, by a waiter that reclaims an abandoned lock).
    """
    lock_path = _lock_path(cache_dir)
    deadline = time.monotonic() + timeout_seconds
    reclaimed = False

    while True:
        created = await run_io(_try_create_lock_sync, lock_path)
        if created:
            break

        age = await run_io(_lock_age_seconds_sync, lock_path)
        if age is not None and age > stale_after_seconds:
            logger.warning(
                "init_lock: reclaiming stale lock at %s (age=%.0fs > stale_after=%.0fs)",
                lock_path, age, stale_after_seconds,
            )
            await run_io(_remove_lock_sync, lock_path)
            reclaimed = True
            continue  # retry create immediately

        if time.monotonic() >= deadline:
            logger.warning(
                "init_lock: could not acquire %s within %.1fs — proceeding without cache "
                "for this run (uncached, bounded fallback)",
                lock_path, timeout_seconds,
            )
            yield LockAcquisition(
                acquired=False,
                reason=f"timeout after {timeout_seconds:.1f}s waiting for {lock_path}",
            )
            return

        await asyncio.sleep(_POLL_INTERVAL_SECONDS)

    try:
        yield LockAcquisition(acquired=True, reclaimed_stale=reclaimed)
    finally:
        await run_io(_remove_lock_sync, lock_path)
