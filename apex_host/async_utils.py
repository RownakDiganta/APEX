# async_utils.py
# Central async utility helpers: thread offload, atomic file write, and bounded semaphores.
"""Central async utilities for Phase 7 responsiveness and cancellation hardening.

Phase 7 invariants enforced here
---------------------------------
- CPU-bound and file-I/O work must not run directly on the event loop.
  ``run_io`` and ``run_cpu`` offload callables to ``asyncio.to_thread``,
  releasing the event loop during execution.
- ``write_atomic`` writes to a ``.tmp`` sibling, syncs, then renames — so a
  crash during the write leaves the original file intact.
- ``read_text_async`` reads a file via ``asyncio.to_thread`` to avoid blocking
  the event loop on potentially large reads.
- ``IO_SEMAPHORE`` and ``CPU_SEMAPHORE`` are process-level, but
  **loop-safe**, bounded semaphores that cap the number of concurrent
  thread submissions so the thread pool is not overwhelmed — see
  ``_LoopBoundSemaphore`` below for why a bare ``asyncio.Semaphore`` module
  global is unsafe here.

These helpers are intended for internal use within ``apex_host``.  Nothing in
``memfabric/`` imports from this module (memfabric stays dependency-free from
the host application).
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import threading
import weakref
from typing import Any, Callable, TypeVar

_T = TypeVar("_T")

# ---------------------------------------------------------------------------
# Process-level bounded semaphores
# ---------------------------------------------------------------------------

#: Maximum concurrent thread pool submissions for file-I/O operations.
#: Keeps open file-descriptor count bounded under high concurrency.
IO_SEMAPHORE_LIMIT: int = max(4, (os.cpu_count() or 2) * 2)

#: Maximum concurrent thread pool submissions for CPU-bound operations.
#: Prevents thread-pool saturation from BM25 / embedding work.
CPU_SEMAPHORE_LIMIT: int = max(2, os.cpu_count() or 2)


class _LoopBoundSemaphore:
    """A bounded-concurrency async context manager safe to reuse across
    multiple asyncio event loops from a single module-level instance.

    ``asyncio.Semaphore`` (like ``asyncio.Lock``/``Event``/``Condition``)
    binds itself, on first use, to whichever event loop is running at that
    moment (via ``asyncio.mixins._LoopBoundMixin``). A module-level
    ``asyncio.Semaphore`` singleton — the previous implementation here — is
    therefore only safe for the *first* event loop that ever touches it in
    a given process. Any later use from a *different* loop raises
    ``RuntimeError: Semaphore is bound to a different event loop``.

    This is not a hypothetical edge case: ``pytest-asyncio`` creates a
    fresh event loop per test function by default, and this module is
    imported exactly once per test session (Python caches modules). Any
    test that calls ``run_io``/``run_cpu`` after an earlier test already
    bound the shared semaphore to *its* loop hits this ``RuntimeError`` —
    observed on a GitHub Actions runner where test collection/execution
    order differed enough from local runs to actually trigger it.

    The fix: never touch the underlying ``asyncio.Semaphore`` outside of a
    running loop, and keep one real ``asyncio.Semaphore`` **per event
    loop**, lazily created the first time this wrapper is used on that
    loop. Each loop gets its own independently-enforced copy of the same
    concurrency limit — the guarantee ("at most N concurrent thread
    submissions") holds exactly as before *within* any single loop; it is
    only the single-process-wide sharing of one Semaphore object across
    unrelated loops that is removed (that sharing was never a meaningful
    guarantee to begin with — two independent event loops, e.g. two
    separate test functions, were never actually contending for the same
    resource in a way this module's own callers depended on).

    ``WeakKeyDictionary`` keyed by the loop object means a per-loop
    semaphore is garbage-collected automatically once its loop is (no
    unbounded growth across, e.g., thousands of short-lived test-created
    loops in a long test session). A ``threading.Lock`` guards the
    lazy-creation check — cheap, and correct even in the (currently
    unused-by-this-project) case of multiple event loops running on
    separate OS threads concurrently.
    """

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._by_loop: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = (
            weakref.WeakKeyDictionary()
        )
        self._creation_lock = threading.Lock()

    def _semaphore_for_current_loop(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        sem = self._by_loop.get(loop)
        if sem is None:
            with self._creation_lock:
                # Re-check after acquiring the lock: another coroutine on
                # this same loop (or, in the multi-thread case, a
                # concurrent creation for a different loop) may have
                # already created it.
                sem = self._by_loop.get(loop)
                if sem is None:
                    sem = asyncio.Semaphore(self._limit)
                    self._by_loop[loop] = sem
        return sem

    async def __aenter__(self) -> None:
        await self._semaphore_for_current_loop().acquire()

    async def __aexit__(self, *exc_info: object) -> None:
        # __aexit__ always runs on the same running loop as the matching
        # __aenter__ (an `async with` block never spans loops), so this
        # looks up and releases the exact semaphore instance that was
        # acquired above.
        self._semaphore_for_current_loop().release()


IO_SEMAPHORE = _LoopBoundSemaphore(IO_SEMAPHORE_LIMIT)
CPU_SEMAPHORE = _LoopBoundSemaphore(CPU_SEMAPHORE_LIMIT)


# ---------------------------------------------------------------------------
# Thread-offload helpers
# ---------------------------------------------------------------------------


async def run_io(fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """Run a blocking I/O callable in a thread pool, bounded by IO_SEMAPHORE.

    The semaphore limits concurrent file-I/O thread submissions so the
    process does not exceed its open file-descriptor budget under concurrency.

    The event loop is released during the thread's execution; coroutines that
    do not wait for this call can make progress normally.
    """
    async with IO_SEMAPHORE:
        if kwargs:
            # asyncio.to_thread passes only positional args; wrap for kwargs.
            def _wrapped() -> _T:
                return fn(*args, **kwargs)
            return await asyncio.to_thread(_wrapped)
        return await asyncio.to_thread(fn, *args)


async def run_cpu(fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """Run a CPU-bound callable in a thread pool, bounded by CPU_SEMAPHORE.

    The semaphore limits concurrent CPU-heavy thread submissions to avoid
    over-saturating the thread pool with compute tasks.

    The event loop is released during the thread's execution.
    """
    async with CPU_SEMAPHORE:
        if kwargs:
            def _wrapped() -> _T:
                return fn(*args, **kwargs)
            return await asyncio.to_thread(_wrapped)
        return await asyncio.to_thread(fn, *args)


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------


async def read_text_async(path: str | pathlib.Path, encoding: str = "utf-8") -> str:
    """Read a text file in a thread pool, releasing the event loop during I/O.

    Equivalent to ``Path(path).read_text(encoding=encoding)`` but
    non-blocking with respect to the event loop.
    """
    p = pathlib.Path(path)
    return await run_io(p.read_text, encoding=encoding)


def _write_atomic_sync(path: pathlib.Path, data: str, encoding: str) -> None:
    """Synchronous atomic write: temp sibling → fsync → rename.

    A crash during the write leaves ``path`` intact (old content).
    The rename is atomic on POSIX filesystems.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(data, encoding=encoding)
        # Flush OS write buffers to disk so the rename is durable.
        with tmp.open("r+b") as fh:
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(path)
    except Exception:
        # Best-effort cleanup — ignore errors on the temp file.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def write_atomic(path: str | pathlib.Path, data: str, encoding: str = "utf-8") -> None:
    """Atomically write *data* to *path*.

    Synchronous. Callers inside ``async def`` should wrap in
    ``run_io(write_atomic, path, data)`` to avoid blocking the event loop.
    This synchronous form is provided for CLI / script contexts that do not
    run inside an event loop.
    """
    _write_atomic_sync(pathlib.Path(path), data, encoding)


async def write_atomic_async(
    path: str | pathlib.Path, data: str, encoding: str = "utf-8"
) -> None:
    """Atomically write *data* to *path*, releasing the event loop during I/O.

    Preferred form inside ``async def`` functions.  Offloads the file write
    to the thread pool via ``IO_SEMAPHORE``-bounded ``run_io``.
    """
    p = pathlib.Path(path)
    await run_io(_write_atomic_sync, p, data, encoding)


async def write_json_atomic(
    path: str | pathlib.Path,
    data: Any,
    *,
    indent: int = 2,
    encoding: str = "utf-8",
    default: Any = str,
) -> None:
    """Serialize *data* as JSON and atomically write it to *path*.

    The serialization is done on the calling coroutine (cheap for small
    payloads); the file write is offloaded to the thread pool.
    """
    serialized = json.dumps(data, indent=indent, default=default)
    await write_atomic_async(path, serialized, encoding)
