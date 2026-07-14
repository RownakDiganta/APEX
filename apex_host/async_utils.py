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
- ``IO_SEMAPHORE`` and ``CPU_SEMAPHORE`` are process-level semaphores that cap
  the number of concurrent thread submissions so the thread pool is not
  overwhelmed.

These helpers are intended for internal use within ``apex_host``.  Nothing in
``memfabric/`` imports from this module (memfabric stays dependency-free from
the host application).
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
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

IO_SEMAPHORE: asyncio.Semaphore = asyncio.Semaphore(IO_SEMAPHORE_LIMIT)
CPU_SEMAPHORE: asyncio.Semaphore = asyncio.Semaphore(CPU_SEMAPHORE_LIMIT)


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
