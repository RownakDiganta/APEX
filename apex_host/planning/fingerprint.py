# fingerprint.py
# Task fingerprinting and duplicate action tracking for APEX engagement runs.
"""Task fingerprinting and duplicate-action detection for APEX.

``task_fingerprint`` produces a stable 8-char hex ID from the normalised
combination of (phase, tool, args, target, parser, executor_domain).  Identical
tasks always produce the same fingerprint regardless of argument ordering.

``DuplicateActionTracker`` maintains a bounded sliding-window history and flags
any fingerprint that has been executed >= max_repeats times as a duplicate.  The
check+record operation is synchronous (no awaits) so it is safe to call from
concurrent asyncio coroutines without an explicit lock — asyncio's cooperative
scheduling ensures only one coroutine runs at a time between await points.
"""
from __future__ import annotations

import hashlib
from collections import deque


def task_fingerprint(
    phase: str,
    tool: str,
    args: list[str],
    target: str,
    parser: str = "",
    executor_domain: str = "",
) -> str:
    """Return a stable 8-char hex fingerprint for a task action.

    All fields are lower-cased and stripped; args are sorted so that
    argument order does not affect the fingerprint.
    """
    norm_args = sorted(str(a).strip() for a in args)
    key = "|".join([
        phase.strip().lower(),
        tool.strip().lower(),
        ",".join(norm_args),
        target.strip().lower(),
        parser.strip().lower(),
        executor_domain.strip().lower(),
    ])
    return hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()[:8]


class DuplicateActionTracker:
    """Sliding-window tracker that flags repeated task fingerprints.

    Parameters
    ----------
    window:
        Maximum number of recent executions to remember.  When a new
        fingerprint is recorded and the history is full, the oldest entry
        is evicted and its count is decremented.
    max_repeats:
        A fingerprint seen >= this many times within the current window
        is considered a duplicate and should be skipped.
        Default 1 means any repeat within the window triggers the gate.
    """

    def __init__(self, window: int = 5, max_repeats: int = 1) -> None:
        self._window = window
        self._max_repeats = max_repeats
        self._history: deque[str] = deque(maxlen=window)
        self._counts: dict[str, int] = {}

    def is_duplicate(self, fingerprint: str) -> bool:
        """Return True if fingerprint has been seen >= max_repeats times."""
        return self._counts.get(fingerprint, 0) >= self._max_repeats

    def record(self, fingerprint: str) -> None:
        """Record a fingerprint as executed.

        Call only after is_duplicate() returns False.  Maintains the
        sliding-window invariant: if the deque is full, the count of the
        entry that will be evicted is decremented before the append.
        """
        if len(self._history) == self._window and self._history:
            # Eviction: the oldest item is about to be removed by deque.append.
            oldest = self._history[0]
            new_count = self._counts.get(oldest, 1) - 1
            if new_count <= 0:
                self._counts.pop(oldest, None)
            else:
                self._counts[oldest] = new_count
        self._history.append(fingerprint)
        self._counts[fingerprint] = self._counts.get(fingerprint, 0) + 1

    def snapshot(self) -> dict[str, object]:
        """Return a JSON-serialisable audit snapshot of the current state."""
        return {
            "window": self._window,
            "max_repeats": self._max_repeats,
            "history_size": len(self._history),
            "unique_fingerprints": len(self._counts),
        }
