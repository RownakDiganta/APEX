# fingerprint.py
# Canonical action-fingerprint identity and duplicate action tracking for APEX engagement runs.
"""Canonical action fingerprinting and duplicate-action detection for APEX.

``task_fingerprint`` produces a stable 16-char hex ID representing the
canonical SEMANTIC IDENTITY of an action — (phase, tool, normalized args,
target, parser, executor_domain, capability_mode). Two ``TaskSpec``
instances with different ``task.id`` values (a fresh UUID minted on every
planner call), different timestamps, or different trace/run IDs still
produce the IDENTICAL fingerprint when their semantic action fields match
— none of those ephemeral identifiers are hashed. This is deliberate: the
fingerprint answers "is this the SAME action as one already attempted?",
never "is this the same TASK OBJECT?".

Phase 2 (post-live-test debugging) correction — argument ORDER is no
longer normalized away by sorting. The pre-Phase-2 implementation sorted
``args`` before hashing so that e.g. ``["-sV", "-T4"]`` and
``["-T4", "-sV"]`` produced the same fingerprint. This is safe for a
FIXED flag set with no positional values, but it is a genuine
over-normalization bug for flag/value pairs: ``["-p", "80", "--exclude",
"443"]`` (scan port 80, exclude port 443) and ``["-p", "443", "--exclude",
"80"]`` (the semantically OPPOSITE command) sort to the IDENTICAL token
multiset and would collide onto the same fingerprint. Argument order is
now preserved; only incidental whitespace is normalized. See
docs/action-fingerprint.md for the full rationale.

``DuplicateActionTracker`` maintains a bounded sliding-window history and flags
any fingerprint that has been executed >= max_repeats times as a duplicate.  The
check+record operation is synchronous (no awaits) so it is safe to call from
concurrent asyncio coroutines without an explicit lock — asyncio's cooperative
scheduling ensures only one coroutine runs at a time between await points.
Note: the canonical, currently-wired duplicate-suppression mechanism used by
``TaskDispatcher`` in production is ``apex_host.execution.registry.TaskRegistry``
(fingerprint-keyed reserve/suppress with outcome-aware status), not this class —
``DuplicateActionTracker`` is a standalone sliding-window utility retained for
callers that want simple repeat-counting without full outcome tracking.
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
    capability_mode: str = "",
) -> str:
    """Return a stable 16-char hex canonical action fingerprint (SHA-256).

    Included fields (the canonical action identity):
      - ``phase``, ``tool``, ``parser``, ``executor_domain``, ``target``:
        lower-cased and stripped — case and incidental whitespace are
        never semantically meaningful for these fields (a hostname target
        is case-insensitive by DNS convention; tool/phase/parser/
        executor_domain names are internal identifiers, not
        case-sensitive CLI content).
      - ``args``: each token stripped of incidental leading/trailing
        whitespace. Order is PRESERVED (not sorted) — see module
        docstring for why blind sorting is an over-normalization bug for
        flag/value argv pairs. Internal token case is preserved
        unchanged — CLI flags are frequently case-sensitive
        (``-sV`` vs ``-sv`` are different nmap options).
      - ``capability_mode``: the backend capability mode the task was
        planned under (e.g. ``"raw_socket"`` / ``"tcp_connect"`` — see
        ``apex_host.tools.backend.backend_supports_raw_sockets``).
        Two otherwise-identical actions planned under different backend
        capability assumptions are treated as distinct actions, even for
        a tool whose argv does not visibly encode the difference.

    Deliberately EXCLUDED (ephemeral, never part of action identity):
    ``task.id`` (a fresh UUID per ``TaskSpec``), any timestamp, any
    trace/run ID. A caller must never pass these in — the function
    signature has no parameter for any of them.
    """
    norm_args = [str(a).strip() for a in args]
    key = "|".join([
        phase.strip().lower(),
        tool.strip().lower(),
        ",".join(norm_args),
        target.strip().lower(),
        parser.strip().lower(),
        executor_domain.strip().lower(),
        capability_mode.strip().lower(),
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


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
