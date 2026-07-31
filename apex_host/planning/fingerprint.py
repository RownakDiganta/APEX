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

Argument canonicalization is TOOL-AWARE (see ``_canonical_args``):

  - ``nmap`` args go through
    ``apex_host.tools.nmap_command.canonical_fingerprint_args`` — an
    order-INDEPENDENT canonical form. Harmless flag reordering
    (``["-sV", "-T4"]`` vs ``["-T4", "-sV"]``) shares ONE identity, while
    flag/value pairs stay bound and are sorted by ``(flag, value)`` so
    semantically-OPPOSITE commands do NOT collide: ``["-p", "80",
    "--exclude", "443"]`` and ``["-p", "443", "--exclude", "80"]`` remain
    distinct fingerprints (the exact over-normalization bug a naive blind
    sort would introduce). This deliberately supersedes the earlier
    Phase-2 "never sort args" rule, which fixed the collision by making
    ALL reordering distinct — over-corrected in the other direction, so a
    planner that re-emitted the same scan with flags in a different order
    was never recognized as a duplicate.
  - every OTHER tool preserves argument ORDER (a generic tool's positional
    arguments can be order-sensitive) and normalizes only incidental
    whitespace, plus canonicalizes any URL-shaped token so equivalent URL
    FORMS (``http://h``, ``http://h/``, ``http://h:80/``) share one action
    identity.

Targets are canonicalized by ``_canonical_target``: a URL is normalized to
one form (default port and trailing slash removed); a bare host stays
case-insensitive. See docs/action-fingerprint.md for the full rationale.

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


def _canonical_target(target: str) -> str:
    """Canonicalize a target field for fingerprint identity.

    A URL-shaped target is normalized to one canonical form
    (``apex_host.graph_ids.normalize_url`` — lower-cased scheme+host, default
    port stripped, redundant/trailing slashes collapsed) and then any lone
    trailing slash is removed so ``http://h``, ``http://h/``, and
    ``http://h:80/`` all share ONE identity. A bare host/IP keeps the existing
    case-insensitive behavior (a hostname is case-insensitive by DNS
    convention). Never raises."""
    value = target.strip()
    if "://" in value:
        from apex_host.graph_ids import normalize_url

        # normalize_url lower-cases scheme+host and strips the default port;
        # rstrip('/') then collapses the root-path-vs-no-path distinction
        # (``http://h/`` == ``http://h``). It only removes a genuine trailing
        # path slash — the scheme separator ``//`` is preceded by ``:`` and is
        # never trailing, so it is untouched.
        return normalize_url(value).rstrip("/")
    return value.lower()


def _canonical_url_token(token: str) -> str:
    """URL-normalize a single arg token when it is URL-shaped; otherwise
    return it whitespace-stripped and unchanged. URL normalization is
    semantics-preserving, so applying it to an argument (e.g. curl's target
    URL) makes equivalent URL FORMS share one action identity without
    reordering or dropping any non-URL token."""
    stripped = str(token).strip()
    if "://" in stripped:
        return _canonical_target(stripped)
    return stripped


def _canonical_args(tool: str, args: list[str], target: str) -> list[str]:
    """Return the canonical fingerprint token list for *args*.

    - ``nmap``: an ORDER-INDEPENDENT canonical form
      (``apex_host.tools.nmap_command.canonical_fingerprint_args``) so that
      harmless flag reordering (``-sV -T4`` vs ``-T4 -sV``) shares one
      identity while opposite flag/value pairs (``-p 80`` vs ``-p 443``) stay
      distinct.
    - every other tool: each token whitespace-stripped and URL-normalized when
      URL-shaped, with ORDER PRESERVED — a generic tool's positional argument
      order can be semantically meaningful, so it is never reordered."""
    if tool.strip().lower() == "nmap":
        from apex_host.tools.nmap_command import canonical_fingerprint_args

        return canonical_fingerprint_args([str(a) for a in args], target)
    return [_canonical_url_token(a) for a in args]


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
    canon_args = _canonical_args(tool, args, target)
    key = "|".join([
        phase.strip().lower(),
        tool.strip().lower(),
        ",".join(canon_args),
        _canonical_target(target),
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
