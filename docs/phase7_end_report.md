# Phase 7 End Report — Async Responsiveness, Event-Loop Safety, Timeouts, Cancellation, and Load Reliability

**Date completed:** 2026-07-14  
**Tests after Phase 7:** 2218 passed (up from 2087 at Phase 7 start)  
**mypy --strict:** Success — no issues found in 109 source files  
**Ruff errors:** 130 (below baseline of 133)

---

## Summary

Phase 7 addresses a class of latency, reliability, and cancel-safety defects that
do not affect functional correctness but do affect production robustness:

- Long-running synchronous operations blocked the asyncio event loop entirely
  (BM25 rebuild, BM25 scoring, JSONL file append, file reads)
- Subprocess timeout and cancellation used immediate SIGKILL instead of
  SIGTERM → grace period → SIGKILL
- Browser launch had no timeout, allowing an unresponsive Playwright to stall
  the engagement indefinitely
- Report and EKG export writes were non-atomic (partial write visible on crash)
- The runtime had no `aclose()` shutdown hook to cancel background tasks

---

## Implementation Fixes

### A01 — BM25 scoring via `asyncio.to_thread`

**File:** `memfabric/stores/lexical_bm25.py`

`BM25Plus.get_scores()` is CPU-bound and blocks the event loop for the duration
of a BM25 search. The fix wraps the call in `asyncio.to_thread(current_index.get_scores, tokens)`
so the event loop remains free for other coroutines while scoring runs in a
thread-pool worker.

A `_build_bm25(corpus)` pure function (no locks, safe to serialize to thread pool)
was extracted to support fix A02.

### A02 — BM25 index rebuild via `asyncio.to_thread`

**File:** `memfabric/stores/lexical_bm25.py`

`_rebuild_async()` moves `BM25Plus(corpus)` construction to `asyncio.to_thread(_build_bm25, corpus)`.
The asyncio.Lock is held across the `await asyncio.to_thread(...)` call — the
lock maintains mutual exclusion while the event loop is free to serve other
coroutines that do not need the same lock (P7-I02, the correct pattern).

### A03 — JSONL append via `asyncio.to_thread`

**File:** `memfabric/stores/episodic_jsonl.py`

The `fh.write(line + "\n")` synchronous file write inside `append()` is moved to
`asyncio.to_thread(_append_line_sync, self._path, line)` where `_append_line_sync`
is a pure function safe for thread pool execution.

### A04 — Compiled loader file reads via `asyncio.to_thread`

**File:** `apex_host/knowledge/compiled_loader.py`

`path.read_text(encoding="utf-8")` inside the JSONL loading loop is changed to
`await asyncio.to_thread(path.read_text, encoding="utf-8")`, preventing large
file reads from blocking the event loop during knowledge seeding.

### A05 — Atomic report JSON write

**File:** `apex_host/eval/report.py`

`write_report_json()` writes to a `.tmp` sibling in the same directory, calls
`fh.flush()` + `os.fsync(fh.fileno())`, then uses `Path(tmp_path).replace(out)`
for an atomic POSIX rename. A partial write (crash mid-write) cannot leave a
truncated file at the final path.

### A06 — Atomic EKG export write

**File:** `apex_host/eval/export_graph.py`

Same atomic temp-file pattern as A05, applied to `write_json()`.

### A07 — SIGTERM grace period on timeout

**File:** `apex_host/tools/runner.py`

Subprocess timeout now calls `_terminate_and_wait(proc, grace_seconds)` instead
of immediate SIGKILL. The helper: sends SIGTERM, waits up to
`config.subprocess_sigterm_grace_seconds` (default 5 s), then sends SIGKILL if
the process is still alive.

New constant: `_DEFAULT_SIGTERM_GRACE: float = 5.0`

### A08 — CancelledError cleanup in runner

**File:** `apex_host/tools/runner.py`

Explicit `except asyncio.CancelledError:` handlers in both the `proc.communicate()`
block and the outer `proc = await asyncio.create_subprocess_exec(...)` call ensure
that if the calling coroutine is cancelled, the child process receives SIGTERM
before the cancellation propagates. This prevents zombie/orphan processes.

### A09 — Browser launch timeout

**File:** `apex_host/agents/browser_executor.py`

`playwright.chromium.launch()` is wrapped in `asyncio.wait_for(..., timeout=launch_timeout)`
where `launch_timeout = float(getattr(self._config, "browser_launch_timeout_seconds", 30.0))`.
Without this, a hung Playwright process stalls the entire event loop indefinitely.

### New config fields (`apex_host/config.py`)

Five new `ApexConfig` fields with safe defaults:

| Field | Default | Purpose |
|---|---|---|
| `subprocess_sigterm_grace_seconds` | `5.0` | SIGTERM grace period before SIGKILL |
| `browser_launch_timeout_seconds` | `30.0` | Playwright launch timeout |
| `telnet_read_timeout_seconds` | `10.0` | Per-read timeout in TelnetExecutor |
| `retrieval_channel_timeout_seconds` | `5.0` | Per-channel retrieval timeout |
| `parser_timeout_seconds` | `10.0` | Parser call timeout |

### Runtime `aclose()` (`apex_host/runtime.py`)

`ApexRuntime.aclose()` provides a clean, idempotent shutdown path. Subsequent
calls after the first are no-ops (`_closed` guard). The implementation cancels
all non-current, non-done asyncio tasks and awaits them with `return_exceptions=True`
so exceptions from cancelled tasks do not propagate.

### `apex_host/async_utils.py` (new module)

Centralizes async utility helpers:
- `run_io(fn, *args)` — offloads to thread pool with `IO_SEMAPHORE` cap
- `run_cpu(fn, *args)` — offloads to thread pool with `CPU_SEMAPHORE` cap
- `write_atomic_async(path, data)` — thread-safe atomic file write
- `write_json_atomic(path, data)` — JSON variant
- `IO_SEMAPHORE_LIMIT`, `CPU_SEMAPHORE_LIMIT`, `IO_SEMAPHORE`, `CPU_SEMAPHORE` constants

---

## Phase 7 Invariants (P7-I01 through P7-I10)

| # | Invariant |
|---|---|
| P7-I01 | CPU-bound BM25 work runs in a thread pool via `asyncio.to_thread`, never blocking the event loop |
| P7-I02 | Holding `asyncio.Lock` while `await asyncio.to_thread(...)` runs is correct — the lock maintains mutual exclusion but the event loop is free |
| P7-I03 | Subprocess timeout sends SIGTERM first, waits grace seconds, then SIGKILL — never immediate SIGKILL |
| P7-I04 | `asyncio.CancelledError` from any subprocess path triggers child cleanup (SIGTERM → wait) before re-raising |
| P7-I05 | Browser launch has an explicit `asyncio.wait_for` timeout — no indefinite blocking on Playwright |
| P7-I06 | Report and EKG export writes are atomic: temp-file write + fsync + POSIX rename |
| P7-I07 | File reads during knowledge seeding are non-blocking: `asyncio.to_thread(path.read_text, ...)` |
| P7-I08 | `asyncio.Semaphore` caps (`IO_SEMAPHORE`, `CPU_SEMAPHORE`) bound concurrent thread-pool submissions |
| P7-I09 | `ApexRuntime.aclose()` is idempotent; cancels all background tasks and awaits them cleanly |
| P7-I10 | All five timeout config fields have safe, non-zero defaults so the system degrades gracefully |

---

## Tests Added

**File:** `tests/apex_host/test_phase7_async.py` — 131 tests across 19 groups

| Group | Class | Count | What it tests |
|---|---|---|---|
| G01 | `TestHeartbeat*` (8 classes) | 8 | Event-loop free during BM25, JSONL, compiled loader, retrieval, reflector, runner |
| G02 | `TestBM25ThreadOffload` | 8 | BM25 scoring and rebuild run in thread pool |
| G03 | `TestJSONLConcurrentAppend` | 6 | Concurrent JSONL appends serialize correctly |
| G04 | `TestSubprocessSIGTERM` | 8 | SIGTERM grace period, SIGKILL escalation, CancelledError cleanup |
| G05 | `TestBrowserExecutorTimeout` | 6 | Browser launch timeout enforced |
| G06 | `TestAtomicFileWrite` | 8 | Temp file pattern, fsync, atomic rename, error cleanup |
| G07 | `TestConfigTimeoutFields` | 8 | All 5 new config fields exist with correct defaults |
| G08 | `TestRuntimeAclose` | 6 | `aclose()` idempotency, cancels background tasks |
| G09 | `TestCompiledLoaderAsync` | 6 | Knowledge loading uses thread offload |
| G10 | `TestRetrievalChannelTimeout` | 6 | Per-channel timeout config field present |
| G11 | `TestBoundedConcurrencySemaphore` | 8 | `IO_SEMAPHORE_LIMIT` cap is not exceeded |
| G12 | `TestArchitectureScan` | 6 | No bare `subprocess.*` calls outside runner.py; no cyber terms in memfabric |
| G13 | `TestCancellationPropagation` | 6 | `asyncio.CancelledError` propagates correctly |
| G14 | `TestGlobalPlannerNoBudgetDoubleCharge` + `TestDuplicateActionsAccumulation` | 12 | F15 (no double budget charge) + F16 (accumulation across turns) |
| G15 | `TestLockDuration` | 6 | Lock held for short duration; released before tool execution |
| G16 | `TestAsyncUtilsHelpers` | 6 | `write_atomic_async`, `write_json_atomic`, `run_io`, `run_cpu` |
| G17 | `TestSIGTERMDetails` | 6 | SIGTERM helper behavior, grace period reads from config |
| G18 | `TestBM25EdgeCases` | 5 | Empty corpus, single document, BM25 returns correct shape |
| G19 | `TestPhase7Integration` | 5 | End-to-end dry-run uses async BM25 and JSONL paths |

---

## Deferred Findings (Phase 6 F15/F16)

Per Phase 6 specification, these were deferred to Phase 7. Both are resolved:

**F15 — GlobalPlanner budget double-charge:** Confirmed this does NOT exist in the
current implementation. `record_turn()` is called exactly once per turn in
`global_plan`. `reflect_or_continue` calls `decide_phase()` read-only (peek)
without calling `record_turn()`. 8 tests in G14 verify this invariant.

**F16 — `duplicate_actions` accumulation across turns:** `Annotated[list[dict], operator.add]`
reducer in `ApexGraphState` correctly concatenates entries from each turn.
4 tests in G14 verify multi-turn accumulation behavior.

---

## Validation Results

```
pytest tests/ -q    →  2218 passed, 0 failed (2218 total)
mypy --strict       →  Success — no issues in 109 source files
ruff check          →  130 errors (below baseline 133)
```

---

## Next Phase

**Phase 8 — Secret Redaction and Graph Representation** (OPEN):
Ensure no secret material appears in graph state or episodic log beyond
`secret_hint="[redacted]"`. Requires Phase 6 to be complete first (§21).
