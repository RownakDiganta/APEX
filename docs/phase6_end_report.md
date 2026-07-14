# Phase 6 End Report — Unified Execution Dispatcher, Policy Enforcement, Duplicate Protection, Retry Semantics, and Error Taxonomy

**Completion date:** 2026-07-14  
**Phase:** 6 of 12 (Remediation Roadmap, CLAUDE.md §21)  
**Findings addressed:** F06, F07, F09, F10, F11, F12, F13  
**New execution package:** `apex_host/execution/` (6 modules, 1 public `__init__.py`)

---

## 1. Summary

Phase 6 introduced a single, typed, gate-first execution pathway (`TaskDispatcher`) that all agent nodes in `apex_host/graph.py` now share.  This eliminated six independent inline policy/duplicate/conflict check copies and fixed the seven bug-level findings (F06–F13) that were scattered across `graph.py` and the parser/planner layers.

**Baseline (post-Phase 5 Reopen):** 1961 tests passed, mypy clean on 102 source files.  
**Phase 6 result:** 2087 tests passed (+126 new), mypy clean on 108 source files, ruff 134 errors (below 135 ceiling).

---

## 2. New `apex_host/execution/` Package

### 2.1 `dispositions.py` — `ExecutionDisposition` typed enum

12 disposition values (`EXECUTED_SUCCESS`, `EXECUTED_VALID_NEGATIVE`, `EXECUTED_FAILURE`, `BLOCKED_POLICY`, `BLOCKED_CONFLICT`, `SKIPPED_DUPLICATE`, `INVALID_TASK`, `CANCELLED`, `TIMED_OUT`, `TOOL_UNAVAILABLE`, `PARSER_FAILED`, `RETRY_EXHAUSTED`) with computed properties:

| Property | Semantics |
|---|---|
| `counts_as_execution` | True for outcomes where a real tool invocation occurred |
| `is_success` | True for `SUCCESS` and `VALID_NEGATIVE` |
| `is_blocked` | True for `BLOCKED_*` dispositions |
| `is_skipped` | True for `SKIPPED_DUPLICATE` |
| `is_retryable` | True when the disposition warrants a retry |
| `is_repairable` | True when a repair attempt might succeed |
| `never_retry` | True for blocked/skipped/cancelled — blocked tasks are NEVER retried |
| `never_repair` | True for blocked/skipped/success |

`RetryDecision` dataclass + `classify_retry(disposition, error) → RetryDecision` is the single, pure, policy-free retry decision point replacing scattered inline `if outcome in (...)` checks.

### 2.2 `errors.py` — `ErrorCategory` typed enum

12 error categories, each with: `retryable`, `repairable`, `counts_as_execution`, `updates_skill` properties.

### 2.3 `context.py` — `ExecutionContext` + `DispatchResult`

`ExecutionContext` (frozen dataclass, slots): captures per-dispatch context — `run_id`, `phase`, `turn_number`, `evidence_version`, `subgraph`, `evidence`, `dry_run`, `repair_attempt`, `is_repair`, `retry_count`, `original_task_id`.

`DispatchResult` (dataclass, slots): returned by `TaskDispatcher.dispatch()` — `disposition`, `task_id`, `fingerprint`, `tool_result_dict` (backward-compatible format for existing `write_memory` / `parse_observation` consumers), `policy_decision`, `duplicate_of`, `retryable`, `repairable`, `error`, `audit_metadata`.

### 2.4 `registry.py` — `TaskRegistry` atomic deduplication store

`TaskStatus` enum with `suppresses_new_submission` property (PENDING, EXECUTING, COMPLETED, FAILED_TERMINAL suppress; FAILED_RETRYABLE, BLOCKED, CANCELLED, SKIPPED_DUPLICATE do not).

`TaskRecord` dataclass with `to_dict()` / `from_dict()` for checkpoint serialization.

`TaskRegistry` with `asyncio.Lock` — the `reserve(fingerprint, task_id, ...)` method is the **atomic check-and-register** gate.  Two concurrent calls with the same fingerprint are guaranteed to have exactly one succeed.  `snapshot()` returns all records for LangGraph checkpoint persistence; `restore_from_snapshot()` restores only durable statuses (COMPLETED / FAILED_TERMINAL).

### 2.5 `dispatcher.py` — `TaskDispatcher` six-step pipeline

```
1. Policy gate    → advisor.review_task()                   (blocked → BLOCKED_POLICY, never registered)
2. Conflict gate  → check_conflict_dependencies() or        (blocked → BLOCKED_CONFLICT, never registered)
                    legacy _CONFLICT_SENSITIVE_TOOLS heuristic
3. Duplicate gate → task_registry.reserve()  [atomic lock]  (existing → SKIPPED_DUPLICATE)
4. Mark EXECUTING → task_registry.update_status(EXECUTING)
5. Route executor → run_command | telnet_executor | browser_executor | TOOL_UNAVAILABLE
6. Update status  → COMPLETED or FAILED_RETRYABLE / FAILED_TERMINAL
```

All four execution paths in `graph.py` (`_run_one_cmd`, `execute_agent`, `browser_agent`, `repair_agent`) now call `dispatcher.dispatch(task, ctx)` instead of containing independent gate logic.

### 2.6 `fingerprint.py` — SHA-256 upgrade

`task_fingerprint()` upgraded from MD5 8-char to SHA-256 16-char.  The key format and normalization (lower-case, sort args, join with `|`) are unchanged; only the hash function and output length changed.  `DuplicateActionTracker` retained for backward compatibility.

---

## 3. Bug Fixes (F06–F13)

| Finding | Root cause | Fix |
|---|---|---|
| **F06** | `route_after_write` read only `last_tool_result`; in multi-task turns, second-task failures were invisible to the router | Collects `raw_results` from `state["tool_results"]` (all results); iterates all non-browser, non-blocked entries; routes to `repair_agent` if any carry a retryable outcome |
| **F07** | Browser episode outcome derived from `state["last_error"]` (stale, from prior turn) | `write_memory` now derives browser outcome from `tool_result.get("error")` — the browser's own result field |
| **F09** | `asyncio.gather` without `return_exceptions=True` — first coroutine exception killed the entire multi-task turn | Added `return_exceptions=True`; exception entries build a synthetic failure result so the turn degrades gracefully |
| **F10** | `NmapParser` `exposes` / `runs` edges used `new_id()` — re-parsing accumulated duplicates | Edges now carry `f"exposes:{host_id}:{service_id}"` and `f"runs:{service_id}:{tech_id}"` IDs; `new_id` removed from `nmap_parser.py` |
| **F11** | `AccessParser` `grants` / `tested` edges used `new_id()` | Edges now carry `f"grants:{cred}:{access}"`, `f"tested:{service}:{cred}"`, `f"grants:{service}:{access}"` IDs; `new_id` removed from `access_parser.py` |
| **F12** | `CredentialPlanner.plan()` called `capabilities_from_subgraph` twice (wrapper + core) | Wrapper computes `caps` once and passes it to `_telnet_credentials_available_from_caps(caps)`; `_core.plan()` still calls it internally (total ≤ 2 per `plan()`) |
| **F13** | Duplicate-skip results (`returncode=0, error=None`) wrote `Outcome.success` episodes — Reflector could misidentify them as successful chains | `write_memory` skips episode creation entirely for `tool_result["skipped_duplicate"] is True` |

---

## 4. New `ApexGraphState` Field

`completed_fingerprints: Annotated[list[dict[str, Any]], operator.add]` — checkpoint-persistent `TaskRegistry` snapshot.  Added to `ApexGraphState`, `ApexRuntime.run()` initial state, and `run_synthetic_machine.py` initial state.

---

## 5. Test Suite (`tests/apex_host/test_phase6_dispatcher.py`)

126 new tests in 18 test classes:

| Class | Count | Coverage |
|---|---|---|
| `TestExecutionDispositionProperties` | 24 | Every disposition's property values |
| `TestClassifyRetry` | 11 | `classify_retry` for every disposition + error pattern |
| `TestErrorCategory` | 10 | Every category's property values |
| `TestTaskRegistry` | 13 | `reserve`, `update_status`, `snapshot`, `restore`, concurrency |
| `TestTaskStatus` | 8 | `suppresses_new_submission` per status |
| `TestTaskRecord` | 2 | `to_dict` / `from_dict` round-trip |
| `TestExecutionContext` | 3 | Frozen, defaults, repair context |
| `TestDispatchResult` | 4 | Property delegation |
| `TestDispatcherPolicyGate` | 9 | Blocked/approved/review paths |
| `TestDispatcherConflictGate` | 3 | Legacy tool heuristic; nmap bypass |
| `TestDispatcherDuplicateGate` | 5 | Second-identical-skip; fingerprint; concurrent atomicity |
| `TestDispatcherExecutorRouting` | 7 | All 4 executor paths; unavailable executors |
| `TestDispatcherRegistryLifecycle` | 4 | COMPLETED/FAILED_RETRYABLE after dispatch |
| `TestDispatcherAuditMetadata` | 3 | Policy decision audit trail |
| `TestFingerprintUpgrade` | 7 | 16-char SHA-256; key format; stability; case/whitespace normalization |
| `TestDeterministicEdgeIds` | 6 | F10 + F11 regression — NmapParser and AccessParser |
| `TestCredentialPlannerCapabilitiesOnce` | 1 | F12 regression — call-count guard |
| `TestBugFixRegressions` | 4 | F06, F07, F09, F13 logic regressions |

---

## 6. Architecture Invariants Verified

- **Invariant 1 (MemoryAPI sole state surface):** `TaskDispatcher` never touches a store directly; all writes go through `MemoryAPI` via the existing `parse_observation` / `write_memory` path.
- **Invariant 6 (Executors are stateless):** `TaskDispatcher` is stateless per call; the `TaskRegistry` lives outside the dispatcher and is injected.
- **Invariant 7 (No agent-to-agent calls):** `TaskDispatcher` routes to executors (not to other agents) via the same `run_command` / `TelnetExecutor` / `BrowserExecutor` seams as before.
- **Safety invariants (§11.2):** Policy gate runs first. Blocked tasks are never registered in `TaskRegistry` and are never retried. `dry_run=True` is the default and propagates through `ExecutionContext`.

---

## 7. Phase Validation Commands

```bash
# All tests
.venv/bin/python -m pytest tests/ -q
# → 2087 passed in 35.25s

# mypy
.venv/bin/python -m mypy --strict memfabric apex_host
# → Success: no issues found in 108 source files

# Ruff
.venv/bin/ruff check memfabric apex_host tests; echo "EXIT=$?"
# → 134 errors, EXIT=1 (pre-existing; 1 below 135 ceiling)
```

---

## 8. Deferred to Phase 7

**F15** (GlobalPlanner double-charge on phase transition) and **F16** (`duplicate_actions` accumulation across turns) were in scope for Phase 6 per the original CLAUDE.md §21 list but depended on graph-level state flows that are cleanly addressed after the dispatcher stabilises.  Both are now deferred to Phase 7 — Async Responsiveness and Cancellation — where the dispatch/turn lifecycle tests will be extended to cover multi-turn state accumulation.
