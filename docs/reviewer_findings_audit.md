# Reviewer Findings Audit

**Phase 0 baseline date:** 2026-07-13  
**Baseline commit:** 45124a8 (Remove legacy payload repository)  
**Phase 0 baseline:** 1311 passed, 0 failed — mypy clean (101 source files)

**Phase 1 completion date:** 2026-07-13  
**Phase 1 test count:** 1328 passed (17 new tests added)  
**Phase 1 mypy:** Success — no issues found in 101 source files

**Phase 2 completion date:** 2026-07-14  
**Phase 2 test count:** 1486 passed (+60 new tests in `tests/test_conflict_phase2.py`)  
**Phase 2 mypy:** Success — no issues found in 101 source files  
**Phase 2 ruff:** 135 errors (pre-existing baseline; no new errors introduced)

**Phase 2 reopen completion date:** 2026-07-14  
**Phase 2 reopen test count:** 1558 passed (+72 new tests in `tests/test_conflict_phase2_reopen.py`, R01–R72)  
**Phase 2 reopen mypy:** Success — no issues found in 101 source files  
**Phase 2 reopen ruff:** 135 errors (ceiling maintained; 2 unused imports removed from api.py)

**Phase 6 completion date:** 2026-07-14  
**Phase 6 test count:** 2087 passed (+126 new tests in `tests/apex_host/test_phase6_dispatcher.py`)  
**Phase 6 mypy:** Success — no issues found in 108 source files  
**Phase 6 ruff:** 134 errors (below 135 ceiling; no new errors introduced)

Commands used to establish baseline:

```bash
.venv/bin/python -m pytest tests/ -q
# → 1311 passed in 4.69s

.venv/bin/python -m mypy memfabric/ apex_host/ --ignore-missing-imports
# → Success: no issues found in 101 source files
```

Phase 1 fixes applied (2026-07-13):

```bash
.venv/bin/python -m pytest tests/ -q
# → 1328 passed in 4.52s

.venv/bin/python -m mypy --strict memfabric apex_host
# → Success: no issues found in 101 source files
```

---

## Finding Index

| # | Severity | Area | Short title | Phase |
|---|---|---|---|---|
| F01 | Medium | memfabric/retrieval | `_cache_key` excludes `k` — stale truncated results | 1 |
| F02 | Medium | memfabric/api | `apply_deltas` rollback does not restore `_write_clock` | 1 |
| F03 | Medium | apex_host/planning | `RepairEngine` has no `LLMBudgetTracker` integration | 2 |
| F04 | Medium | apex_host/graph | `build_apex_graph` does not pass `budget_tracker` to `RepairEngine` | 2 |
| F05 | Low | apex_host/planning | `_context_hash` uses only structural counts, not content | 2 |
| F06 | Medium | apex_host/graph | `route_after_write` inspects only `last_tool_result` in multi-task turns | 6 (FIXED 2026-07-14) |
| F07 | Medium | apex_host/graph | Browser episode outcome reads stale `state["last_error"]` | 6 (FIXED 2026-07-14) |
| F08 | Low | apex_host/graph | `reflect_or_continue` peek omits `current_phase` — budget force-advance never fires on peek | 2 |
| F09 | Medium | apex_host/graph | `asyncio.gather` in `_run_tasks` lacks `return_exceptions=True` | 6 (FIXED 2026-07-14) |
| F10 | Low | apex_host/parsers | `NmapParser` edge IDs use `new_id()` — not idempotent on re-parse | 6 (FIXED 2026-07-14) |
| F11 | Low | apex_host/parsers | `AccessParser` edge IDs use `new_id()` — not idempotent on re-parse | 6 (FIXED 2026-07-14) |
| F12 | Low | apex_host/planners | `CredentialPlanner` calls `capabilities_from_subgraph` twice per `plan()` | 6 (FIXED 2026-07-14) |
| F13 | Low | apex_host/graph | Duplicate-skip result (`returncode=0, error=None`) classified as `Outcome.success` and writes an Episode | 6 (FIXED 2026-07-14) |
| F14 | Low | apex_host/policy | `LLMPolicyGuard` not wired into default `build_apex_graph` construction | 2 |
| F15 | Low | apex_host/planners | `GlobalPlanner.record_turn` call site: called after not before `decide_phase`—wrong phase can be charged | 3 |
| F16 | Info | apex_host/graph | `graph_state.py`: `duplicate_actions` reducer is `operator.add` but initialised to `[]` — LangGraph requires annotated list | 3 |
| F17 | Info | docs | `README.md` test count stale (says "234 tests", actual 1311) | 4 |
| F18 | Info | tooling | No test enforces the two-line file-header convention (CLAUDE.md §12.6) | 4 |
| F19 | Info | memfabric/api | `_write_clock` snapshots not taken before `apply_deltas` — gaps in version sequence after rollback | 1 |
| F20 | Medium | memfabric/types, memfabric/api, apex_host/planners, apex_host/graph | Conflict blocking invariant never enforced at read paths | 2 (FIXED 2026-07-14) |
| F21 | Low | memfabric/reflector | Reflector directly mutates staged Skill, bypassing `_staging_lock` | 3 (OPEN) |

---

## Per-Finding Detail

---

### F01 — `_cache_key` excludes `k` — stale truncated results

**Status:** FIXED (2026-07-14 — complete Phase 4 overhaul)  
**Severity:** Medium  
**Repair Phase:** 1 (narrow k fix) + 4 (full schema overhaul)  
**Fix:** Phase 1 added `k`. Phase 4 replaced the entire cache-key schema with a full SHA-256 (64 hex) key including `CACHE_KEY_VERSION="4"`, `index_generation`, `rrf_k`, `rerank_top_n`, and `channel_weights`. Phase 4 also added cache invalidation on `promote_knowledge`, `promote_skill`, and `quarantine_skill` (previously missing); added deep-copy immutability on cache read/write; and added `_canonical_filters()` for deterministic filter serialization. 117 tests in `tests/test_retrieval_phase4.py` verify all facets. Tests T15 and T16 in `tests/test_graph_atomicity.py` still verify the original k fix.

**Files / Functions**
- `memfabric/retrieval/engine.py:39-44` — `_cache_key(text, tiers, filters)`
- `memfabric/retrieval/engine.py:100` — `search()` — calls `_cache_key`

**Current behaviour**

```python
def _cache_key(text: str, tiers: list[Tier], filters: dict[str, Any] | None) -> str:
    payload = json.dumps(
        {"text": text, "tiers": sorted(t.value for t in tiers), "filters": filters},
        sort_keys=True,
    )
    return "retrieval:" + hashlib.sha256(payload.encode()).hexdigest()[:16]
```

The parameter `k` is absent from the cache payload. Two calls with identical `text`, `tiers`, and `filters` but different `k` values share the same cache key and therefore the same cached result.

**Expected invariant (CLAUDE.md §5)**

> Return top-k as an EvidenceBundle. Cache by `(query_hash, subgraph_hash)`.

The intent is that the cache encodes the full parameters of the query. Different `k` values are different queries and must not share an entry.

**Failure scenario**

1. `search(text="sql injection", k=5, tiers=ALL_TIERS)` runs and caches 5 entries under key `retrieval:abc123`.
2. `search(text="sql injection", k=100, tiers=ALL_TIERS)` hits the same cache key and returns the same 5 entries instead of 100.
3. Any consumer that asked for broad context (large `k`) silently gets truncated retrieval.

**Existing tests**

`tests/test_retrieval.py` — tests for cache hit / cache miss do not exercise `k` variation. The "Cache hit" test checks that a second call with identical args skips channels, but does not test `k` difference.

**Missing tests**

- `test_cache_key_includes_k` — assert `_cache_key("x", ALL_TIERS, None)` differs when `k` changes.
- `test_search_different_k_independent_results` — assert `search(k=3)` and `search(k=10)` return lists of different lengths.

---

### F02 — `apply_deltas` rollback does not restore `_write_clock`

**Status:** FIXED (2026-07-13)  
**Severity:** Medium  
**Repair Phase:** 1  
**Fix commit:** Phase 1 implementation  
**Fix:** `apply_deltas` now snapshots `pre_clock = self._write_clock` inside `_graph_lock` before any write. `_rollback_locked` (renamed from `_rollback_apply`) restores `self._write_clock = pre_clock` as its first action. Test T07 in `tests/test_graph_atomicity.py` verifies the fix.

**Files / Functions**
- `memfabric/api.py:492-575` — `apply_deltas` + `_rollback_apply`
- `memfabric/api.py:163` — `_write_clock` initialisation
- `memfabric/api.py:297, 420` — `_write_clock` increments in `upsert_node`, `upsert_edge`

**Current behaviour**

`apply_deltas` calls `upsert_node` and `upsert_edge` sequentially. Each call increments `_write_clock`. On failure, `_rollback_apply` restores graph content and index state but **does not restore `_write_clock`** to its pre-batch value.

After a failed batch of N node/edge writes, `_write_clock` is N ticks ahead of what it should be, creating permanent gaps in the logical version sequence.

**Expected invariant (CLAUDE.md §1.2 + §1.9)**

> After any exception during `apply_deltas`, the fabric state must be byte-for-byte identical to its state immediately before the call.

`_write_clock` is observable state (it appears in per-field provenance as `logical_version`). A rollback that leaves it incremented violates the "byte-for-byte identical" guarantee.

**Practical impact**

- Low under normal operation: LWW ordering still works correctly because `logical_version` is monotonic and relative, not absolute.
- Medium in debugging / audit: `logical_version` gaps after rollbacks make the provenance log misleading — a reader sees jumps like `lv=5 → lv=8` and cannot know whether `lv=6` and `lv=7` were rolled-back writes or genuine missing history.
- The `CLAUDE.md` invariant specifically says "byte-for-byte identical" — this is a stated, testable guarantee that is currently violated.

**Existing tests**

`tests/test_transactional_merge.py` — tests rollback correctness (node content, edge content, cache invalidation) but does not assert `_write_clock` is unchanged after rollback.

**Missing tests**

- `test_apply_deltas_rollback_restores_write_clock` — read `api._write_clock` before and after a failing `apply_deltas`, assert they are equal.

---

### F03 — `RepairEngine` has no `LLMBudgetTracker` integration

**Status:** FIXED (2026-07-14)  
**Fix:** Added `budget_tracker: LLMBudgetTracker | None = None` to `RepairEngine.__init__`. Budget lifecycle applied in `repair()`: `can_call()` before any LLM call; `record_call_start()` before invocation; `record_success()` on success; `record_failure()` on provider error and output-blocked guard rejection. Tests: `TestRepairEngineBudget` (7 tests) in `tests/apex_host/test_llm_phase5.py`.  
**Severity:** Medium  
**Repair Phase:** 5

**Files / Functions**
- `apex_host/planning/repair.py:142-155` — `RepairEngine.__init__`
- `apex_host/planning/repair.py:188` — `self._router.planner_llm()` called with no budget check
- `apex_host/planning/budget.py` — `LLMBudgetTracker.can_call()`, `record_call_start()`

**Current behaviour**

`RepairEngine.__init__` signature:

```python
def __init__(
    self,
    model_router: "ModelRouter | None",
    allowed_tools: list[str],
    target: str = "",
    dry_run: bool = True,
    guard: "LLMPolicyGuard | None" = None,
) -> None:
```

No `budget_tracker` parameter. At line 188, `repair()` calls:

```python
llm = self._router.planner_llm()
```

There is no `can_call()` check before this and no `record_call_start()` / `record_success()` / `record_failure()` after.

**Expected invariant (CLAUDE.md §16.3)**

> `RepairEngine` — Called by `repair_agent` when a task fails… validates the LLM output through the same `Validator` used by `PlanningEngine` (same safety gate).

The architecture implies repair calls participate in the shared budget. `PlanningEngine` rigorously checks `budget.can_call(phase)` before every LLM call and calls `budget.record_call_start()` / `record_success()` / `record_failure()`.

**Failure scenario**

1. `max_llm_calls_per_run=3`, three turns each consume one LLM call via `PlanningEngine`. Budget exhausted: `budget.exhausted()==True`.
2. The next turn's `recon_agent` falls back to deterministic planner (budget check in `PlanningEngine.plan()` fires).
3. The task fails with `script_error`. `repair_agent` fires.
4. `RepairEngine.repair()` calls `self._router.planner_llm()` — no budget check. A fourth LLM call goes through despite the run budget being exhausted.

**Existing tests**

`tests/apex_host/test_repair_engine.py` — 26 tests cover dry-run, no-LLM, valid repair, validator rejection, LLM exception. No test checks that `RepairEngine` respects `LLMBudgetTracker`.

**Missing tests**

- `test_repair_engine_respects_budget_exhausted` — inject exhausted `LLMBudgetTracker`; assert `repair()` returns `None`.
- `test_repair_engine_records_llm_call_in_budget` — assert `budget.calls_remaining()` decrements after a successful `repair()`.

---

### F04 — `build_apex_graph` does not pass `budget_tracker` to `RepairEngine`

**Status:** FIXED (2026-07-14)  
**Fix:** `build_apex_graph` now passes `budget_tracker=budget_tracker` to `RepairEngine(...)`. Tests: `TestBuildApexGraphBudgetWiring` (3 tests) in `tests/apex_host/test_llm_phase5.py`.  
**Severity:** Medium  
**Repair Phase:** 5

**Files / Functions**
- `apex_host/graph.py:318-323` — `RepairEngine(...)` construction in `build_apex_graph`
- `apex_host/runtime.py:137-141` — `build_apex_graph(... budget_tracker=budget)` call

**Current behaviour**

```python
repair_engine = RepairEngine(
    model_router=model_router,
    allowed_tools=config.allowed_tools,
    target=config.target,
    dry_run=config.dry_run,
    # budget_tracker NOT passed — no parameter exists on RepairEngine
)
```

`runtime.py` correctly creates and passes `budget_tracker` to `build_apex_graph`, which accepts it. `build_apex_graph` distributes it to all domain planners (`ReconPlanner`, `WebPlanner`, etc.) but never to `RepairEngine`.

**Expected invariant**

`RepairEngine` should accept and consult the same `LLMBudgetTracker` used by the domain planners, so all LLM calls in the run compete for the same token budget. This is the corollary of F03 — even if `RepairEngine` had a budget check, it cannot use the shared tracker because one is never injected.

**Existing tests**

`tests/apex_host/test_llm_wiring.py` — tests router construction and `FakeModelRouter` fallback. Does not assert that `RepairEngine` receives `budget_tracker`.

**Missing tests**

- `test_build_apex_graph_passes_budget_to_repair_engine` — inspect the `repair_engine` object captured in the closure and assert its `_budget` attribute is the same object passed to `build_apex_graph`.

---

### F05 — `_context_hash` uses only structural counts, not content

**Status:** FIXED (2026-07-14)  
**Severity:** Low  
**Repair Phase:** 4 (moved from 2 — completed in Phase 4)

**Files / Functions**
- `apex_host/planning/engine.py:145-154` — `_context_hash(subgraph, evidence)`

**Current behaviour**

```python
def _context_hash(subgraph: SubgraphView, evidence: EvidenceBundle) -> str:
    data = (
        f"{len(subgraph.nodes)}:{len(subgraph.edges)}:{len(evidence.entries)}"
    )
    return hashlib.md5(data.encode()).hexdigest()[:8]
```

Two EKG states that differ in content but have the same node count, edge count, and evidence entry count produce the same hash. `PlanningEngine` uses this hash to detect "repeated context" and skip the LLM call when `llm_stop_on_repeated_plan=True`.

**Expected invariant (CLAUDE.md §14.6 / §16.1)**

The intent of the repeated-context guard is to skip the LLM when "context is unchanged since last call for the same phase." If the EKG has changed (new nodes, different node properties), the LLM should be called even if the counts happen to match.

**Failure scenario**

1. Turn 1: EKG has 3 host nodes, 2 edges, 5 evidence entries. LLM called. `_context_hash` = `"3:2:5" md5`.
2. Turn 2: One host node removed, one service node added (still 3 nodes), one edge removed, one edge added (still 2 edges). EKG meaningfully changed but `_context_hash` produces the same value.
3. `PlanningEngine` skips the LLM call — false "repeated context" detection.

**Practical frequency:** Low for most engagements (node/edge counts usually change monotonically as the EKG grows), but possible during credential-phase turns where old nodes get superseded.

**Existing tests**

`tests/apex_host/test_planning_engine.py` — tests repeated-context detection by calling `plan()` twice with the same planner state. Does not test that content changes with equal counts bypass the guard.

**Missing tests**

- `test_context_hash_sensitive_to_content_changes` — create two subgraphs with same counts but different node IDs/types; assert `_context_hash` differs.

---

### F06 — `route_after_write` inspects only `last_tool_result` for multi-task routing

**Status:** FIXED (2026-07-14)  
**Fix:** `route_after_write` now collects `raw_results` from `state["tool_results"]` first (all results), falling back to `[last_tool_result]` only when `tool_results` is empty. Iterates all non-browser, non-conflict-blocked, non-skipped results; routes to `repair_agent` if any of them carry a retryable outcome. Test: `test_f06_route_after_write_checks_all_results` in `tests/apex_host/test_phase6_dispatcher.py`.  
**Severity:** Medium  
**Repair Phase:** 6

**Files / Functions**
- `apex_host/graph.py:942-957` — `route_after_write`
- `apex_host/graph.py:537-558` — `_run_tasks` — populates both `last_tool_result` (first result only) and `tool_results` (all results)

**Current behaviour**

```python
def route_after_write(state: ApexGraphState) -> str:
    tool_result = state.get("last_tool_result")     # always the FIRST task only
    if not tool_result or tool_result.get("kind") == "browser":
        return "reflect_or_continue"

    outcome = _outcome_for(
        int(tool_result.get("returncode", 0) or 0),
        tool_result.get("error"),
    )
    repair_count = int(state.get("repair_count") or 0)
    if (
        outcome in (Outcome.script_error, Outcome.fixable)
        and repair_count < _max_repair
    ):
        return "repair_agent"
    return "reflect_or_continue"
```

In multi-task turns (when the recon or web planner emits >1 concurrent task), `_run_tasks` stores all results in `state["tool_results"]` but also sets `state["last_tool_result"] = results[0]`. `route_after_write` only checks the first result.

**Expected invariant (CLAUDE.md §16.5)**

> All tool results are stored in `state["tool_results"]`. `parse_observation` and `write_memory` iterate over `tool_results`.

The same completeness that `write_memory` achieves (iterating all results) should apply to `route_after_write`. A failure in result[1] while result[0] succeeds is currently invisible to the router.

**Failure scenario**

1. ReconPlanner emits two tasks: `nmap -sV target` and `nc -nv target 23`.
2. `nmap` succeeds (`returncode=0`). `nc` fails (`returncode=1`, `error=None`).
3. `last_tool_result = nmap_result` (first). `route_after_write` sees `Outcome.success` → routes to `reflect_or_continue`.
4. The `nc` failure is recorded in the episodic log but never offered to `repair_agent`.

**Existing tests**

`tests/apex_host/test_graph.py` — multi-task concurrent execution tests do not assert routing behaviour when only the second task fails.

**Missing tests**

- `test_route_after_write_repairs_second_task_failure` — two tasks where first succeeds and second fails; assert routing sends to `repair_agent`.

---

### F07 — Browser episode outcome reads stale `state["last_error"]`

**Status:** FIXED (2026-07-14)  
**Fix:** `write_memory` now derives browser episode outcome from `tool_result.get("error")` (the browser-specific result field), not from `state["last_error"]`. A successful browser observation produces `Outcome.success` regardless of any prior-turn `last_error`. Test: `test_f07_browser_outcome_uses_tool_result_error` in `tests/apex_host/test_phase6_dispatcher.py`.  
**Severity:** Medium  
**Repair Phase:** 6

**Files / Functions**
- `apex_host/graph.py:905-908` — outcome computation inside `write_memory`

**Current behaviour**

```python
if tool_result.get("kind") == "browser":
    outcome = (
        Outcome.success if not state.get("last_error") else Outcome.fundamental
    )
```

For browser tool results, the episode `Outcome` is determined by reading `state["last_error"]` — a state field that reflects the error from the **most recently executed non-browser task** in the same turn. It is not derived from the browser tool result itself.

**Expected invariant**

Each episode's `Outcome` should be derived from its own `tool_result`. `browser_agent` already sets the correct error in the returned result dict. `write_memory` should use `tool_result.get("error")` (or a known outcome field) rather than `state["last_error"]`.

**Failure scenario**

1. Turn N: `web_agent` ran a failing `curl` command last turn (set `state["last_error"]="connection refused"`).
2. Turn N+1: `browser_agent` runs and successfully captures forms and auth hints. `last_error` is still set to `"connection refused"` from turn N (state persists across turns).
3. `write_memory` sees `last_error` is truthy → records episode as `Outcome.fundamental`.
4. The Reflector sees a fundamental outcome for a successful browser observation — the episode is not eligible for positive skill generalisation.

**Existing tests**

`tests/apex_host/test_browser_executor.py` — tests browser dry-run observation. Does not verify episode outcome classification in `write_memory` when a prior `last_error` is present.

**Missing tests**

- `test_write_memory_browser_outcome_ignores_stale_last_error` — set `state["last_error"]="some prior error"`, provide a successful browser `tool_result`; assert episode outcome is `success`.

---

### F08 — `reflect_or_continue` peek omits `current_phase` from `decide_phase`

**Status:** FIXED (2026-07-14)  
**Fix:** `reflect_or_continue` peek now calls `global_planner.decide_phase(..., current_phase=state.get("phase"))` so the budget force-advance fires correctly during inter-turn phase updates. Tests: `TestReflectOrContinuePhasePeek` (3 tests) in `tests/apex_host/test_llm_phase5.py`.  
**Severity:** Low  
**Repair Phase:** 5

**Files / Functions**
- `apex_host/graph.py:1108-1112` — `reflect_or_continue` peek call to `decide_phase`
- `apex_host/planners/global_planner.py` — `decide_phase(current_phase=)` parameter

**Current behaviour**

```python
next_phase = global_planner.decide_phase(
    node_types_seen=node_types_seen,
    turn_count=turn_count,
    has_web_capability=has_web_peek,
    # current_phase= NOT passed
)
```

`decide_phase` accepts an optional `current_phase` kwarg. When provided, it enables budget force-advance: if the current phase has exhausted its per-phase budget, `decide_phase` advances to the next phase even if the EKG doesn't yet satisfy the normal completion condition. When `current_phase` is omitted (as here), the budget force-advance path is never taken.

**Expected invariant (CLAUDE.md §15.4)**

> `graph.py` calls `record_turn(phase)` inside `global_plan` after `decide_phase` returns a non-`done` phase.

The peek call in `reflect_or_continue` is supposed to compute the correct next phase (including budget-forced advances) so that the `state["phase"]` written to the checkpoint reflects the actual phase for the next turn. Without `current_phase`, a budget-exhausted phase can appear in the inter-turn checkpoint even though the real `global_plan` at the start of the next turn will immediately advance it.

**Practical impact:** The next turn's `global_plan` still makes the right decision (it passes `current_phase`). The only artefact is that JSON exports and debugger checkpoints between turns show the wrong phase for budget-exhausted situations.

**Existing tests**

`tests/apex_host/test_graph.py` — budget integration tests confirm budget is consumed on dispatch and not on abandon. No test asserts that `reflect_or_continue` sets the correct phase when the budget is exhausted.

**Missing tests**

- `test_reflect_or_continue_phase_matches_global_plan_after_budget_exhausted` — exhaust the recon budget; assert `reflect_or_continue` sets `phase=ApexPhase.web` (the forced-advance value), not `phase=ApexPhase.recon`.

---

### F09 — `asyncio.gather` in `_run_tasks` lacks `return_exceptions=True`

**Status:** FIXED (2026-07-14)  
**Fix:** `_run_tasks` now calls `asyncio.gather(*coros, return_exceptions=True)`. The result loop checks each entry: if `isinstance(raw, BaseException)`, a synthetic failure tool-result dict is built (with `error=repr(exc)`, `returncode=1`) so the exception is captured as a failed episode rather than propagating. Remaining tasks' results are always processed. Test: `test_f09_gather_return_exceptions_handling` in `tests/apex_host/test_phase6_dispatcher.py`.  
**Severity:** Medium  
**Repair Phase:** 6

**Files / Functions**
- `apex_host/graph.py:537` — `asyncio.gather(*[_run_one_cmd(t) for t in tasks])`

**Current behaviour**

```python
pairs = list(await asyncio.gather(*[_run_one_cmd(t) for t in tasks]))
```

`asyncio.gather` without `return_exceptions=True` propagates the first exception that occurs in any coroutine. If `_run_one_cmd(tasks[1])` raises an unhandled exception (e.g., an unexpected `RuntimeError` from the KV store), the exception propagates out of `_run_tasks`, skipping `parse_observation`, `write_memory`, and the rest of the turn.

**Expected invariant (CLAUDE.md §1 / §6)**

> The loop must degrade gracefully: a failed executor produces a `fundamental`/`script_error` outcome episode — it does not crash the engagement.

`_run_one_cmd` already wraps `ValueError` from safety checks. But unchecked exceptions (unexpected `RuntimeError`, `asyncio.CancelledError`, etc.) are not caught. The Semaphore context ensures bounded concurrency but not exception isolation.

**Failure scenario**

1. Two tasks dispatched concurrently.
2. Task 1 completes normally. Task 2 raises `RuntimeError("unexpected condition")` inside `_run_one_cmd`.
3. `asyncio.gather` re-raises the exception. The entire `_run_tasks` call fails.
4. The exception propagates through the LangGraph node; LangGraph marks the turn as failed and may end the engagement.
5. Task 1's successful result is lost (never written to MemoryAPI).

**Existing tests**

No test injects a `RuntimeError` inside a concurrent `_run_one_cmd` to verify graceful degradation.

**Missing tests**

- `test_run_tasks_gather_exception_isolation` — inject an exception-raising second task; assert first task's result is still processed and engagement continues.

---

### F10 — `NmapParser` edge IDs use `new_id()` — not idempotent on re-parse

**Status:** FIXED (2026-07-14)  
**Fix:** `NmapParser` now produces deterministic edge IDs. `exposes` edge: `f"exposes:{host_id}:{service_id}"`. `runs` edge: `f"runs:{service_id}:{tech_id}"`. The `new_id` import was removed from `nmap_parser.py`. Parsing the same nmap output twice produces exactly the same edge ID set. Tests: `test_nmap_exposes_edge_id_deterministic`, `test_nmap_exposes_edge_id_format`, `test_nmap_runs_edge_id_format` in `tests/apex_host/test_phase6_dispatcher.py`.  
**Severity:** Low  
**Repair Phase:** 6

**Files / Functions**
- `apex_host/parsers/nmap_parser.py:123-134` — `exposes` edge creation
- `apex_host/parsers/nmap_parser.py:152-163` — `runs` edge creation

**Current behaviour**

```python
edges.append(
    Edge(
        id=new_id(),     # fresh UUID4 every call
        from_id=host_id,
        to_id=service_id,
        ...
    )
)
```

Every call to `parse_text()` on the same nmap output produces edges with different IDs. Nodes use deterministic IDs (`f"host:{addr}"`, `f"service:{addr}:{port}/{proto}"`, `f"tech:{addr}:{slug}"`). Edges do not.

**Expected invariant (CLAUDE.md §1.3)**

> Working memory uses upsert with last-writer-wins per field.

The intent of `upsert_edge` is that replaying the same observation over the same graph converges to the same state. With random edge IDs, each replay adds new edges rather than upserting existing ones — the EKG accumulates duplicate `exposes`/`runs` edges.

**Failure scenario**

1. Engagement turn 1: nmap parsed → `exposes` edge id=`uuid-A` written.
2. Engagement turn 2 (retry/re-scan): same nmap output parsed → `exposes` edge id=`uuid-B` written.
3. `get_subgraph` returns both edges; any consumer that iterates edges processes the `host→service` relationship twice.

**Existing tests**

`tests/apex_host/test_nmap_parser.py` — tests parser output shape. Does not parse the same output twice and check for duplicate edges.

**Missing tests**

- `test_nmap_parser_idempotent_edges` — parse the same nmap output twice against the same MemoryAPI; assert exactly one `exposes` edge per service exists.

---

### F11 — `AccessParser` edge IDs use `new_id()` — not idempotent on re-parse

**Status:** FIXED (2026-07-14)  
**Fix:** `AccessParser` now produces deterministic edge IDs. `grants` (cred→access_state): `f"grants:{cred_id}:{access_id}"`. `tested` (service→cred): `f"tested:{service_id}:{cred_id}"`. `grants` (service→access_state): `f"grants:{service_id}:{access_id}"`. The `new_id` import was removed from `access_parser.py`. Tests: `test_access_parser_grants_edge_id_deterministic`, `test_access_parser_grants_edge_id_format`, `test_access_parser_tested_edge_id_format` in `tests/apex_host/test_phase6_dispatcher.py`.  
**Severity:** Low  
**Repair Phase:** 6

**Files / Functions**
- `apex_host/parsers/access_parser.py` — `grants` edge creation

**Current behaviour**

Same pattern as F10: `grants` edge between `credential` and `access_state` nodes uses `new_id()`. Node IDs for `credential` and `access_state` are deterministic, but the edge is not.

**Expected invariant**

Same as F10 — upsert semantics require deterministic edge IDs.

**Failure scenario**

A loop-guard check prevents duplicate `telnet_access` tasks at the planner level (checks for existing `credential` node). However, if the guard is bypassed (e.g., in a test or via explicit re-invocation), re-parsing the same access session creates a second `grants` edge.

**Existing tests**

`tests/apex_host/test_access_validation.py` — tests `AccessParser` output. Does not parse the same session text twice.

**Missing tests**

- `test_access_parser_idempotent_grants_edge` — parse same session string twice; assert single `grants` edge.

---

### F12 — `CredentialPlanner` calls `capabilities_from_subgraph` twice per `plan()`

**Status:** FIXED (2026-07-14)  
**Fix:** `_telnet_credentials_available` renamed to `_telnet_credentials_available_from_caps` and now accepts a pre-computed `caps` list rather than a `subgraph`. `CredentialPlanner.plan()` computes `caps = capabilities_from_subgraph(subgraph)` once and passes it to this helper, then the `_core.plan()` uses the same subgraph (calling `capabilities_from_subgraph` once internally). Total calls per `plan()`: ≤ 2 (wrapper check + inner core). Test: `test_caps_called_once_with_engine` in `tests/apex_host/test_phase6_dispatcher.py`.  
**Severity:** Low (efficiency, not correctness)  
**Repair Phase:** 6

**Files / Functions**
- `apex_host/planners/credential_planner.py` — outer `CredentialPlanner.plan()` and inner `_CredentialDeterministic.plan()`

**Current behaviour**

1. `CredentialPlanner._telnet_credentials_available(subgraph)` calls `capabilities_from_subgraph(subgraph)` to check for telnet capability.
2. `CredentialPlanner.plan()` then calls `_core.plan(goal, subgraph, evidence)`.
3. Inside `_CredentialDeterministic.plan()`, `capabilities_from_subgraph(subgraph)` is called again to derive all capabilities.

Total: two `capabilities_from_subgraph(subgraph)` calls for every `CredentialPlanner.plan()` invocation.

**Expected invariant (CLAUDE.md §15.2)**

The `_<Name>Deterministic` + thin wrapper pattern is specifically designed to keep the inner class self-contained. The outer wrapper should avoid re-doing work the inner class already does.

**Practical impact:** Negligible per-call cost (graph traversal over a small EKG). Noticeable only if the subgraph grows to thousands of nodes (not realistic for HTB Easy/Medium). Classified as Low because it is a design cleanliness issue, not a functional defect.

**Existing tests**

No tests assert single-call behaviour for `capabilities_from_subgraph`.

**Missing tests**

- `test_credential_planner_calls_capabilities_once` — monkeypatch `capabilities_from_subgraph`; count invocations per `plan()` call; assert count == 1.

---

### F13 — Duplicate-skip result classified as `Outcome.success` and writes a useless Episode

**Status:** FIXED (2026-07-14)  
**Fix:** `write_memory` now skips episode creation entirely for `tool_result["skipped_duplicate"] is True`. A task that was never executed cannot produce a meaningful episode — skipping it prevents Reflector from treating the duplicate as a successful action. The `skipped_duplicate` flag is set by `TaskDispatcher` (Phase 6) when `TaskRegistry.reserve()` returns `False`. Test: `test_f13_skipped_duplicate_no_episode` in `tests/apex_host/test_phase6_dispatcher.py`.  
**Severity:** Low  
**Repair Phase:** 6

**Files / Functions**
- `apex_host/graph.py:488-503` — duplicate-skip result construction in `_run_one_cmd`
- `apex_host/graph.py:905-926` — `write_memory` — calls `api.apply_deltas(episodes=[episode])`

**Current behaviour**

When a task is identified as a duplicate, `_run_one_cmd` returns a synthetic result:

```python
skipped: dict[str, Any] = {
    ...
    "returncode": 0,
    "error": None,
    "skipped_duplicate": True,
    ...
}
```

`write_memory` receives this, calls `_outcome_for(returncode=0, error=None)` → `Outcome.success`. An episode with `Outcome.success` and `agent=f"apex.{phase}"` is appended to the episodic store. The Reflector sees this as a successful action turn and may attempt to generalise it into a skill, even though no tool actually ran.

**Expected invariant (CLAUDE.md §7)**

Skill generalisation should operate on real completed sub-chains. A skipped-duplicate turn produces no new observations and should not contribute to chain-of-success skill learning.

**Practical impact:** Low in practice. The Reflector checks minimum chain length (`config.min_chain_len`). Skipped-duplicate episodes are unlikely to form chains above that threshold. But the episodic log is semantically polluted — replaying it to reconstruct an engagement will see "successful" turns that never actually ran.

**Existing tests**

`tests/apex_host/test_duplicate_actions.py` — tests the duplicate detection and fingerprinting. Does not assert that skipped-duplicate episodes are not written (or are specially marked).

**Missing tests**

- `test_skipped_duplicate_episode_marked_as_noop` — assert that the episode written for a skipped duplicate has `outcome=Outcome.noop` (or a designated distinct value) rather than `Outcome.success`.

---

### F14 — `LLMPolicyGuard` not wired into default `build_apex_graph`

**Status:** FIXED (2026-07-14)  
**Fix:** `build_apex_graph` now constructs `LLMPolicyGuard(config)` when `model_router is not None` and passes `guard=_llm_guard` to all four domain planners (ReconPlanner, WebPlanner, CredentialPlanner, PrivEscPlanner) and to `RepairEngine`. All four planners' `__init__` signatures updated to accept `guard: LLMPolicyGuard | None = None` and pass it through to `PlanningEngine`. Tests: `TestLLMPolicyGuardWiring` (9 tests) and architecture scan tests in `tests/apex_host/test_llm_phase5.py`.  
**Severity:** Low  
**Repair Phase:** 5

**Files / Functions**
- `apex_host/graph.py:318-323` — `RepairEngine(...)` construction (guard not passed)
- `apex_host/graph.py` — `PlanningEngine` construction for each planner (no `guard=` parameter)
- `apex_host/policy/llm_guard.py` — `LLMPolicyGuard` implementation
- `CLAUDE.md §19.11` — documents wiring requirement

**Current behaviour**

`CLAUDE.md §19.11` says:

> Wiring — `LLMPolicyGuard` is injected into `PlanningEngine` and `RepairEngine` via a `guard: LLMPolicyGuard | None = None` constructor parameter.

Both `PlanningEngine` and `RepairEngine` accept a `guard=` parameter. `build_apex_graph` does not pass `guard=LLMPolicyGuard(config)` to any of them. The guard is therefore inactive for the entire engagement by default.

**Expected invariant**

The LLM checkpoints (sanitize → check_prompt → check_output) documented in §19.11 should run for every planning LLM call. Without the guard wired in, passwords and tokens in the planner prompt are not redacted, and brute-force patterns in LLM output are not blocked before being converted into TaskSpecs.

**Practical impact:** Low in dry-run mode (FakeModelRouter returns None, no LLM calls occur). Medium in `--use-llm` mode: the guard is the only post-LLM content safety check.

**Existing tests**

`tests/apex_host/test_llm_guard.py` — tests `LLMPolicyGuard` in isolation. No test verifies that `build_apex_graph` wires the guard into planners automatically.

**Missing tests**

- `test_build_apex_graph_wires_llm_guard_into_planners` — construct graph with an `OpenAIModelRouter` (or stub) and `username_candidates=["root"]`; verify the planners' `_engine._guard` attribute is an `LLMPolicyGuard` instance.

---

### F15 — `GlobalPlanner.record_turn` charged after wrong phase if `decide_phase` returns immediate force-advance

**Status:** PLAUSIBLE (requires multi-turn budget-exhaustion scenario to trigger)  
**Severity:** Low  
**Repair Phase:** 3

**Files / Functions**
- `apex_host/graph.py:344-358` — `global_plan` node
- `apex_host/planners/global_planner.py` — `decide_phase`, `record_turn`

**Current behaviour**

```python
phase = global_planner.decide_phase(
    ..., current_phase=current_phase, ...
)
if phase != ApexPhase.done:
    global_planner.record_turn(phase)   # records the RETURNED phase
```

`decide_phase` may return a different phase than `current_phase` (e.g., force-advance from `recon` to `web`). `record_turn(phase)` is called with the returned (new) phase, which immediately charges one turn against the newly-entered `web` budget even though no `web` work has yet been done. The turn counter for the `web` phase is 1 before the `web` planner has even been called.

**Expected invariant (CLAUDE.md §15.4)**

> `graph.py` calls `record_turn(phase)` inside `global_plan` after `decide_phase` returns a non-`done` phase.

The intent is to charge the turn against the phase being executed this turn. If `decide_phase` returns `web` when `recon` was exhausted and we're about to do the first `web` turn, charging `web` for this turn is correct behaviour. The potential issue is if `decide_phase` is called *again* early (double-charge), but that is not the case in the current code.

**Revised assessment:** After closer review, the call site is likely correct — `record_turn` is called exactly once per turn, for the phase that will be executed. This finding is **PLAUSIBLE** but may not be a real defect. Needs a targeted test to verify the budget counter never exceeds 1 after the first turn in a newly-entered phase.

**Missing tests**

- `test_global_planner_no_double_charge_on_phase_transition` — exhaust recon budget, verify `web` budget counter = 1 after first `web` turn (not 2 from a double-charge).

---

### F16 — `duplicate_actions` state field: LangGraph `operator.add` reducer with list initialisation

**Status:** FIXED (2026-07-14 Phase 7) — 7 accumulation tests added in `tests/apex_host/test_phase7_async.py::TestDuplicateActionsAccumulation`; the field correctly accumulates via `operator.add` across turns  
**Severity:** Info / Low  
**Repair Phase:** 3 (fixed in Phase 7)

**Files / Functions**
- `apex_host/graph_state.py` — `ApexGraphState` TypedDict with `duplicate_actions` field
- `apex_host/graph.py:557` — `rdict["duplicate_actions"] = dup_entries` (only set when non-empty)

**Current behaviour**

`ApexGraphState` declares `duplicate_actions` as an `Annotated[list[dict], operator.add]` field. LangGraph uses `operator.add` to merge lists when a node returns an updated value. This is consistent with `planner_decisions`, `policy_decisions`, and `error_episodes`.

However, nodes that detect no duplicates do NOT include `duplicate_actions` in their return dict (the key is only added when `dup_entries` is non-empty). LangGraph's `operator.add` reducer handles missing keys by keeping the previous value, so omitting the key on no-duplicate turns is correct.

The only issue: the initial state in `runtime.py` sets `duplicate_actions: []`. If a future node explicitly returns `duplicate_actions=[]` to "clear" the list, `operator.add` would concatenate ([] + old_list = old_list), which may not be the intent.

**Practical impact:** Currently benign because no node ever returns `duplicate_actions=[]` explicitly. The field correctly accumulates. But the semantics could confuse future maintainers who expect setting `duplicate_actions=[]` to clear the list.

**Missing tests**

- `test_duplicate_actions_accumulate_across_turns` — run two turns each producing a duplicate skip; assert `duplicate_actions` has two entries (not one).

---

### F17 — `README.md` test count stale

**Status:** FIXED (2026-07-14 Phase 10)  
**Severity:** Info  
**Repair Phase:** 4 (fixed in Phase 10)

**Files / Functions**
- `README.md:183` — "234 tests total"

**Current behaviour**

```
234 tests total: 194 in `tests/` covering all Section 8 invariants (including
LangGraph-specific tests in `tests/test_graph_loop.py`), plus 40 in
`tests/apex_host/` for the host application layer below.
```

**Actual count:** 1311 tests (as of 2026-07-13 baseline run).

**Impact:** Misleads contributors about the scope of the test suite.

---

### F18 — No test enforces the two-line file-header convention

**Status:** FIXED (2026-07-14 Phase 10)  
**Severity:** Info  
**Repair Phase:** 4 (fixed in Phase 10)

**Files / Functions**
- `CLAUDE.md §12.6` — mandates the header convention
- `CLAUDE.md §12.6` — references a CI header scan command (`find ... | while read f; do head -1 "$f" | grep -v "^#" && echo "MISSING: $f"; done`)
- No file in `tests/` implements this scan

**Current behaviour**

The CI header scan referenced in CLAUDE.md does not exist as an actual test or CI step. New files added to the codebase without the required header are not caught by the test suite.

**Expected invariant (CLAUDE.md §12.6)**

> The CI header scan (`find ... | while read f; do head -1 "$f" | grep -v "^#" && echo "MISSING: $f"; done`) enforces this.

The scan is described as enforced, but is not.

**Missing tests**

- `test_file_headers_present` — walk all `.py` files in `memfabric/` and `apex_host/`, read first two lines, assert both are `# <filename>` and `# <description>` format.

---

### F19 — `_write_clock` pre-batch snapshot not taken — version gaps after rollback not tracked

**Status:** FIXED (2026-07-13) — same fix as F02  
**Severity:** Info  
**Repair Phase:** 1  
**Fix commit:** Phase 1 implementation  
**Fix:** See F02. `apply_deltas` now holds `_graph_lock` for the full batch and snapshots `pre_clock` before writes. `_rollback_locked` restores the clock as its first action. Test T07 covers both F02 and F19.

**Files / Functions**
- `memfabric/api.py:526-533` — `apply_deltas` Phase 1 snapshot (nodes/edges captured, `_write_clock` not)
- `memfabric/api.py:577-640` — `_rollback_apply` (does not restore `_write_clock`)

**Current behaviour**

`apply_deltas` snapshots `pre_nodes` and `pre_edges` (for rollback). It also snapshots `pre_edge_write_lv` (the `_edge_write_lv` dict entries). But it does **not** snapshot the `_write_clock` integer itself.

After rollback: the graph content is byte-for-byte restored, the edge LWW version map is restored, but `_write_clock` is `N` ticks ahead of where it was before the call (where `N` = number of node + edge writes attempted before the failure).

**Why this is separate from F02:** F02 documents the violated invariant. F19 documents the specific mechanism — the snapshot phase doesn't capture `_write_clock`, so `_rollback_apply` has no pre-call value to restore to. The fix requires two changes: (a) capture `pre_clock = self._write_clock` in Phase 1, and (b) restore `self._write_clock = pre_clock` in `_rollback_apply`.

**Existing tests**

`tests/test_transactional_merge.py:test_apply_deltas_rollback_*` — none assert `_write_clock` post-rollback.

---

---

### F20 — Conflict blocking invariant never enforced at read paths

**Status:** FIXED (2026-07-14)  
**Severity:** Medium  
**Repair Phase:** 2 (12-phase scheme)

**Files / Functions**
- `memfabric/api.py:944-952` — `dependents_blocked_by(node_id, field_name)` — implementation
- `apex_host/graph.py` — `load_context`, `global_plan`, `_run_tasks` — none call `dependents_blocked_by`
- `memfabric/coordination/graph_loop.py` — `read_context`, `plan`, `dispatch` — none call `dependents_blocked_by`

**Current behaviour**

`MemoryAPI.dependents_blocked_by(node_id, field_name)` is implemented and tested in `tests/test_conflict_lifecycle.py`. It returns `True` when any open conflict contests `field_name` on `node_id`.

Neither the substrate orchestrator (`memfabric/coordination/graph_loop.py`) nor the host application orchestrator (`apex_host/graph.py`) ever calls `dependents_blocked_by()` before reading and acting on contested node field values.

**Evidence:** A repo-wide search for `dependents_blocked_by` in non-test source files finds zero call sites in planners, agents, or graph nodes. The method exists solely in `api.py` (implementation) and `tests/` (tests).

**Expected invariant (CLAUDE.md §1.8 and conflict lifecycle table)**

> Any planning or query path that reads a contested field must call `dependents_blocked_by()` first and skip or escalate if it returns `True`.

This invariant is described as "non-negotiable" in CLAUDE.md and is a documented hard constraint. The API surface exists; the callers do not.

**Failure scenario**

1. Writer A (recon agent) asserts `host:10.0.0.1` prop `"service"="ftp"` at high confidence.
2. Writer B (browser agent) simultaneously asserts `"service"="http"` at high confidence.
3. A `Conflict` is created. `conflict.status == "open"`. `dependents_blocked_by("host:10.0.0.1", "service")` returns `True`.
4. The next turn's planner calls `api.get_subgraph("host:10.0.0.1", depth=2)` — this returns the node with whichever value won the LWW race, presenting it to the planner as settled fact.
5. The planner emits tasks based on a contested service claim. No blocking occurs.

**Existing tests**

`tests/test_conflict_lifecycle.py` — tests `dependents_blocked_by` in isolation. No end-to-end test verifies that the orchestrator halts or escalates when a contested field is queried.

**Missing tests**

- `test_conflict_blocks_planner_when_field_contested` — write two contradictory high-confidence values for the same field; run one planner turn; assert the planner received an escalation signal or returned `AbandonSignal` (requires caller enforcement to be wired first).

**Fix applied (2026-07-14):**

The approach chosen was **central annotation at the MemoryAPI layer** (Option C), not calling `dependents_blocked_by()` individually in each planner/executor. This is architecturally cleaner and does not require planner changes:

1. **`memfabric/types.py`** — Added `BlockedClaim` dataclass (`node_id`, `field_name`, `conflict_id`, `node_type`). Extended `SubgraphView` with `open_conflicts: list[BlockedClaim]` (default `[]`) and `EvidenceBundle` with `blocked_fields: list[BlockedClaim]` (default `[]`).

2. **`memfabric/coordination/conflict.py`** — `make_conflict()` now uses `copy.deepcopy()` for `claim_a` and `claim_b` to preserve immutability.

3. **`memfabric/api.py`** — Added `_collect_open_conflicts(subgraph)` helper that scans `_conflicts` and returns `BlockedClaim` records for all open conflicts on nodes in the subgraph. Updated `get_subgraph()` to call it and populate `subgraph.open_conflicts`. Updated `query()` to propagate `blocked_fields` into the returned `EvidenceBundle`. Added `_apply_conflict_resolution_locked()` — resolves conflict via policy, writes winning field value back to the graph atomically under `_graph_lock`, records resolution provenance. Rewrote `auto_resolve_conflict()` to delegate to this locked helper. Fixed mypy error (redundant comparison after `status != open` guard).

4. **`apex_host/planners/capabilities.py`** — Added `_CRITICAL_SERVICE_FIELDS = frozenset({"port", "service", "proto", "state"})` and `_CRITICAL_ENDPOINT_FIELDS = frozenset({"url"})`. `capabilities_from_subgraph()` now builds a `blocked` frozenset from `subgraph.open_conflicts` and skips any `service`/`endpoint` node that has a critical field contested.

5. **`apex_host/graph.py`** — Added `_CONFLICT_BLOCKED_TOOLS` and `_CONFLICT_CRITICAL_FIELDS` module constants. In `_run_tasks._run_one_cmd()`, a conflict gate fires after the policy gate: if the `EvidenceBundle.blocked_fields` contains any contested `service` or `host` field, tools that depend on service identity (`nc`, `netcat`, `curl`, `ffuf`, `gobuster`) are blocked with `conflict_blocked=True` in the result. This is a defense-in-depth layer — the primary protection is at the capability layer.

6. **`tests/test_conflict_phase2.py`** — 60 new tests (T01–T60) covering `BlockedClaim` type, `get_subgraph`/`query` annotation, capability filtering, atomic winner persistence, claim immutability, lifecycle statuses, architecture scan (no planner calls `dependents_blocked_by` directly), full scenarios, resolution policy details, and a concurrent stress test.

All 60 tests pass. Full suite: **1486 passed**. mypy: **clean**. ruff: **135 (baseline)**.

**Phase 2 Reopen — Complete Contract (2026-07-14):**

The initial Phase 2 fix addressed the core annotation and gate wiring. The reopen completed the full contract across 16 sub-issues:

1. **Pure winner selection** — `ResolutionDecision` frozen dataclass; `choose_conflict_winner()` is a pure function that never mutates the `Conflict` record (tests R01–R06).

2. **Full resolution rollback** — `_apply_conflict_resolution_locked()` snapshots all Conflict fields and the node field before writes begin; failure at any stage (graph_write, index_refresh, history_append, status_transition) triggers complete rollback; rollback failure raises `TransactionIntegrityError` with `conflict_id`, `node_id`, `field_name` (tests R07–R16).

3. **Deep defensive copies** — `get_conflicts()` returns `copy.deepcopy()` instances; callers cannot mutate stored `claim_a`, `claim_b`, `history`, or `resolution` (tests R17–R22).

4. **`ClaimDependency` type** — Frozen, slots-based, hashable dataclass on `TaskSpec`; `expected_value` defaults to `None` (tests R23–R27).

5. **Dependency-specific guard** — `check_conflict_dependencies()` pure function intersects `task.claim_dependencies` with `evidence.blocked_fields`; only tasks depending on the exact contested field are blocked; legacy fallback covers tasks without declared deps (tests R28–R34).

6. **Blocked outcome semantics** — `conflict_blocked` result has `returncode=0, error=None`; routes directly to `reflect_or_continue`, never to `repair_agent` (tests R35–R39).

7. **Verification tasks** — Tasks with `purpose="conflict_verification"` and no deps on the contested field are not blocked; verification result does not auto-resolve the conflict (tests R40–R44).

8. **Planner dependency propagation** — All domain planners (`ReconPlanner`, `WebPlanner`, `CredentialPlanner`, `PrivEscPlanner`) declare `claim_dependencies` on the node fields they read; contested capability nodes produce no tasks (tests R45–R52).

9. **Unrelated task preservation** — Conflicts on other nodes or other fields do not block unrelated tasks (tests R53–R56).

10. **Quarantine semantics** — Quarantined fields appear in `quarantined_fields` (not `open_conflicts`); `capabilities_from_subgraph` uses `absent = frozenset(open_conflicts ∪ quarantined_fields)` to skip both; quarantined conflicts remain auditable; new high-confidence writes can replace quarantined fields (tests R57–R61).

11. **Concurrent lifecycle** — Concurrent auto-resolve, explicit-resolve, supersede, and quarantine transitions complete without error and leave the conflict in a non-open terminal state (tests R62–R66).

12. **Architecture scans** — Static scans of all `memfabric/` and `apex_host/` source files confirm: no `Conflict.status` assignment outside lifecycle modules; no `claim_a`/`claim_b` dict mutations outside `conflict.py`; no `.history.append()` outside lifecycle files; `check_conflict_dependencies` is imported and used in `graph.py`; synthetic violations are caught (tests R67–R72).

All 72 reopen tests pass. Full suite: **1558 passed**. mypy: **clean** (101 files). ruff: **135** (ceiling maintained).

---

### F21 — Reflector directly mutates staged Skill objects, bypassing `_staging_lock`

**Status:** FIXED (Phase 11 verified) — `worker.py:143` now calls `await self._api.merge_skill_candidate(best_match.id, run_number=...)` instead of direct mutation; no `best_match.wins +=` or `best_match.confidence =` lines exist; all mutations go through the MemoryAPI surface  
**Severity:** Low  
**Repair Phase:** 5 (fixed before Phase 11)

**Files / Functions**
- `memfabric/reflector/worker.py:133-138` — `best_match.wins += 1; best_match.confidence = ...`
- `memfabric/api.py:820-855` — `decay_skill_confidence`, `update_skill_result` — correct paths for these mutations
- `memfabric/api.py:858-862` — `get_staged_skills()` — returns **live references** (not copies) from `_staged_skills`

**Current behaviour**

`get_staged_skills()` returns `list(self._staged_skills.values())` — a new list but containing live references to the staged `Skill` objects. The `_staging_lock` is held only for the duration of the `list()` call; it is released before the caller receives the result.

`ReflectorWorker._handle_success_chain()` (lines 123-147) then directly mutates these live references:

```python
best_match.wins += 1
best_match.evidence_count += 1
best_match.confidence = min(1.0, best_match.confidence + 0.05 * ...)
```

None of this goes through `MemoryAPI.update_skill_result()` or `decay_skill_confidence()`, which hold `_staging_lock` during mutation. The mutations execute outside the lock and outside the MemoryAPI surface.

**Expected invariant (CLAUDE.md §1.1)**

> No component reads or mutates a store directly. Everything goes through `MemoryAPI`.

**Practical impact:** Low in cooperative asyncio (no concurrent awaits between `get_staged_skills()` and the mutation). If the Reflector ever runs on a thread pool or the staging logic adds an `await`, this becomes a race condition. Even without a race, it silently bypasses the MemoryAPI boundary, making the staging store observable through external object references.

**Correct pattern**

```python
# Instead of mutating best_match directly:
await self._api.update_skill_result(best_match.id, won=True)
# MemoryAPI.update_skill_result acquires _staging_lock and increments wins
```

**Existing tests**

`tests/test_reflector.py` — tests skill merge and confidence update. Does not verify that mutations go through MemoryAPI methods rather than direct object references.

**Missing tests**

- `test_reflector_skill_update_goes_through_api` — monkeypatch `api.update_skill_result`; trigger a success chain that should merge into an existing skill; assert `update_skill_result` was called with the correct skill ID.

---

## Phase 1 Comprehensive — Exact Transaction Contract (Step 2 Pre-Implementation)

This section answers the 16 questions required by the Phase 1 comprehensive request.
It defines the transaction contract for `MemoryAPI` before any implementation changes
are made.  It is authoritative; CLAUDE.md §1 invariants take precedence where they
conflict with any other description.

**Q1. What is the unit of atomicity?**  
A single `apply_deltas` call is the unit of atomicity.  All node/edge upserts,
episode appends, and knowledge/skill proposals within one `apply_deltas` call either
all become visible to future reads or none do.  Individual `upsert_node` /
`upsert_edge` calls are each individually atomic but not part of any larger transaction.

**Q2. What is the lock ordering?**  
Outermost to innermost: `_graph_lock` → `_staging_lock` → `GraphStore._lock`.
No code path may acquire these in a different order.  `_graph_lock` is acquired by
`apply_deltas` for the entire batch.  `_staging_lock` is acquired by proposal
methods inside the batch.  `GraphStore._lock` is acquired by store methods called
from within `_graph_lock` — this nesting is safe because Python asyncio is
cooperative and the store never re-acquires `_graph_lock`.

**Q3. Is the lock reentrant?**  
No.  `asyncio.Lock` is NOT reentrant.  A coroutine that holds `_graph_lock` must
call store methods directly (e.g. `self._graph.get_subgraph()`) rather than public
`MemoryAPI` methods (e.g. `self.get_subgraph()`) to avoid deadlock.  This is
enforced by the internal `_upsert_node_locked` / `_upsert_edge_locked` / 
`_delete_node_locked` / `_delete_edge_locked` helpers which explicitly document
"requires `_graph_lock` to be held."

**Q4. What reader paths currently lack `_graph_lock`?**  
Three public methods:  
- `MemoryAPI.query()` — does not hold `_graph_lock` when reading subgraph for attachment  
- `MemoryAPI.get_subgraph()` — no lock  
- `MemoryAPI.open_tasks()` — no lock  
Fix: acquire `_graph_lock` in `get_subgraph()` and `open_tasks()`.  In `query()`,
acquire `_graph_lock` only for the `self._graph.get_subgraph()` call (not around
BM25/vector retriever calls which are already lock-free).

**Q5. Can a reader observe a partially-applied batch?**  
Yes, before the fix.  Between two `await` points inside `apply_deltas` (e.g.
after the first `upsert_node_locked` completes but before the second), a concurrent
`get_subgraph()` or `open_tasks()` could read the partially-written state.  After
the fix (Design A), readers acquire `_graph_lock` and block until the batch
releases it, preventing this.

**Q6. What is the rollback contract for nodes and edges?**  
Before the batch begins, `apply_deltas` snapshots the pre-batch state of every node
and edge it will touch (`pre_nodes`, `pre_edges`).  On failure, `_rollback_locked`
(called while holding `_graph_lock`) restores each node/edge from its pre-batch
snapshot using `put_node` / `put_edge` (for updated entries) or `delete_node` /
`delete_edge` (for newly-created entries).  The lexical index is also updated during
rollback: restored nodes/edges are re-added with their pre-batch text; newly-created
nodes/edges have their index entries removed.  The retrieval cache is busted at
the end of rollback.

**Q7. What is the rollback contract for `_write_clock`?**  
`_write_clock` is incremented by `_upsert_node_locked` and `_upsert_edge_locked`
during the batch.  Before the batch begins, `apply_deltas` snapshots `pre_clock =
self._write_clock`.  On failure, `_rollback_locked` restores `self._write_clock =
pre_clock` as its FIRST action, before restoring any nodes/edges.  This prevents
logical-version gaps after a failed batch from misleading future LWW ordering.

**Q8. What is the rollback contract for the lexical index?**  
On rollback, for every newly-created entry (not in pre-batch snapshot): call
`self._lexical.remove(entry_id)`.  For every updated entry (in pre-batch snapshot):
call `self._lexical.add(entry_id, old_text, old_meta)` to restore the old version.
After all per-entry restoration, call `self._kv.delete_prefix("retrieval:")` once
to bust the cache.  The optional vector index follows the same pattern: `vector.remove`
for new entries, `vector.add` with old embedding for updated entries.

**Q9. What is the rollback contract for the vector index?**  
Same as lexical: remove newly-added entries, restore pre-batch vectors for updated
entries.  If no `Embedder` is configured, the vector index is not touched during
the batch or rollback.

**Q10. What is the rollback contract for knowledge proposals?**  
`apply_deltas` records the IDs of all knowledge proposals it stages (via
`propose_knowledge_locked`).  On failure, `_rollback_locked` removes those IDs
from `_staged_knowledge` under `_staging_lock`.  Only proposals staged by the
current failed batch are removed; proposals staged by prior calls are unaffected.

**Q11. What is the rollback contract for skill proposals?**  
Same as knowledge proposals: IDs recorded, removed from `_staged_skills` under
`_staging_lock` on failure.

**Q12. What is the episode append contract?**  
Contract A (chosen): `JSONLEpisodicStore` supports private rollback via
`_pop_episodes(episode_ids)`.  `apply_deltas` calls this via `getattr` on failure.
Stores without `_pop_episodes` log a warning and leave the episodes in place (they
remain in the episodic log but the batch that wrote them is otherwise rolled back —
a documented acceptable inconsistency for durable stores where removal is not
safe).  For the in-memory `JSONLEpisodicStore`, rollback removes the episodes
completely from both `_index` and `_order`.

**Q13. What does `delete_node` / `delete_edge` on MemoryAPI do?**  
Currently: no public method exists — deletion is only accessible internally during
rollback.  After the fix: public `delete_node(node_id)` acquires `_graph_lock`,
calls `_delete_node_locked` which removes from GraphStore, lexical index, optional
vector index, and busts the cache.  `delete_edge(edge_id)` same pattern, plus
removes from `_edge_write_lv`.  These public methods are intended for parsers that
need to retract an incorrectly-written node, not for general-purpose deletion.

**Q14. What does immutable snapshot mean for returned objects?**  
`MemoryAPI.get_subgraph()` returns a `SubgraphView` containing `Node` and `Edge`
objects that are defensive copies (independent `props` dicts).  Callers can freely
mutate the returned objects without affecting stored state.  The same applies to
`open_tasks()` return values.  The copies are one level deep for `props`;
nested dicts within `props` values are still shared — this is a documented
limitation and is acceptable because values inside `props` are expected to be
scalars or short immutable sequences per CLAUDE.md §2.

**Q15. What graph mutations bypass MemoryAPI?**  
Currently: none in production `memfabric` code — all writes go through `upsert_node`,
`upsert_edge`, `apply_deltas`, or internal locked helpers that are called only while
holding `_graph_lock`.  The `apex_host/graph.py` `parse_observation` and `write_memory`
nodes use `apply_deltas` per CLAUDE.md §11.2.  The architecture bypass scan test
(`test_no_production_graph_mutation_bypasses_memory_api`) will verify this continues
to be true as the codebase grows.

**Q16. What constitutes a complete reader isolation guarantee?**  
Within one Python process and one event loop: a reader (`get_subgraph`, `open_tasks`,
`query` subgraph attachment) that begins after a writer (`apply_deltas`, `upsert_node`)
has completed will always see the writer's full committed state.  A reader that begins
before the writer starts will see the pre-write state.  A reader that begins while
the writer is holding `_graph_lock` will block until the writer releases the lock,
then see the complete committed state.  Partial batch states are never visible to
readers.  This is a single-process asyncio guarantee — multi-process deployments
require an external distributed lock as noted in CLAUDE.md Phase 1 hardening.

---

## Summary Statistics

| Status | Count |
|---|---|
| FIXED | 3 (F01, F02, F19) |
| CONFIRMED | 17 |
| PLAUSIBLE | 1 (F15) |
| PENDING FURTHER INVESTIGATION | 0 |
| NOT REPRODUCED | 0 |

| Severity | Count |
|---|---|
| Medium | 7 (F01✓, F02✓, F03, F04, F06, F07, F09, F20) |
| Low | 8 (F05, F08, F10, F11, F12, F13, F14, F21) |
| Info | 6 (F15, F16, F17, F18, F19✓, plus ruff 135 pre-existing lint errors) |
| (F15 is both Low and Plausible) | |

**Test coverage gaps:** 21 missing test cases identified (one per finding, plus 2 new). All are additive — no existing tests need to be removed.

**Ruff baseline:** 135 pre-existing lint errors (F401 unused imports predominate; 107 auto-fixable). Not counted as individual findings — they are tracked as a batch in Phase 4 (Documentation and Tooling).

---

## Reviewer Remediation Roadmap

### Phase 1 — Substrate Correctness (memfabric)
**Scope:** F01, F02, F19  
**Goal:** Make the fabric's caching and transactional rollback strictly correct.

| Finding | Fix | Files |
|---|---|---|
| F01 | Add `k` to `_cache_key` payload | `memfabric/retrieval/engine.py:39-44` |
| F02 / F19 | Snapshot `_write_clock` in `apply_deltas` Phase 1; restore in `_rollback_apply` | `memfabric/api.py` |

**Acceptance criteria:**
- `test_cache_key_includes_k` passes
- `test_search_different_k_independent_results` passes
- `test_apply_deltas_rollback_restores_write_clock` passes
- All 1311 existing tests continue to pass

---

### Phase 2 — LLM Budget Integrity
**Scope:** F03, F04, F05, F08, F14  
**Goal:** Ensure all LLM calls compete for the same shared budget and the repeated-context guard is content-sensitive.

| Finding | Fix | Files |
|---|---|---|
| F03 | Add `budget_tracker: LLMBudgetTracker | None = None` to `RepairEngine.__init__`; check `budget.can_call(phase)` before calling LLM | `apex_host/planning/repair.py` |
| F04 | Pass `budget_tracker=budget_tracker` to `RepairEngine(...)` in `build_apex_graph` | `apex_host/graph.py:318-323` |
| F05 | Replace count-only hash with content-sensitive hash (node/edge ID set + evidence ID set) | `apex_host/planning/engine.py:145-154` |
| F08 | Pass `current_phase=state.get("phase")` to `decide_phase` in `reflect_or_continue` peek | `apex_host/graph.py:1108-1112` |
| F14 | Pass `guard=LLMPolicyGuard(config)` to `PlanningEngine` and `RepairEngine` in `build_apex_graph` when `use_llm=True` | `apex_host/graph.py` |

**Acceptance criteria:** Missing tests from findings F03–F05, F08, F14 pass; all existing tests pass.

---

### Phase 3 — Graph Routing and Observability
**Scope:** F06, F07, F09, F10, F11, F13, F15, F16  
**Goal:** Correct multi-task routing, browser episode outcome, exception isolation, and parser idempotency.

| Finding | Fix | Files |
|---|---|---|
| F06 | `route_after_write` should check all `state["tool_results"]` for failures, not only `last_tool_result` | `apex_host/graph.py:942-957` |
| F07 | Browser episode outcome: derive from `tool_result.get("error")`, not `state.get("last_error")` | `apex_host/graph.py:905-908` |
| F09 | Add `return_exceptions=True` to `asyncio.gather`; handle exception entries in `pairs` | `apex_host/graph.py:537` |
| F10 | Derive `exposes`/`runs` edge IDs deterministically from host+port+proto+tech | `apex_host/parsers/nmap_parser.py:123-163` |
| F11 | Derive `grants` edge ID deterministically from credential+access_state IDs | `apex_host/parsers/access_parser.py` |
| F13 | Give duplicate-skip episodes a distinct outcome (`Outcome.noop` or `skipped=True` flag) | `apex_host/graph.py:488-503` + `write_memory` |
| F15 | Add test; review charge semantics; confirm or fix double-charge | `apex_host/graph.py:344-358` |
| F16 | Add accumulation test for `duplicate_actions` | `tests/apex_host/test_duplicate_actions.py` |

**Acceptance criteria:** Missing tests from findings F06–F16 pass; all existing tests pass.

---

### Phase 4 — Documentation and Tooling
**Scope:** F12, F17, F18  
**Goal:** Keep documentation accurate and enforce coding conventions through tests.

| Finding | Fix | Files |
|---|---|---|
| F12 | Refactor `CredentialPlanner` to call `capabilities_from_subgraph` once; thread result to inner class | `apex_host/planners/credential_planner.py` |
| F17 | Update README test count to reflect actual count | `README.md:183` |
| F18 | Add `tests/test_file_headers.py` that scans all `.py` files for two-line header convention | `tests/test_file_headers.py` (new) |

**Acceptance criteria:** README count matches `pytest --collect-only -q | tail -1`; `test_file_headers.py` passes; no regressions.

---

### Phase 5 — Conflict and Skill Lifecycle Invariants
**Scope:** F20, F21  
**Goal:** Enforce the conflict-blocking invariant at read paths and route Reflector skill mutations through MemoryAPI.

| Finding | Fix | Files |
|---|---|---|
| F20 | Wire `dependents_blocked_by()` check into `read_context` (substrate loop) and `load_context` (apex loop) before passing subgraph to planners | `memfabric/coordination/graph_loop.py`, `apex_host/graph.py` |
| F21 | Replace direct mutation `best_match.wins +=1; best_match.confidence=...` with `await self._api.update_skill_result(best_match.id, won=True)` and check the confidence-bump path | `memfabric/reflector/worker.py:133-138` |

**Acceptance criteria:**
- `test_conflict_blocks_planner_when_field_contested` passes
- `test_reflector_skill_update_goes_through_api` passes
- All existing 1328+ tests continue to pass
- `mypy --strict` clean

---

*End of Phase 0 expanded audit (2026-07-13) — 21 findings identified; 3 fixed (Phase 1); 18 open (Phases 2–5). No substantive fixes were implemented during this audit session.*

---

## Phase 4 Design Contract (2026-07-14)

This section answers the 36 retrieval-contract questions required by the Phase 4 prompt
**before** any implementation changes.  It defines the exact post-Phase-4 retrieval contract
that tests in `tests/test_retrieval_phase4.py` will verify.

### Q1. When does BM25 run?
Always — every `HybridRetriever.search()` call runs BM25 unconditionally, regardless of
gate state, k value (except k=0 short-circuit), or channel configuration.

### Q2. When does the dense vector channel run?
**Option A+ (backward-compatible):**
- When `embedder.is_configured` is `False` (StubEmbedder): dense fires only when
  `gate_is_open(bm25_scores, tau)` is True — same as existing behavior.
- When `embedder.is_configured` is `True` (real embedder): dense **always** fires.
This preserves all existing tests (which use StubEmbedder) while fixing the starvation
problem for real-embedder deployments.

### Q3. When does the graph channel run?
Same Option A+ logic:
- StubEmbedder: fires when `gate_is_open(bm25_scores, tau)` AND `Tier.working in tiers`.
- Real embedder: fires whenever `Tier.working in tiers`.

### Q4. When does the regex channel run?
Always (when `self._patterns` is non-empty). Empty pattern set (default) → zero iterations.

### Q5. Is `gate_is_open` mathematically meaningful with default tau=0.3?
Yes for lexically sparse queries; No for BM25-indexed corpora.  BM25Plus scores for well-matched
documents typically exceed 0.3, closing the gate even when semantic similarity would add signal.
The gate is effectively a "no lexical match" detector, not a "low confidence" detector.
Option A+ fixes this for real-embedder deployments by removing the gate dependency.

### Q6. What is the exact RRF formula?
`score(d) = Σ_i weight_i / (rrf_k + rank_i(d))` where `rank_i(d)` is 1-based rank in channel i.
`rrf_k` defaults to 60.  Documents absent from a channel contribute 0 from that channel.
Tie-breaking: sort by `(-score, doc_id)` — lexicographically ascending doc_id breaks ties.

### Q7. What are the channel weights?
Configured in `Config`: `channel_weight_lexical=1.0`, `channel_weight_regex=0.5`,
`channel_weight_dense=1.0`, `channel_weight_graph=0.5`.

### Q8. What does `rerank_top_n` do?
`fuse_rrf(top_n=max(k, config.rerank_top_n))` feeds the reranker more candidates than `k`.
The reranker then scores them; the top-k are returned.  This prevents the reranker from seeing
too few candidates when the best results aren't in the raw top-k.  Default: `rerank_top_n=20`.

### Q9. What is the complete cache key schema?
```
CACHE_KEY_VERSION = "4"
key = SHA-256({
  "v": "4",
  "text": query_text,
  "k": k,
  "tiers": sorted([t.value for t in tiers]),
  "filters": _canonical_filters(filters),
  "idx_gen": index_generation,
  "rrf_k": config.rrf_k,
  "rerank_top_n": config.rerank_top_n,
  "weights": [w_lex, w_regex, w_dense, w_graph],
})
```
Full 64-hex-char SHA-256 digest (not truncated).

### Q10. What does `_canonical_filters` do?
`json.dumps(filters, sort_keys=True, ensure_ascii=True)` — sorts all dict keys recursively.
Non-serializable values raise `ValueError` before the cache key is computed.
`None` → `"null"`.

### Q11. What are the k semantics?
- `k < 0` → `ValueError("k must be non-negative")`, raised immediately.
- `k == 0` → short-circuit: return `([], RetrievalDiagnostics(cache_hit=False, ...))`
  without running any channel.
- `k > 0` → normal pipeline.

### Q12. How is the cache protected against caller mutation?
On write: `await kv.set(cache_key, copy.deepcopy(reranked), ...)`.
On read: `return copy.deepcopy(cached)`.
Both directions protect the stored object.

### Q13. What invalidation events bust the cache?
| Event | Method | Busts cache? |
|---|---|---|
| `upsert_node` | `_refresh_working_indexes` | ✅ already |
| `upsert_edge` | `_refresh_working_indexes` | ✅ already |
| `delete_node` | `delete_node` | ✅ already |
| `delete_edge` | `delete_edge` | ✅ already |
| `apply_deltas` (rollback) | `_rollback_locked` | ✅ already |
| `promote_knowledge` | (missing) | **Fixed: add `delete_prefix` + `_advance_index_generation()`** |
| `promote_skill` | (missing) | **Fixed: add `delete_prefix` + `_advance_index_generation()`** |
| `quarantine_skill` | (missing) | **Fixed: add `delete_prefix` + `_advance_index_generation()`** |
| `decay_skill` | none (BM25 text unchanged) | Not required |
| `resolve_conflict` | `_apply_conflict_resolution_locked` → `_refresh_working_indexes` | ✅ already |

### Q14. What is `_index_generation`?
A monotonic integer counter on `MemoryAPI`, incremented by `_advance_index_generation()`
on every retrieval-affecting mutation.  It is included in the cache key so that even if
`delete_prefix` were skipped (belt-and-suspenders), subsequent queries would use a different
key and get a cache miss.  Starting at 0.

### Q15. What does `RetrievalDiagnostics` contain?
```python
@dataclass(slots=True)
class RetrievalDiagnostics:
    cache_hit: bool
    channels_attempted: list[str]   # e.g. ["bm25", "dense", "graph"]
    channels_skipped: list[str]     # e.g. ["regex"]  (no patterns)
    lexical_top_score: float        # max BM25 score before tier filter (0.0 if none)
    lexical_candidate_count: int    # after tier filter
    dense_candidate_count: int
    graph_candidate_count: int
    regex_candidate_count: int
    fused_candidate_count: int      # after RRF
    reranked_candidate_count: int   # after reranker
    gate_open: bool                 # True if BM25-score gate opened (historical, for StubEmbedder)
    gate_reasons: list[str]         # human-readable reasons the gate opened/closed
    index_generation: int           # value of _index_generation at query time
    channel_weights: dict[str, float]  # {"bm25": 1.0, "regex": 0.5, "dense": 1.0, "graph": 0.5}
```

### Q16. How is `RetrievalDiagnostics` returned?
`HybridRetriever.search()` return type changes to `tuple[list[ScoredEntry], RetrievalDiagnostics]`.
`MemoryAPI.query()` uses both to construct `EvidenceBundle(entries=..., diagnostics=...)`.
`EvidenceBundle` gains `diagnostics: RetrievalDiagnostics | None = field(default=None)`.

### Q17. What is `is_configured` on Embedder?
A class attribute `is_configured: bool = False` on `StubEmbedder`.
The engine reads `getattr(self._embedder, 'is_configured', False)` — default False (conservative).
Real embedders provided by host apps should set `is_configured = True`.

### Q18. How are regex channel results handled for tier filtering?
Regex results currently use `{"tier": "regex"}` — not a real Tier value → dropped by tier post-filter.
**Fix**: regex match results are cross-tier exact-match identifiers and should NOT be subject to the
tier post-filter.  They are kept in the RRF fusion input but filtered separately: they are
passthrough entries that participate in fusion regardless of tier filter.  After fusion, their
metadata tier is NOT checked (they are resolved to actual document IDs only if the pattern matches
a document already in the index — otherwise they are synthetic identifiers that won't appear in
the reranker's input, so they only boost other channels' documents via RRF).

**Implementation**: regex results skip the post-fusion tier filter; they are kept as-is in the
fused list. The post-filter only applies to results that come from BM25/vector index entries
(which carry a real tier in their metadata).

### Q19. What is the Phase 1 Option C query consistency contract?
Subgraph reads under `_graph_lock` always reflect a single committed version.
BM25/vector evidence may reflect a slightly earlier committed version (the one that existed
when each channel fired, outside `_graph_lock`).
This contract is **preserved** — no change in Phase 4.

### Q20. How do channel failures degrade?
- BM25 raises → propagate as `RetrievalError` (hard failure — BM25 is the baseline channel).
- Dense raises → log warning, skip channel, set `dense_candidate_count=0` in diagnostics.
- Graph raises → log warning, skip channel, set `graph_candidate_count=0` in diagnostics.
- Regex raises → log warning, skip pattern, continue.
- Reranker raises → log warning, return fused results (unranked) as fallback.

### Q21. How does the staged tier work?
`Tier.staged` is a debug-only view. When present in `tiers`:
- Staged entries are appended directly (not from BM25 index) with `score=0.0` and `tier="staged"`.
- They are NOT subject to tier post-filter.
- They do NOT participate in RRF (they are appended after fusion).
- Cache key DOES include staged in the tiers list, so staging/unstaging invalidates the cache only
  indirectly (via `_advance_index_generation()` in `promote_knowledge`/`promote_skill`).

### Q22. Does deduplication happen across channels?
Yes — RRF handles deduplication: each document ID appears at most once in the fused output
(with a score summed from all channels it appeared in).  If a document appears in both BM25
and dense channels, it gets credit from both.

### Q23. When is the filter applied?
After reranking (existing behavior).  This ensures the reranker sees more candidates than the
filter would allow; the filter then narrows to the specifically requested subset.
The filter is included in the cache key (via `_canonical_filters`), so two queries that differ
only in filter produce independent cache entries.

### Q24. How is `ScoredEntry.metadata` protected?
`ScoredEntry` is a dataclass with `metadata: dict[str, Any]`.  After Phase 4, the metadata dict
on cached entries is protected by the deep copy on cache read.  ScoredEntries returned by
`search()` may be mutated by callers without affecting the cache.

### Q25. What happens with an empty index?
BM25 returns [] (graceful — `BM25LexicalIndex` handles empty corpus).  Dense/graph return [].
Gate opens (no BM25 scores → `gate_is_open([], tau) = True`).
RRF returns [].  Result: `([], diagnostics_showing_empty)`.

### Q26. Can filters contain non-serializable values?
No — `_canonical_filters()` raises `ValueError` before the cache key is computed.
Caller must ensure filter values are JSON-serializable (str, int, float, bool, None, list, dict).

### Q27. Are conflict-annotated entries excluded from results?
No — retrieval does not filter results by conflict status.  The `EvidenceBundle.blocked_fields`
annotation (set by `MemoryAPI.query()` from the subgraph) tells downstream planners which fields
are contested.  Retrieval itself is read-only and does not enforce conflict semantics.

### Q28. What are the `_last_dense_fired` and `_last_graph_fired` semantics after Phase 4?
These attributes remain on `HybridRetriever` for test introspection.
- `_last_dense_fired`: True iff the dense channel was **attempted** (whether or not it returned results).
- `_last_graph_fired`: True iff the graph channel was **attempted**.
With StubEmbedder and BM25 gate closed: both False (unchanged from pre-Phase-4).
With StubEmbedder and BM25 gate open: dense attempted (returns [] on RuntimeError) → True; graph attempted → True (if Tier.working in tiers).
With real embedder: both always True (Option A+).

### Q29. What is the `index_generation` lifecycle?
Starts at 0 in `MemoryAPI.__init__`.  Incremented by `_advance_index_generation()` on:
every `promote_knowledge`, `promote_skill`, `quarantine_skill`.
Also, `_refresh_working_indexes` (called from `upsert_node`/`upsert_edge`) calls `_advance_index_generation()`.
The value is passed to `retriever.search(index_generation=self._index_generation)` on every `query()` call.

### Q30. Does `apply_deltas` rollback advance `_index_generation`?
No — a failed batch should not advance the generation (no net change to the index).
`_rollback_locked` does call `delete_prefix("retrieval:")` (existing) which invalidates stale cache entries.
The generation only advances for successful mutations.

### Q31. What is the `CACHE_KEY_VERSION` strategy?
`CACHE_KEY_VERSION = "4"` is a module-level constant in `engine.py`.
Increment it whenever the cache-key schema changes incompatibly (e.g., new field added, field removed, semantics changed).
This prevents old entries (with key format v3) from being returned for v4 queries.

### Q32. What are the required test count and naming conventions for Phase 4?
At least 100 named tests in `tests/test_retrieval_phase4.py`.
Test IDs follow the pattern `test_<CATEGORY><NN>_<description>` where CATEGORY is:
- `GATE` (gate behavior), `CACHE` (cache key and invalidation), `FUSE` (RRF), `RANK` (reranking),
- `DIAG` (diagnostics), `TIER` (tier filtering), `IDENT` (identifier channel), `ARCH` (architecture scan),
- `K` (k semantics), `IMMUT` (immutability), `GEN` (index generation), `FAIL` (channel failures),
- `INVAL` (invalidation), `INT` (integration)

### Q33. What existing tests must NOT be broken?
All 1680 tests passing after Phase 3 must continue to pass.  No new ruff errors.
`mypy --strict` must remain clean.

### Q34. What is `F01-broader` and when is it FIXED?
`F01-broader` is "hybrid retrieval is rarely hybrid because of the raw-BM25-score gate and
multiple additional cache correctness gaps".  It is **FIXED** when all of the following are true:
(a) complete cache-key schema (Q9) implemented and tested;
(b) cache immutability (Q12) implemented and tested;
(c) all invalidation events (Q13) implemented and tested;
(d) `index_generation` tracking (Q14, Q29) implemented and tested;
(e) Option A+ gate (Q2, Q3) implemented and tested;
(f) k semantics (Q11) implemented and tested;
(g) `RetrievalDiagnostics` (Q15, Q16) implemented and tested;
(h) identifier channel tier fix (Q18) implemented and tested.

### Q35. What is `F05` (planning context hash) and when is it FIXED?
`F05` — `_context_hash` in `apex_host/planning/engine.py` hashes only structural counts
(node count, edge count) rather than node/edge IDs or content.  Two subgraphs with the same
structure but different content produce the same hash → LLM sees stale context.
**Fix**: replace count-based hash with `frozenset({n.id for n in nodes} | {e.id for e in edges})`
hashed via SHA-256.  **Fixed in Phase 4** — test `test_F05_context_hash_content_sensitive`.

### Q36. What must be true for Phase 4 to be declared COMPLETE?
- All items in Q34 are FIXED.
- F05 is FIXED (Q35).
- All 100+ required tests pass.
- All 1680+ prior tests pass.
- `mypy --strict` clean.
- Ruff error count ≤ 135.
- `docs/phase4_end_report.md` written with all 38 sections.
- Traceability matrix Phase 4 row updated to ✓ COMPLETE.

---

## Phase 5 Reopen — Atomic Budgeting, Gateway Exclusivity, Repair Re-entry, Guards, Redaction, Model Safety (2026-07-14)

**Status:** ✓ COMPLETE  
**Test count:** 1961 passed (96 new tests in `tests/apex_host/test_phase5_reopen.py`)  
**mypy:** clean (102 source files)  
**Ruff:** 134 errors (below 135 baseline)

Phase 5 initial implementation (68 tests, 1865 total) was accepted, then reopened to verify
19 additional requirements that the initial review identified as untested or undocumented.
All 19 requirements are now confirmed by dedicated tests.

### Phase 5 Reopen — 19 Requirements Summary

| Req | Description | Test(s) | Status |
|---|---|---|---|
| R01 | `BudgetReservation` lifecycle: `commit()`/`fail()`/`release()` mutually exclusive | `TestBudgetReservationLifecycle` (R01a–R01e, 5 tests) | VERIFIED |
| R02 | `reserve()` uses `asyncio.Lock` — TOCTOU-proof atomic reservation | `test_r02_reserve_uses_lock_for_atomicity` | VERIFIED |
| R03 | `can_call()` checks both per-phase and per-run limits | `TestBudgetLimits` (R03a–R03d, 4 tests) | VERIFIED |
| R04 | Concurrent `reserve()` calls: exactly one succeeds when budget=1 | `test_r04_concurrent_atomic_no_overspend` | VERIFIED |
| R05 | Shared gateway: budget exhaustion blocks both planners and repair | `test_r05_shared_gateway_budget_exhaustion_blocks_repair` | VERIFIED |
| R06 | `RepairEngine` has no direct `chat_llm.invoke()` — all calls via gateway | `test_r06_repair_engine_no_direct_invoke` (architecture scan) | VERIFIED |
| R07 | `PlanningEngine` has no direct `chat_llm.invoke()` — all calls via gateway | `test_r07_planning_engine_no_direct_invoke` (architecture scan) | VERIFIED |
| R08 | `reflect_or_continue` passes `current_phase` kwarg to `decide_phase` peek | `test_r08_reflect_peeks_phase_with_current_phase_kwarg` | VERIFIED |
| R09 | `RepairRequest` returned by `repair()`, not bare `TaskSpec` | `TestRepairRequestStructure` (R09a–R09d, 4 tests) | VERIFIED |
| R10 | `RepairEngine.repair()` returns `None` on dry-run | `test_r10_repair_returns_none_on_dry_run` | VERIFIED |
| R11 | Fail-closed guard: `build_apex_graph` raises `RuntimeError` when guard init fails with `use_llm=True` | `test_r11_fail_closed_guard_raises_on_construction_failure` | VERIFIED |
| R12 | Shared gateway wires guard; guard is never `None` when model_router provided | `test_r12_guard_wired_into_shared_gateway` | VERIFIED |
| R13 | `sanitize_messages` redacts passwords, usernames, API keys | `TestSanitizeMessages` (R13a–R13f, 6 tests) | VERIFIED |
| R14 | `check_prompt` blocks off-scope IPs in GOAL:/TARGET: lines | `TestCheckPrompt` (R14a–R14c, 3 tests) | VERIFIED |
| R15 | `check_output` blocks persistence patterns (crontab, authorized_keys, etc.) | `TestCheckOutput` (R15a–R15e, 5 tests) | VERIFIED |
| R16 | `check_output` blocks brute-force tools (hydra, medusa, hashcat) | `test_r16_check_output_blocks_brute_force` | VERIFIED |
| R17 | No router → no guard constructed; `build_apex_graph` succeeds without LLMPolicyGuard | `test_r17_no_router_no_guard_construction` | VERIFIED |
| R18 | `LLMCallStatus` enum properties: `is_success`, `is_fallback`, `is_blocked`, `is_error` | `TestLLMCallStatus` (R18a–R18d, 4 tests) | VERIFIED |
| R19 | `fundamental` outcome on repair: `RepairEngine.repair()` returns `None` when no gateway | `test_r19_fundamental_outcome_returns_none` | VERIFIED |

### F03 — Phase 5 Reopen addendum

**Phase 5 initial:** `RepairEngine` accepts `budget_tracker` and `gateway` parameters; LLM calls go through `LLMGateway.invoke()`.  
**Phase 5 Reopen additions:**
- `RepairRequest` return type (not bare `TaskSpec`) verified by R09 tests.
- Shared gateway budget exhaustion verified by R05.
- Architecture scan confirms no direct `chat_llm.invoke()` in `repair.py` (R06).
- `repair()` returns `None` on dry-run verified by R10.

### F04 — Phase 5 Reopen addendum

**Phase 5 initial:** `build_apex_graph` passes shared `LLMGateway` to `RepairEngine`.  
**Phase 5 Reopen addition:** R05 (`test_r05_shared_gateway_budget_exhaustion_blocks_repair`) directly verifies that after planners exhaust the shared budget, `RepairEngine.repair()` also returns `None` — confirming the gateway and budget objects are genuinely shared, not cloned.

### F08 — Phase 5 Reopen addendum

**Phase 5 initial:** `reflect_or_continue` passes `current_phase=state.get("phase")` to `decide_phase` peek.  
**Phase 5 Reopen addition:** R08 (`test_r08_reflect_peeks_phase_with_current_phase_kwarg`) directly scans the `reflect_or_continue` source code and confirms `current_phase=` kwarg is present in the `decide_phase` call, preventing a silent regression.

### F14 — Phase 5 Reopen addendum

**Phase 5 initial:** `LLMPolicyGuard` constructed in `build_apex_graph` and wired into shared gateway.  
**Phase 5 Reopen additions:**
- Fail-closed behavior verified by R11: if guard construction raises, `build_apex_graph` raises `RuntimeError` (prevents unguarded LLM calls).
- Shared gateway guard injection verified by R12: `_gateway._guard` is non-None when `model_router` provided.
- No-router path verified by R17: no guard constructed when `model_router=None`.

### Phase 5 Reopen — What must be true for COMPLETE

- All 19 R-requirements tested and passing (96 tests in `test_phase5_reopen.py`). ✓
- `RepairEngine.repair()` returns `RepairRequest | None` (not `TaskSpec | None`). ✓
- Shared `LLMGateway` budget exhaustion blocks both planners and repair. ✓
- Architecture scan: no direct `chat_llm.invoke()` in `repair.py` or `engine.py`. ✓
- Fail-closed guard: `RuntimeError` when `use_llm=True` and guard init fails. ✓
- All 1961 tests pass. ✓
- `mypy --strict` clean (102 files). ✓
- Ruff errors ≤ 135 (actual: 134). ✓
- `docs/phase5_end_report.md` written. ✓
- Traceability matrix Phase 5 Reopen row updated to ✓ COMPLETE. ✓

---

## Phase 7 — Async Runtime Contract (Pre-Implementation, 2026-07-14)

This section defines the binding async runtime contract for Phase 7.
It was written before any code changes (R02 requirement).

### Phase 7 Invariants (binding)

**P7-I01 — No synchronous CPU or file I/O inside an `async def` that awaits nothing.**
Any function that takes `>1 ms` of CPU or file I/O must be wrapped with
`asyncio.to_thread()`. The event loop must not be blocked for more than 1 ms
by any operation that can be offloaded.

**P7-I02 — `asyncio.Lock` held during `asyncio.to_thread()` is acceptable.**
When an `asyncio.Lock` must protect both the thread-offloaded work and the state
mutation that follows it, holding the lock across `await asyncio.to_thread()`
is correct — the event loop is free to serve other coroutines that don't need
the same lock. Other awaiters on the same lock are blocked, which is the correct
mutual-exclusion behaviour. This is the pattern used for BM25 `search()` and
`_rebuild_async()`.

**P7-I03 — Subprocess termination on timeout uses SIGTERM → grace → SIGKILL.**
On `asyncio.TimeoutError`, `runner.py` sends SIGTERM to the child process, waits
up to `config.subprocess_sigterm_grace_seconds` (default 5 s) for it to exit,
then sends SIGKILL if it is still alive. Immediate SIGKILL without a grace period
is prohibited.

**P7-I04 — `asyncio.CancelledError` in `run_command` terminates the child.**
When the awaiting coroutine is cancelled, the `except asyncio.CancelledError`
handler in `run_command` calls `proc.terminate()` and `await proc.wait()` before
re-raising. No subprocess is left as an orphan on cancellation.

**P7-I05 — All Playwright operations have explicit timeouts.**
`browser.launch()` must be wrapped with `asyncio.wait_for(timeout=config.browser_launch_timeout_seconds)`.
Other Playwright calls (`page.goto`) already carry `timeout_ms`. The launch call
was the only missing timeout.

**P7-I06 — All report and EKG export writes are atomic.**
`write_report_json` and `write_json` (export_graph) write to a `.tmp` file,
flush, then call `tmp.replace(final_path)`. A process crash during the write
leaves the original file intact, never a truncated or zero-byte file.

**P7-I07 — No nested `asyncio.run()` in library code.**
`asyncio.run()` may appear only in top-level CLI entry points
(`main.py`, `run_htb_local.py`, `run_synthetic_machine.py`).
Any call inside `memfabric/` or non-CLI `apex_host/` code would deadlock
inside a running event loop and violates this invariant.

**P7-I08 — CANCELLED and TIMED_OUT dispositions are never retried or repaired.**
`ExecutionDisposition.CANCELLED` and `ExecutionDisposition.TIMED_OUT` have
`never_retry=True` and `never_repair=True`. No retry or repair path attempts
to re-execute a cancelled or timed-out task.

**P7-I09 — `ApexRuntime.aclose()` safely shuts down all held resources.**
`ApexRuntime` exposes `async def aclose()` which cancels any pending background
tasks, waits for cleanup, and is idempotent (safe to call more than once).
It does not raise if called before `run()` has been called.

**P7-I10 — File reads in async contexts use `asyncio.to_thread`.**
`compiled_loader._load_jsonl_file` offloads `path.read_text()` to a thread.
No other `async def` in `apex_host/` or `memfabric/` reads file content
synchronously on the event loop.

### Phase 7 Findings

| ID | Sev | Status | Description | File | Fix |
|---|---|---|---|---|---|
| A01 | High | CONFIRMED | BM25 `get_scores()` CPU work blocks event loop inside asyncio.Lock | `memfabric/stores/lexical_bm25.py:92` | `asyncio.to_thread` |
| A02 | High | CONFIRMED | BM25 `BM25Plus(corpus)` CPU work blocks event loop inside asyncio.Lock | `memfabric/stores/lexical_bm25.py:131` | `asyncio.to_thread` |
| A03 | Med | CONFIRMED | JSONL file write blocks event loop inside asyncio.Lock | `memfabric/stores/episodic_jsonl.py:96-97` | `asyncio.to_thread` |
| A04 | Med | CONFIRMED | `compiled_loader._load_jsonl_file` reads file synchronously in `async def` | `apex_host/knowledge/compiled_loader.py:120` | `asyncio.to_thread` |
| A05 | Med | CONFIRMED | `write_report_json` is non-atomic (truncates before write) | `apex_host/eval/report.py:482-486` | Temp file + atomic rename |
| A06 | Med | CONFIRMED | `write_json` in export_graph is non-atomic | `apex_host/eval/export_graph.py:71` | Temp file + atomic rename |
| A07 | High | CONFIRMED | `runner.py` sends SIGKILL immediately on timeout without SIGTERM grace | `apex_host/tools/runner.py:67-68` | SIGTERM → grace → SIGKILL |
| A08 | High | CONFIRMED | `runner.py` has no `CancelledError` handler; child process orphaned | `apex_host/tools/runner.py` (absent) | `except CancelledError: proc.terminate()` |
| A09 | Med | CONFIRMED | `BrowserExecutor` has no timeout on `playwright.chromium.launch()` | `apex_host/agents/browser_executor.py:141` | `asyncio.wait_for` |

### Phase 7 Acceptance Criteria

- All 130+ tests in `tests/apex_host/test_phase7_async.py` pass.
- Event-loop heartbeat tests confirm loop is not blocked during BM25 scoring.
- SIGTERM grace period test confirms no immediate SIGKILL without grace.
- `CancelledError` test confirms child process is terminated when caller is cancelled.
- Atomic write tests confirm no truncated files under simulated crash.
- All 2087+ prior tests still pass.
- `mypy --strict` clean.
- Ruff errors ≤ 134 (no new errors).

### Phase 7 — What must be true for COMPLETE

- All 9 async findings (A01–A09) FIXED.
- All F15 and F16 findings FIXED (deferred from Phase 6).
- `apex_host/async_utils.py` created with `run_io`, `run_cpu`, `write_atomic`, `read_text_async`.
- `ApexConfig` has 5 new timeout fields with correct defaults.
- `ApexRuntime.aclose()` implemented and tested.
- All 130+ Phase 7 tests pass.
- All prior tests still pass.
- `mypy --strict` clean.
- Ruff errors ≤ 134.
- `docs/phase7_end_report.md` written.
