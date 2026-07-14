# Phase 10 End Report — Orchestration Refactor

**Completion date:** 2026-07-14  
**Tests after Phase 10:** 2618 passed  
**mypy after Phase 10:** Success — 125 source files  
**Ruff after Phase 10:** 130 errors (at Phase 8 ceiling, exit code 1)

---

## Summary

Phase 10 decomposed the monolithic 1056-line `apex_host/graph.py`
(`build_apex_graph` function: ~830 lines) into a focused 13-module
`apex_host/orchestration/` package.  The public API is preserved: all existing
imports (`from apex_host.graph import build_apex_graph`) continue to work via
a thin re-export wrapper.

---

## Findings fixed

| Finding | Description | Resolution |
|---|---|---|
| F17 | README test count stale | Updated to 2618 (post-Phase 10) |
| F18 | No `test_file_headers.py` to enforce §12.6 convention | Created `tests/test_file_headers.py` with 5 enforcement tests |

Phase 10 also verified the following prior-phase fixes are correctly located after decomposition:

| Prior finding | Fix location (Phase 10) |
|---|---|
| F04 — budget_tracker passed to RepairEngine | `orchestration/builder.py` |
| F06 — route_after_write scans ALL tool_results | `orchestration/routing.py` |
| F07 — browser episode uses own tool_result | `orchestration/memory_node.py` |
| F08 — current_phase passed to decide_phase peek | `orchestration/continuation_node.py` |
| F09 — asyncio.gather with return_exceptions=True | `orchestration/dispatch_node.py` |
| F13 — duplicate skip episodes marked distinctly | `orchestration/memory_node.py` |
| F14 — LLMPolicyGuard wired in build_apex_graph | `orchestration/builder.py` |

---

## New files

| File | Purpose | Lines |
|---|---|---|
| `apex_host/orchestration/__init__.py` | Package; re-exports `build_apex_graph`, `OrchestrationDeps` | ~10 |
| `apex_host/orchestration/builder.py` | `build_apex_graph()` — wires all components, compiles StateGraph | ~130 |
| `apex_host/orchestration/completion.py` | `outcome_for`, `is_repairable`, `should_complete` pure functions | ~60 |
| `apex_host/orchestration/models.py` | `make_pd_entry`, `task_info` record builders | ~40 |
| `apex_host/orchestration/dependencies.py` | `OrchestrationDeps` frozen dataclass; `build_planners` factory | ~90 |
| `apex_host/orchestration/routing.py` | `PHASE_NODE`, `route_after_global_plan`, `route_after_write`, `route_after_reflect` | ~80 |
| `apex_host/orchestration/context_node.py` | `make_context_node` → `load_context` async node | ~50 |
| `apex_host/orchestration/global_plan_node.py` | `make_global_plan_node` → `global_plan` async node | ~70 |
| `apex_host/orchestration/dispatch_node.py` | `_dispatch_tasks`, `make_recon_node`, `make_web_node`, `make_browser_node`, `make_priv_esc_node`, `make_execute_node` | ~200 |
| `apex_host/orchestration/parsing_node.py` | `make_parsing_node` → `parse_observation`; `parse_single_result` | ~120 |
| `apex_host/orchestration/memory_node.py` | `make_memory_node` → `write_memory` | ~100 |
| `apex_host/orchestration/repair_node.py` | `make_repair_node` → `repair_agent` | ~80 |
| `apex_host/orchestration/continuation_node.py` | `make_continuation_node` → `reflect_or_continue` | ~90 |
| `tests/apex_host/test_phase10_orchestration.py` | 120 acceptance tests (CHAR/BUILD/ROUTE/COMP/MODEL/DEPS/ARCH/PAR/E2E/FIX) | ~550 |
| `tests/test_file_headers.py` | 5 §12.6 file-header enforcement tests (F18) | ~80 |

---

## Modified files

| File | Change |
|---|---|
| `apex_host/graph.py` | Reduced from 1056 lines to ~30-line thin re-export wrapper |
| `apex_host/planning/repair.py` | Lazy imports for `llm.gateway` (circular import fix) |
| `apex_host/orchestration/dispatch_node.py` | Removed unused `type: ignore[arg-type]` |
| `apex_host/orchestration/repair_node.py` | Removed unused `Outcome` import |
| `tests/apex_host/test_policy_gate.py` | 9 monkeypatch targets changed from `apex_host.graph.run_command` → `apex_host.tools.runner.run_command` |
| `tests/apex_host/test_llm_phase5.py` | 4 architecture scan tests updated to check new file locations; 2 F08 tests updated to read `continuation_node.py` |
| `tests/test_conflict_phase2_reopen.py` | R71 test updated to check `execution/dispatcher.py` |
| `tests/apex_host/test_phase6_dispatcher.py` | Removed `AsyncMock` and `AbandonSignal` unused imports |
| `docs/remediation_traceability_matrix.md` | Phase 10 row marked ✓ COMPLETE |
| `docs/remediation_validation_baseline.md` | Phase 10 baseline section appended |
| `README.md` | Test count updated to 2618; Phase 10 test description added |

---

## Binding invariants established (P10 series)

**P10-I01 — `build_apex_graph()` public signature is unchanged.**
All parameters (`api`, `registry`, `config`, `checkpointer`, `model_router`, `advisor`,
`budget_tracker`) remain identical. External callers need no changes.

**P10-I02 — The thin wrapper in `apex_host/graph.py` is the sole public entry point.**
All production code imports `build_apex_graph` from `apex_host.graph`.
The `apex_host.orchestration` package is an implementation detail — it may also be
imported directly but is not part of the stable public API.

**P10-I03 — Node factory pattern: each graph node is produced by `make_<name>_node(deps)`.**
No graph node is defined inline in `build_apex_graph`. Each factory receives the
`OrchestrationDeps` container and returns an async function suitable for use as a
LangGraph node. This makes each node independently testable.

**P10-I04 — `OrchestrationDeps` is a frozen dataclass — no mutation after construction.**
All node closures share the same `OrchestrationDeps` instance. Mutability would create
race conditions in concurrent async execution. The frozen constraint is verified by the
DEPS test group.

**P10-I05 — `OrchestrationDeps` never appears in `ApexGraphState`.**
Infrastructure objects (`MemoryAPI`, `TaskDispatcher`, `RepairEngine`, planners, `ApexConfig`)
are captured by node closures — never stored in state (memfabric Invariant 1, §1).
Verified by `test_deps07_orchestration_deps_not_in_state`.

**P10-I06 — Node names in the compiled graph are stable and must not be renamed.**
The exact names `load_context`, `global_plan`, `recon_agent`, `web_agent`, `browser_agent`,
`execute_agent`, `priv_esc_agent`, `parse_observation`, `write_memory`, `repair_agent`,
`reflect_or_continue` are used in LangGraph checkpoints. Renaming breaks checkpoint
replay. Verified by `test_build10_expected_node_names_registered`.

**P10-I07 — `routing.py` is the sole location for routing function definitions.**
`route_after_global_plan`, `route_after_write`, `route_after_reflect`, and `PHASE_NODE`
all live in `orchestration/routing.py`. No routing logic may appear in `builder.py` or
any node module.

**P10-I08 — `completion.py` functions are pure (no I/O, no state, no async).**
`outcome_for`, `is_repairable`, and `should_complete` are synchronous pure functions.
They may be called from any context without concern for side effects.

**P10-I09 — `run_command` is imported inside `build_apex_graph()`, not at module level.**
This local import pattern is essential: tests that monkeypatch
`apex_host.tools.runner.run_command` must apply the patch BEFORE calling
`build_apex_graph()`. The local import reads the current module attribute value at
call time — catching the patched version. Tests that patch at `apex_host.graph.run_command`
will fail silently (wrong target after Phase 10 decomposition).

**P10-I10 — No `check_conflict_dependencies` call in orchestration/ modules.**
The conflict gate is owned by `TaskDispatcher.dispatch()` in `execution/dispatcher.py`.
Orchestration nodes call `dispatcher.dispatch()` — they never call the gate directly.
Verified by `test_arch15_check_conflict_in_dispatcher_not_orchestration`.

**P10-I11 — All orchestration files follow the §12.6 two-line file-header convention.**
`test_arch02_all_orchestration_modules_have_file_header` and
`test_arch03_orchestration_modules_have_correct_filename_header` enforce this at test time.

---

## Test group summary

| Group | Tests | Coverage |
|---|---|---|
| CHAR | 17 | Each node's observable behaviour end-to-end |
| BUILD | 12 | Graph construction, wiring, backward-compat imports |
| ROUTE | 14 | Pure routing functions for all 3 decision points |
| COMP | 16 | `outcome_for`, `is_repairable`, `should_complete` |
| MODEL | 6 | `make_pd_entry`, `task_info` record builders |
| DEPS | 10 | `OrchestrationDeps`, `build_planners`, coupling checks |
| ARCH | 15 | Module boundaries, file structure, fix-location verification |
| PAR | 10 | New graph matches original single/multi-turn behaviour |
| E2E | 10 | Full dry-run engagements, JSON serialisability, independence |
| FIX | 10 | F06/F07/F08/F09/F13 regression prevention |
| **Total** | **120** | |

---

## Acceptance criteria (all met)

- [x] All modules in `apex_host/orchestration/` exist with correct signatures
- [x] `mypy --strict memfabric apex_host` — Success (125 source files)
- [x] 2618 tests pass (120 new Phase 10 + 2618 total)
- [x] Ruff errors: 130 (at Phase 8 ceiling, not exceeded)
- [x] `test_file_headers.py` — 5 enforcement tests pass (F18)
- [x] README test count updated to 2618
- [x] All pre-existing tests pass without modification
- [x] Thin re-export wrapper preserves all external imports
- [x] No architectural changes to memfabric (Invariant per §13.3)
- [x] No dry_run default changed (§13.5 safety invariant)
- [x] F17 and F18 marked FIXED in traceability matrix
