# Remediation Traceability Matrix

**Generated:** 2026-07-13  
**Last updated:** 2026-07-14 (Phase 11 complete — 50 Phase 11 verification tests, all findings independently re-verified)  
**Baseline test count:** 2668 passed (post-Phase 11 completion)  
**mypy:** clean (125 source files)  
**ruff:** 130 errors (at Phase 8 ceiling; exit code 1, pre-existing)

This matrix links every finding to its severity, current status, repair phase,
affected files, missing test(s), and acceptance criteria.  It is the single
source of truth for tracking remediation progress.

---

## Legend

| Column | Meaning |
|---|---|
| **ID** | Finding identifier (Fxx) |
| **Sev** | Severity: `High` / `Medium` / `Low` / `Info` |
| **Status** | `FIXED` / `CONFIRMED` / `PLAUSIBLE` |
| **Phase** | Repair phase (1–5) |
| **Area** | Affected package(s) |
| **Affected paths** | Source file(s) and approximate line range |
| **Missing test(s)** | Tests that must be written and pass before the fix |
| **Acceptance criteria** | Observable conditions that confirm the fix is complete |

---

## Full Finding Table

| ID | Sev | Status | Phase | Area | Affected paths | Missing test(s) | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| F01 | Med | FIXED | 1 | memfabric/retrieval | `retrieval/engine.py:39-54` | `test_t15_cache_key_includes_k`, `test_t16_different_k_causes_cache_miss` | Both tests pass; cache entries for k=3 and k=10 are independent |
| F02 | Med | FIXED | 1 | memfabric/api | `api.py:592-700` | `test_t07_write_clock_restored_after_rollback` | `_write_clock` equals pre-batch value after failed `apply_deltas` |
| F03 | Med | FIXED (2026-07-14) | 2 | apex_host/planning | `planning/repair.py:142-215` | `test_repair_engine_respects_budget_exhausted`, `test_repair_engine_records_llm_call_in_budget` (in `test_repair_engine.py`); R01–R19 in `test_phase5_reopen.py` | `repair()` returns `None` when budget exhausted; `calls_remaining()` decrements on success; `RepairEngine` returns `RepairRequest` not bare `TaskSpec`; gateway is shared with planners |
| F04 | Med | FIXED (2026-07-14) | 2 | apex_host/graph | `graph.py:318-323` | `test_build_apex_graph_passes_budget_to_repair_engine`; `test_r05_shared_gateway_budget_exhaustion_blocks_repair` in `test_phase5_reopen.py` | Shared `LLMGateway` injected into `RepairEngine` via `build_apex_graph`; budget tracker shared across all planners and repair |
| F05 | Low | FIXED | 4 | apex_host/planning | `planning/engine.py:145-154` | `test_ctx_different_node_id_different_hash`, `test_ctx_count_only_would_collide_content_sensitive_does_not` | Two subgraphs with identical counts but different node IDs produce different hashes; 6 CTX tests in `tests/test_retrieval_phase4.py` |
| F06 | Med | FIXED (2026-07-14) | 6 | apex_host/graph | `graph.py:942-957` | `test_f06_route_after_write_checks_all_results` (Phase 6 dispatcher suite) | When first task succeeds and second fails, `route_after_write` checks ALL `tool_results` and returns `"repair_agent"` |
| F07 | Med | FIXED (2026-07-14) | 6 | apex_host/graph | `graph.py:905-908` | `test_f07_browser_outcome_uses_tool_result_error` (Phase 6 dispatcher suite) | Browser episode outcome derived from `tool_result.get("error")`, never from `state["last_error"]` |
| F08 | Low | FIXED (2026-07-14) | 2 | apex_host/graph | `graph.py:1108-1112` | `test_reflect_or_continue_phase_matches_global_plan_after_budget_exhausted`; `test_r08_reflect_peeks_phase_with_current_phase_kwarg` in `test_phase5_reopen.py` | `reflect_or_continue` passes `current_phase=state["phase"]` to `decide_phase`; budget force-advance logic fires correctly |
| F09 | Med | FIXED (2026-07-14) | 6 | apex_host/graph | `graph.py:537` | `test_f09_gather_return_exceptions_handling` (Phase 6 dispatcher suite) | `asyncio.gather(..., return_exceptions=True)` catches per-task exceptions; remaining results are still processed |
| F10 | Low | FIXED (2026-07-14) | 6 | apex_host/parsers | `parsers/nmap_parser.py:123-163` | `test_nmap_exposes_edge_id_deterministic`, `test_nmap_exposes_edge_id_format`, `test_nmap_runs_edge_id_format` | `exposes` edges carry `"exposes:<host>:<service>"` IDs; `runs` edges carry `"runs:<service>:<tech>"` IDs; parsing same output twice yields same IDs |
| F11 | Low | FIXED (2026-07-14) | 6 | apex_host/parsers | `parsers/access_parser.py` | `test_access_parser_grants_edge_id_deterministic`, `test_access_parser_grants_edge_id_format`, `test_access_parser_tested_edge_id_format` | `grants` edge has `"grants:<cred>:<access>"` ID; `tested` edge has `"tested:<service>:<cred>"` ID; parsing same session twice yields same IDs |
| F12 | Low | FIXED (2026-07-14) | 6 | apex_host/planners | `planners/credential_planner.py` | `test_caps_called_once_with_engine` (Phase 6 dispatcher suite) | `capabilities_from_subgraph` called at most twice total per `plan()` invocation (once in wrapper, once in `_core`); never triple-called |
| F13 | Low | FIXED (2026-07-14) | 6 | apex_host/graph | `graph.py:488-503` | `test_f13_skipped_duplicate_no_episode` (Phase 6 dispatcher suite) | `write_memory` skips episode creation for `tool_result["skipped_duplicate"] is True`; no episode is appended for a task that never executed |
| F14 | Low | FIXED (2026-07-14) | 2 | apex_host/policy | `graph.py` (all planner constructions) | `test_build_apex_graph_wires_llm_guard_into_planners`; `test_r11_fail_closed_guard_raises_on_construction_failure`, `test_r12_guard_wired_into_shared_gateway` in `test_phase5_reopen.py` | `LLMPolicyGuard` wired into shared `LLMGateway`; fail-closed: raises `RuntimeError` when guard construction fails with `use_llm=True`; guard is never None when LLM is active |
| F15 | Low | PLAUSIBLE | 3 | apex_host/planners | `graph.py:344-358`, `planners/global_planner.py` | `test_global_planner_no_double_charge_on_phase_transition` | `web` budget counter == 1 after first `web` turn following force-advance from `recon` |
| F16 | Info | FIXED (Phase 7) | 3 | apex_host/graph_state | `graph_state.py` | 7 tests in `test_phase7_async.py::TestDuplicateActionsAccumulation` | `duplicate_actions` has N entries after N duplicate-skip turns; `operator.add` accumulates correctly |
| F17 | Info | CONFIRMED | 4 | docs | `README.md:183` | None (documentation update only) | README count matches `pytest --collect-only -q \| tail -1` |
| F18 | Info | CONFIRMED | 4 | tooling | `tests/test_file_headers.py` (new) | `test_file_headers_present` | Test passes; every `.py` file under `memfabric/` and `apex_host/` has two-line header |
| F19 | Info | FIXED | 1 | memfabric/api | `api.py` (rollback path) | Covered by `test_t07_write_clock_restored_after_rollback` | Same fix as F02 |
| F20 | Med | FIXED | 2 | memfabric/types, memfabric/api, memfabric/coordination, apex_host/planners, apex_host/graph | `types.py`, `api.py`, `coordination/conflict.py`, `planners/capabilities.py`, `planners/recon_planner.py`, `planners/web_planner.py`, `planners/credential_planner.py`, `planners/priv_esc_planner.py`, `graph.py` | T01–T60 in `tests/test_conflict_phase2.py`; R01–R72 in `tests/test_conflict_phase2_reopen.py` (132 tests total) | (1) `ResolutionDecision` + `choose_conflict_winner` pure function; (2) `ClaimDependency` on `TaskSpec` + all planner dependency annotations; (3) dependency-specific guard via `check_conflict_dependencies`; (4) full atomic rollback in `_apply_conflict_resolution_locked`; (5) deep copies in `get_conflicts()`; (6) `quarantined_fields` in `SubgraphView`/`EvidenceBundle`; (7) `capabilities_from_subgraph` skips both open and quarantined fields; (8) `conflict_blocked` disposition (returncode=0, routes directly to reflect_or_continue, never repair); architecture scans confirm no direct Conflict mutation outside lifecycle modules |
| F21 | Low | FIXED | 3 | memfabric/reflector, memfabric/api, memfabric/types, memfabric/config, memfabric/reflector/gates | `reflector/worker.py:133-138`, `api.py`, `types.py`, `config.py`, `reflector/gates.py` | 122 tests in `tests/test_skill_lifecycle.py` (S01–S03, C01–C11, D01–D05, R01–R05, RET01–RET07, SEL01–SEL05, EXE01–EXE09, DEC01–DEC08, QUAR01–QUAR07, PROM01–PROM03, GRACE01–GRACE07, QGATE01–QGATE08, MERGE01–MERGE08, F21, ORIGIN01–ORIGIN03, NEW01–NEW12, ARCH01–ARCH05, CONC01–CONC03, INT01–INT06, BACK01–BACK05) | (1) `get_staged_skills()` / `get_staged_knowledge()` return `copy.deepcopy()` instances — caller mutations never affect stored objects; (2) `SkillOutcomeDisposition` enum (WIN/LOSS/NEUTRAL/NOT_EXECUTED) on `types.py`; (3) new `Skill` lifecycle fields: `created_run_number`, `promoted_run_number`, `last_retrieved/selected/executed_run_number`, `last_used_run_number`, `last_decay_run_number`, `quarantined_run_number`, plus wall-clock `_at` timestamps and event counters; (4) `origin_skill_id` on `TaskSpec`; (5) `Config.skill_confidence_floor` + `skill_grace_runs`; (6) `should_decay()` uses `last_used_run_number` preferentially, respects `grace_runs`; (7) `should_quarantine()` adds `min_evidence_count` param, evidence = `max(execution_count, wins+losses)`; (8) `classify_skill_outcome()` pure function in gates.py; (9) `MemoryAPI.advance_run_number()` global monotonic counter; (10) `record_skill_retrieved/selected/execution()` lifecycle methods; (11) `decay_skill()` idempotent via `last_decay_run_number` guard + `confidence_floor`; (12) `quarantine_skill()` records `reason`, `quarantined_at`, `quarantined_run_number`; (13) `promote_skill()` sets `promoted_run_number`; (14) `merge_skill_candidate()` replaces direct mutation — all updates under `_staging_lock` via MemoryAPI; (15) `ReflectorWorker` calls `api.advance_run_number()` at start of run, uses `merge_skill_candidate()` for merges, passes `grace_runs`/`confidence_floor`/`current_run_number` to all lifecycle calls |

---

## Phase Completion Checklist (12-Phase Scheme)

This checklist uses the 12-phase sequence defined in CLAUDE.md §21 (updated 2026-07-13).
The old 5-phase scheme (which mapped F20 to Phase 5) is superseded.

| Phase | Status | Findings | Tests added | All prior tests pass | mypy clean | Ruff errors |
|---|---|---|---|---|---|---|
| Phase 0 — Audit | ✓ COMPLETE | F01–F21 identified | 0 (audit only) | N/A | N/A | N/A |
| Phase 1 — Substrate Correctness (initial) | ✓ COMPLETE | F01, F02, F19 | 17 | ✓ (1328 passed) | ✓ | 135 |
| Phase 1 — Comprehensive Transaction Guarantee | ✓ COMPLETE | reader isolation, delete, rollback | 58 additional | ✓ (1386 passed) | ✓ | 135 |
| Phase 1 — Re-open Corrections | ✓ COMPLETE | I01–O10 (12 issues) | 40 additional | ✓ (1426 passed) | ✓ | 135 (exit 1) |
| Phase 2 — Conflict Enforcement and Winner Persistence (initial) | ✓ COMPLETE | F20 | 60 | ✓ (1486 passed) | ✓ | 135 (exit 1) |
| Phase 2 — Reopen: Atomicity, Dependency Tracking, Planner Enforcement | ✓ COMPLETE | F20 (16 sub-issues) | 72 additional (R01–R72) | ✓ (1558 passed) | ✓ | 135 (exit 1) |
| Phase 3 — Skill Lifecycle, Decay, Quarantine | ✓ COMPLETE | F21 | 122 | ✓ (1680 passed) | ✓ | 135 (exit 1) |
| Phase 4 — Hybrid Retrieval and Cache Correctness | ✓ COMPLETE | F01-broader, F05 | 117 | ✓ (1797 passed) | ✓ | 133 |
| Phase 5 — Centralized LLM Gateway and Repair Budgets | ✓ COMPLETE | F03, F04, F08, F14 | 68 | ✓ (1865 passed) | ✓ | 133 |
| Phase 5 — Reopen: Atomic Budgeting, Gateway Exclusivity, Repair Re-entry, Guards, Redaction, Model Safety | ✓ COMPLETE | R01–R19 (19 reopen requirements) | 96 additional (`test_phase5_reopen.py`) | ✓ (1961 passed) | ✓ (102 files) | 134 |
| Phase 6 — Unified Execution, Policy, Deduplication, Errors | ✓ COMPLETE | F06, F07, F09, F10, F11, F12, F13 FIXED; TaskDispatcher + execution package; F15/F16 deferred to Phase 7 | 126 (`test_phase6_dispatcher.py`) | ✓ (2087 passed) | ✓ (108 files) | 134 |
| Phase 7 — Async Responsiveness and Cancellation | ✓ COMPLETE | A01–A09 (BM25 thread offload, JSONL async, compiled loader async, atomic writes, SIGTERM grace, CancelledError cleanup, browser timeout, `aclose()`, timeout config fields) | 131 (`test_phase7_async.py`) | ✓ (2218 passed) | ✓ (109 files) | 130 |
| Phase 8 — Secret Redaction and Graph Representation | ✓ COMPLETE | P8-I01–P8-I06 established; P8-S01–P8-S04, P8-PAR, P8-DANGLE, P8-ID, P8-URL, P8-SCHEMA enforced | 80 (`test_phase8_redaction.py`) | ✓ (2298 passed) | ✓ (112 files) | 130 |
| Phase 9 — Shared-State Boundaries, Canonical Configuration, and Safe Default Consistency | ✓ COMPLETE | D1–D6 (llm_provider default, from_cli_args factory, to_safe_dict, config_schema_version, run_synthetic_machine.py P8-I04 fix) | 80 (`test_phase9_config.py`) | ✓ (2378 passed) | ✓ (112 files) | 130 |
| Phase 10 — Orchestration Refactor | ✓ COMPLETE | F17 (README count updated), F18 (test_file_headers.py), P10-I01–P10-I11 established; `build_apex_graph` decomposed to 13 modules in `apex_host/orchestration/`; F06/F07/F08/F09/F13 fixes verified | 120 (`test_phase10_orchestration.py`) + 5 (`test_file_headers.py`) | ✓ (2618 passed) | ✓ (125 files) | 130 |
| Phase 11 — Independent Final Verification | ✓ COMPLETE | F16 FIXED, F21 FIXED (independently verified); all 21 findings re-verified; 50 new cross-cutting tests | 50 (`tests/test_final_verification.py`) | ✓ (2668 passed) | ✓ (125 files) | 130 |

---

## Invariant Coverage Map

This table maps each CLAUDE.md §1 design invariant to the findings that test or violate it.

| Invariant | Statement (abbreviated) | Violating findings |
|---|---|---|
| 1 | MemoryAPI is the only way to touch state | F21 (Reflector bypasses MemoryAPI for skill mutations) |
| 2 | Episodic memory is append-only and immutable | — (no violations found) |
| 3 | Working memory LWW per field with provenance | F02, F19 (rollback didn't restore `_write_clock`) ✓ FIXED |
| 4 | Semantic/procedural writes are proposals | — (staging gate is enforced; see `test_staging_isolation`) |
| 5 | Context retrieved and scoped, never accumulated | F01 ✓ FIXED (full cache-key schema + invalidation), F05 ✓ FIXED (content-sensitive _context_hash) |
| 6 | Executors are stateless | — (no violations found) |
| 7 | No agent-to-agent calls | — (blackboard model enforced) |
| 8 | Provenance and confidence travel with every claim; conflicts block dependents | F20 (blocking never enforced at read paths) |

---

## Phase 1 Comprehensive — Transaction-Path Inventory (Step 1 Pre-Implementation)

This inventory was produced before Phase 1 comprehensive implementation began (2026-07-13).
It covers every graph-related path and records its lock usage, index effect, cache effect,
rollback behaviour, and missing tests.

### Writer paths

| Public entry point | Internal method | State touched | Current lock | Required lock | Index effect | Cache effect | Rollback | Existing test | Missing test |
|---|---|---|---|---|---|---|---|---|---|
| `MemoryAPI.upsert_node` | `_upsert_node_locked` | `GraphStore` + `LexicalIndex` + optional `VectorIndex` + `KVStore` | `_graph_lock` ✅ | `_graph_lock` | `lexical.add` + optional `vector.add` | `kv.delete_prefix("retrieval:")` | Not applicable (single write) | T01–T03 (test_graph_atomicity) | `test_concurrent_node_upserts_preserve_disjoint_fields` |
| `MemoryAPI.upsert_edge` | `_upsert_edge_locked` | `GraphStore` + `LexicalIndex` + optional `VectorIndex` + `KVStore` | `_graph_lock` ✅ | `_graph_lock` | `lexical.add` + optional `vector.add` | `kv.delete_prefix("retrieval:")` | Not applicable (single write) | T04–T06 | `test_concurrent_edge_upserts_preserve_disjoint_fields` |
| `MemoryAPI.apply_deltas` | `_upsert_node_locked`, `_upsert_edge_locked`, `append_episode`, `propose_*` | All of above + `EpisodicStore` + staging dicts | `_graph_lock` ✅ for nodes/edges; `_staging_lock` for proposals | `_graph_lock` for full batch | per-item | per-item | `_rollback_locked` | T04–T09, T17 | `test_failed_batch_removes_only_its_knowledge_proposals` |
| Node deletion (rollback path) | `GraphStore.delete_node` via `_rollback_locked` | `GraphStore` | `_graph_lock` ✅ (called from `_rollback_locked`) | `_graph_lock` | `lexical.remove` | `kv.delete_prefix` | N/A (rollback IS the path) | T05, T17 | `test_delete_node_uses_memory_api_transaction` |
| Edge deletion (rollback path) | `GraphStore.delete_edge` via `_rollback_locked` | `GraphStore` | `_graph_lock` ✅ | `_graph_lock` | `lexical.remove` | `kv.delete_prefix` | N/A | T06 | `test_delete_edge_uses_memory_api_transaction` |
| `MemoryAPI.delete_node` | (NOT YET IMPLEMENTED — gap) | — | None ❌ | `_graph_lock` | lexical.remove | cache bust | N/A | None | `test_delete_node_uses_memory_api_transaction` |
| `MemoryAPI.delete_edge` | (NOT YET IMPLEMENTED — gap) | — | None ❌ | `_graph_lock` | lexical.remove | cache bust | N/A | None | `test_delete_edge_uses_memory_api_transaction` |
| Snapshot restore (`pre_node → put_node`) | Inside `_rollback_locked` | `GraphStore` | `_graph_lock` ✅ | `_graph_lock` | `lexical.add` with old text | `kv.delete_prefix` at end | N/A | T05, T08 | `test_failed_batch_restores_graph_and_lexical_index` |
| Conflict winner graph persistence | None — conflict resolution mutates `_conflicts` dict only, does not write to graph | `_conflicts` dict | None | No graph mutation required | None | None | N/A | test_conflict_lifecycle | — |
| Working-tier index refresh | `_refresh_working_indexes` | `LexicalIndex` + optional `VectorIndex` + `KVStore` | Inside `_graph_lock` ✅ | `_graph_lock` held by caller | `lexical.add` | `kv.delete_prefix` | `lexical.remove` in rollback | T31–T35 | `test_successful_batch_updates_graph_and_lexical_index_coherently` |
| Working-tier index removal (rollback) | `lexical.remove`, `vector.remove` in `_rollback_locked` | `LexicalIndex` + optional `VectorIndex` | Inside `_graph_lock` ✅ | `_graph_lock` held by caller | `lexical.remove` | `kv.delete_prefix` at end | — | T17 | `test_failed_batch_restores_graph_and_lexical_index` |
| `MemoryAPI.propose_knowledge` | direct `_staged_knowledge` write | staging dict | `_staging_lock` ✅ | `_staging_lock` | None (not retrievable) | None | Removed in `_rollback_locked` | test_staging_isolation | `test_failed_batch_removes_only_its_knowledge_proposals` |
| `MemoryAPI.propose_skill` | direct `_staged_skills` write | staging dict | `_staging_lock` ✅ | `_staging_lock` | None | None | Removed in `_rollback_locked` | test_staging_isolation | `test_failed_batch_removes_only_its_skill_proposals` |
| `MemoryAPI.promote_knowledge` | `lexical.add` + optional `vector.add` | `LexicalIndex` + optional `VectorIndex` | `_staging_lock` briefly | `_staging_lock` | `lexical.add tier=semantic` | None (no bust needed) | None (promotion not rolled back) | test_reflector_gates | — |
| `MemoryAPI.promote_skill` | `lexical.add` + optional `vector.add` | `LexicalIndex` + optional `VectorIndex` | `_staging_lock` briefly | `_staging_lock` | `lexical.add tier=procedural` | None | None | test_reflector_gates | — |
| `MemoryAPI.append_episode` | `EpisodicStore.append` + `lexical.add` | `EpisodicStore` + `LexicalIndex` | None (uses store's own lock) | Store lock ✅ for append; no `_graph_lock` | `lexical.add tier=episodic` | None | `_pop_episodes` in `_rollback_locked` | test_memory_api | `test_episode_rollback_removes_from_episodic_store` |

### Reader paths

| Public entry point | Internal method | State read | Current lock | Required lock | Notes | Existing test | Missing test |
|---|---|---|---|---|---|---|---|
| `MemoryAPI.query` | `HybridRetriever.search` + optional `graph.get_subgraph` | `LexicalIndex`, `VectorIndex`, optional `GraphStore` | `_graph_lock` ✅ for subgraph | `_graph_lock` for subgraph attachment | BM25/vector reads from indexes updated inside lock; subgraph reads under `_graph_lock` | test_retrieval, test_working_retrieval_freshness, test_a03 | FIXED in Phase 1 Comprehensive |
| `MemoryAPI.get_subgraph` | `GraphStore.get_subgraph` | `GraphStore` | `_graph_lock` ✅ | `_graph_lock` | Returns defensive copies; lock ensures complete batch visible | test_a01, test_a04, test_a06 | FIXED in Phase 1 Comprehensive |
| `MemoryAPI.open_tasks` | `GraphStore.get_nodes_by_type` + `get_edges_for_node` | `GraphStore` | `_graph_lock` ✅ | `_graph_lock` | All reads under same lock acquire → consistent snapshot | test_a02, test_a05, test_a07 | FIXED in Phase 1 Comprehensive |
| Direct node lookup (`_graph.get_node`) | `GraphStore.get_node` | `GraphStore` | Store's own lock ✅ | Store lock | Used internally in rollback and snapshot; not public on MemoryAPI | T10, T17 | — |
| Direct edge lookup (`_graph.get_edge`) | `GraphStore.get_edge` | `GraphStore` | Store's own lock ✅ | Store lock | Used in rollback; not public on MemoryAPI | T11 | — |
| `MemoryAPI.get_staged_knowledge` | dict access | staging dict | `_staging_lock` ✅ | `_staging_lock` | Returns live references (F21 for skills; same issue for knowledge) | test_staging_isolation | — |
| `MemoryAPI.get_staged_skills` | dict access | staging dict | `_staging_lock` ✅ | `_staging_lock` | Returns live references (F21) | test_staging_isolation | — |
| `MemoryAPI.get_conflicts` | dict access | `_conflicts` dict | None | None (asyncio single-process) | Conflict records are mutable; no lock needed for asyncio reads | test_conflict_lifecycle | — |
| `MemoryAPI.dependents_blocked_by` | dict iteration | `_conflicts` dict | None | None | Pure read in asyncio model | test_conflict_lifecycle | — |
| Retrieval graph traversal (via `HybridRetriever`→`GraphMatcher`) | `GraphStore.get_subgraph` called from retriever | `GraphStore` | Store's own lock ✅ | Store lock (bypasses `_graph_lock`) | **DOCUMENTED GAP**: retriever bypasses MemoryAPI._graph_lock; retriever sees store-level isolation only | test_retrieval | — |

### Gap summary (post-Phase-1-Comprehensive)

| Gap | Severity | Fix status |
|---|---|---|
| `get_subgraph()` and `open_tasks()` lack `_graph_lock` | High (reader isolation) | ✓ FIXED — Design A implemented |
| `query()` subgraph attachment lacks `_graph_lock` | Medium | ✓ FIXED |
| No public `delete_node`/`delete_edge` on MemoryAPI | Medium | ✓ FIXED — `delete_node`, `delete_edge`, `_delete_node_locked`, `_delete_edge_locked` added |
| Retriever `GraphMatcher` bypasses `MemoryAPI._graph_lock` | Low (store-level isolation; single-process asyncio) | NOT FIXED — documented limitation |
| `get_staged_knowledge`/`get_staged_skills` return live references (F21) | Low | NOT FIXED — Phase 5 |

---

## Phase Completion Checklist

| Phase | Status | Findings | Tests added | All prior tests pass | mypy clean |
|---|---|---|---|---|---|
| Phase 0 — Audit | ✓ COMPLETE | F01–F21 identified | 0 (audit only) | N/A | N/A |
| Phase 1 — Substrate Correctness (initial) | ✓ COMPLETE | F01, F02, F19 | 17 (in `test_graph_atomicity.py`) | ✓ (1328 passed) | ✓ |
| Phase 1 — Comprehensive Transaction Guarantee | ✓ COMPLETE | reader isolation, delete paths, complete rollback | 58 (51 test_graph_transaction_complete.py + 7 test_graph_stress.py) | ✓ (1386 passed) | ✓ |
| Phase 2 — LLM Budget Integrity | ○ OPEN | F03, F04, F05, F08, F14 | 0 of 5 | — | — |
| Phase 3 — Graph Routing and Observability | ○ OPEN | F06, F07, F09, F10, F11, F13, F15, F16 | 0 of 8 | — | — |
| Phase 4 — Documentation and Tooling | ○ OPEN | F12, F17, F18 | 0 of 3 | — | — |
| Phase 5 — Conflict and Skill Lifecycle | ○ OPEN | F20, F21 | 0 of 2 | — | — |

---

## Invariant Coverage Map

This table maps each CLAUDE.md §1 design invariant to the findings that test or violate it.

| Invariant | Statement (abbreviated) | Violating findings |
|---|---|---|
| 1 | MemoryAPI is the only way to touch state | F21 (Reflector bypasses MemoryAPI for skill mutations); no public delete_node/delete_edge (gap) |
| 2 | Episodic memory is append-only and immutable | — (no violations found) |
| 3 | Working memory LWW per field with provenance | F02, F19 (rollback didn't restore `_write_clock`) ✓ FIXED |
| 4 | Semantic/procedural writes are proposals | — (staging gate is enforced; see `test_staging_isolation`) |
| 5 | Context retrieved and scoped, never accumulated | F01 (stale truncated cache) ✓ FIXED; F05 (coarse context hash) |
| 6 | Executors are stateless | — (no violations found) |
| 7 | No agent-to-agent calls | — (blackboard model enforced) |
| 8 | Provenance and confidence travel with every claim; conflicts block dependents | F20 (blocking never enforced at read paths) |

---

*This matrix is updated at the end of every remediation phase.  The authoritative
detail for each finding is in `docs/reviewer_findings_audit.md`.*

---

## Phase 2 — Conflict-Consumer Inventory (Pre-Implementation)

This inventory was produced before Phase 2 implementation began (2026-07-13).
It covers every path in the codebase that reads EKG node field values and can
influence an action (capability, task, executor call, or graph write).

### Conflict-consumer table

| Consumer / public path | Contested fields it may use | Can produce execution? | Current conflict check | Required central protection | Required local behaviour | Test |
|---|---|---|---|---|---|---|
| `capabilities_from_subgraph()` in `apex_host/planners/capabilities.py` | `service.port`, `service.service`, `service.proto`, `service.state`, `service.version`, `endpoint.url` | **Yes** — produces `Capability` records used by ALL planners to emit `TaskSpec` objects | ❌ None | `SubgraphView.open_conflicts` annotated by `MemoryAPI.get_subgraph()` | Skip any node whose critical field has a `BlockedClaim`; produce no `Capability` | `test_contested_port_service_node_skipped` |
| `GlobalPlanner.decide_phase()` in `global_planner.py` | `node.type` set (node-type set, not field values) | **No** — phase is a routing decision, not a command | ❌ None | Phase advance uses node-type presence; field-level conflict does not affect type presence | No change needed — contested fields do not affect node-type set | `test_global_planner_no_advance_when_service_capability_blocked` |
| `_run_tasks()` in `apex_host/graph.py` (all agent nodes) | `task.params["target"]`, `task.params["args"]` (port in banner probes) | **Yes** — dispatches to runner.py and real tools | ❌ None | `EvidenceBundle.blocked_fields` annotated by `MemoryAPI.query()`; guard inserted after policy gate | If any `BlockedClaim` with `field_name in {"port","service"}` and `node_type=="service"` exists and the task tool is a service-probe type, return `conflict_blocked` result | `test_conflict_gate_blocks_service_probe_on_contested_port` |
| `TelnetExecutor.run()` in `apex_host/agents/telnet_executor.py` | Credential task target (IP, port) from `CredentialPlanner` which reads capabilities | **Yes** — opens TCP connection | ❌ None (upstream capability filtering is the primary gate) | `capabilities_from_subgraph()` already filters contested service nodes; conflict gate in `_run_tasks` is defense-in-depth | No executor-level change needed if upstream gates hold | `test_full_scenario_contested_service_phase_stays_in_recon` |
| `BrowserExecutor.run()` in `apex_host/agents/browser_executor.py` | `endpoint.url` from `WebPlanner` which reads capabilities | **Yes** (live mode) | ❌ None | `capabilities_from_subgraph()` skips contested endpoint URL nodes | Conflict gate in `browser_agent` checks `evidence.blocked_fields` | `test_conflict_gate_does_not_block_when_no_conflicts` |
| `MemoryAPI.auto_resolve_conflict()` / `resolve_conflict()` | `Conflict.claim_a`, `Conflict.claim_b` (field values) | **Yes** — writes winning value back to EKG | ❌ Currently only mutates `_conflicts` dict; winning value NOT written to graph | `_apply_conflict_resolution_locked()` inside `_graph_lock` | Resolve conflict → if resolved, write `winning_value` back to graph field using `put_node` via locked path; roll back resolution on graph-write failure | `test_auto_resolve_writes_winning_value_to_graph`, `test_resolution_graph_write_failure_leaves_conflict_open` |
| `MemoryAPI.upsert_node()` conflict detection | existing field provenance | **Indirect** — conflict detection fires during writes | ✅ Existing: creates `Conflict` record on high-confidence contradiction | Already correct — `make_conflict` called; deep copy required for `claim_a`/`claim_b` | Replace `dict(claim_a)` with `copy.deepcopy(claim_a)` in `conflict.py:make_conflict()` | `test_claim_a_dict_is_deep_copy` |
| `read_context` in `memfabric/coordination/graph_loop.py` | `SubgraphView.nodes` (generic substrate) | **Indirect** — evidence bundle passed to generic planner | ❌ None | `SubgraphView.open_conflicts` set by `MemoryAPI.get_subgraph()`; substrate loop passes annotated bundle | Generic substrate loop requires no additional change; annotation travels in the bundle | `test_query_open_conflict_propagated_to_blocked_fields` |
| `HybridRetriever.search()` in `memfabric/retrieval/engine.py` | `ScoredEntry.metadata` values | **No** — read only; does not produce actions | ❌ N/A | No change needed | — | — |
| `Reflector.consolidate()` in `memfabric/reflector/worker.py` | Episodic `episode.data` field values | **No** — produces skill proposals only | ❌ N/A | Proposals go through staging gate (Invariant 4) | — | — |

### Critical dependent fields

Fields whose contestation MUST block capability derivation and task dispatch:

| Node type | Field | Why critical |
|---|---|---|
| `service` | `port` | All service-probe and banner-probe tasks embed the port in their args |
| `service` | `service` | Service name determines which capability type (telnet, ssh, ftp, http) is produced |
| `service` | `proto` | `tcp` filter in `_map_service_node`; non-tcp services produce no capability |
| `service` | `state` | `open`/`""` filter; closed/filtered services must not be probed |
| `service` | `version` | Determines `exploit_research` capability; contested version → no exploit research |
| `endpoint` | `url` | All web-phase tasks (curl, browser, ffuf) target this URL |
| `host` | `ip` | All tasks ultimately target the host IP; contested IP → all tasks suspect |

Fields whose contestation is informational (does NOT block capability derivation):

| Node type | Field | Why not blocking |
|---|---|---|
| `tech` | `name`, `version` | Tech nodes inform exploit research metadata; the service itself is what's actioned |
| `service` | `confidence` (field) | Meta-field set by the parser, not a service property; not used in capability routing |
| `auth_flow` | `url`, `hint` | Auth flows are downstream of capabilities; CredentialPlanner abandons if no telnet capability |

### Gap summary

| Gap | Severity | Fix location | Phase |
|---|---|---|---|
| `capabilities_from_subgraph()` reads contested fields without checking | High | `apex_host/planners/capabilities.py` | 2 |
| `_run_tasks._run_one_cmd` dispatches to executor without conflict check | Medium | `apex_host/graph.py` | 2 |
| `auto_resolve_conflict()` resolves logically but does NOT write winning value to graph | Medium | `memfabric/api.py` | 2 |
| `make_conflict()` uses shallow `dict()` copy for `claim_a`/`claim_b` | Low | `memfabric/coordination/conflict.py` | 2 |
| `SubgraphView` / `EvidenceBundle` carry no conflict annotation | High | `memfabric/types.py`, `memfabric/api.py` | 2 |

---

## Phase 4 — Retrieval-Path Inventory (Pre-Implementation, 2026-07-14)

This inventory was produced before Phase 4 implementation began.  It covers every retrieval
channel, activation condition, fusion participation, cache identity, invalidation sources, and
missing tests.  Required by Phase 4 Step 1 — no code was changed before this table was written.

### Retrieval-path table

| Public query path | Channel | Activation condition | Input data | Output shape | Fusion? | Rerank? | Cache key inputs (BEFORE fix) | Cache key inputs (AFTER fix) | Invalidation sources | Existing test | Missing test |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `MemoryAPI.query()` → `HybridRetriever.search()` | BM25 (LexicalIndex) | Always | query text, `k*multiplier` | `list[(id, bm25_score, meta)]` | Yes (weight=1.0) | Via RRF output | text, k, tiers, filters | + CACHE_KEY_VERSION, index_generation, rrf_k, rerank_top_n, channel_weights | `upsert_node`, `upsert_edge`, `delete_node`, `delete_edge`, `apply_deltas` (already bust) | `test_retriever_returns_bm25_results` | `test_bm25_channel_always_runs` |
| Same | Regex/identifier (in-process) | When `self._patterns` non-empty | query text, configured patterns | `list[(id, 1.0, meta{tier:"regex"})]` | Yes (weight=0.5) | Via RRF output | (same — but regex results NOT tier-filtered) | + tier metadata fix: regex results need actual index tier or pass-through | `upsert_node` (clears cache) — but patterns are static; no dynamic invalidation needed | `test_regex_channel_fires_with_patterns` | `test_regex_results_participate_in_fusion`, `test_regex_tier_metadata` |
| Same | Dense vector (VectorIndex + Embedder) | `gate_is_open(bm25_scores, tau)` when StubEmbedder; **always** when real embedder (Option A+) | query text → embedding → ANN search | `list[(id, sim_score, meta)]` | Yes (weight=1.0) | Via RRF output | (same) | + `is_configured` gate | `upsert_node`/`upsert_edge` (bust cache), `quarantine_skill` (removes from vector — no bust), `promote_knowledge`/`promote_skill` (adds to vector — no bust) | `test_dense_channel_fires_when_gate_open` | `test_dense_always_fires_with_real_embedder`, `test_dense_never_fires_with_stub_embedder`, `test_promote_knowledge_busts_cache`, `test_quarantine_skill_busts_cache` |
| Same | Graph (GraphStore + GraphMatcher) | `gate_is_open(bm25_scores, tau)` when StubEmbedder; when `Tier.working in tiers` and real embedder (Option A+) | query text, graph | `list[ScoredEntry]` | Yes (weight=0.5) | Via RRF output | (same) | + gate condition in diagnostics | `upsert_node`/`upsert_edge` (bust cache) | `test_graph_channel_fires_when_gate_open_and_working_tier` | `test_graph_always_fires_with_real_embedder_and_working_tier` |
| `MemoryAPI.query(subgraph_anchor=X)` | Subgraph attachment (GraphStore) | When `subgraph_anchor` provided | anchor node ID, depth=2 | `SubgraphView` | No (not fused) | No | (none — not cached) | (unchanged — subgraph never cached, always fresh under `_graph_lock`) | Every `upsert_node`/`upsert_edge` affecting the subgraph (live read, no cache) | `test_a03` | — |

### Cache-key gaps (F01-broader)

| Gap | Current cache key | Required cache key addition | Risk if unfixed |
|---|---|---|---|
| `k` already added (F01 Phase 1) | text + k + tiers + filters | Already fixed | — |
| Missing `CACHE_KEY_VERSION` | none | Add constant "4" | Stale entries survive engine upgrade |
| Missing `index_generation` | none | Add `MemoryAPI._index_generation` | Stale entries survive graph write (caught by delete_prefix, but not by independent key collision) |
| Missing `rrf_k` | none | Add `config.rrf_k` | Two searches with different rrf_k share same cache entry |
| Missing `rerank_top_n` | none | Add `config.rerank_top_n` | Two searches with different rerank budgets share same cache entry |
| Missing `channel_weights` | none | Add tuple of 4 weights | Two searches with different weight configs share same cache entry |
| Truncated SHA-256 ([:16] = 8 bytes) | 16 hex chars = 8 bytes | Full 64 hex chars = 32 bytes | Birthday collision with ~2^32 keys |
| Non-deterministic filter canonicalization | `json.dumps(filters)` (dict iteration order) | `_canonical_filters()` with `sort_keys=True` | Dict with different key order produces different key for same logical filter |

### Invalidation gaps

| Event | Current effect | Required effect | Risk |
|---|---|---|---|
| `upsert_node` / `upsert_edge` | `delete_prefix("retrieval:")` ✅ | (already correct) | — |
| `delete_node` / `delete_edge` | `delete_prefix("retrieval:")` ✅ | (already correct) | — |
| `apply_deltas` rollback | `delete_prefix("retrieval:")` ✅ | (already correct) | — |
| `promote_knowledge` | None ❌ | Add `delete_prefix("retrieval:")` + `_advance_index_generation()` | Stale cache returns results without the newly promoted entry |
| `promote_skill` | None ❌ | Add `delete_prefix("retrieval:")` + `_advance_index_generation()` | Same |
| `quarantine_skill` | None ❌ (removes from lexical/vector but no cache bust) | Add `delete_prefix("retrieval:")` + `_advance_index_generation()` | Stale cache still returns quarantined skill |
| `decay_skill` | None (confidence change doesn't affect BM25 ranking) | None (acceptable — BM25 is text-based) | Negligible — BM25 scores don't change on confidence decay |
| `resolve_conflict` | `_apply_conflict_resolution_locked` → `_refresh_working_indexes` → `delete_prefix` ✅ | (already correct) | — |

### Cache immutability gap

| Location | Current code | Problem | Fix |
|---|---|---|---|
| `search()` cache read | `return cached` | Caller receives the stored list object; mutations corrupt the cache | `return copy.deepcopy(cached)` |
| `search()` cache write | `await self._kv.set(cache_key, reranked)` | Stored list is same object as what's returned; caller or later reranker can mutate it | `await self._kv.set(cache_key, copy.deepcopy(reranked))` |

### k-semantics gap

| Case | Current behavior | Required behavior |
|---|---|---|
| k < 0 | No check — `lexical.search(text, k*5)` with negative → undefined | Raise `ValueError("k must be non-negative")` |
| k == 0 | Runs all channels, returns empty (by top_n=0) | Short-circuit: return `([], empty_diagnostics)` without running channels |
| k > 0 | Correct | (unchanged) |

### RRF tie-breaking gap

| Current | Problem | Fix |
|---|---|---|
| `sorted(fused_scores.items(), key=lambda kv: kv[1], reverse=True)` | `sorted` is stable but secondary key is dict iteration order (non-deterministic across Python versions when hashes differ) | `sorted(fused_scores.items(), key=lambda kv: (-kv[1], kv[0]))` — secondary key is doc ID (lexicographic, always deterministic) |

### Missing identifier-channel tier metadata

| Current | Problem | Fix |
|---|---|---|
| `{"tier": "regex", ...}` on regex results | `"regex"` is not a `Tier` enum value; tier post-filter in engine excludes these results (they appear in fusion but get dropped in post-filter) | Regex results should use `tier` from the matched indexed document, OR treat regex as a cross-tier exact match not subject to tier filtering |

---

## Phase 7 — Async Operation Inventory (Pre-Implementation, 2026-07-14)

This inventory was produced before Phase 7 implementation began.
It covers every blocking operation inside async functions, subprocess lifecycle gaps,
file-write atomicity gaps, and timeout coverage gaps.
**No code was changed before this table was written** (R03 binding rule).

### Blocking-operation table

| ID | File | Approx line | Operation | Why blocking | Event loop freed? | Fix |
|---|---|---|---|---|---|---|
| A01 | `memfabric/stores/lexical_bm25.py` | 92 | `self._index.get_scores(tokens)` | CPU-bound BM25 scoring inside `asyncio.Lock` | ❌ No | `await asyncio.to_thread(self._index.get_scores, tokens)` inside the lock |
| A02 | `memfabric/stores/lexical_bm25.py` | 131 | `BM25Plus(corpus)` in `_rebuild_unlocked` | CPU-bound index construction inside `asyncio.Lock` | ❌ No | `self._index = await asyncio.to_thread(BM25Plus, corpus)` via new `_rebuild_async` helper |
| A03 | `memfabric/stores/episodic_jsonl.py` | 96–97 | `self._path.open("a"); fh.write(...)` | Synchronous file I/O inside `asyncio.Lock` | ❌ No | `await asyncio.to_thread(_write_line_sync, self._path, line)` |
| A04 | `apex_host/knowledge/compiled_loader.py` | 120 | `path.read_text(encoding="utf-8")` | Synchronous file read inside `async def` | ❌ No | `await asyncio.to_thread(path.read_text, encoding="utf-8")` |
| A05 | `apex_host/eval/report.py` | 482–486 | `out.write_text(...)` | Non-atomic write; truncates file before writing | N/A | Temp file + `fsync` + `tmp.replace(out)` |
| A06 | `apex_host/eval/export_graph.py` | 71 | `Path(path).write_text(...)` | Non-atomic write | N/A | Same atomic temp-file pattern |
| A07 | `apex_host/tools/runner.py` | 67–68 | `proc.kill()` on `TimeoutError` | SIGKILL without SIGTERM grace period; children die abruptly | N/A | `proc.terminate()` → 5 s grace → `proc.kill()` |
| A08 | `apex_host/tools/runner.py` | (absent) | No `asyncio.CancelledError` handler | Child process left orphaned when caller is cancelled | N/A | `except asyncio.CancelledError: proc.terminate(); await proc.wait(); raise` |
| A09 | `apex_host/agents/browser_executor.py` | 141 | `playwright.chromium.launch()` | No explicit timeout; can hang indefinitely | ❌ No | `asyncio.wait_for(playwright.chromium.launch(), timeout=config.browser_launch_timeout_seconds)` |

### Subprocess lifecycle table

| Phase | Current behaviour | Required behaviour |
|---|---|---|
| Normal completion | `await proc.communicate()` with outer `wait_for` | Unchanged |
| Timeout | `proc.kill()` immediately → SIGKILL | `proc.terminate()` → 5 s grace wait → `proc.kill()` if still alive |
| `asyncio.CancelledError` | Process not terminated (orphan) | `proc.terminate(); await proc.wait()` before re-raising |
| `OSError` on launch | Returns `ToolResult(error=...)` | Unchanged (already correct) |

### Timeout coverage gaps (new `ApexConfig` fields required)

| Gap | New field | Default value |
|---|---|---|
| No `browser.launch()` timeout | `browser_launch_timeout_seconds` | `30.0` |
| No per-socket Telnet read timeout | `telnet_read_timeout_seconds` | `10.0` |
| No per-channel retrieval timeout | `retrieval_channel_timeout_seconds` | `5.0` |
| No parser-call timeout | `parser_timeout_seconds` | `10.0` |
| No subprocess SIGTERM grace period config | `subprocess_sigterm_grace_seconds` | `5.0` |

### File-write atomicity table

| File | Current write | Problem | Fix |
|---|---|---|---|
| `apex_host/eval/report.py:write_report_json` | `Path.write_text(...)` | Truncates target file before writing; crash leaves zero-byte file | `write_atomic(path, data)` — write to `.tmp`, `fsync`, `replace` |
| `apex_host/eval/export_graph.py:write_json` | `Path.write_text(...)` | Same | Same fix |

### Architecture scan requirements

| Scan | Pass condition |
|---|---|
| No nested `asyncio.run()` in library code | `grep -rn "asyncio.run(" memfabric/ apex_host/` finds only CLI entry points (`main.py`, `run_htb_local.py`, `run_synthetic_machine.py`) |
| No raw subprocess outside `runner.py` | `grep -rn "subprocess\|create_subprocess" memfabric/ apex_host/` finds only `runner.py` and tests |
| No `time.sleep()` in coroutines | `grep -rn "time.sleep" memfabric/ apex_host/` finds no hits in library code |

### Missing tests (to be written in `tests/apex_host/test_phase7_async.py`)

130+ tests in 19 groups:

| Group | Test names | Count |
|---|---|---|
| G01 — Event-loop heartbeat | `test_heartbeat_survives_bm25_search`, `test_heartbeat_survives_bm25_rebuild`, `test_heartbeat_survives_jsonl_append`, `test_heartbeat_survives_compiled_loader_read`, `test_heartbeat_survives_concurrent_graph_upserts`, `test_heartbeat_survives_retrieval_search`, `test_heartbeat_survives_reflector_pass`, `test_heartbeat_survives_runner_dry_run` | 8 |
| G02 — BM25 thread offload | `test_bm25_search_runs_in_thread`, `test_bm25_rebuild_runs_in_thread`, `test_bm25_search_does_not_block_loop`, `test_bm25_concurrent_searches_are_safe`, `test_bm25_search_and_add_concurrent`, `test_bm25_rebuild_after_add`, `test_bm25_search_empty_index`, `test_bm25_add_then_search_immediate` | 8 |
| G03 — JSONL concurrency | `test_jsonl_concurrent_appends_no_corruption`, `test_jsonl_file_is_valid_json_after_concurrent_appends`, `test_jsonl_cancellation_does_not_leave_partial_line`, `test_jsonl_append_does_not_block_loop`, `test_jsonl_pop_episodes_rollback`, `test_jsonl_in_memory_mode_no_file_io` | 6 |
| G04 — Subprocess lifecycle | `test_runner_timeout_sends_sigterm_before_sigkill`, `test_runner_timeout_sigkill_after_grace`, `test_runner_cancellation_terminates_child`, `test_runner_cancellation_does_not_leave_zombie`, `test_runner_dry_run_no_subprocess`, `test_runner_tool_not_found_returns_error`, `test_runner_timeout_returns_error_result`, `test_runner_cancellation_reraises` | 8 |
| G05 — Browser executor | `test_browser_launch_timeout_applied`, `test_browser_dry_run_no_playwright`, `test_browser_stateless_multiple_calls`, `test_browser_synthetic_obs_structure`, `test_browser_config_timeout_field`, `test_browser_launch_timeout_configurable` | 6 |
| G06 — Atomic write | `test_write_report_json_atomic_no_partial`, `test_write_report_json_idempotent`, `test_write_json_graph_atomic`, `test_write_json_graph_creates_parent_dirs`, `test_write_atomic_replaces_existing`, `test_write_atomic_handles_os_error`, `test_write_atomic_temp_not_visible`, `test_write_report_json_content_valid` | 8 |
| G07 — Config timeout fields | `test_config_browser_launch_timeout_default`, `test_config_telnet_read_timeout_default`, `test_config_retrieval_channel_timeout_default`, `test_config_subprocess_sigterm_grace_default`, `test_config_parser_timeout_default`, `test_config_max_command_seconds_default`, `test_config_timeout_fields_serializable`, `test_config_dry_run_default_true` | 8 |
| G08 — Runtime shutdown | `test_runtime_aclose_exists`, `test_runtime_aclose_is_coroutine`, `test_runtime_aclose_idempotent`, `test_runtime_aclose_before_run`, `test_runtime_aclose_after_run`, `test_runtime_aclose_cancels_pending` | 6 |
| G09 — Compiled loader async | `test_compiled_loader_reads_file_in_thread`, `test_compiled_loader_does_not_block_loop`, `test_compiled_loader_missing_file_returns_zero`, `test_compiled_loader_invalid_json_skipped`, `test_compiled_loader_empty_text_skipped`, `test_compiled_loader_concurrent_loads` | 6 |
| G10 — Retrieval timeout | `test_retrieval_channel_timeout_fires`, `test_retrieval_bm25_timeout_returns_empty`, `test_retrieval_vector_timeout_returns_empty`, `test_retrieval_graph_timeout_returns_empty`, `test_retrieval_timeout_does_not_crash_search`, `test_retrieval_timeout_falls_back_gracefully` | 6 |
| G11 — Bounded concurrency | `test_bounded_thread_pool_io_semaphore`, `test_io_semaphore_caps_concurrent_threads`, `test_cpu_semaphore_caps_concurrent_threads`, `test_semaphore_release_on_exception`, `test_semaphore_release_on_cancellation`, `test_io_semaphore_default_value` | 6 |
| G12 — Architecture scan | `test_no_nested_asyncio_run_in_library_code`, `test_no_raw_subprocess_outside_runner`, `test_no_time_sleep_in_async_functions`, `test_bm25_search_is_async_def`, `test_episodic_append_is_async_def`, `test_runner_is_async_def` | 6 |
| G13 — Cancellation disposition | `test_cancelled_disposition_exists`, `test_timed_out_disposition_exists`, `test_cancelled_task_not_retried`, `test_timed_out_task_not_retried`, `test_disposition_cancelled_never_retry`, `test_disposition_timed_out_never_retry` | 6 |
| G14 — F15/F16 deferred | `test_global_planner_no_double_charge_on_phase_transition`, `test_global_planner_budget_charges_once_per_turn`, `test_global_planner_budget_force_advance_fires`, `test_duplicate_actions_accumulate_across_turns`, `test_duplicate_actions_list_has_entries`, `test_duplicate_action_entry_structure` | 6 |
| G15 — Lock duration | `test_graph_lock_released_during_bm25_thread`, `test_lock_not_held_during_file_read`, `test_lock_not_held_during_file_write`, `test_staging_lock_released_during_promotion`, `test_bm25_lock_does_not_starve_concurrent_adds`, `test_jsonl_lock_does_not_starve_concurrent_reads` | 6 |
| G16 — Async utils | `test_run_io_returns_result`, `test_run_cpu_returns_result`, `test_write_atomic_uses_temp_file`, `test_read_text_async_returns_content`, `test_cpu_semaphore_default_value`, `test_run_io_propagates_exception` | 6 |
| G17 — SIGTERM details | `test_sigterm_grace_period_duration`, `test_process_cleanup_on_timeout`, `test_cancelled_coroutine_terminates_child_process`, `test_runner_timeout_error_result_has_duration`, `test_runner_normal_execution_no_sigterm`, `test_runner_sigterm_grace_configurable` | 6 |
| G18 — BM25 edge cases | `test_bm25_remove_then_search`, `test_bm25_tokenize_short_tokens_filtered`, `test_bm25_search_returns_zero_score_filtered`, `test_bm25_search_dedup_guard`, `test_bm25_search_top_k_respected` | 5 |
| G19 — Integration | `test_full_dry_run_completes_without_blocking`, `test_concurrent_upserts_during_retrieval`, `test_api_query_freshness_after_concurrent_writes`, `test_episodic_append_concurrent_stress`, `test_phase7_all_fixes_active_in_integration` | 5 |

---

## Phase 8 — Sensitive-Data Boundary Inventory (Pre-Implementation, 2026-07-14)

This inventory was produced **before** any Phase 8 code changes.
It covers every surface where secret material (passwords, session transcripts, credentials)
may flow from the engagement runtime into persistent stores (EKG, episodic log, JSON export,
LLM prompts, or log output). **No code was changed before this table was written** (Rule R03).

### Sensitive-data flow table

| Surface | File | Line(s) | Data that flows | Sink (where it lands) | Risk | Current protection | Required fix |
|---------|------|---------|----------------|----------------------|------|-------------------|-------------|
| `TelnetExecutor.run()` — live | `apex_host/agents/telnet_executor.py` | 107–121 | `episode.data["stdout"]` = full session transcript; contains post-login `id` command output and possibly echoed credentials | EpisodicStore (JSONL), `ApexGraphState.last_tool_result`, eval JSON export | **HIGH** — raw session text may include echoed username and password prompt interaction | `username` is in episode data (acceptable for audit); no password filtering | Replace `stdout` with `[session_redacted]` in live-mode episode; keep only `stdout_length` and `shell_found` flag |
| `TelnetExecutor._dry_run_result()` | `apex_host/agents/telnet_executor.py` | 129–152 | `episode.data["stdout"]` = synthetic text containing `f"login: {username}\r\n"` and `"Password: \r\n"` | EpisodicStore, graph state | **LOW** (dry-run; no real password; username is not a secret) | None | Strip the username-echo line from synthetic stdout; the dry-run result is otherwise safe |
| `TelnetExecutor.run()` — `action` field | `apex_host/agents/telnet_executor.py` | 108–109 | `action=f"telnet {target}:{port} user={username}"` | EpisodicStore `Episode.action` | **NONE** — username is acceptable in audit log | Acceptable | No change |
| `AccessParser.parse_text()` — `evidence` | `apex_host/parsers/access_parser.py` | 94 | `props["evidence"] = text[:200]` = first 200 chars of raw session text | EKG `access_state` node via `MemoryAPI.upsert_node`, EKG JSON export | **MEDIUM** — first 200 chars of session text contains login banner, username echo, and password prompt response | None | Pass session text through `redact_session_text()` before storing; or derive `evidence` from proven-safe fields only (proof_snippet + outcome) |
| `AccessParser.parse_text()` — `proof` | `apex_host/parsers/access_parser.py` | 95 | `props["proof"] = proof_lines[-1][:120]` = last non-empty line (typically shell prompt or `id` output) | EKG `access_state` node | **LOW** — last line is usually `#`, `$`, or `uid=0(root)` which is not sensitive | None | No change (shell prompt and `id` output are audit evidence, not secrets) |
| `credential` node `props["secret_hint"]` | `apex_host/parsers/access_parser.py` | 67 | Always `"[redacted]"` | EKG `credential` node | **NONE** — already correctly redacted | Already correct | No change |
| `credential` node `props["username"]` | `apex_host/parsers/access_parser.py` | 66 | `username` in plain text | EKG `credential` node | **NONE** — username is not a secret; it is an observable identity claim | Acceptable | No change |
| `PromptBuilder.build_messages()` | `apex_host/planning/prompt_builder.py` | `evidence` entries | `ScoredEntry.text` from retrieved knowledge may include `evidence` fields from `access_state` nodes | LLM API call body | **MEDIUM** — if `access_state.evidence` is included in retrieved text, it goes to the LLM | `LLMPolicyGuard.sanitize_messages()` already redacts configured passwords | Fix `access_state.evidence` at storage time (upstream fix); LLM guard remains defense-in-depth |
| `ApexGraphState.last_tool_result` | `apex_host/graph_state.py` | 60 | May contain `{"stdout": <session text>}` dict | LangGraph checkpoint (in-memory `MemorySaver`) | **LOW** — MemorySaver is in-memory only; not persisted to disk | Checkpoint is in-memory only, not written to disk | No change (in-memory only); the upstream `episode.data["stdout"]` fix is the primary protection |
| `RunReport.to_json_dict()` | `apex_host/eval/report.py` | JSON export | `tool_results` list (from `state["tool_results"]`) may include per-task `stdout` | Disk file | **MEDIUM** — if stdout with session text reaches the report | None | Mask `stdout` field in `tool_results` entries when it contains login session patterns; or exclude `stdout` from tool_result dicts in report output |
| `export_ekg()` in `run_htb_local.py` | `apex_host/eval/run_htb_local.py` | EKG export | Exports all EKG nodes including `access_state.evidence` | Disk file | **MEDIUM** | None | Already handled upstream by fixing `access_parser` |
| Log output in `telnet_executor.py` | `apex_host/agents/telnet_executor.py` | 106 | `logger.info("telnet %s:%s user=%r …")` — username in log line | Python log output | **NONE** — username not sensitive | Acceptable | No change |
| `task.params["password"]` in TaskSpec | Various planners → `TelnetExecutor.run()` | Throughout | Password in `task.params["password"]` | In-memory `TaskSpec`; `ApexGraphState.current_task` dict | **LOW** — in-memory only; `current_task` is overwritten each turn | Not persisted to episodic log directly | Exclude `password` key from `current_task` serialization; OR accept as low-risk since `current_task` is not exported |
| `config.password_candidates` | `apex_host/config.py` | Source field | Passwords in config object | Python object (not serialized to disk by default) | **LOW** — not exported to disk by default | `LLMPolicyGuard.sanitize_messages()` reads these for redaction | No change |

### Redaction contract (binding)

The following invariants must hold after Phase 8 and must never be violated:

| # | Invariant |
|---|---|
| P8-S01 | `credential` node `props["secret_hint"]` is always `"[redacted]"` — the literal string, never the actual password |
| P8-S02 | `access_state` node `props["evidence"]` contains **only** session-text that has been passed through `redact_session_text(text, passwords=[...])` |
| P8-S03 | `Episode.data["stdout"]` for live telnet sessions is replaced with `"[session_redacted]"` before the `Episode` is created — the plaintext session transcript is never stored |
| P8-S04 | `Episode.data["stdout"]` for dry-run sessions may contain synthetic text without real credentials (already true in current code; enforced by test) |
| P8-S05 | `task.params["password"]` is never included in `episode.data` or `access_state.props` |
| P8-S06 | `apex_host/security/redaction.py` is the **sole** source of redaction logic — no inline `str.replace("[redacted]", ...)` calls scattered in parsers or executors |
| P8-S07 | The `redact_session_text(text, *, passwords)` function redacts each password in the passwords list from the session text; minimum password length for redaction is 1 character (unlike `LLMPolicyGuard` which uses 4) |
| P8-S08 | `canary_in_episode_data_after_telnet` test verifies no canary password appears in any episode produced by a live-mode (non-dry-run) `TelnetExecutor.run()` call |

---

## Phase 8 — Graph Identity and Representation Inventory (Pre-Implementation, 2026-07-14)

This inventory covers every node/edge ID generation site, the parallel-edge inconsistency
in `NetworkXGraphStore`, endpoint URL normalization gaps, and the tech-concept vs.
tech-installation distinction. **No code was changed before this table was written** (Rule R03).

### Node ID generation sites

| Node type | ID format | Defined in | Canonical? | Issue |
|-----------|-----------|------------|-----------|-------|
| `host` | `f"host:{ip}"` | `nmap_parser.py:67`, `command_parser.py` | **Yes** — stable, deterministic | None |
| `service` | `f"service:{ip}:{port}/{proto}"` | `nmap_parser.py:101`, `capabilities.py` | **Yes** | None |
| `tech` | `f"tech:{host_addr}:{slug}"` where slug = lowercased product name | `nmap_parser.py:48-49` (inline) | **Partial** — host-scoped but slug-gen logic is inline | Slug generation duplicated in nmap_parser; should be in `graph_ids.py` |
| `endpoint` | `f"endpoint:{url}"` (various) | `command_parser.py`, `browser_parser.py`, `ffuf_parser.py`, `gobuster_parser.py` | **No** — raw URL, no normalization | `http://10.0.0.1/` vs `http://10.0.0.1` → different IDs for same endpoint |
| `auth_flow` | `f"auth_flow:{url}"` | `browser_parser.py`, `command_parser.py` | **No** | Same URL normalization gap |
| `credential` | `f"credential:{target}:{username}"` | `access_parser.py:60` | **Yes** | None |
| `access_state` | `f"access_state:{target}:{username}"` | `access_parser.py:84` | **Yes** | None |
| `form` | `f"form:{url}:{index}"` | `browser_parser.py` | **Partial** | URL part not normalized |
| `token` | `f"token:{url}:{name}"` | `browser_parser.py` | **Partial** | URL part not normalized |
| `tech` (concept vs. installation) | Currently conflated as `tech:{host}:{slug}` | `nmap_parser.py` | **No distinction** | The same software on two hosts creates two nodes with different IDs — this is CORRECT (host-scoped installations). No change needed; distinction is already encoded in the ID. |

### Edge ID generation sites

| Edge type | ID format | Defined in | Canonical? | Issue |
|-----------|-----------|------------|-----------|-------|
| `exposes` | `f"exposes:{host_id}:{service_id}"` | `nmap_parser.py:124` | **Yes** | None |
| `runs` | `f"runs:{service_id}:{tech_id}"` | `nmap_parser.py:153` | **Yes** | None |
| `grants` (cred→access) | `f"grants:{cred_id}:{access_id}"` | `access_parser.py:105` | **Yes** | None |
| `grants` (service→access) | `f"grants:{service_id}:{access_id}"` | `access_parser.py:135` | **Yes** | None |
| `tested` | `f"tested:{service_id}:{cred_id}"` | `access_parser.py:121` | **Yes** | None |
| `contains` | `f"contains:{endpoint_id}:{child_id}"` | `command_parser.py`, `browser_parser.py` | **Partial** | URL part not normalized |
| `requires` | `f"requires:{endpoint_id}:{auth_flow_id}"` | `browser_parser.py`, `command_parser.py` | **Partial** | URL part not normalized |
| `exposes` (host→endpoint) | `f"exposes:{host_id}:{endpoint_id}"` | `command_parser.py` | **Partial** | endpoint_id URL not normalized |

### Parallel-edge inconsistency

| Method | Reads from | Multiple edges per (from,to) pair visible? | Issue |
|--------|-----------|-------------------------------------------|-------|
| `NetworkXGraphStore.put_edge()` | writes to `self._edges` dict **and** `self._g.add_edge()` | n/a | `add_edge(u,v)` in `DiGraph` overwrites the last stored edge's data in `self._g` |
| `NetworkXGraphStore.get_edge()` | `self._edges` dict | **Yes** | Correct — reads by edge ID |
| `NetworkXGraphStore.all_edges()` | `self._edges` dict | **Yes** | Correct |
| `NetworkXGraphStore.get_subgraph()` BFS | `self._g.predecessors/successors` for traversal | **Only one** per directed pair in traversal | BFS uses DiGraph traversal — finds the node even if parallel edge exists; CORRECT for node discovery |
| `NetworkXGraphStore.get_subgraph()` edge collection | `self._edges` dict | **Yes** | Correct — collects all edges whose endpoints are in visited set |
| `NetworkXGraphStore.get_edges_for_node()` | `self._g.out_edges + in_edges` | **Only one** per directed pair | **BUG** — if two edges have same `(from_id, to_id)` but different IDs/types, only the last-written edge is returned |
| `NetworkXGraphStore.delete_edge()` | `self._edges` + `self._g.remove_edge(u,v)` | n/a | Removes ALL edges between that pair in `self._g` (regardless of which edge ID was requested) |

**Impact:** `get_edges_for_node` is inconsistent with `get_subgraph`. In current parser outputs, true parallel edges (same `from_id`, same `to_id`, different IDs) do not occur because each parser uses unique `to_id` values. However, the inconsistency is a latent bug.

**Fix:** Change `get_edges_for_node` to read from `self._edges` dict (consistent with `all_edges` and `get_subgraph`).

**Dangling-edge behavior:** An edge whose `from_id` or `to_id` does not correspond to an existing node in `self._g` is a **dangling edge**. Current behavior: `put_edge(e)` with a non-existent node calls `self._g.add_edge(u, v)` which silently creates the missing node(s) in networkx (as attribute-less nodes). This can cause `get_nodes_by_type` to return attribute-error nodes. **Fix:** `put_edge` must raise `ValueError` if either `from_id` or `to_id` is not in the graph at write time (or alternatively, silently ignore the edge). Conservative choice: raise `ValueError` with a clear message.

### URL normalization contract (binding)

`_normalize_endpoint_url(url)` in `apex_host/graph_ids.py` applies:
1. Lowercase the scheme and host (RFC 3986 §6.2.2.1)
2. Remove default ports: `:80` after `http://`, `:443` after `https://`
3. Collapse multiple consecutive slashes in path to one
4. Strip trailing slash from path UNLESS the path is exactly `/` (preserve root)
5. Return the normalized URL; non-URL inputs are returned unchanged

All `endpoint`, `auth_flow`, `form`, and `token` node IDs must be derived from normalized URLs.

### Graph schema versioning contract

`EKG_SCHEMA_VERSION = "1"` (module-level constant in `apex_host/graph_ids.py`).
The JSON export from `export_ekg()` includes `"schema_version": EKG_SCHEMA_VERSION`.
A future incompatible change to node/edge types or ID format increments this version.
Tests verify the version field is present and equals `"1"`.

### Missing tests (to be written in `tests/apex_host/test_phase8_redaction.py`)

100+ tests across 10 groups:

| Group | Tests | Count |
|-------|-------|-------|
| REDACT — Redaction module | `test_redact01_session_text_removes_password`, `test_redact02_empty_password_no_change`, `test_redact03_multiple_passwords_all_removed`, `test_redact04_no_passwords_configured_no_change`, `test_redact05_redact_dict_recursive`, `test_redact06_redact_list_recursive`, `test_redact07_redact_nested_dict_value`, `test_redact08_redact_none_value_safe`, `test_redact09_redact_returns_new_object`, `test_redact10_short_password_still_redacted` | 10 |
| CANARY — Canary artifact scanning | `test_canary01_no_canary_password_in_live_episode_data`, `test_canary02_no_canary_password_in_episode_action`, `test_canary03_no_canary_in_access_state_evidence`, `test_canary04_no_canary_in_ekg_node_props`, `test_canary05_dry_run_stdout_has_no_real_password` | 5 |
| BOUND — Boundary invariants | `test_bound01_secret_hint_always_redacted_string`, `test_bound02_credential_node_no_secret_prop`, `test_bound03_access_state_evidence_redacted`, `test_bound04_episode_stdout_redacted_live_mode`, `test_bound05_episode_stdout_ok_in_dry_run`, `test_bound06_username_preserved_in_episode`, `test_bound07_username_preserved_in_credential_node`, `test_bound08_no_password_in_task_params_in_episode` | 8 |
| GRAPH_ID — Canonical ID functions | `test_gid01_host_id_format`, `test_gid02_service_id_format`, `test_gid03_tech_id_slug_lowercases`, `test_gid04_tech_id_special_chars_normalized`, `test_gid05_exposes_edge_id_format`, `test_gid06_runs_edge_id_format`, `test_gid07_grants_edge_id_format`, `test_gid08_tested_edge_id_format`, `test_gid09_credential_id_format`, `test_gid10_access_state_id_format` | 10 |
| URL — Endpoint URL normalization | `test_url01_trailing_slash_stripped`, `test_url02_root_slash_preserved`, `test_url03_scheme_lowercased`, `test_url04_host_lowercased`, `test_url05_default_port_80_stripped`, `test_url06_default_port_443_stripped`, `test_url07_non_default_port_preserved`, `test_url08_query_string_preserved`, `test_url09_fragment_preserved`, `test_url10_non_url_input_returned_unchanged`, `test_url11_endpoint_id_uses_normalized_url`, `test_url12_two_equivalent_urls_same_endpoint_id` | 12 |
| PAR — Parallel-edge consistency | `test_par01_two_edges_same_pair_both_in_get_edges_for_node`, `test_par02_get_edges_for_node_consistent_with_get_subgraph`, `test_par03_all_edges_consistent_with_get_edges_for_node`, `test_par04_single_edge_still_returned`, `test_par05_delete_edge_removes_only_target_id` | 5 |
| DANGLE — Dangling edge behavior | `test_dangle01_put_edge_with_missing_from_node_raises`, `test_dangle02_put_edge_with_missing_to_node_raises`, `test_dangle03_put_edge_both_nodes_exist_succeeds`, `test_dangle04_put_node_then_put_edge_ok`, `test_dangle05_dangling_edge_not_returned_by_get_subgraph` | 5 |
| SCHEMA — Schema version | `test_schema01_ekg_schema_version_constant_exists`, `test_schema02_export_ekg_includes_schema_version`, `test_schema03_schema_version_is_string_1`, `test_schema04_schema_version_stable_across_calls` | 4 |
| ARCH — Architecture scans | `test_arch01_redaction_module_is_sole_redaction_source`, `test_arch02_no_inline_redacted_string_assignment_in_parsers`, `test_arch03_no_inline_redacted_string_assignment_in_executors`, `test_arch04_graph_ids_module_exists`, `test_arch05_no_fstring_host_prefix_outside_graph_ids`, `test_arch06_no_fstring_service_prefix_outside_graph_ids`, `test_arch07_no_fstring_credential_prefix_outside_graph_ids`, `test_arch08_no_fstring_access_state_prefix_outside_graph_ids`, `test_arch09_no_fstring_endpoint_prefix_outside_parsers`, `test_arch10_security_module_has_init` | 10 |
| INT — Integration | `test_int01_full_dry_run_engagement_no_canary_in_ekg`, `test_int02_access_parser_output_passes_boundary_invariants`, `test_int03_nmap_parser_output_passes_boundary_invariants`, `test_int04_graph_ids_consistent_with_nmap_parser_output`, `test_int05_graph_ids_consistent_with_access_parser_output`, `test_int06_parallel_edge_fix_survives_apply_deltas`, `test_int07_export_ekg_schema_version_present`, `test_int08_endpoint_normalization_merges_duplicate_nodes`, `test_int09_redaction_module_imported_in_telnet_executor`, `test_int10_redaction_module_imported_in_access_parser`, `test_int11_live_episode_stdout_not_stored_in_ekg_via_parser` | 11 |
