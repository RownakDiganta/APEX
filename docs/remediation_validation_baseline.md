# Remediation Validation Baseline

This document records the exact environment and tool outputs used to establish the
Phase 0 and Phase 1 validation baselines.  Every future phase must be validated
against these baselines to confirm no regressions.

---

## Environment

| Field | Value |
|---|---|
| Date | 2026-07-13 |
| OS | Darwin 24.3.0 (macOS Sequoia 15.x, arm64) |
| Python | 3.11.14 (venv: `.venv/bin/python`) |
| pytest | installed via `pyproject.toml` |
| mypy | installed via `pyproject.toml` |
| ruff | installed via `.venv/bin/pip install ruff` (not in pyproject.toml dev deps) |
| faiss-cpu | via pyproject.toml |
| networkx | via pyproject.toml |
| langgraph | >= 0.2 (pinned via pyproject.toml) |
| playwright | via pyproject.toml |
| pydantic | v2 (via pyproject.toml) |
| Working directory | `/Users/mdrownakdiganta/Desktop/New Apex` |
| Git HEAD (Phase 0 baseline) | `45124a8` (Remove legacy payload repository) |
| Git HEAD (Phase 1 complete) | Phase 1 implementation commit |

---

## Validation Commands

All commands are run from the project root with the venv activated.

### Test suite
```bash
.venv/bin/python -m pytest tests/ -q
```

### Type checking
```bash
.venv/bin/python -m mypy --strict memfabric apex_host
```

### Lint
```bash
.venv/bin/ruff check memfabric apex_host tests
```

### Test collection count only
```bash
.venv/bin/python -m pytest tests/ --collect-only -q | tail -1
```

---

## Phase 0 Baseline (pre-fix; commit 45124a8)

### pytest output
```
1311 passed in 4.69s
```

### mypy output
```
Success: no issues found in 101 source files
```

### ruff output
```
Found 135 errors.
[*] 107 fixable with the `--fix` option (20 hidden fixes can be enabled with the `--unsafe-fixes` option).
```

**Note:** The 135 ruff errors are pre-existing (predominantly F401 unused imports).
They are not introduced by any phase of this remediation and must not be counted
as new defects.  Phase 4 will address them as a batch under finding F18 (enforce
coding conventions through tooling).

---

## Phase 1 Baseline (post-fix; F01, F02, F19 fixed + substrate hardening)

### pytest output
```
1328 passed in 4.35s
```

17 new tests added:
- `tests/test_graph_atomicity.py` — 17 deterministic concurrency, atomicity, and defensive-copy tests (T01–T17)

### mypy output
```
Success: no issues found in 101 source files
```

101 source files checked (unchanged — no new modules added).

### ruff output
```
Found 135 errors.
[*] 107 fixable with the `--fix` option (20 hidden fixes can be enabled with the `--unsafe-fixes` option).
```

Ruff error count unchanged — Phase 1 did not introduce or fix lint errors.

---

## Required Validation After Each Phase

Every phase must produce output that satisfies all three conditions:

1. **pytest:** `N passed` where N ≥ previous phase count. Zero failures.
2. **mypy:** `Success: no issues found in 101 source files` (or more if new modules added).
3. **ruff:** Count must not increase from the baseline for that phase (135 at Phase 1).

If any condition fails, the phase is not complete.

---

## Finding-Level Test Validation

For each finding, the missing test must:
1. Fail before the fix is applied (red).
2. Pass after the fix is applied (green).
3. Be in the correct test file (see `docs/remediation_traceability_matrix.md`).

The Phase 0 audit identified 21 missing tests across findings F01–F21.  F01,
F02, and F19 are resolved; 18 tests remain to be written (one per open finding,
counting F15 even though it is PLAUSIBLE).

---

## Ruff Error Category Breakdown (Phase 0 baseline: 135 errors)

The 135 ruff errors are distributed across files as of the Phase 0 baseline.
The dominant categories are:

- **F401** — unused imports (majority of errors; auto-fixable)
- **F541** — f-string without placeholders (auto-fixable)
- Other minor categories (E501 line length, etc.)

These are pre-existing errors from before the Phase 0 audit.  They were not
introduced during this session and do not affect test passage or mypy status.

---

## Phase 1 Comprehensive Baseline (post-fix; reader isolation + delete API + 58 new tests)

### pytest output
```
1386 passed in 4.32s
```

58 new tests added:
- `tests/test_graph_transaction_complete.py` — 51 tests covering reader isolation (A01–A08),
  commit/index/cache coherence (B01–B05), rollback/index/cache integrity (C01–C10),
  proposal staging isolation (D01–D04), public deletion API (E01–E10), defensive copies
  via public surface (F01–F07), architecture scan (G01–G02), episode contract (H01–H05).
- `tests/test_graph_stress.py` — 7 stress tests covering 100 disjoint-field concurrent
  writes, 50 distinct node upserts, 20 concurrent batches (100 nodes total), mixed
  readers+writers, 100 concurrent same-edge LWW writes, write-clock monotonicity,
  and open_tasks consistency under concurrent writes.

### mypy output
```
Success: no issues found in 101 source files
```

101 source files checked (unchanged — no new modules added; new code is tests only).

### ruff output
```
Found 135 errors.
[*] 107 fixable with the `--fix` option (20 hidden fixes can be enabled with the `--unsafe-fixes` option).
```

Ruff error count unchanged from Phase 1 baseline (135). All 8 new ruff errors from
unused imports in test files were fixed before recording this baseline.

---

## Source File Count History

| After | Source files (mypy --strict) | Test count | Ruff errors |
|---|---|---|---|
| Phase 0 baseline | 101 | 1311 | 135 |
| Phase 1 (initial) | 101 | 1328 (+17 test_graph_atomicity.py) | 135 |
| Phase 1 (comprehensive) | 101 | 1386 (+51 test_graph_transaction_complete.py, +7 test_graph_stress.py) | 135 |
| Phase 1 (re-open) | 101 | 1426 (+40 test_graph_phase1_extended.py) | 135 |
| Phase 2 (initial) | 101 | 1486 (+60 test_conflict_phase2.py) | 135 |
| Phase 2 (reopen) | 101 | 1558 (+72 test_conflict_phase2_reopen.py) | 135 |
| Phase 3 | 101 | 1680 (+122 test_skill_lifecycle.py) | 135 |
| Phase 4 | 106 | 1797 (+117 test_retrieval_phase4.py) | 133 |
| Phase 5 | 102 | 1865 (+68) | 133 |
| Phase 5 (reopen) | 102 | 1961 (+96 test_phase5_reopen.py) | 134 |
| Phase 6 | 108 | 2087 (+126 test_phase6_dispatcher.py) | 134 |
| Phase 7 | 109 | 2218 (+131 test_phase7_async.py) | 130 |
| Phase 8 | 112 | 2298 (+80 test_phase8_redaction.py) | 130 |
| Phase 9 | 112 | 2378 (+80 test_phase9_config.py) | 130 |
| Phase 10 | 125 | 2618 (+120 test_phase10_orchestration.py, +5 test_file_headers.py) | 130 |
| Phase 11 | 125 | 2668 (+50 test_final_verification.py) | 130 |

---

## Phase 8 Baseline (post-fix; 2026-07-14)

### pytest output
```
2298 passed in 136.84s (0:02:16)
```

80 new tests added:
- `tests/apex_host/test_phase8_redaction.py` — 80 tests across 10 groups:
  REDACT (10), CANARY (5), BOUND (8), GRAPH_ID (10), URL (12), PAR (5),
  DANGLE (5), SCHEMA (4), ARCH (10), INT (11).

### mypy output
```
Success: no issues found in 112 source files
```

112 source files checked (up from 109 after Phase 7 — 3 new production files:
`apex_host/security/__init__.py`, `apex_host/security/redaction.py`,
`apex_host/graph_ids.py`).

### ruff output
```
Found 130 errors.
[*] 108 fixable with the `--fix` option (17 hidden fixes can be enabled with the --unsafe-fixes option).
```

130 errors — at the Phase 7 ceiling (not above it). All Phase 8 test and
source files introduced zero new ruff violations.

---

---

## Phase 9 Baseline (post-fix; 2026-07-14)

### pytest output
```
2378 passed in 143.77s (0:02:23)
```

80 new tests added:
- `tests/apex_host/test_phase9_config.py` — 80 tests across 7 groups:
  CFG (15), CLI (15), ENV (10), STATE (15), SERIAL (10), ARCH (10), E2E (5).

### mypy output
```
Success: no issues found in 112 source files
```

112 source files checked (unchanged from Phase 8 — no new production modules added;
new code is `tests/apex_host/test_phase9_config.py` only).

### ruff output
```
Found 130 errors.
[*] 108 fixable with the `--fix` option (17 hidden fixes can be enabled with the --unsafe-fixes option).
```

130 errors — at the Phase 8 ceiling (unchanged). Phase 9 introduced zero new ruff violations
(`import ast` removed from test file to preserve count).

---

---

## Phase 10 Baseline (post-fix; 2026-07-14)

### pytest output
```
2618 passed in 137.22s (0:02:17)
```

240 new tests added since Phase 9:
- `tests/apex_host/test_phase10_orchestration.py` — 120 tests across 10 groups:
  CHAR (17), BUILD (12), ROUTE (14), COMP (16), MODEL (6), DEPS (10),
  ARCH (15), PAR (10), E2E (10), FIX (10).
- `tests/test_file_headers.py` — 5 tests enforcing §12.6 file-header convention (F18).
- Plus 115 tests from prior-session work on orchestration decomposition
  (test_policy_gate.py updates, test_llm_phase5.py updates,
  test_conflict_phase2_reopen.py updates).

### mypy output
```
Success: no issues found in 125 source files
```

125 source files checked (up from 112 in Phase 9 — 13 new orchestration modules
in `apex_host/orchestration/` plus `tests/test_file_headers.py`).

### ruff output
```
Found 130 errors.
[*] 120 fixable with the `--fix` option (17 hidden fixes can be enabled with the --unsafe-fixes option).
```

130 errors — at the Phase 8 ceiling (maintained). Phase 10 introduced zero net
new ruff violations: unused imports removed from `test_phase10_orchestration.py`,
`repair_node.py`, and `test_phase6_dispatcher.py` to stay at the 130 ceiling.

---

---

## Phase 11 Baseline (final verification; 2026-07-14)

### pytest output
```
2668 passed, 53 warnings in 138.70s (0:02:18)
```

50 new tests added:
- `tests/test_final_verification.py` — 50 tests across 10 groups (GRAPH, CONFLICT,
  SKILL, RETRIEVAL, LLM, EXEC, ASYNC, SECRET, CONFIG, INTEG — 5 tests each).
  Independent re-verification of all findings without trusting prior phase labels.

### mypy output
```
Success: no issues found in 125 source files
```

125 source files checked (unchanged from Phase 10 — no new production modules added
in Phase 11; new code is `tests/test_final_verification.py` only).

### ruff output
```
Found 130 errors.
[*] 108 fixable with the `--fix` option (17 hidden fixes can be enabled with the --unsafe-fixes option)
```

130 errors — at the Phase 10 ceiling (maintained). Phase 11 introduced zero net
new ruff violations: 4 initial violations in `test_final_verification.py` were
fixed (2 unused imports `Episode`, `Outcome`; 1 unused import `OrchestrationDeps`;
1 f-string without placeholders) before recording this baseline.

---

*This document is append-only.  Add new sections when new baselines are
established.  Never overwrite or delete existing baseline entries.*
