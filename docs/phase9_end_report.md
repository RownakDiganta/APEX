# Phase 9 End Report — Shared-State Boundaries, Canonical Configuration, and Safe Default Consistency

**Completion date:** 2026-07-14  
**Tests added (Phase 9):** 80 (`tests/apex_host/test_phase9_config.py`)  
**Total tests after Phase 9:** 2378 passed  
**mypy:** Success — 112 source files, no issues  
**Ruff:** 130 errors (at Phase 8 ceiling, exit code 1 — pre-existing; no new violations)

---

## Summary

Phase 9 establishes four system-wide invariants for configuration consistency and
shared-state boundaries:

| ID | Invariant | Enforced by |
|---|---|---|
| P9-I01 | `ApexConfig.from_cli_args()` is the sole CLI→config construction path | `config.py`; ARCH tests 10 |
| P9-I02 | `llm_provider` defaults to `"fake"` in both ApexConfig and CLI | `config.py:68`; CLI tests 01–02, 14–15 |
| P9-I03 | `to_safe_dict()` is the only way to serialize config; redacts passwords via REDACTED_PLACEHOLDER | `config.py`; CFG tests 10–15, SERIAL tests 01–10 |
| P9-I04 | `run_synthetic_machine.py` uses only canonical graph_ids builders — no inline ID f-strings | ARCH tests 01–03; E2E tests 03–04 |

---

## Defects Fixed

| # | Description | File(s) |
|---|---|---|
| D1 | `--llm-provider` CLI default was `"openai"` — overrode ApexConfig's safe `"fake"` default even when user did not pass the flag | `apex_host/main.py`, `apex_host/eval/run_htb_local.py` |
| D2 | Both `main.py` and `run_htb_local.py` each had their own 20-line `config_kwargs` construction block, making divergence between them undetectable | both entry points |
| D3 | `run_synthetic_machine.py` built EKG IDs with inline f-strings (`f"host:{target}"`, `f"service:{target}:80/tcp"`, `f"edge:{host_id}:{to_id}"`) — P8-I04 violation | `apex_host/eval/run_synthetic_machine.py` |
| D4 | No `config_schema_version` field — consumers could not detect incompatible config format changes | `apex_host/config.py` |
| D5 | No `to_safe_dict()` method — no safe serialisation path that redacts credentials | `apex_host/config.py` |
| D6 | No `from_cli_args()` factory — duplicated mapping logic in two separate entry points | `apex_host/config.py` |

---

## Deliverables

### New files

| File | Purpose |
|---|---|
| `tests/apex_host/test_phase9_config.py` | 80 acceptance tests across 7 groups |

### Modified files

| File | Change |
|---|---|
| `apex_host/config.py` | Added `config_schema_version: str = "1"` field; `to_safe_dict()` method (uses `REDACTED_PLACEHOLDER`); `from_cli_args()` classmethod; added `fields as _dc_fields` and `REDACTED_PLACEHOLDER as _REDACTED` imports |
| `apex_host/main.py` | Changed `--llm-provider default="openai"` → `default=None`; replaced 20-line `config_kwargs` block with `config = ApexConfig.from_cli_args(args)` |
| `apex_host/eval/run_htb_local.py` | Same changes as `main.py` |
| `apex_host/eval/run_synthetic_machine.py` | Replaced inline EKG ID f-strings with canonical `graph_ids` builders (`_host_id`, `_service_id`, `_endpoint_id`, `_auth_flow_id`, `_exposes_edge_id`) |

---

## Test Groups

| Group | Tests | Coverage |
|---|---|---|
| CFG (15) | `test_cfg_01` – `test_cfg_15` | ApexConfig field defaults; `to_safe_dict`; schema version; mutation isolation |
| CLI (15) | `test_cli_01` – `test_cli_15` | `parse_args` defaults; `from_cli_args` round-trip; both entry points; llm_provider fix |
| ENV (10) | `test_env_01` – `test_env_10` | No env vars required; no API key fields; config.py OS isolation |
| STATE (15) | `test_state_01` – `test_state_15` | ApexGraphState/TurnState field names; operator.add semantics; serialisability; no infra objects |
| SERIAL (10) | `test_serial_01` – `test_serial_10` | JSON serializability; password redaction; field count alignment; node/episode data |
| ARCH (10) | `test_arch_01` – `test_arch_10` | No inline ID f-strings; no api._ access; no in-place state mutations; source-level defaults |
| E2E (5) | `test_e2e_01` – `test_e2e_05` | dry_run preserved through CLI; canonical IDs in seeded EKG; to_safe_dict on real config |

---

## Binding Invariants Added (P9 series)

**P9-I01 — `ApexConfig.from_cli_args()` is the canonical CLI→config factory.**  
Both `main.py` and `eval/run_htb_local.py` call `ApexConfig.from_cli_args(args)` to
construct `ApexConfig`.  No other production file (except `config.py` itself and
`eval/run_synthetic_machine.py`) may call `ApexConfig(...)` directly.  Adding a new
CLI flag means adding its mapping in `from_cli_args()` only — not in two separate files.

**P9-I02 — `llm_provider` defaults to `"fake"` end-to-end.**  
`ApexConfig.llm_provider = "fake"` is the field default.  Both CLI entry points register
`--llm-provider` with `default=None` so that when the flag is absent, `from_cli_args()`
propagates `None` → field default `"fake"`.  Setting `"openai"` requires an explicit
`--llm-provider openai` flag on every invocation.

**P9-I03 — `to_safe_dict()` is the approved serialisation path.**  
`to_safe_dict()` returns all `ApexConfig` fields as a JSON-serialisable dict with
`password_candidates` replaced by `[REDACTED_PLACEHOLDER]` entries.  It uses
`REDACTED_PLACEHOLDER` (imported from `apex_host.security.redaction`) — never a
hardcoded `"[redacted]"` string literal (which would violate P8-I01).

**P9-I04 — `run_synthetic_machine.py` uses only canonical graph_ids builders.**  
The five inline EKG ID f-strings have been replaced with calls to `_host_id`,
`_service_id`, `_endpoint_id`, `_auth_flow_id`, and `_exposes_edge_id` from
`apex_host.graph_ids`.  ARCH tests 01–03 verify no f-strings remain.

---

## Acceptance Criteria

All acceptance criteria were verified against the real codebase:

- [x] `ApexConfig.config_schema_version == "1"` on every default instance
- [x] `ApexConfig.to_safe_dict()` returns JSON-serialisable dict; passwords → `REDACTED_PLACEHOLDER`; no mutation of original
- [x] `ApexConfig.from_cli_args()` is the single CLI→config path used by `main.py` and `run_htb_local.py`
- [x] `--llm-provider` without explicit value → `config.llm_provider == "fake"` (not `"openai"`)
- [x] `run_synthetic_machine.py` contains no `f"host:`, `f"service:`, or `f"edge:` literals
- [x] No production `apex_host` file accesses `api._*` private attributes
- [x] No in-place `state[x].append(...)` calls in `apex_host/graph.py`
- [x] `config.py` contains no `os.getenv` or `os.environ` calls
- [x] 80 Phase 9 tests pass; 0 regressions in the 2298 prior tests
- [x] `mypy --strict` passes with 112 source files
- [x] ruff error count remains at 130 (at Phase 8 ceiling)

---

## Phase 10 — Next Steps

Phase 10 covers Orchestration Refactor (documentation accuracy and enforcement tooling):

- Update `README.md` test count to match `pytest --collect-only -q` output
- Add `tests/test_file_headers.py` — scan all `.py` files for two-line file-header convention (finding F18)

Prior tests (2378) must all still pass after Phase 10 changes.
