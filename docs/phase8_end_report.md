# Phase 8 End Report — Secret Redaction and Graph Representation

**Completion date:** 2026-07-14  
**Tests added (Phase 8):** 80 (`tests/apex_host/test_phase8_redaction.py`)  
**Total tests after Phase 8:** 2298 passed  
**mypy:** Success — 112 source files, no issues  
**Ruff:** 130 errors (at Phase 7 ceiling, exit code 1 — pre-existing)

---

## Summary

Phase 8 establishes five system-wide invariants for secret handling and graph
identity:

| ID | Invariant | Enforced by |
|---|---|---|
| P8-S01 | Central redaction module is the sole source of redaction logic | `apex_host/security/redaction.py`; ARCH tests 01–07 scan for violations |
| P8-S02 | `secret_hint` is always `REDACTED_PLACEHOLDER` ("[redacted]") | `access_parser.py`; BOUND tests 01, 08 |
| P8-S03 | Live telnet session stdout is NEVER stored; only `SESSION_REDACTED_PLACEHOLDER` | `telnet_executor.py`; BOUND tests 03–04; CANARY tests 03–04 |
| P8-S04 | `access_state.evidence` runs through `redact_session_text()` before storage | `access_parser.py`; BOUND test 08 |
| P8-PAR | `get_edges_for_node` reads from `_edges` dict, not NetworkX iterators | `graph_networkx.py`; PAR tests 01–05 |
| P8-DANGLE | `put_edge` validates both endpoint nodes exist; raises `ValueError` if either missing | `graph_networkx.py`; DANGLE tests 01–04 |
| P8-ID | All parser ID construction goes through `apex_host.graph_ids` canonical builders | `graph_ids.py`; ARCH tests 02–05; all parsers |
| P8-URL | URL normalization: lowercase scheme+host, strip default ports, collapse `//`, strip trailing `/` except root | `graph_ids.normalize_url()`; URL tests 01–12 |
| P8-SCHEMA | `EKG_SCHEMA_VERSION = "1"` embedded in every `export_ekg()` output | `export_graph.py`; SCHEMA tests 01–04 |

---

## Deliverables

### New files

| File | Purpose |
|---|---|
| `apex_host/security/__init__.py` | Package init; re-exports `redact_dict`, `redact_session_text`, `redact_value` |
| `apex_host/security/redaction.py` | Central recursive redaction module; `REDACTED_PLACEHOLDER`, `SESSION_REDACTED_PLACEHOLDER` |
| `apex_host/graph_ids.py` | Canonical EKG ID builders + `normalize_url()` + `EKG_SCHEMA_VERSION` |
| `tests/apex_host/test_phase8_redaction.py` | 80 acceptance tests across 10 groups |

### Modified files

| File | Change |
|---|---|
| `apex_host/agents/telnet_executor.py` | P8-S03: live session stdout → `SESSION_REDACTED_PLACEHOLDER`; adds `stdout_length`, `shell_found` fields |
| `apex_host/parsers/access_parser.py` | P8-S02: `secret_hint = REDACTED_PLACEHOLDER`; P8-S04: `evidence` through `redact_session_text()`; canonical IDs |
| `apex_host/parsers/nmap_parser.py` | Canonical IDs via `graph_ids` |
| `apex_host/parsers/banner_parser.py` | Canonical IDs via `graph_ids` |
| `apex_host/parsers/browser_parser.py` | Canonical IDs via `graph_ids` |
| `apex_host/parsers/command_parser.py` | Canonical IDs via `graph_ids` |
| `apex_host/parsers/ffuf_parser.py` | Canonical IDs via `graph_ids` |
| `apex_host/parsers/gobuster_parser.py` | Canonical IDs via `graph_ids` |
| `memfabric/stores/graph_networkx.py` | P8-PAR: `get_edges_for_node` reads `_edges` dict; P8-DANGLE: `put_edge` validates endpoints; parallel-edge-safe `delete_edge` |
| `apex_host/graph.py` | Anchor node uses `_build_host_id(config.target)` from `graph_ids` |
| `apex_host/eval/export_graph.py` | Adds `schema_version: EKG_SCHEMA_VERSION` key to every export |

---

## Test Groups

| Group | Tests | Coverage |
|---|---|---|
| REDACT (10) | `test_redact_01` – `test_redact_10` | `redaction.py` — constants, `redact_session_text`, `redact_value`, `redact_dict`, edge cases |
| CANARY (5) | `test_canary_01` – `test_canary_05` | Password never reaches EKG node props, episodic log, or any data field |
| BOUND (8) | `test_bound_01` – `test_bound_08` | `secret_hint`, dry-run flag, live SESSION_REDACTED, `stdout_length`, empty/failure/success parse |
| GRAPH_ID (10) | `test_graph_id_01` – `test_graph_id_10` | Every canonical builder function; format and uniqueness |
| URL (12) | `test_url_01` – `test_url_12` | Port stripping, scheme/host lowercase, trailing slash, collision dedup |
| PAR (5) | `test_par_01` – `test_par_05` | Parallel edges visible; delete one keeps other; in-edges returned |
| DANGLE (5) | `test_dangle_01` – `test_dangle_05` | Missing-from/to rejection; both-present success; API-level guard |
| SCHEMA (4) | `test_schema_01` – `test_schema_04` | Version constant type; value is "1"; present in `export_ekg` output |
| ARCH (10) | `test_arch_01` – `test_arch_10` | AST scan for hard-coded "[redacted]" strings; no inline ID f-strings in parsers; graph_ids exports; security package exports; telnet/access/export import checks |
| INT (11) | `test_int_01` – `test_int_11` | Full nmap→EKG pipeline; access parse; canonical edge IDs; no dangling edges; schema in export; URL dedup across parsers |

---

## Acceptance Criteria

All acceptance criteria were verified against the real codebase:

- [x] `REDACTED_PLACEHOLDER = "[redacted]"` is defined in and imported only from `apex_host.security.redaction`
- [x] `SESSION_REDACTED_PLACEHOLDER = "[session_redacted]"` is defined in and imported only from `apex_host.security.redaction`
- [x] No live telnet session text survives into `episode.data` — only `SESSION_REDACTED_PLACEHOLDER`
- [x] `secret_hint` on every `credential` node is exactly `REDACTED_PLACEHOLDER`
- [x] `access_state.evidence` field is passed through `redact_session_text()` with the supplied passwords
- [x] `NetworkXGraphStore.get_edges_for_node()` returns ALL edges (both directions, all types) between any pair of nodes — no DiGraph iterator limitation
- [x] `NetworkXGraphStore.put_edge()` raises `ValueError` when `from_id` or `to_id` is not a known node
- [x] All parsers use `apex_host.graph_ids` canonical builders — zero inline `f"host:"`, `f"credential:"`, `f"access_state:"`, `f"tech:"` strings
- [x] `normalize_url()` produces lowercase scheme+host, strips port 80 from http:// and 443 from https://, collapses double slashes in path, strips trailing slash from non-root paths
- [x] `export_ekg()` always includes `"schema_version": "1"` in the returned dict
- [x] 80 Phase 8 tests pass; 0 regressions in the 2218 prior tests
- [x] `mypy --strict` passes with 112 source files
- [x] ruff error count remains at 130 (at Phase 7 ceiling)

---

## Binding Invariants Added (P8 series)

The following invariants are now codified in CLAUDE.md §22:

**P8-I01 — `apex_host.security.redaction` is the sole source of redaction logic.**
No `apex_host` source file (other than `redaction.py` itself) may contain the
string literals `"[redacted]"` or `"[session_redacted]"` as code constants.
Reference them by importing `REDACTED_PLACEHOLDER` / `SESSION_REDACTED_PLACEHOLDER`.

**P8-I02 — Live session transcripts are never stored.**
`TelnetExecutor` (and any future network session executor) must write
`SESSION_REDACTED_PLACEHOLDER` to `episode.data["stdout"]` — never the raw
session bytes. Metadata fields (`stdout_length`, `shell_found`) may be stored
alongside for debugging without leaking credential material.

**P8-I03 — `secret_hint` is always `REDACTED_PLACEHOLDER`.**
Every `credential` node written to the EKG must have
`props["secret_hint"] = REDACTED_PLACEHOLDER`. The plaintext credential must
never appear in graph state, episodic log, or any proposal.

**P8-I04 — `apex_host.graph_ids` is the sole source of EKG ID construction.**
All parsers and graph-writing components must call the builder functions in
`graph_ids.py`. Inline f-strings like `f"host:{ip}"` in parsers are a violation
and are caught by the ARCH test suite.

**P8-I05 — `put_edge` must validate both endpoint nodes exist.**
`NetworkXGraphStore.put_edge()` raises `ValueError` with a message containing
`"from_id"` or `"to_id"` when the referenced node does not exist. This prevents
dangling edges from entering the graph. `MemoryAPI.upsert_edge()` propagates
this exception.

**P8-I06 — `export_ekg` always includes schema_version.**
Every call to `export_ekg()` must include `"schema_version": EKG_SCHEMA_VERSION`
as the first key in the returned dict so consumers can detect incompatible
schema changes.

---

## Phase 9 — Next Steps

Phase 9 covers State Boundaries and Configuration Consistency:
- Verify `ApexGraphState` never holds non-serializable types across the
  full engagement lifecycle
- Verify `ApexConfig` field defaults are consistent (especially that
  `dry_run=True` is never mutated by runtime auto-detection)
- Audit `TurnState` to confirm no `MemoryAPI`, `Scheduler`, `Executor`,
  `Planner`, or `Config` objects are ever stored in state

Prior tests (2298) must all still pass after Phase 9 changes.
