# RunReport Schema (Phase 3)

This document is the full design record for Phase 3 of the post-live-test
debugging track ("Phase 3 of exactly four debugging phases"). Phases 1 and
2 fixed LLM readiness/container-compatible Nmap execution and duplicate-
action suppression/phase-transition evidence gating, respectively. This
phase fixes six report-quality defects the second authorized HTB live
test's report surfaced, none of which were engine-behavior bugs — the
engagement itself ran correctly; the REPORT built from it was misleading
or missing diagnostic information.

## 1. Live-test evidence and root causes

1. **"Six script errors occurred, but `error_samples` was empty."** An
   ordinary nonzero-exit tool failure (no transport-level exception, e.g.
   nmap's raw-socket permission error) always has `error_episodes[i]["error"]
   == None` — `TaskDispatcher` only sets that field for a genuine transport
   exception, never for "the tool ran and exited nonzero". The old
   `error_samples = [str(e["error"]) for e in error_episodes if
   e.get("error")]` therefore silently dropped every such entry.
   **Fix:** `apex_host.orchestration.memory_node` now attaches
   `returncode`/`stderr_sample`/`diagnostic_category` to every
   `error_episodes` entry; `build_report()`'s `error_samples` construction
   falls back to those fields whenever `error` itself is empty.
2. **"The findings list contained the same host finding six times."**
   `state["findings"]` is an append-only OBSERVATION log — one entry per
   turn's parsed node delta, regardless of whether that node already
   existed. `NmapParser.parse_text()` always re-emits the host node from
   the target, even on a failed scan, so six failed Nmap turns produced
   six finding entries with the identical `id`. **Fix:**
   `apex_host.eval.findings.deduplicate_findings()` collapses the raw
   observation list to one entry per unique `id` before it becomes
   `RunReport.findings`.
3. **"The exported graph correctly contained one host node, but the
   report represented six findings."** A direct consequence of #2 — the
   EKG (`export_ekg`) was always correct (memfabric upserts by node ID);
   only the report's un-deduplicated finding list disagreed with it.
4. **"`phases_reached` showed only recon, while planner decisions
   included credential; termination phase was credential; final phase
   was done."** `phases_reached` was derived from `state["findings"]`'s
   own `"phase"` field — a phase the planner entered but which produced
   no parseable node delta (e.g. `CredentialPlanner` returning an
   `AbandonSignal` on a host-only graph) was silently absent, even though
   `planner_decisions` and `termination_phase` both showed it was
   entered. **Fix:** `phases_reached` (and the new `phases_attempted`/
   `phases_entered`) are now derived from `planner_decisions`' own
   `"phase"` field, union `termination_phase`.
5. **"`completed: true`, `status: abandoned`, `completed_successfully:
   false` — individually defensible, semantics need to be unambiguous."**
   These three fields (plus `outcome`) were already each independently
   correct and independently documented, but nothing tied them together
   for a reader. **Fix:** `RunReport.completion_summary` — one generated
   sentence disambiguating all four.
6. **"Planner decisions showed `selected_task_count: 0`, while benchmark
   totals said six tasks were selected and executed."**
   `PlanningEngine._record_fallback()` always hardcoded
   `selected_task_count=0` for a fallback decision (correct in isolation:
   "the LLM selected zero tasks"), while `apex_host.eval.benchmark`
   deliberately never sums that field for exactly this reason (documented
   there since Phase 17) — but nothing on `PlanDecision` itself captured
   what the fallback planner actually did. **Fix:** `PlanDecision` gained
   `fallback_task_count`, populated by calling the fallback planner
   *first* and recording its real result — see §5.

## 2. New/changed modules

| Module | Purpose |
|---|---|
| `apex_host/execution/error_classifier.py` | Fine-grained, apex_host-level diagnostic classification (9-category vocabulary) — layered on top of, never replacing, `memfabric.types.Outcome` |
| `apex_host/execution/diagnostics.py` | Builds one bounded, redacted execution-diagnostic record per actual tool execution |
| `apex_host/eval/findings.py` | Deduplicates the raw finding-observation log into a unique-entity view |
| `apex_host/eval/report_invariants.py` | Internal-consistency checks for a built `RunReport`; production-safe (never raises) + a test-only strict `assert_report_invariants()` |

## 3. Execution diagnostics

`apex_host.execution.diagnostics.build_execution_diagnostic(tr, *, phase,
passwords=None)` turns an existing dispatcher `tool_result` dict (the
ubiquitous `tr` shape already used throughout `apex_host` — no new,
competing execution-result model was introduced) into one bounded,
redacted record:

| Field | Source |
|---|---|
| `execution_id` | `f"{task_id}:{retry_index}"` — a stable, deterministic composite; distinguishes repeated attempts of the same task |
| `task_id` | `tr["task_id"]` |
| `fingerprint` | `tr["fingerprint"]` — the canonical action fingerprint (Phase 2), now threaded into every `tool_result` by `TaskDispatcher.dispatch()`'s step 6 |
| `phase`, `agent`, `tool`, `target`, `backend` | Threaded through from `tr` / `TaskDispatcher` |
| `args` | Redacted, per-token bounded to 200 chars |
| `start_timestamp`, `end_timestamp`, `duration_seconds` | Captured once per dispatch call, threaded through |
| `returncode`, `timed_out` | `tr["returncode"]` / `tr["timed_out"]` |
| `stdout_sample`, `stderr_sample`, `stdout_truncated`, `stderr_truncated` | Redacted then bounded to 500 chars each, with a deterministic truncation flag |
| `diagnostic_category` | `apex_host.execution.error_classifier.classify_execution_diagnostic(tr)` — the unified 9-category classification |
| `tool_error_category` | A tool-specific classifier's own label when present (e.g. nmap's `raw_socket_permission_denied` — Phase 1), kept alongside, never overwritten by, `diagnostic_category` |
| `classifier_reason` | `apex_host.execution.dispositions.classify_retry()`'s own reason string |
| `policy_decision_ref` | The policy rule name that approved this task, when set |
| `retry_index` | 0-based; how many times this fingerprint had already been attempted |
| `final_disposition` | The `ExecutionDisposition` value |

**Where it's built:** `apex_host.orchestration.memory_node.make_memory_node`'s
`write_memory` node — the SAME loop that already creates one `Episode` per
actual execution (never for a `skipped_duplicate` — already `continue`d —
or a `repair_no_change` non-execution, which never reaches `write_memory`
as a `tool_result` at all). One `execution_diagnostics` entry is built per
episode written, using `episode_data` (already safely redacted for
`user_flag_verify`'s own candidate-output case) rather than the raw `tr`
when they differ.

**Never included:** an API key, bearer token, password, cookie, or raw
payload body beyond the bounded/redacted samples above. Every
stdout/stderr sample and every argument token passes through
`apex_host.security.redaction.redact_secret_patterns` (pattern-based —
catches an API-key/AWS-key/bearer-token/private-key SHAPE even when the
specific value is not known in advance); when the caller supplies
configured credential values (`ApexConfig.password_candidates`), they
also pass through `redact_session_text` (substring-based — catches the
EXACT configured value verbatim).

## 4. Error classification boundaries

`apex_host.execution.error_classifier.DIAGNOSTIC_CATEGORIES`:
`success`, `script_error`, `fixable`, `fundamental`, `provider_error`,
`policy_block`, `backend_error`, `timeout`, `capability_missing`.

This is **layered on top of**, and never replaces,
`memfabric.types.Outcome` (the deliberately small, domain-agnostic
4-value enum — `success`/`script_error`/`fixable`/`fundamental` — that
drives skill-lifecycle and repair-eligibility decisions inside the
generic substrate). Extending `Outcome` itself would violate memfabric's
domain-agnostic invariant; this module answers a narrower, report-facing
question instead: "for a human operator, which of a small, fixed set of
categories best explains why this execution did not succeed?" It is never
consumed by memfabric and never drives a retry/repair control-flow
decision (`classify_retry`/`outcome_for` remain exclusively responsible
for that, unchanged).

**Was the original Nmap raw-socket failure correctly classified as
`script_error`?** At the `Outcome`/repair-eligibility level — **yes**: a
corrected command (Phase 1's `-sT` fix) genuinely resolves it, exactly
matching `Outcome.script_error`'s "repair eligible" intent. At the
REPORT level — before this phase, `"script_error"` was the only label
available and generic enough to also mean a syntax typo or wrong flag
value. `classify_execution_diagnostic()` now yields the more specific
`fundamental` for the exact raw-socket marker (an environment/privilege
constraint, not a simple arg fix) while leaving the underlying `Outcome`/
repair-eligibility path completely untouched.

**Boundary summary** (first match wins — see the module docstring for
the full definition of each):

1. `policy_block` — `PolicyAdvisor` denied the task before any I/O.
2. `provider_error` — an LLM/provider-layer failure (`llm_error_category` set).
3. `capability_missing` — a structured capability/adapter never connected.
4. `timeout` — the executor's own timeout fired, or the error text says so.
5. `success` — no error, returncode 0 (or absent).
6. `backend_error` — a transport/environment failure below the tool's own
   application logic (DNS/connection failure, binary not found in PATH,
   or any other raised transport exception).
7. `fundamental` — a known environment/privilege constraint (currently:
   nmap's raw-socket permission marker).
8. `script_error` — the residual bucket: a nonzero return code matching
   none of the above.
9. `fixable` — reserved for a future finer-grained "known, mechanically
   correctable" bucket; not currently produced.

## 5. Planner/benchmark reconciliation

`PlanDecision` gained `fallback_task_count: int = 0`.
`PlanningEngine._record_fallback()` is now `async` and itself calls the
fallback planner, so it can record the REAL resulting task count:

```python
async def _record_fallback(self, phase, goal, subgraph, evidence, **kwargs):
    fallback_result = await self._fallback.plan(goal, subgraph, evidence)
    fallback_task_count = 0 if isinstance(fallback_result, AbandonSignal) else len(fallback_result)
    self._last_decision = PlanDecision(..., selected_task_count=0, fallback_task_count=fallback_task_count)
    return fallback_result
```

`selected_task_count` stays `0` for every fallback decision, unchanged —
that field's own meaning ("what the LLM selected") is still correctly
zero. `fallback_task_count` is the new, separate signal. Every one of the
~14 call sites in `apex_host/planning/engine.py` that previously called
`self._record_fallback(...)` followed by `return await
self._fallback.plan(...)` now calls `return await
self._record_fallback(...)` directly — mechanical, behavior-preserving
(verified against the full existing `test_llm_phase5.py`/
`test_planners_with_engine.py`/`test_repair_engine.py` suites, all
passing unchanged).

`apex_host.eval.benchmark.compute_benchmark()`'s own `tasks_executed`
computation is **unchanged** — it already deliberately avoided summing
`selected_task_count` (documented there since Phase 17), instead counting
real execution evidence directly (`task_latency_log` + telnet attempts).
This phase does not change that derivation; it makes the OTHER, per-decision
signal (`fallback_task_count`) tell the truth too, so the two numbers no
longer visibly contradict each other in a report.

## 6. Report invariants

`apex_host.eval.report_invariants.check_report_invariants(report)` is a
pure function run automatically, once, inside `build_report()`. It never
raises — a non-empty `RunReport.invariant_violations` list IS the safe
diagnostic signal ("prefer a safe diagnostic status rather than crashing
after an engagement, while recording invariant violations"). Checks:

- `finding_count == len(findings)` (structural self-consistency).
- `completed_successfully` implies `completed`.
- `objective_verified` implies `success` ("objective verified implies
  successful engagement").
- `success` implies `objective_verified` ("benchmark success implies
  objective verified").
- `access_summary.validated` implies `access_summary.protocol` is set.
- If any failed turns were recorded (`script_error_count +
  fixable_count + fundamental_count > 0`), `execution_diagnostics` must
  be non-empty AND at least one entry must reflect a non-success
  `diagnostic_category` — the exact class of defect evidence #1 exposed.
- If `execution_diagnostics` is non-empty (real executions occurred) and
  `planner_decisions` is non-empty, at least one decision must show a
  nonzero `selected_task_count` OR `fallback_task_count` — the exact
  class of defect evidence #6 exposed.

`apex_host.eval.report_invariants.assert_report_invariants(report)` is
the TEST-ONLY strict counterpart — raises `AssertionError` (listing every
violation) when the list is non-empty. Production code never calls it.

## 7. Phase semantics

| Field | Definition |
|---|---|
| `phases_attempted` | Every phase whose own agent node actually ran this engagement — derived from `planner_decisions`' `"phase"` field, union `termination_phase`. Regardless of whether that phase selected or executed any task. |
| `phases_entered` | Identical to `phases_attempted` in this architecture — a **documented, deliberate choice**: APEX's graph routes directly into each `GlobalPlanner`-selected phase's own agent node; there is no "planned but not entered" distinction to represent separately. Kept as its own field name for forward compatibility. |
| `phases_completed` | `phases_attempted` MINUS `termination_phase` — every attempted phase other than the one the engagement was still in when it stopped, matching this architecture's mostly-monotonic phase ladder (`GlobalPlanner` never regresses to an earlier phase). |
| `termination_phase` | Unchanged (Phase 12C) — the phase `GlobalPlanner` was IN when the decision to terminate was made. |
| `final_runtime_state` | New field, identical to `final_phase` (the raw terminal `ApexGraphState["phase"]` value — always `"done"` once `completed=True`) under an explicitly clearer name. `final_phase` is retained, unchanged, for backward compatibility; the two are guaranteed equal. |
| `phases_reached` | Retained (backward-compatible field NAME), now IDENTICAL to `phases_attempted` (a corrected semantic — see §1 item 4). |

**Why phase 3's fix is not a rename:** `phases_reached`'s underlying
meaning changed (this is exactly why `report_schema_version` was bumped —
see §9), but the field name itself is preserved so a consumer that only
reads `phases_reached` (not the newer, more explicitly-named fields)
keeps working without a code change — it simply now sees a MORE complete
(and correct) phase list than before.

## 8. Top-level field semantics

| Field | Meaning |
|---|---|
| `completed` | The runtime (LangGraph) reached a terminal state this run. |
| `completed_successfully` | The configured objective was verified (`EngagementOutcome.user_flag_verified` — the ONLY success outcome, per `apex_host.orchestration.outcome`'s "Success invariant", unchanged by this phase). |
| `status` | The legacy four-value string (`"success"`/`"stopped_max_turns"`/`"stopped_error"`/`"abandoned"`) — a projection of `outcome`, never computed independently. |
| `outcome` / `success` | The canonical `EngagementOutcome` model (Phase 12C) — the single source of truth every other completion field derives from. |
| `completion_summary` | **New.** One generated sentence disambiguating all four fields above for an operator who does not want to cross-reference them — e.g. *"runtime reached a terminal state (completed=True); the configured objective was NOT verified (completed_successfully=False); status='abandoned'; outcome='no_actionable_task'."* |

`completed=True`, `status='abandoned'`, `completed_successfully=False`
(the exact evidence-#5 combination) is a real, valid, common shape: the
engagement stopped cleanly (no crash) without achieving its objective.
`completion_summary` exists specifically so this reads unambiguously
without needing to already know the four fields' individual definitions.

## 9. Schema version 2 migration

`RunReport.report_schema_version` default bumped from `"1"` to `"2"`.

**Backward-incompatible changes** (the reason for the bump):
- `findings` is now the DEDUPLICATED, unique-entity view — one entry per
  unique finding `id`, never one entry per raw observation. A consumer
  that counted `len(findings)` expecting "one per parse event" will now
  see fewer entries for a target that was observed multiple times. The
  new `observation_count` field preserves the old raw count.
- `phases_reached`'s derivation changed (see §7) — a consumer will now
  see MORE phases for a report where a phase was entered but produced no
  finding (this is a correction, not a new omission).

**Purely additive changes** (safe for any v1 consumer — every new field
has a safe default, no v1 field was removed or renamed):
`execution_diagnostics`, `observation_count`, `phases_attempted`,
`phases_entered`, `phases_completed`, `final_runtime_state`,
`completion_summary`, `invariant_violations`, and `PlanDecision
.fallback_task_count` (inside each `planner_decisions` entry).

**Reading an old (v1) report:** `RunReport(report_schema_version="1",
...)` still constructs and serializes without error — every new field
defaults to an empty/zero value. A consumer that checks
`report_schema_version` before interpreting `findings`/`phases_reached`
can detect which semantic applies; a consumer that does not check it will
simply see the OLD, un-deduplicated `findings` list and the OLD,
finding-derived `phases_reached` for any report it never re-builds
through the new `build_report()` — this document is the compatibility
note such a consumer's maintainer needs.

## 10. Diagnosing a failed tool execution from a report

1. Check `RunReport.error_samples` (or the "Error Breakdown" text
   section) — now populated even when the underlying transport-level
   `error` field is `None`, using `returncode`/`diagnostic_category`/
   `stderr_sample`.
2. Check `RunReport.execution_diagnostics` (or the "Execution
   Diagnostics" text section, shown automatically when at least one
   non-success execution occurred) for the FULL bounded record: tool,
   target, backend, returncode, timed_out, `diagnostic_category`,
   `tool_error_category` (when a tool-specific classifier ran — e.g.
   nmap's), and a bounded/redacted `stderr_sample` with a `stderr_truncated`
   flag.
3. Cross-reference `classifier_reason` (from `classify_retry()`) to see
   whether the SAME action was eligible for a bounded retry/repair, and
   `retry_index`/`final_disposition` to see how many times it was
   actually attempted before being suppressed (Phase 2).
4. If `RunReport.invariant_violations` is non-empty, treat every other
   field on the report with proportionally more caution — it means the
   report itself detected an internal inconsistency (see §6) while being
   built.

## 11. Example failure report (abridged, synthetic)

Generated by `tests/apex_host/test_phase3_report_diagnostics.py
::TestSyntheticOriginalConditionsReport` — six identical failed Nmap
executions, one unique host, zero services, an LLM-unavailable signal,
and a credential phase that was considered (evaluated by `GlobalPlanner
._select_phase`) but never actually entered (today's Phase-2-fixed
engine terminates directly from `recon` once its budget is exhausted with
no service evidence — see `docs/action-fingerprint.md` §2.2 and §7):

```json
{
  "report_schema_version": "2",
  "target": "10.10.10.14",
  "completed": true,
  "status": "abandoned",
  "completed_successfully": false,
  "completion_summary": "runtime reached a terminal state (completed=True); the configured objective was NOT verified (completed_successfully=False); status='abandoned'; outcome='no_actionable_task'.",
  "final_phase": "done",
  "final_runtime_state": "done",
  "phases_reached": ["recon"],
  "phases_attempted": ["recon"],
  "phases_entered": ["recon"],
  "phases_completed": [],
  "finding_count": 1,
  "observation_count": 6,
  "findings": [
    {"id": "host:10.10.10.14", "observation_count": 6, "sources": ["nmap"], "confidence": 0.9}
  ],
  "error_counts": {"script_error": 6, "fixable": 0, "fundamental": 0},
  "error_samples": ["nmap: fundamental returncode=1 stderr=\"Couldn't open a raw socket...\""],
  "execution_diagnostics": [
    {
      "tool": "nmap", "target": "10.10.10.14", "backend": "remote",
      "returncode": 1, "timed_out": false,
      "diagnostic_category": "fundamental",
      "tool_error_category": "raw_socket_permission_denied",
      "stderr_sample": "Couldn't open a raw socket. Error: (1) Operation not permitted...",
      "stderr_truncated": false, "retry_index": 0,
      "final_disposition": "executed_failure"
    }
  ],
  "invariant_violations": []
}
```

`invariant_violations` is empty — this report, despite describing a
failed engagement, is internally consistent and fully diagnosable from
its own JSON export alone.
