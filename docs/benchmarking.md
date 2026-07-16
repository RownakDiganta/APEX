# Benchmarking, HTB Evaluation & Run Comparison (Phase 17)

**Status:** implemented. Makes APEX measurable, benchmarkable, diagnosable,
and reproducible for evaluation — without adding any new exploitation
capability, planner behavior change, or execution capability.

## 1. What this is — and is not

This phase adds **instrumentation and reporting**, not new engagement
behavior. Nothing here executes a command, drives a tool, uploads a
payload, generates a reverse shell, uses Metasploit, establishes
persistence, or captures a flag. `GlobalPlanner`, every domain planner, and
`TaskDispatcher` are byte-for-byte unchanged in their decision logic — this
phase only *measures and reports* what those components already do.

Three independent, composable pieces:

1. **Benchmark framework** (`apex_host/eval/benchmark.py`) — deterministic
   metrics computed from an already-built `RunReport`.
2. **HTB evaluation mode** (`apex_host/eval/evaluation.py`) — a structured
   record of one machine's engagement, comparable across machines, that
   never assumes the target was compromised.
3. **Run comparison** (`apex_host/eval/comparison.py`) — a deterministic
   diff between two engagement reports, either in the same process or
   loaded from two separately-exported JSON files.

## 2. Why timing is an external input

`RunReport` (and the `ApexGraphState` it is built from) carries no
wall-clock timestamps beyond `turns_used` — memfabric Invariant 5 ("context
is retrieved and scoped, never accumulated") means the state machine has no
notion of real elapsed time. Measuring "how long did this engagement take"
and "how long did building this report take" can only be done by the
caller wrapping the relevant calls in `time.monotonic()`.
`apex_host/eval/run_htb_local.py`'s `_async_main()` does exactly this:

```python
engagement_start = time.monotonic()
runtime, final_state, seed_results = await run_engagement(config)
total_runtime_seconds = time.monotonic() - engagement_start
...
report_start = time.monotonic()
_timing_report = build_report(..., total_runtime_seconds=total_runtime_seconds, ...)
format_text(_timing_report)
report_generation_seconds = time.monotonic() - report_start
report = build_report(..., report_generation_seconds=report_generation_seconds, ...)
```

`compute_benchmark()`/`build_report()` accept these as plain float
arguments defaulting to `0.0`, so any caller that never measures them
(existing tests, hand-built fixtures) is unaffected and simply sees
zero-valued, non-misleading benchmark fields — never a crash, never a
fabricated number.

## 3. The benchmark model

`apex_host/eval/benchmark.py` is pure — no I/O, no MemoryAPI calls, no
async — consistent with this codebase's "pure reasoning helper" convention
(mirrors `priv_esc_opportunities.py`/`web_opportunities.py`/
`workflow_orchestration.py`/`experience_replay.py`).

```python
@dataclass(slots=True)
class BenchmarkResult:
    target: str
    total_runtime_seconds: float
    planner_decision_count: int
    tasks_selected_total: int
    tasks_executed: int
    tasks_skipped: int
    duplicate_avoidance_count: int
    opportunities_discovered: int   # privilege + web opportunities combined
    browser_findings: int
    credential_attempts: int
    privilege_opportunities: int
    workflow_completion_percentage: float
    learning_replay_hits: int
    engagement_outcome: str
    metrics: BenchmarkMetrics

@dataclass(slots=True)
class BenchmarkMetrics:
    planner_efficiency: float
    workflow_completion_percentage: float
    duplicate_avoidance_percentage: float
    browser_coverage: float
    credential_success_rate: float
    privilege_opportunity_density: float
    replay_usefulness: float
    average_task_latency_seconds: float
    evidence_density: float
    graph_growth_rate: float
    report_generation_seconds: float
```

`compute_benchmark(report, *, total_runtime_seconds=0.0,
report_generation_seconds=0.0, task_latency_log=None)` is the single
function that computes every metric — `RunReport`/`format_text()`/
`to_json_dict()` never duplicate a formula; they call this function and
render its output.

### Exact metric formulas

Every ratio metric uses the same bounded-division helper,
`_ratio(numerator, denominator)`: returns `0.0` on a zero/negative
denominator, otherwise `numerator / denominator` clamped to `[0.0, 1.0]` —
never a division error, never a value outside `[0, 1]` for ratio metrics.

| Metric | Formula |
|---|---|
| `planner_efficiency` | `_ratio(tasks_executed, planner_decision_count)` |
| `workflow_completion_percentage` | Passthrough of `report.workflow_completion_percentage` (Phase 15) |
| `duplicate_avoidance_percentage` | `_ratio(duplicate_avoidance_count, tasks_selected_total) * 100` |
| `browser_coverage` | `_ratio(report.web_pages_visited, node_counts.get("endpoint", 0))` |
| `credential_success_rate` | `_ratio(credential_successes, credential_attempts)` |
| `privilege_opportunity_density` | `_ratio(report.privilege_opportunity_count, report.total_nodes)` |
| `replay_usefulness` | `_ratio(report.learning_replay_hits, report.learning_experience_count)` |
| `average_task_latency_seconds` | Mean of `task_latency_log[*].duration_seconds`, rounded to 6 places; `0.0` on an empty log |
| `evidence_density` | `_ratio(evidence_node_count, report.total_nodes)` — see §3.1 for which node types count as "evidence" |
| `graph_growth_rate` | `total_nodes / turns_used` (rounded to 4 places) if `turns_used > 0`, else `float(total_nodes)` |
| `report_generation_seconds` | Passthrough of the externally-measured value |

### 3.1 Evidence-bearing node types

`evidence_density`'s numerator counts nodes of these types only —
concrete, human-actionable observations, not structural/coordination
scaffolding (`host`, `workflow`, `workflow_step`, `session` are
deliberately excluded):

```
service, tech, endpoint, form, token, auth_flow,
credential, access_state,
priv_esc_opportunity, priv_esc_evidence, priv_esc_recommendation,
web_opportunity,
workflow_recommendation,
experience, experience_recommendation
```

## 4. Why `tasks_executed`/`planner_efficiency` avoid `planner_decisions`

Building this module surfaced a **pre-existing gap, not introduced or
fixed by this phase** (documented here, left for a future phase):
`PlanningEngine._record_fallback()` (`apex_host/planning/engine.py`)
unconditionally records `selected_task_count=0` for every
deterministic-fallback `PlanDecision`, at every one of its ~13 call sites —
because it is called *before* the wrapped deterministic planner's own
result is known. Since `ApexRuntime.run()` always constructs a real
(possibly `FakeModelRouter`) `ModelRouter` and always wires every planner
through `PlanningEngine`, this affects the deterministic-only default mode
too — the overwhelming majority of real usage per this project's own
README — not just LLM-backed runs. The pre-existing
`RunReport.no_action_count` field (Phase 12C) is built from the same
`selected_task_count` data and inherits the same gap.

Verified directly: running a real dry-run engagement against
`ApexRuntime.run()` and inspecting the exported `planner_decisions` showed
`selected_task_count: 0` on every entry, even for turns whose task was
genuinely dispatched and then duplicate-skipped on a later turn.

Rather than silently producing an always-zero `planner_efficiency`/
`duplicate_avoidance_percentage` for the common case, this module counts
real execution evidence directly instead:

```
tasks_executed = len(task_latency_log) + (telnet credential attempts)
tasks_selected_total = tasks_executed + tasks_skipped
tasks_skipped = report.duplicate_action_count   # accurate — real dispatcher-level data
```

`task_latency_log` (see §5) only ever contains genuinely-executed,
non-skipped tool_results, so it is a reliable executed-task count for
every executor except Telnet (which never records a `duration_seconds` —
Phase 12B's own "byte-for-byte unchanged" invariant) and Browser/
`priv_esc_analyze` (zero-I/O, no measurable duration — the same documented
exclusion already applied to `average_task_latency_seconds`). Telnet
attempts are added back in via `credential_validation_log` entries with
`protocol == "telnet"`; SSH/FTP attempts are NOT double-counted this way
since they already produce a `task_latency_log` entry (verified by
`TestDuplicateCalculations::test_ssh_attempts_not_double_counted`).

**This is a documented limitation, not a claim that it is fully fixed.**
Browser-visit and `priv_esc_analyze` tasks are undercounted by
`tasks_executed` for the same structural reason they are excluded from
latency averaging. See §9.

## 5. The task-latency log

`ApexGraphState["task_latency_log"]` (new field, `operator.add` reducer) is
populated by `apex_host/orchestration/memory_node.py::write_memory` — one
entry per non-skipped `tool_result` that carries a real, measured
`duration_seconds` value:

```python
duration = tr.get("duration_seconds")
if duration is not None:
    latency_entries.append({
        "tool": tr.get("tool", tr.get("kind", "unknown")),
        "phase": state["phase"],
        "duration_seconds": float(duration),
    })
```

`duration_seconds` is threaded into the relevant `tool_result` dicts by
`apex_host/execution/dispatcher.py` from data the executors already
compute: `ToolResult.duration_seconds` (generic subprocess/backend
commands), `SSHExecutor`/`FTPExecutor`'s `episode.data["duration_seconds"]`,
and `PrivEscEnumExecutor`'s own tracked duration. **TelnetExecutor**
(byte-for-byte unchanged since Phase 12B), **BrowserExecutor**, and
**PrivEscAnalysisExecutor** (zero-I/O) never set this key — they are
naturally excluded from every latency-derived metric rather than
contributing a fabricated zero. This is purely additive instrumentation:
no executor's behavior, return value, or decision logic changed — only a
pre-existing, already-computed timing value is now threaded through to a
new accumulator.

## 6. Reporting — Benchmark Summary and the four Metrics sections

`RunReport` gains five new raw fields (`task_latency_log`,
`benchmark_total_runtime_seconds`, `benchmark_report_generation_seconds`,
`evaluation_machine_name`, `evaluation_difficulty`) — deliberately NOT one
field per computed metric. Every computed metric is a pure function of
fields already on `RunReport` (see §3's formula table), so `format_text()`/
`to_json_dict()` call `compute_benchmark(report, ...)` on demand rather
than storing (and risking staleness in) a duplicate copy of each metric.

`format_text()` gains, shown only when `report.turns_used > 0` (an
unstarted or hand-built test fixture shows nothing here):

```
Benchmark Summary
  Total runtime        : 0.148s
  Planner decisions    : 4
  Tasks executed       : 1 (skipped: 3)
  Duplicate avoidance  : 3
  Opportunities found  : 0
  Browser findings     : 0
  Credential attempts  : 0
  Privilege opps       : 0
  Workflow completion  : 0.0%
  Learning replay hits : 0
  Engagement outcome   : duplicate_task_stall

Performance Metrics
  Average task latency : 0.0s
  Graph growth rate    : 0.75 nodes/turn
  Report generation    : 0.00015s

Planner Metrics
  Planner efficiency   : 0.25
  Duplicate avoidance %: 75.0%

Memory Metrics
  Evidence density     : 0.6667
  Privilege opp density: 0.0
  Browser coverage     : 0.0
  Credential success % : 0.0

Learning Metrics
  Workflow completion %: 0.0%
  Replay usefulness    : 0.0
```

`to_json_dict()` always includes a `"benchmark"` block (never absent —
zero-valued when unmeasured, never `null`), built from
`benchmark_to_json_dict(compute_benchmark(...))`.

## 7. HTB evaluation mode — never assumes compromise

`apex_host/eval/evaluation.py::HTBEvaluation` records what an engagement
**objectively observed and did** — never what it might have achieved.
`HTBEvaluation.success` is copied verbatim from `RunReport.success`, which
is itself `is_success_outcome(EngagementOutcome(...))` — the exact same
canonical, single-source-of-truth success definition every other part of
this codebase uses (Phase 12C): exactly one thing means success, a
validated `access_state` node in the EKG. An engagement that discovered ten
services, five web findings, and three privilege-escalation opportunities
but never validated a credential is recorded exactly as `success=False` —
verified directly by
`TestHTBEvaluation::test_success_mirrors_report_success_exactly`.

`machine_name`/`difficulty` are the **only** genuinely new fields —
operator-supplied via `--htb-machine-name`/`--htb-difficulty`, never
inferred from the target IP or any EKG content (CLAUDE.md §13.8/§13.9 — no
machine-specific behavior anywhere in this codebase, and this module is no
exception). Every other `HTBEvaluation` field is derived from fields
already on `RunReport`:

| Field | Derivation |
|---|---|
| `services_discovered` | `report.node_counts.get("service", 0)` |
| `credentials_validated` | `report.node_counts.get("access_state", 0)` — one node per genuinely validated protocol/username pair (Phase 12B), never a guess or attempt count |
| `web_findings` | `report.web_opportunity_count` |
| `privilege_opportunities` | `report.privilege_opportunity_count` |
| `final_outcome` | `report.outcome` |
| `success` | `report.success` |

```
Evaluation Summary
  Machine              : TestBox (Easy)
  Target               : 127.0.0.1
  Services discovered  : 0
  Credentials validated: 0
  Web findings         : 0
  Privilege opps       : 0
  Turns used           : 4
  Final outcome        : duplicate_task_stall
  Success              : No
```

`format_text()`/`to_json_dict()` show/include the Evaluation Summary
section/block only when `report.evaluation_machine_name` is non-empty —
`to_json_dict()`'s `"evaluation"` key is explicitly `None` otherwise
(distinct from `"benchmark"`, which is always present — see §6).

## 8. Run comparison

`apex_host/eval/comparison.py::compare_reports(a, b)` computes a
deterministic diff between a baseline (`a`) and a candidate (`b`) — never a
heuristic or fuzzy similarity score. Every field is either an exact
set-difference (findings, matched by stable EKG node `id`) or a plain
numeric/dict delta (`b - a`).

### Two supported input shapes, normalised to one flat comparison-input dict

1. **In-process** — `comparison_input_from_report(report)` on a
   `RunReport` object built in the same process.
2. **Cross-process** — `comparison_input_from_json_export(data)` on a
   plain dict loaded from a JSON file previously written by
   `write_report_json()` (the realistic "compare this run against last
   week's run" workflow — two separate process invocations, e.g. via
   `--compare-with PATH`).

Both extractors read exactly the same set of fields — verified directly by
`TestComparisonJsonExportAndCrossProcess::test_json_export_extractor_matches_in_process_extractor`,
which asserts they produce byte-identical output for the same underlying
report. `compare_reports()` itself never has to know which shape it
received.

```
Comparison Summary
  Baseline (a)         : 10.10.10.5
  Candidate (b)        : 10.10.10.6
  New findings         : 2
  Missing findings     : 0
  Planner differences  : {'decision_count_delta': 1, ...}
  Workflow differences : {'workflow_count_delta': 0, ...}
  Timing differences   : {'turns_used_delta': 2, 'total_nodes_delta': 5, ...}
  Opportunity diffs    : {'privilege_opportunity_count_delta': 1, 'privilege_category_deltas': {'sudo': 1}, ...}
  Learning differences : {'experience_count_delta': 0, ...}
```

### CLI wiring

`apex_host.eval.run_htb_local`'s `--compare-with PATH` loads a
previously-exported `--export-json` file, compares it against the current
run (as the candidate), prints the Comparison Summary, and — with
`--export-comparison PATH` — writes the comparison as JSON. A comparison
failure (e.g. a malformed or missing file) is logged as a warning and never
fails the engagement itself — comparison is advisory, exactly like every
other Phase 13-17 recommendation surface in this codebase.

## 9. Current limitations

- **`tasks_executed` undercounts Browser-visit and `priv_esc_analyze`
  tasks.** Both have zero measurable duration (no I/O / a single page
  fetch with no tracked timing) and therefore never contribute a
  `task_latency_log` entry — the same documented exclusion already applied
  to `average_task_latency_seconds`. `planner_efficiency` and
  `duplicate_avoidance_percentage` inherit this undercount for phases
  dominated by those two task types (primarily the `web` phase's browser
  sub-agent).
- **`PlanningEngine._record_fallback()`'s always-zero `selected_task_count`
  for deterministic-fallback decisions is a pre-existing gap, not fixed by
  this phase.** It was investigated and worked around (§4) rather than
  patched, to avoid a wide-blast-radius change to a heavily-tested, core
  scheduling component outside this phase's own scope (benchmarking
  instrumentation, not planning-engine internals). The pre-existing
  `RunReport.no_action_count` field still inherits this gap unchanged.
- **`graph_growth_rate` is a single-run average (`total_nodes / turns_used`),
  not a real per-turn growth curve.** No historical, per-turn node-count
  snapshot is stored anywhere in `ApexGraphState` to compute a true growth
  rate over time; this is the closest deterministic single-number
  approximation available from data the engagement already produces.
- **`total_runtime_seconds`/`report_generation_seconds` require the caller
  to measure them.** A caller that never wraps `run_engagement()`/
  `build_report()` in `time.monotonic()` (e.g. most existing test
  fixtures) simply sees `0.0` — never a crash, never a fabricated value.
- **No CSV export.** JSON only, per this phase's own scope — `--export-benchmark`/
  `--export-comparison` both write structured JSON.
- **No new exploitation, privilege escalation, persistence, or
  shell-access capability was added or performed.** `access_state` remains
  the engagement's only success signal; this phase adds measurement and
  reporting only.
