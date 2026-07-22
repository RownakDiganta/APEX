# Engagement Termination & Outcome Reporting (Phase 12C)

**Status:** implemented. Covers the canonical `EngagementOutcome` model, the
termination evaluator, bounded stall detection, the exactly-one
terminal-episode guarantee, `RunReport` fields, and CLI exit codes.

> **Phase 18 update (user-flag objective and verification):** the success
> definition documented in this file has been redefined. Before Phase 18,
> `EngagementOutcome.validated_access` (a validated `access_state` node in
> the EKG) was the sole success outcome. As of Phase 18,
> `EngagementOutcome.user_flag_verified` is the sole success outcome —
> `validated_access` is now classified as an intermediate-milestone,
> non-success outcome (exit code changed from `0` to `1`; legacy status
> changed from `"success"` to `"abandoned"`). This file has been updated in
> place to describe the current, correct behavior rather than kept as a
> stale historical record, since it is a living design document (unlike
> CLAUDE.md's append-only correction convention for certain sections). Full
> design: [`docs/user-flag-objective.md`](user-flag-objective.md).

> **Phase 20 update (direct file read capability):** `GlobalPlanner`'s
> credential-phase gate previously required a validated `access_state`
> node before the engagement could ever reach the `objective` phase. It
> now also accepts a validated `access_capability` node (§3's
> `objective_verified`/success-outcome model itself is unchanged — this is
> purely a *reachability* fix, not a new success condition): a
> direct-file-read engagement, where no credential-based login is ever
> attempted, can now reach the objective phase and terminate as
> `user_flag_verified` exactly like an SSH-based engagement can.
> `EngagementOutcome.user_flag_verified` remains the ONLY success outcome
> and the only exit-code-0 outcome; `validated_access` remains an
> intermediate milestone regardless of which access mechanism produced it.
> Full design: [`docs/user-flag-objective.md`](user-flag-objective.md) §17.

> **Phase 21 update (bounded command-execution capability):** no change was
> needed to this file's model at all. `GlobalPlanner`'s phase-ladder gate
> (checking for `"access_state"` OR `"access_capability"`) was already
> capability-type-agnostic as of the Phase 20 update above — a
> `local_shell`/`remote_command`/`web_command` capability reaches the
> objective phase through the exact same gate a direct-file-read
> capability does. `EngagementOutcome.user_flag_verified` remains the ONLY
> success outcome and the only exit-code-0 outcome regardless of which
> capability family (SSH, direct file read, or bounded command execution)
> produced the verified evidence. Full design:
> [`docs/user-flag-objective.md`](user-flag-objective.md) §18.

## 1. Why this exists

Before Phase 12C, an APEX engagement could stop for many different reasons —
maximum turns reached, no more useful work to do, a policy block, a crashed
planner, a validated credential — but all of them collapsed onto the same
observable shape: `ApexGraphState["completed"] = True`. There was no single
place that recorded *why* a run ended, no bounded detector for an engagement
quietly looping without making progress, and no way for a script driving
`run_htb_local.py` to distinguish "we got in" from "we gave up" from "we
crashed" without parsing free-text log lines.

Phase 12C introduces **one canonical outcome model** — `EngagementOutcome`,
`apex_host/orchestration/outcome.py` — that every termination path in the
codebase produces exactly one instance of. Nothing else in the codebase is
allowed to invent a second, competing classification of "how did this run
end." `RunReport.status`/`RunReport.completed_successfully` (the pre-12C
four-value string and boolean) are now *derived from* `EngagementOutcome`,
never computed independently.

## 2. The outcome model

`EngagementOutcome` (`apex_host/orchestration/outcome.py`) is a `str, Enum`
— sixteen members (Phase 18 added `user_flag_verified`), split into five
families:

| Family | Members |
|---|---|
| Success | `user_flag_verified` |
| Intermediate milestone (never success) | `validated_access` |
| Organic / resource exhaustion | `goal_completed`, `max_turns_exhausted`, `phase_budget_exhausted` |
| Stall-detector | `no_actionable_task`, `duplicate_task_stall`, `policy_blocked` |
| Hard failure | `planner_failure`, `parser_failure`, `tool_failure`, `memory_failure`, `unknown_phase` |
| Outside-the-graph | `cancelled`, `configuration_failure`, `internal_error` |

### Success definition (non-negotiable) — redefined by Phase 18

```python
def is_success_outcome(outcome: EngagementOutcome) -> bool:
    return outcome is EngagementOutcome.user_flag_verified
```

Exactly one outcome ever means success: `EngagementOutcome.user_flag_verified`
(the configured engagement objective — default `"user_flag"` — has been
retrieved and cryptographically confirmed by the one authoritative verifier,
`apex_host.verification.user_flag.verify_user_flag()`). Neither
`goal_completed` (an organic, non-error completion of the phase ladder) nor
`validated_access` (a validated `access_state` node — an important
intermediate milestone) is ever success on its own. See
[`docs/user-flag-objective.md`](user-flag-objective.md) for the full design
of the objective model, EKG representation, and verification mechanism this
depends on.

## 3. Termination evaluator (`evaluate_termination`)

`evaluate_termination()` in `apex_host/orchestration/outcome.py` is a pure
function — no I/O, unit-testable with synthetic inputs — that decides
whether a turn should terminate and, if so, with which outcome. It is
called from `apex_host/orchestration/continuation_node.py`'s
`reflect_or_continue` node, the single place every graph-internal
termination reason is decided.

### Precedence (highest first)

1. **`user_flag_verified`** (Phase 18) — the configured objective's
   `objective` EKG node has `status == "verified"` (see
   `apex_host.planners.objective.objective_status_from_subgraph`). Checked
   first, unconditionally, so an objective verified on the very last
   allowed turn is still reported as success, never as an exhaustion
   outcome. A validated `access_state` alone never satisfies this
   condition — `evaluate_termination()`'s parameter for this check is
   `objective_verified: bool`, not `has_access_state: bool` (renamed by
   Phase 18; see `docs/user-flag-objective.md` §9).
2. **An upstream node already produced a definitive terminal outcome this
   turn** — `dispatch_node.py`, `parsing_node.py`, or `memory_node.py`
   caught an exception and set `state["outcome"]` to `planner_failure`,
   `parser_failure`, or `memory_failure` before `reflect_or_continue` even
   ran. `continuation_node.py` detects this via `state.get("outcome")` and
   passes it straight through — `evaluate_termination()` itself is never
   invoked in this case.
3. **Stall-derived outcomes** — `duplicate_task_stall`, `no_actionable_task`,
   `policy_blocked` — from `apex_host/orchestration/stall.py`'s
   `StallTracker` (see §4).
4. **`phase_budget_exhausted` / `goal_completed`** — `GlobalPlanner`
   returned `ApexPhase.done` for a reason other than the hard turn ceiling.
   `phase_budget_exhausted` fires specifically when `priv_esc`'s own
   per-phase budget ran out (priv_esc is the last phase in the ladder — see
   §5). `goal_completed` is the organic `_select_phase()` fallback, kept for
   completeness though not reachable through the current `GlobalPlanner`
   logic.
5. **`max_turns_exhausted`** — the hard turn ceiling (`ApexConfig.max_turns`).

`cancelled`, `configuration_failure`, and `internal_error` are **never**
produced by `evaluate_termination()` — they only occur outside the compiled
graph (before it starts, or via an exception/interrupt that escapes
`graph.ainvoke()`), and are classified by `apex_host.runtime.ApexRuntime.run()`
and the CLI entry points instead (see §7).

### `TerminationDecision`

```python
@dataclass(slots=True)
class TerminationDecision:
    terminate: bool
    outcome: EngagementOutcome | None
    success: bool
    reason: str
    phase: str
    turn: int
```

Every termination — inside or outside the graph — produces exactly one of
these, which is used verbatim to build the one terminal `Episode` (§6) and
to populate `ApexGraphState`'s new fields (§8).

## 4. Bounded stall detection

`apex_host/orchestration/stall.py`'s `StallTracker` accumulates a small set
of streak counters — one per stall category — across the turns of a single
engagement, and resets them the moment genuine progress is observed. It
never allows the engagement to loop forever: once any streak reaches
`threshold` consecutive turns (default 3), it reports a `StallDecision`
that `evaluate_termination()` turns into a terminal outcome.

| Streak | Condition that increments it | Outcome when it hits threshold |
|---|---|---|
| `duplicate_streak` | This turn's `duplicate_actions` list grew (a task was skipped as a repeat of an already-completed fingerprint) | `duplicate_task_stall` |
| `policy_block_streak` | This turn's `policy_decisions` list grew with a `status="blocked"` entry | `policy_blocked` |
| `no_action_streak` | No task was dispatched this turn (`current_task is None`) and it wasn't a policy block | `no_actionable_task` |
| `stagnant_streak` | The EKG/phase fingerprint (`phase + sorted node types`) OR the planner fingerprint (`phase:last_error`) is unchanged from the previous turn | `duplicate_task_stall` (catch-all) |

**Progress resets every streak.** A turn counts as progress when a real
task was dispatched (`had_action=True`) and it was neither a duplicate nor
policy-blocked. On a progress turn, `StallTracker.reset()` clears all four
counters — the engagement gets a clean slate the moment it does something
new.

**The stagnant streak is the catch-all.** Because progress resets every
counter, the narrow duplicate/policy/no-action counters can only reach
their own threshold when the *same* narrow condition repeats for three
consecutive turns. The stagnant streak instead fires when the underlying
EKG/phase state never changes across turns even if the *specific* reason
alternates turn to turn (a duplicate, then a policy block, then no action —
none of which individually reach the threshold, but the engagement is
still visibly not moving).

**Persistence scope (documented limitation).** Like `GlobalPlanner`'s own
per-phase budget counters (`_spent`), a `StallTracker` instance lives in
`OrchestrationDeps` — constructed fresh per engagement, not persisted in
`ApexGraphState`, and therefore not restored across a checkpoint resume.
This mirrors the existing, accepted precedent for `GlobalPlanner` rather
than introducing a new, inconsistent persistence model.

## 5. Phase budget exhaustion

Phase 12A already fixed the credential-phase budget oscillation (the
"peeked priv_esc, re-derived credential, forever" bug). Phase 12C adds the
missing piece at the *other* end of the phase ladder:
`GlobalPlanner.decide_phase()` now checks, after its normal EKG-driven
selection, whether the selected phase is `priv_esc` **and** priv_esc's own
budget is already exhausted — if so it returns `ApexPhase.done` instead of
`priv_esc`. Every other phase (`recon`, `web`, `credential`) has a
`_PHASE_COMPLETION_NODE` entry naming the next phase to force-advance into;
`priv_esc` is the last phase in the ladder with nothing further to
force-advance into, so without this check the engagement would keep
dispatching `priv_esc_agent` every remaining turn until the *global*
`max_turns` ceiling, silently wasting the rest of the run.

`evaluate_termination()` classifies this as `phase_budget_exhausted` — a
distinct, reported reason — rather than letting it ride out to a generic
`max_turns_exhausted`.

## 6. Exactly one terminal episode

`apex_host/orchestration/terminal_episode.py` is the **one** place a
terminal `Episode` is built and written, shared by the two structurally
mutually exclusive call sites that can end an engagement:

- `continuation_node.py`'s `reflect_or_continue` — every graph-internal
  outcome (validated_access, stall-derived, budget/max-turns exhaustion,
  and upstream-preset planner/parser/memory failures).
- `diagnostics_node.py`'s `unknown_phase_agent` — reached only when
  `GlobalPlanner` produces an unroutable phase value; routes directly to
  `END` and never visits `reflect_or_continue`.

Because these two nodes are mutually exclusive by graph topology (one
always routes to `END` without ever reaching the other), "exactly one
terminal episode per engagement" holds by construction, not by a runtime
guard. The shared helper (`write_terminal_episode`) writes through
`MemoryAPI.apply_deltas` — the same transactional path every other episode
write in this codebase uses (memfabric Invariant 1 and the "graph merge
must be transactional" invariant).

The terminal episode's shape:

```python
Episode(
    agent="apex.orchestration",
    action="engagement_terminated",
    outcome=Outcome.success if is_success_outcome(decision.outcome) else Outcome.fundamental,
    data={"outcome": ..., "success": ..., "reason": ..., "phase": ..., "turn": ..., "run_id": ...},
    task_id=None,
    phase=decision.phase,
)
```

## 7. Outside-the-graph outcomes

Three outcomes are never produced by `evaluate_termination()` because they
can only happen outside `graph.ainvoke()`:

- **`cancelled`** — `apex_host.runtime.ApexRuntime.run()` catches
  `asyncio.CancelledError` around `graph.ainvoke()`, writes a best-effort
  terminal episode (phase/turn are recorded as `"unknown"`/`-1` since the
  exact in-flight turn isn't recoverable without a checkpointer), and
  re-raises. Both CLI entry points also catch `KeyboardInterrupt` around
  their own top-level `asyncio.run()` call and exit with the `cancelled`
  code (130) even if the interrupt happens before the runtime's own handler
  gets a chance to run.
- **`configuration_failure`** — raised when `ApexConfig.from_cli_args()`
  (or the earlier `merge_env_into_args()`/`EnvConfigError` path) fails.
  Never reaches the graph at all.
- **`internal_error`** — any other uncaught exception escaping
  `run_engagement()`/`runtime.run()` before the graph produced a real
  outcome, or a `final_state["outcome"]` value that fails to parse into a
  known `EngagementOutcome` (forward-compatibility fallback).

## 8. `ApexGraphState` fields

Four new plain (overwrite, not accumulate) fields, populated only on the
terminating turn (empty string before then):

| Field | Meaning |
|---|---|
| `outcome` | `EngagementOutcome.value` |
| `termination_reason` | Human-readable reason string |
| `termination_phase` | The phase that was active when termination was decided (**not** the same as `phase`, which is always forced to `"done"` on any termination — see below) |
| `stall_reason` | Populated only for the three stall-derived outcomes; empty otherwise |

**Design note — `phase` vs `termination_phase`.** On any termination, the
top-level `phase` field is always set to `ApexPhase.done.value`, matching
what every other "the engagement is over" signal in the state already
means. Before Phase 12C, `phase` sometimes stayed at the last-dispatched
phase name in one code path (the immediate max-turns-skip) and `"done"` in
others — an inconsistency. `termination_phase` is the new, single place to
find "which phase was active when the engagement actually stopped."

## 9. `RunReport` fields

`apex_host/eval/report.py`'s `RunReport` gained eight new fields, all
**projections of** `EngagementOutcome` — never a second, independent
classification:

| Field | Source |
|---|---|
| `outcome` | `EngagementOutcome.value` |
| `success` | `is_success_outcome(outcome)` |
| `termination_reason` | `final_state["termination_reason"]` |
| `termination_phase` | `final_state["termination_phase"]` |
| `termination_turn` | `final_state["turn_count"]` |
| `stall_reason` | `final_state["stall_reason"]` |
| `no_action_count` | Count of `planner_decisions` entries with `selected_task_count == 0` |
| `access_summary` | `{"validated": bool, "protocol": str \| None, "username": str \| None}` — **never a password** |

`status` (the older four-value string) and `completed_successfully` are
derived from `outcome` via `legacy_status_for()`/`is_success_outcome()`,
not computed independently. A `final_state` that predates Phase 12C (no
`outcome` key at all — e.g. a hand-built test fixture) falls back to
`_derive_outcome_from_state()`, which reproduces the exact conditions the
old `_determine_status()` used, so every pre-Phase-12C scenario still
classifies identically.

### Text report

`format_text()` prints an `Outcome:` line in the header and a dedicated
"Engagement Outcome" section right after it:

```
════════════════════════════════════════════════════════════
 APEX HTB Engagement Report
 Target : 10.10.10.14   Mode : live
 Status : SUCCESS   Successful : Yes
 Outcome: SUCCESS — user flag verified
 Turns  : 4   Final phase : done   Completed : Yes
════════════════════════════════════════════════════════════

Engagement Outcome
  Outcome           : user_flag_verified
  Termination phase : objective
  Termination turn  : 4
  Reason            : configured objective verified — evidence recorded in the EKG
  Access validated  : protocol=ssh username=root
```

Representative headlines (`outcome_headline()`) — updated by Phase 18:

| Outcome | Headline |
|---|---|
| `user_flag_verified` | `SUCCESS — user flag verified` |
| `validated_access` | `PARTIAL — validated {protocol} access — objective not verified` |
| `max_turns_exhausted` | `STOPPED — maximum turns exhausted` |
| `no_actionable_task` | `STOPPED — no actionable task remained` |
| `phase_budget_exhausted` | `STOPPED — phase budget exhausted` |
| `duplicate_task_stall` | `STOPPED — repeated duplicate or stagnant tasks` |
| `policy_blocked` | `BLOCKED — policy prevented further progress` |
| `parser_failure` | `FAILED — parser error` |
| `planner_failure` | `FAILED — planner error` |
| `tool_failure` | `FAILED — tool/backend failure` |
| `memory_failure` | `FAILED — memory failure` |
| `unknown_phase` | `FAILED — unroutable phase` |
| `configuration_failure` | `FAILED — configuration error` |
| `internal_error` | `FAILED — internal error` |
| `cancelled` | `CANCELLED — user interrupted run` |

### JSON report

`to_json_dict()` gained an `"engagement_outcome"` block:

```json
{
  "engagement_outcome": {
    "outcome": "user_flag_verified",
    "success": true,
    "headline": "SUCCESS — user flag verified",
    "termination_reason": "configured objective verified — evidence recorded in the EKG",
    "termination_phase": "objective",
    "termination_turn": 4,
    "stall_reason": "",
    "no_action_count": 1,
    "access_summary": {"validated": true, "protocol": "ssh", "username": "root"}
  }
}
```

## 10. CLI exit codes

Both `apex_host/main.py` and `apex_host/eval/run_htb_local.py` now return a
deterministic process exit code derived from `exit_code_for()`:

| Code | Meaning | Outcomes |
|---|---|---|
| `0` | Success | `user_flag_verified`, `goal_completed` |
| `1` | Exhausted / stalled / access-only | `validated_access` (Phase 18 — access alone, objective never verified), `max_turns_exhausted`, `phase_budget_exhausted`, `no_actionable_task`, `duplicate_task_stall` |
| `2` | Configuration error | `configuration_failure` |
| `3` | Policy blocked | `policy_blocked` |
| `4` | Operational failure | `planner_failure`, `parser_failure`, `tool_failure`, `memory_failure`, `unknown_phase`, `internal_error` |
| `130` | Cancelled | `cancelled` (SIGINT / Ctrl+C) |

Examples:

```bash
$ python -m apex_host.eval.run_htb_local --target 10.10.10.14 --dry-run \
    --username root --password ''
...
 Outcome: SUCCESS — user flag verified
$ echo $?
0

$ python -m apex_host.eval.run_htb_local --target 10.10.10.14 --dry-run --max-turns 2
...
 Outcome: STOPPED — maximum turns exhausted
$ echo $?
1
```

**Phase 18 note:** a real dry-run engagement can never actually reach the
`user_flag_verified` outcome — the first example above is illustrative of
the exit-code contract, not a literal transcript; see
[`docs/user-flag-objective.md`](user-flag-objective.md) §10 for what
dry-run engagements can and cannot report, and §6 for the live (or
test-fake-backed) path that can.

`--preflight` remains a distinct utility mode (not an engagement outcome)
and keeps its own plain `0`/`1` exit codes (all tools found / tools
missing). `--help` is unaffected — argparse's own built-in `SystemExit(0)`
fires before any of this logic runs, on both entry points.

## 11. Stall handling — how to read it in practice

If a report shows:

```
Outcome           : no_actionable_task
Stall reason      : 3 consecutive turns produced no actionable task
```

it means the planner returned an `AbandonSignal` (or an empty task list)
for three turns in a row — for example, the credential phase found no
`--username`/`--password` configured and the priv_esc phase found no
`searchsploit` results, back to back. This is a **clean, deliberate stop**,
not a crash: the engagement genuinely ran out of safe, bounded work to do
given the operator-supplied configuration. It is reported with exit code
`1`, the same bucket as `max_turns_exhausted` — both mean "nothing went
wrong, but the run is over."

## 12. Current limitations

- **`StallTracker` and `GlobalPlanner`'s budget counters do not survive a
  checkpoint resume.** Both live in `OrchestrationDeps`, constructed fresh
  per engagement, not persisted in `ApexGraphState`. A resumed engagement
  (from a LangGraph checkpoint) starts stall/budget tracking from zero.
  This mirrors a pre-existing, accepted limitation of `GlobalPlanner`'s own
  `_spent` counters — Phase 12C did not change that persistence model.
- **`goal_completed` is not reachable through the current `GlobalPlanner`
  logic.** It exists in the model for forward-compatibility (a future,
  more elaborate phase ladder might reach an organic "done" from a phase
  other than `priv_esc`) but no code path produces it today.
- **The `cancelled` terminal episode is best-effort.** When
  `asyncio.CancelledError` is caught in `ApexRuntime.run()`, the exact
  in-flight phase/turn is not recoverable without a configured
  checkpointer (this call site does not configure one), so the episode
  records `phase="unknown"`, `turn=-1` rather than guessing.
- **A single transient EKG-read failure during `reflect_or_continue`'s peek
  degrades gracefully rather than terminating immediately** — it logs a
  warning and treats `node_types_seen` as empty for that turn. A
  *persistent* read failure surfaces indirectly, several turns later, via
  the stall detector's stagnant-fingerprint signal (an empty
  `node_types_seen` never changes turn over turn) rather than as an
  immediate `memory_failure`. This is a deliberate trade-off (matching
  memfabric's own graceful-degradation philosophy) rather than an
  oversight, but it does mean a transient-but-persistent read outage takes
  up to the stall threshold's worth of turns to surface as a terminal
  outcome.
- **No new exploitation, privilege-escalation, persistence, or
  shell-access capability was added or changed by this phase.** Phase 12C
  is purely about how an engagement reports its own end state.

> **Note (Phase 22):** Phase 22 (see `docs/user-flag-objective.md` §19)
> completed the live remote runtime path for the `remote_command` access
> capability (a dedicated `apex_tool_service` bounded-file-read operation).
> It made no change to `EngagementOutcome`, `evaluate_termination()`, or
> any value in the table above — `user_flag_verified` remains the sole
> success outcome regardless of which capability/transport produced the
> verified evidence.

> **Note (Phase 23):** Phase 23 (see `docs/user-flag-objective.md` §20)
> added a new `objective_reopened: bool = False` parameter to
> `GlobalPlanner.decide_phase()` — when a validated, runtime-active
> capability is automatically derived after the objective phase was
> already exhausted (`"failed"` status or budget exhaustion), the phase
> ladder now routes back to `objective` instead of proceeding to
> `priv_esc`/`done`. This can extend how long an engagement stays active
> before reaching `evaluate_termination()`'s `phase_budget_exhausted`/
> `max_turns_exhausted` outcomes, but changes nothing about the outcome
> MODEL itself: `EngagementOutcome`, its precedence order, and
> `user_flag_verified` as the sole success outcome are all unchanged.
> `StallTracker`'s own stagnant-fingerprint detection is unaffected — a
> reopened objective phase that is genuinely making progress (a new
> capability, a new candidate path) does not look stagnant to it.

> **Note (Phase 24):** Phase 24 (see `docs/user-flag-objective.md` §21)
> gives `runtime_available` a real invalidation path — a capability whose
> underlying session/adapter is torn down (e.g. a connection-level
> failure, or process shutdown) is unregistered and its
> `runtime_available` flag flips back to `False`, exactly like any other
> per-turn write-back. `objective_reopening_eligible()`'s existing
> `runtime_available` check (unchanged) now behaves more precisely as a
> result: a capability that WAS active and got invalidated correctly stops
> counting toward reopening eligibility until it (or a different
> capability) is re-registered. No change to `GlobalPlanner.decide_phase()`,
> `EngagementOutcome`, or the outcome precedence order.
