# Canonical Action Fingerprint, Retry, and Repair Semantics (Phase 2)

This document is the full design record for Phase 2 of the post-live-test
debugging track ("Phase 2 of exactly four debugging phases"). Phase 1 fixed
LLM readiness/configuration behavior and container-compatible Nmap
execution (`docs/action-fingerprint.md`'s sibling record is the Phase 1
report delivered in conversation, not a separate file). This phase fixes
why the second authorized HTB live test executed the identical Nmap action
six times without `duplicate_actions.total_skipped` ever incrementing, and
tightens phase-transition, retry, and repair semantics so a fixed action
cannot loop forever.

## 1. Live-test evidence

- The exact same Nmap action executed six times.
- The execution fingerprint was repeated.
- `duplicate_actions.total_skipped` remained zero.
- Each failed task received a new task ID.
- All six failures had the same effective command, target, phase, and
  outcome.
- Repair did not produce a changed action.
- The run spent turns repeating the same failed operation.
- `no_action_count` reached nine.
- Termination occurred only after three consecutive no-action turns.
- Deterministic fallback kept reproducing the same ineffective task.

## 2. Root causes (two independent, compounding bugs)

### 2.1 Dispatcher status-assignment bug (why duplicates weren't suppressed)

`apex_host.execution.registry.TaskRegistry.reserve()` suppresses a new
submission only when the existing record's status is `PENDING`,
`EXECUTING`, `COMPLETED`, or `FAILED_TERMINAL` — never `FAILED_RETRYABLE`
(by design: a genuinely retryable failure must not block a legitimate
retry). Before this phase, `TaskDispatcher.dispatch()` chose between
`FAILED_RETRYABLE` and `FAILED_TERMINAL` using the coarse
`ExecutionDisposition.is_retryable` property — `True` for **every**
`EXECUTED_FAILURE`, regardless of the specific error text. Meanwhile,
`apex_host.execution.dispositions.classify_retry()` — the actual,
error-text-aware retry policy — already correctly computed
`may_retry=False` for an nmap raw-socket permission failure (the generic
`EXECUTED_FAILURE` fallthrough: `"script_error — repair eligible"`, not a
`_RETRYABLE_ERRORS` match). That correct decision was computed and
returned in `DispatchResult.retryable`, but never consulted when deciding
the `TaskRegistry` status. So a failure that `classify_retry()` itself
said should never be retried was nonetheless recorded as
`FAILED_RETRYABLE` — which does not suppress resubmission — and the
identical action executed again on the very next turn, forever, until the
turn/repair budgets ran out.

**Fix:** `TaskDispatcher.dispatch()` now computes `classify_retry()`
*first* and uses `retry_decision.may_retry` (not `disposition.is_retryable`)
to choose the final status. A non-retryable failure is `FAILED_TERMINAL`
on the very first attempt.

### 2.2 GlobalPlanner phase-transition bug (why the engagement then cascaded through empty phases)

`GlobalPlanner._select_phase()` requires a real `"service"` node type
before leaving the recon phase. To prevent recon from looping forever when
genuinely nothing more can be discovered, `decide_phase()` has always
force-advanced past a phase whose own turn budget is exhausted by
synthetically injecting that phase's completion node type
(`_PHASE_COMPLETION_NODE`) into the set `_select_phase()` evaluates —
before this phase, `recon -> "service"` was one such entry. Once recon's
default 6-turn budget was exhausted (which the six repeated Nmap failures
did, one real turn each, since turns are consumed regardless of
execution outcome), the engagement fabricated a `"service"` node type it
never actually observed and force-advanced straight into the
CREDENTIAL phase on a host-only graph. `CredentialPlanner` itself still
correctly found no real capability (it reads the REAL subgraph, not
GlobalPlanner's locally-fabricated set) and returned an `AbandonSignal`
— a "no action" turn — but the same forced-advance pattern then repeated
through `objective`/`priv_esc`, producing the observed
"`no_action_count` reached nine" before the (pre-existing, unmodified)
`StallTracker` finally detected three consecutive no-action turns and
stopped the run.

**Fix:** `recon` is removed from `_PHASE_COMPLETION_NODE`. Recon's own
budget exhaustion with no real service now terminates the engagement
directly (`EngagementOutcome.phase_budget_exhausted`, with the reason
`"no services discovered — recon exhausted its turn budget with no
service evidence"`) instead of fabricating evidence for a later,
capability-dependent phase. `web` and `credential` keep their existing
forced-advance behavior — see §5.

With both fixes in place, the combined effect on this exact scenario is:
nmap executes for real once, fails non-retryably, is recorded
`FAILED_TERMINAL`; every subsequent identical proposal from the
(unmodified, still-stateless) `ReconPlanner` is suppressed by the
dispatcher before it ever reaches the backend; `StallTracker`'s
pre-existing `duplicate_streak` counter (unchanged by this phase) reaches
its threshold of 3 within a handful of turns and the engagement stops —
see `tests/apex_host/test_phase2_duplicate_debug.py
::TestSixNmapRepeatScenarioTerminatesEarlier` for the full, real,
in-process (no live target) end-to-end proof.

## 3. Canonical action fingerprint

`apex_host.planning.fingerprint.task_fingerprint(phase, tool, args,
target, parser="", executor_domain="", capability_mode="")` returns a
stable 16-character SHA-256 hex digest of the action's SEMANTIC identity.

**Included fields:**

| Field | Normalization |
|---|---|
| `phase` | lower-cased, stripped |
| `tool` | lower-cased, stripped |
| `args` | each token stripped of incidental whitespace; **order preserved** |
| `target` | lower-cased, stripped |
| `parser` | lower-cased, stripped |
| `executor_domain` | lower-cased, stripped |
| `capability_mode` | lower-cased, stripped — see §4 |

**Deliberately excluded (ephemeral, never part of action identity):**
`task.id` (a fresh UUID minted on every `TaskSpec` construction), any
timestamp, any trace/run ID. The function signature has no parameter for
any of these — there is no way for a caller to accidentally include one.

### 3.1 Why argument order is no longer normalized away

The pre-Phase-2 implementation sorted `args` before hashing, so
`["-sV", "-T4"]` and `["-T4", "-sV"]` produced the same fingerprint. This
is harmless for a fixed flag set with no positional values, but it is a
genuine over-normalization bug for flag/value pairs:
`["-p", "80", "--exclude", "443"]` (scan port 80, exclude port 443) and
`["-p", "443", "--exclude", "80"]` (the semantically OPPOSITE command)
sort to the identical token multiset and would silently collide onto one
fingerprint. Order is now preserved; only incidental leading/trailing
whitespace per token is stripped. Internal token case is left unchanged —
CLI flags are frequently case-sensitive (`-sV` vs `-sv` are different
nmap options).

This correction also matters for the new `repair_no_change` detection
(§6): comparing an original and a repaired task's fingerprints to decide
"did repair actually change anything?" would produce false positives
(wrongly concluding "no change" for a genuinely different repair) under
the old order-insensitive scheme whenever a repair happened to reorder
flag/value pairs.

## 4. Backend capability mode

`apex_host.tools.backend.backend_capability_mode(config)` returns
`"raw_socket"` when `apex_host.tools.backend.backend_supports_raw_sockets(config)`
is `True`, else `"tcp_connect"` — a small, fixed, auditable vocabulary
(never an open string). `TaskDispatcher.dispatch()` includes this in every
fingerprint it computes. Two otherwise-identical actions planned under
different backend capability assumptions are treated as distinct actions
— relevant for tools (like nmap, after Phase 1's `-sT` fix) whose argv
already visibly encodes the capability difference, and future-proofing
for tools where it might not.

## 5. Bounded retry status taxonomy

`apex_host.execution.registry.TaskStatus`:

| Status | `suppresses_new_submission` | Produced when |
|---|---|---|
| `PENDING` | `True` | A reservation was made; the executor has not yet returned |
| `EXECUTING` | `True` | (Reserved for future use — not currently set by `TaskDispatcher`) |
| `COMPLETED` | `True` | `disposition.is_success` |
| `FAILED_RETRYABLE` | `False` | `classify_retry().may_retry` is `True` and the fingerprint's bounded-retry budget is not yet exhausted |
| `TIMED_OUT` | `False` | `ExecutionDisposition.TIMED_OUT` and the bounded-retry budget is not yet exhausted |
| `FAILED_TERMINAL` | `True` | `classify_retry().may_retry` is `False`, OR the fingerprint's bounded-retry budget IS exhausted |
| `BLOCKED` | `True` | (Legacy generic value; not newly produced by this phase) |
| `POLICY_BLOCKED` | `True` | Reserved value for a `PolicyAdvisor` denial — **not currently registered** in `TaskRegistry`; see §5.1 |
| `CANCELLED` | `False` | `asyncio.CancelledError` propagated during dispatch |
| `SKIPPED_DUPLICATE` | `False` | This specific attempt was itself a suppressed duplicate |
| `SUPERSEDED` | `True` | A materially-changed repaired action was dispatched for this fingerprint (§6) |

### 5.1 Why `POLICY_BLOCKED` is not wired into the registry

`TaskDispatcher.dispatch()`'s own "Security invariants" docstring states,
unchanged by this phase: *"Blocked (policy/conflict) tasks are NEVER
registered in `TaskRegistry` — they leave no fingerprint trail — the
operator may re-run after fixing the policy or resolving the conflict."*
This is deliberate, pre-existing, documented behavior with no demonstrated
bug behind it (the live-test evidence does not describe a policy-block
loop) — so this phase adds the `TaskStatus.POLICY_BLOCKED` enum member for
a complete taxonomy (matching the literal requirement to "distinguish...
policy blocked" as a reportable status value) without changing where the
policy gate runs relative to fingerprint registration. See §9 "Remaining
limitations."

### 5.2 Bounded retry budget

`ApexConfig.max_fingerprint_retries` (default `1`) bounds how many
additional resubmissions a fingerprint whose specific failure IS
retryable (`classify_retry().may_retry=True`) may have before it, too, is
forced to `FAILED_TERMINAL`. `TaskRegistry.attempt_count(fingerprint)` is
a cumulative, 1-based, never-reset-within-a-run counter incremented on
every successful `reserve()` call for that fingerprint. `TaskDispatcher`
compares this count against `max_fingerprint_retries` when deciding the
final status — once the bound is exceeded, `tr_dict["retry_budget_exhausted"]
= True` is set so the report can distinguish "never retryable" from
"was retryable, but the bound is spent."

Concretely, with the default `max_fingerprint_retries=1`: attempt 1 fails
transiently → `FAILED_RETRYABLE` (resubmission allowed); attempt 2 (the
one bounded retry) fails transiently again → `FAILED_TERMINAL`
(resubmission now suppressed). "One bounded retry", never unbounded.

## 6. Repair vs `repair_no_change`

`apex_host.orchestration.repair_node.repair_agent` computes the SAME
canonical fingerprint (tool/args/target/phase/parser/executor_domain/
capability_mode) for both the just-failed task and `RepairEngine`'s
proposed correction, **before** ever calling `TaskDispatcher.dispatch()`
for the repaired task:

- **Same fingerprint → `repair_no_change`.** The repaired action is
  rejected before dispatch. No execution turn is consumed (`repair_count`
  still increments by one — a repair attempt WAS made — but no tool ever
  runs and no episode is written). Recorded in
  `state["duplicate_actions"]` with `disposition: "repair_no_change"` and
  `repair_changed_action: false`, so the report shows exactly why nothing
  happened.
- **Different fingerprint → dispatched normally.** The repaired task goes
  through the full policy/conflict/duplicate gate exactly like any other
  task. On dispatch, the ORIGINAL fingerprint's `TaskRegistry` record is
  marked `TaskStatus.SUPERSEDED` (via the new
  `TaskDispatcher.task_registry` property) — it stays suppressed (the
  original broken action must never be blindly resubmitted) but is now
  audit-distinguishable from an unresolved terminal failure.

### 6.1 Provider configuration errors never trigger repeated repair attempts

`RepairEngine.repair()` now checks the SAME shared
`LLMBudgetTracker.permanent_provider_error_category` flag Phase 1 wired
into `PlanningEngine` — once ANY phase this run has confirmed a permanent
LLM provider misconfiguration (missing key, invalid model, authentication
failure, unsupported endpoint, malformed response —
`apex_host.llm.errors.PERMANENT_LLM_ERROR_CATEGORIES`), `repair()` returns
`None` immediately, without a real (doomed) network call. Without this,
every repairable failure in a live run with a broken LLM configuration
would have independently attempted — and failed — repair.

## 7. Phase-transition evidence requirement

See §2.2 for the bug. The corrected rule:

- **Recon** requires a real `"service"` node type before advancing past
  itself under any circumstance — including budget exhaustion, which now
  terminates the engagement (`phase_budget_exhausted`) instead of forcing
  a fabricated advance.
- **Web** and **credential** retain their existing forced-advance
  behavior on their own budget exhaustion. This is not a bug: by the time
  either phase's budget is even checked, the prerequisite evidence for
  being in that phase already exists for real — `web` only ever runs
  when a real HTTP/HTTPS service was already discovered
  (`has_web_capability=True`), and `credential`'s own capability check
  (`capabilities_from_subgraph`) reads the REAL subgraph independently of
  GlobalPlanner's phase-selection bookkeeping.
- **Credential planning** requires a real, discovered service/
  authentication-flow/access-validation capability. This was already true
  at the `CredentialPlanner` level before this phase (it has always
  queried the real subgraph, never GlobalPlanner's internal
  `forced_node_types` set) — the bug was that GlobalPlanner would still
  waste a turn *entering* the credential phase on a host-only graph, even
  though `CredentialPlanner` itself would then correctly abandon.
  `tests/apex_host/test_phase2_duplicate_debug.py
  ::TestPhaseTransitionEvidenceGating::test_host_only_graph_does_not_enter_credential`
  verifies the phase-selection level directly.

## 8. Report fields

Every `duplicate_actions` entry — both ordinary duplicate skips
(`apex_host.orchestration.dispatch_node._dup_entry`) and
`repair_no_change` rejections — carries:

| Field | Meaning |
|---|---|
| `fingerprint` | The canonical action fingerprint |
| `tool` / `target` / `phase` | The action's identifying fields |
| `disposition` | `"skip_task"` (ordinary duplicate) or `"repair_no_change"` |
| `reason` | Human-readable skip reason |
| `previous_status` | The `TaskStatus` value that caused suppression (ordinary duplicates only) |
| `previous_disposition` | The `ExecutionDisposition` value of the prior attempt (ordinary duplicates only) |
| `retry_count` | How many times this fingerprint had already been attempted |
| `repair_changed_action` | `false` for `repair_no_change` entries; absent for ordinary duplicates |

`RunReport.duplicate_action_count` counts BOTH kinds.
`to_json_dict()["duplicate_actions"]["entries"]` exposes the full list.
`format_text()`'s "Duplicate Actions Skipped" section shows up to three
sample entries with previous status / retry count / repair-changed
inline. No entry ever carries a secret argument value — only
`tool`/`target`/`fingerprint`/status metadata are recorded, never raw
command output (which is separately bounded/redacted at the episode
level, unaffected by this phase).

## 9. Remaining limitations

- `TaskStatus.POLICY_BLOCKED` is a complete taxonomy member but is not
  currently written to `TaskRegistry` — see §5.1.
- `apex_host.planning.fingerprint.DuplicateActionTracker` (a standalone
  sliding-window utility in the same module) is not instantiated anywhere
  in production `apex_host` code — the config fields
  `ApexConfig.duplicate_action_window`/`duplicate_action_max_repeats`/
  `duplicate_action_detection_enabled` are similarly unread by any
  production code path. This is pre-existing, unrelated to the confirmed
  bug (the real, currently-wired duplicate-suppression mechanism is
  `TaskRegistry`), and was left untouched — fixing or removing it was
  judged out of this phase's scope.
- `max_fingerprint_retries` has no dedicated CLI flag (config-only),
  matching the existing precedent for several other internal tuning
  fields in `ApexConfig` (e.g. `duplicate_action_window`).
- The `no_action_count` report metric (`apex_host.eval.report`) is
  computed from `PlanDecision.selected_task_count`, which
  `PlanningEngine._record_fallback()` hardcodes to `0` for every
  deterministic-fallback decision regardless of whether the fallback
  planner actually produced a task — a pre-existing, already-documented
  gap (Phase 17's own "Remaining limitations") that this phase did not
  fix (it would require reordering ~9 call sites in
  `apex_host/planning/engine.py`, a wide-blast-radius change judged out
  of this phase's narrower scope). `StallTracker`'s own `no_action_streak`
  is unaffected — it uses the more accurate `state["current_task"]
  is not None` signal, not `selected_task_count`.
