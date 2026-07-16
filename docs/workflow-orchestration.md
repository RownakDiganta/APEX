# Multi-Step Exploitation Orchestration (Phase 15)

**Status:** implemented. Reifies the dependency ordering `GlobalPlanner`
already enforces (recon → web → credential → priv_esc) into an explicit,
inspectable, reportable `Workflow`/`Session`/`WorkflowRecommendation` model,
without changing what APEX is capable of doing to a target.

## 1. What this is — and is not

This is a **reasoning-and-coordination framework, not an exploitation
engine**. It does not execute an exploit, upload a payload, generate a
reverse shell, use Metasploit, establish persistence, or capture a flag.
Every planner in this codebase already reasons over the same EKG data these
workflows describe; what Phase 15 adds is a *reification* — an explicit,
content-addressed, persisted model that a report or an operator can read
directly, instead of the dependency ordering existing only implicitly
inside `GlobalPlanner._select_phase`'s if-chain.

Before this phase, "the engagement understands recon must happen before
credentials, which must happen before privilege enumeration" was true, but
only as an implicit side effect of `GlobalPlanner.decide_phase()`'s
sequential EKG-node checks — there was no queryable object representing
"here is a multi-step chain, here is its current step, here is what's
blocking it, here is the confidence it will complete." Phase 15 builds
exactly that, as a pure, read-only reasoning layer over already-existing
EKG data.

**The dependency enforcement itself is unchanged.** `GlobalPlanner`,
`ReconPlanner`, `WebPlanner`, `BrowserPlanner`, `CredentialPlanner`, and
`PrivEscPlanner` all continue to plan and dispatch tasks exactly as before.
Phase 15 does not add a new phase, a new agent node that dispatches tasks,
or a new execution capability — it adds a synthesis step that runs
alongside the existing turn loop and describes what is already happening.

## 2. Workflow model

`apex_host/types.py`:

| Type | Purpose |
|---|---|
| `WorkflowStepStatus` | `pending` / `completed` / `blocked` / `failed` |
| `WorkflowStatus` | `running` / `blocked` / `completed` / `abandoned` / `stalled` |
| `WorkflowStep` | `name`, `status`, `description` |
| `Workflow` | `id`, `key`, `objective`, `prerequisites`, `steps`, `status`, `confidence`, plus properties `current_step`, `completed_steps`, `blocked_steps`, `failed_steps`, `pending_steps`, `next_candidate`, `completion_percentage` |
| `SessionKind` / `SessionStatus` | `browser`/`credential`/`ssh`/`ftp`/`telnet`; `active`/`attempted`/`inactive` |
| `Session` | `id`, `kind`, `target`, `status`, `detail` — a **planning object only**, never a live executable session |
| `WorkflowRecommendation` | `id`, `workflow_id`, `text`, `category`, `priority` — advisory text for a human operator, never a command APEX itself would run |

## 3. Dependency graph and action chains

`apex_host/planners/workflow_orchestration.py::WORKFLOW_TEMPLATES` is a
fixed, deterministic list of two workflows, matching the task brief's own
two examples exactly:

```
credential_to_privesc
  prerequisites: host, service
  discover_login -> validate_credentials -> enumerate_privilege -> generate_recommendations

web_discovery_to_opportunity
  prerequisites: host, endpoint
  discover_form -> inspect_technology -> identify_opportunity
```

A template is only included in the derived output when its `prerequisites`
(EKG node types) are already present — a target that never reaches the web
phase never produces a `web_discovery_to_opportunity` workflow at all; it
isn't "not started", it simply isn't applicable yet.

### Why later stages cannot begin until prerequisites exist — structurally, not incidentally

`_evaluate_steps()` enforces this as a hard rule of the reasoning engine
itself:

```python
prereqs_met = True
for step_def in step_defs:
    if not prereqs_met:
        status = WorkflowStepStatus.blocked        # never even evaluated
    elif step_def.check_fn(subgraph):
        status = WorkflowStepStatus.completed
    elif step_def.fail_fn and step_def.fail_fn(subgraph):
        status = WorkflowStepStatus.failed
    else:
        status = WorkflowStepStatus.pending
    if status != WorkflowStepStatus.completed:
        prereqs_met = False
```

Once any step is not `completed`, every step after it is unconditionally
`blocked` — its own completion condition is never even evaluated. This
means a `priv_esc_opportunity` node existing in the EKG (which, in
practice, can only happen after `access_state` exists anyway — see
`derive_analytical_opportunities`, Phase 13) is not sufficient on its own
to mark `enumerate_privilege` complete unless `discover_login` and
`validate_credentials` are *also* already complete.

### Step-check functions (pure predicates over the subgraph)

| Step | Completed when | Failed when |
|---|---|---|
| `discover_login` | An `auth_flow` node exists, or an `access_validate_ssh`/`_ftp`/`_telnet` capability is derivable | *(never — discovery doesn't fail, only succeeds or hasn't happened yet)* |
| `validate_credentials` | An `access_state` node exists | A `credential` node exists for a (username, protocol) pair with **no** matching `access_state` |
| `enumerate_privilege` | A `priv_esc_opportunity` or `priv_esc_evidence` node exists | *(never)* |
| `generate_recommendations` | Always true once reached (recommendation text is generated immediately from whatever evidence exists) | *(never)* |
| `discover_form` | A `form` node exists | *(never)* |
| `inspect_technology` | A `tech` node exists | *(never)* |
| `identify_opportunity` | A `web_opportunity` node exists | *(never)* |

Only `validate_credentials` has a real, meaningful "failed" signal — a
credential attempt that produced a `credential` node but no `access_state`
is a genuine negative result (mirrors Phase 12B's own one-attempt-per-
protocol design). The web-discovery chain has no equivalent "attempted but
failed" concept, so its steps are only ever `pending`, `completed`, or
`blocked` — documented as a limitation (§9), not an oversight.

### Workflow-level status

1. All steps `completed` → `completed`.
2. Any step `failed` → `blocked` (a prerequisite genuinely failed; nothing
   automated can proceed).
3. The engagement's own outcome was one of the three stall-derived values
   (`duplicate_task_stall`/`no_actionable_task`/`policy_blocked` — Phase
   12C's `EngagementOutcome`) → `stalled`.
4. The engagement ended (`completed=True`) without this workflow finishing
   → `abandoned`.
5. Otherwise → `running`.

This reuses Phase 12C's own `EngagementOutcome`/stall taxonomy rather than
reinventing stall detection at the workflow level — one source of truth for
"did the engagement stop making progress."

## 4. Session model

`derive_sessions_from_subgraph()` builds `Session` records — **planning
objects only**, reconstructed from evidence other phases already collected:

| Kind | Active when | Attempted when |
|---|---|---|
| `browser` | Any `endpoint` node has `browsed=True` | *(n/a — inactive otherwise)* |
| `credential` (aggregate) | Any `access_state` node exists (any protocol) | Any `credential` node exists but no `access_state` |
| `ssh` / `ftp` / `telnet` | An `access_state` node matches that protocol | A `credential` node matches that protocol but no matching `access_state` |

`detail` never contains a password or cookie value — only counts,
protocol names, and usernames (already-plaintext EKG data per the existing
credential/browser conventions — see `docs/credential-validation.md` and
`docs/web-planning.md`).

## 5. Graph shape

```
host --indicates--> workflow --contains--> workflow_step --indicates--> session
                     workflow --contains--> workflow_step --indicates--> priv_esc_opportunity (implicit, via evidence already in the graph)
                     workflow --recommends--> workflow_recommendation
host --indicates--> session
```

No new edge types were needed — `indicates` (host/step → workflow/session),
`contains` (workflow → workflow_step), and `recommends` (workflow →
workflow_recommendation, the SAME edge type Phase 13B introduced for
`priv_esc_opportunity → priv_esc_recommendation`) were already generic
enough to reuse, mirroring Phase 14's "reuse existing edges, don't fragment
the graph" discipline exactly.

The `host → workflow` and `host → session` `indicates` edges are
load-bearing, not cosmetic: without them, workflow/session nodes would be
orphans, invisible to `MemoryAPI.get_subgraph()`'s bounded host-anchored
traversal — the identical class of bug Phase 13 and Phase 14 each hit and
fixed for their own new node types. This was verified directly (not just
assumed) via a real end-to-end dry-run engagement through the compiled
graph during this phase's own development.

Every node ID is content-addressed (`target`+`workflow_key`/`step_name`/
`session_kind` — never on status), so re-deriving and re-persisting the
same workflow/session state on every turn upserts the same nodes rather
than creating duplicates.

## 6. Orchestration — where this runs

`apex_host/orchestration/continuation_node.py::reflect_or_continue`
(the node that already runs at the end of every turn to decide
termination) now also:

1. Derives `Workflow`/`Session` objects from the SAME subgraph snapshot it
   already fetched for its own termination peek (no extra EKG read).
2. Materializes them into `workflow`/`workflow_step`/`session`/
   `workflow_recommendation` node/edge deltas
   (`build_workflow_graph_deltas`).
3. Persists them via `MemoryAPI.apply_deltas()` — a single, transactional
   batch write.
4. Refreshes `ApexGraphState["workflow_summary"]` (a small live-view dict:
   `workflow_count`, `status_counts`, `active_session_count`).

This is wrapped in a `try/except` — a failed sync degrades gracefully
(logged at debug level) and never affects the termination decision itself.
The live per-turn sync always uses `engagement_completed=False` (it cannot
know in advance whether this turn is the terminating one); the FINAL
report (§7) re-derives independently with the real, final
`engagement_completed`/`engagement_outcome` values, so `abandoned`/`stalled`
classification in the report is always accurate regardless of the live
snapshot's staleness — the same convention Phase 13/14 already established
for `privilege_summary`/`web_session_state`.

## 7. Reporting

`RunReport` gains a "Workflow Summary" section, shown only when at least
one workflow's prerequisites were ever met:

```
Workflow Summary
  Workflows            : 2 (completed=0, blocked=1, running=1, stalled=0, abandoned=0)
  Completion           : 42.9%
  Active sessions      : ssh=active, browser=active
  Planner decisions    : 12 (deterministic=10, llm=2)
  Reasoning chains:
    credential_to_privesc (blocked): discover_login -> [validate_credentials] -> [enumerate_privilege] -> [generate_recommendations]
  Recommendations:
    Workflow 'Validate credentials and enumerate privilege-escalation opportunities' is blocked at 'validate_credentials'...
```

(A `[bracketed]` step name in the reasoning-chain line means "not yet
completed" — `blocked`/`pending`/`failed`; an unbracketed name means
`completed`.)

| Field | Derivation |
|---|---|
| `workflow_count` / `workflows_completed` / `workflows_blocked` / `workflows_running` / `workflows_stalled` / `workflows_abandoned` | `rank_workflows(derive_workflows_from_subgraph(final_subgraph, engagement_completed=..., engagement_outcome=...))` |
| `workflow_completion_percentage` | Average `completion_percentage` across all applicable workflows |
| `active_sessions` | `[{"kind", "status", "detail"}, ...]` from `derive_sessions_from_subgraph(final_subgraph)` |
| `reasoning_chains` | `[{"workflow", "objective", "status", "steps": [...]}, ...]` — the full chain, not just summary counts |
| `workflow_recommendations` | Up to 5 advisory strings |

"Planner decisions" reuses the existing `report.planner_decisions` field
(Phase 5) — no new mechanism was needed; the Workflow Summary section just
surfaces a deterministic/LLM breakdown of data the report already
collects. `to_json_dict()` gains a `"workflow_orchestration"` block with
the same fields.

## 8. Why workflows never need "resume" logic

A workflow's step statuses are computed **fresh, every time**, from
whatever EKG evidence currently exists — never from remembered/imperative
history. Because memfabric's episodic log is append-only (Invariant 2) and
working-memory nodes are only ever upserted, never deleted (Invariant 3),
evidence for an already-completed step can never disappear. A workflow
that reached `completed` on turn 3 is *structurally* incapable of
reverting to an earlier status on turn 5 just because it is re-derived
again — there is no separate "progress" variable to accidentally reset.
"Avoid restarting completed chains" (the task brief's own phrasing) is
therefore satisfied by construction, not by a special case — verified
directly by `TestResumedChains` in the test suite (§10).

## 9. Current limitations

- **The web-discovery chain has no "failed" signal.** Unlike
  `validate_credentials`, none of `discover_form`/`inspect_technology`/
  `identify_opportunity` have a meaningful "attempted but failed" concept
  — a page either has a form or it doesn't. Its steps are only ever
  `pending`, `completed`, or `blocked`.
- **Exactly two workflow templates.** `WORKFLOW_TEMPLATES` is a fixed,
  hardcoded list — not configurable via CLI/config in this phase. Adding a
  new chain means adding a new `_WorkflowDef` to that tuple.
- **`stalled` classification depends on the engagement's own outcome
  already being one of the three Phase 12C stall values** — a workflow is
  never independently "stalled" from turn-over-turn snapshot comparison;
  it borrows the engagement-level signal rather than reimplementing stall
  detection at the workflow level.
- **The live per-turn `workflow_summary` state field is one-turn-stale**,
  same caveat as `privilege_summary`/`web_session_state` — the final
  report is not affected, since it always re-derives from the complete
  final EKG with the real completion/outcome values.
- **No new live command execution, no exploit, no payload, no persistence,
  no flag capture was added or performed.** `access_state` remains the
  engagement's only success signal; this phase adds a reified,
  reportable reasoning layer over already-existing planning data, nothing
  more.
