# Adaptive Learning, Reflection & Experience Replay (Phase 16)

**Status:** implemented. Adds a deterministic, rule-based "learn from past
engagements" layer on top of the existing EKG, without adding any new
execution capability and without ever overriding a planner's decision.

## 1. What this is — and is not

This is **not machine learning**. There is no model, no training loop, no
gradient, no probability estimate, no embedding-based similarity search.
"Experience replay" here means exactly what Phase 15's `Workflow` model and
Phase 13/14's `PrivilegeOpportunity`/`WebOpportunity` models already mean
for their own domains: a fixed, hand-written, deterministic function over
already-observed EKG data — just applied across engagements (via
content-addressed, upserted node state) instead of only within one.

Every "learning rule" in this phase is a lookup-table adjustment
(`apply_learning_rule`) keyed on how many times a pattern has recurred
(`occurrence_count`). The same `(category, occurrence_count, base_confidence)`
input always produces the same output — verified directly by
`TestApplyLearningRule.test_deterministic_same_inputs_same_output` and
`TestReflectionGeneration.test_deterministic_ordering_same_inputs_same_output`.

This is also **not an exploitation capability**. Nothing in this phase
executes a command, drives a tool, uploads a payload, generates a reverse
shell, uses Metasploit, establishes persistence, or captures a flag. It
reads the final EKG a completed engagement already produced and the
episodic/state record of what happened, and writes back structured,
advisory `experience`/`experience_recommendation` nodes — the same "read
the graph, write advisory nodes back" shape as Phase 13's
`priv_esc_opportunity`, Phase 14's `web_opportunity`, and Phase 15's
`workflow` records.

## 2. Experience model

`apex_host/types.py`:

| Type | Purpose |
|---|---|
| `ExperienceCategory` | `successful_workflow` / `failed_workflow` / `abandoned_workflow` / `repeated_planner_mistake` / `repeated_browser_finding` / `repeated_privilege_opportunity` / `repeated_credential_outcome` / `none` (reserved, forward-compatible, never produced by this phase's own code) |
| `Experience` | `id`, `category`, `target`, `discriminator`, `context`, `evidence_excerpt`, `outcome`, `recommendation`, `confidence`, `occurrence_count`, `first_seen`, `last_seen` |
| `ReflectionSummary` | `target`, `experiences_created`, `experiences_reused`, `replay_hits`, `repeated_failures`, `improved_recommendations` |

`discriminator` is the raw value distinguishing this experience from others
in the same category for the same target — a workflow key
(`"credential_to_privesc"`), a `"tool:phase"` pair (`"nmap:recon"`), an
opportunity category name (`"docker"`), or a protocol name (`"ssh"`). It is
stored explicitly as its own field rather than re-parsed out of the
human-readable `context` string — an earlier draft of this module tried
parsing `context` with `str.split("'")` to recover the workflow key for
graph linking, and that approach was deliberately abandoned before any test
was written: it coupled graph-linking logic to the exact wording of prose
text, which is exactly the kind of fragility this project's own conventions
(see `apex_host/graph_ids.py`'s discipline around canonical, explicit IDs)
warn against.

`Experience.confidence` reuses `OpportunityConfidence` (`none`/`low`/
`medium`/`high`) — the same discrete confidence bucket already used by
`PrivilegeOpportunity` and `WebOpportunity` — rather than introducing a
second confidence representation.

## 3. Reflection engine

`apex_host/planners/experience_replay.py::derive_experiences_from_engagement`
is the reflection engine. It is a pure function: `(target, subgraph,
final_state) -> list[Experience]`, called exactly once, at the end of an
engagement (see §5). It draws on five sources, each already the output of
an earlier phase's own reasoning layer — no new EKG scanning logic was
invented for this phase; the reflection engine composes what Phase 13/14/15
already derive:

| Source | Producer | Experience category |
|---|---|---|
| Workflow terminal status | `workflow_orchestration.derive_workflows_from_subgraph` (Phase 15) | `successful_workflow` (`completed`) / `failed_workflow` (`blocked`/`stalled`) / `abandoned_workflow` (`abandoned`) — `running` workflows are skipped (no terminal outcome yet) |
| Duplicate planner tasks | `final_state["duplicate_actions"]` (existing dispatcher fingerprint gate) | `repeated_planner_mistake`, one per distinct `(tool, phase)` pair |
| Recurring web findings | `web_opportunities.opportunities_from_subgraph` (Phase 14), grouped by category, threshold `count >= 2` | `repeated_browser_finding` |
| Recurring privilege-escalation opportunities | `priv_esc_opportunities.opportunities_from_subgraph` (Phase 13/13B), grouped by category, threshold `count >= 2` | `repeated_privilege_opportunity` |
| Failed credential validations | `final_state["credential_validation_log"]` (Phase 12B), successes skipped | `repeated_credential_outcome`, one per protocol |

"What worked / what failed / repeated failures / duplicated actions" (the
task brief's own phrasing) map directly onto this table: successful
workflows are "what worked"; failed/abandoned workflows and repeated
credential failures are "what failed" / "repeated failures"; duplicate
planner tasks are "duplicated actions" / "planner inefficiencies"; recurring
web/priv-esc findings are "missed opportunities" (a category that keeps
turning up and was never acted on is exactly that). "Unnecessary retries"
is covered by the same `repeated_planner_mistake` signal — a retried task
the dispatcher's own duplicate-fingerprint gate already caught.

No LLM call, no randomness, and no I/O occurs anywhere in this function —
consistent with the blackboard model (memfabric Invariant 7) and this
project's "pure reasoning helper" convention.

## 4. Replay algorithm

"Retrieve previous experiences, rank them deterministically, attach them to
planner context" (the task brief's own three steps) map onto three
functions:

1. **Retrieve** — `experiences_from_subgraph(subgraph)` reconstructs every
   `Experience` from `experience`-typed EKG nodes already in the subgraph a
   planner (or the reflection engine's *own next run*) already has. There is
   no separate experience store — the EKG node **is** the experience record
   (memfabric Invariant 1: no second, independent store).

2. **Rank** — `rank_experiences(experiences)`: sort key
   `(-confidence.as_float(), category_priority, id)` — confidence
   descending first, then a fixed category-priority tie-break
   (`repeated_privilege_opportunity` > `failed_workflow` >
   `repeated_credential_outcome` > `repeated_planner_mistake` >
   `repeated_browser_finding` > `successful_workflow` > `abandoned_workflow`),
   then experience ID ascending as the final, fully deterministic
   tie-break. Never random, never insertion-order-dependent — the same
   input list produces the same ranked output every time.

3. **Attach to planner context** — by writing `experience`/
   `experience_recommendation` nodes into the SAME EKG subgraph every
   planner already reads (anchored to `host` via an `indicates` edge, like
   every other Phase 13/14/15 record). A planner that wants to consult
   experiences can call `experiences_from_subgraph(subgraph)` itself — but,
   critically, **no planner in this codebase does so** (see §7). "Attach to
   planner context" is satisfied structurally (the data is reachable from
   the shared subgraph), not by wiring a new call into any planner's
   decision path.

### The replay mechanism itself: content-addressed upsert, not a remembered object

There is no cache, no session object, no in-memory "remembered experience"
carried between engagements. Replay works because `experience_id(target,
category, discriminator)` is a stable, content-addressed ID
(`apex_host/graph_ids.py`) — re-deriving the *same* experience on a later
engagement (sharing the same `MemoryAPI`/EKG) always computes the same ID.
`_make_experience()` looks up that ID in the current subgraph's existing
experiences; if found, it increments `occurrence_count` and recomputes
confidence via `apply_learning_rule()`; if not found, it starts fresh at
`occurrence_count=1`. This is the entire replay mechanism — verified
directly by `TestReplayAndDuplicatePrevention.test_replay_increments_occurrence_count_and_adjusts_confidence`
and, end-to-end through the real `ApexRuntime`, by running the same
dry-run engagement twice against the same runtime instance (see §9).

## 5. Learning rules — the fixed confidence-adjustment table

`apply_learning_rule(category, occurrence_count, base_confidence)`:

```python
if occurrence_count <= 1:
    return base_confidence          # first observation — nothing to adjust yet
steps = occurrence_count - 1
score = base_confidence.as_float()
if category in _REINFORCE_UP:       # repeated_planner_mistake, repeated_privilege_opportunity, successful_workflow
    score = min(1.0, score + 0.15 * steps)
elif category in _REINFORCE_DOWN:   # repeated_browser_finding, repeated_credential_outcome, failed_workflow, abandoned_workflow
    score = max(0.0, score - 0.15 * steps)
return OpportunityConfidence.from_score(score)
```

The task brief's own four examples map directly onto this table:

| Rule | Category | Direction |
|---|---|---|
| "Repeated duplicate task → recommend avoiding it" | `repeated_planner_mistake` | up — a persistently duplicated planner action is a *stronger*, more confidently-worth-flagging signal the more it recurs |
| "Repeated dead-end browser path → reduce priority" | `repeated_browser_finding` | down — a browser-discovery category that keeps turning up without ever converting into a validated finding is "already known, diminishing returns" |
| "Repeated privilege opportunity → increase priority" | `repeated_privilege_opportunity` | up — a recurring privilege-escalation signal is treated as more reliable/valuable, not less |
| "Repeated failed credential validation → lower recommendation confidence" | `repeated_credential_outcome` | down — a credential/protocol combination that keeps failing is progressively less worth retrying |

`successful_workflow`/`failed_workflow`/`abandoned_workflow` extend the same
two-directional table by the same reasoning: a workflow that keeps
succeeding is a more reliably reproducible path (up); a workflow that keeps
failing or getting abandoned is progressively less worth relying on (down).

`0.15` per repetition step is a fixed constant, never a fitted/learned
parameter — the same convention as memfabric's own Reflector
`decay_factor`/`skill_prior` config constants (`memfabric/config.py`).

## 6. Reflection pass timing — once per engagement, not once per turn

This is a **deliberate departure** from Phase 14/15's own convention.
`web_session_state`/`workflow_summary` are refreshed on the live
`ApexGraphState` **every turn** (Phase 14's `browser_agent` node, Phase
15's `reflect_or_continue` node respectively). `learning_summary` is
populated **exactly once**, in `apex_host.runtime.ApexRuntime.run()`,
immediately after `graph.ainvoke()` returns and immediately after
memfabric's own `ReflectorWorker.run_once()` pass — mirroring that
Reflector's own once-per-engagement timing, not the per-turn refresh
pattern.

This matches the task brief's own instruction verbatim: "Implement a
deterministic reflection pass executed **at the end of every engagement**."
A mid-engagement reflection pass would also be premature — workflow
terminal status (`successful_workflow`/`failed_workflow`/`abandoned_workflow`)
is only meaningful once the engagement's real `completed`/`outcome` values
are known, exactly the same reasoning `report.py` already applies when
deriving Phase 15's workflow summary from the *final* subgraph rather than
the live, one-turn-stale state snapshot.

```python
# apex_host/runtime.py — ApexRuntime.run(), after the memfabric Reflector pass
subgraph = await self.api.get_subgraph(host_id(self.config.target), depth=2)
experiences_before = experiences_from_subgraph(subgraph)
experiences_after = derive_experiences_from_engagement(self.config.target, subgraph, dict(final_state))
known_node_ids = {node.id for node in subgraph.nodes}
nodes, edges = build_experience_graph_deltas(self.config.target, experiences_after, known_node_ids=known_node_ids)
if nodes or edges:
    await self.api.apply_deltas(nodes=nodes, edges=edges)
summary = reflection_summary(self.config.target, experiences_before, experiences_after)
final_state["learning_summary"] = {...}
```

Wrapped in its own `try/except` — a failure here is logged and never masks
the engagement's own result, the same graceful-degradation discipline
already applied to the memfabric Reflector call immediately above it.

## 7. No automatic planner override

This is the single most important safety property of this phase, and it is
enforced two ways:

1. **Static scan** — none of `recon_planner.py`, `web_planner.py`,
   `browser_planner.py`, `credential_planner.py`, `priv_esc_planner.py`, or
   `global_planner.py` import `experience_replay` anywhere
   (`TestNoAutomaticPlannerOverride.test_no_planner_file_imports_experience_replay`).
   `experience_replay.py` itself never imports a `*_planner.py` module
   either — it only reads pure reasoning-helper output
   (`priv_esc_opportunities`, `web_opportunities`, `workflow_orchestration`),
   never planner decision logic.

2. **Behavioral proof** — attaching `experience` nodes (even with a high
   `occurrence_count`) to a subgraph does not change what `GlobalPlanner`
   decides for the same `node_types_seen`/`turn_count` input
   (`test_experience_nodes_present_does_not_change_global_planner_output`).
   Experiences are additive EKG content; nothing reads them during planning.

Experiences are "attached to planner context" purely by being reachable
from the same host-anchored subgraph every planner already reads. A future
planner that wants to consult prior experiences can call
`experiences_from_subgraph(subgraph)` — the function exists and is tested
— but doing so is an explicit, deliberate choice a planner's own author
would have to make; it is never automatic.

## 8. Graph shape

```
host --indicates--> experience --recommends--> experience_recommendation
experience --indicates--> workflow   (only for successful_workflow / failed_workflow /
                                       abandoned_workflow experiences, and only when the
                                       referenced workflow node is confirmed present —
                                       see "known_node_ids" below)
```

No new edge types were needed — `indicates` (host → experience, experience
→ workflow) and `recommends` (experience → experience_recommendation, the
same edge type Phase 13B/15 already use for their own `*_recommendation`
nodes) were already generic enough to reuse, continuing the "reuse existing
edges, don't fragment the graph" discipline Phase 14 established.

The `host → experience` edge is load-bearing, not cosmetic: without it, an
`experience` node would be an orphan, invisible to
`MemoryAPI.get_subgraph()`'s bounded host-anchored traversal — the same
class of bug Phase 13/14/15 each hit and fixed for their own new node
types. This was verified directly (not just assumed) via a real end-to-end
dry-run engagement through `ApexRuntime.run()` during this phase's own
development (§9).

### `known_node_ids` — why the `experience → workflow` link is conditional

Unlike the `host`/`experience_recommendation` edges above, the `workflow`
node referenced by a `successful_workflow`/`failed_workflow`/
`abandoned_workflow` experience is **not** part of the same
`apply_deltas()` batch as the experience nodes — Phase 15's own
`reflect_or_continue` sync writes `workflow` nodes independently, on every
turn, not as part of this phase's reflection pass. Linking to it
unconditionally would risk `MemoryAPI.put_edge()`'s dangling-edge
validation (P8-I05) raising `ValueError` if, for any reason, that workflow
node was never actually persisted (e.g. a test fixture, or a target whose
engagement never reached that workflow's prerequisites).

`build_experience_graph_deltas(target, experiences, known_node_ids=None)`
resolves this the same way Phase 8 established for dangling-edge
prevention generally: the cross-batch link edge is only added when
`known_node_ids` is supplied AND the target workflow node's ID is actually
present in that set. `ApexRuntime.run()` passes the caller's own
already-fetched subgraph node-id set. When omitted (the default), the edge
is simply skipped — safe by construction, never a partial-batch failure.

Every `experience`/`experience_recommendation` node ID is content-addressed
(`target`+`category`+`discriminator` — never on `occurrence_count`/
`confidence`), so re-deriving and re-persisting the same experience on a
later engagement upserts the same nodes rather than creating duplicates —
verified directly by
`test_duplicate_experience_prevention_via_apply_deltas` (three reflection
passes against the same `MemoryAPI` produce exactly one `experience` node
with `occurrence_count == 3`).

## 9. Memory integration

- All writes go through `MemoryAPI.apply_deltas()` — a single, transactional
  batch (memfabric Invariant 1). A failure partway through (e.g. a dangling
  edge) rolls back every node/edge from that batch — verified by
  `TestTransactionRollback` (a deliberately dangling edge causes the entire
  batch, including the otherwise-valid `experience` node, to roll back; a
  second, separately-broken batch never corrupts or removes an
  already-persisted experience from an earlier, successful batch).
- Deduplication is structural, not a separate dedup pass: content-addressed
  IDs mean there is nothing to deduplicate — re-deriving identical input
  always upserts the same node.
- Evidence links: every experience's `evidence_excerpt` is bounded to 200
  characters (`_MAX_EXCERPT_CHARS`) and is always a short, human-readable
  summary (a status string, a count, an error category) — never a secret,
  never a full command transcript. Credential-outcome experiences read
  `error_category` (already a fixed, small enum-like string per Phase 12B),
  never the raw password or session text.
- Real end-to-end verification (not just unit tests against synthetic
  subgraphs) was performed by running a full dry-run engagement twice
  through the actual `ApexRuntime.run()` against the same `MemoryAPI`
  instance:
  - First run: one `repeated_planner_mistake` experience created
    (`occurrence_count=1`), `learning_summary = {experiences_created: 1,
    experiences_reused: 0, replay_hits: 0, ...}`.
  - Second run (same runtime, same target): the SAME experience node
    (same ID) is found, `occurrence_count` becomes `2`, confidence steps
    up accordingly, and `learning_summary = {experiences_created: 0,
    experiences_reused: 1, replay_hits: 1, ...}` — proving the replay path
    works through the real production entry point, not only through direct
    calls to `experience_replay.py`'s functions.

## 10. Reporting

`RunReport` gains a "Learning Summary" section, shown only when at least
one experience exists:

```
Learning Summary
  Experiences          : 1 (repeated_planner_mistake=1)
  Reflection pass      : created=1 reused=0 replay_hits=0 repeated_failures=0
  Recommendations:
    tool 'nmap' re-planned in phase 'recon' after already completing; recommend avoiding this duplicate action in future engagements.
```

| Field | Derivation |
|---|---|
| `learning_experience_count` / `learning_experience_categories` | `rank_experiences(experiences_from_subgraph(final_subgraph))` — re-derived from the FINAL EKG, same convention as every other Phase 13/14/15 report section |
| `learning_recommendations` | Up to 5 advisory strings from the highest-ranked experiences |
| `learning_experiences_created` / `learning_experiences_reused` / `learning_replay_hits` / `learning_repeated_failures` | Read from `final_state["learning_summary"]` — the ONE deliberate exception to "always re-derive from the final EKG" (see §11) |

`to_json_dict()` gains a `"learning"` block with the same fields.

## 11. Why created/reused/replay_hits cannot be re-derived from the final EKG alone

Every other Phase 13/14/15/16 report field is re-derived directly from the
final subgraph, on principle — the live per-turn state snapshot
(`web_session_state`, `workflow_summary`) is documented as
possibly-one-turn-stale, and the report always prefers a fresh read. This
principle *cannot* apply to "created vs. reused" counts: a final EKG
snapshot only shows the current `occurrence_count` per experience — it
cannot tell you, after the fact, whether *this specific engagement's*
reflection pass was the one that created the node or the one that merely
incremented an already-existing counter. That distinction only exists at
the moment the reflection pass runs (comparing its own "before" snapshot,
taken at the start of the pass, against its "after" output).

`ReflectionSummary` captures exactly this point-in-time delta, computed
once by `reflection_summary()` inside the reflection pass itself and
threaded through via `final_state["learning_summary"]`. This is the same
documented exception class already established for Phase 13B's
`enum_duplicate_opportunities_avoided` (a duplicate-skipped command
produces no EKG node at all, so it can only be counted at the moment it is
skipped) — a single post-hoc EKG snapshot structurally cannot recover this
kind of delta, so an explicit, narrow exception is made rather than forcing
a false "always re-derive" purity.

## 12. Current limitations

- **Five fixed reflection sources.** The reflection engine only derives
  experiences from workflow terminal status, duplicate planner tasks,
  recurring web/priv-esc opportunity categories, and failed credential
  outcomes — the exact five sources the task brief's own examples name.
  Adding a new experience source means adding a new block to
  `derive_experiences_from_engagement`, not a configuration change.
- **`ExperienceCategory.none` is never produced by this phase's own code.**
  Reserved for forward compatibility, mirroring `OpportunityCategory.none`
  and `EngagementOutcome.goal_completed`'s own "documented but not yet
  reachable" precedent.
- **`0.15` confidence step is a single fixed constant** for every
  reinforce-up/reinforce-down category — there is no per-category tuning.
  A future phase could introduce per-category step sizes if experience
  shows one category's signal should reinforce faster/slower than another's,
  but this phase deliberately keeps the table as simple and auditable as
  possible.
- **No cross-target generalization.** Experience IDs are scoped to
  `target` — an experience learned against one HTB machine's IP is never
  automatically applied to a different target's engagement. This mirrors
  CLAUDE.md §13.8/§13.9's standing prohibition on machine-specific
  behavior: nothing in this phase makes a target-specific shortcut look
  like general knowledge.
- **`learning_summary`'s "before" snapshot is taken from a shallow (`depth=2`)
  subgraph read**, matching the depth already used for the memfabric
  Reflector's own context in `ApexRuntime.run()` — sufficient for every
  experience source used in this phase (none require deeper traversal), but
  a future experience source reasoning over more distant EKG relationships
  would need this depth revisited.
- **No new live command execution, no exploit, no payload, no persistence,
  no flag capture was added or performed.** `access_state` remains the
  engagement's only success signal; this phase adds a reflective,
  cross-engagement advisory layer over already-existing planning data,
  nothing more.
