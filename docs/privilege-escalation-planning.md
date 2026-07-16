# Privilege Escalation Planning Framework (Phase 13)

**Status:** implemented. Covers the opportunity model, the rewritten
`PrivEscPlanner`, the zero-network analytical executor, duplicate
prevention and exhaustion logic, and `RunReport`'s privilege escalation
summary.

## 1. What this is — and is not

This is a **planning framework**, not privilege escalation. It gives the
`priv_esc` phase the ability to organize enumeration, reason about
opportunities, avoid duplicate work, determine when it has run out of safe
things to do, and report its findings clearly. It never executes an
exploit, never escalates privileges, never generates a payload, and never
performs privilege escalation of any kind.

Before this phase, `PrivEscPlanner` did exactly one thing: run
`searchsploit <service> <version>` against up to three services with a
known version string, every single turn, with no memory of what it had
already searched. The `TaskDispatcher`'s generic duplicate-fingerprint gate
silently absorbed the repeats, so the phase eventually terminated via the
Phase 12C stall detector (`duplicate_task_stall`) — but only after wasting
turns on noise, and with nothing structured to show for it. Phase 13 fixes
both problems: the planner now tracks what it has already investigated
directly in the EKG, and every investigation — successful or not — becomes
a structured, reportable `PrivilegeOpportunity` record.

## 2. Scope boundary — no new live enumeration against the target

The task brief's example enumeration list (sudo configuration, mounted
filesystems, capabilities, SUID inventory, scheduled jobs, kernel version,
OS metadata) describes the kind of information a human operator would
gather after gaining a shell. This phase does **not** add a new mechanism
to run those commands against the target. That was a deliberate,
considered decision, not an oversight:

- The only way APEX could run `sudo -l`, `find / -perm -4000`, `mount`, or
  similar commands would be to open a new authenticated session (SSH) and
  execute them — a materially new, security-sensitive execution surface,
  distinct from and riskier than Phase 12B's already-audited
  `SSHExecutor`/`FTPExecutor`, which are scoped narrowly to exactly one
  fixed, harmless identity command (`id`/`whoami`) for the sole purpose of
  *validating* a credential, not investigating the system afterward.
- The task brief itself frames this phase as "NOT privilege escalation"
  and lists a long, explicit set of things not to add (exploit payloads,
  reverse shells, Metasploit integration, ...). Building a new
  general-purpose remote-command-execution channel — even for read-only
  commands — sits materially closer to that boundary than the planning
  framework the brief actually asks for.
- Reusing the **existing, already-safe** mechanisms — `searchsploit` (a
  local exploit-db title lookup with zero target interaction, unchanged
  since before this phase) and **analytical derivation** (reasoning over
  data earlier phases already captured, with zero new tool execution) —
  fully satisfies "organizing enumeration, reasoning about opportunities,
  avoiding duplicate work, determining exhaustion, reporting findings"
  without expanding what APEX is capable of doing to a live target.

Categories that would require new live enumeration (`sudo`, `suid`,
`capabilities`, `cron`, `writable_service`, `path_issue`,
`mounted_filesystem`, `scheduled_task`, `windows_service`, `registry`,
`startup_item`) are fully modeled, ranked, deduplicated, and reportable —
`OpportunityCategory` defines all of them — but only `sudo` and `docker`
are ever populated by this phase's own analytical derivation, and only
when reliable existing evidence supports them (see §5). The rest exist as
forward-compatible planning labels, exactly as the task brief itself
frames them ("These are planning labels only").

## 3. The opportunity model (`apex_host/types.py`)

| Type | Purpose |
|---|---|
| `OpportunityCategory` | `str, Enum` — 16 members: the 14 suggested by the brief, plus `vulnerable_service` (searchsploit hits) and `none` (searched, nothing found) |
| `OpportunityConfidence` | `str, Enum` — `none`/`low`/`medium`/`high`, with `as_float()`/`from_score()` for deterministic ranking |
| `PrivilegeEnumerationStatus` | `str, Enum` — `not_started`/`running`/`opportunities_found`/`exhausted`/`elevated_access_validated` (the last is a documented, currently-unreachable future capability — see §7) |
| `PrivilegeOpportunityEvidence` | `source`, `supporting_node_ids`, bounded `excerpt` (≤200 chars, titles/labels only — never exploit code), `timestamp` |
| `PrivilegeOpportunity` | `id`, `category`, `confidence`, `evidence`, `description`, `recommended_next_action`, `attempted`, `attempt_count`, `exhausted`, `first_seen`, `last_seen` |
| `PrivilegeEscalationState` | A snapshot view over all opportunities for one target — `opportunity_count`/`attempted_count`/`exhausted_count`/`remaining_count`/`categories`/`enumeration_complete` |

`recommended_next_action` is always **advisory text for a human operator**
— e.g. *"Manually run 'sudo -l' via an interactive authorized session to
enumerate configured sudo rules"* — never an executable command string
APEX itself would run.

## 4. EKG representation

Opportunities are stored as `priv_esc_opportunity` nodes (memfabric
Invariant 1 — the dataclass above is a *view* reconstructed from these
nodes, never a second, independent store):

| Node type | Meaning | Key props |
|---|---|---|
| `priv_esc_opportunity` | A non-executable planning record | `category`, `confidence`, `description`, `recommended_next_action`, `attempted`, `attempt_count`, `exhausted`, `source_tool` |

| Edge type | Meaning |
|---|---|
| `indicates` | `host`/`access_state` → `priv_esc_opportunity` — the evidence that produced the opportunity |

Every `priv_esc_opportunity` node has an `indicates` edge linking it back
into the host-anchored subgraph — **this is load-bearing, not cosmetic**.
An orphaned opportunity node (no edge to the anchor) would be invisible to
`MemoryAPI.get_subgraph()`'s bounded traversal, which would silently break
both the planner's own duplicate-prevention check and the report's
opportunity count. This was caught and fixed during this phase's own
manual end-to-end verification (see §9) — the first implementation linked
only analytical opportunities to their source `access_state` node and left
searchsploit-sourced opportunities unlinked; the fix links those to the
`host` node instead.

IDs are built by `apex_host/graph_ids.py::priv_esc_opportunity_id(target,
category, discriminator)` — e.g.
`priv_esc_opportunity:10.10.10.14:vulnerable_service:vsftpd-2-3-4` or
`priv_esc_opportunity:10.10.10.14:sudo:sudo-group-root` — stable and
dedup-safe: the same service+version or the same user+category always
produces the same ID.

## 5. Two safe opportunity sources

### 5.1 `searchsploit` (unchanged mechanism, now opportunity-aware)

`PrivEscPlanner` still finds services with a known version string (via the
existing `capabilities_from_subgraph`/`exploit_research` capability) and
queries `searchsploit <service> <version>` — a local exploit-db title
search on the APEX machine, zero network traffic to the target. What
changed: the result is now parsed into a `priv_esc_opportunity` node
(`apex_host/parsers/priv_esc_parser.py::parse_searchsploit`) instead of a
generic, unstructured `KnowledgeEntry` staging blob:

- **Hits found** → `category=vulnerable_service`, confidence `medium`
  (1–2 hits) or `high` (3+), `description` states the hit count,
  `evidence_excerpt` holds up to 5 exploit-db **titles** (never
  proof-of-concept code — searchsploit's own output format is
  `title | path`, nothing more).
- **No hits** → `category=none`, `confidence=none`. The node still records
  the attempt so the planner never re-searches the same service/version.
- Both cases set `exhausted=True` immediately — a local database lookup is
  a one-shot action; there is nothing further APEX can safely do for that
  specific opportunity.

### 5.2 Analytical derivation (new — zero network, zero subprocess)

`apex_host/planners/priv_esc_opportunities.py::derive_analytical_opportunities`
reasons over EKG data **already captured by earlier phases** — no new tool
execution, no target interaction of any kind. It currently mines
`access_state` node evidence — the redacted `id` command output captured
during Phase 12B SSH credential validation (`response_summary`, stored in
the node's `evidence`/`proof` props) — for two well-known group-membership
escalation hints:

| Group | Category | Confidence | Why |
|---|---|---|---|
| `docker` | `docker` | `high` | A well-documented, reliable escalation vector (container mount escape) |
| `sudo`/`wheel`/`admin` | `sudo` | `medium` | Group membership alone doesn't guarantee passwordless or unrestricted sudo rules — a human must still verify |

**Deliberately does not attempt** kernel-version, SUID, cron, capabilities,
or any other category analytically: none of those have a reliable existing
EKG data source without new live enumeration (see §2). Inventing a
heuristic without real supporting data would produce false "opportunities"
— worse than reporting nothing.

### 5.3 The zero-network analytical executor

Per the blackboard model (memfabric Invariant 7), a planner may only return
`TaskSpec`s — it cannot write to `MemoryAPI` directly. Since analytical
derivation happens inside the planner (which has subgraph access), a
minimal bridge executor was needed: `PrivEscAnalysisExecutor`
(`apex_host/agents/priv_esc_analysis_executor.py`). It performs **no I/O
of any kind** — it takes the planner's already-computed fields (passed
verbatim in `task.params`) and echoes them into an `Episode`, which then
flows through the same `parse_observation` → `MemoryAPI.apply_deltas` path
every other tool result uses. Routed by `TaskDispatcher` via the synthetic
tool name `priv_esc_analyze`, exactly like `telnet_access`/`ssh_access`/
`ftp_access` route to their own dedicated executors.

A dedicated policy rule, `check_bounded_priv_esc_enumeration`
(`apex_host/policy/rules.py`), gives both `searchsploit` and
`priv_esc_analyze` an explicit, named "approved" audit-trail entry — for
transparency, not because either tool would otherwise be blocked (both
already pass the existing default-allow fallthrough).

## 6. Duplicate prevention and exhaustion

Before emitting any task, `_PrivEscDeterministic.plan()`
(`apex_host/planners/priv_esc_planner.py`) reconstructs every already-
recorded opportunity from the subgraph
(`opportunities_from_subgraph`) and skips any candidate whose computed
opportunity ID already exists — bounded to exactly **one attempt per
opportunity**, mirroring `CredentialPlanner`'s per-protocol one-attempt
invariant (Phase 12B). Concretely:

- A searchsploit candidate is skipped if either a `vulnerable_service` or a
  `none` node already exists for that exact service+version.
- An analytical candidate is skipped if a node already exists for that
  exact category+username.

Up to 3 new candidates are emitted per turn (analytical candidates first,
then searchsploit — both zero-risk, but analytical is strictly cheaper),
ranked deterministically by `rank_opportunities()`: confidence descending,
then a fixed category-priority tie-break, then opportunity ID — never
insertion order, never random.

Once every enumerable candidate has already been recorded, the planner
returns an explicit `AbandonSignal`:

> *"privilege-escalation enumeration exhausted: all discovered
> opportunities have already been recorded; no further safe enumeration
> remains"*

This is the framework's own, deliberate "no additional useful enumeration
remains" signal — distinct from the pre-Phase-13 behavior, where the same
outcome was only reached accidentally, several noisy turns later, via the
generic `TaskDispatcher` duplicate gate feeding the Phase 12C stall
detector. The two original abandon messages (`"searchsploit not available
in allowed_tools"` and `"no enumerable service/version strings"`) are
preserved byte-for-byte for the cases they originally covered — this
change is additive, not a rewrite of existing, tested behavior.

## 7. Enumeration status

`PrivilegeEnumerationStatus` (`apex_host/types.py`) distinguishes:

| Status | Meaning |
|---|---|
| `not_started` | No `access_state` yet — `priv_esc` phase cannot meaningfully begin |
| `running` | `access_state` present, no opportunities recorded yet |
| `opportunities_found` | At least one non-exhausted opportunity remains |
| `exhausted` | Every recorded opportunity is exhausted — never true with zero opportunities recorded (that's `running`) |
| `elevated_access_validated` | **Future capability.** No code in this phase ever produces it — it would require APEX to itself validate an elevated shell, which is out of scope (this is a planning framework, not privilege escalation). Documented and defined for forward-compatibility, mirroring the precedent Phase 12C set with `EngagementOutcome.goal_completed`. |

`build_privilege_escalation_state()` (`apex_host/planners/priv_esc_opportunities.py`)
computes this deterministically from the subgraph — no I/O.

## 8. Graph state and reporting

### 8.1 `ApexGraphState` (additive fields)

| Field | Meaning |
|---|---|
| `privilege_state` | A `PrivilegeEnumerationStatus` value, refreshed on every `priv_esc_agent` turn |
| `privilege_summary` | `{opportunity_count, categories, attempted_count, exhausted_count, remaining_count}` |
| `opportunity_ids` | EKG node IDs of every recorded opportunity |
| `attempted_opportunities` | The subset already attempted |
| `enumeration_complete` | `True` once status is `exhausted` |

These are refreshed inside `make_priv_esc_node`
(`apex_host/orchestration/dispatch_node.py`) via a fresh subgraph read
*after* dispatch — mirroring the read-after-write "peek" pattern
`continuation_node.py` already uses, scoped only to the priv_esc agent so
other phases are unaffected. **Known ordering limitation:** because this
refresh happens before `parse_observation`/`write_memory` run for the same
turn, the state snapshot always reflects the EKG as it stood at the
*start* of the current turn — one turn stale relative to that turn's own
newly-recorded opportunities. This is acceptable for a live, in-engagement
view (the next turn's refresh catches up), but it is **not** used for the
final report — see §8.2.

### 8.2 `RunReport` (Phase 13 fields)

`RunReport` gains `privilege_state`, `privilege_opportunity_count`,
`privilege_categories`, `privilege_attempted_count`,
`privilege_exhausted_count`, `privilege_remaining_count`,
`privilege_enumeration_complete`, `privilege_recommendations`. Unlike the
live `ApexGraphState` fields, **every one of these is derived directly from
the final subgraph** at report-build time
(`rank_opportunities(opportunities_from_subgraph(subgraph))`), not from the
possibly-one-turn-stale state snapshot — the report always reflects the
complete, final EKG.

Text report section:

```
Privilege Escalation Summary
  Enumeration status : opportunities_found
  Opportunity count  : 3
  Categories         : docker=1, sudo=1, vulnerable_service=1
  Attempted          : 3
  Exhausted          : 1
  Remaining          : 2
  Enumeration done   : No
  Recommendations:
    Manually verify docker-group container-mount-escape escalation per standard methodology...
    Manually run 'sudo -l' via an interactive authorized session...
```

Shown only when at least one opportunity exists in the final EKG — a
target that never reached `priv_esc`, or reached it with nothing to find,
shows nothing here (same convention as every other conditional section in
this report).

JSON report gains a `"privilege_escalation"` block with the same fields.

## 9. Real end-to-end verification performed

A manual synthetic engagement (seeded `host` + a versioned `ftp` service +
an `access_state` node whose evidence text included `docker`/`sudo` group
membership) was run through the real compiled graph in dry-run mode. This
surfaced and fixed a genuine bug: the first implementation left
searchsploit-sourced opportunity nodes with no edge back into the graph,
making them invisible to both the planner's own dedup check and the
report's opportunity count (`opportunities_from_subgraph` only sees nodes
reachable by `get_subgraph()`'s bounded traversal from the `host` anchor).
Fixed by adding a `host → priv_esc_opportunity` `indicates` edge for the
searchsploit path (analytical opportunities already had one, since they
link from their source `access_state` node). Re-verified after the fix:
all three opportunities (docker, sudo, and the searchsploit result)
appeared correctly in both the EKG traversal and the rendered report, with
accurate counts, categories, and non-exhausted recommendations.

## 10. Current limitations

- **No new live enumeration against the target.** See §2 — a deliberate,
  documented scope boundary, not an oversight.
- **Analytical derivation covers exactly two categories** (`docker`,
  `sudo`) — the only ones with a reliable existing EKG data source. The
  remaining 12 suggested categories are fully modeled (taxonomy, ranking,
  deduplication, reporting) but never populated by this phase's own code.
- **`ApexGraphState`'s live privilege fields are one turn stale** relative
  to the same turn's own new opportunities (see §8.1). The final report is
  not affected — it always reads the complete final EKG directly.
- **`elevated_access_validated` is unreachable by design** (§7) — a future
  capability, not a bug.
- **No new live command execution, no persistent session, no privilege
  escalation of any kind was added or performed.** `access_state` remains
  the engagement's only success signal; this phase adds reasoning and
  reporting around what to investigate next, never the investigation
  itself beyond the two already-safe mechanisms in §5.
