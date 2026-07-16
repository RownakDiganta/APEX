# Safe Privilege Enumeration & Evidence Collection (Phase 13B)

**Status:** implemented. Extends the Phase 13A planning framework
(`docs/privilege-escalation-planning.md`) with a bounded, read-only
enumeration capability, a structured evidence model, deterministic
fact-extraction parsers, and an enumeration-aware reporting section.

## 1. What this is — and is not

Phase 13A gave the `priv_esc` phase a planning framework: it could reason
about opportunities discovered incidentally (a versioned service, group
membership visible in an already-captured `id` output) but it never ran a
single new command against the target. Phase 13B lifts that specific,
narrow boundary — and only that boundary — by adding a small, fixed set of
**harmless, read-only enumeration commands** executed over the *same*
already-validated SSH session Phase 12B's `SSHExecutor` uses to prove a
credential works.

This is still **not** privilege escalation. Nothing in this phase:

- executes an exploit,
- performs privilege escalation of any kind,
- generates a payload or reverse shell,
- uses Metasploit or any exploitation framework,
- uploads or downloads a file,
- captures a flag,
- establishes persistence,
- writes anything to the target filesystem, service configuration, cron
  table, or sudoers file.

Every command in the fixed allowlist (`ENUM_COMMANDS`) is read-only. The
result of running one is a structured `PrivilegeEvidence` record and, where
the facts justify it, a `PrivilegeOpportunity` record — both are EKG data
for a human operator to review, never a step APEX itself takes further.

## 2. Supported enumeration

### Linux (executed)

`apex_host/planners/priv_esc_opportunities.py::ENUM_COMMANDS` is the single,
shared source of truth for which commands exist and what each one runs —
both `PrivEscPlanner` (which command_keys may be planned) and
`PrivEscEnumExecutor` (which command string each key maps to) read the same
table, so they can never drift apart.

| `command_key` | Command run over SSH | Evidence category |
|---|---|---|
| `identity` | `id` | `identity` |
| `os_info` | `cat /etc/os-release` | `os_info` |
| `kernel_version` | `uname -a` | `kernel_version` |
| `sudo_l` | `sudo -n -l` | `sudo` |
| `suid` | `find / -xdev -perm -4000 -type f 2>/dev/null` | `suid` |
| `capabilities` | `getcap -r / 2>/dev/null` | `capabilities` |
| `mounts` | `mount` | `mounted_filesystem` |
| `cron` | `crontab -l 2>/dev/null` | `cron` |
| `service_info` | `systemctl list-units --type=service --no-pager 2>/dev/null` | `service_info` |

`sudo -n -l` uses `-n` (non-interactive) specifically so a missing/expired
sudo timestamp never blocks on a password prompt — it fails immediately and
harmlessly instead. `2>/dev/null` redirects in several commands discard
expected "permission denied" noise (e.g. from `find /` walking directories
the user cannot read) without affecting stdout.

### Windows (planning support only — never executed)

`apex_host/parsers/priv_esc_parser.py` also ships deterministic parsers for
`whoami /priv`, `whoami /groups`, `systeminfo`, service configuration,
scheduled tasks, and registry inspection output
(`parse_windows_privileges_output`, `parse_windows_groups_output`,
`parse_windows_systeminfo_output`, `parse_windows_service_output`,
`parse_windows_scheduled_task_output`, `parse_windows_registry_output`).
**No executor in this codebase ever runs a Windows enumeration command
live** — there is no WinRM/PSRemoting channel anywhere in `apex_host`. These
parsers exist so the evidence/opportunity model is complete and testable
today, and so a future Windows executor (should one ever be added) has a
parsing layer already waiting for it. Adding that executor is explicitly
out of scope for this phase.

### Why this reuses SSH instead of a new channel

`apex_host/tools/backend.py`'s `ToolBackend` (`DryRunToolBackend` /
`LocalToolBackend` / `RemoteToolBackend`) runs a *local* binary (`nmap`,
`curl`, ...) from the APEX/Kali machine *against* the network target — it
has no notion of "run this command inside an already-authenticated remote
shell." Enumeration commands like `sudo -n -l` only make sense executed
*on* the target, which requires the same kind of authenticated session
Phase 12B's `SSHExecutor` already established (and already reviewed for
safety). `PrivEscEnumExecutor` (`apex_host/agents/priv_esc_enum_executor.py`)
is that established, audited pattern, generalized from one fixed command
(`id`/`whoami`) to a small, fixed command set — not a new, more permissive
execution channel.

## 3. The evidence model

`apex_host/types.py`:

| Type | Purpose |
|---|---|
| `EvidenceCategory` | `str, Enum` — one member per supported command family (`identity`, `kernel_version`, `os_info`, `sudo`, `suid`, `capabilities`, `mounted_filesystem`, `cron`, `service_info`, plus six `windows_*` planning-support members) |
| `PrivilegeEvidence` | `id`, `category`, `source_command`, `confidence`, `extracted_facts` (a plain JSON-serialisable dict — never exploit code, never a payload, never a secret), `supporting_node_ids`, `raw_excerpt` (bounded, titles/labels only), `timestamp` |
| `PrivilegeEnumerationProgress` | A snapshot view — `commands_completed`, `commands_failed`, `commands_parsed`, `evidence_count`, `opportunities_created`, plus a `commands_attempted` property |

Evidence is stored in the EKG as a `priv_esc_evidence` node (see §5 for the
graph shape) — `PrivilegeEvidence` is a *view* reconstructed from that node,
never a second, independent store (memfabric Invariant 1).

A **failed** enumeration command (connection/auth/protocol failure — see
§7) never produces an evidence node at all: `parsing_node.py` checks the
tool result's own `error` field before calling `parse_enumeration()`, so a
real failure is tracked only through the existing `error_episodes`
mechanism, never as a misleading "evidence node with no output." A
**successful** command that legitimately produced no output (e.g. an empty
crontab) *does* still get an evidence node — confidence `none`, so the
planner still marks that command_key as done and never re-runs it.

## 4. Parsers (deterministic, no LLM)

`apex_host/parsers/priv_esc_parser.py` has one deterministic,
regex/line-based fact extractor per `EvidenceCategory`:

| Function | Extracts |
|---|---|
| `parse_sudo_output` | Configured sudo rules, `nopasswd`/`all_all` flags |
| `parse_suid_output` | SUID binary paths; flags a small, well-known GTFOBins-flavored subset as "interesting" (excluding a benign allowlist like `sudo`, `passwd`, `mount`) |
| `parse_capabilities_output` | Binary → capability-set entries; flags a fixed set of interesting capability names (`cap_setuid`, `cap_sys_admin`, ...) |
| `parse_mount_output` | Mounted filesystem entries; flags NFS mounts specifically |
| `parse_cron_output` | Non-comment cron job lines |
| `parse_identity_output` | Group membership; docker/sudo-group hints |
| `parse_kernel_output` | Kernel version string |
| `parse_os_info_output` | `/etc/os-release`/`hostnamectl` key:value facts |
| `parse_service_info_output` | Running `.service` unit lines |
| `parse_windows_*` (six functions) | Planning support only — see §2 |

Every extractor is bounded (`_MAX_LIST_ENTRIES = 50`) so a huge SUID or
capability listing on a real target cannot blow up the EKG, and every
extractor degrades gracefully on empty or malformed input (never raises —
returns zero counts/empty lists instead).

`PrivEscParser.parse_enumeration(stdout, *, target, category, command_key,
source_command, port="")` is the entry point that turns one command's
output into evidence + zero or more derived opportunity/recommendation
deltas — see §5.

## 5. Opportunity generation and graph shape

`_opportunities_from_facts()` (in `priv_esc_parser.py`) maps extracted
facts to zero or more candidate opportunities:

| Evidence | Condition | Opportunity produced |
|---|---|---|
| `sudo` | `nopasswd` or `all_all` rule present | `sudo` (confidence `high` if nopasswd, else `medium`) |
| `suid` | any GTFOBins-flavored interesting binary | one `suid` opportunity per interesting binary |
| `capabilities` | any interesting capability entry | one `capabilities` opportunity per entry |
| `mounted_filesystem` | any NFS mount detected | `mounted_filesystem` |
| `cron` | any cron job found | `cron` (confidence `low` — a job existing is not itself a finding) |
| `identity` | docker/sudo group membership | `docker` (`high`) / `sudo` (`medium`) |
| `kernel_version` / `os_info` / `service_info` | *(never)* | informational only — no opportunity is ever derived |

Discriminators for enumeration-sourced opportunities are namespaced with an
`enum-` prefix (`enum-sudo-rules`, `enum-suid-{path}`, `enum-docker-group`,
...) so they can **never collide** with Phase 13A's searchsploit/analytical
discriminator scheme, even when both describe a similar underlying signal
— e.g. docker-group membership can legitimately be recorded once from Phase
12B's `id`-output analytical path (13A) *and* once from this phase's own
dedicated `identity` enumeration command, as two independently-verified,
non-duplicate pieces of evidence.

### Graph relationships

```
host
 --collects-->  priv_esc_evidence
                priv_esc_evidence --produces--> priv_esc_opportunity
                                                  priv_esc_opportunity --recommends--> priv_esc_recommendation
```

| Node type | Meaning | Key props |
|---|---|---|
| `priv_esc_evidence` | One completed+parsed enumeration command | `category`, `source_command`, `command_key`, `confidence`, `extracted_facts`, `raw_excerpt` |
| `priv_esc_recommendation` | Advisory text for a human operator, one per opportunity | `text`, `category`, `priority`, `opportunity_id` |

| Edge type | Meaning |
|---|---|
| `collects` | `host` → `priv_esc_evidence` |
| `produces` | `priv_esc_evidence` → `priv_esc_opportunity` |
| `recommends` | `priv_esc_opportunity` → `priv_esc_recommendation` |

(`priv_esc_opportunity` and the `indicates` edge are unchanged from Phase
13A — see `docs/privilege-escalation-planning.md` §4.)

Every ID is built by a canonical function in `apex_host/graph_ids.py`:
`priv_esc_evidence_id(target, command_key, port="")`,
`priv_esc_recommendation_id(opportunity_id)`, plus the new edge-ID builders
`collects_edge_id`, `produces_edge_id`, `recommends_edge_id`. IDs are
content-addressed on `target` + `command_key` (never on raw output), so
re-running the same command produces the same evidence node ID —
`apply_deltas` upserts it rather than creating a duplicate.

## 6. `PrivEscEnumExecutor`

`apex_host/agents/priv_esc_enum_executor.py` mirrors
`apex_host/agents/ssh_executor.py`'s safety model exactly:

- **Fixed allowlist only.** A task selects a `command_key`; the actual
  command STRING run is always looked up from `ENUM_COMMANDS` — never
  built from free-form task params. An unrecognised `command_key` fails
  closed before any connection is attempted.
- **One command, one connection, per call.** Exactly one
  `SSHClient.connect()` and one `exec_command()` per `run()` — no looping
  across commands inside the executor.
- **No persistent session, no file transfer, no port forwarding.**
  `allow_agent=False`, `look_for_keys=False`, no `pkey`/`key_filename`, no
  `open_sftp()`/`request_port_forward()`/`invoke_shell()` anywhere in this
  module, and the client is always closed in a `finally` block.
- **Dry-run (`config.dry_run=True`, the default) returns a synthetic,
  deliberately unremarkable result** — no network activity at all, and the
  synthetic stdout never fabricates an "interesting" finding (no NOPASSWD
  rule, no SUID hit), so a dry-run engagement never manufactures a
  privilege-escalation opportunity that didn't come from real enumeration.
- **Stateless across calls** (memfabric Invariant 6).
- **The password is never logged, stored in the episode, or included in
  any exception text.**
- Unlike `SSHExecutor`'s credential-validation path, a **non-zero exit
  status is not treated as a failure** here — several enumeration commands
  (`sudo -n -l` without configured rules, `find` skipping
  permission-denied entries) legitimately exit non-zero while still
  producing safe, useful stdout. Only a genuine connection/authentication/
  protocol failure is a real failure.

Host-key strategy is identical to `SSHExecutor` — see that module's
docstring for the full trust-on-first-use rationale.

## 7. Enumeration state — completed, failed, parsed, evidence, opportunities

`apex_host/planners/priv_esc_opportunities.py`:

- `already_run_commands(subgraph) -> set[str]` — the set of `command_key`
  values already recorded as `priv_esc_evidence` nodes. `PrivEscPlanner`
  never re-emits a task for a `command_key` already in this set, whether or
  not the command produced an opportunity — a completed enumeration
  command is never repeated (see §8).
- `evidence_from_subgraph(subgraph) -> list[PrivilegeEvidence]` —
  reconstructs the full evidence set from the EKG.
- `build_enumeration_progress(target, subgraph, *, failed_commands=0) ->
  PrivilegeEnumerationProgress` — `commands_completed`/`commands_parsed`/
  `evidence_count` are all derived from evidence-node count (this parser
  only ever creates an evidence node once a command has both completed AND
  been parsed); `failed_commands` must be supplied by the caller since a
  failed command produces no EKG node at all (§3) — it is tracked instead
  via `error_episodes`.

`privilege_state_fields()` (also in that module) folds these counters into
`ApexGraphState["privilege_summary"]` alongside the Phase 13A opportunity
counts, refreshed on every `priv_esc_agent` turn (same one-turn-stale
caveat documented in Phase 13A — the final report always re-derives from
the complete final EKG instead, never from this live snapshot).

## 8. Planner integration — bounded, ordered, deduplicated

`_PrivEscDeterministic` (in `apex_host/planners/priv_esc_planner.py`) now
accepts optional `username_candidates`/`password_candidates` — the **same**
operator-supplied credentials already used (and already validated) in the
credential phase (Phase 12B). Enumeration never guesses, brute-forces, or
invents a credential of its own.

**Gating (all three must hold before any enumeration task is emitted):**

1. An `access_state` node with `service == "ssh"` already exists for this
   target — a real, successful SSH login was already proven.
2. `--username` and `--password` are configured.
3. At least one enumeration `command_key` has not already been recorded
   (`already_run_commands`).

**Ordering:** `_ENUM_COMMAND_ORDER` is fixed and deterministic — never
random, never based on discovery order:

```
identity, os_info, kernel_version,   # cheap, informational
sudo_l, suid, capabilities,          # higher-signal
mounts, cron, service_info           # remaining categories
```

Up to 3 enumeration tasks are emitted per turn (mirrors the existing
`_MAX_PRIV_ESC_TASKS` cap this phase already used for
analytical/searchsploit candidates in Phase 13A — enumeration tasks now
compete for, and are prioritized first within, that same bounded per-turn
budget). Once every command has been recorded, the planner falls through
to the unchanged Phase 13A analytical/searchsploit logic, and finally to
the "enumeration exhausted" `AbandonSignal` once nothing remains anywhere.

**Port selection:** the lowest-port `access_validate_ssh` capability if a
service node still exists, else the conventional default (`22`) — mirrors
`CredentialPlanner`'s own lowest-port selection.

**Distinct abandon messages** cover the three new conditions this phase
adds, without changing the wording of any pre-existing Phase 13A message:

- SSH access proven but no credentials configured: *"validated ssh access
  present but no credentials configured for enumeration; pass --username
  and --password to enable bounded read-only enumeration"*.
- Nothing left anywhere (enumeration, analytical, and searchsploit all
  exhausted): the existing Phase 13A "enumeration exhausted" message.

## 9. Dispatcher and policy wiring

`TaskDispatcher` (`apex_host/execution/dispatcher.py`) routes `tool ==
"priv_esc_enum"` to a dedicated `_run_priv_esc_enum()` method, exactly like
`ssh_access`/`ftp_access`/`priv_esc_analyze` route to their own dedicated
executors — never through the generic `run_command_fn`/`ToolBackend` path.

`apex_host/policy/rules.py::check_bounded_priv_esc_enumeration` (extended
from Phase 13A) now also covers `priv_esc_enum`, with one additional,
`priv_esc_enum`-specific check: the requested `command_key` must be in the
fixed allowlist `_PRIV_ESC_ENUM_COMMAND_KEYS` — a second, independent
defense-in-depth check on top of `PrivEscEnumExecutor`'s own identical
allowlist (both are sourced from the same
`priv_esc_opportunities.ENUM_COMMANDS` table). A task requesting an
unrecognised `command_key` is **blocked** at the policy boundary before it
ever reaches an executor or opens a connection.

## 10. Reporting

`RunReport` gains a Phase 13B "Privilege Enumeration Summary" section,
shown only when at least one enumeration command was ever attempted:

```
Privilege Enumeration Summary
  Commands executed  : 6 (failed: 0)
  Evidence collected : 6
  Evidence categories: cron=1, identity=1, kernel_version=1, mounts=1, os_info=1, sudo=1
  New opportunities  : 1
  Duplicates avoided : 0
  Enumeration done   : No
```

| Field | Derivation |
|---|---|
| `enum_commands_completed` / `enum_evidence_count` | `len(evidence_from_subgraph(final_subgraph))` |
| `enum_commands_failed` | Count of `error_episodes` entries whose `tool == "priv_esc_enum"` (a failed command produces no evidence node — §3) |
| `enum_evidence_categories` | Per-`EvidenceCategory` counts from the final subgraph |
| `enum_new_opportunities` | Opportunities whose `source_tool == "priv_esc_enum"` specifically (as opposed to Phase 13A's searchsploit/analytical producers) |
| `enum_duplicate_opportunities_avoided` | Count of `state["duplicate_actions"]` entries with `phase == "priv_esc"` — a real, observed count of tasks the dispatcher's fingerprint gate prevented from executing a second time |
| `enum_completeness` | `True` once every `ENUM_COMMANDS` key has a recorded evidence node for this target |

Like the Phase 13A privilege-escalation fields, every one of these (except
`enum_commands_failed`, which has no EKG representation to derive from) is
computed directly from the **final** subgraph at report-build time, never
from the possibly-one-turn-stale `ApexGraphState` snapshot. `to_json_dict()`
gains a `"privilege_enumeration"` block with the same fields.

## 11. Real end-to-end verification performed

A synthetic dry-run engagement (seeded `host` + an SSH `service` node +
an `access_state` node with `service="ssh"`, plus operator credentials)
was run through the real compiled graph. It produced `priv_esc_evidence`
nodes for the first three enumeration commands (`identity`, `os_info`,
`kernel_version` — the per-turn cap), correctly linked back to the `host`
node via `collects` edges, with no duplicate re-emission across repeated
turns.

## 12. Current limitations

- **Linux only, executed.** Windows parsers exist (§2) but no executor
  ever runs a Windows enumeration command live — there is no WinRM/
  PSRemoting channel in this codebase. Adding one is out of scope here.
- **Fixed, non-configurable command set.** `ENUM_COMMANDS` cannot be
  extended via CLI flag or config in this phase — every command is
  reviewed and hardcoded, by design (the allowlist itself is the safety
  boundary, both at the executor and at the policy layer).
- **One SSH connection per command.** Nine commands means up to nine
  separate bounded SSH sessions over the course of an engagement (three
  per turn, per the shared per-turn task cap) — this is deliberate
  (stateless executors, memfabric Invariant 6), not a missed optimization.
- **`enum_commands_failed` has no EKG representation.** A failed
  enumeration command produces no node at all (§3), so this count is
  derived from the generic `error_episodes` mechanism rather than from
  graph data, unlike every other field in the reporting section.
- **No SSH key-based enumeration.** Mirrors Phase 12B's own limitation —
  password authentication only; no key-reference model exists in the
  authorized configuration surface to extend.
- **No new live command execution beyond the fixed nine commands, no
  privilege escalation, no persistence, no payload of any kind was added
  or performed.** `access_state` remains the engagement's only success
  signal; this phase adds structured, read-only reconnaissance evidence
  and reasoning around it, nothing more.
