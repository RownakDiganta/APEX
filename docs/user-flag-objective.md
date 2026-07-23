# User Flag Objective and Verification (Phase 18)

**Status:** implemented. Covers the objective model, EKG representation,
bounded verification mechanism, planner/graph integration, verification
rules, redaction, engagement-outcome integration, CLI exit codes, dry-run
behavior, and tests.

## 1. Why this exists

Ali's confirmed benchmark success definition, in neutral project language:
**for the selected HTB benchmark, success means verified retrieval of the
user flag.** A foothold, a validated credential, a working shell, or an
`access_state` node in the EKG remains an important intermediate
milestone — but none of these may, by themselves, produce the engagement's
final successful outcome or CLI exit code `0`.

Before this phase, `apex_host.orchestration.outcome.EngagementOutcome
.validated_access` was the *only* success outcome: the moment an
`access_state` node appeared in the EKG (Phase 12B credential validation),
`reflect_or_continue` terminated the engagement as success. This
overstated what had actually been achieved — access to a machine is not
the same as proving you solved it. Phase 18 makes that distinction
explicit and load-bearing throughout the codebase:

```text
validated access != benchmark success
verified user flag == benchmark success
```

## 2. Access success vs. benchmark success

| Signal | What it proves | Is it benchmark success? |
|---|---|---|
| `access_state` node in the EKG | A credential was validated; a login/shell exists | **No** — an intermediate milestone |
| `credential_validation_log` entry with `success=True` | The same, from the audit log | **No** |
| `objective` node with `status="verified"` | The configured objective (default `user_flag`) was retrieved and cryptographically confirmed | **Yes** — the only success signal |

`EngagementOutcome.is_success_outcome()` returns `True` for exactly one
value: `EngagementOutcome.user_flag_verified`. `EngagementOutcome
.validated_access` remains a real enum member (used for reporting/
backward-compatible legacy-state fallback) but is classified as an
access-only, non-success outcome — its exit code changed from `0` to `1`
and its legacy status changed from `"success"` to `"abandoned"` (see §9).

## 3. Objective lifecycle

`apex_host.types.ObjectiveStatus` — four values, never collapsed into a
single Boolean:

```text
pending      — no objective node exists yet (implicit; never persisted as a prop)
in_progress  — at least one bounded candidate attempted, more remain, not yet verified
verified     — a candidate was read and passed the authoritative verifier — terminal, success
failed       — every bounded candidate was attempted without success — terminal for this objective, falls through to priv_esc
```

The full engagement lifecycle this phase adds (never one Boolean):

```text
reconnaissance
        -> vulnerability/evidence discovered (service, endpoint, auth_flow nodes)
        -> validated access (access_state node — Phase 12B)
        -> user-flag discovery attempted (objective node: pending -> in_progress)
        -> user flag verified (objective node: status="verified"; objective_evidence node created)
        -> engagement successful (EngagementOutcome.user_flag_verified)
```

## 4. EKG representation

Reuses the existing lowercase node/edge naming convention (CLAUDE.md
§12.8). Two new node types, two new edge types (one new edge type is
reused for host-reachability):

```text
access_state --enables--> objective --satisfied_by--> objective_evidence
host --indicates--> objective   (reachability — same discipline Phase 14/15/16
                                  established for their own opportunity/workflow/
                                  experience nodes; otherwise "objective" would sit
                                  3 hops from host and be invisible to the depth=2
                                  subgraph reads most orchestration nodes use)
```

| Node type | Meaning | Key props |
|---|---|---|
| `objective` | One engagement objective (content-addressed on target+objective_type — exactly one per target+type, upserted, never duplicated) | `objective_type`, `status`, `target`, `attempted_paths` (bounded list of candidate paths already tried), `attempt_count`. **Never a raw flag value.** |
| `objective_evidence` | Proof one objective was satisfied — created ONLY on a verified result | `evidence_type`, `verified` (always `True` — a failed attempt never creates this node type at all), `value_digest` (SHA-256 hex), `redacted_value` (short prefix/suffix display), `source_tool`, `source_path`, `access_identity`, `verification_method`, `confidence`, `evidence_timestamp`. **No plaintext field of any kind.** |

| Edge type | Meaning |
|---|---|
| `enables` | `access_state -> objective` — the semantic relationship: validated access enables pursuing the objective |
| `satisfied_by` | `objective -> objective_evidence` — the objective's proof |
| `indicates` (reused) | `host -> objective` — reachability, same discipline as Phase 14/15/16 |

ID builders (`apex_host/graph_ids.py`): `objective_id(target,
objective_type)`, `objective_evidence_id(target, objective_type,
discriminator)` (discriminator = the candidate path, slugged),
`enables_edge_id(from_id, to_id)`, `satisfied_by_edge_id(from_id, to_id)`.

**At most one `objective_evidence` node ever exists per target+objective_type**
— once verified, the engagement terminates immediately (§7), so no second
attempt is ever made.

**Failed attempts never create `objective_evidence`.** A failed read only
updates the `objective` node's `attempted_paths`/`attempt_count`/`status`
— per `apex_host/parsers/objective_parser.py::ObjectiveParser
.parse_user_flag_result`. A connection-level failure (SSH auth/connect
never succeeded — nothing learned about *this specific candidate*)
produces **no node update at all**, so the same candidate can legitimately
be retried on a later turn once the underlying session issue clears.

## 5. Global Planner routing

`apex_host.types.ApexPhase` gained a new member, `objective`, inserted
into the phase ladder between `credential` and `priv_esc`:

```text
recon -> web -> credential -> objective -> priv_esc -> done
```

`GlobalPlanner._select_phase()` (`apex_host/planners/global_planner.py`):

```python
if "access_state" not in node_types_seen:
    return credential
if objective_status == "verified":
    return done                    # terminal — NEVER routes through priv_esc afterward
if objective_status != "failed" and not objective_budget_exhausted:
    return objective                # the open, actively-pursued goal
if "service" in node_types_seen:
    return priv_esc                 # pre-existing intermediate-milestone phase, unchanged
return done
```

- **Access alone routes to `objective`, never to `done`.** This is the
  literal fix for "the Global Planner must route toward the unresolved
  user_flag objective instead of marking the engagement done."
- **Verified is terminal.** Once `objective_status == "verified"`, the
  engagement goes straight to `done` — it never dispatches `priv_esc_agent`
  afterward. "No further exploitation or privilege-escalation work is
  dispatched" is enforced structurally by this branch ordering, not by a
  runtime flag.
- **Failed or budget-exhausted falls through to `priv_esc`**, preserving
  the pre-existing intermediate-milestone phase and its own tests/behavior
  completely unchanged. `objective`'s own turn budget defaults to 4 (matches
  `credential`'s ceiling) — `ApexPhase.objective.value` was added to
  `GlobalPlanner._DEFAULT_PHASE_BUDGETS`.

`objective_status` is computed once per turn by the caller (`global_plan`
node and `reflect_or_continue`'s inter-turn peek) via
`apex_host.planners.objective.objective_status_from_subgraph()` and passed
in as a plain string — `decide_phase()` remains a pure function, matching
the existing `has_web_capability` parameter convention.

## 6. Bounded, read-only verification mechanism

**Preferred design, as implemented:** a dedicated structured operation,
`user_flag_verify`, routed through the existing dispatcher/policy/
tool-execution architecture exactly like the Phase 13B `priv_esc_enum`
precedent it mirrors. Since the **access-capability abstraction refactor**
(§16), the mechanism is transport-independent: the planner, executor, and
parser below all operate on a generic `AccessCapability` reference, never
on SSH (or any other transport) directly.

```text
apex_host/planners/objective_planner.py    -- emits ONE bounded TaskSpec per turn, selecting the best AccessCapability
apex_host/policy/rules.py                  -- check_bounded_user_flag_verification (defense in depth)
apex_host/execution/dispatcher.py          -- TaskDispatcher._run_user_flag_verify
apex_host/agents/user_flag_executor.py     -- UserFlagExecutor (registry lookup, bounded read, and the ONE verify_user_flag() call site)
apex_host/parsers/objective_parser.py      -- consumes the executor's already-computed verification result, builds EKG deltas
apex_host/runtime_registry.py              -- runtime-only capability_id -> adapter registry + the one concrete adapter (SSH)
apex_host/parsers/capability_parser.py     -- derives an access_capability EKG record from a validated login
apex_host/planners/access_capabilities.py  -- pure AccessCapability reconstruction/ranking helpers
```

### Why this reuses the SSH-session pattern, not `ToolBackend`

Reading a file *inside* an already-authenticated remote session is not
something `apex_host/tools/backend.py`'s `ToolBackend` (which runs a LOCAL
binary against the network target) has any concept of. The one concrete
adapter implemented today, `SSHCapabilityAdapter` (`apex_host/runtime_registry
.py`), reuses the exact SSH-session pattern already reviewed and tested
for `SSHExecutor` (Phase 12B) and `PrivEscEnumExecutor` (Phase 13B): one
`paramiko.SSHClient()` connection, one command, closed in a `finally`
block, `allow_agent=False`, `look_for_keys=False`, no SFTP, no port
forwarding, no persistent session. See §16 for the full abstraction design.

### Bounded candidate generation (`ObjectivePlanner`)

Candidates are built from two config-driven, small, documented lists —
never a machine-specific value:

- `ApexConfig.user_flag_candidate_filenames` — default `["user.txt"]`.
- `ApexConfig.user_flag_candidate_roots` — default `["/home/{username}"]`,
  where `{username}` is substituted with the selected capability's
  `principal` (validated against a conservative POSIX-username charset
  before substitution; a root containing `{username}` is skipped
  defensively if the principal fails that check).
- `ApexConfig.max_user_flag_attempts` — default `3`, a hard cap on
  distinct candidate paths ever attempted.

`ObjectivePlanner` only ever emits a task when:

1. a **validated `AccessCapability`** already exists for the target (see
   §16 — `apex_host.planners.access_capabilities.best_capability_for_objective`)
   — the planner never attempts to establish access itself, and never
   searches for a specific transport (SSH, Telnet, ...) directly;
2. the objective is not already verified; and
3. at least one bounded candidate has not already been attempted (tracked
   via the `objective` node's `attempted_paths` prop, read fresh from the
   subgraph each turn) for the selected capability's own `principal`.

The planner never touches operator-supplied credentials at all —
provisioning the runtime adapter with them (so the executor has something
real to call) is an **orchestration-layer** concern, handled once per turn
by `apex_host.orchestration.dispatch_node.make_objective_node` before
dispatch (§16).

Exactly **one** task per turn (`single_task=True` in
`make_objective_node`, mirroring the credential phase's own
one-task-per-turn pacing for sensitive session operations). Once every
bounded candidate has been attempted, across every validated capability,
without success, the planner returns an explicit "exhausted"
`AbandonSignal`.

**Current limitation: SSH only.** Only `AccessCapabilityType.ssh_command`
has a concrete adapter; Telnet and FTP `access_state` nodes do not (yet)
produce an `AccessCapability` and so are not (yet) acted on by
`ObjectivePlanner` — see §12/§16.

### `UserFlagExecutor` — bounded, capability-agnostic, dumb about transport

`apex_host/agents/user_flag_executor.py::UserFlagExecutor` never knows or
cares which transport backs the capability it was given — it resolves
`capability_id` to a runtime adapter via `CapabilityRuntimeRegistry`, calls
that adapter's ONE exposed operation
(`FlagReadCapability.read_bounded_file(path)`), and is the ONE call site
for the authoritative verifier (§7) — see §16 for why verification moved
here from the parser. Safety properties:

- `candidate_path` is validated with
  `apex_host.verification.user_flag.is_bounded_candidate_path()` **before**
  any adapter is ever invoked — an invalid path fails closed with zero I/O.
  This is the SAME function the policy rule checks (defense in depth).
- The adapter is the only thing that ever knows the transport-specific
  command (for SSH: always `"cat -- " + shlex.quote(candidate_path)` — `--`
  guards against option injection; `shlex.quote` is belt-and-suspenders on
  top of the already charset-restricted, `..`-free path).
- Output is byte-capped at `ApexConfig.user_flag_max_output_bytes`
  (default 4096) inside the adapter itself, before the verifier ever sees
  it.
- **Dry-run (the default) returns a synthetic, deliberately unremarkable
  "no such file or directory (dry-run)" result** — no registry lookup, no
  adapter call, no network activity of any kind, and the synthetic output
  can never look like a plausible flag, so a default dry-run engagement can
  never report a verified success (§10).
- Never holds an adapter, session, or connection on `self` (stateless
  across calls, memfabric Invariant 6) — the registry (injected once at
  construction) is the only thing referenced.
- The raw candidate value and any password are never logged, stored in the
  episode, or included in any exception text — only `verified`,
  `value_digest`, and `redacted_value` (the verifier's already-secret-free
  result fields) ever leave this executor.

## 7. The one authoritative verifier

`apex_host/verification/user_flag.py` is the SOLE place flag-verification
and bounded-path-validation logic lives. No other module — executor,
parser, planner, report, or continuation node — re-implements any part of
this decision; they all call
`verify_user_flag()`/`is_bounded_candidate_path()` from here (mirrors
`apex_host.security.redaction`'s "one authoritative module" convention).
This module was unchanged by the access-capability refactor (§16); only
its **call site** moved — `verify_user_flag()` is now called exactly once,
inside `UserFlagExecutor.run()`, rather than inside `ObjectiveParser` —
see §16 for why.

`verify_user_flag(raw_output, *, raw_error="", format_regex=None,
max_output_bytes=4096) -> FlagVerificationResult`:

Rejection rules, checked in order (first match wins — conservative by
construction: a suspicious/malformed/ambiguous candidate is never accepted):

1. `raw_error` contains a known command-error marker (`no such file or
   directory`, `permission denied`, `is a directory`, `not a directory`,
   `cannot open`, `operation not permitted`) — rejected before even
   inspecting `raw_output`.
2. `raw_output` exceeds `max_output_bytes` — rejected (oversized).
3. `raw_output` itself contains a command-error marker (defense in depth).
4. Normalized (only harmless leading/trailing whitespace stripped) value
   is empty — rejected.
5. Contains a newline/carriage return — rejected (multiline output is not
   a plausible single flag token).
6. Contains any other internal whitespace — rejected.
7. Does not fully match `format_regex` (or
   `DEFAULT_FLAG_FORMAT_REGEX = r"^[A-Za-z0-9_\-{}]{8,128}$"` — a generic,
   conservative bounded-token shape, never a specific known flag value) —
   rejected.

On success: computes `hashlib.sha256(normalized.encode()).hexdigest()` and
a short prefix/suffix redacted display (`ab12...ff90`, or fully masked
`****` for an 8-char-or-shorter value).

**`FlagVerificationResult` has NO plaintext field of any kind** — only
`verified: bool`, `reason: str`, `digest: str`, `redacted: str`,
`length: int`, `method: str`. The raw candidate value exists only as a
local variable inside `verify_user_flag()` and is discarded the instant
the digest/redacted form are computed; it structurally cannot flow further
downstream because there is no field on the result object to carry it.

`is_bounded_candidate_path(path, *, allowed_filenames)` — co-located in
the same module since both functions are "safely handling this bounded
operation": absolute path, conservative charset, no `..` traversal
segment, and the basename must be one of the operator's own configured
`user_flag_candidate_filenames`.

## 8. Redaction — no raw flag anywhere

The raw candidate value's only legitimate use is inside
`verify_user_flag()`'s own stack frame. Everywhere else:

| Surface | What is stored |
|---|---|
| `objective_evidence` node | `value_digest` (SHA-256) + `redacted_value` only |
| `RunReport` / text report / JSON export | `objective_evidence_digest` / `objective_evidence_redacted` only (§9) |
| Episodic log | `apex_host.orchestration.memory_node.write_memory` redacts the `user_flag_verify` tool_result's `stdout` field with `apex_host.security.redaction.redact_user_flag_output()` (a blanket `[user_flag_output_redacted]` replacement — a candidate read is the *unknown* value under investigation, so unlike a known password it cannot be selectively substring-redacted) before building the persisted `Episode`. |
| `state["current_task"]` (checkpoint-visible) | The `password` key is already masked by `apex_host.orchestration.models.task_info()` (pre-existing Phase 12B mechanism) — unchanged, applies to `user_flag_verify` tasks too since they also carry a `password` param. |
| Experience replay (`apex_host.planners.experience_replay`) | Reads only already-redacted EKG node props — since no node anywhere ever stores the plaintext, experience records structurally cannot retain it either (no code change was needed here — see §13). |
| Workflow summaries, planner_decisions | Built from the same already-redacted sources; verified by test (§14). |

**One real leak was found and fixed while building this phase's own test
suite** (`tests/apex_host/test_phase18_user_flag_objective.py
::TestNoRawFlagLeakage::test_raw_flag_absent_from_episodes`): the raw
candidate stdout was flowing from `UserFlagExecutor` through
`TaskDispatcher._run_user_flag_verify`'s `tr["stdout"]` field into the
persisted episode verbatim (the same `tr` dict is read by both
`parse_observation`, which legitimately needs the raw value to verify it,
and `write_memory`, which must never persist it). Fixed by redacting
specifically inside `write_memory` — after parsing has already happened,
immediately before the episode is built — rather than at the executor or
dispatcher layer (which would have broken the parser's ability to verify
at all).

## 9. Engagement outcome integration

`apex_host/orchestration/outcome.py`:

```python
class EngagementOutcome(str, Enum):
    user_flag_verified = "user_flag_verified"    # the ONLY success outcome
    validated_access = "validated_access"        # intermediate milestone; never success now
    ...

def is_success_outcome(outcome: EngagementOutcome) -> bool:
    return outcome is EngagementOutcome.user_flag_verified
```

| Outcome | Exit code (before Phase 18) | Exit code (Phase 18) | Legacy status (before) | Legacy status (Phase 18) |
|---|---|---|---|---|
| `user_flag_verified` | *(did not exist)* | **0** | *(did not exist)* | `"success"` |
| `validated_access` | 0 | **1** | `"success"` | `"abandoned"` |

`evaluate_termination()`'s `has_access_state: bool` parameter was renamed
to `objective_verified: bool` — its precedence-level-1 check (highest
priority, unconditional) now fires only when the configured objective's
`objective` EKG node has `status == "verified"`, never merely because an
`access_state` node exists. `EngagementOutcome.validated_access` is never
produced by `evaluate_termination()` anymore — it remains in the enum only
for `apex_host.eval.report._derive_outcome_from_state()`'s backward-
compatible fallback (a `final_state` predating even Phase 12C, which never
had an `outcome` key populated at all).

`apex_host/orchestration/continuation_node.py`'s `reflect_or_continue`
computes `objective_status_from_subgraph(subgraph, target,
config.objective_type)` from the live EKG every turn (the same subgraph
snapshot already fetched for the stall/replan peek — no extra read) and
passes `objective_verified = (objective_status == "verified")` into
`evaluate_termination()`. All other precedence levels (upstream-preset
outcomes, stall detection, phase-budget/max-turns exhaustion) are
unchanged.

## 10. Dry-run behavior

Dry-run remains safe and useful, and is unaffected in every phase except
`objective`:

- **No real discovery or file read ever occurs.** `UserFlagExecutor`'s
  dry-run branch returns a synthetic result with zero network I/O.
- **The planned structured operation is fully visible** — the
  `user_flag_verify` TaskSpec, its `candidate_path`, and the resulting
  (synthetic) episode are all written through the normal pipeline, so a
  dry-run engagement's report/JSON export shows exactly what *would* have
  been attempted.
- **No synthetic real-looking flag is ever accepted as verified.** The
  dry-run synthetic output (`"no such file or directory (dry-run)"`,
  surfaced as an error, never as stdout content) can never pass
  `verify_user_flag()` — proven by
  `TestEndToEndVerification::test_dry_run_never_creates_verified_success`,
  which additionally proves via the monkeypatched fake SSH backend that
  dry-run mode never even constructs a real SSH client.
- **Unit/integration tests may inject a deterministic fake tool result**
  to exercise the verified-success path end to end — this phase's own test
  suite does exactly that (`_install_fake_ssh()`, monkeypatching
  `paramiko.SSHClient` the same way `tests/apex_host/test_ssh_executor.py`
  already established for Phase 12B).

## 11. Reporting and metrics

`apex_host/eval/report.py::RunReport` gained nine additive fields, all
derived directly from the final subgraph via
`apex_host.planners.objective.objective_report_fields()` (never from a
possibly-stale live-state snapshot — same convention as every Phase 13-17
report section): `objective_type`, `objective_status`,
`objective_verified`, `objective_attempts`, `objective_evidence_digest`,
`objective_evidence_redacted`, `objective_evidence_source_path`,
`objective_evidence_access_identity`, `objective_verification_timestamp`.
The access-capability refactor (§16) added a tenth field,
`objective_evidence_capability_type`, the same way.

The text report gained an always-shown "Objective Summary" section
(objective_type defaults to `"user_flag"` on every `ApexConfig`, so this
section always renders — mirrors the always-shown "Policy Gate" section's
convention):

```text
Objective Summary
  Objective type     : user_flag
  Status             : verified
  Attempts           : 1
  Access obtained    : Yes
  Flag attempted     : Yes
  Flag verified      : Yes
  Benchmark success  : Yes
  Verified at        : 2026-07-22T00:00:00Z
  Evidence digest    : 9f2c4e1a...c93b0d7f
  Evidence (redacted): 9f3a...4d18
  Source path        : /home/testuser/user.txt
  Access identity    : testuser
  Capability used    : SSH Command
```

The digest/redacted/timestamp/source-path/access-identity/capability lines
are shown only when verified. The four yes/no lines (`Access obtained`,
`Flag attempted`, `Flag verified`, `Benchmark success`) are always present
and are exactly the four-way breakdown this phase's own scope required.
The raw flag is never printed.

**`Capability used` — deliberately a capability-type LABEL, never a
"Transport: SSH" framing.** It is rendered via
`apex_host.planners.access_capabilities.capability_type_label()`, which
looks up `objective_evidence_capability_type` (e.g. `"ssh_command"`) in a
fixed `CAPABILITY_TYPE_LABELS` dict (e.g. `"SSH Command"`). A future
capability type (Telnet, arbitrary file read, ...) needs **no change to
this rendering logic at all** — only a new entry in that one dict (§16).

`to_json_dict()` gained an `"objective"` block mirroring the same fields
(`access_obtained`, `attempted`, `benchmark_success` computed inline;
everything else a direct field passthrough), plus two capability-derived
keys: `"capability_type"` (the raw type string, `""` when not verified)
and `"capability_label"` (the human-readable label, `""` when not
verified).

`apex_host/eval/benchmark.py`'s `_EVIDENCE_NODE_TYPES` set gained
`"objective_evidence"` (a concrete, human-actionable observation — the
coordination-only `objective` node itself is deliberately excluded,
mirroring `workflow`/`session`'s existing exclusion).

`apex_host/eval/evaluation.py::HTBEvaluation.success` needed **no code
change** — it already copies `report.success` verbatim, which is itself
`is_success_outcome(...)`, so it picked up the new, stricter definition
automatically. The headline benchmark "solved machines" metric therefore
now counts only verified flags, exactly as required.

## 12. Configuration and CLI

| `ApexConfig` field | Default | CLI flag |
|---|---|---|
| `objective_type` | `"user_flag"` | `--objective-type` |
| `user_flag_candidate_filenames` | `["user.txt"]` | `--user-flag-candidate-filename` (repeatable) |
| `user_flag_candidate_roots` | `["/home/{username}"]` | `--user-flag-candidate-root` (repeatable) |
| `max_user_flag_attempts` | `3` | `--max-user-flag-attempts` |
| `user_flag_max_output_bytes` | `4096` | `--user-flag-max-output-bytes` |
| `user_flag_verification_regex` | `None` (uses `DEFAULT_FLAG_FORMAT_REGEX`) | `--user-flag-format-regex` |
| `user_flag_read_timeout_seconds` | `35.0` | `--user-flag-read-timeout` |

`user_flag_read_timeout_seconds` (added by the access-capability refactor,
§16) is `UserFlagExecutor`'s own outer defensive timeout ceiling around
`adapter.read_bounded_file()` — independent of, and in addition to,
whatever transport-specific timeouts the resolved adapter applies
internally (for SSH: `ssh_connect_timeout_seconds`/
`ssh_auth_timeout_seconds`/`ssh_command_timeout_seconds`, unchanged since
Phase 12B). Belt-and-suspenders only, never the primary bound.

Both `apex_host.main` and `apex_host.eval.run_htb_local` expose all seven
flags. **There is deliberately no CLI option, environment variable, or
config field that accepts an expected plaintext flag value** — the
verifier only ever checks *shape* (a regex describing character set and
length), never a specific known value, matching CLAUDE.md §13.8/§13.9's
"no machine-specific logic anywhere in this codebase."

The general library/runtime remains objective-configurable in principle
(`objective_type` is a plain string field), but `"user_flag"` is the only
implemented objective, and it is the default for the config as a whole —
so the HTB benchmark runner defaults to it without any special-casing.

## 13. Experience replay — no raw flag becomes transferable knowledge

`apex_host/planners/experience_replay.py` was **not modified** by this
phase. It only ever mines already-redacted EKG node props (e.g.
`access_state.evidence`/`.proof`, which are themselves already redacted by
`AccessParser` — a Phase 12B invariant). Since no EKG node anywhere
(objective, objective_evidence, or otherwise) ever stores the plaintext
flag value, experience records derived from them structurally cannot
retain it either — proven by
`TestNoRawFlagLeakage::test_raw_flag_absent_from_workflow_and_experience_replay`,
which runs the real `derive_experiences_from_engagement()` /
`derive_workflows_from_subgraph()` functions over a post-verification
subgraph and confirms the raw value is absent from every text field.

## 14. Tests

`tests/apex_host/test_phase18_user_flag_objective.py` (57 tests, no
network/Docker/VPN/HTB machine/real SSH server required — `paramiko
.SSHClient` is monkeypatched the same way
`tests/apex_host/test_ssh_executor.py` already established):

- Access/credentials/foothold alone are not success (3 tests, including a
  full compiled-graph run).
- End-to-end verified success via a fake SSH backend, and dry-run's own
  guarantee that it never reaches that backend (2 tests).
- CLI exit codes: `0` (verified), `1` (access-only exhaustion via several
  realistic outcomes), `3` (policy-blocked), `4` (operational failures),
  `130` (cancelled), plus one full CLI-level exit-code integration test.
- The verifier: empty/multiline/oversized/malformed rejection, command-
  error-marker rejection, acceptance of a well-formed synthetic token,
  whitespace normalization, exact SHA-256 digest, redacted-display
  correctness, the result dataclass's structural absence of any plaintext
  field, custom-regex support, the default regex's conservative shape,
  and bounded-candidate-path validation (13 tests).
- No raw flag leakage: text report, JSON report, EKG nodes/edges,
  episodes, planner_decisions, workflow/experience-replay derivations, and
  a check that no "unsafe/raw export" mode exists anywhere in the
  reporting API (7 tests).
- Objective/evidence EKG linkage (`indicates`, `enables`, `satisfied_by`
  edges all present with the correct canonical IDs), failed attempts never
  creating `objective_evidence`, and connection-level failures producing
  no node update at all (3 tests).
- Exactly one terminal episode on a verified full-graph run (1 test).
- `ObjectivePlanner`: no work without a validated capability, no work for
  an unvalidated capability, emits exactly one task with the correct
  `capability_id`/`capability_type`/`principal` params once one exists (and
  never a `username`/`port`/`password` field), no work once already
  verified, respects the bounded attempt budget and never repeats an
  attempted candidate, prefers the higher-confidence of two validated
  capabilities, and the thin wrapper correctly records its `PlanDecision`
  (7 tests — updated for the access-capability refactor, §16).
- Full-state JSON serializability of a real post-verification
  `ApexGraphState` (1 test).
- Static architecture scans: no Phase 18 terminology leaked into
  `memfabric`, no machine-specific names in any new source file
  (word-boundary matched to avoid false positives like "escape"/"cap"), no
  expected-plaintext-flag CLI flag or config field, no raw subprocess
  usage in any new file (4 tests).
- Policy/authorization gating: the new rule approves a bounded path and
  blocks an out-of-allowlist one, and a real `TaskDispatcher.dispatch()`
  call proves an off-scope target is blocked by policy before
  `UserFlagExecutor` is ever reached (a spy executor asserts zero calls) —
  3 tests.
- Report/JSON correctly distinguish "access obtained" from "flag verified"
  from "benchmark success," for both the access-only and the fully-verified
  case (2 tests).
- `HTBEvaluation.success` is `False` for access-only and `True` only once
  verified (2 tests).
- Config/CLI defaults: `objective_type` defaults to `"user_flag"`, derived
  helper defaults, and no CLI attribute accepts an expected flag value (4
  tests).

**43 pre-existing tests across 9 files were updated** (never weakened —
each now asserts the *new*, correct behavior) because they encoded the old
"access alone is success" assumption: `test_credential_phase_fix.py`,
`test_credential_planner_multiprotocol.py`, `test_graph.py`,
`test_live_run_fixes.py`, `test_phase10_orchestration.py`,
`test_phase12a_state_machine.py`, `test_phase12c_outcomes.py`,
`test_phase13_priv_esc_planning.py`, `test_phase17_benchmarking.py`,
`test_planners_with_engine.py`, `test_report.py`. Every Phase 12C
non-success outcome semantic (stall detection, phase-budget exhaustion,
max-turns exhaustion, policy blocking, planner/parser/memory/tool
failures, cancellation, configuration errors) is retained exactly as
before — only the success condition changed.

**Access-capability refactor (§16) test coverage:**
`tests/apex_host/test_access_capability_refactor.py` (53 tests) covers the
new abstraction layer directly: `AccessCapability`/`AccessCapabilityType`
data-model shape and secret-field absence, the runtime-only
`CapabilityRuntimeRegistry` (registration, idempotent `ensure_ssh`, no
MemoryAPI/EKG coupling), `FlagReadCapability` protocol conformance and
`SSHCapabilityAdapter` behavior (successful/failed reads, byte-capping,
fresh-client-per-call, `allow_agent=False`/`look_for_keys=False`),
`CapabilityParser.derive_ssh_capability()` node/edge shape and
idempotency, the `access_capabilities` ranking/selection helpers, static
scans proving `ObjectivePlanner`/`UserFlagExecutor`/`ObjectiveParser` have
no SSH/paramiko-specific code, the report's "Capability used" line (both
absent-when-unverified and present-with-the-correct-label cases), policy
validation with capability-shaped task params, `access_capability` graph
node/edge construction and MemoryAPI reachability, proof that a registered
adapter (and any secret used to construct it) never appears in the graph,
JSON serializability, and MemoryAPI-invariant static scans on the three
new pure/parser modules. `test_phase18_user_flag_objective.py` itself was
updated in place (58 tests after the refactor) rather than duplicated —
see §16 for exactly what changed there.

Final total after the access-capability refactor: **4451 tests passing**.

## 15. Known limitations

- **SSH only, though the abstraction is now generic.** Since the
  access-capability refactor (§16), `ObjectivePlanner`/`UserFlagExecutor`/
  `ObjectiveParser`/the report generator are all transport-independent —
  but `SSHCapabilityAdapter` remains the only concrete adapter
  implemented. Telnet and FTP `access_state` nodes are real, validated
  progress (still reflected in `access_summary`/`credential_*` reporting)
  but do not currently produce an `AccessCapability` and so do not
  currently lead to objective verification — extending this now means
  adding ONE new adapter class + one new `CapabilityParser.derive_*`
  method + one new registration branch (§16 "Extending with a new
  capability type"), never touching the planner, executor, parser, or
  report generator.
- **One default candidate path.** With the default config
  (`user_flag_candidate_roots=["/home/{username}"]`,
  `user_flag_candidate_filenames=["user.txt"]`), there is exactly one
  candidate (`/home/<user>/user.txt`) even though
  `max_user_flag_attempts` defaults to 3 — the cap only matters once an
  operator configures additional roots/filenames.
  `derived-analytical`/other-discovery mechanisms for candidate paths
  (e.g. inspecting `/etc/passwd` for other home directories) were not
  added — out of scope per this phase's "no unrestricted recursive
  search" and "smallest coherent seam" constraints.
- **Objective status "failed" is permanent within an engagement.** Once
  every bounded candidate is exhausted, the objective never re-attempts —
  even if, hypothetically, priv_esc later discovered a different user's
  home directory. A future phase could re-open the objective with newly
  discovered candidate roots; this phase does not.
- **No root-flag objective.** Only `objective_type="user_flag"` is
  implemented. `root_flag` (or any other objective type) is out of scope
  per this phase's explicit boundary — CLAUDE.md's existing "no root
  privilege escalation" constraint is unaffected and unchanged.
- **`objective_status`/`objective_summary` state fields are one-turn
  stale** during the live engagement (refreshed only on `objective_agent`
  turns, mirroring `privilege_summary`/`web_session_state`'s established
  pattern) — the final report always re-derives from the complete final
  EKG, so this staleness never affects reported results.
- **This phase alone does not make APEX capable of solving arbitrary HTB
  machines.** It makes user-flag verification the authoritative benchmark
  completion condition and provides the safe, generic mechanism to detect
  that condition once access has already been achieved by earlier phases.

## 16. Access Capability Abstraction (refactor)

Everything in §1-15 above describes the User Flag Objective as it was
originally shipped: hardcoded to SSH end-to-end. This section documents a
follow-on refactor that made the *access mechanism* transport-independent
while leaving the *objective* (still exactly one: `user_flag`) and the
*verifier* (§7, unchanged) exactly as designed. Read this section as an
addendum to, not a replacement for, §6.

### 16.1 Why

Before this refactor, `ObjectivePlanner` searched the EKG for an
`access_state` node with `service == "ssh"`, put a raw `username`/
`password`/`port` into the `TaskSpec`, and `UserFlagExecutor` spoke
Paramiko directly. Adding a second transport (Telnet, a local shell, an
HTTP file-read API) would have meant touching the planner, the executor,
and the parser all over again — the exact kind of transport coupling
CLAUDE.md's Protocol-seam discipline (§1 Invariant 1, §9 "Out of scope")
exists to prevent elsewhere in this codebase. The fix: introduce one
narrow data model (`AccessCapability`) and one narrow runtime interface
(`FlagReadCapability`) between "proof that some access mechanism works"
and "the objective that consumes it."

### 16.2 Module map

```
apex_host/types.py                          -- AccessCapabilityType (enum), AccessCapability (dataclass)
apex_host/graph_ids.py                      -- access_capability_id(), has_capability_edge_id()
apex_host/runtime_registry.py               -- FlagReadCapability (Protocol), CapabilityRuntimeRegistry,
                                                SSHCapabilityAdapter (the one concrete adapter)
apex_host/parsers/capability_parser.py      -- CapabilityParser.derive_ssh_capability()
apex_host/planners/access_capabilities.py   -- access_capabilities_from_subgraph(), rank_capabilities(),
                                                best_capability_for_objective(), capability_type_label()
apex_host/agents/user_flag_executor.py      -- UserFlagExecutor (refactored: registry lookup + verify_user_flag())
apex_host/parsers/objective_parser.py       -- ObjectiveParser (refactored: consumes verified/digest/redacted, not stdout)
apex_host/planners/objective_planner.py     -- ObjectivePlanner (refactored: selects AccessCapability, not access_state)
apex_host/orchestration/dependencies.py     -- OrchestrationDeps.capability_registry (new field)
apex_host/orchestration/dispatch_node.py    -- make_objective_node (new: pre-dispatch adapter registration)
apex_host/orchestration/parsing_node.py     -- routes a successful ssh_access result through CapabilityParser too
apex_host/execution/dispatcher.py           -- _run_user_flag_verify's tr dict reshaped (no raw stdout/username/port)
apex_host/eval/report.py                    -- "Capability used" line + capability_type/capability_label JSON fields
```

### 16.3 The `AccessCapability` data model

```python
class AccessCapabilityType(str, Enum):
    ssh_command = "ssh_command"
    telnet_command = "telnet_command"
    web_command = "web_command"
    local_shell = "local_shell"
    arbitrary_file_read = "arbitrary_file_read"
    api_file_read = "api_file_read"

@dataclass(slots=True)
class AccessCapability:
    capability_id: str
    host_id: str
    capability_type: AccessCapabilityType
    validated: bool
    principal: str
    confidence: float
    source_task_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
```

**These are capability TYPES, never exploit types, and never themselves
executable actions.** Only `ssh_command` has a concrete adapter today; the
other five exist so the taxonomy, ranking, and reporting layers are
already complete and forward-compatible.

**The dataclass structurally cannot hold a secret.** There is no
`password`/`cookie`/`token`/`session`/`socket` field, and there never may
be one (enforced by a static test,
`TestCapabilityCreation::test_capability_forbids_secret_fields_by_construction`
in `tests/apex_host/test_access_capability_refactor.py`). The graph stores
metadata only.

Stored in the EKG as an `access_capability` node
(`apex_host/graph_ids.py::access_capability_id(target, capability_type,
principal)` — content-addressed, so re-deriving it is an idempotent
upsert, never a duplicate). Two new edges:

- `host --has_capability--> access_capability` (reachability, matching the
  "don't fragment the graph" discipline every prior phase's opportunity/
  workflow/experience node established).
- `access_state --enables--> access_capability` (the capability was
  produced by a validated login).

`apex_host/parsers/capability_parser.py::CapabilityParser.derive_ssh_capability(
target, username, source_task_id)` is the ONE place that turns a validated
SSH login into this EKG shape — called from
`apex_host/orchestration/parsing_node.py` immediately after
`AccessParser.parse_structured()` succeeds for `tool == "ssh_access"`, and
merged into the same `ParsedObservation` (one `apply_deltas` batch, memfabric
Invariant 1).

### 16.4 The runtime-only capability registry

**Live sessions must never be stored inside `MemoryAPI`.** The EKG
`access_capability` node is metadata only — it has no field that could
hold a password or an open connection. The thing that can actually *read a
file* lives exclusively in `apex_host/runtime_registry.py`:

```python
class FlagReadCapability(Protocol):
    async def read_bounded_file(self, path: str) -> tuple[bool, str, str | None]: ...

class CapabilityRuntimeRegistry:
    def register(self, capability_id: str, adapter: FlagReadCapability) -> None: ...
    def get(self, capability_id: str) -> FlagReadCapability | None: ...
    def has(self, capability_id: str) -> bool: ...
    def ensure_ssh(self, capability_id: str, *, target, port, username, password, config) -> FlagReadCapability: ...
```

`FlagReadCapability` exposes **exactly one** operation. "The objective must
never request arbitrary command execution" is enforced by construction —
there is no second method to call.

`CapabilityRuntimeRegistry` is a plain in-process `dict[str,
FlagReadCapability]`. It is never written through `MemoryAPI`, never
serialized, never appears in `ApexGraphState` (verified by
`TestNoRuntimeSessionPersistence::test_apex_graph_state_never_contains_a_capability_registry_field`).
One instance lives in `OrchestrationDeps.capability_registry`, constructed
fresh per engagement inside `build_apex_graph()` — the exact same lifecycle
pattern already established for `StallTracker`
(`apex_host/orchestration/stall.py`) and `GlobalPlanner`'s own `_spent`
budget counters. `OrchestrationDeps` is a frozen dataclass and is never
stored in `ApexGraphState` (memfabric Invariant 1/7, unchanged).

**Who populates the registry, and when:** neither the planner (which must
stay pure over subgraph/evidence data, memfabric Invariant 7) nor the
executor (which only ever *looks up* an already-registered adapter).
`apex_host/orchestration/dispatch_node.py::make_objective_node` does it,
once per objective turn, immediately before dispatch: it reads every
validated `AccessCapability` from a fresh subgraph fetch and, for each one
whose type is `ssh_command` and whose `principal` matches
`config.username_candidates[0]` (mirroring `CredentialPlanner`'s own
one-credential-pair-per-engagement invariant), calls
`capability_registry.ensure_ssh(...)` with the real target/port/username/
password. This is the **one and only place** live connection parameters
(e.g. a password) are ever paired with a `capability_id` — neither the
planner nor the executor ever sees them together.

### 16.5 `SSHCapabilityAdapter` — the one concrete adapter

```python
class SSHCapabilityAdapter:
    def __init__(self, *, target, port, username, password, config) -> None: ...
    async def read_bounded_file(self, path: str) -> tuple[bool, str, str | None]: ...
```

Behavior is byte-for-byte what the pre-refactor `UserFlagExecutor` did
directly: one fresh `paramiko.SSHClient()` per call (never a session held
across calls — memfabric Invariant 6 extended to adapters), closed in a
`finally` block, `allow_agent=False`, `look_for_keys=False`, no SFTP, no
port forwarding. `connect()`/`exec_command()` failures are all caught and
converted into `(connected, stdout, error)` tuples — the adapter never
raises. The command is always `"cat -- " + shlex.quote(path)`; output is
byte-capped at `ApexConfig.user_flag_max_output_bytes` before it is ever
returned.

**This phase does NOT implement Telnet or web-shell support** — only the
abstraction and the one SSH adapter, exactly as scoped.

### 16.6 `UserFlagExecutor` — the refactored flow

```python
class UserFlagExecutor:
    def __init__(self, config: ApexConfig, registry: CapabilityRuntimeRegistry | None = None) -> None: ...
    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult: ...
```

`run()`, in order:

1. Validates `task.params["candidate_path"]` via
   `is_bounded_candidate_path()` — fails closed before any adapter call.
2. Dry-run short-circuit (unchanged behavior) — no registry lookup at all.
3. Resolves `task.params["capability_id"]` to an adapter via
   `self._registry.get(capability_id)` — a missing registration produces a
   clean, non-crashing "no registered runtime adapter" error result.
4. Calls `adapter.read_bounded_file(candidate_path)`, wrapped in an outer
   `asyncio.wait_for(..., timeout=config.user_flag_read_timeout_seconds)`
   (belt-and-suspenders on top of the adapter's own internal timeouts).
5. Calls `verify_user_flag()` — **the one authoritative verifier, now
   called from here instead of from `ObjectiveParser`** (see 16.8 for why).
6. Builds the episode with only `verified`/`value_digest`/`redacted_value`/
   `capability_id`/`capability_type`/`principal` — **never the raw
   candidate value**.

"It must never directly know whether the capability is SSH, Telnet, file
read, web shell, etc." is enforced by construction: nothing in this
executor branches on `capability_type` — it is passed through verbatim
into the episode/report, never inspected for control flow (proven by
`TestObjectiveTransportIndependence::test_user_flag_executor_never_branches_on_capability_type`).

### 16.7 `ObjectivePlanner` — selecting a capability, not a transport

`ObjectivePlanner` no longer searches for SSH access specifically. It
calls `apex_host.planners.access_capabilities.best_capability_for_objective()`,
which:

1. Reconstructs every `AccessCapability` from the subgraph's
   `access_capability` nodes (`access_capabilities_from_subgraph`).
2. Ranks them: **validated capabilities first, then higher confidence,
   then `capability_id` ascending as a stable tie-break**
   (`rank_capabilities` — never random, never insertion-order dependent,
   matching every other `rank_*` helper in this codebase).
3. Skips any capability in an `exclude_capability_ids` set — `ObjectivePlanner`
   computes this set itself, per turn, as "every validated capability whose
   own candidate-path set is already fully attempted," so a second,
   still-untried validated capability is preferred over one that has
   nothing left to try (satisfies "prefer capabilities that have not
   already attempted the candidate path").

The emitted `TaskSpec.params` carries `capability_id`, `capability_type`,
`principal`, and `candidate_path` — **never `username`, `port`, or
`password`** (a raw SSH-specific field never existed in the new params
shape at all, closing off the class of leak the old
`apex_host/orchestration/models.py::task_info()` password-masking fix had
to patch defensively for the pre-refactor design).

The planner no longer requires operator-supplied credentials to be
configured at plan time — a validated `AccessCapability` node existing in
the EKG is already structural proof that some earlier phase's credentials
worked, so the planner has no independent use for the raw values.
(Provisioning the runtime adapter is the orchestration layer's job — see
16.4.)

### 16.8 `ObjectiveParser` — consuming, not computing, the verification result

`ObjectiveParser.parse_user_flag_result()` no longer calls
`verify_user_flag()` itself. It now takes the executor's already-computed,
secret-free result directly: `verified: bool`, `value_digest: str`,
`redacted_value: str`, `verification_method: str`, plus `capability_id`/
`capability_type`/`principal` (replacing the old `stdout`/`username`/
`format_regex`/`max_output_bytes` params). This closes the raw-flag-leak
gap at its root — the raw candidate value now never leaves
`UserFlagExecutor`'s own stack frame, so there is nothing for the parser
(or the episode it used to help fill) to leak in the first place.

The semantic edge changed accordingly:
`access_capability --enables--> objective` (previously
`access_state --enables--> objective`) — the capability, one level more
general than the raw credential validation that produced it, is now the
thing that "enables" the objective. `objective_evidence` nodes gained two
new props, `capability_type` and `capability_id`, so a report can show
which transport produced the evidence without re-deriving it.

### 16.9 Report integration

See §11's updated text — `apex_host.planners.access_capabilities.capability_type_label()`
renders `"Capability used: SSH Command"`, never `"Transport: SSH"`,
specifically so a future adapter needs no change to report rendering
logic — only one new entry in the `CAPABILITY_TYPE_LABELS` dict.

### 16.10 Policy

No new policy rule was needed. `check_bounded_user_flag_verification()`
already operated only on `task.params["target"]` and
`task.params["candidate_path"]` — both still present, unchanged, in the
new `TaskSpec.params` shape — so scope enforcement and bounded-path
validation apply identically before and after this refactor.

### 16.11 Extending with a new capability type

Adding Telnet (or arbitrary-file-read, or an API-file-read, or a
web-shell) support requires, and requires ONLY:

1. A new adapter class in `apex_host/runtime_registry.py` implementing
   `FlagReadCapability.read_bounded_file(path)`.
2. A new `derive_<type>_capability()` method on `CapabilityParser`, called
   from the appropriate success branch in
   `apex_host/orchestration/parsing_node.py`.
3. A new registration branch in
   `apex_host/orchestration/dispatch_node.py::_register_capability_adapter()`.
4. A new entry in `apex_host.planners.access_capabilities.CAPABILITY_TYPE_LABELS`.

**Never required:** any change to `ObjectivePlanner`, `UserFlagExecutor`,
`ObjectiveParser`, the report generator, or `check_bounded_user_flag_verification`
— this is the refactor's own success criterion, and is what the static
scans in `tests/apex_host/test_access_capability_refactor.py`
(`TestObjectiveTransportIndependence`) exist to keep true over time.

### 16.12 Known limitations (additive to §15)

- Capability-to-runtime-adapter registration currently only handles SSH
  (16.4's matching logic is SSH-specific by construction, since SSH is the
  only adapter that exists) — adding a second adapter type means adding a
  second `elif` branch in `_register_capability_adapter()`, per 16.11.
- The credential-matching rule in 16.4 (`principal == username_candidates[0]`)
  assumes exactly one configured credential pair, mirroring
  `CredentialPlanner`'s own established one-pair-per-engagement invariant —
  it does not (and is not intended to) support rotating through multiple
  operator-supplied credential pairs.
- `objective_evidence.capability_type`/`.capability_id` are `""` on any
  `objective_evidence` node written before this refactor shipped (backward
  compatible — `objective_report_fields()` defaults both to `""`).

## 17. Direct File Read Capability (Phase 20)

§16.11 predicted exactly this: a second `FlagReadCapability` adapter added
using only the four documented extension points, with **no change** to
`ObjectivePlanner`, `UserFlagExecutor`, `ObjectiveParser`, the report
generator, or `check_bounded_user_flag_verification`. This section
documents that second adapter — a generic, bounded, policy-gated
**direct-file-read** capability, covering primitives such as an arbitrary
file read, a local file inclusion, a path-traversal read, an authenticated
file-download endpoint, an internal application endpoint that returns
bounded file contents, or an XSS-assisted workflow that ultimately resolves
to a bounded file read.

**This phase does not implement a specific exploit or solve a named HTB
machine.** It provides the generic plumbing so that, once an operator has
*already* confirmed (through their own authorized testing) that a fixed,
specific HTTP request shape reads files on the target, APEX can use that
confirmed primitive to satisfy the User Flag Objective — without SSH.

### 17.1 Why this is not a generic HTTP/SSRF executor

The single most important design constraint in this section: **there is no
mechanism anywhere in this codebase that lets a planner, an LLM, or a task
choose an arbitrary URL, host, port, scheme, HTTP method, header set, body,
or redirect target.** `DirectFileReadCapabilityAdapter.read_bounded_file(path)`
takes exactly one parameter — the bounded candidate path — and substitutes
it into ONE pre-validated, operator-supplied request shape
(`DirectFileReadPrimitive`) that was fixed at capability-registration time.
Everything else about the request (origin, endpoint template, method,
headers, timeout, byte cap, redirect policy) is configuration, never
task-controlled data. This is deliberately narrower than a general-purpose
HTTP client — it cannot be repurposed into one without changing the
adapter's public method signature, which the architecture-scan tests in
§14 of the test suite (category 14, "Architecture scans") pin down.

### 17.2 Capability types: reused, not invented

`AccessCapabilityType.arbitrary_file_read` and `.api_file_read` already
existed (added speculatively in §16.3's original six-member enum, ahead of
having a real adapter). Phase 20 gives both a real, shared adapter — no
`alert_xss`/`lfi_exploit`/machine-named capability type was added. **The
capability describes what APEX can do (read a bounded file through a fixed
request shape), not how the primitive was discovered.** Both types are
behaviorally identical at runtime and resolve to the same
`DirectFileReadCapabilityAdapter` class; they exist as two labels only so
an operator/report can distinguish "a raw file-read primitive" from "an
authenticated API endpoint that happens to return file contents" for
audit purposes.

### 17.3 `BoundedReadResult` — the transport-neutral result type

`FlagReadCapability.read_bounded_file()`'s return type changed from a bare
3-tuple to a dataclass, shared by both adapters:

```python
@dataclass(slots=True)
class BoundedReadResult:
    connected: bool
    output: str
    error: str | None
    status_code: int | None = None     # HTTP status, when applicable
    return_code: int | None = None     # process/command exit status, when applicable
    bytes_received: int = 0
    truncated: bool = False
    method: str = ""                   # e.g. "ssh_cat" or "GET"/"POST"
```

`SSHCapabilityAdapter` (§16.5, unchanged behavior) now wraps its internal
`(connected, stdout, error)` tuple into this same shape at its one return
point, so both adapters speak the identical result type — the reason
`UserFlagExecutor` never needs to know which adapter produced a result.
Not persisted anywhere until `UserFlagExecutor` extracts only
`verified`/`digest`/`redacted`/`status_code`/`bytes_received`/`truncated`/
`method` for the episode — `output` (the only field that can ever hold the
raw candidate content) never crosses that boundary.

### 17.4 `DirectFileReadPrimitive` — the fixed, pre-validated request shape

```python
@dataclass(slots=True)
class DirectFileReadPrimitive:
    capability_id: str
    target_origin: str            # e.g. "http://10.10.10.190:80" — no path/query/userinfo
    endpoint_template: str        # MUST contain "{path}"; e.g. "/download.php?file={path}"
    method: str = "GET"           # GET or POST only
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 15.0
    max_response_bytes: int = 4096
    allow_redirects: bool = False
    max_redirect_hops: int = 0
    allowed_filenames: frozenset[str] = field(default_factory=frozenset)
```

`__post_init__` validates, at construction time (never at request time):
method uppercased and restricted to `{GET, POST}`; origin scheme restricted
to `{http, https}`; origin has no userinfo and no path/query/fragment;
`endpoint_template` contains the literal `{path}` placeholder. Constructing
an invalid primitive raises `ValueError` immediately — it is never possible
to reach `read_bounded_file()` with a malformed shape.

### 17.5 `DirectFileReadCapabilityAdapter` — request-shape safety (defense in depth)

`read_bounded_file(path)` performs these checks, in order, before any
network I/O:

1. `is_bounded_candidate_path(path, allowed_filenames=...)` — the SAME
   authoritative validator §7/§17.9 use everywhere else in this codebase.
   Rejects traversal (`..`), relative paths, wildcards, oversized paths,
   and any basename not in the operator's configured allowlist.
2. URL-encodes the path (`urllib.parse.quote(path, safe="/")`) and
   substitutes it into `endpoint_template`, then verifies the resulting URL
   is still same-origin with `target_origin` and has no userinfo.

Then, for the request itself (via `httpx.AsyncClient(follow_redirects=False,
timeout=primitive.timeout_seconds)` — redirects are **always** handled
manually, never delegated to httpx's own follow-redirects machinery):

3. If the response is a redirect: **disabled by default**
   (`allow_redirects=False` → immediate rejection, `error="... redirects
   are disabled"`). When explicitly enabled, each hop is validated —
   scheme, host, and port must all match `target_origin` exactly (no
   scheme upgrade/downgrade, no host change, no port change, no userinfo);
   any violation aborts with `"... outside the authorized origin"`, and the
   hop count is capped by `max_redirect_hops` (defaults to 1 once redirects
   are enabled at all).
4. The body is read via `response.aiter_bytes()`, stopping the moment
   `max_response_bytes` would be exceeded — this simultaneously enforces
   the byte cap AND bounds decompression-bomb risk (httpx decodes
   gzip/deflate lazily as bytes are iterated, so the cap applies to
   post-decompression bytes actually consumed, not to a single
   `response.content` materialization of an arbitrarily large body).
5. **Oversized responses are rejected outright, never partially accepted.**
   An early implementation returned the truncated prefix with a `truncated`
   flag set — this was corrected before shipping: a truncated prefix could,
   in principle, coincidentally resemble a well-formed flag and be verified
   as a (wrong) value. The adapter now always returns `output=""` with an
   explicit `error="response exceeds the maximum bounded size"` whenever
   truncation occurs, so "oversized → never verified" is a structural
   guarantee, not a coincidence of what the truncated bytes happen to
   contain.
6. Timeouts (`httpx.TimeoutException`) and any other transport failure are
   caught and returned as `BoundedReadResult(connected=False, ...)` —
   the adapter never raises.
7. Error strings are built from fixed, generic messages only — never from
   `str(exc)` on an exception that might embed a header value, and never
   including the full request URL with its query string (so a configured
   header value, e.g. a session cookie, can never leak into a log line or
   report through an error message).

**Explicitly not implemented:** a generic "fetch this URL" or "make this
request" method. `read_bounded_file(path)` is the adapter's only public
method (enforced by `inspect.getmembers` in the test suite).

### 17.6 Capability derivation — structured evidence only

`CapabilityParser.derive_direct_file_read_capability(...)` (a new method,
alongside the existing `derive_ssh_capability`) only derives a capability
when the caller supplies:

- A `validation_method` drawn from a small, explicit accepted set:
  `operator_attestation`, `canary_file_match`, `path_dependent_content`,
  `structural_signature_match`. Anything else — including an HTTP 200
  alone, an LLM's own claim of vulnerability, or the mere fact that a
  request was attempted — returns an **empty** `ParsedObservation` (no
  node, no edge). "An endpoint looks interesting" is never sufficient.
- `confidence >= 0.6` (`_MIN_DIRECT_FILE_READ_CONFIDENCE`).
- A non-empty `principal`.
- `capability_type` restricted to `{arbitrary_file_read, api_file_read}`.

On acceptance it builds the same `access_capability` node/edge shape as
§16.3, with sanitized `metadata` limited to exactly `{validation_method,
requires_auth, max_response_bytes, request_shape_id}` — never a cookie,
token, header value, raw request/response body, or raw flag-like value.
`host --has_capability--> access_capability` is always added;
`source_node_id --enables--> access_capability` is added only when a
source evidence node ID was supplied by the caller. The node ID is
content-addressed (`access_capability_id(target, capability_type,
principal)`), so re-deriving the same evidence is an idempotent upsert.

### 17.7 Operator-attested seeding — the trust boundary for this phase

This phase does not add a new live web-exploitation validation
executor/planner/policy-rule to *discover* a direct-file-read primitive
autonomously — doing so would have meant building a new exploitation
mechanism, which is explicitly out of scope. Instead,
`apex_host/orchestration/capability_seed.py::seed_direct_file_read_capability()`
mirrors `--username`/`--password`'s existing trust model: the operator has
**already**, through their own authorized testing, confirmed that a
specific fixed request shape reads files, and supplies that confirmation
through nine new `ApexConfig` fields (`direct_file_read_operator_attested`,
`_capability_type`, `_origin`, `_endpoint_template`, `_method`, `_headers`,
`_principal`, `_max_response_bytes`, `_timeout_seconds`,
`_allow_redirects`, `_confidence`).

Called exactly once, at engagement startup
(`apex_host.runtime.ApexRuntime.run()`, before the graph starts), so a
DFR-only engagement (no SSH ever attempted) has an `access_capability` node
in place before `GlobalPlanner` first evaluates the phase ladder. It
performs **no live network operation** — only fixed EKG deltas from
already-known configuration — and validates that the configured origin's
hostname matches `config.target` before deriving anything (defense in
depth on top of the adapter's own per-request origin checks). Idempotent
(a second call is a no-op once the content-addressed node exists).

### 17.8 Runtime registry integration and the `runtime_available` distinction

`CapabilityRuntimeRegistry.ensure_direct_file_read(capability_id, *,
primitive)` mirrors `ensure_ssh` exactly — idempotent, performs no network
I/O (constructing a `DirectFileReadPrimitive`/adapter pair is always safe;
only the later `read_bounded_file()` call touches the network).

`apex_host/orchestration/dispatch_node.py::_register_capability_adapter()`
now dispatches on `cap.capability_type` to one of two private helpers:
`_register_ssh_adapter` (extracted, unchanged behavior) or the new
`_register_direct_file_read_adapter`, which constructs a
`DirectFileReadPrimitive` from `ApexConfig`'s `direct_file_read_*` fields
— **never from the capability node's own EKG metadata**, which carries no
secret — and requires `cap.principal == config.direct_file_read_principal`
(the same principal-matching discipline §16.4 established for SSH). A
`ValueError` from the primitive's own validation is caught and logged;
registration simply fails (returns `False`) rather than crashing the turn.

**A validated capability with no adapter registered must never be
mistaken for an executable one.** `AccessCapability` gained a
`runtime_available: bool = True` field (default `True` for backward
compatibility with pre-Phase-20 SSH capability nodes that predate this
distinction). `derive_ssh_capability`/`derive_direct_file_read_capability`
both now start a freshly-derived capability at `runtime_available=False`
— no adapter exists yet at the moment of derivation. `make_objective_node`
writes the real registration outcome back onto the EKG node after every
attempt, **but only when it changes**, and — critically — at a fixed
confidence of `0.5`, deliberately **below** `MemoryAPI`'s
`conflict_confidence_floor` (default `0.8`). `runtime_available` is a
re-derived runtime STATUS flag, not an epistemic claim about the world;
writing it at the capability's own (often high) derivation confidence would
make MemoryAPI's epistemic-conflict detector (CLAUDE.md §1 Invariant 3)
treat a `False → True` registration-success transition as a contested,
disputed claim between two equally-confident sources — a real defect found
and fixed during this phase's own test-writing (a spurious `Conflict`
record was observed blocking the very report line meant to confirm
success). Plain last-writer-wins-by-`logical_version` semantics are what
is actually wanted here, which the `0.5` confidence achieves without
touching memfabric's conflict-detection logic at all.

`access_capabilities_from_subgraph()`/`best_capability_for_objective()`
both now read and respect `runtime_available` — a capability that exists as
metadata but has no registered adapter is never selected for execution
(§17.10 below).

### 17.9 `UserFlagExecutor` and `verify_user_flag()` — unchanged

No functional change was needed. `UserFlagExecutor` already resolved
`capability_id → adapter` through the registry, called
`adapter.read_bounded_file(path)`, and passed the result to
`verify_user_flag()` (§16.6) without inspecting `capability_type` for
control flow — the direct-file-read adapter satisfies the exact same
`FlagReadCapability` contract the SSH adapter does. `check_bounded_user_flag_verification()`
(the policy rule) also needed no change — it inspects only
`task.params["target"]`/`["candidate_path"]`, neither of which is
transport-specific; the request shape itself is never task-controlled at
all, so the policy layer never needs to reason about headers, origin,
method, or redirects. Both facts are enforced by architecture-scan tests
(category 14/9 in the new test file) that grep each module's source for
transport-specific branching and request-shape vocabulary.

### 17.10 `ObjectivePlanner` — ranking, never hardcoded transport preference

`ObjectivePlanner` requires no exploit- or transport-specific planning
branch. It already ranked candidates generically (validated status, then
confidence, then a stable ID tie-break — §16.7); Phase 20 adds one
low-priority tie-break dimension, `_DIRECTNESS_RANK` (direct file-read
capabilities rank ahead of local/remote command capabilities *only when
confidence and validation status are otherwise equal*) — directness is
never allowed to override a confidence-based ranking. The planner also now
skips any capability with `runtime_available=False` before ever considering
it — a capability whose metadata exists but has no registered adapter is
recorded as present (visible in the EKG and in reporting) but never
selected for execution.

### 17.11 Attempt tracking became pair-scoped: `(capability_id, candidate_path)`

Before this phase, exhaustion was tracked as a flat list of attempted
paths on the `objective` node. This meant a failed SSH attempt on
`/home/app/user.txt` would permanently block ever trying that same path
through a *different*, later-available capability (e.g. a direct-file-read
primitive) — the objective would report "exhausted" even though a
perfectly good alternative access mechanism existed. This phase makes the
change CLAUDE.md's own instructions anticipated ("make the smallest
necessary correction so failure is attempt-scoped rather than
capability-global... if that change becomes substantial, document it
clearly and add focused tests"):

- `objective.attempted_capability_paths` now stores `[capability_id,
  candidate_path]` pairs (alongside the original flat `attempted_paths`,
  kept unchanged for backward-compatible display).
- `_ObjectiveDeterministic._select_capability()` excludes a capability from
  consideration only when **every one of its own candidates** has already
  been attempted through **that same capability** — a path attempted
  through a different capability never counts against this one.
- The objective's status only becomes `"failed"` once
  `_is_globally_exhausted()` confirms **every** validated+available
  capability's **every** candidate is present in
  `attempted_capability_paths` — true global exhaustion, computed fresh
  each turn, never "the one capability the planner happened to pick this
  turn ran out."

This is covered by a dedicated planner test
(`test_failed_ssh_attempt_does_not_block_dfr_retry_on_same_path`) proving
the exact scenario: an SSH attempt recorded as attempted for
`/home/application/user.txt`, with a separate, validated, available
direct-file-read capability for the same principal — the planner still
offers that same path through the direct-file-read capability.

### 17.12 `GlobalPlanner` phase-ladder fix

`_select_phase()`'s credential-phase gate previously required an
`access_state` node (i.e., a validated SSH/Telnet/FTP login) before the
engagement could ever reach the `objective` phase — a DFR-only engagement,
where no credential-based access is ever attempted, could never progress
past the credential phase. The gate now reads:

```python
if "access_state" not in node_types_seen and "access_capability" not in node_types_seen:
    return ApexPhase.credential
```

An operator-attested (or otherwise validated) `access_capability` node —
regardless of transport — is now sufficient to advance to the objective
phase, exactly like a validated `access_state` node already was. This is
the one change that makes a pure direct-file-read engagement (no SSH ever
attempted) reachable at all.

### 17.13 Reporting and metrics

`capability_type_label("arbitrary_file_read")` now returns `"Direct File
Read"` (previously `"Arbitrary File Read"` — renamed to match the
CLAUDE.md-specified report wording; verified no other code or test
depended on the old string before renaming). `"api_file_read"` remains
`"API File Read"`. The existing "Capability used: <label>" line (§16.9)
therefore now also renders "Capability used: Direct File Read" with zero
report-generator changes.

A new, always-derived-from-the-final-EKG "Direct File Read Summary" report
section (shown only when at least one direct-file-read capability node
exists) adds seven fields to `RunReport`:

| Field | Derivation |
|---|---|
| `direct_file_read_capabilities_derived` | Count of `access_capability` nodes with a direct-file-read type |
| `direct_file_read_adapters_registered` | Same, filtered to `runtime_available=True` |
| `direct_file_read_attempts` | Non-blocked `user_flag_verify` attempts against a direct-file-read capability (from `direct_file_read_log`) |
| `direct_file_read_blocked_attempts` | Same, `blocked=True` entries |
| `direct_file_read_verified_count` | Same, `connected and verified` entries |
| `direct_file_read_rejected_oversized` | Same, `truncated=True` entries |
| `direct_file_read_rejected_cross_origin` | Same, `error` matching an origin/redirect-rejection message |

`ApexGraphState.direct_file_read_log` (an `operator.add`-reduced list,
mirroring `credential_validation_log`'s established pattern) is populated
by `write_memory` for every `user_flag_verify` result whose
`capability_type` is a direct-file-read type — never for SSH attempts,
which continue to use the existing `credential_validation_log`/objective
fields exclusively. No full URL, header, cookie, or raw candidate value
ever appears in this log, the report text, or the report's JSON export
(verified directly by a full-graph test asserting the flag's exact value
never appears anywhere in `format_text()`/`to_json_dict()` output).

### 17.14 Redirect and origin protections — summary

All defaults are conservative: `allow_redirects=False` by default (a
redirect response is rejected outright, never silently followed);
enabling redirects still caps hops at a small, explicit limit
(`max_redirect_hops`, defaulting to 1) and validates **every** hop against
the exact authorized origin (scheme, host, and port must all match — no
scheme upgrade, no host change, no port change, no userinfo introduced
partway through a redirect chain). "Do not add broad SSRF protections to
memfabric" is honored structurally — all of this logic lives in
`apex_host/runtime_registry.py`; memfabric has no reference to HTTP,
origins, or redirects anywhere (verified by an architecture-scan test
grepping the entire `memfabric/` tree for direct-file-read-specific
terminology).

### 17.15 Raw-output and secret lifecycle

The raw file/flag content's lifecycle is identical to the SSH path (§8),
now traced through one additional hop: `httpx.Response.aiter_bytes()` →
local `text` variable inside `read_bounded_file()` → `BoundedReadResult.output`
→ `UserFlagExecutor`'s local stack frame → `verify_user_flag()`'s local
`raw_output` parameter → digest/redacted computation → discarded. At no
point does the raw value get assigned to a dataclass field that survives
past that call chain, get logged (verified directly by a `caplog`-based
test), or reach a checkpoint, episode, report, or experience record.
Configured `direct_file_read_headers` (e.g. a session cookie) are
substituted into the outgoing request only — they are never persisted to
the EKG (metadata is limited to the fixed field set in §17.6), and
`ApexConfig.to_safe_dict()` redacts header *values* (keeping header
*names* visible) exactly as it does for `tool_service_token`.

### 17.16 How the same objective now works through two transports

No change was needed to make this true — it falls directly out of §16's
original design plus this phase's two fixes (§17.8's `runtime_available`
plumbing and §17.12's phase-gate fix):

```
SSH path (§16):
  validated access_state --derive_ssh_capability--> access_capability(ssh_command)
    --ensure_ssh--> SSHCapabilityAdapter --read_bounded_file--> verify_user_flag --> objective_evidence

Direct-file-read path (§17):
  operator attestation --seed_direct_file_read_capability--> access_capability(arbitrary_file_read | api_file_read)
    --ensure_direct_file_read--> DirectFileReadCapabilityAdapter --read_bounded_file--> verify_user_flag --> objective_evidence
```

Both converge on the identical `verify_user_flag()` call and the identical
`objective_evidence` node shape — `ObjectivePlanner`, `UserFlagExecutor`,
and `ObjectiveParser` are byte-for-byte the same code regardless of which
path produced the capability.

### 17.17 Extending with a THIRD capability type

Unchanged from §16.11's four steps — this phase adds nothing new to that
list, and the fact that it didn't need to is the point:

1. A new adapter class in `apex_host/runtime_registry.py` implementing
   `FlagReadCapability.read_bounded_file(path) -> BoundedReadResult`.
2. A new `derive_<type>_capability()` method on `CapabilityParser`.
3. A new registration branch in `_register_capability_adapter()`.
4. A new entry in `CAPABILITY_TYPE_LABELS`.

**Still never required:** any change to `ObjectivePlanner`,
`UserFlagExecutor`, `ObjectiveParser`, the report generator, or
`check_bounded_user_flag_verification` — now proven twice (SSH, then
direct-file-read) rather than once.

### 17.18 Known limitations (additive to §15/§16.12)

- Only one operator-attested direct-file-read primitive can be configured
  per engagement (`ApexConfig` has exactly one set of `direct_file_read_*`
  fields, not a list) — a target with two independently-discovered
  file-read primitives would need two separate engagement configurations
  or a follow-on change to make these fields a list.
- There is no live web-exploitation validation step that *discovers* a
  direct-file-read primitive automatically (e.g. by trying a canary file
  against a suspected LFI endpoint) — the operator must supply the
  confirmed request shape via configuration. Building that discovery
  mechanism was explicitly out of this phase's scope.
- `max_redirect_hops` defaults to 1 once `allow_redirects=True`; a request
  shape that legitimately requires more than one authorized-origin hop
  needs an explicit, operator-supplied higher value.
- The `_DIRECTNESS_RANK` tie-break in §17.10 only ever applies when two
  candidates are otherwise equal on validation status and confidence —
  it does not, and is not intended to, override a genuinely more confident
  SSH capability with a lower-confidence direct-file-read one.

## 18. Bounded Command-Execution Capability (Phase 21)

§17.17 predicted this too, and it holds a second time over: a further
`FlagReadCapability` adapter added using only the same four extension
points, with **no change** to `ObjectivePlanner`, `UserFlagExecutor`,
`ObjectiveParser`, the report generator, or
`check_bounded_user_flag_verification` (only a defensive hardening — see
§18.9). This section documents a generic, bounded, policy-gated
**command-execution** capability, covering primitives such as an
authenticated web command endpoint, a validated command-injection
primitive, an established web-shell-like channel, a validated local
shell/session handle, a validated remote command channel, or an existing
authorized execution backend that can run one narrow read action.

**This phase does not implement vulnerability discovery, payload
generation, reverse-shell creation, persistence, privilege escalation, or
arbitrary interactive shells.** It lets the User Flag Objective consume a
validated execution capability through the same transport-independent
interface SSH and Direct File Read already use.

### 18.1 Capability types: reused where possible, one genuine addition

`AccessCapabilityType.web_command` already existed (added speculatively in
Phase 18B, alongside `local_shell`, ahead of either having a real
adapter). This phase reuses both:

- **`web_command`** — reused with NO new adapter class. Registered through
  the exact same `_register_direct_file_read_adapter` and
  `ApexConfig.direct_file_read_*` configuration `arbitrary_file_read`/
  `api_file_read` already use — the underlying mechanism (a fixed HTTP
  request shape) is identical; only the capability_type label differs,
  recording whether the operator classifies the primitive as "serves a
  file directly" or "executes a command whose response happens to contain
  the read output." Its *derivation* still goes through the new
  command-evidence vocabulary (§18.2), not the file-read-evidence
  vocabulary — the mechanism is shared, the required evidence is not.
- **`local_shell`** — reused, relabeled `"Local Command"` in reports (the
  same rename pattern `arbitrary_file_read` → `"Direct File Read"`
  already established in Phase 20). Represents "execution inside an
  already-established local runtime/session context."
- **`remote_command`** — a genuinely NEW 7th enum member. No existing type
  represented "an already-established, non-web, non-SSH remote session" —
  `ssh_command`/`telnet_command` are already protocol-specific. Added
  additively (backward compatible — no existing member removed or
  renamed).

`local_shell` and `remote_command` share ONE new adapter class,
`BoundedCommandCapabilityAdapter` — they differ only in which runtime
strategy/backend was constructed for them, never in the adapter's own
logic, matching "if two types are behaviorally identical and only differ
as metadata labels, they may share one adapter."

### 18.2 `derive_command_capability` — a fourth, evidence-appropriate derivation method

A new `CapabilityParser.derive_command_capability(...)` method (alongside
`derive_ssh_capability`/`derive_direct_file_read_capability`) handles all
three command-oriented types (`local_shell`, `remote_command`,
`web_command`). It requires an accepted `validation_method` — a DIFFERENT
vocabulary from Direct File Read's, since "proving a controlled command
execution" is evidentially distinct from "proving a file-serving
endpoint":

- `operator_attestation` — the same trust boundary as `--username`/
  `--password` and Direct File Read's own attestation.
- `canary_output_match` — a harmless, fixed, operator-approved canary
  command was executed and its output matched exactly.
- `nonce_bound_execution` — a single-use random value embedded in the
  command/expected output was observed in the result, proving the
  response came from a real execution of THIS request.
- `deterministic_benign_command` — a fixed, universally benign command
  with predictable output was executed and verified.
- `backend_confirmed_session` — an existing, already-authorized execution
  backend confirmed (via its own session/handle validation) that this
  session can run a bounded read action.

An HTTP 200 alone, an LLM's own claim of successful command injection,
output merely containing a common OS word, a shell-like error, discovered
credentials, or application administrator access are all explicitly
**not** accepted evidence — none of them demonstrate that APEX itself can
invoke a specific, bounded, read-only command and observe its real
output. `confidence >= 0.6` and a non-empty `principal` are required, same
as every other `derive_*` method.

Sanitized `metadata`: `{validation_method, max_output_bytes, strategy_id,
read_only: True}` — never a command string, shell payload, session token,
or raw canary/flag value. `strategy_id` is an opaque label identifying
which fixed strategy binding produced the capability, never the strategy
object itself.

### 18.3 The narrow strategy protocol — how arbitrary command execution was prevented

The single most important design constraint in this section:

```python
class BoundedCommandReadStrategy(Protocol):
    async def read_file(
        self, path: str, *, timeout_seconds: float, max_output_bytes: int,
    ) -> BoundedReadResult: ...
```

There is no `execute()`, `run_shell()`, `send_command()`, or `exec()`
anywhere in this Protocol, in `BoundedCommandCapabilityAdapter`, or
reachable from `ObjectivePlanner`/`UserFlagExecutor`/task metadata. A
strategy implementation may internally hold a reference to a much
broader execution backend, but it exposes only this one bounded,
path-scoped method to the capability layer — enforced by a static test
(`inspect.getmembers` shows exactly one public method).
`BoundedCommandCapabilityAdapter.read_bounded_file(path)` — the SAME
narrow, objective-facing interface every other adapter implements — is
the ONLY method the objective layer, the LLM, or task metadata can ever
reach. The objective controls exactly one `capability_id` and one
approved candidate path; it never controls a command name, shell
operator, pipe, redirect, environment variable, working directory,
interpreter, executable path, or any argument beyond the path value.

`BoundedCommandReadPrimitive` (the command-execution analogue of
`DirectFileReadPrimitive`) binds a `capability_id` to a fixed `strategy`
object plus `allowed_filenames`/`timeout_seconds`/`max_output_bytes` —
constructed once, validated at construction (`__post_init__` rejects
non-positive timeout/byte values), and never mutated afterward. The only
per-call variable is the candidate path.

### 18.4 `BoundedCommandCapabilityAdapter` — defense in depth on every call

On every `read_bounded_file(path)` call:

1. Re-validates *path* via `is_bounded_candidate_path()` — the adapter
   never trusts a caller to have already validated.
2. Invokes the strategy under an outer `asyncio.wait_for` timeout
   (belt-and-suspenders on top of whatever internal timeout the strategy
   itself applies).
3. Re-enforces the maximum output size on the strategy's own returned
   output — an oversized result is rejected outright (`output=""`, a
   bounded `truncated=True` result, never a partially-accepted prefix),
   mirroring `DirectFileReadCapabilityAdapter`'s identical invariant.
4. Maps exceptions to bounded, sanitized error categories
   (`execution_context_unavailable`, `timeout: ...`) — the adapter never
   raises, and error strings never include a raw exception message that
   might embed sensitive detail.
5. Never logs, returns, or persists the raw output beyond the
   `BoundedReadResult` handed to `UserFlagExecutor`.

### 18.5 `ToolBackendCommandReadStrategy` — the one concrete reference implementation

Rather than spawning a subprocess directly (which would violate CLAUDE.md
§13.6, "no raw child-process spawning outside
`apex_host/tools/runner.py`"), the one shipped reference strategy wraps an
existing, already-safety-gated `apex_host.tools.backend.ToolBackend` —
the SAME seam Infra Phase 2/4 already built for every other command
execution in this codebase (`LocalToolBackend`/`RemoteToolBackend`/
`DryRunToolBackend`).

It issues exactly one fixed, non-configurable command per call:

```python
await backend.execute("cat", ["--", path], timeout_seconds=timeout_seconds)
```

Argv-list only, never a shell string. `"cat"` is a new, optional entry in
`apex_host/tools/registry.py::_KNOWN_TOOLS` (not in the default
`allowed_tools` — the operator must explicitly allow it, mirroring
`ffuf`/`gobuster`'s existing optional-tool precedent) and is still
independently checked against the allowlist and the destructive-command
blocklist by `apex_host.tools.safety.check_command` on every call — the
same gate every other tool invocation passes through. Requesting an
unlisted tool raises `ValueError`, which the adapter catches and maps to
`execution_context_unavailable` rather than letting it escape.

Dry-run is honored twice, independently: `UserFlagExecutor` already
short-circuits before ever resolving an adapter when `config.dry_run` is
`True` (unchanged, transport-independent behavior), and separately,
whichever `ToolBackend` the orchestration layer injects here is *itself*
guaranteed to be a `DryRunToolBackend` whenever `config.dry_run` is `True`
(`apex_host.tools.backend.select_runtime_backend`'s own binding
invariant) — so even a hypothetical future caller that bypassed the
executor's own dry-run gate could not reach a real command execution
through this strategy.

`remote_command`'s intended real-world backend (a Kali tool-service
container, via `RemoteToolBackend`) is architecturally supported by this
same strategy class — only the injected `ToolBackend` instance differs —
but wiring `"cat"` into `apex_tool_service`'s own separate allowlist
(`apex_tool_service/allowlist.py`) was out of this phase's scope (that
service is a separately deployable component with its own allowlist
review process). `remote_command`'s registration therefore currently
succeeds only when `config.tool_backend` resolves to a backend that
already accepts `"cat"` — see §18.13 for the documented limitation.

### 18.6 Registration — `_register_bounded_command_adapter`

`apex_host/orchestration/dispatch_node.py::_register_capability_adapter`
gained one more routing branch:

```python
if cap.capability_type in (AccessCapabilityType.local_shell, AccessCapabilityType.remote_command):
    return _register_bounded_command_adapter(deps, target, cap)
```

Mirrors `_register_direct_file_read_adapter`'s principal-matching
discipline exactly: only a capability whose principal matches
`config.bounded_command_principal` gets provisioned. Construction is
always safe (constructing a `ToolBackend` and wrapping it in a strategy
performs no execution); a `ValueError` from primitive construction (e.g. a
misconfigured `RemoteToolBackend` with no `tool_service_url`) is caught
and logged, and the capability simply stays `runtime_available=False`.

### 18.7 Operator-attested seeding

`apex_host/orchestration/capability_seed.py::seed_bounded_command_capability`
mirrors `seed_direct_file_read_capability` exactly in shape and safety
properties: six new `ApexConfig` fields
(`bounded_command_operator_attested`, `_capability_type`, `_principal`,
`_confidence`, `_timeout_seconds`, `_max_output_bytes`), called once at
engagement startup, **no live command execution** — only fixed EKG deltas
from already-known configuration. Deliberately **no**
`--command`/`--exec`/`--shell-command`/`--payload` CLI flag exists
anywhere — only structured configuration that binds an already-safe
runtime strategy. `web_command` is seeded through the EXISTING
`seed_direct_file_read_capability` (extended to special-case
`web_command`'s derivation call to use `derive_command_capability` instead
of `derive_direct_file_read_capability`, while still validating and
reusing the identical `direct_file_read_origin`/`endpoint_template`/etc.
configuration) — see that function's own updated docstring.

### 18.8 Attempt tracking — no new work needed

Pair-scoped `(capability_id, candidate_path)` tracking (§17.11) already
generalizes to any number of capability types with zero changes — a
failed SSH attempt, a failed direct-file-read attempt, or a failed
bounded-command attempt on the same path never blocks a retry through a
different, still-available capability. `_is_globally_exhausted()` already
iterates every validated+available capability regardless of type.

### 18.9 Policy — one defensive hardening, no weakening

`check_bounded_user_flag_verification()` needed no functional change to
support command capabilities — it already inspected only
`task.params["target"]`/`["candidate_path"]`, and `ObjectivePlanner` never
emits a `command`/`shell_command`/`exec`/`payload`/`env`/`cwd`/
`executable`/`args` field in a `user_flag_verify` task's params regardless
of capability type. This phase adds one defensive check to the SAME rule
(`_FORBIDDEN_COMMAND_PARAM_KEYS`): a task whose params contain any of
those keys is blocked outright. This is belt-and-suspenders against a
future planner bug ever adding one of those keys — not a response to
anything the current planner can produce — and is proven by a dedicated
dispatcher-level test that a task carrying a `command` field never
reaches the executor.

### 18.10 Reporting and metrics

`capability_type_label("local_shell")` now returns `"Local Command"`
(previously `"Local Shell"`); `"remote_command"` returns `"Remote
Command"`; `"web_command"` remains `"Web Command"`. The existing
"Capability used: <label>" line (§16.9) renders all three with zero
report-generator changes.

A new "Bounded Command Summary" report section (shown only when at least
one command-capability node exists) adds eight `RunReport` fields —
`bounded_command_capabilities_derived`, `_adapters_registered`,
`_unavailable_strategies` (derived — capabilities minus registered
adapters, never negative), `_attempts`, `_blocked_attempts`, `_timeouts`,
`_oversized`, `_verified_count` — all derived from the final subgraph plus
a new `ApexGraphState.bounded_command_log` accumulator (mirrors
`direct_file_read_log`'s exact convention; disjoint capability-type sets
mean a given attempt is counted in at most one of the two logs). No raw
command string, session handle, or candidate output ever appears in the
report text or JSON export.

### 18.11 EKG design — no new node/edge types

Reuses `access_capability` nodes and the existing `has_capability`/
`enables` relationships exactly as SSH and Direct File Read do. No
separate shell/session node was introduced — a command capability remains
represented as sanitized capability metadata only; the live strategy/
backend object is never stored in the graph.

### 18.12 Raw-output and secret lifecycle

Identical to the SSH/DFR lifecycle (§8/§17.15), traced through one more
hop: `ToolResult.stdout` → local variable inside
`ToolBackendCommandReadStrategy.read_file()` → `BoundedReadResult.output`
→ `BoundedCommandCapabilityAdapter`'s pass-through → `UserFlagExecutor`'s
local stack frame → `verify_user_flag()`'s local `raw_output` parameter →
digest/redacted computation → discarded. At no point does the raw value
reach a dataclass field that survives past that call chain, get logged,
or reach a checkpoint, episode, report, or experience record.

### 18.13 Known limitations (additive to §15/§16.12/§17.18)

- `remote_command`'s real-world backend (a Kali tool-service container)
  requires `"cat"` to be independently allowlisted in
  `apex_tool_service/allowlist.py` — out of this phase's scope. Until
  that's done, `remote_command` registration only succeeds against a
  `ToolBackend` that already accepts `"cat"` (e.g. a custom `local`
  backend configuration).
- Only one operator-attested bounded-command primitive can be configured
  per engagement (mirrors Direct File Read's identical limitation).
- There is no live web-exploitation or session-discovery step that
  *discovers* a command-execution primitive automatically — the operator
  must supply the confirmed strategy binding via configuration or a
  future planner/executor pairing that wires a real backend.
- `local_shell`'s report label ("Local Command") no longer matches its own
  enum member name ("local_shell") — a deliberate rename, per the same
  precedent as `arbitrary_file_read` → "Direct File Read," documented here
  so it is never mistaken for an inconsistency.
- `_FORBIDDEN_COMMAND_PARAM_KEYS` is a fixed, hardcoded set — a future
  planner bug that introduces a differently-named forbidden field would
  not be caught by this specific check (though it would still need to
  pass `is_bounded_candidate_path` and every other existing rule).

## 19. Live Remote Bounded File Read Through the Kali Tool Service (Phase 22)

Phase 21 shipped the full `local_shell`/`remote_command`/`web_command`
capability abstraction, but `remote_command`'s only real strategy
(`ToolBackendCommandReadStrategy`) submitted its fixed `cat -- <path>` read
through `ToolBackend.execute()` — a generic call. For `RemoteToolBackend`
this meant POSTing `{"tool": "cat", "arguments": ["--", path]}` to
`apex_tool_service`'s existing `/v1/execute` endpoint, where `cat` has
never been (and, deliberately, should never be) in `ALLOWED_TOOLS` —
adding it there would let ANY caller of the generic endpoint read ANY file
the service process can see, using ONLY the existing shell-metacharacter/
control-character checks as protection — far too broad a capability to
grant just to unblock one narrow, already-safe operation. A live remote
bounded-command read therefore could not complete.

This phase adds a **dedicated, structurally separate** bounded-file-read
operation to `apex_tool_service` — never by widening the generic
allowlist — and wires `RemoteToolBackend`/`ToolBackendCommandReadStrategy`
to use it. **This phase does not add vulnerability discovery, payload
generation, reverse-shell creation, or persistence** — it only completes
the runtime path for an already-validated bounded command-read capability.

### 19.1 Why not just add `cat` to `ALLOWED_TOOLS`

`ALLOWED_TOOLS` governs `POST /v1/execute` — a caller there supplies
`arguments` freely (any argv tokens that pass the existing shell-
metacharacter/control-character checks). Adding `cat` would mean any
authenticated caller of that endpoint could read `cat <arbitrary-path>` —
an unrestricted arbitrary-file-read primitive, with no path allowlist, no
target-authorization check, and no basename restriction. The **dedicated**
`POST /v1/bounded-file-read` operation this phase adds instead never
accepts a `tool`/`arguments`/`command` field at all
(`ReadBoundedFileRequest`'s `model_config = ConfigDict(extra="forbid")`
rejects any such field by schema alone) — the caller supplies only
`target`/`path`/bounds, and the SERVICE constructs the fixed
`["cat", "--", validated_path]` argv internally, after its own independent
target-authorization and path-allowlist checks. `cat` remains absent from
`ALLOWED_TOOLS` — proven by a dedicated test
(`test_no_generic_cat_allowance_added`).

### 19.2 The dedicated service operation

```
POST /v1/bounded-file-read
Authorization: Bearer <token>          (same bearer-token auth as /v1/execute)

{
  "target": "10.129.1.5",
  "path": "/home/application/user.txt",
  "timeout_seconds": 10,
  "max_output_bytes": 4096,
  "dry_run": false
}
```

`ReadBoundedFileRequest`/`ReadBoundedFileResponse`
(`apex_tool_service/models.py`) are structurally separate Pydantic models
from `ExecuteRequest`/`ExecuteResponse` — there is no `tool`, `arguments`,
`stdin`, `command`, `argv`, `executable`, or `shell` field anywhere on the
request model, and none may ever be added (enforced by
`test_no_arbitrary_command_fields_in_bounded_request_model`, which asserts
the exact field set). The response carries `ok`, `output`, `error_code`,
`sanitized_error`, `return_code`, `bytes_received`, `oversized`,
`timed_out`, `duration_ms`, `method` — `output` is the ONLY field that may
ever carry file content, and it is populated only on `ok=True`.

Order of operations inside the route handler (`apex_tool_service/app.py::
read_bounded_file`), mirroring `/v1/execute`'s own discipline exactly: (1)
bearer-token auth (503 if unconfigured, 401 if invalid — same
`check_bearer_token` function, unmodified); (2) request-schema validation;
(3) target authorization; (4) path validation; (5) limit resolution
(`min(requested, service_hard_limit)`); (6) dry-run short-circuit; (7)
execution; (8) sanitized audit log; (9) response. Ordinary read failures
(file not found, permission denied, oversized, timeout) all return HTTP
`200` with `ok=false` — exactly like `/v1/execute`'s "ordinary command
failure is data, not an HTTP error" convention — only auth failures
(`401`/`503`) and validation failures (`400`) are non-`200`.

### 19.3 Target authorization (independent, service-side)

`validate_target_authorized(target, *, authorized_cidrs)`
(`apex_tool_service/validation.py`) requires `target` to be a
syntactically valid IP address falling within at least one configured
CIDR (`ServiceSettings.authorized_cidrs`, env `
APEX_TOOL_SERVICE_AUTHORIZED_CIDRS`, default `10.129.0.0/16` — mirroring
`ApexConfig.htb_route_cidr`'s own established default, the standard HTB
lab network range). This naturally rejects loopback, link-local, the cloud
metadata endpoint (`169.254.169.254`), and unrelated private/public
networks by default, since none of them fall within `10.129.0.0/16` unless
an operator has explicitly reconfigured `authorized_cidrs` to include them
(e.g. `127.0.0.0/8` for local testing) — there is no separate hardcoded
blocklist to bypass or maintain. This is a genuinely independent
authorization check, not a weaker parallel to `apex_host`'s own policy
gate: `apex_tool_service` still has no import of `apex_host`/`memfabric`
anywhere (unchanged from Infra Phase 3) and still has no concept of
"engagement" — it validates the request against its OWN configured scope,
in addition to (never instead of) `apex_host`'s
`check_bounded_user_flag_verification` policy rule running first, entirely
on the `apex_host` side, before the HTTP request is even sent.

### 19.4 Path validation (independent, service-side, with parity tests)

`validate_bounded_path(path, *, allowed_basenames)`
(`apex_tool_service/validation.py`) mirrors
`apex_host.verification.user_flag.is_bounded_candidate_path`'s exact
invariants — same charset regex (absolute path, conservative character
set, bounded to 254 characters), same `..`-traversal rejection, same
approved-basename requirement (`ServiceSettings.allowed_flag_basenames`,
env `APEX_TOOL_SERVICE_ALLOWED_FLAG_BASENAMES`, default `user.txt` only —
never widened to arbitrary filenames or system paths). This is a
DUPLICATED, not shared, validator — `apex_tool_service` still never
imports `apex_host` (§7/§15 of `docs/kali-tool-service.md`) — and a
dedicated parity test
(`TestPathValidatorParity::test_apex_host_and_service_validators_agree`,
parametrized across the same adversarial inputs: traversal, wildcards,
shell metacharacters, newlines, NUL bytes, oversized paths) proves the two
validators reach identical accept/reject decisions.

### 19.5 Fixed argv construction (the core safety property)

`apex_tool_service/executor.py::execute_bounded_file_read` is the
function that actually launches the read. The fixed executable
(`_BOUNDED_READ_EXECUTABLE = "cat"`) and the `--` separator are Python
constants inside this trusted module — never a request field, a
`ServiceSettings` value, or an environment variable. The ONLY caller-
supplied input is the already-validated `path`, substituted into the argv
list as its own separate argument:

```python
argv = ["cat", "--", path]
proc = await asyncio.create_subprocess_exec(*argv, ...)   # never shell=True
```

This is the second (and last) `asyncio.create_subprocess_exec` call site
in `apex_tool_service` — both remain confined to `executor.py`
(`test_exactly_one_subprocess_creation_call_site`'s own assertion is
`all(name == "executor.py" ...)`, not an exact count, so this addition
does not weaken that invariant). Output is read incrementally, in small
chunks, stopping the instant more than `max_output_bytes` has been
received — never buffering an unbounded amount of data before checking
the limit. **Oversized output is discarded completely**: the function
returns `output=""` with `oversized=True`, never a truncated prefix — the
adapter/executor's identical "never partially accept" invariant, now also
enforced service-side. stderr is captured (bounded, generously) only to
classify a non-zero exit into a stable category
(`file_not_found`/`permission_denied`/`invalid_path`/`process_failed`) via
`_classify_stderr()` — the raw stderr text itself is discarded immediately
after classification and never returned, logged, or persisted anywhere.

### 19.6 `ToolBackend` — a narrow, checked capability seam

`apex_host/tools/backend.py` gained a SEPARATE Protocol,
`BoundedFileReadBackend` (`@runtime_checkable`, one method:
`read_bounded_file(target, path, *, timeout_seconds, max_output_bytes) ->
BoundedReadResult`) — not an addition to the existing `ToolBackend`
Protocol, since not every backend needs this narrower capability.
`ToolBackendCommandReadStrategy.read_file()` checks support via
`isinstance(backend, BoundedFileReadBackend)` — a real, checked capability
test against a `@runtime_checkable` Protocol, never blind duck-typing.

All three real backends implement it:

- **`DryRunToolBackend.read_bounded_file()`** — returns a deterministic,
  synthetic, never-executed result UNCONDITIONALLY (never delegates to
  `execute()`, unlike its own `execute()` method, which still runs
  `check_command()` even in dry-run — a bounded file read has no
  equivalent "was this approved" concern, so making this depend on an
  unrelated tool-allowlist entry would undermine this backend's whole
  purpose as an unconditional safe backstop).
- **`LocalToolBackend.read_bounded_file()`** — reuses the existing trusted
  `execute("cat", ["--", path])` path (local execution is the operator's
  own machine, not a shared multi-tenant service, so the "do not widen a
  shared allowlist" concern that motivates the dedicated remote endpoint
  does not apply here; `cat` must still be in `ApexConfig.allowed_tools`,
  an optional, not-default tool).
- **`RemoteToolBackend.read_bounded_file()`** — calls the new dedicated
  `POST /v1/bounded-file-read` operation (§19.2), never `/v1/execute`.

A FALLBACK path is preserved in `ToolBackendCommandReadStrategy` for test
doubles that implement only `execute()` (e.g. a minimal fake `ToolBackend`
used across the Phase 21 test suite) — when the injected backend does NOT
implement `BoundedFileReadBackend`, the strategy falls back to its
original Phase 21 behavior byte-for-byte. This is why every pre-existing
Phase 21 test continued to pass unmodified.

### 19.7 `RemoteToolBackend.read_bounded_file()` — client implementation

Mirrors `execute()`'s own structure closely: dry-run short-circuit first
(delegates to `DryRunToolBackend.read_bounded_file()`, never touching the
network); POSTs a structured `{target, path, timeout_seconds,
max_output_bytes}` body (never a command/argv/executable field) to
`{base_url}/v1/bounded-file-read`; the same `Authorization: Bearer <token>`
header as `/v1/execute`; the same client-side timeout margin
(`_CLIENT_TIMEOUT_MARGIN_SECONDS`) strategy; the same transport-failure
taxonomy (connect timeout, read timeout, connect error, generic
`RequestError`) — all mapped to a `BoundedReadResult` (not a `ToolResult`
— a structurally distinct return type with its own required-field
validation, `_REQUIRED_BOUNDED_READ_RESPONSE_FIELDS`). A malformed/missing-
field response is rejected the same way `_map_response()` already rejects
one for the generic path. `connected` is `True` for every well-formed
response except `error_code == "backend_unavailable"` (the one case where
the service could not even attempt the read) — a failed-but-engaged read
(file not found, permission denied, oversized) still counts as
`connected=True`, mirroring `ToolBackendCommandReadStrategy`'s own
established "connected unless the mechanism itself never engaged"
convention. Never logs the response body/output — only a bounded,
sanitized failure message on the error paths.

`BoundedReadResult` (`apex_host/runtime_registry.py`) gained one new,
additive, backward-compatible field: `timed_out: bool = False` — a
distinct, structured signal from the server's own explicit timeout
detection, kept separate from `error` so callers never need to substring-
match error text to detect a timeout.

### 19.8 Policy — unchanged, re-verified at both layers

`check_bounded_user_flag_verification()` (`apex_host/policy/rules.py`)
needed no change for this phase — it already blocks an off-scope target
before `UserFlagExecutor` is ever reached, entirely on the `apex_host`
side, regardless of which capability type or transport would have serviced
the (now-blocked) request. This phase adds a dedicated test proving the
SAME guarantee holds independently at the SERVICE layer too — an
unauthorized-target `POST /v1/bounded-file-read` request never reaches
`asyncio.create_subprocess_exec` (`test_blocked_request_never_reaches_
subprocess_on_service`), and a `dry_run: true` request never does either
(`test_dry_run_never_calls_subprocess`).

### 19.9 Dry-run — defense in depth at three layers

1. `UserFlagExecutor` still short-circuits before ever resolving an
   adapter when `config.dry_run` is `True` (unchanged since Phase 18).
2. `RemoteToolBackend.read_bounded_file()` checks `config.dry_run` first
   and delegates to `DryRunToolBackend.read_bounded_file()` without ever
   touching the network (unchanged pattern from `execute()`).
3. **New this phase:** `ReadBoundedFileRequest.dry_run` — an independent,
   service-side mirror. When `true`, the service returns
   `{"ok": false, "error_code": "dry_run", ...}` without ever calling
   `execute_bounded_file_read()` — proven by a test that monkeypatches
   `asyncio.create_subprocess_exec` to raise if called at all, then sends
   `dry_run: true` and confirms it is never invoked.

### 19.10 Error categories

`apex_tool_service`'s stable `error_code` vocabulary:
`backend_unavailable`, `timeout`, `oversized_output`, `file_not_found`,
`permission_denied`, `invalid_path`, `process_failed`, `dry_run` — each
mapped to a fixed, generic `sanitized_error` phrase
(`apex_host/app.py::_ERROR_CODE_MESSAGES`), never derived from raw
stderr/exception text. `apex_host`'s own `RemoteToolBackend` layers its
own transport-level categories on top (`could not connect...`, `... timed
out`, `response missing required field(s): ...`) for failures that never
reached the service at all.

### 19.11 Logging and secret handling

Never logged, anywhere in the new code: raw file content/output (neither
service-side `audit.py::log_bounded_read_result` nor client-side
`RemoteToolBackend` ever pass `output`/response body to a log call), raw
stderr (discarded immediately after `_classify_stderr()` categorizes it),
the bearer token (reuses the exact same `check_bearer_token`/
`log_auth_failure` discipline as `/v1/execute`). Audit log fields are
bounded metadata only: correlation ID, `target`, the candidate's basename
(already drawn from a small, approved allowlist — not sensitive), `ok`,
`error_code`, `bytes_received`, `oversized`, `timed_out`,
`duration_seconds`. The full path (not just the basename) is never logged.

### 19.12 Reporting — unchanged

"Capability used: Remote Command" (`capability_type_label`, unchanged
since Phase 21) continues to render exactly as before — this phase adds
no new report field, no raw command/path/output surfacing. The existing
"Bounded Command Summary" section and its seven metrics
(`bounded_command_*`) already counted `remote_command` attempts/successes/
timeouts/oversized responses generically via `bounded_command_log`
(populated from the `user_flag_verify` tool_result, which is identical in
shape regardless of which capability type or transport produced it) — no
change was needed there either.

### 19.13 Tests

`tests/apex_tool_service/test_bounded_file_read.py` (79 tests) — request
model, authentication, path/target security (with the apex_host parity
test), process safety (real subprocess execution against temp files —
argv exactly `["cat", "--", path]`, oversized-output discarded, stderr
never returned), generic-endpoint isolation (`cat` still rejected on
`/v1/execute` with or without `--`), output/error sanitization, limit
resolution, service-side dry-run, health, and architecture scans.

`tests/apex_host/test_phase22_remote_bounded_file_read.py` (41 tests) —
`RemoteToolBackend.read_bounded_file()` unit tests (dedicated route,
structured body, token handling, malformed-response rejection, timeout
mapping, no output logging), strategy integration (preferred path used,
generic `execute()` never called for a `BoundedFileReadBackend`-supporting
backend), policy (blocked-at-both-layers, dry-run-never-subprocess),
**a full synthetic engagement proving `remote_command` alone — no SSH, no
Direct File Read — reaches `EngagementOutcome.user_flag_verified` through
a REAL, in-process `apex_tool_service` app** (via `httpx.ASGITransport`,
no Docker, no real socket, no HTB), a matching negative suite (service
unavailable, unauthorized, invalid candidate, not found, permission
denied, oversized, malformed response — all non-success, non-zero exit),
and architecture scans.

### 19.14 Docker/Compose

`compose.yaml`'s `kali` service gained four new environment variables
(`APEX_TOOL_SERVICE_BOUNDED_READ_MAX_BYTES`,
`APEX_TOOL_SERVICE_BOUNDED_READ_TIMEOUT`,
`APEX_TOOL_SERVICE_ALLOWED_FLAG_BASENAMES`,
`APEX_TOOL_SERVICE_AUTHORIZED_CIDRS`), each `${VAR:-default}`-interpolated
with the default matching `ServiceSettings`'s own real implementation
default — overridable via `.env`, zero behavior change for an operator who
does not edit it. No Dockerfile change was needed — `cat` is part of
`coreutils`, already present in the Kali image (a base-system package,
never explicitly installed or removed) since Infra Phase 6; only the
*application-layer* allowlist gap (§19.1) needed fixing, not anything at
the container/image level. `compose.htb.yaml` needed no changes — it
overrides only `network_mode`/`APEX_TOOL_SERVICE_URL`, not the `kali`
service's other environment variables, which continue to merge in
unchanged from the base file.

### 19.15 Known limitations (additive to §15/§16.12/§17.18/§18.13)

- No server-side rate limiting on the new endpoint (same pre-existing
  limitation as `/v1/execute` — see `docs/kali-tool-service.md` §16).
- `authorized_cidrs`/`allowed_flag_basenames` are service-wide, not
  per-caller — there is still exactly one configured bearer token and no
  multi-tenant scoping (unchanged limitation from Infra Phase 3).
- The dedicated endpoint's own `dry_run` field (§19.9) is independent of,
  and does not read from, `apex_host`'s `ApexConfig.dry_run` — an operator
  driving the service directly (bypassing `apex_host` entirely) must set
  it explicitly per request if that defense-in-depth layer matters to
  them.
- `web_command` continues to share `DirectFileReadCapabilityAdapter`/the
  `/v1/execute`-adjacent HTTP mechanism from Phase 20/21, unchanged by
  this phase — this phase's new dedicated endpoint and
  `BoundedFileReadBackend` seam apply to `local_shell`/`remote_command`
  only.
- No Docker Compose integration test in the default `pytest` suite spins
  up a REAL container and calls the new endpoint over a real socket — the
  "real remote path" proof in this phase's test suite uses
  `httpx.ASGITransport` against the real, unmodified `apex_tool_service`
  FastAPI app in-process (no Docker), which exercises the identical
  request/response contract and code paths a real container would, but
  does not itself prove container networking/health/build correctness
  (those remain covered by the separate, pre-existing Infra Phase 6/7
  Docker test suite and manual `docker compose` verification).

> **Correction (Phase 22, live remote path):** the first limitation listed
> above ("`remote_command`'s real-world backend requires `cat` to be
> independently allowlisted in `apex_tool_service/allowlist.py`") described
> the state of the codebase as it existed at the end of Phase 21 and is
> left in place per this file's append-only correction convention, not
> rewritten. **It is no longer the reason a live remote bounded-command
> read cannot complete.** Phase 22 (§19 below) resolves this properly —
> not by adding `cat` to the generic allowlist, but by giving
> `apex_tool_service` a dedicated, narrower `POST /v1/bounded-file-read`
> operation that never touches `ALLOWED_TOOLS` at all. `RemoteToolBackend`
> (and therefore `remote_command`) now completes a real bounded file read
> through the actual Kali tool service.

## 20. Structured Automatic Capability Derivation (Phase 23)

**Status:** implemented. This section documents the deterministic
capability-evidence discovery pipeline in `apex_host/capabilities/` — the
mechanism that lets a validated execution result automatically produce an
`AccessCapability` (§16) without the operator manually seeding one every
time. **This is not autonomous vulnerability discovery.** It does not
teach APEX to discover SQL injection, XSS, command injection, or arbitrary
file read from scratch, does not generate exploit payloads, and does not
trust an LLM's own claim as evidence. It closes one narrower architectural
gap: a validated execution result already proves a capability exists —
this pipeline makes that fact deterministically flow into the same
`AccessCapability` records `ObjectivePlanner` already consumes, instead of
requiring the operator to have already known and pre-configured it.

### 20.1 Terminology

Three terms are used precisely and never interchangeably:

- **`CapabilityObservation`** — something merely observed (an open port, an
  HTTP 200, a discovered-but-untested credential). May be weak or
  incomplete. Cannot itself create a capability. This codebase has no
  dataclass for it — it is simply whatever signal a caller chooses NOT to
  turn into evidence, because it fails the acceptance bar below.
- **`CapabilityEvidence`** (`apex_host/capabilities/evidence.py`) —
  structured, validated proof. Has an accepted `evidence_type`. May be
  evaluated by a `CapabilityProvider`.
- **`CapabilityDerivationDecision`** (`apex_host/capabilities/decisions.py`)
  — a deterministic provider result: `accepted`, `rejected`, `duplicate`,
  `updated`, `runtime_unavailable`, or one of two reserved-for-forward-
  compatibility statuses (`superseded`, `expired`).
- **`AccessCapability`** (`apex_host/types.py`, unchanged since the access-
  capability refactor, §16) — persistent, sanitized capability metadata.
  This is what the pipeline ultimately writes to the EKG, via
  `CapabilityParser` — the same authoritative writer §16 already
  established, never bypassed.

### 20.2 Baseline before this phase — where AccessCapability was created

Only two paths existed:

1. `CapabilityParser.derive_ssh_capability()` — called inline from
   `apex_host/orchestration/parsing_node.py`'s `parse_single_result()`
   immediately after a real, successful SSH login (`AccessParser
   .parse_structured` had already validated it). The one genuinely
   parser-driven, automatic path.
2. `CapabilityParser.derive_direct_file_read_capability()`/
   `derive_command_capability()` — called ONLY from
   `apex_host/orchestration/capability_seed.py`'s two `seed_*` functions,
   both 100% operator-attested, startup-only.

There was no automatic/parser-driven path for direct-file-read,
`local_shell`, `remote_command`, or `web_command` — every one of those
required the operator to already know a working request/strategy shape
existed. That remains the reality after this phase for those four
families' *runtime activation* (see §20.9) — what changes is that ALL
FIVE families now share one common, deterministic derivation pipeline,
and SSH gains no new automatic trigger beyond the one it already had
(just relocated behind the same pipeline).

### 20.3 The pipeline

```
Executor or validated runtime operation
    -> CapabilityEvidence
    -> CapabilityDiscoveryEngine.discover()
        -> validate_evidence()              (central, family-agnostic gate)
        -> CapabilityProvider.evaluate()    (pure, one per family)
        -> CapabilityDerivationDecision
        -> CapabilityParser.derive_*()      (the sole metadata writer)
        -> MemoryAPI.apply_deltas()         (the ONLY graph write in this package)
        -> runtime_resolution.register_capability_adapter()
    -> CapabilityRuntimeRegistry adapter (when resolvable)
    -> ObjectivePlanner (unchanged — still just reads AccessCapability records)
```

Insertion point: `apex_host/orchestration/parsing_node.py`'s existing
`parse_observation` node, once per turn, immediately after that turn's
normal per-tool_result parse+`apply_deltas` loop — not a new LangGraph
node. This mirrors the SSH inline-derivation precedent exactly (evidence
naturally arises as a byproduct of the same "turn a tool result into graph
deltas" step parsing already performs) and satisfies "insert capability
discovery after structured parsing/validation and before the next global
planning decision" (`global_plan` runs at the START of the next turn).

### 20.4 `CapabilityEvidence` — the evidence model

Immutable (`@dataclass(frozen=True, slots=True)`). Never contains a
password, private key, bearer token, cookie value, raw command/HTTP
output, or a raw flag-like value — `validate_evidence()` scans
`sanitized_attributes`' KEYS (never values) against a fixed forbidden-key
set (`password`, `token`, `raw_output`, `flag_value`, ...) before any
provider ever sees it.

Key fields: `evidence_id`, `evidence_type`, `capability_family`,
`target_host_id`, `source_task_id`, `principal`, `validation_method`,
`confidence`, `timestamp`, `runtime_reference_id` (opaque, non-secret —
see §20.9), `runtime_generation`, `sanitized_attributes`, `is_dry_run`.

### 20.5 Evidence types

`CapabilityEvidenceType` (`apex_host/capabilities/evidence.py`):
`SSH_AUTHENTICATED_COMMAND`, `DIRECT_FILE_READ_VALIDATED`,
`LOCAL_COMMAND_VALIDATED`, `REMOTE_COMMAND_VALIDATED`,
`WEB_COMMAND_VALIDATED`, `RUNTIME_SESSION_CONFIRMED` (reserved — no
current provider consumes it standalone), `OPERATOR_ATTESTED` (the
pre-existing `--username`/`--password`-equivalent trust boundary, now
routed through this same pipeline — see §20.10). No member is ever named
after a vulnerability or a machine (no `SQLI_SUCCESS`, no
`ACADEMY_ADMIN`) — evidence describes WHAT KIND OF PROOF was produced,
never how a target-specific weakness was found.

### 20.6 Central evidence validation

`validate_evidence()` is the ONE place these are enforced, so no provider
re-implements any of them: missing target, unsupported/mismatched
evidence-type-vs-family pairing, confidence below the universal floor
(0.6), a rejected validation method (`http_200`, `llm_claim`,
`credentials_found`, `admin_access`, `payload_attempted`, `banner_only`,
`port_open` — an HTTP 200 alone, an LLM's own assertion, or a mere
credential/admin-access/payload-attempt record is NEVER sufficient
evidence), a raw secret/output/flag field smuggled into
`sanitized_attributes`, dry-run evidence (rejected unconditionally — a
dry-run result can never derive a live capability), a malformed negative
`runtime_generation`, and (opt-in, `ApexConfig
.capability_evidence_ttl_seconds`, default `0.0` = disabled) evidence
older than the configured TTL.

### 20.7 Provider interface and the five providers

`CapabilityProvider` (`apex_host/capabilities/providers.py`) — pure
functions from evidence to decision. Providers **never** write
`MemoryAPI`, **never** mutate `CapabilityRuntimeRegistry`, **never** open
a network connection, **never** invoke a tool, and **never** call an
LLM — enforced by a static architecture-scan test in addition to
construction (no such object is reachable from a provider's narrow
arguments).

- **`SSHCapabilityProvider`** — accepts only `SSH_AUTHENTICATED_COMMAND`
  (or `OPERATOR_ATTESTED` for the `ssh_command` family) evidence with a
  non-empty principal and confidence ≥ 0.85. Rejects: discovered-but-
  untested credentials, an open port 22, a banner, a failed login (none
  of these ever produce this evidence type in the first place).
- **`DirectFileReadCapabilityProvider`** — reuses
  `CapabilityParser`'s own pre-existing `_ACCEPTED_VALIDATION_METHODS`/
  `_MIN_DIRECT_FILE_READ_CONFIDENCE` (0.6) — the same acceptance authority
  §17 already established, not duplicated.
- **`LocalCommandCapabilityProvider`** / **`RemoteCommandCapabilityProvider`**
  — share acceptance logic (`_BoundedCommandProviderBase`) since both are
  serviced by the same `BoundedCommandCapabilityAdapter` at the runtime
  layer (§18); differ only in accepted `evidence_type`/`capability_family`.
  Reuse `_ACCEPTED_COMMAND_VALIDATION_METHODS`/
  `_MIN_COMMAND_CAPABILITY_CONFIDENCE` (0.6) from `CapabilityParser`.
- **`WebCommandCapabilityProvider`** — accepts evidence on its own merits
  (metadata can always be derived), but returns
  `CapabilityDerivationStatus.runtime_unavailable` whenever no
  `runtime_reference_id` is present — **honestly reporting** that no
  current mechanism activates a `web_command` runtime adapter from
  automatically-produced evidence alone (its adapter still requires an
  operator-fixed HTTP request shape — see §20.9). Never fakes runtime
  availability.

`DEFAULT_PROVIDERS` is a stable, ordered tuple — never a set/dict-
iteration-order dependency.

### 20.8 Identity, deduplication, and confidence merging

Capability identity is UNCHANGED from §16:
`access_capability_id(target, capability_type, principal)` — content-
addressed, never a function of any secret value. Re-deriving the same
identity always upserts the same node.

Provenance: each capability node's `metadata.evidence_provenance` is a
bounded list (capped at 20 entries) of contributing `evidence_id`s.
Replaying an evidence_id already present → `duplicate` status, confidence
**unchanged**. New, different evidence for an already-known identity →
`updated` status, confidence merged via **`new = max(existing, incoming)`**
— documented, deterministic, never a hidden average, never lowers a
validated capability because weaker duplicate evidence arrived, never
raises confidence by replaying identical evidence twice.

**A subtlety this phase had to resolve:** memfabric's own epistemic-
conflict invariant (CLAUDE.md §1.3 — "two high-confidence claims that
disagree are never silently overwritten") means a bare re-upsert with a
DIFFERENT confidence/metadata value for an already-high-confidence field
legitimately raises an open `Conflict`, blocking the plain upsert. Rather
than fighting that invariant (which exists for good reason — see §1), the
discovery engine, after every successful batch write, checks for and
immediately auto-resolves any resulting open conflict via `MemoryAPI
.auto_resolve_conflict()` — the substrate's own documented default policy
("higher confidence wins, tie → higher logical_version"). This achieves
exactly the `max(existing, incoming)` merge rule this section documents,
through the correct, substrate-endorsed mechanism, never a second,
competing merge implementation that bypasses the conflict model.

### 20.9 Runtime reference resolution — metadata vs. runtime availability

`apex_host/capabilities/runtime_resolution.py` contains the ONE
implementation of "construct + register a runtime adapter for a validated
`AccessCapability`" — relocated verbatim from
`apex_host/orchestration/dispatch_node.py`'s former private functions
(`_register_ssh_adapter`/`_register_direct_file_read_adapter`/
`_register_bounded_command_adapter`), which dispatch_node.py now imports
and calls, so both the pre-existing per-turn `make_objective_node`
registration loop and the new discovery engine share one implementation —
never two.

**Registration still requires `ApexConfig` fields matched by principal**
(the operator's configured credentials/request-shape/strategy) — evidence
carries a `runtime_reference_id` field for forward compatibility with a
future resolver design where an executor holds a reusable runtime object,
but no CURRENT concrete resolver consumes it: SSH/DFR/bounded-command
adapters are all reconstructed fresh from `ApexConfig` each time, exactly
matching the pre-existing per-turn registration behavior. This is why
`local_shell`/`remote_command`/`web_command` capabilities can gain
METADATA automatically (a decision is `accepted`) while remaining
`runtime_unavailable` until the operator has ALSO configured the matching
`bounded_command_*`/`direct_file_read_*` fields — the distinction between
"a validated capability exists" and "a runtime adapter is registered for
it" (`AccessCapability.runtime_available`) is preserved exactly as §16/§17
established.

`CapabilityRuntimeRegistry` remains the sole runtime source of truth.
`runtime_available` on the EKG node is written back as an advisory mirror
only, at confidence 0.5 (deliberately below `conflict_confidence_floor`),
exactly matching the pre-existing `make_objective_node` write-back
discipline.

### 20.10 Capability lifecycle

`apex_host/capabilities/lifecycle.py` — a PURE, derived view, never a
second stored source of truth. `CapabilityLifecycleState`: `candidate`
(not validated — never actually produced, since `CapabilityParser` only
ever materializes `validated=True` nodes), `active` (validated + runtime
adapter registered), `unavailable` (validated, no runtime adapter). Three
further members (`validated`, `expired`, `revoked`, `superseded`) are
reserved for forward compatibility — matching this codebase's own
repeated "documented but not yet produced" convention (e.g.
`EngagementOutcome.goal_completed`, `PrivilegeEnumerationStatus
.elevated_access_validated`) — no current code path assigns them, since
nothing in this phase revokes a capability or expires one after creation
(`capability_evidence_ttl_seconds` governs EVIDENCE staleness at
validation time, before a capability is ever created, not retroactive
capability expiry).

### 20.11 Objective reopening (the "reopening the objective" gap)

Before this phase, once `GlobalPlanner._select_phase` decided the
objective was `"failed"` (globally exhausted across every THEN-known
capability) or the objective phase's own turn budget was exhausted, the
phase ladder routed to `priv_esc` and NEVER revisited `objective` again —
even if a brand-new, validated, runtime-active capability appeared later
(e.g. discovered automatically from evidence produced during priv_esc/web
enumeration).

`apex_host.planners.objective.objective_reopening_eligible(subgraph,
target, objective_type)` (pure, no I/O) closes this gap generically — no
transport-specific logic: it returns `True` whenever the objective is not
`"verified"` AND at least one validated+`runtime_available` capability's
`capability_id` has NEVER appeared in `attempted_capability_paths`. A
capability that has never been given a chance is, by definition, new —
`ObjectivePlanner`'s own `_select_capability` will find at least one
untried candidate for it the moment the objective phase runs again.

`GlobalPlanner.decide_phase()` gained an `objective_reopened: bool = False`
parameter (default preserves all prior behavior). When `True`, it
overrides BOTH the `"failed"`-status skip and the exhausted-budget skip —
never the `"verified"` terminal check, which is always checked first.
`apex_host/orchestration/planning_node.py` (`global_plan`, the real
per-turn decision) and `continuation_node.py` (`reflect_or_continue`'s
peek) both compute this value from the SAME already-fetched subgraph — no
extra `MemoryAPI` read.

**Old failed `(capability_id, candidate_path)` pairs are never deleted** —
`objective_attempted_capability_pairs` (§17) is untouched; reopening only
ever creates NEW pairs for the newly-available capability's own untried
candidates, never retries an already-failed pair. Duplicate evidence
replay never introduces a new `capability_id`, so it can never spuriously
reopen the objective.

### 20.12 Operator seed migration

`apex_host/orchestration/capability_seed.py`'s two `seed_*` functions no
longer call `CapabilityParser.derive_*` directly — they construct an
`OPERATOR_ATTESTED` `CapabilityEvidence` and call
`run_capability_discovery()`, the SAME pipeline every automatically-
derived capability now goes through. `OPERATOR_ATTESTED` evidence carries
no evidence-type-implied family (unlike e.g. `SSH_AUTHENTICATED_COMMAND`,
which only ever means `ssh_command`), so the engine routes it to the
correct provider by `capability_family` alone, via each provider's
`accepted_capability_families` property.

Seeding runs BEFORE the engagement graph starts (`ApexRuntime.run()`), so
no real `CapabilityRuntimeRegistry` exists yet — attempting registration
against a throwaway instance would write a misleading
`runtime_available=True` the real, per-engagement registry does not back.
`CapabilityDiscoveryContext.attempt_runtime_registration=False` (seeding's
own explicit opt-out) skips registration entirely, leaving
`runtime_available=False` exactly as `CapabilityParser.derive_*` already
defaulted it — the pre-existing per-turn `make_objective_node` loop
performs the real registration on the first objective turn regardless,
exactly as it did before this phase.

A regression test (`tests/apex_host/test_phase20_direct_file_read_capability.py`,
`test_phase21_bounded_command_capability.py`, both unmodified) proves the
resulting EKG node metadata is unchanged (modulo the new, additive
`evidence_provenance`/`runtime_generation` bookkeeping keys) from the
pre-Phase-23 direct-call path.

### 20.13 Replay and reflection

Replay of identical evidence is idempotent — the SAME `evidence_id`
reprocessed produces `duplicate` status and changes nothing.
`CapabilityRuntimeRegistry` is never restored from persistence — it is
always constructed fresh per engagement (unchanged since §16), so a
capability's `runtime_available=True` EKG claim from a PRIOR engagement is
never trusted as proof a runtime adapter exists NOW; every engagement
re-resolves registration from scratch via the SAME
`runtime_resolution.register_capability_adapter()` call. Discovery never
touches the episodic store (no `append_episode` call anywhere in
`apex_host/capabilities/`) — episodic append-only immutability (memfabric
Invariant 2) is entirely unaffected.

### 20.14 Redaction and secret boundaries

Everything §16's redaction discipline already established remains
unchanged: `AccessCapability` has no field for a password, cookie, bearer
token, SSH session, shell object, or socket. This phase adds one more
guarantee at the EVIDENCE layer: `validate_evidence()` rejects any
`sanitized_attributes` KEY drawn from a fixed forbidden set (`password`,
`token`, `raw_output`, `flag`, `session`, ...) before a provider ever sees
it — a defense-in-depth check on top of the discipline every evidence
PRODUCER (e.g. `ssh_capability_evidence_for_result()`) already follows by
construction (never populating such a key in the first place).

### 20.15 Reporting and metrics

`ApexGraphState.capability_discovery_log` — one accumulated
`CapabilityDiscoveryResult.to_dict()` entry per turn that emitted at least
one piece of evidence. `apex_host/eval/report.py` gained a "Capability
Discovery Summary" section (shown only when at least one evidence item was
ever evaluated) and a `"capability_discovery"` JSON block: evidence
evaluated/accepted/rejected/duplicate, capabilities derived/updated,
runtime adapters registered, validated-but-unavailable, provider failures.
Never reports raw evidence, raw output, raw canaries, passwords, cookies,
tokens, exact command strings, sensitive URLs, raw flags, or runtime
handles. **Capability derivation is never itself a benchmark success
condition** — verified user flag (`EngagementOutcome.user_flag_verified`)
remains the only exit-code-0 outcome, entirely unaffected by this phase.

### 20.16 Configuration

Three new `ApexConfig` fields, all with safe defaults: `capability_discovery_enabled`
(default `True` — discovery only ever processes already-validated
structured evidence and cannot execute anything itself, so it is safe to
leave on, unlike every `*_operator_attested` flag which gates a genuinely
sensitive capability from being seeded at all), `capability_evidence_ttl_seconds`
(default `0.0` — disabled; no current evidence source produces evidence
worth rejecting on age alone), `capability_discovery_max_evidence_per_cycle`
(default `50` — a hard per-turn ceiling, mirroring this codebase's
established "bounded batch" convention). No CLI flags were added for
these three — they are advanced/internal tuning knobs, not operator-facing
safety toggles.

### 20.17 Extension rule for a future provider

Adding a new capability family's automatic derivation requires only: (1)
a new `CapabilityEvidenceType` member (never named after a vulnerability
or machine); (2) a new `CapabilityProvider` implementing pure
`evaluate()`; (3) one more entry in `DEFAULT_PROVIDERS`; (4) an evidence-
emission function at whatever real executor/parser call site organically
produces the qualifying signal (mirrors `ssh_capability_evidence_for_result()`).
It must NEVER require touching `ObjectivePlanner`, `UserFlagExecutor`,
`ObjectiveParser`, `verify_user_flag()`, or the report generator's
capability-oriented rendering — the SAME extension guarantee §16
established for a new `AccessCapabilityType` now extends to how that
type's capability gets discovered in the first place, not just how it's
represented once discovered.

### 20.18 Tests

`tests/apex_host/test_phase23_capability_discovery.py` (179 tests) covers:
evidence model, evidence types, central validation, provider protocol, all
five providers individually, the discovery engine, identity/deduplication,
runtime resolution, lifecycle, objective reopening, operator-seed
migration, `CapabilityParser` integration, orchestration wiring, replay,
persistence/redaction, and architecture scans (memfabric unchanged, no
machine names, no hardcoded flags, no `shell=True`, no arbitrary execute
API, no LLM authority in providers, no provider writes `MemoryAPI` or
mutates the runtime registry, `ObjectivePlanner`/`UserFlagExecutor`/
`ObjectiveParser` remain transport-independent, `verify_user_flag()`
remains the sole verifier, `dry_run` defaults `True`,
`user_flag_verified` remains the sole benchmark-success outcome). All
pre-existing Phase 18–22 tests pass unchanged except two small, legitimate
updates (a stale `GlobalPlanner.decide_phase` monkeypatch stub gained the
new `objective_reopened` parameter; two direct
`_register_capability_adapter` test call sites were updated to import from
the new `apex_host.capabilities.runtime_resolution` location with its new
keyword-argument signature — the relocation this phase performed, not a
behavior change).

### 20.19 Known limitations

- Only SSH gains a genuinely new, organic, live-executor-produced
  evidence source in this phase (`ssh_capability_evidence_for_result()`).
  Direct-file-read/`local_shell`/`remote_command`/`web_command` still
  require an operator-supplied request/strategy shape before a runtime
  adapter can ever activate — this phase unifies HOW all five families are
  derived, it does not add autonomous discovery of a new primitive for
  the latter four.
- `WebCommandCapabilityProvider` never reaches `active` lifecycle state
  from automatically-produced evidence alone (always `runtime_unavailable`
  without an operator-configured request shape) — honestly reported, never
  faked.
- ~~`runtime_generation`/`runtime_reference_id` are accepted, validated
  fields with no current concrete resolver consuming them — reserved for
  a future executor-held-session resolver design.~~ **Superseded by
  Phase 24 (§21):** a real `RuntimeReferenceStore`/`RuntimeReferenceResolver`
  now mints, resolves, and invalidates these — see §21.
- Conflict auto-resolution always applies the substrate's DEFAULT policy
  (higher confidence wins, tie → higher logical_version) — there is no
  per-capability override; a genuine three-way disagreement between
  operator attestation and two different live evidence sources still
  resolves deterministically via that one fixed policy, never a bespoke
  per-family rule.
- ~~`repair_node.py`'s own, separate `parse_single_result()` call site (for
  a repaired task's single result) does not emit capability evidence —
  only the main per-turn `parse_observation` loop does. A capability
  derived from a REPAIRED SSH task is not automatically captured; this is
  a narrow, documented edge case, not the common path.~~ **Fixed in Phase 24
  (§21):** both node factories now share `parse_result_and_collect_evidence`/
  `run_pending_capability_discovery`, so a repaired `ssh_access` success
  emits capability evidence identically to a normally-dispatched one.
- No new exploitation, privilege escalation, persistence, or shell-access
  capability was added or performed anywhere in this phase. Command
  execution alone, and access alone, remain non-success — verified user
  flag remains the only exit-code-0 outcome. `memfabric/` was not
  modified.

## 21. Runtime Reference Resolution (Phase 24)

**Status:** implemented. Phase 23 (§20) scaffolded
`CapabilityEvidence.runtime_reference_id`/`runtime_generation` and
`CapabilityDerivationDecision.runtime_reference_id` but nothing ever
minted or resolved a real value — every emitter left them at their
defaults. This phase makes the concept real: a `RuntimeReferenceStore`
mints opaque, non-secret handles bound to a target/capability_type/
generation, a `RuntimeReferenceResolver` validates and resolves them back
to a live adapter, `CapabilityRuntimeRegistry` gained safe-replacement
semantics (`replace()`/`unregister()`/`generation_for()`), and the two
Phase 23 known-limitations struck through above are both closed.

### 21.1 Why this is a runtime-only layer, not a new persisted concept

`RuntimeReference` objects live only in `apex_host/capabilities/
runtime_references.py`'s `RuntimeReferenceStore`, one instance per
engagement, constructed alongside `CapabilityRuntimeRegistry` in
`apex_host.orchestration.builder.build_apex_graph` — never written
through `MemoryAPI`, never a field on `ApexGraphState`, never touched by
the LangGraph checkpointer. This is deliberate, not an oversight: a
runtime reference exists to let the objective layer resolve "does a live
adapter still back this capability_id, and is it the SAME construction of
runtime material as before" — a question whose only correct answer source
is the live, in-process registry. Persisting a `RuntimeReference` would
create exactly the failure mode this phase is designed to prevent: a
resolver trusting stale, disk-durable metadata about a session that no
longer exists.

Capability-node IDENTITY itself (`access_capability_id(target,
capability_type, principal)`, §16) never changes across generations —
this phase does not introduce versioned capability nodes. "Which
construction of the runtime material this is" lives entirely in the
runtime-reference/registry-generation concept, layered transparently on
top of the unchanged, content-addressed capability identity scheme.

### 21.2 `RuntimeReference` / `RuntimeReferenceStore` / `RuntimeReferenceResolver`

`RuntimeReference` (`@dataclass(frozen=True, slots=True)`): `reference_id`
(opaque, `secrets.token_urlsafe(32)` — explicitly NOT a Python `id()`
value, NOT derived from any secret), `capability_id`, `target`,
`capability_type`, `generation`, `authorization_scope_id`, `created_at`,
`expires_at`, `revoked`, `revocation_reason`. `to_dict()`/`__repr__()`
both expose only an 8-character digest of `reference_id`, never the full
value.

`RuntimeReferenceStore` — `mint()` (creates a reference, automatically
revoking any prior live reference for the same `capability_id` —
`revocation_reason="superseded_by_new_generation"`), `get()`,
`current_reference_for(capability_id)`, `invalidate()` (explicit),
`invalidate_for_capability()`, `invalidate_for_target()` (authorization/
target-change trigger), `invalidate_all()` (process-shutdown trigger,
wired from `ApexRuntime.aclose()` — see §21.5).

`RuntimeReferenceResolver.resolve(reference_id, *, target, capability_type,
now_iso="", expected_generation=None)` — validates, in order: existence
→ revocation → expiry → target match → capability-type match →
generation match (only when `expected_generation` is supplied) → registry
lookup by `capability_id`. **Never falls back to a "global" adapter for a
mismatched target** — a `target_mismatch` is always a hard rejection.
**Never reconstructs an adapter from the reference's own fields** — the
adapter always comes from a live `CapabilityRuntimeRegistry.get()` call at
the very end of `resolve()`, so even a reference minted before the
adapter was (re-)registered resolves correctly once it is.

### 21.3 The 13 sanitized error/revocation reasons (`RuntimeReferenceError`)

One bounded, `str`-valued enum serves double duty: (1) `resolve()`'s
return-code vocabulary, and (2) the `revocation_reason` a store-level
invalidation call records. `not_found`, `revoked`, `expired`,
`target_mismatch`, `type_mismatch`, `generation_mismatch`,
`scope_mismatch` (reserved — no current multi-scope deployment), `adapter_
unavailable` (reserved — no registry entry violates `FlagReadCapability`
today), `capability_unregistered`, `backend_disconnected`, `authorization_
revoked`, `session_invalid`, `internal_error` (reserved defensive
catch-all). Never derived from raw adapter/exception content.

### 21.4 Meaningful `runtime_generation`

`CapabilityRuntimeRegistry` gained a per-capability generation counter.
`generation_for(capability_id)` returns 0 (never registered), 1 (first
registration), or prior+1. Three safe-replacement primitives:

- `replace(capability_id, adapter)` — unconditional install, always bumps
  the generation ("newer replaces").
- `unregister(capability_id)` — removes the adapter but **preserves** the
  generation counter ("revoke unregisters" — a subsequent re-registration
  is still a NEW generation, never silently renumbered back to 1).
- `register()`/`ensure_ssh()`/`ensure_direct_file_read()`/
  `ensure_bounded_command()` — all route through the same "is this the
  first-ever registration?" check, keyed off whether a generation was
  *ever* recorded (`self._generations`), not current adapter presence —
  this is what makes a re-registration after `unregister()` correctly bump
  rather than reset.

`generation` only increments on a REAL replacement — never on replay of
identical evidence, never on an idempotent `ensure_*` call that returns an
existing adapter unchanged, and never on checkpoint replay (there is no
checkpoint for this data — see §21.6).

### 21.5 Invalidation triggers

| Trigger | Mechanism |
|---|---|
| Process shutdown | `ApexRuntime.aclose()` calls `self._runtime_reference_store.invalidate_all(reason="shutdown")`. `ApexRuntime` now constructs `CapabilityRuntimeRegistry`/`RuntimeReferenceStore` explicitly (mirroring how it already constructs and closes `tool_backend`) and passes them into `build_apex_graph(capability_registry=..., runtime_reference_store=...)` — both new, optional kwargs; `None` (every pre-Phase-24 caller) preserves exact prior behavior. |
| Explicit revocation | `RuntimeReferenceStore.invalidate(reference_id)` / `invalidate_for_capability(capability_id)`. |
| Authorization/target change | `RuntimeReferenceStore.invalidate_for_target(target)` — a tested, available method; no synthetic call site was added inside `ApexRuntime` since `config.target` never changes mid-engagement in this codebase's current architecture. |
| Backend-disconnected / session-invalid read | `apex_host.orchestration.dispatch_node._invalidate_on_connection_failure`: a `user_flag_verify` tool_result with `connected=False` (a connection/auth/backend-level failure, distinct from "file not found," which is `connected=True` — see `BoundedReadResult.connected`'s own docstring) triggers `capability_registry.unregister(capability_id)` + `runtime_reference_store.invalidate_for_capability(..., reason="session_invalid")`, so the NEXT objective turn's registration loop registers fresh instead of silently reusing a dead adapter forever (the pre-Phase-24 `ensure_*` methods were otherwise idempotent-forever). |
| Natural expiry | `mint(..., ttl_seconds=...)`; `ApexConfig.capability_runtime_reference_ttl_seconds` (default `0.0` — no expiry) threads through both registration call sites. |
| Generation supersession | Automatic inside `mint()` — see §21.2. |

`apex_host.orchestration.dispatch_node.make_objective_node`'s per-turn
registration loop now also calls a new `_ensure_runtime_reference` helper
after every successful registration (both the "not yet registered" and
the "already registered, just needs a fresh-generation reference" paths),
and `apex_host.capabilities.discovery.CapabilityDiscoveryEngine` mirrors
the identical logic via a new, optional `CapabilityDiscoveryContext
.runtime_reference_store` field (`None` — the default — preserves exact
pre-Phase-24 behavior for every existing caller/test).

### 21.6 Persistence and replay guarantee

Neither `RuntimeReference`/`RuntimeReferenceStore`/`RuntimeReferenceResolver`
nor `CapabilityRuntimeRegistry` ever appear in `ApexGraphState` or any
LangGraph checkpoint payload (a static architecture-scan test proves this
via `typing.get_type_hints(ApexGraphState)`). A resumed/replayed engagement
always starts with an EMPTY store and registry — every previously-"active"
capability's EKG node may still say `runtime_available=True` from before
the restart (that is stale metadata, not live state) until the
orchestration layer re-registers it fresh on the next objective turn. A
`reference_id` minted by one `RuntimeReferenceStore` instance is
meaningless to a different instance (including one built after a process
restart) — proven directly by a test that mints in one store and attempts
to resolve against a resolver backed by a second, empty store.

### 21.7 Typed organic evidence emission (`apex_host/capabilities/emission.py`)

Every evidence-emission function takes a **typed dataclass result**, never
a generic dict. `evidence_from_ssh_validation(result: CredentialValidationResult,
...)` is the one function with a real, live producer today —
`apex_host.orchestration.parsing_node.ssh_capability_evidence_for_result`
(the pre-existing dict-based tr-dict wrapper) now constructs a
`CredentialValidationResult` from the tr-dict's known fields and delegates
to it, so the acceptance logic lives in exactly one typed place.

The other four families (`DirectFileReadValidationResult`,
`LocalCommandValidationResult`, `RemoteCommandValidationResult`,
`WebCommandValidationResult`, each with a matching `evidence_from_*`
function) have **no live validating executor anywhere in this codebase**
— confirmed by re-reading `apex_host/execution/dispatcher.py` in full
during this phase's own architecture assessment: DFR/local-command/
remote-command/web-command capabilities are activated exclusively through
operator attestation (`apex_host/orchestration/capability_seed.py`) today.
Per this phase's own explicit scope boundary, only the minimal typed
result model and emission seam were added for those four — building live
discovery for them was out of scope. `web_command` in particular is
documented, not merely deferred: its runtime adapter requires an
operator-fixed HTTP request shape that no executor in this codebase
derives autonomously (`WebCommandCapabilityProvider` already explained
this before this phase; nothing changed it).

### 21.8 Shared result-processing helper (closes the repair-node gap)

`apex_host/orchestration/parsing_node.py` now exposes two functions
factored out of `parse_observation`'s per-result loop:
`parse_result_and_collect_evidence(tool_result, state, *, target)` (parse
+ collect evidence; kept separate from the `MemoryAPI` write so a parser
failure and a memory-write failure can still be told apart, exactly as
before — `parser_failure` vs. `memory_failure`) and
`apply_parsed_observation(deps, parsed)` (the write). A third function,
`run_pending_capability_discovery(deps, pending_evidence)`, wraps the
"run discovery once, build the `capability_discovery_log` state update,
degrade gracefully on failure" logic both node factories need.
`apex_host/orchestration/repair_node.py`'s `repair_agent` now calls all
three instead of a direct, evidence-blind `parse_single_result()` +
`apply_deltas()` — a repaired `ssh_access` success now emits capability
evidence identically to a normally-dispatched one.

### 21.9 Configuration

| Field | Default | Purpose |
|---|---|---|
| `capability_runtime_reference_ttl_seconds` | `0.0` | 0 disables reference expiry entirely (still invalidated by generation supersession, explicit revocation, target change, connection-failure, or shutdown). No CLI flag — set via `ApexConfig(...)` construction or `ApexConfig.from_cli_args()`'s generic `_g()` fallback, mirroring `capability_evidence_ttl_seconds`'s own precedent (§20.16). |

### 21.10 Dry-run guarantee

`config.dry_run=True` guarantees **no `RuntimeReference` object of any
kind is ever created** — checked independently in both minting call sites
(`dispatch_node._ensure_runtime_reference` and
`CapabilityDiscoveryEngine._ensure_runtime_reference`), each returning
before calling `store.mint()` when `config.dry_run` is `True`. Verified by
a full dry-run engagement run through the real compiled graph asserting
the store's internal reference map is empty afterward, regardless of how
many capabilities were derived/registered during the run (adapter
registration itself is unaffected by dry-run — only the runtime-reference
bookkeeping layer is gated).

### 21.11 Objective-reopening interaction

`apex_host.planners.objective.objective_reopening_eligible` (§20.11)
already reasoned at the capability level (`validated and runtime_available
and never-attempted capability_id`) — this phase adds tests proving the
FULL transition it was designed for: a capability that was
`runtime_available=True`, gets invalidated (its EKG node's
`runtime_available` flips back to `False` by the same per-turn write-back
`make_objective_node` already performed before this phase), is correctly
NOT eligible for reopening while unavailable, and a *different*,
newly-available capability_id (e.g. a fallback transport) correctly IS
eligible even though the objective's own `status` still reads `"failed"`
from the exhausted first capability.

### 21.12 Tests

`tests/apex_host/test_phase24_runtime_reference_activation.py` (144
tests) covers: the `RuntimeReference` model, the 13-member error
vocabulary, `RuntimeReferenceStore` (mint/lookup/all four invalidation
methods/supersession), `RuntimeReferenceResolver` (success path + every
individual mismatch/failure reason + never-falls-back-to-global +
never-reconstructs-from-fields-alone), `CapabilityRuntimeRegistry` safe-
replacement semantics, typed SSH emission, the four typed stub emitters,
the dict-wrapper/typed-emitter parity, the shared result-processing
helper (both in isolation and via a real `repair_node` integration test),
`dispatch_node`'s minting/invalidation wiring, `discovery.py`'s optional
store wiring, `builder.py`/`OrchestrationDeps` wiring, `ApexRuntime.aclose()`
invalidation, objective-reopening runtime-activation transitions,
persistence/replay architecture scans, dry-run guarantees, configuration,
and a full synthetic end-to-end generation lifecycle (register → mint →
resolve → connection failure → invalidate → re-register → new generation
→ resolve again). No test performs a real network operation or requires
Docker/VPN/a real HTB machine.

### 21.13 Known limitations (Phase 24)

- `invalidate_for_target()` (the authorization/target-change trigger) is a
  real, tested store method but has no synthetic call site inside
  `ApexRuntime` — `config.target` is fixed for the lifetime of one
  engagement in this codebase's current architecture, so there is no
  natural "target changed mid-run" event to wire it to yet.
- `scope_mismatch`/`adapter_unavailable`/`internal_error` in
  `RuntimeReferenceError` are reserved, documented-but-not-reachable
  members (mirrors this codebase's own established convention, e.g.
  `CapabilityDerivationStatus.superseded`/`revoked`) — no current code path
  produces a multi-authorization-scope deployment, a registry entry that
  fails the `FlagReadCapability` check, or an internal resolver error.
  `expected_generation` is an opt-in resolver parameter; no current caller
  supplies it (the objective/discovery registration loops always resolve
  by capability_id through the registry directly, never by reference_id —
  the reference is bookkeeping for audit/generation-tracking, not yet a
  required hop in the live read path).
- DFR/local-command/remote-command/web-command still have no live
  validating executor — only typed stub result models and emission seams
  were added (§21.7), per this phase's own explicit scope boundary. No
  live discovery mechanism was fabricated for them.
- No new exploitation, privilege escalation, persistence, or shell-access
  capability was added or performed anywhere in this phase. Command
  execution alone, and access alone, remain non-success — verified user
  flag remains the only exit-code-0 outcome. `memfabric/` was not
  modified.

## 22. Phase 25 — Final Architecture Integration & Live-Readiness

Phase 25 completes the current Phase 1–25 architecture roadmap by
integrating and hardening everything §1–§21 built, for controlled,
authorized live testing — it changes nothing about the objective/
capability model documented above. See
[`docs/phase25-release-readiness.md`](phase25-release-readiness.md) for
the full record: the centralized live-run safety interlock, the
synthetic release-gate suite, the truthful capability support matrix, and
the corrected `EngagementOutcome.goal_completed` exit-code entry (was
`0`, inconsistent with its own `is_success_outcome() is False`
classification; corrected to `1` — see `docs/engagement-outcomes.md`'s
own Phase 25 correction note). `verify_user_flag()` and
`user_flag_verified` remain exactly as documented throughout this file —
unchanged by Phase 25.
