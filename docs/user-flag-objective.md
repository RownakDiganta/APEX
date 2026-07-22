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
