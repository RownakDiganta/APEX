# Bounded Credential Validation (Telnet / SSH / FTP)

**Phase:** 12B. Depends on Phase 12A (state-machine correctness) — see
CLAUDE.md §21 "Phase 12A" and the HTB Exploitation Workflow Diagnostic
Report for why credential validation, not exploitation, is the deliberate
scope boundary of this feature.

## 1. Purpose

APEX's `credential` phase exists to answer exactly one question, safely:
*does this operator-supplied credential pair work against a discovered
service on the authorized target?* It is not a login brute-forcer, not a
shell, and not a privilege-escalation tool. A single bounded, one-attempt
login validation either produces `access_state` (proof the pair works) or
it doesn't — and the engagement's phase state machine (Phase 12A) only
advances past `credential` when that proof genuinely exists.

Phase 12A fixed the *routing* bugs that stopped APEX from ever reaching or
leaving the credential phase correctly. Phase 12B fixes the fact that,
before it, the credential phase could only ever prove Telnet worked — and
almost no real HTB service exposes Telnet. SSH and FTP are the two
protocols that actually appear on realistic targets.

## 2. Supported protocols

| Protocol | Executor | Library | Default port | Default validation operation |
|---|---|---|---|---|
| Telnet | `apex_host/agents/telnet_executor.py` | raw `asyncio.open_connection` | 23 | `id` (sent over the session) |
| SSH | `apex_host/agents/ssh_executor.py` | [Paramiko](https://www.paramiko.org/) | 22 | `id` (or `whoami`) |
| FTP | `apex_host/agents/ftp_executor.py` | stdlib `ftplib` | 21 | `PWD` (or `NOOP`) |

## 3. Telnet (unchanged)

Telnet's implementation and behavior are **exactly as they were before
Phase 12B** — this phase's own explicit constraint. See
`apex_host/agents/telnet_executor.py`'s own docstring and CLAUDE.md §12.12
for its design. Nothing in this document changes it; it is described here
only for completeness and comparison.

## 4. SSH

`apex_host/agents/ssh_executor.py::SSHExecutor` wraps Paramiko's
`SSHClient`. One `run()` call = one bounded validation attempt:

1. Construct a fresh `paramiko.SSHClient()` (never reused across calls —
   the executor is stateless, matching memfabric Invariant 6).
2. `set_missing_host_key_policy(paramiko.AutoAddPolicy())` — see §11 below.
3. `connect(hostname, port, username, password, timeout=..., banner_timeout=...,
   auth_timeout=..., allow_agent=False, look_for_keys=False, pkey=None,
   key_filename=None)` — exactly one authentication attempt, no local key
   discovery, no SSH-agent, and (by construction — see Paramiko's own
   `SSHClient._auth`) no keyboard-interactive fallback, since no key attempt
   is ever made for that fallback path to trigger from.
4. On success, run exactly one allowlisted harmless command
   (`_ALLOWED_VALIDATION_COMMANDS = {"id", "whoami"}`, default `id`) via
   `exec_command(command, timeout=...)`.
5. `client.close()` in a `finally` block — every path, always.

No `open_sftp()`, no `get_transport().request_port_forward(...)`, no
`invoke_shell()` — this module contains no calls to any of those methods at
all (statically verified by
`tests/apex_host/test_ssh_executor.py::TestNoForwardingNoFileTransfer` and
`tests/apex_host/test_credential_validation_security.py`).

### Dependency

`paramiko>=3.4` was added to `[project].dependencies` in `pyproject.toml`
(a runtime dependency, since `ssh_executor.py` imports it directly) with
`types-paramiko` added to the dev group for `mypy --strict`. It was chosen
over shelling out to the system `ssh` binary specifically so the executor
can disable agent forwarding, local key discovery, and the
keyboard-interactive fallback precisely and in-process, rather than trying
to control an external `ssh` process's interactive prompts and config
files (`~/.ssh/config`, `~/.ssh/known_hosts`) from the outside. No
brute-force/cracking library (Hydra, Medusa, Ncrack) was added or used.

## 5. FTP

`apex_host/agents/ftp_executor.py::FTPExecutor` wraps the standard
library's `ftplib.FTP` — no new dependency was needed. One `run()` call =
one bounded validation attempt:

1. Construct a fresh `ftplib.FTP()`.
2. `connect(host, port, timeout=...)`.
3. `set_pasv(True)` explicitly (see §12 below).
4. `login(user, passwd)` — exactly one authentication attempt.
5. On success, run exactly one allowlisted harmless operation
   (`_ALLOWED_VALIDATION_OPERATIONS = {"PWD", "NOOP"}`, default `PWD`).
6. `ftp.quit()` on the clean path; falls back to `ftp.close()` only if
   `quit()` itself raises — every path closes the connection.

No `retrbinary`/`retrlines`/`storbinary`/`storlines` (file transfer), no
`delete`/`mkd`/`rmd`/`rename` (mutation), no `nlst`/`dir` (recursive
listing) — this module contains no calls to any of those methods at all
(statically verified the same way as SSH).

## 6. One-attempt safety model

This is the same invariant Telnet already established (§12.12), extended
identically to SSH and FTP:

- `CredentialPlanner` (`apex_host/planners/credential_planner.py`) emits
  **at most one task per turn**, using only `username_candidates[0]` /
  `password_candidates[0]` — never a loop over multiple candidates, never
  every protocol in one turn.
- Once a `credential` node already exists for a given
  **protocol + target + username**, that protocol is never re-attempted
  (`_protocol_already_attempted`) — enforced by inspecting the live EKG,
  not by any in-memory counter that could reset.
- Each executor (`TelnetExecutor`/`SSHExecutor`/`FTPExecutor`) performs
  exactly one `connect()`/`login()` call internally — there is no retry
  loop inside the executor itself, regardless of what fails.

## 7. Explicit credential requirement

Credentials are never invented, guessed, or defaulted. `ApexConfig.username_candidates`
/ `password_candidates` (shared across all three protocols — the same
`--username`/`--password` CLI flags Telnet already used) default to empty
lists. `CredentialPlanner` returns an `AbandonSignal` directing the operator
to supply `--username`/`--password` when a protocol capability exists but no
credentials are configured. An explicitly empty password (`--password ""`,
i.e. `password_candidates == [""]`) is distinguishable from *no* password
configured (`password_candidates == []`) — `has_credentials()` checks list
non-emptiness, not truthiness of the string inside it.

No credential value was added to `.env.example` — it documents variable
*names* only, never values, and this phase did not add any new
credential-shaped environment variable at all (SSH/FTP reuse the existing
`--username`/`--password` CLI flags, which have never had environment-variable
equivalents — see `apex_host/config_env.py`).

## 8. No brute force, no credential spraying

- Exactly one username, one password, one protocol, one attempt per turn.
- `CredentialPlanner` never iterates `username_candidates`/`password_candidates`
  beyond index `[0]`.
- No wordlist, no password-list file, no `itertools.product` over
  candidate pairs anywhere in `credential_planner.py`, `ssh_executor.py`, or
  `ftp_executor.py` — statically verified in
  `tests/apex_host/test_credential_validation_security.py`.
- Hydra, Medusa, Ncrack, and similar cracking/spraying tools are not used,
  not imported, not shelled out to, and not mentioned anywhere in the new
  modules (also statically verified).

## 9. Harmless validation actions

| Protocol | Allowed actions | Never |
|---|---|---|
| SSH | `id`, `whoami` | Any other command string |
| FTP | `PWD`, `NOOP` | `LIST`/`NLST`, `RETR`/`STOR`, `DELE`/`MKD`/`RMD`/`RNFR`/`RNTO` |

Both executors validate the requested command/operation against a fixed
allowlist and silently fall back to the default (`id` / `PWD`) if a task
somehow requested anything else — defense in depth on top of
`apex_host/policy/rules.py::check_bounded_credential_validation`, which
performs the same check at the policy boundary, *before* any executor is
ever reached.

## 10. SSH host-key behavior

`SSHExecutor` uses `paramiko.AutoAddPolicy()` with a **fresh,
never-persisted, in-memory-only** `SSHClient` per call:

- No `load_system_host_keys()`, no `load_host_keys()`, no
  `save_host_keys()` — the host-key store starts empty for every single
  call and is discarded when the client is closed.
- This is a deliberate trust-on-first-use (TOFU) decision, scoped to one
  bounded attempt: HTB lab machines are ephemeral, and their host key
  changes across VM resets, so persisting an accepted key to
  `~/.ssh/known_hosts` (the way interactive `ssh` normally does) would give
  no real security benefit while adding stale-entry operational complexity
  every time the target is reset.
- It is not silent about this — this document and the module's own
  docstring both state the rationale explicitly, per this phase's own
  requirement to document (not hide) the host-key strategy.
- Verified via `tests/apex_host/test_ssh_executor.py::TestHostKeyStrategy`.

## 11. FTP passive-mode behavior

`FTPExecutor` calls `set_pasv(True)` explicitly, even though passive mode
has been `ftplib.FTP`'s own default since Python 3 — the explicit call
means the choice is visible in code and does not silently depend on the
stdlib default never changing. Passive mode means the *client* opens the
data connection; the server is never directed to connect back to an
operator-chosen address (which active mode's `PORT` command would allow).

## 12. Timeout behavior

Six new `ApexConfig` fields (`apex_host/config.py`), mirroring the existing
Phase 7 per-component timeout pattern (`telnet_read_timeout_seconds`, etc.):

| Field | Default | Bounds |
|---|---|---|
| `ssh_connect_timeout_seconds` | 10.0 | TCP connect + banner |
| `ssh_auth_timeout_seconds` | 10.0 | Authentication exchange |
| `ssh_command_timeout_seconds` | 10.0 | The one harmless command |
| `ftp_connect_timeout_seconds` | 10.0 | TCP connect |
| `ftp_login_timeout_seconds` | 10.0 | `USER`/`PASS` exchange |
| `ftp_command_timeout_seconds` | 10.0 | The one harmless operation |

Each executor also wraps its whole synchronous worker (run via
`asyncio.to_thread`) in an outer `asyncio.wait_for(..., timeout=sum(the three) + 5.0)`
as a second, independent ceiling — belt and suspenders in case a blocking
call inside the thread does not honor its own timeout.

## 13. Error categories

`apex_host/types.py::CredentialErrorCategory` — used by SSH/FTP only
(Telnet predates this taxonomy and is intentionally left with its original,
coarser `Outcome.success`/`Outcome.fundamental`/`Outcome.fixable` split):

`success`, `auth_rejected`, `connection_failed`, `connect_timeout`,
`auth_timeout`, `command_timeout`, `protocol_error`, `command_failed`.

`TaskDispatcher._credential_result_to_tr` (`apex_host/execution/dispatcher.py`)
maps these to `ExecutionDisposition`: `success` → `EXECUTED_SUCCESS`;
`auth_rejected` → `EXECUTED_VALID_NEGATIVE` (a clean, definitive "wrong
credentials" signal — never retried or repaired, matching how Telnet's own
success/failure split already worked); everything else →
`EXECUTED_FAILURE`.

## 14. Access-state creation

`AccessParser.parse_structured()` (new method, `apex_host/parsers/access_parser.py`)
— unlike `parse_text` (Telnet, text-heuristic based), this takes an
explicit `success: bool` / `authenticated: bool` from the executor, since
SSH and FTP both determine success/failure definitively via a typed
exception or protocol response code, not a shell-prompt regex.

- A `credential` node is emitted only when authentication was actually
  *attempted* (reached the login exchange) — a pre-authentication failure
  (connection refused, connect timeout, protocol error before login)
  produces **no node at all**, mirroring Telnet's existing behavior for
  connection-level failures.
- An `access_state` node is emitted **only** when `success` is true — a
  successful login followed by the harmless command itself timing out or
  failing produces a `credential` node (the login was real) but never
  `access_state` (incomplete evidence is never treated as success).
- **An open port alone never creates `access_state`.** **A login banner
  alone never creates `access_state`.** Only a fully successful, executed
  validation does.

### Node-ID protocol isolation

`apex_host/graph_ids.py::credential_id` / `access_state_id` gained an
optional `protocol` parameter (default `""`, preserving Telnet's exact
pre-Phase-12B ID format for backward compatibility). SSH/FTP pass an
explicit `protocol="ssh"`/`"ftp"`, so `credential:<target>:<username>:ssh`
and `credential:<target>:<username>:ftp` are always distinct node IDs from
each other and from Telnet's untagged `credential:<target>:<username>` —
a failed SSH attempt can never be mistaken for, or block, an unrelated FTP
attempt.

## 15. Planner integration

`CredentialPlanner`'s deterministic core now consumes all three protocol
capabilities (`access_validate_telnet`/`_ssh`/`_ftp` from
`apex_host/planners/capabilities.py` — unchanged since before Phase 12B,
now finally consumed for SSH/FTP too).

**Deterministic protocol ordering** — fixed, documented, never random:
`_PROTOCOL_ORDER = ("telnet", "ssh", "ftp")`. Telnet is checked first purely
for backward compatibility (it was the only protocol before, and its
existing single-protocol behavior must stay byte-for-byte the same). Within
one protocol, if multiple services exist (e.g. two SSH ports), the lowest
port number is chosen. See
`tests/apex_host/test_credential_planner_multiprotocol.py::TestDeterministicOrdering`.

**Per-protocol duplicate guard** — `_protocol_already_attempted()` scopes
matching to `(protocol, target, username)` by inspecting each credential
node's `protocol` prop. A failed SSH attempt never blocks an unrelated FTP
attempt, and vice versa; this was the entire point of making SSH/FTP node
IDs protocol-tagged (§14).

**Scoping decision, documented honestly:** the duplicate guard matches on
`protocol + target + username`, not `protocol + target + port + username`.
Telnet's original, tested implementation never considered port either;
extending SSH/FTP to be port-sensitive while leaving Telnet unchanged would
have created an inconsistent, undocumented asymmetry between protocols for
a scenario (multiple services of the *same* protocol on the *same* host)
that essentially never occurs on a single HTB target. A `credential_ref`
short SHA-256 hash of `username:password` (never the raw password) is
attached to episode metadata as a safe, opaque per-attempt identity marker,
but is not itself the primary dedup key.

## 16. Policy integration

`apex_host/policy/rules.py::check_bounded_credential_validation` (new
rule, appended to `ALL_RULES` after `check_safe_recon_allowed`):

- Recognizes `telnet_access` / `ssh_access` / `ftp_access` tasks.
- Every existing blocking rule (`check_target_in_scope`,
  `check_no_attacking_infrastructure`, `check_no_password_list`,
  `check_no_sensitive_data`, `check_require_review`) already applies to
  these tasks unmodified — they carry the same `target`/`args` params any
  other task does.
- Adds one credential-validation-specific check: the requested
  `command`/`operation` (if the task specifies one) must be in the fixed
  harmless allowlist — defense in depth on top of the executors' own
  identical allowlists (§9).
- On success, returns an explicit `approved` decision (not just `None`) so
  the policy audit log records *why* — the same transparency
  `check_safe_recon_allowed` already provides for recon tools.
- This rule **cannot** make an unsafe planner safe — it only classifies
  tasks `CredentialPlanner` already produced under the one-attempt
  invariant (§6). It never broadens what `CredentialPlanner` is allowed to
  emit.

Not one existing policy restriction was weakened. No tool was added to any
allow-list that wasn't already reachable; `hydra`/`medusa`/`ncrack` remain
absent from every list.

## 17. Reporting

`ApexGraphState.credential_validation_log` (new, additive field) — one
entry per telnet/ssh/ftp attempt, populated in
`apex_host/orchestration/memory_node.py::write_memory`:
`{protocol, target, port, username, success, authenticated, error_category,
timed_out, phase}` — **never a password**.

`apex_host/eval/report.py::RunReport` gained three additive fields:
`credential_attempts_by_protocol`, `credential_outcome_counts`,
`credential_validation_entries`. Surfaced in both `format_text()` (a new
"Credential Validation" section, shown only when at least one attempt
occurred) and `to_json_dict()` (a new `"credential_validation"` key).
Outcome counts distinguish attempted / authenticated (`success`) / rejected
(`auth_rejected`) / timed out (`connect_timeout`/`auth_timeout`/`command_timeout`)
/ connection failed (`connection_failed`) / protocol error
(`protocol_error`) — exactly the breakdown this phase required. All
pre-existing `RunReport`/JSON fields are unchanged (backward compatible).

## 18. Secret redaction

Passwords are never present in:

- **Result models** — `CredentialValidationResult` (`apex_host/types.py`)
  has no password field at all.
- **Episodes** — `SSHExecutor`/`FTPExecutor` build `episode.data` entirely
  from `CredentialValidationResult` fields, none of which is the password.
- **EKG nodes** — `credential` nodes always carry `secret_hint="[redacted]"`
  (`apex_host.security.redaction.REDACTED_PLACEHOLDER`), never the value.
- **Reports** — `credential_validation_log`/`RunReport` entries are built
  from the same password-free `episode.data`.
- **Logs** — `logger.info(...)` calls in both executors log only
  `target`/`port`/`username`/`outcome`/`error_category`, never the password.
- **Exceptions** — every `error_detail` string embeds either a fixed
  message or `type(exc).__name__` (the exception *class* name), never
  `str(exc)` — with one deliberate exception: FTP's `error_perm` handler
  includes the server's own response text for diagnostics, but routes it
  through `apex_host.security.redaction.redact_session_text()` first (the
  project's sole redaction function, P8-S06) in case a server response
  happens to echo back the submitted password.
- **`repr()`/serialized state** — `apex_host.config.ApexConfig.to_safe_dict()`
  already redacted `password_candidates`; this phase additionally fixed
  `apex_host/orchestration/models.py::task_info()`, which builds the
  **public, checkpoint-persisted** `ApexGraphState["current_task"]` field.
  It previously echoed `TaskSpec.params` verbatim — including the raw
  password for telnet/ssh/ftp tasks. `task_info()` now masks any
  `"password"` key by name before the dict enters state. This is a
  pre-existing gap (present for Telnet since Phase 12A) that Phase 12B's
  own "never in serialized state" requirement surfaced and fixed; verified
  safe against `RepairEngine` (whose own LLM output schema never carries a
  `username`/`password` field, so no repair functionality depended on the
  raw value being present).

All of the above is proven by dedicated tests across
`test_ssh_executor.py`, `test_ftp_executor.py`,
`test_dispatcher_credential_protocols.py`, `test_access_parser_structured.py`,
and `test_credential_validation_security.py`.

## 19. Current limitations

- **Telnet, SSH, and FTP only.** No RDP, WinRM, SMB, database, or other
  credential-validation protocol exists.
- **One credential pair per protocol per engagement.** No rotation through
  multiple candidate pairs, by design (§6, §8).
- **No key-based SSH authentication.** Only password authentication is
  supported; `--username`/`--password` are the only credential inputs. A
  key-reference model was not already present in the repository's
  authorized configuration surface, so one was not invented for this
  phase (per this phase's own instruction: do not invent hidden defaults
  or new credential models beyond what already exists).
- **The duplicate guard is not port-sensitive** (§15) — a documented,
  deliberate scoping decision, not an oversight.
- **No Kali container change was needed or made.** Both SSH and FTP
  validation run entirely inside the APEX process via Python libraries
  (Paramiko, `ftplib`) — never through the Kali Tool API / `apex_tool_service`,
  and never through `RemoteToolBackend`. `TaskDispatcher` routes
  `ssh_access`/`ftp_access` to their dedicated executors exactly like
  `telnet_access` and `browser` already were — never through the generic
  `ToolBackend`/`run_command_fn` path.

## 20. No exploitation or shell persistence

Nothing in this phase executes a payload, escalates privileges, opens an
interactive/persistent shell, transfers a file, or reads a target file
beyond the one fixed harmless command's own bounded output (`id`/`whoami`'s
identity string, or FTP's current-directory response). Every session is
closed immediately after the single validation step, on every code path,
proven by dedicated "always closed" tests for both executors. This remains
a strict superset of Telnet's own pre-existing scope boundary — never a
step toward exploitation.

## 21. Testing strategy

No test requires a real HTB machine, Docker, VPN, internet access, a real
SSH server, a real FTP server, or real credentials. `paramiko.SSHClient`
and `ftplib.FTP` are monkeypatched with in-process fakes that raise the
*real* `paramiko`/`ftplib` exception classes, so each executor's own
exception-handling branches are exercised exactly as they run in
production. Test files:

- `tests/apex_host/test_ssh_executor.py` (29 tests)
- `tests/apex_host/test_ftp_executor.py` (27 tests)
- `tests/apex_host/test_credential_planner_multiprotocol.py` (17 tests)
- `tests/apex_host/test_dispatcher_credential_protocols.py` (15 tests)
- `tests/apex_host/test_access_parser_structured.py` (14 tests, including
  two full-compiled-graph tests proving the engagement genuinely advances
  past the credential phase after a real dispatch → executor → parser →
  EKG round trip, not merely that `decide_phase()` returns the right value
  in isolation)
- `tests/apex_host/test_credential_validation_security.py` (19 tests)

## 22. Deferred exploitation scope

Consistent with the HTB Exploitation Workflow Diagnostic Report's Phase R4
("scope decision on exploitation/priv-esc... requires explicit user
sign-off, not an engineering task"): reaching `access_state` remains the
engagement's terminal success signal. Nothing beyond it — privilege
escalation, payload execution, flag capture, persistent shell access, or
lateral movement — is in scope for this phase or implied by it. Any future
work in that direction is a deliberate, separate scope-expansion decision,
not a natural extension of bounded credential validation.
