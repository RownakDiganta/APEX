# Tool Execution Architecture

**Status:** Infra Phase 2 — architecture and contracts established; remote
transport NOT implemented.
**Date:** 2026-07-14
**Scope:** `apex_host` tool execution only. Does not cover Docker, Kali
container images, VPN, CI, or Meow-specific behavior — those remain
unimplemented and are explicitly out of scope for this document (see
§17 and §19).

This document describes, precisely, how APEX currently executes security
tools, what changed in Infra Phase 2, and what a later phase must build to
reach the target architecture:

```text
APEX application
    ↓
policy/legal approval
    ↓
ToolBackend abstraction
    ├── DryRunToolBackend
    ├── LocalToolBackend
    └── RemoteToolBackend
              ↓
       restricted Kali tool service
```

Every module and class name below refers to code that exists in this
repository today. Nothing in this document describes code that has not
been written.

---

## 1. Current execution flow

There are, as of Infra Phase 2, **two execution paths** in `apex_host`.
Only one of them is wired into the live, multi-turn engagement graph; the
other is a standalone, test-only implementation of the generic `memfabric`
`Executor` Protocol that predates (or was superseded by) the dispatcher
architecture. Both are documented here because both exist in the tree.

### 1.1 The live path — `TaskDispatcher` (used by `build_apex_graph`)

```text
Planner (e.g. ReconPlanner) proposes a TaskSpec
        ↓
apex_host/orchestration/dispatch_node.py  (recon_agent / web_agent / …)
        ↓
apex_host/execution/dispatcher.py :: TaskDispatcher.dispatch(task, context)
        │
        ├── 1. Policy gate:    PolicyAdvisor.review_task(...)               [apex_host/policy/advisor.py]
        ├── 2. Conflict gate:  check_conflict_dependencies(...)             [memfabric/coordination/conflict.py]
        ├── 3. Duplicate gate: TaskRegistry.reserve(...)                    [apex_host/execution/registry.py]
        ├── 4. Mark EXECUTING: TaskRegistry.update_status(...)
        ├── 5. Route to executor:
        │       tool == "browser"        → BrowserExecutor.run()           [apex_host/agents/browser_executor.py]
        │       tool == "telnet_access"   → TelnetExecutor.run()            [apex_host/agents/telnet_executor.py]
        │       otherwise                 → self._run_command_fn(cmd, cfg)  ← currently apex_host.tools.runner.run_command
        └── 6. Record final status; return DispatchResult
        ↓
apex_host/orchestration/parsing_node.py :: parse_observation
        ↓
apex_host/orchestration/memory_node.py :: write_memory  →  MemoryAPI
```

`TaskDispatcher` is constructed once per engagement inside
`apex_host/orchestration/builder.py :: build_apex_graph()` and captured in
node closures — it is never stored in `ApexGraphState` (memfabric
Invariant 1/7; CLAUDE.md §11.3, §16.5, §21 P10 rules).

`RepairEngine`-produced repaired tasks go through the **exact same**
`TaskDispatcher.dispatch()` call (`apex_host/orchestration/repair_node.py`,
line: `repair_dr = await deps.dispatcher.dispatch(repaired_task, repair_ctx)`).
There is no separate execution path for repaired tasks.

### 1.2 The subprocess primitive — `apex_host/tools/runner.py`

Regardless of which caller reaches it, exactly one function ever spawns a
process: `apex_host.tools.runner.run_command(cmd: ToolCommand, config:
ApexConfig) -> ToolResult`. It:

1. Calls `apex_host.tools.safety.check_command(cmd, config)` first —
   allowlist, destructive-command block, shell-metacharacter block.
2. If `config.dry_run` is `True` (the default), returns a synthetic
   `ToolResult` immediately — no process, no PATH check, no network.
3. Otherwise checks `shutil.which(cmd.tool)`, then calls
   `asyncio.create_subprocess_exec(cmd.tool, *cmd.args, ...)` — never
   `shell=True`, arguments always passed as a list.
4. On timeout: SIGTERM, wait `config.subprocess_sigterm_grace_seconds`
   (default 5s), then SIGKILL (Phase 7 hardening, P7-I03).
5. On `asyncio.CancelledError`: terminate the child before re-raising
   (P7-I04).

A repo-wide, test-enforced invariant
(`tests/apex_host/test_phase7_async.py::TestArchitectureScan::test_no_subprocess_outside_runner`)
statically scans every `apex_host/*.py` file except `runner.py` for
`create_subprocess_exec`, `create_subprocess_shell`, and
`subprocess.{run,Popen,call,check_output}` and fails the build if any are
found. This is the mechanism that keeps "exactly one subprocess chokepoint"
true, not just documented.

### 1.3 The orphaned path — `ReconExecutor` / `ExecuteExecutor`

`apex_host/agents/recon_executor.py` and `apex_host/agents/execute_executor.py`
implement the generic `memfabric.coordination.protocols.Executor` Protocol
and call `apex_host.tools.runner.run_command` directly. They are **not**
referenced by `build_apex_graph` or any orchestration node — the only
production or test code that imports them is their own test file,
`tests/apex_host/test_recon.py`. They are not a security problem (they still
go through `run_command` → `check_command`), but they are a second,
unused implementation of "how to execute a tool" that this document flags
as a consolidation opportunity (§19), not something Infra Phase 2 removes
(removing them is out of scope: "narrowly scoped... without changing
runtime behavior").

### 1.4 Interactive tools — `TelnetExecutor`

`apex_host/agents/telnet_executor.py::TelnetExecutor` is a **dedicated
adapter**, not a `ToolCommand`/`run_command` invocation. It uses
`asyncio.open_connection` directly (never a subprocess, never a shell) to
speak the telnet protocol: read banner → send username → send password
(only if a password prompt is seen) → send a harmless `id` probe to confirm
shell access. In dry-run mode (`config.dry_run=True`, the default) it
returns a synthetic transcript with zero network activity. See §12 for how
this generalizes.

### 1.5 Policy boundary in detail

`PolicyAdvisor.review_task(task, phase, evidence, config) ->
PolicyDecision` (`apex_host/policy/advisor.py`, `apex_host/policy/models.py`)
is purely synchronous, deterministic, and LLM-free (CLAUDE.md §19). It
evaluates a fixed, ordered rule list (`apex_host/policy/rules.py`):
destructive-command block → target-scope check → attacking-infrastructure
check → password-list check → sensitive-data check → require-review check →
safe-recon-allow → default allow. `PolicyDecision.is_approved` is `False`
for both `blocked` and `needs_human_review` statuses.

---

## 2. Problems with the current design

1. **The backend seam is implicit and untyped.** `TaskDispatcher.__init__`
   accepts `run_command_fn: Callable[[ToolCommand, ApexConfig],
   Awaitable[ToolResult]]` — a bare callable, not a named, documented,
   independently-testable abstraction. Anyone wiring a different execution
   strategy (e.g. a remote Kali service) had to know to pass a
   duck-typed function with the right shape; nothing named this contract or
   enumerated its intended implementations.
2. **No `ToolResult` field records *how* a result was produced.** Before
   this phase, `ToolResult` had no `backend` field and no explicit
   `timed_out` boolean (timeout was only detectable by string-matching
   `error`, e.g. `"timed out"` — see the pre-Phase-2 test
   `test_real_execution_timeout_enforced` in
   `tests/apex_host/test_tool_safety.py`, which does exactly that).
3. **No remote-execution contract exists at all**, typed or otherwise —
   there is no way today to describe "run this on a restricted Kali host"
   without inventing new code from scratch.
4. **Two parallel local-execution implementations exist** (§1.1 vs §1.3),
   which is confusing for a reader trying to find "the" execution path.
5. **`stdin` has no place in the model.** `ToolCommand` had no `stdin`
   field, and no code path could express "run this tool and feed it this
   input" even though `TelnetExecutor`'s own protocol (username/password
   over a socket) is conceptually the same shape of problem for a different
   transport.
6. **Configuration for a remote backend does not exist.** There is no
   `ApexConfig` field for a service URL, a token, or a backend selector —
   every future Kali-service integration would have had to invent its own
   ad-hoc configuration surface, risking exactly the kind of scattered
   `os.environ` reads `apex_host/config.py`'s own architecture test
   (`test_arch_08_config_py_has_no_env_access`,
   `tests/apex_host/test_phase9_config.py`) exists to prevent.

None of these are correctness bugs — the current system is safe (single
subprocess chokepoint, policy gate always runs first, dry-run defaults to
`True`). They are architecture gaps that block building a remote backend
without first deciding on a shape.

---

## 3. Target architecture

```text
Planner → TaskSpec
    ↓
TaskDispatcher.dispatch()          ← policy / conflict / duplicate gates (UNCHANGED)
    ↓ (only for approved, non-duplicate, non-conflicted tasks)
ToolBackend.execute(tool, arguments, timeout_seconds, stdin)
    │
    ├── DryRunToolBackend   — synthetic result, zero I/O
    ├── LocalToolBackend    — apex_host/tools/runner.py (subprocess, argv-list, safety-gated)
    └── RemoteToolBackend   — HTTPS call to a restricted Kali tool service
                                  (allowlisted tools, structured JSON request/response,
                                   authenticated, no shell, bounded output — Phase 3+)
    ↓
ToolResult  (tool, args, returncode, stdout, stderr, timed_out, duration_seconds,
             backend, dry_run, error)
    ↓
parse_observation → MemoryAPI (EKG + episodic log) → RunReport
```

`TaskDispatcher` itself does **not** need to change to reach this target —
it already depends on a callable of the right shape. What Infra Phase 2
adds is the *named, typed, independently-testable* implementation of that
shape, plus an explicit, optional way to supply it
(`build_apex_graph(..., tool_backend=...)`).

---

## 4. Trust boundaries

| Boundary | Enforced by | Crossed by |
|---|---|---|
| Operator intent → approved action | `PolicyAdvisor.review_task()` (deterministic, no LLM) | `TaskDispatcher.dispatch()` step 1, always, before any backend call |
| Approved action → normalized command | `TaskDispatcher._run_command()` / `_run_telnet()` / `_run_browser()` build the `ToolCommand`/task params from already-approved `task.params` only | Nothing else constructs commands after approval |
| Normalized command → argv list | `ToolCommand.tool` + `ToolCommand.args` (a `list[str]`) — never a shell string | `apex_host/tools/safety.py::check_command` rejects shell metacharacters in every token as defense in depth even though `shell=True` is never used |
| APEX process → child process (local) | `asyncio.create_subprocess_exec` (argv list, no shell) inside `runner.py` only | Enforced by the static architecture scan in `test_phase7_async.py` |
| APEX process → remote Kali service (future) | Not yet built. Will be: HTTPS + bearer/token auth + JSON request/response, no shell string ever sent (§10) | `RemoteToolBackend.execute()` — currently raises `NotImplementedError` |
| Secret material → logs/reports | `apex_host.security.redaction` (existing, CLAUDE.md §"Sensitive Data Handling") | Applies equally regardless of backend; `ApexConfig.tool_service_token` is redacted by `to_safe_dict()` |

---

## 5. Policy-to-execution invariant

**No backend may bypass policy approval. The backend executes exactly the
normalized command that was approved.**

This is enforced today, and unchanged by Infra Phase 2, entirely inside
`apex_host/execution/dispatcher.py::TaskDispatcher.dispatch()`:

```python
pd = self._advisor.review_task(task, phase, context.evidence, self._config)
...
if not pd.is_approved:
    ...
    return DispatchResult(disposition=ExecutionDisposition.BLOCKED_POLICY, ...)
# --- only tasks that reach this line can ever call a backend ---
...
tr_dict, disposition = await self._run_command(task, context, args, target, parser, phase)
```

The policy gate (step 1) runs unconditionally before the conflict gate
(step 2), the duplicate gate (step 3), and executor routing (step 5). A
blocked task's `tool_result_dict` is synthesized entirely by
`_make_blocked_result()` — the backend function/object is never invoked.

`tests/apex_host/test_phase6_dispatcher.py::TestToolBackendSeam::test_policy_blocked_task_never_reaches_backend_adapter`
(added in this phase) proves this holds through the new `ToolBackend`
abstraction specifically: a policy-blocked task dispatched with a
spy-wrapped `DryRunToolBackend` never calls `backend.execute()`.

**Where a future change is required:** none, for the invariant itself.
`RemoteToolBackend`, once implemented, sits *downstream* of this same gate
— it is a drop-in replacement for "how an approved command executes," and
the gate does not need to know or care which `ToolBackend` is configured.

---

## 6. Backend interface

`apex_host/tools/backend.py::ToolBackend` — a `typing.Protocol`:

```python
class ToolBackend(Protocol):
    name: str

    async def execute(
        self,
        tool: str,
        arguments: list[str],
        *,
        timeout_seconds: float | None = None,
        stdin: str | None = None,
    ) -> ToolExecutionResult: ...
```

`ToolExecutionResult` is a type alias for `apex_host.types.ToolResult` (see
§7) — no duplicate parallel model was created. `arguments` is always a
`list[str]`; no implementation may join it into a shell string. Every
implementation calls `apex_host.tools.safety.check_command` (directly or by
delegating to `run_command`, which already does) before doing anything
else, and lets the resulting `ValueError` propagate — `TaskDispatcher`
already catches `ValueError` from this call site and maps it to
`ExecutionDisposition.INVALID_TASK`.

---

## 7. Result model

`apex_host/types.py::ToolResult` was extended (not replaced) with two new
fields:

```python
@dataclass(slots=True)
class ToolResult:
    command: ToolCommand
    stdout: str
    stderr: str
    returncode: int
    duration_seconds: float
    dry_run: bool = False
    error: str | None = None
    timed_out: bool = False   # NEW — True only on the timeout path
    backend: str = ""         # NEW — "dry-run" | "local" | (future) "remote"
```

`apex_host/types.py::ToolCommand` gained one new optional field:

```python
@dataclass(slots=True)
class ToolCommand:
    tool: str
    args: list[str]
    timeout_seconds: int = 30
    metadata: dict[str, Any] = field(default_factory=dict)
    stdin: str | None = None   # NEW — see §12 and §19 for wiring status
```

Both changes are additive (new fields have defaults); no existing
construction site (`runner.py`, `test_policy_gate.py`, etc.) needed to
change. `apex_host/tools/runner.py::run_command`'s five `ToolResult(...)`
construction sites were updated to populate `backend` (`"dry-run"` or
`"local"`) and `timed_out` (`True` only on the timeout branch) — no other
field's value changed.

**Important nuance, stated explicitly because it is easy to misread:**
`backend` records the *execution mode that actually produced the result*,
not necessarily *which `ToolBackend` class was called*. `LocalToolBackend`
delegates to `run_command`, which still honors `ApexConfig.dry_run`
internally — so `LocalToolBackend.execute()` on a `dry_run=True` config
returns a result tagged `backend="dry-run"`. This is intentional defense in
depth (§8), proven by
`tests/apex_host/test_tool_backend.py::test_local_backend_honors_dry_run_internally`.

**Not done in this phase:** `apex_host/execution/dispatcher.py`'s
`_run_command()` builds its own `tr: dict[str, Any]` for
`parse_observation`/`write_memory`/`RunReport` and does not currently copy
`timed_out`/`backend` into that dict, so they do not yet appear in EKG
episodes or JSON reports. Threading them through the dispatcher's
dict-building code and `apex_host/eval/report.py` is deferred (§17, §19) —
doing it here would touch the parser/report pipeline, which is explicitly
out of this phase's narrow scope.

---

## 8. Backend roles

### `DryRunToolBackend` (`apex_host/tools/backend.py`)

- Never executes a process and never opens a network connection — proven
  by monkeypatching both `asyncio.create_subprocess_exec` and
  `asyncio.open_connection` to raise if called
  (`tests/apex_host/test_tool_backend.py`).
- Calls `check_command()` first — a disallowed or destructive command is
  still rejected with `ValueError`, exactly as `run_command`'s dry-run
  branch already behaves today.
- Returns a deterministic result: `stdout=f"[dry-run] would execute: {tool}
  {' '.join(arguments)}"`, `returncode=0`, `dry_run=True`,
  `backend="dry-run"` — the same shape `run_command`'s dry-run branch
  already produces, so downstream parsers see no difference.
- Accepts (and ignores) `stdin` — harmless, since nothing runs.

### `LocalToolBackend` (`apex_host/tools/backend.py`)

- Preserves the current trusted local subprocess behavior **exactly** by
  delegating to `apex_host.tools.runner.run_command` — no subprocess logic
  is duplicated. All Phase 7 hardening (SIGTERM→SIGKILL, cancellation
  cleanup, PATH check) applies unchanged.
- Uses argument arrays end-to-end; `shell=False` always (inherited from
  `runner.py`, which never sets `shell=True`).
- Captures stdout and stderr; applies the configured timeout
  (`ApexConfig.max_command_seconds`, overridable per-call via
  `timeout_seconds`).
- Does **not** become the default execution path for a containerized /
  production deployment merely by existing — `build_apex_graph()`'s default
  (`tool_backend=None`) still uses `run_command` directly, not this class
  (§9). A future phase must explicitly opt in.
- Explicitly rejects a non-`None` `stdin` with `NotImplementedError` rather
  than silently dropping it — `runner.py`'s subprocess call has no stdin
  pipe wired up yet (§19).

### `RemoteToolBackend` (`apex_host/tools/backend.py`)

- **Contract only.** Constructing it is always safe (pure data holder — no
  I/O in `__init__`). Calling `execute()` unconditionally raises
  `NotImplementedError` naming the docs section a later phase must
  implement against.
- Requires a non-empty `service_url`; raises `ValueError` immediately in
  `__init__` if one is not supplied — this is deliberately a fail-fast
  constructor check, not a runtime surprise inside `execute()`.
- No HTTP client, no `httpx`/`requests` import, no FastAPI/Flask — none of
  that exists anywhere in this phase's changes.

---

## 9. Configuration design

New `ApexConfig` fields (`apex_host/config.py`), all additive, all with
safe non-secret defaults:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `tool_backend` | `str` | `"local"` | Selects the backend `apex_host.tools.backend.select_tool_backend()` constructs. `"local"` is the default because it is what `build_apex_graph()` has always used (`run_command`) — this field does not change default runtime behavior by existing. |
| `tool_service_url` | `str \| None` | `None` | Base URL for a future restricted Kali tool service (e.g. `http://kali:8080`). |
| `tool_service_token` | `str` | `""` | Auth token for the future remote service. Never a real credential by default; redacted by `to_safe_dict()` when non-empty. |
| `tool_service_timeout_seconds` | `float` | `120.0` | Overall request timeout budget for the future remote transport. |

These map directly to the CLI-flag/env-var design sketched in the Phase 2
task brief (`APEX_TOOL_BACKEND`, `APEX_TOOL_SERVICE_URL`,
`APEX_TOOL_SERVICE_TOKEN`, `APEX_TOOL_TIMEOUT_SECONDS`) but **no
environment-variable reading was added anywhere** in this phase —
`apex_host/config.py` has its own architecture test
(`test_arch_08_config_py_has_no_env_access`) that forbids `os.getenv` /
`os.environ` inside that file, and no other module reads these env vars
either. `.env.example` and any CLI flag wiring (`--tool-backend`,
`--tool-service-url`, ...) are explicitly deferred — the task that
requested this document says so directly ("Do not create `.env.example`
yet; that is Phase 8"), and no CLI parser in `main.py` or
`run_htb_local.py` was touched.

`config.tool_backend` is **not** yet consumed by `build_apex_graph()`'s
default construction path — see §11 and §17 for why, and what a later
phase must do to close that gap.

---

## 10. Remote request/response contract

> **Update (Infra Phase 3):** the server side of this contract is now
> implemented and finalized — see [`docs/kali-tool-service.md`](kali-tool-service.md)
> for the authoritative, tested request/response schema
> (`apex_tool_service/models.py::ExecuteRequest`/`ExecuteResponse`), which
> matches the sketch below with one addition: the response also always
> includes `backend: "kali-service"` and `error: string | null`. The
> *client* side (`RemoteToolBackend`'s HTTP transport, in `apex_host`) is
> still not implemented — that remains Phase 4. The sketch below is kept
> for historical context; treat `docs/kali-tool-service.md` as
> authoritative where the two differ.

**Request** (JSON body, `POST` to the restricted Kali tool service):

```json
{
  "tool": "nmap",
  "arguments": ["-Pn", "-n", "-p", "23", "10.129.0.1"],
  "timeout_seconds": 60,
  "stdin": null
}
```

Never `{"command": "nmap ... && ..."}` — no field on this contract may
carry a shell string. `arguments` is always a JSON array of strings, one
argv token each.

**Response** (sketch — exact shape to be finalized when Phase 3
implements the transport):

```json
{
  "tool": "nmap",
  "arguments": ["-Pn", "-n", "-p", "23", "10.129.0.1"],
  "returncode": 0,
  "stdout": "...",
  "stderr": "",
  "timed_out": false,
  "duration_seconds": 4.2
}
```

`RemoteToolBackend.execute()` (once implemented) is responsible for mapping
this response onto `apex_host.types.ToolResult` with `backend="remote"`,
and for handling, without raising an unhandled exception up through
`TaskDispatcher`:

- connection errors (host unreachable, TLS failure) → `ToolResult` with
  `error` set, `returncode` a sentinel (e.g. `-1`), matching the existing
  convention `run_command` already uses for its own `OSError` branch;
- non-2xx HTTP responses → `error` describing the status code;
- malformed/undecodable response bodies → `error` describing the parse
  failure, never a raw traceback leaked into `stdout`;
- remote-side timeouts (the service itself reports a timeout, or the HTTP
  client's own timeout fires) → `timed_out=True`, mirroring
  `LocalToolBackend`'s contract.

`RemoteToolBackend.execute()` must never raise for any of the above — only
for the two documented "this is a genuine defect" cases: safety-gate
rejection (`ValueError`, same as every other backend) and "transport not
implemented yet" (`NotImplementedError`, this phase only).

---

## 11. Tool allowlisting

Enforced today, client-side, by `apex_host/tools/safety.py::check_command`
— every `ToolBackend` implementation calls it (directly, or transitively
via `run_command`) before doing anything else. This does not change.

**For Phase 3's server**, the restricted Kali tool service must
additionally enforce, server-side (client-side enforcement alone is not a
trust boundary once a network hop exists):

- an **allowlisted tool-name set** — reject any `tool` not on the service's
  own list, independent of what the APEX client believes is allowed;
- **no arbitrary binaries** — the service must not expose a general
  "run anything in PATH" capability;
- **no shell expansion** — the service must invoke the tool the same way
  `runner.py` does today (argv list, no shell), never interpolate
  `arguments` into a shell command line;
- **no pipes, no redirects, no command substitution** — enforced by never
  constructing a shell string in the first place (a corollary of the
  point above, stated separately because it is the exact class of bug this
  whole document exists to prevent);
- **maximum argument count and total payload size** — bound the request
  body so a malformed or malicious client cannot exhaust server resources;
- **execution timeout**, enforced server-side independent of what the
  client requested (a client-requested `timeout_seconds` should be treated
  as a ceiling, not a promise the server blindly trusts);
- **request authentication** — the `tool_service_token` contract (§9)
  must be verified server-side on every request;
- **structured audit logging** — every request (tool, arguments, caller
  identity, timestamp, result summary) logged server-side, independent of
  and in addition to APEX's own episodic log;
- **bounded output size** — stdout/stderr must be truncated or rejected
  past some server-defined cap before ever reaching the network, so a
  runaway tool cannot flood the response;
- **a health endpoint reporting tool availability** — analogous to
  `apex_host/tools/preflight.py::check_local_tools()`'s local PATH check,
  but server-side, so APEX can distinguish "target unreachable" from
  "the Kali service's `nmap` binary is missing" before attempting a real
  engagement.

None of this is implemented in Infra Phase 2 — it is the specification
Phase 3 builds against.

---

## 12. Interactive-tool strategy

`TelnetExecutor` (§1.4) is the existing, working example of the pattern
this document generalizes: **interactive protocols get a dedicated
adapter, not a generic shell string.** It already implements, for telnet
specifically:

- login-prompt detection (reads the banner, does not assume a fixed byte
  count means "ready");
- username entry (`writer.write((username + "\r\n").encode())`);
- blank-password entry (an empty `password_candidates` value still sends
  `"\r\n"`, correct for no-auth services — CLAUDE.md §12.12);
- command execution (`writer.write(b"id\r\n")` as a harmless probe once a
  shell is detected);
- shell validation (`_login_succeeded()` checks for `$`/`#` while excluding
  known failure phrases);
- timeout handling (`asyncio.wait_for(..., timeout=config.max_command_seconds)`
  wraps the whole login attempt).

**How this generalizes to `ToolBackend`:** `ToolCommand.stdin` and
`ToolBackend.execute(..., stdin=...)` exist specifically so that a *future*
interactive adapter (for a tool that reads from stdin rather than speaking
its own socket protocol, e.g. some `nc` usages) has a place in the type
system to put that input, without inventing a parallel "interactive"
special case. `TelnetExecutor` itself does **not** need to move onto this
interface — its protocol (raw TCP with prompt-detection, not a
`ToolCommand`-shaped subprocess or HTTP call) is a poor fit for
`ToolBackend.execute()`'s "one argv command, one result" shape, and
forcing it onto that shape would be exactly the kind of "broad executor
refactoring unrelated to the backend seam" this phase's task brief
prohibits. The correct generalization is: **build new dedicated adapters
for new interactive protocols, the way `TelnetExecutor` already does for
telnet** — not route everything through one `stdin` string.

**Not implemented in this phase:** actually piping `ToolCommand.stdin` into
`runner.py`'s subprocess call. `LocalToolBackend.execute()` raises
`NotImplementedError` if `stdin` is non-`None` rather than silently
dropping it (§8, §19). The live Meow telnet exploit path is unchanged and
was not touched.

---

## 13. Error handling

| Failure | Represented as | Where |
|---|---|---|
| Safety-gate rejection (disallowed/destructive tool, shell metachar) | `ValueError` raised, caught by `TaskDispatcher._run_command`, mapped to `ExecutionDisposition.INVALID_TASK` | `apex_host/tools/safety.py`, unchanged |
| Tool not found in PATH (local) | `ToolResult(error="tool '...' not found in PATH", returncode=-1)` | `runner.py`, unchanged |
| Local process timeout | `ToolResult(timed_out=True, error="command timed out after Ns", returncode=-1)` | `runner.py`, `timed_out` is new in this phase |
| Local `OSError` on launch | `ToolResult(error=str(exc), returncode=-1)` | `runner.py`, unchanged |
| Remote transport not implemented | `NotImplementedError` (this phase only — deliberately loud, not swallowed) | `RemoteToolBackend.execute()` |
| Remote connection/HTTP/parse errors (future) | `ToolResult(error=..., returncode=-1)`, never an unhandled exception | Specified in §10; not yet built |
| Policy block | `DispatchResult(disposition=BLOCKED_POLICY, ...)`, backend never called | `TaskDispatcher.dispatch()`, unchanged |
| Conflict block | `DispatchResult(disposition=BLOCKED_CONFLICT, ...)`, backend never called | `TaskDispatcher.dispatch()`, unchanged |
| Duplicate task | `DispatchResult(disposition=SKIPPED_DUPLICATE, ...)`, backend never called | `TaskDispatcher.dispatch()`, unchanged |

The design principle carried into `ToolBackend`: **ordinary command
failure is data (a `ToolResult` with a non-zero `returncode` or a
populated `error`), never an exception.** The only exceptions any
implementation is expected to raise are `ValueError` (safety-gate
rejection — a caller bug, not a runtime condition) and, for
`RemoteToolBackend` only in this phase, `NotImplementedError`.

---

## 14. Timeouts and output limits

**Today (local):** `ApexConfig.max_command_seconds` (default 30) is the
per-command ceiling; `ToolCommand.timeout_seconds` can request a lower
value per call (`min(cmd.timeout_seconds, config.max_command_seconds)` in
`runner.py`). `ApexConfig.subprocess_sigterm_grace_seconds` (default 5.0,
Phase 7) controls the SIGTERM→SIGKILL escalation window. There is
currently **no output-size cap** on local execution — `stdout`/`stderr`
are captured in full via `proc.communicate()`.

**Future (remote, §11):** the server must enforce its own execution
timeout independent of the client-requested value, and must bound output
size before it ever reaches the network (a local tool can only exhaust
local memory; a remote tool with unbounded output can also exhaust
network/bandwidth and the APEX process's memory receiving it). This is
listed as a required server-side control in §11 and is not implemented.

---

## 15. Audit/report integration

Today, `apex_host/eval/report.py::RunReport` and `to_json_dict()` do not
reference `ToolResult` directly — they work from the plain
`tool_result_dict` that `TaskDispatcher._run_command()` /
`_run_telnet()` / `_run_browser()` build, and from `state["policy_decisions"]`
/ `state["planner_decisions"]`. The new `ToolResult.timed_out` and
`ToolResult.backend` fields exist on the dataclass but are **not yet**
copied into that dict, so they do not yet appear in `RunReport` JSON
exports or EKG episode data (§7). Threading them through is deferred —
doing so touches `dispatcher.py`'s dict-construction and
`apex_host/eval/report.py`, both outside this phase's narrow scope, and
several existing tests assert on the current dict shape (changing it
without a clear need risks an unrelated regression).

---

## 16. Docker and networking implications for later phases

**Explicitly not decided or built in this phase.** Two shapes are on the
table for later phases; this document records both without picking a
loser:

1. **Restricted service API (the architecture this document specifies).**
   APEX calls `RemoteToolBackend.execute()`, which makes an authenticated
   HTTPS request to a purpose-built Kali tool service (§10, §11). The
   service is the only thing with tool binaries installed; it exposes a
   narrow, allowlisted, non-shell API surface. This is the selected target
   architecture (see the module docstring in `apex_host/tools/backend.py`
   and the diagram in §3).

2. **Docker socket integration — explicitly rejected unless a later,
   explicit design decision accepts the risk.** APEX must **not** control
   a Kali container via `/var/run/docker.sock` or `docker exec` as its
   execution mechanism. Mounting the Docker socket into (or making it
   reachable from) the APEX process is equivalent to granting root on the
   host — it lets a compromised or misbehaving APEX process escape its own
   container boundary entirely, which defeats the entire purpose of
   isolating tool execution into a separate service. See §18 for the full
   rejected-alternative writeup.

No Dockerfile, Compose file, or Kali image was added or modified as part
of this phase (per the task brief's explicit prohibition).

---

## 17. Phase-by-phase implementation map

| Phase | Deliverable | Status |
|---|---|---|
| Infra Phase 1 | `uv` dependency/environment management | ✓ Complete (see CLAUDE.md §22) |
| **Infra Phase 2 (this document)** | `ToolBackend` protocol, `DryRunToolBackend`, `LocalToolBackend`, `RemoteToolBackend` (contract only), `ApexConfig` fields, `build_apex_graph(tool_backend=...)` opt-in seam, this document, focused tests | ✓ Complete |
| **Infra Phase 3** | Build and containerize-*ready* (not yet containerized) the restricted Kali tool service (`apex_tool_service/`) implementing §11's server-side allowlist/timeout/audit/health requirements — see [`docs/kali-tool-service.md`](kali-tool-service.md) | ✓ Complete |
| Infra Phase 4 (proposed) | Implement `RemoteToolBackend`'s HTTP transport in `apex_host` against the now-finalized contract (§10, `docs/kali-tool-service.md` §5); wire `config.tool_backend` into `build_apex_graph()`'s *default* construction (today it requires an explicit `tool_backend=` argument); thread `ToolResult.timed_out`/`backend` into `dispatcher.py`'s dict and `RunReport` (§7, §15) | Not started |
| Infra Phase 5 (proposed) | Kali-based Dockerfile running `apex_tool_service` as its entrypoint; APEX application Dockerfile | Not started |
| Infra Phase 6 (proposed) | Docker Compose wiring APEX + Kali service on an isolated network | Not started |
| Infra Phase 7 (proposed) | Wire `ToolCommand.stdin` into `runner.py`'s subprocess call for local interactive use cases that need it (§8, §12, §19) | Not started |
| Infra Phase 8 (proposed) | `.env.example`, CLI flags (`--tool-backend`, `--tool-service-url`, `--tool-service-token`, `--tool-timeout-seconds`) wired via `ApexConfig.from_cli_args()` | Not started |
| Infra Phase 9+ | VPN validation, CI publishing, Meow-specific live-run debugging over the new architecture | Not started |

> **Note (Infra Phase 3):** this renumbers Phases 3–4 from how they were
> originally proposed when this document was written (Phase 2): the
> service was built *before* the client transport, not after, since the
> client needs a finalized contract to implement against. Phases 5+ are
> otherwise unchanged. See `docs/kali-tool-service.md` §17–§18 for what
> Phase 4 and Phase 5 still require.

This numbering is independent of, and must not be confused with, the
Reviewer Remediation Program's "Phase 1"–"Phase 11" in CLAUDE.md §21 (see
CLAUDE.md §22's own disambiguation note).

---

## 18. Rejected alternatives

### Docker socket / `docker exec` control plane

**Rejected** unless a later, explicit design decision accepts the risk in
writing. Reasoning:

- Mounting `/var/run/docker.sock` into the APEX container (or otherwise
  making it reachable) gives APEX the ability to create, inspect, and
  attach to *any* container on the host — functionally equivalent to
  root on the host, not a scoped capability to run tools.
- `docker exec` as an execution primitive reintroduces exactly the
  "arbitrary command in a shared environment" problem this whole
  architecture exists to bound — there is no way to allowlist tool names
  or argument shapes at the `docker exec` layer without building the same
  policy/allowlist logic this document already specifies for a proper
  service API, except with a much larger blast radius on failure.
- A restricted service API (§3, §10, §11) can enforce allowlisting,
  argument-shape validation, timeouts, and audit logging *before* a
  process ever starts, entirely within a purpose-built, minimal-privilege
  service. Docker-socket access cannot be scoped that tightly.

### Rewriting `TaskDispatcher` to consume a `ToolBackend` directly in this phase

**Rejected for this phase, not permanently.** `TaskDispatcher` is a
heavily-tested (131 tests in `tests/apex_host/test_phase6_dispatcher.py`
after this phase), security-critical component. Changing its constructor
to require a `ToolBackend` instance instead of accepting any
`run_command_fn`-shaped callable would be a larger, riskier change than
this phase's stated scope ("narrowly scoped... without changing runtime
behavior"; "Unacceptable changes include... broad executor refactoring
unrelated to the backend seam"). Instead, `apex_host.tools.backend.
to_run_command_fn()` adapts any `ToolBackend` to the shape
`TaskDispatcher` already accepts — proven equivalent by
`tests/apex_host/test_phase6_dispatcher.py::TestToolBackendSeam`. A later
phase can revisit whether `TaskDispatcher` should be updated to hold a
`ToolBackend` natively once `RemoteToolBackend` is real and the two
changes can be validated together.

### A new, parallel `ToolExecutionResult` dataclass

**Rejected.** The task brief that requested this architecture explicitly
says "prefer using existing models... do not create duplicate parallel
result models unnecessarily." `apex_host.types.ToolResult` already had
every field the new contract needs except `timed_out` and `backend`
(both added, non-breaking). `ToolExecutionResult` is a type alias, not a
new type (§6).

---

## 19. Open risks and deferred questions

1. **`ToolCommand.stdin` is not wired into `runner.py`'s subprocess call.**
   `LocalToolBackend.execute(..., stdin=...)` raises `NotImplementedError`
   rather than silently ignoring the input. Wiring `stdin=asyncio.subprocess.PIPE`
   and writing to it is a small, low-risk change in isolation, but it
   touches the safety-critical, Phase-7-hardened subprocess code path and
   currently has no real caller (no local interactive use case needs it
   yet — `TelnetExecutor` uses its own transport). Deferred to Infra
   Phase 7 rather than done speculatively here.
2. **`config.tool_backend` is defined but not consumed by
   `build_apex_graph()`'s default construction.** Only the explicit
   `tool_backend=` keyword argument is honored. This was a deliberate,
   conservative choice: auto-wiring `config.tool_backend` into the default
   path would mean the *value read from configuration*, not just an
   explicit test/caller argument, decides which backend runs in
   production — worth validating end-to-end against a real
   `RemoteToolBackend` (Phase 3) rather than wiring blind.
3. **`ToolResult.timed_out`/`backend` are not yet visible in
   `RunReport`/EKG episodes.** See §7, §15. Anyone building tooling that
   needs to distinguish "this result came from the remote Kali service" at
   the report layer will need Phase 3's dict/report threading first.
4. **`ReconExecutor`/`ExecuteExecutor` (§1.3) remain unconsolidated.**
   They are dead code from the live graph's perspective but are still
   exercised by their own tests. Deleting or merging them was judged out
   of scope ("narrowly scoped... without changing runtime behavior") but
   is flagged here so a future cleanup phase does not have to rediscover
   it.
5. **The exact remote response schema (§10) is a sketch, not a contract
   frozen by a server implementation.** Field names/types may need to
   change once Phase 3 builds against a real service and discovers what
   the service can actually report (e.g. process exit signal vs. exit
   code, partial-output-on-timeout semantics).
6. **Output-size bounding for local execution is still unbounded** (§14).
   This is pre-existing behavior, not introduced by this phase, but it is
   a real deferred risk worth fixing before any local tool execution is
   exposed to less-trusted input than an authorized operator's own CLI
   flags.
7. **No health-check equivalent exists for a future remote backend.**
   `apex_host/tools/preflight.py` checks local PATH availability; nothing
   analogous exists for "is the Kali service up and does it have `nmap`."
   Specified as a requirement in §11; not built.
