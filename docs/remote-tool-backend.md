# Remote Tool Backend (Infra Phase 4)

**Status:** implemented and wired into the default runtime. **Not yet
deployed against a live Kali container** — no Dockerfile, Compose, or VPN
networking exists; this document describes the APEX-side HTTP client only.
**Date:** 2026-07-14

This document is the client-side counterpart to
[`docs/kali-tool-service.md`](kali-tool-service.md) (the server) and
extends [`docs/tool-execution-architecture.md`](tool-execution-architecture.md)
(the overall architecture, written in Infra Phase 2). Read those two first;
this document only covers what changed in Infra Phase 4.

---

## 1. What Infra Phase 4 built

1. **`RemoteToolBackend`** (`apex_host/tools/remote_backend.py`) — a real,
   asynchronous HTTP client implementing the contract in
   `docs/kali-tool-service.md` §5. Previously (Infra Phase 2) this class
   was a contract-only stub whose `execute()` always raised
   `NotImplementedError`.
2. **`select_runtime_backend(config)`** (`apex_host/tools/backend.py`) —
   the centralized, safety-aware backend selector that enforces the
   binding invariant: `config.dry_run=True` always yields
   `DryRunToolBackend`, regardless of `config.tool_backend`.
3. **Centralized default wiring** — `apex_host.runtime.ApexRuntime.run()`
   and `apex_host.orchestration.builder.build_apex_graph()` (when no
   explicit `tool_backend=` is injected) now call `select_runtime_backend()`
   automatically. Before this phase, every caller that wanted anything
   other than the literal `apex_host.tools.runner.run_command` function had
   to inject a backend manually.
4. **CLI flags** (`--tool-backend`, `--tool-service-url`,
   `--tool-service-timeout`) on both `apex_host/main.py` and
   `apex_host/eval/run_htb_local.py`, wired through
   `ApexConfig.from_cli_args()`.
5. **Report/EKG threading** — `ToolResult.timed_out`/`.backend` (added in
   Infra Phase 2 but never consumed) now flow through
   `TaskDispatcher._run_command()`'s result dict into episode data, and a
   new accumulated state field (`ApexGraphState.execution_backend_log`)
   feeds a new `RunReport.backend_usage`/`.timed_out_count` summary.

---

## 2. Client implementation

### 2.1 Construction

```python
from apex_host.tools.remote_backend import RemoteToolBackend

backend = RemoteToolBackend(config)                    # lazy httpx.AsyncClient
backend = RemoteToolBackend(config, client=my_client)   # injected client (tests)
```

Constructed from `ApexConfig`, never from bare positional arguments —
`service_url`, `token`, and `timeout_seconds` are all derived from config
fields (plus one environment-variable fallback for the token; see §3).
Construction validates eagerly and raises `ValueError` immediately (a
configuration error, not a runtime condition) for:

- an empty or missing `tool_service_url`;
- a `tool_service_url` whose scheme is not `http`/`https` (or otherwise
  unparseable);
- no bearer token available from either `tool_service_token` or
  `APEX_TOOL_SERVICE_TOKEN`.

### 2.2 Client lifecycle

The `httpx.AsyncClient` is created **lazily**, on the first real
(non-dry-run) `execute()` call — not in `__init__`. This means:

- Constructing a `RemoteToolBackend` that is never executed (e.g. because
  `dry_run=True` shadows every call — see §4) never opens a socket.
- `aclose()` closes the client only if this backend created it
  (`client=None` was passed to the constructor); it is a no-op when a
  client was injected (the injector owns that client's lifecycle) and a
  no-op when no client was ever created. It is idempotent.

**Managed lifecycle:** `apex_host.runtime.ApexRuntime.run()` constructs the
backend explicitly via `select_runtime_backend(self.config)`, passes it to
`build_apex_graph(..., tool_backend=backend)`, and closes it in a `finally`
block after `graph.ainvoke(...)` completes — this is the recommended,
fully-managed entry point and the one `apex_host.eval.run_htb_local` uses.

**Documented limitation:** a caller that calls `build_apex_graph()`
directly with `tool_backend=None` and ends up with a remote backend
selected via `config.tool_backend="remote"` (through `build_apex_graph`'s
own internal `select_runtime_backend()` fallback) does **not** get
automatic `aclose()` — `build_apex_graph()` has no return-value hook to
expose the backend it constructed internally, and adding one would change
its return type for every caller. Direct callers who care about clean
shutdown in this situation should inject `tool_backend=` explicitly
instead and call `.aclose()` themselves. This is documented in
`build_apex_graph()`'s own docstring.

### 2.3 Request format

```json
{"tool": "nmap", "arguments": ["-Pn", "-n", "-p", "23", "10.129.0.1"], "timeout_seconds": 60, "stdin": null}
```

- `POST {tool_service_url.rstrip('/')}/v1/execute` — URL construction
  strips any trailing slash from the configured base URL before appending
  `/v1/execute`, so `http://kali:8080` and `http://kali:8080/` both
  produce `http://kali:8080/v1/execute` (never a duplicate slash).
- `Authorization: Bearer <token>` header.
- `arguments` is always the literal `list[str]` passed to `execute()` —
  never joined into a string, never a `"command"` field.
- `timeout_seconds` in the body is the *requested remote process* timeout
  (what the server should apply — see `docs/kali-tool-service.md` §8);
  this is distinct from the *client-side* HTTP timeout (§2.4).

### 2.4 Timeout strategy

The client-side `httpx` request timeout is always
`effective_timeout_seconds + 10.0` (a fixed margin,
`_CLIENT_TIMEOUT_MARGIN_SECONDS` in `remote_backend.py`). This margin
exists so the *service's* own SIGTERM-then-grace-period timeout handling
(`docs/kali-tool-service.md` §8) has a chance to produce a structured
`timed_out=true` JSON response before the *client* gives up and reports its
own (less informative) transport-level timeout.

### 2.5 Error mapping

Every ordinary failure becomes a structured `ToolResult` — none of them
propagate as a raised `httpx` exception into `TaskDispatcher`:

| Condition | `ToolResult` fields |
|---|---|
| HTTP 200, well-formed body | Fields mapped directly from the response (§2.6) |
| HTTP 400/401/403/404/422/500/503 | `error="tool service returned HTTP {status}: {detail}"`, `returncode=-1`, `backend="remote"` |
| Malformed JSON body | `error="response body is not valid JSON"` (or similar), `returncode=-1` |
| Valid JSON, missing required field(s) | `error="response missing required field(s): ..."` |
| Valid JSON, wrong field type(s) | `error="response field(s) have unexpected type: ..."` |
| Connection refused / DNS failure | `error="could not connect to tool service: ..."`, `timed_out=False` |
| Connect timeout | `error="connection to tool service timed out"`, `timed_out=False` (never reached the server — the remote process never started) |
| Read timeout | `error="tool service did not respond within the client timeout"`, `timed_out=True` (the server accepted the connection; the remote command may genuinely still be running or have timed out server-side) |
| Any other `httpx.RequestError` | `error="tool service request failed: ..."`, `returncode=-1` |

**The distinction that matters for `timed_out`:** a connect-phase timeout
means we never started talking to the server, so we cannot claim the
remote *process* timed out — only that *we* gave up connecting. A
read-phase timeout means the server accepted the request (the remote
process may well have started), so `timed_out=True` is the more accurate
signal even though it is still a client-side inference (the server's own
structured response, when it arrives in time, is always preferred — this
path only fires when it does *not* arrive in time).

**What is never caught, and why (the configuration/programming-error
distinction this phase's task brief asked for):**

- `ValueError` from `apex_host.tools.safety.check_command()` — the same
  contract every other `ToolBackend` honors. `TaskDispatcher` already
  catches this and maps it to `ExecutionDisposition.INVALID_TASK`. This is
  a *caller* bug (an unapproved/dangerous command reached a backend that
  should never have received it), not a runtime condition to recover from.
- `ValueError` from `RemoteToolBackend.__init__` (bad URL, missing
  token) — a configuration bug, raised immediately at construction time,
  before any task is ever dispatched. Continuing with a backend that
  cannot possibly make a valid request would be unsafe (it would either
  crash unpredictably later or silently do nothing useful); failing fast
  and loud at construction is the correct behavior.

Everything else — every condition where the *request itself* was
well-formed and approved but something about *sending it or interpreting
the response* went wrong — becomes data, not an exception.

### 2.6 Response mapping

```json
{"tool": "nmap", "arguments": [...], "stdout": "...", "stderr": "", "returncode": 0, "duration_seconds": 0.42, "timed_out": false, "backend": "kali-service", "error": null}
```

maps directly onto `apex_host.types.ToolResult`: `stdout`, `stderr`,
`returncode`, `duration_seconds`, `timed_out`, `error` are copied through
type-checked (`_REQUIRED_RESPONSE_FIELDS` in `remote_backend.py` validates
every required field's presence and Python type before trusting it).
`backend` is copied through as-is — apex_tool_service always sends the
literal string `"kali-service"`, so a successful `RemoteToolBackend`
result's `ToolResult.backend` is `"kali-service"`, not `"remote"`. (`"remote"`
is used only for the *failure* paths above, where no service response was
ever received to copy a `backend` value from.) `ToolResult.command` is
reconstructed from the original `tool`/`arguments` this client sent — it
is not parsed back out of the response body.

### 2.7 Safety checks (defense in depth)

Before sending any request, `RemoteToolBackend.execute()`:

1. Checks `config.dry_run` first (§4) — if true, delegates to
   `DryRunToolBackend` and returns without ever touching the network.
2. Calls `apex_host.tools.safety.check_command()` — the exact same
   allowlist/destructive-command/shell-metacharacter check every other
   `ToolBackend` applies. This is early rejection using APEX's own
   allowlist; **the server remains authoritative** — apex_tool_service
   enforces its own, independent, typically-smaller allowlist
   (`docs/kali-tool-service.md` §6) regardless of what this client-side
   check permits. A tool this client considers safe to *send* can still be
   rejected by the server (proven by
   `tests/apex_host/test_remote_backend.py::test_contract_integration_unknown_tool_rejected_by_real_service`).

No independently-divergent client-side allowlist was created — the
existing `check_command()` (and therefore `ApexConfig.allowed_tools`) is
reused as-is, per this phase's own instruction ("Do not maintain an
independently divergent allowlist unless necessary").

---

## 3. Configuration

### 3.1 `ApexConfig` fields (refined in this phase)

| Field | Default | Notes |
|---|---|---|
| `tool_backend` | `"local"` | Normalized (case/whitespace) at the point of interpretation — `select_tool_backend()`/`select_runtime_backend()` never mutate the field itself. Valid values: `"dry-run"`, `"local"`, `"remote"`. |
| `tool_service_url` | `None` | Must be `http://` or `https://` when `tool_backend="remote"` is actually selected. |
| `tool_service_token` | `""` | **No CLI flag.** See §3.2. |
| `tool_service_timeout_seconds` | `120.0` | Overall request timeout budget. |

`config.dry_run` / `config.tool_backend` interaction — the binding
invariant, implemented in `select_runtime_backend()`:

```text
dry_run=True                      -> DryRunToolBackend, ALWAYS (tool_backend ignored)
dry_run=False, tool_backend="dry-run" -> DryRunToolBackend
dry_run=False, tool_backend="local"   -> LocalToolBackend   (the default)
dry_run=False, tool_backend="remote"  -> RemoteToolBackend
```

An explicitly inconsistent configuration (e.g. `tool_backend="remote"`
with no `tool_service_url`) is never silently normalized to something
else — `RemoteToolBackend.__init__`'s `ValueError` fires the moment
`select_runtime_backend()` (or `select_tool_backend()`) is called, making
the misconfiguration impossible to miss.

### 3.2 The bearer token: environment variable, never a CLI flag

**There is deliberately no `--tool-service-token` CLI flag.** Command-line
arguments are visible in shell history and to any other user on the same
host via `ps`/`/proc`; environment variables set with `export` are not.
Set the token this way instead:

```bash
export APEX_TOOL_SERVICE_TOKEN=...
python -m apex_host.eval.run_htb_local --tool-backend remote --tool-service-url http://kali:8080 --target <IP> --no-dry-run
```

`RemoteToolBackend.__init__` resolves the token as
`config.tool_service_token or os.environ.get("APEX_TOOL_SERVICE_TOKEN") or ""`
— an explicit `ApexConfig.tool_service_token` value (e.g. set
programmatically, not via CLI) always wins; the environment variable is
only consulted as a fallback. This exactly mirrors the existing precedent
in `apex_host/llm/router.py::OpenAIModelRouter` for `OPENAI_API_KEY` /
`OPENAI_BASE_URL`. **`apex_host/config.py` itself never reads this
environment variable** — enforced by the pre-existing
`test_arch_08_config_py_has_no_env_access` architecture test; the read
happens only inside `remote_backend.py`, at the point the backend is
actually constructed.

### 3.3 Safe serialization

`ApexConfig.to_safe_dict()` already redacted `tool_service_token` (added in
Infra Phase 2); this phase adds no new secret-bearing fields, so no change
was needed there. Proven again in this phase's tests
(`test_remote_backend.py::test_token_redacted_in_config_safe_dict`).

---

## 4. `dry_run` vs `tool_backend` — the full picture

Three layers of defense, deliberately redundant:

1. **`select_runtime_backend(config)`** — the centralized selector never
   even constructs a `RemoteToolBackend` when `dry_run=True`; it returns
   `DryRunToolBackend` directly. This is the layer every normal engagement
   (`ApexRuntime.run()`, `build_apex_graph()`'s own default) goes through.
2. **`RemoteToolBackend.execute()` itself** checks `self._config.dry_run`
   as its very first action and delegates to `DryRunToolBackend` if true —
   so even a caller that bypasses `select_runtime_backend()` entirely and
   constructs/injects a `RemoteToolBackend` directly still cannot make a
   network call while `dry_run=True`.
3. **`LocalToolBackend`** (unchanged since Infra Phase 2) delegates to
   `apex_host.tools.runner.run_command`, which has its own, independent
   `dry_run` short-circuit — the oldest and most heavily-tested layer.

**Do not allow `dry_run=True` to contact the tool service** (this phase's
own requirement) is therefore true regardless of which of the three layers
a given code path happens to go through — proven at each layer
independently in `tests/apex_host/test_remote_backend.py` and
`tests/apex_host/test_runtime_backend_wiring.py`.

---

## 5. Runtime routing (generic vs interactive)

**This section is the authoritative statement of the routing distinction
this phase's task brief required to be "documented clearly."**

```text
TaskSpec.params["tool"]
    │
    ├── "telnet_access"  → TaskDispatcher._run_telnet()  → TelnetExecutor.run()
    │                       (asyncio.open_connection — its own protocol,
    │                        never a ToolBackend, never run_command_fn)
    │
    ├── "browser"         → TaskDispatcher._run_browser() → BrowserExecutor.run()
    │                       (Playwright — its own protocol, never a
    │                        ToolBackend, never run_command_fn)
    │
    └── anything else     → TaskDispatcher._run_command() → self._run_command_fn(cmd, config)
                             = to_run_command_fn(select_runtime_backend(config))
                             = DryRunToolBackend | LocalToolBackend | RemoteToolBackend
```

**`tool_backend` configuration affects only the third branch.** Setting
`config.tool_backend="remote"` does not change how Telnet or Browser tasks
are executed in any way — `TelnetExecutor` and `BrowserExecutor` are wired
into `TaskDispatcher` through their own dedicated constructor parameters
(`telnet_executor=`, `browser_executor=`), completely independent of
`run_command_fn`. This was already true before Infra Phase 4 (the routing
`if`/`elif`/`else` in `TaskDispatcher.dispatch()` was not touched by this
phase); Infra Phase 4 only proves it explicitly with new tests
(`tests/apex_host/test_runtime_backend_wiring.py::test_telnet_and_browser_bypass_even_with_remote_backend_configured`)
and documents it here so it cannot be missed.

**Do not reroute `TelnetExecutor`/`BrowserExecutor` through
`RemoteToolBackend.execute("telnet", ...)` or similar** — their protocols
(raw TCP prompt-detection; a full browser automation session) do not fit
`ToolBackend.execute()`'s "one argv command, one bounded result" shape, and
forcing them onto that shape was explicitly out of this phase's scope. If
a future phase wants remote-container execution of interactive protocols,
it needs a **dedicated, protocol-aware remote adapter** — not a
mis-shaped call through the generic command endpoint. **No Meow-specific
login automation was implemented or changed by this phase** — `TelnetExecutor`
is entirely unmodified.

---

## 6. Report fields

`apex_host/eval/report.py::RunReport` gained two additive fields:

| Field | Populated from |
|---|---|
| `backend_usage: dict[str, int]` | Count of executions per backend identifier (`"dry-run"`, `"local"`, `"kali-service"`, ...) — from the new `ApexGraphState.execution_backend_log` accumulator |
| `timed_out_count: int` | Count of executions where `timed_out=True` |

**Population path:** `TaskDispatcher._run_command()` now copies
`result.timed_out`/`result.backend` into its per-task result dict (which
already carried every other `ToolResult` field). `apex_host/orchestration/memory_node.py::write_memory`
appends one small `{tool, backend, timed_out, phase}` entry per
backend-tagged result (Telnet/Browser results carry no `"backend"` key and
are therefore excluded automatically — no special-casing needed) to the new
`execution_backend_log` state field. `build_report()` aggregates that log
into `backend_usage`/`timed_out_count`. Both `format_text()` (an
"Execution Backend" section, shown only when non-empty) and `to_json_dict()`
(an `"execution_backend"` key) surface them.

**Backward compatibility:** both new `RunReport` fields default to
`{}`/`0`. A state dict built before this phase (missing
`execution_backend_log` entirely) produces an empty summary, not an error
— proven by `tests/apex_host/test_report.py::TestExecutionBackendSummary::test_no_backend_log_yields_empty_summary`.
No existing `RunReport` field changed meaning or shape.

**Token redaction proof:** `build_report()` never reads
`config.tool_service_token` at all, so it is structurally impossible for
it to leak into a report regardless of what value is configured — proven
by `test_report.py::TestExecutionBackendSummary::test_no_token_appears_in_serialized_report`.

**Not done:** individual per-episode EKG queries/exports were not changed
beyond what already flows through `episode.data` (the full `tr` dict,
including the two new fields, was already stored there — nothing new was
needed for that path). No redesign of the report schema beyond these two
additive fields.

---

## 7. Testing

```bash
uv run pytest tests/apex_host/test_remote_backend.py -q          # 57 tests
uv run pytest tests/apex_host/test_runtime_backend_wiring.py -q  # 14 tests
uv run pytest tests/apex_host/test_report.py -q                  # 77 tests (8 new)
```

All transport/HTTP-failure tests use `httpx.MockTransport` or a custom
`httpx.AsyncBaseTransport` that raises a specific `httpx` exception — no
real socket is ever opened by the mocked tests. The three
contract-integration tests
(`test_remote_backend.py::test_contract_integration_*`) mount the real
Phase 3 `apex_tool_service` FastAPI app in-process via
`httpx.ASGITransport` and drive a complete
`RemoteToolBackend → POST /v1/execute → apex_tool_service → ToolResult`
round trip using `curl --version` (present on macOS and virtually every
Linux distribution, makes no network call) — no Docker, no Kali, no HTB,
no real network socket.

---

## 8. Known limitations and deferred work

- **`build_apex_graph()`'s own internal default backend is not
  lifecycle-managed** (§2.2) — only `ApexRuntime.run()` is. Documented, not
  fixed, in this phase.
- **No retry/backoff logic.** A single transport failure or non-2xx
  response produces one structured `ToolResult`; nothing retries
  automatically. (`TaskDispatcher`'s own retry/repair machinery, unchanged
  by this phase, may still retry the *task* at a higher level depending on
  the resulting `ExecutionDisposition`.)
- **No connection pooling tuning, no HTTP/2 configuration, no proxy
  support** — `httpx.AsyncClient()` is constructed with its library
  defaults.
- **Kali Docker image, APEX Docker image, Docker Compose, `.env.example`,
  container entrypoint scripting, VPN networking, CI image publishing,
  Meow-specific diagnosis, deterministic Meow tests, and authorized live
  Meow validation are all still entirely unimplemented.** This phase is
  the APEX-side HTTP client only.
