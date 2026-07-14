# Kali Tool Service

**Status:** Infra Phase 3 — implemented, independently runnable, independently
tested. **Not yet deployed inside any Kali container. Not yet callable from
`apex_host`.**
**Date:** 2026-07-14
**Package:** `apex_tool_service/` (repo root, parallel to `apex_host/` and
`memfabric/`)

This document describes the restricted HTTP tool-execution service built in
Infra Phase 3, implementing the contract specified in
[`docs/tool-execution-architecture.md`](tool-execution-architecture.md) §10.
Every claim below refers to code that exists in this repository today.

**What this phase did NOT do** (see §17–§18): no Kali container image, no
APEX Dockerfile, no Docker Compose, no `RemoteToolBackend` HTTP client in
`apex_host`, no `.env.example`, no VPN networking, no CI publishing, no
Meow-specific change. This service currently only runs as a local process
on the developer's own machine or in a future CI job — nothing calls it
over a network from APEX yet.

---

## 1. Purpose

`apex_tool_service` is a small, independently deployable HTTP service that
accepts structured tool-execution requests, validates them mechanically,
executes only an explicit allowlist of binaries without ever invoking a
shell, and returns a structured result. It is designed to run inside a
more restrictive container (a future Kali Linux image) than the APEX
application itself, so that even a fully compromised APEX process cannot
do anything this service's own allowlist and validation do not permit.

**It is a constrained execution boundary, not a general remote shell.**

---

## 2. Trust boundary

```text
APEX application (apex_host)
    │  policy/legal approval already happened (apex_host.policy.PolicyAdvisor)
    ▼
[FUTURE: RemoteToolBackend HTTP client — not built in this phase]
    │  HTTPS + Authorization: Bearer <token>
    ▼
apex_tool_service  (THIS PHASE)
    │  1. bearer-token auth (fail closed if unconfigured)
    │  2. request-schema validation (Pydantic, extra="forbid")
    │  3. tool allowlist check
    │  4. executable-availability check
    │  5. argument/stdin size + shell-metacharacter/control-character validation
    │  6. timeout-bounds validation
    ▼
asyncio.create_subprocess_exec(binary, *arguments, ...)   ← the ONLY subprocess call site
    │  shell=False always; argv list only
    ▼
structured ExecuteResponse (stdout, stderr, returncode, timed_out, duration, backend, error)
```

`apex_tool_service` does not know, and does not need to know, why a
particular tool/argument combination was approved — that decision was
already made upstream by APEX's policy layer before any request would ever
be sent here (see §15). This service's only job is mechanical: is this
exact tool allowlisted, are these exact arguments well-formed and
non-shell, is the caller authenticated, are the limits respected.

---

## 3. API endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | None (see §4) | Service + tool-binary availability |
| `POST` | `/v1/execute` | Bearer token (required) | Execute one allowlisted tool invocation |

Implemented in `apex_tool_service/app.py::create_app()`.

---

## 4. Authentication

`POST /v1/execute` requires `Authorization: Bearer <token>`.

**`/health` is intentionally unauthenticated.** Decision, documented here
as required: `/health` exposes only a fixed service name, a status string,
and a `{tool_name: bool}` availability map — no secrets, no paths, no
environment variables, no request-execution capability. An unauthenticated
health check is standard practice (container orchestrators, load
balancers, and monitoring systems routinely need to reach it without
credentials) and the information it discloses ("is `nmap` installed on
this host") is not sensitive in the context this service is designed for
(an operator-controlled restricted execution node). If this changes (e.g.
tool *versions* were ever added to the response), this decision should be
revisited.

Implementation (`apex_tool_service/auth.py`):

- `check_bearer_token(authorization, settings)` returns an `AuthResult`
  with one of five statuses: `ok`, `missing_header`, `malformed_header`,
  `invalid_token`, `service_misconfigured`.
- **Fail closed:** if `settings.token` is `None` (unset), the function
  returns `service_misconfigured` for *every* call, regardless of what the
  client sends. `app.py` maps this to HTTP `503` — distinct from `401`, so
  an operator can tell "the service itself isn't safely configured" apart
  from "the caller sent bad credentials."
- **Timing-safe comparison:** `hmac.compare_digest(supplied, settings.token)`
  — never a plain `==`.
- **Never logged:** the `Authorization` header value is never passed to any
  logging call, on either the success or failure path
  (`apex_tool_service/audit.py::log_auth_failure` only logs the
  `AuthStatus` name, never the header). Verified by
  `tests/apex_tool_service/test_auth.py::test_token_never_logged_on_failure`
  / `test_token_never_logged_on_success`.
- **Never echoed back:** neither the configured token nor a wrong supplied
  token appears in any response body (success or failure).

---

## 5. Request and response schemas

Defined with Pydantic v2 in `apex_tool_service/models.py`.

### Request (`ExecuteRequest`)

```json
{
  "tool": "nmap",
  "arguments": ["-Pn", "-n", "-p", "23", "10.129.0.1"],
  "timeout_seconds": 60,
  "stdin": null
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `tool` | `string` | yes | Must be an exact key in `ALLOWED_TOOLS` (§6) |
| `arguments` | `string[]` | yes (may be empty) | Never a shell string; each element is one argv token |
| `timeout_seconds` | `number \| null` | no | Omitted → `default_timeout_seconds`; explicit value must be within `[min_timeout_seconds, max_timeout_seconds]` |
| `stdin` | `string \| null` | no | `null` means no input pipe; bounded by `max_stdin_bytes` (§9) |

`model_config = ConfigDict(extra="forbid")` — any additional field (in
particular a raw `"command"` string) is rejected by schema validation
alone, before this service's own validation logic ever runs.

### Response (`ExecuteResponse`)

```json
{
  "tool": "nmap",
  "arguments": ["-Pn", "-n", "-p", "23", "10.129.0.1"],
  "stdout": "...",
  "stderr": "",
  "returncode": 0,
  "duration_seconds": 0.42,
  "timed_out": false,
  "backend": "kali-service",
  "error": null
}
```

Field names deliberately mirror `apex_host.types.ToolResult`
(`tool`/`arguments` correspond to `ToolCommand.tool`/`.args`) so a future
`RemoteToolBackend` can map this response onto `ToolResult` with minimal
translation (`docs/tool-execution-architecture.md` §7, §10). `backend` is
always the literal string `"kali-service"` — this service's own
self-identifier; the future `RemoteToolBackend` client is responsible for
normalizing it to `ToolResult.backend="remote"` on the APEX side.

**Ordinary command failure is data, not an HTTP error.** A non-zero
`returncode`, a `timed_out=true`, or a populated `error` string all still
return HTTP `200` — the *request* was valid and was executed; the *tool*
failing is exactly what a caller needs to see in the response body, not
inferred from an HTTP status code. Only auth failures (`401`/`503`) and
validation failures (`400`) are non-`200`.

### `GET /health` response

```json
{"status": "ok", "service": "apex-tool-service", "tools": {"nmap": true, "curl": true, "telnet": false}}
```

---

## 6. Tool allowlist

`apex_tool_service/allowlist.py::ALLOWED_TOOLS` — a fixed
`dict[str, str]` mapping API-facing tool name to the exact binary name
passed to `asyncio.create_subprocess_exec`:

| Tool | Binary | Evidence / rationale |
|---|---|---|
| `nmap` | `nmap` | `apex_host/tools/registry.py`; `ReconPlanner`; `NmapParser` |
| `curl` | `curl` | `apex_host/tools/registry.py`; `WebPlanner`; `CommandParser` |
| `nc` | `nc` | `apex_host/tools/registry.py`; `ReconPlanner` banner probes; `BannerParser` |
| `netcat` | `netcat` | Alternate binary name for `nc` on some systems — same evidence as `nc` |
| `ping` | `ping` | No direct APEX usage evidence; included per this phase's own task brief as a safe, read-only network diagnostic with the same risk profile as the tools above |
| `telnet` | `telnet` | No direct APEX usage evidence as a *subprocess* (APEX's `TelnetExecutor` speaks the protocol itself over `asyncio.open_connection`, never shelling out); included because this phase's task brief names it explicitly in the required `/health` response shape, with the same risk profile as `nc` |

**Deliberately excluded**, with evidence acknowledged: `ffuf`, `gobuster`
(wordlist-driven fuzzers — APEX's own `apex_host/policy/rules.py` already
treats `-w`/`--wordlist` as opt-in/blocked by default; this service would
need matching wordlist-path validation not designed in this phase);
`searchsploit` (a local exploit-database search tool, a different risk
shape than a network execution primitive); `python3` (APEX's own local
`allowed_tools` default includes it, but this phase's task brief
explicitly forbids general-purpose interpreters here — the explicit
prohibition overrides local usage evidence).

**`NEVER_ALLOWED`** (`apex_tool_service/allowlist.py`) is a second,
independent constant — shells, other interpreters, `env`, `sudo`/`su`,
container/orchestration control planes, and destructive commands — checked
by `is_allowed()` in addition to `ALLOWED_TOOLS` membership, so a careless
future edit that adds e.g. `"bash": "bash"` to `ALLOWED_TOOLS` is still
rejected. Proven by
`tests/apex_tool_service/test_security_invariants.py::test_never_allowed_tool_rejected_even_if_added_to_allowlist`.

An unknown `tool` value is rejected in
`apex_tool_service/validation.py::resolve_and_validate_tool` — before any
process creation, before even checking whether the named binary exists on
PATH.

---

## 7. Validation rules

All in `apex_tool_service/validation.py`, all raising the client-safe
`RequestValidationError` (never a raw traceback):

| Check | Enforced against |
|---|---|
| Tool allowlisted | `ALLOWED_TOOLS` / `NEVER_ALLOWED` (§6) |
| Argument count | `settings.max_arguments` |
| Per-argument length | `settings.max_argument_length` |
| Total argument byte size | `settings.max_total_argument_bytes` |
| Shell metacharacters (`;`, `&&`, `\|\|`, `\|`, `>>`, `>`, `<`, `` $( ``, `` ` ``) | every argument *and* the `tool` field itself |
| Control characters (newline, carriage return, null byte) | every argument *and* the `tool` field itself |
| Stdin byte size | `settings.max_stdin_bytes` |
| Timeout bounds | `[settings.min_timeout_seconds, settings.max_timeout_seconds]` — an out-of-bounds *explicit* value is rejected, never silently clamped |

The shell-metacharacter list intentionally duplicates (does not import)
`apex_host/tools/safety.py::_SHELL_OPERATORS` — see
`apex_tool_service/validation.py`'s module docstring for why (keeping the
two packages independently deployable).

`asyncio.create_subprocess_exec(...)` with `shell=False` (the implicit,
only mode — this project never sets `shell=True`) is used for every
execution; arguments are never concatenated into a command string. See §16
for the static/dynamic tests proving this.

---

## 8. Timeout behavior

- `timeout_seconds` omitted → `settings.default_timeout_seconds` (30s
  default) is used, never rejected.
- An *explicit* `timeout_seconds` outside `[min_timeout_seconds,
  max_timeout_seconds]` (1s–120s by default) is a `400` validation
  rejection — the caller is told, not silently clamped.
- On timeout, `apex_tool_service/executor.py::_terminate_and_wait` sends
  `SIGTERM`, waits up to a 5-second grace period, and escalates to
  `SIGKILL` if the process is still alive — the same discipline as
  `apex_host/tools/runner.py` (Phase 7 hardening), reimplemented
  independently here (no shared import — see §15).
  The process is always reaped (`await proc.wait()`), never left as a
  zombie.
- The response for a timed-out execution has `timed_out=true`,
  `returncode=-1`, and a populated `error` string.

---

## 9. Output bounding

`apex_tool_service/executor.py::_decode_bounded(data, max_bytes)`:

- Truncates the raw **bytes** (not the decoded string) to
  `settings.max_stdout_bytes` / `settings.max_stderr_bytes` (1 MiB each by
  default) before decoding — this avoids splitting a multi-byte UTF-8
  sequence in a way that would raise; any resulting partial sequence is
  handled by `errors="replace"`.
- Decodes with `"utf-8", errors="replace"` — invalid bytes become the
  Unicode replacement character, never an exception.
- Truncation is logged (tool name + which stream(s)) at `INFO` level, but
  the truncated content itself is not specially flagged in the response
  body beyond simply being shorter than the process actually produced.

---

## 10. Audit logging

`apex_tool_service/audit.py`, using the stdlib `logging` package (matching
`apex_host`'s own convention of module-level `logging.getLogger(__name__)`
loggers — there is no pre-existing structured-logging framework in this
repository to instead adopt).

Per accepted request, logged: a `correlation_id` (UUID4 hex), `tool`,
argument count, timeout, acceptance timestamp (implicit in the log
record), completion status (via `returncode`/`error`/`timed_out`),
duration, and stdout/stderr **byte counts** (not content).

**Argument logging decision:** arguments are logged as a *bounded
preview* — each argument truncated to 40 characters, the joined preview
further truncated to 200 characters
(`apex_tool_service/audit.py::preview_arguments`) — not logged in full.
This bounds log volume and reduces incidental exposure if a validation gap
ever let something sensitive-looking through; the trade-off is less
complete audit detail than full logging. An operator needing the complete
argument list should correlate the `correlation_id` against the *caller's*
own audit trail (APEX's EKG/episodic log, which already redacts
credentials via `apex_host.security.redaction`), not reconstruct it from
this service's logs alone.

**Never logged, anywhere:** the bearer token (§4), the full `stdin`
payload (only its presence/size would need to be added if that level of
audit detail is ever wanted — today it is not logged at all), environment
variables, the configured `ServiceSettings.token`.

Failed authentication attempts are logged (`AuthStatus` value +
correlation ID) without ever including the credential that was supplied.

---

## 11. Configuration

`apex_tool_service/settings.py::ServiceSettings` — the sole place this
package reads environment variables (`ServiceSettings.from_env()`; a
`Mapping` can be injected for tests instead of touching real `os.environ`).

| Env var | Default | Purpose |
|---|---|---|
| `APEX_TOOL_SERVICE_TOKEN` | *(unset)* | Bearer token; unset → `/v1/execute` fails closed (503) |
| `APEX_TOOL_SERVICE_HOST` | `127.0.0.1` | Bind host — **not** `0.0.0.0` by default; broader exposure is an explicit opt-in |
| `APEX_TOOL_SERVICE_PORT` | `8080` | Bind port |
| `APEX_TOOL_SERVICE_DEFAULT_TIMEOUT_SECONDS` | `30` | Used when a request omits `timeout_seconds` |
| `APEX_TOOL_SERVICE_MAX_TIMEOUT_SECONDS` | `120` | Ceiling for an explicit `timeout_seconds` |
| `APEX_TOOL_SERVICE_MIN_TIMEOUT_SECONDS` | `1` | Floor for an explicit `timeout_seconds` (additive to the task brief's required set) |
| `APEX_TOOL_SERVICE_MAX_ARGUMENTS` | `32` | Max `arguments` list length |
| `APEX_TOOL_SERVICE_MAX_ARGUMENT_LENGTH` | `512` | Max characters per argument |
| `APEX_TOOL_SERVICE_MAX_TOTAL_ARGUMENT_BYTES` | `4096` | Max combined UTF-8 byte size of all arguments (additive) |
| `APEX_TOOL_SERVICE_MAX_STDIN_BYTES` | `65536` | Max `stdin` UTF-8 byte size |
| `APEX_TOOL_SERVICE_MAX_STDOUT_BYTES` | `1048576` | stdout truncation ceiling |
| `APEX_TOOL_SERVICE_MAX_STDERR_BYTES` | `1048576` | stderr truncation ceiling |

No field has a secret default. `ServiceSettings.to_safe_dict()` returns
every field except the raw token (replaced by a `token_configured: bool`)
— used for any future diagnostics endpoint or startup log line, never the
token itself. **No `.env.example` was created in this phase** — deferred,
per this phase's own task brief, to whichever phase adds `apex_host`'s
`.env.example` too.

---

## 12. Running locally for development

```bash
# One-time: install dependencies (fastapi, uvicorn added to pyproject.toml this phase)
uv sync --all-groups

# Start the service (binds 127.0.0.1:8080 by default)
APEX_TOOL_SERVICE_TOKEN=dev-only-token uv run python -m apex_tool_service

# Or override host/port via CLI flags
uv run python -m apex_tool_service --host 127.0.0.1 --port 18080

# Or run the ASGI app object directly via uvicorn
APEX_TOOL_SERVICE_TOKEN=dev-only-token uv run uvicorn apex_tool_service.app:app --port 8080
```

Then, in another terminal:

```bash
curl -s http://127.0.0.1:8080/health

curl -s -X POST http://127.0.0.1:8080/v1/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-only-token" \
  -d '{"tool": "curl", "arguments": ["--version"]}'
```

If `APEX_TOOL_SERVICE_TOKEN` is not set, `__main__.py` prints a warning to
stderr and every `/v1/execute` call returns `503` (fail closed) — `/health`
still works.

No Kali installation, no Docker, and no root privileges are required to
run or test this service locally — every allowlisted tool used in the test
suite (`curl`, `python3` for direct `executor.py` unit tests) is either
already present on a standard macOS/Linux development machine or is the
Python interpreter running the tests itself.

---

## 13. Testing

```bash
# Full focused suite
uv run pytest tests/apex_tool_service -q

# Security-invariant tests only
uv run pytest tests/apex_tool_service/test_security_invariants.py -q
```

Test files (`tests/apex_tool_service/`): `test_health.py`, `test_auth.py`,
`test_validation.py`, `test_execution.py`, `test_security_invariants.py`,
`test_settings.py`, `test_audit.py`, `test_separation_from_apex_policy.py`.

All tests run against an in-process ASGI transport
(`httpx.AsyncClient(transport=httpx.ASGITransport(app=app))`) — no real
socket, no external server process, in the normal test run. Execution
tests that need a real subprocess use `curl --version` (present on macOS
and virtually every Linux distribution, makes no network call) or call
`apex_tool_service.executor.execute_tool()` directly with `python3` (the
interpreter already running the tests) — never `nmap`, Docker, root, HTB,
or internet access. This is intentional so the suite runs identically on
the current macOS development environment and a future Linux CI runner.

---

## 14. Expected future Kali-container integration

**Not built in this phase.** The intended shape (Infra Phase 4+, per
`docs/tool-execution-architecture.md` §17):

1. A Kali-based container image installs the real `nmap`/`curl`/`nc`/etc.
   binaries and runs `apex_tool_service` (this package, unchanged) as its
   entrypoint (`python -m apex_tool_service`).
2. The container is reachable only from the APEX application's own
   container/network segment — never exposed publicly — consistent with
   `APEX_TOOL_SERVICE_HOST` defaulting to `127.0.0.1` (an operator
   deploying this into a container must explicitly bind `0.0.0.0` or the
   container's interface).
3. `apex_host`'s `RemoteToolBackend.execute()` (currently a contract-only
   stub — `docs/tool-execution-architecture.md` §8) gains an actual HTTP
   client implementation that calls this service's `POST /v1/execute`
   using the exact request/response shapes in §5 above.

No Dockerfile for this service, no base-image selection, and no
container-networking decision were made in this phase.

---

## 15. Relationship to APEX policy approval

Two independent checks are both required in the final system — this is
defense in depth, not either/or:

| | APEX policy/legal gate | This service |
|---|---|---|
| **What it decides** | Whether an *action* is authorized — is this target in scope, is this tool/argument combination permitted for this engagement, does this need human review | Whether a *request* is mechanically safe to execute — allowlisted tool, well-formed non-shell arguments, authenticated caller, within size/timeout limits |
| **Where** | `apex_host.policy.PolicyAdvisor.review_task()`, runs inside `apex_host.execution.dispatcher.TaskDispatcher.dispatch()`, entirely before any backend (local or, eventually, remote) is ever called | `apex_tool_service/app.py`, runs on every `POST /v1/execute`, with no visibility into *why* a request was sent |
| **Knows about targets/scope?** | Yes — this is its entire purpose | **No** — `ExecuteRequest` has no `target`/`scope`/`authorized` field; proven by `tests/apex_tool_service/test_separation_from_apex_policy.py::test_apex_tool_service_does_not_make_authorization_decisions_about_targets` |
| **Can be bypassed by the other?** | No — a request this service would happily execute (e.g. `curl --version`) never reaches it unless APEX's policy gate already approved sending it | No — even a policy-approved request must still pass this service's allowlist/validation/auth before anything executes |

**This service does not decide whether a target is legally authorized.**
It has no concept of "target," "scope," or "authorization" at all — see
the schema in §5. `apex_tool_service` does not import `apex_host` or
`memfabric` anywhere (`tests/apex_tool_service/test_separation_from_apex_policy.py`
proves this structurally), so it has no way to see or duplicate APEX's
policy decision even by accident. The `PolicyAdvisor`/`PolicyDecision`
types were deliberately not moved into this service, per this phase's own
task brief.

---

## 16. Known limitations

- **No server-side rate limiting.** A caller that has a valid token can
  send requests as fast as it likes; nothing here throttles per-token or
  per-IP request rate. Left for a future phase — this service's execution
  timeout and output bounds limit the *impact* of any single request, but
  not request *frequency*.
- **No TLS termination in this service.** `uvicorn.run()` is started
  without TLS configuration — a production deployment must terminate TLS
  in front of this service (a reverse proxy, the container platform's own
  ingress, etc.). Not configured or decided in this phase.
- **No multi-tenant token scoping.** There is exactly one configured
  token; every authenticated caller has identical allowlist/limit access.
  No per-caller allowlist restriction exists.
- **`stdin` support is intentionally minimal.** It pipes a single bounded
  string to the process and closes the pipe — there is no interactive,
  multi-turn stdin/stdout exchange (that remains the job of a dedicated
  adapter like `apex_host`'s `TelnetExecutor`, which this service
  explicitly does not replace or reimplement — see
  `docs/tool-execution-architecture.md` §12).
- **No output streaming.** The full (bounded) stdout/stderr is returned
  only after the process exits or times out — there is no
  server-sent-events or chunked-streaming variant for long-running tools.
- **Health check does not verify binary *correctness*, only presence.**
  `shutil.which(binary) is not None` confirms the binary exists on PATH;
  it does not run `--version` or otherwise validate the binary actually
  works.

---

## 17. Deferred Phase 4 client work

- Implement `apex_host.tools.backend.RemoteToolBackend.execute()`'s actual
  HTTP transport (currently `NotImplementedError` —
  `docs/tool-execution-architecture.md` §8) against this service's
  `POST /v1/execute` contract (§5).
- Wire `ApexConfig.tool_backend` into `build_apex_graph()`'s *default*
  backend construction (today only the explicit `tool_backend=` keyword
  argument is honored — `docs/tool-execution-architecture.md` §19).
- Thread `ExecuteResponse`'s `timed_out`/`backend` fields (already present
  on `apex_host.types.ToolResult` since Infra Phase 2) through
  `TaskDispatcher`'s dict-building code and `RunReport`/EKG episodes.
- Client-side connection-error/non-2xx/malformed-response/remote-timeout
  handling exactly as specified in `docs/tool-execution-architecture.md`
  §10 — none of that client logic exists yet; only the server side
  (this document) is built.

---

## 18. Deferred Docker and Compose work

**Not started in this phase, explicitly:**

- A Kali-based Dockerfile that installs the real allowlisted binaries and
  runs this service as its entrypoint.
- An APEX application Dockerfile.
- A `docker-compose.yml` (or equivalent) wiring the two containers
  together on an isolated network.
- Any VPN container or tunnel configuration for reaching authorized HTB
  targets from inside this architecture.
- A GitHub Actions workflow or any other CI publishing pipeline.
- `.env.example` for either `apex_host` or `apex_tool_service`.
- Any Meow-specific exploitation change — this phase touched no
  machine-specific logic anywhere (and per CLAUDE.md §13.9, never will:
  "No machine-specific profile files").

Docker-socket-based control of a Kali container remains explicitly
rejected as an architecture choice, unless a later, explicit design
decision accepts that risk in writing — see
`docs/tool-execution-architecture.md` §16 and §18 for the full reasoning,
unchanged by this phase.
