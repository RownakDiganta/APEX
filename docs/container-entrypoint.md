# Container Entrypoint and Automated Preflight

**Status:** Infra Phase 9 — implemented and validated end-to-end against a
real Docker Compose environment (Kali health check, real `RemoteToolBackend`
smoke execution, real `docker compose up --build` default startup).
**Date:** 2026-07-15
**Files:** [`apex_host/container_entrypoint.py`](../apex_host/container_entrypoint.py),
[`apex_host/eval/preflight.py`](../apex_host/eval/preflight.py),
[`docker/apex/Dockerfile`](../docker/apex/Dockerfile),
[`compose.yaml`](../compose.yaml),
[`tests/apex_host/test_eval_preflight.py`](../tests/apex_host/test_eval_preflight.py),
[`tests/apex_host/test_container_entrypoint.py`](../tests/apex_host/test_container_entrypoint.py)

This document describes the final safe container entrypoint and automated
preflight orchestration built in Infra Phase 9, on top of Infra Phases 1–8
(`uv` environment management; `ToolBackend` architecture; the restricted
Kali tool service; `RemoteToolBackend` wiring; the APEX application
container; the Kali tool-service container; Docker Compose integration;
centralized environment configuration and `.env.example`).

---

## 1. Purpose

Every prior Infra Phase built one piece of the deployable system (an image,
a client, a Compose file, an environment-loading module) but none of them
verified, at container start time, that the *whole* environment — real
configuration, real report-directory permissions, real compiled knowledge,
real policy file, real Kali connectivity — was actually usable before an
operator (or Compose) attempted a real engagement. `apex_host/container_entrypoint.py`
closes that gap: it is the APEX container's `ENTRYPOINT`, and it always runs
a structured preflight pass before dispatching to any operational command.

The default `docker compose up --build` must remain safe, deterministic,
target-free, and suitable purely for proving the two-container setup is
operational — it must never start an engagement merely because the
container started. This phase preserves that guarantee while making the
verification itself real (an actual Kali `GET /health` and an actual
harmless tool execution, not an argparse `--help` no-op).

---

## 2. Startup flow

Every mode except `exec` (which deliberately bypasses this — see §4)
follows the same sequence:

```
parse environment + CLI configuration
  -> print redacted configuration summary
  -> verify report directory (writable, not overwritten)
  -> verify compiled knowledge (only when a knowledge root is configured)
  -> verify policy file (when configured, or required by mode)
  -> [smoke/run only] verify Kali tool-service health (GET /health)
  -> [smoke/run only] one harmless remote-tool smoke command
  -> only on success: execute the selected command
```

Configuration parsing reuses the Infra Phase 8 `apex_host/config_env.py`
loader (`load_apex_config_from_env`) unchanged — the entrypoint never
constructs `ApexConfig` directly and never duplicates CLI>environment>default
precedence logic. `check`/`smoke` never import or construct the engagement
graph (`apex_host.graph`/`apex_host.orchestration`) at all — only
`dry-run`/`run` import `apex_host.eval.run_htb_local.run_engagement`, and
they do so lazily, inside their own handler functions, so a plain
`check`/`smoke` invocation never pays the cost or risk of loading the full
orchestration stack.

---

## 3. Modes

| Mode | Target required | Contacts Kali | Runs an engagement | Confirmation required |
|---|---|---|---|---|
| `check` | No | No | No | No |
| `smoke` | No | Yes (real) | No | No |
| `dry-run` | Yes | No | Yes — forced `dry_run=True` | No |
| `run` | Yes | Yes (when `tool_backend=remote`) | Yes — real | `--no-dry-run` **and** `--confirm-live` |
| `exec` | N/A | N/A | N/A (bypasses the workflow) | No |

```bash
python -m apex_host.container_entrypoint check
python -m apex_host.container_entrypoint smoke
python -m apex_host.container_entrypoint dry-run --target 10.10.10.14
python -m apex_host.container_entrypoint run --target 10.10.10.14 --no-dry-run --confirm-live
python -m apex_host.container_entrypoint exec -- python -m apex_host.main --help
```

### 3.1 `check` mode

Local-only validation: configuration shape, report-directory writability,
compiled knowledge (when `--knowledge-root`/`$APEX_KNOWLEDGE_ROOT` is set),
policy file (when configured — otherwise a soft, informational pass, since
the conservative built-in default is a legitimate outcome outside live
mode), and LLM readiness (a trivial pass when `use_llm=False`, the
default). No target is required — `--target`/`$APEX_TARGET` are both
optional; when neither is supplied, the synthetic placeholder
`"config-check"` (`apex_host.config_env.CONFIG_CHECK_TARGET_PLACEHOLDER`)
is used instead, exactly as `apex_host.eval.check_config` already does.
Never touches the network. Never instantiates an LLM client. Never runs a
tool. Exit code `0` only when every required check passes.

### 3.2 `smoke` mode

Everything `check` does, plus two network-touching checks:

1. **`remote backend selected`** — requires `tool_backend == "remote"`
   explicitly (a bare, actionable failure rather than letting the health
   check fail confusingly when an operator simply forgot
   `--tool-backend remote`).
2. **`Kali health`** — an unauthenticated `GET /health` against
   `tool_service_url`, bounded by a 5-second timeout. Verifies HTTP 200,
   correct `service`/`status` fields, and that every tool in the required
   set (`curl`, by default) reports available. The bearer token is never
   sent to this endpoint (`/health` is intentionally public — see
   `docs/kali-tool-service.md` §4).
3. **`remote tool smoke`** — executes exactly one deterministic, harmless,
   already-allowlisted command (`curl --version`) through the real
   `apex_host.tools.backend.select_runtime_backend(config)` — the same
   selection function the production engagement path uses. No target, no
   externally-reachable network call (`curl --version` makes no HTTP
   request at all).

Like `check`, `smoke` never requires a target and never runs an
engagement. Unlike `check`, `smoke` **forces `dry_run=False` unconditionally**
— no CLI flag, no `$APEX_DRY_RUN` involvement — so that the connectivity
check is real rather than synthetic.

**Why forcing `dry_run=False` here does not weaken CLAUDE.md §13.5:** that
invariant protects against arbitrary, target-directed, user/environment-
controllable command execution defaulting to real. Smoke mode has none of
that shape — no target, no user-supplied tool or arguments, exactly one
hardcoded command with a return value that cannot affect any external
system. This is the same safety profile already established and accepted
for Infra Phase 7/8's `apex_host.eval.compose_smoke --no-dry-run`, which
`compose.yaml`'s default command used before this phase. Infra Phase 9
simply moves that same, already-accepted default into the container's real
`ENTRYPOINT` instead of a separate ad hoc smoke script.

### 3.3 `dry-run` mode

Requires a target (`--target` or `$APEX_TARGET`). Forces `dry_run=True`
unconditionally — there is no `--dry-run`/`--no-dry-run` flag on this
subcommand at all, so there is no way to accidentally request real
execution through it. Runs the same local checks as `check` (report
directory, knowledge, policy — soft pass when unconfigured, LLM
readiness), never contacts Kali, and on success dispatches to the existing
`apex_host.eval.run_htb_local.run_engagement()` pipeline — the same,
unmodified, already-tested dry-run engagement path used by every prior
phase. Reports are written to `--report-dir` (default `/app/run_reports`
inside the container) and optionally exported via `--export-json`/
`--export-graph`.

### 3.4 `run` mode — the live-run safeguard

Represents future authorized live operation. Requires **all** of:

1. `--target` (or `$APEX_TARGET`).
2. `--no-dry-run` — resolved through the normal, unmodified
   `apex_host.config_env.resolve_dry_run` precedence (CLI flag wins
   outright; `$APEX_DRY_RUN=false` alone can never enable it — CLAUDE.md
   §13.5).
3. `--confirm-live` — an explicit CLI flag, checked by
   `apex_host.eval.preflight.check_live_confirmation`. **There is
   deliberately no environment-variable equivalent anywhere in this
   module.** An operator's shell history or a stale exported
   `$APEX_LIVE_CONFIRM` could otherwise silently re-arm a future
   invocation; requiring a flag on every single command means the operator
   must consciously type it every time.
4. A full preflight pass, **with the policy check now `required=True`**
   (`run_local_checks(..., policy_required=True)`) — unlike every other
   mode, `run` refuses to proceed on the conservative built-in default; an
   explicit, resolvable policy file is mandatory for live operation.
5. When `tool_backend == "remote"`: a passing Kali health check and a
   passing harmless remote-tool smoke check, run exactly as in `smoke`
   mode, before the real engagement's own tool calls are ever attempted.

If confirmation is missing, dry-run was not explicitly disabled, or any
required preflight check fails, `run` mode refuses with exit code `1` and
**never dispatches to the engagement pipeline** — proven by
`tests/apex_host/test_container_entrypoint.py::TestRunModeRefusal`, where
every refusal path injects an `AssertionError`-raising fake in place of
the real dispatch function to guarantee it is never called.

`run` mode was never exercised against a real target in this phase (no HTB
VPN routing exists yet — see §19) — only its refusal paths were validated,
both in automated tests and by direct manual invocation.

### 3.5 `exec` mode

Runs an arbitrary command via `os.execvp` — **process replacement**, argv-list
only, never a shell, never string reinterpretation:

```bash
docker run --rm apex-image exec -- python -m apex_host.main --help
```

This intentionally bypasses the entire APEX preflight/configuration
workflow (useful for debugging, or for the documented `--help` equivalent
of prior phases — see §16) but does **not** bypass container OS
permissions: the exec'd process still runs as the image's non-root `apex`
user with exactly the filesystem/network access any other process in the
container has. Because `os.execvp` replaces the current process image
entirely, no signal-forwarding logic is needed or possible once the call
succeeds — there is no longer a Python process to forward anything through;
signals sent to the container's PID 1 are delivered directly to the new
program.

---

## 4. Preflight implementation (`apex_host/eval/preflight.py`)

A reusable module, independent of the entrypoint, built around two frozen
dataclasses:

```python
@dataclass(frozen=True, slots=True)
class PreflightCheck:
    name: str
    passed: bool
    detail: str
    required: bool = True   # False = informational warning, never blocks

@dataclass(frozen=True, slots=True)
class PreflightResult:
    checks: list[PreflightCheck]
    # .passed / .failed_required / .warnings / .required_count
    # .to_dict() / .format_text()
```

Every check function returns a `PreflightCheck` and never raises for an
*ordinary* failure (a missing file, an unreachable service, an invalid
value) — this matches the "ordinary failure is data" discipline already
established by `apex_host.tools.backend`/`apex_host.tools.remote_backend`
for tool execution. The one place this discipline was not yet applied when
first written — `check_remote_smoke`'s call to `select_runtime_backend()`,
which can raise `ValueError` for a missing bearer token — was found and
fixed during this phase's own manual testing (see §17).

---

## 5. Report directory validation

`check_report_directory(default_dir=..., report_path=None, graph_path=None)`
verifies the default report directory and the parent directory of any
explicitly requested `--export-json`/`--export-graph` path exist (creating
them with `mkdir(parents=True, exist_ok=True)` if not) and are writable by
the current user. Writability is proven with a uniquely-named
(`.apex_preflight_write_test_<pid>_<ms>`), immediately-removed marker file
— never a real report filename, so an existing report is never at risk of
being overwritten or deleted by the check itself. No recursive permission
or ownership change is ever performed.

---

## 6. Compiled knowledge validation

`check_compiled_knowledge(knowledge_root)` delegates entirely to the
existing `apex_host.knowledge.compiler.verify_compiled.verify_compiled()`
— the same nine-required-output spec, JSONL parseability check, and
minimum-record-count enforcement documented in CLAUDE.md §18.8. This check
never duplicates that logic and never recompiles or silently accepts a
corrupted compiled tree. When no knowledge root is configured at all, this
is a **soft pass** (`required=False`) — knowledge is optional application
configuration, not a hard prerequisite for `check`/`smoke`/`dry-run`. It
is never soft for a *configured* root: a `--knowledge-root` that resolves
to missing or malformed compiled outputs is always a required, blocking
failure.

---

## 7. Policy validation

`check_policy(config, required=...)` reuses
`apex_host.policy.policy_loader._resolve_policy_path` — the exact same
three-tier resolution order `load_policy()` itself uses (explicit
`config.policy_file` > `knowledge_root`-derived > the conventional local
`knowledge/policy_db/compiled/hackthebox_lab.yaml` path) — so this check
validates precisely what would actually be loaded at runtime, never a
looser or stricter approximation. A **configured** policy path that is
missing or fails to parse as a non-empty YAML mapping is always a required,
blocking failure, regardless of mode. When no path resolves at all, the
outcome depends on the caller's `required` flag: a soft, informational
pass for `check`/`smoke`/`dry-run` (the conservative built-in default that
`load_policy()` already falls back to is a legitimate, safe outcome
outside live mode), and a hard, blocking failure for `run` mode. The
policy file itself is never mutated, regenerated, or substituted by this
check.

---

## 8. Tool-service health validation

`check_tool_service_health(tool_service_url, required_tools=("curl",), timeout_seconds=5.0, client=None)`
issues a bounded, unauthenticated `GET <url>/health`. It validates the URL
shape first (must be `http`/`https` with a network location) before making
any request, checks for HTTP `200`, a JSON object body, `status == "ok"`
and `service == "apex-tool-service"`, and that every tool named in
`required_tools` is present and `true` in the response's `tools` mapping.
The bearer token is never sent to this endpoint — `/health` is
intentionally unauthenticated by design (`docs/kali-tool-service.md` §4).
`client` is injectable (an `httpx.AsyncClient` backed by
`httpx.MockTransport`) purely for testing; production callers leave it
`None` and a real, short-lived client is created and closed internally.
`check`/`dry-run` never call this function at all — only `smoke` and
`run` (when `tool_backend == "remote"`) do.

The minimum required tool set for a generic smoke check is `curl` alone —
sufficient to prove the tool-service pipeline works end-to-end without
assuming any Meow-specific or machine-specific tool requirement. A future
caller that needs a stronger guarantee (e.g. `nmap` availability before a
recon-heavy engagement) can pass a wider `required_tools` sequence
explicitly; nothing in this phase hardcodes that assumption into the
default.

---

## 9. Harmless remote smoke

`check_remote_smoke(config, tool="curl", args=["--version"])` constructs
the real runtime backend via `apex_host.tools.backend.select_runtime_backend(config)`
and executes exactly one command through it — never a scan, never a call
that reaches any host other than the Kali container itself (`curl --version`
makes no network request at all; it only prints the locally-installed
curl's own version string). The client is always closed (`aclose()`, if the
backend exposes one) even when execution fails. A successful result must
have `result.backend != "dry-run"` (proving a real backend was actually
used, not a silent fallback), `result.timed_out is False`,
`result.returncode == 0`, and non-empty stdout or stderr.

`select_runtime_backend()`/`RemoteToolBackend.__init__` fail fast with a
`ValueError` for a configuration problem (a missing bearer token, a
malformed URL) rather than raising once `execute()` is called
(`docs/remote-tool-backend.md` §2.1). `check_remote_smoke` catches that
`ValueError` and turns it into an ordinary failed `PreflightCheck` —
**no request is ever sent** when the backend cannot even be constructed.
This was a real bug found and fixed during this phase (§17).

---

## 10. LLM readiness

`check_llm_readiness(config)` is a trivial, always-passing, non-required
check when `use_llm=False` (the default — no credential, no contact
required at all). When `use_llm=True` with a real provider (not `"fake"`),
it verifies `$OPENAI_API_KEY` is *present* (never its value) and does not
itself make any external model request — that remains a separate, explicit
connectivity concern outside this preflight pass's scope.

---

## 11. Output format and exit codes

Human-readable output resembles:

```
[PASS] configuration
[PASS] report directory
[WARN] compiled knowledge
       not configured (APEX_KNOWLEDGE_ROOT unset) — skipped
[PASS] policy
[PASS] LLM readiness

Preflight passed: 4 required check(s)
```

or, on failure:

```
[FAIL] policy
       file not found: /app/knowledge/policy_db/compiled/hackthebox_lab.yaml

Preflight FAILED: 1 required check(s) failed (policy)
```

`--json` (every mode) instead prints `PreflightResult.to_dict()` as
indented, sorted JSON (`passed`, `required_count`, `failed_required_count`,
`warning_count`, `checks: [...]`) — machine-parseable, same information
content as the text form. Exit code is `0` only when every *required*
check passes; a `WARN` (a non-required, informational check that did not
pass) never blocks success. `check`/`smoke` return `1` on any required
failure; `dry-run`/`run` return `1` on a required preflight failure
(before the engagement is ever dispatched) or propagate the engagement
pipeline's own return code (`0` on success) once dispatched. A malformed
CLI/environment value (e.g. an unparseable `$APEX_MAX_TURNS`) is a
distinct, earlier failure mode — exit code `2`, reported before any
preflight check even runs, mirroring `apex_host.eval.check_config`'s own
convention for a configuration-construction error versus a validation
failure.

---

## 12. Secret redaction

No preflight check function accepts or returns a token/API-key *value* —
only `bool` presence flags, exactly matching `apex_host.eval.check_config`'s
existing redaction discipline. The entrypoint's own configuration summary
(`_print_config_summary`) prints `ApexConfig.to_safe_dict()`'s already-redacted
fields plus two presence-only lines:

```
  tool_service_token: present (never displayed)
  OPENAI_API_KEY: absent (never displayed)
```

`tests/apex_host/test_container_entrypoint.py::TestRedaction` sets a real,
distinctive token value via `$APEX_TOOL_SERVICE_TOKEN` and asserts the
literal string never appears in either stdout or stderr for `check` or
`smoke` mode — the token is only ever reflected as `"present"`/`"absent"`.
No check function, no JSON output, and no log line anywhere in this phase's
new code prints a raw authorization header, a full environment dump, or
sensitive stdin.

---

## 13. Dockerfile behavior

`docker/apex/Dockerfile` now declares:

```dockerfile
ENTRYPOINT ["python", "-m", "apex_host.container_entrypoint"]
CMD ["check", "--knowledge-root", "/app/knowledge"]
```

Both directives use the exec-form JSON array — no shell, so `docker run`/
Compose deliver signals (`SIGTERM`, `SIGINT`) directly to the Python
interpreter rather than to an intermediate `/bin/sh -c` process, and `CMD`'s
arguments are appended to `ENTRYPOINT`'s argv rather than being
shell-interpreted or reinterpolated. The safe default is `check` mode,
scoped to the image's own baked-in compiled knowledge at `/app/knowledge`
— a stricter, more thorough default than Infra Phase 5's bare `--help`: it
actually exercises the image's own configuration, report-directory, and
knowledge/policy paths, not just argparse usage text. `docker run --rm
apex-image` with no arguments therefore runs a real (if entirely local,
network-free) verification pass and exits `0` or `1` accordingly — never a
live engagement. Direct CLI overrides remain fully possible
(`docker run --rm apex-image dry-run --target ...`, or `docker run --rm
apex-image smoke`); the non-root `USER apex` (UID/GID 1000, established in
Infra Phase 5) is unchanged, and no secret is baked into the image at any
layer.

---

## 14. Compose behavior

`compose.yaml`'s `apex` service command changed from Infra Phase 7/8's
`apex_host.eval.compose_smoke` module invocation to:

```yaml
command: ["smoke", "--knowledge-root", "/app/knowledge"]
```

`docker compose up --build` therefore: starts `kali`, waits for its
`condition: service_healthy` (unchanged, image-defined `HEALTHCHECK` from
Infra Phase 6), then starts `apex`, which runs the new entrypoint's `smoke`
mode — validating local configuration, the mounted `./run_reports` report
directory, the image's own baked-in compiled knowledge, the (soft-pass,
since none is configured in the default Compose environment) policy check,
Kali's real `GET /health` over the internal `apex-internal` network, and
one real, harmless `curl --version` through the real `RemoteToolBackend` —
then exits `0`. No target is contacted anywhere in this flow; no secret is
printed (the token is only ever shown as "present"). `kali` has no natural
exit (it is a long-running HTTP server), so `--abort-on-container-exit`
remains the documented, recommended one-shot workflow
(`docker compose up --build --abort-on-container-exit`) — established in
Infra Phase 7 and unchanged here. Bare `docker compose up --build` (without
that flag) is also a valid, documented workflow: it leaves `kali` running
after `apex` exits cleanly, useful for an operator who wants to follow up
with `docker compose run apex dry-run --target ...` against the same,
already-running Kali service without a second Kali startup. Compose's
default `restart: "no"` policy already produces exactly this "Kali stays
up, apex exits once" behavior with zero additional configuration — no
restart-policy hack was needed or added.

---

## 15. `.env.example`

No new variables were required for Infra Phase 9's own operation — every
value the entrypoint reads (`APEX_TOOL_SERVICE_TOKEN`, `APEX_KNOWLEDGE_ROOT`,
`APEX_POLICY_FILE`, `APEX_TOOL_BACKEND`, `APEX_TOOL_SERVICE_URL`, `OPENAI_API_KEY`,
etc.) was already documented by Infra Phase 8. `.env.example` was **not**
modified in this phase: no default target was added, live mode was not
enabled by default, no `APEX_LIVE_CONFIRM` (or any other environment-variable
substitute for `--confirm-live`) was introduced anywhere — that safeguard is
deliberately CLI-only (§3.4), and no VPN-related variable was added.

---

## 16. Troubleshooting / command equivalents

| Prior-phase command | Infra Phase 9 equivalent |
|---|---|
| `docker run --rm apex:phase5 python -m apex_host.main --help` | `docker run --rm apex-image exec -- python -m apex_host.main --help` |
| (same, bypassing the entrypoint entirely) | `docker run --rm --entrypoint python apex-image -m apex_host.main --help` |
| `docker run --rm apex:phase5 python -m apex_host.eval.run_htb_local --help` | `docker run --rm apex-image exec -- python -m apex_host.eval.run_htb_local --help` |
| Full dry-run engagement with report export | `docker run --rm -v "$(pwd)/run_reports:/app/run_reports" apex-image dry-run --target <IP> --export-json /app/run_reports/run.json` |

If `check`/`smoke` fails inside a container, re-run the same command with
`--json` for machine-parseable detail, or `-v`/`--verbose` for `DEBUG`-level
logging. A `[FAIL] compiled knowledge` result means the image's
`/app/knowledge` tree is missing one of the nine required compiled outputs
— rebuild the image (`docker compose build --no-cache`) rather than trying
to patch a running container. A `[FAIL] Kali health` result inside Compose
almost always means `kali`'s own health check has not yet passed — Compose's
`condition: service_healthy` dependency should prevent `apex` from even
starting until it has, so this would indicate the health check itself is
failing; check `docker compose logs kali`.

---

## 17. Bug found and fixed during this phase

`check_remote_smoke`'s first implementation did not catch the `ValueError`
that `select_runtime_backend(config)` raises fail-fast (an established,
documented Infra Phase 4 behavior — `docs/remote-tool-backend.md` §2.1) when
no bearer token is configured. Direct manual testing
(`python -m apex_host.container_entrypoint smoke --tool-backend remote
--tool-service-url http://127.0.0.1:19999 --report-dir ./run_reports` with
no token set) surfaced a full, unhandled Python traceback instead of a
clean, structured failure — a violation of this module's own "ordinary
failure is data, never an unhandled exception" discipline. Fixed by
wrapping the `select_runtime_backend(config)` call in
`try/except ValueError` and returning a normal, actionable
`PreflightCheck(passed=False, ...)` instead. Re-tested and confirmed: clean
output, no traceback, exit code `1`, and — critically — **no HTTP request
is ever sent**, since the backend was never successfully constructed. This
directly satisfies the "missing service token: smoke fails before
execution, never sends a request" runtime-validation requirement (§18,
scenario 5).

---

## 18. Runtime validation performed

All of the following were exercised for real against this repository's
actual code, not merely designed:

1. Host-side `check` mode — real pass and real failure (unwritable report
   directory) paths.
2. Host-side `smoke` mode against a running `apex_tool_service` instance —
   real health check, real `curl --version` execution.
3. Missing compiled knowledge — `--knowledge-root` pointed at an empty
   directory produces a clear, non-zero, actionable `[FAIL] compiled
   knowledge` result.
4. Missing/malformed policy file — both a nonexistent `--policy-file` path
   and a malformed YAML file produce clear, non-zero, actionable failures.
5. Missing service token — `smoke` with `--tool-backend remote` and no
   `$APEX_TOOL_SERVICE_TOKEN` fails before any request is sent (§17).
6. Kali unavailable — `smoke` against an unreachable URL fails with a
   bounded timeout, never hangs.
7. Default `docker compose up --build` — real two-container startup: Kali
   reports healthy, APEX's `smoke` preflight is visible in `docker compose
   logs apex`, the harmless remote smoke succeeds, no target is contacted,
   no secret is printed, and `apex` exits `0` while `kali` remains healthy
   and running afterward (documented post-exit behavior, §14).
8. Container `check` mode run directly via `docker run`.
9. Container `smoke` mode run via Compose (`docker compose run apex smoke ...`).
10. `dry-run` mode with a harmless placeholder target — completes the full
    dry-run engagement pipeline, writes a report, and never issues a
    request to Kali (proven both by direct observation and by a dedicated
    automated test that monkeypatches `check_tool_service_health` to raise
    if called).
11. `run` mode refusal — verified independently for "missing
    `--confirm-live`" and "missing `--no-dry-run`" (even with
    `--confirm-live` present); real live execution against a real target
    was never attempted in this phase (no VPN routing exists yet, §19).
12. Signal behavior — `SIGTERM` delivered to a running
    `_run_with_signal_handling(...)`-wrapped coroutine is cancelled
    cleanly and returns exit code `143`, verified both manually and by an
    automated test (`TestSignalHandling::test_sigterm_cancels_running_coroutine_cleanly`).
13. Cleanup — all temporary containers, networks, `.env` files, and smoke
    artifacts created during manual validation were removed afterward;
    legitimate user reports and any real `.env` file were never touched.

---

## 19. Deferred work (explicitly out of scope for Infra Phase 9)

- **HTB VPN routing** is not configured anywhere in this repository. `run`
  mode's live-execution path has never been exercised against a real
  target and cannot be, until a future Infra Phase adds VPN connectivity.
- **GitHub Actions / CI publishing** was not added.
- **Meow-specific debugging, deterministic exploitation tests, or a live
  HTB engagement** were not performed and remain entirely out of scope —
  consistent with CLAUDE.md §13.8/§13.9's standing prohibition on any
  machine-specific code or behavior anywhere in this repository.
- No git branch was created; no commit or push was made as part of this
  phase's work.

> **Correction (Infra Phase 10, 2026-07-15):** "HTB VPN routing is not
> configured anywhere" is now out of date — a dedicated `vpn` container
> and `htb` Compose profile exist (`docs/htb-vpn-container.md`).
> `run_local_checks`/`run_vpn_checks` in `apex_host/eval/preflight.py`
> (called from every mode of this entrypoint, including `smoke` and
> `run`) now include VPN readiness checks (`check_htb_profile_configured`,
> `check_vpn_readiness`) that fire automatically once
> `config.vpn_service_url`/`config.htb_ovpn_path` are configured — inert
> otherwise, so every claim in §3.1-§3.4 above about the default,
> non-VPN-configured behavior of each mode remains accurate unchanged.
> `run` mode's live-execution path is still unexercised against a real
> HTB target — that remains outstanding, tracked in
> `docs/htb-vpn-manual-validation.md`. GitHub Actions/CI publishing and
> any Meow-specific work remain out of scope, unchanged.

---

## 20. Relationship to `apex_host/eval/check_config.py`

`apex_host.eval.check_config` (Infra Phase 8) remains a separate, standalone
configuration-validation command with its own `main()` entry point,
unchanged in purpose. This phase renamed its internal
`_validate_combinations` helper to the public `validate_combinations` so
that `apex_host/eval/preflight.py::check_configuration` could reuse it
directly rather than duplicating the same required-field-combination
logic — both callers now share exactly one implementation. `check_config.py`
itself is otherwise untouched; it is not the container's `ENTRYPOINT` and
was never intended to be.

---

## 21. Summary of new/changed files

| File | Change |
|---|---|
| `apex_host/eval/preflight.py` | New — reusable, structured preflight checks (8 categories) |
| `apex_host/container_entrypoint.py` | New — the container `ENTRYPOINT`, 5 modes |
| `apex_host/eval/check_config.py` | `_validate_combinations` renamed to public `validate_combinations` |
| `docker/apex/Dockerfile` | `ENTRYPOINT`/`CMD` now point at the new entrypoint, safe `check` default |
| `compose.yaml` | `apex` service default command now `["smoke", "--knowledge-root", "/app/knowledge"]` |
| `tests/apex_host/test_eval_preflight.py` | New — 65 tests covering every preflight check function |
| `tests/apex_host/test_container_entrypoint.py` | New — 28 tests covering every mode, redaction, exec, signals |
| `tests/apex_host/test_phase8_env_architecture.py` | Two new files added to the approved-env-readers allowlist |
| `tests/docker/test_apex_dockerfile.py` | Updated for the new `ENTRYPOINT`/`CMD` contract |
| `tests/docker/test_compose.py` | Updated for the new `smoke`-mode default command |
