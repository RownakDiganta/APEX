# Phase 25 — Final Architecture Integration & Live-Readiness

**Status:** implemented. Phase 25 completes the current Phase 1–25
architecture roadmap: it integrates, validates, and hardens the existing
Phase 18–24 capability-driven user-flag architecture for controlled,
authorized live testing. It does **not** introduce a new architecture
layer — every workstream below either closes a demonstrated gap (a
missing centralized live-run gate, a missing report schema version, a
missing synthetic release-gate runner) or adds a test/documentation pass
over architecture that already existed.

**The one-sentence summary to keep in mind throughout this document:**
completion of Phase 25 makes APEX *"a generic, capability-driven
user-flag retrieval and verification framework for supported,
already-obtained access paths."* It does **not** make APEX *"a universal
generic user-flag capturer for arbitrary machines."* Access alone is not
success. Command execution alone is not success. `user_flag_verified`
remains the only benchmark-success outcome. `dry_run` remains enabled by
default. `memfabric/` was not modified in this phase.

## 1. Concrete gaps found and closed

A full read of `apex_host/eval/preflight.py`, `apex_host/container_entrypoint.py`,
`apex_host/eval/run_htb_local.py`, `apex_host/eval/check_config.py`, and
`apex_host/orchestration/outcome.py` (the required Phase 25 architecture
assessment) found the following real, demonstrated gaps — not
hypothetical ones:

1. **No centralized live-run safety interlock reachable from the primary
   host-side entrypoint.** `apex_host.container_entrypoint` (Docker-only)
   had a full ad-hoc interlock (`check_live_confirmation` + full
   preflight) before dispatching to a live engagement.
   `apex_host.eval.run_htb_local` — the documented, everyday host-side
   entrypoint — had **none of this**: it resolved `dry_run` and went
   straight to `run_engagement()`. **Fixed:** extracted the interlock into
   `apex_host/eval/live_interlock.py`, the ONE centralized implementation
   both entrypoints now call.
2. **`ApexRuntime.aclose()` was never called by `run_htb_local.py`.** The
   Phase 24 runtime-reference invalidation-on-shutdown logic lived inside
   `aclose()`, but the primary entrypoint never invoked it. **Fixed:** the
   post-engagement report-building/export section is now wrapped in
   `try/finally: await runtime.aclose()`.
3. **No `report_schema_version` field on `RunReport`.** **Fixed:** added,
   defaulting to `"1"`, surfaced in both `format_text()` and
   `to_json_dict()`.
4. **No synthetic release-gate runner existed.** **Fixed:**
   `apex_host/eval/release_gate.py`, twelve deterministic scenarios (§5).
5. **`EngagementOutcome.goal_completed` mapped to exit code `0`** despite
   `is_success_outcome(goal_completed)` already correctly returning
   `False` — a leftover from Phase 12C's original definition of success,
   never updated when Phase 18 redefined success to `user_flag_verified`
   only (`validated_access`'s exit code WAS updated at the time; this
   sibling entry was missed). Currently unreachable through
   `GlobalPlanner` (reserved for forward compatibility), so this had no
   live-run impact — but it directly violated the explicit Phase 25
   invariant "no outcome other than `user_flag_verified` maps to exit
   code 0." **Fixed:** corrected to `1`; the one pre-existing test that
   encoded the old value (`test_phase12c_outcomes.py
   ::test_exit_code_table_matches_spec`) was corrected alongside it — see
   `docs/engagement-outcomes.md`'s own Phase 25 correction note.
6. **Two unrelated things are both named "preflight."**
   `apex_host.tools.preflight.check_local_tools` (§12.7, local allowed-tool
   binary availability) and `apex_host.eval.preflight` (Infra Phase 9,
   environment/policy/service readiness) check genuinely different things
   and were **not** merged (merging risked breaking the documented
   `--preflight` CLI flag's existing meaning) — instead, the richer check
   is now reachable via a distinctly-named `--preflight-only` flag on
   `run_htb_local.py`, and the distinction is documented explicitly here
   and in this module's own docstrings.

Everything else audited (loop prevention, redaction, the sole-verifier/
sole-success-outcome invariants, executor statelessness, provider purity,
`CapabilityRuntimeRegistry` as the runtime-availability authority) was
already correct — see §9 "Architecture invariants re-confirmed."

## 2. The centralized live-run safety interlock

`apex_host/eval/live_interlock.py::evaluate_live_interlock()` is the
**one** place "may a real, target-directed engagement start?" is decided.
It requires **five independent, named confirmations**, all `True`:

| Confirmation | What it checks |
|---|---|
| `dry_run_disabled` | `config.dry_run` resolved to `False` through the normal CLI>env>default precedence (`apex_host.config_env.resolve_dry_run`) — never bypassed or duplicated here. |
| `live_confirmed` | An explicit `--confirm-live` CLI flag was passed. **Never satisfiable by an environment variable alone.** |
| `target_supplied` | A real target was configured (not empty, not the config-check placeholder). |
| `target_in_scope` | `config.target` is within `PolicyAdvisor`'s resolved scope (`load_policy(config).allowed_targets`) — the SAME scope every tool execution is already gated against, never a second, invented scope concept. |
| `preflight_passed` | The full preflight (`run_local_checks(policy_required=True)`, plus Kali health/one harmless smoke command when `tool_backend="remote"`, plus VPN readiness when configured) passes with no required-check failures. |

**Fail-fast:** when any of the first four (cheap, purely local)
confirmations already fails, the expensive, network-touching preflight is
skipped entirely — "terminate before target execution" applies to
unnecessary Kali/VPN health calls too, not only to the target itself.

**Shared by both entrypoints:**
`apex_host.container_entrypoint._handle_run` and
`apex_host.eval.run_htb_local`'s live-mode gate both call
`evaluate_live_interlock()` — there is no second, divergent
implementation anywhere.

**Dry-run is completely unaffected.** The interlock is only ever
consulted when `config.dry_run` is `False` — a plain dry-run invocation
(the default) never imports or evaluates it.

## 3. `run_htb_local.py`'s new flags

| Flag | Purpose |
|---|---|
| `--preflight-only` | Runs the full environment/policy/service readiness preflight (§4) and exits — never runs the engagement, never attempts exploitation, never submits a payload, never retrieves a flag. Distinct from the pre-existing `--preflight` (local allowed-tool binary check only — see §1 point 6). |
| `--confirm-live` | Required, in addition to `--no-dry-run`, to run a real, target-directed engagement. Cannot be satisfied by any environment variable. Has no effect when `dry_run` is `True` (the default). |

Example — safe, no-network validation before ever touching a target:

```bash
uv run python -m apex_host.eval.run_htb_local --target <HTB_IP> --preflight-only
```

Example — the full, explicit live-run confirmation:

```bash
uv run python -m apex_host.eval.run_htb_local \
  --target <HTB_IP> --no-dry-run --confirm-live \
  --username <USER> --password <PASS>
```

Omitting `--confirm-live` (or leaving `dry_run` at its default `True`)
always exits non-zero before any engagement code runs.

## 4. Preflight workflow (PASS / WARN / FAIL / SKIP)

`apex_host/eval/preflight.py` (Infra Phase 9, extended by Infra Phase 10
for VPN readiness) is the single, reusable set of structured checks both
`container_entrypoint.py` and `run_htb_local.py --preflight-only` /
`live_interlock.py` compose from. Every check returns a `PreflightCheck`
with `passed: bool` and `required: bool` — `required=False` renders as a
**WARN** when failing, `required=True` renders as **FAIL**. A check
returning an empty list (e.g. `check_vpn_readiness(None)` when no VPN
service is configured) is effectively a **SKIP** — no check ran, no
network call was made.

| Scenario | Result |
|---|---|
| VPN unavailable in a synthetic/non-HTB run (`vpn_service_url` unset) | SKIP (empty check list — see `run_vpn_checks`) |
| VPN unavailable in an HTB live run (`vpn_service_url` configured but unreachable) | FAIL |
| `dry_run=True` for a live-mode invocation | FAIL (`live_confirmed`/`dry_run_disabled` confirmation) unless explicitly running `--preflight-only`/a dry-run |
| Missing authorization (`--confirm-live` not passed) | FAIL |
| Missing `$OPENAI_API_KEY` while `use_llm=True` with a real provider | FAIL |
| Missing `$OPENAI_API_KEY` while `use_llm=False` | SKIP (no credential required at all) |
| No policy file configured, no VPN profile configured | PASS (soft, informational — the conservative built-in default is a legitimate, safe state) |

No preflight check ever makes a destructive or exploitative request — the
only network calls are a bounded, unauthenticated `GET /health` (Kali,
VPN readiness) and one fixed, harmless `curl --version` (never a network
call itself).

## 5. Synthetic release-gate suite

```bash
uv run python -m apex_host.eval.release_gate
```

**This is a test-suite result, not an engagement-success signal.** Its
exit code answers "does the implemented architecture behave correctly
across its supported scenarios?", never "was a real target compromised?".
No scenario contacts a real network, requires Docker/VPN/a real HTB
machine, or performs real exploitation.

Twelve scenarios, each building an in-memory `MemoryAPI` (the same
synthetic-target pattern `apex_host.eval.run_synthetic_machine` already
established) and driving the REAL production classes directly:

1. **SSH user-flag success** — organic SSH evidence → discovery →
   registration → runtime-reference mint/resolve → bounded read →
   authoritative verification → `verified`.
2. **Direct File Read user-flag success** — same chain via a
   `DIRECT_FILE_READ_VALIDATED` evidence item.
3. **Remote bounded-command user-flag success** — same chain via a
   `REMOTE_COMMAND_VALIDATED` evidence item.
4. **No-capability failure** — reconnaissance-only fixture, no capability
   ever exists, objective never reaches `verified`.
5. **Candidate-not-verified failure** — a read succeeds but the content
   fails `verify_user_flag`; the raw (non-flag-shaped) candidate is
   confirmed absent from persisted state.
6. **Runtime-reference expiry** — capability metadata persists, but the
   adapter was unregistered; the resolver correctly refuses to activate.
7. **Authorization revoked** — the reference is explicitly revoked and
   the adapter removed; resolution fails.
8. **Policy denial** — an off-scope task is rejected by `PolicyAdvisor`
   with no bypass.
9. **Dry-run** — the executor returns a synthetic, unverified result; no
   `RuntimeReference` is ever minted.
10. **Repair-path capability activation** — a repaired, typed SSH result
    emits capability evidence identically to a normally-dispatched one
    (Phase 24's shared result-processing helper).
11. **Duplicate evidence** — a replayed `evidence_id` is classified
    `duplicate`; exactly one capability node exists; no confidence
    inflation.
12. **Restart/replay** — capability metadata is restored from the
    persisted EKG, but a fresh (simulated post-restart) runtime
    registry/reference store has no adapter; replay alone cannot reach
    `verified`.

The one deliberate synthetic substitution across all twelve: the
lowest-level *transport* (a real SSH/Paramiko session, a real HTTP
request, a real subprocess) is replaced with a bounded, in-memory
`_FakeFlagReadCapability` — exactly the pluggable extension point
`apex_host/runtime_registry.py` documents for "a future adapter." Real
transport correctness for each family is already covered by that
family's own dedicated test suite (`test_ssh_executor.py`,
`test_phase20_direct_file_read_capability.py`,
`test_phase21_bounded_command_capability.py`); this release gate proves
the INTEGRATION around those transports.

## 6. Runtime cleanup

`ApexRuntime.aclose()` (Phase 24, wired into `run_htb_local.py` in this
phase — see §1 point 2):

- Invalidates every live `RuntimeReference` (`reason="shutdown"`).
- Idempotent — a second call is a harmless no-op.
- Safe before `run()` has ever been called (`_capability_registry`/
  `_runtime_reference_store` are `None` until the first `run()`).
- Cancels any background asyncio tasks that were started but not
  awaited.

`container_entrypoint.py`'s async modes forward `SIGTERM` into a clean
task cancellation (`_run_with_signal_handling`) rather than leaving the
interpreter's default disposition to kill it mid-await.

## 7. Report schema

`RunReport.report_schema_version` (default `"1"`) is now present in both
`format_text()` (the report header line) and `to_json_dict()` (the first
key). Increment it whenever a field is added, removed, or its meaning
changes in a backward-incompatible way — the same convention
`ApexConfig.config_schema_version` already established. Confirmed absent
from the report at all times: API keys, passwords, private keys, bearer
tokens, cookies, raw tool stdout/stderr, raw HTTP bodies, raw flag
candidates, the verified raw flag, full runtime-reference IDs, and any
runtime object representation.

## 8. Outcome semantics (unchanged model, one corrected value)

`EngagementOutcome.user_flag_verified` remains the **only** outcome for
which `is_success_outcome()` returns `True` and `exit_code_for()` returns
`0` — see §1 point 5 for the one exit-code inconsistency found and fixed
this phase. Access alone (`validated_access`), command execution alone,
credential discovery alone, admin-portal access alone, an HTTP-status
success alone, an LLM's own claim, and flag-shaped output without the
authoritative verifier are all explicitly non-success — enforced by
`verify_user_flag()` being the sole verifier call site inside
`UserFlagExecutor` (statically checked — see the Phase 25 test suite's
`TestArchitectureInvariants`).

## 9. Architecture invariants re-confirmed (already correct, not changed)

- `memfabric/` contains no cybersecurity-specific logic and no import of
  `apex_host` (checked; zero occurrences).
- All persistent graph/memory writes go through `MemoryAPI` — no
  provider, no capability discovery code, writes a raw `Node`/`Edge`
  outside `CapabilityParser.derive_*` (one narrow, documented exception:
  the `runtime_available`-only write-back — see §1's audit and the test
  suite's own check for it).
- `CapabilityProvider` implementations remain pure — no `MemoryAPI` call,
  no registry mutation, no network/tool/LLM call (statically scanned).
- Executors (`SSHExecutor`, `FTPExecutor`, `UserFlagExecutor`) hold no
  mutable session/socket/client state on `self`.
- `ObjectivePlanner`/`UserFlagExecutor`/`ObjectiveParser` remain fully
  transport-independent — no branching on capability type, no import of
  a transport module (paramiko/httpx/ftplib).
- `RuntimeReferenceStore` is never serialized — never a field on
  `ApexGraphState`, never touched by the LangGraph checkpointer.
- `dry_run` defaults `True` on `ApexConfig` — no code path sets a
  `False` default.
- Loop prevention already existed and remains bounded: `GlobalPlanner`
  turn/phase budgets, `StallTracker`'s four streak detectors (duplicate,
  policy-block, no-action, stagnant-fingerprint), `RepairEngine
  .max_repair_attempts`, `ObjectivePlanner`'s pair-scoped exhaustion, and
  `objective_reopening_eligible()`'s requirement of a genuinely new,
  never-attempted `capability_id` (so reopening itself cannot loop).

## 10. Capability support matrix

| Capability / function | Implemented | Organic evidence producer | Operator seed supported | Runtime adapter supported | Synthetic test coverage | Controlled live support | Known limitations |
|---|---|---|---|---|---|---|---|
| Reconnaissance (nmap/curl/ffuf/gobuster) | Yes | N/A | N/A | N/A | Yes | Yes | No autonomous exploitation of findings |
| SSH authentication validation | Yes | Yes (`SSHExecutor`) | Yes | Yes | Yes | Yes | One credential pair per protocol per engagement; password auth only |
| SSH bounded file read | Yes | Yes | Yes | Yes | Yes | Yes | Fixed candidate-path allowlist only |
| Direct File Read | Yes (metadata + adapter) | No | Yes | Yes | Yes | Yes (operator-attested request shape) | No autonomous DFR *discovery* — operator must supply the confirmed request shape |
| Local bounded command read | Yes (metadata + adapter) | No | Yes | Yes | Yes | Yes (operator-attested strategy) | No autonomous discovery of the primitive |
| Remote bounded command read | Yes (metadata + adapter) | No | Yes | Yes | Yes | Yes (operator-attested strategy) | Requires the remote backend's own allowlist to include the fixed read command |
| Web command | Metadata + adapter model exists | No | Yes | Shared with DFR adapter | Partial (provider logic only) | No | `WebCommandCapabilityProvider` always reports `runtime_unavailable` without an operator-supplied request shape — no mechanism activates it from evidence alone |
| User-flag candidate extraction | Yes | N/A | N/A | N/A | Yes | Yes | Fixed candidate filename/path allowlist |
| User-flag verification | Yes | N/A | N/A | N/A | Yes | Yes | One authoritative verifier (`verify_user_flag`) — no alternate path |
| Capability derivation (structured evidence pipeline) | Yes | Yes (SSH only) | Yes (all 5 families) | N/A | Yes | Yes | Only SSH has a live, organic (non-operator-attested) evidence producer |
| Runtime reference activation | Yes | N/A | N/A | Yes | Yes | Yes | No multi-authorization-scope deployment support (reserved, unreachable) |
| Objective reopening | Yes | N/A | N/A | N/A | Yes | Yes | Requires a genuinely new `capability_id` — cannot reopen on the same one |
| Replay / restart | Yes (correctly refuses to reactivate) | N/A | N/A | N/A | Yes | Yes | Runtime state never survives a restart, by design |
| SQL injection discovery | **Not implemented** | No | No | No | No | No | Out of scope — no vulnerability-discovery mechanism of any kind exists |
| NoSQL injection discovery | **Not implemented** | No | No | No | No | No | Out of scope |
| XSS discovery | **Not implemented** | No | No | No | No | No | Out of scope |
| Application-logic exploitation | **Not implemented** | No | No | No | No | No | Out of scope |
| API abuse discovery | **Not implemented** | No | No | No | No | No | Out of scope |
| Privilege escalation (beyond planning) | Planning/enumeration only (Phase 13/13B) | N/A | N/A | N/A | Yes | Read-only enumeration only | No privilege-escalation *execution* exists — enumeration and opportunity modeling only |
| Root-flag objective | **Not implemented** | No | No | No | No | No | Only `objective_type="user_flag"` exists; no `root_flag` objective type |

**Legend, applied honestly per this phase's own explicit instruction:**
"model exists" (a dataclass/enum member exists) is distinct from
"metadata derivation exists" (a `CapabilityParser.derive_*` method
produces a real EKG node) is distinct from "runtime adapter exists" (a
`FlagReadCapability` implementation can actually be registered) is
distinct from "organic discovery exists" (a live executor produces the
evidence without operator attestation) is distinct from "end-to-end live
support exists" (the full chain has been exercised, synthetically, start
to finish). No row in this table claims a stronger level than what was
actually verified.

## 11. Known limitations (unsupported vulnerability classes)

APEX has **no vulnerability-discovery or exploitation mechanism of any
kind** for: SQL injection, NoSQL injection, XSS, CSRF exploitation,
application-logic abuse, API abuse, deserialization vulnerabilities,
authentication bypass discovery, or privilege escalation *execution*
(only read-only enumeration and opportunity modeling exist — see Phase
13/13B). It cannot be assumed to solve an arbitrary HTB Easy/Medium
machine. Vulnerability-family support must be assessed separately, per
target, by a human operator — APEX's role begins once an access path
(SSH, a direct file read, a bounded command channel) has *already* been
established by the operator or by APEX's own narrow, already-implemented
credential-validation mechanisms.

## 12. Restart/replay behavior

Covered exhaustively by release-gate scenario 12 and the Phase 25 test
suite's `TestReplay` class: capability *metadata* (the EKG's own
`access_capability` nodes) is durable and correctly restored on replay
(memfabric's own persistence guarantees). Runtime *material* (an SSH
password held in memory, a registered adapter, a minted
`RuntimeReference`) is **never** durable — a restarted process always
begins with an empty `CapabilityRuntimeRegistry` and an empty
`RuntimeReferenceStore`. Replay alone — reprocessing the same persisted
evidence with no new organic result — can, at most, re-derive the exact
same capability metadata (an idempotent no-op); it can never reactivate
a runtime adapter or reach `user_flag_verified` on its own.

## 13. Dry-run behavior

`dry_run=True` is `ApexConfig`'s default and remains so. Verified,
end-to-end, three independent times across Phases 18B/20/24/25: no
`RuntimeReference` is ever minted, `UserFlagExecutor` returns a synthetic
unverified result before ever resolving an adapter, and the live
interlock is never even consulted (dry-run mode never imports
`live_interlock`).

## 14. Authorization requirements

A live, target-directed engagement requires **all** of: `dry_run=False`
(via `--no-dry-run`, never a stale environment variable alone),
`--confirm-live` (CLI-only, no environment equivalent), a real target
in `PolicyAdvisor`'s resolved scope, and a passing preflight (policy file
valid, knowledge compiled if configured, LLM credential present if
enabled, Kali/VPN reachable if configured) — see §2.

## 15. Secret handling

No API key, password, private key, bearer token, or cookie is ever
printed, logged, or persisted — `ApexConfig.to_safe_dict()` redacts every
secret-shaped field; `apex_host/security/redaction.py` redacts session
text, dict values, and user-flag candidate output; `RuntimeReference
.to_dict()`/`__repr__()` expose only an 8-character digest of the opaque
reference ID, never the full value.

## 16. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Docker unavailable | `docker compose ps` fails to connect — start Docker Desktop; retry `docker compose config` first (no daemon required) to validate the compose file itself. |
| Kali unhealthy | `docker compose logs kali` — check the container's own `HEALTHCHECK`; confirm `APEX_TOOL_SERVICE_TOKEN` matches between `apex` and `kali` services. |
| VPN not ready | `check_vpn_readiness` reports `tunnel not yet ready` — the `.ovpn` profile may be invalid, or the tunnel needs more time; re-run `--preflight-only` after a short wait. |
| No HTB route | VPN readiness reports a `route_cidr` mismatch — check `APEX_HTB_ROUTE_CIDR` matches what the HTB VPN profile actually routes. |
| Target outside scope | `PolicyAdvisor` blocks with `rule=target_in_scope` — confirm `--target`/`$APEX_TARGET` exactly matches the machine you intend to test; scope is always exactly one target. |
| Tool service unauthorized | `check_tool_service_health`/`check_remote_smoke` fail — confirm `$APEX_TOOL_SERVICE_TOKEN` is set and matches the Kali container's own configured token. |
| LLM key missing | `check_llm_readiness` fails — set `$OPENAI_API_KEY`, or leave `--use-llm` unset (the default; deterministic planners run with no LLM). |
| No viable capability | `no_capability_failure`-shaped run — reconnaissance found no exploitable access path; this is a correct, honest negative result, not a bug — see §11. |
| Capability metadata exists but runtime unavailable | The capability was derived but no adapter is currently registered (e.g. after a connection failure or a fresh process) — the next objective turn attempts re-registration automatically; if credentials/request-shape configuration is missing, it will remain `runtime_unavailable`. |
| Runtime reference expired | `RuntimeReferenceResolver` reports `expired`/`revoked` — this is correct rejection of stale state, not an error; the next turn mints a fresh reference at a new generation once re-registered. |
| Verifier rejected candidate | `verify_user_flag()` returned `verified=False` — the read succeeded but the content did not match the expected flag format; confirm `user_flag_verification_regex`/candidate paths are configured correctly for the target. |
| Max turns reached | `max_turns_exhausted` — increase `--max-turns`, or investigate why the phase ladder did not progress (check `policy_decisions`/`duplicate_actions` in the exported report). |

## 17. Live-testing readiness statement

Phase 25 completes the current architecture roadmap. APEX is ready for
controlled, authorized live testing **of the access paths it actually
supports** (SSH credential validation, direct file read, bounded local/
remote command reads, all gated by the live-run safety interlock and
policy scope). It is **not** a universal vulnerability-discovery and
exploitation system, and completing Phase 25 does not change that. Every
real, authorized live run must go through: `--preflight-only` first,
then a `--dry-run` rehearsal, then an explicit `--no-dry-run
--confirm-live` invocation — never a direct jump to live mode.
