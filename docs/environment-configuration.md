# Environment Configuration

**Status:** Infra Phase 8 — implemented and validated end-to-end (unit
tests, `docker compose config`, a real `docker compose up` smoke run).
**Date:** 2026-07-15
**Files:** [`.env.example`](../.env.example),
[`apex_host/config_env.py`](../apex_host/config_env.py),
[`apex_host/eval/check_config.py`](../apex_host/eval/check_config.py),
[`compose.yaml`](../compose.yaml) (updated),
[`.gitignore`](../.gitignore) / [`.dockerignore`](../.dockerignore) (updated)

This document describes the environment-variable configuration workflow
built in Infra Phase 8. It extends
[`docs/docker-compose.md`](docker-compose.md) (Infra Phase 7) and
[`docs/remote-tool-backend.md`](remote-tool-backend.md) (Infra Phase 4);
read those first for the underlying `ToolBackend`/Compose architecture this
phase adds a configuration layer on top of.

---

## 1. Purpose

Before this phase, every `APEX_*`/`OPENAI_*` environment variable used
anywhere in this repository was read ad hoc, by whichever module happened
to need it (`RemoteToolBackend.__init__`, `OpenAIModelRouter.__init__`,
`compose_smoke.py`'s own CLI defaults), with no single place documenting
what was actually supported, no `.env.example` template, and no way for a
CLI flag to reliably win over an environment variable (several flags used
concrete, non-`None` `argparse` defaults, which silently masked whatever
the environment might have supplied).

This phase adds:

1. **`.env.example`** — one template file documenting every supported
   variable, its real default, and whether it is a secret.
2. **`apex_host/config_env.py`** — the single, explicit, opt-in place
   `apex_host` reads `APEX_*` application-level environment variables,
   with strict parsing, clear validation errors, and a binding CLI >
   environment > default precedence rule.
3. **`apex_host/eval/check_config.py`** — a safe, network-free-by-default
   command that parses configuration, validates it, and prints a redacted
   summary.
4. Updated `.gitignore`/`.dockerignore` rules, and updated `compose.yaml`
   interpolation, so the whole workflow is consistent end to end.

---

## 2. `.env.example` workflow

```bash
cp .env.example .env
# edit .env: at minimum, generate and set APEX_TOOL_SERVICE_TOKEN
python -c "import secrets; print(secrets.token_urlsafe(32))"

APEX_TOOL_SERVICE_TOKEN=<paste-the-generated-value> \
  docker compose up --build --abort-on-container-exit
```

Docker Compose automatically reads a `.env` file in the same directory as
`compose.yaml` — no extra flag is needed for the command above; the token
shown inline is only there because `compose.yaml`'s fail-fast
interpolation (§9) requires it to be present in *some* form (a real `.env`
file with the line uncommented and filled in works identically to passing
it inline on the command line).

---

## 3. `.env.example` vs `.env`

| | `.env.example` | `.env` |
|---|---|---|
| Committed to Git? | **Yes** — always | **Never** — gitignored (§17) |
| Contains secrets? | **No** — every secret field is blank | Yes, once you fill it in |
| Contains a target? | **No** — `APEX_TARGET=` is always blank | Optional — you may set one |
| Copied into a Docker image? | Never (neither Dockerfile `COPY`s it) | Never — dockerignored (§17) |
| Purpose | Documentation + starting template | Your real, local, disposable configuration |

`.env.example`'s own values are either genuinely safe defaults (matching
what the code already does when the variable is absent) or intentionally
blank placeholders that make the *shape* of a complete configuration
visible without supplying anything usable.

---

## 4. Which values are secrets

| Variable | Why it's a secret |
|---|---|
| `APEX_TOOL_SERVICE_TOKEN` | Bearer token for `apex_tool_service` — grants tool-execution access |
| `OPENAI_API_KEY` | Billable API credential |

Both are **blank** in `.env.example`, both are validated as "present" vs.
"absent" only (never echoed) by `apex_host.eval.check_config` (§15), and
both are redacted by `ApexConfig.to_safe_dict()` when they flow through
`ApexConfig` at all (only `tool_service_token` does — `OPENAI_API_KEY` is
never read into `ApexConfig` in the first place, see §11).

Every other variable in `.env.example` is non-secret operational
configuration (timeouts, size limits, backend selection, log level, ...).

---

## 5. Which values are safe defaults

Every variable that is **not** blank in `.env.example` documents a value
that reproduces the code's own existing, unchanged behavior when the
variable is absent entirely — copying `.env.example` to `.env` without
editing anything except the required token changes nothing about runtime
behavior. Examples: `APEX_DRY_RUN=true` (the hardcoded safe default),
`APEX_LLM_PROVIDER=fake` (the hardcoded safe default — never an external
provider), `APEX_TOOL_SERVICE_PORT=8080` (the real
`apex_tool_service.settings.ServiceSettings` default).

---

## 6. Configuration precedence

**Binding rule, implemented and tested throughout
`apex_host/config_env.py`:**

```text
explicit CLI argument  >  environment value  >  built-in safe default
```

Mechanically: every CLI flag this rule applies to is declared with
`argparse`'s `default=None`. `apex_host.config_env.merge_env_into_args()`
fills in any attribute that is still `None` after parsing from the
matching environment variable (validating it strictly as it does), then
leaves untouched attributes for `ApexConfig.from_cli_args()`'s own
pre-existing `None`-means-"use the hardcoded default" logic to resolve.
**A CLI flag that was actually passed is never overwritten by an
environment variable — a `None` argparse default is what makes "not
passed" distinguishable from "explicitly passed a falsy/zero value."**

Two fields have their own, stricter, dedicated resolution rules layered on
top of the generic one:

### `dry_run` — an asymmetric safety rule

`APEX_DRY_RUN` can only ever *reinforce* the already-safe default; it can
never, by itself, enable real command execution:

```text
--dry-run / --no-dry-run passed explicitly  →  that value wins, always
neither passed, APEX_DRY_RUN=true (or unset) →  True (the safe default)
neither passed, APEX_DRY_RUN=false           →  ERROR — see §18
```

This is CLAUDE.md §13.5's own invariant ("real execution must always
require an explicit CLI flag") extended one layer further: an environment
variable is not a CLI flag, so it cannot satisfy that requirement either.
Loading a `.env` file that happens to contain `APEX_DRY_RUN=false` can
never, by itself, start a live engagement (this phase's own philosophy
rule 10) — the operator must still pass `--no-dry-run` explicitly.

### `target` — "at least one of two, blank counts as absent"

```text
--target passed explicitly           →  that value wins, always
--target absent, APEX_TARGET set     →  APEX_TARGET's value
--target absent, APEX_TARGET blank   →  same as absent — see below
both absent                          →  ERROR (except check_config, §15)
```

No default target is ever provided anywhere in this codebase — see §12.

---

## 7. Direct host CLI usage

```bash
# Option 1: real, exported environment variables (predictable, explicit)
export APEX_TARGET=10.10.10.14
export APEX_DRY_RUN=true
uv run python -m apex_host.eval.run_htb_local

# Option 2: explicit, opt-in dotenv-file loading (never automatic)
cp .env.example .env   # then edit .env
uv run python -m apex_host.eval.run_htb_local --env-file .env --target 10.10.10.14
```

**`--env-file PATH` is never loaded implicitly.** No entry point scans the
current working directory for a `.env` file on its own — you must pass
`--env-file` explicitly (`apex_host.main`, `apex_host.eval.run_htb_local`,
and `apex_host.eval.check_config` all support it identically). This was a
deliberate design choice (§16): Docker Compose already has its own,
separate, built-in `.env` reading for the containerized workflow; the host
CLI path needed its own explicit, predictable mechanism, not an implicit
one that could surprise a user running the same command from a different
directory.

`--env-file`-sourced values are combined with real, already-exported
environment variables as `{**file_values, **os.environ}` — an actually
exported shell variable always wins over the same name found in the file,
matching common `dotenv` tooling convention.

---

## 8. Docker Compose usage

```bash
cp .env.example .env
# edit .env: set APEX_TOOL_SERVICE_TOKEN
docker compose up --build --abort-on-container-exit
```

Compose reads `.env` **automatically** — this is Compose's own built-in
behavior, entirely independent of Python and `apex_host/config_env.py`.
Every variable interpolated in `compose.yaml` (§9) now has a
`${VAR:-default}` or `${VAR:?...}` form whose default matches either
`apex_tool_service`'s own real `ServiceSettings` default or this
project's own pre-existing Infra Phase 7 default — filling in `.env`
without editing `compose.yaml` changes nothing unless you actually
uncomment and edit a line.

---

## 9. Tool backend variables

| Variable | Consumed by | Notes |
|---|---|---|
| `APEX_TOOL_BACKEND` | `apex_host/config_env.py` (generic CLI/env merge); `apex_host/eval/compose_smoke.py` (its own default) | `dry-run`\|`local`\|`remote`; normalized case-insensitively |
| `APEX_TOOL_SERVICE_URL` | Same as above | Validated as a well-formed `http`/`https` URL at parse time |
| `APEX_TOOL_SERVICE_TOKEN` | `apex_host.tools.remote_backend.RemoteToolBackend.__init__` directly (unchanged, Infra Phase 4) | **Not** read by `config_env.py` — see §11 for why |
| `APEX_TOOL_SERVICE_TIMEOUT_SECONDS` | `apex_host/config_env.py` | Maps to `ApexConfig.tool_service_timeout_seconds`; real default 120.0 |

`compose.yaml`'s `apex` service sets `APEX_TOOL_BACKEND=${APEX_TOOL_BACKEND:-remote}`
and `APEX_TOOL_SERVICE_URL=${APEX_TOOL_SERVICE_URL:-http://kali:8080}` —
both overridable via `.env`, both defaulting to exactly what Infra Phase 7
already hardcoded.

**Important — `apex_host/config.py` never reads environment variables**
(unchanged architecture invariant, §14). Only `apex_host/config_env.py`
(the generic CLI/env merge, used by `apex_host.main` and
`apex_host.eval.run_htb_local`) and `apex_host/eval/compose_smoke.py` (its
own narrow CLI-flag defaults) read `APEX_TOOL_BACKEND`/
`APEX_TOOL_SERVICE_URL` directly. A future engagement wired into Compose
via `run_htb_local` would need `--tool-backend remote --tool-service-url
http://kali:8080` CLI flags (or `--env-file`) — the Compose environment
variables alone do not automatically reach `apex_host.main`/
`run_htb_local` without going through `config_env.py`'s merge, since those
two entry points build `ApexConfig` via `ApexConfig.from_cli_args()`, not
by reading Compose's injected process environment as if it were
`ApexConfig` fields directly.

---

## 10. Tool-service variables

Read directly by `apex_tool_service/settings.py::ServiceSettings.from_env()`
— entirely independent of everything in §6–§9 (a completely separate
process/container). Unchanged by this phase; documented here (and wired
into `compose.yaml`'s `kali` service, §9) for the first time as part of
the unified `.env.example` template:

| Variable | Real default |
|---|---|
| `APEX_TOOL_SERVICE_HOST` | `127.0.0.1` (never `0.0.0.0` by the library's own default — `docker/kali/Dockerfile` bakes in `0.0.0.0`, now also overridable via Compose) |
| `APEX_TOOL_SERVICE_PORT` | `8080` |
| `APEX_TOOL_SERVICE_DEFAULT_TIMEOUT_SECONDS` | `30` |
| `APEX_TOOL_SERVICE_MAX_TIMEOUT_SECONDS` | `120` |
| `APEX_TOOL_SERVICE_MAX_ARGUMENTS` | `32` |
| `APEX_TOOL_SERVICE_MAX_ARGUMENT_LENGTH` | `512` |
| `APEX_TOOL_SERVICE_MAX_STDIN_BYTES` | `65536` |
| `APEX_TOOL_SERVICE_MAX_STDOUT_BYTES` | `1048576` |
| `APEX_TOOL_SERVICE_MAX_STDERR_BYTES` | `1048576` |

(`APEX_TOOL_SERVICE_MIN_TIMEOUT_SECONDS` and
`APEX_TOOL_SERVICE_MAX_TOTAL_ARGUMENT_BYTES` also exist as real
`ServiceSettings` fields but are not wired into `compose.yaml`'s
interpolation — export them directly, or add a mapping entry yourself, if
you need to override them.)

**These values, as documented above, are the real defaults verified from
`apex_tool_service/settings.py`'s own source — not the illustrative
numbers this phase's own task brief happened to suggest**, per that
brief's own instruction ("Use the actual defaults and names implemented in
`ServiceSettings`. Do not invent values.").

---

## 11. LLM variables

| Variable | Consumed by |
|---|---|
| `APEX_USE_LLM` | `apex_host/config_env.py` → `ApexConfig.use_llm` |
| `APEX_LLM_PROVIDER` | `apex_host/config_env.py` → `ApexConfig.llm_provider` (normalized lowercase) |
| `APEX_LLM_MODEL` | `apex_host/config_env.py` → `ApexConfig.planner_model`/`.executor_model`/`.parser_model` |
| `OPENAI_API_KEY` | `apex_host.llm.router.OpenAIModelRouter.__init__` directly (pre-existing, unchanged) |
| `OPENAI_BASE_URL` | Same as above |

**`OPENAI_API_KEY`/`OPENAI_BASE_URL` are deliberately not read by
`config_env.py`.** They are not `ApexConfig` fields at all —
`OpenAIModelRouter` reads them directly, at the point a real LLM call is
about to be made, exactly as it did before this phase. Duplicating that
read in `config_env.py` would create a second source of truth for the same
value with no benefit.

`.env.example`'s defaults (`APEX_USE_LLM=false`, `APEX_LLM_PROVIDER=fake`)
match `ApexConfig`'s own hardcoded safe defaults exactly — per this
phase's own instruction, an external provider is never the template's
default.

---

## 12. Target handling

**No default target exists anywhere in this codebase, and none was added
by this phase.** `APEX_TARGET=` in `.env.example` is always blank.

| Entry point | Target requirement |
|---|---|
| `apex_host.main` | Required — `--target` or `APEX_TARGET` (blank counts as absent); at least one must resolve, or the command fails with a clear error |
| `apex_host.eval.run_htb_local` | Same rule as above |
| `apex_host.eval.check_config` | **Not required** — falls back to the synthetic placeholder `"config-check"` (`apex_host.config_env.CONFIG_CHECK_TARGET_PLACEHOLDER`) when neither is supplied; this command validates configuration *shape*, not a real engagement |
| `apex_host.eval.compose_smoke` | Not applicable — uses its own fixed placeholder (`"compose-smoke-test"`), unrelated to a real target, since it only ever calls a `ToolBackend` directly |

See §6 for the exact precedence/blank-handling rule.

---

## 13. Knowledge/policy paths

| Variable | Maps to | CLI flag |
|---|---|---|
| `APEX_KNOWLEDGE_ROOT` | `ApexConfig.knowledge_root` | `--knowledge-root` |
| `APEX_POLICY_FILE` | `ApexConfig.policy_file` | `--policy-file` |

Both are optional everywhere — `None` (unset) means the corresponding
knowledge family or policy discovery path is skipped gracefully (unchanged
pre-existing behavior, `apex_host/knowledge/seed_loader.py` /
`apex_host/policy/policy_loader.py`). The APEX container image already
bakes in compiled knowledge at `/app/knowledge` (`docs/apex-container.md`
§9), so `APEX_KNOWLEDGE_ROOT` typically only needs setting if you mount a
different knowledge directory yourself.

---

## 14. Report paths

| Variable | Maps to | Entry point |
|---|---|---|
| `APEX_REPORT_PATH` | `--export-json` | `apex_host.eval.run_htb_local` only |
| `APEX_GRAPH_PATH` | `--export-graph` | `apex_host.eval.run_htb_local` only |

**`apex_host.main` has no report-export flags at all** (pre-existing,
unrelated to this phase) — these two variables have no effect there;
`apex_host/config_env.py::merge_env_into_args()`'s `hasattr()` guard
silently skips them for a namespace that lacks `export_json`/
`export_graph` attributes, rather than erroring.

Neither variable is a secret; neither has a default in `.env.example` —
no report is written unless one of these (or the matching CLI flag) is
set, exactly matching the pre-existing opt-in behavior of
`--export-json`/`--export-graph` themselves.

---

## 15. Config validation command

```bash
uv run python -m apex_host.eval.check_config
uv run python -m apex_host.eval.check_config --tool-backend remote --tool-service-url http://kali:8080 --no-dry-run
uv run python -m apex_host.eval.check_config --check-connectivity --tool-backend remote --tool-service-url http://kali:8080 --no-dry-run
```

Works identically on the host and inside the `apex` container (it has no
container-specific behavior — verified this phase via `docker compose run
--rm apex python -m apex_host.eval.check_config`).

- Parses CLI flags merged with environment variables (§6).
- Validates required combinations (§18).
- Prints a redacted summary — every field via `ApexConfig.to_safe_dict()`
  plus `tool_service_token`/`OPENAI_API_KEY` presence (`"present"`/
  `"absent"` only, **never** the value itself).
- **No target is required** (§12) — a config-only check has no real
  engagement to prepare.
- **No network call by default.** The optional `--check-connectivity`
  flag is the *only* way to make this command touch the network, and even
  then it issues nothing but an unauthenticated `GET /health` against the
  configured tool-service URL — never `POST /v1/execute`, never a tool
  invocation.
- Exits `0` for valid configuration, `1` for invalid (or a connectivity
  check that failed), `2` for a malformed CLI invocation (argparse's own
  usage-error convention) or a malformed environment value.

---

## 16. Secret redaction

Three independent layers, all verified this phase:

1. **`ApexConfig.to_safe_dict()`** (pre-existing, unchanged) — redacts
   `tool_service_token` and `password_candidates` whenever non-empty.
2. **`apex_host.eval.check_config`'s summary printer** — never prints
   `tool_service_token`/`OPENAI_API_KEY` values at all, only a
   `"present"`/`"absent"` boolean derived from
   `os.environ.get(...)`/`config.tool_service_token`.
3. **`apex_host.config_env.load_env_file()`** — uses `dotenv_values()`
   (never `load_dotenv()`), so a `--env-file`-sourced secret is never
   written into the real process environment as a side effect; it flows
   only through the explicit `env=` mapping parameter every function in
   this module accepts.

`tests/apex_host/test_phase8_env_architecture.py` enforces (1) via a
repository-wide scan asserting every `str`/`list[str]` `ApexConfig` field
whose name contains "token" or "password" is referenced inside
`to_safe_dict()`'s own source.

---

## 17. Git and Docker ignore behavior

### `.gitignore`

```gitignore
.env
.env.local
.env.*.local
secrets/
*.ovpn
```

**Exact-name matches, never a broad `.env*` glob** — `.env.example` is
never accidentally caught (verified:
`git check-ignore -q .env.example` exits `1`, meaning "not ignored";
`git check-ignore -q .env` exits `0`, meaning "ignored").

### `.dockerignore`

```dockerignore
.env
.env.local
.env.*.local
.env.*
!.env.example
*.ovpn
secrets/
```

Here, `.env.*` genuinely **is** a glob (Docker's ignore-file syntax has no
exact-name-vs-glob distinction the way Git's bare `.env` entry
incidentally provides) — it would match `.env.example` too, so the
explicit `!.env.example` negation immediately below it is required and
present, restoring `.env.example` to the build context. Neither
`docker/apex/Dockerfile` nor `docker/kali/Dockerfile` actually `COPY`s
`.env.example` into an image today (both use fully explicit, selective
`COPY` instructions — see each Dockerfile's own comments), so this
negation is not currently load-bearing for image *contents*, but it keeps
the build *context* itself from silently excluding a file a future test,
doc build, or Dockerfile change might reasonably expect to find — exactly
this phase's own explicit requirement.

Verified this phase: neither image contains a `.env` file after a real
`docker compose build` (`docker run --rm <image> sh -c "ls -la /app |
grep env"` found nothing — see §11 of `docs/apex-container.md` /
`docs/kali-container.md` for the pre-existing, broader "no secrets in the
image" verification this phase's runtime validation re-confirmed).

---

## 18. Common validation errors

All produced by `apex_host.config_env`/`apex_host.eval.check_config`,
every message names the offending variable and never echoes a secret
value:

| Error | Cause | Fix |
|---|---|---|
| `no target provided: pass --target explicitly or set APEX_TARGET` | Neither given (or `APEX_TARGET` was blank) on an entry point that requires one | Pass `--target <IP>` or `export APEX_TARGET=<IP>` |
| `APEX_DRY_RUN=false was set but --no-dry-run was not passed...` | `.env`/environment says go live, but no CLI flag confirmed it | Pass `--no-dry-run` explicitly (never rely on the environment alone) |
| `APEX_MAX_TURNS: invalid integer value '...'` | Non-numeric value | Use a plain integer |
| `APEX_TOOL_SERVICE_TIMEOUT_SECONDS: value ... is below the minimum allowed (0.0)` | Negative timeout | Use `0` or a positive number |
| `APEX_TOOL_BACKEND: invalid tool backend '...'` | Typo | One of `dry-run`, `local`, `remote` |
| `APEX_TOOL_SERVICE_URL: URL must use http or https, got scheme ''` | Malformed URL (missing scheme) | `http://host:port` or `https://host:port` |
| `tool_backend='remote' requires --tool-service-url or $APEX_TOOL_SERVICE_URL` | Remote backend selected, no URL configured, and not in dry-run | Set the URL, or leave `--dry-run` in effect |
| `tool_backend='remote' requires a bearer token via $APEX_TOOL_SERVICE_TOKEN` | Same, but the token is missing | `export APEX_TOOL_SERVICE_TOKEN=...` |
| `use_llm=True with llm_provider='openai' requires $OPENAI_API_KEY to be set` | LLM enabled with a real provider, no key | `export OPENAI_API_KEY=sk-...`, or leave `llm_provider=fake` |
| `--env-file '...' does not exist or is not a file` | Typo'd `--env-file` path | Check the path |

---

## 19. Current lack of VPN integration

**Not implemented in this phase, deliberately.** `.env.example` contains
only a commented-out, inert note about a future `APEX_HTB_OVPN_PATH`-style
variable — no such variable is read by any code, and `compose.yaml`
references nothing VPN-related at all
(`tests/docker/test_env_files.py::test_compose_yaml_does_not_reference_vpn_variable`
enforces this). Nothing in the Compose environment (§8,
`docs/docker-compose.md` §17) can reach an authorized HTB target as of
this phase.

---

## 20. Current lack of automatic live engagement

**Loading `.env` — by any mechanism (`cp .env.example .env` +
`docker compose up`, or `--env-file` on the host) — can never, by itself,
start a live engagement.** This is enforced structurally, not just by
convention:

- `dry_run` defaults to `True` everywhere, and `APEX_DRY_RUN=false` alone
  is rejected with a clear error rather than silently taking effect (§6,
  §18) — real execution always requires the explicit `--no-dry-run` CLI
  flag, exactly as CLAUDE.md §13.5 has always required.
- `compose.yaml`'s default `apex` command
  (`apex_host.eval.compose_smoke`, no flags) is dry-run by construction
  and never contacts `kali` for real — `docker compose up` alone never
  performs a live engagement, verified live in Infra Phase 7's own
  runtime validation and unaffected by this phase.
- No entry point in this repository (`apex_host.main`,
  `apex_host.eval.run_htb_local`, `apex_host.eval.check_config`,
  `apex_host.eval.compose_smoke`) has a default target — every one of
  them requires an explicit `--target`/`APEX_TARGET` (or, for
  `check_config`, uses a synthetic, clearly-non-real placeholder) before
  any engagement-shaped work could even begin.
