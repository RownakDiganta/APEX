# First Controlled Live HTB Test — Operator Runbook (Phase 25)

This is the exact, ordered procedure for the **first** controlled, authorized
HTB live test on macOS with Docker Desktop. It assumes no prior local setup.
Every step is either read-only or explicitly, individually confirmed before
anything live-directed happens — see
[`docs/phase25-release-readiness.md`](phase25-release-readiness.md) for the
architecture this runbook exercises.

**Authorization reminder (non-negotiable, unchanged since CLAUDE.md §12.3):**
only run a live (`--no-dry-run`) step against a machine you are explicitly
authorized to test — an HTB machine reached over the official HTB VPN, or
another explicitly authorized lab environment. Never against a machine you do
not own or have written permission to test.

## 1. Repository checkout

```bash
git clone <your-fork-or-clone-url> apex
cd apex
```

## 2. Confirm `uv` is available

```bash
uv --version   # expect uv >= the version pinned in this repo's own tooling
uv sync --all-groups
```

## 3. Confirm Docker Desktop is running

```bash
docker info >/dev/null && echo "Docker is running"
```

If this fails, start Docker Desktop and wait for it to report "running" in
its own UI before continuing.

## 4. Place your HTB OpenVPN file

Copy your authorized HTB `.ovpn` profile somewhere **outside** the git
working tree (never commit it):

```bash
mkdir -p ~/apex-secrets
cp ~/Downloads/your-htb-lab-profile.ovpn ~/apex-secrets/htb.ovpn
chmod 600 ~/apex-secrets/htb.ovpn
```

## 5. Create your `.env`

```bash
cp .env.example .env
```

`.env` is already `.gitignore`d (verified — `git check-ignore -q .env` exits
0). Edit it to set, at minimum:

```
APEX_HTB_OVPN_PATH=/Users/you/apex-secrets/htb.ovpn
```

Leave `APEX_DRY_RUN` unset/`true` and `APEX_TARGET` blank for now — you will
supply the target explicitly, per invocation, later in this runbook.

## 6. Export your API key securely (only if you plan to enable LLM planning)

The **default, recommended path is to skip this entirely** — `APEX_USE_LLM=false`
(the `.env.example` default) means fully deterministic, rule-based planning
with zero API calls and zero cost. Only continue this step if you
specifically want LLM-assisted planning.

```bash
export OPENAI_API_KEY="sk-..."
```

**Shell-history consideration:** prefix the command with a leading space (many
shells configured with `HISTCONTROL=ignorespace`/`HIST_IGNORE_SPACE` will then
not record it in `~/.bash_history`/`~/.zsh_history`), or set it via your
terminal's own "run a command without saving to history" mechanism, or store
it in a password manager and paste it fresh each session rather than
`export`-ing it in a script. Never put a real key directly into `.env` if
`.env` might ever be accidentally committed, backed up, or synced somewhere —
the codebase's own convention is a real, exported shell environment variable,
not a committed file value.

**Provider distinction (native providers — see `docs/llm-providers.md` §24
and CLAUDE.md §24):** each provider is its own identity with its own
credential and its own model-naming rules. There is no shared fallback and
no silent rewriting — the configured model string is sent to the provider
byte-for-byte.

| Path | `APEX_LLM_PROVIDER` | Env var for the key | `APEX_LLM_MODEL` (model-name shape) |
|---|---|---|---|
| OpenAI direct API | `openai` | `OPENAI_API_KEY` | a **native** OpenAI model id — **no `vendor/` prefix**, e.g. `gpt-5.5` (illustrative — use a model your OpenAI account can access) |
| Anthropic direct API | `anthropic` | `ANTHROPIC_API_KEY` | a **native** Anthropic model id — no `vendor/` prefix, e.g. `claude-...` (use a model your account can access) |
| OpenRouter (aggregator) | `openrouter` | `OPENROUTER_API_KEY` | a **router-style** `vendor/model` id, e.g. `openai/gpt-4o` |
| Deterministic (no LLM) | `fake` (the default) | none required | unused |

Native model names for `openai`/`anthropic` **never contain a `/`**. Passing a
router-style `vendor/model` id (e.g. `openai/gpt-5.5`) to `--llm-provider openai`
or `anthropic` is rejected up front with a `provider_model_mismatch` error that
tells you to select `--llm-provider openrouter` instead — APEX will **not**
silently strip the prefix or reroute the request. Likewise, do **not** point
`provider=openai`/`anthropic` at an OpenRouter base URL; use `provider=openrouter`
for OpenRouter.

Do not set `APEX_LLM_MODEL` to a name your provider account cannot access —
`apex_host.llm.providers.*` passes the string straight through to the configured
API, so an unsupported model name fails at the provider, not in APEX itself.
APEX never hardcodes or assumes a specific model is available.

## 7. Generate the tool-service token

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Paste the output into `.env` as `APEX_TOOL_SERVICE_TOKEN=...`. This same
value must be used by both the `apex` and `kali` Compose services — the
provided `compose.yaml` already interpolates one `${APEX_TOOL_SERVICE_TOKEN:?...}`
value into both, so setting it once in `.env` is sufficient.

## 8. Build the Docker images

```bash
docker compose config   # validates the rendered compose file — no daemon call beyond parsing
docker compose build
```

## 9. Run the synthetic smoke test (no target, no VPN, no network beyond localhost)

```bash
docker compose up --build --abort-on-container-exit
```

Expect `apex` to run its default `smoke` mode (Kali health + one harmless
`curl --version`), exit `0`, and `kali` to remain healthy. No target was
contacted.

## 10. Run the release-gate test

```bash
uv run python -m apex_host.eval.release_gate
```

Expect `RELEASE GATE PASSED: 12 scenario(s).` and exit code `0`. This is a
test-suite result, not an engagement-success signal (see
`docs/phase25-release-readiness.md` §5) — it proves the architecture behaves
correctly, not that any target has been compromised.

## 11. HTB VPN preflight

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb up -d vpn
```

Wait for the `vpn` service's own healthcheck to report healthy
(`docker compose ps`), then check tunnel/route readiness. The VPN readiness
server (port `8090`) is **not** published to the host — run the check from
inside the `apex` container over the Compose network, where it is reachable
at `http://vpn:8090`. `--vpn-service-url` is **required** on every invocation
(there is no default):

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  run --rm --entrypoint python apex \
  -m apex_host.eval.vpn_route_check \
  --vpn-service-url http://vpn:8090 --target "$HTB_TARGET"
```

**Route lookup vs. a real connection.** By default this command performs a
*route-table lookup only* — it asks the VPN container whether traffic to the
target *would* use the tunnel route (`would use route: True`, `device: tun0`,
`gateway: ...`). It sends **no packet to the target**, so a successful route
lookup alone does **not** prove the target is up or reachable. To also attempt
exactly one bounded TCP connection, add `--port` with a port you expect open
on that machine:

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  run --rm --entrypoint python apex \
  -m apex_host.eval.vpn_route_check \
  --vpn-service-url http://vpn:8090 --target "$HTB_TARGET" --port 80
```

The `--port` outcome distinguishes: `connected` (TCP succeeded), `refused`
(host up, port closed), `timeout` (silent — likely filtered or host down),
and `unreachable` (`EHOSTUNREACH`/`ENETUNREACH` — no route to host). A failed
*individual* port does not by itself mean the VPN is broken: the machine may
simply not have that port open. Only treat a persistent `unreachable`/`timeout`
across multiple ports (with a good route lookup) as a VPN- or target-side
problem — see `docs/htb-vpn-manual-validation.md` for the full troubleshooting
table.

## 12. Export your target IP

```bash
export APEX_TARGET=<HTB_TARGET_IP>
```

## 13. Route check (already covered in step 11 — repeat after any VPN reconnect)

Re-run the `vpn_route_check` command above whenever the tunnel is
re-established, before trusting that a route exists.

## 14. Preflight-only run (no exploitation, no target contact beyond the checks themselves)

```bash
uv run python -m apex_host.eval.run_htb_local \
  --target "$APEX_TARGET" --preflight-only
```

Expect a PASS/WARN/FAIL table (§4 of `docs/phase25-release-readiness.md`)
and exit code `0` if everything required passes. In dry-run (the default here)
this is a purely local check — no target contact, no real command execution,
and the report directory it validates is the documented default
(`/app/run_reports` in the container, `./run_reports` on the host), never the
working directory.

A **live** preflight that also exercises the real remote-tool path (one harmless
`curl --version` through the Kali service) requires `--no-dry-run --confirm-live`
— it is routed through the same live-run interlock as a real engagement, so
`--tool-backend remote` alone never turns off dry-run. The canonical Docker
form of that live preflight is documented in `README.md`
("Authorized HTB run — canonical Docker workflow").

## 15. Dry-run target run

```bash
uv run python -m apex_host.eval.run_htb_local \
  --target "$APEX_TARGET" --dry-run --export-json ./run_reports/dry_run.json
```

This exercises the full phase ladder, planning, and reporting pipeline with
**zero** real network traffic to the target and **zero** runtime-reference
activation (verified — see the Phase 25 test suite's `TestDryRunGuarantees`).

## 16. Explicit live-mode enablement

Live mode requires **both** flags, every time, with no environment-variable
shortcut for either:

```bash
uv run python -m apex_host.eval.run_htb_local \
  --target "$APEX_TARGET" --no-dry-run --confirm-live \
  --username <AUTHORIZED_USERNAME> --password <AUTHORIZED_PASSWORD>
```

Before any target action occurs, the centralized live-run safety interlock
(`docs/phase25-release-readiness.md` §2) evaluates all five confirmations
and prints its own PASS/FAIL table. Any failure blocks the run before a
single packet reaches the target.

## 17. Controlled live run

The command in step 16 *is* the controlled live run — there is no separate
invocation. Watch the console output for phase transitions, findings, and
(if reached) the `user_flag_verified` outcome.

## 18. Report inspection

```bash
cat ./run_reports/dry_run.json | python -m json.tool | less
```

Confirm `report_schema_version`, `outcome`, and the absence of any secret or
raw flag value in the exported JSON.

## 19. Logs inspection

```bash
docker compose logs kali
docker compose logs vpn
```

Look for `execution_accepted`/`execution_complete` audit lines (Kali) and
tunnel-status lines (VPN) — neither service ever logs your bearer token or
any command's raw output beyond what's already documented as safe to log.

## 20. Runtime cleanup

`ApexRuntime.aclose()` is called automatically at the end of every
`run_htb_local.py` invocation now (Phase 25 fix — previously omitted). To
tear down the Compose environment:

```bash
docker compose --profile htb down --remove-orphans
```

## 21. Reset to dry-run

Nothing to "reset" in `.env` itself if you followed step 5/6 correctly
(`APEX_DRY_RUN` was left at its safe default throughout) — the only
per-invocation live-mode trigger is the explicit `--no-dry-run --confirm-live`
pair on the command line, which never persists between invocations. If you
did export `APEX_DRY_RUN=false` in your shell for a session, unset it:

```bash
unset APEX_DRY_RUN
```
