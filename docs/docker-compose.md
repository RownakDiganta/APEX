# Docker Compose Integration

**Status:** Infra Phase 7 — implemented, built, and validated end-to-end
against a real Docker Compose environment (`docker compose v2.34.0-desktop.1`),
including a real `apex_host.tools.remote_backend.RemoteToolBackend` call
from the `apex` container to the `kali` container over Compose's internal
network.
**Date:** 2026-07-15
**Files:** [`compose.yaml`](../compose.yaml),
[`apex_host/eval/compose_smoke.py`](../apex_host/eval/compose_smoke.py),
[`tests/docker/test_compose.py`](../tests/docker/test_compose.py)

This document describes the Docker Compose environment built in Infra
Phase 7. Every claim below refers to configuration and code that exists in
this repository today, and was independently verified by an actual
`docker compose build`/`up`/`run` session recorded during this phase — not
merely designed.

---

## 1. Purpose

`compose.yaml` wires the two container images built in prior phases —
the APEX application (`docker/apex/Dockerfile`, Infra Phase 5) and the
Kali tool-service appliance (`docker/kali/Dockerfile`, Infra Phase 6) —
into a runnable two-service environment on a dedicated, non-host-published
internal network:

```text
apex container  --internal authenticated HTTP-->  kali container
(orchestration/planning/policy/memory)  apex-internal  (restricted tool execution)
```

This closes the "still missing" gap both prior phases' documentation
explicitly called out: `RemoteToolBackend` had only ever been exercised
in-process or against a locally-started process on the same machine
(`docs/remote-tool-backend.md` §8; `docs/kali-tool-service.md` §14). It has
now been exercised for real, container-to-container, over Docker's own
network stack.

---

## 2. Service topology

| Service | Built from | Role | Reachable from host? |
|---|---|---|---|
| `kali` | `docker/kali/Dockerfile` | Restricted, allowlisted HTTP tool-execution appliance (Infra Phase 6, unmodified) | **No** — internal only (§16) |
| `apex` | `docker/apex/Dockerfile` | Orchestration/planning/policy/memory application (Infra Phase 5, unmodified) | N/A — no server, exits after its command |

Both services join a single dedicated network, `apex-internal`
(`networks.apex-internal` in `compose.yaml`). No fixed IP addresses are
assigned to either service — both are reached exclusively through
Compose's built-in service-name DNS (§6). No third "helper" service exists;
`docker compose config`'s parsed service list is exactly `{apex, kali}`.

Neither `docker/apex/Dockerfile` nor `docker/kali/Dockerfile` was modified
in this phase — both images are used exactly as built in their respective
prior phases. All new behavior lives in `compose.yaml` and the new
`apex_host/eval/compose_smoke.py` module.

---

## 3. Safe default behavior

```bash
APEX_TOOL_SERVICE_TOKEN=replace-with-a-disposable-test-token \
  docker compose up --build --abort-on-container-exit
```

**Verified live, this phase:**

```text
kali-1  | INFO:     Uvicorn running on http://0.0.0.0:8080 (Press CTRL+C to quit)
kali-1  | INFO:     127.0.0.1:47490 - "GET /health HTTP/1.1" 200 OK
apex-1  | compose_smoke: dry_run=True tool_backend='remote' tool_service_url='http://kali:8080' tool='curl' args=['--version']
apex-1  | compose_smoke: backend_used='dry-run' returncode=0 timed_out=False dry_run=True error=None elapsed_seconds=0.000
apex-1  | compose_smoke: OK
apex-1 exited with code 0
Aborting on container exit...
 Container newapex-apex-1  Stopping
 Container newapex-kali-1  Stopping
```

What this proves, in order:

1. `kali` builds and starts; its baked-in `HEALTHCHECK` (Infra Phase 6,
   unchanged) passes.
2. `apex`'s `depends_on: kali: condition: service_healthy` correctly waits
   — `apex`'s command does not start until `kali` is healthy.
3. `apex`'s default command (`apex_host.eval.compose_smoke`, no flags) runs
   a **dry-run** connectivity check — `backend_used='dry-run'`,
   `dry_run=True` — and exits `0` without ever contacting `kali`.
4. No target is contacted anywhere in this sequence (dry-run has zero
   network I/O; `kali` never receives a `POST /v1/execute` at all here —
   only the `GET /health` calls its own `HEALTHCHECK` makes).
5. No secret (the token, or any other value) appears in either container's
   logs.

**Why the default command is dry-run, not a real check:** CLAUDE.md §13.5
is explicit and unconditional — `ApexConfig.dry_run` defaults to `True`
everywhere in this codebase, and "real execution... must always require an
explicit CLI flag on every invocation," never an implicit default. This
phase's own task brief separately requires "Starting Compose must remain
safe and must not automatically run a live engagement." Both are satisfied
simultaneously by making the *default* `apex` command dry-run (§10 below
documents the separate, explicit-flag-gated real check) — this is the
one design that cannot violate either constraint.

**Chosen workflow — `--abort-on-container-exit`:** `apex`'s default command
completes in well under a second, while `kali` is a long-running HTTP
server with no natural exit. Without `--abort-on-container-exit`,
`docker compose up` would leave `kali` running indefinitely after `apex`
finishes, requiring a separate manual `docker compose down`. This flag
makes the default invocation a single, deterministic, self-cleaning
command — the one workflow this phase's task brief asked to be chosen
explicitly, documented here, and used consistently (this document uses it
throughout; `docker compose up -d` remains available for anyone who wants
`kali` to keep running, e.g. to issue further `docker compose run apex ...`
commands manually — see §12).

---

## 4. Token requirement

Both services require `APEX_TOOL_SERVICE_TOKEN` via Compose's fail-fast
interpolation syntax:

```yaml
environment:
  APEX_TOOL_SERVICE_TOKEN: ${APEX_TOOL_SERVICE_TOKEN:?APEX_TOOL_SERVICE_TOKEN must be set — see docs/docker-compose.md}
```

**Verified live, this phase:**

```text
$ docker compose config
error while interpolating services.kali.environment.APEX_TOOL_SERVICE_TOKEN:
  required variable APEX_TOOL_SERVICE_TOKEN is missing a value:
  APEX_TOOL_SERVICE_TOKEN must be set — see docs/docker-compose.md
$ echo $?
1
```

`docker compose config`/`build`/`up`/`run` **all** refuse to proceed when
the variable is unset or empty — this is Compose's own `:?` interpolation
operator, not custom scripting. No reusable default token is baked into
`compose.yaml`, either Dockerfile, or any committed file — grepping the
built images' `docker history --no-trunc` output for the disposable test
token used during this phase's validation (`phase7-test-token`, itself
never a real credential) found zero matches, confirming it never entered
either image's layer history (it was supplied only as a `docker compose`
environment variable at run time, never baked into a build).

**No `.env.example` was created in this phase** (explicitly deferred — see
§20). An operator must export `APEX_TOOL_SERVICE_TOKEN` (or prefix every
command with it, as every example in this document does) before running
any `docker compose` command against this file.

---

## 5. Internal networking

A single dedicated network, `apex-internal`:

```yaml
networks:
  apex-internal:
    name: apex-internal
```

Both services join it (`networks: [apex-internal]` on each service). No
`ports:` mapping exists for `kali` (only `expose: ["8080"]`, which is
documentation-only — Compose already makes a service's ports reachable to
other services on the same network without it). No `ports:` mapping exists
for `apex` either (it is not a server). No fixed IP addresses
(`ipam`/`ipv4_address`) are configured anywhere — both services rely
entirely on Compose's built-in DNS (§6). No `network_mode: host` and no
`network_mode: service:*` anywhere in this file.

**Docker-internal communication is complete. HTB target reachability is
NOT** — see §17.

---

## 6. Service discovery

**Verified live, this phase:**

```text
$ docker compose run --rm apex python -c "import socket; print(socket.gethostbyname('kali'))"
172.19.0.2
```

`kali` resolves via Compose's built-in DNS to the container's actual
address on `apex-internal` — no `/etc/hosts` entry, no manual network
configuration, no fixed IP assignment anywhere in `compose.yaml`.

**Important nuance — environment variables vs. CLI flags:**
`apex_host/config.py` itself never reads environment variables (enforced
by `test_arch_08_config_py_has_no_env_access` — an architecture invariant
this phase did not touch). The three environment variables set on the
`apex` service —

```yaml
environment:
  APEX_TOOL_BACKEND: remote
  APEX_TOOL_SERVICE_URL: http://kali:8080
  APEX_TOOL_SERVICE_TOKEN: ${APEX_TOOL_SERVICE_TOKEN:?...}
```

— are consumed in two different, both pre-existing, ways:

- `APEX_TOOL_SERVICE_TOKEN` is read directly by
  `RemoteToolBackend.__init__` itself as a fallback when
  `config.tool_service_token` is empty (`docs/remote-tool-backend.md` §3.2
  — unchanged, pre-existing Infra Phase 4 behavior).
- `APEX_TOOL_BACKEND` and `APEX_TOOL_SERVICE_URL` have **no** corresponding
  environment-variable read anywhere in `apex_host` before this phase —
  they are normally set only via the `--tool-backend`/`--tool-service-url`
  CLI flags (`ApexConfig.from_cli_args()`). This phase's new
  `apex_host/eval/compose_smoke.py` reads both directly via
  `os.environ.get(...)` (a new module, not `config.py`, so the
  architecture invariant above is unaffected) as its own CLI-flag
  *defaults* — `--tool-backend`/`--tool-service-url` flags on
  `compose_smoke.py` still take precedence if passed explicitly.

**A future full multi-turn engagement** (`apex_host.eval.run_htb_local`, not
run by this phase's default Compose command — see §22) would need the
equivalent `--tool-backend remote --tool-service-url http://kali:8080` CLI
flags passed explicitly on its own command line, since that entry point's
`ApexConfig` is built via CLI arguments, not these Compose environment
variables directly. This is documented here so a future phase wiring
`run_htb_local` into Compose does not assume the environment variables
alone are sufficient.

---

## 7. Kali health dependency

```yaml
apex:
  depends_on:
    kali:
      condition: service_healthy
```

No `healthcheck:` block is duplicated in `compose.yaml` for `kali` — the
image's own baked-in `HEALTHCHECK` (`docker/kali/Dockerfile`, Infra
Phase 6, unmodified: `curl -fsS http://127.0.0.1:8080/health`, no bearer
token required, no tool invoked) is what Compose observes for the
`service_healthy` condition. Docker's health-status tracking works
identically regardless of whether the `HEALTHCHECK` was declared in the
Dockerfile or in `compose.yaml` — duplicating it here would only risk the
two definitions drifting apart over time.

**Verified live, this phase:** `docker compose ps` after startup shows
`Up ... (healthy)`; `docker compose up --abort-on-container-exit`'s log
ordering (§3) shows `apex`'s command only begins after `kali`'s `/health`
endpoint has already been hit successfully by Docker's own health-check
poller.

---

## 8. Report persistence

```yaml
apex:
  volumes:
    - ./run_reports:/app/run_reports
```

A plain bind mount (not a named volume) — an operator can inspect
`./run_reports/*.json` directly from the host with no `docker cp` step.
`/app/run_reports` is already created and `chown`ed to the image's
non-root `apex` user (UID 1000) at build time (`docker/apex/Dockerfile`,
Infra Phase 5, unmodified).

**macOS bind-mount / non-root UID finding (evaluated this phase, as
required):** writing from inside the container as UID 1000 and reading the
result from the host (a different, arbitrary macOS user UID) worked with
**no permission errors and no extra configuration** — Docker Desktop for
macOS's bind-mount implementation (gRPC-FUSE/VirtioFS) does not enforce
Linux-style UID/GID matching between the container's UID and the host
filesystem's owning user the way a native Linux bind mount would; files
written by container UID 1000 simply appear as normal, host-readable files
owned by the invoking host user. This was verified empirically, not
assumed:

```text
$ docker compose run --rm apex python -m apex_host.eval.compose_smoke \
    --no-dry-run --report-path /app/run_reports/compose_smoke.json
compose_smoke: report written to /app/run_reports/compose_smoke.json
compose_smoke: OK

$ ls -la run_reports/compose_smoke.json
-rw-r--r--  1 <host-user>  staff  436 ... compose_smoke.json
$ cat run_reports/compose_smoke.json
{
  "backend_used": "kali-service",
  "dry_run": false,
  ...
  "note": "Synthetic infrastructure connectivity check — not a real engagement report.",
  "ok": true,
  "smoke_test": true,
  "smoke_test_module": "apex_host.eval.compose_smoke",
  ...
}
```

The artifact persisted on the host filesystem after the container exited
and was removed after validation, per this phase's own instruction not to
leave test artifacts that could be confused with real results
(`compose_smoke.json` — a filename and content shape distinct from any
real engagement report, and clearly marked `"smoke_test": true`) — no
pre-existing legitimate report under `run_reports/` was touched.

**`kali` cannot access reports** — it has no `volumes:` entry at all
(`tests/docker/test_compose.py::test_kali_has_no_volumes_at_all`).

---

## 9. Compiled knowledge availability

Compiled knowledge is available **exactly once**: baked into the `apex`
image itself at `/app/knowledge` (`docker/apex/Dockerfile`, Infra Phase 5,
unmodified — see `docs/apex-container.md` §9 for the full compiled-vs-raw
rationale and the `Knowledge/` vs `knowledge/` casing investigation).
`compose.yaml` deliberately does **not** additionally bind-mount
`./Knowledge` or `./knowledge` over that path — doing so would create a
second, differently-cased, potentially-inconsistent copy, which this
phase's task brief explicitly warned against
(`tests/docker/test_compose.py::test_no_duplicate_knowledge_volume_mount`
enforces this statically).

---

## 10. Build command

```bash
APEX_TOOL_SERVICE_TOKEN=phase7-test-token \
  docker compose build --no-cache
```

**Verified live, this phase:** both images built successfully
(`newapex-apex:latest`, 688 MB; `newapex-kali:latest`, 813 MB — sizes
match their respective prior-phase standalone builds exactly, confirming
Compose's build did not change either image's contents). One transient
network timeout occurred during the first attempt (a `langgraph` wheel
download failed after 4 retries over 126 s — an external PyPI network
condition, not a build or Compose defect); a plain retry of the identical
command succeeded without any file changes.

---

## 11. Default startup command

```bash
APEX_TOOL_SERVICE_TOKEN=replace-with-a-disposable-test-token \
  docker compose up --build --abort-on-container-exit
```

See §3 for the full verified transcript and rationale. `docker compose ps`
while `kali` is running shows:

```text
NAME             IMAGE          COMMAND                  SERVICE   STATUS
newapex-kali-1   newapex-kali   "python /app/entrypo…"   kali      Up 8 seconds (healthy)
```

with a `PORTS` column of `8080/tcp` — no `0.0.0.0:xxxx->8080/tcp` host
mapping (§16 covers this in full detail).

---

## 12. Connectivity smoke test

Two distinct, deliberately separate modes, both using the same
`apex_host.eval.compose_smoke` module (chosen over two divergent
implementations specifically to avoid drift — see the module's own
docstring):

### Default mode (dry-run, no network contact)

```bash
docker compose up --abort-on-container-exit
# or, with kali already running (docker compose up -d kali):
docker compose run --rm apex python -m apex_host.eval.compose_smoke
```

### Remote smoke mode (real contact — requires the explicit flag)

```bash
docker compose run --rm apex python -m apex_host.eval.compose_smoke --no-dry-run
```

**Verified live, this phase:**

```text
$ docker compose run --rm apex python -m apex_host.eval.compose_smoke --no-dry-run
compose_smoke: dry_run=False tool_backend='remote' tool_service_url='http://kali:8080' tool='curl' args=['--version']
compose_smoke: backend_used='kali-service' returncode=0 timed_out=False dry_run=False error=None elapsed_seconds=0.128
compose_smoke: OK
```

This is the completion-criterion #9 proof: **real APEX-to-Kali remote
execution succeeds through Compose.** `backend_used='kali-service'` (the
real value `apex_tool_service` itself reports — see the note in
`docs/kali-container.md` §13.9 about the pre-existing, unrelated
`docs/kali-tool-service.md` §5 documentation/code discrepancy on this
exact field, unchanged by this phase), `returncode=0`,
`elapsed_seconds=0.128` (a real HTTP round trip, not instantaneous like
the dry-run path).

`compose_smoke.py` deliberately calls
`apex_host.tools.backend.select_runtime_backend()` directly rather than
routing through the full `TaskDispatcher`/`PolicyAdvisor` engagement
pipeline (`apex_host/execution/dispatcher.py`) — assembling the
`TaskSpec`/`SubgraphView`/`EvidenceBundle`/`MemoryAPI` scaffolding that
pipeline requires would be disproportionate for an infrastructure
connectivity check with no target and no engagement context. **This is
explicitly an infrastructure connectivity smoke test, not an engagement
execution path** — stated in the module's own docstring, and enforced by
the fact it never constructs a `TaskSpec` or touches `MemoryAPI` at all.

---

## 13. Dry-run isolation test

**Verified live, this phase**, with the `kali` service actually running
(so a real network attempt, if one were made, would have every
opportunity to succeed) and a deliberately invalid, unreachable URL
substituted:

```text
$ docker compose run --rm -e APEX_TOOL_SERVICE_URL=http://invalid-unreachable-host.test:9999 \
    apex python -m apex_host.eval.compose_smoke --dry-run
compose_smoke: dry_run=True tool_backend='remote' tool_service_url='http://invalid-unreachable-host.test:9999' tool='curl' args=['--version']
compose_smoke: backend_used='dry-run' returncode=0 timed_out=False dry_run=True error=None elapsed_seconds=0.000
compose_smoke: OK
```

`elapsed_seconds=0.000` is the proof: a real attempt to contact
`invalid-unreachable-host.test` would have to at minimum attempt DNS
resolution (which would fail, but not instantly — typically hundreds of
milliseconds to seconds depending on resolver timeout behavior). Zero
elapsed time confirms `RemoteToolBackend.execute()`'s own internal
`dry_run` check (`docs/remote-tool-backend.md` §4, layer 2) fired and
delegated to `DryRunToolBackend` before any socket was ever opened — this
was independently re-confirmed outside the container too (`uv run python
-m apex_host.eval.compose_smoke --dry-run --tool-service-url
http://invalid-unreachable-host.test:9999` on the host, 0.115 s total
wall time including Python interpreter startup).

---

## 14. Non-root behavior

**Verified live, this phase:**

```text
$ docker compose run --rm apex id
uid=1000(apex) gid=1000(apex) groups=1000(apex)

$ docker compose run --rm kali id
uid=1000(apextool) gid=1000(apextool) groups=1000(apextool)
```

Neither image's `USER` directive is overridden anywhere in `compose.yaml`
(no `user:` key on either service) — both containers run as the exact
same non-root accounts established in their respective prior phases
(`docs/apex-container.md` §5, `docs/kali-container.md` §5).

---

## 15. Security restrictions

Every restriction below was verified against the **live, running**
containers this phase (`docker inspect`), not just the static
`compose.yaml` text:

```text
$ docker inspect newapex-kali-1 --format \
  'Privileged={{.HostConfig.Privileged}} NetworkMode={{.HostConfig.NetworkMode}} CapAdd={{.HostConfig.CapAdd}} CapDrop={{.HostConfig.CapDrop}} User={{.Config.User}}'
Privileged=false NetworkMode=apex-internal CapAdd=[] CapDrop=[] User=apextool

$ docker inspect newapex-kali-1 --format '{{json .Mounts}}'
[]
```

- **No `privileged: true`** anywhere — confirmed both statically
  (`compose.yaml`) and live (`HostConfig.Privileged=false`).
- **No added Linux capabilities** — `CapAdd=[]`. In particular, **no
  `NET_ADMIN`, no `NET_RAW`** — this phase's task brief explicitly forbids
  adding `NET_RAW` "merely to make default Nmap SYN scans work"; the
  Infra Phase 6 finding that `nmap`'s default/SYN-scan mode does not work
  unprivileged (only `nmap -sT` and `ping` do — `docs/kali-container.md`
  §5) is therefore **still true inside this Compose environment**, and
  was deliberately not "fixed" here. A future Compose phase would need to
  add `cap_add: [NET_RAW, NET_ADMIN]` explicitly if unprivileged default
  scans are ever required — not attempted in this phase.
- **No host networking** — `NetworkMode=apex-internal`, not `host`.
- **No Docker socket** — `docker.sock` does not appear anywhere in
  `compose.yaml`, either Dockerfile, or `docker inspect`'s `Mounts` output
  for either container.
- **No host filesystem secrets** — `kali`'s `Mounts` is `[]` (nothing
  mounted at all); `apex`'s only mount is the report-output bind (§8),
  which contains no secret material either before or after a run.
- **No token in image history** — `docker history --no-trunc` for both
  `newapex-apex` and `newapex-kali` was grepped for the disposable test
  token used this phase (`phase7-test-token`) and found zero matches.
- **No token printed in logs** — both containers' `docker logs` output
  was grepped for the same token across the full validation session
  (health checks, the default dry-run smoke check, the real `--no-dry-run`
  check, the dry-run-isolation check, and the report-persistence check)
  and found zero matches.

---

## 16. Why Kali is not host-published

`kali`'s service definition has no `ports:` key — only `expose: ["8080"]`,
which is Compose-internal-only and never binds a host port. Verified two
ways this phase:

```text
$ docker compose port kali 8080
:0
$ curl -s -m 3 http://127.0.0.1:8080/health; echo $?
7
$ docker port newapex-kali-1
(empty)
```

`docker compose port` reports an unbound (`:0`) mapping, a direct `curl`
from the host to `127.0.0.1:8080` fails with curl's own "could not
connect" exit code (`7`), and `docker port` (the lower-level Docker CLI,
independent of Compose) confirms no port mapping exists for the container
at all. `kali` is reachable **only** from `apex` (or any other future
service joined to `apex-internal`), never from the host machine or the
wider network — this is the entire point of not publishing it: even a
fully compromised `apex` process is contained to talking to `kali`'s own
restricted, allowlisted, authenticated API (`apex_tool_service`'s own
boundary, `docs/kali-tool-service.md` §2) — it cannot expose that surface
to the host network by itself, since `compose.yaml` never opened that
door in the first place.

---

## 17. Current lack of HTB VPN connectivity

**Nothing in this Compose environment can reach an HTB target.**
`apex-internal` is a private, Docker-managed bridge network with no route
to any VPN tunnel, HTB infrastructure, or the wider internet beyond what
each container's own outbound connectivity already permits (e.g. `uv`'s
own PyPI fetches during the build — unrelated to engagement traffic). No
VPN container, no `.ovpn` file, no VPN-related environment variable, and
no VPN-related network configuration exists anywhere in `compose.yaml` or
either Dockerfile. This is explicitly deferred to a later Infra Phase —
see §21.

---

## 18. Cleanup

```bash
APEX_TOOL_SERVICE_TOKEN=... docker compose down --remove-orphans
```

**Verified live, this phase:** both containers and the `apex-internal`
network were removed cleanly; `docker ps -a --filter name=newapex` and
`docker network ls | grep apex-internal` both confirmed nothing remained.
The one test artifact this phase's validation created
(`run_reports/compose_smoke.json`) was removed afterward; every
pre-existing, legitimate report file already present under `run_reports/`
(from prior, unrelated engagement runs) was left untouched.

---

## 19. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker compose config` / `up` / `build` fails with `required variable APEX_TOOL_SERVICE_TOKEN is missing a value` | Token not exported | `export APEX_TOOL_SERVICE_TOKEN=<disposable-value>` before any `docker compose` command |
| `apex` never starts / `docker compose up` appears to hang | `kali`'s `HEALTHCHECK` has not passed yet (`start-period=5s`, `interval=10s`, `retries=3` — up to ~35 s before Compose gives up) | Wait, or check `docker compose ps` / `docker logs <kali-container>` for a startup problem |
| `curl`/browser to `http://localhost:8080` from the host fails | Expected — `kali` is intentionally not published to the host (§16) | Use `docker compose run --rm apex ...` to reach it from inside the network, or (for manual debugging only) temporarily add a `ports:` mapping locally — never commit that change |
| `docker compose build` fails with a PyPI/network timeout | Transient network condition (observed once this phase — §10) | Retry the identical `docker compose build` command |
| `nmap` default/SYN scan fails inside `kali` with "Couldn't open a raw socket" | Expected — no `NET_RAW` capability is granted (§15); unchanged from Infra Phase 6 | Use `nmap -sT` (TCP connect scan) instead, or wait for a future phase that adds the capability explicitly |
| Report file not visible under `./run_reports/` after a run | `--report-path` was not passed to `compose_smoke.py`, or the wrong path was used | Pass `--report-path /app/run_reports/<name>.json` explicitly (§8) |

---

## 20. Deferred `.env.example`

**Not created in this phase**, per this phase's own explicit instruction.
Every example in this document sets `APEX_TOOL_SERVICE_TOKEN` inline on
the command line instead. A future phase should add `.env.example` (with
a placeholder, non-functional token value) alongside the equivalent file
for `apex_host` itself (`docs/kali-tool-service.md` §11 already notes this
is deferred "to whichever phase adds `apex_host`'s `.env.example` too") —
not attempted here.

---

## 21. Deferred VPN phase

**Not started in this phase.** No VPN container, no `.ovpn` mount, no VPN
network configuration, and no route from `apex-internal` to any HTB
target exists anywhere in this repository as of this phase — see §17 for
the full statement of what this environment can and cannot reach. A
future Infra Phase must add VPN container/tunnel wiring before any
authorized live engagement could run through this Compose environment.

---

## 22. Deferred live engagement

**No live HTB run, no `run_htb_local` invocation, and no engagement
execution of any kind was performed against a real target in this
phase.** `apex`'s default Compose command is the dry-run connectivity
smoke check (§3), not `apex_host.eval.run_htb_local` — wiring a full
multi-turn engagement into Compose (with `--target`, `--tool-backend
remote --tool-service-url http://kali:8080`, and real credentials) is
future work this phase deliberately did not attempt, consistent with the
task brief's explicit prohibition on "GitHub Actions, Meow-specific
fixes, deterministic Meow workflow tests, or a live HTB engagement." No
machine-specific code, expected credentials, or target-specific logic was
added anywhere in this phase — `compose.yaml` and
`apex_host/eval/compose_smoke.py` contain no IP literals other than the
loopback/service-name addresses already documented above, enforced by
`tests/docker/test_compose.py::test_no_hardcoded_target_ip_anywhere`.
