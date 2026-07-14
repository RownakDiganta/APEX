# Kali Tool-Service Container

**Status:** Infra Phase 6 — implemented, built, and validated end-to-end
against a real Docker daemon, including a real
`apex_host.tools.remote_backend.RemoteToolBackend` client talking to a real
running container over HTTP.
**Date:** 2026-07-15
**Files:** `docker/kali/Dockerfile`, `docker/kali/entrypoint.py`,
`tests/docker/test_apex_kali_dockerfile.py`

This document describes the Kali Linux tool-execution appliance image built
in Infra Phase 6. Every claim below refers to code that exists in this
repository today and was independently verified by an actual `docker build`
+ `docker run` session recorded during this phase (not merely designed).

---

## 1. Purpose

`docker/kali/Dockerfile` builds a container image whose only job is to run
`apex_tool_service` (Infra Phase 3) against a small, evidence-justified set
of pre-installed network/recon binaries. It is the execution boundary that
[`docs/tool-execution-architecture.md`](tool-execution-architecture.md) and
[`docs/kali-tool-service.md`](kali-tool-service.md) designed but never
built: a real Kali filesystem, with real `nmap`/`curl`/`nc`/`ping`/`telnet`
binaries on `PATH`, running the same restricted, allowlisted HTTP service
unchanged from Infra Phase 3.

**This image is a controlled tool appliance, not an interactive Kali
desktop.** It starts nothing but `apex_tool_service`; every execution still
passes through that service's own allowlist, argument validation, and
bearer-token authentication (`apex_tool_service/{allowlist,validation,
auth}.py`) — this Dockerfile does not, and structurally cannot, bypass that
boundary, because it installs and runs the exact same unmodified Python
package built in Infra Phase 3.

---

## 2. Base image

```dockerfile
FROM kalilinux/kali-rolling@sha256:8a1ea7281085ffef4963e82766c70869d7db910df88dcbb1f03d2899420b9577
```

This is the **official** `kalilinux/kali-rolling` image on Docker Hub,
pinned by content digest. Verified on 2026-07-15:

```bash
docker pull kalilinux/kali-rolling
docker buildx imagetools inspect kalilinux/kali-rolling@sha256:8a1ea7281085ffef4963e82766c70869d7db910df88dcbb1f03d2899420b9577
```

confirmed a genuine multi-platform manifest list (`linux/amd64`,
`linux/arm64`, `linux/arm/v7`, `linux/386`) published under the official
`kalilinux` Docker Hub organization, and the built image's own OCI labels
(captured via `docker image inspect apex-kali:phase6 --format
'{{json .Config.Labels}}'`) confirm the provenance directly:

```json
"org.opencontainers.image.vendor": "OffSec",
"org.opencontainers.image.source": "https://gitlab.com/kalilinux/build-scripts/kali-docker",
"org.opencontainers.image.title": "Kali Linux (kali-rolling branch)"
```

**Why digest pinning, not a tag:** Kali rolling has no versioned release-tag
scheme at all (unlike Debian's `bookworm`/`bullseye` or Ubuntu's
`22.04`/`24.04`) — there is only ever a `kali-rolling` tag that is
continuously replaced. A digest pin is therefore the *only* reproducible
base-image reference available; it is not a substitute for using the
official image (this is not a community-maintained/unofficial image), it is
the official image, pinned. `:latest` is never used anywhere in this
Dockerfile.

**Documented limitation — APT package versions are NOT pinned.** The base
filesystem digest above is fixed and reproducible, but every
`apt-get install` in the Dockerfile resolves against Kali's live rolling
repositories at build time. Re-running the exact same
`docker build -f docker/kali/Dockerfile .` on a different day can install a
different `nmap`/`curl`/`telnet`/`netcat-openbsd` version even though the
`FROM` digest never changes — Kali's rolling-release model has no dated
snapshot repository analogous to Debian's `snapshot.debian.org` configured
here. A future phase could vendor an apt snapshot mirror to close this gap;
that was evaluated and deliberately not attempted in this phase (it would
be a meaningful new piece of infrastructure, out of this phase's scope).

The versions actually resolved during this phase's validation build (for
the record, not a guarantee for future builds):

| Package | Version resolved (2026-07-15) |
|---|---|
| `nmap` | `7.99+dfsg-1kali1` |
| `curl` | `8.20.0-5` |
| `iputils-ping` | `3:20250605-1+b1` |
| `netcat-openbsd` | `1.238-1` |
| `telnet` | `0.17+2.8-2` |
| `ca-certificates` | `20260601` |

---

## 3. Installed tools and rationale

Every installed apt package maps 1:1 to a key in
`apex_tool_service/allowlist.py::ALLOWED_TOOLS`. No tool is installed
without a corresponding allowlist entry; no allowlist entry is left without
an installed binary — verified live via the running container's own
`GET /health` response (§13):

```json
{"status":"ok","service":"apex-tool-service","tools":{"nmap":true,"curl":true,"nc":true,"netcat":true,"ping":true,"telnet":true}}
```

| apt package | Allowlist tool(s) satisfied | Evidence |
|---|---|---|
| `nmap` | `nmap` | `apex_host/tools/registry.py`; `ReconPlanner`; `NmapParser` |
| `curl` | `curl` | `apex_host/tools/registry.py`; `WebPlanner`; `CommandParser` |
| `iputils-ping` | `ping` | Provides `/usr/bin/ping`; no direct APEX code-path evidence, included per this service's own allowlist rationale (a safe, read-only network diagnostic, same risk profile as the others) |
| `netcat-openbsd` | `nc` **and** `netcat` | **One package satisfies both allowlist entries.** Verified empirically this phase: `dpkg -L netcat-openbsd` shows it installs `/etc/alternatives/nc`/`/etc/alternatives/netcat`, and both `/usr/bin/nc` and `/usr/bin/netcat` are `update-alternatives` symlinks resolving to the same `nc.openbsd` executable. `netcat-traditional` was evaluated and NOT installed — it would be redundant. |
| `telnet` | `telnet` | Client only. `telnetd` (the Telnet *server*, a separate Debian/Kali package) was evaluated via `apt-cache policy telnetd` and confirmed to exist independently — it is explicitly **not** installed. |
| `ca-certificates` | *(not itself an allowlisted tool)* | TLS trust store for `curl`'s and the tool-service's own outbound HTTPS calls. Required for `uv python install`'s and `uv sync`'s own HTTPS fetches in the builder stage too. |

**Repo-wide tool-usage sweep performed this phase** (`grep` across
`apex_host/`, `memfabric/`, `tests/` for nmap/curl/ping/nc/netcat/telnet/
hydra/gobuster/ffuf/nikto/whatweb/dig/host/whois/masscan/sqlmap/
metasploit): confirmed `apex_host/tools/registry.py::_KNOWN_TOOLS` =
`nmap, curl, python3, nc, netcat, ffuf, gobuster, searchsploit`. `hydra`
appears **only** as a blocked-tool constant in
`apex_host/policy/policy_loader.py::_ALWAYS_BLOCKED_TOOLS` and a
brute-force detection pattern in `apex_host/policy/llm_guard.py` — i.e. the
only repository evidence for `hydra` is evidence *against* installing it.
`ping` appears only as a code comment (`# -Pn skips host-discovery ping` in
`apex_host/planners/recon_planner.py`), not a real invocation. `nikto`,
`whatweb`, `dig`, `host`, `whois`, `masscan`, `sqlmap`, `metasploit`: zero
hits anywhere in the repository.

### Explicitly NOT installed

Per this phase's task brief and the evidence above, none of the following
were installed, and each is verified absent in the built image (§13):

`kali-linux-default`, `kali-linux-large`, `kali-linux-everything`,
`metasploit-framework`, `sqlmap`, `hydra`, `medusa`, `patator`, `gobuster`,
`ffuf`, `nikto`, `whatweb`, `masscan`, `john`, `hashcat`, `telnetd`,
`openssh-server`, any Docker/container client, `sudo`, `iproute2`.

**`gobuster`/`ffuf`** *are* in `apex_host`'s own `allowed_tools` default and
`ToolRegistry._KNOWN_TOOLS`, but `apex_tool_service/allowlist.py` itself
deliberately excludes them (documented in `docs/kali-tool-service.md` §6:
wordlist-driven fuzzers need matching wordlist-path validation this service
was never designed to perform) — since this image installs exactly the
service's own allowlist, they are correctly absent here too. Expanding the
tool-service's allowlist to cover them is out of this phase's scope.

**`iproute2`** was in this phase's own "minimum evaluation set" but was
evaluated and excluded: it maps to no `apex_tool_service` allowlist entry
(there is no `ip`/`ss` tool in `ALLOWED_TOOLS`), no code path in this
repository invokes it, and basic container TCP/IP networking does not
require the `ip` binary to be present — `curl`/`nmap`/`nc` all use socket
syscalls directly via libc, not shell invocations of `ip`.

---

## 4. Python service installation

`apex_tool_service` (together with `apex_host`/`memfabric`, see §16) is
installed via a multi-stage build using `uv sync --frozen --no-dev
--no-editable`, identical discipline to `docker/apex/Dockerfile` (Infra
Phase 5):

- `--frozen`: the build fails outright if `pyproject.toml`/`uv.lock` are
  inconsistent — never regenerated in-image.
- `--no-dev`: `pytest`/`ruff`/`mypy`/type stubs are excluded. Verified
  absent in the built image (§13).
- `--no-editable`: real, self-contained copies are installed into
  site-packages; only the resulting virtual environment is copied into the
  runtime stage, never the source tree or `uv` itself.
- No manual `requirements.txt` exists anywhere — `uv.lock` is the sole
  dependency source of truth.

### Python interpreter: uv-managed, not Kali's own `python3`

Unlike `docker/apex/Dockerfile` (which uses the official `python:3.11-slim`
image directly as its own base), this image's base is Kali, which ships a
bleeding-edge, frequently-changing `python3` with no stable version pin.
The builder stage instead provisions a **uv-managed** (`python-build-
standalone`) CPython, pinned to the exact same `3.11.14` patch version used
by `docker/apex/Dockerfile` and this project's own development environment:

```dockerfile
ENV UV_PYTHON_INSTALL_DIR=/opt/uv-python ...
RUN uv python install 3.11.14
ENV UV_PYTHON_DOWNLOADS=never UV_PYTHON=3.11.14
```

Both `/opt/uv-python` (the managed interpreter) and `/app/.venv` (the
prepared virtual environment) are copied byte-for-byte into the runtime
stage at the same absolute paths they were built at, so the venv's
`bin/python3` symlink resolves correctly without needing Kali's own apt
`python3` package in either stage.

**Why not Kali's own `python3`:** because of the packaging limitation in
§16, `uv sync` installs the *full* project dependency graph — including
`numpy`, `faiss-cpu`, `playwright`, `langgraph` — even though this image
only ever runs `apex_tool_service`, whose own runtime needs are just
`fastapi`/`uvicorn`/`pydantic`/`httpx`. Several of those heavy scientific
dependencies do not reliably publish prebuilt manylinux wheels for a
brand-new CPython release the instant it lands in Kali's rolling repos;
using Kali's own `python3` risked `uv sync` falling back to a from-source
build, requiring a full C/C++ compiler toolchain — directly contradicting
this phase's "avoid unnecessary compilers/build tools" requirement, and
making build success dependent on whatever Python version Kali happens to
ship on a given day. The uv-managed interpreter sidesteps this entirely:
pinned, portable (`python-build-standalone` targets a broadly compatible
glibc baseline), and proven — this is the exact same interpreter version
already validated end-to-end by `docker/apex/Dockerfile` and this
project's own CI/dev environment.

**Verified during the real build** (`docker build` transcript, this
phase): `uv sync --frozen --no-dev --no-install-project` downloaded and
installed 54 packages using only prebuilt wheels — zero compilation, zero
compiler toolchain invoked, confirming the interpreter choice avoided the
risk it was designed to avoid.

### `uv` itself is not present in the runtime image

```dockerfile
COPY --from=builder /opt/uv-python /opt/uv-python
COPY --from=builder --chown=apextool:apextool /app/.venv /app/.venv
```

Only the managed interpreter and the prepared venv are copied into the
runtime stage — the `uv` binary itself (copied into the *builder* stage
from the pinned `ghcr.io/astral-sh/uv` image) is never copied forward.
Enforced by `tests/docker/test_apex_kali_dockerfile.py::test_no_uv_in_runtime_stage_env_path`.

---

## 5. Non-root execution

```dockerfile
RUN groupadd --gid 1000 apextool \
    && useradd --uid 1000 --gid apextool --no-create-home --home-dir /app --shell /usr/sbin/nologin apextool
...
USER apextool
```

Verified live:

```
$ docker run --rm apex-kali:phase6 id
uid=1000(apextool) gid=1000(apextool) groups=1000(apextool)
```

No password, no login shell (`/usr/sbin/nologin`), no `sudo` anywhere in
the image (`tests/docker/test_apex_kali_dockerfile.py::test_no_sudo_or_password_setup`),
no passwordless privilege escalation of any kind. This account exists
solely to run `apex_tool_service` and the tool subprocesses it spawns.

### Linux capability findings (empirical, this phase)

**No `--cap-add` or `setcap` appears anywhere in this Dockerfile** — a
Docker `RUN` instruction cannot grant a *runtime* capability to a
container anyway (capabilities are a `docker run`/Compose-time concern,
correctly deferred to a future Compose phase per this phase's own task
brief). What this phase *did* do is empirically characterize which
allowlisted tools work for the non-root `apextool` user under Docker's
**default** capability set (no `--cap-add` at `docker run` time):

| Tool / mode | Works unprivileged (default caps)? | Mechanism |
|---|---|---|
| `ping` | **Yes** | Linux's unprivileged-ICMP-ping-socket kernel feature. `getcap /usr/bin/ping` is empty (no file capability), no setuid bit — verified via `getcap`/`ls -la` inside a throwaway container. `/proc/sys/net/ipv4/ping_group_range` returns `0 2147483647` (all GIDs permitted) inside the Kali base image, i.e. the permissive default is what makes this work, not any capability grant. |
| `nmap -sT` (TCP connect scan) | **Yes** | Uses ordinary `connect()` syscalls, no raw socket needed. Verified live against the real running container: `nmap -sT -Pn -n -p 22,80 127.0.0.1` as `apextool` returns a normal scan report (`returncode=0`). |
| `nmap --version` | **Yes** | No socket access needed at all. |
| `nmap` **default scan / `-sS`** (SYN scan) | **No** | Kali's `nmap` package sets file capabilities `cap_net_bind_service,cap_net_admin,cap_net_raw=eip` on the real binary at `/usr/lib/nmap/nmap` (behind a thin `/usr/bin/nmap` wrapper) — but this elevation does **not** take effect for the non-root `apextool` exec path even under Docker's default capability bounding set. Verified live: a bare/default-flags nmap request (the exact request shape used throughout every prior phase's documented API examples, `{"tool": "nmap", "arguments": ["-Pn", "-n", "-p", "80", ...]}`, i.e. no explicit `-sT`) fails outright with `returncode=1` and `stderr: "Couldn't open a raw socket. Error: (1) Operation not permitted\nCouldn't open a raw socket or eth handle.\nQUITTING!"` — **nmap 7.99 does not gracefully fall back to a connect scan; it just quits.** |
| `curl`, `nc`/`netcat`, `telnet` | **Yes** | Ordinary TCP/HTTP clients, no raw sockets. |

**Practical consequence:** a caller sending a bare/default nmap request
(no explicit `-sT`) through this container today gets a clean,
structured failure (`returncode=1`, a specific stderr message) — not a
hang, not a crash, not a silently-wrong result. Any caller (a future
`ReconPlanner`/`PlanningEngine`-generated task, a manual API caller) that
needs a working scan against this container **must pass `-sT`
explicitly**. This is a real, load-bearing operational constraint of the
current image and is called out here so it is not rediscovered the hard
way during Meow validation (deferred, §19).

**Deferred to Compose (Phase 7 or later):** granting `--cap-add=NET_RAW
--cap-add=NET_ADMIN` at `docker run`/Compose time would very likely restore
default/SYN-scan behavior (untested — capability decisions were
deliberately kept out of this Dockerfile per the task brief; `-sT` and
`--version` are sufficient to validate the image today, so no capability
grant was required to complete this phase). This finding, not a capability
grant, is this phase's deliverable on the topic.

---

## 6. Port and health check

```dockerfile
EXPOSE 8080
ENV APEX_TOOL_SERVICE_HOST=0.0.0.0 APEX_TOOL_SERVICE_PORT=8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1
```

`apex_tool_service/settings.py`'s own default bind host is `127.0.0.1`
(localhost-only — broader exposure is an explicit opt-in at the library
level). Because a container's whole purpose is to be reached from outside
itself, this Dockerfile explicitly overrides that default via
`APEX_TOOL_SERVICE_HOST=0.0.0.0`, matching this phase's own requirement to
"bind by default to 0.0.0.0 inside the container." Port 8080 is
non-privileged (no `docker run --privileged`, no capability needed to bind
it) and matches the service's own built-in default port.

**Health check semantics, verified live:**
- Targets the service's own unauthenticated `GET /health` — no bearer
  token required (`tests/docker/test_apex_kali_dockerfile.py::test_healthcheck_does_not_require_bearer_token`).
- Uses `curl`, already installed for the allowlist (no extra dependency
  added just for the health check).
- Fails only when the HTTP server itself is not responding with 2xx — the
  handler always returns `200` with a per-tool availability map
  (`apex_tool_service/app.py`), so an individual missing optional tool
  never marks the container unhealthy.
- `docker inspect` on the built image shows the exact configured values:
  `Interval: 10000000000` (10s), `Timeout: 3000000000` (3s),
  `StartPeriod: 5000000000` (5s), `Retries: 3`.
- Verified live: a freshly started container transitions from
  `health: starting` to `healthy` within the configured start period.

---

## 7. Required token configuration and fail-closed behavior

`APEX_TOOL_SERVICE_TOKEN` is **not** set anywhere in the Dockerfile — no
`ENV`, no `ARG`, no default value, enforced by
`tests/docker/test_apex_kali_dockerfile.py::test_no_hardcoded_bearer_token`.
Verified live, twice:

**Without a token** (`docker run ... apex-kali:phase6`, no
`-e APEX_TOOL_SERVICE_TOKEN`):
```
$ curl -s http://127.0.0.1:18080/health
{"status":"ok","service":"apex-tool-service","tools":{...}}          # 200 — unauthenticated, as designed

$ curl -s -X POST http://127.0.0.1:18080/v1/execute -d '{"tool":"curl","arguments":["--version"]}'
{"detail":"tool service is not configured with an authentication token"}   # 503 — fails closed
```
Container logs contain no secret and no default/placeholder token value —
only the operator-facing warning line
`apex_tool_service/__main__.py` already prints to stderr.

**With an operator-supplied token** (`-e
APEX_TOOL_SERVICE_TOKEN=phase6-test-token`, a disposable value used only
for this validation session, never committed anywhere as a real
credential):
```
$ curl -s -X POST http://127.0.0.1:18081/v1/execute -H "Authorization: Bearer wrong-token" -d '...'
{"detail":"invalid or missing bearer token"}          # 401

$ curl -s -X POST http://127.0.0.1:18081/v1/execute -H "Authorization: Bearer phase6-test-token" -d '{"tool":"curl","arguments":["--version"]}'
{"tool":"curl", ..., "returncode":0, "backend":"kali-service", ...}   # 200 — executes for real
```

An operator **must** supply `-e APEX_TOOL_SERVICE_TOKEN=...` at `docker run`
time for the execution endpoint to accept anything; `GET /health` remains
reachable either way, matching `apex_tool_service/auth.py`'s documented
fail-closed design (unchanged by this phase).

---

## 8. Build command

```bash
docker build -f docker/kali/Dockerfile -t apex-kali:phase6 .
```

Must be run from the **repository root** (not `docker/kali/`), so the
build context includes `pyproject.toml`, `uv.lock`, `memfabric/`,
`apex_host/`, and `apex_tool_service/`.

**Verified this phase:** a cold build completed successfully end-to-end
(Kali base pull, apt tool install, `uv python install 3.11.14`, `uv sync`
resolving 54 packages from prebuilt wheels with zero compilation, project
package build/install, final image export). A second build after only
adding `docker/kali/entrypoint.py` completed in under 1 second, entirely
from Docker's build cache, confirming the layer-ordering (dependency
manifests before source, source before the tiny entrypoint copy) works as
intended.

**Final image:** `apex-kali:phase6`, **813 MB**, `docker history
--no-trunc` breakdown:

| Layer | Size | Contents |
|---|---|---|
| Kali rootfs base | 155 MB | Official `kalilinux/kali-rolling` base layer |
| `apt-get install` (6 tools) | 50.5 MB | nmap, curl, iputils-ping, netcat-openbsd, telnet, ca-certificates |
| `useradd`/`groupadd` | 49.2 kB | `apextool` account |
| `/opt/uv-python` copy | 99.9 MB | uv-managed CPython 3.11.14 |
| `/app/.venv` copy | 313 MB | Full project dependency graph (see §16 — the packaging limitation) |
| ENV/USER/EXPOSE/HEALTHCHECK/CMD | 0 B | Metadata only |

---

## 9. Local run commands

```bash
# Build
docker build -f docker/kali/Dockerfile -t apex-kali:phase6 .

# Start with an operator-supplied token (never commit a real token)
docker run -d --name apex-kali \
  -p 8080:8080 \
  -e APEX_TOOL_SERVICE_TOKEN=your-local-dev-token \
  apex-kali:phase6

# Check health (no token needed)
curl -s http://127.0.0.1:8080/health

# Execute an allowlisted tool
curl -s -X POST http://127.0.0.1:8080/v1/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-local-dev-token" \
  -d '{"tool": "curl", "arguments": ["--version"]}'

# Stop and remove
docker rm -f apex-kali
```

No HTB VPN, no live target, and no `apex_host`/`apex-kali` Compose wiring
is required for any of the above — this is a standalone container talking
only to itself and the loopback interface.

---

## 10. Safe smoke tests

Every command run against the real container during this phase's
validation was either a version/help query or a loopback-only probe — no
external network target was ever contacted:

- `curl --version`, `nmap --version`, `nc -h`, `netcat -h` — pure
  version/usage output, no network activity.
- `ping -c 1 127.0.0.1` — loopback only.
- `nmap -sT -Pn -n -p 22,80 127.0.0.1` / the bare-flags negative-result
  demonstration above — loopback only.
- `telnet` with no arguments (immediate EOF on stdin, no connection
  attempted).

All of these are safe to run against any instance of this image, on any
machine, with no authorization concerns — they touch nothing but the
container's own loopback interface.

---

## 11. Tool availability reporting

`GET /health` (unauthenticated by design, `apex_tool_service/app.py`) is
the accurate, live source of truth for which allowlisted binaries are
actually present — it calls `shutil.which()` per tool at request time, not
a static/build-time snapshot. Verified against the real built image: all
six allowlisted tools report `true`. If a future change to this Dockerfile
ever dropped one of the apt packages, `/health` would immediately reflect
that as `false` for the corresponding tool, without the service crashing or
requiring a restart — this is unchanged, pre-existing Phase 3 behavior,
just now exercised against real binaries for the first time.

---

## 12. Filesystem and logging

- **No persistent writable application directory.** `/app` contains only
  `.venv/` (owned by `apextool`, read+execute needed to run the
  interpreter) and `entrypoint.py` — no directory is created for reports,
  logs, or credentials. Verified: `docker run --rm apex-kali:phase6 ls -la
  /app` shows exactly these two entries.
- **No credential storage, no report generation, no APEX run reports, no
  compiled/raw knowledge, no VPN profiles.** Verified absent:
  `.env`, `.env.local`, `*.ovpn`, `Knowledge/`/`knowledge/`, `run_reports/`,
  `secrets/`, `.git/` — none exist anywhere in the built image filesystem
  (checked at both `/` and `/app`).
- **Logs go to stdout/stderr only**, via the standard `logging` module and
  uvicorn's own access logger — no log file is ever written to disk.
- **No hidden persistent command-history file** — the `apextool` account
  has `--no-create-home`/`nologin`, so no shell history mechanism exists
  for it in the first place.

### Audit logging fix: `docker/kali/entrypoint.py`

`apex_tool_service`'s own module-level loggers
(`apex_tool_service.app`/`.audit`/`.executor`) are created via plain
`logging.getLogger(__name__)` with no explicit level set anywhere in that
package — by design, since a *library* embeddable as `uvicorn
apex_tool_service.app:app` should not impose logging configuration on its
embedding process (`apex_tool_service/__main__.py` correspondingly never
calls `logging.basicConfig`). Under Python's default logging configuration
(root logger effectively `WARNING`, only the automatic `logging.lastResort`
handler attached), this means the `INFO`-level audit lines
`apex_tool_service/audit.py` already computes on every request
(`execution_accepted`, `execution_complete`, `execution_rejected`) were
silently dropped when running via plain `python -m apex_tool_service` in a
container with no other logging setup — verified: only uvicorn's own
independently-configured access-log lines and `WARNING`-level events
(`auth_failure`) reached `docker logs` before this fix.

A standalone container's only observability surface *is* stdout/stderr, so
this phase adds `docker/kali/entrypoint.py` — a single `logging.basicConfig
(level=logging.INFO, ...)` call followed by delegating to the exact same
`apex_tool_service.__main__.main()` — as the container's `CMD`. This is
purely an observability/logging-level configuration change: no allowlist,
validation, authentication, or execution logic in `apex_tool_service` is
modified. It is the same class of "entrypoint script" this phase's own
task brief lists as an allowed `docker/kali/` support file.

**Verified live, before and after:** without the entrypoint, `docker logs`
showed only uvicorn access-log lines and `auth_failure` warnings for a
sequence of health checks, executions, and auth failures. After adding
the entrypoint and rebuilding, the same sequence produced:

```
2026-07-14 18:28:52,628 INFO apex_tool_service.audit: execution_accepted id=59d6e49eef0c41f2ac5f96319a4650cf tool=curl arg_count=1 timeout_seconds=30.0
2026-07-14 18:28:52,642 INFO apex_tool_service.audit: execution_complete id=59d6e49eef0c41f2ac5f96319a4650cf tool=curl returncode=0 duration_seconds=0.013 timed_out=False stdout_bytes=586 stderr_bytes=0 error= args=--version
2026-07-14 18:28:52,660 WARNING apex_tool_service.audit: auth_failure id=e125091a54e04fea97c11932bc0b811a status=missing_header
```

Correlation ID and tool metadata are present on every line; the bearer
token (correct or incorrect) never appears in any log line, matching
`apex_tool_service/audit.py`'s own documented "never logged" guarantee
(unchanged — this fix only changes *whether* the already-safe log lines are
emitted, not *what* they contain).

---

## 13. Tests

### Static (no Docker daemon required)

```bash
uv run pytest tests/docker/test_apex_kali_dockerfile.py -q
```

53 tests, mirroring the pattern established by
`tests/docker/test_apex_dockerfile.py` (Infra Phase 5): read
`docker/kali/Dockerfile` and `.dockerignore` as text, assert on content
(substrings/regexes/logical-line grouping across `\`-continued `RUN`
instructions), never exact formatting. Covers: official/pinned Kali base
(both stages), no `latest`, no forbidden packages (metapackages, exploit
frameworks, brute-force tools, fuzzers, `telnetd`, `openssh-server`), no
Docker socket/CLI reference, no `sudo`, non-root `USER`, no capability
grants in the Dockerfile, frozen/no-dev `uv sync`, no `uv` in the runtime
stage, pinned managed-Python version, `EXPOSE 8080`, `0.0.0.0` bind,
non-theater `HEALTHCHECK` targeting `/health` with no auth requirement, safe
CMD (no shell, no offensive-tool autostart), no hardcoded token/secrets, no
`.env`/`.ovpn`/knowledge/`run_reports`/secrets copied, apt cache cleanup,
noninteractive/no-recommends install, single combined `apt-get update &&
install` layer, no dev-tool (`pytest`/`ruff`/`mypy`) references, and a
cross-check that `apex_tool_service/allowlist.py`'s `ALLOWED_TOOLS` keys
exactly match this document's tool manifest.

### Real build + runtime validation (this phase, recorded here since a
`docker build`/`docker run` session in a test suite would be slow and
environment-dependent — the same rationale `test_apex_dockerfile.py`
already documents for Infra Phase 5)

All nine parts of this phase's runtime-validation checklist were executed
against a real `apex-kali:phase6` image on a real Docker daemon:

1. **No-token startup** — healthy, `/health` 200 and accurate, `/v1/execute`
   fails closed (503), no secret in logs. ✓
2. **Test-token startup** — healthy, `/health` accurate, unauthorized
   `/v1/execute` → 401 (missing header) and 401 (wrong token), authorized →
   200 with a real `curl --version` execution. ✓
3. **Safe tool executions** — `nmap --version`, `ping -c 1 127.0.0.1`, `nc
   -h`, `netcat -h`, `curl --version` all return `backend: "kali-service"`,
   `returncode: 0`, populated `duration_seconds`; the nmap privilege
   finding (§5) demonstrated live (`-sT` succeeds, bare/default flags fail
   cleanly with `returncode: 1`). ✓
4. **Unknown/dangerous tool rejection** — `bash`, `python3`, `sh`, `sudo`
   all rejected with `400 tool '<x>' is not in the server allowlist`
   *before* any process is created; a shell-metacharacter argument
   (`--version; rm -rf /`) rejected with `400 argument[0] contains shell
   operator ';'`. ✓
5. **Non-root execution** — `docker run --rm apex-kali:phase6 id` →
   `uid=1000(apextool) gid=1000(apextool)`. ✓
6. **Installed-tool inspection** — `command -v` confirms all six
   allowlisted binaries present at `/usr/bin/*`; `hydra`, `medusa`,
   `gobuster`, `ffuf`, `nikto`, `whatweb`, `masscan`, `john`, `hashcat`,
   `sqlmap`, `msfconsole`, `telnetd`, `sshd` all confirmed absent. ✓
7. **Development-tool absence** — `pytest`/`ruff`/`mypy` confirmed absent
   from `PATH`. ✓
8. **Filesystem review** — `.env`, `.env.local`, `.ovpn`, `Knowledge/`,
   `knowledge/`, `run_reports/`, `secrets/`, `.git/` all confirmed absent
   at both `/` and `/app`; `/app` contains only `.venv/` and
   `entrypoint.py`; the 243 entries under `/etc/ssl/certs` are the public
   CA trust bundle, not secrets. ✓
9. **Real `RemoteToolBackend` contract smoke test** — a standalone script
   constructed a real `apex_host.tools.remote_backend.RemoteToolBackend`
   (with `ApexConfig(dry_run=False, tool_service_url="http://127.0.0.1:18081",
   tool_service_token="phase6-test-token")`) and called
   `await backend.execute("curl", ["--version"])` against the real running
   container. Result: `ToolResult(backend="kali-service", returncode=0,
   timed_out=False, error=None, stdout=<real curl --version output>)`,
   confirming the full chain **real `RemoteToolBackend` → real Dockerized
   Kali service → real installed binary → `ToolResult`**. The client was
   closed cleanly via `await backend.aclose()` in a `finally` block. No
   Compose, no HTB VPN, no internet access, and no live target were
   required — only the loopback-bound container from part 2. ✓

   **Minor, pre-existing documentation/code note surfaced by this test**
   (not a Phase 6 defect, not fixed in this phase): `docs/kali-tool-service.md`
   §5 states the future `RemoteToolBackend` client "is responsible for
   normalizing [the server's `backend` field] to `ToolResult.backend=
   "remote"`". The real Infra Phase 4 implementation
   (`apex_host/tools/remote_backend.py::_map_response`) instead passes the
   server's own reported value through verbatim
   (`backend=str(data.get("backend") or "remote")`), so a successful
   response's `ToolResult.backend` is observed as `"kali-service"`, not
   `"remote"` — `"remote"` is only ever used as a fallback for transport
   failures/malformed responses where no server value exists. This is a
   real, observed discrepancy between that doc's stated design and Infra
   Phase 4's shipped behavior; recorded here for visibility. It was not
   modified as part of Phase 6 — `apex_host/tools/remote_backend.py` is
   outside this phase's authorized file list (`docker/kali/` only).

All nine parts passed. All temporary containers (`apex-kali-phase6-no-token`,
`apex-kali-phase6-token`) were stopped and removed after validation;
`docker ps -a --filter name=apex-kali` returns empty.

---

## 14. Linux capability considerations (summary — full detail in §5)

No capabilities are added by this Dockerfile (no `--cap-add`, no
`setcap`), matching the task brief's instruction to keep capability
decisions for a future Compose phase. `ping` works unprivileged with zero
capability grant (kernel feature, not a capability). `nmap -sT` works
unprivileged. `nmap`'s default/SYN-scan modes do **not** work unprivileged
under Docker's default capability set — a caller must pass `-sT`
explicitly, or a future Compose phase must grant `--cap-add=NET_RAW
--cap-add=NET_ADMIN` (untested; deferred).

---

## 15. Audit logging

See §12's "Audit logging fix" subsection for the full account of the
`docker/kali/entrypoint.py` addition and its verified before/after
behavior. The underlying audit content and guarantees (correlation ID,
bounded argument preview, token never logged) are entirely
`apex_tool_service/audit.py`'s existing Phase 3 design, unmodified by this
phase — see `docs/kali-tool-service.md` §10 for that design's full
documentation. This phase only ensures those existing log lines actually
reach `docker logs` when the service runs as a container's main process.

---

## 16. Security properties

Summary of the properties verified this phase (each with a corresponding
live check recorded in §13):

- Official, digest-pinned Kali base image (§2).
- Only six allowlist-mapped apt packages installed; every forbidden
  package/metapackage/exploit-framework/brute-force-tool confirmed absent
  (§3, §13.6).
- No SSH server, no Telnet daemon, no Docker client/socket, no `sudo`
  anywhere in the image (§13.6).
- Frozen, lock-file-driven Python dependency installation; zero dev tools
  in the final image (§4, §13.7).
- Non-root execution (UID/GID 1000, no login shell, no password) (§5).
- No Linux capabilities added by this Dockerfile; empirically documented
  which allowlisted tools do/don't need one (§5, §14).
- No hardcoded bearer token anywhere; execution fails closed (503) when
  unconfigured; live 401 on bad/missing credentials (§7).
- Non-privileged port 8080; meaningful, unauthenticated, non-tool-invoking
  health check (§6).
- No secrets, credentials, `.ovpn` profiles, knowledge corpora, or
  APEX run-report directories present in the image filesystem (§12).
- Defense in depth preserved end-to-end: this container's own
  allowlist/validation/auth (`apex_tool_service`) is a second, independent
  gate behind `apex_host`'s own `PolicyAdvisor`/`check_command` client-side
  checks — proven live by the real `RemoteToolBackend` smoke test in
  §13.9, which exercises both layers in sequence.

---

## 17. Packaging limitations

**`apex_tool_service` is bundled with `apex_host`/`memfabric` in the same
Hatchling distribution** (`[tool.hatch.build.targets.wheel].packages =
["memfabric", "apex_host", "apex_tool_service"]` in `pyproject.toml`) — this
is unavoidable with the project's current packaging configuration, not a
Phase 6 decision. `uv sync` resolves and installs the **entire** project
dependency graph (`numpy`, `faiss-cpu`, `playwright`, `langgraph`,
`langchain-openai`, ...) even though this image's runtime CMD only ever
imports and runs `apex_tool_service`, whose own real dependencies are just
`fastapi`/`uvicorn`/`pydantic`/`httpx`.

**Observed impact:** the copied `/app/.venv` layer is 313 MB — the large
majority of this image's 813 MB total — almost entirely consisting of
dependencies `apex_tool_service` never imports at runtime.

**A broader packaging split (separate `pyproject.toml`/distribution for
`apex_tool_service` alone) was considered and deliberately NOT performed in
this phase**, per this phase's own task brief ("consider-but-do-not-
perform"). This image never starts, imports at module-execution time, or
exposes anything from `apex_host`/`memfabric` — no `CMD`/`ENTRYPOINT` here
ever invokes them, and no knowledge corpora, VPN profiles, or APEX-specific
configuration is copied into this image (verified in §12) — so the
unnecessary dependency weight is a build-size/attack-surface cost, not a
functional or security leak: the extra installed packages are inert,
unimported code sitting in `site-packages`, never executed by this image's
`CMD`.

A future phase that wants a smaller image would need one of: (a) splitting
`apex_tool_service` into its own `pyproject.toml`/package so `uv sync`
never sees the heavier dependencies, or (b) a `uv sync --package
apex_tool_service`-style selective install once Hatchling/uv support that
cleanly for this project's layout. Neither was implemented here.

---

## 18. Deferred Compose integration

**Not started in this phase, explicitly, per the task brief:**

- `docker-compose.yml` (or equivalent) wiring this Kali image and the
  Infra Phase 5 APEX application image together on a shared, isolated
  network.
- `.env.example` for either image.
- Final container entrypoint orchestration beyond the single-service
  `docker/kali/entrypoint.py` added this phase.
- Linux capability grants (`--cap-add=NET_RAW`/`NET_ADMIN`) for
  default/SYN-scan `nmap` support — the finding is documented (§5, §14);
  the grant itself is not configured anywhere, since no Compose file exists
  yet to configure it in.
- GitHub Actions or any other CI publishing pipeline for this image.

---

## 19. Deferred VPN networking

No VPN container, no HTB OpenVPN profile, no tunnel configuration of any
kind exists in this repository as of this phase. This image has no network
route to any HTB target — every command executed against it during
validation (§10, §13) touched only its own loopback interface. Reaching an
authorized HTB machine from this architecture requires a VPN container (or
equivalent host-level VPN routing) that does not exist yet.

---

## 20. Deferred Meow validation

**No live HTB run was performed in this phase**, per the task brief. The
nmap privilege finding in §5 is directly relevant to the eventual Meow
smoke test (CLAUDE.md §12.2): whichever component eventually issues nmap
tasks against this container (a future `ReconPlanner`-driven
`RemoteToolBackend` call) must use `-sT` rather than relying on nmap's
default scan type, or the container must be run with the capability grant
noted in §14 — otherwise the very first live recon task against Meow (or
any HTB target) through this container would fail with the exact
`"Couldn't open a raw socket"` error demonstrated live in §5/§13.3. This is
recorded here specifically so it is not rediscovered as a surprise during
the eventual Meow validation phase.

No machine-specific code, expected credentials, or target-specific logic
was added anywhere in this phase (`docker/kali/Dockerfile` and
`docker/kali/entrypoint.py` contain no IP literals other than
`127.0.0.1`/`0.0.0.0`, enforced by
`tests/docker/test_apex_kali_dockerfile.py::test_no_hardcoded_target_ip_anywhere`).
