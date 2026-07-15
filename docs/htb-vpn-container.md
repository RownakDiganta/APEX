# HTB VPN Container Architecture

**Status:** Infra Phase 10 — implemented, built, and validated end-to-end
against a real Docker environment: a real VPN image build/inspection, a
real missing-profile fail-fast, a real bounded invalid-profile failure, a
real mock-VPN network-namespace-sharing integration proving APEX reaches
Kali's tool-service API through the shared namespace, and a real
confirmation that the default (non-HTB) Compose workflow is completely
unaffected. **No real HTB profile was available to this phase** — live
OpenVPN initialization against an actual HTB server and live route/target
validation were **not** performed. See `docs/htb-vpn-manual-validation.md`
for the exact remaining steps an operator with a real profile must run.
**Date:** 2026-07-15
**Files:** [`docker/vpn/`](../docker/vpn/), [`compose.yaml`](../compose.yaml)
(updated), [`compose.htb.yaml`](../compose.htb.yaml) (new),
[`compose.mock-vpn.yaml`](../compose.mock-vpn.yaml) (new, test-only),
[`apex_host/eval/preflight.py`](../apex_host/eval/preflight.py) (updated),
[`apex_host/config.py`](../apex_host/config.py) /
[`apex_host/config_env.py`](../apex_host/config_env.py) (updated),
[`apex_host/eval/vpn_route_check.py`](../apex_host/eval/vpn_route_check.py) (new)

---

## 1. Architecture

```text
                    Docker internal control network (apex-internal)
┌──────────┐                                                    │
│  apex    │ ───────────────── HTTP ──────────────────────────► │
│(unpriv.) │  http://vpn:8080 (kali API)  http://vpn:8090 (VPN  │
└──────────┘                                readiness API)      │
                                                                  │
                              ┌───────────────────────────────────┐
                              │   vpn container (network owner)   │
                              │   - OpenVPN (foreground)          │
                              │   - readiness HTTP server :8090   │
                              │   - NET_ADMIN + /dev/net/tun       │
                              └───────────────┬───────────────────┘
                                              │ network_mode: service:vpn
                              ┌───────────────▼───────────────────┐
                              │   kali container (netns guest)    │
                              │   - apex_tool_service :8080       │
                              │   - non-root, zero added caps     │
                              └───────────────┬───────────────────┘
                                              │ tunnel (tun0)
                                        HTB 10.129.0.0/16
```

Three services (`apex`, `kali`, `vpn`), one Docker Compose base file
(`compose.yaml`) plus one **override** file (`compose.htb.yaml`, only
merged in when HTB mode is explicitly requested) plus one **test-only**
override (`compose.mock-vpn.yaml`, never used in a real engagement).
`vpn` owns the tunnel and the network namespace; `kali` joins that
namespace (`network_mode: service:vpn`) so its outbound tool traffic uses
the tunnel; `apex` remains on the ordinary `apex-internal` bridge network
and reaches both `kali`'s tool API and `vpn`'s own readiness API through
`vpn`'s Compose DNS name (§8).

---

## 2. Trust boundaries

| Boundary | Enforced by |
|---|---|
| Only `vpn` can create a tun device / modify the container's routing table | `cap_add: [NET_ADMIN]` + `devices: [/dev/net/tun]` — granted **only** to `vpn`, verified live (§16) |
| `kali` never gains a capability from sharing `vpn`'s namespace | `network_mode: service:X` shares **only** the network namespace, never capabilities/filesystem/user namespace — verified live (§12) |
| `apex` never touches VPN internals directly | `apex` only ever speaks HTTP to `http://vpn:8080`/`http://vpn:8090` — no Docker socket, no `docker exec`, no shared namespace with anything |
| The `.ovpn` profile never enters an image | Mounted read-only at *container run time* only (§6) — `docker/vpn/Dockerfile` has no `COPY *.ovpn` anywhere, verified via `docker history` (§16) |
| The `.ovpn` profile is never read by `apex` | Only `vpn` mounts it; `apex`'s own `htb_ovpn_path` field is a **host**-side visibility check only (`apex_host/eval/preflight.py::check_htb_profile_configured`) — it inspects file existence/readability, never content, and the apex *container* never receives this file |
| Default Compose workflow stays VPN-free | `vpn` is `profiles: ["htb"]` — never started by a bare `docker compose up` (§13, verified live) |

---

## 3. Why the VPN runs in a dedicated container

Four alternatives were explicitly rejected by this phase's own task brief:
directly on the Mac host, inside `apex`, inside the Kali service process,
or through Docker socket commands. A dedicated container is the only
option that satisfies every one of: (a) `apex` and `kali` stay
unprivileged and non-root, (b) the tunnel's network effects are isolated
to exactly the container that needs them (`kali`, via explicit namespace
sharing — not the whole host), (c) no component needs Docker API access
to inspect or control another container, and (d) the blast radius of a
compromised `apex` process is bounded to an authenticated HTTP call to
`kali`'s already-restricted, allowlisted tool API — never direct access
to routing tables, credentials, or the tunnel itself.

---

## 4. VPN image

`docker/vpn/Dockerfile` — single-stage, built from the same digest-pinned
`python:3.11.14-slim-bookworm` base `docker/apex/Dockerfile` uses (Infra
Phase 5), for build consistency and because a small Python interpreter is
needed for the readiness server (§9). Installs exactly three packages:
`openvpn`, `iproute2` (provides `ip`, used by the readiness/route-check
scripts), `ca-certificates`. No SSH, no remote-shell tool, no Kali
tooling, no `apex_host`/`memfabric`/`apex_tool_service` source, no
knowledge corpora, no `pyproject.toml`/`uv.lock` — verified via
`docker history --no-trunc` (§16) and static tests
(`tests/docker/test_vpn_dockerfile.py`, 28 tests).

Four first-party Python scripts, all stdlib-only (no FastAPI/uvicorn/
httpx/`apex_host` import — verified statically):

| File | Purpose |
|---|---|
| `docker/vpn/entrypoint.py` | Container `ENTRYPOINT` — validates inputs, starts the readiness server thread, runs OpenVPN in the foreground, forwards signals |
| `docker/vpn/readiness_server.py` | Minimal `http.server`-based HTTP server: `GET /health`, `GET /route-check` |
| `docker/vpn/tunnel_status.py` | Tunnel interface / route detection (`ip link show` / `ip route show` parsing) |
| `docker/vpn/route_check.py` | The safe, no-packet `ip route get <target>` utility |

**Why a small first-party image over a third-party VPN image:** an
opaque, pre-built VPN Docker image's entrypoint behavior cannot be
audited line-by-line the way this ~250-line, four-file, stdlib-only
implementation can. Every subprocess call in every one of these four
files is an explicit argument list (`shell=False`) — verified both
statically (grep for `shell=True`) and by direct code inspection.

---

## 5. Profile mounting

The profile is **never** baked into the image. `docker/vpn/Dockerfile`
creates an empty `/vpn` directory at build time (`RUN mkdir -p /vpn`) —
the real file is mounted read-only at *container run time* only:

```yaml
volumes:
  - ${APEX_HTB_OVPN_PATH:?Set APEX_HTB_OVPN_PATH ...}:/vpn/htb.ovpn:ro
```

`docker/vpn/entrypoint.py::_verify_profile()` checks the mounted path
exists and is readable, then hands it to OpenVPN via `--config` — the
entrypoint itself never opens the file for writing (`grep -c '"w"'` finds
nothing in that file) and never echoes its content.

---

## 6. Compose profile

`vpn` is declared directly in the **base** `compose.yaml`, gated behind
`profiles: ["htb"]` — Compose's own mechanism for "this service exists in
the file but never starts unless explicitly requested." A bare
`docker compose up` (no `--profile htb`) never starts it — verified live
(§13). Its `volumes:` entry in the base file uses a **soft** default
(`${APEX_HTB_OVPN_PATH:-/dev/null}`), not the fail-fast `:?` form —
Compose validates/interpolates every declared service up front regardless
of profile activation, so a `:?` requirement in the base file would have
broken the default workflow (discovered and fixed this phase — see §5 of
the design notes in `compose.yaml`'s own header comment, and the exact
error transcript in §17 below).

---

## 7. Shared network namespace — the coherent design chosen

Three options were on the table (per this phase's own task brief):

1. Put the VPN service on `apex-internal` and reach the shared namespace
   through the VPN service's own Compose DNS name.
2. Use an internal alias like `kali` on the VPN service.
3. Bind Kali's HTTP service to `0.0.0.0:8080` inside the shared namespace.

**Chosen: option 1, plus (3) as a supporting fact rather than a separate
choice** — Kali's HTTP service was *already* bound to `0.0.0.0:8080`
(Infra Phase 6, unchanged), so once it shares `vpn`'s namespace that
binding is automatically reachable at whatever address resolves to that
namespace. Option 2 (aliasing `vpn` as `kali`) was rejected: `kali` stops
having its own Compose DNS entry once it uses `network_mode: service:vpn`
(a container using another container's network namespace has no network
identity of its own to alias), so the only real address is `vpn`'s own —
inventing a second alias would only add confusion, not remove a real
constraint.

**Why a separate override file (`compose.htb.yaml`), not one shared
`compose.yaml`:** Compose has no mechanism to give a single named service
two different `network_mode`/`networks` configurations depending on which
`--profile` flag is passed — profiles only gate whether a whole service
*starts*, not which of two configs it *uses*. `compose.htb.yaml` is the
standard, documented Compose idiom for this ("override file," merged via
`-f compose.yaml -f compose.htb.yaml`). It redefines exactly two
services — `kali` (network mode) and `apex` (service-discovery
environment variables) — and never redefines `vpn` itself.

```yaml
# compose.htb.yaml (excerpt)
services:
  kali:
    networks: !reset null      # clears the base file's apex-internal membership
    network_mode: "service:vpn"
    expose: !reset null
    depends_on:
      vpn:
        condition: service_healthy
  apex:
    environment:
      APEX_TOOL_SERVICE_URL: http://vpn:8080
      APEX_VPN_SERVICE_URL: http://vpn:8090
```

`!reset` is the Compose Specification's own tag for explicitly clearing a
value inherited from a merged-in base file — required here because
`network_mode` and `networks` are mutually exclusive; without it,
`docker compose config` fails validation (this exact failure was
reproduced and fixed during this phase — the error was
`services.kali has both "network_mode" and "networks" set, which are mutually exclusive`,
before `!reset` was added).

---

## 8. APEX-to-Kali service discovery

| In this Compose environment | Default mode (`compose.yaml` only) | HTB mode (`+ compose.htb.yaml`) |
|---|---|---|
| Kali tool API | `http://kali:8080` | `http://vpn:8080` |
| VPN readiness API | not applicable | `http://vpn:8090` |

`apex_host/config.py` never reads environment variables itself
(unchanged architecture invariant). `APEX_TOOL_SERVICE_URL`/
`APEX_VPN_SERVICE_URL` are consumed the same way every other Compose
environment variable is: through `apex_host/config_env.py`'s generic
merge (`apex_host.container_entrypoint`'s own CLI flags, `default=None`,
filled from the environment). No new environment-reading module was
added — this phase reuses the exact mechanism Infra Phase 8/9 already
built.

---

## 9. Tunnel health

OpenVPN process existence alone is **not** treated as readiness.
`docker/vpn/readiness_server.py`'s `GET /health` calls
`docker/vpn/tunnel_status.py::check_tunnel_status(route_cidr)`, which:

1. Runs `ip -o link show` and looks for an interface whose name starts
   with `tun`/`tap`/`ppp` **and** whose state is `UP` — the literal name
   `tun0` is never assumed (a profile can specify `dev tap0` or a
   non-zero unit number).
2. Runs `ip route show` and checks whether any route's destination
   network is the configured CIDR (or a subnet of it).

Both are read-only inspection commands (`show`, never `add`/`del`) — no
route is created, modified, or removed by this check, and no packet is
ever sent. `docker/vpn/Dockerfile`'s own `HEALTHCHECK` targets this same
`/health` endpoint (not `pgrep openvpn` or similar), so Docker's own
health status (used by `depends_on: vpn: condition: service_healthy`)
reflects genuine tunnel readiness, not mere process existence.

---

## 10. Route readiness

`APEX_HTB_ROUTE_CIDR` (default `10.129.0.0/16`, matching HTB's own common
machine-lab range — documented, not silently assumed) configures what
`check_tunnel_status` compares the live routing table against. Validated
strictly via `ipaddress.ip_network(..., strict=False)`
(`docker/vpn/tunnel_status.py::validate_cidr`, independently re-implemented
in `apex_host/config_env.py::validate_cidr` for the APEX-side config layer
— the two must never import each other, since `apex_host` and
`docker/vpn/` are separate, non-overlapping dependency trees). A malformed
CIDR is rejected at parse time in both places, never silently ignored.

---

## 11. Capabilities and `/dev/net/tun`

```yaml
vpn:
  cap_add: [NET_ADMIN]
  devices: ["/dev/net/tun:/dev/net/tun"]
```

Only `vpn` receives these — verified both statically
(`tests/docker/test_compose.py::test_vpn_has_exactly_net_admin_capability`,
`test_only_vpn_mounts_dev_net_tun`) and live
(`docker inspect newapex-kali-1` showed `CapAdd=[]` while sharing `vpn`'s
namespace, §12). No `NET_RAW`, no `SYS_ADMIN`, no other capability — the
task brief's explicit "avoid broad capability requirements beyond
NET_ADMIN and /dev/net/tun" is honored exactly.

---

## 12. Non-root behavior

`apex` and `kali` remain non-root (UID 1000 `apex`/`apextool`,
unchanged from Infra Phase 5/6) in **every** mode, including HTB mode —
verified live: `docker inspect newapex-kali-1` while sharing `vpn`'s
namespace still showed `User=apextool`.

`vpn` runs as **root** — the one documented, deliberate exception to this
project's otherwise-universal non-root convention. OpenVPN must create a
tun/tap device and modify this container's own routing table, which
requires `CAP_NET_ADMIN` *and*, in practice, root inside the container's
own user namespace on every kernel this was tested against — `NET_ADMIN`
alone does not grant a non-root user permission to open `/dev/net/tun` or
reconfigure routes. This is the same operational requirement essentially
every mainstream OpenVPN container image accepts. It grants nothing
beyond this one container's own, isolated network namespace: no
`privileged: true`, no host networking, no Docker socket, no capability
beyond `NET_ADMIN`.

---

## 13. Default safe mode

```bash
APEX_TOOL_SERVICE_TOKEN=<disposable> docker compose up --build --abort-on-container-exit
```

**Verified live, this phase:** `vpn` never appears in `docker compose
config`'s default output at all (Compose excludes non-active-profile
services from `config`, not merely from `up`) — only `apex`+`kali` start,
exactly as in Infra Phase 7-9. `apex`'s `smoke` preflight now includes one
additional, always-soft-pass check, `[PASS] HTB profile configured`
(informational — `APEX_HTB_OVPN_PATH` unset), and is otherwise byte-for-byte
identical to Infra Phase 9's output: 7 required checks pass, `apex` exits
`0`, no target is contacted, no secret is printed.

---

## 14. HTB mode

```bash
APEX_TOOL_SERVICE_TOKEN=<disposable> APEX_HTB_OVPN_PATH=./secrets/htb.ovpn \
  docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  up --build --abort-on-container-exit
```

Starts exactly `vpn`, `kali`, `apex` (in that dependency order —
`kali`/`apex` both `depends_on: vpn: condition: service_healthy`). `apex`'s
default command is still `smoke` (unchanged from the base file — HTB mode
does **not** override `command:`) — it performs VPN readiness/tunnel-route
checks, Kali health, and one harmless `curl --version`, **never** a live
engagement, never `--target`, never `--confirm-live`, never
`run_htb_local` — statically enforced
(`tests/docker/test_compose_htb.py::test_apex_does_not_redefine_command_or_confirm_live`).

---

## 15. Route lookup

`GET /route-check?target=<ip>` on the VPN container's readiness server
(never on `apex_tool_service`'s own API) answers "would traffic to this
target use the tunnel?" without sending a packet — `ip route get <ip>` is
a kernel routing-table lookup only. Client-side, `apex_host/eval/vpn_route_check.py`
is a **manual, operator-invoked** CLI (`python -m
apex_host.eval.vpn_route_check --vpn-service-url http://vpn:8090 --target
<ip>`) — never called by any automatic preflight path
(`tests/apex_host/test_vpn_preflight.py::test_never_calls_route_check_endpoint`
proves `run_vpn_checks` never hits `/route-check`) and never run against a
real target automatically anywhere in this codebase.

---

## 16. Secrets and ignore rules

`*.ovpn` and `secrets/` were **already** present in both `.gitignore` and
`.dockerignore` before this phase (Infra Phase 8) — no change was needed.
Verified this phase:

- `docker history --no-trunc apex-vpn:phase10 | grep -i "ovpn\|secret\|password\|token"` → **zero matches**.
- `docker run --rm --entrypoint sh apex-vpn:phase10 -c "ls -la /vpn"` → empty directory.
- No `.env`/credential file present in the built image.
- `.env.example`'s `APEX_HTB_OVPN_PATH=` is active but always blank (`tests/docker/test_env_files.py::test_htb_ovpn_path_is_active_but_blank`).

---

## 17. Docker Desktop/macOS limitations

This phase's development and validation environment is macOS with Docker
Desktop (the Linux VM it manages). `/dev/net/tun` and `NET_ADMIN` both
worked as expected inside that VM's container runtime during this phase's
testing (the entrypoint's own `_verify_tun_device()` check passed once
`--device /dev/net/tun:/dev/net/tun` was supplied, and failed clearly
when it was not — §18 scenario 6). No Docker-Desktop-specific TUN driver
issue was encountered during this phase's testing, but this has **not**
been validated against a real OpenVPN handshake — only against OpenVPN's
own config-parsing failure path (§18 scenario 5), which does not exercise
the tun device at all. An operator with a real profile should treat first
real-tunnel validation as the first real test of this specific
combination — see `docs/htb-vpn-manual-validation.md` §13 for known
Docker Desktop VPN-conflict troubleshooting (host VPN clients and
container-side OpenVPN can interact unpredictably on some Docker Desktop
network configurations).

---

## 18. Mock validation versus live validation

**Mock validation (performed this phase, real Docker, no real HTB
profile):** `compose.mock-vpn.yaml` substitutes a plain `python -m
http.server` for the real `docker/vpn/Dockerfile` build — no OpenVPN, no
`NET_ADMIN`, no `/dev/net/tun`, no real profile. Run via:

```bash
APEX_TOOL_SERVICE_TOKEN=<disposable> APEX_HTB_OVPN_PATH=/dev/null \
  docker compose -f compose.yaml -f compose.htb.yaml -f compose.mock-vpn.yaml \
  --profile htb up --build
```

**Verified live, this phase — real transcript:**

```text
vpn-1   Healthy
kali-1  Healthy
apex-1  | [PASS] configuration
apex-1  | [PASS] report directory
apex-1  | [PASS] compiled knowledge
apex-1  | [PASS] policy
apex-1  | [PASS] LLM readiness
apex-1  | [PASS] HTB profile configured
apex-1  | [PASS] remote backend selected
apex-1  | [PASS] Kali health
apex-1  | [PASS] remote tool smoke
apex-1  | [FAIL] VPN service reachable
apex-1  |        GET http://vpn:8090/health -> HTTP 404
apex-1  |
apex-1  | Preflight FAILED: 1 required check(s) failed (VPN service reachable)
```

**What this proves:** `kali` (the real, unmodified image) is reachable at
`http://vpn:8080` while sharing the mock `vpn` service's network
namespace — a real `GET /health` and a real `curl --version` executed
successfully through it (`[PASS] Kali health`, `[PASS] remote tool
smoke`). `docker inspect newapex-kali-1` showed
`NetworkMode=container:<vpn-container-id>`, `CapAdd=[]`, `User=apextool` —
namespace sharing granted zero extra privilege. Neither `kali`'s port 8080
nor the mock `vpn`'s port 8090 was published to the host (`docker compose
port` returned unbound; a direct host `curl` failed with connection
refused). `[FAIL] VPN service reachable` is **expected and correct** — the
mock deliberately does not implement the real readiness JSON contract, so
this failure proves the check is not a false positive.

**What this does NOT prove:** OpenVPN initialization, tunnel
establishment, HTB route installation, or reachability of any real HTB
target. **Never cite the mock validation above as evidence of live HTB
connectivity.**

**Live validation (NOT performed this phase — no real HTB profile was
available):** see `docs/htb-vpn-manual-validation.md` for the exact
remaining steps.

---

## 19. Cleanup

```bash
docker compose down --remove-orphans                                          # default mode
docker compose -f compose.yaml -f compose.htb.yaml --profile htb down --remove-orphans   # HTB mode
```

**Verified live, this phase**, for every scenario run: `docker ps -a
--filter name=newapex` and `docker network ls | grep apex-internal` both
confirmed nothing remained after each `down --remove-orphans`. No
`docker network prune`/`docker system prune` was used anywhere in this
phase — every cleanup was scoped to this project's own containers/network
via `down --remove-orphans` plus one targeted `docker rmi` per disposable
test image.

---

## 20. Deferred Meow diagnosis

**Not started in this phase, per its own explicit instruction.** No
Meow-specific debugging, no deterministic Meow exploitation logic, and no
machine-specific code of any kind was added anywhere in this phase — this
document and every file it describes are fully target-agnostic (CLAUDE.md
§13.8/§13.9's standing prohibition, unchanged). A real HTB engagement
against any authorized target — Meow or otherwise — requires completing
`docs/htb-vpn-manual-validation.md` first; nothing in this phase attempted
or claimed that.
