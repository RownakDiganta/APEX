# HTB VPN Manual Validation

This document provides the exact steps **you** (a human operator with a
real, authorized HTB account) must perform to validate live HTB VPN
connectivity. **Claude Code cannot and did not perform these steps** — no
real HTB profile was available in the Infra Phase 10 development
environment, and none of the commands below were executed automatically
on your behalf. Follow them yourself, in order, and stop immediately if
any step's expected result does not match what you actually see.

See [`docs/htb-vpn-container.md`](htb-vpn-container.md) for the full
architecture this validates.

---

## Before you start

- You must have an active, authorized Hack The Box account with VPN
  access to a lab you are permitted to test (Starting Point, a Machines
  subscription, a CTF event you are registered for, etc.).
- **Never** run any `--no-dry-run`/`run`/live command against a target you
  do not own or have explicit written authorization to test (CLAUDE.md
  §12.3, unchanged and binding here).
- You will need Docker Desktop (or an equivalent Docker Compose v2
  environment) running locally.

---

## 1. Download a fresh HTB Machines `.ovpn` profile

Log in to the HTB web UI, navigate to **Access** (or **Starting
Point**/**Machines**, depending on which product you're using), and
download the `.ovpn` profile for the specific lab/VPN server you intend to
use. HTB profiles are region- and product-specific — make sure you
download the one matching the machine you actually intend to start.

**Expected result:** a file named something like `lab_yourusername.ovpn`
or `starting_point_yourusername.ovpn` downloads to your machine.

---

## 2. Store it under the gitignored `secrets/` directory

```bash
mkdir -p secrets
mv ~/Downloads/lab_yourusername.ovpn secrets/htb.ovpn
```

**Expected result:** `git status` shows nothing new (the `secrets/`
directory and `*.ovpn` files are already gitignored — verified by
`tests/docker/test_env_files.py`). Confirm yourself:

```bash
git check-ignore -v secrets/htb.ovpn
# should print a match against the *.ovpn or secrets/ rule in .gitignore
```

**Never commit this file.** If `git status` ever shows it as untracked-but-
stageable, stop and re-check your `.gitignore` before proceeding.

---

## 3. Set only the path in `.env`

```bash
cp .env.example .env   # if you haven't already
```

Edit `.env` and set:

```dotenv
APEX_HTB_OVPN_PATH=./secrets/htb.ovpn
APEX_TOOL_SERVICE_TOKEN=<generate your own — see .env.example's own instructions>
```

Leave `APEX_TARGET` **blank** for now — you don't have a machine IP yet
(that comes in step 8, and it changes every time a machine restarts, see
step 9).

**Expected result:** `.env` (not `.env.example`) now contains your real,
local path and token. Confirm it's still ignored:

```bash
git check-ignore -v .env
```

---

## 4. Start the VPN profile

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  up --build --abort-on-container-exit
```

This starts `vpn` → `kali` (sharing `vpn`'s namespace) → `apex` (runs
`smoke` mode: local config checks, VPN readiness, Kali health, one
harmless `curl --version`). **This does not start an engagement and does
not contact any HTB machine target** — it only starts the tunnel and
verifies infrastructure readiness.

**Expected result:** all three containers report healthy in sequence;
`apex`'s final line is either `Preflight passed: N required check(s)` (if
the tunnel came up before `apex`'s bounded readiness checks ran) or a
`[FAIL] VPN tunnel/route ready` line (if OpenVPN was still negotiating —
this is a *timing* issue, not necessarily a failure; see step 6/13 below).

---

## 5. Inspect VPN logs for successful initialization

In a second terminal, while the environment from step 4 is running:

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb logs vpn
```

**Expected result:** OpenVPN's own log lines, ending with something like:

```text
Initialization Sequence Completed
```

If instead you see `AUTH_FAILED`, `TLS Error`, or a repeated retry loop,
your profile may be expired, region-mismatched, or your HTB VPN session
may already be active elsewhere (HTB profiles are typically single-session)
— see the troubleshooting table (§13).

---

## 6. Check service health

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb ps
```

**Expected result:** `vpn` and `kali` both show `(healthy)`. If `vpn`
shows `(unhealthy)` or `(health: starting)` for more than ~30 seconds
past what step 5's log showed as "Initialization Sequence Completed,"
something is wrong with the readiness server's own route detection (not
necessarily the tunnel itself) — check `docker compose ... logs vpn` for
`vpn_readiness` log lines.

---

## 7. Check tunnel/route presence

```bash
curl -s http://127.0.0.1:8090/health 2>&1 || echo "expected: connection refused, vpn is not published to the host — this confirms it correctly, see below"
```

The command above is **expected to fail** — `vpn`'s readiness server is
never published to the host (by design, `docs/htb-vpn-container.md` §13).
To actually query it, run the check from *inside* the Compose network:

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  exec apex python -m apex_host.eval.vpn_route_check \
  --vpn-service-url http://vpn:8090 --target 10.129.5.5
```

(Replace `10.129.5.5` with any placeholder IP for now — you just want to
confirm the readiness server itself responds; you'll use a real machine IP
in step 10.)

**Expected result:** structured output including `lookup ok: True` and
`device: tun0` (or whatever interface name your profile's OpenVPN
negotiated) if the tunnel is up, or a clear `error:` field if not.

---

## 8. Start a specific authorized HTB machine

In the HTB web UI, start the specific machine you are authorized to test
(e.g. via the **Starting Point** or **Machines** dashboard). Wait for HTB
to report it as running/ready — this can take 1-2 minutes.

**Expected result:** the HTB UI shows the machine's status as "Running"
and displays its current IP address.

---

## 9. Copy its current IP into `APEX_TARGET`

Copy the IP address HTB's UI shows for the machine you just started into
your `.env` file:

```dotenv
APEX_TARGET=10.129.XXX.XXX
```

**This IP changes every time the machine is reset or restarted** — if you
stop and later restart the same machine, re-check the UI and update this
value again. A stale IP is one of the most common sources of confusing
"unreachable" results (see §13).

---

## 10. Use route lookup before sending traffic

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  exec apex python -m apex_host.eval.vpn_route_check \
  --vpn-service-url http://vpn:8090 --target <the-real-machine-IP-from-step-9>
```

**Expected result:** `would use route: True` and a tunnel-shaped `device`
(e.g. `tun0`). If `would_use_route` is `False`, the CIDR the tunnel
installed doesn't match what you expected — check `docker compose ... exec
vpn ip route show` directly, and adjust `APEX_HTB_ROUTE_CIDR` in `.env` if
your specific HTB profile/region genuinely uses a different private range
than `10.129.0.0/16` (uncommon, but not impossible — HTB has used other
ranges for specific events).

**This step sends no packet** — it is a routing-table lookup only. It
does **not** by itself prove the target host is currently reachable
(a route can exist to a host that is powered off, still booting, or
network-isolated for another reason) — that's step 11.

---

## 11. Perform a minimal reachability check from Kali

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  exec kali sh -c "which ping && ping -c 2 -W 2 <the-real-machine-IP>"
```

**Expected result:** 2 ICMP replies. Some HTB machines/firewalls block
ICMP — a failure here does not necessarily mean the machine is
unreachable for other protocols. If you need a TCP-level check instead,
use the same `docker compose ... exec kali` pattern with `nc -zv -w 2
<IP> <port>` against a port you already know should be open (or run a
real `nmap -sT` scan through the normal APEX engagement flow once you're
ready to actually begin working the machine — that is a separate,
deliberate step, not part of this readiness validation).

---

## 12. Stop and clean up only project containers

```bash
docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  down --remove-orphans
```

**Do not** run `docker network prune` or `docker system prune` — those
affect resources outside this project. The command above removes exactly
the `apex`/`kali`/`vpn` containers and the `apex-internal` network this
project created.

Also disconnect your own host machine's network monitoring/VPN clients if
you started them separately for troubleshooting (see §13's last row) —
they are not managed by Compose and `down` does not touch them.

---

## 13. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `/dev/net/tun not found` at `vpn` container startup | Docker wasn't given the device, or you're on a Docker runtime that doesn't expose it the same way | Confirm `compose.htb.yaml`/`compose.yaml` still declare `devices: ["/dev/net/tun:/dev/net/tun"]`; on some Docker Desktop versions, restarting Docker Desktop resolves stale device-passthrough state |
| Docker Desktop networking oddities (containers can't resolve each other, health checks time out) | Docker Desktop's VM networking occasionally needs a restart after sleep/wake cycles | Restart Docker Desktop, then re-run `docker compose ... down --remove-orphans` followed by a fresh `up` |
| `vpn` container healthy but `route_present: false` | Tunnel is up but hasn't installed the expected route yet, or your profile uses a non-default range | Wait a few more seconds and re-check; if it persists, run `docker compose ... exec vpn ip route show` directly and compare against `APEX_HTB_ROUTE_CIDR` |
| Stale target IP / "unreachable" after working fine before | HTB machine was reset/restarted and got a new IP | Re-check the HTB UI (step 8/9) and update `APEX_TARGET` |
| Machine shows as reachable in route lookup but `ping`/`nc` both fail | Machine not fully booted yet, or ICMP/the specific port is filtered | Wait 1-2 minutes after HTB reports "Running"; try a TCP port check instead of ICMP |
| Profile expired or wrong HTB region | HTB profiles can expire or be tied to a specific VPN server/region | Re-download a fresh `.ovpn` from the HTB UI (step 1) |
| `AUTH_FAILED` in `vpn` container logs | HTB VPN sessions are typically single-session — you may already be connected elsewhere (another machine, your host's own OpenVPN client, a previous container that wasn't cleaned up) | Disconnect any other active session for this profile, then retry |
| You also have a host-level VPN client (HTB's own desktop app, or a manually-run `openvpn` on your Mac) running at the same time | Simultaneous host-level and container-level VPN sessions against the same HTB profile will conflict (single-session limit) or cause routing confusion even if HTB allowed it | Use exactly one — either the container (this workflow) or a host-level client, never both against the same profile at the same time |

---

## Important reminders

- **The `.ovpn` file must never be committed.** Re-verify with
  `git status`/`git check-ignore` after every session.
- **The target IP changes when machines are reset or restarted.** Always
  re-confirm it in the HTB UI before assuming a stale value is still
  correct.
- **Successful OpenVPN initialization (step 5) does not by itself prove
  the target is currently reachable.** Complete steps 10 and 11 before
  assuming connectivity.
- **No exploitation should begin until route lookup (step 10) and minimal
  connectivity (step 11) are both validated.** Jumping straight to a full
  engagement without these checks risks wasting time diagnosing what is
  actually an infrastructure problem, not a target problem.
- Once all of the above genuinely pass against a real HTB target, you have
  what Infra Phase 10's own completion criteria call "live validation" —
  record what you found (which steps passed, the actual `ip route`
  output, actual ping/nc results) if you want a durable record; this
  document does not do that recording for you.
