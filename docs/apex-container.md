# APEX Application Container

**Status:** Infra Phase 5 — implemented, built, and runtime-smoke-tested.
**Not yet part of any multi-container deployment** — no Docker Compose, no
Kali tool-service image, no VPN networking exists yet.
**Date:** 2026-07-14
**Files:** [`docker/apex/Dockerfile`](../docker/apex/Dockerfile),
[`.dockerignore`](../.dockerignore)

This document describes the APEX application container image built in
Infra Phase 5. Every claim below was verified by actually building the
image and running the commands shown (`docker build`, `docker run`,
`docker image inspect`, `docker history`) — see §13 for the exact commands
and §14 for what those runs produced.

---

## 1. Purpose

`docker/apex/Dockerfile` produces a reproducible, non-root, dependency-locked
container image that can run the two established APEX CLIs
(`apex_host.main`, `apex_host.eval.run_htb_local`) without requiring a local
Python environment, `uv` installation, or manual dependency setup on the
host. It is the APEX *application* image — the orchestration/planning/
policy/memory layers. It is not a server and does not expose a network
port.

---

## 2. What it contains

- First-party Python packages, installed as real (non-editable) packages
  into a virtual environment built from the committed `uv.lock`:
  `memfabric`, `apex_host`, and `apex_tool_service` (§11 explains why the
  third is unavoidably present).
- Every **runtime** dependency declared in `pyproject.toml`'s
  `[project].dependencies` (`langgraph`, `pydantic`, `numpy`, `faiss-cpu`,
  `fastapi`, `httpx`, `playwright` — the Python package only, not browser
  binaries, see §12 — etc.), installed exactly as locked.
- Two OS packages: `libgomp1` (faiss-cpu's OpenMP runtime dependency) and
  `ca-certificates` (TLS verification for outbound HTTPS calls).
- Compiled knowledge only — the four `*/compiled/` artifact directories
  (~49 MB total), never the multi-gigabyte raw corpora (§9).
- An empty, writable `/app/run_reports` directory (§10).

## 3. What it deliberately excludes

- The `dev` dependency group (`pytest`, `pytest-asyncio`, `mypy`, `ruff`,
  type stubs) — verified absent at runtime (§14).
- `uv` itself, `pyproject.toml`, `uv.lock`, and the raw first-party source
  tree — the runtime stage only copies the already-built virtual
  environment (`--no-editable` install; see §5), not the builder stage's
  working directory.
- Raw knowledge corpora: SecLists (1.9 GB), the NVD CVE raw feed (2.3 GB),
  MITRE ATT&CK/CWE/CAPEC raw downloads, GTFOBins/LOLBAS/PayloadsAllTheThings
  vendored repositories, raw methodology PDFs, raw HTB legal-policy PDFs —
  none of this ever reaches the Docker build context at all (excluded in
  `.dockerignore`), let alone the image.
- Kali/offensive security tools (`nmap`, `telnet`, `nc`, `hydra`,
  `gobuster`, `ffuf`) — never installed; verified absent at runtime (§14).
  Every generic command APEX executes goes through the pluggable
  `ToolBackend` abstraction (`docs/tool-execution-architecture.md`); the
  binaries themselves belong only to the future Kali tool-service image
  (Infra Phase 6).
- Secrets, `.env` files, VPN configuration (`.ovpn`), private keys — none
  exist anywhere in this repository today, and `.dockerignore` excludes
  the relevant patterns defensively regardless.
- `.git`, `.github`, test suites, documentation, examples, build/test
  caches, IDE metadata, OS artifacts (`.DS_Store`).
- A real browser binary (Chromium) — see §12.

---

## 4. Build command

Build from the **repository root** (the Dockerfile expects the full
project layout as its build context):

```bash
docker build -f docker/apex/Dockerfile -t apex:phase5 .
```

BuildKit (Docker's default builder since Docker Desktop 23+) is used
automatically; no special flags are required. A `docker buildx version`
check was performed during this phase (`v0.22.0-desktop.1`) to confirm
buildx is available, though the plain `docker build` invocation above is
sufficient — no multi-platform build was requested in this phase.

---

## 5. Image design

### Base image

`python:3.11.14-slim-bookworm`, pinned **by digest**
(`@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d`
— the manifest-list digest, verified via `docker buildx imagetools inspect`
during this phase so it resolves correctly on any platform, not just the
build machine's own architecture). Never `latest`, never a floating
`3.11`/`3-slim` tag. `3.11.14` matches the exact patch version this project
has been developed and tested against in every prior Infra Phase
(`.python-version` pins `3.11`; the dev venv is `3.11.14`). Debian
"bookworm" slim was chosen over Alpine specifically because Alpine's musl
libc has a history of subtle incompatibility with scientific-Python wheels
(`numpy`, `faiss-cpu`) that Debian's glibc does not share.

### Multi-stage strategy

```text
uv     (ghcr.io/astral-sh/uv:0.11.28, digest-pinned) — binary source only
  ↓
builder (python:3.11.14-slim-bookworm) — uv sync --frozen, builds the venv
  ↓
runtime (python:3.11.14-slim-bookworm) — copies only the finished venv
```

The `uv` executable is copied from Astral's own minimal distribution image
(`COPY --from=uv /uv /usr/local/bin/uv`) — no `curl | sh` install script,
no `pip install uv` bootstrap.

### uv installation strategy

Two-step `uv sync` in the builder, chosen specifically for Docker layer
caching:

1. `COPY pyproject.toml uv.lock ./` then `uv sync --frozen --no-dev
   --no-install-project` — installs every third-party dependency, but not
   the project itself. This is the slow layer (faiss-cpu, numpy, playwright,
   langgraph, ... — about two minutes on a cold cache in this phase's build);
   it is only invalidated when `pyproject.toml`/`uv.lock` actually change.
2. `COPY memfabric apex_host apex_tool_service` then `uv sync --frozen
   --no-dev --no-editable` — builds and installs the three first-party
   packages as real, self-contained site-packages entries (not an editable
   link back to `/app`).

`--frozen` means the build **fails** if `pyproject.toml` and `uv.lock` are
inconsistent — confirmed by design (this is `uv sync`'s documented
behavior for `--frozen`; no separate failure-path test was added since it
would require deliberately corrupting the committed lock file to
demonstrate, which is out of scope for a "leave the repo working"
constraint). No `uv lock` (which would regenerate the lock file) appears
anywhere in the Dockerfile — statically enforced by
`tests/docker/test_apex_dockerfile.py::test_lock_file_not_regenerated_in_image`.

### Runtime dependency strategy

Because the project install uses `--no-editable`, the runtime stage needs
**only** the finished `/app/.venv` directory — not `pyproject.toml`,
`uv.lock`, `uv` itself, or the raw source tree. This is a deliberately
minimal runtime stage: no build toolchain, no dependency-resolution
metadata, no first-party source files outside what's already inside
`site-packages`.

### Filesystem layout

```text
/app/.venv/           the complete virtual environment (deps + first-party packages)
/app/knowledge/        compiled knowledge only (§9) — intel_db, methodology_db, payload_db, policy_db
/app/run_reports/      empty, writable — mount point for --export-json / --export-graph output
```

### Non-root user

`apex`, UID/GID 1000 (explicit, not `--system` — see the Dockerfile's own
comment for why `--system` together with an explicit UID ≥ 1000 produces a
spurious `useradd` warning without changing anything meaningful). No
password, no login shell (`/usr/sbin/nologin`), no `sudo`, no home
directory created. `USER apex` is the last user-setting directive before
`CMD`, so every process the container runs — including the default
`--help` invocation and any operator-supplied override — runs as this
account. Verified: `docker run --rm apex:phase5 id` →
`uid=1000(apex) gid=1000(apex) groups=1000(apex)`.

### Startup command

```dockerfile
CMD ["python", "-m", "apex_host.main", "--help"]
```

Prints CLI usage and exits 0. Requires no API key, no HTB VPN, no remote
tool service, and — because `--target` is a required argument on both
`apex_host.main` and `apex_host.eval.run_htb_local` — even an operator who
overrides this default with the bare module (no `--help`) gets a fast,
safe `argparse` usage error, never an accidental live engagement. No
`ENTRYPOINT` is set, so `docker run apex:phase5 <anything>` cleanly
replaces the whole command (matching every smoke-test invocation in §14).

### Knowledge strategy

See §9 for the full investigation and rationale; summary: bake in the
~49 MB of compiled knowledge, exclude the ~4.3 GB of raw corpora entirely.

### Report strategy

See §10.

---

## 6. `.dockerignore`

### Important exclusions

- **Version control / caches:** `.git`, `.github`, `.venv`, `__pycache__`,
  `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.coverage`, `htmlcov`,
  `build`, `dist`, `*.egg-info`.
- **Secrets (defensive — none exist in this repo today):** `.env`,
  `.env.*`, `*.ovpn`, `secrets/`, `*.pem`, `*.key`.
- **Local/ephemeral:** `run_reports` (the image creates its own empty one),
  `*.log`, `.DS_Store`.
- **Not required at runtime:** `tests`, `docs`, `README.md`, `CLAUDE.md`,
  `APEX-Nexus-Unified-Architecture-Detailed.md`, `Makefile`, `examples`.
- **Raw knowledge corpora** (§9): `Knowledge/payload_db/{SecLists,
  PayloadsAllTheThings,GTFOBins,LOLBAS}`, `Knowledge/intel_db/{cve,cwe,
  capec,attack}`, `Knowledge/methodology_db/*.pdf`,
  `Knowledge/policy_db/sources`, plus generic archive/cache patterns under
  `Knowledge/**`.

### Confirmation: required runtime files remain included

`pyproject.toml`, `uv.lock`, `memfabric/`, `apex_host/`,
`apex_tool_service/`, and all four `Knowledge/*/compiled/` directories are
**never** matched by any exclusion pattern — verified both by manual
review (documented in the `.dockerignore` file's own trailing comment
block) and by
`tests/docker/test_apex_dockerfile.py::test_dockerignore_does_not_exclude_required_runtime_files`
/ `::test_dockerignore_does_not_exclude_compiled_knowledge`, and empirically
by the successful build + the in-container knowledge-verification smoke
test (§14.8), which would fail immediately if any compiled file were
missing.

`.python-version` is not excluded, but is also never `COPY`-ed by the
Dockerfile (the build uses the base image's system Python directly via
`UV_PYTHON_DOWNLOADS=never`), so its presence or absence in the build
context has no effect either way.

---

## 7. Non-root user

Covered in §5. UID 1000, GID 1000, no privileged Linux capabilities were
added (none were ever granted — the Dockerfile never issues a `--cap-add`-
equivalent instruction, and Docker containers drop most capabilities by
default), no Docker socket is mounted or referenced anywhere in the image
(`docker.sock` appears nowhere in the Dockerfile — verified by
`tests/docker/test_apex_dockerfile.py::test_no_docker_socket_reference`).

---

## 8. Filesystem paths

See §5 "Filesystem layout." `/app/knowledge` is the conventional path an
operator should pass to `--knowledge-root` when running the image
(`--knowledge-root /app/knowledge`); it is not passed automatically — the
default `CMD` does not reference it, and `ApexConfig.knowledge_root`
defaults to `None` (no knowledge loaded) unless a caller explicitly opts
in. `/app/run_reports` is intended as a bind-mount or named-volume target
for a future Compose phase; nothing in `apex_host` writes there unless the
operator passes `--export-json`/`--export-graph` with a path under it.

---

## 9. Knowledge strategy

**Investigation performed this phase** (see the Dockerfile's own inline
comment for the same finding, recorded at the point it matters):

- `du -sh Knowledge` on the local checkout: **4.3 GB** total.
- `du -sh Knowledge/*/compiled`: **~49 MB** total (37 MB intel_db, 11 MB
  payload_db, 32 KB policy_db, 4 KB methodology_db).
- The largest single contributors to the 4.3 GB are
  `Knowledge/payload_db/SecLists` (1.9 GB) and `Knowledge/intel_db/cve`
  (2.3 GB, the raw NVD feed) — both raw, vendored/downloaded corpora that
  `apex_host/knowledge/compiler/` already distills into the compact
  `compiled/*.jsonl` files the loader actually reads at runtime
  (`apex_host/knowledge/compiled_loader.py`).
- **Casing discovery:** the git-tracked directory is `Knowledge/` (capital
  K) — confirmed via `git ls-files | ... | sort -u` returning only
  `Knowledge`, never `knowledge`. This directly contradicts CLAUDE.md §18's
  claim that "the real on-disk directory is `knowledge/` (all lowercase,
  no typo)." That claim is only true on a case-**insensitive** filesystem
  (macOS/APFS, where `Knowledge` and `knowledge` resolve to the same inode
  — verified via `os.stat().st_ino` during this phase's investigation); on
  the case-**sensitive** Linux filesystem a Docker build/runtime actually
  uses, only `Knowledge/` (capital K) exists. This phase's Dockerfile
  `COPY` instructions therefore reference the source path as `Knowledge/`
  (matching git), while the destination inside the image is deliberately
  `/app/knowledge/` (lowercase, matching every documented
  `--knowledge-root` CLI example in this repository) — see the Dockerfile's
  own comment for the full explanation. CLAUDE.md is updated (§ "Infra
  Phase 5") to record this correction without rewriting the original §18
  text (append-only convention).

**Decision:** bake in the four `compiled/` directories (~49 MB — small,
deterministic, git-tracked, reasonable for a container image) rather than
requiring a mount. `--knowledge-root` remains fully operator-controlled —
nothing forces its use, and an operator who wants fresher or different
knowledge can still bind-mount a different directory over `/app/knowledge`
at `docker run` time (untested in this phase, since no Compose/orchestration
work was in scope, but the path is a plain directory with no image-layer
magic preventing a mount override).

---

## 10. Report-output strategy

`/app/run_reports` is created empty and owned by `apex:apex` at build
time. Verified writable by the non-root runtime user:
`docker run --rm apex:phase5 sh -c 'touch /app/run_reports/container-write-test && test -f ...'`
→ succeeds (§14.5). Reports are never written here automatically — both
`--export-json` and `--export-graph` are opt-in CLI flags on
`apex_host.eval.run_htb_local`; the safe default `CMD` (`--help`) writes
nothing.

---

## 11. Remote tool-service relationship

The APEX image does **not** start `apex_tool_service` — no `CMD` or
`ENTRYPOINT` in `docker/apex/Dockerfile` references it (statically
enforced by `tests/docker/test_apex_dockerfile.py::test_does_not_start_the_tool_service`).
`apex_tool_service`'s Python source **is** copied into the builder stage
and **is** installed into the shared virtual environment, because it is a
package of the same Hatchling distribution as `memfabric`/`apex_host`
(`[tool.hatch.build.targets.wheel] packages = [...]` in `pyproject.toml`
lists all three) — `uv sync`'s project-install step cannot build a wheel
for this distribution with only two of its three declared packages present.
This is the exact situation this phase's own task brief anticipated
("include `apex_tool_service` only if it is installed as part of the same
Python distribution and cannot cleanly be excluded"). The APEX application
talks to a *remote* tool-service instance over HTTP via
`apex_host.tools.remote_backend.RemoteToolBackend` (Infra Phase 4) — it
never imports or runs `apex_tool_service.app` locally. The Kali
tool-service **image** (which would actually run
`python -m apex_tool_service`) is Infra Phase 6 — not built here.

---

## 12. Browser / Playwright limitation

The `playwright` **Python package** is a runtime dependency
(`pyproject.toml`) and is installed in this image, because
`apex_host.agents.browser_executor.BrowserExecutor` imports it (lazily,
inside a function body — see `apex_host/agents/browser_executor.py`).
**No browser binary was installed** (`playwright install chromium` /
`playwright install-deps` were never run) — verified by inspecting the
image size (688 MB total; a Chromium download alone is typically
300+ MB, and installing it would also require several additional
`apt-get` OS packages for headless rendering that this image does not
have). `BrowserExecutor` only reaches its Playwright import when
`config.dry_run=False` (live mode); in dry-run — the default — it returns
a synthetic observation and never touches Playwright at all. **Practical
consequence:** running this image with `--no-dry-run` against a task that
reaches the browser phase will fail when `BrowserExecutor` attempts to
launch Chromium, because no browser binary is present. This is a
deliberate, documented limitation — installing a real browser bundle is a
separate future decision (would meaningfully increase image size and OS
package surface) that this phase does not make. Dry-run engagements are
entirely unaffected.

---

## 13. Local smoke-test commands

```bash
# Build
docker build -f docker/apex/Dockerfile -t apex:phase5 .

# Inspect
docker image inspect apex:phase5
docker history --no-trunc apex:phase5

# Main CLI help
docker run --rm apex:phase5 python -m apex_host.main --help

# HTB runner help
docker run --rm apex:phase5 python -m apex_host.eval.run_htb_local --help

# Imports
docker run --rm apex:phase5 python -c "import apex_host, memfabric; print('imports-ok')"

# Non-root
docker run --rm apex:phase5 id

# Writable report directory
docker run --rm apex:phase5 sh -c \
  'touch /app/run_reports/container-write-test && test -f /app/run_reports/container-write-test'

# Knowledge verification
docker run --rm apex:phase5 python -m apex_host.knowledge.compiler.verify_compiled \
  --knowledge-root /app/knowledge

# Offensive-tool absence
docker run --rm apex:phase5 sh -c \
  "for t in nmap telnet nc hydra gobuster ffuf; do command -v \$t || echo \"absent: \$t\"; done"
```

Exact results from this phase's own run of every command above are
recorded in the Phase 5 final report (not duplicated here to avoid drift —
this document describes the *commands*, the report captures the *point-in-
time results*).

---

## 14. Security properties

- **Non-root runtime:** `USER apex` (UID 1000), verified via `docker run
  --rm apex:phase5 id`.
- **No secrets copied:** no `.env`, `.ovpn`, private key, or credential
  file exists anywhere in this repository, and `.dockerignore` excludes
  the relevant patterns regardless. `docker history --no-trunc` was
  inspected for any `.env`/`.ovpn`/token-shaped string and found clean.
  The only `.pem` file present in the image filesystem is
  `certifi`'s public CA bundle (`cacert.pem`) — a legitimate runtime
  dependency artifact, not a secret.
- **No Docker socket:** `docker.sock` appears nowhere in the Dockerfile;
  no privileged capability is added; the container has no ability to
  control other containers or the host Docker daemon.
- **No Kali/offensive tools:** `nmap`, `telnet`, `nc`, `hydra`,
  `gobuster`, `ffuf` all confirmed absent from `PATH` inside a running
  container.
- **No live-engagement default:** the default `CMD` requires no
  credentials, starts no network activity, and does not begin an
  engagement merely because the container starts.
- **Locked dependency installation:** `uv sync --frozen` — the build fails
  outright if `pyproject.toml`/`uv.lock` ever drift apart; no
  `pip install -r requirements.txt`, no unlocked dependency resolution
  inside the image.
- **Dev tooling absent:** `pytest`, `ruff`, `mypy` all confirmed
  `importlib.util.find_spec(...) is None` inside a running container.

---

## 15. Current limitations

- No digest pinning verification is automated (the digests in the
  Dockerfile were captured once, by hand, during this phase — see §5).
  Re-pinning after a future intentional base-image bump is a manual step.
- No multi-platform (`--platform linux/amd64,linux/arm64`) build was
  performed in this phase — only the local build machine's native
  platform (`linux/arm64`, since this development machine is Apple
  Silicon) was built and tested. The digest-pinned `FROM` lines resolve
  correctly for either platform (both are OCI image indexes), but only one
  platform was actually built and smoke-tested here.
- No automated CI step builds or scans this image yet (CI publishing is a
  later, explicitly deferred phase — see §16 below).
- No image vulnerability scan (`docker scout`, `trivy`, or equivalent) was
  run in this phase.
- `RemoteToolBackend` inside this image has only ever been exercised
  in-process (Infra Phase 4's own tests) — it has never made a real
  network call from *inside a running container* to a tool-service
  instance, because that service does not have a container image yet
  (Infra Phase 6).

---

## 16. Deferred Kali image

Not started. The Kali tool-service (`apex_tool_service`) container image —
installing real `nmap`/`curl`/`nc`/etc. binaries and running
`python -m apex_tool_service` as its entrypoint — is Infra Phase 6.

## 17. Deferred Docker Compose

Not started, and explicitly out of scope for this phase. No
`docker-compose.yml` (or equivalent) exists. Wiring the APEX image and a
future Kali image together on an isolated network, with the operational
`run_htb_local` command as the actual Compose service command, is a later
phase.

## 18. Deferred VPN and Meow validation

Not started. No VPN container, no VPN networking configuration, no
Meow-specific diagnosis, no deterministic Meow test, and no authorized
live Meow validation exist inside or alongside this image. This phase
built and smoke-tested the APEX application container only — running it
against any real target (authorized or otherwise) was not attempted.
