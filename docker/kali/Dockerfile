# Dockerfile
# Multi-stage build for the Kali Linux tool-execution appliance (Infra Phase 6) — runs only apex_tool_service, a restricted allowlisted tool-execution HTTP boundary; non-root; no APEX orchestration, no knowledge corpora, no VPN.
#
# Build from the REPOSITORY ROOT (not this directory), so the build context
# includes pyproject.toml, uv.lock, and the first-party packages:
#
#   docker build -f docker/kali/Dockerfile -t apex-kali:phase6 .
#
# This image is a controlled tool appliance, not an interactive Kali
# desktop: it installs a small, evidence-justified set of network/recon
# binaries, starts nothing but the restricted `apex_tool_service` HTTP API,
# and every execution it performs still passes through that service's own
# allowlist/validation/auth layer (apex_tool_service/{allowlist,validation,
# auth}.py) — this Dockerfile does not, and cannot, bypass that boundary.
#
# See docs/kali-container.md for the full design rationale, the installed
# tool manifest with evidence, Linux-capability findings (nmap's default/
# SYN scan modes are NOT usable by the non-root service user without an
# explicit Compose-phase `--cap-add=NET_RAW`; only `nmap -sT` and `ping`
# work unprivileged out of the box — see docs/kali-container.md §14), and
# what remains deferred to a future Compose/VPN phase.

# ---------------------------------------------------------------------------
# Pinned tool image: uv's own official static-binary distribution (the same
# digest pin used by docker/apex/Dockerfile, Infra Phase 5) — copies only
# the `uv` executable into the builder stage below. No curl|sh install, no
# pip bootstrap.
# ---------------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa AS uv

# ---------------------------------------------------------------------------
# Base image: the OFFICIAL Kali Linux rolling image (`kalilinux/kali-rolling`
# on Docker Hub), pinned by content digest rather than a floating tag.
# Kali rolling has no versioned release-tag scheme at all (unlike Debian's
# bookworm/bullseye or Ubuntu's 22.04/24.04), so a digest pin is the only
# reproducible reference available — this is NOT a substitute for a
# community-maintained/unofficial image; it is the official image, pinned.
#
# Digest verified on 2026-07-15 via:
#   docker pull kalilinux/kali-rolling
#   docker buildx imagetools inspect kalilinux/kali-rolling@sha256:8a1ea728...
# confirming a genuine multi-platform manifest list (linux/amd64,
# linux/arm64, linux/arm/v7, linux/386) published under the official
# `kalilinux` Docker Hub organization.
#
# DOCUMENTED LIMITATION — APT package versions are NOT pinned. The base
# filesystem digest below is fixed and reproducible, but every
# `apt-get install` in this file resolves against Kali's live rolling
# repositories at build time. Re-running this exact `docker build` on a
# different day can install different nmap/curl/telnet/netcat-openbsd
# versions even though `FROM kalilinux/kali-rolling@sha256:...` never
# changes. This is inherent to Kali's rolling-release model (there are no
# dated snapshot repositories analogous to Debian snapshot.debian.org
# configured here). See docs/kali-container.md "Base image" for the full
# discussion and what a future phase could do about it (e.g. a vendored
# apt snapshot mirror) — not attempted in this phase.
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling@sha256:8a1ea7281085ffef4963e82766c70869d7db910df88dcbb1f03d2899420b9577 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# ca-certificates: required for uv's own HTTPS fetches below (the managed
# Python interpreter download, and PyPI wheel downloads via `uv sync`).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv

# ---------------------------------------------------------------------------
# Python provisioning strategy: a uv-*managed* (python-build-standalone)
# CPython, deliberately NOT Kali's own apt `python3` package.
#
# Why: `apex_tool_service` is packaged in the same Hatchling distribution as
# `apex_host`/`memfabric` (see [tool.hatch.build.targets.wheel].packages in
# pyproject.toml — all three are one project, one dependency graph). `uv
# sync` therefore installs the FULL dependency set (numpy, faiss-cpu,
# langgraph, playwright, hnswlib-adjacent build chain, ...) even though this
# image only ever runs `apex_tool_service`, which itself needs only fastapi/
# uvicorn/pydantic/httpx. This is an acknowledged, documented packaging
# limitation (see docs/kali-container.md "Packaging limitations") — a
# broader package split was considered and deliberately NOT performed in
# this phase, per this phase's own task brief.
#
# Kali rolling ships a bleeding-edge, frequently-changing `python3` version
# with no stable pin. Several of the heavy scientific dependencies pulled in
# above (faiss-cpu, numpy) do not reliably publish prebuilt manylinux wheels
# for every brand-new CPython release the instant it lands in Kali's repos —
# using Kali's own python3 would risk `uv sync` falling back to a
# from-source build, which would require installing a full C/C++ compiler
# toolchain (cmake, g++, ...), directly contradicting this phase's own
# "avoid unnecessary compilers/build tools" requirement, and would make
# build success dependent on Kali's upstream Python version at the moment
# of each rebuild.
#
# The uv-managed interpreter avoids all of that: it is pinned to the exact
# same 3.11.14 patch version used by docker/apex/Dockerfile (Infra Phase 5)
# and this project's own `.python-version`, is a portable/relocatable Linux
# build (python-build-standalone), and is copied byte-for-byte into the
# runtime stage below at the same absolute path — so the copied venv's
# `bin/python3` symlink resolves correctly with zero dependency on whatever
# python3 package (if any) Kali's own apt repos happen to offer that day.
# ---------------------------------------------------------------------------
ENV UV_PYTHON_INSTALL_DIR=/opt/uv-python \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

RUN uv python install 3.11.14

ENV UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=3.11.14

# --- Dependency layer (cached independently of application source) --------
COPY pyproject.toml uv.lock ./

# --frozen: fail the build if pyproject.toml/uv.lock are inconsistent.
# --no-dev: exclude pytest/ruff/mypy/type-stubs — none belong in this image.
# --no-install-project: third-party dependencies only in this layer.
RUN uv sync --frozen --no-dev --no-install-project

# --- Project layer ----------------------------------------------------
# memfabric/apex_host are copied and installed alongside apex_tool_service
# only because Hatchling's current [tool.hatch.build.targets.wheel]
# packages list bundles all three as one distribution (see the comment
# block above) — this Dockerfile's runtime stage never starts, imports at
# module-execution time, or exposes anything from apex_host/memfabric; no
# CMD/ENTRYPOINT here ever invokes them.
COPY memfabric ./memfabric
COPY apex_host ./apex_host
COPY apex_tool_service ./apex_tool_service

# --no-editable: install real, self-contained copies into site-packages
# rather than an editable link back to /app — only the resulting virtual
# environment is copied into the runtime stage, not this source tree.
RUN uv sync --frozen --no-dev --no-editable


# ---------------------------------------------------------------------------
# Runtime stage — the official Kali Linux rolling base again (same digest
# pin as the builder stage), with only the tool-service's own allowlisted
# binaries installed. No build toolchain, no uv, no dev dependencies, no
# first-party source tree, no Kali metapackages, no offensive frameworks.
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling@sha256:8a1ea7281085ffef4963e82766c70869d7db910df88dcbb1f03d2899420b9577 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# Installed tool manifest — every entry below maps 1:1 to a key in
# `apex_tool_service/allowlist.py::ALLOWED_TOOLS`. No tool is installed
# without a corresponding allowlist entry, and no allowlist entry is left
# without an installed binary (see docs/kali-container.md §3 for the full
# evidence table). Explicitly NOT installed: `kali-linux-default`,
# `kali-linux-large`, `kali-linux-everything`, `metasploit-framework`,
# `sqlmap`, `hydra`, `gobuster`, `ffuf`, `nikto`, `whatweb`, `masscan`,
# `john`, `hashcat`, `telnetd` (the Telnet *server* — only the client
# `telnet` package is installed), `openssh-server`, any Docker/container
# client, `sudo`, and `iproute2` (no `apex_tool_service` allowlist entry
# maps to it; base container networking does not require the `ip` binary).
#
#   nmap             -> allowlist "nmap"     (apex_host/tools/registry.py;
#                        ReconPlanner; NmapParser)
#   curl              -> allowlist "curl"     (apex_host/tools/registry.py;
#                        WebPlanner; CommandParser)
#   iputils-ping      -> allowlist "ping"     (provides /usr/bin/ping)
#   netcat-openbsd    -> allowlist "nc" AND "netcat" — ONE package provides
#                        BOTH binaries via update-alternatives symlinks to
#                        the same nc.openbsd executable (verified empirically
#                        this phase; see docs/kali-container.md §3)
#   telnet            -> allowlist "telnet"   (client only; telnetd is a
#                        separate, NOT installed, package)
#   ca-certificates   -> TLS trust store for curl's/tool-service's outbound
#                        HTTPS calls (not itself an allowlisted "tool")
# ---------------------------------------------------------------------------
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        iputils-ping \
        netcat-openbsd \
        telnet \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged user/group, explicit UID/GID 1000 (matching the
# convention already used by docker/apex/Dockerfile's `apex` user). No
# password, no shell (nologin), no sudo, no passwordless privilege
# escalation of any kind — this account exists solely to run
# `apex_tool_service` and the tool subprocesses it spawns on the caller's
# behalf.
RUN groupadd --gid 1000 apextool \
    && useradd --uid 1000 --gid apextool --no-create-home --home-dir /app --shell /usr/sbin/nologin apextool

WORKDIR /app

# The uv-managed interpreter (see the builder-stage comment above) and the
# prepared virtual environment — copied byte-for-byte at the same absolute
# paths they were built at, so the venv's bin/python3 symlink resolves
# without needing Kali's own apt python3 package in this stage at all.
COPY --from=builder /opt/uv-python /opt/uv-python
COPY --from=builder --chown=apextool:apextool /app/.venv /app/.venv

# Narrowly-scoped support file (see docker/kali/entrypoint.py's own
# docstring): enables INFO-level stdout logging for apex_tool_service's
# own audit lines (execution_accepted/execution_complete/
# execution_rejected), which Python's default logging configuration
# otherwise drops silently. Pure observability configuration — no
# allowlist/validation/auth/execution behavior is changed.
COPY --chown=apextool:apextool docker/kali/entrypoint.py /app/entrypoint.py

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APEX_TOOL_SERVICE_HOST=0.0.0.0 \
    APEX_TOOL_SERVICE_PORT=8080

# Runtime authentication configuration is accepted, never embedded:
#   APEX_TOOL_SERVICE_TOKEN is intentionally NOT set here. Per
#   apex_tool_service/auth.py, an unset token makes every POST /v1/execute
#   call fail closed with HTTP 503 ("service_misconfigured") — there is no
#   default/fallback token baked into this image. An operator MUST supply
#   `-e APEX_TOOL_SERVICE_TOKEN=...` at `docker run` time for the execution
#   endpoint to accept any request. GET /health remains available either
#   way (see apex_tool_service/app.py, apex_tool_service/auth.py).

USER apextool

# Non-privileged HTTP port — matches apex_tool_service's own default
# (apex_tool_service/settings.py::_DEFAULT_PORT).
EXPOSE 8080

# Meaningful readiness probe against the service's own unauthenticated
# health endpoint, using the already-installed `curl`. Fails (and marks the
# container unhealthy) only when the HTTP server itself is not responding
# with 2xx — never based on which optional tool binaries happen to be
# present (apex_tool_service/app.py's /health handler always returns 200
# with a per-tool availability map; it does not 5xx just because e.g.
# telnet were hypothetically missing). No bearer token required, no tool
# invoked, no secret exposed by this check.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

# Safe, single-purpose startup command: the restricted HTTP tool-execution
# service only, via the thin logging-enabling entrypoint above (see
# docker/kali/entrypoint.py — it changes no security/allowlist/auth
# behavior, only enables INFO-level stdout logging, then calls the exact
# same apex_tool_service.__main__.main() that `python -m apex_tool_service`
# would). This does NOT launch a shell, does NOT start sshd/telnetd, does
# NOT run any offensive tool automatically, and does NOT execute an
# engagement merely because the container starts. Host/port are supplied
# via the ENV vars above (apex_tool_service/__main__.py resolves
# CLI flag > env var > built-in default; no CLI flags are passed here, so
# the ENV vars above take effect).
CMD ["python", "/app/entrypoint.py"]
