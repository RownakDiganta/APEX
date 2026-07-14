# Dockerfile
# Multi-stage build for the APEX application image (Infra Phase 5; entrypoint added Infra Phase 9) — locked, non-root, dependency-only runtime. Does NOT build or start the Kali tool service (Infra Phase 6+).
#
# Build from the REPOSITORY ROOT (not this directory), so the build context
# includes pyproject.toml, uv.lock, and the first-party packages:
#
#   docker build -f docker/apex/Dockerfile -t apex:phase5 .
#
# See docs/apex-container.md for the Phase 5 image design rationale (what
# this image contains/excludes) and docs/container-entrypoint.md for the
# Phase 9 ENTRYPOINT/CMD (apex_host.container_entrypoint) design.

# ---------------------------------------------------------------------------
# Pinned tool image: uv's own official static-binary distribution, used only
# to copy the `uv` executable into the builder stage — no curl|sh install,
# no pip bootstrap. Pinned by digest (immutable regardless of the `0.11.28`
# tag ever being retagged).
# ---------------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa AS uv

# ---------------------------------------------------------------------------
# Base image: Python 3.11, Debian "bookworm" slim variant, pinned to the
# exact patch version this project has been developed and tested against
# (.python-version pins "3.11"; the dev/CI venv used by every prior Infra
# Phase is 3.11.14 — see CLAUDE.md). Pinned by digest for full reproducibility
# regardless of the `3.11.14-slim-bookworm` tag ever being reused for a
# rebuild. Never `latest`, never a floating `3.11`/`3-slim` tag.
#
# Rationale for slim-bookworm specifically: smaller attack surface and image
# size than the full `python:3.11.14` image (which bundles a full build
# toolchain and many OS packages this application never uses), while still
# being a well-maintained, officially supported Debian base with predictable
# apt package availability (unlike Alpine, whose musl libc has caused
# historical compatibility issues with scientific-Python wheels such as
# faiss-cpu/numpy).
# ---------------------------------------------------------------------------
FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d AS builder

COPY --from=uv /uv /usr/local/bin/uv

# UV_PYTHON_DOWNLOADS=never: forbid uv from fetching its own Python — it must
#   use the base image's interpreter (which already matches requires-python).
# UV_LINK_MODE=copy: avoid uv's default hardlink/reflink behavior, which can
#   warn or misbehave across the Docker layer/cache-mount boundary.
# UV_PROJECT_ENVIRONMENT: explicit, predictable venv path to copy forward
#   into the runtime stage.
ENV UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# --- Dependency layer (cached independently of application source) --------
# Copying only the dependency manifests first means this (slow: numpy,
# faiss-cpu, langgraph, playwright, ...) layer is only invalidated when
# pyproject.toml or uv.lock actually change — not on every source edit.
COPY pyproject.toml uv.lock ./

# --frozen: fail the build if pyproject.toml and uv.lock are inconsistent —
#   never regenerate/update the lock file inside the image.
# --no-dev: exclude the `dev` dependency group (pytest, ruff, mypy, type
#   stubs) — none of that belongs in a runtime image.
# --no-install-project: install only third-party dependencies in this layer;
#   the project itself is installed in the next layer, after source is
#   copied, so editing application code never invalidates this layer.
RUN uv sync --frozen --no-dev --no-install-project

# --- Project layer -----------------------------------------------------
# apex_tool_service is copied and installed alongside apex_host/memfabric
# because all three are packages of the *same* Hatchling distribution
# (see [tool.hatch.build.targets.wheel] packages in pyproject.toml) — this
# project cannot be installed with uv/Hatchling's current configuration
# without all three package directories present. This does NOT mean the
# APEX image runs the tool service: no CMD/ENTRYPOINT in this Dockerfile
# ever invokes `apex_tool_service`, and it is never started by this image.
# See docs/apex-container.md "Remote tool service relationship".
COPY memfabric ./memfabric
COPY apex_host ./apex_host
COPY apex_tool_service ./apex_tool_service

# --no-editable: install real, self-contained copies of memfabric/apex_host/
#   apex_tool_service into site-packages rather than an editable (`pip install
#   -e .`-style) link back to /app — the runtime stage below copies only the
#   resulting virtual environment, not this source tree, so an editable
#   install would silently break at runtime.
RUN uv sync --frozen --no-dev --no-editable


# ---------------------------------------------------------------------------
# Runtime stage — no build toolchain, no uv, no dev dependencies, no first-
# party source tree (everything needed is already inside the copied venv).
# ---------------------------------------------------------------------------
FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d AS runtime

# libgomp1: faiss-cpu's OpenMP runtime dependency (not present on the slim
#   base image by default; faiss-cpu wheels dynamically link against it).
# ca-certificates: TLS verification for outbound HTTPS calls this
#   application legitimately makes (OpenAI-compatible LLM APIs when
#   --use-llm is set; a future RemoteToolBackend HTTPS deployment).
# No compilers, no Kali/offensive tools (nmap, telnet, nc, hydra, gobuster,
# ffuf, ...) — those belong to the separate Kali tool-service image
# (Infra Phase 6), never this one.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libgomp1 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged user/group, explicit UID/GID 1000 (the conventional
# "first normal user" ID, chosen so it never collides with a bind-mounted
# host directory owned by a typical single-user Linux/macOS host). No
# password, no shell (nologin), no sudo, no home-directory login capability
# — this account exists solely to own and run the application process.
# (Not `--system`: system accounts conventionally stay below UID 1000;
# using --system together with an explicit UID >= 1000 only produces a
# spurious useradd warning without changing anything meaningful here.)
RUN groupadd --gid 1000 apex \
    && useradd --uid 1000 --gid apex --no-create-home --home-dir /app --shell /usr/sbin/nologin apex

WORKDIR /app

# The prepared virtual environment (all runtime dependencies + the
# non-editable-installed first-party packages) — nothing else from the
# builder stage is copied forward.
COPY --from=builder --chown=apex:apex /app/.venv /app/.venv

# Runtime-required compiled knowledge only (~49 MB total) — see
# docs/apex-container.md "Knowledge strategy" for the full rationale.
#
# IMPORTANT — source-path casing: the git-tracked directory is `Knowledge/`
# (capital K). CLAUDE.md §18 states the real directory is lowercase
# `knowledge/`; that statement is INACCURATE on a case-sensitive filesystem
# (this build's Docker context) — verified by `git ls-files`, which shows
# every tracked path uses `Knowledge/...`. It is only "no typo" on the
# case-INSENSITIVE macOS/APFS filesystem this project has been developed on
# (`Knowledge` and `knowledge` resolve to the same inode there). The
# destination path below is deliberately lowercase (`/app/knowledge`),
# matching every documented `--knowledge-root` CLI example in this repo, so
# operator-facing usage stays consistent regardless of this source-tree
# quirk. Only the four `*/compiled/` subdirectories are copied — never the
# multi-gigabyte raw corpora (SecLists, NVD CVE feeds, GTFOBins, LOLBAS,
# PayloadsAllTheThings, raw PDFs) that live alongside them in git.
COPY --chown=apex:apex Knowledge/intel_db/compiled /app/knowledge/intel_db/compiled
COPY --chown=apex:apex Knowledge/methodology_db/compiled /app/knowledge/methodology_db/compiled
COPY --chown=apex:apex Knowledge/payload_db/compiled /app/knowledge/payload_db/compiled
COPY --chown=apex:apex Knowledge/policy_db/compiled /app/knowledge/policy_db/compiled

# Writable output directory for --export-json / --export-graph. Intended as
# a future bind-mount / named-volume target — not part of the read-only
# application source, and never written to implicitly (both CLI flags are
# opt-in; nothing in apex_host writes here unless explicitly told to).
RUN mkdir -p /app/run_reports && chown apex:apex /app/run_reports

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Runtime configuration is accepted, never embedded. None of the following
# are set here — they are read from the environment (or CLI flags) at
# container-run time only:
#   OPENAI_API_KEY, APEX_TOOL_BACKEND, APEX_TOOL_SERVICE_URL,
#   APEX_TOOL_SERVICE_TOKEN, OPENAI_BASE_URL
# No .env file is copied into this image (none exists in the repository yet
# — see CLAUDE.md Infra Phase roadmap for when one will be introduced) and
# no placeholder/fake credential value is defined for any of them.

USER apex

# No HEALTHCHECK: APEX is a one-shot CLI application, not a long-running
# server (apex_tool_service, the actual HTTP server in this repository, is
# a separate image — Infra Phase 6). A Docker HEALTHCHECK is meaningful for
# processes with an observable "ready" state; a CLI invocation has none to
# probe from outside the process, and a check that merely confirms "the
# Python interpreter starts" would be theater, not a real signal. See
# docs/apex-container.md "Health check decision".

# ---------------------------------------------------------------------------
# Entrypoint (Infra Phase 9): apex_host.container_entrypoint — parses
# configuration, prints a redacted summary, runs local preflight (report
# directory, compiled knowledge, policy) and, for `smoke`/`run`, connectivity
# checks — before dispatching to any operational command. Exec-form JSON
# array (no shell), so `docker run`/Compose deliver signals directly to the
# Python interpreter, and CMD's arguments are appended to ENTRYPOINT's argv
# rather than being shell-interpreted. See docs/container-entrypoint.md for
# the full mode reference (check/smoke/dry-run/run/exec).
#
# Safe default mode: `check` — local-only configuration/report-directory/
# knowledge/policy validation. Requires no target, contacts no network, and
# does not start an engagement merely because the container starts. This is
# a stricter, more thorough safe default than Phase 5's bare `--help`: it
# actually exercises the image's own configuration and knowledge/report
# paths, not just argparse usage text.
# --knowledge-root points at this image's own baked-in compiled knowledge
# (§ "Runtime-required compiled knowledge only" above) so the default
# `check` actually validates the real artifact this image ships, not a
# skipped/optional check — knowledge validation is otherwise a soft-pass
# when no root is configured (apex_host/eval/preflight.py::check_compiled_knowledge).
ENTRYPOINT ["python", "-m", "apex_host.container_entrypoint"]
CMD ["check", "--knowledge-root", "/app/knowledge"]

# Equivalents for prior bare-module invocations, now that ENTRYPOINT is set
# (docs/container-entrypoint.md "Troubleshooting" has the full reference):
#
#   Old (Infra Phase 5):
#     docker run --rm apex:phase5 python -m apex_host.main --help
#
#   New, via the `exec` mode (argv-list os.execvp, no shell, no preflight —
#   documented as intentionally bypassing the engagement workflow but not
#   container OS permissions):
#     docker run --rm apex-image exec -- python -m apex_host.main --help
#
#   New, bypassing the entrypoint entirely (also always available):
#     docker run --rm --entrypoint python apex-image -m apex_host.main --help
#
#   Full dry-run engagement with report export:
#     docker run --rm -v "$(pwd)/run_reports:/app/run_reports" apex-image \
#       dry-run --target <IP> --export-json /app/run_reports/run.json
