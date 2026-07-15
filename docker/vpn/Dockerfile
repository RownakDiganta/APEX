# Dockerfile
# Dedicated first-party OpenVPN container (Infra Phase 10) — owns the HTB VPN tunnel and network namespace; the Kali tool-service container joins this namespace in HTB profile mode. No APEX source, no knowledge corpora, no Kali tools, no SSH, no VPN profile baked in.
#
# Build from the REPOSITORY ROOT (not this directory):
#
#   docker build -f docker/vpn/Dockerfile -t apex-vpn:phase10 .
#
# This image is a small, first-party, auditable wrapper around the
# official Debian `openvpn` package — deliberately NOT a third-party VPN
# image whose entrypoint behavior cannot be inspected line-by-line here.
# See docs/htb-vpn-container.md for the full architecture, trust boundary,
# and capability rationale.

# ---------------------------------------------------------------------------
# Base image: the exact same digest-pinned python:3.11.14-slim-bookworm used
# by docker/apex/Dockerfile (Infra Phase 5) — reused here purely for build
# consistency and because a small Python interpreter is needed to run the
# readiness HTTP server (docker/vpn/readiness_server.py). This image does
# NOT install uv, does NOT run `uv sync`, and does NOT copy pyproject.toml/
# uv.lock/memfabric/apex_host/apex_tool_service — none of that dependency
# tree is needed here. The readiness server and route-check/tunnel-status
# utilities are stdlib-only Python (see each file's own docstring).
# ---------------------------------------------------------------------------
FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d

ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# Installed packages — minimal and evidence-justified:
#   openvpn           -> the VPN client itself (this image's entire purpose)
#   iproute2          -> provides the `ip` binary used by
#                        docker/vpn/tunnel_status.py (tunnel/route detection)
#                        and docker/vpn/route_check.py (`ip route get`)
#   ca-certificates   -> TLS trust store for OpenVPN's own TLS handshake
#                        with the HTB VPN server
# Explicitly NOT installed: any SSH server/client, any remote-shell tool,
# any Kali/offensive tooling, any APEX/Python dependency beyond the base
# image's own stdlib. No package manager cache is left behind (`rm -rf
# /var/lib/apt/lists/*`).
# ---------------------------------------------------------------------------
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openvpn \
        iproute2 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# First-party scripts only — no third-party entrypoint, no vendored VPN
# client wrapper. Each file's own docstring documents its exact behavior;
# all three are readable, auditable, ordinary Python source with zero
# external dependencies beyond the Python standard library.
COPY docker/vpn/entrypoint.py /app/entrypoint.py
COPY docker/vpn/readiness_server.py /app/readiness_server.py
COPY docker/vpn/route_check.py /app/route_check.py
COPY docker/vpn/tunnel_status.py /app/tunnel_status.py

# ---------------------------------------------------------------------------
# The VPN profile is NEVER baked into this image. /vpn is an empty
# directory created here only so the mount point exists; the real
# ./secrets/htb.ovpn (or whatever path APEX_HTB_OVPN_PATH points at) is
# mounted read-only at container-*run*-time by compose.htb.yaml — see
# docs/htb-vpn-container.md "Profile mounting". No credential, no .ovpn
# file, and no APEX source/knowledge/reports/Kali tools exist anywhere in
# this image — verified by `tests/docker/test_vpn_dockerfile.py` (static)
# and this phase's own `docker history --no-trunc` inspection.
# ---------------------------------------------------------------------------
RUN mkdir -p /vpn

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APEX_HTB_ROUTE_CIDR=10.129.0.0/16

# ---------------------------------------------------------------------------
# Root, by necessity — documented, not an oversight. OpenVPN must create a
# tun/tap network device and modify this container's own routing table;
# doing so requires CAP_NET_ADMIN (granted explicitly via `cap_add:` in
# compose.yaml, never via `privileged: true`) *and*, in practice, root
# inside this container's own user namespace — CAP_NET_ADMIN alone does not
# grant a non-root user permission to open /dev/net/tun or reconfigure
# routes on every kernel. This is the same operational requirement every
# mainstream OpenVPN container image (including Docker's own
# openvpn-install guidance) accepts. It does NOT grant anything beyond
# this container's own, isolated network namespace: no `privileged: true`,
# no host networking, no Docker socket, no capability beyond NET_ADMIN (no
# SYS_ADMIN, no NET_RAW). See docs/htb-vpn-container.md §11 "Capabilities
# and /dev/net/tun" and §12 "Non-root behavior" for the full discussion,
# including why this is the one narrow, justified exception to this
# project's otherwise-universal non-root convention (apex_host, Infra
# Phase 5; apex_tool_service, Infra Phase 6 — both remain non-root and
# unaffected by this decision).
# ---------------------------------------------------------------------------

# No EXPOSE for OpenVPN's own outbound tunnel port (client-initiated, no
# inbound listener). The readiness HTTP server listens on 8090 internally
# (never published to the host — see compose.yaml/compose.htb.yaml).
EXPOSE 8090

# Meaningful readiness probe: the readiness server's own /health endpoint,
# which reports tunnel+route status (docker/vpn/tunnel_status.py) — not
# mere OpenVPN process existence. No bearer token required (see
# docker/vpn/readiness_server.py's own docstring for why this endpoint is
# intentionally unauthenticated), no packet sent, no secret exposed.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/health', timeout=2).status == 200 else 1)"

# Exec-form JSON array — no shell, no shell string evaluation. Every
# subprocess this entrypoint spawns (openvpn; the readiness server's own
# `ip` calls) is an explicit argument list, never a shell command line.
ENTRYPOINT ["python3", "/app/entrypoint.py"]
