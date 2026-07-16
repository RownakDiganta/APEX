# tunnel_status.py
# Detects whether a VPN tunnel interface exists and whether the expected private route is installed — process-existence alone is not proof of a working tunnel.
"""Tunnel/route readiness detection.

OpenVPN process existence is not sufficient evidence of a working tunnel —
the process can be running while still negotiating, or have failed after
startup while remaining alive. This module instead inspects the kernel's
own view of the network state:

1. Does a tunnel-shaped interface (``tun*``/``tap*``/``ppp*`` — OpenVPN's
   own naming convention; the literal name ``tun0`` is not assumed, since
   a profile can configure ``dev tap0`` or a non-zero unit number) exist
   and report as UP?
2. Is a route matching the configured HTB CIDR (default
   ``10.129.0.0/16``, configurable — see ``docker/vpn/Dockerfile`` /
   ``APEX_HTB_ROUTE_CIDR``) present in the routing table?

Both checks use ``ip link show`` / ``ip route show`` — read-only
inspection commands. Neither check pings, scans, or contacts a target.

Deliberately dependency-free (stdlib only), consistent with
``route_check.py`` in this same directory — copied into the VPN image
standalone, never imports ``apex_host``.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass

_IP_COMMAND_TIMEOUT_SECONDS = 5.0
_TUNNEL_PREFIXES = ("tun", "tap", "ppp")

# Matches an interface name and its flags bracket at the start of an
# `ip -o link show` line, e.g. "3: tun0: <POINTOPOINT,...,UP,LOWER_UP> mtu
# 1500 ... state UNKNOWN ..." — group(1) is the interface name, group(2)
# is the comma-separated flags list. Readiness is determined from the
# flags bracket (administrative up/down), NOT from the trailing "state"
# token — see find_tunnel_interface()'s own docstring for why the trailing
# state token is unreliable for tun/tap devices specifically.
_LINK_LINE_RE = re.compile(r"^\d+:\s+([^:@]+)[:@]\s*<([^>]*)>", re.MULTILINE)


class CidrValidationError(ValueError):
    """Raised when a configured route CIDR string is not a valid network."""


def validate_cidr(raw: str) -> str:
    """Validate *raw* as a well-formed CIDR network (e.g. ``10.129.0.0/16``).

    Returns the normalized string on success. Raises ``CidrValidationError``
    (a ``ValueError`` subclass) for anything malformed — a bare IP with no
    prefix, an out-of-range prefix length, or garbage input.
    """
    stripped = raw.strip()
    try:
        network = ipaddress.ip_network(stripped, strict=False)
    except ValueError as exc:
        raise CidrValidationError(f"{raw!r} is not a valid CIDR network") from exc
    return str(network)


@dataclass(frozen=True, slots=True)
class TunnelStatus:
    """Structured tunnel/route readiness result."""

    tunnel_interface_present: bool
    tunnel_interface_name: str | None
    route_present: bool
    route_cidr: str
    error: str | None = None

    @property
    def ready(self) -> bool:
        return self.tunnel_interface_present and self.route_present and self.error is None

    def to_dict(self) -> dict[str, object]:
        return {
            "tunnel_interface_present": self.tunnel_interface_present,
            "tunnel_interface_name": self.tunnel_interface_name,
            "route_present": self.route_present,
            "route_cidr": self.route_cidr,
            "ready": self.ready,
            "error": self.error,
        }


def _run_ip(*args: str) -> tuple[bool, str]:
    """Run ``ip <args>`` as an argv-list subprocess (no shell). Returns
    ``(succeeded, stdout_or_error)``."""
    argv = ["ip", *args]
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False, fixed subcommand
            argv, capture_output=True, text=True, timeout=_IP_COMMAND_TIMEOUT_SECONDS, shell=False,
        )
    except FileNotFoundError:
        return False, "'ip' binary not found in PATH"
    except subprocess.TimeoutExpired:
        return False, f"'ip {' '.join(args)}' timed out after {_IP_COMMAND_TIMEOUT_SECONDS}s"
    if proc.returncode != 0:
        return False, proc.stderr.strip() or f"ip {' '.join(args)} exited {proc.returncode}"
    return True, proc.stdout


def find_tunnel_interface(link_show_output: str) -> str | None:
    """Parse ``ip -o link show`` output and return the first UP interface
    whose name starts with a tunnel-shaped prefix (``tun``/``tap``/``ppp``),
    or ``None`` if none is found. Pure function — no subprocess call.

    Readiness is determined from the **administrative** ``UP`` flag inside
    the interface's flags bracket (``<POINTOPOINT,...,UP,LOWER_UP>``), not
    from the trailing ``state <X>`` token that follows the flags bracket
    in ``ip -o link show`` output. This distinction is load-bearing: Linux
    reports the *operational* state (``state``) as ``UNKNOWN`` for NOARP
    point-to-point interfaces — which includes essentially every ``tun``
    device — even when the interface is fully configured and passing
    traffic, because the kernel has no carrier-detection mechanism for a
    software point-to-point link (see the kernel's own
    ``Documentation/networking/operstates.rst``: "UNKNOWN: cannot conclude
    anything, no operations have been carried out to determine actual
    state"). A real, working OpenVPN ``tun0`` therefore commonly logs as:

        3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 ... state UNKNOWN ...

    An earlier version of this function required ``state == "UP"``
    exactly, which never matches this real-world output and caused every
    genuinely-ready tunnel to be reported as not-ready (see the Infra
    Phase 10 bug report this fix resolves). The administrative ``UP`` flag
    in the brackets is always set once OpenVPN brings the interface up
    (``ip link set tun0 up``, which OpenVPN performs unconditionally on a
    successful connection) and is not subject to the same operstate
    ambiguity.
    """
    for match in _LINK_LINE_RE.finditer(link_show_output):
        name, flags_str = match.group(1), match.group(2)
        flags = {f.strip() for f in flags_str.split(",")}
        if name.startswith(_TUNNEL_PREFIXES) and "UP" in flags:
            return name
    return None


def route_matches_cidr(route_show_output: str, cidr: str) -> bool:
    """True if *route_show_output* (``ip route show`` stdout) contains a
    route line whose destination network is the configured *cidr*, or a
    line whose destination is a subnet of *cidr* (an HTB profile may
    install a route for the exact CIDR or something equivalent/narrower).
    Pure function — no subprocess call."""
    try:
        expected = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    for line in route_show_output.splitlines():
        token = line.strip().split()[0] if line.strip() else ""
        if token in ("default", ""):
            continue
        candidate = token if "/" in token else f"{token}/32"
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        try:
            if network.subnet_of(expected) or network == expected:
                return True
        except TypeError:
            continue
    return False


def check_tunnel_status(route_cidr: str) -> TunnelStatus:
    """Run the real ``ip link show`` / ``ip route show`` commands and
    return a structured, safe-to-serialize result. Never raises for an
    ordinary failure (missing ``ip`` binary, timeout, malformed CIDR)."""
    try:
        normalized_cidr = validate_cidr(route_cidr)
    except CidrValidationError as exc:
        return TunnelStatus(
            tunnel_interface_present=False, tunnel_interface_name=None,
            route_present=False, route_cidr=route_cidr, error=str(exc),
        )

    link_ok, link_output = _run_ip("-o", "link", "show")
    if not link_ok:
        return TunnelStatus(
            tunnel_interface_present=False, tunnel_interface_name=None,
            route_present=False, route_cidr=normalized_cidr, error=link_output,
        )
    interface = find_tunnel_interface(link_output)

    route_ok, route_output = _run_ip("route", "show")
    if not route_ok:
        return TunnelStatus(
            tunnel_interface_present=interface is not None, tunnel_interface_name=interface,
            route_present=False, route_cidr=normalized_cidr, error=route_output,
        )
    route_present = route_matches_cidr(route_output, normalized_cidr)

    return TunnelStatus(
        tunnel_interface_present=interface is not None,
        tunnel_interface_name=interface,
        route_present=route_present,
        route_cidr=normalized_cidr,
    )
