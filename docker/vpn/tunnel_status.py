# tunnel_status.py
# Detects whether a VPN tunnel interface exists and whether the expected private route is installed — process-existence alone is not proof of a working tunnel.
"""Tunnel/route readiness detection.

Neither OpenVPN process existence NOR a listening HTTP readiness sidecar is
sufficient evidence of a working tunnel — the process can be running while
still negotiating, a route line can match the HTB CIDR textually yet egress
via ``eth0``, and the HTTP sidecar answers long before OpenVPN installs any
route. This module instead inspects, as DISTINCT LAYERS, the kernel's own
view of the network state (see :class:`TunnelStatus` for the full contract):

1. Is an ``openvpn`` process actually running (``/proc`` scan — a dead
   process with a stale interface is not readiness)?
2. Does a tunnel-shaped interface (``tun*``/``tap*``/``ppp*`` — OpenVPN's
   own naming convention; the literal name ``tun0`` is not assumed, since
   a profile can configure ``dev tap0`` or a non-zero unit number) exist,
   and is it administratively UP (missing vs down are distinguished)?
3. Is a route matching the configured HTB CIDR (default ``10.129.0.0/16``,
   configurable — see ``docker/vpn/Dockerfile`` / ``APEX_HTB_ROUTE_CIDR``)
   present in the routing table, AND does that route egress via the tunnel
   device rather than ``eth0``?

The interface/route checks use ``ip link show`` / ``ip route show`` — read-
only inspection commands. The process check reads only ``/proc/<pid>/comm``.
Nothing here pings, scans, or contacts a target, and nothing reads the
mounted profile, a credential, or the environment.

Deliberately dependency-free (stdlib only), consistent with
``route_check.py`` in this same directory — copied into the VPN image
standalone, never imports ``apex_host``.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass

_IP_COMMAND_TIMEOUT_SECONDS = 5.0
_TUNNEL_PREFIXES = ("tun", "tap", "ppp")
_DEFAULT_PROC_ROOT = "/proc"

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
    """Structured, LAYERED tunnel/route readiness result.

    A working tunnel requires ALL of the following, checked as distinct
    layers so a diagnostic can name the exact failure (never conflating "the
    HTTP sidecar is alive" with "HTB traffic is actually routed through the
    tunnel"):

    - ``openvpn_running``    — an ``openvpn`` process exists (a live tunnel
      cannot exist without one; a dead process with a stale interface is not
      readiness).
    - ``tunnel_interface_present`` / ``tunnel_interface_up`` — a tunnel-shaped
      device (``tun*``/``tap*``/``ppp*``) exists, and is administratively UP.
      These are separate so "interface missing" and "interface down" produce
      distinct diagnostics.
    - ``route_present``      — a route whose destination matches the configured
      HTB CIDR (exact or a covered subnet) is installed.
    - ``route_via_tunnel``   — that HTB route egresses via the tunnel device,
      NOT ``eth0``. A route that matches the CIDR textually but exits via the
      Docker bridge would still send target traffic outside the tunnel — the
      exact failure this field exists to catch.

    ``ready`` is the conjunction of all layers. It is the single value the
    Docker healthcheck and ``apex_host.eval.preflight`` gate on, so "container
    healthy" now means "HTB traffic is genuinely routed through the tunnel",
    not merely "the readiness HTTP server answered".
    """

    openvpn_running: bool
    tunnel_interface_present: bool
    tunnel_interface_name: str | None
    tunnel_interface_up: bool
    route_present: bool
    route_via_tunnel: bool
    route_device: str | None
    route_cidr: str
    error: str | None = None

    @property
    def ready(self) -> bool:
        return (
            self.openvpn_running
            and self.tunnel_interface_present
            and self.tunnel_interface_up
            and self.route_present
            and self.route_via_tunnel
            and self.error is None
        )

    @property
    def reason(self) -> str:
        """A short, secret-free explanation of the FIRST failing layer (or
        ``"tunnel ready"`` when ``ready``). Never contains profile content,
        certificates, keys, or an environment dump — only interface names,
        the configured CIDR, and a device name."""
        if self.error is not None:
            return f"route/interface inspection failed: {self.error}"
        if not self.openvpn_running:
            return "VPN process is not running"
        if not self.tunnel_interface_present:
            return "Tunnel interface is missing"
        if not self.tunnel_interface_up:
            return f"Tunnel interface {self.tunnel_interface_name} exists but is down"
        if not self.route_present:
            return f"No HTB route for {self.route_cidr} was installed (route pushing may be disabled)"
        if not self.route_via_tunnel:
            return (
                f"HTB route for {self.route_cidr} is present but egresses via "
                f"{self.route_device!r} instead of the tunnel"
            )
        return "tunnel ready"

    def to_dict(self) -> dict[str, object]:
        return {
            "openvpn_running": self.openvpn_running,
            "tunnel_interface_present": self.tunnel_interface_present,
            "tunnel_interface_name": self.tunnel_interface_name,
            "tunnel_interface_up": self.tunnel_interface_up,
            "route_present": self.route_present,
            "route_via_tunnel": self.route_via_tunnel,
            "route_device": self.route_device,
            "route_cidr": self.route_cidr,
            "ready": self.ready,
            "reason": self.reason,
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


def _device_is_tunnel_shaped(device: str | None) -> bool:
    """True when *device* is a tunnel-shaped interface name
    (``tun*``/``tap*``/``ppp*``) — the VPN's own naming convention. A route
    egressing via such a device traverses the tunnel; ``eth0`` (or ``None``)
    does not."""
    return bool(device) and str(device).startswith(_TUNNEL_PREFIXES)


def find_any_tunnel_interface(link_show_output: str) -> tuple[str | None, bool]:
    """Parse ``ip -o link show`` output and return
    ``(first_tunnel_interface_name_or_None, is_up)``. Unlike
    :func:`find_tunnel_interface` (which returns only an UP tunnel), this
    reports a tunnel-shaped interface REGARDLESS of its administrative state,
    plus whether it is UP — so a caller can distinguish "interface missing"
    from "interface present but down". Pure function — no subprocess call."""
    for match in _LINK_LINE_RE.finditer(link_show_output):
        name, flags_str = match.group(1), match.group(2)
        if name.startswith(_TUNNEL_PREFIXES):
            flags = {f.strip() for f in flags_str.split(",")}
            return name, "UP" in flags
    return None, False


def find_htb_route(route_show_output: str, cidr: str) -> tuple[bool, str | None]:
    """Return ``(present, device)`` for the first route whose destination is
    *cidr* or a subnet covered by it. ``device`` is that route's ``dev <X>``
    egress interface (``None`` if the line has no ``dev`` token). Pure function
    — no subprocess call. See :func:`route_matches_cidr` for the destination-
    matching rationale (broader/narrower HTB ranges are both accepted)."""
    try:
        expected = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False, None
    for line in route_show_output.splitlines():
        tokens = line.strip().split()
        if not tokens:
            continue
        dest = tokens[0]
        if dest == "default":
            continue
        candidate = dest if "/" in dest else f"{dest}/32"
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        try:
            if not (network.subnet_of(expected) or network == expected):
                continue
        except TypeError:
            continue
        device: str | None = None
        for i, tok in enumerate(tokens):
            if tok == "dev" and i + 1 < len(tokens):
                device = tokens[i + 1]
                break
        return True, device
    return False, None


def openvpn_process_running(proc_root: str = _DEFAULT_PROC_ROOT) -> bool:
    """True when an ``openvpn`` process is running, determined by scanning
    ``/proc/<pid>/comm`` (stdlib only — no ``subprocess``, no ``pgrep``
    dependency). Never raises; an unreadable ``/proc`` returns ``False``.

    Reads only the process COMMAND NAME (``comm``), never the command line or
    environment — so it can never leak a mounted profile path, a credential,
    or any argument. ``comm`` is kernel-truncated to 15 chars; ``openvpn`` is
    well within that."""
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return False
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, entry, "comm"), encoding="utf-8", errors="replace") as fh:
                if fh.read().strip() == "openvpn":
                    return True
        except OSError:
            continue
    return False


def check_tunnel_status(route_cidr: str) -> TunnelStatus:
    """Run the real ``ip link show`` / ``ip route show`` commands (and scan
    ``/proc`` for the OpenVPN process) and return a structured, safe-to-
    serialize LAYERED result. Never raises for an ordinary failure (missing
    ``ip`` binary, timeout, malformed CIDR, unreadable ``/proc``)."""
    running = openvpn_process_running()

    try:
        normalized_cidr = validate_cidr(route_cidr)
    except CidrValidationError as exc:
        return TunnelStatus(
            openvpn_running=running, tunnel_interface_present=False,
            tunnel_interface_name=None, tunnel_interface_up=False,
            route_present=False, route_via_tunnel=False, route_device=None,
            route_cidr=route_cidr, error=str(exc),
        )

    link_ok, link_output = _run_ip("-o", "link", "show")
    if not link_ok:
        return TunnelStatus(
            openvpn_running=running, tunnel_interface_present=False,
            tunnel_interface_name=None, tunnel_interface_up=False,
            route_present=False, route_via_tunnel=False, route_device=None,
            route_cidr=normalized_cidr, error=link_output,
        )
    interface_name, interface_up = find_any_tunnel_interface(link_output)

    route_ok, route_output = _run_ip("route", "show")
    if not route_ok:
        return TunnelStatus(
            openvpn_running=running, tunnel_interface_present=interface_name is not None,
            tunnel_interface_name=interface_name, tunnel_interface_up=interface_up,
            route_present=False, route_via_tunnel=False, route_device=None,
            route_cidr=normalized_cidr, error=route_output,
        )
    route_present, route_device = find_htb_route(route_output, normalized_cidr)

    return TunnelStatus(
        openvpn_running=running,
        tunnel_interface_present=interface_name is not None,
        tunnel_interface_name=interface_name,
        tunnel_interface_up=interface_up,
        route_present=route_present,
        route_via_tunnel=_device_is_tunnel_shaped(route_device),
        route_device=route_device,
        route_cidr=normalized_cidr,
    )
