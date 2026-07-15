# route_check.py
# Safe, no-packet route-lookup utility for the VPN container — validates a target IP, then runs `ip route get <ip>` as an argv-list subprocess (no shell) and returns a structured result.
"""Route-check utility.

Answers "would traffic to <target IP> use the VPN route?" without sending
any packet. ``ip route get <ip>`` is a pure routing-table lookup — the
kernel resolves which interface/gateway would be used, but no ICMP/TCP/UDP
traffic is ever transmitted.

Deliberately dependency-free (stdlib only) so it can run inside the
minimal VPN image without pulling in ``apex_host``/``httpx``/etc. Zero
imports from this repository's other packages — this module is copied
into the VPN image standalone (see ``docker/vpn/Dockerfile``).

Security properties:
- Argument-array subprocess only (``subprocess.run([...], shell=False)``)
  — never a shell, never string interpolation into a command line.
- The target is validated as a syntactically well-formed IPv4/IPv6 address
  via ``ipaddress.ip_address()`` *before* it is ever placed in the argv
  list — an invalid string never reaches ``subprocess.run``.
- No other route command is ever constructed — ``ip route get`` is the
  only subcommand this module invokes. There is no way for a caller to
  inject an arbitrary ``ip`` subcommand.
- Bounded timeout on every subprocess call.
"""
from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass

_IP_ROUTE_GET_TIMEOUT_SECONDS = 5.0


class InvalidTargetError(ValueError):
    """Raised when a caller-supplied target string is not a valid IP address."""


@dataclass(frozen=True, slots=True)
class RouteCheckResult:
    """Structured result of an ``ip route get <target>`` lookup.

    ``would_use_route`` is a best-effort classification: True when the
    resolved route's output device is a tunnel-shaped interface name
    (``tun*``/``tap*``/``ppp*``) — the VPN's own interface naming
    convention (see ``tunnel_status.py``). False otherwise (e.g. the
    route would exit via ``eth0``, meaning traffic to that target would
    NOT traverse the VPN tunnel).
    """

    target: str
    ok: bool
    would_use_route: bool
    device: str | None
    gateway: str | None
    raw_output: str
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "ok": self.ok,
            "would_use_route": self.would_use_route,
            "device": self.device,
            "gateway": self.gateway,
            "raw_output": self.raw_output,
            "error": self.error,
        }


def validate_target_ip(raw: str) -> str:
    """Validate *raw* as a syntactically well-formed IPv4 or IPv6 address.

    Returns the normalized string form on success. Raises
    ``InvalidTargetError`` (never a bare ``ValueError`` reaching a caller
    unexpectedly, though it is itself a ``ValueError`` subclass so
    ``except ValueError`` still catches it) for anything else — including
    CIDR notation, hostnames, or shell metacharacters, none of which are a
    single valid address.
    """
    stripped = raw.strip()
    if not stripped:
        raise InvalidTargetError("target must not be blank")
    try:
        addr = ipaddress.ip_address(stripped)
    except ValueError as exc:
        raise InvalidTargetError(f"{raw!r} is not a valid IPv4/IPv6 address") from exc
    return str(addr)


def _parse_route_get_output(output: str) -> tuple[str | None, str | None]:
    """Extract the output device and gateway (if any) from ``ip route get``
    stdout. Tolerant of the two common formats:

        10.129.5.5 via 10.129.0.1 dev tun0 src 10.10.14.5 uid 1000
        10.129.5.5 dev tun0 src 10.129.0.5 uid 1000
    """
    device: str | None = None
    gateway: str | None = None
    tokens = output.split()
    for i, tok in enumerate(tokens):
        if tok == "dev" and i + 1 < len(tokens):
            device = tokens[i + 1]
        elif tok == "via" and i + 1 < len(tokens):
            gateway = tokens[i + 1]
    return device, gateway


def _device_is_tunnel_shaped(device: str | None) -> bool:
    if not device:
        return False
    return device.startswith(("tun", "tap", "ppp"))


def run_route_get(
    target: str, *, timeout_seconds: float = _IP_ROUTE_GET_TIMEOUT_SECONDS,
) -> RouteCheckResult:
    """Run ``ip route get <target>`` and return a structured result.

    Never sends a packet — this is a kernel routing-table lookup only.
    Never raises for an ordinary failure (invalid target, missing ``ip``
    binary, non-zero exit, timeout) — those are represented in the
    returned ``RouteCheckResult.ok``/``error`` fields, matching the
    "ordinary failure is data" discipline used throughout this project's
    other tool-execution boundaries.
    """
    try:
        normalized = validate_target_ip(target)
    except InvalidTargetError as exc:
        return RouteCheckResult(
            target=target, ok=False, would_use_route=False,
            device=None, gateway=None, raw_output="", error=str(exc),
        )

    argv = ["ip", "route", "get", normalized]
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False, fixed subcommand
            argv, capture_output=True, text=True, timeout=timeout_seconds, shell=False,
        )
    except FileNotFoundError:
        return RouteCheckResult(
            target=normalized, ok=False, would_use_route=False,
            device=None, gateway=None, raw_output="", error="'ip' binary not found in PATH",
        )
    except subprocess.TimeoutExpired:
        return RouteCheckResult(
            target=normalized, ok=False, would_use_route=False,
            device=None, gateway=None, raw_output="",
            error=f"'ip route get' timed out after {timeout_seconds}s",
        )

    if proc.returncode != 0:
        return RouteCheckResult(
            target=normalized, ok=False, would_use_route=False,
            device=None, gateway=None, raw_output=proc.stdout.strip(),
            error=proc.stderr.strip() or f"ip route get exited {proc.returncode}",
        )

    device, gateway = _parse_route_get_output(proc.stdout)
    return RouteCheckResult(
        target=normalized, ok=True,
        would_use_route=_device_is_tunnel_shaped(device),
        device=device, gateway=gateway, raw_output=proc.stdout.strip(),
    )
