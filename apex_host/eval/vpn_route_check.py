# vpn_route_check.py
# Manual, on-demand route-lookup (and optional connect-diagnostic) utility — asks the VPN container's readiness server "would traffic to <target IP> use the VPN route?" and, when --port is given, "what actually happens if I try to connect?". Never invoked automatically by any preflight path or engagement mode.
"""Manual VPN route-lookup / connect-diagnostic utility.

    # Route lookup only — sends no packet:
    uv run python -m apex_host.eval.vpn_route_check \\
        --vpn-service-url http://vpn:8090 --target 10.129.5.5

    # Route lookup PLUS one bounded TCP connect attempt:
    uv run python -m apex_host.eval.vpn_route_check \\
        --vpn-service-url http://vpn:8090 --target 10.129.5.5 --port 23

This is a **manual, operator-invoked** tool for the "later manual
validation phase" (``docs/htb-vpn-manual-validation.md``) — it is never
called by ``apex_host/eval/preflight.py``'s automatic checks
(``run_local_checks``/``run_smoke_checks``/``run_vpn_checks``), never
called by ``apex_host/container_entrypoint.py`` in any mode, and never
runs against a target automatically. An operator runs it by hand, after
confirming VPN tunnel readiness (``docker compose --profile htb up`` /
``container_entrypoint.py smoke``), to sanity-check that a *specific*
target IP would route through the tunnel — and, optionally, that a
specific port on it actually accepts a connection — before starting any
real engagement work.

**Without ``--port``:** calls the VPN container's read-only
``GET /route-check?target=<ip>`` endpoint (``ip route get <ip>`` — a
kernel routing-table lookup only, sends **no packet**).

**With ``--port``:** calls ``GET /diagnose?target=<ip>&port=<port>``
instead, which performs the same route lookup *plus* exactly one bounded
TCP connect attempt (``docker/vpn/connect_check.py``). This matters
because a route that resolves correctly in the routing table can still
fail to connect — e.g. an ICMP Destination/Host Unreachable received back
from somewhere in the network manifests as a *delayed*
``EHOSTUNREACH``/``ENETUNREACH``, which a routing-table lookup alone can
never detect (`ip route get` never sends a packet or waits for a network
response). The tool prints both results together so the two can be
compared directly.

Client-side IP/port validation happens *before* any HTTP request is made
— consistent with ``docker/vpn/route_check.py``/``connect_check.py``'s
own "invalid input never reaches a subprocess" discipline, applied here
to "invalid input never reaches an HTTP call."
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sys

import httpx

_ROUTE_CHECK_TIMEOUT_SECONDS = 10.0
_MIN_PORT = 1
_MAX_PORT = 65535


class InvalidTargetError(ValueError):
    """Raised when the supplied --target is not a valid IP address."""


class InvalidPortError(ValueError):
    """Raised when the supplied --port is not a valid TCP port number."""


def validate_target_ip(raw: str) -> str:
    stripped = raw.strip()
    if not stripped:
        raise InvalidTargetError("target must not be blank")
    try:
        addr = ipaddress.ip_address(stripped)
    except ValueError as exc:
        raise InvalidTargetError(f"{raw!r} is not a valid IPv4/IPv6 address") from exc
    return str(addr)


def validate_port(raw: int) -> int:
    if not (_MIN_PORT <= raw <= _MAX_PORT):
        raise InvalidPortError(f"port {raw} is out of range ({_MIN_PORT}-{_MAX_PORT})")
    return raw


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="apex_host.eval.vpn_route_check",
        description=(
            "Ask the VPN container's readiness server whether traffic to a "
            "target IP would use the VPN tunnel route, and (with --port) "
            "attempt exactly one bounded TCP connection to distinguish "
            "'no route to host' from a silent timeout from a refused "
            "connection. Manual, operator-invoked only; never run "
            "automatically by any preflight path or engagement mode."
        ),
    )
    parser.add_argument(
        "--vpn-service-url", required=True, metavar="URL",
        help="Base URL of the VPN container's readiness server, e.g. http://vpn:8090",
    )
    parser.add_argument(
        "--target", required=True, metavar="IP",
        help="A single IPv4/IPv6 address to check (not a hostname, not a CIDR range).",
    )
    parser.add_argument(
        "--port", type=int, default=None, metavar="PORT",
        help="Optional. When given, also attempts one bounded TCP connect to this port "
             "(via GET /diagnose instead of GET /route-check).",
    )
    parser.add_argument(
        "--timeout", type=float, default=_ROUTE_CHECK_TIMEOUT_SECONDS, metavar="SECS",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", default=False)
    return parser.parse_args(argv)


async def _query_route_check(vpn_service_url: str, target: str, timeout_seconds: float) -> dict[str, object]:
    url = f"{vpn_service_url.rstrip('/')}/route-check"
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.get(url, params={"target": target})
    data: object = response.json()
    if not isinstance(data, dict):
        raise ValueError(f"unexpected non-object response from {url}: {data!r}")
    return data


async def _query_diagnose(
    vpn_service_url: str, target: str, port: int, timeout_seconds: float,
) -> dict[str, object]:
    url = f"{vpn_service_url.rstrip('/')}/diagnose"
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.get(url, params={"target": target, "port": port})
    data: object = response.json()
    if not isinstance(data, dict):
        raise ValueError(f"unexpected non-object response from {url}: {data!r}")
    return data


def _print_route_result(result: dict[str, object]) -> None:
    print(f"target:          {result.get('target')}")
    print(f"lookup ok:       {result.get('ok')}")
    print(f"would use route: {result.get('would_use_route')}")
    print(f"device:          {result.get('device')}")
    print(f"gateway:         {result.get('gateway')}")
    if result.get("error"):
        print(f"error:           {result.get('error')}")


def _connect_ok(payload: dict[str, object]) -> bool:
    connect = payload.get("connect")
    if not isinstance(connect, dict):
        return False
    return bool(connect.get("ok"))


def _print_diagnose_result(payload: dict[str, object]) -> None:
    route = payload.get("route", {})
    connect = payload.get("connect", {})
    assert isinstance(route, dict) and isinstance(connect, dict)
    print("-- route lookup (no packet sent) --")
    _print_route_result(route)
    print()
    print("-- TCP connect attempt (one bounded attempt) --")
    print(f"outcome:         {connect.get('outcome')}")
    print(f"ok:              {connect.get('ok')}")
    print(f"errno:           {connect.get('errno')} ({connect.get('errno_name')})")
    print(f"elapsed:         {connect.get('elapsed_seconds')}s")
    print(f"detail:          {connect.get('detail')}")


async def _async_main(argv: list[str] | None) -> int:
    args = _parse_args(argv)

    try:
        target = validate_target_ip(args.target)
    except InvalidTargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    port: int | None = None
    if args.port is not None:
        try:
            port = validate_port(args.port)
        except InvalidPortError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        if port is not None:
            result = await _query_diagnose(args.vpn_service_url, target, port, args.timeout)
        else:
            result = await _query_route_check(args.vpn_service_url, target, args.timeout)
    except httpx.RequestError as exc:
        print(f"error: could not reach {args.vpn_service_url}: {exc.__class__.__name__}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
        ok = bool(result.get("ok")) if port is None else _connect_ok(result)
    elif port is not None:
        _print_diagnose_result(result)
        print()
        print(
            "Note: 'unreachable' means an ICMP/kernel-level unreachable was "
            "encountered (this can happen even when the route lookup above "
            "succeeds — a route resolving in the table does not guarantee "
            "the destination is actually reachable); 'timeout' means no "
            "response at all came back (the same outcome a port scanner "
            "reports as 'filtered'); 'refused' means the host responded "
            "but the port is closed."
        )
        ok = _connect_ok(result)
    else:
        _print_route_result(result)
        print()
        print(
            "Note: this is a routing-table lookup only — it does NOT prove "
            "the target is currently reachable. No packet was sent. Pass "
            "--port to also attempt a real, bounded TCP connection."
        )
        ok = bool(result.get("ok"))

    return 0 if ok else 1


def main(argv: list[str] | None = None) -> None:
    sys.exit(asyncio.run(_async_main(argv)))


if __name__ == "__main__":
    main()
