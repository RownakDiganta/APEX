# vpn_route_check.py
# Manual, on-demand route-lookup utility — asks the VPN container's readiness server "would traffic to <target IP> use the VPN route?" without ever sending a packet. Never invoked automatically by any preflight path or engagement mode.
"""Manual VPN route-lookup utility.

    uv run python -m apex_host.eval.vpn_route_check \\
        --vpn-service-url http://vpn:8090 --target 10.129.5.5

This is a **manual, operator-invoked** tool for the "later manual
validation phase" (``docs/htb-vpn-manual-validation.md``) — it is never
called by ``apex_host/eval/preflight.py``'s automatic checks
(``run_local_checks``/``run_smoke_checks``/``run_vpn_checks``), never
called by ``apex_host/container_entrypoint.py`` in any mode, and never
runs against a target automatically. An operator runs it by hand, after
confirming VPN tunnel readiness (``docker compose --profile htb up`` /
``container_entrypoint.py smoke``), to sanity-check that a *specific*
target IP would route through the tunnel before starting any real
engagement work.

Sends **no packet** — it calls the VPN container's own read-only
``GET /route-check?target=<ip>`` endpoint
(``docker/vpn/readiness_server.py`` -> ``docker/vpn/route_check.py`` ->
``ip route get <ip>``, a kernel routing-table lookup only).

Client-side IP validation happens *before* any HTTP request is made —
consistent with ``docker/vpn/route_check.py``'s own "invalid input never
reaches a subprocess" discipline, applied here to "invalid input never
reaches an HTTP call."
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sys

import httpx

_ROUTE_CHECK_TIMEOUT_SECONDS = 10.0


class InvalidTargetError(ValueError):
    """Raised when the supplied --target is not a valid IP address."""


def validate_target_ip(raw: str) -> str:
    stripped = raw.strip()
    if not stripped:
        raise InvalidTargetError("target must not be blank")
    try:
        addr = ipaddress.ip_address(stripped)
    except ValueError as exc:
        raise InvalidTargetError(f"{raw!r} is not a valid IPv4/IPv6 address") from exc
    return str(addr)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="apex_host.eval.vpn_route_check",
        description=(
            "Ask the VPN container's readiness server whether traffic to a "
            "target IP would use the VPN tunnel route. Sends no packet — a "
            "kernel routing-table lookup only. Manual, operator-invoked only; "
            "never run automatically by any preflight path or engagement mode."
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


async def _async_main(argv: list[str] | None) -> int:
    args = _parse_args(argv)

    try:
        target = validate_target_ip(args.target)
    except InvalidTargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        result = await _query_route_check(args.vpn_service_url, target, args.timeout)
    except httpx.RequestError as exc:
        print(f"error: could not reach {args.vpn_service_url}: {exc.__class__.__name__}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"target:          {result.get('target')}")
        print(f"lookup ok:       {result.get('ok')}")
        print(f"would use route: {result.get('would_use_route')}")
        print(f"device:          {result.get('device')}")
        print(f"gateway:         {result.get('gateway')}")
        if result.get("error"):
            print(f"error:           {result.get('error')}")
        print()
        print(
            "Note: this is a routing-table lookup only — it does NOT prove "
            "the target is currently reachable. No packet was sent."
        )

    return 0 if result.get("ok") else 1


def main(argv: list[str] | None = None) -> None:
    sys.exit(asyncio.run(_async_main(argv)))


if __name__ == "__main__":
    main()
