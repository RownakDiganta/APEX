# readiness_server.py
# Minimal, dependency-free (stdlib-only) HTTP readiness server run inside the VPN container — exposes GET /health (tunnel/route status) and GET /route-check (no-packet route lookup). No FastAPI/uvicorn/apex_host dependency, deliberately, to keep the VPN image minimal.
"""VPN container readiness HTTP server.

Runs as a background thread inside ``docker/vpn/entrypoint.py`` alongside
the foreground OpenVPN process. Exposes exactly three read-only, GET-only
endpoints:

    GET /health
        {"status": "ok"|"degraded", "tunnel": bool, "route_cidr": "..."}

    GET /route-check?target=<ip>
        {"target": ..., "ok": ..., "would_use_route": ..., "device": ...,
         "gateway": ..., "raw_output": ..., "error": ...}

    GET /diagnose?target=<ip>&port=<port>
        {"route": {...same shape as /route-check...},
         "connect": {"target", "port", "ok", "outcome", "errno",
                      "errno_name", "elapsed_seconds", "detail"}}

``/diagnose`` is the combined, one-call diagnostic this project's own
task brief requested: a routing-table lookup (no packet) *plus* one
bounded, single-attempt real TCP connection, so the two can be compared
directly — a route that resolves correctly in the table but still fails
to connect (e.g. a delayed ``EHOSTUNREACH`` from an ICMP Destination
Unreachable received back from the network) is exactly the case
``/route-check`` alone cannot detect, since it never sends a packet. See
``docker/vpn/connect_check.py`` for the full outcome classification.

Deliberately exposes only non-sensitive fields — never the mounted
profile's content or path, never OpenVPN's server certificate, never the
full routing table, never an environment dump. Unauthenticated by design
(the same rationale ``apex_tool_service``'s own ``GET /health`` uses — see
``docs/kali-tool-service.md`` §4): it reveals only a fixed service name,
tunnel status, and the configured route CIDR, and (for ``/route-check``/
``/diagnose``) a single caller-supplied target's route/connect
classification — no secret, no scan, no packet flood (``/diagnose`` sends
at most one SYN, exactly like a single `nc -zv` probe). This service is
never published to the host and is reachable only from other containers
on the same internal Compose network (``apex-internal``) — see
``docs/htb-vpn-container.md``.

Uses only ``http.server`` (stdlib) — no FastAPI/uvicorn/pydantic/httpx —
so this file can be copied into the minimal VPN image standalone, without
pulling in ``apex_host``'s heavy dependency tree (the same packaging
lesson already documented for the Kali image, ``docs/kali-container.md``
"Packaging limitations" — this VPN image avoids that problem entirely by
never depending on ``apex_host`` at all).
"""
from __future__ import annotations

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from connect_check import run_connect_check
from route_check import run_route_get
from tunnel_status import check_tunnel_status

logger = logging.getLogger("vpn_readiness")

SERVICE_NAME = "apex-vpn-readiness"
DEFAULT_PORT = 8090
DEFAULT_HOST = "0.0.0.0"  # nosec - intentional: internal-network-only container, see module docstring
ENV_PORT = "APEX_VPN_READINESS_PORT"
ENV_ROUTE_CIDR = "APEX_HTB_ROUTE_CIDR"
DEFAULT_ROUTE_CIDR = "10.129.0.0/16"


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, object]) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class ReadinessHandler(BaseHTTPRequestHandler):
    server_version = "apex-vpn-readiness/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        logger.info("%s - %s", self.address_string(), format % args)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler method name
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._handle_health()
        elif parsed.path == "/route-check":
            self._handle_route_check(parsed.query)
        elif parsed.path == "/diagnose":
            self._handle_diagnose(parsed.query)
        else:
            _json_response(self, 404, {"error": "not found"})

    def _handle_health(self) -> None:
        route_cidr = os.environ.get(ENV_ROUTE_CIDR, DEFAULT_ROUTE_CIDR)
        status = check_tunnel_status(route_cidr)
        logger.info(
            "health tunnel_interface=%s route_present=%s ready=%s",
            status.tunnel_interface_name, status.route_present, status.ready,
        )
        _json_response(
            self, 200,
            {
                "status": "ok" if status.ready else "degraded",
                "service": SERVICE_NAME,
                "tunnel": status.ready,
                "route_cidr": status.route_cidr,
            },
        )

    def _handle_route_check(self, query: str) -> None:
        params = parse_qs(query)
        targets = params.get("target", [])
        if not targets:
            _json_response(self, 400, {"error": "missing required 'target' query parameter"})
            return
        result = run_route_get(targets[0])
        logger.info(
            "route-check target=%s ok=%s would_use_route=%s device=%s",
            result.target, result.ok, result.would_use_route, result.device,
        )
        _json_response(self, 200 if result.ok else 422, result.to_dict())

    def _handle_diagnose(self, query: str) -> None:
        """Combined route-lookup + single bounded TCP connect diagnostic —
        see this module's own docstring for why the two are complementary
        (a route that resolves in the table can still fail to connect).
        """
        params = parse_qs(query)
        targets = params.get("target", [])
        ports = params.get("port", [])
        if not targets:
            _json_response(self, 400, {"error": "missing required 'target' query parameter"})
            return
        if not ports:
            _json_response(self, 400, {"error": "missing required 'port' query parameter"})
            return

        route_result = run_route_get(targets[0])
        connect_result = run_connect_check(targets[0], ports[0])

        # Explicit, distinguishable log line per outcome — "no route to
        # host" (outcome="unreachable"), a silent timeout ("filtered" in
        # scanner terms), "refused" (RST received), and "connected" are
        # never conflated with each other or with a route-lookup failure.
        logger.info(
            "diagnose target=%s port=%s route_ok=%s route_device=%s "
            "connect_outcome=%s connect_errno=%s connect_elapsed=%.3fs",
            connect_result.target, connect_result.port, route_result.ok, route_result.device,
            connect_result.outcome, connect_result.errno_name, connect_result.elapsed_seconds,
        )

        _json_response(
            self, 200,
            {"route": route_result.to_dict(), "connect": connect_result.to_dict()},
        )


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Blocking call — run the readiness HTTP server forever. Intended to
    be called from a background thread by ``entrypoint.py``."""
    httpd = ThreadingHTTPServer((host, port), ReadinessHandler)
    logger.info("vpn readiness server listening on %s:%d", host, port)
    httpd.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    port = int(os.environ.get(ENV_PORT, DEFAULT_PORT))
    run_server(port=port)
