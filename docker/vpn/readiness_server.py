# readiness_server.py
# Minimal, dependency-free (stdlib-only) HTTP readiness server run inside the VPN container — exposes GET /health (tunnel/route status) and GET /route-check (no-packet route lookup). No FastAPI/uvicorn/apex_host dependency, deliberately, to keep the VPN image minimal.
"""VPN container readiness HTTP server.

Runs as a background thread inside ``docker/vpn/entrypoint.py`` alongside
the foreground OpenVPN process. Exposes exactly two read-only, GET-only
endpoints:

    GET /health
        {"status": "ok"|"degraded", "tunnel": bool, "route_cidr": "..."}

    GET /route-check?target=<ip>
        {"target": ..., "ok": ..., "would_use_route": ..., "device": ...,
         "gateway": ..., "raw_output": ..., "error": ...}

Deliberately exposes only non-sensitive fields — never the mounted
profile's content or path, never OpenVPN's server certificate, never the
full routing table, never an environment dump. Unauthenticated by design
(the same rationale ``apex_tool_service``'s own ``GET /health`` uses — see
``docs/kali-tool-service.md`` §4): it reveals only a fixed service name,
tunnel status, and the configured route CIDR, and (for ``/route-check``)
a single caller-supplied target's route classification — no secret, no
scan, no packet sent. This service is never published to the host and is
reachable only from other containers on the same internal Compose network
(``apex-internal``) — see ``docs/htb-vpn-container.md``.

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
        else:
            _json_response(self, 404, {"error": "not found"})

    def _handle_health(self) -> None:
        route_cidr = os.environ.get(ENV_ROUTE_CIDR, DEFAULT_ROUTE_CIDR)
        status = check_tunnel_status(route_cidr)
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
        _json_response(self, 200 if result.ok else 422, result.to_dict())


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
