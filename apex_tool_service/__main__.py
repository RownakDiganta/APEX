# __main__.py
# CLI entrypoint: `uv run python -m apex_tool_service` starts the service via uvicorn.
"""Run apex_tool_service standalone.

    uv run python -m apex_tool_service
    uv run python -m apex_tool_service --host 0.0.0.0 --port 8080

Host/port CLI flags override ``ServiceSettings`` (which itself reads
``APEX_TOOL_SERVICE_HOST`` / ``APEX_TOOL_SERVICE_PORT``) — the CLI flag wins
when supplied, otherwise the environment-derived setting applies.

This does not start a Kali container or any network transport in
``apex_host`` — see ``docs/kali-tool-service.md`` "Expected future
Kali-container integration" for what this phase's task brief deferred.
"""
from __future__ import annotations

import argparse
import sys

from apex_tool_service.settings import ServiceSettings


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apex_tool_service",
        description=(
            "Restricted, allowlisted tool-execution HTTP service intended to run "
            "inside a future Kali Linux container. See docs/kali-tool-service.md."
        ),
    )
    parser.add_argument(
        "--host", default=None,
        help="Bind host (default: $APEX_TOOL_SERVICE_HOST or 127.0.0.1).",
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="Bind port (default: $APEX_TOOL_SERVICE_PORT or 8080).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = ServiceSettings.from_env()
    host = args.host or settings.host
    port = args.port or settings.port

    if settings.token is None:
        print(
            "warning: APEX_TOOL_SERVICE_TOKEN is not set — POST /v1/execute will "
            "reject every request with 503 until a token is configured (fail-closed).",
            file=sys.stderr,
        )

    import uvicorn

    from apex_tool_service.app import create_app

    uvicorn.run(create_app(settings), host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
