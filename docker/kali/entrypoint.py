# entrypoint.py
# Container entrypoint: enables INFO-level stdout logging before delegating to the standard apex_tool_service CLI — a pure observability configuration change, no security/allowlist/auth behavior is touched.
"""Kali tool-service container entrypoint.

``apex_tool_service``'s own module-level loggers (``apex_tool_service.app``,
``apex_tool_service.audit``, ``apex_tool_service.executor``) are created via
plain ``logging.getLogger(__name__)`` calls with no explicit level set (see
each module's own docstring). Nothing in ``apex_tool_service/__main__.py``
calls ``logging.basicConfig`` — that is intentional there, since a library
importable as ``uvicorn apex_tool_service.app:app`` should not impose a
logging configuration on its embedding process.

A standalone container, however, has no such embedding process: its only
observability surface *is* stdout/stderr (`docs/kali-container.md` §15).
Under Python's default logging configuration (root logger effectively at
``WARNING``, with only the automatic ``logging.lastResort`` handler
attached), the INFO-level audit lines this service already computes on
every request (``execution_accepted``, ``execution_complete``,
``execution_rejected`` in ``apex_tool_service/audit.py``) are silently
dropped — only ``WARNING``+ events (``auth_failure``) and uvicorn's own
independently-configured access-log lines would otherwise reach
``docker logs``. This entrypoint closes that gap with a single
``logging.basicConfig`` call, at the container-process boundary only.

This intentionally does not modify ``apex_tool_service`` itself — no
allowlist, validation, authentication, or execution logic changes. It is
the same class of "entrypoint script" this phase's own task brief lists as
an allowed `docker/kali/` support file.
"""
from __future__ import annotations

import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)

from apex_tool_service.__main__ import main  # noqa: E402 - logging must be configured first

if __name__ == "__main__":
    raise SystemExit(main())
