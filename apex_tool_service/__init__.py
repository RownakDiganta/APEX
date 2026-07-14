# __init__.py
# apex_tool_service — a restricted, standalone HTTP execution boundary intended to run inside a future Kali Linux container.
"""apex_tool_service: restricted Kali-compatible tool-execution service.

This package is deliberately independent of ``apex_host`` — it does not
import the APEX orchestration graph, planners, or ``MemoryAPI``. It exists
to be deployable inside a separate, more restrictive container than the
APEX application itself (Infra Phase 3; see
``docs/kali-tool-service.md`` and ``docs/tool-execution-architecture.md``).

APEX's own policy/legal approval (``apex_host.policy``) still runs before
any request would ever reach this service — this package is a second,
independent, mechanical safety boundary (defense in depth), not a
replacement for policy approval. See ``docs/kali-tool-service.md``
("Relationship to APEX policy approval") for the full explanation.

Run it with::

    uv run python -m apex_tool_service

No `RemoteToolBackend` HTTP client exists yet in ``apex_host`` — wiring
APEX to call this service over the network is Infra Phase 4.
"""
from __future__ import annotations

__version__ = "0.1.0"
