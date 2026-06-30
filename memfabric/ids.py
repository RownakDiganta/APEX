"""Canonical ID and timestamp helpers.  Use these everywhere; never call
datetime.now() or uuid.uuid4() scattered around the codebase."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone


def new_id() -> str:
    """Return a new opaque, globally unique identifier (UUID4 string)."""
    return str(uuid.uuid4())


def now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()
