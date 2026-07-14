# export_graph.py
# Exports EKG nodes and edges into JSON for debugging.
"""Serialises a MemoryAPI subgraph into a JSON-compatible dict.

``export_ekg`` is the main entry point.  It performs a deep subgraph
traversal from the engagement anchor (``host:<target>``) and returns a
plain ``dict`` that ``json.dumps`` can consume directly — no custom
encoders required.

All source data comes through MemoryAPI (memfabric Invariant 1); this
module never touches a store directly.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apex_host.graph_ids import EKG_SCHEMA_VERSION

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI


async def export_ekg(
    api: "MemoryAPI",
    anchor: str,
    *,
    depth: int = 10,
) -> dict[str, Any]:
    """Return a JSON-serialisable snapshot of the EKG rooted at *anchor*.

    Args:
        api:    The live MemoryAPI for the current engagement.
        anchor: Subgraph root, typically ``"host:<target>"``.
        depth:  Traversal depth; 10 covers typical engagement EKGs fully.

    Returns:
        A dict with keys ``"anchor"``, ``"nodes"``, and ``"edges"``.
        All values are JSON primitives (str / float / dict of str/float).
    """
    subgraph = await api.get_subgraph(anchor, depth=depth)
    return {
        "schema_version": EKG_SCHEMA_VERSION,
        "anchor": anchor,
        "nodes": [
            {
                "id": node.id,
                "type": node.type,
                "props": node.props,
                "confidence": node.confidence,
                "source": node.source,
                "first_seen": node.first_seen,
                "last_seen": node.last_seen,
            }
            for node in subgraph.nodes
        ],
        "edges": [
            {
                "id": edge.id,
                "from": edge.from_id,
                "to": edge.to_id,
                "type": edge.type,
                "confidence": edge.confidence,
                "source": edge.source,
            }
            for edge in subgraph.edges
        ],
    }


def write_json(data: dict[str, Any], path: str | Path) -> None:
    """Write *data* as pretty-printed JSON to *path*.

    The write is atomic (P7-I06 / A06): data is first written to a temporary
    sibling file, synced, then renamed into place.  A process crash during the
    write leaves the original file intact — never a truncated or zero-byte file.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(data, indent=2, default=str)
    fd, tmp_path = tempfile.mkstemp(dir=out.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp_path).replace(out)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
