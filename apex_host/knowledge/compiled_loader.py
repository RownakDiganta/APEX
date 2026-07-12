# compiled_loader.py
# Loads compiled JSONL knowledge records from <family>/compiled/ into MemoryAPI staging via propose_knowledge().
"""Load compiled knowledge records from JSONL files into the MemoryAPI staging area.

Rules (non-negotiable)
-----------------------
- **Only reads compiled/ JSONL files** — never raw source files at runtime.
- **All writes go through MemoryAPI.propose_knowledge()** (memfabric Invariant 1).
- **Staging gate is preserved** — proposed entries are NOT retrievable until
  ReflectorWorker promotes them (memfabric Invariant 4).
- Metadata fields ``source_family``, ``source_type``, ``source_path``, ``title``,
  ``tags``, and ``restricted_use`` are preserved in the KnowledgeEntry.metadata
  dict so they survive promotion into the lexical index and can be used as
  post-retrieval filters via MemoryAPI.query(filters=...).

Typical usage (via seed_loader.seed_compiled_knowledge):
    counts = await seed_compiled_knowledge(api, config)
    # counts == {"policy_db": 21, "intel_db": 53505, ...}
"""
from __future__ import annotations

import json
import logging
import pathlib
from typing import TYPE_CHECKING, Any

from memfabric.ids import new_id, now
from memfabric.types import KnowledgeEntry

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled-file names expected per family (must match REQUIRED_OUTPUTS in
# compile_knowledge.py and layout.py).
# ---------------------------------------------------------------------------

_FAMILY_JSONL: dict[str, list[str]] = {
    "policy_db": ["policy_records.jsonl"],
    "methodology_db": ["methodology_chunks.jsonl"],
    "intel_db": [
        "attack_techniques.jsonl",
        "cwe_weaknesses.jsonl",
        "capec_patterns.jsonl",
        "cve_slim.jsonl",
    ],
    "payload_db": ["payload_records.jsonl", "wordlist_manifest.jsonl"],
}

# Source for all compiled knowledge entries — used as KnowledgeEntry.source.
_COMPILED_SOURCE = "compiled_knowledge"


async def load_compiled_family(
    compiled_dir: str | pathlib.Path,
    family_name: str,
    api: "MemoryAPI",
    *,
    confidence_override: float | None = None,
) -> int:
    """Stage all compiled JSONL records from *compiled_dir* for *family_name*.

    Parameters
    ----------
    compiled_dir:
        Path to the ``compiled/`` subdirectory for this family
        (e.g. ``knowledge/policy_db/compiled``).
    family_name:
        One of ``"policy_db"``, ``"methodology_db"``, ``"intel_db"``,
        ``"payload_db"``.  Used as the ``source_family`` metadata field so
        callers can filter results with
        ``api.query(filters={"source_family": family_name})``.
    api:
        Live ``MemoryAPI`` instance.  All writes go through
        ``api.propose_knowledge()`` — no direct store access.
    confidence_override:
        When set, overrides the confidence value from the compiled record.
        Useful for loading untrusted or low-quality families at lower confidence.

    Returns
    -------
    int
        Number of records staged (before Reflector promotion).
    """
    src = pathlib.Path(compiled_dir)
    if not src.is_dir():
        logger.warning("compiled_loader: compiled dir does not exist: %s", src)
        return 0

    filenames = _FAMILY_JSONL.get(family_name)
    if filenames is None:
        # Load all .jsonl files in the directory for unknown families.
        filenames = [p.name for p in src.glob("*.jsonl")]

    total = 0
    for filename in filenames:
        path = src / filename
        if not path.exists():
            logger.debug("compiled_loader: %s not found, skipping", path)
            continue
        count = await _load_jsonl_file(path, family_name, api, confidence_override)
        total += count
        logger.debug("compiled_loader: staged %d records from %s", count, path.name)

    logger.info("compiled_loader: staged %d total records from family=%s", total, family_name)
    return total


async def _load_jsonl_file(
    path: pathlib.Path,
    family_name: str,
    api: "MemoryAPI",
    confidence_override: float | None,
) -> int:
    """Read one JSONL file and propose each record via MemoryAPI."""
    count = 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("compiled_loader: cannot read %s: %s", path, exc)
        return 0

    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning(
                "compiled_loader: invalid JSON in %s line %d: %s", path.name, line_no, exc
            )
            continue

        entry = _record_to_knowledge_entry(record, family_name, confidence_override)
        if entry is None:
            continue
        try:
            await api.propose_knowledge(entry)
            count += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "compiled_loader: propose_knowledge failed for %s line %d: %s",
                path.name, line_no, exc,
            )

    return count


def _record_to_knowledge_entry(
    record: dict[str, Any],
    family_name: str,
    confidence_override: float | None,
) -> KnowledgeEntry | None:
    """Convert a raw compiled-record dict into a KnowledgeEntry."""
    text = record.get("text", "")
    if not isinstance(text, str) or not text.strip():
        return None

    rec_id = record.get("id") or new_id()
    confidence = confidence_override if confidence_override is not None else float(record.get("confidence", 0.7))
    tags = record.get("tags") or []
    rec_metadata: dict[str, Any] = dict(record.get("metadata") or {})

    # Preserve all provenance fields that must survive promotion into the
    # lexical index so they are available as retrieval filter keys.
    metadata: dict[str, Any] = {
        **rec_metadata,
        "source_family": family_name,
        "source_type": record.get("source_type", ""),
        "source_path": record.get("source_path", ""),
        "title": record.get("title", ""),
        "tags": tags,
        "tier": "semantic",
    }
    # Preserve restricted_use from inner metadata if present.
    if "restricted_use" not in metadata:
        metadata["restricted_use"] = rec_metadata.get("restricted_use", "general")

    return KnowledgeEntry(
        id=str(rec_id),
        text=text.strip(),
        source=_COMPILED_SOURCE,
        confidence=confidence,
        timestamp=record.get("updated_at", now()),
        metadata=metadata,
    )
