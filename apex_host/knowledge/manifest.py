# manifest.py
# Deterministic, content-hash-based identity for a compiled knowledge family — never modification time — used to decide whether cached initialization state can be reused.
"""Deterministic per-family manifest computation (Phase 4 knowledge-initialization cache).

A ``FamilyManifest`` answers one question precisely: "is this family's
compiled-knowledge input, as it exists on disk right now, identical to what
was staged and promoted in a prior run?" The identity is computed from
record IDs and content hashes — **never** from file modification time,
which is explicitly disallowed by this feature's own design brief (mtimes
change on every container rebuild/checkout/copy even when byte content is
unchanged, which would make the cache never hit).

Two levels of hashing are used, deliberately:

1. Per-record ``content_hash`` — SHA-256 over a canonical
   ``(text, confidence, tags, metadata)`` tuple for one compiled record.
   Compiled-record ``id`` values are content-addressed on ``source_path`` +
   ``chunk_index`` (see ``apex_host.knowledge.compiler.common
   .stable_record_id``), NOT on the record's own text/confidence/metadata —
   so two runs of the compiler over an *edited* source file can produce the
   SAME id with DIFFERENT content. Relying on ID-set comparison alone would
   silently miss that edit. ``content_hash`` closes that gap: a same-id,
   different-content record always produces a different ``content_hash``.

2. ``dataset_id`` (the family-level identity) — SHA-256 over every
   ``"id:content_hash"`` pair, sorted, joined. Deterministic regardless of
   file order, JSONL line order, or which physical file a record happens to
   live in — a family manifest computed from the same logical record set is
   always identical, even if the compiler's own file layout changes.

Reading every compiled record to compute this is a full JSON-parse pass
over the family's JSONL files (same I/O a full stage would need) but with
none of the downstream cost (no MemoryAPI writes, no Reflector promotion) —
measured at a small fraction of a second even for a 60k+ record family (see
``docs/knowledge-initialization.md`` "Manifest identity" for a timing
note). This is intentionally NOT "free" — it is "cheap enough to run on
every startup, every family, unconditionally" without needing its own
separate cache.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import pathlib
from dataclasses import dataclass, field
from typing import Any

from apex_host.knowledge.compiled_loader import FAMILY_JSONL_FILES
from apex_host.knowledge.compiler.schemas import COMPILER_SCHEMA_VERSION

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RecordDigest:
    """One compiled record's identity + content fingerprint."""

    record_id: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class FamilyManifest:
    """Deterministic identity for one knowledge family's compiled input.

    ``compiled_at`` is diagnostic-only (the maximum ``updated_at`` value
    seen across the family's records, or ``""`` if none carry one) — it is
    NEVER consulted when deciding whether the manifest matches a persisted
    one. Only ``dataset_id`` (plus ``schema_version`` and ``family``) is the
    identity.
    """

    family: str
    schema_version: str
    source_artifacts: list[str]
    record_count: int
    dataset_id: str
    compiled_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "schema_version": self.schema_version,
            "source_artifacts": list(self.source_artifacts),
            "record_count": self.record_count,
            "dataset_id": self.dataset_id,
            "compiled_at": self.compiled_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FamilyManifest":
        return cls(
            family=str(d.get("family", "")),
            schema_version=str(d.get("schema_version", "")),
            source_artifacts=list(d.get("source_artifacts") or []),
            record_count=int(d.get("record_count", 0)),
            dataset_id=str(d.get("dataset_id", "")),
            compiled_at=str(d.get("compiled_at", "")),
        )

    def identity_matches(self, other: "FamilyManifest") -> bool:
        """True when *other* describes the exact same dataset for reuse purposes.

        Compares ``family`` + ``schema_version`` + ``dataset_id`` only —
        deliberately excludes ``compiled_at`` (diagnostic-only) and
        ``source_artifacts``/``record_count`` (already folded into
        ``dataset_id``; kept as separate fields purely for human-readable
        reporting, not identity).
        """
        return (
            self.family == other.family
            and self.schema_version == other.schema_version
            and self.dataset_id == other.dataset_id
        )


@dataclass(slots=True)
class FamilyRecordSet:
    """A computed manifest plus the per-record digests it was built from.

    ``digests`` is keyed by record id — used by
    ``apex_host.knowledge.init_cache`` to diff against a persisted prior
    digest set and determine exactly which records are new/changed/removed,
    without re-reading the compiled files a second time.
    """

    manifest: FamilyManifest
    digests: dict[str, RecordDigest] = field(default_factory=dict)


def _record_content_hash(record: dict[str, Any]) -> str:
    """Stable hash of a compiled record's content-bearing fields.

    Deliberately excludes ``id``/``source_path``/``chunk_index`` (identity,
    not content) and ``updated_at`` (diagnostic timestamp — see module
    docstring on why timestamps are never part of identity).
    """
    canonical = json.dumps(
        {
            "text": record.get("text", ""),
            "confidence": record.get("confidence", 0.7),
            "tags": record.get("tags") or [],
            "metadata": record.get("metadata") or {},
            "title": record.get("title", ""),
            "source_type": record.get("source_type", ""),
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_family_record_set_sync(
    compiled_dir: pathlib.Path, family_name: str
) -> FamilyRecordSet | None:
    """Synchronous implementation — safe to run in a thread via ``asyncio.to_thread``."""
    if not compiled_dir.is_dir():
        return None

    filenames = FAMILY_JSONL_FILES.get(family_name)
    if filenames is None:
        filenames = sorted(p.name for p in compiled_dir.glob("*.jsonl"))

    digests: dict[str, RecordDigest] = {}
    present_artifacts: list[str] = []
    max_updated_at = ""

    for filename in filenames:
        path = compiled_dir / filename
        if not path.exists():
            continue
        present_artifacts.append(filename)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("manifest: cannot read %s: %s", path, exc)
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "manifest: invalid JSON in %s line %d: %s", path.name, line_no, exc
                )
                continue
            rec_text = record.get("text", "")
            if not isinstance(rec_text, str) or not rec_text.strip():
                continue  # matches compiled_loader's own "skip empty text" rule
            rec_id = str(record.get("id") or "")
            if not rec_id:
                continue
            digests[rec_id] = RecordDigest(
                record_id=rec_id, content_hash=_record_content_hash(record)
            )
            updated_at = str(record.get("updated_at", ""))
            if updated_at > max_updated_at:
                max_updated_at = updated_at

    if not present_artifacts:
        return None

    dataset_payload = "\n".join(
        f"{rid}:{digests[rid].content_hash}" for rid in sorted(digests)
    )
    dataset_id = hashlib.sha256(dataset_payload.encode("utf-8")).hexdigest()

    manifest = FamilyManifest(
        family=family_name,
        schema_version=COMPILER_SCHEMA_VERSION,
        source_artifacts=sorted(present_artifacts),
        record_count=len(digests),
        dataset_id=dataset_id,
        compiled_at=max_updated_at,
    )
    return FamilyRecordSet(manifest=manifest, digests=digests)


async def compute_family_record_set(
    compiled_dir: str | pathlib.Path, family_name: str
) -> FamilyRecordSet | None:
    """Compute the current, deterministic manifest + per-record digests for a family.

    Returns ``None`` when the compiled directory does not exist or none of
    the family's expected JSONL files are present (mirrors
    ``load_compiled_family``'s own graceful-degradation behavior — a
    missing family is not an error).

    Offloaded to a thread (``asyncio.to_thread``) since this does
    synchronous file I/O and JSON parsing — consistent with this codebase's
    established Phase 7 pattern of never blocking the event loop on file
    reads (``apex_host/async_utils.py``).
    """
    return await asyncio.to_thread(
        _compute_family_record_set_sync, pathlib.Path(compiled_dir), family_name
    )
