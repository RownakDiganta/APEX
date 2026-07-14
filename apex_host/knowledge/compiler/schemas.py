# schemas.py
# Typed dataclasses for compiled knowledge records and their source-family / source-type enumerations.
"""Schemas for the compiled knowledge records that APEX ingests at runtime.

The external knowledge base is organised into four top-level families:

  intel_db/       — CVE, CWE, CAPEC, MITRE ATT&CK
  methodology_db/ — NIST, OWASP, PTES methodology PDFs
  payload_db/     — GTFOBins, LOLBAS, PayloadsAllTheThings, SecLists
  policy_db/      — HTB legal / authorisation documents

Compiler scripts read raw source files from those directories, produce
``CompiledKnowledgeRecord`` instances, and write them to JSONL files under
a ``compiled/`` subdirectory.  At runtime APEX ingests the compiled JSONL
files, NOT the raw source documents.  This keeps startup fast and avoids
loading hundreds of megabytes of raw JSON or PDF into memory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Source-family and source-type enumerations
# ---------------------------------------------------------------------------

SourceFamily = Literal[
    "intel_db",
    "methodology_db",
    "payload_db",
    "policy_db",
]

SourceType = Literal[
    # intel_db
    "cve",
    "cwe",
    "capec",
    "attack",
    # methodology_db
    "methodology",
    # payload_db
    "payload",
    "wordlist_manifest",
    # policy_db
    "htb_rule",
    "legal_doc",
]

_VALID_FAMILIES: frozenset[str] = frozenset(
    {"intel_db", "methodology_db", "payload_db", "policy_db"}
)

_VALID_TYPES: frozenset[str] = frozenset(
    {
        "cve", "cwe", "capec", "attack",
        "methodology",
        "payload", "wordlist_manifest",
        "htb_rule", "legal_doc",
    }
)


# ---------------------------------------------------------------------------
# Compiled record
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class CompiledKnowledgeRecord:
    """A single compiled knowledge unit ready for ingestion via MemoryAPI.

    Fields
    ------
    id
        Stable, content-addressed identifier (see ``stable_record_id``).
    source_family
        Top-level knowledge directory: one of the ``SourceFamily`` literals.
    source_type
        Semantic type of the source: one of the ``SourceType`` literals.
    source_path
        Absolute or repo-relative path to the original source file.
    title
        Short human-readable label (file name, section heading, CVE ID, …).
    text
        The textual content that will be indexed and retrieved.
    tags
        Free-form string labels for filtering (e.g. ``["sql-injection"]``).
    confidence
        Prior confidence score (0–1) assigned at compile time.
    updated_at
        ISO-8601 UTC timestamp of when this record was compiled.
    metadata
        Arbitrary extra fields passed through to ``KnowledgeEntry.metadata``.
    """

    id: str
    source_family: str
    source_type: str
    source_path: str
    title: str
    text: str
    tags: list[str] = field(default_factory=list)
    confidence: float = 0.7
    updated_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.source_family not in _VALID_FAMILIES:
            raise ValueError(
                f"source_family {self.source_family!r} is not one of {sorted(_VALID_FAMILIES)}"
            )
        if self.source_type not in _VALID_TYPES:
            raise ValueError(
                f"source_type {self.source_type!r} is not one of {sorted(_VALID_TYPES)}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")
        if not self.id:
            raise ValueError("id must not be empty")
        if not self.source_path:
            raise ValueError("source_path must not be empty")
        if not self.text:
            raise ValueError("text must not be empty")

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (for JSONL output)."""
        return {
            "id": self.id,
            "source_family": self.source_family,
            "source_type": self.source_type,
            "source_path": self.source_path,
            "title": self.title,
            "text": self.text,
            "tags": self.tags,
            "confidence": self.confidence,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CompiledKnowledgeRecord":
        """Deserialise from a plain dict (from JSONL input)."""
        return cls(
            id=d["id"],
            source_family=d["source_family"],
            source_type=d["source_type"],
            source_path=d["source_path"],
            title=d.get("title", ""),
            text=d["text"],
            tags=list(d.get("tags", [])),
            confidence=float(d.get("confidence", 0.7)),
            updated_at=d.get("updated_at", ""),
            metadata=dict(d.get("metadata", {})),
        )
