# policy_compiler.py
# Compiles policy_db sources (HTB rules, legal docs) into JSONL records for APEX RAG ingestion.
"""Compile policy_db sources into CompiledKnowledgeRecord JSONL.

Input:  <knowledge_root>/policy_db/sources/
Output: <knowledge_root>/policy_db/compiled/policy_records.jsonl
        <knowledge_root>/policy_db/compiled/hackthebox_lab.yaml  (htb_rule summary)

Behaviour
---------
- .md and .txt files are read directly; rule-like lines are extracted as
  individual records, falling back to full-text chunking when no rules found.
- htb_platform_rules.md is treated as source_type="htb_rule" at confidence 0.9.
- All other .md/.txt files are source_type="legal_doc" at confidence 0.7.
- .pdf files produce a metadata-only stub record (no text extraction dependency).
- Missing source directory is a graceful no-op (returns 0).
"""
from __future__ import annotations

import logging
import pathlib
from typing import Any

import yaml

from apex_host.knowledge.compiler.common import (
    iter_files,
    normalize_whitespace,
    read_text_safely,
    stable_record_id,
    write_jsonl,
)
from apex_host.knowledge.compiler.schemas import CompiledKnowledgeRecord
from memfabric.ids import now

logger = logging.getLogger(__name__)

_MD_EXTENSIONS = frozenset({".md", ".txt"})
_PDF_EXTENSION = ".pdf"

# Lines that look like rules: start with a verb or bullet, or contain
# "must", "shall", "prohibited", "allowed", "not allowed".
_RULE_PATTERNS = (
    "must", "shall", "prohibited", "not allowed", "may not",
    "is required", "you must", "you may not", "users must",
)

_MAX_CHUNK_CHARS = 1500


def compile_policy(
    sources_path: str | pathlib.Path,
    output_dir: str | pathlib.Path,
) -> int:
    """Compile all policy source files into JSONL records.

    Parameters
    ----------
    sources_path:
        Directory containing raw policy source files (e.g. ``policy_db/sources/``).
    output_dir:
        Directory where compiled JSONL and YAML are written.

    Returns
    -------
    int
        Number of records written.
    """
    src = pathlib.Path(sources_path)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not src.is_dir():
        logger.warning("policy_compiler: sources path does not exist: %s", src)
        return 0

    records: list[CompiledKnowledgeRecord] = []
    htb_rule_records: list[dict[str, Any]] = []

    for path in iter_files(src):
        ext = path.suffix.lower()
        if ext in _MD_EXTENSIONS:
            recs = _compile_text_file(path)
            records.extend(recs)
            if path.name.lower() == "htb_platform_rules.md":
                htb_rule_records = [r.to_dict() for r in recs]
        elif ext == _PDF_EXTENSION:
            rec = _compile_pdf_stub(path)
            records.append(rec)
        else:
            logger.debug("policy_compiler: skipping unsupported file type: %s", path)

    count = write_jsonl(records, out / "policy_records.jsonl")

    # Write HTB rule summary YAML if we have any htb_rule records
    yaml_path = out / "hackthebox_lab.yaml"
    _write_htb_yaml(htb_rule_records, yaml_path)

    logger.info("policy_compiler: compiled %d records from %s", count, src)
    return count


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compile_text_file(path: pathlib.Path) -> list[CompiledKnowledgeRecord]:
    text = read_text_safely(path)
    if not text.strip():
        return []

    is_rule_file = path.name.lower() == "htb_platform_rules.md"
    source_type = "htb_rule" if is_rule_file else "legal_doc"
    confidence = 0.9 if is_rule_file else 0.7
    tags = ["htb", "policy"] if is_rule_file else ["legal", "policy"]

    if is_rule_file:
        # Split on top-level headings to preserve full rule sections with context.
        # Each section becomes one record so retrievers get coherent rule text.
        chunks = _split_on_headings(text)
        records = []
        for idx, chunk in enumerate(chunks):
            chunk = normalize_whitespace(chunk)
            if not chunk:
                continue
            first_line = next(
                (ln.lstrip("#").strip() for ln in chunk.splitlines() if ln.strip()), path.stem
            )
            rec_id = stable_record_id("policy_db", source_type, str(path), idx)
            records.append(CompiledKnowledgeRecord(
                id=rec_id,
                source_family="policy_db",
                source_type=source_type,
                source_path=str(path),
                title=first_line[:120] or path.stem,
                text=chunk,
                tags=tags,
                confidence=confidence,
                updated_at=now(),
                metadata={"section_index": idx, "source_file": path.name},
            ))
        if records:
            return records

    # Non-rule files and empty-section fallback: chunk by size
    return _chunk_text(text, path, source_type, confidence, tags)


def _extract_rules(text: str) -> list[str]:
    """Return lines that look like policy rules."""
    rules = []
    for line in text.splitlines():
        stripped = line.strip().lstrip("-*• ").strip()
        if len(stripped) < 20:
            continue
        low = stripped.lower()
        if any(kw in low for kw in _RULE_PATTERNS):
            rules.append(normalize_whitespace(stripped))
    return rules


def _chunk_text(
    text: str,
    path: pathlib.Path,
    source_type: str,
    confidence: float,
    tags: list[str],
) -> list[CompiledKnowledgeRecord]:
    chunks = _split_chunks(text, _MAX_CHUNK_CHARS)
    records = []
    for idx, chunk in enumerate(chunks):
        chunk = normalize_whitespace(chunk)
        if not chunk:
            continue
        rec_id = stable_record_id("policy_db", source_type, str(path), idx)
        records.append(CompiledKnowledgeRecord(
            id=rec_id,
            source_family="policy_db",
            source_type=source_type,
            source_path=str(path),
            title=f"{path.stem} — chunk {idx + 1}",
            text=chunk,
            tags=tags,
            confidence=confidence,
            updated_at=now(),
            metadata={"chunk_index": idx, "source_file": path.name},
        ))
    return records


def _compile_pdf_stub(path: pathlib.Path) -> CompiledKnowledgeRecord:
    """Create a metadata-only record for a PDF we cannot parse."""
    rec_id = stable_record_id("policy_db", "legal_doc", str(path), 0)
    title = path.stem.replace("_", " ").replace("-", " ").title()
    stub_text = (
        f"[PDF document — text extraction unavailable] "
        f"File: {path.name}. "
        f"Document: {title}. "
        f"Source family: policy_db. "
        f"This record is a metadata stub; obtain the compiled text version to retrieve content."
    )
    return CompiledKnowledgeRecord(
        id=rec_id,
        source_family="policy_db",
        source_type="legal_doc",
        source_path=str(path),
        title=title,
        text=stub_text,
        tags=["legal", "policy", "pdf-stub"],
        confidence=0.4,
        updated_at=now(),
        metadata={"pdf_stub": True, "source_file": path.name},
    )


def _write_htb_yaml(records: list[dict[str, Any]], path: pathlib.Path) -> None:
    """Write an HTB rule summary YAML file (compact, human-readable)."""
    summary = {
        "description": "HTB platform rule records compiled by policy_compiler.py",
        "updated_at": now(),
        "record_count": len(records),
        "records": [
            {
                "id": r["id"],
                "title": r["title"],
                "text": r["text"][:200],
                "confidence": r["confidence"],
            }
            for r in records
        ],
    }
    path.write_text(yaml.dump(summary, allow_unicode=True, sort_keys=False), encoding="utf-8")
    logger.debug("policy_compiler: wrote HTB rule YAML to %s", path)


def _split_on_headings(text: str) -> list[str]:
    """Split text on top-level markdown headings (# or ##), keeping the heading with its body."""
    lines = text.splitlines()
    chunks: list[str] = []
    current: list[str] = []
    for line in lines:
        if (line.startswith("# ") or line.startswith("## ")) and current:
            chunk = "\n".join(current).strip()
            if chunk:
                chunks.append(chunk)
            current = [line]
        else:
            current.append(line)
    if current:
        chunk = "\n".join(current).strip()
        if chunk:
            chunks.append(chunk)
    return chunks


def _split_chunks(text: str, max_chars: int) -> list[str]:
    stripped = text.strip()
    if not stripped:
        return []
    return [stripped[i: i + max_chars] for i in range(0, len(stripped), max_chars)]
