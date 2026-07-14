# methodology_compiler.py
# Compiles methodology_db sources (NIST, OWASP, PTES PDFs and markdown) into JSONL records.
"""Compile methodology_db sources into CompiledKnowledgeRecord JSONL.

Input:  <knowledge_root>/methodology_db/  (or a sources/ subdirectory)
Output: <knowledge_root>/methodology_db/compiled/methodology_chunks.jsonl

Behaviour
---------
- .md and .txt files are read and chunked on "## " section headings first,
  then by size (1500 chars) if no headings are present.
- .pdf files produce a metadata-only stub record (no PDF dependency).
- source_family is always "methodology_db", source_type "methodology".
- Missing source directory is a graceful no-op (returns 0).
"""
from __future__ import annotations

import logging
import pathlib

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

_TEXT_EXTENSIONS = frozenset({".md", ".txt"})
_PDF_EXTENSION = ".pdf"
_MAX_CHUNK_CHARS = 1500


def compile_methodology(
    sources_path: str | pathlib.Path,
    output_dir: str | pathlib.Path,
) -> int:
    """Compile all methodology source files into JSONL records.

    Parameters
    ----------
    sources_path:
        Directory containing raw methodology files.  May be the family root
        (``methodology_db/``) or its ``sources/`` subdirectory.
    output_dir:
        Directory where the compiled JSONL file is written.

    Returns
    -------
    int
        Number of records written.
    """
    src = pathlib.Path(sources_path)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not src.is_dir():
        logger.warning("methodology_compiler: sources path does not exist: %s", src)
        return 0

    records: list[CompiledKnowledgeRecord] = []

    for path in iter_files(src):
        ext = path.suffix.lower()
        if ext in _TEXT_EXTENSIONS:
            records.extend(_compile_text_file(path))
        elif ext == _PDF_EXTENSION:
            records.append(_compile_pdf_stub(path))
        else:
            logger.debug("methodology_compiler: skipping unsupported file: %s", path)

    count = write_jsonl(records, out / "methodology_chunks.jsonl")
    logger.info("methodology_compiler: compiled %d records from %s", count, src)
    return count


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compile_text_file(path: pathlib.Path) -> list[CompiledKnowledgeRecord]:
    text = read_text_safely(path)
    if not text.strip():
        return []

    chunks = _chunk_markdown_or_size(text, _MAX_CHUNK_CHARS)
    records = []
    for idx, chunk in enumerate(chunks):
        chunk = normalize_whitespace(chunk)
        if not chunk:
            continue
        rec_id = stable_record_id("methodology_db", "methodology", str(path), idx)
        # Use first non-empty line of chunk as title
        first_line = next((line.strip().lstrip("#").strip() for line in chunk.splitlines() if line.strip()), path.stem)
        records.append(CompiledKnowledgeRecord(
            id=rec_id,
            source_family="methodology_db",
            source_type="methodology",
            source_path=str(path),
            title=first_line[:120] or path.stem,
            text=chunk,
            tags=["methodology", _doc_tag(path.name)],
            confidence=0.75,
            updated_at=now(),
            metadata={"chunk_index": idx, "source_file": path.name},
        ))
    return records


def _compile_pdf_stub(path: pathlib.Path) -> CompiledKnowledgeRecord:
    rec_id = stable_record_id("methodology_db", "methodology", str(path), 0)
    title = path.stem.replace("_", " ").replace("-", " ").title()
    stub_text = (
        f"[PDF document — text extraction unavailable] "
        f"File: {path.name}. "
        f"Document: {title}. "
        f"This methodology reference covers security testing procedures. "
        f"Source family: methodology_db."
    )
    return CompiledKnowledgeRecord(
        id=rec_id,
        source_family="methodology_db",
        source_type="methodology",
        source_path=str(path),
        title=title,
        text=stub_text,
        tags=["methodology", _doc_tag(path.name), "pdf-stub"],
        confidence=0.4,
        updated_at=now(),
        metadata={"pdf_stub": True, "source_file": path.name},
    )


def _chunk_markdown_or_size(text: str, max_chars: int) -> list[str]:
    """Split on '## ' headings; fall back to size-based chunks."""
    lines = text.splitlines()
    chunks: list[str] = []
    current: list[str] = []
    for line in lines:
        if line.startswith("## ") and current:
            chunks.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)
    if current:
        chunks.append("\n".join(current).strip())

    # If no headings produced more than 1 chunk, use size-based splitting
    if len(chunks) <= 1:
        raw = text.strip()
        if not raw:
            return []
        return [raw[i: i + max_chars] for i in range(0, len(raw), max_chars)]
    return [c for c in chunks if c.strip()]


def _doc_tag(filename: str) -> str:
    """Map a filename to a short tag (e.g. 'nist', 'owasp', 'ptes')."""
    lower = filename.lower()
    if "nist" in lower:
        return "nist"
    if "owasp" in lower:
        return "owasp"
    if "ptes" in lower:
        return "ptes"
    return "methodology"
