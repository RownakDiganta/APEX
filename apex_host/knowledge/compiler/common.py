# common.py
# Shared filesystem helpers used by knowledge compiler scripts: file iteration, safe text reading, JSONL I/O, stable ID generation, and whitespace normalisation.
"""Filesystem and serialisation helpers for the knowledge compiler.

All functions here are pure utilities with no dependency on memfabric or
apex_host business logic, making them easy to unit-test in isolation.
"""
from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import re
import unicodedata
from collections.abc import Generator
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from apex_host.knowledge.compiler.schemas import CompiledKnowledgeRecord

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File iteration
# ---------------------------------------------------------------------------

def iter_files(
    root: str | pathlib.Path,
    extensions: frozenset[str] | set[str] | None = None,
) -> Generator[pathlib.Path, None, None]:
    """Yield every regular file under *root*, optionally filtered by extension.

    Parameters
    ----------
    root:
        Directory to walk recursively.
    extensions:
        If given, only files whose ``suffix.lower()`` is in this set are
        yielded.  Pass ``None`` to yield all files.

    Yields
    ------
    pathlib.Path
        Absolute paths to matching files, in sorted order (deterministic).
    """
    root_path = pathlib.Path(root)
    if not root_path.is_dir():
        logger.warning("iter_files: root does not exist or is not a directory: %s", root_path)
        return
    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        if extensions is not None and path.suffix.lower() not in extensions:
            continue
        yield path


# ---------------------------------------------------------------------------
# Text I/O
# ---------------------------------------------------------------------------

def read_text_safely(path: str | pathlib.Path, max_bytes: int = 10_000_000) -> str:
    """Read a text file, returning an empty string on any error.

    Truncates to *max_bytes* (default 10 MB) to guard against accidentally
    reading a multi-GB NVD JSON dump into memory.

    Parameters
    ----------
    path:
        File to read.
    max_bytes:
        Maximum bytes to read.  Files larger than this are truncated with a
        warning log so callers can decide whether to handle the truncation.
    """
    path = pathlib.Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        logger.warning("read_text_safely: cannot read %s: %s", path, exc)
        return ""
    if len(raw) > max_bytes:
        logger.warning(
            "read_text_safely: %s is %d bytes, truncating to %d",
            path, len(raw), max_bytes,
        )
        raw = raw[:max_bytes]
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# JSONL I/O
# ---------------------------------------------------------------------------

def write_jsonl(
    records: list["CompiledKnowledgeRecord"],
    path: str | pathlib.Path,
) -> int:
    """Serialise *records* to a JSONL file, one record per line.

    Creates parent directories as needed.  Returns the number of records
    written.  Raises ``OSError`` if the file cannot be written.
    """
    out = pathlib.Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
            count += 1
    logger.info("write_jsonl: wrote %d records to %s", count, out)
    return count


def read_jsonl(path: str | pathlib.Path) -> list[dict[str, Any]]:
    """Read a JSONL file, returning a list of parsed dicts.

    Skips blank lines and logs (but does not raise on) malformed lines.
    Returns an empty list if the file does not exist.
    """

    p = pathlib.Path(path)
    if not p.exists():
        return []
    results: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("read_jsonl: malformed line %d in %s: %s", lineno, p, exc)
    return results


# ---------------------------------------------------------------------------
# Stable ID generation
# ---------------------------------------------------------------------------

def stable_record_id(
    source_family: str,
    source_type: str,
    source_path: str,
    chunk_index: int = 0,
    extra: str = "",
) -> str:
    """Return a stable, content-addressed hex ID for a knowledge record.

    The ID is derived from a SHA-256 hash of the key fields so that:
    - Re-running the compiler on unchanged source files yields the same IDs.
    - Different chunks of the same file get different IDs.
    - Changing any key field (including ``extra``) invalidates the ID.

    The returned string is the first 32 hex characters of the SHA-256 digest
    — long enough to be collision-resistant in practice, short enough to be
    readable in logs.
    """
    payload = f"{source_family}|{source_type}|{source_path}|{chunk_index}|{extra}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest[:32]


# ---------------------------------------------------------------------------
# Text normalisation
# ---------------------------------------------------------------------------

_MULTI_WHITESPACE = re.compile(r"[ \t]+")
_MULTI_NEWLINE = re.compile(r"\n{3,}")


def normalize_whitespace(text: str) -> str:
    """Collapse runs of spaces/tabs to a single space and runs of 3+ newlines to 2.

    Also strips leading/trailing whitespace and normalises Unicode to NFC so
    that different encodings of the same character compare equal in BM25.
    """
    text = unicodedata.normalize("NFC", text)
    text = _MULTI_WHITESPACE.sub(" ", text)
    text = _MULTI_NEWLINE.sub("\n\n", text)
    return text.strip()
