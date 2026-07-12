# payload_compiler.py
# Compiles payload_db sources (GTFOBins, LOLBAS, PayloadsAllTheThings) into semantic records and SecLists into wordlist manifests.
"""Compile payload_db sources into two JSONL files.

Input:  <knowledge_root>/payload_db/
Output: <knowledge_root>/payload_db/compiled/
          payload_records.jsonl    — semantic records from markdown/yaml/text
          wordlist_manifest.jsonl  — manifest records for SecLists wordlists

Behaviour
---------
Payload sources:

GTFOBins (_gtfobins/ subdirectory):
  - Entries are extensionless YAML files (one per binary, e.g. ``curl``, ``7z``).
  - YAML key ``functions`` maps to function categories, each with a ``code`` field.
  - source_type="payload", confidence=0.7.

LOLBAS (yml/ subdirectory):
  - Entries are .yml files with ``Name``, ``Description``, ``Commands`` keys.
  - source_type="payload", confidence=0.7.

PayloadsAllTheThings:
  - .md files split on "## " headings then chunked by size.
  - source_type="payload", confidence=0.7.

SecLists (wordlists):
  - Line-by-line content is NOT ingested as RAG text.
  - One manifest record per file: path, category, approx line count, recommended_use.
  - source_type="wordlist_manifest", confidence=0.6.
  - Passwords/ and credential-adjacent directories have
    metadata.restricted_use="explicit_operator_approval_required".

Missing source directory is a graceful no-op (returns 0, 0).
"""
from __future__ import annotations

import logging
import pathlib

import yaml as _yaml

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
_YAML_EXTENSIONS = frozenset({".yml", ".yaml"})
_MAX_CHUNK_CHARS = 1500

# SecLists subdirectories that are wordlists (manifest-only, no RAG ingestion).
_SECLISTS_SUBDIR = "SecLists"

# GTFOBins stores extensionless YAML entries in this subdirectory.
_GTFOBINS_SUBDIR = "_gtfobins"

# Directories whose contents require explicit operator approval to use.
_RESTRICTED_DIRS = frozenset({
    "Passwords", "Leaked-Databases", "Cracked-Hashes",
    "Honeypot-Captures", "Default-Credentials",
})

# Directories whose wordlists have a clear recommended use label.
_RECOMMENDED_USE = {
    "Discovery": "directory_and_file_discovery",
    "Fuzzing": "protocol_fuzzing",
    "Usernames": "username_enumeration",
    "Passwords": "password_testing",
    "Web-Shells": "web_shell_reference",
    "Payloads": "attack_payload_reference",
    "Pattern-Matching": "source_code_grep",
    "Ai": "llm_testing",
    "Miscellaneous": "general_reference",
}


def compile_payload(
    payload_db_path: str | pathlib.Path,
    output_dir: str | pathlib.Path,
) -> tuple[int, int]:
    """Compile payload_db sources.

    Returns
    -------
    tuple[int, int]
        (payload_record_count, wordlist_manifest_count)
    """
    src = pathlib.Path(payload_db_path)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not src.is_dir():
        logger.warning("payload_compiler: payload_db path does not exist: %s", src)
        return 0, 0

    payload_records: list[CompiledKnowledgeRecord] = []
    manifest_records: list[CompiledKnowledgeRecord] = []

    for path in iter_files(src):
        # Route to manifest if path is under SecLists
        if _is_seclists(path, src):
            rec = _make_manifest_record(path, src)
            if rec is not None:
                manifest_records.append(rec)
            continue

        ext = path.suffix.lower()
        if ext in _MD_EXTENSIONS:
            payload_records.extend(_compile_markdown(path))
        elif ext in _YAML_EXTENSIONS:
            rec = _compile_yaml(path)
            if rec is not None:
                payload_records.append(rec)
        elif ext == "" and _is_gtfobins_entry(path, src):
            # GTFOBins: extensionless YAML files in _gtfobins/ subdirectory
            rec = _compile_gtfobins(path)
            if rec is not None:
                payload_records.append(rec)
        else:
            logger.debug("payload_compiler: skipping unsupported file: %s", path)

    p_count = write_jsonl(payload_records, out / "payload_records.jsonl")
    m_count = write_jsonl(manifest_records, out / "wordlist_manifest.jsonl")
    logger.info(
        "payload_compiler: %d payload records, %d manifest records from %s",
        p_count, m_count, src,
    )
    return p_count, m_count


# ---------------------------------------------------------------------------
# Payload source compilers
# ---------------------------------------------------------------------------

def _compile_markdown(path: pathlib.Path) -> list[CompiledKnowledgeRecord]:
    text = read_text_safely(path)
    if not text.strip():
        return []

    chunks = _chunk_markdown_or_size(text, _MAX_CHUNK_CHARS)
    records = []
    tags = _path_tags(path)
    for idx, chunk in enumerate(chunks):
        chunk = normalize_whitespace(chunk)
        if not chunk:
            continue
        rec_id = stable_record_id("payload_db", "payload", str(path), idx)
        first_line = next((l.lstrip("#").strip() for l in chunk.splitlines() if l.strip()), path.stem)
        records.append(CompiledKnowledgeRecord(
            id=rec_id,
            source_family="payload_db",
            source_type="payload",
            source_path=str(path),
            title=first_line[:120] or path.stem,
            text=chunk,
            tags=tags,
            confidence=0.7,
            updated_at=now(),
            metadata={"chunk_index": idx, "source_file": path.name, "payload_family": path.parent.name},
        ))
    return records


def _compile_yaml(path: pathlib.Path) -> CompiledKnowledgeRecord | None:
    """Extract key text fields from a YAML payload entry."""
    raw = read_text_safely(path)
    if not raw.strip():
        return None
    try:
        data = _yaml.safe_load(raw)
    except _yaml.YAMLError as exc:
        logger.warning("payload_compiler: YAML parse error in %s: %s", path, exc)
        return None
    if not isinstance(data, dict):
        return None

    # LOLBAS / GTFOBins YAML: Name, Description, Commands[]
    name = data.get("Name") or data.get("name") or path.stem
    description = data.get("Description") or data.get("description") or ""
    commands = data.get("Commands") or data.get("commands") or data.get("functions") or []

    text_parts = [str(name)]
    if description:
        text_parts.append(str(description))
    if isinstance(commands, list):
        for cmd in commands[:10]:  # cap at 10 commands to keep records bounded
            if isinstance(cmd, dict):
                for field in ("Command", "command", "code", "description", "Description", "Usecase"):
                    val = cmd.get(field)
                    if val and isinstance(val, str) and val.strip():
                        text_parts.append(val.strip())
                        break

    text = normalize_whitespace("\n".join(text_parts))
    if not text or len(text) < 10:
        return None

    rec_id = stable_record_id("payload_db", "payload", str(path), 0)
    tags = _path_tags(path)
    return CompiledKnowledgeRecord(
        id=rec_id,
        source_family="payload_db",
        source_type="payload",
        source_path=str(path),
        title=str(name)[:120],
        text=text,
        tags=tags,
        confidence=0.7,
        updated_at=now(),
        metadata={"source_file": path.name, "payload_family": path.parent.name},
    )


# ---------------------------------------------------------------------------
# SecLists manifest
# ---------------------------------------------------------------------------

def _make_manifest_record(
    path: pathlib.Path, src_root: pathlib.Path
) -> CompiledKnowledgeRecord | None:
    """Create a manifest record for a SecLists wordlist file."""
    # Only create manifests for text-like wordlist files
    if path.suffix.lower() not in frozenset({".txt", ".lst", ".list", ".dict", "", ".fuzz"}):
        if path.suffix.lower() not in frozenset({".txt", ""}):
            return None

    rel = path.relative_to(src_root / _SECLISTS_SUBDIR) if _SECLISTS_SUBDIR in path.parts else path
    parts = rel.parts

    # Approximate line count without loading the whole file
    approx_lines = _approx_line_count(path)
    category = _wordlist_category(parts)
    recommended_use = _RECOMMENDED_USE.get(parts[0] if parts else "", "general_reference")

    restricted = any(part in _RESTRICTED_DIRS for part in parts)
    restricted_use = "explicit_operator_approval_required" if restricted else "general"

    text = (
        f"Wordlist: {path.name}. "
        f"Category: {category}. "
        f"Approximate entries: {approx_lines}. "
        f"Recommended use: {recommended_use}. "
        f"Restricted use: {restricted_use}. "
        f"Path: {rel}."
    )

    rec_id = stable_record_id("payload_db", "wordlist_manifest", str(path), 0)
    return CompiledKnowledgeRecord(
        id=rec_id,
        source_family="payload_db",
        source_type="wordlist_manifest",
        source_path=str(path),
        title=f"Wordlist: {path.name}",
        text=text,
        tags=["wordlist", "seclists", category],
        confidence=0.6,
        updated_at=now(),
        metadata={
            "category": category,
            "approx_lines": approx_lines,
            "recommended_use": recommended_use,
            "restricted_use": restricted_use,
            "relative_path": str(rel),
        },
    )


def _approx_line_count(path: pathlib.Path, sample_bytes: int = 65536) -> int:
    """Estimate line count from first sample_bytes without reading the whole file."""
    try:
        stat = path.stat()
        if stat.st_size == 0:
            return 0
        raw = path.read_bytes()[:sample_bytes]
        lines_in_sample = raw.count(b"\n") + 1
        if len(raw) < stat.st_size:
            return int(lines_in_sample * stat.st_size / len(raw))
        return lines_in_sample
    except OSError:
        return 0


def _wordlist_category(parts: tuple[str, ...]) -> str:
    if not parts:
        return "general"
    top = parts[0]
    if len(parts) > 1:
        return f"{top}/{parts[1]}"
    return top


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _is_gtfobins_entry(path: pathlib.Path, root: pathlib.Path) -> bool:
    """Return True if *path* is an extensionless entry inside a GTFOBins _gtfobins/ dir."""
    try:
        rel = path.relative_to(root)
        parts = rel.parts
        return _GTFOBINS_SUBDIR in parts and path.suffix == ""
    except ValueError:
        return False


def _compile_gtfobins(path: pathlib.Path) -> CompiledKnowledgeRecord | None:
    """Compile one GTFOBins extensionless YAML entry."""
    raw = read_text_safely(path)
    if not raw.strip():
        return None
    try:
        data = _yaml.safe_load(raw)
    except _yaml.YAMLError as exc:
        logger.warning("payload_compiler: YAML parse error in GTFOBins file %s: %s", path, exc)
        return None
    if not isinstance(data, dict):
        return None

    name = path.name  # the binary name (e.g. "curl", "7z")
    functions = data.get("functions", {})
    if not isinstance(functions, dict):
        functions = {}

    text_parts = [f"GTFOBins: {name}"]
    for func_category, entries in functions.items():
        if not entries:
            continue
        if isinstance(entries, list):
            for entry in entries[:5]:  # cap per category
                if isinstance(entry, dict):
                    code = entry.get("code", "")
                    if code and isinstance(code, str):
                        text_parts.append(f"[{func_category}] {code.strip()[:300]}")
        text_parts.append(f"function: {func_category}")

    text = normalize_whitespace("\n".join(text_parts))
    if not text or len(text) < 10:
        return None

    rec_id = stable_record_id("payload_db", "payload", str(path), 0, extra=name)
    return CompiledKnowledgeRecord(
        id=rec_id,
        source_family="payload_db",
        source_type="payload",
        source_path=str(path),
        title=f"GTFOBins: {name}",
        text=text,
        tags=["payload", "gtfobins", "lolbins"],
        confidence=0.7,
        updated_at=now(),
        metadata={
            "source_file": path.name,
            "payload_family": "GTFOBins",
            "function_categories": list(functions.keys()),
        },
    )


def _is_seclists(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        rel = path.relative_to(root)
        return rel.parts[0] == _SECLISTS_SUBDIR if rel.parts else False
    except ValueError:
        return False


def _chunk_markdown_or_size(text: str, max_chars: int) -> list[str]:
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
    if len(chunks) <= 1:
        raw = text.strip()
        return [raw[i: i + max_chars] for i in range(0, len(raw), max_chars)] if raw else []
    return [c for c in chunks if c.strip()]


def _path_tags(path: pathlib.Path) -> list[str]:
    """Derive tags from the file's ancestor directory names."""
    tags = ["payload"]
    for part in path.parts:
        lower = part.lower()
        if lower in {"gtfobins", "lolbas", "payloadsallthethings", "seclists"}:
            tags.append(lower.replace("payloadsallthethings", "payloads-all-the-things"))
        elif lower in {"osbinaries", "oslibraries", "osscripts"}:
            tags.append(lower)
    return tags
