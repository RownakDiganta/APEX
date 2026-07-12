# __init__.py
# Package marker for the knowledge compiler sub-package.
"""Public exports for apex_host.knowledge.compiler."""
from __future__ import annotations

from apex_host.knowledge.compiler.schemas import (
    CompiledKnowledgeRecord,
    SourceFamily,
    SourceType,
)
from apex_host.knowledge.compiler.common import (
    iter_files,
    normalize_whitespace,
    read_text_safely,
    stable_record_id,
    write_jsonl,
)

__all__ = [
    "CompiledKnowledgeRecord",
    "SourceFamily",
    "SourceType",
    "iter_files",
    "normalize_whitespace",
    "read_text_safely",
    "stable_record_id",
    "write_jsonl",
]
