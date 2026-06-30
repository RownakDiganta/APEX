"""RAG seed source: ingest an external payload repository into memfabric's
staged knowledge tier.

This module reads files from a host-supplied directory at runtime and stages
each chunk via ``MemoryAPI.propose_knowledge()``. Per memfabric Invariant 4,
staged entries are not retrievable until the Reflector promotes them — this
loader does not bypass that gate.

Do not hardcode payload content here. The payload repository is the only
source of payload text; this module only chunks and tags it.
"""
from __future__ import annotations

import logging
import pathlib
from typing import TYPE_CHECKING

from memfabric.types import KnowledgeEntry

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI

logger = logging.getLogger(__name__)

_INGESTIBLE_SUFFIXES = frozenset({".md", ".txt", ".py", ".rb", ".sh", ".json", ".yaml", ".yml"})
_MAX_CHUNK_CHARS = 1500


class PayloadRepoLoader:
    """Recursively loads a payload repository as staged semantic knowledge."""

    def __init__(self, payload_repo_path: str, api: "MemoryAPI") -> None:
        self._root = pathlib.Path(payload_repo_path)
        self._api = api

    async def load(self) -> int:
        """Chunk and propose every ingestible file under the repo root.

        Returns the number of chunks proposed. Returns 0 (logs a warning)
        if the repo path does not exist — this is not a fatal error since
        the host may run without a payload repo configured.
        """
        if not self._root.is_dir():
            logger.warning("payload repo path does not exist: %s", self._root)
            return 0

        count = 0
        for path in sorted(self._root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in _INGESTIBLE_SUFFIXES:
                continue
            for chunk_text in self._chunk_file(path):
                if not chunk_text.strip():
                    continue
                entry = KnowledgeEntry(
                    text=chunk_text,
                    source=str(path),
                    confidence=0.7,
                    metadata={
                        "source_path": str(path),
                        "payload_family": path.parent.name,
                        "file_ext": path.suffix.lower(),
                        "tier": "semantic",
                        "source": "payload_repo",
                    },
                )
                await self._api.propose_knowledge(entry)
                count += 1
        logger.info("payload repo loader: proposed %d chunks from %s", count, self._root)
        return count

    def _chunk_file(self, path: pathlib.Path) -> list[str]:
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.lower() == ".md":
            return self._chunk_markdown(text)
        return self._chunk_by_size(text)

    def _chunk_markdown(self, text: str) -> list[str]:
        """Split on '## ' headings (the predecessor APEX project's lazy
        section-chunking pattern), falling back to size-chunking if no
        '## ' headings are present."""
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
            return self._chunk_by_size(text)
        return chunks

    def _chunk_by_size(self, text: str, max_chars: int = _MAX_CHUNK_CHARS) -> list[str]:
        stripped = text.strip()
        if not stripped:
            return []
        return [stripped[i : i + max_chars] for i in range(0, len(stripped), max_chars)]
