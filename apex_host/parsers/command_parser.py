"""Generic fallback parser for tool output that has no dedicated parser.

Implements memfabric.coordination.protocols.Parser. Unlike the specialised
parsers (nmap/ffuf/gobuster/browser), this does not attempt structural
extraction — it stores the raw observation as a single low-confidence
KnowledgeEntry proposal and produces no graph deltas, so unrecognised tool
output is never silently dropped.
"""
from __future__ import annotations

from memfabric.ids import now
from memfabric.types import KnowledgeEntry, ParsedObservation, RawObservation


class CommandParser:
    """Stateless fallback parser: RawObservation -> ParsedObservation."""

    def parse(self, raw: RawObservation) -> ParsedObservation:
        text = raw.raw.strip()
        if not text:
            return ParsedObservation()

        entry = KnowledgeEntry(
            text=text[:2000],
            source=str(raw.metadata.get("source", "command")),
            confidence=0.3,
            timestamp=now(),
            metadata={**raw.metadata, "tier": "semantic", "kind": "raw_command_output"},
        )
        return ParsedObservation(proposed_knowledge=[entry])
