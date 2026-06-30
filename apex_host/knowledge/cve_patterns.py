"""Configurable identifier regex patterns, fed into HybridRetriever's regex
channel (memfabric/retrieval/engine.py's ``identifier_patterns`` parameter).

The patterns themselves are config, not domain content — they match
well-known public identifier formats (CVE, CWE) plus a generic
service/version token, not any specific vulnerability or payload.
"""
from __future__ import annotations

import re


def default_identifier_patterns() -> dict[str, re.Pattern[str]]:
    """Pattern set the APEX host supplies to memfabric's regex channel."""
    return {
        "cve": re.compile(r"CVE-\d{4}-\d{4,7}"),
        "cwe": re.compile(r"CWE-\d{1,5}"),
        "service_version": re.compile(r"\b[A-Za-z][\w.+-]*\/\d+(?:\.\d+){1,3}\b"),
    }
