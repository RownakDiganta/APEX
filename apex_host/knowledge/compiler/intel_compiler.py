# intel_compiler.py
# Compiles intel_db sources (MITRE ATT&CK, CVE, CWE, CAPEC) into compact JSONL records.
"""Compile intel_db sources into four targeted JSONL files.

Input:  <knowledge_root>/intel_db/
Output: <knowledge_root>/intel_db/compiled/
          attack_techniques.jsonl
          cwe_weaknesses.jsonl
          capec_patterns.jsonl
          cve_slim.jsonl

Behaviour
---------
- MITRE ATT&CK (enterprise-attack.json): STIX bundle — extract technique
  objects (type=="attack-pattern") with external_id, name, description.
- CVE (nvdcve-2.0-*.json): NVD 2.0 format — extract id, description,
  publishedDate, severity.  Files are processed one at a time to keep
  memory bounded; a per-file record cap prevents huge outputs.
- CWE (cwe.xml): extract Weakness/@ID, @Name, Description.
- CAPEC (capec.xml): extract Attack_Pattern/@ID, @Name, Description.
- Unknown / malformed files are logged and skipped without crashing.
- Missing source directory is a graceful no-op (returns 0).
"""
from __future__ import annotations

import json
import logging
import pathlib
import xml.etree.ElementTree as ET
from collections.abc import Callable
from typing import Any

from apex_host.knowledge.compiler.common import (
    normalize_whitespace,
    stable_record_id,
    write_jsonl,
)
from apex_host.knowledge.compiler.schemas import CompiledKnowledgeRecord
from memfabric.ids import now

logger = logging.getLogger(__name__)

# Cap per CVE file to keep compiled output bounded (NVD files can have ~25k entries).
_CVE_RECORDS_PER_FILE = 2000
# Minimum description length to bother creating a record.
_MIN_DESC_LEN = 20


def compile_intel(
    intel_db_path: str | pathlib.Path,
    output_dir: str | pathlib.Path,
) -> int:
    """Compile all intel_db sources.

    Returns the total number of records written across all output files.
    """
    src = pathlib.Path(intel_db_path)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not src.is_dir():
        logger.warning("intel_compiler: intel_db path does not exist: %s", src)
        return 0

    total = 0
    total += _compile_attack(src / "attack", out / "attack_techniques.jsonl")
    total += _compile_cwe(src / "cwe", out / "cwe_weaknesses.jsonl")
    total += _compile_capec(src / "capec", out / "capec_patterns.jsonl")
    total += _compile_cve(src / "cve", out / "cve_slim.jsonl")

    logger.info("intel_compiler: total %d records compiled from %s", total, src)
    return total


# ---------------------------------------------------------------------------
# ATT&CK
# ---------------------------------------------------------------------------

def _compile_attack(attack_dir: pathlib.Path, out_path: pathlib.Path) -> int:
    json_files = sorted(attack_dir.glob("*.json")) if attack_dir.is_dir() else []
    if not json_files:
        logger.warning("intel_compiler: no ATT&CK JSON found in %s", attack_dir)
        write_jsonl([], out_path)
        return 0

    records: list[CompiledKnowledgeRecord] = []
    for json_path in json_files:
        try:
            data = json.loads(json_path.read_bytes())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("intel_compiler: cannot parse ATT&CK file %s: %s", json_path, exc)
            continue

        objects = data.get("objects", []) if isinstance(data, dict) else []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            ext_refs = obj.get("external_references", [])
            tech_id = next(
                (r.get("external_id", "") for r in ext_refs if r.get("source_name") == "mitre-attack"),
                "",
            )
            name = obj.get("name", "").strip()
            description = normalize_whitespace(obj.get("description", ""))
            if not name or not description or len(description) < _MIN_DESC_LEN:
                continue

            rec_id = stable_record_id("intel_db", "attack", str(json_path), 0, extra=tech_id or name)
            records.append(CompiledKnowledgeRecord(
                id=rec_id,
                source_family="intel_db",
                source_type="attack",
                source_path=str(json_path),
                title=f"{tech_id} {name}".strip(),
                text=f"{tech_id} {name}\n{description}".strip(),
                tags=["attack", "mitre", "technique"],
                confidence=0.85,
                updated_at=now(),
                metadata={
                    "technique_id": tech_id,
                    "mitre_name": name,
                    "platforms": obj.get("x_mitre_platforms", []),
                },
            ))

    count = write_jsonl(records, out_path)
    logger.info("intel_compiler: %d ATT&CK technique records", count)
    return count


# ---------------------------------------------------------------------------
# CWE
# ---------------------------------------------------------------------------

def _compile_cwe(cwe_dir: pathlib.Path, out_path: pathlib.Path) -> int:
    xml_files = sorted(cwe_dir.glob("*.xml")) if cwe_dir.is_dir() else []
    if not xml_files:
        logger.warning("intel_compiler: no CWE XML found in %s", cwe_dir)
        write_jsonl([], out_path)
        return 0

    records: list[CompiledKnowledgeRecord] = []
    for xml_path in xml_files:
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as exc:
            logger.warning("intel_compiler: cannot parse CWE XML %s: %s", xml_path, exc)
            continue

        root = tree.getroot()
        # Strip namespace from tag for matching
        ns_strip = _ns_stripper(root.tag)
        for weakness in root.iter():
            tag = ns_strip(weakness.tag)
            if tag != "Weakness":
                continue
            cwe_id = weakness.get("ID", "")
            cwe_name = weakness.get("Name", "")
            desc_el = _find_ns(weakness, "Description", ns_strip)
            description = normalize_whitespace(desc_el.text or "") if desc_el is not None else ""

            if not cwe_id or not description or len(description) < _MIN_DESC_LEN:
                continue

            label = f"CWE-{cwe_id}"
            rec_id = stable_record_id("intel_db", "cwe", str(xml_path), 0, extra=label)
            records.append(CompiledKnowledgeRecord(
                id=rec_id,
                source_family="intel_db",
                source_type="cwe",
                source_path=str(xml_path),
                title=f"{label}: {cwe_name}",
                text=f"{label} {cwe_name}\n{description}".strip(),
                tags=["cwe", "weakness", "mitre"],
                confidence=0.85,
                updated_at=now(),
                metadata={"cwe_id": label, "cwe_name": cwe_name},
            ))

    count = write_jsonl(records, out_path)
    logger.info("intel_compiler: %d CWE records", count)
    return count


# ---------------------------------------------------------------------------
# CAPEC
# ---------------------------------------------------------------------------

def _compile_capec(capec_dir: pathlib.Path, out_path: pathlib.Path) -> int:
    xml_files = sorted(capec_dir.glob("*.xml")) if capec_dir.is_dir() else []
    if not xml_files:
        logger.warning("intel_compiler: no CAPEC XML found in %s", capec_dir)
        write_jsonl([], out_path)
        return 0

    records: list[CompiledKnowledgeRecord] = []
    for xml_path in xml_files:
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as exc:
            logger.warning("intel_compiler: cannot parse CAPEC XML %s: %s", xml_path, exc)
            continue

        root = tree.getroot()
        ns_strip = _ns_stripper(root.tag)

        for pattern in root.iter():
            tag = ns_strip(pattern.tag)
            if tag != "Attack_Pattern":
                continue
            capec_id = pattern.get("ID", "")
            capec_name = pattern.get("Name", "")
            desc_el = _find_ns(pattern, "Description", ns_strip)
            description = normalize_whitespace(desc_el.text or "") if desc_el is not None else ""

            if not capec_id or not description or len(description) < _MIN_DESC_LEN:
                continue

            label = f"CAPEC-{capec_id}"
            rec_id = stable_record_id("intel_db", "capec", str(xml_path), 0, extra=label)
            records.append(CompiledKnowledgeRecord(
                id=rec_id,
                source_family="intel_db",
                source_type="capec",
                source_path=str(xml_path),
                title=f"{label}: {capec_name}",
                text=f"{label} {capec_name}\n{description}".strip(),
                tags=["capec", "attack-pattern", "mitre"],
                confidence=0.85,
                updated_at=now(),
                metadata={"capec_id": label, "capec_name": capec_name},
            ))

    count = write_jsonl(records, out_path)
    logger.info("intel_compiler: %d CAPEC records", count)
    return count


# ---------------------------------------------------------------------------
# CVE
# ---------------------------------------------------------------------------

def _compile_cve(cve_dir: pathlib.Path, out_path: pathlib.Path) -> int:
    json_files = sorted(cve_dir.glob("nvdcve-*.json")) if cve_dir.is_dir() else []
    if not json_files:
        logger.warning("intel_compiler: no NVD CVE JSON found in %s", cve_dir)
        write_jsonl([], out_path)
        return 0

    records: list[CompiledKnowledgeRecord] = []

    for json_path in json_files:
        file_records: list[CompiledKnowledgeRecord] = []
        try:
            data = json.loads(json_path.read_bytes())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("intel_compiler: cannot parse CVE file %s: %s", json_path, exc)
            continue

        items = _extract_cve_items(data)
        for item in items:
            if len(file_records) >= _CVE_RECORDS_PER_FILE:
                break
            rec = _make_cve_record(item, json_path)
            if rec is not None:
                file_records.append(rec)

        records.extend(file_records)
        logger.debug("intel_compiler: %d CVE records from %s", len(file_records), json_path.name)

    count = write_jsonl(records, out_path)
    logger.info("intel_compiler: %d CVE records total", count)
    return count


def _extract_cve_items(data: Any) -> list[Any]:
    """Extract the list of CVE items from NVD JSON 2.0 or legacy 1.1 format."""
    if not isinstance(data, dict):
        return []
    # NVD 2.0: {"vulnerabilities": [{"cve": {...}}, ...]}
    if "vulnerabilities" in data:
        return [v.get("cve", v) for v in data["vulnerabilities"] if isinstance(v, dict)]
    # NVD 1.x: {"CVE_Items": [...]}
    if "CVE_Items" in data:
        items = data["CVE_Items"]
        return list(items) if isinstance(items, list) else []
    return []


def _make_cve_record(
    item: Any, source_path: pathlib.Path
) -> CompiledKnowledgeRecord | None:
    """Build a slim CVE record from one NVD item dict."""
    if not isinstance(item, dict):
        return None

    # Normalise across NVD 1.x and 2.0 layouts
    cve_block = item.get("cve", item)
    if not isinstance(cve_block, dict):
        return None

    # CVE ID
    cve_id = (
        cve_block.get("id")
        or cve_block.get("CVE_data_meta", {}).get("ID", "")
    )
    if not cve_id:
        return None

    # Description (first English entry)
    description = _extract_cve_description(cve_block)
    if not description or len(description) < _MIN_DESC_LEN:
        return None

    # Published date
    published = (
        cve_block.get("published")
        or cve_block.get("publishedDate", "")
    )

    # CVSS severity (best-effort)
    severity = _extract_severity(cve_block)

    rec_id = stable_record_id("intel_db", "cve", str(source_path), 0, extra=cve_id)
    text_parts = [cve_id]
    if severity:
        text_parts.append(f"Severity: {severity}")
    text_parts.append(description)

    return CompiledKnowledgeRecord(
        id=rec_id,
        source_family="intel_db",
        source_type="cve",
        source_path=str(source_path),
        title=cve_id,
        text=normalize_whitespace(" ".join(text_parts)),
        tags=["cve", "vulnerability", "nvd"],
        confidence=0.8,
        updated_at=now(),
        metadata={
            "cve_id": cve_id,
            "published": published,
            "severity": severity or "",
        },
    )


def _extract_cve_description(cve_block: dict[str, Any]) -> str:
    """Pull the first English description from various NVD layouts."""
    # NVD 2.0: {"descriptions": [{"lang": "en", "value": "..."}]}
    descs_20 = cve_block.get("descriptions", [])
    for d in descs_20:
        if isinstance(d, dict) and d.get("lang") == "en":
            return str(d.get("value", "")).strip()

    # NVD 1.x: {"description": {"description_data": [{"lang":"en", "value":"..."}]}}
    descs_1x = cve_block.get("description", {}).get("description_data", [])
    for d in descs_1x:
        if isinstance(d, dict) and d.get("lang") == "en":
            return str(d.get("value", "")).strip()

    return ""


def _extract_severity(cve_block: dict[str, Any]) -> str:
    """Best-effort CVSS severity extraction (v3.1 → v3.0 → v2)."""
    metrics = cve_block.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries and isinstance(entries, list):
            cvss = entries[0].get("cvssData", entries[0])
            severity = cvss.get("baseSeverity") or cvss.get("severity", "")
            if severity:
                return str(severity).upper()
    return ""


# ---------------------------------------------------------------------------
# XML namespace helpers
# ---------------------------------------------------------------------------

def _ns_stripper(tag: str) -> Callable[[str], str]:
    """Return a function that strips the namespace from an element tag."""
    if tag.startswith("{"):
        ns = tag.split("}")[0] + "}"
        return lambda t: t.replace(ns, "") if t.startswith(ns) else t.split("}")[-1] if "}" in t else t
    return lambda t: t.split("}")[-1] if "}" in t else t


def _find_ns(element: ET.Element, local_name: str, strip_fn: Callable[[str], str]) -> ET.Element | None:
    """Find first child whose local name matches, namespace-agnostically."""
    for child in element:
        if strip_fn(child.tag) == local_name:
            return child
    return None
