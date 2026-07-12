# verify_compiled.py
# Verifies that all 9 required compiled knowledge outputs exist, are non-empty, and contain valid records.
"""Verify compiled knowledge outputs are present and structurally sound.

Checks all nine required compiled files produced by the knowledge compiler:
- file exists on disk
- file is non-empty
- JSONL files: every line parses as valid JSON
- JSONL files: every record has ``source_family`` and ``source_type`` fields
- minimum record counts per family (from CLAUDE.md §18.8)

``hackthebox_lab.yaml`` is the one non-JSONL output; it is only checked for
existence and non-emptiness (YAML parsing is not verified here).

Exit codes
----------
0 — all checks passed
1 — one or more checks failed (details printed to stdout)

Usage
-----
    python -m apex_host.knowledge.compiler.verify_compiled \\
        --knowledge-root ./knowledge
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Required output specification
# ---------------------------------------------------------------------------

@dataclass
class _OutputSpec:
    """Specification for one required compiled output file."""
    family: str           # e.g. "intel_db"
    filename: str         # e.g. "cve_slim.jsonl"
    is_jsonl: bool        # False for .yaml outputs
    min_records: int      # 0 means no count check (e.g. for .yaml)


_REQUIRED: list[_OutputSpec] = [
    _OutputSpec("policy_db",      "policy_records.jsonl",   True,  1),
    _OutputSpec("policy_db",      "hackthebox_lab.yaml",    False, 0),
    _OutputSpec("methodology_db", "methodology_chunks.jsonl", True, 1),
    _OutputSpec("intel_db",       "attack_techniques.jsonl", True,  100),
    _OutputSpec("intel_db",       "cwe_weaknesses.jsonl",    True,  100),
    _OutputSpec("intel_db",       "capec_patterns.jsonl",    True,   50),
    _OutputSpec("intel_db",       "cve_slim.jsonl",          True, 1000),
    _OutputSpec("payload_db",     "payload_records.jsonl",   True,  100),
    _OutputSpec("payload_db",     "wordlist_manifest.jsonl", True,   10),
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class FileResult:
    """Verification result for one output file."""
    spec: _OutputSpec
    path: pathlib.Path
    ok: bool
    problems: list[str] = field(default_factory=list)
    record_count: int = 0

    @property
    def relative_path(self) -> str:
        return f"{self.spec.family}/compiled/{self.spec.filename}"


@dataclass
class VerifyResult:
    """Overall verification result for one knowledge root."""
    root: pathlib.Path
    file_results: list[FileResult]

    @property
    def passed(self) -> bool:
        return all(r.ok for r in self.file_results)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.file_results if not r.ok)


# ---------------------------------------------------------------------------
# Core verification logic
# ---------------------------------------------------------------------------

def verify_file(spec: _OutputSpec, root: pathlib.Path) -> FileResult:
    """Verify one compiled output file against its specification.

    Parameters
    ----------
    spec:
        The ``_OutputSpec`` describing what to expect.
    root:
        The knowledge root directory (e.g. ``./knowledge``).

    Returns
    -------
    FileResult
        Always returns; never raises.
    """
    path = root / spec.family / "compiled" / spec.filename
    problems: list[str] = []
    record_count = 0

    # 1. File must exist
    if not path.exists():
        return FileResult(spec=spec, path=path, ok=False,
                          problems=[f"file not found: {path}"])

    # 2. File must be non-empty
    size = path.stat().st_size
    if size == 0:
        return FileResult(spec=spec, path=path, ok=False,
                          problems=[f"file is empty: {path}"])

    # 3. JSONL-specific checks
    if spec.is_jsonl:
        line_num = 0
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for raw_line in fh:
                    raw_line = raw_line.rstrip("\n\r")
                    if not raw_line:
                        continue  # skip blank lines
                    line_num += 1
                    # 3a. Valid JSON per line
                    try:
                        record = json.loads(raw_line)
                    except json.JSONDecodeError as exc:
                        problems.append(
                            f"line {line_num}: invalid JSON — {exc}"
                        )
                        if len(problems) >= 5:
                            problems.append("(further JSON errors suppressed)")
                            break
                        continue
                    # 3b. Required provenance fields
                    if not isinstance(record, dict):
                        problems.append(
                            f"line {line_num}: record is not a JSON object"
                        )
                        continue
                    missing_fields = [
                        f for f in ("source_family", "source_type")
                        if f not in record
                    ]
                    if missing_fields:
                        problems.append(
                            f"line {line_num}: missing required field(s): "
                            + ", ".join(missing_fields)
                        )
                        if len(problems) >= 5:
                            problems.append("(further missing-field errors suppressed)")
                            break
                    record_count += 1
        except OSError as exc:
            return FileResult(spec=spec, path=path, ok=False,
                              problems=[f"could not read file: {exc}"])

        # 3c. Minimum record count
        if spec.min_records > 0 and record_count < spec.min_records:
            problems.append(
                f"too few records: {record_count} < required {spec.min_records}"
            )

    ok = len(problems) == 0
    return FileResult(
        spec=spec, path=path, ok=ok,
        problems=problems, record_count=record_count,
    )


def verify_compiled(knowledge_root: str | pathlib.Path) -> VerifyResult:
    """Verify all required compiled outputs under *knowledge_root*.

    Parameters
    ----------
    knowledge_root:
        Path to the directory containing ``intel_db``, ``methodology_db``,
        ``payload_db``, and ``policy_db`` subdirectories.

    Returns
    -------
    VerifyResult
        Full results for all 9 required outputs.
    """
    root = pathlib.Path(knowledge_root).resolve()
    results = [verify_file(spec, root) for spec in _REQUIRED]
    return VerifyResult(root=root, file_results=results)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _format_result(result: VerifyResult) -> str:
    """Format a human-readable verification report."""
    lines: list[str] = [
        f"Verification root: {result.root}",
        "",
    ]

    for fr in result.file_results:
        status = "OK" if fr.ok else "FAIL"
        count_str = f"  ({fr.record_count:,} records)" if fr.spec.is_jsonl else ""
        lines.append(f"  [{status}]  {fr.relative_path}{count_str}")
        for problem in fr.problems:
            lines.append(f"           ✗ {problem}")

    lines.append("")
    if result.passed:
        total = sum(r.record_count for r in result.file_results)
        lines.append(
            f"All {len(result.file_results)} required outputs verified OK  "
            f"({total:,} total records)."
        )
    else:
        lines.append(
            f"FAILED: {result.fail_count}/{len(result.file_results)} output(s) "
            f"did not pass verification."
        )
        lines.append(
            "Run: python -m apex_host.knowledge.compiler.compile_knowledge "
            f"--knowledge-root {result.root}"
        )

    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m apex_host.knowledge.compiler.verify_compiled",
        description=(
            "Verify that all 9 required compiled knowledge outputs exist, "
            "are non-empty, contain valid JSON per line (for JSONL files), "
            "and include 'source_family' and 'source_type' fields in every record."
        ),
    )
    parser.add_argument(
        "--knowledge-root",
        metavar="DIR",
        required=True,
        help="Root of the knowledge directory (e.g. ./knowledge).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns 0 on success, 1 on any failure."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    result = verify_compiled(args.knowledge_root)
    print(_format_result(result))
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
