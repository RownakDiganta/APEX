# layout.py
# Detects the real structure of a knowledge/ root directory and reports presence, source files, and expected compiled outputs.
"""Knowledge directory layout detector.

Examines the on-disk structure of a ``knowledge/`` (or ``Knowlwdge/``) root
directory and returns a structured report of:

- which family directories exist
- which source files are present inside each family
- which compiled JSONL outputs are expected
- which expected outputs are currently missing

Typical usage
-------------
    from apex_host.knowledge.compiler.layout import detect_layout, format_inspect_report
    layout = detect_layout("./knowledge")
    print(format_inspect_report(layout))

This module has no side-effects and makes no writes to disk.
"""
from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Expected compiled output files per family
# ---------------------------------------------------------------------------

_POLICY_OUTPUTS = [
    "policy_records.jsonl",
    "hackthebox_lab.yaml",
]
_METHODOLOGY_OUTPUTS = [
    "methodology_chunks.jsonl",
]
_INTEL_OUTPUTS = [
    "attack_techniques.jsonl",
    "cwe_weaknesses.jsonl",
    "capec_patterns.jsonl",
    "cve_slim.jsonl",
]
_PAYLOAD_OUTPUTS = [
    "payload_records.jsonl",
    "wordlist_manifest.jsonl",
]

# Source extensions (per family) used to count discoverable source files.
_POLICY_EXTS = frozenset({".md", ".txt", ".pdf"})
_METHODOLOGY_EXTS = frozenset({".md", ".txt", ".pdf"})
_INTEL_EXTS = frozenset({".json", ".xml"})
# payload_db: .md, .yml, .yaml, .txt + extensionless GTFOBins files
_PAYLOAD_EXTS = frozenset({".md", ".yml", ".yaml", ".txt"})

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FamilyLayout:
    """Layout information for one knowledge family directory."""
    name: str
    root: pathlib.Path | None
    exists: bool
    source_root: pathlib.Path | None
    source_file_count: int
    compiled_dir: pathlib.Path
    expected_outputs: list[str]
    missing_outputs: list[str]
    present_outputs: list[str]
    notes: list[str] = field(default_factory=list)

    @property
    def compiled_exists(self) -> bool:
        return self.compiled_dir.is_dir()


@dataclass
class KnowledgeLayout:
    """Detected layout of the entire knowledge root directory."""
    root: pathlib.Path
    root_exists: bool
    families: dict[str, FamilyLayout]

    def all_outputs_present(self) -> bool:
        return all(
            len(f.missing_outputs) == 0
            for f in self.families.values()
            if f.exists
        )

    def any_family_found(self) -> bool:
        return any(f.exists for f in self.families.values())


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def detect_layout(knowledge_root: str | pathlib.Path) -> KnowledgeLayout:
    """Detect the layout of a knowledge root directory.

    Parameters
    ----------
    knowledge_root:
        Path to the directory containing ``intel_db``, ``methodology_db``,
        ``payload_db``, and ``policy_db`` subdirectories.  The directory does
        not need to exist; missing directories are reported as absent.

    Returns
    -------
    KnowledgeLayout
        Structured report — never raises.
    """
    root = pathlib.Path(knowledge_root).resolve()
    families: dict[str, FamilyLayout] = {
        "policy_db":      _detect_policy(root / "policy_db"),
        "methodology_db": _detect_methodology(root / "methodology_db"),
        "intel_db":       _detect_intel(root / "intel_db"),
        "payload_db":     _detect_payload(root / "payload_db"),
    }
    return KnowledgeLayout(root=root, root_exists=root.is_dir(), families=families)


def _detect_policy(family_dir: pathlib.Path) -> FamilyLayout:
    if not family_dir.is_dir():
        return _absent("policy_db", family_dir, _POLICY_OUTPUTS)

    # Policy sources live in sources/ (and its subdirectories, e.g. sources/htb/)
    sources_dir = family_dir / "sources"
    if sources_dir.is_dir():
        src_root = sources_dir
        file_count = _count_files(sources_dir, _POLICY_EXTS)
    else:
        src_root = family_dir
        file_count = _count_files(family_dir, _POLICY_EXTS, skip_compiled=True)

    notes = []
    htb_dir = family_dir / "sources" / "htb"
    if htb_dir.is_dir():
        notes.append(f"HTB sources found: {htb_dir}")

    return _make_layout("policy_db", family_dir, src_root, file_count,
                        _POLICY_OUTPUTS, notes)


def _detect_methodology(family_dir: pathlib.Path) -> FamilyLayout:
    if not family_dir.is_dir():
        return _absent("methodology_db", family_dir, _METHODOLOGY_OUTPUTS)

    # methodology_db has PDFs and markdown directly at the root — no sources/ subdir.
    file_count = _count_files(family_dir, _METHODOLOGY_EXTS, skip_compiled=True)
    notes = []
    if not (family_dir / "sources").is_dir():
        notes.append("Files are directly at root (no sources/ subdirectory).")
    return _make_layout("methodology_db", family_dir, family_dir, file_count,
                        _METHODOLOGY_OUTPUTS, notes)


def _detect_intel(family_dir: pathlib.Path) -> FamilyLayout:
    if not family_dir.is_dir():
        return _absent("intel_db", family_dir, _INTEL_OUTPUTS)

    subdirs = {
        "attack": family_dir / "attack",
        "cwe":    family_dir / "cwe",
        "capec":  family_dir / "capec",
        "cve":    family_dir / "cve",
    }
    file_count = _count_files(family_dir, _INTEL_EXTS, skip_compiled=True)
    notes = []
    for sub, path in subdirs.items():
        if path.is_dir():
            n = _count_files(path, _INTEL_EXTS)
            notes.append(f"  {sub}/: {n} source file(s)")
        else:
            notes.append(f"  {sub}/: MISSING")

    return _make_layout("intel_db", family_dir, family_dir, file_count,
                        _INTEL_OUTPUTS, notes)


def _detect_payload(family_dir: pathlib.Path) -> FamilyLayout:
    if not family_dir.is_dir():
        return _absent("payload_db", family_dir, _PAYLOAD_OUTPUTS)

    projects = {
        "GTFOBins":            family_dir / "GTFOBins",
        "LOLBAS":              family_dir / "LOLBAS",
        "PayloadsAllTheThings": family_dir / "PayloadsAllTheThings",
        "SecLists":            family_dir / "SecLists",
    }
    notes = []
    total_files = 0

    for name, path in projects.items():
        if path.is_dir():
            if name == "GTFOBins":
                # Entries live in _gtfobins/ as extensionless YAML files
                gtfobins_dir = path / "_gtfobins"
                count = _count_extensionless_files(gtfobins_dir)
                notes.append(f"  GTFOBins/_gtfobins/: {count} extensionless YAML entries")
                total_files += count
            elif name == "LOLBAS":
                # Entries live in yml/{OSBinaries,OSLibraries,...}/*.yml
                yml_dir = path / "yml"
                count = _count_files(yml_dir, frozenset({".yml", ".yaml"})) if yml_dir.is_dir() else 0
                notes.append(f"  LOLBAS/yml/: {count} .yml entries")
                total_files += count
            elif name == "PayloadsAllTheThings":
                count = _count_files(path, frozenset({".md", ".txt"}))
                notes.append(f"  PayloadsAllTheThings/: {count} .md/.txt files")
                total_files += count
            elif name == "SecLists":
                count = _count_files(path, frozenset({".txt", ".lst"}))
                notes.append(f"  SecLists/: {count} wordlist files (manifest-only)")
                total_files += count
        else:
            notes.append(f"  {name}/: MISSING")

    return _make_layout("payload_db", family_dir, family_dir, total_files,
                        _PAYLOAD_OUTPUTS, notes)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _absent(name: str, root: pathlib.Path, outputs: list[str]) -> FamilyLayout:
    return FamilyLayout(
        name=name,
        root=root,
        exists=False,
        source_root=None,
        source_file_count=0,
        compiled_dir=root / "compiled",
        expected_outputs=outputs,
        missing_outputs=outputs[:],
        present_outputs=[],
        notes=[f"Directory does not exist: {root}"],
    )


def _make_layout(
    name: str,
    root: pathlib.Path,
    src_root: pathlib.Path,
    file_count: int,
    expected_outputs: list[str],
    notes: list[str],
) -> FamilyLayout:
    compiled_dir = root / "compiled"
    missing = [f for f in expected_outputs if not (compiled_dir / f).exists()]
    present = [f for f in expected_outputs if (compiled_dir / f).exists()]
    return FamilyLayout(
        name=name,
        root=root,
        exists=True,
        source_root=src_root,
        source_file_count=file_count,
        compiled_dir=compiled_dir,
        expected_outputs=expected_outputs,
        missing_outputs=missing,
        present_outputs=present,
        notes=notes,
    )


def _count_files(
    directory: pathlib.Path,
    extensions: frozenset[str],
    skip_compiled: bool = False,
) -> int:
    if not directory.is_dir():
        return 0
    count = 0
    for p in directory.rglob("*"):
        if not p.is_file():
            continue
        if skip_compiled and "compiled" in p.parts:
            continue
        if p.suffix.lower() in extensions:
            count += 1
    return count


def _count_extensionless_files(directory: pathlib.Path) -> int:
    """Count regular files with no extension in a directory."""
    if not directory.is_dir():
        return 0
    return sum(
        1 for p in directory.rglob("*")
        if p.is_file() and p.suffix == ""
    )


# ---------------------------------------------------------------------------
# Report formatter
# ---------------------------------------------------------------------------

def format_inspect_report(layout: KnowledgeLayout) -> str:
    """Return a human-readable inspection report for a detected layout."""
    lines: list[str] = []

    status = "EXISTS" if layout.root_exists else "MISSING"
    lines.append(f"Knowledge root: {layout.root}  [{status}]")
    if not layout.root_exists:
        lines.append("  ERROR: root directory does not exist — no families can be detected.")
        return "\n".join(lines)

    lines.append("")
    all_ok = True

    for family_name, family in layout.families.items():
        if family.exists:
            lines.append(f"[{family_name}]  root: {family.root}")
            lines.append(f"  source root:  {family.source_root}")
            lines.append(f"  source files: {family.source_file_count}")
            for note in family.notes:
                lines.append(f"  {note}")
            if family.compiled_exists:
                lines.append(f"  compiled dir: {family.compiled_dir}")
            else:
                lines.append(f"  compiled dir: {family.compiled_dir}  [NOT YET CREATED]")
            lines.append(f"  expected outputs ({len(family.expected_outputs)}):")
            for out_name in family.expected_outputs:
                out_path = family.compiled_dir / out_name
                if out_path.exists():
                    size = out_path.stat().st_size
                    lines.append(f"    OK      {out_name}  ({size:,} bytes)")
                else:
                    lines.append(f"    MISSING {out_name}")
                    all_ok = False
        else:
            lines.append(f"[{family_name}]  MISSING  ({family.root})")
            all_ok = False
        lines.append("")

    if all_ok and layout.any_family_found():
        lines.append("All expected compiled outputs are present.")
    elif layout.any_family_found():
        missing_count = sum(len(f.missing_outputs) for f in layout.families.values())
        lines.append(f"WARNING: {missing_count} compiled output(s) missing.")
        lines.append(
            "Run: python -m apex_host.knowledge.compiler.compile_knowledge "
            f"--knowledge-root {layout.root}"
        )
    else:
        lines.append("ERROR: No knowledge family directories found at this root.")

    return "\n".join(lines)
