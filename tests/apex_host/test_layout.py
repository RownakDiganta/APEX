# test_layout.py
# Tests for apex_host.knowledge.compiler.layout — knowledge directory detection and inspect CLI.
"""Tests for the knowledge layout detector and --inspect CLI mode.

All tests use tmp_path fixtures — no real knowledge directory is required.
"""
from __future__ import annotations

import pathlib
import textwrap

import pytest

from apex_host.knowledge.compiler.layout import (
    KnowledgeLayout,
    FamilyLayout,
    detect_layout,
    format_inspect_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_policy_db(root: pathlib.Path) -> None:
    """Create a minimal policy_db with sources/htb/ layout."""
    htb = root / "policy_db" / "sources" / "htb"
    htb.mkdir(parents=True)
    (htb / "htb_platform_rules.md").write_text("- You must not attack unauthorized targets.\n")
    (htb / "htb_terms_of_service.pdf").write_bytes(b"%PDF-1.4 stub")


def _make_methodology_db(root: pathlib.Path) -> None:
    """Create a minimal methodology_db with PDFs at root (no sources/ subdir)."""
    md = root / "methodology_db"
    md.mkdir(parents=True)
    (md / "NIST_SP800_115.pdf").write_bytes(b"%PDF-1.4 stub")
    (md / "ptes_technical_guidelines.pdf").write_bytes(b"%PDF-1.4 stub")


def _make_intel_db(root: pathlib.Path) -> None:
    """Create a minimal intel_db with attack/cwe/capec/cve subdirs."""
    intel = root / "intel_db"
    (intel / "attack").mkdir(parents=True)
    (intel / "cwe").mkdir(parents=True)
    (intel / "capec").mkdir(parents=True)
    (intel / "cve").mkdir(parents=True)
    (intel / "attack" / "enterprise-attack.json").write_text('{"objects": []}')
    (intel / "cwe" / "cwe.xml").write_text("<Weakness_Catalog/>")
    (intel / "capec" / "capec.xml").write_text("<Attack_Pattern_Catalog/>")
    (intel / "cve" / "nvdcve-2.0-2024.json").write_text('{"vulnerabilities": []}')


def _make_payload_db(root: pathlib.Path) -> None:
    """Create a minimal payload_db matching the real structure."""
    payload = root / "payload_db"
    # GTFOBins: extensionless YAML in _gtfobins/
    gtfobins = payload / "GTFOBins" / "_gtfobins"
    gtfobins.mkdir(parents=True)
    (gtfobins / "curl").write_text("functions:\n  file-read:\n  - code: curl http://target\n")
    (gtfobins / "wget").write_text("functions:\n  file-write:\n  - code: wget http://target -O out\n")
    # LOLBAS: .yml in yml/ subdirs
    lolbas_yml = payload / "LOLBAS" / "yml" / "OSBinaries"
    lolbas_yml.mkdir(parents=True)
    (lolbas_yml / "Cmd.yml").write_text(textwrap.dedent("""\
        Name: Cmd.exe
        Description: Windows command-line interpreter.
        Commands:
          - Command: cmd.exe /c whoami
            Description: Execute whoami
            Usecase: Recon
    """))
    # PayloadsAllTheThings: markdown
    pat = payload / "PayloadsAllTheThings" / "SQL Injection"
    pat.mkdir(parents=True)
    (pat / "README.md").write_text(
        "## Basic Payloads\n' OR 1=1 --\n## Blind\ntime-based\n"
    )
    # SecLists: wordlist files
    seclists = payload / "SecLists" / "Discovery" / "Web-Content"
    seclists.mkdir(parents=True)
    (seclists / "common.txt").write_text("\n".join(f"word{i}" for i in range(50)))
    seclists_pw = payload / "SecLists" / "Passwords"
    seclists_pw.mkdir(parents=True)
    (seclists_pw / "10k-most-common.txt").write_text("\n".join(["pass1", "letmein"]))


# ---------------------------------------------------------------------------
# detect_layout — missing root
# ---------------------------------------------------------------------------

class TestDetectLayoutMissingRoot:
    def test_missing_root_is_reported(self, tmp_path: pathlib.Path) -> None:
        layout = detect_layout(tmp_path / "nonexistent")
        assert not layout.root_exists
        assert not layout.any_family_found()

    def test_missing_root_all_families_absent(self, tmp_path: pathlib.Path) -> None:
        layout = detect_layout(tmp_path / "nonexistent")
        assert all(not f.exists for f in layout.families.values())

    def test_missing_root_all_outputs_missing(self, tmp_path: pathlib.Path) -> None:
        layout = detect_layout(tmp_path / "nonexistent")
        for family in layout.families.values():
            assert len(family.missing_outputs) == len(family.expected_outputs)


# ---------------------------------------------------------------------------
# detect_layout — policy_db
# ---------------------------------------------------------------------------

class TestDetectLayoutPolicyDb:
    def test_absent_policy_reported(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        layout = detect_layout(root)
        assert not layout.families["policy_db"].exists

    def test_present_policy_detected(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        layout = detect_layout(root)
        f = layout.families["policy_db"]
        assert f.exists
        assert f.source_root is not None
        assert "sources" in str(f.source_root)

    def test_policy_source_files_counted(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        layout = detect_layout(root)
        assert layout.families["policy_db"].source_file_count >= 2

    def test_policy_expected_outputs_listed(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        layout = detect_layout(root)
        f = layout.families["policy_db"]
        assert "policy_records.jsonl" in f.expected_outputs
        assert "hackthebox_lab.yaml" in f.expected_outputs

    def test_policy_outputs_missing_before_compile(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        layout = detect_layout(root)
        f = layout.families["policy_db"]
        assert len(f.missing_outputs) == len(f.expected_outputs)
        assert len(f.present_outputs) == 0

    def test_policy_outputs_present_after_compile(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        compiled = root / "policy_db" / "compiled"
        compiled.mkdir()
        (compiled / "policy_records.jsonl").write_text("")
        (compiled / "hackthebox_lab.yaml").write_text("")
        layout = detect_layout(root)
        f = layout.families["policy_db"]
        assert len(f.missing_outputs) == 0
        assert len(f.present_outputs) == 2

    def test_htb_sources_htb_subdir_detected(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        layout = detect_layout(root)
        f = layout.families["policy_db"]
        assert any("htb" in note.lower() for note in f.notes)


# ---------------------------------------------------------------------------
# detect_layout — methodology_db
# ---------------------------------------------------------------------------

class TestDetectLayoutMethodologyDb:
    def test_absent_methodology_reported(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        layout = detect_layout(root)
        assert not layout.families["methodology_db"].exists

    def test_methodology_files_at_root_detected(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_methodology_db(root)
        layout = detect_layout(root)
        f = layout.families["methodology_db"]
        assert f.exists
        assert f.source_file_count >= 2

    def test_methodology_no_sources_subdir_noted(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_methodology_db(root)
        layout = detect_layout(root)
        f = layout.families["methodology_db"]
        # Source root should be the family root (no sources/ subdirectory)
        assert str(f.source_root) == str(f.root)

    def test_methodology_expected_outputs(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_methodology_db(root)
        layout = detect_layout(root)
        assert "methodology_chunks.jsonl" in layout.families["methodology_db"].expected_outputs


# ---------------------------------------------------------------------------
# detect_layout — intel_db
# ---------------------------------------------------------------------------

class TestDetectLayoutIntelDb:
    def test_absent_intel_reported(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        layout = detect_layout(root)
        assert not layout.families["intel_db"].exists

    def test_intel_subdirs_detected(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_intel_db(root)
        layout = detect_layout(root)
        f = layout.families["intel_db"]
        assert f.exists
        assert f.source_file_count >= 4

    def test_intel_expected_outputs_listed(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_intel_db(root)
        layout = detect_layout(root)
        f = layout.families["intel_db"]
        for expected in ["attack_techniques.jsonl", "cwe_weaknesses.jsonl",
                         "capec_patterns.jsonl", "cve_slim.jsonl"]:
            assert expected in f.expected_outputs

    def test_missing_subdir_noted(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        # Only create attack/ — no cwe/capec/cve
        (root / "intel_db" / "attack").mkdir(parents=True)
        (root / "intel_db" / "attack" / "enterprise-attack.json").write_text("{}")
        layout = detect_layout(root)
        f = layout.families["intel_db"]
        # Notes should mention MISSING for absent subdirs
        missing_notes = [n for n in f.notes if "MISSING" in n]
        assert len(missing_notes) >= 3


# ---------------------------------------------------------------------------
# detect_layout — payload_db
# ---------------------------------------------------------------------------

class TestDetectLayoutPayloadDb:
    def test_absent_payload_reported(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        layout = detect_layout(root)
        assert not layout.families["payload_db"].exists

    def test_gtfobins_extensionless_files_counted(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_payload_db(root)
        layout = detect_layout(root)
        f = layout.families["payload_db"]
        assert f.exists
        # GTFOBins notes should mention extensionless entries
        gtfobins_notes = [n for n in f.notes if "GTFOBins" in n]
        assert gtfobins_notes
        assert any("2" in n or "extensionless" in n for n in gtfobins_notes)

    def test_lolbas_yml_files_counted(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_payload_db(root)
        layout = detect_layout(root)
        f = layout.families["payload_db"]
        lolbas_notes = [n for n in f.notes if "LOLBAS" in n]
        assert lolbas_notes
        assert any("1" in n for n in lolbas_notes)

    def test_seclists_noted_as_manifest(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_payload_db(root)
        layout = detect_layout(root)
        f = layout.families["payload_db"]
        seclists_notes = [n for n in f.notes if "SecLists" in n]
        assert seclists_notes
        assert any("manifest" in n for n in seclists_notes)

    def test_payload_expected_outputs(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_payload_db(root)
        layout = detect_layout(root)
        f = layout.families["payload_db"]
        assert "payload_records.jsonl" in f.expected_outputs
        assert "wordlist_manifest.jsonl" in f.expected_outputs

    def test_missing_subdirs_noted(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        (root / "payload_db").mkdir(parents=True)
        layout = detect_layout(root)
        f = layout.families["payload_db"]
        missing_notes = [n for n in f.notes if "MISSING" in n]
        assert len(missing_notes) == 4  # all four sub-projects absent


# ---------------------------------------------------------------------------
# all_outputs_present / any_family_found
# ---------------------------------------------------------------------------

class TestKnowledgeLayoutPredicates:
    def test_any_family_found_false_for_empty_root(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        layout = detect_layout(root)
        assert not layout.any_family_found()

    def test_any_family_found_true_when_one_exists(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        layout = detect_layout(root)
        assert layout.any_family_found()

    def test_all_outputs_present_false_before_compile(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        layout = detect_layout(root)
        assert not layout.all_outputs_present()

    def test_all_outputs_present_true_when_all_files_written(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        compiled = root / "policy_db" / "compiled"
        compiled.mkdir()
        (compiled / "policy_records.jsonl").write_text("")
        (compiled / "hackthebox_lab.yaml").write_text("")
        layout = detect_layout(root)
        assert layout.all_outputs_present()


# ---------------------------------------------------------------------------
# format_inspect_report
# ---------------------------------------------------------------------------

class TestFormatInspectReport:
    def test_missing_root_shown_in_report(self, tmp_path: pathlib.Path) -> None:
        layout = detect_layout(tmp_path / "nonexistent")
        report = format_inspect_report(layout)
        assert "MISSING" in report

    def test_report_shows_all_four_families(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        _make_methodology_db(root)
        _make_intel_db(root)
        _make_payload_db(root)
        report = format_inspect_report(layout := detect_layout(root))
        for family in ["policy_db", "methodology_db", "intel_db", "payload_db"]:
            assert family in report

    def test_report_shows_missing_outputs(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        report = format_inspect_report(detect_layout(root))
        assert "MISSING" in report
        assert "policy_records.jsonl" in report

    def test_report_shows_ok_when_outputs_present(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        compiled = root / "policy_db" / "compiled"
        compiled.mkdir()
        (compiled / "policy_records.jsonl").write_text("x")
        (compiled / "hackthebox_lab.yaml").write_text("x")
        report = format_inspect_report(detect_layout(root))
        assert "OK" in report

    def test_report_includes_compile_command_when_missing(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        report = format_inspect_report(detect_layout(root))
        assert "compile_knowledge" in report

    def test_empty_root_error_message(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "knowledge"
        root.mkdir()
        report = format_inspect_report(detect_layout(root))
        assert "No knowledge family directories found" in report


# ---------------------------------------------------------------------------
# --inspect CLI flag
# ---------------------------------------------------------------------------

class TestInspectCLI:
    def test_inspect_flag_missing_root_returns_nonzero(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        result = main(["--knowledge-root", str(tmp_path / "nonexistent"), "--inspect"])
        assert result != 0

    def test_inspect_flag_existing_root_no_families_returns_nonzero(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        root = tmp_path / "knowledge"
        root.mkdir()
        result = main(["--knowledge-root", str(root), "--inspect"])
        assert result != 0

    def test_inspect_flag_with_missing_compiled_returns_nonzero(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        result = main(["--knowledge-root", str(root), "--inspect"])
        assert result != 0

    def test_inspect_flag_with_all_outputs_present_returns_zero(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        compiled = root / "policy_db" / "compiled"
        compiled.mkdir()
        (compiled / "policy_records.jsonl").write_text("x")
        (compiled / "hackthebox_lab.yaml").write_text("x")
        result = main(["--knowledge-root", str(root), "--inspect"])
        assert result == 0

    def test_inspect_does_not_write_to_disk(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_policy_db(root)
        main(["--knowledge-root", str(root), "--inspect"])
        # No compiled/ directory should have been created
        assert not (root / "policy_db" / "compiled").exists()

    def test_inspect_reports_gtfobins_extensionless_entries(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        import io, contextlib
        root = tmp_path / "knowledge"
        root.mkdir()
        _make_payload_db(root)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["--knowledge-root", str(root), "--inspect"])
        output = buf.getvalue()
        assert "GTFOBins" in output
        assert "extensionless" in output


# ---------------------------------------------------------------------------
# payload_compiler — GTFOBins extensionless file handling
# ---------------------------------------------------------------------------

class TestPayloadCompilerGTFOBins:
    def test_gtfobins_extensionless_files_compiled(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        import json
        src = tmp_path / "payload_db"
        gtfobins = src / "GTFOBins" / "_gtfobins"
        gtfobins.mkdir(parents=True)
        (gtfobins / "curl").write_text(
            "functions:\n  file-read:\n  - code: curl http://target/file\n"
        )
        (gtfobins / "wget").write_text(
            "functions:\n  file-write:\n  - code: wget http://target -O out\n"
        )
        out = tmp_path / "out"
        p_count, m_count = compile_payload(src, out)
        assert p_count == 2
        records = [
            json.loads(line)
            for line in (out / "payload_records.jsonl").read_text().splitlines()
            if line.strip()
        ]
        titles = [r["title"] for r in records]
        assert any("curl" in t for t in titles)
        assert any("wget" in t for t in titles)

    def test_gtfobins_functions_key_extracted(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        import json
        src = tmp_path / "payload_db"
        gtfobins = src / "GTFOBins" / "_gtfobins"
        gtfobins.mkdir(parents=True)
        (gtfobins / "python3").write_text(textwrap.dedent("""\
            functions:
              shell:
              - code: python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
              file-read:
              - code: python3 -c 'print(open("/etc/passwd").read())'
        """))
        out = tmp_path / "out"
        compile_payload(src, out)
        records = [
            json.loads(line)
            for line in (out / "payload_records.jsonl").read_text().splitlines()
            if line.strip()
        ]
        assert records
        assert "python3" in records[0]["title"]
        # function categories should be in metadata
        assert "function_categories" in records[0]["metadata"]

    def test_gtfobins_tags_include_gtfobins_and_lolbins(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        import json
        src = tmp_path / "payload_db"
        gtfobins = src / "GTFOBins" / "_gtfobins"
        gtfobins.mkdir(parents=True)
        (gtfobins / "7z").write_text(
            "functions:\n  file-read:\n  - code: 7z a -ttar -an -so /path/to/file\n"
        )
        out = tmp_path / "out"
        compile_payload(src, out)
        records = [
            json.loads(line)
            for line in (out / "payload_records.jsonl").read_text().splitlines()
            if line.strip()
        ]
        assert records
        tags = records[0]["tags"]
        assert "gtfobins" in tags
        assert "lolbins" in tags

    def test_malformed_gtfobins_file_skipped(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        gtfobins = src / "GTFOBins" / "_gtfobins"
        gtfobins.mkdir(parents=True)
        (gtfobins / "bad_tool").write_bytes(b"\x00\xff\xfe")
        out = tmp_path / "out"
        p_count, _ = compile_payload(src, out)
        assert p_count == 0

    def test_gtfobins_and_lolbas_compile_together(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        # GTFOBins
        gtfobins = src / "GTFOBins" / "_gtfobins"
        gtfobins.mkdir(parents=True)
        (gtfobins / "curl").write_text(
            "functions:\n  file-read:\n  - code: curl http://x\n"
        )
        # LOLBAS
        lolbas = src / "LOLBAS" / "yml" / "OSBinaries"
        lolbas.mkdir(parents=True)
        (lolbas / "Cmd.yml").write_text(textwrap.dedent("""\
            Name: Cmd.exe
            Description: Windows command interpreter.
            Commands:
              - Command: cmd.exe /c whoami
                Usecase: Recon
        """))
        out = tmp_path / "out"
        p_count, m_count = compile_payload(src, out)
        assert p_count == 2  # 1 GTFOBins + 1 LOLBAS
        assert m_count == 0


# ---------------------------------------------------------------------------
# Real knowledge/ directory smoke test (skipped if not present)
# ---------------------------------------------------------------------------

_REAL_KNOWLEDGE = pathlib.Path(__file__).parents[2] / "knowledge"


@pytest.mark.skipif(
    not _REAL_KNOWLEDGE.is_dir(),
    reason="real knowledge/ directory not present",
)
class TestRealKnowledgeDirectory:
    def test_detect_layout_finds_all_four_families(self) -> None:
        layout = detect_layout(_REAL_KNOWLEDGE)
        assert layout.root_exists
        assert layout.any_family_found()
        for family_name in ["policy_db", "methodology_db", "intel_db", "payload_db"]:
            assert layout.families[family_name].exists, f"{family_name} not detected"

    def test_policy_sources_at_sources_htb(self) -> None:
        layout = detect_layout(_REAL_KNOWLEDGE)
        f = layout.families["policy_db"]
        assert f.source_root is not None
        assert "sources" in str(f.source_root)

    def test_methodology_files_at_root(self) -> None:
        layout = detect_layout(_REAL_KNOWLEDGE)
        f = layout.families["methodology_db"]
        assert f.source_file_count >= 3  # at least 3 PDFs

    def test_gtfobins_entries_counted(self) -> None:
        layout = detect_layout(_REAL_KNOWLEDGE)
        f = layout.families["payload_db"]
        assert f.source_file_count >= 10  # GTFOBins has 400+ entries

    def test_intel_subdirs_all_present(self) -> None:
        layout = detect_layout(_REAL_KNOWLEDGE)
        f = layout.families["intel_db"]
        missing_notes = [n for n in f.notes if "MISSING" in n]
        assert missing_notes == [], f"Intel subdirs missing: {missing_notes}"

    def test_inspect_cli_does_not_crash_on_real_knowledge(self) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        result = main(["--knowledge-root", str(_REAL_KNOWLEDGE), "--inspect"])
        # Returns 0 (all compiled) or 1 (some missing) — either is fine, just must not raise
        assert result in (0, 1)
