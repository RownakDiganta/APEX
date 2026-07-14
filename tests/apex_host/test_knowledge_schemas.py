# test_knowledge_schemas.py
# Tests for apex_host.knowledge.compiler schemas, common utilities, and ApexConfig knowledge fields.
"""Tests for the knowledge compiler package (schemas, common utilities, config)."""
from __future__ import annotations

import json
import pathlib

import pytest

from apex_host.config import ApexConfig
from apex_host.knowledge.compiler.common import (
    iter_files,
    normalize_whitespace,
    read_text_safely,
    stable_record_id,
    write_jsonl,
)
from apex_host.knowledge.compiler.schemas import (
    CompiledKnowledgeRecord,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record(**kwargs) -> CompiledKnowledgeRecord:
    defaults = dict(
        id="abc123",
        source_family="payload_db",
        source_type="payload",
        source_path="/some/file.md",
        title="Test record",
        text="Some payload text here.",
        tags=["test"],
        confidence=0.7,
        updated_at="2026-07-10T00:00:00Z",
        metadata={"chunk_index": 0},
    )
    defaults.update(kwargs)
    return CompiledKnowledgeRecord(**defaults)


# ---------------------------------------------------------------------------
# CompiledKnowledgeRecord — construction and validation
# ---------------------------------------------------------------------------

class TestCompiledKnowledgeRecord:
    def test_valid_record_constructs(self) -> None:
        r = _record()
        assert r.id == "abc123"
        assert r.source_family == "payload_db"
        assert r.source_type == "payload"
        assert r.confidence == 0.7

    def test_all_valid_source_families(self) -> None:
        for family in ("intel_db", "methodology_db", "payload_db", "policy_db"):
            r = _record(source_family=family, source_type=_type_for(family))
            assert r.source_family == family

    def test_all_valid_source_types(self) -> None:
        type_to_family = {
            "cve": "intel_db", "cwe": "intel_db", "capec": "intel_db",
            "attack": "intel_db", "methodology": "methodology_db",
            "payload": "payload_db", "wordlist_manifest": "payload_db",
            "htb_rule": "policy_db", "legal_doc": "policy_db",
        }
        for stype, family in type_to_family.items():
            r = _record(source_family=family, source_type=stype)
            assert r.source_type == stype

    def test_invalid_source_family_raises(self) -> None:
        with pytest.raises(ValueError, match="source_family"):
            _record(source_family="unknown_db")

    def test_invalid_source_type_raises(self) -> None:
        with pytest.raises(ValueError, match="source_type"):
            _record(source_type="unknown_type")

    def test_confidence_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            _record(confidence=1.5)
        with pytest.raises(ValueError, match="confidence"):
            _record(confidence=-0.1)

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="id"):
            _record(id="")

    def test_empty_source_path_raises(self) -> None:
        with pytest.raises(ValueError, match="source_path"):
            _record(source_path="")

    def test_empty_text_raises(self) -> None:
        with pytest.raises(ValueError, match="text"):
            _record(text="")

    def test_confidence_boundary_values(self) -> None:
        r0 = _record(confidence=0.0)
        r1 = _record(confidence=1.0)
        assert r0.confidence == 0.0
        assert r1.confidence == 1.0

    def test_tags_default_empty(self) -> None:
        r = _record(tags=[])
        assert r.tags == []

    def test_metadata_default_empty(self) -> None:
        r = _record(metadata={})
        assert r.metadata == {}


# ---------------------------------------------------------------------------
# Serialisation round-trip
# ---------------------------------------------------------------------------

class TestCompiledKnowledgeRecordSerialisation:
    def test_to_dict_contains_all_required_fields(self) -> None:
        r = _record()
        d = r.to_dict()
        required = {
            "id", "source_family", "source_type", "source_path",
            "title", "text", "tags", "confidence", "updated_at", "metadata",
        }
        assert required.issubset(d.keys())

    def test_to_dict_values_match(self) -> None:
        r = _record(title="My Title", tags=["a", "b"])
        d = r.to_dict()
        assert d["title"] == "My Title"
        assert d["tags"] == ["a", "b"]

    def test_from_dict_round_trip(self) -> None:
        r = _record()
        r2 = CompiledKnowledgeRecord.from_dict(r.to_dict())
        assert r2.id == r.id
        assert r2.source_family == r.source_family
        assert r2.source_type == r.source_type
        assert r2.text == r.text
        assert r2.confidence == r.confidence

    def test_from_dict_optional_fields_default(self) -> None:
        minimal = {
            "id": "x1",
            "source_family": "policy_db",
            "source_type": "htb_rule",
            "source_path": "/p",
            "text": "rules text",
        }
        r = CompiledKnowledgeRecord.from_dict(minimal)
        assert r.title == ""
        assert r.tags == []
        assert r.confidence == 0.7
        assert r.updated_at == ""
        assert r.metadata == {}


# ---------------------------------------------------------------------------
# common.iter_files
# ---------------------------------------------------------------------------

class TestIterFiles:
    def test_yields_files_recursively(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "a.md").write_text("a")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.txt").write_text("b")
        paths = list(iter_files(tmp_path))
        names = {p.name for p in paths}
        assert names == {"a.md", "b.txt"}

    def test_extension_filter(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "keep.md").write_text("md")
        (tmp_path / "skip.json").write_text("{}")
        paths = list(iter_files(tmp_path, extensions={".md"}))
        assert all(p.suffix == ".md" for p in paths)
        assert len(paths) == 1

    def test_nonexistent_root_yields_nothing(self, tmp_path: pathlib.Path) -> None:
        paths = list(iter_files(tmp_path / "does_not_exist"))
        assert paths == []

    def test_yields_in_sorted_order(self, tmp_path: pathlib.Path) -> None:
        for name in ["c.md", "a.md", "b.md"]:
            (tmp_path / name).write_text(name)
        paths = list(iter_files(tmp_path))
        names = [p.name for p in paths]
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# common.read_text_safely
# ---------------------------------------------------------------------------

class TestReadTextSafely:
    def test_reads_existing_file(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("hello world")
        assert read_text_safely(f) == "hello world"

    def test_returns_empty_on_missing_file(self, tmp_path: pathlib.Path) -> None:
        result = read_text_safely(tmp_path / "missing.txt")
        assert result == ""

    def test_truncates_large_file(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "big.txt"
        f.write_bytes(b"x" * 200)
        result = read_text_safely(f, max_bytes=50)
        assert len(result) == 50

    def test_handles_utf8_errors_gracefully(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "bad.txt"
        f.write_bytes(b"\xff\xfe hello")
        result = read_text_safely(f)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# common.write_jsonl
# ---------------------------------------------------------------------------

class TestWriteJsonl:
    def test_writes_one_line_per_record(self, tmp_path: pathlib.Path) -> None:
        records = [_record(id=f"id{i}", text=f"text {i}") for i in range(3)]
        out = tmp_path / "out.jsonl"
        count = write_jsonl(records, out)
        assert count == 3
        lines = out.read_text().strip().splitlines()
        assert len(lines) == 3

    def test_written_lines_are_valid_json(self, tmp_path: pathlib.Path) -> None:
        records = [_record()]
        out = tmp_path / "out.jsonl"
        write_jsonl(records, out)
        obj = json.loads(out.read_text().strip())
        assert obj["id"] == "abc123"

    def test_creates_parent_directories(self, tmp_path: pathlib.Path) -> None:
        out = tmp_path / "deep" / "nested" / "out.jsonl"
        write_jsonl([_record()], out)
        assert out.exists()

    def test_empty_records_writes_empty_file(self, tmp_path: pathlib.Path) -> None:
        out = tmp_path / "empty.jsonl"
        count = write_jsonl([], out)
        assert count == 0
        assert out.read_text() == ""


# ---------------------------------------------------------------------------
# common.stable_record_id
# ---------------------------------------------------------------------------

class TestStableRecordId:
    def test_same_inputs_same_id(self) -> None:
        a = stable_record_id("payload_db", "payload", "/file.md", 0)
        b = stable_record_id("payload_db", "payload", "/file.md", 0)
        assert a == b

    def test_different_chunk_index_different_id(self) -> None:
        a = stable_record_id("payload_db", "payload", "/file.md", 0)
        b = stable_record_id("payload_db", "payload", "/file.md", 1)
        assert a != b

    def test_different_family_different_id(self) -> None:
        a = stable_record_id("payload_db", "payload", "/file.md", 0)
        b = stable_record_id("intel_db", "payload", "/file.md", 0)
        assert a != b

    def test_extra_field_changes_id(self) -> None:
        a = stable_record_id("payload_db", "payload", "/f", 0, extra="")
        b = stable_record_id("payload_db", "payload", "/f", 0, extra="x")
        assert a != b

    def test_id_is_32_hex_chars(self) -> None:
        result = stable_record_id("policy_db", "htb_rule", "/policy.md", 0)
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)


# ---------------------------------------------------------------------------
# common.normalize_whitespace
# ---------------------------------------------------------------------------

class TestNormalizeWhitespace:
    def test_collapses_multiple_spaces(self) -> None:
        assert normalize_whitespace("hello   world") == "hello world"

    def test_collapses_tabs(self) -> None:
        assert normalize_whitespace("a\t\tb") == "a b"

    def test_trims_leading_trailing(self) -> None:
        assert normalize_whitespace("  hello  ") == "hello"

    def test_collapses_triple_newlines(self) -> None:
        result = normalize_whitespace("a\n\n\n\nb")
        assert result == "a\n\nb"

    def test_preserves_double_newline(self) -> None:
        result = normalize_whitespace("a\n\nb")
        assert result == "a\n\nb"

    def test_empty_string(self) -> None:
        assert normalize_whitespace("") == ""

    def test_only_whitespace(self) -> None:
        assert normalize_whitespace("   \t\n   ") == ""


# ---------------------------------------------------------------------------
# ApexConfig knowledge fields
# ---------------------------------------------------------------------------

class TestApexConfigKnowledgeFields:
    def test_knowledge_fields_default_to_none(self) -> None:
        cfg = ApexConfig(target="10.0.0.1")
        assert cfg.knowledge_root is None
        assert cfg.policy_db_path is None
        assert cfg.methodology_db_path is None
        assert cfg.intel_db_path is None
        assert cfg.payload_db_path is None

    def test_knowledge_root_can_be_set(self) -> None:
        cfg = ApexConfig(target="10.0.0.1", knowledge_root="/data/Knowlwdge")
        assert cfg.knowledge_root == "/data/Knowlwdge"

    def test_per_family_paths_can_be_set_independently(self) -> None:
        cfg = ApexConfig(
            target="10.0.0.1",
            policy_db_path="/data/Knowlwdge/policy_db",
            intel_db_path="/data/Knowlwdge/intel_db",
        )
        assert cfg.policy_db_path == "/data/Knowlwdge/policy_db"
        assert cfg.intel_db_path == "/data/Knowlwdge/intel_db"
        assert cfg.methodology_db_path is None
        assert cfg.payload_db_path is None

    def test_existing_fields_unaffected(self) -> None:
        cfg = ApexConfig(target="10.0.0.1", dry_run=True, max_turns=5)
        assert cfg.dry_run is True
        assert cfg.max_turns == 5
        assert cfg.payload_repo_path == "./payloads"


# ---------------------------------------------------------------------------
# Package-level import check
# ---------------------------------------------------------------------------

class TestPackageImport:
    def test_compiler_package_imports_cleanly(self) -> None:
        from apex_host.knowledge.compiler import (  # noqa: F401
            CompiledKnowledgeRecord,
            SourceFamily,
            SourceType,
            iter_files,
            normalize_whitespace,
            read_text_safely,
            stable_record_id,
            write_jsonl,
        )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _type_for(family: str) -> str:
    return {
        "intel_db": "cve",
        "methodology_db": "methodology",
        "payload_db": "payload",
        "policy_db": "htb_rule",
    }[family]
