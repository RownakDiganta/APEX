# test_compiled_loader.py
# Tests for compiled_loader.py, query_filters.py, and the seed_compiled_knowledge() seeding flow.
"""Tests for compiled knowledge loading.

Covers four acceptance criteria:
1. Staging isolation — compiled records are NOT retrievable before promotion.
2. After seeding, policy_db filter returns only policy records.
3. After seeding, payload_db filter returns only payload records.
4. After seeding, intel_db filter returns only intel records.

Plus helper tests for the filter utilities and loader internals.
"""
from __future__ import annotations

import json
import pathlib

import pytest
import pytest_asyncio

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_record(
    *,
    id: str,
    text: str,
    source_type: str,
    title: str = "Test record",
    confidence: float = 0.7,
    tags: list[str] | None = None,
    metadata: dict | None = None,
) -> dict:
    return {
        "id": id,
        "text": text,
        "source_type": source_type,
        "title": title,
        "source_path": f"/fake/{id}.txt",
        "tags": tags or [],
        "confidence": confidence,
        "updated_at": "2026-01-01T00:00:00Z",
        "metadata": metadata or {},
    }


def _write_jsonl(path: pathlib.Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


@pytest.fixture
def memfabric_config() -> Config:
    return Config()


@pytest_asyncio.fixture
async def api(memfabric_config: Config) -> MemoryAPI:
    graph = NetworkXGraphStore()
    episodic = JSONLEpisodicStore(path=None)
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=memfabric_config.vector_dim)
    kv = InMemoryKVStore()
    instance = MemoryAPI(
        graph=graph, episodic=episodic, lexical=lexical, vector=vector,
        kv=kv, config=memfabric_config,
    )
    retriever = HybridRetriever(
        lexical=lexical, vector=vector,
        embedder=StubEmbedder(), reranker=PassthroughReranker(),
        graph=graph, graph_matcher=TextGraphMatcher(),
        kv=kv, config=memfabric_config,
    )
    instance.set_retriever(retriever)
    return instance


@pytest.fixture
def knowledge_root(tmp_path: pathlib.Path) -> pathlib.Path:
    """Create a minimal compiled knowledge tree with one file per family."""
    policy_compiled = tmp_path / "policy_db" / "compiled"
    policy_compiled.mkdir(parents=True)
    _write_jsonl(policy_compiled / "policy_records.jsonl", [
        _make_record(id="pol-001", text="HTB rules: authorized lab engagement only", source_type="htb_rule"),
        _make_record(id="pol-002", text="HTB policy: respect terms of service", source_type="legal_doc"),
    ])

    payload_compiled = tmp_path / "payload_db" / "compiled"
    payload_compiled.mkdir(parents=True)
    _write_jsonl(payload_compiled / "payload_records.jsonl", [
        _make_record(id="pay-001", text="GTFOBins curl payload for file read", source_type="payload"),
        _make_record(id="pay-002", text="LOLBAS certutil payload download", source_type="payload"),
    ])
    _write_jsonl(payload_compiled / "wordlist_manifest.jsonl", [
        _make_record(
            id="wl-001", text="SecLists Discovery Web Content common.txt",
            source_type="wordlist_manifest",
            metadata={"restricted_use": "general"},
        ),
    ])

    intel_compiled = tmp_path / "intel_db" / "compiled"
    intel_compiled.mkdir(parents=True)
    _write_jsonl(intel_compiled / "attack_techniques.jsonl", [
        _make_record(id="att-001", text="T1059 Command and Scripting Interpreter", source_type="attack"),
    ])
    _write_jsonl(intel_compiled / "cwe_weaknesses.jsonl", [
        _make_record(id="cwe-001", text="CWE-89 SQL Injection weakness", source_type="cwe"),
    ])
    _write_jsonl(intel_compiled / "capec_patterns.jsonl", [
        _make_record(id="cap-001", text="CAPEC-1 Accessing Functionality Not Properly Constrained", source_type="capec"),
    ])
    _write_jsonl(intel_compiled / "cve_slim.jsonl", [
        _make_record(id="cve-001", text="CVE-2021-44228 Log4Shell critical RCE", source_type="cve"),
    ])

    methodology_compiled = tmp_path / "methodology_db" / "compiled"
    methodology_compiled.mkdir(parents=True)
    _write_jsonl(methodology_compiled / "methodology_chunks.jsonl", [
        _make_record(id="meth-001", text="OWASP testing guide web application security", source_type="methodology"),
    ])

    return tmp_path


# ---------------------------------------------------------------------------
# 1. Staging isolation — records NOT retrievable before promotion
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_staging_isolation_policy(api: MemoryAPI, knowledge_root: pathlib.Path) -> None:
    """Staging isolation: policy records are invisible before promotion."""
    from apex_host.knowledge.compiled_loader import load_compiled_family

    compiled_dir = knowledge_root / "policy_db" / "compiled"
    count = await load_compiled_family(compiled_dir, "policy_db", api)
    assert count == 2

    # Must NOT be retrievable yet — promotion hasn't happened.
    bundle = await api.query(text="HTB rules authorized lab", k=10)
    texts = [e.text for e in bundle.entries]
    assert not any("HTB" in t for t in texts), (
        "Staged entries must not be retrievable until Reflector promotes them"
    )


@pytest.mark.asyncio
async def test_staging_isolation_payload(api: MemoryAPI, knowledge_root: pathlib.Path) -> None:
    """Staging isolation: payload records are invisible before promotion."""
    from apex_host.knowledge.compiled_loader import load_compiled_family

    compiled_dir = knowledge_root / "payload_db" / "compiled"
    count = await load_compiled_family(compiled_dir, "payload_db", api)
    assert count == 3

    bundle = await api.query(text="GTFOBins curl payload", k=10)
    texts = [e.text for e in bundle.entries]
    assert not any("GTFOBins" in t for t in texts)


@pytest.mark.asyncio
async def test_staging_isolation_intel(api: MemoryAPI, knowledge_root: pathlib.Path) -> None:
    """Staging isolation: intel records are invisible before promotion."""
    from apex_host.knowledge.compiled_loader import load_compiled_family

    compiled_dir = knowledge_root / "intel_db" / "compiled"
    count = await load_compiled_family(compiled_dir, "intel_db", api)
    assert count == 4

    bundle = await api.query(text="Log4Shell critical RCE", k=10)
    texts = [e.text for e in bundle.entries]
    assert not any("Log4Shell" in t for t in texts)


# ---------------------------------------------------------------------------
# 2. After seeding, policy_db filter returns only policy records
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_policy_filter_after_seeding(
    api: MemoryAPI, memfabric_config: Config, knowledge_root: pathlib.Path,
) -> None:
    """After seed_compiled_knowledge, policy_db filter returns policy records only."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge
    from apex_host.knowledge.query_filters import POLICY_FILTER

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(knowledge_root))
    counts = await seed_compiled_knowledge(api, config, memfabric_config)
    assert counts.get("policy_db", 0) > 0

    bundle = await api.query(text="HTB rules authorized", k=20, filters=POLICY_FILTER)
    assert len(bundle.entries) > 0, "Expected policy records to be retrievable after seeding"
    for entry in bundle.entries:
        assert entry.metadata.get("source_family") == "policy_db", (
            f"Filter leak: expected source_family=policy_db, got {entry.metadata.get('source_family')!r}"
        )


@pytest.mark.asyncio
async def test_policy_filter_excludes_other_families(
    api: MemoryAPI, memfabric_config: Config, knowledge_root: pathlib.Path,
) -> None:
    """Policy filter must not return payload or intel records."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge
    from apex_host.knowledge.query_filters import POLICY_FILTER

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(knowledge_root))
    await seed_compiled_knowledge(api, config, memfabric_config)

    bundle = await api.query(text="payload GTFOBins CVE Log4Shell", k=20, filters=POLICY_FILTER)
    for entry in bundle.entries:
        assert entry.metadata.get("source_family") == "policy_db"


# ---------------------------------------------------------------------------
# 3. After seeding, payload_db filter returns only payload records
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_payload_filter_after_seeding(
    api: MemoryAPI, memfabric_config: Config, knowledge_root: pathlib.Path,
) -> None:
    """After seed_compiled_knowledge, payload_db filter returns payload records only."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge
    from apex_host.knowledge.query_filters import PAYLOAD_FILTER

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(knowledge_root))
    counts = await seed_compiled_knowledge(api, config, memfabric_config)
    assert counts.get("payload_db", 0) > 0

    bundle = await api.query(text="GTFOBins curl LOLBAS wordlist", k=20, filters=PAYLOAD_FILTER)
    assert len(bundle.entries) > 0, "Expected payload records to be retrievable after seeding"
    for entry in bundle.entries:
        assert entry.metadata.get("source_family") == "payload_db"


@pytest.mark.asyncio
async def test_payload_filter_excludes_other_families(
    api: MemoryAPI, memfabric_config: Config, knowledge_root: pathlib.Path,
) -> None:
    """Payload filter must not return policy or intel records."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge
    from apex_host.knowledge.query_filters import PAYLOAD_FILTER

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(knowledge_root))
    await seed_compiled_knowledge(api, config, memfabric_config)

    bundle = await api.query(text="HTB rules CVE Log4Shell", k=20, filters=PAYLOAD_FILTER)
    for entry in bundle.entries:
        assert entry.metadata.get("source_family") == "payload_db"


# ---------------------------------------------------------------------------
# 4. After seeding, intel_db filter returns only intel records
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_intel_filter_after_seeding(
    api: MemoryAPI, memfabric_config: Config, knowledge_root: pathlib.Path,
) -> None:
    """After seed_compiled_knowledge, intel_db filter returns intel records only."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge
    from apex_host.knowledge.query_filters import INTEL_FILTER

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(knowledge_root))
    counts = await seed_compiled_knowledge(api, config, memfabric_config)
    assert counts.get("intel_db", 0) > 0

    bundle = await api.query(text="CVE Log4Shell MITRE ATT&CK CWE SQL", k=20, filters=INTEL_FILTER)
    assert len(bundle.entries) > 0, "Expected intel records to be retrievable after seeding"
    for entry in bundle.entries:
        assert entry.metadata.get("source_family") == "intel_db"


@pytest.mark.asyncio
async def test_intel_filter_excludes_other_families(
    api: MemoryAPI, memfabric_config: Config, knowledge_root: pathlib.Path,
) -> None:
    """Intel filter must not return policy or payload records."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge
    from apex_host.knowledge.query_filters import INTEL_FILTER

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(knowledge_root))
    await seed_compiled_knowledge(api, config, memfabric_config)

    bundle = await api.query(text="HTB rules GTFOBins LOLBAS authorized", k=20, filters=INTEL_FILTER)
    for entry in bundle.entries:
        assert entry.metadata.get("source_family") == "intel_db"


# ---------------------------------------------------------------------------
# 5. metadata_db filter
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_methodology_filter_after_seeding(
    api: MemoryAPI, memfabric_config: Config, knowledge_root: pathlib.Path,
) -> None:
    """After seeding, methodology_db filter returns methodology records only."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge
    from apex_host.knowledge.query_filters import METHODOLOGY_FILTER

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(knowledge_root))
    counts = await seed_compiled_knowledge(api, config, memfabric_config)
    assert counts.get("methodology_db", 0) > 0

    bundle = await api.query(text="OWASP testing web security", k=20, filters=METHODOLOGY_FILTER)
    assert len(bundle.entries) > 0
    for entry in bundle.entries:
        assert entry.metadata.get("source_family") == "methodology_db"


# ---------------------------------------------------------------------------
# 6. seed_all() returns correct counts dict
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_seed_all_returns_counts(
    api: MemoryAPI, memfabric_config: Config, knowledge_root: pathlib.Path,
) -> None:
    """seed_compiled_knowledge returns a dict with per-family counts."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(knowledge_root))
    counts = await seed_compiled_knowledge(api, config, memfabric_config)

    assert isinstance(counts, dict)
    assert "policy_db" in counts
    assert "payload_db" in counts
    assert "intel_db" in counts
    assert "methodology_db" in counts
    assert counts["policy_db"] == 2
    assert counts["payload_db"] == 3  # 2 payload + 1 wordlist_manifest
    assert counts["intel_db"] == 4   # attack + cwe + capec + cve
    assert counts["methodology_db"] == 1


# ---------------------------------------------------------------------------
# 7. Graceful degradation — missing families produce count 0
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_missing_family_returns_zero(
    api: MemoryAPI, memfabric_config: Config, tmp_path: pathlib.Path,
) -> None:
    """Families whose compiled/ dir is absent contribute count 0, no crash."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge

    # Only policy_db exists.
    policy_compiled = tmp_path / "policy_db" / "compiled"
    policy_compiled.mkdir(parents=True)
    _write_jsonl(policy_compiled / "policy_records.jsonl", [
        _make_record(id="pol-x01", text="HTB platform rules reference", source_type="htb_rule"),
    ])

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(tmp_path))
    counts = await seed_compiled_knowledge(api, config, memfabric_config)

    assert counts["policy_db"] == 1
    assert counts["intel_db"] == 0
    assert counts["payload_db"] == 0
    assert counts["methodology_db"] == 0


@pytest.mark.asyncio
async def test_no_knowledge_root_all_zeros(
    api: MemoryAPI, memfabric_config: Config,
) -> None:
    """When knowledge_root is None and no per-family paths are set, counts are 0."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge

    config = ApexConfig(target="127.0.0.1", dry_run=True)
    counts = await seed_compiled_knowledge(api, config, memfabric_config)

    # All families should be absent — counts 0.
    for family in ("policy_db", "intel_db", "payload_db", "methodology_db"):
        assert counts.get(family, 0) == 0


# ---------------------------------------------------------------------------
# 8. ScoredEntry.text is populated after seeding (retrieval text fix)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_retrieved_text_populated_after_seeding(
    api: MemoryAPI, memfabric_config: Config, knowledge_root: pathlib.Path,
) -> None:
    """ScoredEntry.text must not be empty after promotion."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge
    from apex_host.knowledge.query_filters import POLICY_FILTER

    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(knowledge_root))
    await seed_compiled_knowledge(api, config, memfabric_config)

    bundle = await api.query(text="HTB authorized lab engagement", k=10, filters=POLICY_FILTER)
    assert len(bundle.entries) > 0
    for entry in bundle.entries:
        assert entry.text, f"ScoredEntry.text must not be empty; got {entry.text!r}"
        assert "HTB" in entry.text or "authorized" in entry.text or "policy" in entry.text.lower()


# ---------------------------------------------------------------------------
# 9. query_filters.py helper tests
# ---------------------------------------------------------------------------

def test_source_family_filter() -> None:
    from apex_host.knowledge.query_filters import source_family_filter
    f = source_family_filter("intel_db")
    assert f == {"source_family": "intel_db"}


def test_source_type_filter() -> None:
    from apex_host.knowledge.query_filters import source_type_filter
    f = source_type_filter("cve")
    assert f == {"source_type": "cve"}


def test_combined_filter() -> None:
    from apex_host.knowledge.query_filters import combined_filter, PAYLOAD_FILTER, source_type_filter
    f = combined_filter(PAYLOAD_FILTER, source_type_filter("wordlist_manifest"))
    assert f == {"source_family": "payload_db", "source_type": "wordlist_manifest"}


def test_filter_by_source_family_helper() -> None:
    from apex_host.knowledge.query_filters import filter_by_source_family
    from memfabric.types import ScoredEntry

    entries = [
        ScoredEntry(id="a", text="x", score=1.0, source="s", tier="semantic", metadata={"source_family": "policy_db"}),
        ScoredEntry(id="b", text="y", score=0.9, source="s", tier="semantic", metadata={"source_family": "intel_db"}),
        ScoredEntry(id="c", text="z", score=0.8, source="s", tier="semantic", metadata={"source_family": "policy_db"}),
    ]
    result = filter_by_source_family(entries, "policy_db")
    assert [e.id for e in result] == ["a", "c"]


def test_filter_by_source_type_helper() -> None:
    from apex_host.knowledge.query_filters import filter_by_source_type
    from memfabric.types import ScoredEntry

    entries = [
        ScoredEntry(id="a", text="x", score=1.0, source="s", tier="semantic", metadata={"source_type": "cve"}),
        ScoredEntry(id="b", text="y", score=0.9, source="s", tier="semantic", metadata={"source_type": "attack"}),
    ]
    result = filter_by_source_type(entries, "cve")
    assert [e.id for e in result] == ["a"]


def test_filter_by_metadata_helper() -> None:
    from apex_host.knowledge.query_filters import filter_by_metadata
    from memfabric.types import ScoredEntry

    entries = [
        ScoredEntry(id="a", text="x", score=1.0, source="s", tier="semantic", metadata={"source_family": "payload_db", "source_type": "payload"}),
        ScoredEntry(id="b", text="y", score=0.9, source="s", tier="semantic", metadata={"source_family": "payload_db", "source_type": "wordlist_manifest"}),
        ScoredEntry(id="c", text="z", score=0.8, source="s", tier="semantic", metadata={"source_family": "intel_db", "source_type": "cve"}),
    ]
    result = filter_by_metadata(entries, source_family="payload_db", source_type="wordlist_manifest")
    assert [e.id for e in result] == ["b"]


def test_wordlist_manifest_filter_constant() -> None:
    from apex_host.knowledge.query_filters import WORDLIST_MANIFEST_FILTER
    assert WORDLIST_MANIFEST_FILTER == {"source_family": "payload_db", "source_type": "wordlist_manifest"}


# ---------------------------------------------------------------------------
# 10. CLI arg tests
# ---------------------------------------------------------------------------

def test_main_parse_knowledge_root() -> None:
    from apex_host.main import parse_args
    args = parse_args(["--target", "10.0.0.1", "--knowledge-root", "./knowledge"])
    assert args.knowledge_root == "./knowledge"


def test_main_parse_knowledge_root_default_none() -> None:
    from apex_host.main import parse_args
    args = parse_args(["--target", "10.0.0.1"])
    assert args.knowledge_root is None


def test_run_htb_local_parse_knowledge_root() -> None:
    from apex_host.eval.run_htb_local import parse_args
    args = parse_args(["--target", "10.0.0.1", "--knowledge-root", "./knowledge"])
    assert args.knowledge_root == "./knowledge"


def test_run_htb_local_parse_knowledge_root_default_none() -> None:
    from apex_host.eval.run_htb_local import parse_args
    args = parse_args(["--target", "10.0.0.1"])
    assert args.knowledge_root is None


# ---------------------------------------------------------------------------
# 11. Per-family path override tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_per_family_path_override(
    api: MemoryAPI, memfabric_config: Config, tmp_path: pathlib.Path,
) -> None:
    """ApexConfig.policy_db_path overrides knowledge_root for policy family."""
    from apex_host.config import ApexConfig
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge
    from apex_host.knowledge.query_filters import POLICY_FILTER

    # policy_db lives at an explicit path, not under knowledge_root.
    policy_dir = tmp_path / "custom_policy"
    policy_compiled = policy_dir / "compiled"
    policy_compiled.mkdir(parents=True)
    _write_jsonl(policy_compiled / "policy_records.jsonl", [
        _make_record(id="pol-override-01", text="Custom policy override record", source_type="htb_rule"),
    ])

    # knowledge_root doesn't exist at all — override path takes effect.
    config = ApexConfig(
        target="127.0.0.1", dry_run=True,
        knowledge_root=str(tmp_path / "nonexistent_root"),
        policy_db_path=str(policy_dir),
    )
    counts = await seed_compiled_knowledge(api, config, memfabric_config)
    assert counts["policy_db"] == 1
    assert counts["intel_db"] == 0

    bundle = await api.query(text="Custom policy override", k=10, filters=POLICY_FILTER)
    assert len(bundle.entries) > 0
    assert any("Custom policy" in e.text for e in bundle.entries)


# ---------------------------------------------------------------------------
# 12. load_compiled_family — graceful handling of malformed lines
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_malformed_jsonl_lines_skipped(
    api: MemoryAPI, tmp_path: pathlib.Path,
) -> None:
    """Malformed JSON lines are skipped; valid lines are still staged."""
    from apex_host.knowledge.compiled_loader import load_compiled_family

    compiled_dir = tmp_path / "compiled"
    compiled_dir.mkdir()
    mixed_path = compiled_dir / "policy_records.jsonl"
    valid_rec = _make_record(id="pol-valid", text="Valid policy line content", source_type="htb_rule")
    mixed_path.write_text(
        "NOT VALID JSON\n"
        + json.dumps(valid_rec) + "\n"
        + "{also bad\n"
    )

    count = await load_compiled_family(compiled_dir, "policy_db", api)
    assert count == 1  # Only the valid line is staged.


@pytest.mark.asyncio
async def test_empty_text_records_skipped(
    api: MemoryAPI, tmp_path: pathlib.Path,
) -> None:
    """Records with empty or missing text fields are silently skipped."""
    from apex_host.knowledge.compiled_loader import load_compiled_family

    compiled_dir = tmp_path / "compiled"
    compiled_dir.mkdir()
    path = compiled_dir / "policy_records.jsonl"
    records = [
        {"id": "e1", "text": "", "source_type": "htb_rule", "tags": [], "confidence": 0.7, "metadata": {}},
        {"id": "e2", "text": "   ", "source_type": "htb_rule", "tags": [], "confidence": 0.7, "metadata": {}},
        _make_record(id="e3", text="Good non-empty record", source_type="htb_rule"),
    ]
    with path.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

    count = await load_compiled_family(compiled_dir, "policy_db", api)
    assert count == 1


@pytest.mark.asyncio
async def test_missing_compiled_dir_returns_zero(
    api: MemoryAPI, tmp_path: pathlib.Path,
) -> None:
    """load_compiled_family returns 0 when the compiled dir doesn't exist."""
    from apex_host.knowledge.compiled_loader import load_compiled_family

    absent = tmp_path / "nonexistent" / "compiled"
    count = await load_compiled_family(absent, "policy_db", api)
    assert count == 0


# ---------------------------------------------------------------------------
# 13. _record_to_knowledge_entry preserves all metadata fields
# ---------------------------------------------------------------------------

def test_record_to_knowledge_entry_metadata() -> None:
    """All provenance fields survive _record_to_knowledge_entry."""
    from apex_host.knowledge.compiled_loader import _record_to_knowledge_entry

    record = {
        "id": "test-meta-01",
        "text": "Test record content",
        "source_type": "attack",
        "source_path": "/fake/attack.json",
        "title": "T1059",
        "tags": ["lateral-movement"],
        "confidence": 0.85,
        "updated_at": "2026-01-01T00:00:00Z",
        "metadata": {"mitre_id": "T1059", "restricted_use": "general"},
    }
    entry = _record_to_knowledge_entry(record, "intel_db", None)
    assert entry is not None
    assert entry.metadata["source_family"] == "intel_db"
    assert entry.metadata["source_type"] == "attack"
    assert entry.metadata["source_path"] == "/fake/attack.json"
    assert entry.metadata["title"] == "T1059"
    assert "lateral-movement" in entry.metadata["tags"]
    assert entry.metadata["tier"] == "semantic"
    assert entry.metadata.get("mitre_id") == "T1059"
    assert entry.confidence == 0.85


def test_record_to_knowledge_entry_confidence_override() -> None:
    """confidence_override replaces the record's confidence value."""
    from apex_host.knowledge.compiled_loader import _record_to_knowledge_entry

    record = _make_record(id="x", text="some text", source_type="cve")
    entry = _record_to_knowledge_entry(record, "intel_db", confidence_override=0.5)
    assert entry is not None
    assert entry.confidence == 0.5


def test_record_to_knowledge_entry_none_for_empty_text() -> None:
    """_record_to_knowledge_entry returns None when text is empty."""
    from apex_host.knowledge.compiled_loader import _record_to_knowledge_entry

    record = {"id": "bad", "text": "", "source_type": "cve", "tags": [], "metadata": {}}
    assert _record_to_knowledge_entry(record, "intel_db", None) is None
