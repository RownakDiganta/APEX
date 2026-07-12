# test_promotion_loop.py
# Tests for promote_staged_knowledge_until_stable() and multi-pass seeding.
"""Acceptance tests for the startup Reflector promotion loop.

Covers:
5.  A corpus larger than one Reflector batch requires multiple passes.
6.  All promotable records are eventually promoted in until_stable mode.
7.  single_pass mode performs exactly one pass.
8.  Zero-progress condition stops safely.
9.  Maximum-pass limit stops safely.
10. Missing knowledge folders still degrade gracefully (count 0, no crash).
11. Existing source-family filtering still works after multi-pass promotion.
12. No direct store writes occur — all reads/writes go through MemoryAPI.
13. Promotion summary appears in seed_all() result (_promotion key).
14. Policy source appears in report built from seed_all() data.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
import pytest_asyncio

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.reflector.worker import ReflectorWorker
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher

from apex_host.config import ApexConfig
from apex_host.knowledge.seed_loader import PromotionSummary, promote_staged_knowledge_until_stable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mf_config(**kwargs: Any) -> Config:
    return Config(**kwargs)


def _make_api(mf_config: Config) -> MemoryAPI:
    graph = NetworkXGraphStore()
    episodic = JSONLEpisodicStore(path=None)
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=mf_config.vector_dim)
    kv = InMemoryKVStore()
    instance = MemoryAPI(
        graph=graph, episodic=episodic, lexical=lexical, vector=vector,
        kv=kv, config=mf_config,
    )
    retriever = HybridRetriever(
        lexical=lexical, vector=vector,
        embedder=StubEmbedder(), reranker=PassthroughReranker(),
        graph=graph, graph_matcher=TextGraphMatcher(),
        kv=kv, config=mf_config,
    )
    instance.set_retriever(retriever)
    return instance


def _make_record(idx: int, family: str = "intel_db", prefix: str = "") -> dict[str, Any]:
    uid = f"{prefix}rec-{idx:04d}"
    return {
        "id": uid,
        "text": f"Knowledge record {idx} about {family} ({prefix}{idx})",
        "source_type": "attack",
        "source_family": family,
        "title": f"Record {idx}",
        "source_path": f"/fake/{prefix}{idx}.json",
        "tags": [],
        "confidence": 0.7,
        "updated_at": "2026-01-01T00:00:00Z",
        "metadata": {"source_family": family},
    }


def _write_jsonl(path: pathlib.Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


async def _stage_n_records(api: MemoryAPI, n: int, family: str = "intel_db") -> None:
    """Stage n knowledge records via MemoryAPI.propose_knowledge (not direct store)."""
    from apex_host.knowledge.compiled_loader import _record_to_knowledge_entry
    for i in range(n):
        rec = _make_record(i, family)
        entry = _record_to_knowledge_entry(rec, family, None)
        if entry is not None:
            await api.propose_knowledge(entry)


# ---------------------------------------------------------------------------
# 5. Large corpus requires multiple passes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_large_corpus_requires_multiple_passes() -> None:
    """200 records with a batch cap of 50 requires at least 4 passes."""
    # Use a small batch cap so we can test the multi-pass behaviour quickly.
    mf_config = _make_mf_config(reflector_max_promotions_per_run=50)
    api = _make_api(mf_config)
    worker = ReflectorWorker(api, mf_config)

    await _stage_n_records(api, 200)
    assert len(await api.get_staged_knowledge()) == 200

    summary = await promote_staged_knowledge_until_stable(api, worker, mode="until_stable")

    assert summary.passes_run >= 4, (
        f"Expected >= 4 passes for 200 records at cap=50, got {summary.passes_run}"
    )
    assert summary.records_promoted == 200
    assert summary.records_remaining == 0
    assert summary.stop_reason == "exhausted"


# ---------------------------------------------------------------------------
# 6. until_stable promotes all promotable records
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_until_stable_promotes_all_records() -> None:
    """until_stable mode promotes every record that clears the quality gate."""
    mf_config = _make_mf_config(reflector_max_promotions_per_run=10)
    api = _make_api(mf_config)
    worker = ReflectorWorker(api, mf_config)

    n = 75
    await _stage_n_records(api, n)

    summary = await promote_staged_knowledge_until_stable(api, worker, mode="until_stable")

    assert summary.records_promoted == n
    assert summary.records_remaining == 0
    assert summary.stop_reason == "exhausted"
    assert summary.passes_run >= (n // 10)  # at least ceil(75/10) = 8 passes


# ---------------------------------------------------------------------------
# 7. single_pass performs exactly one pass
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_single_pass_mode_performs_exactly_one_pass() -> None:
    """single_pass mode calls run_once() exactly once."""
    mf_config = _make_mf_config(reflector_max_promotions_per_run=5)
    api = _make_api(mf_config)
    worker = ReflectorWorker(api, mf_config)

    await _stage_n_records(api, 30)

    summary = await promote_staged_knowledge_until_stable(api, worker, mode="single_pass")

    assert summary.passes_run == 1
    assert summary.stop_reason == "single_pass"
    # With cap=5, only 5 records are promoted per pass.
    assert summary.records_promoted == 5
    assert summary.records_remaining == 25


# ---------------------------------------------------------------------------
# 8. Zero-progress condition stops safely
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_progress_stops_safely() -> None:
    """When all remaining records are below min_confidence, stop on no_progress."""
    # Set min_confidence high so records at confidence=0.3 never promote.
    mf_config = _make_mf_config(
        reflector_max_promotions_per_run=100,
        min_confidence=0.9,
    )
    api = _make_api(mf_config)
    worker = ReflectorWorker(api, mf_config)

    # Stage records below the quality gate — confidence=0.3 < min_confidence=0.9.
    from memfabric.types import KnowledgeEntry
    from memfabric.ids import now
    for i in range(5):
        entry = KnowledgeEntry(
            id=f"lowconf-{i}",
            text=f"Low confidence record {i}",
            source="test",
            confidence=0.3,
            timestamp=now(),
            metadata={"source_family": "intel_db", "tier": "semantic"},
        )
        await api.propose_knowledge(entry)

    assert len(await api.get_staged_knowledge()) == 5

    summary = await promote_staged_knowledge_until_stable(
        api, worker, mode="until_stable", max_passes=50,
    )

    assert summary.stop_reason == "no_progress"
    assert summary.records_promoted == 0
    assert summary.records_remaining == 5
    assert summary.passes_run == 1  # stopped after the first unproductive pass


# ---------------------------------------------------------------------------
# 9. max_passes limit stops safely
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_max_passes_limit_stops_safely() -> None:
    """When max_passes is reached, loop exits with stop_reason='max_passes'."""
    mf_config = _make_mf_config(reflector_max_promotions_per_run=1)
    api = _make_api(mf_config)
    worker = ReflectorWorker(api, mf_config)

    await _stage_n_records(api, 20)

    summary = await promote_staged_knowledge_until_stable(
        api, worker, mode="until_stable", max_passes=5,
    )

    assert summary.stop_reason == "max_passes"
    assert summary.passes_run == 5
    assert summary.records_promoted == 5
    assert summary.records_remaining == 15


# ---------------------------------------------------------------------------
# 10. Missing folders degrade gracefully (count 0, no crash)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_missing_knowledge_folders_degrade_gracefully(
    tmp_path: pathlib.Path,
) -> None:
    """Missing compiled/ dirs produce count 0 and no exception."""
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge

    mf_config = Config()
    api = _make_api(mf_config)
    # No compiled dirs exist under tmp_path.
    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(tmp_path))

    counts = await seed_compiled_knowledge(api, config, mf_config)
    assert all(v == 0 for v in counts.values())
    # No staged records, no crash.
    assert len(await api.get_staged_knowledge()) == 0


# ---------------------------------------------------------------------------
# 11. Source-family filtering still works after multi-pass promotion
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_source_family_filter_after_multipass(tmp_path: pathlib.Path) -> None:
    """After multi-pass promotion, query with POLICY_FILTER returns only policy records."""
    from apex_host.knowledge.query_filters import POLICY_FILTER, INTEL_FILTER
    from apex_host.knowledge.seed_loader import seed_compiled_knowledge

    # 150 policy records + 4×37=148 intel records = 298 total (> default cap of 100).
    policy_compiled = tmp_path / "policy_db" / "compiled"
    _write_jsonl(policy_compiled / "policy_records.jsonl", [
        {**_make_record(i, "policy_db", prefix="p-"),
         "source_type": "htb_rule",
         "metadata": {"source_family": "policy_db"}}
        for i in range(150)
    ])

    # Each intel file uses a unique prefix so IDs don't collide.
    intel_compiled = tmp_path / "intel_db" / "compiled"
    intel_file_map = {
        "attack_techniques.jsonl": "atk-",
        "cwe_weaknesses.jsonl": "cwe-",
        "capec_patterns.jsonl": "cap-",
        "cve_slim.jsonl": "cve-",
    }
    for fname, prefix in intel_file_map.items():
        _write_jsonl(intel_compiled / fname, [
            {**_make_record(i, "intel_db", prefix=prefix),
             "source_type": "attack",
             "metadata": {"source_family": "intel_db"}}
            for i in range(37)
        ])

    mf_config = Config()  # default cap=100; 298 records need 3+ passes
    api = _make_api(mf_config)
    config = ApexConfig(target="127.0.0.1", dry_run=True, knowledge_root=str(tmp_path))

    counts = await seed_compiled_knowledge(api, config, mf_config)
    assert counts["policy_db"] == 150
    assert counts["intel_db"] == 148  # 4 files × 37 unique IDs = 148

    # Source-family filter must not leak across families.
    policy_bundle = await api.query(text="Knowledge record", k=20, filters=POLICY_FILTER)
    for entry in policy_bundle.entries:
        assert entry.metadata.get("source_family") == "policy_db", (
            f"Expected policy_db, got {entry.metadata.get('source_family')!r}"
        )

    intel_bundle = await api.query(text="Knowledge record", k=20, filters=INTEL_FILTER)
    for entry in intel_bundle.entries:
        assert entry.metadata.get("source_family") == "intel_db", (
            f"Expected intel_db, got {entry.metadata.get('source_family')!r}"
        )


# ---------------------------------------------------------------------------
# 12. No direct store writes occur
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_direct_store_writes() -> None:
    """promote_staged_knowledge_until_stable never touches the store directly."""
    import unittest.mock as mock

    mf_config = Config()
    api = _make_api(mf_config)

    # Patch the graph store's put_node to detect any direct write.
    original_put_node = api._graph.put_node  # type: ignore[attr-defined]
    direct_calls: list[str] = []

    async def _tracking_put_node(node: Any) -> str:
        direct_calls.append(node.id)
        return await original_put_node(node)

    api._graph.put_node = _tracking_put_node  # type: ignore[method-assign]

    await _stage_n_records(api, 10)
    worker = ReflectorWorker(api, mf_config)
    await promote_staged_knowledge_until_stable(api, worker, mode="until_stable")

    # The staging was done via propose_knowledge → no graph-store writes
    # during promotion (knowledge goes to lexical/vector index, not graph).
    assert direct_calls == [], (
        f"Unexpected direct graph-store writes during promotion: {direct_calls[:5]}"
    )


# ---------------------------------------------------------------------------
# 13. Promotion summary appears in seed_all() _promotion key
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_seed_all_returns_promotion_summary(tmp_path: pathlib.Path) -> None:
    """seed_all() result includes _promotion key with PromotionSummary data."""
    from apex_host.runtime import build_runtime

    policy_compiled = tmp_path / "policy_db" / "compiled"
    _write_jsonl(policy_compiled / "policy_records.jsonl", [
        {**_make_record(i, "policy_db", prefix="p-"),
         "source_type": "htb_rule",
         "metadata": {"source_family": "policy_db"}}
        for i in range(5)
    ])

    config = ApexConfig(
        target="127.0.0.1", dry_run=True, knowledge_root=str(tmp_path),
    )
    runtime = build_runtime(config)
    seed_results = await runtime.seed_all()

    assert "_promotion" in seed_results, (
        f"Expected '_promotion' key in seed_all() result, got keys: {list(seed_results)}"
    )
    promo = seed_results["_promotion"]
    assert isinstance(promo, dict)
    for key in ("records_staged_initial", "records_promoted", "records_remaining",
                "passes_run", "stop_reason", "elapsed_seconds"):
        assert key in promo, f"Missing key {key!r} in promotion summary"

    assert promo["records_promoted"] == 5
    assert promo["records_remaining"] == 0
    assert promo["stop_reason"] == "exhausted"


# ---------------------------------------------------------------------------
# 14. Policy source appears in report from seed_all data
# ---------------------------------------------------------------------------

def test_policy_source_in_report(tmp_path: pathlib.Path) -> None:
    """build_report populates policy_source when passed; to_json_dict includes it."""
    import asyncio
    from memfabric.types import SubgraphView
    from apex_host.eval.report import build_report, to_json_dict
    from apex_host.graph_state import ApexGraphState

    config = ApexConfig(target="127.0.0.1", dry_run=True)
    subgraph = SubgraphView(anchor="host:127.0.0.1", nodes=[], edges=[], depth=10)

    state: ApexGraphState = {
        "run_id": "test",
        "target": "127.0.0.1",
        "phase": "recon",
        "goal": "test",
        "current_task": None,
        "evidence_summary": "",
        "findings": [],
        "error_episodes": [],
        "last_tool_result": None,
        "last_error": None,
        "completed": False,
        "turn_count": 0,
        "planner_decisions": [],
        "tool_results": None,
        "repair_count": 0,
        "policy_decisions": [],
    }

    report = build_report(
        state, subgraph, config,
        seed_results={"policy_db": 5, "_promotion": {"records_promoted": 5, "passes_run": 1,
                                                       "records_remaining": 0, "stop_reason": "exhausted",
                                                       "records_staged_initial": 5, "elapsed_seconds": 0.1}},
        policy_source="knowledge/policy_db/compiled/hackthebox_lab.yaml",
    )

    assert report.policy_source == "knowledge/policy_db/compiled/hackthebox_lab.yaml"
    assert report.seeding_counts.get("policy_db") == 5
    assert report.seeding_promotion.get("records_promoted") == 5

    j = to_json_dict(report)
    assert j["policy_gate"]["policy_source"] == "knowledge/policy_db/compiled/hackthebox_lab.yaml"
    assert j["knowledge_seeding"]["family_counts"]["policy_db"] == 5
    assert j["knowledge_seeding"]["promotion"]["stop_reason"] == "exhausted"


# ---------------------------------------------------------------------------
# 15. disabled mode returns empty summary
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disabled_mode_returns_empty_summary() -> None:
    """mode='disabled' skips all promotion and returns a zero-pass summary."""
    mf_config = Config()
    api = _make_api(mf_config)
    worker = ReflectorWorker(api, mf_config)

    await _stage_n_records(api, 10)

    summary = await promote_staged_knowledge_until_stable(api, worker, mode="disabled")

    assert summary.stop_reason == "disabled"
    assert summary.passes_run == 0
    assert summary.records_promoted == 0
    assert summary.records_remaining == 10  # all still staged


# ---------------------------------------------------------------------------
# 16. ApexConfig promotion fields have correct defaults
# ---------------------------------------------------------------------------

def test_apex_config_promotion_defaults() -> None:
    """ApexConfig promotion fields default to safe, documented values."""
    config = ApexConfig(target="10.0.0.1")
    assert config.knowledge_promotion_mode == "until_stable"
    assert config.knowledge_promotion_max_passes == 1000
    assert config.knowledge_promotion_max_records is None
    assert config.knowledge_promotion_timeout_seconds is None
