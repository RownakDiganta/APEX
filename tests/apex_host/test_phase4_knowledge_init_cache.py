# test_phase4_knowledge_init_cache.py
# Acceptance tests for Phase 4 (post-live-test debugging): the O(records x passes) promotion-loop fix and the persistent, incremental knowledge-initialization cache.
"""Phase 4 acceptance tests.

Live-test evidence addressed: 63,783 records staged, 63,764 promoted, 19
remained, 639 promotion passes, stop_reason=no_progress, elapsed_seconds
~1,757.752, almost the entire ~1,785s total runtime spent re-seeding
knowledge that had not changed since the previous run.

Covers (numbered to match this phase's own acceptance-criteria list):
1.  First clean cold initialization processes all required records correctly.
2.  Second startup with unchanged manifests does not restage/re-promote.
3.  Second startup is substantially faster (records_staged == 0 vs > 0).
4.  Changing one family processes only that family.
5.  Adding one record processes only necessary work (incremental).
6.  Interrupted initialization does not mark the cache complete.
7.  Corrupted manifest state triggers a safe rebuild.
8.  Blocked records do not cause hundreds of no-progress passes.
9.  The "19 remaining after 639 passes" class of behavior — explicit reasons.
10. Reflector remains the sole promotion path.
11. No direct promoted-store writes are introduced.
12. (Existing MemoryAPI/conflict/LWW/transaction tests — verified by the
    full suite run, not duplicated here.)
13. Docker Compose durable storage configuration — see tests/docker/test_compose.py.
14. Reset/rebuild behavior works.

Plus unit coverage for the underlying memfabric performance primitives
(filtered staging accessors, predicate-based selection, BM25 snapshot
export/import) and the manifest/init_state/init_lock building blocks.
"""
from __future__ import annotations

import ast
import inspect
import json
import pathlib
import time
from types import ModuleType
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.reflector.gates import classify_unpromoted_knowledge, classify_unpromoted_skill
from memfabric.reflector.worker import ReflectorWorker
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import KnowledgeEntry, Skill

from apex_host.config import ApexConfig
from apex_host.knowledge import init_cache, init_lock, init_state, manifest
from apex_host.knowledge.seed_loader import promote_staged_knowledge_until_stable

# pyproject.toml sets asyncio_mode = "auto" — every `async def test_*` here is
# automatically treated as an asyncio test with no per-file/per-test marker
# needed. Do NOT add `pytestmark = pytest.mark.asyncio`: this file also has
# plain (non-async) static-scan tests, and that module-level mark would
# apply — incorrectly — to those too.


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_mf_config(**kwargs: Any) -> Config:
    return Config(**kwargs)


def _make_api(mf_config: Config | None = None) -> tuple[MemoryAPI, BM25LexicalIndex, Config]:
    cfg = mf_config or _make_mf_config()
    lexical = BM25LexicalIndex()
    api = MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=lexical,
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )
    return api, lexical, cfg


def _record(rid: str, text: str, confidence: float = 0.9, **extra: Any) -> dict[str, Any]:
    rec = {
        "id": rid, "source_family": "policy_db", "source_type": "htb_rule",
        "source_path": "x", "title": rid, "text": text, "tags": [],
        "confidence": confidence, "updated_at": "2024-01-01T00:00:00Z", "metadata": {},
    }
    rec.update(extra)
    return rec


def _write_family(root: pathlib.Path, family: str, records: list[dict[str, Any]], filename: str) -> None:
    d = root / family / "compiled"
    d.mkdir(parents=True, exist_ok=True)
    with (d / filename).open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def _write_policy_family(root: pathlib.Path, records: list[dict[str, Any]]) -> None:
    _write_family(root, "policy_db", records, "policy_records.jsonl")


def _write_methodology_family(root: pathlib.Path, records: list[dict[str, Any]]) -> None:
    recs = [dict(r, source_family="methodology_db") for r in records]
    _write_family(root, "methodology_db", recs, "methodology_chunks.jsonl")


async def _init(api, lexical, cfg, apex_cfg, mf_cfg):
    return await init_cache.initialize_compiled_knowledge(api, lexical, apex_cfg, mf_cfg)


def _code_only_source(module: ModuleType) -> str:
    """Return *module*'s source with docstrings stripped (comments are
    already dropped by the ast round-trip), so static scans below check
    actual code, never prose in a docstring that happens to mention a
    forbidden call/attribute name for explanatory purposes."""
    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                node.body[0].value.value = ""
    return ast.unparse(tree)


# ---------------------------------------------------------------------------
# 1-3. Cold / warm / substantially-faster
# ---------------------------------------------------------------------------

class TestColdWarmReuse:
    async def test_cold_init_processes_all_records(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one"), _record("p2", "two")])
        api, lexical, mf_cfg = _make_api()
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(tmp_path / "cache"))
        counts, report = await _init(api, lexical, mf_cfg, apex_cfg, mf_cfg)
        assert counts["policy_db"] == 2
        assert report.initialization_mode == "cold"
        assert report.records_promoted == 2
        assert report.records_staged == 2

    async def test_second_startup_unchanged_does_not_restage(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one"), _record("p2", "two")])
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(tmp_path / "cache"))

        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg, mf1)

        api2, lex2, mf2 = _make_api()
        counts2, report2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        assert report2.initialization_mode == "reused"
        assert report2.records_staged == 0
        assert report2.records_promoted == 0
        assert report2.records_skipped_existing == 2
        # And the reused documents are genuinely present in the fresh process's index.
        assert await lex2.document_count() == 2

    async def test_second_startup_substantially_faster(self, tmp_path: pathlib.Path) -> None:
        records = [_record(f"p{i}", f"text number {i}") for i in range(500)]
        _write_policy_family(tmp_path, records)
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(tmp_path / "cache"))

        api1, lex1, mf1 = _make_api()
        t0 = time.monotonic()
        await _init(api1, lex1, mf1, apex_cfg, mf1)
        cold_elapsed = time.monotonic() - t0

        api2, lex2, mf2 = _make_api()
        t1 = time.monotonic()
        _, report2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        warm_elapsed = time.monotonic() - t1

        assert report2.records_staged == 0
        # The warm path does zero propose_knowledge/promote_knowledge calls;
        # the cold path does 500 of each. Timing comparison is a secondary,
        # generous check (avoids CI flakiness) — the authoritative signal is
        # records_staged==0 above.
        assert warm_elapsed <= cold_elapsed + 0.05


# ---------------------------------------------------------------------------
# 4. Changing one family processes only that family
# ---------------------------------------------------------------------------

class TestFamilyIsolation:
    async def test_changing_one_family_processes_only_that_family(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one")])
        _write_methodology_family(tmp_path, [_record("m1", "meth one")])
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(tmp_path / "cache"))

        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg, mf1)

        # Change only policy_db.
        _write_policy_family(tmp_path, [_record("p1", "one"), _record("p2", "two, added")])

        api2, lex2, mf2 = _make_api()
        counts2, report2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        assert report2.families_changed == ["policy_db"]
        assert report2.families_reused == ["methodology_db"]
        assert report2.records_staged == 1  # only p2


# ---------------------------------------------------------------------------
# 5. Adding one record -> only necessary work
# ---------------------------------------------------------------------------

class TestIncrementalAddition:
    async def test_adding_one_record_stages_only_that_record(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one"), _record("p2", "two")])
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(tmp_path / "cache"))

        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg, mf1)

        _write_policy_family(tmp_path, [_record("p1", "one"), _record("p2", "two"), _record("p3", "three, new")])

        api2, lex2, mf2 = _make_api()
        counts2, report2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        assert report2.initialization_mode == "incremental"
        assert report2.records_staged == 1
        assert report2.records_skipped_existing == 2
        assert await lex2.document_count() == 3

    async def test_edited_record_same_id_is_detected_and_restaged(self, tmp_path: pathlib.Path) -> None:
        """A record whose id is unchanged but content changed must still be re-staged."""
        _write_policy_family(tmp_path, [_record("p1", "original text")])
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(tmp_path / "cache"))

        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg, mf1)

        _write_policy_family(tmp_path, [_record("p1", "EDITED text, same id")])

        api2, lex2, mf2 = _make_api()
        counts2, report2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        assert report2.records_staged == 1
        results = await lex2.search("EDITED", k=5)
        assert any(r[0] == "p1" for r in results)

    async def test_removed_record_is_deprecated_not_deleted(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one"), _record("p2", "two")])
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(tmp_path / "cache"))

        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg, mf1)

        _write_policy_family(tmp_path, [_record("p1", "one")])  # p2 removed from source

        api2, lex2, mf2 = _make_api()
        await _init(api2, lex2, mf2, apex_cfg, mf2)
        # Not silently deleted: still present and queryable this run.
        assert await lex2.document_count() == 2
        state_result = await init_state.read_init_state(apex_cfg.knowledge_cache_path)
        rec = state_result.state.families["policy_db"]
        assert "p2" in rec.deprecated_ids


# ---------------------------------------------------------------------------
# 6. Interrupted initialization does not mark the cache complete
# ---------------------------------------------------------------------------

class TestInterruptedInitialization:
    async def test_interrupted_run_leaves_status_in_progress(self, tmp_path: pathlib.Path) -> None:
        records = [_record(f"p{i}", f"text {i}") for i in range(10)]
        _write_policy_family(tmp_path, records)
        apex_cfg = ApexConfig(
            target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(tmp_path / "cache"),
            knowledge_promotion_max_passes=0,  # guarantees an incomplete promotion pass
        )
        api, lex, mf = _make_api()
        counts, report = await _init(api, lex, mf, apex_cfg, mf)
        assert report.records_promoted == 0

        state_result = await init_state.read_init_state(apex_cfg.knowledge_cache_path)
        rec = state_result.state.families["policy_db"]
        assert rec.status == "in_progress"

    async def test_next_run_after_interruption_is_marked_resumed_and_completes(self, tmp_path: pathlib.Path) -> None:
        records = [_record(f"p{i}", f"text {i}") for i in range(10)]
        _write_policy_family(tmp_path, records)
        cache_dir = tmp_path / "cache"

        apex_cfg_interrupted = ApexConfig(
            target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(cache_dir),
            knowledge_promotion_max_passes=0,
        )
        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg_interrupted, mf1)

        apex_cfg_resume = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(cache_dir))
        api2, lex2, mf2 = _make_api()
        counts2, report2 = await _init(api2, lex2, mf2, apex_cfg_resume, mf2)
        assert report2.initialization_mode == "resumed"
        assert report2.records_promoted == 10

        state_result = await init_state.read_init_state(cache_dir)
        assert state_result.state.families["policy_db"].status == "complete"

    async def test_crash_before_write_leaves_no_false_complete_state(self, tmp_path: pathlib.Path) -> None:
        """No state file at all (simulating a crash before any write) must never be misread as complete."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        result = await init_state.read_init_state(cache_dir)
        assert result.status == "missing"
        assert result.state.families == {}


# ---------------------------------------------------------------------------
# 7. Corrupted manifest state triggers a safe rebuild
# ---------------------------------------------------------------------------

class TestCorruptionRecovery:
    async def test_corrupt_state_json_triggers_rebuild(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one")])
        cache_dir = tmp_path / "cache"
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(cache_dir))

        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg, mf1)

        (cache_dir / "init_state.json").write_text("{ not valid json !!!")

        api2, lex2, mf2 = _make_api()
        counts2, report2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        assert report2.initialization_mode == "rebuild"
        assert report2.reuse_rejected_reason  # a human-readable reason is present
        # The payload file was untouched by the corruption, so this is a safe,
        # minimal rebuild — no data loss, still queryable.
        assert await lex2.document_count() == 1

    async def test_incompatible_schema_version_triggers_rebuild(self, tmp_path: pathlib.Path) -> None:
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        (cache_dir / "init_state.json").write_text(json.dumps({"state_schema_version": "999", "families": {}}))
        result = await init_state.read_init_state(cache_dir)
        assert result.status == "incompatible_schema"

    async def test_missing_payload_with_complete_state_falls_back_to_processing(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one")])
        cache_dir = tmp_path / "cache"
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(cache_dir))

        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg, mf1)
        (cache_dir / "family_policy_db.json").unlink()

        api2, lex2, mf2 = _make_api()
        counts2, report2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        assert "policy_db" in report2.families_changed
        assert report2.records_staged == 1
        assert await lex2.document_count() == 1


# ---------------------------------------------------------------------------
# 8-9. Blocked records: bounded passes + explicit reasons
# ---------------------------------------------------------------------------

class TestBlockedRecordDiagnostics:
    async def test_original_evidence_class_reproduced_with_reasons(self, tmp_path: pathlib.Path) -> None:
        """Reproduces the '19 remaining after 639 passes' class of behavior
        with a smaller corpus, verifying bounded passes and explicit reasons."""
        records = [_record(f"p{i}", f"text {i}", confidence=0.9) for i in range(300)]
        for i in range(0, 300, 30):
            records[i]["confidence"] = 0.1  # 10 permanently-blocked records, interspersed
        api, lex, cfg = _make_api(_make_mf_config(reflector_max_promotions_per_run=25))
        for r in records:
            entry = KnowledgeEntry(id=r["id"], text=r["text"], source="t", confidence=r["confidence"])
            await api.propose_knowledge(entry)

        worker = ReflectorWorker(api, cfg)
        t0 = time.monotonic()
        summary = await promote_staged_knowledge_until_stable(api, worker, mode="until_stable", max_passes=1000)
        elapsed = time.monotonic() - t0

        assert summary.stop_reason == "no_progress"
        assert summary.records_remaining == 10
        assert summary.blocked_reason_counts == {"below_min_confidence": 10}
        # Bounded, not "hundreds of useless passes": 300 records / 25 per
        # pass == 12 productive passes + 1 confirming no-progress pass.
        assert summary.passes_run <= 15
        assert elapsed < 5.0  # was ~1757s before this phase's fix

    async def test_one_blocked_record_does_not_cause_hundreds_of_passes(self, tmp_path: pathlib.Path) -> None:
        api, lex, cfg = _make_api(_make_mf_config(reflector_max_promotions_per_run=10))
        await api.propose_knowledge(KnowledgeEntry(id="blocked", text="x", source="t", confidence=0.01))
        worker = ReflectorWorker(api, cfg)
        summary = await promote_staged_knowledge_until_stable(api, worker, mode="until_stable", max_passes=1000)
        assert summary.passes_run == 1
        assert summary.stop_reason == "no_progress"
        assert summary.blocked_reason_counts == {"below_min_confidence": 1}

    async def test_blocked_skill_reason_classification(self) -> None:
        api, lex, cfg = _make_api()
        skill = Skill(
            id="s1", name="low_evidence_skill", description="d",
            template={}, preconditions={}, source_episodes=[],
            confidence=0.9, evidence_count=0,
        )
        await api.propose_skill(skill)
        staged = (await api.get_staged_skills())[0]
        reason = classify_unpromoted_skill(
            staged, min_evidence_count=cfg.min_evidence_count, min_confidence=cfg.min_confidence
        )
        assert reason == "below_min_evidence"

    async def test_classify_unpromoted_knowledge_permanent_vs_pending(self) -> None:
        low = KnowledgeEntry(id="a", text="x", source="t", confidence=0.1)
        eligible = KnowledgeEntry(id="b", text="x", source="t", confidence=0.9)
        assert classify_unpromoted_knowledge(low, min_confidence=0.5) == "below_min_confidence"
        assert classify_unpromoted_knowledge(eligible, min_confidence=0.5) == "eligible_pending_pass"


# ---------------------------------------------------------------------------
# 10-11. Reflector remains sole promotion path; no direct store writes
# ---------------------------------------------------------------------------

class TestNoBypass:
    def test_init_cache_never_calls_promote_directly(self) -> None:
        src = _code_only_source(init_cache)
        assert ".promote_knowledge(" not in src
        assert ".promote_skill(" not in src

    def test_init_cache_never_touches_lexical_docs_directly(self) -> None:
        src = _code_only_source(init_cache)
        assert "_docs" not in src
        assert "_id_to_pos" not in src

    def test_manifest_module_never_writes_to_memory_api(self) -> None:
        src = _code_only_source(manifest)
        assert "propose_knowledge" not in src
        assert "promote_knowledge" not in src
        assert "MemoryAPI" not in src

    async def test_reflector_worker_is_the_only_promoter_in_a_full_init(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one"), _record("p2", "two")])
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(tmp_path / "cache"))
        api, lex, mf = _make_api()

        original = ReflectorWorker.run_once
        calls = {"n": 0}

        async def spy(self):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            return await original(self)

        ReflectorWorker.run_once = spy  # type: ignore[method-assign]
        try:
            await _init(api, lex, mf, apex_cfg, mf)
        finally:
            ReflectorWorker.run_once = original  # type: ignore[method-assign]
        assert calls["n"] >= 1


# ---------------------------------------------------------------------------
# 14. Reset / rebuild
# ---------------------------------------------------------------------------

class TestResetRebuild:
    async def test_reset_all_forces_cold_rebuild(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one")])
        cache_dir = tmp_path / "cache"
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(cache_dir))

        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg, mf1)

        removed = await init_cache.reset_knowledge_cache(cache_dir)
        assert removed >= 1

        api2, lex2, mf2 = _make_api()
        counts2, report2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        assert report2.initialization_mode == "cold"
        assert report2.records_staged == 1

    async def test_reset_single_family_leaves_others_cached(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one")])
        _write_methodology_family(tmp_path, [_record("m1", "meth")])
        cache_dir = tmp_path / "cache"
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path), knowledge_cache_path=str(cache_dir))

        api1, lex1, mf1 = _make_api()
        await _init(api1, lex1, mf1, apex_cfg, mf1)

        await init_cache.reset_knowledge_cache(cache_dir, family="policy_db")

        api2, lex2, mf2 = _make_api()
        counts2, report2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        assert "policy_db" in report2.families_changed
        assert "methodology_db" in report2.families_reused


# ---------------------------------------------------------------------------
# No durable storage configured -> bounded fallback, no false persistence claim
# ---------------------------------------------------------------------------

class TestNoPersistenceFallback:
    async def test_no_cache_path_configured_still_correct_but_not_persistent(self, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one")])
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path))  # no knowledge_cache_path
        api, lex, mf = _make_api()
        with caplog.at_level("WARNING"):
            counts, report = await _init(api, lex, mf, apex_cfg, mf)
        assert counts["policy_db"] == 1
        assert report.persistence_enabled is False
        assert report.persistence_path_category == "not_configured"
        assert any("persistence is DISABLED" in r.message for r in caplog.records)

    async def test_running_twice_without_cache_restages_both_times(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one")])
        apex_cfg = ApexConfig(target="t", knowledge_root=str(tmp_path))
        api1, lex1, mf1 = _make_api()
        _, r1 = await _init(api1, lex1, mf1, apex_cfg, mf1)
        api2, lex2, mf2 = _make_api()
        _, r2 = await _init(api2, lex2, mf2, apex_cfg, mf2)
        assert r1.records_staged == 1
        assert r2.records_staged == 1  # no persistence => always re-staged


# ---------------------------------------------------------------------------
# Manifest identity — content-hash based, never mtime
# ---------------------------------------------------------------------------

class TestManifestIdentity:
    async def test_identical_content_same_manifest_regardless_of_mtime(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one")])
        rs1 = await manifest.compute_family_record_set(tmp_path / "policy_db" / "compiled", "policy_db")
        assert rs1 is not None

        # Touch the file (changes mtime) without changing content.
        path = tmp_path / "policy_db" / "compiled" / "policy_records.jsonl"
        content = path.read_text()
        time.sleep(0.01)
        path.write_text(content)

        rs2 = await manifest.compute_family_record_set(tmp_path / "policy_db" / "compiled", "policy_db")
        assert rs2 is not None
        assert rs1.manifest.identity_matches(rs2.manifest)

    async def test_content_change_produces_different_dataset_id(self, tmp_path: pathlib.Path) -> None:
        _write_policy_family(tmp_path, [_record("p1", "one")])
        rs1 = await manifest.compute_family_record_set(tmp_path / "policy_db" / "compiled", "policy_db")
        _write_policy_family(tmp_path, [_record("p1", "one CHANGED")])
        rs2 = await manifest.compute_family_record_set(tmp_path / "policy_db" / "compiled", "policy_db")
        assert rs1 is not None and rs2 is not None
        assert not rs1.manifest.identity_matches(rs2.manifest)

    async def test_missing_family_returns_none(self, tmp_path: pathlib.Path) -> None:
        result = await manifest.compute_family_record_set(tmp_path / "nope" / "compiled", "policy_db")
        assert result is None

    def test_manifest_module_never_reads_mtime_for_identity(self) -> None:
        src = inspect.getsource(manifest)
        assert "st_mtime" not in src
        assert ".stat()" not in src


# ---------------------------------------------------------------------------
# init_state — atomic write, schema versioning
# ---------------------------------------------------------------------------

class TestInitStatePersistence:
    async def test_write_then_read_roundtrip(self, tmp_path: pathlib.Path) -> None:
        fam_manifest = manifest.FamilyManifest(
            family="policy_db", schema_version="1", source_artifacts=["a.jsonl"],
            record_count=2, dataset_id="abc123",
        )
        rec = init_state.FamilyInitRecord(manifest=fam_manifest, status="complete", records_promoted=2)
        state = init_state.KnowledgeInitState(families={"policy_db": rec})
        await init_state.write_init_state(tmp_path, state)

        result = await init_state.read_init_state(tmp_path)
        assert result.status == "ok"
        assert result.state.families["policy_db"].status == "complete"
        assert result.state.families["policy_db"].manifest.dataset_id == "abc123"

    async def test_missing_file_is_missing_not_corrupt(self, tmp_path: pathlib.Path) -> None:
        result = await init_state.read_init_state(tmp_path)
        assert result.status == "missing"

    async def test_write_is_atomic_no_tmp_file_left_behind(self, tmp_path: pathlib.Path) -> None:
        state = init_state.KnowledgeInitState()
        await init_state.write_init_state(tmp_path, state)
        leftovers = list(tmp_path.glob("*.tmp"))
        assert leftovers == []
        assert (tmp_path / "init_state.json").exists()


# ---------------------------------------------------------------------------
# init_lock — cross-process advisory lock
# ---------------------------------------------------------------------------

class TestInitLock:
    async def test_acquire_and_release(self, tmp_path: pathlib.Path) -> None:
        async with init_lock.cache_directory_lock(tmp_path) as lock:
            assert lock.acquired is True
            assert (tmp_path / ".init.lock").exists()
        assert not (tmp_path / ".init.lock").exists()

    async def test_second_concurrent_waiter_times_out_and_degrades(self, tmp_path: pathlib.Path) -> None:
        async with init_lock.cache_directory_lock(tmp_path) as outer:
            assert outer.acquired
            async with init_lock.cache_directory_lock(tmp_path, timeout_seconds=0.2) as inner:
                assert inner.acquired is False
                assert inner.reason

    async def test_stale_lock_is_reclaimed(self, tmp_path: pathlib.Path) -> None:
        lock_path = tmp_path / ".init.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps({"pid": 999999, "acquired_at": 0}))
        import os
        old_time = time.time() - 10000
        os.utime(lock_path, (old_time, old_time))

        async with init_lock.cache_directory_lock(
            tmp_path, timeout_seconds=2.0, stale_after_seconds=1.0
        ) as lock:
            assert lock.acquired is True
            assert lock.reclaimed_stale is True

    async def test_two_sequential_acquisitions_both_succeed(self, tmp_path: pathlib.Path) -> None:
        async with init_lock.cache_directory_lock(tmp_path) as l1:
            assert l1.acquired
        async with init_lock.cache_directory_lock(tmp_path) as l2:
            assert l2.acquired


# ---------------------------------------------------------------------------
# MemoryAPI performance primitives (the root-cause fix)
# ---------------------------------------------------------------------------

class TestMemoryApiStagingPerformance:
    async def test_get_staged_knowledge_promoted_filter(self) -> None:
        api, lex, cfg = _make_api()
        e1 = KnowledgeEntry(id="a", text="x", source="t", confidence=0.9)
        e2 = KnowledgeEntry(id="b", text="y", source="t", confidence=0.9)
        await api.propose_knowledge(e1)
        await api.propose_knowledge(e2)
        await api.promote_knowledge("a")

        unpromoted = await api.get_staged_knowledge(promoted=False)
        assert {e.id for e in unpromoted} == {"b"}
        promoted = await api.get_staged_knowledge(promoted=True)
        assert {e.id for e in promoted} == {"a"}
        everything = await api.get_staged_knowledge()
        assert {e.id for e in everything} == {"a", "b"}

    async def test_count_staged_knowledge_matches_get(self) -> None:
        api, lex, cfg = _make_api()
        for i in range(5):
            await api.propose_knowledge(KnowledgeEntry(id=f"k{i}", text="x", source="t", confidence=0.9))
        await api.promote_knowledge("k0")
        await api.promote_knowledge("k1")
        assert await api.count_staged_knowledge(promoted=False) == 3
        assert await api.count_staged_knowledge(promoted=True) == 2
        assert await api.count_staged_knowledge() == 5

    async def test_select_unpromoted_knowledge_ids_respects_limit(self) -> None:
        api, lex, cfg = _make_api()
        for i in range(10):
            await api.propose_knowledge(KnowledgeEntry(id=f"k{i}", text="x", source="t", confidence=0.9))
        ids = await api.select_unpromoted_knowledge_ids(lambda e: True, limit=3)
        assert len(ids) == 3
        assert set(ids) <= {f"k{i}" for i in range(10)}

    async def test_select_unpromoted_knowledge_ids_predicate_filters(self) -> None:
        api, lex, cfg = _make_api()
        await api.propose_knowledge(KnowledgeEntry(id="lo", text="x", source="t", confidence=0.1))
        await api.propose_knowledge(KnowledgeEntry(id="hi", text="x", source="t", confidence=0.9))
        ids = await api.select_unpromoted_knowledge_ids(lambda e: e.confidence >= 0.5)
        assert ids == ["hi"]

    async def test_rollback_removes_ids_from_pending_index(self) -> None:
        from memfabric.types import Node

        api, lex, cfg = _make_api()
        # apply_deltas with a knowledge proposal that fails alongside a bad node
        # (node upsert never fails in the reference store, so trigger a failure
        # via episodes requiring _pop_episodes on a store that doesn't have it —
        # simpler: directly test that propose+rollback path leaves no dangling id
        # by calling the rollback helper indirectly through a forced exception).
        entry = KnowledgeEntry(id="rb1", text="x", source="t", confidence=0.9)
        try:
            await api.apply_deltas(
                nodes=[Node(id="n1", type="host", props={}, confidence=0.9, source="t",
                            first_seen="t", last_seen="t")],
                knowledge=[entry],
                episodes=[object()],  # type: ignore[list-item]  # forces a failure -> rollback
            )
        except Exception:
            pass
        remaining = await api.count_staged_knowledge(promoted=False)
        assert remaining == 0  # rolled back — never left dangling in the pending index


# ---------------------------------------------------------------------------
# BM25LexicalIndex export/import (generic snapshot support)
# ---------------------------------------------------------------------------

class TestLexicalSnapshot:
    async def test_export_import_roundtrip(self) -> None:
        idx = BM25LexicalIndex()
        await idx.add("a", "hello world", {"source_family": "policy_db"})
        await idx.add("b", "goodbye world", {"source_family": "intel_db"})

        docs = await idx.export_documents()
        assert {d["id"] for d in docs} == {"a", "b"}

        idx2 = BM25LexicalIndex()
        n = await idx2.import_documents(docs)
        assert n == 2
        results = await idx2.search("hello", k=5)
        assert results and results[0][0] == "a"

    async def test_export_with_predicate_filters_by_family(self) -> None:
        idx = BM25LexicalIndex()
        await idx.add("a", "x", {"source_family": "policy_db"})
        await idx.add("b", "y", {"source_family": "intel_db"})
        docs = await idx.export_documents(lambda m: m.get("source_family") == "policy_db")
        assert [d["id"] for d in docs] == ["a"]

    async def test_export_excludes_tombstones(self) -> None:
        idx = BM25LexicalIndex()
        await idx.add("a", "x", {})
        await idx.add("b", "y", {})
        await idx.remove("a")
        docs = await idx.export_documents()
        assert [d["id"] for d in docs] == ["b"]

    async def test_document_count(self) -> None:
        idx = BM25LexicalIndex()
        assert await idx.document_count() == 0
        await idx.add("a", "x", {})
        assert await idx.document_count() == 1
        await idx.remove("a")
        assert await idx.document_count() == 0
