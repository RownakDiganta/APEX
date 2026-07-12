# test_reflector_bounded.py
# Tests for the bounded Reflector promotion gate: cap, summary logging, no re-promotion.
"""Tests for the bounded reflector promotion gate (Part B).

Invariants verified:
- At most reflector_max_promotions_per_run entries are promoted per run_once().
- Entries above the cap remain staged with promoted=False and are picked up
  on the next run_once() call.
- Per-item logs are at DEBUG (not INFO); end-of-pass summary is also at DEBUG (Part 5).
- Already-promoted entries are not re-promoted on subsequent calls.
"""
from __future__ import annotations

import logging

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.reflector.worker import ReflectorWorker
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import KnowledgeEntry


def _make_api(
    *,
    max_promotions: int = 100,
    log_every_n: int = 25,
    min_confidence: float = 0.5,
) -> tuple[MemoryAPI, Config]:
    cfg = Config(
        min_confidence=min_confidence,
        reflector_max_promotions_per_run=max_promotions,
        reflector_log_every_n=log_every_n,
    )
    api = MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )
    return api, cfg


def _make_entry(confidence: float = 0.7) -> KnowledgeEntry:
    return KnowledgeEntry(
        id=new_id(),
        text=f"knowledge entry {new_id()}",
        source="test_source",
        confidence=confidence,
        timestamp=now(),
    )


@pytest.mark.asyncio
async def test_promotion_cap_limits_total_promoted() -> None:
    """At most max_promotions entries are promoted in a single run_once call."""
    api, cfg = _make_api(max_promotions=5)
    worker = ReflectorWorker(api, cfg)

    # Stage 10 entries — all above the confidence gate.
    for _ in range(10):
        await api.propose_knowledge(_make_entry(confidence=0.9))

    await worker.run_once()

    staged = await api.get_staged_knowledge()
    promoted_count = sum(1 for e in staged if e.promoted)
    assert promoted_count == 5, f"Expected 5 promoted, got {promoted_count}"


@pytest.mark.asyncio
async def test_remaining_promoted_on_next_run() -> None:
    """Entries not promoted due to cap are picked up on the next run_once()."""
    api, cfg = _make_api(max_promotions=3)
    worker = ReflectorWorker(api, cfg)

    for _ in range(6):
        await api.propose_knowledge(_make_entry(confidence=0.9))

    # First pass: promote 3.
    await worker.run_once()
    staged = await api.get_staged_knowledge()
    assert sum(1 for e in staged if e.promoted) == 3

    # Second pass: promote remaining 3.
    await worker.run_once()
    staged = await api.get_staged_knowledge()
    assert sum(1 for e in staged if e.promoted) == 6


@pytest.mark.asyncio
async def test_already_promoted_not_reprocessed() -> None:
    """Entries already promoted are skipped on subsequent run_once() calls."""
    api, cfg = _make_api(max_promotions=10)
    worker = ReflectorWorker(api, cfg)

    for _ in range(4):
        await api.propose_knowledge(_make_entry(confidence=0.9))

    await worker.run_once()
    staged_after_first = await api.get_staged_knowledge()
    first_promoted = sum(1 for e in staged_after_first if e.promoted)
    assert first_promoted == 4

    # Second run: no new entries → 0 new promotions (already all promoted).
    await worker.run_once()
    staged_after_second = await api.get_staged_knowledge()
    assert sum(1 for e in staged_after_second if e.promoted) == 4


@pytest.mark.asyncio
async def test_below_confidence_not_promoted() -> None:
    """Entries below min_confidence are skipped and count as 'skipped'."""
    api, cfg = _make_api(min_confidence=0.8)
    worker = ReflectorWorker(api, cfg)

    await api.propose_knowledge(_make_entry(confidence=0.6))
    await api.propose_knowledge(_make_entry(confidence=0.9))

    await worker.run_once()

    staged = await api.get_staged_knowledge()
    promoted = [e for e in staged if e.promoted]
    assert len(promoted) == 1
    assert promoted[0].confidence == 0.9


@pytest.mark.asyncio
async def test_summary_log_at_debug_not_info(caplog: pytest.LogCaptureFixture) -> None:
    """Per-pass promotion summary is at DEBUG, not INFO.

    Part 5 moved the per-pass summary from INFO to DEBUG so that 638 Reflector
    passes during a 63 k-record corpus seed do not flood the terminal under -v.
    Interval progress logs (every 50 passes) are emitted at INFO by seed_loader.py
    instead — not by the worker.  Zero INFO lines should come from the worker's
    promotion pass itself.
    """
    api, cfg = _make_api(max_promotions=50, log_every_n=5)
    worker = ReflectorWorker(api, cfg)

    for _ in range(3):
        await api.propose_knowledge(_make_entry(confidence=0.9))

    with caplog.at_level(logging.DEBUG, logger="memfabric.reflector.worker"):
        await worker.run_once()

    # The per-pass summary "promoted=... skipped=... remaining=..." must be at DEBUG.
    debug_summary = [r for r in caplog.records if r.levelno == logging.DEBUG
                     and "promoted=" in r.message and "reflector.worker" in r.name]
    assert len(debug_summary) >= 1, "Expected at least one DEBUG summary record"
    # No INFO record should contain "promoted=" (that would be the old per-pass INFO).
    info_with_promoted = [r for r in caplog.records if r.levelno == logging.INFO
                          and "promoted=" in r.message and "reflector.worker" in r.name]
    assert len(info_with_promoted) == 0, (
        f"Per-pass summary must not be at INFO; found: {info_with_promoted}"
    )


@pytest.mark.asyncio
async def test_per_item_logs_at_debug_only(caplog: pytest.LogCaptureFixture) -> None:
    """Per-item 'promoted knowledge id=…' lines are at DEBUG, not INFO."""
    api, cfg = _make_api(max_promotions=50, log_every_n=1)  # log every 1 so debug fires
    worker = ReflectorWorker(api, cfg)

    for _ in range(3):
        await api.propose_knowledge(_make_entry(confidence=0.9))

    with caplog.at_level(logging.DEBUG, logger="memfabric.reflector.worker"):
        await worker.run_once()

    # No INFO records for individual promotions.
    info_with_id = [r for r in caplog.records if r.levelno == logging.INFO
                    and "id=" in r.message and "promoted=" not in r.message]
    assert len(info_with_id) == 0, f"Per-item logs must be DEBUG: {info_with_id}"


@pytest.mark.asyncio
async def test_api_level_promotion_log_is_debug(caplog: pytest.LogCaptureFixture) -> None:
    """The api.py-level 'promoted knowledge id=…' log is also at DEBUG."""
    api, cfg = _make_api()
    worker = ReflectorWorker(api, cfg)

    await api.propose_knowledge(_make_entry(confidence=0.9))

    with caplog.at_level(logging.DEBUG, logger="memfabric.api"):
        await worker.run_once()

    api_info = [r for r in caplog.records if r.levelno == logging.INFO
                and "memfabric.api" in r.name and "promoted" in r.message]
    assert len(api_info) == 0, f"api.py must log promotions at DEBUG, not INFO: {api_info}"


@pytest.mark.asyncio
async def test_config_new_fields_have_correct_defaults() -> None:
    """New Config fields exist with the correct defaults."""
    cfg = Config()
    assert cfg.reflector_max_promotions_per_run == 100
    assert cfg.reflector_log_every_n == 25


@pytest.mark.asyncio
async def test_zero_entries_summary_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    """run_once() with no staged entries emits the pass summary at DEBUG (not INFO).

    Per-pass summaries are at DEBUG since Part 5 so that large corpus seeds
    (638+ passes) do not flood the terminal under normal -v.
    """
    api, cfg = _make_api()
    worker = ReflectorWorker(api, cfg)

    with caplog.at_level(logging.DEBUG, logger="memfabric.reflector.worker"):
        await worker.run_once()

    debug_summary = [r for r in caplog.records if r.levelno == logging.DEBUG
                     and "promoted=" in r.message and "reflector.worker" in r.name]
    assert len(debug_summary) >= 1, "Expected DEBUG summary even with zero entries"
    assert "promoted=0" in debug_summary[0].message
