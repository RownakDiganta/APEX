# init_cache.py
# Orchestrates safe, persistent, incremental knowledge initialization: compares deterministic manifests against durable state, skips unchanged families, incrementally re-stages only added/changed records, and always promotes exclusively through the Reflector.
"""Safe, persistent, incremental knowledge-initialization orchestrator (Phase 4).

Root cause this module fixes
-----------------------------
A live-test run showed ~1,785 total seconds spent on startup, of which
~1,758s was the Reflector promotion loop for a 63,783-record compiled
corpus — repeated on **every** run, even when the compiled knowledge files
had not changed at all. Two independent problems combined to cause this:

1. The promotion loop itself was accidentally O(records × passes) — fixed
   separately (see ``memfabric.api.MemoryAPI.select_unpromoted_knowledge_ids``
   and ``docs/knowledge-initialization.md`` "Promotion-loop performance
   fix"). That fix alone takes the SAME 63,783-record corpus from ~1,758s
   to ~0.2s for one run.
2. Even at ~0.2s, EVERY disposable APEX container re-did this work from
   scratch, because none of the underlying memfabric reference stores this
   codebase wires up (``BM25LexicalIndex``, in-memory staging dicts) persist
   across a process restart. This module is the fix for THAT problem: when
   a durable cache directory is configured (surviving container restarts —
   see ``compose.yaml``'s ``apex-knowledge-cache`` named volume), and a
   family's compiled input is byte-for-byte identical (by deterministic
   content hash, never file mtime) to what was staged and Reflector-
   promoted in a prior run, that family's promoted documents are reloaded
   directly into a fresh ``BM25LexicalIndex`` instance and staging/
   promotion is skipped entirely for it.

Why this does not violate any Memory Fabric invariant
-------------------------------------------------------
- **No second write path.** The ONLY way a document ever enters
  ``BM25LexicalIndex._docs`` is through ``BM25LexicalIndex.add()`` — called
  either by ``MemoryAPI.promote_knowledge()`` (the normal, Reflector-gated
  path) or by ``BM25LexicalIndex.import_documents()`` (this module's reuse
  path), which is ITSELF implemented as a loop of plain ``add()`` calls
  (see ``memfabric/stores/lexical_bm25.py``). There is no direct
  manipulation of the index's internal state from here or anywhere else.
- **Reflector remains the sole promoter.** A "reuse" hit imports documents
  that were themselves ONLY ever written by a real
  ``MemoryAPI.promote_knowledge()`` call in some PRIOR run — this module
  never calls ``promote_knowledge()`` directly and never marks a fresh
  ``KnowledgeEntry`` as promoted. Reloading a store's own prior, legitimate,
  already-gate-cleared output at process start is the exact same pattern
  the reference ``JSONLEpisodicStore`` already uses (it replays its own
  file into memory at construction) — not a new promotion mechanism.
- **Not "rebuilding from files behind MemoryAPI's back."** This module
  never reads the RAW compiled knowledge JSONL files to reconstruct
  promoted state. It reads its OWN prior serialization of what
  ``MemoryAPI``/the lexical index already legitimately produced (a
  ``family_<name>.json`` payload file written by THIS module, in THIS
  module's own format) — the raw compiled files are read only to compute
  the current, comparison-only ``FamilyManifest`` (a cheap, read-only
  operation with no MemoryAPI interaction at all — see
  ``apex_host.knowledge.manifest``).
- **Staging/Reflector-promotion is untouched for changed or new content.**
  Any family whose manifest does not match — including every record that is
  new or content-changed within an otherwise-matching family — goes through
  the EXACT SAME ``propose_knowledge()`` → ``ReflectorWorker.run_once()``
  path as before this feature existed. Nothing here ever adds a record to
  the graph/lexical/vector index without first being staged and gate-
  checked, UNLESS that exact record was already gate-checked in a prior run
  (the reuse case above).

Two-file persisted format (see ``apex_host.knowledge.init_state`` and this
module's own payload helpers for the full field-by-field description):

- ``init_state.json`` — small, always read/written every run: per-family
  manifest identity + completion status + summary counts.
- ``family_<name>.json`` — one per family, read only on a reuse hit or an
  incremental-diff computation, written only after that family was
  (re-)processed this run: the manifest, per-record content-hash digests
  (for computing "what changed" without re-reading compiled files a second
  time), and the actual promoted document content for
  ``BM25LexicalIndex.import_documents()``.

Removed-record policy (item 8 of this feature's design brief)
----------------------------------------------------------------
memfabric has no "delete promoted knowledge" primitive (only
``delete_node``/``delete_edge`` for the GRAPH tier — knowledge/skill
promotion is index-only, upsert/add semantics, by design). This module
therefore NEVER deletes a promoted document merely because its source
record disappeared from the compiled files. Instead: a record id present in
a family's PRIOR payload but absent from the CURRENT manifest is recorded
in ``FamilyInitRecord.deprecated_ids`` (bounded id list, never content) and
its already-imported document is left in place (still retrievable). The
explicit, documented way to actually drop it is a full rebuild for that
family (``reset_family_cache`` / the ``--reset-knowledge-cache`` CLI flag —
see ``docs/knowledge-initialization.md`` "Reset and rebuild"), which starts
from an empty snapshot and stages only what currently exists in the
compiled files.
"""
from __future__ import annotations

import json
import logging
import pathlib
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from apex_host.async_utils import read_text_async, write_json_atomic
from apex_host.knowledge.compiled_loader import load_compiled_family
from apex_host.knowledge.init_lock import cache_directory_lock
from apex_host.knowledge.init_state import (
    FamilyInitRecord,
    read_init_state,
    write_init_state,
)
from apex_host.knowledge.manifest import FamilyManifest, FamilyRecordSet, compute_family_record_set
from apex_host.knowledge.seed_loader import (
    PromotionSummary,
    promote_staged_knowledge_until_stable,
    resolve_family_paths,
)
from memfabric.ids import now
from memfabric.reflector.worker import ReflectorWorker

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI
    from memfabric.config import Config
    from memfabric.stores.lexical_bm25 import BM25LexicalIndex
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

_KNOWN_FAMILIES = ("policy_db", "methodology_db", "intel_db", "payload_db")

# Terminal PromotionSummary.stop_reason values — "nothing more can happen
# without new input or a config change". Anything else (max_passes/timeout/
# max_records) means the run was budget-interrupted, not genuinely done.
_TERMINAL_STOP_REASONS = frozenset({"exhausted", "no_progress"})


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class KnowledgeInitReport:
    """Structured, report-ready summary of one knowledge-initialization run."""

    initialization_mode: str = "cold"  # cold | resumed | incremental | reused | rebuild
    families_reused: list[str] = field(default_factory=list)
    families_changed: list[str] = field(default_factory=list)
    records_examined: int = 0
    records_staged: int = 0
    records_promoted: int = 0
    records_skipped_existing: int = 0
    records_blocked: int = 0
    blocked_reason_counts: dict[str, int] = field(default_factory=dict)
    manifest_identities: dict[str, str] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    persistence_enabled: bool = False
    persistence_path_category: str = "not_configured"  # not_configured | configured
    reuse_rejected_reason: str = ""
    family_counts: dict[str, int] = field(default_factory=dict)
    promotion: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "initialization_mode": self.initialization_mode,
            "families_reused": list(self.families_reused),
            "families_changed": list(self.families_changed),
            "records_examined": self.records_examined,
            "records_staged": self.records_staged,
            "records_promoted": self.records_promoted,
            "records_skipped_existing": self.records_skipped_existing,
            "records_blocked": self.records_blocked,
            "blocked_reason_counts": dict(self.blocked_reason_counts),
            "manifest_identities": dict(self.manifest_identities),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "persistence_enabled": self.persistence_enabled,
            "persistence_path_category": self.persistence_path_category,
            "reuse_rejected_reason": self.reuse_rejected_reason,
            "family_counts": dict(self.family_counts),
            "promotion": dict(self.promotion),
        }


# ---------------------------------------------------------------------------
# Per-family payload persistence (manifest + digests + document snapshot)
# ---------------------------------------------------------------------------

def _family_payload_path(cache_dir: pathlib.Path, family: str) -> pathlib.Path:
    return cache_dir / f"family_{family}.json"


async def _read_family_payload(
    cache_dir: pathlib.Path, family: str
) -> tuple[FamilyManifest, dict[str, str], list[dict[str, Any]]] | None:
    """Returns (manifest, {id: content_hash}, documents) or None if absent/corrupt."""
    path = _family_payload_path(cache_dir, family)
    if not path.exists():
        return None
    try:
        raw = await read_text_async(path)
        parsed = json.loads(raw)
        manifest = FamilyManifest.from_dict(dict(parsed["manifest"]))
        digests = {str(k): str(v) for k, v in dict(parsed.get("digests") or {}).items()}
        documents = list(parsed.get("documents") or [])
        return manifest, digests, documents
    except Exception as exc:  # noqa: BLE001 — any corruption here just triggers a fresh stage
        logger.warning("init_cache: family payload %s unreadable, ignoring: %s", path, exc)
        return None


async def _write_family_payload(
    cache_dir: pathlib.Path,
    family: str,
    manifest: FamilyManifest,
    digests: dict[str, str],
    documents: list[dict[str, Any]],
) -> None:
    await write_json_atomic(
        _family_payload_path(cache_dir, family),
        {"family": family, "manifest": manifest.to_dict(), "digests": digests, "documents": documents},
    )


def _family_predicate(family: str) -> "Callable[[dict[str, Any]], bool]":
    """Return a predicate matching lexical-index documents tagged with *family*."""
    def _match(meta: dict[str, Any]) -> bool:
        return meta.get("source_family") == family
    return _match


def _persistence_configured(apex_config: "ApexConfig") -> bool:
    return bool(getattr(apex_config, "knowledge_cache_enabled", True)) and bool(
        getattr(apex_config, "knowledge_cache_path", None)
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def initialize_compiled_knowledge(
    api: "MemoryAPI",
    lexical: "BM25LexicalIndex",
    apex_config: "ApexConfig",
    memfabric_config: "Config",
) -> tuple[dict[str, int], KnowledgeInitReport]:
    """Stage/promote (or reuse) all four compiled-knowledge families.

    Returns ``(family_counts, report)`` — ``family_counts`` has the SAME
    shape as ``seed_compiled_knowledge_full``'s own return value (backward
    compatible with existing ``RunReport.seeding_counts`` consumers);
    ``report`` is the new, richer ``KnowledgeInitReport``.
    """
    t0 = time.monotonic()
    family_paths = resolve_family_paths(apex_config)
    configured_families = [f for f, p in family_paths.items() if p is not None]

    if not _persistence_configured(apex_config):
        logger.warning(
            "knowledge init cache: no durable knowledge_cache_path configured — "
            "persistence is DISABLED for this run. Every startup will re-stage "
            "compiled knowledge from scratch (the promotion loop itself is fast, "
            "but the cross-run 'skip unchanged families entirely' behavior is not "
            "active). Set --knowledge-cache-path (or APEX_KNOWLEDGE_CACHE_PATH) "
            "to a durable, container-surviving path to enable it."
        )
        return await _cold_no_persistence(api, apex_config, memfabric_config, family_paths, t0)

    cache_dir = pathlib.Path(str(apex_config.knowledge_cache_path))
    lock_timeout = float(getattr(apex_config, "knowledge_cache_lock_timeout_seconds", 30.0))
    stale_after = float(getattr(apex_config, "knowledge_cache_stale_lock_seconds", 300.0))

    async with cache_directory_lock(
        cache_dir, timeout_seconds=lock_timeout, stale_after_seconds=stale_after
    ) as lock:
        if not lock.acquired:
            logger.warning(
                "knowledge init cache: could not acquire cache lock (%s) — "
                "proceeding with an UNCACHED cold initialization for this run only",
                lock.reason,
            )
            counts, report = await _cold_no_persistence(
                api, apex_config, memfabric_config, family_paths, t0
            )
            report.persistence_enabled = True
            report.persistence_path_category = "configured"
            report.reuse_rejected_reason = lock.reason
            return counts, report

        return await _initialize_with_lock_held(
            api, lexical, apex_config, memfabric_config, family_paths,
            configured_families, cache_dir, t0,
        )


async def _cold_no_persistence(
    api: "MemoryAPI",
    apex_config: "ApexConfig",
    memfabric_config: "Config",
    family_paths: dict[str, pathlib.Path | None],
    t0: float,
) -> tuple[dict[str, int], KnowledgeInitReport]:
    """Bounded fallback: full stage + (fast) promote, no cross-run persistence."""
    counts: dict[str, int] = {}
    records_examined = 0
    for family, compiled_dir in family_paths.items():
        if compiled_dir is None or not compiled_dir.is_dir():
            counts[family] = 0
            continue
        n = await load_compiled_family(compiled_dir, family, api)
        counts[family] = n
        records_examined += n

    summary: PromotionSummary | None = None
    if records_examined > 0:
        worker = ReflectorWorker(api, memfabric_config)
        summary = await promote_staged_knowledge_until_stable(
            api, worker,
            mode=apex_config.knowledge_promotion_mode,
            max_passes=apex_config.knowledge_promotion_max_passes,
            max_records=apex_config.knowledge_promotion_max_records,
            timeout_seconds=apex_config.knowledge_promotion_timeout_seconds,
        )

    report = KnowledgeInitReport(
        initialization_mode="cold",
        families_changed=[f for f, c in counts.items() if c > 0],
        records_examined=records_examined,
        records_staged=records_examined,
        records_promoted=summary.records_promoted if summary else 0,
        records_blocked=summary.records_remaining if summary else 0,
        blocked_reason_counts=dict(summary.blocked_reason_counts) if summary else {},
        elapsed_seconds=time.monotonic() - t0,
        persistence_enabled=False,
        persistence_path_category="not_configured",
        reuse_rejected_reason="no durable knowledge_cache_path configured",
        family_counts=counts,
        promotion=summary.to_dict() if summary else {},
    )
    return counts, report


async def _initialize_with_lock_held(
    api: "MemoryAPI",
    lexical: "BM25LexicalIndex",
    apex_config: "ApexConfig",
    memfabric_config: "Config",
    family_paths: dict[str, pathlib.Path | None],
    configured_families: list[str],
    cache_dir: pathlib.Path,
    t0: float,
) -> tuple[dict[str, int], KnowledgeInitReport]:
    state_result = await read_init_state(cache_dir)
    state = state_result.state
    reuse_rejected_reason = "" if state_result.status == "ok" else state_result.reason

    families_reused: list[str] = []
    families_changed: list[str] = []
    manifest_identities: dict[str, str] = {}
    counts: dict[str, int] = {}
    records_examined = 0
    records_staged = 0
    records_skipped_existing = 0
    any_resumed = False
    any_incremental = False
    # Populated for every CHANGED family during the classification loop below,
    # so the persistence loop after promotion never needs to re-read/re-hash
    # the compiled files a second time.
    changed_family_data: dict[str, tuple[FamilyRecordSet, list[str]]] = {}

    for family in _KNOWN_FAMILIES:
        compiled_dir = family_paths.get(family)
        if compiled_dir is None or not compiled_dir.is_dir():
            counts[family] = 0
            continue

        record_set = await compute_family_record_set(compiled_dir, family)
        if record_set is None:
            counts[family] = 0
            continue

        current_manifest = record_set.manifest
        manifest_identities[family] = current_manifest.dataset_id
        records_examined += current_manifest.record_count

        prior = state.families.get(family)
        if prior is not None and prior.status == "in_progress":
            any_resumed = True

        if (
            prior is not None
            and prior.status == "complete"
            and prior.manifest.identity_matches(current_manifest)
        ):
            # --- REUSE: identical dataset already staged + promoted before ---
            payload = await _read_family_payload(cache_dir, family)
            if payload is None:
                # State said complete but the payload file is gone/corrupt —
                # cannot actually reuse; fall through to full processing.
                logger.warning(
                    "knowledge init cache: %s marked complete but payload snapshot "
                    "missing/corrupt — treating as changed", family,
                )
            else:
                _, _, documents = payload
                imported = await lexical.import_documents(documents)
                families_reused.append(family)
                records_skipped_existing += current_manifest.record_count
                counts[family] = current_manifest.record_count
                logger.info(
                    "knowledge init cache: %s reused (%d records imported from cache, "
                    "0 staged, 0 promoted)", family, imported,
                )
                continue

        # --- PROCESS: new family, changed family, or interrupted prior run ---
        families_changed.append(family)
        prior_payload = await _read_family_payload(cache_dir, family)
        only_ids: set[str] | None = None
        removed_ids: list[str] = []
        deprecated_ids: list[str] = list(prior.deprecated_ids) if prior else []

        if prior_payload is not None:
            # A prior payload existing (even if init_state.json disagreed or
            # was corrupt) means this family had SOME earlier cached state —
            # this run does a genuine partial/incremental update relative to
            # it, not a from-scratch first stage.
            any_incremental = True
            _prior_manifest, prior_digests, prior_documents = prior_payload
            current_digests = {rid: d.content_hash for rid, d in record_set.digests.items()}
            added_or_changed = {
                rid for rid, h in current_digests.items() if prior_digests.get(rid) != h
            }
            removed_ids = [rid for rid in prior_digests if rid not in current_digests]
            only_ids = added_or_changed
            # Re-import the prior snapshot's own documents first (restores
            # every unchanged record instantly); added/changed ones are then
            # staged+promoted fresh below and correctly overwrite by id.
            await lexical.import_documents(prior_documents)
            # "Skipped existing" = prior ids that are neither removed nor
            # changed/re-added this run. `added_or_changed` may contain ids
            # that are brand NEW (not present in prior_digests at all), so
            # intersecting with prior_digests' own keys before subtracting
            # is required — otherwise a purely-additive update would
            # under-count how many prior records were genuinely reused.
            changed_from_prior = added_or_changed & prior_digests.keys()
            records_skipped_existing += len(prior_digests) - len(changed_from_prior) - len(removed_ids)

        # Removed-record policy (item 8): never delete — accumulate into the
        # persisted deprecated-id list, bounded set of ids only.
        deprecated_ids = sorted(set(deprecated_ids) | set(removed_ids))

        n = await load_compiled_family(compiled_dir, family, api, only_ids=only_ids)
        counts[family] = current_manifest.record_count
        records_staged += n
        changed_family_data[family] = (record_set, deprecated_ids)

    # One shared promotion pass covers every family that staged anything —
    # the Reflector remains the sole promotion path.
    summary: PromotionSummary | None = None
    if records_staged > 0:
        worker = ReflectorWorker(api, memfabric_config)
        summary = await promote_staged_knowledge_until_stable(
            api, worker,
            mode=apex_config.knowledge_promotion_mode,
            max_passes=apex_config.knowledge_promotion_max_passes,
            max_records=apex_config.knowledge_promotion_max_records,
            timeout_seconds=apex_config.knowledge_promotion_timeout_seconds,
        )

    is_terminal = summary is None or summary.stop_reason in _TERMINAL_STOP_REASONS

    # Persist a fresh payload + state record for every CHANGED family.
    #
    # Interrupted-run correctness (item 6 of this feature's acceptance
    # criteria — "interrupted initialization does not mark the cache
    # complete"): the payload file is ONLY (re-)written when this run's
    # promotion pass reached a terminal state (is_terminal). If it did not
    # (budget-interrupted — stop_reason in {"max_passes","timeout",
    # "max_records"}), the family's digests reflect every VALID source
    # record regardless of whether it was actually promoted, so writing a
    # payload here would make a future run's incremental diff wrongly
    # treat "staged but never promoted" records as "already handled" (their
    # content did not change, only their promotion status did) — they
    # would then be silently skipped forever. Leaving the PRIOR payload (or
    # no payload, on a first-ever interrupted run) untouched means the next
    # run either diffs against still-accurate prior state, or — if there
    # was no prior state — performs a full, safe re-stage (a resumed run's
    # promotion pass is what needs to make progress, not staging; staging
    # is cheap and idempotent by id).
    updated_records: dict[str, FamilyInitRecord] = {}
    for family, (record_set, deprecated_ids) in changed_family_data.items():
        if is_terminal:
            documents = await lexical.export_documents(_family_predicate(family))
            digests = {rid: d.content_hash for rid, d in record_set.digests.items()}
            await _write_family_payload(cache_dir, family, record_set.manifest, digests, documents)

        updated_records[family] = FamilyInitRecord(
            manifest=record_set.manifest,
            status="complete" if is_terminal else "in_progress",
            records_staged=counts.get(family, 0),
            records_promoted=(summary.records_promoted if summary else 0),
            records_blocked=(summary.records_remaining if summary else 0),
            updated_at=now(),
            deprecated_ids=deprecated_ids,
        )

    if updated_records:
        for family, rec in updated_records.items():
            state.families[family] = rec
        await write_init_state(cache_dir, state)

    # Determine initialization_mode.
    #
    # Precedence: rebuild (state corruption detected) > resumed (a prior
    # run left a family interrupted) > incremental (at least one family did
    # a genuine partial add/change update against its own prior cached
    # payload — this is the record-level "only new/changed records staged"
    # case, independent of how many OTHER families were fully reused or
    # fully cold) > reused (every configured family matched, nothing
    # processed) > cold (first run, or every processed family had no prior
    # cached data at all to diff against).
    if state_result.status in ("corrupt", "incompatible_schema"):
        mode = "rebuild"
    elif any_resumed:
        mode = "resumed"
    elif any_incremental:
        mode = "incremental"
    elif state_result.status == "missing":
        mode = "cold"
    elif families_reused and not families_changed:
        mode = "reused"
    else:
        mode = "cold"

    report = KnowledgeInitReport(
        initialization_mode=mode,
        families_reused=families_reused,
        families_changed=families_changed,
        records_examined=records_examined,
        records_staged=records_staged,
        records_promoted=summary.records_promoted if summary else 0,
        records_skipped_existing=records_skipped_existing,
        records_blocked=summary.records_remaining if summary else 0,
        blocked_reason_counts=dict(summary.blocked_reason_counts) if summary else {},
        manifest_identities=manifest_identities,
        elapsed_seconds=time.monotonic() - t0,
        persistence_enabled=True,
        persistence_path_category="configured",
        reuse_rejected_reason=reuse_rejected_reason,
        family_counts=counts,
        promotion=summary.to_dict() if summary else {},
    )
    return counts, report


# ---------------------------------------------------------------------------
# Reset / rebuild
# ---------------------------------------------------------------------------

async def reset_knowledge_cache(cache_dir: str | pathlib.Path, family: str | None = None) -> int:
    """Delete persisted cache files so the next startup performs a full rebuild.

    ``family=None`` (default) resets every known family plus the shared
    ``init_state.json``. ``family="intel_db"`` (etc.) resets only that
    family's payload and its entry inside ``init_state.json`` (other
    families' cached state is untouched). Returns the number of files
    removed. Safe to call when nothing is cached yet (returns 0).
    """
    cache_path = pathlib.Path(cache_dir)
    removed = 0

    if family is None:
        for fam in _KNOWN_FAMILIES:
            p = _family_payload_path(cache_path, fam)
            if p.exists():
                p.unlink()
                removed += 1
        state_file = cache_path / "init_state.json"
        if state_file.exists():
            state_file.unlink()
            removed += 1
        return removed

    p = _family_payload_path(cache_path, family)
    if p.exists():
        p.unlink()
        removed += 1
    state_result = await read_init_state(cache_path)
    if state_result.status == "ok" and family in state_result.state.families:
        del state_result.state.families[family]
        await write_init_state(cache_path, state_result.state)
        removed += 1
    return removed
