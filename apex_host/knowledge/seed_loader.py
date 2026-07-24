# seed_loader.py
# Bootstrap helpers that load knowledge into staged entries and run Reflector promotion passes before engagement starts.
"""Bootstrap helpers: load knowledge into staged entries, then promote through the Reflector.

Three public surfaces are provided:

``seed_payload_repo(path, api, config)``
    Original seeder — reads raw payload-repo files from an external directory
    and stages them.  Kept for backward compatibility.

``seed_compiled_knowledge(api, apex_config, memfabric_config)``
    Reads compiled JSONL files from the knowledge/ directory structure.
    Returns ``dict[str, int]`` of records staged per family (unchanged type).
    Internally uses ``promote_staged_knowledge_until_stable`` to clear the
    staging gate in multi-pass mode when the corpus is large.

``promote_staged_knowledge_until_stable(api, worker, *, mode, max_passes, ...)``
    Safe bounded promotion loop: calls ``ReflectorWorker.run_once()`` repeatedly
    until no staged records remain, no progress is made, or a safety limit is
    reached.  Returns a ``PromotionSummary`` with audit data for the run report.

All helpers follow memfabric Invariants 1 and 4: all writes go through
``MemoryAPI``; ``ReflectorWorker`` is the sole component that promotes staged
entries.
"""
from __future__ import annotations

import logging
import pathlib
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from apex_host.knowledge.payload_repo_loader import PayloadRepoLoader
from memfabric.reflector.gates import classify_unpromoted_knowledge, classify_unpromoted_skill
from memfabric.reflector.worker import ReflectorWorker

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI
    from memfabric.config import Config
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Promotion summary
# ---------------------------------------------------------------------------

@dataclass
class PromotionSummary:
    """Structured result of a startup promotion loop.

    Fields
    ------
    records_staged_initial:
        Total staged records found at the start of the loop.
    records_promoted:
        Records promoted across all passes.
    records_remaining:
        Staged records still present when the loop ended.
    passes_run:
        Number of ``run_once()`` calls made.
    stop_reason:
        Why the loop terminated:
        - ``"exhausted"`` — all staged records promoted.
        - ``"no_progress"`` — a pass promoted zero records (gate threshold
          blocks all remaining; they stay staged).
        - ``"max_passes"`` — ``max_passes`` reached.
        - ``"max_records"`` — ``max_records`` cap reached.
        - ``"timeout"`` — ``timeout_seconds`` elapsed.
        - ``"single_pass"`` — mode was ``"single_pass"``; only one pass ran.
        - ``"disabled"`` — mode was ``"disabled"``; no pass ran.
    elapsed_seconds:
        Wall-clock time from loop start to end.
    """
    records_staged_initial: int
    records_promoted: int
    records_remaining: int
    passes_run: int
    stop_reason: str
    elapsed_seconds: float
    blocked_reason_counts: dict[str, int] = None  # type: ignore[assignment]
    """Bounded summary of *records_remaining*, grouped by why each one did
    not promote (Phase 4). Never a per-record ID list — see
    ``_classify_remaining_staged`` for the classification rules and
    ``docs/knowledge-initialization.md`` "Promotion-loop diagnostics" for
    the full rationale. ``None`` only for callers that construct this
    dataclass directly without the classification step (defaults to ``{}``
    in ``__post_init__``)."""

    def __post_init__(self) -> None:
        if self.blocked_reason_counts is None:
            self.blocked_reason_counts = {}

    def to_dict(self) -> dict[str, object]:
        return {
            "records_staged_initial": self.records_staged_initial,
            "records_promoted": self.records_promoted,
            "records_remaining": self.records_remaining,
            "passes_run": self.passes_run,
            "stop_reason": self.stop_reason,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "blocked_reason_counts": dict(self.blocked_reason_counts),
        }


# ---------------------------------------------------------------------------
# Core promotion loop
# ---------------------------------------------------------------------------

_PROMOTION_LOG_INTERVAL = 50
"""Log a progress summary at INFO every this many Reflector passes.

With 100 records/pass and 638 passes for a 63 k corpus, an interval of 50
produces ~13 progress lines instead of 638 — visible and not noisy.
"""


async def promote_staged_knowledge_until_stable(
    api: "MemoryAPI",
    worker: ReflectorWorker,
    *,
    mode: str = "until_stable",
    max_passes: int = 1000,
    max_records: int | None = None,
    timeout_seconds: float | None = None,
) -> PromotionSummary:
    """Loop ReflectorWorker.run_once() until stable or a safety limit is reached.

    This is the only promotion path that handles corpora larger than
    ``reflector_max_promotions_per_run`` (default 100).  It preserves all
    memfabric invariants: no direct store writes, no gate bypass.

    Parameters
    ----------
    api:             MemoryAPI used to count staged records.
    worker:          Configured ReflectorWorker (shared cursor across passes).
    mode:            ``"until_stable"`` | ``"single_pass"`` | ``"disabled"``.
    max_passes:      Hard cap on loop iterations (prevents infinite loops).
    max_records:     Optional cap on total promoted records.
    timeout_seconds: Optional wall-clock timeout.

    Returns
    -------
    PromotionSummary with full audit data.
    """
    t0 = time.monotonic()

    # Count only un-promoted entries: promoted ones stay in the staging dict
    # (for auditability) but are already indexed and need no further action.
    #
    # Phase 4 knowledge-initialization performance fix: uses the cheap
    # count_staged_*() accessors (attribute scan only, no per-entry
    # copy.deepcopy) instead of deep-copying every staged entry just to
    # count a subset — see memfabric.api.MemoryAPI.count_staged_knowledge's
    # docstring. This is the dominant fix for the "1757 seconds spent
    # promoting" live-test finding: the OLD code deep-copied the ENTIRE
    # staging dict (promoted + unpromoted) on every one of ~1,300 calls
    # across a ~638-pass loop — roughly 40 million dataclass deep-copies for
    # a 63,783-record corpus. The new code below is O(remaining) per call,
    # so the SUM across the whole loop is O(total staged) once, not
    # O(total staged × passes).
    initial_staged = await api.count_staged_knowledge(promoted=False)
    initial_skills = await api.count_staged_skills(promoted=False, quarantined=False)
    total_initial = initial_staged + initial_skills

    if mode == "disabled":
        return PromotionSummary(
            records_staged_initial=total_initial,
            records_promoted=0,
            records_remaining=total_initial,
            passes_run=0,
            stop_reason="disabled",
            elapsed_seconds=time.monotonic() - t0,
        )

    total_promoted = 0
    passes_run = 0

    while True:
        # Safety limits checked before each pass.
        if passes_run >= max_passes:
            stop_reason = "max_passes"
            break
        if timeout_seconds is not None and (time.monotonic() - t0) >= timeout_seconds:
            stop_reason = "timeout"
            break
        if max_records is not None and total_promoted >= max_records:
            stop_reason = "max_records"
            break

        staged_before = (
            await api.count_staged_knowledge(promoted=False)
            + await api.count_staged_skills(promoted=False, quarantined=False)
        )
        if staged_before == 0:
            stop_reason = "exhausted"
            break

        await worker.run_once()
        passes_run += 1

        staged_after = (
            await api.count_staged_knowledge(promoted=False)
            + await api.count_staged_skills(promoted=False, quarantined=False)
        )
        promoted_this_pass = staged_before - staged_after
        total_promoted += promoted_this_pass

        if promoted_this_pass == 0:
            # Quality gate is blocking all remaining entries — no point
            # looping further; classify_remaining below determines exactly
            # why (below_min_confidence / below_min_evidence / etc.).
            logger.warning(
                "promote_staged_knowledge_until_stable: no progress after pass %d "
                "(%d records remain staged); stopping — see blocked_reason_counts "
                "for why each one is blocked",
                passes_run, staged_after,
            )
            stop_reason = "no_progress"
            break

        # Emit a compact progress summary every _PROMOTION_LOG_INTERVAL passes
        # so operators see activity without flooding the terminal.
        if passes_run % _PROMOTION_LOG_INTERVAL == 0:
            pct = (total_promoted / total_initial * 100.0) if total_initial else 0.0
            logger.info(
                "Reflector seeding: pass %d — promoted %d/%d (%.0f%%) remaining %d",
                passes_run, total_promoted, total_initial, pct, staged_after,
            )

        if mode == "single_pass":
            stop_reason = "single_pass"
            break

    remaining = (
        await api.count_staged_knowledge(promoted=False)
        + await api.count_staged_skills(promoted=False, quarantined=False)
    )
    elapsed = time.monotonic() - t0

    # One bounded classification pass over ONLY the remaining unpromoted
    # entries (never the whole corpus) — grouped-by-reason, never a
    # per-record ID list (CLAUDE.md-style "do not serialize tens of
    # thousands of record IDs into the ordinary report" constraint from
    # this phase's own task). Skipped entirely when nothing remains.
    blocked_reason_counts: dict[str, int] = {}
    if remaining > 0:
        blocked_reason_counts = await classify_remaining_staged(api, config=worker.config)

    summary = PromotionSummary(
        records_staged_initial=total_initial,
        records_promoted=total_promoted,
        records_remaining=remaining,
        passes_run=passes_run,
        stop_reason=stop_reason,
        elapsed_seconds=elapsed,
        blocked_reason_counts=blocked_reason_counts,
    )
    logger.info(
        "Reflector bootstrap: passes=%d promoted=%d remaining=%d "
        "stop_reason=%s elapsed=%.1fs blocked_reasons=%s",
        summary.passes_run, summary.records_promoted, summary.records_remaining,
        summary.stop_reason, summary.elapsed_seconds, summary.blocked_reason_counts,
    )
    return summary


async def classify_remaining_staged(api: "MemoryAPI", *, config: "Config") -> dict[str, int]:
    """Return a bounded ``{reason: count}`` summary of un-promoted staged entries.

    Called once, after a promotion loop stops, over ONLY the un-promoted
    subset (cheap — see ``get_staged_knowledge(promoted=False)``'s
    docstring). Never returns per-record identifiers, only aggregate counts,
    so this is safe to embed in an ordinary run report even for a
    corpus-sized remainder.

    Reason categories are produced by ``memfabric.reflector.gates
    .classify_unpromoted_knowledge`` / ``classify_unpromoted_skill`` — see
    those functions' docstrings for the full category list and which ones
    are permanent (will never resolve without new evidence or a config
    change) versus transient (may resolve on a future pass given more
    budget). ``docs/knowledge-initialization.md`` "Blocked-record
    diagnostics" documents the operator-facing meaning of each category.
    """
    counts: dict[str, int] = {}
    for entry in await api.get_staged_knowledge(promoted=False):
        reason = classify_unpromoted_knowledge(entry, min_confidence=config.min_confidence)
        counts[reason] = counts.get(reason, 0) + 1
    for skill in await api.get_staged_skills(promoted=False, quarantined=False):
        reason = classify_unpromoted_skill(
            skill,
            min_evidence_count=config.min_evidence_count,
            min_confidence=config.min_confidence,
        )
        counts[reason] = counts.get(reason, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Payload-repo seeder (backward compat — unchanged public API)
# ---------------------------------------------------------------------------

async def seed_payload_repo(
    payload_repo_path: str, api: "MemoryAPI", config: "Config"
) -> int:
    """Load *payload_repo_path* into staged knowledge and run one promotion pass.

    Returns the number of chunks proposed (promotion count may differ if some
    entries don't clear the gate).
    """
    loader = PayloadRepoLoader(payload_repo_path, api)
    count = await loader.load()
    if count:
        worker = ReflectorWorker(api, config)
        await worker.run_once()
    return count


# ---------------------------------------------------------------------------
# Compiled-knowledge seeder
# ---------------------------------------------------------------------------

async def seed_compiled_knowledge(
    api: "MemoryAPI",
    apex_config: "ApexConfig",
    memfabric_config: "Config",
) -> dict[str, int]:
    """Stage compiled JSONL records via MemoryAPI and promote through the Reflector.

    Backward-compatible wrapper — returns ``dict[str, int]`` (family → records
    staged).  For a richer return that includes the ``PromotionSummary``, call
    ``seed_compiled_knowledge_full()`` directly.
    """
    counts, _ = await seed_compiled_knowledge_full(api, apex_config, memfabric_config)
    return counts


async def seed_compiled_knowledge_full(
    api: "MemoryAPI",
    apex_config: "ApexConfig",
    memfabric_config: "Config",
) -> tuple[dict[str, int], PromotionSummary | None]:
    """Stage compiled JSONL records and return both per-family counts and a promotion summary.

    Reads only from ``<family>/compiled/`` directories.  Resolves family paths in
    priority order:
    1. Per-family override (``ApexConfig.policy_db_path``, etc.)
    2. ``ApexConfig.knowledge_root / <family_name> / compiled``

    Returns
    -------
    tuple[dict[str, int], PromotionSummary | None]
        - ``counts``: ``family_name → records_staged`` (0 for skipped families).
        - ``summary``: ``PromotionSummary`` if promotion ran; ``None`` if total
          staged was 0 (nothing to promote).

    The promotion loop is controlled by ``apex_config.knowledge_promotion_mode``:
    - ``"until_stable"`` (default): multiple passes until all records are promoted.
    - ``"single_pass"``: one Reflector pass (legacy behaviour).
    - ``"disabled"``: stages but does not promote.

    Logging emits a structured summary:

        Compiled knowledge staged:
          policy_db:      33
          methodology_db: 4
          intel_db:       53,505
          payload_db:     10,241
          total:          63,783

        Reflector bootstrap: passes=638 promoted=63,700 remaining=83
            stop_reason=exhausted elapsed=4.2s
    """
    from apex_host.knowledge.compiled_loader import load_compiled_family

    counts: dict[str, int] = {}

    family_paths = resolve_family_paths(apex_config)

    total = 0
    for family, compiled_dir in family_paths.items():
        if compiled_dir is None or not compiled_dir.is_dir():
            counts[family] = 0
            if compiled_dir is not None:
                logger.debug(
                    "seed_compiled_knowledge: %s compiled dir not found: %s",
                    family, compiled_dir,
                )
            continue
        n = await load_compiled_family(compiled_dir, family, api)
        counts[family] = n
        total += n

    # Emit structured staging summary.
    if total > 0:
        logger.info("Compiled knowledge staged:")
        for family, n in counts.items():
            logger.info("  %s: %s", family, f"{n:,}")
        logger.info("  total: %s", f"{total:,}")
    else:
        logger.info("seed_compiled_knowledge: no records staged (all families empty or absent)")
        return counts, None

    # Run the promotion loop.
    worker = ReflectorWorker(api, memfabric_config)
    summary = await promote_staged_knowledge_until_stable(
        api,
        worker,
        mode=apex_config.knowledge_promotion_mode,
        max_passes=apex_config.knowledge_promotion_max_passes,
        max_records=apex_config.knowledge_promotion_max_records,
        timeout_seconds=apex_config.knowledge_promotion_timeout_seconds,
    )

    return counts, summary


# ---------------------------------------------------------------------------
# Public path-resolution helper (shared with apex_host.knowledge.init_cache)
# ---------------------------------------------------------------------------

def resolve_family_paths(apex_config: "ApexConfig") -> dict[str, pathlib.Path | None]:
    """Resolve the four known families' compiled/ directories from *apex_config*.

    Single source of truth for family-path resolution — shared by
    ``seed_compiled_knowledge_full`` (above) and
    ``apex_host.knowledge.init_cache`` (Phase 4) so the two code paths can
    never disagree about where a family's compiled files live.
    """
    root = pathlib.Path(apex_config.knowledge_root) if apex_config.knowledge_root else None
    return {
        "policy_db": _resolve_compiled(apex_config.policy_db_path, root, "policy_db"),
        "methodology_db": _resolve_compiled(apex_config.methodology_db_path, root, "methodology_db"),
        "intel_db": _resolve_compiled(apex_config.intel_db_path, root, "intel_db"),
        "payload_db": _resolve_compiled(apex_config.payload_db_path, root, "payload_db"),
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _resolve_compiled(
    explicit: str | None,
    root: pathlib.Path | None,
    family_name: str,
) -> pathlib.Path | None:
    """Return the resolved compiled/ directory for a knowledge family.

    Priority: explicit per-family override > knowledge_root/<family>/compiled/.
    Returns None when neither is configured.
    """
    if explicit:
        return pathlib.Path(explicit) / "compiled"
    if root:
        return root / family_name / "compiled"
    return None
