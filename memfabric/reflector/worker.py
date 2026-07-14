# worker.py
# Async Reflector worker that reads new episodes, generalises success chains into staged skills, and applies promotion, decay, and quarantine gates — the only component allowed to promote proposals.
"""Async Reflector worker — driven off the episodic stream (Section 7).

The worker:
1. Reads new episodes since the last cursor.
2. Groups them into sub-chains (by chain_id or by consecutive success runs).
3. For completed success chains of length >= min_chain_len → generalise → propose.
4. For fundamental failures → propose a negative skill.
5. Applies promotion, decay, and quarantine through the MemoryAPI.

This runs asynchronously and NEVER blocks the orchestrator loop.
The worker is the ONLY component allowed to promote a proposal.

F21 fix (Phase 3): all Skill object mutations go through MemoryAPI methods
(merge_skill_candidate, decay_skill, quarantine_skill).  The worker never
mutates Skill objects returned by get_staged_skills() directly.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from memfabric.reflector.consolidate import generalize
from memfabric.reflector.gates import (
    decayed_confidence,
    should_decay,
    should_promote_knowledge,
    should_promote_skill,
    should_quarantine,
)
from memfabric.types import Episode, Outcome, Skill

if TYPE_CHECKING:
    from memfabric.api import MemoryAPI
    from memfabric.config import Config

logger = logging.getLogger(__name__)


class ReflectorWorker:
    """Async worker that reads the episodic stream and updates knowledge/skills.

    Parameters
    ----------
    api:    MemoryAPI (the only way to touch state)
    config: Config dataclass
    """

    def __init__(self, api: MemoryAPI, config: Config) -> None:
        self._api = api
        self._config = config
        self._cursor: str = ""   # episode id of the last-processed episode
        self._run_count: int = 0

    async def run_once(self) -> None:
        """Process all new episodes since the last cursor, then apply gates.

        ``advance_run_number()`` is called first so that all lifecycle events
        within this pass share the same global run number.  ``_run_count`` is
        updated to reflect the global counter (replacing the previous local
        ``+= 1`` increment).
        """
        self._run_count = await self._api.advance_run_number()

        # 1. Fetch new episodes
        new_episodes = await self._api._episodic.since(self._cursor)
        if new_episodes:
            self._cursor = new_episodes[-1].id
            await self._process_episodes(new_episodes)

        # 2. Apply promotion gate to staged entries
        await self._apply_promotion_gate()

        # 3. Apply decay and quarantine to all skills
        await self._apply_decay_and_quarantine()

        logger.debug("reflector run=%d cursor=%s", self._run_count, self._cursor[:8] if self._cursor else "start")

    async def run_loop(self, interval_seconds: float = 5.0) -> None:
        """Run forever, processing episodes on a schedule.

        Call ``stop()`` to request a graceful shutdown.
        """
        self._running = True
        while self._running:
            await self.run_once()
            await asyncio.sleep(interval_seconds)

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Episode processing
    # ------------------------------------------------------------------

    async def _process_episodes(self, episodes: list[Episode]) -> None:
        # Group by chain_id; episodes without a chain_id each form a singleton chain
        chains: dict[str, list[Episode]] = defaultdict(list)
        unchained: list[Episode] = []

        for ep in episodes:
            if ep.chain_id:
                chains[ep.chain_id].append(ep)
            else:
                unchained.append(ep)

        # Process named chains
        for chain_id, chain_eps in chains.items():
            # Check that the chain ended with a terminal episode
            final = chain_eps[-1]
            if final.outcome == Outcome.success and len(chain_eps) >= self._config.min_chain_len:
                await self._generalise_and_propose(chain_eps)
            elif final.outcome == Outcome.fundamental:
                await self._propose_negative_skill(chain_eps)

        # Process unchained episodes (treat each as a singleton or small run)
        for ep in unchained:
            if ep.outcome == Outcome.fundamental:
                await self._propose_negative_skill([ep])

    async def _generalise_and_propose(self, chain: list[Episode]) -> None:
        # get_staged_skills() returns deep copies — safe to compare, never mutate.
        staged = await self._api.get_staged_skills()
        candidate = generalize(
            chain,
            confidence=self._config.skill_prior,
            slot_patterns=self._config.slot_patterns,
        )

        best_match: Skill | None = None
        best_sim = 0.0
        for existing in staged:
            sim = _name_similarity(candidate.name, existing.name)
            if sim > best_sim:
                best_sim = sim
                best_match = existing

        if best_match and best_sim >= self._config.skill_merge_theta:
            # F21 fix: route through MemoryAPI instead of direct object mutation.
            merged = await self._api.merge_skill_candidate(
                best_match.id, run_number=self._run_count
            )
            if merged:
                logger.info(
                    "reflector merged into skill id=%s name=%s",
                    best_match.id, best_match.name,
                )
            else:
                # Skill disappeared (quarantined between lookup and merge);
                # propose a new one instead.
                await self._api.propose_skill(candidate)
                logger.info(
                    "reflector proposed new skill name=%s (merge target gone)",
                    candidate.name,
                )
        else:
            await self._api.propose_skill(candidate)
            logger.info(
                "reflector proposed new skill name=%s", candidate.name
            )

    async def _propose_negative_skill(self, chain: list[Episode]) -> None:
        if not chain:
            return
        candidate = generalize(
            chain,
            confidence=self._config.skill_prior * 0.5,
            slot_patterns=self._config.slot_patterns,
        )
        candidate.name = "NEGATIVE_" + candidate.name
        candidate.description = "[negative] " + candidate.description
        # candidate is a newly-created Skill not yet in the staging dict;
        # setting losses on it before proposal is intentional (initial state).
        candidate.losses += 1
        await self._api.propose_skill(candidate)
        logger.info("reflector proposed negative skill name=%s", candidate.name)

    # ------------------------------------------------------------------
    # Promotion gate
    # ------------------------------------------------------------------

    async def _apply_promotion_gate(self) -> None:
        """Promote staged knowledge and skills that clear the quality gate.

        Bounded at ``config.reflector_max_promotions_per_run`` combined
        promotions per call so that large batch seeds do not flood the log.
        Unpromoted entries remain staged and are picked up on the next
        ``run_once()`` call.

        Logging contract:
        - Individual promotions → DEBUG only.
        - End-of-pass summary (promoted=N skipped=M remaining=K) → INFO.
        """
        cap = self._config.reflector_max_promotions_per_run
        log_every = self._config.reflector_log_every_n
        promoted = 0
        skipped = 0

        knowledge_entries = await self._api.get_staged_knowledge()
        for entry in knowledge_entries:
            if promoted >= cap:
                break
            if should_promote_knowledge(
                entry,
                min_confidence=self._config.min_confidence,
            ):
                await self._api.promote_knowledge(entry.id)
                promoted += 1
                if promoted % log_every == 0:
                    logger.debug(
                        "reflector promoted knowledge id=%s (%d so far)",
                        entry.id, promoted,
                    )
            else:
                skipped += 1

        skill_entries = await self._api.get_staged_skills()
        for skill in skill_entries:
            if promoted >= cap:
                break
            if should_promote_skill(
                skill,
                min_evidence_count=self._config.min_evidence_count,
                min_confidence=self._config.min_confidence,
            ):
                await self._api.promote_skill(skill.id)
                promoted += 1
                if promoted % log_every == 0:
                    logger.debug(
                        "reflector promoted skill id=%s name=%s (%d so far)",
                        skill.id, skill.name, promoted,
                    )
            else:
                skipped += 1

        total = len(knowledge_entries) + len(skill_entries)
        remaining = max(0, total - promoted - skipped)
        logger.debug(
            "reflector promotion pass: promoted=%d skipped=%d remaining=%d",
            promoted, skipped, remaining,
        )

    # ------------------------------------------------------------------
    # Decay and quarantine
    # ------------------------------------------------------------------

    async def _apply_decay_and_quarantine(self) -> None:
        """Apply quarantine and confidence decay to all non-quarantined skills.

        Uses the global run number (``self._run_count``) — set by
        ``advance_run_number()`` at the start of ``run_once()`` — so that
        ``decay_skill()``'s idempotence guard works correctly and all lifecycle
        events in the same pass share the same ordering key.

        Passes ``config.skill_grace_runs`` and ``config.skill_confidence_floor``
        so the decay policy respects both the grace period and the floor.
        """
        for skill in await self._api.get_staged_skills():
            if skill.quarantined:
                continue

            if should_quarantine(
                skill,
                winrate_floor=self._config.winrate_floor,
                min_evidence_count=self._config.min_evidence_count,
            ):
                await self._api.quarantine_skill(
                    skill.id,
                    reason="winrate_below_floor",
                    current_run_number=self._run_count,
                )
                logger.info("reflector quarantined skill id=%s name=%s", skill.id, skill.name)
                continue

            if should_decay(
                skill,
                current_run=self._run_count,
                decay_unused_runs=self._config.decay_unused_runs,
                grace_runs=self._config.skill_grace_runs,
            ):
                new_conf = decayed_confidence(skill, decay_factor=self._config.decay_factor)
                await self._api.decay_skill(
                    skill.id,
                    self._config.decay_factor,
                    current_run_number=self._run_count,
                    confidence_floor=self._config.skill_confidence_floor,
                )
                logger.info(
                    "reflector decayed skill id=%s conf %.3f→%.3f",
                    skill.id, skill.confidence, new_conf,
                )


def _name_similarity(a: str, b: str) -> float:
    """Simple Jaccard similarity on token sets (proxy for skill merge theta)."""
    ta = set(a.lower().split("_"))
    tb = set(b.lower().split("_"))
    if not ta and not tb:
        return 1.0
    intersection = ta & tb
    union = ta | tb
    return len(intersection) / len(union)
