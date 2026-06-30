"""Async Reflector worker — driven off the episodic stream (Section 7).

The worker:
1. Reads new episodes since the last cursor.
2. Groups them into sub-chains (by chain_id or by consecutive success runs).
3. For completed success chains of length >= min_chain_len → generalise → propose.
4. For fundamental failures → propose a negative skill.
5. Applies promotion, decay, and quarantine through the MemoryAPI.

This runs asynchronously and NEVER blocks the orchestrator loop.
The worker is the ONLY component allowed to promote a proposal.
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
        """Process all new episodes since the last cursor, then apply gates."""
        self._run_count += 1

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
        # Check for similar existing skill
        staged = await self._api.get_staged_skills()
        candidate = generalize(chain, confidence=self._config.skill_prior)

        best_match: Skill | None = None
        best_sim = 0.0
        for existing in staged:
            sim = _name_similarity(candidate.name, existing.name)
            if sim > best_sim:
                best_sim = sim
                best_match = existing

        if best_match and best_sim >= self._config.skill_merge_theta:
            # Merge into existing skill
            best_match.wins += 1
            best_match.evidence_count += 1
            best_match.confidence = min(
                1.0,
                best_match.confidence + 0.05 * (1.0 - best_match.confidence),
            )
            logger.info(
                "reflector merged into skill id=%s name=%s wins=%d",
                best_match.id, best_match.name, best_match.wins,
            )
        else:
            await self._api.propose_skill(candidate)
            logger.info(
                "reflector proposed new skill name=%s", candidate.name
            )

    async def _propose_negative_skill(self, chain: list[Episode]) -> None:
        if not chain:
            return
        candidate = generalize(chain, confidence=self._config.skill_prior * 0.5)
        candidate.name = "NEGATIVE_" + candidate.name
        candidate.description = "[negative] " + candidate.description
        candidate.losses += 1
        await self._api.propose_skill(candidate)
        logger.info("reflector proposed negative skill name=%s", candidate.name)

    # ------------------------------------------------------------------
    # Promotion gate
    # ------------------------------------------------------------------

    async def _apply_promotion_gate(self) -> None:
        for entry in await self._api.get_staged_knowledge():
            if should_promote_knowledge(
                entry,
                min_confidence=self._config.min_confidence,
            ):
                await self._api.promote_knowledge(entry.id)
                logger.info("reflector promoted knowledge id=%s", entry.id)

        for skill in await self._api.get_staged_skills():
            if should_promote_skill(
                skill,
                min_evidence_count=self._config.min_evidence_count,
                min_confidence=self._config.min_confidence,
            ):
                await self._api.promote_skill(skill.id)
                logger.info("reflector promoted skill id=%s name=%s", skill.id, skill.name)

    # ------------------------------------------------------------------
    # Decay and quarantine
    # ------------------------------------------------------------------

    async def _apply_decay_and_quarantine(self) -> None:
        for skill in await self._api.get_staged_skills():
            if skill.quarantined:
                continue

            if should_quarantine(skill, winrate_floor=self._config.winrate_floor):
                await self._api.quarantine_skill(skill.id)
                logger.info("reflector quarantined skill id=%s name=%s", skill.id, skill.name)
                continue

            if should_decay(
                skill,
                current_run=self._run_count,
                decay_unused_runs=self._config.decay_unused_runs,
            ):
                new_conf = decayed_confidence(skill, decay_factor=self._config.decay_factor)
                await self._api.decay_skill(skill.id, self._config.decay_factor)
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
