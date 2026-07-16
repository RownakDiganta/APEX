# runtime.py
# Wires MemoryAPI, reference stores, HybridRetriever, payload-repo seeding, and the APEX LangGraph into a single runnable ApexRuntime engagement object.
"""Wires MemoryAPI + reference stores + HybridRetriever + the payload-repo
seed loader + the APEX LangGraph into one runnable engagement.

This is the only place in apex_host that constructs memfabric store/retriever
instances — everything downstream (graph.py, agents/, planners/) only ever
touches state through MemoryAPI, consistent with memfabric Invariant 1.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex

from memfabric.reflector.worker import ReflectorWorker

from apex_host.config import ApexConfig
from apex_host.graph import build_apex_graph
from apex_host.llm.router import FakeModelRouter, ModelRouter, OpenAIModelRouter
from apex_host.graph_state import ApexGraphState
from apex_host.knowledge.cve_patterns import default_identifier_patterns
from apex_host.knowledge.seed_loader import (
    seed_compiled_knowledge_full,
    seed_payload_repo,
)
from apex_host.planning.budget import LLMBudgetTracker
from apex_host.tools.backend import select_runtime_backend
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ApexRuntime:
    """A fully-wired APEX engagement, ready to run via ``run()``."""

    api: MemoryAPI
    config: ApexConfig
    memfabric_config: Config
    registry: ToolRegistry
    # Populated by run() after the graph completes; None before the first run.
    last_budget: LLMBudgetTracker | None = None
    # Internal flag to track whether aclose() has already been called.
    _closed: bool = False

    async def aclose(self) -> None:
        """Gracefully shut down all resources held by this runtime.

        Idempotent: safe to call more than once.  Does not raise if called
        before ``run()`` has been invoked.

        Phase 7 (P7-I09): provides a clean shutdown path for callers that need
        to release resources (e.g. thread pools, open file handles) after the
        engagement completes or is cancelled.
        """
        if self._closed:
            return
        self._closed = True
        # Cancel any background tasks that were started but not awaited.
        # Currently ApexRuntime does not start background tasks directly; this
        # hook is provided for future use and ensures the pattern is in place.
        tasks = [
            t for t in asyncio.all_tasks()
            if t is not asyncio.current_task() and not t.done()
        ]
        if tasks:
            logger.debug("aclose: cancelling %d pending task(s)", len(tasks))
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        logger.debug("aclose: runtime closed")

    async def seed(self) -> int:
        """Load the payload repo into staged knowledge and promote it once.

        Kept for backward compatibility.  Use ``seed_all()`` to also load
        compiled knowledge families when ``knowledge_root`` is configured.
        """
        return await seed_payload_repo(self.config.payload_repo_path, self.api, self.memfabric_config)

    async def seed_all(self) -> dict[str, Any]:
        """Seed both the payload repo and compiled knowledge families.

        Returns a dict with:
        - ``"payload_repo"`` (int) → records staged from the raw payload repo
        - ``"policy_db"``, ``"intel_db"``, etc. (int) → records from compiled JSONL
        - ``"_promotion"`` (dict) → ``PromotionSummary.to_dict()`` when compiled
          families were staged (absent when no compiled families are configured
          or the total staged count is 0).

        When ``knowledge_root`` is None and no per-family paths are configured,
        the compiled-knowledge families are skipped gracefully (count 0).
        Backward-compatible: integer-keyed family counts are present as before;
        the ``"_promotion"`` key is additive.
        """
        results: dict[str, Any] = {}

        payload_count = await seed_payload_repo(
            self.config.payload_repo_path, self.api, self.memfabric_config
        )
        results["payload_repo"] = payload_count

        _has_knowledge = (
            self.config.knowledge_root is not None
            or self.config.policy_db_path is not None
            or self.config.methodology_db_path is not None
            or self.config.intel_db_path is not None
            or self.config.payload_db_path is not None
        )
        if _has_knowledge:
            compiled_counts, promo_summary = await seed_compiled_knowledge_full(
                self.api, self.config, self.memfabric_config
            )
            results.update(compiled_counts)
            if promo_summary is not None:
                results["_promotion"] = promo_summary.to_dict()
        else:
            logger.debug("seed_all: no knowledge_root configured; skipping compiled families")

        return results

    async def run(self) -> ApexGraphState:
        """Run the APEX engagement graph to completion and return final state.

        After the graph completes, one pass of the ``ReflectorWorker`` is
        triggered so that successful episode chains are generalised into
        staged skills and below-threshold skills decay or are quarantined.
        The Reflector runs asynchronously within this coroutine (not in the
        hot path) — it is the only component allowed to promote proposals
        (memfabric Invariant 4, CLAUDE.md §13.10).
        """
        model_router: ModelRouter
        if self.config.use_llm and self.config.llm_provider != "fake":
            model_router = OpenAIModelRouter(self.config)
            logger.info(
                "LLM planning enabled: provider=%s model=%s base_url=%s",
                self.config.llm_provider,
                self.config.planner_model,
                self.config.llm_base_url or "(env OPENAI_BASE_URL)",
            )
        else:
            model_router = FakeModelRouter()

        # Create the shared budget tracker for this run.  With FakeModelRouter
        # the tracker is constructed but its budget is never consulted (all
        # planners fall back immediately before the budget check).
        budget = LLMBudgetTracker(
            max_per_run=self.config.max_llm_calls_per_run,
            max_per_phase=self.config.max_llm_calls_per_phase,
            stop_on_repeated_plan=self.config.llm_stop_on_repeated_plan,
        )
        self.last_budget = budget

        # Infra Phase 4: construct the tool-execution backend explicitly here
        # (rather than relying on build_apex_graph()'s own internal default)
        # specifically so this method — the fully lifecycle-managed
        # production entrypoint — can close it in the `finally` block below.
        # select_runtime_backend() enforces dry_run=True → DryRunToolBackend
        # regardless of config.tool_backend (docs/remote-tool-backend.md).
        # See build_apex_graph()'s docstring "Lifecycle note" for the
        # documented limitation that applies to callers who do NOT go
        # through ApexRuntime.
        tool_backend = select_runtime_backend(self.config)

        graph = build_apex_graph(
            self.api, self.registry, self.config,
            model_router=model_router,
            budget_tracker=budget,
            tool_backend=tool_backend,
        )
        run_id = new_id()
        initial: ApexGraphState = {
            "run_id": run_id,
            "target": self.config.target,
            "phase": ApexPhase.recon.value,
            "goal": f"Begin engagement against {self.config.target}",
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
            "duplicate_actions": [],
            "completed_fingerprints": [],
            "execution_backend_log": [],
            "diagnostic_events": [],
            "credential_validation_log": [],
            "outcome": "",
            "termination_reason": "",
            "termination_phase": "",
            "stall_reason": "",
            "privilege_state": "",
            "privilege_summary": {},
            "opportunity_ids": [],
            "attempted_opportunities": [],
            "enumeration_complete": False,
            "web_session_state": {},
            "workflow_summary": {},
        }
        invoke_config: dict[str, Any] = {
            "configurable": {"thread_id": run_id},
            "recursion_limit": max(50, self.config.max_turns * 10),
        }
        try:
            final_state: ApexGraphState = await graph.ainvoke(initial, config=invoke_config)
        except asyncio.CancelledError:
            # Phase 12C: best-effort terminal episode for a cancelled
            # engagement (e.g. Ctrl+C / SIGINT during the run). The exact
            # phase/turn at the moment of cancellation is not recoverable
            # here (no checkpointer is configured for this call — see
            # build_apex_graph()'s docstring), so the episode records that
            # explicitly rather than guessing. Writing is wrapped in its
            # own try/except so a secondary failure here never masks the
            # original cancellation — CancelledError is always re-raised.
            logger.warning("engagement cancelled — recording best-effort terminal episode")
            try:
                from apex_host.orchestration.outcome import EngagementOutcome, TerminationDecision
                from apex_host.orchestration.terminal_episode import write_terminal_episode

                decision = TerminationDecision(
                    terminate=True, outcome=EngagementOutcome.cancelled, success=False,
                    reason="engagement cancelled (interrupt received); exact phase/turn not recoverable",
                    phase="unknown", turn=-1,
                )
                await write_terminal_episode(self.api, decision, run_id=run_id)
            except Exception as inner_exc:
                logger.warning("failed to write cancellation terminal episode: %s", inner_exc)
            raise
        finally:
            aclose = getattr(tool_backend, "aclose", None)
            if aclose is not None:
                await aclose()

        # Post-engagement Reflector pass — generalise success chains into
        # staged skills, promote entries above the quality gate, apply decay
        # and quarantine to stale/losing skills.
        try:
            reflector = ReflectorWorker(self.api, self.memfabric_config)
            await reflector.run_once()
            logger.info("reflector.run_once() completed after engagement")
        except Exception as exc:
            logger.warning("reflector.run_once() failed (non-fatal): %s", exc)

        return final_state


def build_runtime(config: ApexConfig) -> ApexRuntime:
    """Construct a fully-wired ApexRuntime from an ApexConfig.

    Mirrors the wiring pattern in examples/smoke_run.py: networkx graph +
    JSONL episodic store + BM25 lexical + faiss vector + in-memory KV, with
    the identifier-pattern channel supplied by apex_host (memfabric ships an
    empty default per Section 9).
    """
    memfabric_config = Config(max_concurrency=config.max_concurrency, max_retries=config.max_retries)

    graph = NetworkXGraphStore()
    episodic = JSONLEpisodicStore(path=None)
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=memfabric_config.vector_dim)
    kv = InMemoryKVStore()

    api = MemoryAPI(graph=graph, episodic=episodic, lexical=lexical, vector=vector, kv=kv, config=memfabric_config)

    retriever = HybridRetriever(
        lexical=lexical,
        vector=vector,
        embedder=StubEmbedder(),
        reranker=PassthroughReranker(),
        graph=graph,
        graph_matcher=TextGraphMatcher(),
        kv=kv,
        config=memfabric_config,
        identifier_patterns=default_identifier_patterns(),
    )
    api.set_retriever(retriever)

    registry = ToolRegistry.from_config(config)

    return ApexRuntime(api=api, config=config, memfabric_config=memfabric_config, registry=registry)
