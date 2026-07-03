# runtime.py
# Wires MemoryAPI, reference stores, HybridRetriever, payload-repo seeding, and the APEX LangGraph into a single runnable ApexRuntime engagement object.
"""Wires MemoryAPI + reference stores + HybridRetriever + the payload-repo
seed loader + the APEX LangGraph into one runnable engagement.

This is the only place in apex_host that constructs memfabric store/retriever
instances — everything downstream (graph.py, agents/, planners/) only ever
touches state through MemoryAPI, consistent with memfabric Invariant 1.
"""
from __future__ import annotations

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
from apex_host.knowledge.seed_loader import seed_payload_repo
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

    async def seed(self) -> int:
        """Load the payload repo into staged knowledge and promote it once."""
        return await seed_payload_repo(self.config.payload_repo_path, self.api, self.memfabric_config)

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

        graph = build_apex_graph(self.api, self.registry, self.config, model_router=model_router)
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
        }
        invoke_config: dict[str, Any] = {
            "configurable": {"thread_id": run_id},
            "recursion_limit": max(50, self.config.max_turns * 10),
        }
        final_state: ApexGraphState = await graph.ainvoke(initial, config=invoke_config)

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
