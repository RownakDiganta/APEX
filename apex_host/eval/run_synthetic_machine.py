# run_synthetic_machine.py
# Synthetic-machine evaluation harness that seeds a deterministic EKG and runs the APEX graph in dry-run mode to verify phase coverage without real execution.
"""Synthetic-machine evaluation harness — no real network/target involved.

Seeds a MemoryAPI with a deterministic synthetic EKG (host -> service ->
endpoint -> auth_flow) representing a stand-in "machine", then runs the
APEX graph in dry_run mode and reports basic coverage metrics. This is the
domain-neutral substitute for testing against a real lab machine — useful
for CI and for sanity-checking phase routing without any real execution.
"""
from __future__ import annotations

import asyncio

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node

from apex_host.config import ApexConfig
from apex_host.eval.metrics import EngagementMetrics, summarize
from apex_host.graph import build_apex_graph
from apex_host.graph_state import ApexGraphState
from apex_host.tools.registry import ToolRegistry

SYNTHETIC_TARGET = "synthetic.local"


def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


async def seed_synthetic_machine(api: MemoryAPI, target: str = SYNTHETIC_TARGET) -> None:
    """Populate the EKG with a deterministic synthetic surface: one host
    exposing one HTTP service, one discovered endpoint, and one auth_flow."""
    timestamp = now()
    host_id = f"host:{target}"
    service_id = f"service:{target}:80/tcp"
    endpoint_id = f"endpoint:{target}:seed"
    auth_id = f"auth_flow:{target}:seed"

    await api.upsert_node(Node(id=host_id, type="host", props={"ip": target}, confidence=0.9, source="synthetic", first_seen=timestamp, last_seen=timestamp))
    await api.upsert_node(Node(id=service_id, type="service", props={"port": "80", "service": "http"}, confidence=0.85, source="synthetic", first_seen=timestamp, last_seen=timestamp))
    await api.upsert_node(Node(id=endpoint_id, type="endpoint", props={"url": f"http://{target}/login"}, confidence=0.7, source="synthetic", first_seen=timestamp, last_seen=timestamp))
    await api.upsert_node(Node(id=auth_id, type="auth_flow", props={"url": f"http://{target}/login"}, confidence=0.75, source="synthetic", first_seen=timestamp, last_seen=timestamp))

    for to_id in (service_id, endpoint_id, auth_id):
        await api.upsert_edge(
            Edge(
                id=f"edge:{host_id}:{to_id}",
                from_id=host_id,
                to_id=to_id,
                type="exposes",
                props={},
                confidence=0.85,
                source="synthetic",
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )


async def run_synthetic_machine(*, max_turns: int = 5) -> EngagementMetrics:
    """Run the APEX graph (dry_run, no real execution) against a seeded
    synthetic machine and return coverage metrics."""
    api = _make_api()
    await seed_synthetic_machine(api)

    config = ApexConfig(target=SYNTHETIC_TARGET, dry_run=True, max_turns=max_turns)
    registry = ToolRegistry.from_config(config)
    graph = build_apex_graph(api, registry, config)

    initial: ApexGraphState = {
        "run_id": "synthetic-run",
        "target": SYNTHETIC_TARGET,
        "phase": "recon",
        "goal": f"Begin engagement against {SYNTHETIC_TARGET}",
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
    final_state: ApexGraphState = await graph.ainvoke(initial)
    return summarize(final_state)


def main() -> None:
    metrics = asyncio.run(run_synthetic_machine())
    print(metrics)


if __name__ == "__main__":
    main()
