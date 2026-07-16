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
from apex_host.graph_ids import (
    auth_flow_id as _auth_flow_id,
    endpoint_id as _endpoint_id,
    exposes_edge_id as _exposes_edge_id,
    host_id as _host_id,
    service_id as _service_id,
)
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
    login_url = f"http://{target}/login"
    nid_host = _host_id(target)
    nid_service = _service_id(target, "80", "tcp")
    nid_endpoint = _endpoint_id(login_url)
    nid_auth = _auth_flow_id(login_url)

    await api.upsert_node(Node(id=nid_host, type="host", props={"ip": target}, confidence=0.9, source="synthetic", first_seen=timestamp, last_seen=timestamp))
    await api.upsert_node(Node(id=nid_service, type="service", props={"port": "80", "service": "http"}, confidence=0.85, source="synthetic", first_seen=timestamp, last_seen=timestamp))
    await api.upsert_node(Node(id=nid_endpoint, type="endpoint", props={"url": login_url}, confidence=0.7, source="synthetic", first_seen=timestamp, last_seen=timestamp))
    await api.upsert_node(Node(id=nid_auth, type="auth_flow", props={"url": login_url}, confidence=0.75, source="synthetic", first_seen=timestamp, last_seen=timestamp))

    for to_id in (nid_service, nid_endpoint, nid_auth):
        await api.upsert_edge(
            Edge(
                id=_exposes_edge_id(nid_host, to_id),
                from_id=nid_host,
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
    }
    final_state: ApexGraphState = await graph.ainvoke(initial)
    return summarize(final_state)


def main() -> None:
    metrics = asyncio.run(run_synthetic_machine())
    print(metrics)


if __name__ == "__main__":
    main()
