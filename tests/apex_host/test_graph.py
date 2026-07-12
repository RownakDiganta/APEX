# test_graph.py
# Tests for the APEX LangGraph and ApexGraphState covering state-field type safety, dry-run subprocess prevention, and phase progression from seeded EKG data.
"""Tests for apex_host/graph.py and graph_state.py.

Covers:
- ApexGraphState stays generic (no MemoryAPI/Executor/Planner/Config types).
- The compiled graph runs end-to-end in dry_run mode with zero real
  subprocess calls.
- Phase progression reflects GlobalPlanner.decide_phase given seeded EKG
  node types (deterministic, no real tool output needed).
"""
from __future__ import annotations

from typing import Any, get_type_hints

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Node

from apex_host.config import ApexConfig
from apex_host.graph import build_apex_graph
from apex_host.graph_state import ApexGraphState
from apex_host.tools.registry import ToolRegistry


def make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def make_initial_state(target: str, run_id: str = "run-1") -> ApexGraphState:
    return {
        "run_id": run_id,
        "target": target,
        "phase": "recon",
        "goal": f"Begin engagement against {target}",
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
    }


class TestApexGraphStateStructure:
    def test_state_stays_generic_no_api_objects(self) -> None:
        import apex_host.config as _cfg_mod
        import apex_host.tools.registry as _registry_mod
        import memfabric.api as _api_mod
        import memfabric.config as _mf_cfg_mod
        import memfabric.coordination.protocols as _proto_mod

        banned_classes = (
            _api_mod.MemoryAPI,
            _mf_cfg_mod.Config,
            _cfg_mod.ApexConfig,
            _registry_mod.ToolRegistry,
            _proto_mod.Executor,
            _proto_mod.Planner,
        )

        def _flatten(hint: object) -> set[object]:
            args = getattr(hint, "__args__", None) or ()
            result: set[object] = {hint}
            for a in args:
                result |= _flatten(a)
            return result

        hints = get_type_hints(ApexGraphState, include_extras=True)
        for field_name, hint in hints.items():
            for cls in banned_classes:
                assert cls not in _flatten(hint), (
                    f"ApexGraphState.{field_name} must not reference {cls.__name__}; got: {hint}"
                )

    def test_state_contains_expected_fields(self) -> None:
        hints = get_type_hints(ApexGraphState, include_extras=True)
        for field_name in (
            "run_id", "target", "phase", "goal", "current_task",
            "evidence_summary", "findings", "error_episodes", "last_tool_result",
            "last_error", "completed", "turn_count",
        ):
            assert field_name in hints


class TestApexGraphExecution:
    async def test_graph_compiles(self) -> None:
        api = make_api()
        registry = ToolRegistry.from_config(ApexConfig(target="127.0.0.1"))
        graph = build_apex_graph(api, registry, ApexConfig(target="127.0.0.1"))
        assert graph is not None

    async def test_dry_run_never_spawns_a_real_subprocess(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import asyncio

        def _forbidden(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("dry_run must never spawn a real subprocess")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _forbidden)

        api = make_api()
        config = ApexConfig(target="127.0.0.1", dry_run=True, max_turns=3)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)

        final_state = await graph.ainvoke(make_initial_state(config.target))

        assert final_state["turn_count"] == 3
        assert final_state["completed"] is True

    async def test_phase_progresses_with_seeded_graph_state(self) -> None:
        """With host+endpoint+auth_flow+service already known, GlobalPlanner
        should route straight to priv_esc on the very first turn — proving
        global_plan/route_phase correctly read live EKG state rather than
        relying on accumulated turn history."""
        api = make_api()
        target = "10.0.0.5"
        timestamp = now()
        host_id = f"host:{target}"
        for node_type in ("host", "endpoint", "auth_flow", "service"):
            node_id = host_id if node_type == "host" else f"{node_type}:{target}:seed"
            await api.upsert_node(
                Node(
                    id=node_id,
                    type=node_type,
                    props={},
                    confidence=0.9,
                    source="test-seed",
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
        # graph traversal needs these reachable from the host anchor
        from memfabric.types import Edge
        for node_type in ("endpoint", "auth_flow", "service"):
            await api.upsert_edge(
                Edge(
                    id=f"edge:{node_type}:{target}",
                    from_id=host_id,
                    to_id=f"{node_type}:{target}:seed",
                    type="exposes",
                    props={},
                    confidence=0.9,
                    source="test-seed",
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

        config = ApexConfig(target=target, dry_run=True, max_turns=1)
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)

        final_state = await graph.ainvoke(make_initial_state(target))

        assert final_state["phase"] == "priv_esc"
        assert final_state["turn_count"] == 1
        assert final_state["completed"] is True
