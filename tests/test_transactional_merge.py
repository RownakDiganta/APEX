# test_transactional_merge.py
# Tests for MemoryAPI.apply_deltas — transactional batch writes with rollback.
"""Tests for MemoryAPI.apply_deltas transactional batch writes.

Invariant under test: a failed apply_deltas leaves the memory fabric
in exactly the state it was before the call — no partial writes visible.
"""
from __future__ import annotations

import asyncio
import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex

from memfabric.types import (
    Edge,
    Episode,
    KnowledgeEntry,
    Node,
    Outcome,
    Skill,
    Tier,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_api(graph: NetworkXGraphStore | None = None,
              episodic: JSONLEpisodicStore | None = None) -> MemoryAPI:
    cfg = Config()
    g = graph or NetworkXGraphStore()
    ep = episodic or JSONLEpisodicStore()
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=cfg.vector_dim)
    kv = InMemoryKVStore()
    api = MemoryAPI(
        graph=g, episodic=ep, lexical=lexical, vector=vector, kv=kv, config=cfg,
    )
    retriever = HybridRetriever(
        lexical=lexical, vector=vector,
        embedder=StubEmbedder(),
        reranker=PassthroughReranker(),
        graph=g, graph_matcher=TextGraphMatcher(),
        kv=kv, config=cfg,
    )
    api.set_retriever(retriever)
    return api


def _node(label: str, **props: object) -> Node:
    return Node(id=f"node:{label}", type="test", props={"label": label, **props},
                confidence=0.9, source="test", first_seen=now(), last_seen=now())


def _edge(from_id: str, to_id: str, etype: str = "relates") -> Edge:
    return Edge(id=f"edge:{from_id}-{etype}-{to_id}", type=etype,
                from_id=from_id, to_id=to_id, props={},
                confidence=0.8, source="test", first_seen=now(), last_seen=now())


def _episode(label: str) -> Episode:
    return Episode(agent="test", action=label, outcome=Outcome.success, data={})


def _knowledge(text: str) -> KnowledgeEntry:
    return KnowledgeEntry(
        id=new_id(), text=text, source="test", confidence=0.7,
        metadata={"tier": "semantic"}
    )


def _skill(name: str) -> Skill:
    return Skill(
        id=new_id(), name=name, description="test skill",
        template={}, preconditions={}, source_episodes=[],
        confidence=0.6,
    )


# ---------------------------------------------------------------------------
# Happy-path: successful batch commits everything
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_successful_batch_commits_nodes() -> None:
    api = _make_api()
    n1 = _node("alpha")
    n2 = _node("beta")
    await api.apply_deltas(nodes=[n1, n2])
    assert await api._graph.get_node("node:alpha") is not None
    assert await api._graph.get_node("node:beta") is not None


@pytest.mark.asyncio
async def test_successful_batch_commits_edges() -> None:
    api = _make_api()
    n1 = _node("src")
    n2 = _node("dst")
    e = _edge("node:src", "node:dst")
    await api.apply_deltas(nodes=[n1, n2], edges=[e])
    assert await api._graph.get_edge(e.id) is not None


@pytest.mark.asyncio
async def test_successful_batch_commits_episodes() -> None:
    api = _make_api()
    ep = _episode("my-action")
    await api.apply_deltas(episodes=[ep])
    episodes = await api._episodic.all()
    assert any(e.action == "my-action" for e in episodes)


@pytest.mark.asyncio
async def test_successful_batch_commits_all_categories() -> None:
    api = _make_api()
    n = _node("x")
    e = _edge("node:x", "node:x")
    ep = _episode("batch-ep")
    ke = _knowledge("batch knowledge text")
    sk = _skill("batch-skill")
    await api.apply_deltas(nodes=[n], edges=[e], episodes=[ep], knowledge=[ke], skills=[sk])

    assert await api._graph.get_node("node:x") is not None
    assert await api._graph.get_edge(e.id) is not None
    all_eps = await api._episodic.all()
    assert any(ep2.action == "batch-ep" for ep2 in all_eps)
    # Knowledge and skill should be staged (not yet promoted, but staged)
    assert ke.id in api._staged_knowledge
    assert sk.id in api._staged_skills


# ---------------------------------------------------------------------------
# Rollback: node write failure
# ---------------------------------------------------------------------------

class _FailOnSecondPut(NetworkXGraphStore):
    """GraphStore that raises on the second put_node call."""

    def __init__(self) -> None:
        super().__init__()
        self._put_node_calls = 0

    async def put_node(self, node: Node) -> str:
        self._put_node_calls += 1
        if self._put_node_calls == 2:
            raise RuntimeError("injected failure on second node write")
        return await super().put_node(node)


@pytest.mark.asyncio
async def test_rollback_first_node_not_visible_after_second_fails() -> None:
    graph = _FailOnSecondPut()
    api = _make_api(graph=graph)

    n1 = _node("first")
    n2 = _node("second")

    with pytest.raises(RuntimeError, match="injected failure"):
        await api.apply_deltas(nodes=[n1, n2])

    assert await graph.get_node("node:first") is None, "first node must be rolled back"
    assert await graph.get_node("node:second") is None


@pytest.mark.asyncio
async def test_rollback_episode_not_appended_after_node_failure() -> None:
    graph = _FailOnSecondPut()
    episodic = JSONLEpisodicStore()
    api = _make_api(graph=graph, episodic=episodic)

    n1 = _node("first")
    n2 = _node("second")
    ep = _episode("should-not-appear")

    # apply_deltas writes nodes first, then episodes; failure on node 2 means
    # the episode write is never reached — no episode should be appended.
    with pytest.raises(RuntimeError):
        await api.apply_deltas(nodes=[n1, n2], episodes=[ep])

    all_eps = await episodic.all()
    assert not any(e.action == "should-not-appear" for e in all_eps)


@pytest.mark.asyncio
async def test_rollback_proposal_not_staged_after_node_failure() -> None:
    graph = _FailOnSecondPut()
    api = _make_api(graph=graph)

    n1 = _node("first")
    n2 = _node("second")
    ke = _knowledge("should not be staged")

    with pytest.raises(RuntimeError):
        await api.apply_deltas(nodes=[n1, n2], knowledge=[ke])

    assert ke.id not in api._staged_knowledge


@pytest.mark.asyncio
async def test_query_finds_nothing_after_rollback() -> None:
    graph = _FailOnSecondPut()
    api = _make_api(graph=graph)

    n1 = _node("findme-alpha")
    n2 = _node("findme-beta")

    with pytest.raises(RuntimeError):
        await api.apply_deltas(nodes=[n1, n2])

    bundle = await api.query(text="findme-alpha", tiers=[Tier.working], k=5)
    hits = [e for e in bundle.entries if "findme" in (e.text or "")]
    assert not hits, "rolled-back node must not appear in retrieval results"


# ---------------------------------------------------------------------------
# Rollback: episode write failure
# ---------------------------------------------------------------------------

class _FailingEpisodicStore(JSONLEpisodicStore):
    """EpisodicStore that raises on the first append call."""

    async def append(self, episode: Episode) -> str:
        raise RuntimeError("injected episode write failure")


@pytest.mark.asyncio
async def test_rollback_nodes_when_episode_write_fails() -> None:
    graph = NetworkXGraphStore()
    episodic = _FailingEpisodicStore()
    api = _make_api(graph=graph, episodic=episodic)

    n = _node("gamma")
    ep = _episode("failing-ep")

    with pytest.raises(RuntimeError, match="injected episode write failure"):
        await api.apply_deltas(nodes=[n], episodes=[ep])

    # Nodes written before the episode attempt must also be rolled back
    assert await graph.get_node("node:gamma") is None


# ---------------------------------------------------------------------------
# Rollback: edge write failure
# ---------------------------------------------------------------------------

class _FailOnEdgePut(NetworkXGraphStore):
    """GraphStore that raises on every put_edge call."""

    async def put_edge(self, edge: Edge) -> str:
        raise RuntimeError("injected edge write failure")


@pytest.mark.asyncio
async def test_rollback_nodes_when_edge_write_fails() -> None:
    graph = _FailOnEdgePut()
    api = _make_api(graph=graph)

    n1 = _node("edge-src")
    n2 = _node("edge-dst")
    e = _edge("node:edge-src", "node:edge-dst")

    with pytest.raises(RuntimeError, match="injected edge write failure"):
        await api.apply_deltas(nodes=[n1, n2], edges=[e])

    # Nodes written before the edge attempt must be rolled back
    assert await graph.get_node("node:edge-src") is None
    assert await graph.get_node("node:edge-dst") is None


# ---------------------------------------------------------------------------
# Episode rollback actually removes appended episode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_episode_is_rolled_back_when_downstream_write_fails() -> None:
    episodic = JSONLEpisodicStore()
    # Build a normal api then swap propose_skill at the instance level so we
    # can keep the properly wired stores/retriever while injecting a failure.
    api = _make_api(episodic=episodic)

    async def _fail_skill(skill: Skill) -> str:
        raise RuntimeError("injected skill staging failure")

    api.propose_skill = _fail_skill  # type: ignore[method-assign]

    ep = _episode("should-be-rolled-back")
    sk = _skill("failing-skill")

    # Episodes are written before skills; the skill failure should roll back
    # the already-appended episode.
    with pytest.raises(RuntimeError, match="injected skill staging failure"):
        await api.apply_deltas(episodes=[ep], skills=[sk])

    all_eps = await episodic.all()
    assert not any(e.action == "should-be-rolled-back" for e in all_eps), (
        "episode must be rolled back when a downstream write fails"
    )


# ---------------------------------------------------------------------------
# Pre-existing nodes are restored (not deleted) on update rollback
# ---------------------------------------------------------------------------

class _FailOnNodeId(NetworkXGraphStore):
    """GraphStore that raises put_node for a specific node id."""

    def __init__(self, fail_id: str) -> None:
        super().__init__()
        self._fail_id = fail_id

    async def put_node(self, node: Node) -> str:
        if node.id == self._fail_id:
            raise RuntimeError(f"injected failure for node {self._fail_id}")
        return await super().put_node(node)


@pytest.mark.asyncio
async def test_pre_existing_node_restored_after_failed_update() -> None:
    # Use a graph that blocks writes to "node:brandnew" only, so the first
    # node ("node:existing") is updated and then rolled back.
    graph = _FailOnNodeId(fail_id="node:brandnew")
    api = _make_api(graph=graph)

    original = _node("existing", status="old")
    await api.upsert_node(original)

    stored = await api._graph.get_node("node:existing")
    assert stored is not None
    assert stored.props.get("status") == "old"

    updated = _node("existing", status="new")
    new_node = _node("brandnew")

    with pytest.raises(RuntimeError, match="injected failure for node node:brandnew"):
        await api.apply_deltas(nodes=[updated, new_node])

    # Rollback must restore the pre-batch state of "node:existing"
    restored = await graph.get_node("node:existing")
    assert restored is not None
    assert restored.props.get("status") == "old", (
        f"pre-existing node must be restored to pre-batch state, got {restored.props}"
    )
    assert await graph.get_node("node:brandnew") is None
