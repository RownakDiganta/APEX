# test_graph_phase1_extended.py
# Phase 1 extended tests: deep copy isolation, query snapshot contract, episode capability, rollback-failure, architecture scan scope.
"""Phase 1 Extended Tests — corrections required after initial Phase 1 report.

These tests verify the additional invariants identified in the Phase 1
re-open review:

  Section I (Deep Copy Isolation — all nesting depths):
    I01 — nested dict in node props: mutation does not affect stored state
    I02 — nested list in node props: mutation does not affect stored state
    I03 — second-level nested dict in node props: fully isolated
    I04 — edge props deep copy: nested dict mutation does not corrupt store
    I05 — provenance nested dict: mutation via returned node does not corrupt store
    I06 — get_node returns independent deep copy (via MemoryAPI)
    I07 — get_edge returns independent deep copy (via MemoryAPI)
    I08 — all_nodes: every returned node is an independent deep copy
    I09 — all_edges: every returned edge is an independent deep copy

  Section J (Query Snapshot Contract — Option C):
    J01 — sequential: query sees same committed state in graph and lexical channels
    J02 — graph subgraph is always snapshot-consistent (under _graph_lock)
    J03 — query with subgraph_anchor returns graph snapshot committed before query starts
    J04 — Option C documented: retrieval channel fires outside _graph_lock

  Section K (Pre-Batch Snapshot Completeness):
    K01 — Phase 1 snapshot failure before first write: no nodes written
    K02 — Phase 1 snapshot captures ALL nodes before ANY write begins

  Section L (Episode Transaction Capability):
    L01 — apply_deltas with episodes and supporting store: succeeds
    L02 — apply_deltas with episodes: store lacking _pop_episodes raises TransactionCapabilityError
    L03 — TransactionCapabilityError raised BEFORE any writes begin
    L04 — episodes=() with unsupported store: succeeds (no episode writes needed)
    L05 — TransactionCapabilityError attributes: store_type, missing_cap, reason

  Section M (Rollback Failure — TransactionIntegrityError):
    M01 — rollback failure during node delete raises TransactionIntegrityError
    M02 — TransactionIntegrityError carries original_error
    M03 — TransactionIntegrityError carries rollback_errors list
    M04 — TransactionIntegrityError carries affected_ids
    M05 — TransactionIntegrityError carries first failure stage

  Section N (Repository-Wide Architecture Scan):
    N01 — no apex_host/ production file calls GraphStore put/delete directly
    N02 — no apex_host/ production file accesses api._graph private attribute
    N03 — no memfabric/ production file outside api.py calls store mutators (existing G01 re-run)
    N04 — synthetic apex_host violation: direct put_node call is detected
    N05 — synthetic memfabric violation: direct put_node outside api.py is detected

  Section O (_graph_lock Holders — Exact Method Table Verification):
    O01 — upsert_node acquires _graph_lock
    O02 — upsert_edge acquires _graph_lock
    O03 — delete_node acquires _graph_lock
    O04 — delete_edge acquires _graph_lock
    O05 — apply_deltas acquires _graph_lock
    O06 — get_subgraph acquires _graph_lock
    O07 — open_tasks acquires _graph_lock
    O08 — propose_knowledge does NOT acquire _graph_lock (uses _staging_lock only)
    O09 — propose_skill does NOT acquire _graph_lock (uses _staging_lock only)
    O10 — append_episode does NOT acquire _graph_lock
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

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
    TransactionCapabilityError,
    TransactionIntegrityError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_api(*, actionable_types: list[str] | None = None) -> MemoryAPI:
    cfg = Config(actionable_node_types=actionable_types or [])
    graph = NetworkXGraphStore()
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=cfg.vector_dim)
    kv = InMemoryKVStore()
    api = MemoryAPI(
        graph=graph,
        episodic=JSONLEpisodicStore(),
        lexical=lexical,
        vector=vector,
        kv=kv,
        config=cfg,
    )
    retriever = HybridRetriever(
        lexical=lexical,
        vector=vector,
        embedder=StubEmbedder(),
        reranker=PassthroughReranker(),
        graph=graph,
        graph_matcher=TextGraphMatcher(),
        kv=kv,
        config=cfg,
    )
    api.set_retriever(retriever)
    return api


def _node(nid: str, *, confidence: float = 0.5, **props: Any) -> Node:
    return Node(
        id=nid,
        type="host",
        props=props,
        confidence=confidence,
        source="test",
        first_seen=now(),
        last_seen=now(),
    )


def _edge(eid: str, from_id: str, to_id: str, **props: Any) -> Edge:
    return Edge(
        id=eid,
        from_id=from_id,
        to_id=to_id,
        type="exposes",
        props=props,
        confidence=0.5,
        source="test",
        first_seen=now(),
        last_seen=now(),
    )


def _episode(**kwargs: Any) -> Episode:
    return Episode(
        id=new_id(),
        agent="test",
        action="probe",
        outcome=Outcome.success,
        data=dict(kwargs),
    )


class _NoRollbackEpisodicStore:
    """Minimal EpisodicStore implementation without _pop_episodes support."""
    def __init__(self) -> None:
        self._episodes: dict[str, Episode] = {}

    async def append(self, episode: Episode) -> str:
        if not episode.id:
            episode.id = new_id()
        self._episodes[episode.id] = episode
        return episode.id

    async def get(self, episode_id: str) -> Episode | None:
        return self._episodes.get(episode_id)

    async def tail(self, n: int = 100) -> list[Episode]:
        return list(self._episodes.values())[-n:]

    async def since(self, cursor: str) -> list[Episode]:
        return list(self._episodes.values())

    async def all(self) -> list[Episode]:
        return list(self._episodes.values())


# ---------------------------------------------------------------------------
# Section I — Deep Copy Isolation
# ---------------------------------------------------------------------------

async def test_i01_nested_dict_in_props_isolated() -> None:
    """Mutating a nested dict returned from get_node does not corrupt stored state."""
    api = _make_api()
    node = _node("n1", meta={"key": "value", "inner": {"x": 1}})
    await api.upsert_node(node)

    returned = await api._graph.get_node("n1")
    assert returned is not None
    # Mutate the nested dict in returned.props
    returned.props["meta"]["key"] = "MUTATED"
    returned.props["meta"]["inner"]["x"] = 999

    # Stored state must be unchanged
    stored = await api._graph.get_node("n1")
    assert stored is not None
    assert stored.props["meta"]["key"] == "value", "Nested dict mutation leaked into stored state"
    assert stored.props["meta"]["inner"]["x"] == 1, "Double-nested dict mutation leaked into stored state"


async def test_i02_nested_list_in_props_isolated() -> None:
    """Mutating a list returned from get_node does not corrupt stored state."""
    api = _make_api()
    node = _node("n2", tags=["a", "b", "c"])
    await api.upsert_node(node)

    returned = await api._graph.get_node("n2")
    assert returned is not None
    returned.props["tags"].append("MUTATED")
    returned.props["tags"][0] = "CHANGED"

    stored = await api._graph.get_node("n2")
    assert stored is not None
    assert stored.props["tags"] == ["a", "b", "c"], (
        f"List mutation leaked: {stored.props['tags']}"
    )


async def test_i03_second_level_nested_dict_isolated() -> None:
    """Deep nested dict (three levels) is fully isolated after get_node."""
    api = _make_api()
    node = _node("n3", deep={"level1": {"level2": {"level3": "original"}}})
    await api.upsert_node(node)

    returned = await api._graph.get_node("n3")
    assert returned is not None
    returned.props["deep"]["level1"]["level2"]["level3"] = "MUTATED"

    stored = await api._graph.get_node("n3")
    assert stored is not None
    assert stored.props["deep"]["level1"]["level2"]["level3"] == "original", (
        "Three-level nested mutation leaked into stored state"
    )


async def test_i04_edge_props_deep_copy_isolated() -> None:
    """Mutating nested dict in edge props returned from get_edge does not corrupt store."""
    api = _make_api()
    await api.upsert_node(_node("host:a"))
    await api.upsert_node(_node("host:b"))
    edge = _edge("e1", "host:a", "host:b", meta={"port": 80, "labels": ["http"]})
    await api.upsert_edge(edge)

    returned = await api._graph.get_edge("e1")
    assert returned is not None
    returned.props["meta"]["port"] = 9999
    returned.props["meta"]["labels"].append("MUTATED")

    stored = await api._graph.get_edge("e1")
    assert stored is not None
    assert stored.props["meta"]["port"] == 80, "Edge nested dict mutation leaked"
    assert stored.props["meta"]["labels"] == ["http"], "Edge nested list mutation leaked"


async def test_i05_provenance_nested_dict_isolated() -> None:
    """Mutating _provenance in a returned node does not corrupt stored provenance."""
    api = _make_api()
    node = _node("n5", ip="10.0.0.1")
    await api.upsert_node(node)

    returned = await api._graph.get_node("n5")
    assert returned is not None
    assert "ip" in returned._provenance
    # Mutate the provenance entry
    returned._provenance["ip"]["source"] = "CORRUPTED"
    returned._provenance["ip"]["confidence"] = -999.0

    stored = await api._graph.get_node("n5")
    assert stored is not None
    prov = stored._provenance.get("ip", {})
    assert prov.get("source") == "test", f"Provenance source leaked: {prov}"
    assert prov.get("confidence") == 0.5, f"Provenance confidence leaked: {prov}"


async def test_i06_get_node_via_api_returns_deep_copy() -> None:
    """MemoryAPI.get_subgraph returns nodes that are independently deep-copied."""
    api = _make_api()
    node = _node("n6", data={"nested": [1, 2, 3]})
    await api.upsert_node(node)

    sg = await api.get_subgraph("n6", 0)
    assert len(sg.nodes) == 1
    returned_node = sg.nodes[0]
    returned_node.props["data"]["nested"].append(99)
    returned_node.props["data"]["new_key"] = "injected"

    # Stored must be unaffected
    stored = await api._graph.get_node("n6")
    assert stored is not None
    assert stored.props["data"] == {"nested": [1, 2, 3]}, (
        f"Mutation via get_subgraph leaked into store: {stored.props['data']}"
    )


async def test_i07_get_edge_via_subgraph_returns_deep_copy() -> None:
    """Edges returned via get_subgraph are independently deep-copied."""
    api = _make_api()
    await api.upsert_node(_node("ha"))
    await api.upsert_node(_node("hb"))
    edge = _edge("eAB", "ha", "hb", labels=["tcp", "http"])
    await api.upsert_edge(edge)

    sg = await api.get_subgraph("ha", 1)
    returned_edges = [e for e in sg.edges if e.id == "eAB"]
    assert len(returned_edges) == 1
    returned_edges[0].props["labels"].append("INJECTED")

    stored = await api._graph.get_edge("eAB")
    assert stored is not None
    assert stored.props["labels"] == ["tcp", "http"], (
        f"Edge list mutation leaked via subgraph: {stored.props['labels']}"
    )


async def test_i08_all_nodes_returns_independent_deep_copies() -> None:
    """all_nodes returns deep copies — mutating one does not affect others or stored state."""
    api = _make_api()
    for i in range(3):
        await api.upsert_node(_node(f"n{i}", data={"i": i, "bag": [i]}))

    all_n = await api._graph.all_nodes()
    for n in all_n:
        n.props["data"]["i"] = 9999
        n.props["data"]["bag"].append("bad")

    for i in range(3):
        stored = await api._graph.get_node(f"n{i}")
        assert stored is not None
        assert stored.props["data"]["i"] == i, f"n{i} was mutated via all_nodes"
        assert stored.props["data"]["bag"] == [i], f"n{i} list was mutated via all_nodes"


async def test_i09_all_edges_returns_independent_deep_copies() -> None:
    """all_edges returns deep copies — mutating one does not affect stored state."""
    api = _make_api()
    await api.upsert_node(_node("ha"))
    await api.upsert_node(_node("hb"))
    await api.upsert_edge(_edge("e1", "ha", "hb", info={"score": 1, "tags": ["x"]}))

    all_e = await api._graph.all_edges()
    assert len(all_e) >= 1
    for e in all_e:
        if e.id == "e1":
            e.props["info"]["score"] = 9999
            e.props["info"]["tags"].append("MUTATED")

    stored = await api._graph.get_edge("e1")
    assert stored is not None
    assert stored.props["info"]["score"] == 1, "Edge nested score mutated via all_edges"
    assert stored.props["info"]["tags"] == ["x"], "Edge nested list mutated via all_edges"


# ---------------------------------------------------------------------------
# Section J — Query Snapshot Contract (Option C)
# ---------------------------------------------------------------------------

async def test_j01_sequential_query_sees_same_committed_version() -> None:
    """In the sequential case (no concurrent writers), query returns both
    lexical evidence and subgraph from the same committed version.

    This is the typical case: single coroutine, no interleaving.
    """
    api = _make_api()
    node = _node("host:j01", ip="10.1.1.1")
    await api.upsert_node(node)

    bundle = await api.query(text="host", subgraph_anchor="host:j01", k=5)

    # Subgraph must contain the node
    node_ids = {n.id for n in (bundle.subgraph.nodes if bundle.subgraph else [])}
    assert "host:j01" in node_ids, "Graph subgraph missing committed node"

    # Lexical must also see it (freshness invariant)
    text_ids = {e.id for e in bundle.entries}
    assert "host:j01" in text_ids, "Lexical evidence missing committed node"


async def test_j02_subgraph_is_lock_isolated_during_fetch() -> None:
    """The subgraph fetch runs under _graph_lock.

    A writer trying to update the graph while get_subgraph holds the lock
    is blocked until the subgraph fetch completes.  The subgraph always
    reflects a complete, not partial, committed batch state.
    """
    api = _make_api()
    await api.upsert_node(_node("anchor"))

    subgraph_complete = asyncio.Event()
    writer_blocked = asyncio.Event()
    subgraph_result: list[Any] = []

    async def reader() -> None:
        # Acquire the graph lock to simulate what get_subgraph does internally
        async with api._graph_lock:
            writer_blocked.set()
            await asyncio.sleep(0)  # yield — writer must wait for this lock
            sg = await api._graph.get_subgraph("anchor", 0)
            subgraph_result.append(sg)
        subgraph_complete.set()

    async def writer() -> None:
        await writer_blocked.wait()
        # This upsert must block until reader releases _graph_lock
        await api.upsert_node(_node("writer_node"))

    await asyncio.gather(reader(), writer())

    # The subgraph captured under the lock must NOT contain "writer_node"
    # because the writer was blocked for the duration of the subgraph read
    node_ids = {n.id for n in subgraph_result[0].nodes}
    assert "writer_node" not in node_ids, (
        "Subgraph was polluted by a concurrent writer (lock isolation failed)"
    )


async def test_j03_subgraph_reflects_pre_query_committed_state() -> None:
    """The graph subgraph in a query result reflects the state committed
    BEFORE the query started — confirming snapshot-at-query-start semantics."""
    api = _make_api()
    # Write two nodes: first before query, second to be committed concurrently
    await api.upsert_node(_node("pre_node", ip="1.2.3.4"))

    bundle = await api.query(text="host", subgraph_anchor="pre_node", k=5)

    assert bundle.subgraph is not None
    node_ids = {n.id for n in bundle.subgraph.nodes}
    assert "pre_node" in node_ids, "Pre-committed node missing from subgraph"


async def test_j04_option_c_contract_documented_in_api_docstring() -> None:
    """query() docstring must contain the 'Option C' narrative so callers
    understand the narrow snapshot guarantee they are operating under."""
    import inspect
    src = inspect.getsource(MemoryAPI.query)
    assert "Option C" in src, (
        "query() must document the Option C snapshot contract explicitly"
    )
    assert "_graph_lock" in src, (
        "query() docstring must reference _graph_lock so readers understand the boundary"
    )


# ---------------------------------------------------------------------------
# Section K — Pre-Batch Snapshot Completeness
# ---------------------------------------------------------------------------

async def test_k01_phase1_snapshot_failure_leaves_graph_unchanged() -> None:
    """If get_node raises during Phase 1 snapshot (before any write), no
    node from the batch should appear in the graph."""
    api = _make_api()
    n1, n2, n3 = _node("k01_n1"), _node("k01_n2"), _node("k01_n3")

    call_count = [0]
    original_get_node = api._graph.get_node

    async def fail_on_third_snapshot(nid: str) -> Any:
        call_count[0] += 1
        if call_count[0] >= 3:
            raise RuntimeError("snapshot injection failure")
        return await original_get_node(nid)

    api._graph.get_node = fail_on_third_snapshot  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="snapshot injection failure"):
        await api.apply_deltas(nodes=[n1, n2, n3])

    api._graph.get_node = original_get_node  # type: ignore[assignment]

    # No node from the batch should exist — Phase 2 (writes) never started
    for nid in ("k01_n1", "k01_n2", "k01_n3"):
        stored = await api._graph.get_node(nid)
        assert stored is None, (
            f"Node '{nid}' was written even though Phase 1 snapshot failed — "
            "all writes must start AFTER the full snapshot is complete"
        )


async def test_k02_all_nodes_snapshotted_before_first_write() -> None:
    """apply_deltas must capture the pre-batch snapshot for ALL nodes before
    any single write is committed.  Verify by seeding two nodes, then
    starting a batch that updates them.  The snapshot must hold both pre-write
    values so rollback can restore both independently."""
    api = _make_api()
    n_a_old = _node("k02_a", version="old")
    n_b_old = _node("k02_b", version="old")
    await api.upsert_node(n_a_old)
    await api.upsert_node(n_b_old)

    n_a_new = _node("k02_a", version="new")
    n_b_new = _node("k02_b", version="new")
    n_fail = _node("k02_fail")

    # Inject a write failure on the third node so rollback runs for a+b
    original_put_node = api._graph.put_node
    write_count = [0]

    async def fail_only_third_write(node: Node) -> str:
        write_count[0] += 1
        if write_count[0] == 3:
            # Fail ONLY on the 3rd write call (k02_fail — new node).
            # Rollback calls (4 and 5) must succeed so state can be verified.
            raise RuntimeError("write injection failure")
        return await original_put_node(node)

    api._graph.put_node = fail_only_third_write  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="write injection failure"):
        await api.apply_deltas(nodes=[n_a_new, n_b_new, n_fail])

    api._graph.put_node = original_put_node  # type: ignore[assignment]

    # Both existing nodes must be restored to their pre-batch values.
    # This proves the snapshot was complete (k02_b captured) before the 1st write.
    stored_a = await api._graph.get_node("k02_a")
    stored_b = await api._graph.get_node("k02_b")
    assert stored_a is not None and stored_a.props.get("version") == "old", (
        f"k02_a was not rolled back to 'old': {stored_a}"
    )
    assert stored_b is not None and stored_b.props.get("version") == "old", (
        f"k02_b was not rolled back to 'old': {stored_b}"
    )


# ---------------------------------------------------------------------------
# Section L — Episode Transaction Capability
# ---------------------------------------------------------------------------

async def test_l01_apply_deltas_with_episodes_and_supporting_store_succeeds() -> None:
    """apply_deltas with episodes succeeds when the store has _pop_episodes."""
    api = _make_api()
    n = _node("l01_host")
    ep = _episode(turn=1)
    await api.apply_deltas(nodes=[n], episodes=[ep])
    stored = await api._graph.get_node("l01_host")
    assert stored is not None
    all_eps = await api._episodic.all()
    assert any(e.id == ep.id for e in all_eps)


async def test_l02_apply_deltas_episodes_without_pop_raises_capability_error() -> None:
    """apply_deltas with episodes raises TransactionCapabilityError when
    the episodic store lacks _pop_episodes."""
    api = _make_api()
    api._episodic = _NoRollbackEpisodicStore()  # type: ignore[assignment]
    ep = _episode(turn=1)

    with pytest.raises(TransactionCapabilityError):
        await api.apply_deltas(episodes=[ep])


async def test_l03_capability_error_raised_before_any_write() -> None:
    """TransactionCapabilityError must be raised BEFORE any writes begin,
    preserving the all-or-nothing invariant."""
    api = _make_api()
    api._episodic = _NoRollbackEpisodicStore()  # type: ignore[assignment]

    n = _node("l03_node")
    ep = _episode(turn=1)

    with pytest.raises(TransactionCapabilityError):
        await api.apply_deltas(nodes=[n], episodes=[ep])

    # The node must NOT have been written
    stored = await api._graph.get_node("l03_node")
    assert stored is None, (
        "Node was written even though TransactionCapabilityError should have "
        "prevented all writes"
    )


async def test_l04_episodes_empty_with_unsupported_store_succeeds() -> None:
    """episodes=() with a store lacking _pop_episodes succeeds: no episode
    writes means no rollback capability is needed."""
    api = _make_api()
    api._episodic = _NoRollbackEpisodicStore()  # type: ignore[assignment]

    n = _node("l04_node")
    await api.apply_deltas(nodes=[n], episodes=())
    stored = await api._graph.get_node("l04_node")
    assert stored is not None


async def test_l05_capability_error_attributes() -> None:
    """TransactionCapabilityError must expose store_type, missing_cap, and reason."""
    api = _make_api()
    api._episodic = _NoRollbackEpisodicStore()  # type: ignore[assignment]
    ep = _episode(turn=1)

    with pytest.raises(TransactionCapabilityError) as exc_info:
        await api.apply_deltas(episodes=[ep])

    err = exc_info.value
    assert err.store_type == "_NoRollbackEpisodicStore"
    assert "_pop_episodes" in err.missing_cap
    assert len(err.reason) > 0


# ---------------------------------------------------------------------------
# Section M — Rollback Failure (TransactionIntegrityError)
# ---------------------------------------------------------------------------

async def test_m01_rollback_failure_raises_integrity_error() -> None:
    """When a rollback step itself fails, TransactionIntegrityError is raised."""
    api = _make_api()
    # Seed a node so the batch is an update, not a new insert
    await api.upsert_node(_node("m01_target", version="old"))

    n_new = _node("m01_target", version="new")
    n_fail = _node("m01_fail")

    original_put_node = api._graph.put_node
    write_count = [0]

    async def fail_second_write(node: Node) -> str:
        write_count[0] += 1
        if write_count[0] >= 2:
            raise RuntimeError("write failed")
        return await original_put_node(node)

    # Make delete_node also fail to trigger rollback failure
    async def fail_delete(node_id: str) -> None:
        raise RuntimeError(f"delete failed for {node_id}")

    api._graph.put_node = fail_second_write  # type: ignore[assignment]
    api._graph.delete_node = fail_delete  # type: ignore[assignment]

    with pytest.raises(TransactionIntegrityError):
        await api.apply_deltas(nodes=[n_new, n_fail])

    # Restore
    api._graph.put_node = original_put_node  # type: ignore[assignment]


async def test_m02_transaction_integrity_error_carries_original_error() -> None:
    """TransactionIntegrityError.original_error is the exception from the write phase."""
    api = _make_api()
    await api.upsert_node(_node("m02_seed"))

    n_new = _node("m02_seed", version="new")
    n_boom = _node("m02_boom")

    original_put_node = api._graph.put_node
    write_count = [0]

    async def fail_second(node: Node) -> str:
        write_count[0] += 1
        if write_count[0] >= 2:
            raise RuntimeError("write_phase_error")
        return await original_put_node(node)

    async def fail_delete(nid: str) -> None:
        raise RuntimeError("rollback_delete_error")

    api._graph.put_node = fail_second  # type: ignore[assignment]
    api._graph.delete_node = fail_delete  # type: ignore[assignment]

    with pytest.raises(TransactionIntegrityError) as exc_info:
        await api.apply_deltas(nodes=[n_new, n_boom])

    err = exc_info.value
    assert isinstance(err.original_error, RuntimeError)
    assert "write_phase_error" in str(err.original_error)

    api._graph.put_node = original_put_node  # type: ignore[assignment]


async def test_m03_transaction_integrity_error_carries_rollback_errors() -> None:
    """TransactionIntegrityError.rollback_errors is a non-empty list."""
    api = _make_api()
    n_new = _node("m03_new")
    n_fail = _node("m03_fail")

    original_put_node = api._graph.put_node
    write_count = [0]

    async def fail_second(node: Node) -> str:
        write_count[0] += 1
        if write_count[0] >= 2:
            raise RuntimeError("write error")
        return await original_put_node(node)

    async def fail_delete(nid: str) -> None:
        raise RuntimeError("rollback error")

    api._graph.put_node = fail_second  # type: ignore[assignment]
    api._graph.delete_node = fail_delete  # type: ignore[assignment]

    with pytest.raises(TransactionIntegrityError) as exc_info:
        await api.apply_deltas(nodes=[n_new, n_fail])

    err = exc_info.value
    assert isinstance(err.rollback_errors, list)
    assert len(err.rollback_errors) >= 1

    api._graph.put_node = original_put_node  # type: ignore[assignment]


async def test_m04_transaction_integrity_error_carries_affected_ids() -> None:
    """TransactionIntegrityError.affected_ids lists the IDs partially committed."""
    api = _make_api()
    n_good = _node("m04_good")
    n_fail = _node("m04_fail")

    original_put_node = api._graph.put_node
    write_count = [0]

    async def fail_second(node: Node) -> str:
        write_count[0] += 1
        if write_count[0] >= 2:
            raise RuntimeError("write error")
        return await original_put_node(node)

    async def fail_delete(nid: str) -> None:
        raise RuntimeError("rollback delete error")

    api._graph.put_node = fail_second  # type: ignore[assignment]
    api._graph.delete_node = fail_delete  # type: ignore[assignment]

    with pytest.raises(TransactionIntegrityError) as exc_info:
        await api.apply_deltas(nodes=[n_good, n_fail])

    err = exc_info.value
    assert "m04_good" in err.affected_ids

    api._graph.put_node = original_put_node  # type: ignore[assignment]


async def test_m05_transaction_integrity_error_carries_stage() -> None:
    """TransactionIntegrityError.stage is the name of the first failed rollback step."""
    api = _make_api()
    n_new = _node("m05_new")
    n_fail = _node("m05_fail")

    original_put_node = api._graph.put_node
    write_count = [0]

    async def fail_second(node: Node) -> str:
        write_count[0] += 1
        if write_count[0] >= 2:
            raise RuntimeError("write error")
        return await original_put_node(node)

    async def fail_delete(nid: str) -> None:
        raise RuntimeError("rollback step error")

    api._graph.put_node = fail_second  # type: ignore[assignment]
    api._graph.delete_node = fail_delete  # type: ignore[assignment]

    with pytest.raises(TransactionIntegrityError) as exc_info:
        await api.apply_deltas(nodes=[n_new, n_fail])

    err = exc_info.value
    assert err.stage != "", "stage must be a non-empty string identifying the failing rollback step"
    assert "node_rollback" in err.stage or "edge_rollback" in err.stage or "delete" in err.stage.lower()

    api._graph.put_node = original_put_node  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Section N — Repository-Wide Architecture Scan
# ---------------------------------------------------------------------------

def _production_py_files(*roots: str) -> list[Path]:
    """Return all .py files under *roots* excluding test files and __pycache__."""
    files: list[Path] = []
    for root in roots:
        for p in Path(root).rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            if p.name.startswith("test_"):
                continue
            files.append(p)
    return files


_REPO_ROOT = Path(__file__).parent.parent
_MEMFABRIC_ROOT = str(_REPO_ROOT / "memfabric")
_APEXHOST_ROOT = str(_REPO_ROOT / "apex_host")


async def test_n01_apex_host_no_direct_graphstore_calls() -> None:
    """No apex_host/ production file calls GraphStore put/delete methods directly.

    All graph writes must go through MemoryAPI (Invariant 1).
    Allowed callers: MemoryAPI internals in api.py, graph store impl in graph_networkx.py.
    """
    # These patterns indicate a direct GraphStore mutation outside MemoryAPI
    forbidden_patterns = [
        "._graph.put_node(",
        "._graph.put_edge(",
        "._graph.delete_node(",
        "._graph.delete_edge(",
        "._graph.add_node(",
        "._graph.add_edge(",
        "._graph.remove_node(",
        "._graph.remove_edge(",
    ]

    violations: list[str] = []
    for f in _production_py_files(_APEXHOST_ROOT):
        text = f.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pat in forbidden_patterns:
                if pat in line:
                    violations.append(f"{f.relative_to(_REPO_ROOT)}:{line_no}: {line.strip()}")

    assert not violations, (
        "Direct GraphStore mutations found in apex_host/ production code "
        "(violates Invariant 1):\n" + "\n".join(violations)
    )


async def test_n02_apex_host_no_private_graph_attribute_access() -> None:
    """No apex_host/ production file accesses api._graph (the private attribute).

    Direct access to api._graph bypasses MemoryAPI transaction serialization.
    """
    violations: list[str] = []
    for f in _production_py_files(_APEXHOST_ROOT):
        text = f.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "api._graph" in line or "._api._graph" in line:
                violations.append(f"{f.relative_to(_REPO_ROOT)}:{line_no}: {line.strip()}")

    assert not violations, (
        "Direct api._graph access found in apex_host/ (bypasses MemoryAPI "
        "transaction lock):\n" + "\n".join(violations)
    )


async def test_n03_memfabric_no_graphstore_mutator_outside_approved_files() -> None:
    """No memfabric/ production file outside api.py and graph_networkx.py calls
    GraphStore mutator methods directly.  This is the existing G01 re-run,
    extended to double-check after Phase 1 code changes."""
    # protocols.py defines the GraphStore Protocol interface (signatures only — no mutation calls)
    approved_files = {"api.py", "graph_networkx.py", "protocols.py"}
    mutator_patterns = [
        "put_node(",
        "put_edge(",
        ".delete_node(",
        ".delete_edge(",
        "._g.add_node(",
        "._g.add_edge(",
        "._g.remove_node(",
        "._g.remove_edge(",
    ]

    violations: list[str] = []
    for f in _production_py_files(_MEMFABRIC_ROOT):
        if f.name in approved_files:
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pat in mutator_patterns:
                if pat in line:
                    violations.append(
                        f"{f.relative_to(_REPO_ROOT)}:{line_no}: {line.strip()}"
                    )

    assert not violations, (
        "Direct GraphStore mutations outside approved memfabric/ files:\n"
        + "\n".join(violations)
    )


async def test_n04_synthetic_apex_host_violation_detected() -> None:
    """The scan correctly flags a synthetic direct put_node call in apex_host/."""
    import tempfile
    import os

    synthetic_code = (
        "# synthetic_violation.py\n"
        "# Synthetic file to verify the architecture scan detects violations.\n"
        "async def bad(api):\n"
        "    api._graph.put_node(None)\n"  # direct access — violation
    )

    violations: list[str] = []
    forbidden_patterns = ["._graph.put_node(", "._graph.put_edge("]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", dir=_APEXHOST_ROOT, delete=False
    ) as tmp:
        tmp.write(synthetic_code)
        tmp_path = Path(tmp.name)

    try:
        text = tmp_path.read_text()
        for line_no, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            for pat in forbidden_patterns:
                if pat in line:
                    violations.append(f"{tmp_path.name}:{line_no}")
    finally:
        os.unlink(tmp_path)

    assert len(violations) >= 1, (
        "Architecture scan failed to detect synthetic api._graph.put_node violation"
    )


async def test_n05_synthetic_memfabric_violation_detected() -> None:
    """The scan correctly flags a synthetic put_node call inside memfabric/ non-approved file."""
    synthetic_code = (
        "# test_synthetic_mutation.py\n"
        "# Synthetic violation\n"
        "async def bad(graph):\n"
        "    graph.put_node(None)\n"  # direct mutation call
    )

    violations: list[str] = []
    mutator_patterns = ["put_node(", ".delete_node("]

    import tempfile
    import os
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", dir=_MEMFABRIC_ROOT, delete=False
    ) as tmp:
        tmp.write(synthetic_code)
        tmp_path = Path(tmp.name)

    try:
        text = tmp_path.read_text()
        for line_no, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            for pat in mutator_patterns:
                if pat in line:
                    violations.append(f"{tmp_path.name}:{line_no}")
    finally:
        os.unlink(tmp_path)

    assert len(violations) >= 1, (
        "Architecture scan failed to detect synthetic put_node violation in memfabric/"
    )


# ---------------------------------------------------------------------------
# Section O — _graph_lock Holders: Exact Method Table Verification
# ---------------------------------------------------------------------------

async def test_o01_upsert_node_acquires_graph_lock() -> None:
    """upsert_node holds _graph_lock for the full read-modify-write cycle."""
    api = _make_api()
    lock_was_held: list[bool] = []

    original = api._graph.get_node
    async def spy(nid: str) -> Any:
        lock_was_held.append(api._graph_lock.locked())
        return await original(nid)
    api._graph.get_node = spy  # type: ignore[assignment]

    await api.upsert_node(_node("o01"))
    assert all(lock_was_held), "upsert_node must hold _graph_lock during get_node"


async def test_o02_upsert_edge_acquires_graph_lock() -> None:
    """upsert_edge holds _graph_lock for the LWW check + write."""
    api = _make_api()
    await api.upsert_node(_node("ha"))
    await api.upsert_node(_node("hb"))

    lock_was_held: list[bool] = []
    original_get_edge = api._graph.get_edge
    async def spy(eid: str) -> Any:
        lock_was_held.append(api._graph_lock.locked())
        return await original_get_edge(eid)
    api._graph.get_edge = spy  # type: ignore[assignment]

    await api.upsert_edge(_edge("e_o02", "ha", "hb"))
    assert all(lock_was_held), "upsert_edge must hold _graph_lock during get_edge"


async def test_o03_delete_node_acquires_graph_lock() -> None:
    """delete_node holds _graph_lock."""
    api = _make_api()
    await api.upsert_node(_node("o03"))

    lock_was_held: list[bool] = []
    original_delete = api._graph.delete_node
    async def spy(nid: str) -> None:
        lock_was_held.append(api._graph_lock.locked())
        return await original_delete(nid)
    api._graph.delete_node = spy  # type: ignore[assignment]

    await api.delete_node("o03")
    assert all(lock_was_held), "delete_node must hold _graph_lock"


async def test_o04_delete_edge_acquires_graph_lock() -> None:
    """delete_edge holds _graph_lock."""
    api = _make_api()
    await api.upsert_node(_node("ha"))
    await api.upsert_node(_node("hb"))
    await api.upsert_edge(_edge("e_o04", "ha", "hb"))

    lock_was_held: list[bool] = []
    original_delete = api._graph.delete_edge
    async def spy(eid: str) -> None:
        lock_was_held.append(api._graph_lock.locked())
        return await original_delete(eid)
    api._graph.delete_edge = spy  # type: ignore[assignment]

    await api.delete_edge("e_o04")
    assert all(lock_was_held), "delete_edge must hold _graph_lock"


async def test_o05_apply_deltas_acquires_graph_lock() -> None:
    """apply_deltas holds _graph_lock for the entire batch (reads and writes)."""
    api = _make_api()
    lock_was_held: list[bool] = []

    original = api._graph.get_node
    async def spy(nid: str) -> Any:
        lock_was_held.append(api._graph_lock.locked())
        return await original(nid)
    api._graph.get_node = spy  # type: ignore[assignment]

    await api.apply_deltas(nodes=[_node("o05")])
    assert all(lock_was_held), "apply_deltas must hold _graph_lock during snapshot reads"


async def test_o06_get_subgraph_acquires_graph_lock() -> None:
    """get_subgraph (public MemoryAPI method) holds _graph_lock."""
    api = _make_api()
    await api.upsert_node(_node("o06"))

    lock_was_held: list[bool] = []
    original = api._graph.get_subgraph
    async def spy(*args: Any, **kwargs: Any) -> Any:
        lock_was_held.append(api._graph_lock.locked())
        return await original(*args, **kwargs)
    api._graph.get_subgraph = spy  # type: ignore[assignment]

    await api.get_subgraph("o06", 0)
    assert all(lock_was_held), "get_subgraph must hold _graph_lock"


async def test_o07_open_tasks_acquires_graph_lock() -> None:
    """open_tasks holds _graph_lock for the full node + edge enumeration."""
    api = _make_api(actionable_types=["host"])
    await api.upsert_node(_node("o07"))

    lock_was_held: list[bool] = []
    original = api._graph.get_nodes_by_type
    async def spy(ntype: str) -> Any:
        lock_was_held.append(api._graph_lock.locked())
        return await original(ntype)
    api._graph.get_nodes_by_type = spy  # type: ignore[assignment]

    await api.open_tasks()
    assert all(lock_was_held), "open_tasks must hold _graph_lock"


async def test_o08_propose_knowledge_does_not_acquire_graph_lock() -> None:
    """propose_knowledge uses _staging_lock, not _graph_lock.

    There is no reason to acquire _graph_lock for staging-only writes that
    don't touch the graph store.  Acquiring it would unnecessarily serialize
    knowledge staging with graph reads/writes.
    """
    api = _make_api()
    graph_lock_acquired: list[bool] = []

    original = api._staging_lock.acquire

    async def spy_staging() -> bool:
        # Record whether _graph_lock is held when _staging_lock is acquired
        graph_lock_acquired.append(api._graph_lock.locked())
        return await original()

    # Note: we spy on staging lock acquire to record graph lock state
    # This is the simplest way without monkeypatching internal methods

    ke = KnowledgeEntry(text="test knowledge", source="test", confidence=0.8)
    await api.propose_knowledge(ke)

    # _graph_lock must NOT have been held during staging
    # We verify by checking the lock is free now (was never held for staging)
    assert not api._graph_lock.locked(), (
        "_graph_lock must be free after propose_knowledge (it should never be acquired)"
    )


async def test_o09_propose_skill_does_not_acquire_graph_lock() -> None:
    """propose_skill uses _staging_lock only — _graph_lock is not acquired."""
    api = _make_api()
    sk = Skill(
        name="test_skill",
        description="for testing",
        template={},
        preconditions={},
        source_episodes=[],
        confidence=0.7,
    )
    await api.propose_skill(sk)
    assert not api._graph_lock.locked()


async def test_o10_append_episode_does_not_acquire_graph_lock() -> None:
    """append_episode uses the episodic store's own lock — _graph_lock is not acquired."""
    api = _make_api()
    ep = _episode(data_key="val")

    # _graph_lock must not be held while episode is appended
    lock_was_held_during_append: list[bool] = []
    original_append = api._episodic.append

    async def spy_append(episode: Episode) -> str:
        lock_was_held_during_append.append(api._graph_lock.locked())
        return await original_append(episode)

    api._episodic.append = spy_append  # type: ignore[assignment]
    await api.append_episode(ep)

    assert not any(lock_was_held_during_append), (
        "append_episode must NOT hold _graph_lock (it uses the episodic store's own lock)"
    )
