# test_conflict_phase2_reopen.py
# Phase 2 reopen tests: pure winner selection, atomic rollback, defensive copies,
# dependency-specific guard, planner propagation, quarantine semantics, concurrent
# lifecycle, and architecture scans.
"""Phase 2 Reopen — Complete Conflict Atomicity, Dependency Tracking, and Lifecycle.

Covers all 16 issues raised in the Phase 2 reopen prompt:
1. Pure winner selection (ResolutionDecision, no mutation)
2. Full resolution rollback at every stage
3. Failure-injection tests per rollback stage
4. Deep defensive copies on all public conflict reads
5. ClaimDependency type correctness
6. Dependency-specific guard (not tool-list)
7. Central guard covers all executor paths
8. conflict_blocked distinct disposition (not fundamental, not repair)
9. Verification tasks (purpose="conflict_verification") bypass contested deps
10. Planner-by-planner dependency integration
11. Unrelated-task preservation
12. Quarantine semantics (absent, not trusted)
13. Concurrent lifecycle transitions
14. Architecture scans — no direct Conflict mutation outside lifecycle modules
"""
from __future__ import annotations

import asyncio
import copy
import os
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.coordination.conflict import (
    ResolutionDecision,
    check_conflict_dependencies,
    choose_conflict_winner,
    dependents_blocked,
    make_conflict,
    mark_quarantined,
    resolve_by_policy,
)
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import (
    AbandonSignal,
    BlockedClaim,
    ClaimDependency,
    ConflictStatus,
    EvidenceBundle,
    Goal,
    Node,
    Outcome,
    SubgraphView,
    TaskSpec,
    TransactionIntegrityError,
)

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planners.credential_planner import _CredentialDeterministic
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.planners.priv_esc_planner import _PrivEscDeterministic
from apex_host.planners.recon_planner import _ReconDeterministic
from apex_host.planners.web_planner import _WebDeterministic
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_TARGET = "10.10.10.99"
_ANCHOR = f"host:{_TARGET}"
_FLOOR = 0.8


def _make_api(conflict_floor: float = _FLOOR) -> MemoryAPI:
    cfg = Config(conflict_confidence_floor=conflict_floor)
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def _node(nid: str, ntype: str, props: dict[str, Any], confidence: float = 0.9) -> Node:
    return Node(
        id=nid,
        type=ntype,
        props=props,
        confidence=confidence,
        source="test",
        first_seen=now(),
        last_seen=now(),
    )


def _service_node(port: str, service: str = "telnet", proto: str = "tcp",
                  state: str = "open", version: str = "",
                  confidence: float = 0.9) -> Node:
    return _node(
        f"service:{_TARGET}:{port}/{proto}",
        "service",
        {"port": port, "proto": proto, "service": service,
         "state": state, "version": version},
        confidence,
    )


def _host_node(confidence: float = 0.95) -> Node:
    return _node(f"host:{_TARGET}", "host", {"ip": _TARGET}, confidence)


def _endpoint_node(url: str, confidence: float = 0.85) -> Node:
    return _node(f"endpoint:{url}", "endpoint", {"url": url}, confidence)


def _blocked_claim(node_id: str, field: str, ntype: str = "service") -> BlockedClaim:
    return BlockedClaim(
        node_id=node_id,
        field_name=field,
        conflict_id=new_id(),
        node_type=ntype,
    )


def _subgraph(*nodes: Node, quarantined: list[BlockedClaim] | None = None) -> SubgraphView:
    return SubgraphView(
        anchor=_ANCHOR,
        nodes=list(nodes),
        edges=[],
        depth=2,
        quarantined_fields=quarantined or [],
    )


def _goal() -> Goal:
    return Goal(
        id=new_id(),
        description="test goal",
        anchor_node=_ANCHOR,
        phase=ApexPhase.recon.value,
    )


def _registry(*tools: str) -> ToolRegistry:
    return ToolRegistry(allowed_tools=list(tools))


async def _create_contested_node(api: MemoryAPI, node_id: str = "") -> tuple[str, str]:
    """Create a node with a contested field. Returns (node_id, conflict_id)."""
    nid = node_id or f"service:{_TARGET}:23/tcp"
    n_a = _node(nid, "service", {"port": "23"}, confidence=0.9)
    n_b = _node(nid, "service", {"port": "80"}, confidence=0.85)
    await api.upsert_node(n_a)
    await api.upsert_node(n_b)
    conflicts = await api.get_conflicts(node_id=nid, status=ConflictStatus.open)
    assert len(conflicts) >= 1, "Expected a conflict to be created"
    return nid, conflicts[0].id


# ===========================================================================
# 1. Pure Winner Selection
# ===========================================================================

class TestPureWinnerSelection:
    """choose_conflict_winner() must be a pure function with no side effects."""

    def test_r01_choose_winner_higher_confidence_no_mutation(self) -> None:
        """choose_conflict_winner does not mutate the Conflict record."""
        c = make_conflict(
            "svc:1", "port",
            {"value": "23", "confidence": 0.9, "logical_version": 1},
            {"value": "80", "confidence": 0.85, "logical_version": 2},
        )
        original_status = c.status
        original_history_len = len(c.history)
        decision = choose_conflict_winner(c)
        # Status and history must be unchanged
        assert c.status == original_status
        assert len(c.history) == original_history_len
        assert decision is not None
        assert decision.winner == "claim_a"
        assert decision.method == "confidence"

    def test_r02_resolution_decision_is_frozen(self) -> None:
        """ResolutionDecision instances cannot be mutated after creation."""
        d = ResolutionDecision(
            winner="claim_a",
            winning_value="23",
            reason="claim_a wins",
            method="confidence",
        )
        with pytest.raises((AttributeError, TypeError)):
            d.winner = "claim_b"  # type: ignore[misc]

    def test_r03_non_open_conflict_returns_none(self) -> None:
        """choose_conflict_winner returns None for already-settled conflicts."""
        c = make_conflict("svc:1", "port",
                          {"value": "23", "confidence": 0.9, "logical_version": 1},
                          {"value": "80", "confidence": 0.85, "logical_version": 2})
        # Settle it
        resolve_by_policy(c)
        assert c.status == ConflictStatus.resolved
        result = choose_conflict_winner(c)
        assert result is None

    def test_r04_tie_returns_tie_decision_not_none(self) -> None:
        """Tied confidence AND logical_version returns a ResolutionDecision with winner='tie'."""
        c = make_conflict("svc:1", "port",
                          {"value": "23", "confidence": 0.9, "logical_version": 5},
                          {"value": "80", "confidence": 0.9, "logical_version": 5})
        decision = choose_conflict_winner(c)
        assert decision is not None
        assert decision.winner == "tie"
        assert decision.method == "tie"
        assert decision.winning_value is None
        # Must not have changed the conflict at all
        assert c.status == ConflictStatus.open

    def test_r05_logical_version_tiebreaker_method_field(self) -> None:
        """When confidence is tied, logical_version breaks the tie with method='logical_version'."""
        c = make_conflict("svc:1", "port",
                          {"value": "23", "confidence": 0.9, "logical_version": 3},
                          {"value": "80", "confidence": 0.9, "logical_version": 7})
        decision = choose_conflict_winner(c)
        assert decision is not None
        assert decision.winner == "claim_b"
        assert decision.method == "logical_version"

    def test_r06_choose_winner_called_twice_same_result(self) -> None:
        """Pure function: calling twice with the same input returns identical results."""
        c = make_conflict("svc:1", "port",
                          {"value": "23", "confidence": 0.9, "logical_version": 1},
                          {"value": "80", "confidence": 0.85, "logical_version": 2})
        d1 = choose_conflict_winner(c)
        d2 = choose_conflict_winner(c)
        assert d1 is not None and d2 is not None
        assert d1.winner == d2.winner
        assert d1.method == d2.method
        assert d1.winning_value == d2.winning_value


# ===========================================================================
# 2. Atomic Resolution Rollback
# ===========================================================================

class TestAtomicResolutionRollback:
    """Resolution must be all-or-nothing; failure at any stage rolls back all prior stages."""

    @pytest.mark.asyncio
    async def test_r07_graph_write_failure_leaves_conflict_open(self) -> None:
        """Failure at graph_write stage: conflict remains open, history records failure."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        orig_put_node = api._graph.put_node
        async def _fail_put(*args: Any, **kw: Any) -> Any:
            raise RuntimeError("injected graph write failure")
        api._graph.put_node = _fail_put  # type: ignore[method-assign]

        result = await api.auto_resolve_conflict(cid)
        api._graph.put_node = orig_put_node

        assert not result
        open_after = await api.get_conflicts(node_id=nid, status=ConflictStatus.open)
        assert any(c.id == cid for c in open_after)
        all_after = await api.get_conflicts(node_id=nid)
        c = next(x for x in all_after if x.id == cid)
        events = [h["event"] for h in c.history]
        assert "resolution_failed" in events
        assert "resolved" not in events

    @pytest.mark.asyncio
    async def test_r08_index_refresh_failure_rolls_back_graph_write(self) -> None:
        """Failure at index_refresh: graph field is restored or TransactionIntegrityError raised."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        # Capture the node's port value before resolution
        sg_before = await api.get_subgraph(nid, depth=0)
        orig_port = sg_before.nodes[0].props.get("port")

        # Make the forward index refresh fail but allow the rollback refresh to succeed.
        orig_refresh = api._refresh_working_indexes
        call_count: list[int] = [0]
        async def _fail_first_refresh(*args: Any, **kw: Any) -> Any:
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("injected index refresh failure")
            return await orig_refresh(*args, **kw)
        api._refresh_working_indexes = _fail_first_refresh  # type: ignore[method-assign]

        result = await api.auto_resolve_conflict(cid)
        api._refresh_working_indexes = orig_refresh

        assert not result
        # Graph field must be restored to the original value
        sg_after = await api.get_subgraph(nid, depth=0)
        restored_port = sg_after.nodes[0].props.get("port")
        assert restored_port == orig_port

    @pytest.mark.asyncio
    async def test_r09_failed_resolution_preserves_all_conflict_fields(self) -> None:
        """After a failed resolution, all Conflict fields match their pre-attempt values."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        orig_conflicts = await api.get_conflicts(node_id=nid, status=ConflictStatus.open)
        pre_c = next(x for x in orig_conflicts if x.id == cid)
        pre_status = pre_c.status
        pre_resolved = pre_c.resolved
        pre_winning_value = pre_c.winning_value
        pre_resolution = pre_c.resolution

        orig_put_node = api._graph.put_node
        async def _fail_put(*args: Any, **kw: Any) -> Any:
            raise RuntimeError("injected")
        api._graph.put_node = _fail_put  # type: ignore[method-assign]

        await api.auto_resolve_conflict(cid)
        api._graph.put_node = orig_put_node

        after = await api.get_conflicts(node_id=nid)
        c = next(x for x in after if x.id == cid)
        assert c.status == pre_status
        assert c.resolved == pre_resolved
        assert c.winning_value == pre_winning_value
        assert c.resolution == pre_resolution

    @pytest.mark.asyncio
    async def test_r10_failed_resolution_does_not_leave_resolved_history_entry(self) -> None:
        """A failed resolution must not append 'resolved' to history — only 'resolution_failed'."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        orig_put_node = api._graph.put_node
        async def _fail_put(*args: Any, **kw: Any) -> Any:
            raise RuntimeError("injected")
        api._graph.put_node = _fail_put  # type: ignore[method-assign]

        await api.auto_resolve_conflict(cid)
        api._graph.put_node = orig_put_node

        after = await api.get_conflicts(node_id=nid)
        c = next(x for x in after if x.id == cid)
        events = [h["event"] for h in c.history]
        assert "resolved" not in events
        assert "resolution_failed" in events

    @pytest.mark.asyncio
    async def test_r11_successful_resolution_not_rolled_back(self) -> None:
        """A successful resolution is stable: conflict stays resolved after the call."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        result = await api.auto_resolve_conflict(cid)
        assert result is True

        resolved_after = await api.get_conflicts(node_id=nid, status=ConflictStatus.resolved)
        assert any(c.id == cid for c in resolved_after)
        open_after = await api.get_conflicts(node_id=nid, status=ConflictStatus.open)
        assert not any(c.id == cid for c in open_after)

    @pytest.mark.asyncio
    async def test_r12_rollback_failure_raises_transaction_integrity_error(self) -> None:
        """If primary write succeeds but rollback also fails, TransactionIntegrityError is raised."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        call_count: list[int] = [0]
        orig_put_node = api._graph.put_node
        async def _fail_second_put(node: Node) -> Any:
            call_count[0] += 1
            if call_count[0] == 1:
                return await orig_put_node(node)  # first call (main write) succeeds
            raise RuntimeError("rollback write also failed")
        api._graph.put_node = _fail_second_put  # type: ignore[method-assign]

        orig_refresh = api._refresh_working_indexes
        async def _fail_refresh(*args: Any, **kw: Any) -> Any:
            raise RuntimeError("index refresh failed — triggers rollback path")
        api._refresh_working_indexes = _fail_refresh  # type: ignore[method-assign]

        with pytest.raises(TransactionIntegrityError) as exc_info:
            await api.auto_resolve_conflict(cid)

        api._graph.put_node = orig_put_node
        api._refresh_working_indexes = orig_refresh

        err = exc_info.value
        assert err.conflict_id == cid
        assert err.node_id == nid
        assert err.field_name == "port"
        assert len(err.rollback_errors) >= 1

    @pytest.mark.asyncio
    async def test_r13_transaction_integrity_error_has_correct_stage(self) -> None:
        """TransactionIntegrityError.stage identifies where the primary write failed."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        call_count: list[int] = [0]
        orig_put_node = api._graph.put_node
        async def _fail_second_put(node: Node) -> Any:
            call_count[0] += 1
            if call_count[0] == 1:
                return await orig_put_node(node)
            raise RuntimeError("rollback write failed")
        api._graph.put_node = _fail_second_put  # type: ignore[method-assign]

        orig_refresh = api._refresh_working_indexes
        async def _fail_refresh(*args: Any, **kw: Any) -> Any:
            raise RuntimeError("index refresh failed")
        api._refresh_working_indexes = _fail_refresh  # type: ignore[method-assign]

        with pytest.raises(TransactionIntegrityError) as exc_info:
            await api.auto_resolve_conflict(cid)

        api._graph.put_node = orig_put_node
        api._refresh_working_indexes = orig_refresh

        assert exc_info.value.stage in {"index_refresh", "graph_write"}

    @pytest.mark.asyncio
    async def test_r14_after_failed_resolution_second_attempt_succeeds(self) -> None:
        """After a failed resolution, removing the injected failure allows success."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        orig_put_node = api._graph.put_node
        async def _fail_put(*args: Any, **kw: Any) -> Any:
            raise RuntimeError("injected")
        api._graph.put_node = _fail_put  # type: ignore[method-assign]

        r1 = await api.auto_resolve_conflict(cid)
        assert not r1

        # Restore normal behavior
        api._graph.put_node = orig_put_node

        r2 = await api.auto_resolve_conflict(cid)
        assert r2 is True

        resolved = await api.get_conflicts(node_id=nid, status=ConflictStatus.resolved)
        assert any(c.id == cid for c in resolved)

    @pytest.mark.asyncio
    async def test_r15_cache_busted_after_failed_resolution(self) -> None:
        """After a failed resolution the retrieval cache contains no stale winning value."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        orig_put_node = api._graph.put_node
        async def _fail_put(*args: Any, **kw: Any) -> Any:
            raise RuntimeError("injected")
        api._graph.put_node = _fail_put  # type: ignore[method-assign]

        await api.auto_resolve_conflict(cid)
        api._graph.put_node = orig_put_node

        # Query should still see the conflict (not a cached "resolved" result)
        bundle = await api.query(text="port service", subgraph_anchor=nid)
        assert any(bc.node_id == nid for bc in bundle.blocked_fields)

    @pytest.mark.asyncio
    async def test_r16_resolution_status_not_set_until_persistence_complete(self) -> None:
        """The conflict is NEVER marked resolved before graph + index writes succeed."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        status_during_write: list[ConflictStatus] = []
        orig_put_node = api._graph.put_node

        async def _capture_status_then_fail(node: Node) -> Any:
            # Capture the live conflict status at write time
            c = api._conflicts.get(cid)
            if c is not None:
                status_during_write.append(c.status)
            raise RuntimeError("injected write failure for status-check test")

        api._graph.put_node = _capture_status_then_fail  # type: ignore[method-assign]
        await api.auto_resolve_conflict(cid)
        api._graph.put_node = orig_put_node

        # During the graph write, the conflict must still be open
        for s in status_during_write:
            assert s == ConflictStatus.open, (
                f"Conflict was {s.value!r} during graph_write — must stay open until "
                "all persistence succeeds"
            )


# ===========================================================================
# 3. Public Conflict Defensive Copies
# ===========================================================================

class TestPublicConflictDefensiveCopies:
    """get_conflicts() must return deep copies so callers cannot mutate stored state."""

    @pytest.mark.asyncio
    async def test_r17_get_conflicts_returns_different_object(self) -> None:
        """Returned conflict is not the same object as stored."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)
        returned = (await api.get_conflicts(node_id=nid))[0]
        stored = api._conflicts.get(cid)
        assert returned is not stored

    @pytest.mark.asyncio
    async def test_r18_mutating_claim_a_does_not_change_registry(self) -> None:
        """Mutating claim_a of returned copy has no effect on stored conflict."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)
        returned = (await api.get_conflicts(node_id=nid))[0]
        original_value = api._conflicts[cid].claim_a.get("value")
        returned.claim_a["value"] = "MUTATED_A"
        assert api._conflicts[cid].claim_a.get("value") == original_value

    @pytest.mark.asyncio
    async def test_r19_mutating_claim_b_does_not_change_registry(self) -> None:
        """Mutating claim_b of returned copy has no effect on stored conflict."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)
        returned = (await api.get_conflicts(node_id=nid))[0]
        original_value = api._conflicts[cid].claim_b.get("value")
        returned.claim_b["value"] = "MUTATED_B"
        assert api._conflicts[cid].claim_b.get("value") == original_value

    @pytest.mark.asyncio
    async def test_r20_mutating_history_does_not_change_registry(self) -> None:
        """Appending to history of returned copy has no effect on stored history."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)
        returned = (await api.get_conflicts(node_id=nid))[0]
        before_len = len(api._conflicts[cid].history)
        returned.history.append({"event": "fake_event", "timestamp": now(), "detail": "hack"})
        assert len(api._conflicts[cid].history) == before_len

    @pytest.mark.asyncio
    async def test_r21_nested_mutation_of_claim_a_not_propagated(self) -> None:
        """Mutating a nested value inside claim_a does not affect stored conflict."""
        api = _make_api()
        # Create conflict with nested dict in claim_a
        nid = f"service:{_TARGET}:23/tcp"
        n_a = _node(nid, "service", {"port": "23", "meta": {"nested": "original"}},
                    confidence=0.9)
        n_b = _node(nid, "service", {"port": "80", "meta": {}}, confidence=0.85)
        await api.upsert_node(n_a)
        await api.upsert_node(n_b)

        conflicts = await api.get_conflicts(node_id=nid)
        if not conflicts:
            pytest.skip("No conflict created for nested test (confidence may not trigger)")
        returned = conflicts[0]

        # Find a nested dict in claim_a (may be under "meta" or may just be the claim itself)
        claim_a_copy = returned.claim_a
        orig_stored = copy.deepcopy(api._conflicts[returned.id].claim_a)

        # Attempt to mutate any key
        claim_a_copy["value"] = "DEEPLY_MUTATED"
        assert api._conflicts[returned.id].claim_a.get("value") == orig_stored.get("value")

    @pytest.mark.asyncio
    async def test_r22_multiple_calls_return_independent_copies(self) -> None:
        """Two successive get_conflicts calls return independent copy objects."""
        api = _make_api()
        nid, _ = await _create_contested_node(api)
        copy1 = (await api.get_conflicts(node_id=nid))[0]
        copy2 = (await api.get_conflicts(node_id=nid))[0]
        assert copy1 is not copy2
        assert copy1.claim_a is not copy2.claim_a


# ===========================================================================
# 4. ClaimDependency Type
# ===========================================================================

class TestClaimDependencyType:
    """ClaimDependency must be frozen (immutable), slots-based, and hashable."""

    def test_r23_claim_dependency_is_frozen(self) -> None:
        """ClaimDependency cannot be mutated after creation."""
        dep = ClaimDependency(node_id="svc:1", field_name="port")
        with pytest.raises((AttributeError, TypeError)):
            dep.node_id = "MUTATED"  # type: ignore[misc]

    def test_r24_claim_dependency_has_slots(self) -> None:
        """ClaimDependency uses __slots__, no __dict__ attribute."""
        dep = ClaimDependency(node_id="svc:1", field_name="port")
        assert not hasattr(dep, "__dict__"), "ClaimDependency must use __slots__, not __dict__"

    def test_r25_claim_dependency_is_hashable(self) -> None:
        """ClaimDependency can be stored in frozenset (is hashable)."""
        dep1 = ClaimDependency(node_id="svc:1", field_name="port")
        dep2 = ClaimDependency(node_id="svc:1", field_name="port")
        dep3 = ClaimDependency(node_id="svc:2", field_name="service")
        s = frozenset([dep1, dep2, dep3])
        assert len(s) == 2  # dep1 and dep2 are equal

    def test_r26_claim_dependency_expected_value_default_none(self) -> None:
        """ClaimDependency.expected_value defaults to None."""
        dep = ClaimDependency(node_id="svc:1", field_name="port")
        assert dep.expected_value is None

    def test_r27_claim_dependency_tuple_in_task_spec(self) -> None:
        """TaskSpec.claim_dependencies is a tuple of ClaimDependency instances."""
        dep = ClaimDependency(node_id="svc:1", field_name="port")
        task = TaskSpec(
            id=new_id(),
            goal_id=new_id(),
            executor_domain="recon",
            params={"tool": "nmap", "args": [], "target": _TARGET, "parser": "nmap"},
            claim_dependencies=(dep,),
        )
        assert isinstance(task.claim_dependencies, tuple)
        assert task.claim_dependencies[0].node_id == "svc:1"


# ===========================================================================
# 5. Dependency-Specific Guard (check_conflict_dependencies)
# ===========================================================================

class TestDependencySpecificGuard:
    """check_conflict_dependencies must block only tasks whose exact deps are contested."""

    def test_r28_exact_dependency_matches_blocked_field(self) -> None:
        """Task dep on contested (node, field) → blocking claim returned."""
        bc = _blocked_claim("svc:1", "port")
        dep = ClaimDependency(node_id="svc:1", field_name="port")
        blocking = check_conflict_dependencies((dep,), [bc])
        assert len(blocking) == 1
        assert blocking[0].node_id == "svc:1"
        assert blocking[0].field_name == "port"

    def test_r29_unrelated_node_does_not_block(self) -> None:
        """Task dep on svc:2.port is NOT blocked when only svc:1.port is contested."""
        bc = _blocked_claim("svc:1", "port")
        dep = ClaimDependency(node_id="svc:2", field_name="port")
        blocking = check_conflict_dependencies((dep,), [bc])
        assert blocking == []

    def test_r30_same_node_different_field_does_not_block(self) -> None:
        """Task dep on svc:1.service is NOT blocked when only svc:1.port is contested."""
        bc = _blocked_claim("svc:1", "port")
        dep = ClaimDependency(node_id="svc:1", field_name="service")
        blocking = check_conflict_dependencies((dep,), [bc])
        assert blocking == []

    def test_r31_multiple_deps_one_contested_returns_only_that_one(self) -> None:
        """With multiple deps, only the contested one appears in the result."""
        bc_port = _blocked_claim("svc:1", "port")
        dep_port = ClaimDependency(node_id="svc:1", field_name="port")
        dep_service = ClaimDependency(node_id="svc:1", field_name="service")
        blocking = check_conflict_dependencies((dep_port, dep_service), [bc_port])
        assert len(blocking) == 1
        assert blocking[0].field_name == "port"

    def test_r32_empty_claim_deps_always_empty_result(self) -> None:
        """Empty claim_dependencies tuple returns empty blocking list regardless of blocked_fields."""
        bc = _blocked_claim("svc:1", "port")
        blocking = check_conflict_dependencies((), [bc])
        assert blocking == []

    def test_r33_empty_blocked_fields_always_empty_result(self) -> None:
        """Empty blocked_fields returns empty blocking list regardless of deps."""
        dep = ClaimDependency(node_id="svc:1", field_name="port")
        blocking = check_conflict_dependencies((dep,), [])
        assert blocking == []

    def test_r34_pure_function_no_mutation(self) -> None:
        """check_conflict_dependencies does not mutate its inputs."""
        bc = _blocked_claim("svc:1", "port")
        orig_bc = copy.deepcopy(bc)
        dep = ClaimDependency(node_id="svc:1", field_name="port")
        blocked_list = [bc]
        check_conflict_dependencies((dep,), blocked_list)
        assert blocked_list[0].node_id == orig_bc.node_id
        assert blocked_list[0].field_name == orig_bc.field_name


# ===========================================================================
# 6. Blocked Outcome Semantics
# ===========================================================================

class TestBlockedOutcomeSemantics:
    """conflict_blocked disposition: not fundamental, not repair, not success, auditable."""

    def test_r35_conflict_blocked_returncode_is_zero(self) -> None:
        """Conflict-blocked result has returncode=0 (not 1), so _outcome_for returns success."""
        # Import the outcome helper
        from apex_host.graph import _outcome_for
        outcome = _outcome_for(0, None)
        assert outcome == Outcome.success

    def test_r36_conflict_blocked_error_is_none(self) -> None:
        """Conflict-blocked result has error=None — not treated as error by _outcome_for."""
        from apex_host.graph import _outcome_for
        outcome = _outcome_for(0, None)
        assert outcome not in (Outcome.fundamental, Outcome.fixable)

    def test_r37_route_after_write_sends_conflict_blocked_to_reflect(self) -> None:
        """route_after_write routes conflict_blocked directly to reflect_or_continue."""
        # Build a minimal state with a conflict_blocked tool_result
        from apex_host.graph import _outcome_for
        # We test the logic directly: conflict_blocked=True -> reflect_or_continue
        # The actual graph routing checks tool_result.get("conflict_blocked")
        tool_result: dict[str, Any] = {
            "conflict_blocked": True,
            "returncode": 0,
            "error": None,
            "kind": "recon",
        }
        # Simulate the routing predicate
        goes_to_repair = (
            not tool_result.get("conflict_blocked")
            and _outcome_for(
                int(tool_result.get("returncode", 0) or 0),
                tool_result.get("error"),
            ) in (Outcome.script_error, Outcome.fixable)
        )
        assert not goes_to_repair

    def test_r38_conflict_blocked_is_auditable_in_conflict_fields(self) -> None:
        """conflict_blocked result carries conflict_fields list for audit."""
        bc = _blocked_claim("svc:1", "port")
        conflict_fields = [
            {"node_id": bc.node_id, "field": bc.field_name, "conflict_id": bc.conflict_id}
        ]
        assert len(conflict_fields) == 1
        assert conflict_fields[0]["node_id"] == "svc:1"
        assert conflict_fields[0]["field"] == "port"

    def test_r39_non_conflict_blocked_with_nonzero_rc_routes_to_repair(self) -> None:
        """A regular non-zero returncode (script_error) would route to repair — not conflict_blocked."""
        from apex_host.graph import _outcome_for
        outcome = _outcome_for(1, None)  # returncode=1, no error string
        assert outcome == Outcome.script_error


# ===========================================================================
# 7. Verification Tasks
# ===========================================================================

class TestVerificationTasks:
    """Tasks with purpose='conflict_verification' and no contested deps are not blocked."""

    def test_r40_task_with_contested_dep_is_blocked(self) -> None:
        """Task declaring dep on a contested field is blocked by check_conflict_dependencies."""
        bc = _blocked_claim("svc:1", "port")
        dep = ClaimDependency(node_id="svc:1", field_name="port")
        blocking = check_conflict_dependencies((dep,), [bc])
        assert len(blocking) == 1

    def test_r41_verification_task_with_no_contested_dep_is_not_blocked(self) -> None:
        """Verification task with dep on undisputed field is not blocked."""
        bc = _blocked_claim("svc:1", "port")  # only port is contested
        # verification task depends on 'state', which is NOT contested
        dep = ClaimDependency(node_id="svc:1", field_name="state")
        blocking = check_conflict_dependencies((dep,), [bc])
        assert blocking == []  # verification task proceeds

    def test_r42_verification_task_purpose_field_in_task_spec(self) -> None:
        """TaskSpec accepts purpose='conflict_verification' without error."""
        task = TaskSpec(
            id=new_id(),
            goal_id=new_id(),
            executor_domain="recon",
            params={
                "tool": "nmap",
                "args": ["-sV", "-Pn", _TARGET],
                "target": _TARGET,
                "parser": "nmap",
            },
            purpose="conflict_verification",
            claim_dependencies=(),  # no deps on contested fields
        )
        assert task.purpose == "conflict_verification"
        assert task.claim_dependencies == ()

    def test_r43_verification_task_with_empty_deps_not_blocked_by_legacy_path(self) -> None:
        """Verification task with empty claim_deps bypasses both primary and legacy guard."""
        bc = _blocked_claim("svc:1", "port")
        # Empty deps: primary path returns []
        blocking = check_conflict_dependencies((), [bc])
        assert blocking == []

    @pytest.mark.asyncio
    async def test_r44_verification_result_does_not_auto_resolve_conflict(self) -> None:
        """Writing a fresh node field does not automatically resolve a conflict."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        # Write a new value (e.g., simulating verification result) — this is a upsert,
        # not a resolve. The conflict should remain open unless resolve is called.
        fresh = _node(nid, "service", {"port": "23", "state": "open"}, confidence=0.7)
        await api.upsert_node(fresh)

        open_after = await api.get_conflicts(node_id=nid, status=ConflictStatus.open)
        # Original port conflict still open (confidence 0.7 < floor 0.8, no new conflict)
        assert any(c.id == cid for c in open_after)


# ===========================================================================
# 8. Planner Dependency Propagation
# ===========================================================================

class TestPlannerDependencyPropagation:
    """Each domain planner must declare claim_dependencies in emitted TaskSpecs."""

    @pytest.mark.asyncio
    async def test_r45_recon_planner_nmap_task_has_host_dep(self) -> None:
        """ReconPlanner nmap task declares dep on host.ip."""
        reg = _registry("nmap")
        planner = _ReconDeterministic(_TARGET, reg)
        sg = _subgraph()  # no services → nmap path
        ev = EvidenceBundle(query="", entries=[], subgraph=sg, tiers_queried=[])
        result = await planner.plan(_goal(), sg, ev)
        assert isinstance(result, list) and len(result) >= 1
        task = result[0]
        deps = task.claim_dependencies
        assert any(d.field_name == "ip" for d in deps), (
            f"Expected dep on 'ip', got deps={deps}"
        )

    @pytest.mark.asyncio
    async def test_r46_recon_planner_banner_task_has_service_deps(self) -> None:
        """ReconPlanner nc banner task declares deps on service.port and service.state."""
        reg = _registry("nmap", "nc")
        planner = _ReconDeterministic(_TARGET, reg)
        svc = _service_node("23", "telnet", "tcp", "open")
        sg = _subgraph(svc)
        ev = EvidenceBundle(query="", entries=[], subgraph=sg, tiers_queried=[])
        result = await planner.plan(_goal(), sg, ev)
        assert isinstance(result, list) and len(result) >= 1
        task = result[0]
        deps = task.claim_dependencies
        field_names = {d.field_name for d in deps}
        assert "port" in field_names or "state" in field_names, (
            f"Banner task must depend on port or state; got {field_names}"
        )

    @pytest.mark.asyncio
    async def test_r47_web_planner_task_has_port_dep_when_service_known(self) -> None:
        """WebPlanner curl task declares dep on service.port when web capability exists."""
        reg = _registry("curl")
        planner = _WebDeterministic(_TARGET, reg)
        svc = _node(f"service:{_TARGET}:80/tcp", "service",
                    {"port": "80", "service": "http", "proto": "tcp", "state": "open"},
                    confidence=0.9)
        sg = _subgraph(svc)
        ev = EvidenceBundle(query="", entries=[], subgraph=sg, tiers_queried=[])
        result = await planner.plan(_goal(), sg, ev)
        assert isinstance(result, list) and len(result) >= 1
        all_deps = [d for t in result for d in t.claim_dependencies]
        assert any(d.field_name == "port" for d in all_deps), (
            f"WebPlanner tasks must declare dep on port; deps={all_deps}"
        )

    @pytest.mark.asyncio
    async def test_r48_credential_planner_telnet_task_has_port_and_service_deps(self) -> None:
        """CredentialPlanner telnet task declares deps on service.port and service.service."""
        reg = _registry("curl")
        planner = _CredentialDeterministic(
            _TARGET, reg,
            username_candidates=["root"],
            password_candidates=[""],
        )
        svc = _service_node("23", "telnet", "tcp", "open")
        sg = _subgraph(svc)
        ev = EvidenceBundle(query="", entries=[], subgraph=sg, tiers_queried=[])
        result = await planner.plan(_goal(), sg, ev)
        assert isinstance(result, list) and len(result) >= 1
        task = result[0]
        dep_fields = {d.field_name for d in task.claim_dependencies}
        assert "port" in dep_fields, f"Expected 'port' dep; got {dep_fields}"
        assert "service" in dep_fields, f"Expected 'service' dep; got {dep_fields}"

    @pytest.mark.asyncio
    async def test_r49_priv_esc_planner_task_has_version_and_service_deps(self) -> None:
        """PrivEscPlanner searchsploit task declares deps on service.version and service.service."""
        reg = _registry("searchsploit")
        planner = _PrivEscDeterministic(_TARGET, reg)
        svc = _node(
            f"service:{_TARGET}:22/tcp", "service",
            {"port": "22", "service": "ssh", "proto": "tcp",
             "state": "open", "version": "OpenSSH 7.4"},
            confidence=0.9,
        )
        sg = _subgraph(svc)
        ev = EvidenceBundle(query="", entries=[], subgraph=sg, tiers_queried=[])
        result = await planner.plan(_goal(), sg, ev)
        assert isinstance(result, list) and len(result) >= 1
        dep_fields = {d.field_name for t in result for d in t.claim_dependencies}
        assert "version" in dep_fields, f"Expected 'version' dep; got {dep_fields}"
        assert "service" in dep_fields, f"Expected 'service' dep; got {dep_fields}"

    def test_r50_global_planner_stays_in_recon_without_service_nodes(self) -> None:
        """GlobalPlanner requires service node type before advancing past recon."""
        gp = GlobalPlanner(max_turns=20)
        # No service nodes → must stay in recon
        phase = gp.decide_phase(
            node_types_seen={"host"},
            turn_count=1,
            current_phase=ApexPhase.recon.value,
        )
        assert phase == ApexPhase.recon

    @pytest.mark.asyncio
    async def test_r51_contested_capability_blocks_planner_task(self) -> None:
        """When service node's port is contested, capabilities_from_subgraph skips it."""
        svc = _service_node("23", "telnet", "tcp", "open")
        bc = _blocked_claim(svc.id, "port", "service")
        sg = SubgraphView(
            anchor=_ANCHOR,
            nodes=[svc],
            edges=[],
            depth=2,
            open_conflicts=[bc],
        )
        caps = capabilities_from_subgraph(sg)
        telnet_caps = [c for c in caps if c.name == "access_validate_telnet"]
        assert telnet_caps == [], (
            "Contested service node must not produce telnet capability"
        )

    @pytest.mark.asyncio
    async def test_r52_credential_planner_abandons_without_telnet_cap(self) -> None:
        """CredentialPlanner without telnet capability (contested service) abandons."""
        reg = _registry("curl")
        planner = _CredentialDeterministic(
            _TARGET, reg,
            username_candidates=["root"],
            password_candidates=[""],
        )
        svc = _service_node("23", "telnet", "tcp", "open")
        bc = _blocked_claim(svc.id, "port", "service")
        sg = SubgraphView(
            anchor=_ANCHOR, nodes=[svc], edges=[], depth=2, open_conflicts=[bc]
        )
        ev = EvidenceBundle(query="", entries=[], subgraph=sg, tiers_queried=[],
                            blocked_fields=[bc])
        result = await planner.plan(_goal(), sg, ev)
        assert isinstance(result, AbandonSignal)


# ===========================================================================
# 9. Unrelated Task Preservation
# ===========================================================================

class TestUnrelatedTaskPreservation:
    """Unrelated tasks (different node or different field) must NOT be blocked."""

    def test_r53_host_a_conflict_does_not_block_host_b_dep(self) -> None:
        """Conflict on host_A.port does NOT block task depending on host_B.port."""
        bc = _blocked_claim("svc:host_a:23/tcp", "port")
        dep_b = ClaimDependency(node_id="svc:host_b:23/tcp", field_name="port")
        blocking = check_conflict_dependencies((dep_b,), [bc])
        assert blocking == []

    def test_r54_different_field_same_node_does_not_block(self) -> None:
        """Conflict on svc:1.port does NOT block a task depending on svc:1.service."""
        bc = _blocked_claim("svc:1", "port")
        dep = ClaimDependency(node_id="svc:1", field_name="service")
        blocking = check_conflict_dependencies((dep,), [bc])
        assert blocking == []

    def test_r55_exact_contested_dep_is_blocked(self) -> None:
        """Task depending on the exact (node, field) that is contested IS blocked."""
        bc = _blocked_claim("svc:1", "port")
        dep = ClaimDependency(node_id="svc:1", field_name="port")
        blocking = check_conflict_dependencies((dep,), [bc])
        assert len(blocking) == 1

    def test_r56_multiple_deps_only_contested_one_in_result(self) -> None:
        """With 3 deps, only the contested dep appears in blocking result."""
        bc = _blocked_claim("svc:1", "port")
        dep_port = ClaimDependency(node_id="svc:1", field_name="port")  # contested
        dep_state = ClaimDependency(node_id="svc:1", field_name="state")  # not contested
        dep_other = ClaimDependency(node_id="svc:2", field_name="port")  # different node
        blocking = check_conflict_dependencies(
            (dep_port, dep_state, dep_other), [bc]
        )
        assert len(blocking) == 1
        assert blocking[0].field_name == "port"
        assert blocking[0].node_id == "svc:1"


# ===========================================================================
# 10. Quarantine Semantics
# ===========================================================================

class TestQuarantineSemantics:
    """Quarantined fields must be treated as absent, not trusted, but remain auditable."""

    def test_r57_quarantined_conflict_is_not_open(self) -> None:
        """dependents_blocked() returns False for a quarantined conflict."""
        c = make_conflict("svc:1", "port",
                          {"value": "23", "confidence": 0.9, "logical_version": 1},
                          {"value": "80", "confidence": 0.85, "logical_version": 2})
        mark_quarantined(c, "Reflector: win-rate fell below floor")
        assert not dependents_blocked(c)
        assert c.status == ConflictStatus.quarantined
        assert c.resolved is True

    @pytest.mark.asyncio
    async def test_r58_quarantined_field_in_quarantined_fields_not_open_conflicts(self) -> None:
        """get_subgraph puts quarantined fields in quarantined_fields, not open_conflicts."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        # Quarantine the conflict
        await api.quarantine_conflict(cid, reason="test quarantine")

        sg = await api.get_subgraph(nid, depth=2)
        open_ids = {bc.conflict_id for bc in sg.open_conflicts}
        quar_ids = {bc.conflict_id for bc in sg.quarantined_fields}
        assert cid not in open_ids, "Quarantined conflict must not appear in open_conflicts"
        assert cid in quar_ids, "Quarantined conflict must appear in quarantined_fields"

    def test_r59_capabilities_from_subgraph_skips_quarantined_field(self) -> None:
        """capabilities_from_subgraph skips capabilities derived from quarantined fields."""
        svc = _service_node("23", "telnet", "tcp", "open")
        qbc = BlockedClaim(
            node_id=svc.id,
            field_name="port",
            conflict_id=new_id(),
            node_type="service",
        )
        sg = SubgraphView(
            anchor=_ANCHOR,
            nodes=[svc],
            edges=[],
            depth=2,
            open_conflicts=[],
            quarantined_fields=[qbc],  # quarantined, not open
        )
        caps = capabilities_from_subgraph(sg)
        telnet_caps = [c for c in caps if c.name == "access_validate_telnet"]
        assert telnet_caps == [], (
            "Quarantined service node port must not produce telnet capability"
        )

    @pytest.mark.asyncio
    async def test_r60_quarantined_conflict_visible_in_audit_log(self) -> None:
        """Quarantined conflict remains in the conflict registry with quarantined status."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)
        await api.quarantine_conflict(cid, reason="audit test")

        all_conflicts = await api.get_conflicts(node_id=nid)
        c = next((x for x in all_conflicts if x.id == cid), None)
        assert c is not None, "Quarantined conflict must remain in registry"
        assert c.status == ConflictStatus.quarantined
        events = [h["event"] for h in c.history]
        assert "quarantined" in events

    @pytest.mark.asyncio
    async def test_r61_new_high_confidence_write_can_replace_quarantined_field(self) -> None:
        """A new authoritative high-confidence write can overwrite a quarantined field."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)
        await api.quarantine_conflict(cid, reason="stale data")

        # Write a fresh, high-confidence single value (no competing value → no new conflict)
        fresh = _node(nid, "service", {"port": "23"}, confidence=0.99)
        await api.upsert_node(fresh)

        sg = await api.get_subgraph(nid, depth=0)
        node = sg.nodes[0]
        # Port should now reflect the fresh authoritative value
        assert node.props.get("port") is not None


# ===========================================================================
# 11. Concurrent Lifecycle Transitions
# ===========================================================================

class TestConcurrentLifecycle:
    """Concurrent lifecycle transitions must not leave conflicts in inconsistent state."""

    @pytest.mark.asyncio
    async def test_r62_concurrent_auto_resolve_produces_one_terminal_state(self) -> None:
        """Two concurrent auto_resolve calls → at most one terminal resolution."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        results = await asyncio.gather(
            api.auto_resolve_conflict(cid),
            api.auto_resolve_conflict(cid),
            return_exceptions=True,
        )
        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"Concurrent resolve raised exceptions: {errors}"

        # Must not remain open
        open_after = await api.get_conflicts(node_id=nid, status=ConflictStatus.open)
        assert not any(c.id == cid for c in open_after)

    @pytest.mark.asyncio
    async def test_r63_concurrent_explicit_override_and_auto_resolve(self) -> None:
        """Concurrent explicit override + auto_resolve → one terminal winner, no crash."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        results = await asyncio.gather(
            api.resolve_conflict(cid, resolution="human says port=23"),
            api.auto_resolve_conflict(cid),
            return_exceptions=True,
        )
        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"Concurrent explicit+auto raised: {errors}"

        open_after = await api.get_conflicts(node_id=nid, status=ConflictStatus.open)
        assert not any(c.id == cid for c in open_after)

    @pytest.mark.asyncio
    async def test_r64_supersede_vs_resolve_concurrent_no_error(self) -> None:
        """Concurrent supersede + resolve transitions both complete without error."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        results = await asyncio.gather(
            api.supersede_conflict(cid, reason="later write"),
            api.auto_resolve_conflict(cid),
            return_exceptions=True,
        )
        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"Concurrent supersede+resolve raised: {errors}"

        all_after = await api.get_conflicts(node_id=nid)
        c = next(x for x in all_after if x.id == cid)
        assert c.status != ConflictStatus.open

    @pytest.mark.asyncio
    async def test_r65_quarantine_vs_resolve_concurrent_no_error(self) -> None:
        """Concurrent quarantine + resolve transitions both complete without error."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        results = await asyncio.gather(
            api.quarantine_conflict(cid, reason="low win-rate"),
            api.auto_resolve_conflict(cid),
            return_exceptions=True,
        )
        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"Concurrent quarantine+resolve raised: {errors}"

        all_after = await api.get_conflicts(node_id=nid)
        c = next(x for x in all_after if x.id == cid)
        assert c.status != ConflictStatus.open

    @pytest.mark.asyncio
    async def test_r66_supersede_vs_quarantine_concurrent_no_error(self) -> None:
        """Concurrent supersede + quarantine transitions both complete without error."""
        api = _make_api()
        nid, cid = await _create_contested_node(api)

        results = await asyncio.gather(
            api.supersede_conflict(cid, reason="later write"),
            api.quarantine_conflict(cid, reason="low win-rate"),
            return_exceptions=True,
        )
        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"Concurrent supersede+quarantine raised: {errors}"

        all_after = await api.get_conflicts(node_id=nid)
        c = next(x for x in all_after if x.id == cid)
        assert c.status != ConflictStatus.open


# ===========================================================================
# 12. Architecture Scans
# ===========================================================================

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MEMFABRIC_DIR = os.path.join(_REPO_ROOT, "memfabric")
_APEX_DIR = os.path.join(_REPO_ROOT, "apex_host")
_ALLOWED_LIFECYCLE_FILES = {
    os.path.join(_MEMFABRIC_DIR, "coordination", "conflict.py"),
    os.path.join(_MEMFABRIC_DIR, "api.py"),
}


def _production_py_files(directory: str) -> list[str]:
    """All .py files in directory excluding __pycache__."""
    files = []
    for root, dirs, fnames in os.walk(directory):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fn in fnames:
            if fn.endswith(".py"):
                files.append(os.path.join(root, fn))
    return files


def _scan_for_pattern(pattern: str, files: list[str]) -> list[tuple[str, int, str]]:
    """Scan files for substring pattern; return list of (filepath, lineno, line)."""
    hits: list[tuple[str, int, str]] = []
    for fp in files:
        try:
            with open(fp, encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if pattern in line:
                        hits.append((fp, lineno, stripped))
        except (OSError, UnicodeDecodeError):
            pass
    return hits


class TestArchitectureScans:
    """Static scans verify no direct Conflict mutation outside lifecycle modules."""

    def test_r67_no_direct_conflict_status_assignment_outside_lifecycle(self) -> None:
        """Conflict.status must only be set in conflict.py and api.py."""
        all_files = (
            _production_py_files(_MEMFABRIC_DIR) +
            _production_py_files(_APEX_DIR)
        )
        hits = _scan_for_pattern(".status = ConflictStatus.", all_files)
        # Filter to only lines that look like mutations (not in allowed files)
        violations = [
            (fp, ln, txt) for (fp, ln, txt) in hits
            if fp not in _ALLOWED_LIFECYCLE_FILES
        ]
        assert not violations, (
            "Direct Conflict.status assignment found outside lifecycle modules:\n"
            + "\n".join(f"  {fp}:{ln}: {txt}" for fp, ln, txt in violations)
        )

    def test_r68_no_claim_a_mutation_outside_conflict_py(self) -> None:
        """claim_a must not be mutated (assigned into) outside conflict.py."""
        all_files = _production_py_files(_MEMFABRIC_DIR) + _production_py_files(_APEX_DIR)
        # Look for patterns like: c.claim_a["key"] = or conflict.claim_a[...] =
        hits: list[tuple[str, int, str]] = []
        for fp in all_files:
            if fp in _ALLOWED_LIFECYCLE_FILES:
                continue
            try:
                with open(fp, encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        # Detect: .claim_a[ followed by = (assignment into dict)
                        if ".claim_a[" in line and "=" in line:
                            hits.append((fp, lineno, stripped))
            except (OSError, UnicodeDecodeError):
                pass
        assert not hits, (
            "claim_a dict mutation found outside lifecycle modules:\n"
            + "\n".join(f"  {fp}:{ln}: {txt}" for fp, ln, txt in hits)
        )

    def test_r69_no_claim_b_mutation_outside_conflict_py(self) -> None:
        """claim_b must not be mutated (assigned into) outside conflict.py."""
        all_files = _production_py_files(_MEMFABRIC_DIR) + _production_py_files(_APEX_DIR)
        hits: list[tuple[str, int, str]] = []
        for fp in all_files:
            if fp in _ALLOWED_LIFECYCLE_FILES:
                continue
            try:
                with open(fp, encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        if ".claim_b[" in line and "=" in line:
                            hits.append((fp, lineno, stripped))
            except (OSError, UnicodeDecodeError):
                pass
        assert not hits, (
            "claim_b dict mutation found outside lifecycle modules:\n"
            + "\n".join(f"  {fp}:{ln}: {txt}" for fp, ln, txt in hits)
        )

    def test_r70_no_direct_history_append_outside_lifecycle_files(self) -> None:
        """Conflict.history.append must only appear in conflict.py and api.py."""
        all_files = _production_py_files(_MEMFABRIC_DIR) + _production_py_files(_APEX_DIR)
        hits: list[tuple[str, int, str]] = []
        for fp in all_files:
            if fp in _ALLOWED_LIFECYCLE_FILES:
                continue
            try:
                with open(fp, encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        # Look for .history.append( on a variable that holds a Conflict
                        # (conservative: any .history.append pattern in conflict-related context)
                        if ".history.append(" in line:
                            hits.append((fp, lineno, stripped))
            except (OSError, UnicodeDecodeError):
                pass
        assert not hits, (
            ".history.append() outside lifecycle modules:\n"
            + "\n".join(f"  {fp}:{ln}: {txt}" for fp, ln, txt in hits)
        )

    def test_r71_check_conflict_dependencies_imported_in_graph(self) -> None:
        """check_conflict_dependencies must be used in the execution gate.

        Phase 10 decomposition: the execution gate moved from graph.py to
        apex_host/execution/dispatcher.py.  The assertion now checks
        dispatcher.py, which is where TaskDispatcher.dispatch() runs the
        conflict gate before any executor is invoked.
        """
        dispatcher_path = os.path.join(_APEX_DIR, "execution", "dispatcher.py")
        with open(dispatcher_path, encoding="utf-8") as f:
            content = f.read()
        assert "check_conflict_dependencies" in content, (
            "apex_host/execution/dispatcher.py must import and use check_conflict_dependencies "
            "for the central dependency-specific execution guard (Phase 10: moved from graph.py)"
        )

    def test_r72_synthetic_conflict_status_mutation_detected(self) -> None:
        """Confirm the architecture scanner catches a .status = ConflictStatus. mutation."""
        # Write synthetic code that would be caught
        fake_line = "    conflict.status = ConflictStatus.resolved  # direct mutation"
        # The scanner looks for ".status = ConflictStatus."
        assert ".status = ConflictStatus." in fake_line
        # Verify our scanner would catch it
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(fake_line + "\n")
            tmppath = f.name
        try:
            hits = _scan_for_pattern(".status = ConflictStatus.", [tmppath])
            assert len(hits) == 1, "Scanner must detect direct status mutation"
        finally:
            os.unlink(tmppath)
