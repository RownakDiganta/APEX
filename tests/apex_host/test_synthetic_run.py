"""Tests for apex_host/eval/run_synthetic_machine.py — the domain-neutral
synthetic-machine evaluation harness (no real network/target involved)."""
from __future__ import annotations

from apex_host.eval.run_synthetic_machine import (
    _make_api,
    run_synthetic_machine,
    seed_synthetic_machine,
)


class TestSyntheticRun:
    async def test_seed_synthetic_machine_populates_graph(self) -> None:
        api = _make_api()
        await seed_synthetic_machine(api)
        subgraph = await api.get_subgraph("host:synthetic.local", depth=2)
        node_types = {n.type for n in subgraph.nodes}
        assert {"host", "service", "endpoint", "auth_flow"} <= node_types

    async def test_run_synthetic_machine_reaches_priv_esc(self) -> None:
        metrics = await run_synthetic_machine(max_turns=1)
        assert metrics.reached_phase == "priv_esc"
        assert metrics.turns_used == 1
        assert metrics.completed is True

    async def test_run_synthetic_machine_is_bounded_by_max_turns(self) -> None:
        metrics = await run_synthetic_machine(max_turns=2)
        assert metrics.turns_used <= 2
        assert metrics.completed is True
