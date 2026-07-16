# priv_esc_analysis_executor.py
# Zero-network, zero-subprocess executor that packages a planner-precomputed analytical opportunity signal into an Episode.
"""Analytical privilege-escalation opportunity executor (Phase 13).

Unlike every other executor in ``apex_host/agents/``, this one never touches
the network, never spawns a subprocess, and never contacts the target in any
way. ``PrivEscPlanner`` derives analytical opportunity candidates entirely
from EKG data it already has (see
``apex_host/planners/priv_esc_opportunities.py::derive_analytical_opportunities``),
but — per the blackboard model (memfabric Invariant 7) — a planner may only
return ``TaskSpec``s, never write to ``MemoryAPI`` directly. This executor is
the minimal, safe bridge: it takes the planner's already-decided fields
(passed verbatim in ``task.params``) and echoes them into an ``Episode`` so
they flow through the same ``parse_observation`` -> ``MemoryAPI.apply_deltas``
path every other tool result uses (memfabric Invariant 1).

Stateless across calls, consistent with every other executor in this
package (memfabric Invariant 6). No dry-run/live distinction is needed —
there is no live/synthetic difference to make, since no I/O of any kind
ever occurs here.
"""
from __future__ import annotations

from memfabric.types import Episode, EvidenceBundle, ExecutorResult, Outcome, TaskSpec


class PrivEscAnalysisExecutor:
    """Stateless executor: echoes a precomputed analytical signal into an Episode."""

    domain: str = "priv_esc"

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        params = task.params
        category = str(params.get("category", ""))
        episode = Episode(
            agent="apex.priv_esc",
            action=f"analyze {category} {params.get('discriminator', '')}".strip(),
            outcome=Outcome.success,
            data={
                "category": category,
                "confidence": str(params.get("confidence", "")),
                "description": str(params.get("description", "")),
                "recommended_next_action": str(params.get("recommended_next_action", "")),
                "discriminator": str(params.get("discriminator", "")),
                "evidence_source": str(params.get("evidence_source", "")),
                "evidence_excerpt": str(params.get("evidence_excerpt", ""))[:200],
                "source_node_id": str(params.get("source_node_id", "")),
                "target": str(params.get("target", "")),
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)
