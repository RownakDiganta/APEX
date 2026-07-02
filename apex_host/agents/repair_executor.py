# repair_executor.py
# Repair executor that synthesises a low-confidence repair suggestion from a failed task's clue without re-running any tool.
"""Repair executor. Implements memfabric.coordination.protocols.Executor.

Handles tasks routed to the "repair" domain after a script_error/fixable
outcome. It never re-runs a tool itself — it only synthesises a low-
confidence repair suggestion (as a staged KnowledgeEntry) from the clue
attached to the failed task. Actual retries of the original command happen
through the normal dispatch-retry path in memfabric's coordination loop,
which re-invokes the *original* executor with the clue folded into params;
this executor exists for explicit repair tasks a planner may emit when it
wants the suggestion to be reviewed before another tool run.
"""
from __future__ import annotations

from memfabric.types import EvidenceBundle, Episode, ExecutorResult, KnowledgeEntry, Outcome, TaskSpec


class RepairExecutor:
    domain: str = "repair"

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        clue = str(task.params.get("clue", ""))
        original_tool = str(task.params.get("tool", "unknown"))

        if clue:
            suggestion = f"Retry {original_tool} with adjusted parameters based on clue: {clue}"
        else:
            suggestion = f"No clue available for failed task {task.id}; manual review needed"

        episode = Episode(
            agent=self.domain,
            action=f"repair {original_tool}",
            outcome=Outcome.success,
            data={"clue": clue, "suggestion": suggestion, "original_task_id": task.id},
            task_id=task.id,
            phase=task.phase,
        )
        knowledge = KnowledgeEntry(
            text=suggestion,
            source=self.domain,
            confidence=0.4,
            metadata={
                "tier": "semantic",
                "kind": "repair_suggestion",
                "original_task_id": task.id,
            },
        )
        return ExecutorResult(task_id=task.id, episode=episode, proposed_knowledge=[knowledge])
