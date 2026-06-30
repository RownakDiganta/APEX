"""Recon-phase executor. Implements memfabric.coordination.protocols.Executor.

Runs a safe enumeration tool (nmap, per ReconPlanner) through
apex_host/tools/runner.py — safety-checked, dry-run aware — and parses the
result into EKG deltas via NmapParser. Stateless: all state for the next
call comes from the TaskSpec/EvidenceBundle, nothing is held on self
between run() calls (memfabric Invariant 6).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from memfabric.types import EvidenceBundle, Episode, ExecutorResult, Outcome, TaskSpec

from apex_host.parsers.nmap_parser import NmapParser
from apex_host.tools.runner import run_command
from apex_host.types import ToolCommand

if TYPE_CHECKING:
    from apex_host.config import ApexConfig


def _outcome_for(returncode: int, error: str | None) -> Outcome:
    if error:
        return Outcome.fixable if "timed out" in error else Outcome.fundamental
    if returncode != 0:
        return Outcome.script_error
    return Outcome.success


class ReconExecutor:
    domain: str = "recon"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config
        self._parser = NmapParser()

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        tool = str(task.params.get("tool", "nmap"))
        args = [str(a) for a in task.params.get("args", [])]
        target = str(task.params.get("target", self._config.target))

        cmd = ToolCommand(
            tool=tool,
            args=[*args, target],
            timeout_seconds=self._config.max_command_seconds,
        )

        try:
            result = await run_command(cmd, self._config)
        except ValueError as exc:
            episode = Episode(
                agent=self.domain,
                action=f"{tool} {target}",
                outcome=Outcome.fundamental,
                data={"error": str(exc)},
                task_id=task.id,
                phase=task.phase,
            )
            return ExecutorResult(task_id=task.id, episode=episode)

        parsed = self._parser.parse_text(result.stdout, target=target, source=self.domain)
        outcome = _outcome_for(result.returncode, result.error)

        episode = Episode(
            agent=self.domain,
            action=f"{tool} {' '.join(args)} {target}".strip(),
            outcome=outcome,
            data={
                "tool": tool,
                "stdout": result.stdout[:1000],
                "returncode": result.returncode,
                "dry_run": result.dry_run,
                "error": result.error,
            },
            task_id=task.id,
            phase=task.phase,
        )

        clue = result.error if outcome == Outcome.fixable else None
        return ExecutorResult(
            task_id=task.id,
            episode=episode,
            node_deltas=parsed.node_deltas,
            edge_deltas=parsed.edge_deltas,
            clue=clue,
        )
