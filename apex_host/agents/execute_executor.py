# execute_executor.py
# Generic bounded-command executor that dispatches allowlisted tools through the safety-gated runner for web, credential, and priv_esc phases.
"""Generic bounded-command executor for the web/credential/priv_esc phases.

Implements memfabric.coordination.protocols.Executor. Dispatches the parser
named in task.params["parser"] (ffuf/gobuster/command) and always runs the
command through apex_host/tools/runner.py — the only place a subprocess may
be spawned. Bounded execution only: no destructive commands (enforced by
tools/safety.py at the runner layer) and no autonomous exploit decisions.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from memfabric.types import (
    EvidenceBundle,
    Episode,
    ExecutorResult,
    Outcome,
    ParsedObservation,
    RawObservation,
    TaskSpec,
)

from apex_host.parsers.command_parser import CommandParser
from apex_host.parsers.ffuf_parser import FfufParser
from apex_host.parsers.gobuster_parser import GobusterParser
from apex_host.tools.runner import run_command
from apex_host.types import ToolCommand

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

_FFUF = FfufParser()
_GOBUSTER = GobusterParser()
_COMMAND = CommandParser()


def _outcome_for(returncode: int, error: str | None) -> Outcome:
    if error:
        return Outcome.fixable if "timed out" in error else Outcome.fundamental
    if returncode != 0:
        return Outcome.script_error
    return Outcome.success


class ExecuteExecutor:
    """Bound to multiple executor_domain keys ("web", "priv_esc",
    "credential") in apex_host/runtime.py — one instance serves all three,
    since the work is identical: run an allowlisted tool, parse its output."""

    domain: str = "execute"

    def __init__(self, config: "ApexConfig") -> None:
        self._config = config

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        tool = str(task.params.get("tool", ""))
        args = [str(a) for a in task.params.get("args", [])]
        target = str(task.params.get("target", self._config.target))
        parser_name = str(task.params.get("parser", "command"))

        cmd = ToolCommand(
            tool=tool,
            args=args,
            timeout_seconds=self._config.max_command_seconds,
        )

        try:
            result = await run_command(cmd, self._config)
        except ValueError as exc:
            episode = Episode(
                agent=self.domain,
                action=f"{tool}",
                outcome=Outcome.fundamental,
                data={"error": str(exc)},
                task_id=task.id,
                phase=task.phase,
            )
            return ExecutorResult(task_id=task.id, episode=episode)

        parsed = self._parse(parser_name, result.stdout, target=target, tool=tool)
        outcome = _outcome_for(result.returncode, result.error)

        episode = Episode(
            agent=self.domain,
            action=f"{tool} {' '.join(args)}".strip(),
            outcome=outcome,
            data={
                "tool": tool,
                "parser": parser_name,
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
            proposed_knowledge=parsed.proposed_knowledge,
            clue=clue,
        )

    def _parse(
        self, parser_name: str, stdout: str, *, target: str, tool: str
    ) -> ParsedObservation:
        if parser_name == "ffuf":
            return _FFUF.parse_text(stdout, target=target)
        if parser_name == "gobuster":
            return _GOBUSTER.parse_text(stdout, target=target)
        raw = RawObservation(raw=stdout, metadata={"source": tool, "target": target})
        return _COMMAND.parse(raw)
