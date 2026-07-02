# recon_executor.py
# Recon-phase executor that runs nmap or nc/netcat via the safety-gated runner and dispatches to the right parser based on the task's tool or parser param.
"""Recon-phase executor. Implements memfabric.coordination.protocols.Executor.

Dispatches to the right parser based on ``task.params["tool"]`` or the
explicit ``task.params["parser"]`` key:

  tool == "nmap"       → NmapParser   (host / service / tech nodes)
  tool in nc/netcat    → BannerParser (service / tech nodes from banner)
  anything else        → CommandParser fallback (staged KnowledgeEntry)

Args are passed through **as-is** from task.params["args"] — they must
already be a complete list (target included) as emitted by ReconPlanner.
No target is appended here.  Stateless: nothing is held on self between
run() calls (memfabric Invariant 6).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from memfabric.types import (
    Episode,
    EvidenceBundle,
    ExecutorResult,
    Outcome,
    RawObservation,
    TaskSpec,
)

from apex_host.parsers.banner_parser import BannerParser
from apex_host.parsers.command_parser import CommandParser
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
        self._nmap_parser = NmapParser()
        self._banner_parser = BannerParser()
        self._command_parser = CommandParser()

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        tool = str(task.params.get("tool", "nmap"))
        args = [str(a) for a in task.params.get("args", [])]
        target = str(task.params.get("target", self._config.target))
        parser_name = str(task.params.get("parser", ""))
        port = str(task.params.get("port", ""))

        # args are already complete; never append target a second time
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
                action=f"{tool} {target}",
                outcome=Outcome.fundamental,
                data={"error": str(exc)},
                task_id=task.id,
                phase=task.phase,
            )
            return ExecutorResult(task_id=task.id, episode=episode)

        # Parser dispatch: explicit parser_name takes precedence; tool name is fallback
        if tool == "nmap" or parser_name == "nmap":
            parsed = self._nmap_parser.parse_text(result.stdout, target=target, source=self.domain)
        elif tool in ("nc", "netcat") or parser_name == "banner":
            parsed = self._banner_parser.parse_text(
                result.stdout, target=target, source=tool, port=port
            )
        else:
            raw = RawObservation(raw=result.stdout, metadata={"source": tool, "target": target})
            parsed = self._command_parser.parse(raw)

        outcome = _outcome_for(result.returncode, result.error)

        episode = Episode(
            agent=self.domain,
            action=f"{tool} {' '.join(args)}".strip(),
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
            proposed_knowledge=parsed.proposed_knowledge,
            clue=clue,
        )
