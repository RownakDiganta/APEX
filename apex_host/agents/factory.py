# factory.py
# Minimal dynamic-agent factory: a planner registers AgentSpec "types" as data and the orchestrator builds stateless agents from them on demand.
"""Minimal dynamic-agent factory.

This is the smallest thing that lets a planner *create specific agents
dynamically* without breaking any memfabric invariant:

- An agent **type** is data (an ``AgentSpec``), never generated code — so
  registering a new type is a validated dict write, not a class definition.
- An agent **instance** is a stateless ``DynamicAgent`` built by the factory
  on demand (memfabric Invariant 6 — nothing is held across ``run()`` calls).
- Agents are never called by other agents.  A planner (or a running agent)
  *requests* a child by emitting a ``TaskSpec`` into the fabric via
  ``spawn_task``; the orchestrator materialises it with the factory
  (blackboard model, memfabric Invariant 7).
- Every command still goes through ``apex_host/tools/runner.py`` (safety-gated,
  dry-run aware).  A spec's ``allowed_tools`` is a *narrower* per-agent gate on
  top of the global ``ApexConfig.allowed_tools`` allowlist — it can only
  restrict, never widen.

The recursion the tree needs is bounded: ``spawn_task`` refuses to create a
child past ``max_depth``, so ``orchestrator -> a -> b -> ...`` cannot run away.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from memfabric.ids import new_id
from memfabric.types import (
    Episode,
    EvidenceBundle,
    ExecutorResult,
    Outcome,
    ParsedObservation,
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
    from memfabric.api import MemoryAPI


def _outcome_for(returncode: int, error: str | None) -> Outcome:
    if error:
        return Outcome.fixable if "timed out" in error else Outcome.fundamental
    if returncode != 0:
        return Outcome.script_error
    return Outcome.success


@dataclass(slots=True, frozen=True)
class AgentSpec:
    """An agent *type*, expressed purely as data.

    name:          unique type name; also the ``executor_domain`` a TaskSpec
                   targets to reach an agent of this type.
    allowed_tools: per-agent tool allowlist (must be a subset of the global
                   ApexConfig allowlist — this narrows, never widens).
    parser:        which parser turns this agent's stdout into EKG deltas
                   ("command" | "nmap" | "banner").
    max_depth:     deepest spawn level this type may be created at.
    may_spawn:     child type names this agent is permitted to request.
    """

    name: str
    allowed_tools: frozenset[str]
    parser: str = "command"
    max_depth: int = 2
    may_spawn: frozenset[str] = frozenset()


class AgentRegistry:
    """Holds AgentSpec types.  Register new types at runtime; look them up by name."""

    def __init__(self) -> None:
        self._specs: dict[str, AgentSpec] = {}

    def register(self, spec: AgentSpec) -> None:
        self._specs[spec.name] = spec

    def get(self, name: str) -> AgentSpec | None:
        return self._specs.get(name)

    def names(self) -> list[str]:
        return list(self._specs)


class DynamicAgent:
    """A stateless executor built from an AgentSpec.

    Implements the memfabric ``Executor`` protocol (``domain`` + ``run``).
    Writes nothing to memory itself (Invariant 1) — it returns EKG deltas that
    the orchestrator persists.
    """

    def __init__(self, spec: AgentSpec, config: "ApexConfig") -> None:
        self._spec = spec
        self._config = config
        self._nmap = NmapParser()
        self._banner = BannerParser()
        self._command = CommandParser()

    @property
    def domain(self) -> str:
        return self._spec.name

    async def run(self, task: TaskSpec, evidence: EvidenceBundle) -> ExecutorResult:
        tool = str(task.params.get("tool", ""))
        args = [str(a) for a in task.params.get("args", [])]
        target = str(task.params.get("target", self._config.target))
        depth = int(task.params.get("depth", 0))

        # Per-agent allowlist gate (narrower than the global safety allowlist).
        if tool not in self._spec.allowed_tools:
            return self._fail(
                task, f"tool {tool!r} not permitted for agent {self._spec.name!r}"
            )

        cmd = ToolCommand(
            tool=tool, args=args, timeout_seconds=self._config.max_command_seconds
        )
        try:
            result = await run_command(cmd, self._config)
        except ValueError as exc:  # safety-gate rejection
            return self._fail(task, str(exc))

        parsed = self._parse(result.stdout, target=target, port=str(task.params.get("port", "")))
        outcome = _outcome_for(result.returncode, result.error)
        episode = Episode(
            agent=self._spec.name,
            action=f"{tool} {' '.join(args)}".strip(),
            outcome=outcome,
            data={
                "tool": tool,
                "stdout": result.stdout[:1000],
                "returncode": result.returncode,
                "dry_run": result.dry_run,
                "error": result.error,
                "depth": depth,
            },
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(
            task_id=task.id,
            episode=episode,
            node_deltas=parsed.node_deltas,
            edge_deltas=parsed.edge_deltas,
            proposed_knowledge=parsed.proposed_knowledge,
        )

    def _parse(self, stdout: str, *, target: str, port: str) -> ParsedObservation:
        if self._spec.parser == "nmap":
            return self._nmap.parse_text(stdout, target=target, source=self._spec.name)
        if self._spec.parser == "banner":
            return self._banner.parse_text(
                stdout, target=target, source=self._spec.name, port=port
            )
        raw = RawObservation(raw=stdout, metadata={"source": self._spec.name, "target": target})
        return self._command.parse(raw)

    def _fail(self, task: TaskSpec, error: str) -> ExecutorResult:
        episode = Episode(
            agent=self._spec.name,
            action=f"reject {task.params.get('tool', '')}".strip(),
            outcome=Outcome.fundamental,
            data={"error": error},
            task_id=task.id,
            phase=task.phase,
        )
        return ExecutorResult(task_id=task.id, episode=episode)


class AgentFactory:
    """Builds a stateless DynamicAgent from a registered AgentSpec on demand."""

    def __init__(self, registry: AgentRegistry, config: "ApexConfig") -> None:
        self._registry = registry
        self._config = config

    def create(self, name: str, *, depth: int = 0) -> DynamicAgent | None:
        """Return an agent of type *name*, or None if the type is unknown or
        the requested *depth* exceeds the type's ``max_depth``."""
        spec = self._registry.get(name)
        if spec is None or depth > spec.max_depth:
            return None
        return DynamicAgent(spec, self._config)


def spawn_task(
    child_type: str,
    *,
    tool: str,
    args: list[str],
    target: str,
    goal_id: str,
    parser: str = "command",
    parent_depth: int = 0,
    max_depth: int = 2,
    anchor: str | None = None,
    phase: str | None = None,
) -> TaskSpec | None:
    """Build a spawn-request TaskSpec for a child agent, or None past max_depth.

    This is how a planner (or a running agent) *requests* a more specialised
    child without ever calling it directly — the returned TaskSpec is fabric
    data the orchestrator dispatches via ``dispatch_agent``.
    """
    child_depth = parent_depth + 1
    if child_depth > max_depth:
        return None
    return TaskSpec(
        id=new_id(),
        goal_id=goal_id,
        executor_domain=child_type,
        params={
            "tool": tool,
            "args": args,
            "target": target,
            "parser": parser,
            "depth": child_depth,
        },
        subgraph_anchor=anchor,
        phase=phase,
    )


async def dispatch_agent(
    task: TaskSpec,
    factory: AgentFactory,
    api: "MemoryAPI",
    evidence: EvidenceBundle,
) -> ExecutorResult | None:
    """Materialise the agent named by ``task.executor_domain`` and run it, then
    persist its deltas through MemoryAPI (the ONLY memory write, Invariant 1).

    Returns the ExecutorResult, or None if the requested type/depth is invalid.
    """
    agent = factory.create(task.executor_domain, depth=int(task.params.get("depth", 0)))
    if agent is None:
        return None
    result = await agent.run(task, evidence)
    await api.apply_deltas(
        nodes=result.node_deltas,
        edges=result.edge_deltas,
        episodes=[result.episode],
        knowledge=result.proposed_knowledge,
    )
    return result
