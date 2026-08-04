# recon_planner.py
# Deterministic two-phase recon planner with an optional PlanningEngine LLM seam.
"""Deterministic recon-phase planner with optional LLM backend.

``_ReconDeterministic`` contains the original rule-based logic — two phases
driven entirely by the SubgraphView passed in, no direct MemoryAPI calls
(blackboard model, Invariant 7).

``ReconPlanner`` is the public thin wrapper: when a ``model_router`` is
provided it constructs a ``PlanningEngine`` and routes through it; otherwise
it delegates directly to ``_ReconDeterministic``.  The public ``plan()``
signature is identical in both cases so ``graph.py`` needs no changes.

Two-pass deterministic logic (§25.6):

Phase 1 — no service nodes in subgraph:
    Emit one fast, bounded port-DISCOVERY scan
    (``nmap [-sT] -Pn -T4 --top-ports N --max-retries 2 --host-timeout <bound>
    <target>``) — NO ``-sV``, so it completes within the timeout instead of a
    full 1000-port version scan that times out over VPN latency.

Phase 2 — service nodes exist but none have version info yet:
    Emit a separate, smaller ``-sV`` scan on ONLY the discovered open ports
    (``nmap [-sT] -Pn -sV -p <open-ports> --max-retries 2 --host-timeout
    <bound> <target>``). Once versions are populated, recon moves on.

Phase 3 — service nodes with version info exist:
    Derive capabilities from the subgraph via ``capabilities_from_subgraph``
    and emit up to _MAX_BANNER_TASKS nc banner-probe TaskSpecs for open TCP
    services that carry a probeable capability.  Falls back to a bounded
    version scan if no suitable probe targets are found.

All emitted args are **complete** (target already included), so
``graph.py:_run_one_task`` never needs to append target separately.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memfabric.ids import new_id, now
from memfabric.types import (
    AbandonSignal,
    ClaimDependency,
    EvidenceBundle,
    Goal,
    SubgraphView,
    TaskSpec,
)

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.planning.models import PlanDecision
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.llm.gateway import LLMGateway
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.policy.llm_guard import LLMPolicyGuard
    from apex_host.planning.engine import PlanningEngine

# Capability names that a raw nc banner probe is safe and informative for.
# All service-classification knowledge lives in capabilities.py; this set
# just maps capability names to the "nc-probeable" decision.
_BANNER_PROBE_CAPABILITIES: frozenset[str] = frozenset({
    "access_validate_ssh",
    "access_validate_telnet",
    "access_validate_ftp",
    "service_probe",
})
_MAX_BANNER_TASKS: int = 3


class _ReconDeterministic:
    """Pure rule-based recon planner — the fallback for PlanningEngine."""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        *,
        raw_socket_capable: bool = True,
        top_ports: int = 1000,
        execution_timeout_seconds: float = 90.0,
    ) -> None:
        self._target = target
        self._registry = registry
        # Two-pass scan bounding (§25.6): the first pass is a fast port
        # DISCOVERY scan over the top-N ports (no -sV); version detection is a
        # separate, smaller follow-up scan on only the ports found open. Both
        # carry a --host-timeout derived from the per-execution nmap timeout
        # (a margin below it) so nmap self-terminates gracefully before the
        # outer SIGTERM, and --max-retries 2 to bound VPN-latency retransmits.
        self._top_ports = top_ports
        self._host_timeout = f"{max(10, int(execution_timeout_seconds) - 10)}s"
        # Capability seam (apex_host.tools.backend.backend_supports_raw_sockets):
        # when the execution backend lacks CAP_NET_RAW/root (the Kali
        # tool-service container's own documented non-root, zero-capability
        # design — docs/kali-container.md §5/§14), nmap's default scan mode
        # ("-sV" alone implies a SYN scan) hard-fails with "Couldn't open a
        # raw socket... QUITTING!" rather than falling back automatically.
        # raw_socket_capable=True (the default) preserves the exact
        # pre-existing scan args for every caller that does not pass this
        # parameter explicitly.
        self._raw_socket_capable = raw_socket_capable

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        service_nodes = [n for n in subgraph.nodes if n.type == "service"]

        # Pass 1 — no services known yet: a fast, bounded port-DISCOVERY scan
        # (top-N ports, no -sV) so it completes within the timeout instead of
        # a full 1000-port -sV that times out over VPN latency.
        if not service_nodes:
            return self._discovery_scan(goal)

        # Pass 2 — services discovered but none have version info yet: a
        # separate, smaller -sV scan on ONLY the open ports. This is where
        # service/version detection happens, decoupled from discovery.
        version_task = self._version_scan(goal, service_nodes)
        if version_task is not None:
            return version_task

        banner_tasks = self._banner_tasks(goal, subgraph)
        if banner_tasks:
            return banner_tasks
        # Fallback: a bounded -sV scan on the discovered ports. If there are no
        # scannable ports it returns None; an empty task list is a valid
        # "nothing to do this turn" result (stall/termination handles it).
        fallback = self._version_scan_all(goal, service_nodes)
        return fallback if fallback is not None else banner_tasks

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    # -sT (TCP connect scan) is prepended when the backend cannot open raw
    # sockets. The dispatcher's single authoritative nmap path
    # (apex_host.tools.nmap_command.normalize_nmap_command) additionally
    # injects --unprivileged and -Pn on an unprivileged backend, so the
    # planner only needs to signal the connect-scan intent.
    def _scan_prefix(self) -> list[str]:
        return [] if self._raw_socket_capable else ["-sT"]

    def _bounds(self) -> list[str]:
        # Bound retransmits and per-host scan time so a scan cannot run to the
        # hard execution timeout. --host-timeout is a margin below the
        # per-execution nmap timeout (see __init__).
        return ["--max-retries", "2", "--host-timeout", self._host_timeout]

    def _service_ports(self, service_nodes: list[Any]) -> list[str]:
        ports = {
            str(n.props.get("port"))
            for n in service_nodes
            if str(n.props.get("port") or "").strip()
        }
        return sorted(ports, key=lambda p: int(p) if p.isdigit() else 1 << 20)

    def _nmap_taskspec(self, goal: Goal, args: list[str]) -> TaskSpec:
        host_node_id = f"host:{self._target}"
        return TaskSpec(
            id=new_id(),
            goal_id=goal.id,
            executor_domain="recon",
            params={"tool": "nmap", "args": args, "target": self._target, "parser": "nmap"},
            subgraph_anchor=goal.anchor_node,
            phase=goal.phase,
            # Nmap probes the host IP — depends on ip being undisputed.
            claim_dependencies=(ClaimDependency(node_id=host_node_id, field_name="ip"),),
        )

    def _discovery_scan(self, goal: Goal) -> list[TaskSpec] | AbandonSignal:
        """Pass 1: fast, bounded port discovery over the top-N ports — no -sV,
        so it completes within the timeout instead of timing out."""
        if self._registry.get("nmap") is None:
            return AbandonSignal(reason="nmap not available in allowed_tools")
        args = [
            *self._scan_prefix(), "-Pn", "-T4",
            "--top-ports", str(self._top_ports), *self._bounds(), self._target,
        ]
        return [self._nmap_taskspec(goal, args)]

    def _version_scan(
        self, goal: Goal, service_nodes: list[Any]
    ) -> list[TaskSpec] | None:
        """Pass 2: a smaller -sV scan on ONLY the open ports, emitted only when
        no service has version info yet (once versions are populated, recon
        moves on to banner probes). ``None`` means no version scan is needed."""
        if self._registry.get("nmap") is None:
            return None
        already_versioned = any(
            str(n.props.get("version") or "").strip() for n in service_nodes
        )
        if already_versioned:
            return None
        return self._version_scan_all(goal, service_nodes)

    def _version_scan_all(
        self, goal: Goal, service_nodes: list[Any]
    ) -> list[TaskSpec] | None:
        """Build a bounded -sV scan targeting exactly the discovered open
        ports (a small port set, not the full default 1000)."""
        if self._registry.get("nmap") is None:
            return None
        ports = self._service_ports(service_nodes)
        if not ports:
            return None
        args = [
            *self._scan_prefix(), "-Pn", "-sV",
            "-p", ",".join(ports), *self._bounds(), self._target,
        ]
        return [self._nmap_taskspec(goal, args)]

    def _banner_tasks(
        self, goal: Goal, subgraph: SubgraphView
    ) -> list[TaskSpec]:
        nc_tool = (
            "nc" if self._registry.get("nc") is not None
            else "netcat" if self._registry.get("netcat") is not None
            else None
        )
        if nc_tool is None:
            return []

        # Loop guard: skip services whose banner has already been captured.
        # A 'runs' edge from a service node to a tech node signals that
        # BannerParser (or NmapParser) already produced banner information for
        # that port — probing it again with nc would be redundant.
        services_with_tech: set[str] = {
            e.from_id for e in subgraph.edges if e.type == "runs"
        }

        # Derive probeable services via the capability layer — no scattered
        # service-name or port sets here; that knowledge lives in capabilities.py.
        caps = capabilities_from_subgraph(subgraph)
        probeable = [c for c in caps if c.name in _BANNER_PROBE_CAPABILITIES]

        tasks: list[TaskSpec] = []
        seen_ports: set[str] = set()

        for cap in probeable:
            if len(tasks) >= _MAX_BANNER_TASKS:
                break
            if not cap.port or cap.port in seen_ports:
                continue
            # Skip services that already have tech/banner information.
            if cap.source_node_id in services_with_tech:
                continue
            seen_ports.add(cap.port)
            tasks.append(
                TaskSpec(
                    id=new_id(),
                    goal_id=goal.id,
                    executor_domain="recon",
                    params={
                        "tool": nc_tool,
                        "args": ["-nv", self._target, cap.port],
                        "target": self._target,
                        "parser": "banner",
                        "port": cap.port,
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                    # Banner probe reads the port and state from the service node.
                    claim_dependencies=(
                        ClaimDependency(
                            node_id=cap.source_node_id, field_name="port"
                        ),
                        ClaimDependency(
                            node_id=cap.source_node_id, field_name="state"
                        ),
                    ),
                )
            )

        return tasks


class ReconPlanner:
    """Thin wrapper: routes through PlanningEngine when model_router is provided,
    falls back to _ReconDeterministic otherwise."""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        *,
        model_router: "ModelRouter | None" = None,
        allowed_tools: list[str] | None = None,
        confidence_threshold: float = 0.4,
        max_retries: int = 1,
        budget_tracker: "LLMBudgetTracker | None" = None,
        guard: "LLMPolicyGuard | None" = None,
        gateway: "LLMGateway | None" = None,
        raw_socket_capable: bool = True,
        top_ports: int = 1000,
        execution_timeout_seconds: float = 90.0,
    ) -> None:
        self._core = _ReconDeterministic(
            target, registry, raw_socket_capable=raw_socket_capable,
            top_ports=top_ports, execution_timeout_seconds=execution_timeout_seconds,
        )
        self._engine: PlanningEngine | None = None
        self._last_decision: PlanDecision | None = None
        if model_router is not None:
            from apex_host.planning.engine import PlanningEngine as _PE
            tools = allowed_tools if allowed_tools is not None else registry.available()
            self._engine = _PE(
                model_router=model_router,
                fallback_planner=self._core,
                allowed_tools=tools,
                target=target,
                confidence_threshold=confidence_threshold,
                max_retries=max_retries,
                budget=budget_tracker,
                guard=guard,
                gateway=gateway,
            )

    @property
    def last_decision(self) -> PlanDecision | None:
        """Most recent ``PlanDecision`` from the last ``plan()`` call."""
        if self._engine is not None:
            return self._engine.last_decision
        return self._last_decision

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        if self._engine is not None:
            return await self._engine.plan(goal, ApexPhase.recon, subgraph, evidence)
        self._last_decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="deterministic",
            fallback_used=True,
            timestamp=now(),
            phase=ApexPhase.recon.value,
        )
        return await self._core.plan(goal, subgraph, evidence)
