# credential_planner.py
# Deterministic credential-phase planner that emits one bounded telnet access-validation task when credentials are configured and a telnet capability exists, or falls back to a curl HEAD probe.
"""Deterministic credential-phase planner.

Implements memfabric.coordination.protocols.Planner. Three paths, in order:

1. ``access_validate_telnet`` capability found AND credentials configured:
   Emit exactly ONE bounded telnet-login task. No looping, no credential
   stuffing. Credentials must come from explicit operator config (never
   guessed autonomously).

2. ``access_validate_telnet`` capability found but NO credentials:
   Return AbandonSignal with a helpful message directing the operator to
   supply --username / --password flags.

3. No telnet capability: fall back to a curl HEAD probe against a known
   auth_flow endpoint, or abandon if none exists.
"""
from __future__ import annotations

from memfabric.ids import new_id
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.tools.registry import ToolRegistry


class CredentialPlanner:
    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        username_candidates: list[str] | None = None,
        password_candidates: list[str] | None = None,
        max_access_attempts: int = 1,
    ) -> None:
        self._target = target
        self._registry = registry
        self._usernames: list[str] = list(username_candidates or [])
        self._passwords: list[str] = list(password_candidates or [])
        # max_access_attempts is bounded at 1 in this iteration; stored for
        # future multi-credential support behind an explicit gate.
        self._max_attempts = max(1, max_access_attempts)

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        caps = capabilities_from_subgraph(subgraph)
        telnet_caps = [c for c in caps if c.name == "access_validate_telnet"]

        if telnet_caps:
            if not self._usernames or not self._passwords:
                return AbandonSignal(
                    reason=(
                        "access_validate_telnet capability present but no credentials configured; "
                        "pass --username and --password to attempt a bounded login validation"
                    )
                )
            cap = telnet_caps[0]
            username = self._usernames[0]
            password = self._passwords[0]
            return [
                TaskSpec(
                    id=new_id(),
                    goal_id=goal.id,
                    executor_domain="credential",
                    params={
                        "tool": "telnet_access",
                        "target": self._target,
                        "port": cap.port or "23",
                        "username": username,
                        "password": password,
                        "parser": "access",
                    },
                    subgraph_anchor=goal.anchor_node,
                    phase=goal.phase,
                )
            ]

        # No telnet capability — fall back to a passive curl HEAD probe.
        if self._registry.get("curl") is None:
            return AbandonSignal(
                reason="no access_validate_telnet capability and curl not available in allowed_tools"
            )

        auth_nodes = [n for n in subgraph.nodes if n.type == "auth_flow"]
        if not auth_nodes:
            return AbandonSignal(
                reason="no access_validate_telnet capability and no known auth_flow endpoints"
            )

        target_url = str(auth_nodes[0].props.get("url", self._target))
        return [
            TaskSpec(
                id=new_id(),
                goal_id=goal.id,
                executor_domain="credential",
                params={
                    "tool": "curl",
                    "args": ["-s", "-I", target_url],
                    "target": target_url,
                    "parser": "command",
                },
                subgraph_anchor=goal.anchor_node,
                phase=goal.phase,
            )
        ]
