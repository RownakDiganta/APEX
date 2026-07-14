# credential_planner.py
# Deterministic credential-phase planner with an optional PlanningEngine LLM seam.
"""Deterministic credential-phase planner with optional LLM backend.

``_CredentialDeterministic`` contains the original rule-based logic — three
paths, in order:

1. ``access_validate_telnet`` capability found AND credentials configured:
   Emit exactly ONE bounded telnet-login task. No looping, no credential
   stuffing. Credentials must come from explicit operator config (never
   guessed autonomously).

2. ``access_validate_telnet`` capability found but NO credentials:
   Return AbandonSignal with a helpful message directing the operator to
   supply --username / --password flags.

3. No telnet capability: fall back to a curl HEAD probe against a known
   auth_flow endpoint, or abandon if none exists.

``CredentialPlanner`` is the public thin wrapper: when a ``model_router`` is
provided it constructs a ``PlanningEngine`` and routes through it; otherwise
it delegates directly to ``_CredentialDeterministic``.
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
    from apex_host.planning.engine import PlanningEngine
    from apex_host.policy.llm_guard import LLMPolicyGuard


class _CredentialDeterministic:
    """Pure rule-based credential planner — the fallback for PlanningEngine."""

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

    def has_credentials(self) -> bool:
        """True when at least one username and one password are configured."""
        return bool(self._usernames) and bool(self._passwords)

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        caps = capabilities_from_subgraph(subgraph)
        telnet_caps = [c for c in caps if c.name == "access_validate_telnet"]

        if telnet_caps:
            # Loop guard: if a credential node already exists for this
            # target+username, a login attempt has already been recorded.
            # Do not repeat — the one-attempt invariant is enforced here.
            if self._usernames:
                username0 = self._usernames[0]
                already_attempted = any(
                    n.type == "credential"
                    and str(n.props.get("target", "")) == self._target
                    and str(n.props.get("username", "")) == username0
                    for n in subgraph.nodes
                )
                if already_attempted:
                    return AbandonSignal(
                        reason=(
                            f"telnet credential already recorded for "
                            f"{username0}@{self._target}; "
                            "not repeating (one-attempt invariant)"
                        )
                    )

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
                    # Telnet login reads port and service from the capability node.
                    claim_dependencies=(
                        ClaimDependency(
                            node_id=cap.source_node_id, field_name="port"
                        ),
                        ClaimDependency(
                            node_id=cap.source_node_id, field_name="service"
                        ),
                    ),
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

        auth_node = auth_nodes[0]
        target_url = str(auth_node.props.get("url", self._target))
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
                # curl uses the auth_flow node's URL.
                claim_dependencies=(
                    ClaimDependency(node_id=auth_node.id, field_name="url"),
                ),
            )
        ]


class CredentialPlanner:
    """Thin wrapper: routes through PlanningEngine when model_router is provided,
    falls back to _CredentialDeterministic otherwise."""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        username_candidates: list[str] | None = None,
        password_candidates: list[str] | None = None,
        max_access_attempts: int = 1,
        *,
        model_router: "ModelRouter | None" = None,
        allowed_tools: list[str] | None = None,
        confidence_threshold: float = 0.4,
        max_retries: int = 1,
        budget_tracker: "LLMBudgetTracker | None" = None,
        guard: "LLMPolicyGuard | None" = None,
        gateway: "LLMGateway | None" = None,
    ) -> None:
        self._core = _CredentialDeterministic(
            target, registry,
            username_candidates=username_candidates,
            password_candidates=password_candidates,
            max_access_attempts=max_access_attempts,
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
        """Most recent ``PlanDecision`` from the last ``plan()`` call.

        ``_last_decision`` is set whenever we bypass the engine (telnet+creds
        safety path) or when there is no engine.  Engine's own ``last_decision``
        is used only when the LLM path ran unimpeded.
        """
        if self._last_decision is not None:
            return self._last_decision
        if self._engine is not None:
            return self._engine.last_decision
        return None

    def _telnet_credentials_available_from_caps(
        self, caps: list[Any]
    ) -> bool:
        """True when pre-computed caps include telnet AND credentials are configured."""
        has_telnet = any(c.name == "access_validate_telnet" for c in caps)
        return has_telnet and self._core.has_credentials()

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        if self._engine is not None:
            # Compute capabilities exactly ONCE per plan() call (F12).
            caps = capabilities_from_subgraph(subgraph)
            if self._telnet_credentials_available_from_caps(caps):
                # Safety bypass: telnet login must use the bounded deterministic
                # path.  Never let the LLM substitute nc/python3 probes for the
                # telnet_access executor — that would loop indefinitely.
                result = await self._core.plan(goal, subgraph, evidence)
                task_count = len(result) if isinstance(result, list) else 0
                self._last_decision = PlanDecision(
                    planner_model="deterministic",
                    confidence=1.0,
                    selected_task_count=task_count,
                    rejected_task_count=0,
                    reasoning_summary="telnet+credentials: LLM bypassed (one-attempt safety invariant)",
                    fallback_used=True,
                    timestamp=now(),
                    phase=ApexPhase.credential.value,
                )
                return result
            # No telnet bypass — let the engine decide.
            self._last_decision = None
            return await self._engine.plan(goal, ApexPhase.credential, subgraph, evidence)
        self._last_decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="deterministic",
            fallback_used=True,
            timestamp=now(),
            phase=ApexPhase.credential.value,
        )
        return await self._core.plan(goal, subgraph, evidence)
