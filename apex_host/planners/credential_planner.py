# credential_planner.py
# Deterministic credential-phase planner with an optional PlanningEngine LLM seam.
"""Deterministic credential-phase planner with optional LLM backend.

``_CredentialDeterministic`` contains the original rule-based logic — for
each configured credential pair, at most ONE bounded login task is emitted
per turn, chosen deterministically across three protocols:

1. A protocol capability (``access_validate_telnet`` / ``_ssh`` / ``_ftp``)
   is present AND credentials are configured AND that protocol has not
   already been attempted for this target/username: emit exactly ONE
   bounded login task for the highest-priority such protocol (see
   ``_PROTOCOL_ORDER`` below). No looping, no credential stuffing, no
   trying every protocol in one turn.

2. At least one protocol capability is present but no credentials are
   configured: AbandonSignal directing the operator to supply
   --username / --password.

3. Every available protocol capability has already been attempted (a
   credential node already exists for each): AbandonSignal — the one-attempt
   invariant applies per protocol, not just to the phase as a whole.

4. No protocol capability at all: fall back to a passive curl HEAD probe
   against a known auth_flow endpoint (unchanged since before Phase 12B),
   or abandon if none exists.

Deterministic protocol ordering (Phase 12B)
--------------------------------------------
``_PROTOCOL_ORDER = ("telnet", "ssh", "ftp")`` is a fixed, documented
priority — never randomized, never based on service *discovery order* (which
is not guaranteed stable across runs). Telnet is checked first purely for
historical/backward-compatibility reasons (it was the only protocol before
Phase 12B and its existing behavior must remain unchanged when it is the
only capability present). When multiple services exist for the *same*
protocol (e.g. two SSH ports), the lowest port number is chosen — also
deterministic, no randomness. See docs/credential-validation.md "Planner
integration" for the full rationale and test coverage.

Per-protocol duplicate guard (Phase 12B)
------------------------------------------
Each protocol tracks its own "already attempted" state independently by
inspecting existing ``credential`` nodes' ``protocol`` prop (set by
``AccessParser`` — see ``apex_host/graph_ids.py``'s ``credential_id``
docstring for why SSH/FTP credential-node IDs embed the protocol). A failed
SSH attempt therefore never blocks an unrelated FTP attempt, or vice versa —
each protocol's one-attempt invariant is enforced separately.

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
    Node,
    SubgraphView,
    TaskSpec,
)

from apex_host.planners.capabilities import Capability, capabilities_from_subgraph
from apex_host.planning.models import PlanDecision
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

if TYPE_CHECKING:
    from apex_host.llm.gateway import LLMGateway
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.planning.engine import PlanningEngine
    from apex_host.policy.llm_guard import LLMPolicyGuard

# Fixed, documented, deterministic protocol priority — see module docstring.
_PROTOCOL_ORDER: tuple[str, ...] = ("telnet", "ssh", "ftp")

_PROTOCOL_CAPABILITY: dict[str, str] = {
    "telnet": "access_validate_telnet",
    "ssh": "access_validate_ssh",
    "ftp": "access_validate_ftp",
}

_PROTOCOL_TASK_TOOL: dict[str, str] = {
    "telnet": "telnet_access",
    "ssh": "ssh_access",
    "ftp": "ftp_access",
}

_PROTOCOL_DEFAULT_PORT: dict[str, str] = {"telnet": "23", "ssh": "22", "ftp": "21"}


def _protocol_already_attempted(
    subgraph_nodes: "list[Node]", target: str, protocol: str, username: str
) -> bool:
    """True when a credential node already exists for *protocol* against
    *target*/*username*.

    Matching is protocol-scoped so one protocol's attempt (successful or
    failed) never blocks another protocol's attempt against the same
    target/username — see the module docstring "Per-protocol duplicate
    guard". Telnet matches both the historical, protocol-tag-free node
    shape (``props`` has no ``protocol`` key at all — the shape produced by
    ``AccessParser.parse_text`` when called with the pre-Phase-12B default,
    and by any credential node built directly rather than through the
    parser) and the real pipeline's own ``protocol="telnet_access"`` value,
    preserving Telnet's exact pre-Phase-12B behavior. SSH/FTP only match
    their own explicit protocol tag.
    """
    for n in subgraph_nodes:
        if n.type != "credential":
            continue
        if str(n.props.get("target", "")) != target:
            continue
        if str(n.props.get("username", "")) != username:
            continue
        node_protocol = str(n.props.get("protocol", "")).lower()
        if protocol == "telnet":
            if node_protocol == "" or "telnet" in node_protocol:
                return True
        elif protocol in node_protocol:
            return True
    return False


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

    def _build_task(
        self, goal: Goal, protocol: str, cap: Capability, username: str, password: str
    ) -> TaskSpec:
        """Build the single bounded login TaskSpec for *protocol*.

        Identical params shape across all three protocols (only ``tool`` and
        the default port differ) — the dedicated executor for each protocol
        (``TelnetExecutor`` / ``SSHExecutor`` / ``FTPExecutor``) reads the
        same ``target``/``port``/``username``/``password`` keys.
        """
        return TaskSpec(
            id=new_id(),
            goal_id=goal.id,
            executor_domain="credential",
            params={
                "tool": _PROTOCOL_TASK_TOOL[protocol],
                "target": self._target,
                "port": cap.port or _PROTOCOL_DEFAULT_PORT[protocol],
                "username": username,
                "password": password,
                "parser": "access",
            },
            subgraph_anchor=goal.anchor_node,
            phase=goal.phase,
            # Login reads port and service from the capability's source node.
            claim_dependencies=(
                ClaimDependency(node_id=cap.source_node_id, field_name="port"),
                ClaimDependency(node_id=cap.source_node_id, field_name="service"),
            ),
        )

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        caps = capabilities_from_subgraph(subgraph)
        caps_by_protocol: dict[str, list[Capability]] = {p: [] for p in _PROTOCOL_ORDER}
        for c in caps:
            for protocol, cap_name in _PROTOCOL_CAPABILITY.items():
                if c.name == cap_name:
                    caps_by_protocol[protocol].append(c)

        any_protocol_cap = any(caps_by_protocol[p] for p in _PROTOCOL_ORDER)

        if any_protocol_cap:
            if not self._usernames or not self._passwords:
                # Preserve the exact, tested message when telnet is (one of)
                # the available capabilities; generalize only when telnet is
                # not involved at all (a pure SSH/FTP-only target).
                if caps_by_protocol["telnet"]:
                    return AbandonSignal(
                        reason=(
                            "access_validate_telnet capability present but no credentials configured; "
                            "pass --username and --password to attempt a bounded login validation"
                        )
                    )
                return AbandonSignal(
                    reason=(
                        "a credential-validation capability is present but no credentials "
                        "configured; pass --username and --password to attempt a bounded "
                        "login validation"
                    )
                )

            username0 = self._usernames[0]
            password0 = self._passwords[0]

            # Deterministic ordering: telnet, then ssh, then ftp (see module
            # docstring). Within one protocol, lowest port number first.
            for protocol in _PROTOCOL_ORDER:
                protocol_caps = caps_by_protocol[protocol]
                if not protocol_caps:
                    continue
                # Loop guard: this protocol's own one-attempt invariant —
                # a failed/successful SSH attempt never blocks FTP, and
                # vice versa (see _protocol_already_attempted).
                if _protocol_already_attempted(subgraph.nodes, self._target, protocol, username0):
                    continue
                cap = sorted(
                    protocol_caps,
                    key=lambda c: int(c.port) if c.port.isdigit() else 0,
                )[0]
                return [self._build_task(goal, protocol, cap, username0, password0)]

            # Every protocol with a capability has already been attempted.
            attempted = ", ".join(p for p in _PROTOCOL_ORDER if caps_by_protocol[p])
            if caps_by_protocol["telnet"] and not caps_by_protocol["ssh"] and not caps_by_protocol["ftp"]:
                # Single-protocol (telnet-only) case: preserve the exact,
                # tested pre-Phase-12B message text.
                return AbandonSignal(
                    reason=(
                        f"telnet credential already recorded for "
                        f"{username0}@{self._target}; "
                        "not repeating (one-attempt invariant)"
                    )
                )
            return AbandonSignal(
                reason=(
                    f"credential already recorded for {username0}@{self._target} on every "
                    f"available protocol ({attempted}); not repeating (one-attempt invariant)"
                )
            )

        # No protocol capability at all — fall back to a passive curl HEAD probe.
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
