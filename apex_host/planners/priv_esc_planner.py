# priv_esc_planner.py
# Deterministic privilege-escalation-phase planner with an optional PlanningEngine LLM seam.
"""Deterministic privilege-escalation-phase planner with optional LLM backend.

``_PrivEscDeterministic`` is a privilege-escalation *planning* framework —
organizing enumeration, reasoning about opportunities, avoiding duplicate
work, and determining exhaustion (Phase 13). It never executes an exploit,
escalates privileges, generates a payload, or performs any live enumeration
beyond two already-safe mechanisms:

1. ``searchsploit`` lookups against already-known service/version strings
   (unchanged mechanism since before Phase 13 — a local exploit-db title
   search, zero target interaction).
2. Zero-network, zero-subprocess *analytical* derivation — reasoning over
   EKG data already captured by earlier phases (see
   ``apex_host/planners/priv_esc_opportunities.py::derive_analytical_opportunities``)
   to recognise well-known escalation hints (e.g. docker/sudo group
   membership from a Phase 12B credential-validation ``id`` output) without
   any new tool execution.

Both mechanisms feed the same ``PrivilegeOpportunity`` model (see
``apex_host/types.py``) and are recorded in the EKG as ``priv_esc_opportunity``
nodes so the planner never re-searches or re-derives the same opportunity
twice — see "Duplicate prevention" below.

Phase 13B adds a third, bounded mechanism: live, read-only enumeration
commands (``id``, ``uname -a``, ``sudo -n -l``, ``find ... -perm -4000``,
``getcap -r /``, ``mount``, ``crontab -l``, ``systemctl list-units``, ...)
executed over an SSH session using the SAME operator-supplied credentials
already validated in the credential phase (Phase 12B). This is gated
strictly: it only fires when an ``access_state`` node with
``service == "ssh"`` already exists (a real, successful login was already
proven) AND ``--username``/``--password`` are configured. Each fixed
command is executed at most once per engagement — see "Avoid rerunning
enumeration" below. See ``apex_host/agents/priv_esc_enum_executor.py`` and
docs/privilege-enumeration.md for the full design and safety rationale.

Duplicate prevention
---------------------
Before emitting any task, the planner reconstructs already-recorded
opportunities from the subgraph (``opportunities_from_subgraph``) and skips
any candidate (searchsploit service+version, or analytical category+user)
whose opportunity ID already exists — bounded to exactly one attempt per
opportunity, mirroring ``CredentialPlanner``'s per-protocol one-attempt
invariant (Phase 12B). Once every enumerable candidate has been recorded,
the planner returns an explicit "enumeration exhausted" ``AbandonSignal``
instead of silently re-emitting tasks the generic ``TaskDispatcher``
duplicate gate would only skip after the fact.

Avoid rerunning enumeration
----------------------------
Enumeration commands are tracked separately from opportunities: a
``priv_esc_evidence`` node is written per completed+parsed command (see
``apex_host/planners/priv_esc_opportunities.py::already_run_commands``),
and the planner never re-emits a ``command_key`` already present in that
set — a completed enumeration command is never repeated, whether or not it
produced an opportunity.

``PrivEscPlanner`` is the public thin wrapper: when a ``model_router`` is
provided it constructs a ``PlanningEngine`` and routes through it; otherwise
it delegates directly to ``_PrivEscDeterministic``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from memfabric.ids import new_id, now
from memfabric.types import (
    AbandonSignal,
    ClaimDependency,
    EvidenceBundle,
    Goal,
    SubgraphView,
    TaskSpec,
)

from apex_host.graph_ids import priv_esc_opportunity_id
from apex_host.planners.capabilities import Capability, capabilities_from_subgraph
from apex_host.planners.priv_esc_opportunities import (
    AnalyticalCandidate,
    already_run_commands,
    derive_analytical_opportunities,
    opportunities_from_subgraph,
)
from apex_host.planning.models import PlanDecision
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase, OpportunityCategory

# Deterministic, fixed enumeration-command order — never random, never based
# on discovery order. Cheap/informational commands first (identity, OS/kernel
# metadata), then higher-signal commands (sudo, SUID, capabilities), then the
# remaining lower-priority categories. See docs/privilege-enumeration.md
# "Enumeration ordering".
_ENUM_COMMAND_ORDER: tuple[str, ...] = (
    "identity", "os_info", "kernel_version",
    "sudo_l", "suid", "capabilities",
    "mounts", "cron", "service_info",
)

if TYPE_CHECKING:
    from apex_host.llm.gateway import LLMGateway
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker
    from apex_host.planning.engine import PlanningEngine
    from apex_host.policy.llm_guard import LLMPolicyGuard

# Bounded per-turn cap across BOTH task kinds (analytical + searchsploit) —
# mirrors ReconPlanner's _MAX_BANNER_TASKS convention: a small, deterministic
# batch, never "every candidate at once".
_MAX_PRIV_ESC_TASKS = 3


class _PrivEscDeterministic:
    """Pure rule-based priv-esc planner — the fallback for PlanningEngine."""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        username_candidates: list[str] | None = None,
        password_candidates: list[str] | None = None,
    ) -> None:
        self._target = target
        self._registry = registry
        # Phase 13B — the SAME operator-supplied credentials already used
        # (and already validated) in the credential phase; enumeration never
        # guesses or brute-forces a credential of its own. See module
        # docstring "Avoid rerunning enumeration".
        self._usernames: list[str] = list(username_candidates or [])
        self._passwords: list[str] = list(password_candidates or [])

    def _ssh_access_username(self, subgraph: SubgraphView) -> str:
        """The username of an already-validated SSH ``access_state`` node
        for this target, or ``""`` if none exists.

        Enumeration is gated on a REAL, already-proven SSH login (Phase
        12B) — never attempted speculatively, and never with a credential
        this planner invented itself.
        """
        for n in subgraph.nodes:
            if (
                n.type == "access_state"
                and str(n.props.get("target", "")) == self._target
                and str(n.props.get("service", "")).lower() == "ssh"
            ):
                return str(n.props.get("username", ""))
        return ""

    def _ssh_port(self, subgraph: SubgraphView) -> str:
        """Best-known SSH port for this target — from the
        ``access_validate_ssh`` capability if a service node still exists,
        else the conventional default (mirrors ``CredentialPlanner``'s own
        lowest-port selection)."""
        caps = [c for c in capabilities_from_subgraph(subgraph) if c.name == "access_validate_ssh"]
        if not caps:
            return "22"
        return sorted(caps, key=lambda c: int(c.port) if c.port.isdigit() else 22)[0].port or "22"

    def _build_enum_task(self, goal: Goal, port: str, username: str, password: str, command_key: str) -> TaskSpec:
        return TaskSpec(
            id=new_id(),
            goal_id=goal.id,
            executor_domain="priv_esc",
            params={
                "tool": "priv_esc_enum",
                # command_key only — never a free-form command string (see
                # apex_host/agents/priv_esc_enum_executor.py's fixed
                # ENUM_COMMANDS table).
                "args": [command_key],
                "target": self._target,
                "port": port,
                "username": username,
                "password": password,
                "parser": "priv_esc_enum",
                "command_key": command_key,
            },
            subgraph_anchor=goal.anchor_node,
            phase=goal.phase,
        )

    def _build_searchsploit_task(
        self, goal: Goal, cap: Capability, service: str, version: str
    ) -> TaskSpec:
        return TaskSpec(
            id=new_id(),
            goal_id=goal.id,
            executor_domain="priv_esc",
            params={
                "tool": "searchsploit",
                # Two separate argv tokens (searchsploit treats multiple
                # positional args as combined search terms) rather than one
                # pre-joined string — lets the parser recover service/version
                # from tool_result["args"] without re-parsing free text.
                "args": [service, version] if version else [service],
                "target": self._target,
                "parser": "priv_esc",
                "service": service,
                "version": version,
            },
            subgraph_anchor=goal.anchor_node,
            phase=goal.phase,
            # searchsploit queries the service version string.
            claim_dependencies=(
                ClaimDependency(node_id=cap.source_node_id, field_name="version"),
                ClaimDependency(node_id=cap.source_node_id, field_name="service"),
            ),
        )

    def _build_analysis_task(self, goal: Goal, cand: AnalyticalCandidate) -> TaskSpec:
        return TaskSpec(
            id=new_id(),
            goal_id=goal.id,
            executor_domain="priv_esc",
            params={
                "tool": "priv_esc_analyze",
                # discriminator/category encoded in args so the generic
                # TaskDispatcher fingerprint distinguishes different
                # analytical candidates (e.g. docker vs sudo for the same
                # user) — the executor itself reads the named params below,
                # not args.
                "args": [cand.category, cand.discriminator],
                "target": self._target,
                "parser": "priv_esc",
                "category": cand.category,
                "confidence": cand.confidence,
                "description": cand.description,
                "recommended_next_action": cand.recommended_next_action,
                "discriminator": cand.discriminator,
                "evidence_source": cand.evidence_source,
                "evidence_excerpt": cand.evidence_excerpt,
                "source_node_id": cand.source_node_id,
            },
            subgraph_anchor=goal.anchor_node,
            phase=goal.phase,
            # The analytical signal reads the source access_state node's
            # evidence text — undisputed evidence is a precondition.
            claim_dependencies=(
                ClaimDependency(node_id=cand.source_node_id, field_name="evidence"),
            ) if cand.source_node_id else (),
        )

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        attempted_ids = {o.id for o in opportunities_from_subgraph(subgraph)}

        # ---- Enumeration candidates (Phase 13B): only when a real SSH ----
        # ---- login was already validated AND credentials are configured. --
        enum_username = self._ssh_access_username(subgraph)
        new_enum_commands: list[str] = []
        if enum_username and self._usernames and self._passwords:
            already = already_run_commands(subgraph)
            new_enum_commands = [k for k in _ENUM_COMMAND_ORDER if k not in already]

        # ---- Analytical candidates: zero-cost, zero-risk, always considered. ----
        analytical = derive_analytical_opportunities(subgraph)
        new_analytical = [
            cand for cand in analytical
            if priv_esc_opportunity_id(self._target, cand.category, cand.discriminator)
            not in attempted_ids
        ]

        # ---- searchsploit candidates: only when the tool is available. ----
        searchsploit_available = self._registry.get("searchsploit") is not None
        research_candidates: list[tuple[Capability, str, str]] = []
        if searchsploit_available:
            caps = capabilities_from_subgraph(subgraph)
            research = [c for c in caps if c.name == "exploit_research"]
            node_by_id = {n.id: n for n in subgraph.nodes}
            # Deterministic ranking: highest capability confidence first,
            # tie-broken by source node id (never insertion order alone).
            research_sorted = sorted(research, key=lambda c: (-c.confidence, c.source_node_id))
            for cap in research_sorted:
                node = node_by_id.get(cap.source_node_id)
                if node is None:
                    continue
                version = str(node.props.get("version", "")).strip()
                service = cap.service
                if not service:
                    continue
                research_candidates.append((cap, service, version))

        new_research: list[tuple[Capability, str, str]] = []
        for cap, service, version in research_candidates:
            discriminator = f"{service} {version}".strip()
            found_id = priv_esc_opportunity_id(
                self._target, OpportunityCategory.vulnerable_service.value, discriminator
            )
            none_id = priv_esc_opportunity_id(
                self._target, OpportunityCategory.none.value, discriminator
            )
            if found_id in attempted_ids or none_id in attempted_ids:
                continue
            new_research.append((cap, service, version))

        tasks: list[TaskSpec] = []
        if new_enum_commands:
            port = self._ssh_port(subgraph)
            username0 = self._usernames[0]
            password0 = self._passwords[0]
            for command_key in new_enum_commands:
                if len(tasks) >= _MAX_PRIV_ESC_TASKS:
                    break
                tasks.append(self._build_enum_task(goal, port, username0, password0, command_key))
        for cand in new_analytical:
            if len(tasks) >= _MAX_PRIV_ESC_TASKS:
                break
            tasks.append(self._build_analysis_task(goal, cand))
        for cap, service, version in new_research:
            if len(tasks) >= _MAX_PRIV_ESC_TASKS:
                break
            tasks.append(self._build_searchsploit_task(goal, cap, service, version))

        if tasks:
            return tasks

        # Nothing to do this turn. Distinguish WHY, preserving the exact,
        # tested message shapes from before Phase 13A for the two original
        # conditions, and adding distinct "exhausted"/"no credentials"
        # messages for the Phase 13B enumeration path.
        if not searchsploit_available and not analytical and not enum_username:
            return AbandonSignal(reason="searchsploit not available in allowed_tools")
        if not analytical and not research_candidates and not enum_username:
            return AbandonSignal(reason="no enumerable service/version strings")
        if enum_username and not (self._usernames and self._passwords):
            return AbandonSignal(
                reason=(
                    "validated ssh access present but no credentials configured for "
                    "enumeration; pass --username and --password to enable bounded "
                    "read-only enumeration"
                )
            )
        return AbandonSignal(
            reason=(
                "privilege-escalation enumeration exhausted: all discovered "
                "opportunities have already been recorded; no further safe "
                "enumeration remains"
            )
        )


class PrivEscPlanner:
    """Thin wrapper: routes through PlanningEngine when model_router is provided,
    falls back to _PrivEscDeterministic otherwise."""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        username_candidates: list[str] | None = None,
        password_candidates: list[str] | None = None,
        *,
        model_router: "ModelRouter | None" = None,
        allowed_tools: list[str] | None = None,
        confidence_threshold: float = 0.4,
        max_retries: int = 1,
        budget_tracker: "LLMBudgetTracker | None" = None,
        guard: "LLMPolicyGuard | None" = None,
        gateway: "LLMGateway | None" = None,
    ) -> None:
        self._core = _PrivEscDeterministic(
            target, registry,
            username_candidates=username_candidates,
            password_candidates=password_candidates,
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
            return await self._engine.plan(goal, ApexPhase.priv_esc, subgraph, evidence)
        self._last_decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="deterministic",
            fallback_used=True,
            timestamp=now(),
            phase=ApexPhase.priv_esc.value,
        )
        return await self._core.plan(goal, subgraph, evidence)
