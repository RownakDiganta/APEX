# objective_planner.py
# Deterministic user-flag-objective planner: emits bounded, read-only verification tasks against the best validated AccessCapability, never repeating an already-attempted candidate, and stops once verified.
"""Deterministic user-flag-objective planner (Phase 18; made
capability-generic in the access-capability refactor).

``_ObjectiveDeterministic`` is a bounded verification *planning* framework
— it never guesses, brute-forces, or scans an unrestricted filesystem
surface. It only ever emits ``user_flag_verify`` tasks (see
``apex_host/agents/user_flag_executor.py``) once:

1. a validated, runtime-available ``AccessCapability`` already exists for
   the target (proof a real access mechanism already works — see
   ``apex_host/planners/access_capabilities.py``); the planner never
   attempts to establish access itself, and — since the capability
   refactor — never searches for a specific transport (SSH, Telnet, ...)
   directly. It ranks and selects among whatever ``AccessCapability``
   records the live EKG has, generically;
2. the user_flag objective is not already verified; and
3. at least one bounded candidate path (from
   ``ApexConfig.user_flag_candidate_roots`` x
   ``user_flag_candidate_filenames``, capped at
   ``max_user_flag_attempts``) has not already been attempted THROUGH THAT
   SPECIFIC CAPABILITY (tracked via the ``objective`` EKG node's
   ``attempted_capability_paths`` prop — see
   ``apex_host/planners/objective.py``'s
   ``objective_attempted_capability_pairs``).

Attempt tracking is scoped to ``(capability_id, candidate_path)`` pairs,
not bare paths (Phase 20). A failed attempt through one capability (e.g.
SSH) never blocks a DIFFERENT, newly-available capability (e.g. a
direct-file-read primitive) from trying the very same candidate path — and
the objective's ``status`` only ever becomes ``"failed"`` once EVERY
candidate has been tried through EVERY currently-known validated+available
capability (true global exhaustion, computed fresh each turn — see
``_is_globally_exhausted``), never merely because the one capability the
planner happened to pick this turn ran out of its own candidates.

Note this planner no longer requires operator-supplied credentials to be
configured at plan time — a validated ``AccessCapability`` node existing in
the EKG is already structural proof that some earlier phase's credentials
worked; the planner itself never invents or re-validates access, so it has
no independent use for the raw credential values. (Provisioning the
underlying runtime adapter — e.g. opening a fresh SSH connection per
read — is an orchestration-layer concern; see
``apex_host.orchestration.dispatch_node.make_objective_node``, which is
where ``ApexConfig.username_candidates``/``password_candidates`` are
actually consumed for this phase's one SSH adapter.)

Capability ranking: prefer a VALIDATED capability, then higher confidence,
then a capability that still has an untried bounded candidate path for its
own ``principal`` — implemented by excluding any capability whose full
candidate-path set is already exhausted before calling
``apex_host.planners.access_capabilities.best_capability_for_objective``
(see ``_select_capability`` below).

Exactly one task is emitted per turn (mirrors ``CredentialPlanner``'s
one-attempt-per-turn pacing for sensitive session-based operations). Once
every bounded candidate has been attempted, across every validated
capability, without success, the planner returns an explicit "exhausted"
``AbandonSignal`` rather than silently looping.

No LLM seam. Unlike most other domain planners in this codebase,
``ObjectivePlanner`` does not wrap a ``PlanningEngine`` — bounded
capability-bearing verification tasks are too safety-sensitive to route
through an LLM-backed planner (the same reasoning
``CredentialPlanner``/``PrivEscPlanner`` already apply to their own
telnet/ssh bypass paths, made unconditional here since this planner has no
other kind of task to emit).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from memfabric.ids import new_id, now
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec

from apex_host.planners.access_capabilities import access_capabilities_from_subgraph, best_capability_for_objective
from apex_host.planners.objective import (
    find_objective_node,
    objective_attempted_capability_pairs,
    objective_status_from_subgraph,
)
from apex_host.planning.models import PlanDecision
from apex_host.tools.registry import ToolRegistry
from apex_host.types import AccessCapability, ApexPhase

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

#: Conservative, portable username charset — a principal failing this check
#: is never interpolated into a candidate root template (defensive; avoids
#: building an unexpected path from an unusual capability principal).
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

#: One bounded verification task per turn — mirrors CredentialPlanner's
#: single-attempt-per-turn invariant for sensitive session operations.
_MAX_TASKS_PER_TURN = 1


class _ObjectiveDeterministic:
    """Pure rule-based objective planner."""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        *,
        objective_type: str = "user_flag",
        candidate_filenames: list[str] | None = None,
        candidate_roots: list[str] | None = None,
        max_attempts: int = 3,
        format_regex: str | None = None,
        max_output_bytes: int = 4096,
    ) -> None:
        self._target = target
        self._registry = registry
        self._objective_type = objective_type
        self._filenames = list(candidate_filenames or ["user.txt"])
        self._roots = list(candidate_roots or ["/home/{username}"])
        self._max_attempts = max(1, max_attempts)
        self._format_regex = format_regex
        self._max_output_bytes = max_output_bytes

    def _candidate_paths(self, principal: str) -> list[str]:
        safe_principal = principal if _USERNAME_RE.match(principal) else None
        candidates: list[str] = []
        for root in self._roots:
            if "{username}" in root and safe_principal is None:
                # Unsafe/unmatched principal — skip this templated root
                # defensively rather than building an unvalidated path.
                continue
            resolved_root = (root.format(username=safe_principal) if safe_principal else root).rstrip("/")
            if not resolved_root:
                continue
            for filename in self._filenames:
                path = f"{resolved_root}/{filename}"
                if path not in candidates:
                    candidates.append(path)
                if len(candidates) >= self._max_attempts:
                    return candidates
        return candidates

    def _select_capability(
        self, subgraph: SubgraphView, attempted_pairs: set[tuple[str, str]]
    ) -> tuple[AccessCapability, list[str]] | None:
        """Pick the best validated+available capability that still has an
        untried bounded candidate path FOR ITSELF (pair-scoped — a path
        already attempted through a DIFFERENT capability never counts
        against this one), and return it with its full ordered
        candidate-path list. ``None`` when no validated+available
        capability has any candidate left to try."""
        exhausted_ids: set[str] = set()
        for entry in access_capabilities_from_subgraph(subgraph):
            if not entry.validated or not entry.runtime_available:
                continue
            candidates = self._candidate_paths(entry.principal)
            if not candidates or all((entry.capability_id, c) in attempted_pairs for c in candidates):
                exhausted_ids.add(entry.capability_id)

        best = best_capability_for_objective(subgraph, exclude_capability_ids=frozenset(exhausted_ids))
        if best is None:
            return None
        candidates = self._candidate_paths(best.principal)
        if not candidates:
            return None
        return best, candidates

    def _is_globally_exhausted(
        self, subgraph: SubgraphView, attempted_pairs: set[tuple[str, str]]
    ) -> bool:
        """True only when EVERY validated+available capability's full
        candidate-path set is already contained in *attempted_pairs* —
        i.e. nothing remains to try through ANY currently-known capability.
        This (not "the one capability picked this turn ran out") is what
        the ``objective`` node's ``status`` becomes ``"failed"`` from, so a
        failed SSH-only attempt never marks the objective globally failed
        while a validated direct-file-read capability still has an
        untried candidate."""
        for entry in access_capabilities_from_subgraph(subgraph):
            if not entry.validated or not entry.runtime_available:
                continue
            candidates = self._candidate_paths(entry.principal)
            if any((entry.capability_id, c) not in attempted_pairs for c in candidates):
                return False
        return True

    def _build_task(
        self,
        goal: Goal,
        capability: AccessCapability,
        candidate_path: str,
        attempted_paths: list[str],
        attempted_pairs: list[tuple[str, str]],
        *,
        is_last: bool,
    ) -> TaskSpec:
        return TaskSpec(
            id=new_id(),
            goal_id=goal.id,
            executor_domain="objective",
            params={
                "tool": "user_flag_verify",
                "target": self._target,
                "capability_id": capability.capability_id,
                "capability_type": capability.capability_type.value,
                "principal": capability.principal,
                "candidate_path": candidate_path,
                "objective_type": self._objective_type,
                "attempted_paths": list(attempted_paths),
                "attempted_capability_paths": [list(p) for p in attempted_pairs],
                "is_last_candidate": is_last,
                "format_regex": self._format_regex,
                "max_output_bytes": self._max_output_bytes,
                "parser": "objective",
            },
            subgraph_anchor=goal.anchor_node,
            phase=goal.phase,
        )

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        status = objective_status_from_subgraph(subgraph, self._target, self._objective_type)
        if status == "verified":
            return AbandonSignal(reason=f"{self._objective_type} objective already verified")

        obj_node = find_objective_node(subgraph, self._target, self._objective_type)
        attempted_paths = list(obj_node.props.get("attempted_paths", [])) if obj_node is not None else []
        attempted_pairs_list = objective_attempted_capability_pairs(subgraph, self._target, self._objective_type)
        attempted_pairs = set(attempted_pairs_list)

        selection = self._select_capability(subgraph, attempted_pairs)
        if selection is None:
            has_available = any(
                c.validated and c.runtime_available for c in access_capabilities_from_subgraph(subgraph)
            )
            if not has_available:
                return AbandonSignal(
                    reason="no validated access capability available for user-flag verification"
                )
            return AbandonSignal(
                reason=(
                    "user-flag verification exhausted: all bounded candidate paths "
                    "already attempted across every validated access capability "
                    "without success"
                )
            )

        capability, candidates = selection
        remaining = [c for c in candidates if (capability.capability_id, c) not in attempted_pairs]
        candidate_path = remaining[0]
        prospective_pairs = attempted_pairs | {(capability.capability_id, candidate_path)}
        is_last = self._is_globally_exhausted(subgraph, prospective_pairs)
        task = self._build_task(
            goal, capability, candidate_path, attempted_paths, attempted_pairs_list, is_last=is_last,
        )
        return [task][:_MAX_TASKS_PER_TURN]


class ObjectivePlanner:
    """Thin wrapper matching this codebase's domain-planner shape — no LLM
    seam (see module docstring)."""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        *,
        config: "ApexConfig | None" = None,
        **_ignored: Any,
    ) -> None:
        self._core = _ObjectiveDeterministic(
            target,
            registry,
            objective_type=getattr(config, "objective_type", "user_flag") if config else "user_flag",
            candidate_filenames=getattr(config, "user_flag_candidate_filenames", None) if config else None,
            candidate_roots=getattr(config, "user_flag_candidate_roots", None) if config else None,
            max_attempts=getattr(config, "max_user_flag_attempts", 3) if config else 3,
            format_regex=getattr(config, "user_flag_verification_regex", None) if config else None,
            max_output_bytes=getattr(config, "user_flag_max_output_bytes", 4096) if config else 4096,
        )
        self._last_decision: PlanDecision | None = None

    @property
    def last_decision(self) -> PlanDecision | None:
        return self._last_decision

    async def plan(
        self, goal: Goal, subgraph: SubgraphView, evidence: EvidenceBundle
    ) -> list[TaskSpec] | AbandonSignal:
        result = await self._core.plan(goal, subgraph, evidence)
        task_count = len(result) if isinstance(result, list) else 0
        self._last_decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=task_count,
            rejected_task_count=0,
            reasoning_summary="deterministic (ObjectivePlanner has no LLM seam)",
            fallback_used=True,
            timestamp=now(),
            phase=ApexPhase.objective.value,
        )
        return result
