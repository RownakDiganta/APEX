# global_planner.py
# Rule-based global phase router with per-phase budget tracking and optional LLM goal decomposition.
"""Rule-based phase router for the top-level APEX engagement.

Unlike the other planners in this package, GlobalPlanner does not implement
memfabric.coordination.protocols.Planner (it doesn't emit TaskSpecs) — it
decides which ApexPhase the engagement should be in next, based on which
node types have been observed so far and the turn budget. apex_host/graph.py
calls it directly from the ``global_plan`` node.

New in this version:
- ``record_turn(phase)`` — tracks turns spent per phase for budget accounting.
- ``budget_remaining(phase)`` — returns remaining turns for a phase.
- ``phase_budgets`` constructor param overrides default per-phase turn ceilings.
  When a phase exhausts its budget, ``decide_phase`` advances to the next phase
  even if the usual EKG-node trigger hasn't fired yet.

The LLM seam for GlobalPlanner is reserved for future goal decomposition
(breaking a high-level goal into sub-goals). Phase selection itself remains
deterministic so the engagement never gets stuck or loops unexpectedly.
"""
from __future__ import annotations

from apex_host.types import ApexPhase

_PHASE_GOALS: dict[ApexPhase, str] = {
    ApexPhase.recon: "Perform reconnaissance on {target}",
    ApexPhase.web: "Enumerate web endpoints on {target}",
    ApexPhase.credential: "Probe authentication flows on {target}",
    ApexPhase.priv_esc: "Enumerate privilege-escalation surface on {target}",
    ApexPhase.exploit: "Investigate exploitation surface on {target}",
    ApexPhase.lateral: "Investigate lateral-movement surface on {target}",
    ApexPhase.done: "Engagement on {target} complete",
}

# Default maximum turns allowed per phase before force-advancing.
# These are generous defaults; a real engagement may need fewer.
_DEFAULT_PHASE_BUDGETS: dict[str, int] = {
    ApexPhase.recon.value: 6,
    ApexPhase.web.value: 5,
    ApexPhase.credential.value: 4,
    ApexPhase.priv_esc.value: 4,
    ApexPhase.exploit.value: 4,
    ApexPhase.lateral.value: 4,
}


class GlobalPlanner:
    """Deterministic phase router with per-phase budget tracking.

    LLM seam: swap ``decide_phase`` or add ``decompose_goal`` backed by the
    PlanningEngine in a future iteration without touching graph.py.

    Parameters
    ----------
    max_turns:
        Hard ceiling on total engagement turns.  When reached, phase is set
        to ``done`` regardless of EKG state.
    phase_budgets:
        Optional dict of ``{phase_value: max_turns_in_phase}``.  Merges with
        ``_DEFAULT_PHASE_BUDGETS`` (provided keys override defaults).  When a
        phase's budget is exhausted, the planner force-advances regardless of
        the usual EKG trigger.
    """

    def __init__(
        self,
        max_turns: int,
        *,
        phase_budgets: dict[str, int] | None = None,
    ) -> None:
        self._max_turns = max_turns
        self._budgets: dict[str, int] = dict(_DEFAULT_PHASE_BUDGETS)
        if phase_budgets:
            self._budgets.update(phase_budgets)
        # Mutable: tracks turns spent in each phase across the engagement.
        self._spent: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Budget accounting
    # ------------------------------------------------------------------

    def record_turn(self, phase: ApexPhase | str) -> None:
        """Increment the turn counter for *phase* by one."""
        key = phase.value if isinstance(phase, ApexPhase) else str(phase)
        self._spent[key] = self._spent.get(key, 0) + 1

    def budget_remaining(self, phase: ApexPhase | str) -> int:
        """Return remaining turns allowed for *phase* (0 = budget exhausted)."""
        key = phase.value if isinstance(phase, ApexPhase) else str(phase)
        ceiling = self._budgets.get(key, 9999)
        return max(0, ceiling - self._spent.get(key, 0))

    # ------------------------------------------------------------------
    # Phase selection
    # ------------------------------------------------------------------

    def decide_phase(
        self,
        *,
        node_types_seen: set[str],
        turn_count: int,
        current_phase: str | None = None,
        has_web_capability: bool = True,
    ) -> ApexPhase:
        """Return the phase the engagement should run in this turn.

        Decision order (first match wins):
        1. Hard budget ceiling → done.
        2. Current phase budget exhausted → advance to the next EKG-driven phase.
        3. EKG-driven phase selection.

        Parameters
        ----------
        has_web_capability:
            When ``False`` (e.g. no HTTP/HTTPS service in the EKG), the web
            phase is skipped entirely and the engagement proceeds directly from
            recon to credential.  This avoids wasting web-phase budget on
            targets that have no web surface.
        """
        if turn_count >= self._max_turns:
            return ApexPhase.done

        # If the current phase has exhausted its budget, skip to the EKG logic
        # for the *next* phase by pretending the completion node was observed.
        forced_node_types = set(node_types_seen)
        if current_phase and self.budget_remaining(current_phase) == 0:
            _phase_to_completion_node: dict[str, str] = {
                ApexPhase.recon.value: "service",
                ApexPhase.web.value: "endpoint",
                ApexPhase.credential.value: "auth_flow",
            }
            completion_node = _phase_to_completion_node.get(current_phase)
            if completion_node:
                forced_node_types.add(completion_node)

        return self._select_phase(forced_node_types, has_web_capability=has_web_capability)

    def _select_phase(
        self, node_types_seen: set[str], *, has_web_capability: bool = True
    ) -> ApexPhase:
        """EKG-driven phase selection.

        ``has_web_capability=False`` skips the web phase when no HTTP/HTTPS
        services were discovered, preventing wasted budget on a pure-telnet
        or pure-SSH target.

        ``access_state`` in node_types_seen signals a successful login and
        triggers priv_esc advance alongside the existing ``auth_flow`` trigger,
        so the engagement advances naturally after a successful telnet login
        without waiting for the credential phase budget to exhaust.
        """
        if "host" not in node_types_seen:
            return ApexPhase.recon
        if "service" not in node_types_seen:
            return ApexPhase.recon
        if "endpoint" not in node_types_seen and has_web_capability:
            return ApexPhase.web
        if "auth_flow" not in node_types_seen and "access_state" not in node_types_seen:
            return ApexPhase.credential
        if "service" in node_types_seen:
            return ApexPhase.priv_esc
        return ApexPhase.done

    def goal_for_phase(self, phase: ApexPhase, target: str) -> str:
        return _PHASE_GOALS[phase].format(target=target)
