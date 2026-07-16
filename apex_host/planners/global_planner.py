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

Phase 12A (R1) state-machine fixes
-----------------------------------
Bug A (oscillation): budget-exhaustion forcing used to be keyed off the
``current_phase`` argument alone — it only fired on the single call where
``current_phase`` happened to equal the exhausted phase.  Because the
*next* turn's ``current_phase`` is whatever the *previous* call returned
(round-tripped through ``ApexGraphState``), that phase's own budget was
never exhausted, so forcing silently stopped applying and ``_select_phase``
fell back to its organic, EKG-driven condition — which still failed (no
real ``access_state`` yet) and bounced the engagement straight back into
the just-exhausted phase, forever.  ``decide_phase`` now checks every
budget-tracked phase's *own persistent* ``_spent`` counter on every call,
independent of what ``current_phase`` names — so a phase that has
exhausted its budget stays force-skipped on every subsequent call, not
just one.

Bug B (auth_flow != access_state): ``_select_phase`` used to let a bare
``auth_flow`` node (a login mechanism merely *discovered*, e.g. by
``BrowserParser`` finding a login form) satisfy the same condition as
``access_state`` (a *validated* successful login), skipping the credential
phase entirely.  Only ``access_state`` now gates the credential→priv_esc
transition; discovering a login page no longer substitutes for actually
attempting to authenticate.
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

# Maps a budget-tracked phase to the EKG node type that, when synthetically
# injected into node_types_seen, lets _select_phase's organic condition
# advance past that phase even though it was never really satisfied.  Used
# only when the named phase's own turn budget is exhausted (see decide_phase).
#
# credential -> "access_state" (not "auth_flow", per Bug B above): forcing
# past credential on budget exhaustion must use the same field that
# legitimately signals success, so a forced skip and a real success are
# handled by exactly one gate in _select_phase.
_PHASE_COMPLETION_NODE: dict[str, str] = {
    ApexPhase.recon.value: "service",
    ApexPhase.web.value: "endpoint",
    ApexPhase.credential.value: "access_state",
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
        2. Any budget-tracked phase whose own budget is exhausted is
           force-skipped (see ``_PHASE_COMPLETION_NODE``), regardless of
           ``current_phase`` — this is the Bug A fix: forcing must survive
           across turns, not just the one call where ``current_phase``
           happens to name the exhausted phase.
        3. EKG-driven phase selection.

        Parameters
        ----------
        current_phase:
            Accepted for backward compatibility and diagnostic/logging call
            sites (``apex_host/orchestration/planning_node.py`` and
            ``continuation_node.py`` both pass it).  It is no longer the
            sole trigger for budget-exhaustion forcing — see (2) above —
            since keying forcing off a single-call match was the root cause
            of the credential/priv_esc oscillation (Bug A).
        has_web_capability:
            When ``False`` (e.g. no HTTP/HTTPS service in the EKG), the web
            phase is skipped entirely and the engagement proceeds directly from
            recon to credential.  This avoids wasting web-phase budget on
            targets that have no web surface.
        """
        if turn_count >= self._max_turns:
            return ApexPhase.done

        # Force past any budget-tracked phase whose own persistent budget
        # counter is exhausted, no matter what current_phase names.  This is
        # what makes the forced skip *stick* turn over turn: as long as the
        # phase's budget stays at 0, its completion node stays injected.
        forced_node_types = set(node_types_seen)
        for phase_value, completion_node in _PHASE_COMPLETION_NODE.items():
            if self.budget_remaining(phase_value) == 0:
                forced_node_types.add(completion_node)

        return self._select_phase(forced_node_types, has_web_capability=has_web_capability)

    def _select_phase(
        self, node_types_seen: set[str], *, has_web_capability: bool = True
    ) -> ApexPhase:
        """EKG-driven phase selection.

        ``has_web_capability=False`` skips the web phase when no HTTP/HTTPS
        services were discovered, preventing wasted budget on a pure-telnet
        or pure-SSH target.

        Only ``access_state`` (a *validated* successful login) advances the
        engagement past the credential phase (Bug B fix).  A bare
        ``auth_flow`` node — a login mechanism that was merely *discovered*
        (e.g. a web login form found by ``BrowserParser``) — no longer
        substitutes for it: finding a login page is not equivalent to
        authenticating, so it must not skip the one phase
        (``CredentialPlanner``/``execute_agent``) capable of ever producing
        ``access_state``.
        """
        if "host" not in node_types_seen:
            return ApexPhase.recon
        if "service" not in node_types_seen:
            return ApexPhase.recon
        if "endpoint" not in node_types_seen and has_web_capability:
            return ApexPhase.web
        if "access_state" not in node_types_seen:
            return ApexPhase.credential
        if "service" in node_types_seen:
            return ApexPhase.priv_esc
        return ApexPhase.done

    def goal_for_phase(self, phase: ApexPhase, target: str) -> str:
        return _PHASE_GOALS[phase].format(target=target)
