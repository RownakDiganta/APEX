# workflow_orchestration.py
# Pure, no-IO helpers that reify GlobalPlanner's existing phase-dependency ordering into explicit, inspectable, reportable Workflow/Session/Recommendation records, plus the functions that materialize them as EKG deltas.
"""Multi-step exploitation orchestration — reasoning and coordination, not
exploitation (Phase 15).

Everything here is pure — no I/O, no MemoryAPI calls, no tool execution, no
task dispatch — consistent with the blackboard model (memfabric Invariant
7). This module does not change what APEX is capable of doing to a target;
``GlobalPlanner.decide_phase`` already enforces the recon -> web ->
credential -> priv_esc dependency ordering, and every planner in this
package already reasons over the same EKG data these workflows describe.
What Phase 15 adds is a REIFICATION: an explicit, inspectable,
content-addressed ``Workflow``/``Session``/``WorkflowRecommendation`` model
(see ``apex_host/types.py``) that a report or an operator can read directly,
instead of the dependency ordering existing only implicitly inside
``GlobalPlanner._select_phase``'s if-chain.

Why workflows never need "resume" logic
-----------------------------------------
A workflow's step statuses are computed FRESH, every time, from whatever
EKG evidence currently exists — never from remembered/imperative history.
Because memfabric's episodic log is append-only (Invariant 2) and working-
memory nodes are only ever upserted, never deleted (Invariant 3), evidence
for an already-completed step can never disappear. This means a workflow
that reached ``completed`` status on turn 3 is *structurally* incapable of
reverting to an earlier status on turn 5 just because it is re-derived
again — there is no separate "progress" variable to accidentally reset.
"Avoid restarting completed chains" (the task brief's own phrasing) is
therefore satisfied by construction, not by a special case.

Why later stages cannot begin until prerequisites exist
-----------------------------------------------------------
``_evaluate_steps()`` enforces this structurally: once any step in a
workflow is not yet ``completed`` (whether ``pending`` or ``failed``),
every step after it is unconditionally marked ``blocked`` — its own
completion condition is never even evaluated. A step's ``check_fn`` only
ever runs once every step before it has already completed.

No new edge types needed
--------------------------
``indicates`` (host/step -> workflow/session/opportunity), ``contains``
(workflow -> workflow_step), and ``recommends`` (workflow ->
workflow_recommendation) were already generic enough to reuse — mirrors
Phase 14's "reuse existing node/edge types, don't fragment the graph"
discipline exactly.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from memfabric.ids import now
from memfabric.types import Edge, Node

from apex_host.graph_ids import (
    contains_edge_id,
    host_id,
    indicates_edge_id,
    recommends_edge_id,
    session_id as _session_id_fn,
    workflow_id as _workflow_id_fn,
    workflow_recommendation_id,
    workflow_step_id,
)
from apex_host.planners.capabilities import capabilities_from_subgraph
from apex_host.types import (
    OpportunityConfidence,
    Session,
    SessionKind,
    SessionStatus,
    Workflow,
    WorkflowRecommendation,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepStatus,
)

if TYPE_CHECKING:
    from memfabric.types import SubgraphView

# ---------------------------------------------------------------------------
# Step-check helpers — pure predicates over a SubgraphView.
# ---------------------------------------------------------------------------

_LOGIN_CAPABILITY_NAMES = frozenset({"access_validate_ssh", "access_validate_ftp", "access_validate_telnet"})


def _has_login_mechanism(subgraph: "SubgraphView") -> bool:
    if any(n.type == "auth_flow" for n in subgraph.nodes):
        return True
    caps = capabilities_from_subgraph(subgraph)
    return any(c.name in _LOGIN_CAPABILITY_NAMES for c in caps)


def _credential_attempts_and_validations(subgraph: "SubgraphView") -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Returns (attempted, validated) sets of (username, protocol) pairs.

    ``credential`` nodes carry ``protocol``; ``access_state`` nodes carry
    ``service`` set to the same protocol value (see
    ``apex_host/parsers/access_parser.py``) — both default to ``""``
    (pre-Phase-12B Telnet shape), which still matches correctly since both
    sides use the same default.
    """
    attempted: set[tuple[str, str]] = set()
    validated: set[tuple[str, str]] = set()
    for n in subgraph.nodes:
        if n.type == "credential":
            attempted.add((str(n.props.get("username", "")), str(n.props.get("protocol", ""))))
        elif n.type == "access_state":
            validated.add((str(n.props.get("username", "")), str(n.props.get("service", ""))))
    return attempted, validated


def _has_validated_credential(subgraph: "SubgraphView") -> bool:
    return any(n.type == "access_state" for n in subgraph.nodes)


def _credential_attempt_failed(subgraph: "SubgraphView") -> bool:
    attempted, validated = _credential_attempts_and_validations(subgraph)
    return bool(attempted) and not bool(validated)


def _has_priv_esc_data(subgraph: "SubgraphView") -> bool:
    return any(n.type in ("priv_esc_opportunity", "priv_esc_evidence") for n in subgraph.nodes)


def _has_form(subgraph: "SubgraphView") -> bool:
    return any(n.type == "form" for n in subgraph.nodes)


def _has_tech(subgraph: "SubgraphView") -> bool:
    return any(n.type == "tech" for n in subgraph.nodes)


def _has_web_opportunity(subgraph: "SubgraphView") -> bool:
    return any(n.type == "web_opportunity" for n in subgraph.nodes)


def _always_true(_subgraph: "SubgraphView") -> bool:
    return True


_CheckFn = Callable[["SubgraphView"], bool]


class _StepDef:
    __slots__ = ("name", "check_fn", "fail_fn", "description")

    def __init__(self, name: str, check_fn: _CheckFn, fail_fn: _CheckFn | None, description: str) -> None:
        self.name = name
        self.check_fn = check_fn
        self.fail_fn = fail_fn
        self.description = description


class _WorkflowDef:
    __slots__ = ("key", "objective", "prerequisites", "steps")

    def __init__(self, key: str, objective: str, prerequisites: tuple[str, ...], steps: tuple[_StepDef, ...]) -> None:
        self.key = key
        self.objective = objective
        self.prerequisites = prerequisites
        self.steps = steps


# Fixed, deterministic templates — evaluated in this exact order, never
# random, never reordered by confidence or discovery order. Mirrors the two
# action-chain examples in the task brief exactly.
WORKFLOW_TEMPLATES: tuple[_WorkflowDef, ...] = (
    _WorkflowDef(
        key="credential_to_privesc",
        objective="Validate credentials and enumerate privilege-escalation opportunities",
        prerequisites=("host", "service"),
        steps=(
            _StepDef("discover_login", _has_login_mechanism, None,
                     "Identify a login mechanism (SSH/FTP/Telnet capability or a discovered web auth_flow)"),
            _StepDef("validate_credentials", _has_validated_credential, _credential_attempt_failed,
                     "Attempt bounded, operator-supplied credential validation"),
            _StepDef("enumerate_privilege", _has_priv_esc_data, None,
                     "Enumerate privilege-escalation opportunities over the validated session"),
            _StepDef("generate_recommendations", _always_true, None,
                     "Summarize enumerated opportunities into advisory recommendations"),
        ),
    ),
    _WorkflowDef(
        key="web_discovery_to_opportunity",
        objective="Discover web functionality and identify potential opportunities",
        prerequisites=("host", "endpoint"),
        steps=(
            _StepDef("discover_form", _has_form, None, "Discover forms (login/upload/search) on visited pages"),
            _StepDef("inspect_technology", _has_tech, None, "Detect the technology stack in use"),
            _StepDef("identify_opportunity", _has_web_opportunity, None, "Identify structured web opportunities"),
        ),
    ),
)

# Deterministic tie-breaker for ranking — never affects which workflows
# exist, only display/report ordering.
_STATUS_PRIORITY: dict[str, int] = {
    WorkflowStatus.running.value: 0,
    WorkflowStatus.blocked.value: 1,
    WorkflowStatus.stalled.value: 2,
    WorkflowStatus.completed.value: 3,
    WorkflowStatus.abandoned.value: 4,
}


def _evaluate_steps(step_defs: tuple[_StepDef, ...], subgraph: "SubgraphView") -> list[WorkflowStep]:
    """Evaluate a workflow's steps in order.

    Once any step is not ``completed``, every subsequent step is
    unconditionally ``blocked`` — see module docstring "Why later stages
    cannot begin until prerequisites exist".
    """
    steps: list[WorkflowStep] = []
    prereqs_met = True
    for step_def in step_defs:
        if not prereqs_met:
            status = WorkflowStepStatus.blocked
        elif step_def.check_fn(subgraph):
            status = WorkflowStepStatus.completed
        elif step_def.fail_fn is not None and step_def.fail_fn(subgraph):
            status = WorkflowStepStatus.failed
        else:
            status = WorkflowStepStatus.pending
        steps.append(WorkflowStep(name=step_def.name, status=status, description=step_def.description))
        if status is not WorkflowStepStatus.completed:
            prereqs_met = False
    return steps


def _workflow_status(
    steps: list[WorkflowStep], *, engagement_completed: bool, engagement_outcome: str,
) -> WorkflowStatus:
    if all(s.status is WorkflowStepStatus.completed for s in steps):
        return WorkflowStatus.completed
    if any(s.status is WorkflowStepStatus.failed for s in steps):
        return WorkflowStatus.blocked
    if engagement_outcome in ("duplicate_task_stall", "no_actionable_task", "policy_blocked"):
        return WorkflowStatus.stalled
    if engagement_completed:
        return WorkflowStatus.abandoned
    return WorkflowStatus.running


def derive_workflows_from_subgraph(
    target: str,
    subgraph: "SubgraphView",
    *,
    engagement_completed: bool = False,
    engagement_outcome: str = "",
) -> list[Workflow]:
    """Derive the current set of applicable ``Workflow`` records.

    A template is only included when its own ``prerequisites`` (EKG node
    types) are present — a workflow whose prerequisites don't exist yet
    isn't "not started", it simply isn't applicable to this target yet
    (e.g. a pure-SSH target never produces a ``web_discovery_to_opportunity``
    workflow at all).
    """
    node_types_seen = {n.type for n in subgraph.nodes}
    ts = now()
    out: list[Workflow] = []
    for wf_def in WORKFLOW_TEMPLATES:
        if not set(wf_def.prerequisites).issubset(node_types_seen):
            continue
        steps = _evaluate_steps(wf_def.steps, subgraph)
        status = _workflow_status(
            steps, engagement_completed=engagement_completed, engagement_outcome=engagement_outcome,
        )
        completed_fraction = (
            sum(1 for s in steps if s.status is WorkflowStepStatus.completed) / len(steps) if steps else 0.0
        )
        out.append(
            Workflow(
                id=_workflow_id_fn(target, wf_def.key),
                key=wf_def.key,
                objective=wf_def.objective,
                prerequisites=wf_def.prerequisites,
                steps=tuple(steps),
                status=status,
                confidence=OpportunityConfidence.from_score(completed_fraction),
                first_seen=ts,
                last_seen=ts,
            )
        )
    return out


def rank_workflows(workflows: list[Workflow]) -> list[Workflow]:
    """Deterministic ranking: status priority, then workflow id — never
    random, never insertion-order-dependent."""
    return sorted(workflows, key=lambda w: (_STATUS_PRIORITY.get(w.status.value, 50), w.id))


# ---------------------------------------------------------------------------
# Sessions — planning objects only, never a live executable session.
# ---------------------------------------------------------------------------

_PROTOCOL_SESSION_KINDS: tuple[SessionKind, ...] = (SessionKind.ssh, SessionKind.ftp, SessionKind.telnet)


def _protocol_matches(kind: SessionKind, protocol: str) -> bool:
    protocol = protocol.lower()
    if kind is SessionKind.telnet:
        return protocol == "" or "telnet" in protocol
    return kind.value in protocol


def derive_sessions_from_subgraph(target: str, subgraph: "SubgraphView") -> list[Session]:
    """Derive planning-object ``Session`` records from already-recorded
    credential/browser evidence. Never includes a password or cookie value
    — only counts, protocol names, and usernames (already-plaintext EKG
    data per the existing credential/browser conventions)."""
    ts = now()
    sessions: list[Session] = []

    endpoints = [n for n in subgraph.nodes if n.type == "endpoint"]
    if endpoints:
        browsed_count = sum(1 for n in endpoints if n.props.get("browsed") is True)
        status = SessionStatus.active if browsed_count > 0 else SessionStatus.inactive
        sessions.append(Session(
            id=_session_id_fn(target, SessionKind.browser.value),
            kind=SessionKind.browser, target=target, status=status,
            detail=f"{browsed_count} page(s) visited", first_seen=ts, last_seen=ts,
        ))

    attempted, validated = _credential_attempts_and_validations(subgraph)
    if attempted or validated:
        protocols = sorted({p for _u, p in (attempted | validated) if p} or {"telnet"})
        sessions.append(Session(
            id=_session_id_fn(target, SessionKind.credential.value),
            kind=SessionKind.credential, target=target,
            status=SessionStatus.active if validated else SessionStatus.attempted,
            detail=f"protocols attempted: {', '.join(protocols)}", first_seen=ts, last_seen=ts,
        ))

    for kind in _PROTOCOL_SESSION_KINDS:
        kind_attempted = {(u, p) for u, p in attempted if _protocol_matches(kind, p)}
        kind_validated = {(u, p) for u, p in validated if _protocol_matches(kind, p)}
        if not kind_attempted and not kind_validated:
            continue
        usernames = sorted({u for u, _p in (kind_attempted | kind_validated) if u})
        sessions.append(Session(
            id=_session_id_fn(target, kind.value),
            kind=kind, target=target,
            status=SessionStatus.active if kind_validated else SessionStatus.attempted,
            detail=f"username(s): {', '.join(usernames) if usernames else 'unknown'}",
            first_seen=ts, last_seen=ts,
        ))

    return sessions


def rank_sessions(sessions: list[Session]) -> list[Session]:
    """Deterministic ranking: kind name, then id — never random."""
    return sorted(sessions, key=lambda s: (s.kind.value, s.id))


# ---------------------------------------------------------------------------
# Recommendations — advisory text only, never an executable action.
# ---------------------------------------------------------------------------

def workflow_recommendation_text(workflow: Workflow) -> str:
    if workflow.status is WorkflowStatus.completed:
        return (
            f"Workflow '{workflow.objective}' is complete; review the collected "
            "evidence for manual follow-up. APEX does not act on it automatically."
        )
    if workflow.status is WorkflowStatus.blocked:
        failed = ", ".join(workflow.failed_steps) or "an earlier step"
        return (
            f"Workflow '{workflow.objective}' is blocked at {failed!r}; manual "
            "operator intervention is required before this chain can proceed."
        )
    if workflow.status in (WorkflowStatus.stalled, WorkflowStatus.abandoned):
        return (
            f"Workflow '{workflow.objective}' did not complete this engagement; "
            "manual review of the partial evidence is recommended."
        )
    next_candidate = workflow.next_candidate or "the next step"
    return (
        f"Workflow '{workflow.objective}' can proceed to {next_candidate!r}; "
        "continued automated data collection is safe to continue."
    )


# ---------------------------------------------------------------------------
# Graph materialization — Workflow/Session objects -> Node/Edge deltas.
# ---------------------------------------------------------------------------

def build_workflow_graph_deltas(
    target: str, workflows: list[Workflow], sessions: list[Session],
) -> tuple[list[Node], list[Edge]]:
    """Convert already-derived ``Workflow``/``Session`` objects into EKG
    node/edge deltas, ready for ``MemoryAPI.apply_deltas()``.

    Every node is content-addressed (workflow/step/session/recommendation
    IDs depend only on target+key/name — never on status), so re-deriving
    and re-applying identical input upserts the same nodes rather than
    creating duplicates (memfabric per-field LWW upsert). Every node also
    has a path back to the ``host`` anchor — orphaned nodes would be
    invisible to ``MemoryAPI.get_subgraph()``'s bounded traversal (the exact
    class of bug Phase 13/14 each hit and fixed for their own new node
    types).
    """
    nodes: list[Node] = []
    edges: list[Edge] = []
    ts = now()
    h_id = host_id(target)

    for session in sessions:
        nodes.append(Node(
            id=session.id, type="session",
            props={
                "kind": session.kind.value, "target": session.target,
                "status": session.status.value, "detail": session.detail,
            },
            confidence=0.7, source="workflow_orchestration", first_seen=ts, last_seen=ts,
        ))
        edges.append(Edge(
            id=indicates_edge_id(h_id, session.id), from_id=h_id, to_id=session.id, type="indicates",
            props={}, confidence=0.7, source="workflow_orchestration", first_seen=ts, last_seen=ts,
        ))

    sessions_by_kind = {s.kind: s for s in sessions}

    for workflow in workflows:
        nodes.append(Node(
            id=workflow.id, type="workflow",
            props={
                "key": workflow.key, "target": target, "objective": workflow.objective,
                "prerequisites": list(workflow.prerequisites),
                "status": workflow.status.value, "confidence": workflow.confidence.value,
                "completed_steps": workflow.completed_steps, "blocked_steps": workflow.blocked_steps,
                "failed_steps": workflow.failed_steps, "next_candidate": workflow.next_candidate,
                "completion_percentage": workflow.completion_percentage,
            },
            confidence=workflow.confidence.as_float(), source="workflow_orchestration",
            first_seen=ts, last_seen=ts,
        ))
        edges.append(Edge(
            id=indicates_edge_id(h_id, workflow.id), from_id=h_id, to_id=workflow.id, type="indicates",
            props={}, confidence=workflow.confidence.as_float(), source="workflow_orchestration",
            first_seen=ts, last_seen=ts,
        ))

        for step in workflow.steps:
            step_id = workflow_step_id(workflow.id, step.name)
            nodes.append(Node(
                id=step_id, type="workflow_step",
                props={
                    "name": step.name, "status": step.status.value, "description": step.description,
                    "workflow_id": workflow.id,
                },
                confidence=0.7, source="workflow_orchestration", first_seen=ts, last_seen=ts,
            ))
            edges.append(Edge(
                id=contains_edge_id(workflow.id, step_id), from_id=workflow.id, to_id=step_id, type="contains",
                props={}, confidence=0.7, source="workflow_orchestration", first_seen=ts, last_seen=ts,
            ))
            # Link the credential-validation step to its matching session,
            # when one exists — satisfies the "steps -> sessions" graph shape.
            if step.name == "validate_credentials":
                for kind in (SessionKind.credential, SessionKind.ssh, SessionKind.ftp, SessionKind.telnet):
                    sess = sessions_by_kind.get(kind)
                    if sess is not None:
                        edges.append(Edge(
                            id=indicates_edge_id(step_id, sess.id), from_id=step_id, to_id=sess.id, type="indicates",
                            props={}, confidence=0.7, source="workflow_orchestration", first_seen=ts, last_seen=ts,
                        ))
            elif step.name == "discover_form" and SessionKind.browser in sessions_by_kind:
                sess = sessions_by_kind[SessionKind.browser]
                edges.append(Edge(
                    id=indicates_edge_id(step_id, sess.id), from_id=step_id, to_id=sess.id, type="indicates",
                    props={}, confidence=0.7, source="workflow_orchestration", first_seen=ts, last_seen=ts,
                ))

        rec_id = workflow_recommendation_id(workflow.id)
        rec_text = workflow_recommendation_text(workflow)
        nodes.append(Node(
            id=rec_id, type="workflow_recommendation",
            props={"text": rec_text, "category": workflow.key, "priority": workflow.confidence.value, "workflow_id": workflow.id},
            confidence=workflow.confidence.as_float(), source="workflow_orchestration", first_seen=ts, last_seen=ts,
        ))
        edges.append(Edge(
            id=recommends_edge_id(workflow.id, rec_id), from_id=workflow.id, to_id=rec_id, type="recommends",
            props={}, confidence=workflow.confidence.as_float(), source="workflow_orchestration",
            first_seen=ts, last_seen=ts,
        ))

    return nodes, edges


def workflow_recommendations_from_workflows(workflows: list[Workflow]) -> list[WorkflowRecommendation]:
    """Build ``WorkflowRecommendation`` view objects directly from already-
    ranked ``Workflow`` records — used by the report, which prefers the
    freshest possible text rather than re-reading persisted node props."""
    out: list[WorkflowRecommendation] = []
    for w in workflows:
        out.append(WorkflowRecommendation(
            id=workflow_recommendation_id(w.id), workflow_id=w.id,
            text=workflow_recommendation_text(w), category=w.key, priority=w.confidence,
        ))
    return out


def workflow_summary_fields(target: str, subgraph: "SubgraphView") -> dict[str, Any]:
    """Build the ``ApexGraphState`` partial-update dict for the current turn.

    Pure derivation from the subgraph — mirrors
    ``priv_esc_opportunities.privilege_state_fields`` /
    ``web_opportunities.web_session_state_fields`` exactly. Always uses
    ``engagement_completed=False`` here (the live, in-engagement view can
    never know in advance that this turn is the terminating one) — the
    final report re-derives independently with the real, final
    ``engagement_completed``/``engagement_outcome`` values (see
    ``apex_host.eval.report.build_report``), so this one-turn-stale
    live snapshot never affects report correctness.
    """
    workflows = rank_workflows(derive_workflows_from_subgraph(target, subgraph))
    sessions = rank_sessions(derive_sessions_from_subgraph(target, subgraph))
    counts: dict[str, int] = {}
    for w in workflows:
        counts[w.status.value] = counts.get(w.status.value, 0) + 1
    return {
        "workflow_summary": {
            "workflow_count": len(workflows),
            "status_counts": counts,
            "active_session_count": sum(1 for s in sessions if s.status is SessionStatus.active),
        },
    }
