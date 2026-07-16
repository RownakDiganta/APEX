# experience_replay.py
# Pure, no-IO helpers implementing deterministic reflection and experience replay: turning one engagement's outcome into structured, content-addressed Experience records that later engagements can retrieve and rank — never machine learning.
"""Adaptive learning, reflection & experience replay (Phase 16).

Everything here is pure — no I/O, no MemoryAPI calls, no tool execution, no
task dispatch — consistent with the blackboard model (memfabric Invariant
7). Nothing here is machine learning: there is no model, no training loop,
no gradient, no probabilistic prediction. Every "learning rule" is a fixed,
hand-written, deterministic function over a counted number of repetitions
(``apply_learning_rule``) — the exact same kind of rule table this codebase
already uses for opportunity ranking (Phase 13/14) and workflow status
(Phase 15), just applied to cross-engagement repetition instead of
within-engagement EKG state.

Two responsibilities:

1. ``experiences_from_subgraph`` / ``rank_experiences`` reconstruct the
   current ``Experience`` set from ``experience`` EKG nodes — mirrors
   ``priv_esc_opportunities.opportunities_from_subgraph`` /
   ``web_opportunities.opportunities_from_subgraph`` /
   ``workflow_orchestration.derive_workflows_from_subgraph`` exactly. This
   is the "retrieve previous experiences" half of experience replay.

2. ``derive_experiences_from_engagement`` is the REFLECTION ENGINE — run
   once at the end of an engagement (see
   ``apex_host.runtime.ApexRuntime.run()``), it reads the final subgraph
   plus the final ``ApexGraphState`` and produces (or updates) structured
   ``Experience`` records: which workflows succeeded/failed/were abandoned
   (Phase 15), which planner actions were repeated needlessly, which
   browser/priv-esc findings recurred, and which credential validations
   failed. When an experience with the SAME id already exists (from an
   earlier engagement sharing the same ``MemoryAPI`` instance), its
   ``occurrence_count`` is incremented and its confidence is adjusted by
   ``apply_learning_rule`` — this IS the replay mechanism: a
   content-addressed upsert, never a remembered Python object.

No automatic planner override
------------------------------
Nothing in this module is imported by, or changes the behavior of,
``ReconPlanner``/``WebPlanner``/``BrowserPlanner``/``CredentialPlanner``/
``PrivEscPlanner``/``BrowserPlanner``/``GlobalPlanner``. Experiences are
attached to "planner context" purely by being written into the SAME EKG
subgraph every planner already reads (they are anchored to ``host`` like
every other Phase 13/14/15 record) — a planner that wants to consult them
can call ``experiences_from_subgraph(subgraph)`` itself, but no existing
planner in this codebase does so automatically. This is a deliberate,
tested invariant (see ``docs/experience-replay.md`` "No automatic planner
override" and ``tests/apex_host/test_phase16_experience_replay.py``).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memfabric.ids import now
from memfabric.types import Edge, Node

from apex_host.graph_ids import (
    experience_id as _experience_id_fn,
    experience_recommendation_id,
    host_id,
    indicates_edge_id,
    recommends_edge_id,
)
from apex_host.planners.priv_esc_opportunities import opportunities_from_subgraph as priv_esc_opportunities_from_subgraph
from apex_host.planners.web_opportunities import opportunities_from_subgraph as web_opportunities_from_subgraph
from apex_host.planners.workflow_orchestration import derive_workflows_from_subgraph
from apex_host.types import (
    Experience,
    ExperienceCategory,
    OpportunityConfidence,
    ReflectionSummary,
    WorkflowStatus,
)

if TYPE_CHECKING:
    from memfabric.types import SubgraphView

    from apex_host.graph_state import ApexGraphState

# Categories whose confidence INCREASES as occurrence_count grows — a
# recurring signal is a STRONGER signal here (a persistently duplicated
# planner action really is wasteful; a recurring privilege-escalation
# opportunity really does deserve more attention; a workflow that keeps
# succeeding is a reliably reproducible path).
_REINFORCE_UP: frozenset[ExperienceCategory] = frozenset({
    ExperienceCategory.repeated_planner_mistake,
    ExperienceCategory.repeated_privilege_opportunity,
    ExperienceCategory.successful_workflow,
})

# Categories whose confidence DECREASES as occurrence_count grows — a
# recurring signal here means "already known, diminishing returns" (a
# browser-discovery category that keeps turning up is saturated, not
# newly interesting) or "confirmed unreliable" (a credential/workflow that
# keeps failing is less and less worth retrying).
_REINFORCE_DOWN: frozenset[ExperienceCategory] = frozenset({
    ExperienceCategory.repeated_browser_finding,
    ExperienceCategory.repeated_credential_outcome,
    ExperienceCategory.failed_workflow,
    ExperienceCategory.abandoned_workflow,
})

# Deterministic per-repetition confidence step. Never random, never a
# learned/fitted parameter — a fixed constant, same convention as
# memfabric's own Reflector `decay_factor`/`skill_prior` config constants.
_CONFIDENCE_STEP = 0.15

# Deterministic category ordering used only as a ranking tie-breaker.
_CATEGORY_PRIORITY: dict[str, int] = {
    ExperienceCategory.repeated_privilege_opportunity.value: 0,
    ExperienceCategory.failed_workflow.value: 1,
    ExperienceCategory.repeated_credential_outcome.value: 2,
    ExperienceCategory.repeated_planner_mistake.value: 3,
    ExperienceCategory.repeated_browser_finding.value: 4,
    ExperienceCategory.successful_workflow.value: 5,
    ExperienceCategory.abandoned_workflow.value: 6,
    ExperienceCategory.none.value: 99,
}

_MAX_EXCERPT_CHARS = 200


def apply_learning_rule(
    category: ExperienceCategory, occurrence_count: int, base_confidence: OpportunityConfidence,
) -> OpportunityConfidence:
    """The fixed, deterministic confidence-adjustment table (never a
    trained model). ``occurrence_count`` is always >= 1 (an experience is
    only ever created once its base condition is already met); the
    adjustment only applies for repeats (``occurrence_count > 1``).
    """
    if occurrence_count <= 1:
        return base_confidence
    steps = occurrence_count - 1
    score = base_confidence.as_float()
    if category in _REINFORCE_UP:
        score = min(1.0, score + _CONFIDENCE_STEP * steps)
    elif category in _REINFORCE_DOWN:
        score = max(0.0, score - _CONFIDENCE_STEP * steps)
    return OpportunityConfidence.from_score(score)


def _node_to_experience(node: "Node") -> Experience | None:
    props = node.props
    try:
        category = ExperienceCategory(str(props.get("category", "")))
        confidence = OpportunityConfidence(str(props.get("confidence", "")))
    except ValueError:
        return None
    return Experience(
        id=node.id,
        category=category,
        target=str(props.get("target", "")),
        discriminator=str(props.get("discriminator", "")),
        context=str(props.get("context", "")),
        evidence_excerpt=str(props.get("evidence_excerpt", "")),
        outcome=str(props.get("outcome", "")),
        recommendation=str(props.get("recommendation", "")),
        confidence=confidence,
        occurrence_count=int(props.get("occurrence_count", 1) or 1),
        first_seen=node.first_seen,
        last_seen=node.last_seen,
    )


def experiences_from_subgraph(subgraph: "SubgraphView") -> list[Experience]:
    """Reconstruct every recorded ``Experience`` from the subgraph — the
    "retrieve previous experiences" half of experience replay.

    Nodes whose ``category``/``confidence`` props no longer parse as a
    known enum member are skipped (forward-compatibility, mirrors every
    other ``*_from_subgraph`` reconstructor in this codebase)."""
    out: list[Experience] = []
    for node in subgraph.nodes:
        if node.type != "experience":
            continue
        exp = _node_to_experience(node)
        if exp is not None:
            out.append(exp)
    return out


def rank_experiences(experiences: list[Experience]) -> list[Experience]:
    """Deterministic ranking: confidence desc, then category priority, then
    id asc — never random, never insertion-order-dependent."""
    return sorted(
        experiences,
        key=lambda e: (-e.confidence.as_float(), _CATEGORY_PRIORITY.get(e.category.value, 50), e.id),
    )


# ---------------------------------------------------------------------------
# Reflection engine — derive new/updated experiences from one engagement.
# ---------------------------------------------------------------------------

def _existing_by_id(subgraph: "SubgraphView") -> dict[str, Experience]:
    return {e.id: e for e in experiences_from_subgraph(subgraph)}


def _make_experience(
    existing: dict[str, Experience],
    *,
    exp_id: str,
    category: ExperienceCategory,
    target: str,
    discriminator: str,
    context: str,
    evidence_excerpt: str,
    outcome: str,
    base_confidence: OpportunityConfidence,
    ts: str,
) -> Experience:
    prior = existing.get(exp_id)
    occurrence_count = (prior.occurrence_count + 1) if prior is not None else 1
    confidence = apply_learning_rule(category, occurrence_count, base_confidence)
    return Experience(
        id=exp_id, category=category, target=target, discriminator=discriminator, context=context,
        evidence_excerpt=evidence_excerpt[:_MAX_EXCERPT_CHARS], outcome=outcome,
        recommendation="",  # filled in by recommendation_text_for_experience() below
        confidence=confidence, occurrence_count=occurrence_count,
        first_seen=prior.first_seen if prior is not None else ts, last_seen=ts,
    )


def derive_experiences_from_engagement(
    target: str, subgraph: "SubgraphView", final_state: "ApexGraphState | dict[str, Any]",
) -> list[Experience]:
    """The reflection engine: derive (or update, via replay) the full set of
    ``Experience`` records for one completed engagement.

    Deterministic — the same ``subgraph``+``final_state`` always produce
    the same output, in the same order. No LLM call, no randomness.
    """
    ts = now()
    existing = _existing_by_id(subgraph)
    out: list[Experience] = []

    # ---- Workflow outcomes (Phase 15) ----
    engagement_completed = bool(final_state.get("completed", False))
    engagement_outcome = str(final_state.get("outcome") or "")
    workflows = derive_workflows_from_subgraph(
        target, subgraph, engagement_completed=engagement_completed, engagement_outcome=engagement_outcome,
    )
    _WORKFLOW_STATUS_MAP: dict[WorkflowStatus, tuple[ExperienceCategory, OpportunityConfidence]] = {
        WorkflowStatus.completed: (ExperienceCategory.successful_workflow, OpportunityConfidence.high),
        WorkflowStatus.blocked: (ExperienceCategory.failed_workflow, OpportunityConfidence.medium),
        WorkflowStatus.stalled: (ExperienceCategory.failed_workflow, OpportunityConfidence.medium),
        WorkflowStatus.abandoned: (ExperienceCategory.abandoned_workflow, OpportunityConfidence.low),
    }
    for wf in workflows:
        mapping = _WORKFLOW_STATUS_MAP.get(wf.status)
        if mapping is None:  # running — no terminal outcome yet, nothing to learn
            continue
        category, base_conf = mapping
        exp_id = _experience_id_fn(target, category.value, wf.key)
        out.append(_make_experience(
            existing, exp_id=exp_id, category=category, target=target, discriminator=wf.key,
            context=f"workflow {wf.key!r}: {wf.objective}",
            evidence_excerpt=f"status={wf.status.value} completion={wf.completion_percentage}%",
            outcome=wf.status.value, base_confidence=base_conf, ts=ts,
        ))

    # ---- Repeated planner mistakes: duplicate (tool, phase) task attempts ----
    duplicate_actions = list(final_state.get("duplicate_actions") or [])
    seen_dup_pairs: set[tuple[str, str]] = set()
    for entry in duplicate_actions:
        pair = (str(entry.get("tool", "")), str(entry.get("phase", "")))
        if pair in seen_dup_pairs or not pair[0]:
            continue
        seen_dup_pairs.add(pair)
        discriminator = f"{pair[0]}:{pair[1]}"
        exp_id = _experience_id_fn(target, ExperienceCategory.repeated_planner_mistake.value, discriminator)
        out.append(_make_experience(
            existing, exp_id=exp_id, category=ExperienceCategory.repeated_planner_mistake, target=target,
            discriminator=discriminator,
            context=f"tool {pair[0]!r} re-planned in phase {pair[1]!r} after already completing",
            evidence_excerpt=str(entry.get("reason", ""))[:_MAX_EXCERPT_CHARS],
            outcome="duplicate_task", base_confidence=OpportunityConfidence.medium, ts=ts,
        ))

    # ---- Repeated browser findings (Phase 14 web_opportunity categories) ----
    web_opps = web_opportunities_from_subgraph(subgraph)
    web_counts: dict[str, int] = {}
    for web_opp in web_opps:
        web_counts[web_opp.category.value] = web_counts.get(web_opp.category.value, 0) + 1
    for category_name, count in sorted(web_counts.items()):
        if count < 2:
            continue
        exp_id = _experience_id_fn(target, ExperienceCategory.repeated_browser_finding.value, category_name)
        out.append(_make_experience(
            existing, exp_id=exp_id, category=ExperienceCategory.repeated_browser_finding, target=target,
            discriminator=category_name,
            context=f"web opportunity category {category_name!r} recurred {count} time(s)",
            evidence_excerpt=f"count={count}", outcome="recurring_finding",
            base_confidence=OpportunityConfidence.medium, ts=ts,
        ))

    # ---- Repeated privilege opportunities (Phase 13/13B categories) ----
    priv_opps = priv_esc_opportunities_from_subgraph(subgraph)
    priv_counts: dict[str, int] = {}
    for priv_opp in priv_opps:
        priv_counts[priv_opp.category.value] = priv_counts.get(priv_opp.category.value, 0) + 1
    for category_name, count in sorted(priv_counts.items()):
        if count < 2:
            continue
        exp_id = _experience_id_fn(target, ExperienceCategory.repeated_privilege_opportunity.value, category_name)
        out.append(_make_experience(
            existing, exp_id=exp_id, category=ExperienceCategory.repeated_privilege_opportunity, target=target,
            discriminator=category_name,
            context=f"privilege-escalation category {category_name!r} recurred {count} time(s)",
            evidence_excerpt=f"count={count}", outcome="recurring_opportunity",
            base_confidence=OpportunityConfidence.medium, ts=ts,
        ))

    # ---- Repeated (failed) credential outcomes (Phase 12B) ----
    cred_log = list(final_state.get("credential_validation_log") or [])
    seen_protocols: set[str] = set()
    for entry in cred_log:
        protocol = str(entry.get("protocol", ""))
        if not protocol or protocol in seen_protocols:
            continue
        if bool(entry.get("success", False)):
            continue  # only failures are "repeated credential outcome" candidates
        seen_protocols.add(protocol)
        exp_id = _experience_id_fn(target, ExperienceCategory.repeated_credential_outcome.value, protocol)
        out.append(_make_experience(
            existing, exp_id=exp_id, category=ExperienceCategory.repeated_credential_outcome, target=target,
            discriminator=protocol,
            context=f"{protocol} credential validation did not succeed",
            evidence_excerpt=str(entry.get("error_category", ""))[:_MAX_EXCERPT_CHARS],
            outcome="credential_failed", base_confidence=OpportunityConfidence.medium, ts=ts,
        ))

    # Fill in recommendation text now that confidence/occurrence_count are final.
    return [
        Experience(
            id=e.id, category=e.category, target=e.target, discriminator=e.discriminator, context=e.context,
            evidence_excerpt=e.evidence_excerpt, outcome=e.outcome,
            recommendation=recommendation_text_for_experience(e), confidence=e.confidence,
            occurrence_count=e.occurrence_count, first_seen=e.first_seen, last_seen=e.last_seen,
        )
        for e in out
    ]


def recommendation_text_for_experience(experience: Experience) -> str:
    """Fixed, hand-written advisory text per category — never a command or
    payload APEX itself would run, and never overrides any planner
    decision (see module docstring "No automatic planner override")."""
    repeated = f" (seen {experience.occurrence_count}x)" if experience.occurrence_count > 1 else ""
    if experience.category is ExperienceCategory.successful_workflow:
        return f"{experience.context} completed successfully{repeated}; this path is a reliable reference for similar targets."
    if experience.category is ExperienceCategory.failed_workflow:
        return f"{experience.context} was blocked{repeated}; review the failed step manually before relying on this path again."
    if experience.category is ExperienceCategory.abandoned_workflow:
        return f"{experience.context} did not finish before the engagement ended{repeated}; consider a longer turn budget."
    if experience.category is ExperienceCategory.repeated_planner_mistake:
        return f"{experience.context}{repeated}; recommend avoiding this duplicate action in future engagements."
    if experience.category is ExperienceCategory.repeated_browser_finding:
        return f"{experience.context}{repeated}; this finding is well-established — reduce exploration priority for it."
    if experience.category is ExperienceCategory.repeated_privilege_opportunity:
        return f"{experience.context}{repeated}; this is a recurring, high-value signal — increase investigation priority."
    if experience.category is ExperienceCategory.repeated_credential_outcome:
        return f"{experience.context}{repeated}; lower confidence in retrying this exact credential/protocol combination."
    return f"{experience.context}{repeated}."


def build_experience_graph_deltas(
    target: str, experiences: list[Experience], known_node_ids: set[str] | None = None,
) -> tuple[list[Node], list[Edge]]:
    """Convert already-derived ``Experience`` objects into EKG node/edge
    deltas, ready for ``MemoryAPI.apply_deltas()``.

    Content-addressed IDs mean re-deriving and re-applying identical input
    upserts the same nodes rather than creating duplicates. Every node has
    a path back to ``host`` — an orphaned node would be invisible to
    ``MemoryAPI.get_subgraph()``'s bounded traversal (the same class of bug
    Phase 13/14/15 each hit and fixed for their own new node types).

    ``known_node_ids`` (typically the caller's own already-fetched subgraph
    node-id set) is used to safely link a workflow-category experience back
    to its ``workflow`` node — UNLIKE the ``host``/``experience_recommendation``
    edges above, the referenced ``workflow`` node is NOT part of this same
    batch (Phase 15's own sync writes it separately), so linking to it
    blindly would risk ``MemoryAPI.put_edge``'s dangling-edge rejection
    (P8-I05) if that workflow somehow was never persisted. When
    ``known_node_ids`` is omitted (the default), this cross-reference edge
    is simply skipped — safe by construction, never a partial-batch failure.
    """
    nodes: list[Node] = []
    edges: list[Edge] = []
    ts = now()
    h_id = host_id(target)

    for exp in experiences:
        nodes.append(Node(
            id=exp.id, type="experience",
            props={
                "category": exp.category.value, "target": exp.target,
                "discriminator": exp.discriminator, "context": exp.context,
                "evidence_excerpt": exp.evidence_excerpt, "outcome": exp.outcome,
                "recommendation": exp.recommendation, "confidence": exp.confidence.value,
                "occurrence_count": exp.occurrence_count,
            },
            confidence=exp.confidence.as_float(), source="experience_replay",
            first_seen=exp.first_seen, last_seen=ts,
        ))
        edges.append(Edge(
            id=indicates_edge_id(h_id, exp.id), from_id=h_id, to_id=exp.id, type="indicates",
            props={}, confidence=exp.confidence.as_float(), source="experience_replay",
            first_seen=ts, last_seen=ts,
        ))

        if (
            known_node_ids is not None
            and exp.category in (ExperienceCategory.successful_workflow, ExperienceCategory.failed_workflow, ExperienceCategory.abandoned_workflow)
        ):
            from apex_host.graph_ids import workflow_id as _workflow_id_fn
            # `discriminator` is the workflow key, set explicitly at
            # creation time (never re-parsed from free text) — see
            # apex_host.types.Experience.discriminator.
            wf_node_id = _workflow_id_fn(target, exp.discriminator)
            if wf_node_id in known_node_ids:
                edges.append(Edge(
                    id=indicates_edge_id(exp.id, wf_node_id), from_id=exp.id, to_id=wf_node_id, type="indicates",
                    props={}, confidence=exp.confidence.as_float(), source="experience_replay",
                    first_seen=ts, last_seen=ts,
                ))

        rec_id = experience_recommendation_id(exp.id)
        nodes.append(Node(
            id=rec_id, type="experience_recommendation",
            props={"text": exp.recommendation, "category": exp.category.value, "priority": exp.confidence.value, "experience_id": exp.id},
            confidence=exp.confidence.as_float(), source="experience_replay", first_seen=ts, last_seen=ts,
        ))
        edges.append(Edge(
            id=recommends_edge_id(exp.id, rec_id), from_id=exp.id, to_id=rec_id, type="recommends",
            props={}, confidence=exp.confidence.as_float(), source="experience_replay", first_seen=ts, last_seen=ts,
        ))

    return nodes, edges


def reflection_summary(
    target: str, experiences_before: list[Experience], experiences_after: list[Experience],
) -> ReflectionSummary:
    """Compute the point-in-time delta between the pre-reflection and
    post-reflection experience sets — see ``ReflectionSummary`` docstring
    for why this cannot be recomputed later from the final EKG alone."""
    before_ids = {e.id for e in experiences_before}
    created = sum(1 for e in experiences_after if e.id not in before_ids)
    reused = sum(1 for e in experiences_after if e.id in before_ids)
    repeated_failures = sum(
        1 for e in experiences_after
        if e.category in (ExperienceCategory.failed_workflow, ExperienceCategory.abandoned_workflow, ExperienceCategory.repeated_credential_outcome)
        and e.occurrence_count > 1
    )
    ranked = rank_experiences(experiences_after)
    improved = [e.recommendation for e in ranked if e.occurrence_count > 1][:5]
    return ReflectionSummary(
        target=target, experiences_created=created, experiences_reused=reused,
        replay_hits=reused, repeated_failures=repeated_failures,
        improved_recommendations=tuple(improved),
    )


def learning_summary_fields(target: str, subgraph: "SubgraphView") -> dict[str, Any]:
    """Build a small live-view dict — mirrors ``privilege_state_fields`` /
    ``web_session_state_fields`` / ``workflow_summary_fields`` exactly.
    Unlike those, this is populated once (post-engagement, in
    ``apex_host.runtime.ApexRuntime.run()``), not refreshed every turn —
    reflection runs once per engagement, not once per turn (see
    docs/experience-replay.md)."""
    experiences = rank_experiences(experiences_from_subgraph(subgraph))
    counts: dict[str, int] = {}
    for e in experiences:
        counts[e.category.value] = counts.get(e.category.value, 0) + 1
    return {
        "learning_summary": {
            "experience_count": len(experiences),
            "category_counts": counts,
        },
    }
