# priv_esc_opportunities.py
# Pure, no-IO helpers for reconstructing, ranking, deduplicating, and analytically deriving PrivilegeOpportunity records from EKG subgraph data.
"""Privilege-escalation opportunity reasoning helpers (Phase 13).

Everything here is pure — no I/O, no MemoryAPI calls, no tool execution —
consistent with the blackboard model (memfabric Invariant 7): planners only
ever read the ``SubgraphView``/``EvidenceBundle`` they are handed and return
``TaskSpec``s; all persistence happens later through the standard
parse_observation -> MemoryAPI.apply_deltas path.

Two responsibilities:

1. ``opportunities_from_subgraph`` / ``rank_opportunities`` /
   ``build_privilege_escalation_state`` reconstruct the current
   ``PrivilegeOpportunity`` set from ``priv_esc_opportunity`` EKG nodes —
   this is how ``PrivEscPlanner`` avoids re-searching a service/version (or
   re-deriving an analytical signal) it has already recorded.

2. ``derive_analytical_opportunities`` finds NEW candidate opportunities
   using only data already captured in the EKG by earlier phases — no new
   tool execution, no target interaction. Currently it mines
   ``access_state`` node evidence (the redacted ``id`` command output
   captured during Phase 12B SSH credential validation) for well-known
   group-membership escalation hints (``docker``, ``sudo``/``wheel``).  See
   ``docs/privilege-escalation-planning.md`` "Analytical derivation" for the
   full rationale and current limitations.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from apex_host.types import (
    EvidenceCategory,
    OpportunityCategory,
    OpportunityConfidence,
    PrivilegeEnumerationProgress,
    PrivilegeEnumerationStatus,
    PrivilegeEscalationState,
    PrivilegeEvidence,
    PrivilegeOpportunity,
    PrivilegeOpportunityEvidence,
)

if TYPE_CHECKING:
    from memfabric.types import Node, SubgraphView

# Deterministic category ordering used only as a ranking tie-breaker (never
# affects which categories exist — see OpportunityCategory in types.py).
_CATEGORY_PRIORITY: dict[str, int] = {
    OpportunityCategory.vulnerable_service.value: 0,
    OpportunityCategory.sudo.value: 1,
    OpportunityCategory.docker.value: 2,
    OpportunityCategory.suid.value: 3,
    OpportunityCategory.capabilities.value: 4,
    OpportunityCategory.cron.value: 5,
    OpportunityCategory.scheduled_task.value: 6,
    OpportunityCategory.writable_service.value: 7,
    OpportunityCategory.path_issue.value: 8,
    OpportunityCategory.kernel_version.value: 9,
    OpportunityCategory.mounted_filesystem.value: 10,
    OpportunityCategory.credentials.value: 11,
    OpportunityCategory.windows_service.value: 12,
    OpportunityCategory.registry.value: 13,
    OpportunityCategory.startup_item.value: 14,
    OpportunityCategory.none.value: 99,
}


def _node_to_opportunity(node: "Node") -> PrivilegeOpportunity | None:
    props = node.props
    try:
        category = OpportunityCategory(str(props.get("category", "")))
        confidence = OpportunityConfidence(str(props.get("confidence", "")))
    except ValueError:
        return None
    evidence = PrivilegeOpportunityEvidence(
        source=str(props.get("evidence_source", "")),
        supporting_node_ids=(),
        excerpt=str(props.get("evidence_excerpt", "")),
        timestamp=str(props.get("evidence_timestamp", "")),
    )
    return PrivilegeOpportunity(
        id=node.id,
        category=category,
        confidence=confidence,
        evidence=evidence,
        description=str(props.get("description", "")),
        recommended_next_action=str(props.get("recommended_next_action", "")),
        attempted=bool(props.get("attempted", True)),
        attempt_count=int(props.get("attempt_count", 1) or 1),
        exhausted=bool(props.get("exhausted", True)),
        first_seen=node.first_seen,
        last_seen=node.last_seen,
    )


def opportunities_from_subgraph(subgraph: "SubgraphView") -> list[PrivilegeOpportunity]:
    """Reconstruct every recorded ``PrivilegeOpportunity`` from the subgraph.

    Nodes whose ``category``/``confidence`` props no longer parse as a known
    enum member are skipped (forward-compatibility: a future taxonomy change
    must not crash an older planner reading a newer EKG, or vice versa).
    """
    out: list[PrivilegeOpportunity] = []
    for node in subgraph.nodes:
        if node.type != "priv_esc_opportunity":
            continue
        opp = _node_to_opportunity(node)
        if opp is not None:
            out.append(opp)
    return out


def rank_opportunities(opportunities: list[PrivilegeOpportunity]) -> list[PrivilegeOpportunity]:
    """Deterministic ranking: confidence desc, then category priority, then id asc.

    Never random, never insertion-order-dependent — the same opportunity set
    always ranks identically regardless of EKG traversal order.
    """
    return sorted(
        opportunities,
        key=lambda o: (
            -o.confidence.as_float(),
            _CATEGORY_PRIORITY.get(o.category.value, 50),
            o.id,
        ),
    )


def build_privilege_escalation_state(
    target: str, subgraph: "SubgraphView", *, has_access_state: bool
) -> PrivilegeEscalationState:
    """Build the current ``PrivilegeEscalationState`` snapshot for *target*.

    Status derivation (deterministic, no I/O):
      not_started              — no access_state yet (priv_esc cannot start)
      running                  — access_state present, no opportunities recorded yet
      opportunities_found      — at least one non-exhausted opportunity remains
      exhausted                — every recorded opportunity is exhausted
                                  (never true with zero opportunities recorded —
                                  "nothing found yet" is `running`, not `exhausted`)

    ``elevated_access_validated`` is never returned here — see
    ``PrivilegeEnumerationStatus`` docstring (future capability).
    """
    opportunities = rank_opportunities(opportunities_from_subgraph(subgraph))

    if not has_access_state:
        status = PrivilegeEnumerationStatus.not_started
    elif not opportunities:
        status = PrivilegeEnumerationStatus.running
    elif any(not o.exhausted for o in opportunities):
        status = PrivilegeEnumerationStatus.opportunities_found
    else:
        status = PrivilegeEnumerationStatus.exhausted

    return PrivilegeEscalationState(target=target, status=status, opportunities=tuple(opportunities))


# ---------------------------------------------------------------------------
# Analytical derivation — new candidates from already-known EKG data only.
# ---------------------------------------------------------------------------

# `id` command output shape: "uid=1000(user) gid=1000(user) groups=1000(user),27(sudo),999(docker)"
_GROUP_NAME_RE = re.compile(r"\((?P<name>[a-zA-Z0-9_-]+)\)")
_DOCKER_GROUP_NAMES: frozenset[str] = frozenset({"docker"})
_SUDO_GROUP_NAMES: frozenset[str] = frozenset({"sudo", "wheel", "admin"})


class AnalyticalCandidate:
    """A planner-computed, not-yet-persisted analytical opportunity signal.

    Carries exactly the fields ``PrivEscParser.parse_analytical`` needs —
    this is the hand-off shape between the planner (which has subgraph
    access) and the ``priv_esc_analyze`` task's params (see
    ``apex_host/planners/priv_esc_planner.py``).
    """

    __slots__ = (
        "category", "confidence", "description", "recommended_next_action",
        "discriminator", "evidence_source", "evidence_excerpt", "source_node_id",
    )

    def __init__(
        self, *, category: str, confidence: str, description: str,
        recommended_next_action: str, discriminator: str,
        evidence_source: str, evidence_excerpt: str, source_node_id: str,
    ) -> None:
        self.category = category
        self.confidence = confidence
        self.description = description
        self.recommended_next_action = recommended_next_action
        self.discriminator = discriminator
        self.evidence_source = evidence_source
        self.evidence_excerpt = evidence_excerpt
        self.source_node_id = source_node_id


def derive_analytical_opportunities(subgraph: "SubgraphView") -> list[AnalyticalCandidate]:
    """Derive candidate opportunities purely from already-known EKG data.

    No new tool execution, no target interaction. Currently mines
    ``access_state`` node ``evidence``/``proof`` text (already redacted by
    ``AccessParser`` — see ``apex_host/security/redaction.py``) for two
    well-known group-membership escalation hints:

    - ``docker`` group membership -> ``OpportunityCategory.docker`` (high
      confidence: a well-documented, reliable escalation vector).
    - ``sudo``/``wheel``/``admin`` group membership -> ``OpportunityCategory.sudo``
      (medium confidence: group membership alone does not guarantee
      passwordless or unrestricted sudo rules — a human must still check).

    Deliberately does NOT attempt kernel-version, SUID, cron, capabilities,
    or any other category: none of those have a reliable existing EKG data
    source without new live enumeration, which this phase does not add (see
    docs/privilege-escalation-planning.md "Scope boundary — no new live
    enumeration"). Inventing a heuristic without real data would produce
    false "opportunities" — worse than reporting nothing.
    """
    candidates: list[AnalyticalCandidate] = []
    for node in subgraph.nodes:
        if node.type != "access_state":
            continue
        text = f"{node.props.get('evidence', '')} {node.props.get('proof', '')}"
        groups = {m.group("name").lower() for m in _GROUP_NAME_RE.finditer(text)}
        username = str(node.props.get("username", "unknown"))
        target = str(node.props.get("target", ""))

        if groups & _DOCKER_GROUP_NAMES:
            candidates.append(AnalyticalCandidate(
                category=OpportunityCategory.docker.value,
                confidence=OpportunityConfidence.high.value,
                description=f"user {username!r} is a member of the docker group on {target!r}",
                recommended_next_action=(
                    "Manually verify docker-group container-mount-escape escalation "
                    "per standard methodology; APEX does not attempt this automatically"
                ),
                discriminator=f"docker-group-{username}",
                evidence_source="id_groups",
                evidence_excerpt=text.strip()[:200],
                source_node_id=node.id,
            ))

        if groups & _SUDO_GROUP_NAMES:
            candidates.append(AnalyticalCandidate(
                category=OpportunityCategory.sudo.value,
                confidence=OpportunityConfidence.medium.value,
                description=f"user {username!r} is a member of a sudo-capable group on {target!r}",
                recommended_next_action=(
                    "Manually run 'sudo -l' via an interactive authorized session to "
                    "enumerate configured sudo rules; APEX does not run this automatically"
                ),
                discriminator=f"sudo-group-{username}",
                evidence_source="id_groups",
                evidence_excerpt=text.strip()[:200],
                source_node_id=node.id,
            ))

    return candidates


def privilege_state_fields(subgraph: "SubgraphView", *, target: str) -> dict[str, Any]:
    """Build the ``ApexGraphState`` partial-update dict for one priv_esc turn.

    Pure derivation from the subgraph — see ``build_privilege_escalation_state``.
    Called only from ``apex_host.orchestration.dispatch_node.make_priv_esc_node``
    so this state summary is refreshed exactly on priv_esc turns; every other
    node simply omits these keys and LangGraph's partial-update semantics
    preserve the last known snapshot (see ``ApexGraphState`` docstring).
    """
    has_access_state = any(n.type == "access_state" for n in subgraph.nodes)
    state = build_privilege_escalation_state(target, subgraph, has_access_state=has_access_state)
    progress = build_enumeration_progress(target, subgraph)
    return {
        "privilege_state": state.status.value,
        "privilege_summary": {
            "opportunity_count": state.opportunity_count,
            "categories": state.categories,
            "attempted_count": state.attempted_count,
            "exhausted_count": state.exhausted_count,
            "remaining_count": state.remaining_count,
            # Phase 13B — enumeration command/evidence counters.
            "commands_completed": progress.commands_completed,
            "commands_parsed": progress.commands_parsed,
            "evidence_count": progress.evidence_count,
            "opportunities_from_enumeration": progress.opportunities_created,
        },
        "opportunity_ids": [o.id for o in state.opportunities],
        "attempted_opportunities": [o.id for o in state.opportunities if o.attempted],
        "enumeration_complete": state.enumeration_complete,
    }


# ---------------------------------------------------------------------------
# Phase 13B — command deduplication and enumeration progress tracking.
# ---------------------------------------------------------------------------

#: Fixed, read-only, non-destructive enumeration commands — the single
#: source of truth shared by ``PrivEscPlanner`` (which command_keys are
#: eligible to be planned) and ``PrivEscEnumExecutor`` (which command STRING
#: each key actually runs). Value shape: (command string run verbatim over
#: the SSH exec channel, ``EvidenceCategory`` value used to route parsing —
#: see ``apex_host/parsers/priv_esc_parser.py``). Every command here is
#: read-only: no writes, no file creation, no service/cron/sudoers
#: mutation, no persistence mechanism of any kind.
ENUM_COMMANDS: dict[str, tuple[str, str]] = {
    "identity": ("id", "identity"),
    "os_info": ("cat /etc/os-release", "os_info"),
    "kernel_version": ("uname -a", "kernel_version"),
    "sudo_l": ("sudo -n -l", "sudo"),
    "suid": ("find / -xdev -perm -4000 -type f 2>/dev/null", "suid"),
    "capabilities": ("getcap -r / 2>/dev/null", "capabilities"),
    "mounts": ("mount", "mounted_filesystem"),
    "cron": ("crontab -l 2>/dev/null", "cron"),
    "service_info": ("systemctl list-units --type=service --no-pager 2>/dev/null", "service_info"),
}


def already_run_commands(subgraph: "SubgraphView") -> set[str]:
    """The set of enumeration ``command_key`` values already recorded as
    ``priv_esc_evidence`` nodes for this target — the planner must never
    re-run one of these (see ``PrivEscPlanner`` "Avoid rerunning successful
    enumeration")."""
    return {
        str(n.props.get("command_key", ""))
        for n in subgraph.nodes
        if n.type == "priv_esc_evidence" and n.props.get("command_key")
    }


def evidence_from_subgraph(subgraph: "SubgraphView") -> list[PrivilegeEvidence]:
    """Reconstruct every recorded ``PrivilegeEvidence`` from the subgraph.

    Mirrors ``opportunities_from_subgraph``'s forward-compatibility
    discipline: a node whose category/confidence no longer parses as a
    known enum member is skipped rather than raising.
    """
    out: list[PrivilegeEvidence] = []
    for node in subgraph.nodes:
        if node.type != "priv_esc_evidence":
            continue
        try:
            category = EvidenceCategory(str(node.props.get("category", "")))
            confidence = OpportunityConfidence(str(node.props.get("confidence", "")))
        except ValueError:
            continue
        out.append(PrivilegeEvidence(
            id=node.id,
            category=category,
            source_command=str(node.props.get("source_command", "")),
            confidence=confidence,
            extracted_facts=dict(node.props.get("extracted_facts") or {}),
            supporting_node_ids=(),
            raw_excerpt=str(node.props.get("raw_excerpt", "")),
            timestamp=node.first_seen,
        ))
    return out


def build_enumeration_progress(
    target: str, subgraph: "SubgraphView", *, failed_commands: int = 0
) -> PrivilegeEnumerationProgress:
    """Build the current ``PrivilegeEnumerationProgress`` snapshot for *target*.

    ``commands_completed``/``commands_parsed``/``evidence_count`` are all
    derived from ``priv_esc_evidence`` node count — this parser only ever
    creates an evidence node once a command has both completed AND been
    parsed (see ``PrivEscParser.parse_enumeration``), so the three counts
    are equal by construction here; ``failed_commands`` must be supplied by
    the caller since a failed command produces no EKG node at all (tracked
    instead via the existing generic ``error_episodes`` mechanism — see
    docs/privilege-enumeration.md "Enumeration state").
    """
    evidence = evidence_from_subgraph(subgraph)
    opportunities_from_enum = [
        n for n in subgraph.nodes
        if n.type == "priv_esc_opportunity" and n.props.get("source_tool") == "priv_esc_enum"
    ]
    return PrivilegeEnumerationProgress(
        target=target,
        commands_completed=len(evidence),
        commands_failed=failed_commands,
        commands_parsed=len(evidence),
        evidence_count=len(evidence),
        opportunities_created=len(opportunities_from_enum),
    )
