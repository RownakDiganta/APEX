# priv_esc_parser.py
# Parses searchsploit output, planner-derived analytical signals, and live enumeration command output into non-executable priv_esc_opportunity/priv_esc_evidence/priv_esc_recommendation EKG deltas.
"""Parser for privilege-escalation planning output (Phase 13A + 13B).

Stateless — no IO, no stored state, all writes go through MemoryAPI
(memfabric Invariant 1) when the caller upserts the returned deltas.

``parse_searchsploit`` / ``parse_analytical`` (Phase 13A, unchanged):
    See each method's own docstring below.

``parse_enumeration`` (Phase 13B, new):
    Turns the output of one harmless, read-only enumeration command
    (already executed by ``apex_host.agents.priv_esc_enum_executor.PrivEscEnumExecutor``
    against a fixed allowlist — this parser never executes anything) into a
    ``priv_esc_evidence`` node, zero or more derived ``priv_esc_opportunity``
    nodes (one ``priv_esc_recommendation`` node per opportunity), and the
    graph edges linking them: ``host -> evidence`` (``collects``),
    ``evidence -> opportunity`` (``produces``), ``opportunity ->
    recommendation`` (``recommends``). Fact extraction is entirely
    deterministic (regex/line-based) — no LLM parsing anywhere in this file.

Neither entry point ever writes exploit code, payload content, or a
recommended action that itself constitutes an executable command — see
``OpportunityCategory``/``PrivilegeOpportunityEvidence`` docstrings in
``apex_host/types.py`` for the "no payloads" invariant this parser upholds.
"""
from __future__ import annotations

import re
from typing import Any

from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation

from apex_host.graph_ids import (
    collects_edge_id,
    host_id,
    indicates_edge_id,
    priv_esc_evidence_id,
    priv_esc_opportunity_id,
    priv_esc_recommendation_id,
    produces_edge_id,
    recommends_edge_id,
)
from apex_host.types import EvidenceCategory, OpportunityCategory, OpportunityConfidence

# Bounded evidence excerpt length — titles only, never full PoC/exploit text.
_MAX_EXCERPT_CHARS = 200
_MAX_TITLES = 5

# searchsploit's default table output uses " | " to separate the exploit
# title from its exploit-db path; header/separator lines are skipped.
_RESULT_LINE_RE = re.compile(r"^(?P<title>.+?)\s*\|\s*(?P<path>\S+)\s*$")
_SEPARATOR_RE = re.compile(r"^-+\s+-+$")


def _extract_titles(stdout: str) -> list[str]:
    titles: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or _SEPARATOR_RE.match(stripped):
            continue
        if stripped.lower().startswith(("exploit title", "shellcodes:", "papers:")):
            continue
        m = _RESULT_LINE_RE.match(stripped)
        if m:
            titles.append(m.group("title").strip())
    return titles


# ---------------------------------------------------------------------------
# Phase 13B — deterministic evidence fact extraction (no LLM parsing).
#
# Each function takes raw command stdout and returns a plain,
# JSON-serialisable dict of extracted facts. Bounded to a small number of
# entries (never unbounded — a huge SUID/capabilities listing on a real
# target must not blow up the EKG). Never returns exploit code or payload
# content — only paths, names, and boolean/count facts.
# ---------------------------------------------------------------------------

_MAX_LIST_ENTRIES = 50

# SUID binaries that are expected/benign on almost any Linux system — never
# flagged as "interesting" on their own. Not exhaustive; a conservative,
# well-known allowlist only.
_SUID_BENIGN: frozenset[str] = frozenset({
    "sudo", "su", "passwd", "chsh", "chfn", "chage", "gpasswd", "newgrp",
    "mount", "umount", "fusermount", "pkexec", "ping", "ping6", "crontab",
    "at", "write", "wall",
})

# GTFOBins-flavored basenames commonly abusable for privilege escalation
# when found with the SUID bit or an interesting capability. A deliberately
# small, well-known set — not a substitute for manual GTFOBins lookup.
_SUID_INTERESTING: frozenset[str] = frozenset({
    "find", "vim", "vi", "nmap", "python", "python2", "python3", "perl",
    "awk", "gawk", "bash", "sh", "less", "more", "nano", "cp", "env",
    "tar", "man", "ftp", "gdb", "node", "ruby", "lua", "php", "docker",
})

_INTERESTING_CAPABILITY_NAMES: frozenset[str] = frozenset({
    "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_net_raw",
})

_GROUP_NAME_RE = re.compile(r"\((?P<name>[a-zA-Z0-9_-]+)\)")
_DOCKER_GROUP_NAMES: frozenset[str] = frozenset({"docker"})
_SUDO_GROUP_NAMES: frozenset[str] = frozenset({"sudo", "wheel", "admin"})

_CAP_LINE_RE = re.compile(r"^(?P<path>/\S+)\s*=\s*(?P<caps>.+)$")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if "/" in path else path


def parse_sudo_output(stdout: str) -> dict[str, Any]:
    """Extract configured sudo rules from ``sudo -n -l`` output."""
    rules: list[str] = []
    in_rules = False
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if "may run the following commands" in line.lower():
            in_rules = True
            continue
        if in_rules and line:
            rules.append(line)
    rules = rules[:_MAX_LIST_ENTRIES]
    nopasswd = any("nopasswd" in r.lower() for r in rules)
    all_all = any(re.search(r"\(\s*all\b.*\)", r, re.IGNORECASE) for r in rules)
    return {"rules": rules, "rule_count": len(rules), "nopasswd": nopasswd, "all_all": all_all}


def parse_suid_output(stdout: str) -> dict[str, Any]:
    """Extract SUID binary paths from a ``find ... -perm -4000`` listing."""
    paths = [ln.strip() for ln in stdout.splitlines() if ln.strip().startswith("/")]
    interesting = [
        p for p in paths
        if _basename(p) in _SUID_INTERESTING and _basename(p) not in _SUID_BENIGN
    ]
    return {
        "suid_binaries": paths[:_MAX_LIST_ENTRIES],
        "interesting_suid_binaries": interesting[:_MAX_LIST_ENTRIES],
        "count": len(paths),
    }


def parse_capabilities_output(stdout: str) -> dict[str, Any]:
    """Extract binary capability entries from ``getcap -r /`` output."""
    entries: list[dict[str, str]] = []
    for raw_line in stdout.splitlines():
        m = _CAP_LINE_RE.match(raw_line.strip())
        if m:
            entries.append({"path": m.group("path"), "capabilities": m.group("caps").strip()})
    interesting = [
        e for e in entries
        if any(name in e["capabilities"].lower() for name in _INTERESTING_CAPABILITY_NAMES)
    ]
    return {
        "capabilities": entries[:_MAX_LIST_ENTRIES],
        "interesting_capabilities": interesting[:_MAX_LIST_ENTRIES],
        "count": len(entries),
    }


def parse_mount_output(stdout: str) -> dict[str, Any]:
    """Extract filesystem entries from ``mount``/``df -h``/``lsblk`` output."""
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    nfs_entries = [ln for ln in lines if " nfs " in f" {ln.lower()} " or ln.lower().startswith("nfs")]
    return {
        "entries": lines[:_MAX_LIST_ENTRIES],
        "count": len(lines),
        "nfs_entries": nfs_entries[:_MAX_LIST_ENTRIES],
    }


def parse_cron_output(stdout: str) -> dict[str, Any]:
    """Extract cron job lines from ``crontab -l`` / ``/etc/crontab`` output."""
    jobs = [
        ln.strip() for ln in stdout.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    return {"jobs": jobs[:_MAX_LIST_ENTRIES], "count": len(jobs)}


def parse_identity_output(stdout: str) -> dict[str, Any]:
    """Extract group membership facts from ``id``/``groups`` output."""
    groups = {m.group("name").lower() for m in _GROUP_NAME_RE.finditer(stdout)}
    if not groups:
        # `groups` (no parens) prints a plain space-separated list.
        groups = {tok.strip().lower() for tok in stdout.split() if tok.strip()}
    return {
        "groups": sorted(groups)[:_MAX_LIST_ENTRIES],
        "in_docker_group": bool(groups & _DOCKER_GROUP_NAMES),
        "in_sudo_group": bool(groups & _SUDO_GROUP_NAMES),
    }


def parse_kernel_output(stdout: str) -> dict[str, Any]:
    """Extract the kernel version string from ``uname -a`` output."""
    text = stdout.strip()
    m = re.search(r"Linux\s+\S+\s+(?P<version>\S+)", text)
    return {"kernel_version": m.group("version") if m else "", "raw": text[:200]}


def parse_os_info_output(stdout: str) -> dict[str, Any]:
    """Extract OS metadata from ``/etc/os-release`` / ``hostnamectl`` output."""
    facts: dict[str, str] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            facts[key.strip().upper()] = value.strip().strip('"')
        elif ":" in line:
            key, _, value = line.partition(":")
            facts[key.strip()] = value.strip()
    return {"os_facts": dict(list(facts.items())[:_MAX_LIST_ENTRIES])}


def parse_service_info_output(stdout: str) -> dict[str, Any]:
    """Extract running-service lines from ``systemctl list-units`` output."""
    lines = [ln.strip() for ln in stdout.splitlines() if ".service" in ln]
    return {"services": lines[:_MAX_LIST_ENTRIES], "count": len(lines)}


# ---------------------------------------------------------------------------
# Windows fact extraction — PLANNING SUPPORT ONLY.
#
# No executor in this codebase ever runs a Windows enumeration command live
# (no WinRM/PSRemoting channel exists) — these functions exist so the
# evidence/opportunity model can accept Windows enumeration output if and
# when a future phase adds a Windows executor, and so the taxonomy is
# testable today. See docs/privilege-enumeration.md "Windows support scope".
# ---------------------------------------------------------------------------

_WINDOWS_INTERESTING_PRIVILEGES: frozenset[str] = frozenset({
    "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
    "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
})
_WINDOWS_PRIV_LINE_RE = re.compile(r"(Se\w+Privilege)\s+.*?\s+(Enabled|Disabled)", re.IGNORECASE)


def parse_windows_privileges_output(stdout: str) -> dict[str, Any]:
    """Extract enabled/disabled privileges from ``whoami /priv`` output. Planning support only."""
    privileges: list[dict[str, str]] = []
    for raw_line in stdout.splitlines():
        m = _WINDOWS_PRIV_LINE_RE.search(raw_line.strip())
        if m:
            privileges.append({"privilege": m.group(1), "state": m.group(2).capitalize()})
    interesting = [
        p for p in privileges
        if p["privilege"] in _WINDOWS_INTERESTING_PRIVILEGES and p["state"] == "Enabled"
    ]
    return {
        "privileges": privileges[:_MAX_LIST_ENTRIES],
        "interesting_privileges": interesting[:_MAX_LIST_ENTRIES],
        "count": len(privileges),
    }


def parse_windows_groups_output(stdout: str) -> dict[str, Any]:
    """Extract group membership from ``whoami /groups`` output. Planning support only."""
    lines = [
        ln.strip() for ln in stdout.splitlines()
        if ln.strip() and not ln.strip().lower().startswith(("group name", "===", "-----"))
    ]
    is_admin = any("administrators" in ln.lower() for ln in lines)
    return {"groups": lines[:_MAX_LIST_ENTRIES], "is_local_admin_group": is_admin}


def parse_windows_systeminfo_output(stdout: str) -> dict[str, Any]:
    """Extract key:value facts from ``systeminfo`` output. Planning support only."""
    facts: dict[str, str] = {}
    for raw_line in stdout.splitlines():
        if ":" in raw_line:
            key, _, value = raw_line.partition(":")
            key = key.strip()
            if key:
                facts[key] = value.strip()
    return {"system_info": dict(list(facts.items())[:_MAX_LIST_ENTRIES])}


def parse_windows_service_output(stdout: str) -> dict[str, Any]:
    """Extract service configuration lines. Planning support only."""
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    return {"service_entries": lines[:_MAX_LIST_ENTRIES], "count": len(lines)}


def parse_windows_scheduled_task_output(stdout: str) -> dict[str, Any]:
    """Extract scheduled-task lines. Planning support only."""
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    return {"task_entries": lines[:_MAX_LIST_ENTRIES], "count": len(lines)}


def parse_windows_registry_output(stdout: str) -> dict[str, Any]:
    """Extract registry key/value lines. Planning support only."""
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    return {"registry_entries": lines[:_MAX_LIST_ENTRIES], "count": len(lines)}


class PrivEscParser:
    """Stateless parser: searchsploit output / analytical signal -> EKG priv_esc_opportunity deltas."""

    def parse_searchsploit(
        self,
        stdout: str,
        *,
        target: str,
        service: str,
        version: str,
    ) -> ParsedObservation:
        if not service:
            return ParsedObservation()

        timestamp = now()
        discriminator = f"{service} {version}".strip()
        titles = _extract_titles(stdout)

        if titles:
            confidence = (
                OpportunityConfidence.high if len(titles) >= 3
                else OpportunityConfidence.medium
            )
            category = OpportunityCategory.vulnerable_service
            excerpt = "; ".join(titles[:_MAX_TITLES])[:_MAX_EXCERPT_CHARS]
            description = (
                f"{len(titles)} known exploit-db entr{'y' if len(titles) == 1 else 'ies'} "
                f"found for {discriminator!r}"
            )
            recommended_next_action = (
                f"Manually review exploit-db entries for {discriminator!r} "
                "and confirm applicability before any authorized action; "
                "APEX does not execute exploits"
            )
        else:
            confidence = OpportunityConfidence.none
            category = OpportunityCategory.none
            excerpt = ""
            description = f"no known exploit-db entries found for {discriminator!r}"
            recommended_next_action = (
                "no automated action recommended; consider manual research "
                "against other vulnerability databases"
            )

        opp_id = priv_esc_opportunity_id(target, category.value, discriminator)
        node = Node(
            id=opp_id,
            type="priv_esc_opportunity",
            props={
                "target": target,
                "category": category.value,
                "confidence": confidence.value,
                "description": description,
                "recommended_next_action": recommended_next_action,
                "attempted": True,
                "attempt_count": 1,
                "exhausted": True,  # searchsploit is a one-shot local lookup — nothing more to do
                "source_tool": "searchsploit",
                "evidence_source": "searchsploit",
                "evidence_excerpt": excerpt,
                "evidence_timestamp": timestamp,
                "service": service,
                "version": version,
            },
            confidence=confidence.as_float() if confidence is not OpportunityConfidence.none else 0.3,
            source="searchsploit",
            first_seen=timestamp,
            last_seen=timestamp,
        )
        # Link back to the host node so the opportunity is reachable via a
        # normal host-anchored subgraph traversal — without this edge the
        # node would be an orphan: invisible to get_subgraph() and therefore
        # invisible to opportunities_from_subgraph()'s dedup check, which
        # would make the planner re-search the same service/version forever.
        h_id = host_id(target)
        edge = Edge(
            id=indicates_edge_id(h_id, opp_id),
            from_id=h_id,
            to_id=opp_id,
            type="indicates",
            props={},
            confidence=node.confidence,
            source="searchsploit",
            first_seen=timestamp,
            last_seen=timestamp,
        )
        return ParsedObservation(node_deltas=[node], edge_deltas=[edge])

    def parse_analytical(
        self,
        *,
        target: str,
        category: str,
        confidence: str,
        description: str,
        recommended_next_action: str,
        discriminator: str,
        evidence_source: str,
        evidence_excerpt: str,
        source_node_id: str = "",
    ) -> ParsedObservation:
        """Build one opportunity node from a planner-precomputed analytical signal.

        ``evidence_excerpt`` must already be bounded/redacted by the caller
        (``derive_analytical_opportunities`` only ever reads already-redacted
        EKG text — see that function's docstring); this parser additionally
        re-truncates defensively.
        """
        if not category or not discriminator:
            return ParsedObservation()

        timestamp = now()
        opp_id = priv_esc_opportunity_id(target, category, discriminator)
        node = Node(
            id=opp_id,
            type="priv_esc_opportunity",
            props={
                "target": target,
                "category": category,
                "confidence": confidence,
                "description": description,
                "recommended_next_action": recommended_next_action,
                "attempted": True,
                "attempt_count": 1,
                "exhausted": True,  # analytical derivation is a one-shot read of already-known data
                "source_tool": "analysis",
                "evidence_source": evidence_source,
                "evidence_excerpt": evidence_excerpt[:_MAX_EXCERPT_CHARS],
                "evidence_timestamp": timestamp,
            },
            confidence=OpportunityConfidence(confidence).as_float(),
            source=evidence_source,
            first_seen=timestamp,
            last_seen=timestamp,
        )
        edges: list[Edge] = []
        if source_node_id:
            edges.append(
                Edge(
                    id=indicates_edge_id(source_node_id, opp_id),
                    from_id=source_node_id,
                    to_id=opp_id,
                    type="indicates",
                    props={},
                    confidence=OpportunityConfidence(confidence).as_float(),
                    source=evidence_source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
        return ParsedObservation(node_deltas=[node], edge_deltas=edges)

    # ------------------------------------------------------------------
    # Phase 13B — live enumeration command output -> evidence + opportunities
    # ------------------------------------------------------------------

    def parse_enumeration(
        self,
        stdout: str,
        *,
        target: str,
        category: str,
        command_key: str,
        source_command: str,
        port: str = "",
    ) -> ParsedObservation:
        """Build evidence (+ any derived opportunity/recommendation) deltas
        from one enumeration command's output.

        ``category`` must be a valid ``EvidenceCategory`` value; an unknown
        or empty category returns an empty observation rather than guessing.
        Fact extraction is entirely deterministic — see the module-level
        ``parse_*_output`` functions above (no LLM parsing).
        """
        try:
            cat = EvidenceCategory(category)
        except ValueError:
            return ParsedObservation()
        if not command_key:
            return ParsedObservation()

        timestamp = now()
        extractor = _EVIDENCE_EXTRACTORS.get(cat)
        facts: dict[str, Any] = extractor(stdout) if extractor else {}
        has_output = bool(stdout.strip())
        evidence_confidence = (
            OpportunityConfidence.high if has_output and facts
            else OpportunityConfidence.low if has_output
            else OpportunityConfidence.none
        )

        ev_id = priv_esc_evidence_id(target, command_key, port)
        evidence_node = Node(
            id=ev_id,
            type="priv_esc_evidence",
            props={
                "target": target,
                "category": cat.value,
                "source_command": source_command,
                "command_key": command_key,
                "confidence": evidence_confidence.value,
                "extracted_facts": facts,
                "raw_excerpt": stdout.strip()[:_MAX_EXCERPT_CHARS],
                "evidence_timestamp": timestamp,
            },
            confidence=evidence_confidence.as_float(),
            source="priv_esc_enum",
            first_seen=timestamp,
            last_seen=timestamp,
        )

        nodes: list[Node] = [evidence_node]
        edges: list[Edge] = []
        h_id = host_id(target)
        edges.append(
            Edge(
                id=collects_edge_id(h_id, ev_id),
                from_id=h_id, to_id=ev_id, type="collects", props={},
                confidence=evidence_node.confidence, source="priv_esc_enum",
                first_seen=timestamp, last_seen=timestamp,
            )
        )

        for candidate in _opportunities_from_facts(cat, facts):
            opp_conf = OpportunityConfidence(candidate["confidence"])
            opp_id = priv_esc_opportunity_id(target, candidate["category"], candidate["discriminator"])
            opp_node = Node(
                id=opp_id,
                type="priv_esc_opportunity",
                props={
                    "target": target,
                    "category": candidate["category"],
                    "confidence": candidate["confidence"],
                    "description": candidate["description"],
                    "recommended_next_action": candidate["recommended_next_action"],
                    "attempted": True,
                    "attempt_count": 1,
                    "exhausted": True,
                    "source_tool": "priv_esc_enum",
                    "evidence_source": command_key,
                    "evidence_excerpt": stdout.strip()[:_MAX_EXCERPT_CHARS],
                    "evidence_timestamp": timestamp,
                },
                confidence=opp_conf.as_float(),
                source="priv_esc_enum",
                first_seen=timestamp,
                last_seen=timestamp,
            )
            nodes.append(opp_node)
            edges.append(
                Edge(
                    id=produces_edge_id(ev_id, opp_id),
                    from_id=ev_id, to_id=opp_id, type="produces", props={},
                    confidence=opp_conf.as_float(), source="priv_esc_enum",
                    first_seen=timestamp, last_seen=timestamp,
                )
            )

            rec_id = priv_esc_recommendation_id(opp_id)
            rec_node = Node(
                id=rec_id,
                type="priv_esc_recommendation",
                props={
                    "text": candidate["recommended_next_action"],
                    "category": candidate["category"],
                    "priority": candidate["confidence"],
                    "opportunity_id": opp_id,
                },
                confidence=opp_conf.as_float(),
                source="priv_esc_enum",
                first_seen=timestamp,
                last_seen=timestamp,
            )
            nodes.append(rec_node)
            edges.append(
                Edge(
                    id=recommends_edge_id(opp_id, rec_id),
                    from_id=opp_id, to_id=rec_id, type="recommends", props={},
                    confidence=opp_conf.as_float(), source="priv_esc_enum",
                    first_seen=timestamp, last_seen=timestamp,
                )
            )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)


# ---------------------------------------------------------------------------
# Phase 13B — evidence category -> extractor / opportunity-derivation maps
# ---------------------------------------------------------------------------

_EVIDENCE_EXTRACTORS: dict[EvidenceCategory, Any] = {
    EvidenceCategory.sudo: parse_sudo_output,
    EvidenceCategory.suid: parse_suid_output,
    EvidenceCategory.capabilities: parse_capabilities_output,
    EvidenceCategory.mounted_filesystem: parse_mount_output,
    EvidenceCategory.cron: parse_cron_output,
    EvidenceCategory.identity: parse_identity_output,
    EvidenceCategory.kernel_version: parse_kernel_output,
    EvidenceCategory.os_info: parse_os_info_output,
    EvidenceCategory.service_info: parse_service_info_output,
}


def _opportunities_from_facts(category: EvidenceCategory, facts: dict[str, Any]) -> list[dict[str, str]]:
    """Map extracted facts to zero or more candidate opportunities.

    Discriminators are namespaced with an ``enum-`` prefix so they can never
    collide with Phase 13A's searchsploit/analytical discriminator scheme
    (which never uses this prefix) even when both describe a similar signal
    (e.g. docker-group membership can be recorded once from Phase 12B's `id`
    evidence — 13A's path — and once from this phase's own `groups` command
    — a distinct, independently-verified piece of evidence, not a duplicate).
    """
    candidates: list[dict[str, str]] = []

    if category is EvidenceCategory.sudo and (facts.get("nopasswd") or facts.get("all_all")):
        confidence = OpportunityConfidence.high if facts.get("nopasswd") else OpportunityConfidence.medium
        candidates.append({
            "category": OpportunityCategory.sudo.value,
            "confidence": confidence.value,
            "description": (
                f"sudo -l reports {facts.get('rule_count', 0)} configured rule(s) "
                "including passwordless or unrestricted entries"
            ),
            "recommended_next_action": (
                "Manually review the sudo rules in this evidence and verify "
                "escalation potential before any authorized action"
            ),
            "discriminator": "enum-sudo-rules",
        })

    elif category is EvidenceCategory.suid:
        for path in facts.get("interesting_suid_binaries", []):
            candidates.append({
                "category": OpportunityCategory.suid.value,
                "confidence": OpportunityConfidence.high.value,
                "description": f"SUID bit set on {path!r} — commonly abusable for privilege escalation",
                "recommended_next_action": f"Manually verify {path!r} against GTFOBins before any authorized action",
                "discriminator": f"enum-suid-{path}",
            })

    elif category is EvidenceCategory.capabilities:
        for entry in facts.get("interesting_capabilities", []):
            candidates.append({
                "category": OpportunityCategory.capabilities.value,
                "confidence": OpportunityConfidence.high.value,
                "description": f"{entry['path']!r} has capability {entry['capabilities']!r}",
                "recommended_next_action": (
                    f"Manually verify {entry['path']!r}'s capability against GTFOBins "
                    "before any authorized action"
                ),
                "discriminator": f"enum-cap-{entry['path']}",
            })

    elif category is EvidenceCategory.mounted_filesystem and facts.get("nfs_entries"):
        candidates.append({
            "category": OpportunityCategory.mounted_filesystem.value,
            "confidence": OpportunityConfidence.medium.value,
            "description": f"{len(facts['nfs_entries'])} NFS mount(s) detected — check export options",
            "recommended_next_action": (
                "Manually inspect NFS export options (no_root_squash) from an "
                "authorized vantage point before any action"
            ),
            "discriminator": "enum-nfs-mounts",
        })

    elif category is EvidenceCategory.cron and facts.get("count", 0) > 0:
        candidates.append({
            "category": OpportunityCategory.cron.value,
            "confidence": OpportunityConfidence.low.value,
            "description": f"{facts['count']} cron job(s) discovered — review script targets",
            "recommended_next_action": (
                "Manually review cron job script paths and permissions before any action"
            ),
            "discriminator": "enum-cron-jobs",
        })

    elif category is EvidenceCategory.identity:
        if facts.get("in_docker_group"):
            candidates.append({
                "category": OpportunityCategory.docker.value,
                "confidence": OpportunityConfidence.high.value,
                "description": "user is a member of the docker group",
                "recommended_next_action": (
                    "Manually verify docker-group container-mount-escape escalation "
                    "per standard methodology; APEX does not attempt this automatically"
                ),
                "discriminator": "enum-docker-group",
            })
        if facts.get("in_sudo_group"):
            candidates.append({
                "category": OpportunityCategory.sudo.value,
                "confidence": OpportunityConfidence.medium.value,
                "description": "user is a member of a sudo-capable group",
                "recommended_next_action": (
                    "Manually run 'sudo -l' via an interactive authorized session to "
                    "enumerate configured sudo rules"
                ),
                "discriminator": "enum-sudo-group",
            })

    # kernel_version / os_info / service_info: informational only — no
    # opportunity is ever derived from these categories (see module docstring).
    return candidates
