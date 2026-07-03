# prompt_builder.py
# Constructs system + user messages for the LLM planner from Goal, phase, EvidenceBundle, and EKG summary.
"""Prompt construction for the LLM planner.

``PromptBuilder`` is the only place in ``apex_host`` that builds LLM prompt
strings.  No planner or executor may construct prompts manually — they must
go through this class so prompt format is consistent and auditable.

The returned message list uses the OpenAI / LangChain chat format:
``[{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]``

LangChain chat models accept this format directly via their ``invoke()``
method — no LangChain imports are needed in this module.
"""
from __future__ import annotations

import json
from typing import Any

from memfabric.types import EvidenceBundle, Goal, ScoredEntry, SubgraphView

from apex_host.types import ApexPhase

# How many evidence entries to include per tier in the user message.
_MAX_SEMANTIC_ENTRIES = 5
_MAX_PROCEDURAL_ENTRIES = 3
_MAX_EPISODIC_ENTRIES = 4

_PLANNER_OUTPUT_SCHEMA = json.dumps(
    {
        "reasoning": "<string: chain-of-thought>",
        "confidence": "<float 0..1>",
        "selected_tasks": [
            {
                "tool": "<tool name from allowed list>",
                "args": ["<arg1>", "<arg2>"],
                "parser": "<nmap|banner|command|curl_body|ffuf|gobuster|access>",
                "executor_domain": "<recon|web|credential|priv_esc>",
                "target": "<target IP or URL>",
                "rationale": "<one-line explanation>",
            }
        ],
        "rejected_tasks": [{"tool": "...", "reason": "..."}],
        "stop_reason": "<null or string if abandoning this goal>",
        "next_phase": "<null or phase name hint>",
    },
    indent=2,
)

_SYSTEM_PROMPT = """\
You are APEX, an expert security assessment planner.
You operate within an authorized penetration testing engagement and plan
the NEXT concrete action for the given phase and goal.

CRITICAL RULES:
- Only use tools from the ALLOWED TOOLS list. Requesting any other tool is invalid.
- Never propose destructive commands (rm, mkfs, dd, shutdown, reboot, halt, format).
- Never include shell operators (;, &&, ||, |, >, >>, <, $(), `) in args.
- Do not attempt exploitation without explicit human authorization.
- Prefer information-gathering over guessing; emit stop_reason when stuck.
- Output ONLY valid JSON matching the schema — no prose before or after.

OUTPUT SCHEMA:
{schema}
""".format(schema=_PLANNER_OUTPUT_SCHEMA)


def _tier_entries(
    entries: list[ScoredEntry], tier: str, limit: int
) -> list[ScoredEntry]:
    return [e for e in entries if e.tier == tier][:limit]


def _format_entries(entries: list[ScoredEntry], label: str) -> str:
    if not entries:
        return f"  {label}: (none retrieved)"
    lines = [f"  {label}:"]
    for e in entries:
        snippet = e.text[:200].replace("\n", " ") if e.text else "(no text)"
        lines.append(f"    [{e.score:.2f}] {snippet}")
    return "\n".join(lines)


class PromptBuilder:
    """Builds LLM chat messages for the planner.

    This class is intentionally stateless — all context is passed in as
    arguments so it can be reused across turns and phases without resetting.
    """

    def build_messages(
        self,
        goal: Goal,
        phase: ApexPhase,
        evidence: EvidenceBundle,
        ekg_summary: str,
        allowed_tools: list[str],
        *,
        findings: list[dict[str, Any]] | None = None,
        candidate_tasks: list[str] | None = None,
    ) -> list[dict[str, str]]:
        """Return ``[system_msg, user_msg]`` for the LLM planner.

        Parameters
        ----------
        findings:
            Findings accumulated so far this engagement (from
            ``ApexGraphState.findings``).  Summarised — never the full graph.
        candidate_tasks:
            Human-readable descriptions of tasks the deterministic fallback
            would emit.  Helps the LLM contextualise which alternatives it
            has and why it might choose differently.
        """
        user_content = self._build_user_content(
            goal, phase, evidence, ekg_summary, allowed_tools,
            findings=findings, candidate_tasks=candidate_tasks,
        )
        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_user_content(
        self,
        goal: Goal,
        phase: ApexPhase,
        evidence: EvidenceBundle,
        ekg_summary: str,
        allowed_tools: list[str],
        *,
        findings: list[dict[str, Any]] | None = None,
        candidate_tasks: list[str] | None = None,
    ) -> str:
        semantic = _tier_entries(evidence.entries, "semantic", _MAX_SEMANTIC_ENTRIES)
        procedural = _tier_entries(evidence.entries, "procedural", _MAX_PROCEDURAL_ENTRIES)
        episodic = _tier_entries(evidence.entries, "episodic", _MAX_EPISODIC_ENTRIES)

        sections: list[str] = [
            f"PHASE: {phase.value}",
            f"GOAL: {goal.description}",
            f"GOAL ID: {goal.id}",
            "",
            "ALLOWED TOOLS:",
            "  " + ", ".join(allowed_tools) if allowed_tools else "  (none)",
            "",
            "EKG STATE:",
            ekg_summary or "  (empty — no nodes observed yet)",
        ]

        # Include accumulated findings (summarised, never the full graph)
        if findings:
            sections.append("")
            sections.append("CURRENT FINDINGS:")
            for f in findings[-10:]:  # cap at 10 most-recent
                phase_str = str(f.get("phase", "?"))
                title = str(f.get("title", ""))
                conf = float(f.get("confidence", 0.0))
                sections.append(f"  [{phase_str}] {title} (conf={conf:.2f})")

        # Include candidate tasks the deterministic planner would emit
        if candidate_tasks:
            sections.append("")
            sections.append("CANDIDATE TASKS (deterministic planner suggestions):")
            for desc in candidate_tasks[:5]:
                sections.append(f"  - {desc}")

        sections += [
            "",
            "RETRIEVED CONTEXT:",
            _format_entries(semantic, "Semantic knowledge"),
            _format_entries(procedural, "Procedural skills"),
            _format_entries(episodic, "Recent episodes"),
            "",
            "Output your JSON plan now.",
        ]

        return "\n".join(sections)
