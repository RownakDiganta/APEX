# repair.py
# RepairEngine: generates a corrected TaskSpec when a planner task fails with script_error or fixable outcome.
"""Repair planner for failed task correction.

``RepairEngine`` is called by the ``repair_agent`` graph node when a task
fails with a ``script_error`` or ``fixable`` ``Outcome``.  It builds a
focused repair prompt describing the failure and asks the LLM to propose
a corrected ``TaskSpec``.

Safety invariants (non-negotiable)
------------------------------------
- Returns ``None`` immediately when ``config.dry_run is True`` — no repair
  attempts in dry-run mode (the failure was synthetic).
- Returns ``None`` when ``ModelRouter.planner_llm()`` returns ``None``
  (``FakeModelRouter`` path) — no LLM call, no stall.
- All proposed args go through the same ``Validator`` used by
  ``PlanningEngine`` — destructive tools and shell metacharacters are blocked.
- Only one corrected ``TaskSpec`` is produced per call; no loops, no
  autonomous retry chains.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, cast

from memfabric.ids import new_id, now
from memfabric.types import (
    AbandonSignal,
    EvidenceBundle,
    Goal,
    SubgraphView,
    TaskSpec,
)

from apex_host.planning.engine import _LLMChatModel, _to_task_spec, summarize_subgraph
from apex_host.planning.validator import Validator

if TYPE_CHECKING:
    from apex_host.llm.router import ModelRouter

logger = logging.getLogger(__name__)

_REPAIR_SCHEMA = json.dumps(
    {
        "reasoning": "<string: why the previous call failed and what to change>",
        "confidence": "<float 0..1>",
        "selected_tasks": [
            {
                "tool": "<tool name from allowed list>",
                "args": ["<corrected arg1>", "<corrected arg2>"],
                "parser": "<nmap|banner|command|curl_body|ffuf|gobuster|access>",
                "executor_domain": "<recon|web|credential|priv_esc>",
                "target": "<target IP or URL>",
                "rationale": "<one-line: what was fixed>",
            }
        ],
        "rejected_tasks": [],
        "stop_reason": "<null or 'cannot_repair' if fix is impossible>",
        "next_phase": None,
    },
    indent=2,
)

_REPAIR_SYSTEM = """\
You are APEX-Repair, a focused task-correction planner.
A tool call in an authorized penetration test failed.  Your ONLY job is to
produce ONE corrected version of the failing task.

CRITICAL RULES:
- Only use tools from the ALLOWED TOOLS list.
- Never propose destructive commands (rm, mkfs, dd, shutdown, reboot, halt, format).
- Never include shell operators (;, &&, ||, |, >, >>, <, $(), `) in args.
- Produce exactly ONE corrected task — no chains, no sequences.
- Set stop_reason="cannot_repair" if you cannot determine a safe correction.
- Output ONLY valid JSON matching the schema — no prose before or after.

OUTPUT SCHEMA:
{schema}
""".format(schema=_REPAIR_SCHEMA)


def _build_repair_messages(
    failed_task: TaskSpec,
    error: str,
    phase: str,
    ekg_summary: str,
    allowed_tools: list[str],
) -> list[dict[str, str]]:
    """Build [system_msg, user_msg] for the repair LLM."""
    tool = str(failed_task.params.get("tool", ""))
    args = list(failed_task.params.get("args", []))
    parser = str(failed_task.params.get("parser", "command"))
    target = str(failed_task.params.get("target", ""))

    user_content = "\n".join([
        f"PHASE: {phase}",
        f"FAILED TOOL: {tool}",
        f"FAILED ARGS: {json.dumps(args)}",
        f"PARSER: {parser}",
        f"TARGET: {target}",
        f"ERROR: {error}",
        "",
        "ALLOWED TOOLS:",
        "  " + ", ".join(allowed_tools) if allowed_tools else "  (none)",
        "",
        "EKG STATE:",
        ekg_summary or "  (empty — no nodes observed yet)",
        "",
        "Produce ONE corrected task or set stop_reason=cannot_repair.",
        "Output your JSON plan now.",
    ])
    return [
        {"role": "system", "content": _REPAIR_SYSTEM},
        {"role": "user", "content": user_content},
    ]


class RepairEngine:
    """Produces a corrected ``TaskSpec`` when a planner task fails.

    ``repair()`` is the only public entry point.  It returns ``None``
    immediately when no LLM is available or when ``dry_run=True`` — the
    caller (``repair_agent`` in ``graph.py``) treats ``None`` as "skip
    repair, continue to ``reflect_or_continue``".

    Parameters
    ----------
    model_router:
        A ``ModelRouter`` instance.  ``FakeModelRouter`` returns ``None``
        for all roles, making this a no-op in tests and dry-run runs.
    allowed_tools:
        Tool names permitted in the current engagement.
    target:
        Primary engagement target; used as default if the LLM omits it.
    dry_run:
        When ``True``, ``repair()`` returns ``None`` without any LLM call —
        the failure was synthetic and requires no real correction.
    """

    def __init__(
        self,
        model_router: "ModelRouter | None",
        allowed_tools: list[str],
        target: str = "",
        dry_run: bool = True,
    ) -> None:
        self._router = model_router
        self._allowed_tools = allowed_tools
        self._target = target
        self._dry_run = dry_run
        self._validator = Validator()

    async def repair(
        self,
        failed_task: TaskSpec,
        error: str,
        phase: str,
        evidence: EvidenceBundle,
        subgraph: SubgraphView,
    ) -> TaskSpec | None:
        """Return a corrected ``TaskSpec`` or ``None`` if repair is unavailable.

        Parameters
        ----------
        failed_task:
            The ``TaskSpec`` that produced the failing tool result.
        error:
            The error string from the failing ``ToolResult``.
        phase:
            The current engagement phase (``ApexPhase.value``).
        evidence:
            The ``EvidenceBundle`` from the current turn (for context).
        subgraph:
            The current EKG subgraph (for context).
        """
        if self._dry_run:
            logger.debug("repair_engine: dry_run=True — skipping repair")
            return None

        if self._router is None:
            logger.debug("repair_engine: no router configured — skipping repair")
            return None

        llm = self._router.planner_llm()
        if llm is None:
            logger.debug("repair_engine: no LLM configured — skipping repair")
            return None

        ekg_summary = summarize_subgraph(subgraph)
        messages = _build_repair_messages(
            failed_task, error, phase, ekg_summary, self._allowed_tools
        )
        chat_llm = cast(_LLMChatModel, llm)

        try:
            response = chat_llm.invoke(messages)
            raw = str(getattr(response, "content", response))
        except Exception as exc:
            logger.warning("repair_engine: LLM error (%s) — repair skipped", exc)
            return None

        output = self._validator.validate(raw, self._allowed_tools)
        if output is None:
            logger.info("repair_engine: validator rejected repair output — skipping")
            return None

        if output.stop_reason:
            logger.info("repair_engine: LLM signalled cannot_repair — skipping")
            return None

        if not output.selected_tasks:
            logger.info("repair_engine: no tasks in repair output — skipping")
            return None

        goal = Goal(
            id=failed_task.goal_id,
            description=f"repair/{phase}",
            phase=phase,
            anchor_node=failed_task.subgraph_anchor or "",
        )
        task_spec = _to_task_spec(output.selected_tasks[0], goal, self._target)
        logger.info(
            "repair_engine: produced corrected task tool=%s phase=%s",
            task_spec.params.get("tool"),
            phase,
        )
        return task_spec
