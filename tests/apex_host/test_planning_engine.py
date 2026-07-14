# test_planning_engine.py
# Tests for PlanningEngine, PromptBuilder, Validator, and fallback behaviour under all failure scenarios.
"""Tests for the LLM Planning Layer (apex_host/planning/).

Coverage:
- Validator: JSON parse, schema validation, tool allowlist, destructive
  commands, shell metacharacters, executor_domain whitelist.
- PromptBuilder: message structure, required content inclusions.
- PlanningEngine (FakeModelRouter path): falls back to deterministic planner.
- PlanningEngine (StubLLM path): valid output → TaskSpec conversion; each
  failure mode → fallback to deterministic planner.
- summarize_subgraph: various subgraph states.
"""
from __future__ import annotations

import json


from memfabric.ids import new_id, now
from memfabric.types import (
    AbandonSignal,
    Edge,
    EvidenceBundle,
    Goal,
    Node,
    ScoredEntry,
    SubgraphView,
    TaskSpec,
)

from apex_host.llm.router import FakeModelRouter
from apex_host.planning.engine import PlanningEngine, summarize_subgraph
from apex_host.planning.prompt_builder import PromptBuilder
from apex_host.planning.validator import Validator
from apex_host.types import ApexPhase


# ---------------------------------------------------------------------------
# Shared fixtures / factories
# ---------------------------------------------------------------------------

_ALLOWED_TOOLS = ["nmap", "curl", "nc"]
_TARGET = "10.10.10.99"


def _goal(phase: str = "recon") -> Goal:
    return Goal(
        id=new_id(),
        description=f"Perform {phase} on {_TARGET}",
        phase=phase,
        anchor_node=f"host:{_TARGET}",
    )


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="test", entries=[], subgraph=None, tiers_queried=[])


def _evidence_with_entries() -> EvidenceBundle:
    entries = [
        ScoredEntry(
            id=new_id(), score=0.9, text="Telnet service often has default creds",
            source="kb", tier="semantic",
        ),
        ScoredEntry(
            id=new_id(), score=0.8, text="skill_scan: nmap -> service discovery",
            source="reflector", tier="procedural",
        ),
        ScoredEntry(
            id=new_id(), score=0.7, text="episode: nmap succeeded on port 23",
            source="episode-store", tier="episodic",
        ),
    ]
    return EvidenceBundle(query="recon", entries=entries, subgraph=None, tiers_queried=["semantic", "procedural", "episodic"])


def _subgraph(nodes: list[Node] | None = None, edges: list[Edge] | None = None) -> SubgraphView:
    return SubgraphView(
        anchor=f"host:{_TARGET}",
        nodes=nodes or [],
        edges=edges or [],
        depth=2,
    )


def _host_node() -> Node:
    return Node(
        id=f"host:{_TARGET}", type="host",
        props={"ip": _TARGET, "target": _TARGET},
        confidence=0.9, source="nmap",
        first_seen=now(), last_seen=now(),
    )


def _service_node(port: str = "23", service: str = "telnet") -> Node:
    return Node(
        id=f"service:{_TARGET}:{port}", type="service",
        props={"port": port, "proto": "tcp", "service": service, "version": ""},
        confidence=0.9, source="nmap",
        first_seen=now(), last_seen=now(),
    )


def _valid_output_json(
    tool: str = "nmap",
    args: list[str] | None = None,
    stop_reason: str | None = None,
) -> str:
    return json.dumps({
        "reasoning": "The target has no known services yet; run nmap to enumerate.",
        "confidence": 0.85,
        "selected_tasks": [] if stop_reason else [
            {
                "tool": tool,
                "args": args if args is not None else ["-sV", "-T4", _TARGET],
                "parser": "nmap",
                "executor_domain": "recon",
                "target": _TARGET,
                "rationale": "Discover open ports and service versions.",
            }
        ],
        "rejected_tasks": [],
        "stop_reason": stop_reason,
        "next_phase": None,
    })


# ---------------------------------------------------------------------------
# StubLLM — deterministic fake that returns canned JSON
# ---------------------------------------------------------------------------

class _StubLLMResponse:
    """Mimics a LangChain ChatMessage response object."""

    def __init__(self, content: str) -> None:
        self.content = content


class _StubLLM:
    """Synchronous fake LLM that returns a canned response."""

    def __init__(self, json_str: str) -> None:
        self._json_str = json_str
        self.call_count = 0

    def invoke(self, messages: list[dict[str, str]]) -> _StubLLMResponse:
        self.call_count += 1
        return _StubLLMResponse(self._json_str)


class _RaisingLLM:
    """LLM that always raises on invoke — simulates network/API failure."""

    def invoke(self, messages: list[dict[str, str]]) -> _StubLLMResponse:
        raise RuntimeError("simulated LLM failure")


class _StubRouter:
    """ModelRouter fake that returns a controlled LLM object."""

    def __init__(self, llm: object) -> None:
        self._llm = llm

    def planner_llm(self) -> object:
        return self._llm

    def executor_llm(self) -> object:
        return None

    def parser_llm(self) -> object:
        return None

    def reflector_llm(self) -> object:
        return None


# ---------------------------------------------------------------------------
# FallbackPlanner — predictable deterministic stub
# ---------------------------------------------------------------------------

class _FallbackPlanner:
    """Minimal deterministic fallback planner."""

    def __init__(self) -> None:
        self.call_count = 0

    async def plan(
        self,
        goal: Goal,
        subgraph: SubgraphView,
        evidence: EvidenceBundle,
    ) -> list[TaskSpec] | AbandonSignal:
        self.call_count += 1
        return [
            TaskSpec(
                id="fallback-task",
                goal_id=goal.id,
                executor_domain="recon",
                params={"tool": "nmap", "args": ["-sV", _TARGET], "parser": "nmap", "target": _TARGET},
            )
        ]


class _AbandoningFallback:
    async def plan(
        self,
        goal: Goal,
        subgraph: SubgraphView,
        evidence: EvidenceBundle,
    ) -> list[TaskSpec] | AbandonSignal:
        return AbandonSignal(reason="fallback says abandon")


# ---------------------------------------------------------------------------
# Validator tests
# ---------------------------------------------------------------------------

class TestValidator:
    def _v(self) -> Validator:
        return Validator()

    def test_valid_output_accepted(self) -> None:
        v = self._v()
        out = v.validate(_valid_output_json(), _ALLOWED_TOOLS)
        assert out is not None
        assert len(out.selected_tasks) == 1
        assert out.selected_tasks[0].tool == "nmap"

    def test_malformed_json_returns_none(self) -> None:
        v = self._v()
        assert v.validate("not json at all }{", _ALLOWED_TOOLS) is None

    def test_missing_required_field_returns_none(self) -> None:
        v = self._v()
        # 'reasoning' is required
        bad = json.dumps({"confidence": 0.5, "selected_tasks": []})
        assert v.validate(bad, _ALLOWED_TOOLS) is None

    def test_unsupported_tool_returns_none(self) -> None:
        v = self._v()
        out_json = _valid_output_json(tool="gobuster")  # not in _ALLOWED_TOOLS
        assert v.validate(out_json, _ALLOWED_TOOLS) is None

    def test_destructive_tool_blocked(self) -> None:
        v = self._v()
        for tool in ("rm", "mkfs", "dd", "shutdown"):
            out_json = _valid_output_json(tool=tool)
            # Even if accidentally added to allowed_tools, must be rejected
            assert v.validate(out_json, [*_ALLOWED_TOOLS, tool]) is None

    def test_shell_metachar_in_args_blocked(self) -> None:
        v = self._v()
        for bad_arg in ("; ls", "&& echo x", "| cat /etc/passwd", "$(id)"):
            out_json = _valid_output_json(tool="nmap", args=["-sV", bad_arg])
            assert v.validate(out_json, _ALLOWED_TOOLS) is None

    def test_pipe_blocked_in_args(self) -> None:
        # The pipe character is inside the URL token — validator must still catch it.
        v = self._v()
        out_json = _valid_output_json(tool="curl", args=["-s", "http://x | cat"])
        assert v.validate(out_json, ["curl"]) is None

    def test_unknown_executor_domain_blocked(self) -> None:
        v = self._v()
        data = json.loads(_valid_output_json())
        data["selected_tasks"][0]["executor_domain"] = "hacking"  # unknown
        assert v.validate(json.dumps(data), _ALLOWED_TOOLS) is None

    def test_stop_reason_preserved(self) -> None:
        v = self._v()
        out = v.validate(_valid_output_json(stop_reason="no viable path"), _ALLOWED_TOOLS)
        assert out is not None
        assert out.stop_reason == "no viable path"
        assert out.selected_tasks == []

    def test_markdown_code_fence_stripped(self) -> None:
        v = self._v()
        fenced = "```json\n" + _valid_output_json() + "\n```"
        out = v.validate(fenced, _ALLOWED_TOOLS)
        assert out is not None

    def test_empty_string_returns_none(self) -> None:
        v = self._v()
        assert v.validate("", _ALLOWED_TOOLS) is None

    def test_confidence_clipped_at_bounds(self) -> None:
        v = self._v()
        data = json.loads(_valid_output_json())
        data["confidence"] = 1.5  # out of 0..1
        assert v.validate(json.dumps(data), _ALLOWED_TOOLS) is None

    def test_allowed_actions_override(self) -> None:
        v = self._v()
        data = json.loads(_valid_output_json())
        data["selected_tasks"][0]["executor_domain"] = "recon"
        # Restricting allowed_actions to only "web" → recon rejected
        assert v.validate(json.dumps(data), _ALLOWED_TOOLS, allowed_actions=["web"]) is None

    def test_next_phase_hint_preserved(self) -> None:
        v = self._v()
        data = json.loads(_valid_output_json())
        data["next_phase"] = "web"
        out = v.validate(json.dumps(data), _ALLOWED_TOOLS)
        assert out is not None
        assert out.next_phase == "web"


# ---------------------------------------------------------------------------
# PromptBuilder tests
# ---------------------------------------------------------------------------

class TestPromptBuilder:
    def _build(
        self,
        evidence: EvidenceBundle | None = None,
        phase: ApexPhase = ApexPhase.recon,
    ) -> list[dict[str, str]]:
        pb = PromptBuilder()
        goal = _goal(phase.value)
        ev = evidence or _empty_evidence()
        return pb.build_messages(
            goal, phase, ev, "EKG anchor: host:10.10.10.99", _ALLOWED_TOOLS
        )

    def test_returns_two_messages(self) -> None:
        msgs = self._build()
        assert len(msgs) == 2

    def test_system_role_first(self) -> None:
        msgs = self._build()
        assert msgs[0]["role"] == "system"

    def test_user_role_second(self) -> None:
        msgs = self._build()
        assert msgs[1]["role"] == "user"

    def test_system_message_mentions_rules(self) -> None:
        msgs = self._build()
        assert "CRITICAL RULES" in msgs[0]["content"]
        assert "destructive" in msgs[0]["content"]

    def test_user_message_contains_phase(self) -> None:
        msgs = self._build(phase=ApexPhase.web)
        assert "web" in msgs[1]["content"].lower()

    def test_user_message_contains_goal(self) -> None:
        msgs = self._build()
        assert "recon" in msgs[1]["content"].lower()

    def test_user_message_contains_allowed_tools(self) -> None:
        msgs = self._build()
        for tool in _ALLOWED_TOOLS:
            assert tool in msgs[1]["content"]

    def test_user_message_contains_ekg_summary(self) -> None:
        msgs = self._build()
        assert "EKG" in msgs[1]["content"]

    def test_evidence_entries_included(self) -> None:
        ev = _evidence_with_entries()
        msgs = self._build(evidence=ev)
        user_content = msgs[1]["content"]
        assert "Telnet service" in user_content  # semantic entry
        assert "skill_scan" in user_content       # procedural entry
        assert "nmap succeeded" in user_content   # episodic entry

    def test_schema_in_system_message(self) -> None:
        msgs = self._build()
        assert "selected_tasks" in msgs[0]["content"]
        assert "stop_reason" in msgs[0]["content"]


# ---------------------------------------------------------------------------
# summarize_subgraph tests
# ---------------------------------------------------------------------------

class TestSummarizeSubgraph:
    def test_none_returns_empty_label(self) -> None:
        result = summarize_subgraph(None)
        assert "empty" in result.lower()

    def test_empty_subgraph_returns_empty_label(self) -> None:
        result = summarize_subgraph(_subgraph())
        assert "empty" in result.lower()

    def test_host_node_included(self) -> None:
        sg = _subgraph(nodes=[_host_node()])
        result = summarize_subgraph(sg)
        assert "host" in result
        assert _TARGET in result

    def test_service_node_shows_port(self) -> None:
        sg = _subgraph(nodes=[_host_node(), _service_node("23", "telnet")])
        result = summarize_subgraph(sg)
        assert "service" in result
        assert "23" in result

    def test_anchor_always_present(self) -> None:
        sg = _subgraph(nodes=[_host_node()])
        result = summarize_subgraph(sg)
        assert "anchor" in result

    def test_edge_count_shown(self) -> None:
        host = _host_node()
        svc = _service_node()
        edge = Edge(
            id="e1", from_id=host.id, to_id=svc.id,
            type="exposes", props={}, confidence=0.9,
            source="nmap", first_seen=now(), last_seen=now(),
        )
        sg = _subgraph(nodes=[host, svc], edges=[edge])
        result = summarize_subgraph(sg)
        assert "1" in result  # 1 edge


# ---------------------------------------------------------------------------
# PlanningEngine — FakeModelRouter (always falls back)
# ---------------------------------------------------------------------------

class TestPlanningEngineWithFakeRouter:
    def _engine(self) -> tuple[PlanningEngine, _FallbackPlanner]:
        fb = _FallbackPlanner()
        engine = PlanningEngine(
            model_router=FakeModelRouter(),
            fallback_planner=fb,
            allowed_tools=_ALLOWED_TOOLS,
            target=_TARGET,
        )
        return engine, fb

    async def test_fallback_called_when_no_llm(self) -> None:
        engine, fb = self._engine()
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert fb.call_count == 1
        assert isinstance(result, list)

    async def test_fallback_result_returned_unchanged(self) -> None:
        engine, fb = self._engine()
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert isinstance(result, list)
        assert result[0].id == "fallback-task"  # type: ignore[union-attr]

    async def test_fallback_abandon_signal_propagated(self) -> None:
        fb = _AbandoningFallback()
        engine = PlanningEngine(
            model_router=FakeModelRouter(),
            fallback_planner=fb,
            allowed_tools=_ALLOWED_TOOLS,
            target=_TARGET,
        )
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert isinstance(result, AbandonSignal)


# ---------------------------------------------------------------------------
# PlanningEngine — StubLLM path
# ---------------------------------------------------------------------------

class TestPlanningEngineWithStubLLM:
    def _engine(self, json_str: str) -> tuple[PlanningEngine, _FallbackPlanner, _StubLLM]:
        llm = _StubLLM(json_str)
        fb = _FallbackPlanner()
        engine = PlanningEngine(
            model_router=_StubRouter(llm),
            fallback_planner=fb,
            allowed_tools=_ALLOWED_TOOLS,
            target=_TARGET,
        )
        return engine, fb, llm

    async def test_valid_llm_output_converted_to_task_specs(self) -> None:
        engine, fb, llm = self._engine(_valid_output_json())
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0].params["tool"] == "nmap"
        assert fb.call_count == 0  # fallback NOT called
        assert llm.call_count == 1

    async def test_task_spec_goal_id_matches(self) -> None:
        engine, _, _ = self._engine(_valid_output_json())
        goal = _goal()
        result = await engine.plan(goal, ApexPhase.recon, _subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].goal_id == goal.id

    async def test_task_spec_has_target(self) -> None:
        engine, _, _ = self._engine(_valid_output_json())
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert isinstance(result, list)
        assert result[0].params["target"] == _TARGET

    async def test_task_spec_default_target_used_when_empty(self) -> None:
        """When LLM omits target in task, engine fills in the configured target."""
        data = json.loads(_valid_output_json())
        data["selected_tasks"][0]["target"] = ""
        engine, _, _ = self._engine(json.dumps(data))
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert isinstance(result, list)
        assert result[0].params["target"] == _TARGET

    async def test_malformed_json_falls_back_to_deterministic(self) -> None:
        engine, fb, _ = self._engine("not valid json {{")
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert fb.call_count == 1
        assert result[0].id == "fallback-task"  # type: ignore[union-attr]

    async def test_unsafe_tool_in_llm_output_falls_back(self) -> None:
        engine, fb, _ = self._engine(_valid_output_json(tool="rm"))
        await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(_subgraph().nodes), _empty_evidence()
        )
        assert fb.call_count == 1

    async def test_unknown_tool_in_llm_output_falls_back(self) -> None:
        engine, fb, _ = self._engine(_valid_output_json(tool="gobuster"))
        await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert fb.call_count == 1

    async def test_llm_exception_falls_back(self) -> None:
        raising = _RaisingLLM()
        fb = _FallbackPlanner()
        engine = PlanningEngine(
            model_router=_StubRouter(raising),
            fallback_planner=fb,
            allowed_tools=_ALLOWED_TOOLS,
            target=_TARGET,
        )
        await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert fb.call_count == 1

    async def test_stop_reason_produces_abandon_signal(self) -> None:
        engine, fb, _ = self._engine(
            _valid_output_json(stop_reason="target appears offline")
        )
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert isinstance(result, AbandonSignal)
        assert "offline" in result.reason
        assert fb.call_count == 0  # NOT a fallback — stop_reason is a valid outcome

    async def test_empty_selected_tasks_falls_back(self) -> None:
        data = json.loads(_valid_output_json())
        data["selected_tasks"] = []
        data["stop_reason"] = None
        engine, fb, _ = self._engine(json.dumps(data))
        await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert fb.call_count == 1

    async def test_next_phase_hint_in_output_is_informational(self) -> None:
        """next_phase is forwarded but does not change the plan itself."""
        data = json.loads(_valid_output_json())
        data["next_phase"] = "web"
        engine, fb, _ = self._engine(json.dumps(data))
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        # Engine still returns the task — next_phase is a hint, not a control signal
        assert isinstance(result, list)
        assert len(result) == 1

    async def test_multiple_tasks_all_converted(self) -> None:
        data = {
            "reasoning": "Need both nmap and nc",
            "confidence": 0.9,
            "selected_tasks": [
                {
                    "tool": "nmap", "args": ["-sV", _TARGET],
                    "parser": "nmap", "executor_domain": "recon",
                    "target": _TARGET, "rationale": "discover",
                },
                {
                    "tool": "nc", "args": ["-nv", _TARGET, "23"],
                    "parser": "banner", "executor_domain": "recon",
                    "target": _TARGET, "rationale": "banner grab",
                },
            ],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        }
        engine, fb, _ = self._engine(json.dumps(data))
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0].params["tool"] == "nmap"
        assert result[1].params["tool"] == "nc"

    async def test_phase_attached_to_task_spec(self) -> None:
        engine, _, _ = self._engine(_valid_output_json())
        goal = Goal(id=new_id(), description="recon", phase="recon")
        result = await engine.plan(goal, ApexPhase.recon, _subgraph(), _empty_evidence())
        assert isinstance(result, list)
        assert result[0].phase == "recon"

    async def test_parser_from_llm_output_used(self) -> None:
        data = json.loads(_valid_output_json())
        data["selected_tasks"][0]["parser"] = "banner"
        engine, _, _ = self._engine(json.dumps(data))
        result = await engine.plan(
            _goal(), ApexPhase.recon, _subgraph(), _empty_evidence()
        )
        assert isinstance(result, list)
        assert result[0].params["parser"] == "banner"
