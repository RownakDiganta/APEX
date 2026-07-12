# test_llm_guard.py
# Unit and integration tests for LLMPolicyGuard, PlanningEngine guard wiring, and RepairEngine guard wiring.
"""Tests for LLM policy checkpoints.

Acceptance criteria verified:
- LLM never receives a configured password (sanitize_messages).
- Prompt with out-of-scope target in GOAL line falls back to deterministic.
- LLM output with destructive/persistence/brute-force content is blocked
  before the Validator sees it.
- RepairEngine output is checked by the same guard.
- No real LLM calls: FakeModelRouter and _StubRouter stubs only.
- PlanDecision audit fields (policy_checkpoint_status, redaction_count,
  policy_block_reason) are populated correctly.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView, TaskSpec
from memfabric.ids import new_id

from apex_host.config import ApexConfig
from apex_host.planning.engine import PlanningEngine
from apex_host.planning.models import PlanDecision
from apex_host.planning.repair import RepairEngine
from apex_host.policy.llm_guard import LLMPolicyGuard
from apex_host.types import ApexPhase


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

TARGET = "10.10.10.14"


def _make_config(
    *,
    passwords: list[str] | None = None,
    usernames: list[str] | None = None,
    target: str = TARGET,
    dry_run: bool = True,
) -> ApexConfig:
    return ApexConfig(
        target=target,
        password_candidates=passwords or [],
        username_candidates=usernames or [],
        dry_run=dry_run,
    )


def _make_guard(
    *,
    passwords: list[str] | None = None,
    usernames: list[str] | None = None,
    target: str = TARGET,
) -> LLMPolicyGuard:
    config = _make_config(passwords=passwords, usernames=usernames, target=target)
    return LLMPolicyGuard(config)


def _make_goal(description: str = "test goal") -> Goal:
    return Goal(
        id=new_id(),
        description=description,
        phase="recon",
        anchor_node=f"host:{TARGET}",
    )


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=f"host:{TARGET}", nodes=[], edges=[], depth=2)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _valid_nmap_json(target: str = TARGET) -> str:
    return json.dumps({
        "reasoning": "run nmap to discover services",
        "confidence": 0.9,
        "selected_tasks": [{
            "tool": "nmap",
            "args": ["-sV", "-T4", target],
            "parser": "nmap",
            "executor_domain": "recon",
            "target": target,
            "rationale": "service discovery",
        }],
        "rejected_tasks": [],
        "stop_reason": None,
        "next_phase": None,
    })


def _make_failed_task(target: str = TARGET) -> TaskSpec:
    return TaskSpec(
        id=new_id(),
        goal_id="goal-1",
        executor_domain="recon",
        params={"tool": "nmap", "args": ["-sV", target], "parser": "nmap", "target": target},
        subgraph_anchor=f"host:{target}",
        phase="recon",
    )


# ---------------------------------------------------------------------------
# Stub LLM / router helpers
# ---------------------------------------------------------------------------

class _StubLLM:
    """Returns a fixed response string from invoke()."""

    def __init__(self, response: str) -> None:
        self._response = response

    def invoke(self, messages: list[dict[str, str]]) -> object:
        return type("R", (), {"content": self._response})()


class _CapturingLLM:
    """Records every message list it receives, then returns a fixed response."""

    def __init__(self, response: str) -> None:
        self._response = response
        self.received: list[list[dict[str, str]]] = []

    def invoke(self, messages: list[dict[str, str]]) -> object:
        self.received.append([dict(m) for m in messages])
        return type("R", (), {"content": self._response})()


class _StubRouter:
    """ModelRouter stub that always returns the given LLM for planner_llm()."""

    def __init__(self, llm: object) -> None:
        self._llm = llm

    def planner_llm(self) -> object:
        return self._llm

    def executor_llm(self) -> None:
        return None

    def parser_llm(self) -> None:
        return None


class _FakeModelRouter:
    """Returns None for all roles — triggers immediate deterministic fallback."""

    def planner_llm(self) -> None:
        return None

    def executor_llm(self) -> None:
        return None

    def parser_llm(self) -> None:
        return None


class _StubFallback:
    """Deterministic fallback planner stub — records call count."""

    def __init__(self, result: list[Any] | None = None) -> None:
        self.call_count = 0
        self._result: list[Any] = result if result is not None else []

    async def plan(
        self,
        goal: Goal,
        subgraph: SubgraphView,
        evidence: EvidenceBundle,
    ) -> list[TaskSpec] | AbandonSignal:
        self.call_count += 1
        return list(self._result)


# ===========================================================================
# Unit tests: LLMPolicyGuard.sanitize_messages
# ===========================================================================

class TestSanitizeMessages:
    def test_redacts_configured_password(self) -> None:
        guard = _make_guard(passwords=["s3cr3t_pass"])
        msgs = [{"role": "user", "content": "The password is s3cr3t_pass here."}]
        sanitized, count = guard.sanitize_messages(msgs)
        assert "s3cr3t_pass" not in sanitized[0]["content"]
        assert "[REDACTED_PASSWORD]" in sanitized[0]["content"]
        assert count >= 1

    def test_redacts_openai_api_key_pattern(self) -> None:
        guard = _make_guard()
        key = "sk-abcdefghijklmnopqrstuvwxyz01234"
        msgs = [{"role": "user", "content": f"Use key: {key}"}]
        sanitized, count = guard.sanitize_messages(msgs)
        assert key not in sanitized[0]["content"]
        assert "[REDACTED_API_KEY]" in sanitized[0]["content"]
        assert count >= 1

    def test_redacts_bearer_token(self) -> None:
        guard = _make_guard()
        msgs = [{"role": "system", "content": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghi"}]
        sanitized, count = guard.sanitize_messages(msgs)
        assert "eyJhbGciO" not in sanitized[0]["content"]
        assert count >= 1

    def test_redacts_private_key_header(self) -> None:
        guard = _make_guard()
        msgs = [{"role": "user", "content": "-----BEGIN RSA PRIVATE KEY----- MIIE..."}]
        sanitized, count = guard.sanitize_messages(msgs)
        assert "-----BEGIN RSA PRIVATE KEY-----" not in sanitized[0]["content"]
        assert count >= 1

    def test_redaction_count_accumulates_across_messages(self) -> None:
        guard = _make_guard(passwords=["pass1", "pass2"])
        msgs = [
            {"role": "system", "content": "pass1 in system"},
            {"role": "user", "content": "pass2 in user"},
        ]
        _, count = guard.sanitize_messages(msgs)
        assert count == 2

    def test_empty_password_not_redacted(self) -> None:
        guard = _make_guard(passwords=[""])
        msgs = [{"role": "user", "content": "some content without anything special"}]
        sanitized, count = guard.sanitize_messages(msgs)
        assert sanitized[0]["content"] == "some content without anything special"
        assert count == 0

    def test_short_password_below_min_len_skipped(self) -> None:
        guard = _make_guard(passwords=["ab"])  # len 2 < _MIN_SECRET_LEN=4
        msgs = [{"role": "user", "content": "ab is a prefix"}]
        _, count = guard.sanitize_messages(msgs)
        assert count == 0

    def test_original_messages_not_mutated(self) -> None:
        guard = _make_guard(passwords=["secret"])
        original = [{"role": "user", "content": "secret is here"}]
        guard.sanitize_messages(original)
        assert original[0]["content"] == "secret is here"

    def test_role_field_preserved(self) -> None:
        guard = _make_guard(passwords=["secret"])
        msgs = [{"role": "system", "content": "no secrets here"}, {"role": "user", "content": "secret"}]
        sanitized, _ = guard.sanitize_messages(msgs)
        assert sanitized[0]["role"] == "system"
        assert sanitized[1]["role"] == "user"

    def test_redacts_configured_username(self) -> None:
        guard = _make_guard(usernames=["admin_user"])
        msgs = [{"role": "user", "content": "login as admin_user now"}]
        sanitized, count = guard.sanitize_messages(msgs)
        assert "admin_user" not in sanitized[0]["content"]
        assert "[REDACTED_USERNAME]" in sanitized[0]["content"]
        assert count >= 1


# ===========================================================================
# Unit tests: LLMPolicyGuard.check_prompt
# ===========================================================================

class TestCheckPrompt:
    def test_blocks_residual_password_after_sanitize(self) -> None:
        guard = _make_guard(passwords=["letmein1234"])
        # Simulate a message where sanitize was skipped / failed
        msgs = [{"role": "user", "content": "GOAL: probe target, password=letmein1234"}]
        blocked, reason = guard.check_prompt(msgs)
        assert blocked is True
        assert "credential" in reason.lower() or "unsanitized" in reason.lower()

    def test_blocks_private_key_in_prompt(self) -> None:
        guard = _make_guard()
        content = "-----BEGIN RSA PRIVATE KEY----- MIIE... -----END RSA PRIVATE KEY-----"
        msgs = [{"role": "user", "content": content}]
        blocked, reason = guard.check_prompt(msgs)
        assert blocked is True
        assert "private key" in reason.lower()

    def test_blocks_out_of_scope_ip_in_goal_line(self) -> None:
        guard = _make_guard(target="10.10.10.14")
        msgs = [{"role": "user", "content": "PHASE: recon\nGOAL: attack 192.168.100.50\nALLOWED TOOLS: nmap"}]
        blocked, reason = guard.check_prompt(msgs)
        assert blocked is True
        assert "192.168.100.50" in reason

    def test_allows_target_ip_in_goal_line(self) -> None:
        guard = _make_guard(target="10.10.10.14")
        msgs = [{"role": "user", "content": "PHASE: recon\nGOAL: scan 10.10.10.14\nALLOWED TOOLS: nmap"}]
        blocked, reason = guard.check_prompt(msgs)
        assert blocked is False
        assert reason == ""

    def test_allows_clean_prompt(self) -> None:
        guard = _make_guard(passwords=["mypass"])
        msgs = [
            {"role": "system", "content": "You are APEX planner. No secrets here."},
            {"role": "user", "content": "PHASE: recon\nGOAL: scan the target\nALLOWED TOOLS: nmap"},
        ]
        blocked, reason = guard.check_prompt(msgs)
        assert blocked is False
        assert reason == ""

    def test_blocks_out_of_scope_in_target_line(self) -> None:
        guard = _make_guard(target="10.10.10.14")
        msgs = [{"role": "user", "content": "TARGET: 172.16.0.5 is the host"}]
        blocked, reason = guard.check_prompt(msgs)
        assert blocked is True
        assert "172.16.0.5" in reason

    def test_ignores_ip_in_non_goal_lines(self) -> None:
        """IPs in evidence / EKG context sections should not trigger the gate."""
        guard = _make_guard(target="10.10.10.14")
        msgs = [{"role": "user", "content": "EKG STATE:\n  host: 10.10.10.14\nSemantic knowledge:\n  example IP 192.168.1.1 appeared in a technique\nGOAL: scan 10.10.10.14"}]
        blocked, _ = guard.check_prompt(msgs)
        assert blocked is False


# ===========================================================================
# Unit tests: LLMPolicyGuard.check_output
# ===========================================================================

class TestCheckOutput:
    def test_blocks_crontab_edit(self) -> None:
        guard = _make_guard()
        blocked, reason = guard.check_output('{"reasoning": "use crontab -e to schedule", ...}')
        assert blocked is True
        assert "persistence" in reason.lower()
        assert "crontab" in reason

    def test_blocks_authorized_keys(self) -> None:
        guard = _make_guard()
        blocked, reason = guard.check_output('{"args": ["echo key >> /root/.ssh/authorized_keys"]}')
        assert blocked is True
        assert "persistence" in reason.lower()

    def test_blocks_hydra(self) -> None:
        guard = _make_guard()
        blocked, reason = guard.check_output('{"tool": "hydra", "args": ["-l", "admin"]}')
        assert blocked is True
        assert "brute force" in reason.lower()
        assert "hydra" in reason

    def test_blocks_medusa(self) -> None:
        guard = _make_guard()
        blocked, reason = guard.check_output('run medusa to crack the password')
        assert blocked is True
        assert "brute force" in reason.lower()

    def test_blocks_hashcat(self) -> None:
        guard = _make_guard()
        blocked, reason = guard.check_output('{"tool": "hashcat", "args": ["-m", "0"]}')
        assert blocked is True
        assert "brute force" in reason.lower()

    def test_blocks_shadow_file_exfiltration(self) -> None:
        guard = _make_guard()
        blocked, reason = guard.check_output('{"args": ["cat", "/etc/shadow"]}')
        assert blocked is True
        assert "exfiltration" in reason.lower()

    def test_blocks_out_of_scope_target_field(self) -> None:
        guard = _make_guard(target="10.10.10.14")
        out = json.dumps({
            "selected_tasks": [{
                "tool": "nmap",
                "args": ["-sV", "10.10.10.14"],
                "target": "192.168.1.100",
                "executor_domain": "recon",
                "parser": "nmap",
                "rationale": "test",
            }],
        })
        blocked, reason = guard.check_output(out)
        assert blocked is True
        assert "192.168.1.100" in reason

    def test_blocks_out_of_scope_ip_in_args(self) -> None:
        guard = _make_guard(target="10.10.10.14")
        out = json.dumps({
            "selected_tasks": [{
                "tool": "nmap",
                "args": ["-sV", "172.16.0.50"],
                "target": "10.10.10.14",
                "executor_domain": "recon",
                "parser": "nmap",
                "rationale": "test",
            }],
        })
        blocked, reason = guard.check_output(out)
        assert blocked is True
        assert "172.16.0.50" in reason

    def test_allows_target_ip_in_args(self) -> None:
        guard = _make_guard(target="10.10.10.14")
        out = _valid_nmap_json("10.10.10.14")
        blocked, _ = guard.check_output(out)
        assert blocked is False

    def test_clean_json_passes(self) -> None:
        guard = _make_guard(target="10.10.10.14")
        blocked, reason = guard.check_output(_valid_nmap_json())
        assert blocked is False
        assert reason == ""

    def test_blocks_systemctl_enable(self) -> None:
        guard = _make_guard()
        blocked, reason = guard.check_output("systemctl enable backdoor.service")
        assert blocked is True
        assert "persistence" in reason.lower()

    def test_blocks_bashrc_modification(self) -> None:
        guard = _make_guard()
        blocked, reason = guard.check_output('{"args": ["echo cmd >> ~/.bashrc"]}')
        assert blocked is True
        assert "persistence" in reason.lower()


# ===========================================================================
# Integration tests: PlanningEngine with LLMPolicyGuard
# ===========================================================================

class TestPlanningEngineGuard:
    """Tests that the guard is correctly wired into PlanningEngine."""

    @pytest.mark.asyncio
    async def test_password_not_in_messages_sent_to_llm(self) -> None:
        """The configured password must not appear in messages the LLM receives."""
        password = "hunter2_secret"
        # Put the password in the goal description — it ends up in the user message.
        goal = _make_goal(description=f"test goal — password hint: {password}")
        config = _make_config(passwords=[password])
        guard = LLMPolicyGuard(config)

        llm = _CapturingLLM(_valid_nmap_json())
        router = _StubRouter(llm)
        fallback = _StubFallback()

        engine = PlanningEngine(
            model_router=router,
            fallback_planner=fallback,
            allowed_tools=["nmap"],
            target=TARGET,
            guard=guard,
        )
        await engine.plan(goal, ApexPhase.recon, _empty_subgraph(), _empty_evidence())

        # Verify the LLM received at least one message
        assert len(llm.received) == 1
        # Password must not appear in any message content
        for msg in llm.received[0]:
            assert password not in msg.get("content", ""), (
                f"Password leaked into LLM message: {msg['content'][:200]}"
            )

    @pytest.mark.asyncio
    async def test_password_redaction_recorded_in_plan_decision(self) -> None:
        password = "p4ssw0rd_xyz"
        goal = _make_goal(description=f"probe target with {password}")
        config = _make_config(passwords=[password])
        guard = LLMPolicyGuard(config)

        llm = _CapturingLLM(_valid_nmap_json())
        router = _StubRouter(llm)
        fallback = _StubFallback()
        engine = PlanningEngine(
            model_router=router,
            fallback_planner=fallback,
            allowed_tools=["nmap"],
            target=TARGET,
            guard=guard,
        )
        await engine.plan(goal, ApexPhase.recon, _empty_subgraph(), _empty_evidence())

        decision = engine.last_decision
        assert decision is not None
        assert decision.redaction_count >= 1
        assert decision.policy_checkpoint_status in ("redacted", "clean")

    @pytest.mark.asyncio
    async def test_prompt_with_out_of_scope_ip_triggers_fallback(self) -> None:
        """A GOAL line referencing an out-of-scope IP must trigger the fallback."""
        # Inject an out-of-scope IP directly into the goal description.
        # PromptBuilder emits "GOAL: <description>", which check_prompt scans.
        goal = _make_goal(description="scan 192.168.99.1 for services")
        config = _make_config(target=TARGET)
        guard = LLMPolicyGuard(config)

        llm = _CapturingLLM(_valid_nmap_json())
        router = _StubRouter(llm)
        fallback = _StubFallback()
        engine = PlanningEngine(
            model_router=router,
            fallback_planner=fallback,
            allowed_tools=["nmap"],
            target=TARGET,
            guard=guard,
        )
        await engine.plan(goal, ApexPhase.recon, _empty_subgraph(), _empty_evidence())

        # LLM was never called (prompt blocked)
        assert len(llm.received) == 0
        # Fallback was used
        assert fallback.call_count == 1
        # PlanDecision records the block
        decision = engine.last_decision
        assert decision is not None
        assert decision.policy_checkpoint_status == "blocked"
        assert "192.168.99.1" in decision.policy_block_reason

    @pytest.mark.asyncio
    async def test_blocked_output_triggers_fallback(self) -> None:
        """LLM output containing hydra must be blocked before Validator."""
        hydra_json = json.dumps({
            "reasoning": "use hydra to brute force",
            "confidence": 0.8,
            "selected_tasks": [{
                "tool": "hydra",
                "args": ["-l", "admin", "-p", "pass", TARGET],
                "parser": "command",
                "executor_domain": "credential",
                "target": TARGET,
                "rationale": "brute force login",
            }],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        })
        guard = _make_guard()
        llm = _StubLLM(hydra_json)
        router = _StubRouter(llm)
        fallback = _StubFallback()
        engine = PlanningEngine(
            model_router=router,
            fallback_planner=fallback,
            allowed_tools=["nmap", "hydra"],  # hydra in allowlist to bypass Validator
            target=TARGET,
            guard=guard,
        )
        await engine.plan(
            _make_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence()
        )

        assert fallback.call_count == 1
        decision = engine.last_decision
        assert decision is not None
        assert decision.policy_checkpoint_status == "blocked"
        assert "hydra" in decision.policy_block_reason or "brute force" in decision.policy_block_reason

    @pytest.mark.asyncio
    async def test_persistence_in_output_triggers_fallback(self) -> None:
        """LLM reasoning mentioning crontab -e must be blocked."""
        crontab_json = json.dumps({
            "reasoning": "crontab -e to schedule a backdoor",
            "confidence": 0.75,
            "selected_tasks": [{
                "tool": "nc",
                "args": ["-nv", TARGET, "23"],
                "parser": "banner",
                "executor_domain": "recon",
                "target": TARGET,
                "rationale": "banner grab",
            }],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        })
        guard = _make_guard()
        llm = _StubLLM(crontab_json)
        router = _StubRouter(llm)
        fallback = _StubFallback()
        engine = PlanningEngine(
            model_router=router,
            fallback_planner=fallback,
            allowed_tools=["nc"],
            target=TARGET,
            guard=guard,
        )
        await engine.plan(
            _make_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence()
        )

        assert fallback.call_count == 1
        decision = engine.last_decision
        assert decision is not None
        assert decision.policy_checkpoint_status == "blocked"

    @pytest.mark.asyncio
    async def test_deterministic_fallback_unaffected_by_guard(self) -> None:
        """FakeModelRouter → immediate fallback regardless of guard presence."""
        guard = _make_guard()
        fallback = _StubFallback()
        engine = PlanningEngine(
            model_router=_FakeModelRouter(),
            fallback_planner=fallback,
            allowed_tools=["nmap"],
            target=TARGET,
            guard=guard,
        )
        result = await engine.plan(
            _make_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence()
        )

        assert fallback.call_count == 1
        decision = engine.last_decision
        assert decision is not None
        assert decision.planner_model == "deterministic"
        # Guard never ran (FakeModelRouter returned None before guard could run)
        assert decision.policy_checkpoint_status == ""

    @pytest.mark.asyncio
    async def test_clean_llm_output_has_clean_checkpoint_status(self) -> None:
        """Valid nmap output with no guard triggers → status is 'clean' (not blocked)."""
        guard = _make_guard()
        llm = _StubLLM(_valid_nmap_json())
        router = _StubRouter(llm)
        fallback = _StubFallback()
        engine = PlanningEngine(
            model_router=router,
            fallback_planner=fallback,
            allowed_tools=["nmap"],
            target=TARGET,
            guard=guard,
        )
        result = await engine.plan(
            _make_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence()
        )

        assert fallback.call_count == 0
        decision = engine.last_decision
        assert decision is not None
        assert decision.policy_checkpoint_status == "clean"
        assert decision.redaction_count == 0
        assert decision.policy_block_reason == ""

    @pytest.mark.asyncio
    async def test_no_guard_leaves_checkpoint_status_empty(self) -> None:
        """Without a guard, PlanDecision.policy_checkpoint_status is empty string."""
        llm = _StubLLM(_valid_nmap_json())
        router = _StubRouter(llm)
        fallback = _StubFallback()
        engine = PlanningEngine(
            model_router=router,
            fallback_planner=fallback,
            allowed_tools=["nmap"],
            target=TARGET,
            # No guard injected
        )
        await engine.plan(
            _make_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence()
        )
        decision = engine.last_decision
        assert decision is not None
        assert decision.policy_checkpoint_status == ""

    @pytest.mark.asyncio
    async def test_shadow_file_in_output_blocked(self) -> None:
        shadow_json = json.dumps({
            "reasoning": "read /etc/shadow to get hashes",
            "confidence": 0.9,
            "selected_tasks": [{
                "tool": "nc",
                "args": ["-nv", TARGET, "22"],
                "parser": "banner",
                "executor_domain": "recon",
                "target": TARGET,
                "rationale": "SSH banner",
            }],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        })
        guard = _make_guard()
        llm = _StubLLM(shadow_json)
        router = _StubRouter(llm)
        fallback = _StubFallback()
        engine = PlanningEngine(
            model_router=router,
            fallback_planner=fallback,
            allowed_tools=["nc"],
            target=TARGET,
            guard=guard,
        )
        await engine.plan(
            _make_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence()
        )
        assert fallback.call_count == 1
        decision = engine.last_decision
        assert decision is not None
        assert decision.policy_checkpoint_status == "blocked"
        assert "shadow" in decision.policy_block_reason or "exfiltration" in decision.policy_block_reason


# ===========================================================================
# Integration tests: RepairEngine with LLMPolicyGuard
# ===========================================================================

class TestRepairEngineGuard:
    """Tests that the guard is correctly wired into RepairEngine."""

    @pytest.mark.asyncio
    async def test_repair_output_with_persistence_is_blocked(self) -> None:
        """RepairEngine must not return a TaskSpec when output contains crontab -e."""
        crontab_json = json.dumps({
            "reasoning": "crontab -e to add a backdoor task",
            "confidence": 0.7,
            "selected_tasks": [{
                "tool": "nc",
                "args": ["-nv", TARGET, "23"],
                "parser": "banner",
                "executor_domain": "recon",
                "target": TARGET,
                "rationale": "retry banner grab",
            }],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        })
        guard = _make_guard()
        engine = RepairEngine(
            model_router=_StubRouter(_StubLLM(crontab_json)),
            allowed_tools=["nc"],
            target=TARGET,
            dry_run=False,  # must be False for repair() to proceed past dry_run guard
            guard=guard,
        )
        result = await engine.repair(
            _make_failed_task(),
            "nmap: command not found",
            "recon",
            _empty_evidence(),
            _empty_subgraph(),
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_repair_output_with_brute_force_is_blocked(self) -> None:
        hydra_json = json.dumps({
            "reasoning": "use hydra to fix the credential issue",
            "confidence": 0.6,
            "selected_tasks": [{
                "tool": "hydra",
                "args": ["-l", "root"],
                "parser": "command",
                "executor_domain": "credential",
                "target": TARGET,
                "rationale": "brute force attempt",
            }],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        })
        guard = _make_guard()
        engine = RepairEngine(
            model_router=_StubRouter(_StubLLM(hydra_json)),
            allowed_tools=["hydra"],
            target=TARGET,
            dry_run=False,
            guard=guard,
        )
        result = await engine.repair(
            _make_failed_task(),
            "connection refused",
            "credential",
            _empty_evidence(),
            _empty_subgraph(),
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_repair_clean_output_passes_guard(self) -> None:
        """Valid repair output with no guard triggers should produce a TaskSpec."""
        valid_repair = json.dumps({
            "reasoning": "use nc for banner grab instead",
            "confidence": 0.8,
            "selected_tasks": [{
                "tool": "nc",
                "args": ["-nv", TARGET, "23"],
                "parser": "banner",
                "executor_domain": "recon",
                "target": TARGET,
                "rationale": "retry with nc",
            }],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        })
        guard = _make_guard()
        engine = RepairEngine(
            model_router=_StubRouter(_StubLLM(valid_repair)),
            allowed_tools=["nc"],
            target=TARGET,
            dry_run=False,
            guard=guard,
        )
        result = await engine.repair(
            _make_failed_task(),
            "nmap not found",
            "recon",
            _empty_evidence(),
            _empty_subgraph(),
        )
        assert result is not None
        assert isinstance(result, TaskSpec)

    @pytest.mark.asyncio
    async def test_repair_dry_run_returns_none_before_guard(self) -> None:
        """dry_run=True returns None immediately — guard is never reached."""
        guard = _make_guard()
        engine = RepairEngine(
            model_router=_StubRouter(_StubLLM("irrelevant")),
            allowed_tools=["nmap"],
            target=TARGET,
            dry_run=True,  # dry_run gate fires first
            guard=guard,
        )
        result = await engine.repair(
            _make_failed_task(), "error", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_repair_password_redacted_from_prompt(self) -> None:
        """Configured password must not appear in repair messages sent to LLM."""
        password = "r3p4ir_p4ss"
        # Inject the password into the failed task's target so it ends up in the prompt
        failed = TaskSpec(
            id=new_id(),
            goal_id="goal-1",
            executor_domain="recon",
            params={"tool": "nmap", "args": ["-sV", TARGET], "parser": "nmap",
                    "target": TARGET, "extra": password},
            subgraph_anchor=f"host:{TARGET}",
            phase="recon",
        )
        config = _make_config(passwords=[password], dry_run=False)
        guard = LLMPolicyGuard(config)

        capturing = _CapturingLLM(json.dumps({
            "reasoning": "try nc instead",
            "confidence": 0.8,
            "selected_tasks": [{
                "tool": "nc",
                "args": ["-nv", TARGET, "23"],
                "parser": "banner",
                "executor_domain": "recon",
                "target": TARGET,
                "rationale": "retry",
            }],
            "rejected_tasks": [],
            "stop_reason": None,
            "next_phase": None,
        }))
        engine = RepairEngine(
            model_router=_StubRouter(capturing),
            allowed_tools=["nc"],
            target=TARGET,
            dry_run=False,
            guard=guard,
        )
        await engine.repair(
            failed, f"error with {password}", "recon", _empty_evidence(), _empty_subgraph()
        )
        assert len(capturing.received) == 1
        for msg in capturing.received[0]:
            assert password not in msg.get("content", "")


# ===========================================================================
# No-real-LLM-calls verification
# ===========================================================================

class TestNoRealLLMCalls:
    @pytest.mark.asyncio
    async def test_fake_router_never_reaches_guard_check_output(self) -> None:
        """FakeModelRouter → planner_llm() returns None → fallback before any guard."""
        guard = _make_guard(passwords=["supersecret"])
        fallback = _StubFallback()
        engine = PlanningEngine(
            model_router=_FakeModelRouter(),
            fallback_planner=fallback,
            allowed_tools=["nmap"],
            target=TARGET,
            guard=guard,
        )
        # No exception — guard never fires because LLM path is never taken
        result = await engine.plan(
            _make_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence()
        )
        assert fallback.call_count == 1

    def test_plan_decision_new_fields_have_safe_defaults(self) -> None:
        """PlanDecision can be constructed without policy checkpoint kwargs."""
        from memfabric.ids import now
        decision = PlanDecision(
            planner_model="deterministic",
            confidence=1.0,
            selected_task_count=0,
            rejected_task_count=0,
            reasoning_summary="deterministic",
            fallback_used=True,
            timestamp=now(),
            phase="recon",
        )
        assert decision.policy_checkpoint_status == ""
        assert decision.redaction_count == 0
        assert decision.policy_block_reason == ""

    def test_plan_decision_to_dict_includes_policy_fields(self) -> None:
        from memfabric.ids import now
        decision = PlanDecision(
            planner_model="llm",
            confidence=0.9,
            selected_task_count=1,
            rejected_task_count=0,
            reasoning_summary="test",
            fallback_used=False,
            timestamp=now(),
            phase="recon",
            policy_checkpoint_status="redacted",
            redaction_count=2,
            policy_block_reason="",
        )
        d = decision.to_dict()
        assert d["policy_checkpoint_status"] == "redacted"
        assert d["redaction_count"] == 2
        assert d["policy_block_reason"] == ""
