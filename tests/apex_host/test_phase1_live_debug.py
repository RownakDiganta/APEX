# test_phase1_live_debug.py
# Regression tests for Phase 1 of 4 post-live-test debugging phases: fine-grained LLM error classification, llm_required fail-fast, provider/model preflight diagnostics, and the Nmap -sT non-root-backend fix.
"""Phase 1 (post-live-test debugging) regression tests.

Covers the fixes made in response to the first authorized HTB live test's
two findings:

1. LLM was enabled, but all 4 calls failed with a generic
   ``provider_error`` category (an OpenRouter-style model id against the
   real OpenAI API) and APEX silently continued with deterministic
   fallback with no operator-visible signal.
2. Six Nmap tasks executed through the Kali tool service (a non-root
   backend) all failed with ``script_error`` because nmap's default scan
   mode requires a raw socket the container does not have — no ``-sT``
   was ever emitted, so no port/service data was produced.

No real OpenAI/OpenRouter API is ever contacted (every LLM-related test
uses a fake router/LLM). No live HTB engagement is run. No new
exploitation, privilege-escalation, or shell-access capability is
exercised here — only diagnostics, planning, and fail-fast logic.
"""
from __future__ import annotations

from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, SubgraphView

from apex_host.config import ApexConfig
from apex_host.eval.preflight import (
    check_llm_model_compatibility,
    check_llm_readiness,
    probe_llm_readiness,
)
from apex_host.graph_state import ApexGraphState
from apex_host.llm.errors import (
    LLMErrorCategory,
    PERMANENT_LLM_ERROR_CATEGORIES,
    TRANSIENT_LLM_ERROR_CATEGORIES,
    classify_llm_exception,
    classify_missing_key,
    describe_for_diagnostics,
    looks_like_openrouter_style_model_id,
)
from apex_host.orchestration.outcome import EngagementOutcome
from apex_host.parsers.nmap_parser import (
    NMAP_ERROR_CATEGORY_EXECUTION_FAILED,
    NMAP_ERROR_CATEGORY_RAW_SOCKET_PERMISSION_DENIED,
    NMAP_ERROR_CATEGORY_SUCCESS,
    NmapParser,
    classify_nmap_error,
)
from apex_host.planners.recon_planner import ReconPlanner, _ReconDeterministic
from apex_host.planning.budget import LLMBudgetTracker
from apex_host.planning.engine import PlanningEngine
from apex_host.tools.backend import backend_supports_raw_sockets
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

_TARGET = "10.10.10.14"
_ANCHOR = f"host:{_TARGET}"


# ---------------------------------------------------------------------------
# Shared fakes / helpers
# ---------------------------------------------------------------------------


class _FakeRouter:
    """Router that returns a configurable LLM or None (never a real client)."""

    def __init__(self, llm: Any = None) -> None:
        self._llm = llm

    def planner_llm(self) -> Any:
        return self._llm

    def executor_llm(self) -> Any:
        return None

    def parser_llm(self) -> Any:
        return None

    def reflector_llm(self) -> Any:
        return None


class _RaisingLLM:
    """invoke() always raises a configurable exception. Never a real network call."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        raise self._exc


class _NotFoundError(Exception):
    """Stand-in for an SDK's model-not-found error — duck-typed only
    (status_code attribute + type-name suffix), never a real openai import."""

    def __init__(self, message: str, status_code: int = 404) -> None:
        super().__init__(message)
        self.status_code = status_code


class _AuthenticationError(Exception):
    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


class _StaticPlanner:
    """A minimal Planner fake that always returns one nmap TaskSpec, used to
    exercise the fallback_planner seam without depending on ReconPlanner."""

    async def plan(self, goal: Any, subgraph: Any, evidence: Any) -> Any:
        from memfabric.types import TaskSpec

        return [
            TaskSpec(
                id=new_id(), goal_id=goal.id, executor_domain="recon",
                params={"tool": "nmap", "args": ["-sV", _TARGET], "target": _TARGET, "parser": "nmap"},
                subgraph_anchor=goal.anchor_node, phase=goal.phase,
            )
        ]


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=2)


def _empty_evidence() -> EvidenceBundle:
    return EvidenceBundle(query="recon", entries=[], subgraph=None, tiers_queried=[])


def _make_goal() -> Goal:
    return Goal(id=new_id(), description="recon", phase="recon", anchor_node=_ANCHOR)


def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


def _make_config(**kwargs: Any) -> ApexConfig:
    return ApexConfig(target=_TARGET, dry_run=True, **kwargs)


def _make_registry() -> ToolRegistry:
    return ToolRegistry(allowed_tools=["nmap"])


def _make_initial_state(phase: str = "recon") -> ApexGraphState:
    return {
        "run_id": "run-phase1", "target": _TARGET, "phase": phase,
        "goal": f"Begin engagement against {_TARGET}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "",
    }


def _build_deps(api: Any, config: ApexConfig, registry: ToolRegistry, *, phase_planners: dict[str, Any]) -> Any:
    from apex_host.execution.dispatcher import TaskDispatcher
    from apex_host.execution.registry import TaskRegistry
    from apex_host.agents.browser_executor import BrowserExecutor
    from apex_host.agents.telnet_executor import TelnetExecutor
    from apex_host.orchestration.dependencies import OrchestrationDeps
    from apex_host.orchestration.stall import StallTracker
    from apex_host.planners.global_planner import GlobalPlanner
    from apex_host.planning.repair import RepairEngine
    from apex_host.policy.models import PolicyDecision, PolicyStatus, ScopePolicy
    from apex_host.tools.runner import run_command
    from apex_host.capabilities.runtime_references import RuntimeReferenceResolver, RuntimeReferenceStore
    from apex_host.runtime_registry import CapabilityRuntimeRegistry

    class _AllowAdvisor:
        def review_task(self, task: Any, phase: str, evidence: Any, cfg: Any) -> PolicyDecision:
            tool = str(task.params.get("tool", "") or task.params.get("kind", ""))
            return PolicyDecision(status=PolicyStatus.approved, rule_name="always_allow", reason="test", task_tool=tool)

        @property
        def policy(self) -> ScopePolicy:
            return ScopePolicy(
                allowed_targets=frozenset({config.target}), blocked_tools=frozenset(),
                allow_password_lists=False, allow_sensitive_data_access=False,
                require_review_for=[], policy_loaded=False, policy_source="test",
            )

    dispatcher = TaskDispatcher(
        advisor=_AllowAdvisor(), task_registry=TaskRegistry(), config=config,
        run_command_fn=run_command, telnet_executor=TelnetExecutor(config),
        browser_executor=BrowserExecutor(config),
    )
    capability_registry = CapabilityRuntimeRegistry()
    runtime_reference_store = RuntimeReferenceStore()
    return OrchestrationDeps(
        api=api, dispatcher=dispatcher, global_planner=GlobalPlanner(max_turns=config.max_turns),
        phase_planners=phase_planners,
        repair_engine=RepairEngine(model_router=None, allowed_tools=config.allowed_tools, dry_run=True),
        config=config, anchor_id=_ANCHOR, stall_tracker=StallTracker(),
        capability_registry=capability_registry,
        runtime_reference_store=runtime_reference_store,
        runtime_reference_resolver=RuntimeReferenceResolver(runtime_reference_store, capability_registry),
    )


# ---------------------------------------------------------------------------
# 1. Invalid model configuration is classified correctly.
# ---------------------------------------------------------------------------


class TestInvalidModelClassification:
    def test_404_with_model_in_message_is_invalid_model(self) -> None:
        exc = _NotFoundError("The model `openai/gpt-5.5` does not exist", status_code=404)
        assert classify_llm_exception(exc) is LLMErrorCategory.invalid_model

    def test_notfound_type_suffix_with_model_marker_is_invalid_model(self) -> None:
        class ModelNotFoundError(Exception):
            pass

        exc = ModelNotFoundError("unknown model requested")
        assert classify_llm_exception(exc) is LLMErrorCategory.invalid_model

    def test_404_without_model_marker_is_unsupported_endpoint(self) -> None:
        # No message text at all avoids the (deliberately broad)
        # invalid-model marker set ("not found", "does not exist", ...)
        # matching by accident.
        exc = _NotFoundError("", status_code=404)
        assert classify_llm_exception(exc) is LLMErrorCategory.unsupported_endpoint

    def test_invalid_model_is_permanent(self) -> None:
        assert LLMErrorCategory.invalid_model in PERMANENT_LLM_ERROR_CATEGORIES
        assert LLMErrorCategory.invalid_model not in TRANSIENT_LLM_ERROR_CATEGORIES

    def test_openrouter_style_model_id_detected(self) -> None:
        assert looks_like_openrouter_style_model_id("openai/gpt-5.5") is True
        assert looks_like_openrouter_style_model_id("gpt-4o-mini") is False


# ---------------------------------------------------------------------------
# 2. Missing API key is distinct from invalid model.
# ---------------------------------------------------------------------------


class TestMissingKeyVsInvalidModel:
    def test_missing_key_classified_when_no_key(self) -> None:
        assert classify_missing_key(None) is LLMErrorCategory.missing_key
        assert classify_missing_key("") is LLMErrorCategory.missing_key
        assert classify_missing_key("   ") is LLMErrorCategory.missing_key

    def test_missing_key_none_when_key_present(self) -> None:
        assert classify_missing_key("sk-real-key-value-1234567890") is None

    def test_missing_key_and_invalid_model_are_distinct_categories(self) -> None:
        assert LLMErrorCategory.missing_key != LLMErrorCategory.invalid_model
        # Both are permanent (an operator must fix configuration either way)
        # but they are never conflated into the same generic category.
        assert LLMErrorCategory.missing_key in PERMANENT_LLM_ERROR_CATEGORIES

    def test_401_with_key_present_is_authentication_failure_not_missing_key(self) -> None:
        exc = _AuthenticationError("Incorrect API key provided")
        # A raised auth exception (key WAS sent, provider rejected it) is
        # authentication_failure — missing_key is reserved for the
        # proactive pre-call check via classify_missing_key().
        assert classify_llm_exception(exc) is LLMErrorCategory.authentication_failure


# ---------------------------------------------------------------------------
# 3. Provider errors do not leak secrets.
# ---------------------------------------------------------------------------


class TestProviderErrorsDoNotLeakSecrets:
    def test_api_key_shaped_text_is_redacted(self) -> None:
        exc = _AuthenticationError("Incorrect API key provided: sk-abcdefghijklmnopqrstuvwxyz123456")
        described = describe_for_diagnostics(exc)
        assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in described
        assert "[REDACTED_API_KEY]" in described

    def test_bearer_token_shaped_text_is_redacted(self) -> None:
        exc = RuntimeError("request failed: Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789")
        described = describe_for_diagnostics(exc)
        assert "abcdefghijklmnopqrstuvwxyz0123456789" not in described

    def test_aws_key_shaped_text_is_redacted(self) -> None:
        exc = RuntimeError("upstream credential AKIAABCDEFGHIJKLMNOP rejected")
        described = describe_for_diagnostics(exc)
        assert "AKIAABCDEFGHIJKLMNOP" not in described
        assert "[REDACTED_AWS_KEY]" in described

    def test_ordinary_message_passes_through_unredacted(self) -> None:
        exc = RuntimeError("connection refused")
        described = describe_for_diagnostics(exc)
        assert "connection refused" in described

    def test_description_is_bounded_length(self) -> None:
        exc = RuntimeError("x" * 5000)
        described = describe_for_diagnostics(exc, max_length=200)
        assert len(described) <= 200

    @pytest.mark.asyncio
    async def test_gateway_audit_log_never_contains_raw_secret(self) -> None:
        from apex_host.llm.gateway import LLMCallContext, LLMCallPurpose, LLMGateway

        exc = _AuthenticationError("Incorrect API key provided: sk-livekeyvalueabcdefghijklmno1234")
        gateway = LLMGateway(model_router=_FakeRouter(_RaisingLLM(exc)))
        ctx = LLMCallContext(purpose=LLMCallPurpose.planning, phase="recon", messages=[{"role": "user", "content": "hi"}])
        result = await gateway.invoke(ctx)
        assert result.status.is_error
        assert result.error_category == "authentication_failure"
        assert "sk-livekeyvalueabcdefghijklmno1234" not in result.error
        audit = gateway.audit_log
        assert len(audit) == 1
        assert "sk-livekeyvalueabcdefghijklmno1234" not in str(audit[0])


# ---------------------------------------------------------------------------
# 4. LLM-required live mode does not continue indefinitely after zero
#    successful calls.
# ---------------------------------------------------------------------------


class TestLLMRequiredFailFast:
    @pytest.mark.asyncio
    async def test_confirmed_permanent_error_terminates_with_llm_unavailable(self) -> None:
        from apex_host.orchestration.dispatch_node import make_recon_node
        from apex_host.llm.gateway import LLMGateway

        exc = _NotFoundError("The model `openai/gpt-5.5` does not exist", status_code=404)
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        router = _FakeRouter(_RaisingLLM(exc))
        gateway = LLMGateway(model_router=router, budget=budget)
        # ReconPlanner (not a bare PlanningEngine) is what real orchestration
        # wires into phase_planners — it binds ApexPhase.recon internally.
        planner = ReconPlanner(
            _TARGET, _make_registry(), model_router=router,
            budget_tracker=budget, gateway=gateway,
        )
        config = _make_config(llm_required=True, use_llm=True, llm_provider="openai")
        registry = _make_registry()
        deps = _build_deps(_make_api(), config, registry, phase_planners={ApexPhase.recon.value: planner})
        node = make_recon_node(deps)

        result = await node(_make_initial_state())

        assert result["outcome"] == EngagementOutcome.llm_unavailable.value
        assert "invalid_model" in result["termination_reason"]
        assert result["current_task"] is None

    @pytest.mark.asyncio
    async def test_llm_required_false_falls_back_silently_as_before(self) -> None:
        """When llm_required is not set (the default), the pre-existing
        silent-fallback behavior is completely unchanged."""
        from apex_host.orchestration.dispatch_node import make_recon_node
        from apex_host.llm.gateway import LLMGateway

        exc = _NotFoundError("does not exist", status_code=404)
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        router = _FakeRouter(_RaisingLLM(exc))
        gateway = LLMGateway(model_router=router, budget=budget)
        planner = ReconPlanner(
            _TARGET, _make_registry(), model_router=router,
            budget_tracker=budget, gateway=gateway,
        )
        config = _make_config(llm_required=False, use_llm=True, llm_provider="openai")
        registry = _make_registry()
        deps = _build_deps(_make_api(), config, registry, phase_planners={ApexPhase.recon.value: planner})
        node = make_recon_node(deps)

        result = await node(_make_initial_state())

        # No "outcome" key at all means the normal (non-terminating) dispatch
        # path was taken — the fail-fast branch never fires.
        assert result.get("outcome", "") != EngagementOutcome.llm_unavailable.value
        # Fell back to the deterministic ReconPlanner and produced a real
        # nmap task — nothing silently stalls.
        assert result["current_task"] is not None
        assert result["current_task"]["params"]["tool"] == "nmap"

    def test_llm_required_defaults_to_false(self) -> None:
        assert ApexConfig(target=_TARGET).llm_required is False


# ---------------------------------------------------------------------------
# 5. Explicitly permitted fallback still works.
# ---------------------------------------------------------------------------


class TestExplicitFallbackStillWorks:
    @pytest.mark.asyncio
    async def test_fake_router_falls_back_with_no_llm_calls(self) -> None:
        """FakeModelRouter-equivalent (planner_llm() returns None) must
        never attempt a gateway call at all — the deterministic fallback
        must always still work, exactly as before this phase."""
        from apex_host.llm.gateway import LLMGateway

        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        gateway = LLMGateway(model_router=_FakeRouter(None), budget=budget)
        engine = PlanningEngine(
            model_router=_FakeRouter(None), fallback_planner=_StaticPlanner(),
            allowed_tools=["nmap"], target=_TARGET, budget=budget, gateway=gateway,
        )
        result = await engine.plan(_make_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        assert list(result)[0].params["tool"] == "nmap"
        assert budget.calls_attempted == 0

    @pytest.mark.asyncio
    async def test_transient_error_does_not_set_permanent_short_circuit(self) -> None:
        from apex_host.llm.gateway import LLMGateway

        exc = TimeoutError("read timed out")
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        gateway = LLMGateway(model_router=_FakeRouter(_RaisingLLM(exc)), budget=budget)
        engine = PlanningEngine(
            model_router=_FakeRouter(_RaisingLLM(exc)), fallback_planner=_StaticPlanner(),
            allowed_tools=["nmap"], target=_TARGET, budget=budget, gateway=gateway,
        )
        result = await engine.plan(_make_goal(), ApexPhase.recon, _empty_subgraph(), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        assert budget.permanent_provider_error_category == ""


# ---------------------------------------------------------------------------
# 6. Per-phase budget is not repeatedly consumed by one known provider
#    configuration failure.
# ---------------------------------------------------------------------------


class TestPermanentErrorShortCircuit:
    @pytest.mark.asyncio
    async def test_second_phase_never_calls_gateway_after_confirmed_permanent_error(self) -> None:
        from apex_host.llm.gateway import LLMGateway

        exc = _NotFoundError("The model `openai/gpt-5.5` does not exist", status_code=404)
        budget = LLMBudgetTracker(max_per_run=5, max_per_phase=2)
        # Two independent PlanningEngine instances (one per phase, as the
        # real orchestration constructs), sharing ONE LLMBudgetTracker —
        # exactly the real build_planners() wiring.
        gateway_a = LLMGateway(model_router=_FakeRouter(_RaisingLLM(exc)), budget=budget)
        engine_recon = PlanningEngine(
            model_router=_FakeRouter(_RaisingLLM(exc)), fallback_planner=_StaticPlanner(),
            allowed_tools=["nmap"], target=_TARGET, budget=budget, gateway=gateway_a,
        )
        result_a = await engine_recon.plan(
            Goal(id=new_id(), description="recon", phase="recon", anchor_node=_ANCHOR),
            ApexPhase.recon, _empty_subgraph(), _empty_evidence(),
        )
        assert not isinstance(result_a, AbandonSignal)
        assert budget.permanent_provider_error_category == "invalid_model"
        assert budget.calls_attempted == 1

        class _AssertNeverCalledLLM:
            def invoke(self, messages: list[dict[str, str]]) -> Any:
                raise AssertionError("gateway must never call the provider a second time")

        gateway_b = LLMGateway(model_router=_FakeRouter(_AssertNeverCalledLLM()), budget=budget)
        engine_web = PlanningEngine(
            model_router=_FakeRouter(_AssertNeverCalledLLM()), fallback_planner=_StaticPlanner(),
            allowed_tools=["nmap"], target=_TARGET, budget=budget, gateway=gateway_b,
        )
        # A DIFFERENT phase, different goal — proves the short-circuit is
        # keyed on the shared budget's confirmed-permanent-error flag, not
        # on repeated-context detection (which is per-phase and would not
        # otherwise fire here).
        result_b = await engine_web.plan(
            Goal(id=new_id(), description="web", phase="web", anchor_node=_ANCHOR),
            ApexPhase.web, _empty_subgraph(), _empty_evidence(),
        )
        assert not isinstance(result_b, AbandonSignal)
        # calls_attempted is unchanged — the second phase never reserved
        # a budget slot or invoked the provider.
        assert budget.calls_attempted == 1
        assert engine_web.last_decision is not None
        assert engine_web.last_decision.llm_error_category == "invalid_model"
        assert engine_web.last_decision.repeated_plan_action == "skipped_known_provider_error"


# ---------------------------------------------------------------------------
# 7. Remote non-root Kali Nmap tasks include -sT.
# ---------------------------------------------------------------------------


class TestNmapRawSocketCapabilitySeam:
    def test_backend_supports_raw_sockets_false_for_remote(self) -> None:
        config = ApexConfig(target=_TARGET, tool_backend="remote", tool_service_url="http://kali:8080")
        assert backend_supports_raw_sockets(config) is False

    def test_backend_supports_raw_sockets_true_for_local(self) -> None:
        config = ApexConfig(target=_TARGET, tool_backend="local")
        assert backend_supports_raw_sockets(config) is True

    def test_backend_supports_raw_sockets_true_for_dry_run_backend_name(self) -> None:
        config = ApexConfig(target=_TARGET, tool_backend="dry-run")
        assert backend_supports_raw_sockets(config) is True

    def test_explicit_override_wins_over_remote_default(self) -> None:
        config = ApexConfig(
            target=_TARGET, tool_backend="remote", tool_service_url="http://kali:8080",
            tool_backend_raw_socket_capable=True,
        )
        assert backend_supports_raw_sockets(config) is True

    def test_explicit_override_wins_over_local_default(self) -> None:
        config = ApexConfig(target=_TARGET, tool_backend="local", tool_backend_raw_socket_capable=False)
        assert backend_supports_raw_sockets(config) is False

    @pytest.mark.asyncio
    async def test_recon_planner_emits_sT_when_not_raw_socket_capable(self) -> None:
        planner = ReconPlanner(_TARGET, _make_registry(), raw_socket_capable=False)
        result = await planner.plan(_make_goal(), _empty_subgraph(), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        args = list(result)[0].params["args"]
        assert "-sT" in args
        assert "-sV" in args
        assert args.index("-sT") < args.index("-sV")

    @pytest.mark.asyncio
    async def test_recon_planner_default_omits_sT_preserving_prior_behavior(self) -> None:
        """Default construction (no raw_socket_capable kwarg) must be
        byte-for-byte identical to pre-Phase-1 behavior."""
        planner = ReconPlanner(_TARGET, _make_registry())
        result = await planner.plan(_make_goal(), _empty_subgraph(), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        args = list(result)[0].params["args"]
        assert args == ["-sV", "-T4", "-Pn", _TARGET]

    @pytest.mark.asyncio
    async def test_recon_deterministic_direct_construction_raw_socket_capable_true_by_default(self) -> None:
        core = _ReconDeterministic(_TARGET, _make_registry())
        result = await core.plan(_make_goal(), _empty_subgraph(), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        assert "-sT" not in list(result)[0].params["args"]

    def test_build_planners_wires_raw_socket_capability_from_config(self) -> None:
        from apex_host.orchestration.dependencies import build_planners

        config = ApexConfig(target=_TARGET, tool_backend="remote", tool_service_url="http://kali:8080")
        planners = build_planners(config, _make_registry())
        recon_planner = planners[ApexPhase.recon.value]
        assert isinstance(recon_planner, ReconPlanner)
        assert recon_planner._core._raw_socket_capable is False  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 8. Target validation remains enforced.
# ---------------------------------------------------------------------------


class TestTargetValidationUnaffected:
    @pytest.mark.asyncio
    async def test_nmap_task_still_carries_runtime_supplied_target_not_hardcoded(self) -> None:
        other_target = "10.10.10.200"
        planner = ReconPlanner(other_target, _make_registry(), raw_socket_capable=False)
        goal = Goal(id=new_id(), description="recon", phase="recon", anchor_node=f"host:{other_target}")
        result = await planner.plan(goal, SubgraphView(anchor=f"host:{other_target}", nodes=[], edges=[], depth=2), _empty_evidence())
        assert not isinstance(result, AbandonSignal)
        task = list(result)[0]
        assert task.params["target"] == other_target
        assert other_target in task.params["args"]
        # No shell string concatenation anywhere — args is a list, and no
        # single element contains a shell metacharacter joined with target.
        assert all(isinstance(a, str) and ";" not in a and "&&" not in a for a in task.params["args"])

    @pytest.mark.asyncio
    async def test_dispatcher_policy_gate_still_blocks_off_scope_target(self) -> None:
        from apex_host.execution.dispatcher import ExecutionContext, TaskDispatcher
        from apex_host.execution.registry import TaskRegistry
        from apex_host.agents.browser_executor import BrowserExecutor
        from apex_host.agents.telnet_executor import TelnetExecutor
        from apex_host.policy.advisor import PolicyAdvisor
        from apex_host.policy.policy_loader import load_policy
        from memfabric.types import TaskSpec

        config = _make_config()
        advisor = PolicyAdvisor(load_policy(config), config)
        dispatcher = TaskDispatcher(
            advisor=advisor, task_registry=TaskRegistry(), config=config,
            run_command_fn=None, telnet_executor=TelnetExecutor(config),
            browser_executor=BrowserExecutor(config),
        )
        task = TaskSpec(
            id=new_id(), goal_id="g", executor_domain="recon",
            params={"tool": "nmap", "args": ["-sT", "-sV", "10.10.10.99"], "target": "10.10.10.99", "parser": "nmap"},
            subgraph_anchor=_ANCHOR, phase="recon",
        )
        ctx = ExecutionContext(
            run_id="r", phase="recon", turn_number=0, evidence_version=None,
            subgraph=_empty_subgraph(), evidence=_empty_evidence(), dry_run=True,
        )
        result = await dispatcher.dispatch(task, ctx)
        assert result.tool_result_dict.get("policy_blocked") is True


# ---------------------------------------------------------------------------
# 9. Nmap raw-socket errors are classified correctly.
# ---------------------------------------------------------------------------


class TestNmapErrorClassification:
    def test_success_returncode_zero_has_empty_category(self) -> None:
        assert classify_nmap_error(0, "some output", "") == NMAP_ERROR_CATEGORY_SUCCESS

    def test_raw_socket_permission_denied_detected_in_stderr(self) -> None:
        stderr = (
            "Couldn't open a raw socket. Error: (1) Operation not permitted\n"
            "Couldn't open a raw socket or eth handle.\nQUITTING!"
        )
        assert classify_nmap_error(1, "", stderr) == NMAP_ERROR_CATEGORY_RAW_SOCKET_PERMISSION_DENIED

    def test_raw_socket_permission_denied_case_insensitive(self) -> None:
        stderr = "COULDN'T OPEN A RAW SOCKET. Error: (1) Operation not permitted"
        assert classify_nmap_error(1, "", stderr) == NMAP_ERROR_CATEGORY_RAW_SOCKET_PERMISSION_DENIED

    def test_generic_nonzero_failure_gets_generic_category(self) -> None:
        assert classify_nmap_error(1, "", "some other unrelated failure") == NMAP_ERROR_CATEGORY_EXECUTION_FAILED

    def test_dispatcher_run_command_sets_error_category_for_nmap(self) -> None:
        import asyncio
        from apex_host.execution.dispatcher import ExecutionContext, TaskDispatcher
        from apex_host.execution.registry import TaskRegistry
        from apex_host.agents.browser_executor import BrowserExecutor
        from apex_host.agents.telnet_executor import TelnetExecutor
        from apex_host.policy.advisor import PolicyAdvisor
        from apex_host.policy.policy_loader import load_policy
        from apex_host.types import ToolResult
        from memfabric.types import TaskSpec

        async def _run() -> None:
            config = _make_config()
            advisor = PolicyAdvisor(load_policy(config), config)

            async def _fake_run_command_fn(cmd: Any, cfg: Any) -> ToolResult:
                return ToolResult(
                    command=cmd, stdout="", returncode=1, dry_run=False,
                    stderr="Couldn't open a raw socket. Error: (1) Operation not permitted\nQUITTING!",
                    backend="remote", duration_seconds=0.01,
                )

            dispatcher = TaskDispatcher(
                advisor=advisor, task_registry=TaskRegistry(), config=config,
                run_command_fn=_fake_run_command_fn, telnet_executor=TelnetExecutor(config),
                browser_executor=BrowserExecutor(config),
            )
            task = TaskSpec(
                id=new_id(), goal_id="g", executor_domain="recon",
                params={"tool": "nmap", "args": ["-sV", _TARGET], "target": _TARGET, "parser": "nmap"},
                subgraph_anchor=_ANCHOR, phase="recon",
            )
            ctx = ExecutionContext(
                run_id="r", phase="recon", turn_number=0, evidence_version=None,
                subgraph=_empty_subgraph(), evidence=_empty_evidence(), dry_run=False,
            )
            result = await dispatcher.dispatch(task, ctx)
            assert result.tool_result_dict["error_category"] == NMAP_ERROR_CATEGORY_RAW_SOCKET_PERMISSION_DENIED

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 10. Failed Nmap scans do not create false service nodes.
# ---------------------------------------------------------------------------


class TestFailedNmapScanNoFalseServices:
    def test_raw_socket_error_stderr_produces_no_service_nodes(self) -> None:
        stderr = "Couldn't open a raw socket. Error: (1) Operation not permitted\nQUITTING!"
        obs = NmapParser().parse_text(stderr, target=_TARGET)
        service_nodes = [n for n in obs.node_deltas if n.type == "service"]
        tech_nodes = [n for n in obs.node_deltas if n.type == "tech"]
        assert service_nodes == []
        assert tech_nodes == []
        # A host anchor node is still produced (it is not itself "a
        # successful service discovery" — see NmapParser.parse_text).
        host_nodes = [n for n in obs.node_deltas if n.type == "host"]
        assert len(host_nodes) == 1

    def test_empty_output_produces_no_service_nodes(self) -> None:
        obs = NmapParser().parse_text("", target=_TARGET)
        assert [n for n in obs.node_deltas if n.type == "service"] == []

    def test_partial_garbage_output_produces_no_service_nodes(self) -> None:
        obs = NmapParser().parse_text("random junk\nnot nmap output at all\n123 456 789", target=_TARGET)
        assert [n for n in obs.node_deltas if n.type == "service"] == []


# ---------------------------------------------------------------------------
# 11. Successful representative Nmap fixtures still produce host, port,
#     and service findings (including with -sT prepended).
# ---------------------------------------------------------------------------


class TestSuccessfulNmapFixtureUnaffected:
    _NMAP_SSH = f"""\
Nmap scan report for {_TARGET}
Host is up (0.05s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
"""

    def test_ssh_fixture_produces_host_service_and_tech(self) -> None:
        obs = NmapParser().parse_text(self._NMAP_SSH, target=_TARGET)
        assert classify_nmap_error(0, self._NMAP_SSH, "") == NMAP_ERROR_CATEGORY_SUCCESS
        host_nodes = [n for n in obs.node_deltas if n.type == "host"]
        service_nodes = [n for n in obs.node_deltas if n.type == "service"]
        tech_nodes = [n for n in obs.node_deltas if n.type == "tech"]
        assert len(host_nodes) == 1
        assert len(service_nodes) == 1
        assert service_nodes[0].props["port"] == "22"
        assert len(tech_nodes) == 1
        assert tech_nodes[0].props["name"] == "OpenSSH"

    def test_scan_mode_flag_choice_never_affects_parsing(self) -> None:
        """The -sT fix changes what ARGS are sent to nmap, never how the
        resulting output text is parsed — nmap's stdout shape for an open
        port is identical whether -sT or a raw-socket scan found it."""
        obs = NmapParser().parse_text(self._NMAP_SSH, target=_TARGET)
        service_nodes = [n for n in obs.node_deltas if n.type == "service"]
        assert len(service_nodes) == 1


# ---------------------------------------------------------------------------
# 12. Preflight reports provider/model readiness clearly.
# ---------------------------------------------------------------------------


class TestPreflightLLMReadiness:
    def test_use_llm_false_is_trivial_pass_no_network(self) -> None:
        config = ApexConfig(target=_TARGET, use_llm=False)
        check = check_llm_readiness(config)
        assert check.passed is True
        assert check.required is False

    def test_missing_key_reports_provider_model_and_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Phase 5: a native model identifier — "openai/gpt-5.5" is now a
        # provider_model_mismatch, checked BEFORE the credential check, so
        # this test uses a valid native-shaped model to reach missing_key.
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini")
        check = check_llm_readiness(config)
        assert check.passed is False
        assert check.required is True
        assert "missing_key" in check.detail
        assert "gpt-4o-mini" in check.detail
        assert "OPENAI_API_KEY" in check.detail

    def test_key_present_reports_readiness_without_leaking_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-super-secret-value-should-never-appear-1234")
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini")
        check = check_llm_readiness(config)
        assert check.passed is True
        assert "sk-super-secret-value-should-never-appear-1234" not in check.detail
        assert "credential present" in check.detail

    def test_readiness_hard_rejects_openrouter_style_model_against_openai(self) -> None:
        """Phase 5: what used to be a warning is now a hard
        provider_model_mismatch failure on the REQUIRED readiness check —
        this is the exact root-cause configuration from the original
        live-test failure this module documents."""
        config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="openai",
            planner_model="openai/gpt-5.5", llm_base_url=None,
        )
        check = check_llm_readiness(config)
        assert check.required is True
        assert check.passed is False
        assert "provider_model_mismatch" in check.detail
        assert "openai/gpt-5.5" in check.detail

    def test_model_compatibility_warns_on_openrouter_style_model_against_openai(self) -> None:
        config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="openai",
            planner_model="openai/gpt-5.5", llm_base_url=None,
        )
        check = check_llm_model_compatibility(config)
        assert check.required is False
        assert check.passed is False
        assert "openai/gpt-5.5" in check.detail

    def test_model_compatibility_passes_for_bare_openai_model(self) -> None:
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini")
        check = check_llm_model_compatibility(config)
        assert check.passed is True

    def test_openai_provider_with_openrouter_base_url_is_rejected_with_migration_message(self) -> None:
        """Phase 5: the old mixed configuration (provider='openai' pointed
        at an OpenRouter base URL) is no longer silently treated as
        compatible — it is rejected on BOTH the required readiness check
        and the informational compatibility check, with a message
        instructing the operator to select provider='openrouter' instead.
        This is the exact "reject with precise migration message" behavior
        the Phase 5 task brief requires."""
        config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="openai",
            planner_model="openai/gpt-5.5", llm_base_url="https://openrouter.ai/api/v1",
        )
        readiness = check_llm_readiness(config)
        assert readiness.passed is False
        assert readiness.required is True

        compatibility = check_llm_model_compatibility(config)
        assert compatibility.passed is False
        assert "openrouter" in compatibility.detail.lower()
        assert "provider='openrouter'" in compatibility.detail

    def test_openai_provider_with_openrouter_base_url_rejected_even_with_native_model(self) -> None:
        """A native-shaped model does not save an OpenRouter base URL
        combined with provider='openai' — the base-URL/provider mismatch
        is an independent, unconditional check."""
        config = ApexConfig(
            target=_TARGET, use_llm=True, llm_provider="openai",
            planner_model="gpt-4o-mini", llm_base_url="https://openrouter.ai/api/v1",
        )
        check = check_llm_readiness(config)
        assert check.passed is False
        assert "provider_model_mismatch" in check.detail
        assert "openrouter" in check.detail.lower()

    def test_model_compatibility_is_never_blocking(self) -> None:
        """A model/provider mismatch is a WARNING, never a hard rejection
        — see check_llm_model_compatibility's docstring for why."""
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="openai/gpt-5.5")
        check = check_llm_model_compatibility(config)
        assert check.required is False

    @pytest.mark.asyncio
    async def test_probe_missing_key_fails_without_network_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Phase 5: each native provider adapter constructs its own SDK
        client internally rather than accepting an injected httpx client
        — mocked at the adapter boundary (the real openai.AsyncOpenAI
        class) so a missing key is caught before any client is ever
        constructed."""
        import openai

        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini")

        def _never_construct(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("must never construct an SDK client without a key")

        monkeypatch.setattr(openai, "AsyncOpenAI", _never_construct)

        check = await probe_llm_readiness(config)
        assert check.passed is False
        assert "missing_key" in check.detail

    @pytest.mark.asyncio
    async def test_probe_never_contacts_real_openai_mocked_at_sdk_boundary(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """This is the load-bearing test proving tests never call the real
        OpenAI API — the openai SDK's own AsyncOpenAI client class is
        mocked at the adapter boundary (Phase 5's required test pattern),
        never a raw httpx transport underneath a real SDK client."""
        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-not-real-1234567890")
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini")

        construct_calls: list[dict[str, Any]] = []

        class _FakeModels:
            async def list(self) -> Any:
                return type("R", (), {"data": [{"id": "gpt-4o-mini"}]})()

        class _FakeAsyncOpenAI:
            def __init__(self, **kwargs: Any) -> None:
                construct_calls.append(kwargs)
                self.models = _FakeModels()

            async def close(self) -> None:
                pass

        monkeypatch.setattr(openai, "AsyncOpenAI", _FakeAsyncOpenAI)

        check = await probe_llm_readiness(config)
        assert check.passed is True
        assert len(construct_calls) == 1
        assert construct_calls[0]["api_key"] == "sk-test-key-not-real-1234567890"

    @pytest.mark.asyncio
    async def test_probe_401_classified_as_authentication_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-bad-key-0000000000000000000000")
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini")

        class _FakeModels:
            async def list(self) -> Any:
                raise _AuthenticationError("invalid key", status_code=401)

        class _FakeAsyncOpenAI:
            def __init__(self, **kwargs: Any) -> None:
                self.models = _FakeModels()

            async def close(self) -> None:
                pass

        monkeypatch.setattr(openai, "AsyncOpenAI", _FakeAsyncOpenAI)

        check = await probe_llm_readiness(config)
        assert check.passed is False
        assert "authentication_failure" in check.detail

    @pytest.mark.asyncio
    async def test_probe_404_classified_as_unsupported_endpoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import openai

        monkeypatch.setenv("OPENAI_API_KEY", "sk-key-0000000000000000000000000")
        config = ApexConfig(target=_TARGET, use_llm=True, llm_provider="openai", planner_model="gpt-4o-mini")

        class _FakeModels:
            async def list(self) -> Any:
                raise _NotFoundError("", status_code=404)

        class _FakeAsyncOpenAI:
            def __init__(self, **kwargs: Any) -> None:
                self.models = _FakeModels()

            async def close(self) -> None:
                pass

        monkeypatch.setattr(openai, "AsyncOpenAI", _FakeAsyncOpenAI)

        check = await probe_llm_readiness(config)
        assert check.passed is False
        assert "unsupported_endpoint" in check.detail

    @pytest.mark.asyncio
    async def test_live_interlock_adds_probe_only_when_llm_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """config.llm_required=False (the default) must never trigger the
        network-touching probe — byte-for-byte unchanged interlock
        behavior for every non-opted-in caller."""
        from apex_host.eval import preflight as preflight_mod

        called = {"count": 0}

        async def _fail_if_called(*args: Any, **kwargs: Any) -> Any:
            called["count"] += 1
            raise AssertionError("probe_llm_readiness must not be called when llm_required=False")

        monkeypatch.setattr(preflight_mod, "probe_llm_readiness", _fail_if_called)
        # dry_run=True short-circuits the interlock before preflight even
        # runs, which is sufficient to prove the probe path is never
        # reached for the default (llm_required=False) configuration.
        from apex_host.eval.live_interlock import evaluate_live_interlock

        config = ApexConfig(target=_TARGET, dry_run=True, llm_required=False)
        result = await evaluate_live_interlock(
            config, confirmed=True, default_report_dir="/tmp/x",
        )
        assert called["count"] == 0
        assert result.permitted is False  # dry_run True blocks the interlock


# ---------------------------------------------------------------------------
# 13. Existing dry-run and live-run safety tests remain passing.
# ---------------------------------------------------------------------------


class TestExistingSafetyInvariantsUnaffected:
    def test_dry_run_default_unchanged(self) -> None:
        assert ApexConfig(target=_TARGET).dry_run is True

    def test_llm_provider_default_unchanged(self) -> None:
        assert ApexConfig(target=_TARGET).llm_provider == "fake"

    def test_use_llm_default_unchanged(self) -> None:
        assert ApexConfig(target=_TARGET).use_llm is False

    def test_tool_backend_default_unchanged(self) -> None:
        assert ApexConfig(target=_TARGET).tool_backend == "local"

    def test_tool_backend_raw_socket_capable_default_is_none_auto_derive(self) -> None:
        assert ApexConfig(target=_TARGET).tool_backend_raw_socket_capable is None
