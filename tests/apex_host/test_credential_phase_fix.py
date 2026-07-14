# test_credential_phase_fix.py
# Tests for credential-phase loop guard, LLM bypass, phase-skip, and service edges.
"""Acceptance tests for the credential-phase fixes.

Covers:
- CredentialPlanner loop guard: abandon after credential already recorded.
- CredentialPlanner LLM bypass: deterministic path taken when telnet+creds present.
- GlobalPlanner web-skip: no web phase when no HTTP service discovered.
- GlobalPlanner access_state trigger: access_state advances to priv_esc.
- AccessParser service edges: service→access_state edge emitted when port known.
"""
from __future__ import annotations


from memfabric.ids import new_id, now
from memfabric.types import (
    AbandonSignal,
    EvidenceBundle,
    Goal,
    Node,
    SubgraphView,
)

from apex_host.parsers.access_parser import AccessParser
from apex_host.planners.credential_planner import CredentialPlanner
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

_TARGET = "10.10.10.14"
_ANCHOR = f"host:{_TARGET}"


def _subgraph(*nodes: Node) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=[], depth=2)


def _empty_subgraph() -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=2)


def _telnet_service_node(port: str = "23") -> Node:
    return Node(
        id=f"service:{_TARGET}:{port}/tcp",
        type="service",
        props={"port": port, "proto": "tcp", "service": "telnet", "state": "open"},
        confidence=0.9,
        source="nmap",
        first_seen=now(),
        last_seen=now(),
    )


def _credential_node(username: str, target: str = _TARGET) -> Node:
    return Node(
        id=f"credential:{target}:{username}",
        type="credential",
        props={"username": username, "target": target, "secret_hint": "[redacted]"},
        confidence=0.9,
        source="telnet",
        first_seen=now(),
        last_seen=now(),
    )


def _access_state_node(username: str = "root") -> Node:
    return Node(
        id=f"access_state:{_TARGET}:{username}",
        type="access_state",
        props={"level": "user", "username": username, "target": _TARGET},
        confidence=0.85,
        source="telnet",
        first_seen=now(),
        last_seen=now(),
    )


def _http_service_node(port: str = "80") -> Node:
    return Node(
        id=f"service:{_TARGET}:{port}/tcp",
        type="service",
        props={"port": port, "proto": "tcp", "service": "http", "state": "open"},
        confidence=0.9,
        source="nmap",
        first_seen=now(),
        last_seen=now(),
    )


def _goal() -> Goal:
    return Goal(
        id=new_id(),
        description=f"validate access to {_TARGET}",
        phase="credential",
        anchor_node=_ANCHOR,
    )


def _evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _planner(
    *,
    usernames: list[str] | None = None,
    passwords: list[str] | None = None,
) -> CredentialPlanner:
    registry = ToolRegistry(allowed_tools=["nmap", "nc"])
    return CredentialPlanner(
        _TARGET, registry,
        username_candidates=usernames,
        password_candidates=passwords,
    )


# ---------------------------------------------------------------------------
# Loop guard: credential already recorded → AbandonSignal
# ---------------------------------------------------------------------------

class TestCredentialLoopGuard:
    async def test_abandons_after_credential_recorded_same_user(self) -> None:
        """If a credential node already exists for this user, abort — don't loop."""
        planner = _planner(usernames=["root"], passwords=[""])
        subgraph = _subgraph(_telnet_service_node(), _credential_node("root"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)
        assert "already" in result.reason.lower() or "recorded" in result.reason.lower()

    async def test_abandon_message_names_the_user(self) -> None:
        planner = _planner(usernames=["admin"], passwords=["pass"])
        subgraph = _subgraph(_telnet_service_node(), _credential_node("admin"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)
        assert "admin" in result.reason

    async def test_no_loop_guard_on_first_attempt(self) -> None:
        """First call with no prior credential node emits telnet_access normally."""
        planner = _planner(usernames=["root"], passwords=[""])
        subgraph = _subgraph(_telnet_service_node())  # no credential node
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0].params["tool"] == "telnet_access"

    async def test_loop_guard_ignores_different_target(self) -> None:
        """Credential node for a different target does not trigger the guard."""
        planner = _planner(usernames=["root"], passwords=[""])
        other_target_cred = Node(
            id="credential:192.168.1.1:root",
            type="credential",
            props={"username": "root", "target": "192.168.1.1", "secret_hint": "[redacted]"},
            confidence=0.9,
            source="telnet",
            first_seen=now(),
            last_seen=now(),
        )
        subgraph = _subgraph(_telnet_service_node(), other_target_cred)
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)  # emits normally

    async def test_loop_guard_ignores_different_username(self) -> None:
        """Credential node for a different user does not block the configured user."""
        planner = _planner(usernames=["root"], passwords=[""])
        subgraph = _subgraph(_telnet_service_node(), _credential_node("admin"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)  # root hasn't been tried yet

    async def test_empty_password_preserved_through_loop_guard(self) -> None:
        """Empty password is preserved when no prior attempt exists."""
        planner = _planner(usernames=["root"], passwords=[""])
        subgraph = _subgraph(_telnet_service_node())
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert result[0].params["password"] == ""

    async def test_no_credentials_abandons_with_telnet_cap(self) -> None:
        """telnet cap present but no credentials → AbandonSignal (unchanged behavior)."""
        planner = _planner()  # no credentials
        subgraph = _subgraph(_telnet_service_node())
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)
        assert "--username" in result.reason or "credentials" in result.reason.lower()


# ---------------------------------------------------------------------------
# LLM bypass: telnet+credentials → always deterministic
# ---------------------------------------------------------------------------

class TestLLMBypassForTelnet:
    """When CredentialPlanner has an engine but telnet+creds are available,
    the deterministic path is forced (never nc/python3 probes from the LLM)."""

    def _stub_llm_planner_that_would_emit_nc(self) -> object:
        """A stub ModelRouter whose planner_llm() returns a fake LLM that
        always outputs an nc probe — verifying it is never called is the test."""

        class _NcOutput:
            content = (
                '{"reasoning":"use nc","confidence":0.9,'
                '"selected_tasks":[{"tool":"nc","args":["-nv","10.10.10.14","23"],'
                '"parser":"banner","executor_domain":"credential",'
                '"target":"10.10.10.14","rationale":"probe port"}],'
                '"rejected_tasks":[],"stop_reason":null,"next_phase":null}'
            )

        class _FakeLLM:
            def invoke(self, messages: list) -> _NcOutput:
                return _NcOutput()

        class _StubRouter:
            def planner_llm(self) -> object:
                return _FakeLLM()

            def executor_llm(self) -> None:
                return None

            def parser_llm(self) -> None:
                return None

        return _StubRouter()

    async def test_bypass_emits_telnet_access_not_nc(self) -> None:
        """Even when the LLM would return nc probes, telnet+creds forces telnet_access."""
        registry = ToolRegistry(allowed_tools=["nmap", "nc", "curl"])
        router = self._stub_llm_planner_that_would_emit_nc()
        planner = CredentialPlanner(
            _TARGET, registry,
            username_candidates=["root"],
            password_candidates=[""],
            model_router=router,  # type: ignore[arg-type]
            allowed_tools=["nmap", "nc", "curl"],
        )
        subgraph = _subgraph(_telnet_service_node())
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "telnet_access"

    async def test_bypass_records_deterministic_decision(self) -> None:
        """Bypass path records a deterministic PlanDecision, not an LLM decision."""
        registry = ToolRegistry(allowed_tools=["nmap", "nc", "curl"])
        router = self._stub_llm_planner_that_would_emit_nc()
        planner = CredentialPlanner(
            _TARGET, registry,
            username_candidates=["root"],
            password_candidates=[""],
            model_router=router,  # type: ignore[arg-type]
            allowed_tools=["nmap", "nc", "curl"],
        )
        subgraph = _subgraph(_telnet_service_node())
        await planner.plan(_goal(), subgraph, _evidence())
        decision = planner.last_decision
        assert decision is not None
        assert decision.fallback_used is True
        assert decision.planner_model == "deterministic"

    async def test_no_bypass_without_telnet_cap(self) -> None:
        """When no telnet capability, the engine path is taken (not the bypass)."""
        registry = ToolRegistry(allowed_tools=["nmap", "nc", "curl"])
        call_count = {"n": 0}

        class _CountingRouter:
            def planner_llm(self) -> None:
                call_count["n"] += 1
                return None  # FakeModelRouter behavior: return None → fallback

            def executor_llm(self) -> None:
                return None

            def parser_llm(self) -> None:
                return None

        planner = CredentialPlanner(
            _TARGET, registry,
            username_candidates=["root"],
            password_candidates=[""],
            model_router=_CountingRouter(),  # type: ignore[arg-type]
            allowed_tools=["nmap", "nc", "curl"],
        )
        # No telnet cap in subgraph → engine should be consulted
        subgraph = _empty_subgraph()
        await planner.plan(_goal(), subgraph, _evidence())
        assert call_count["n"] >= 1


# ---------------------------------------------------------------------------
# GlobalPlanner: web-skip when no web services
# ---------------------------------------------------------------------------

class TestGlobalPlannerWebSkip:
    def _gp(self) -> GlobalPlanner:
        return GlobalPlanner(max_turns=20)

    def test_skips_web_when_no_web_capability(self) -> None:
        """Service nodes exist but no HTTP → go directly to credential."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service"},
            turn_count=0,
            has_web_capability=False,
        )
        assert phase == ApexPhase.credential

    def test_uses_web_when_web_capability_exists(self) -> None:
        """Service nodes with HTTP → web phase (existing behavior)."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service"},
            turn_count=0,
            has_web_capability=True,
        )
        assert phase == ApexPhase.web

    def test_default_has_web_capability_is_true(self) -> None:
        """Omitting has_web_capability defaults to the existing behavior (web phase)."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service"},
            turn_count=0,
        )
        assert phase == ApexPhase.web

    def test_web_skip_still_needs_host_and_service(self) -> None:
        """has_web_capability=False with no service → still recon."""
        phase = self._gp().decide_phase(
            node_types_seen={"host"},
            turn_count=0,
            has_web_capability=False,
        )
        assert phase == ApexPhase.recon

    def test_web_skip_advances_to_credential_not_done(self) -> None:
        """Skip-web should land in credential, not done."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service"},
            turn_count=0,
            has_web_capability=False,
        )
        assert phase != ApexPhase.done

    def test_budget_exhausted_web_still_advances_correctly(self) -> None:
        """Web budget exhaustion with has_web_capability=False: endpoint added but
        no web was ever run, so credential still selected (no auth_flow yet)."""
        gp = self._gp()
        # Simulate web budget spent (though we wouldn't normally spend it when
        # has_web_capability=False, budget force-advance adds endpoint anyway).
        for _ in range(gp._budgets.get("web", 5)):
            gp.record_turn(ApexPhase.web)
        phase = gp.decide_phase(
            node_types_seen={"host", "service"},
            turn_count=3,
            current_phase="web",
            has_web_capability=False,
        )
        # After budget exhaustion adds "endpoint", still check auth_flow/access_state.
        # Neither exists → credential.
        assert phase == ApexPhase.credential


# ---------------------------------------------------------------------------
# GlobalPlanner: access_state triggers priv_esc
# ---------------------------------------------------------------------------

class TestGlobalPlannerAccessStateTrigger:
    def _gp(self) -> GlobalPlanner:
        return GlobalPlanner(max_turns=20)

    def test_access_state_advances_to_priv_esc(self) -> None:
        """access_state in EKG triggers priv_esc advancement (successful login)."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "access_state"},
            turn_count=0,
            has_web_capability=False,
        )
        assert phase == ApexPhase.priv_esc

    def test_access_state_with_endpoint_advances_to_priv_esc(self) -> None:
        """access_state + endpoint → priv_esc (not stuck in credential)."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "endpoint", "access_state"},
            turn_count=0,
        )
        assert phase == ApexPhase.priv_esc

    def test_auth_flow_still_triggers_priv_esc(self) -> None:
        """Existing auth_flow trigger still works (backward-compatible)."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "endpoint", "auth_flow"},
            turn_count=0,
        )
        assert phase == ApexPhase.priv_esc

    def test_no_access_state_no_auth_flow_stays_credential(self) -> None:
        """Without access_state or auth_flow, we stay in credential."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "endpoint"},
            turn_count=0,
        )
        assert phase == ApexPhase.credential

    def test_access_state_with_no_endpoint_still_advances(self) -> None:
        """access_state alone (telnet-only, no web endpoint) → priv_esc."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "access_state"},
            turn_count=0,
            has_web_capability=False,
        )
        assert phase == ApexPhase.priv_esc


# ---------------------------------------------------------------------------
# AccessParser: service→access_state edge when port provided
# ---------------------------------------------------------------------------

class TestAccessParserServiceEdge:
    _PARSER = AccessParser()

    _SUCCESS = "login: root\r\nPassword:\r\nroot@host:~# "
    _FAILURE = "Login incorrect"

    def test_service_edge_emitted_on_success_with_port(self) -> None:
        # Two edges from service: 'tested' (svc→cred) + 'grants' (svc→access_state).
        obs = self._PARSER.parse_text(
            self._SUCCESS, target=_TARGET, username="root", port="23"
        )
        service_edges = [e for e in obs.edge_deltas if e.from_id.startswith("service:")]
        assert len(service_edges) == 2

    def test_service_edge_has_correct_service_id(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS, target=_TARGET, username="root", port="23", proto="tcp"
        )
        service_edges = [e for e in obs.edge_deltas if e.from_id.startswith("service:")]
        assert all(e.from_id == f"service:{_TARGET}:23/tcp" for e in service_edges)

    def test_service_edge_type_is_grants(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS, target=_TARGET, username="root", port="23"
        )
        grants_from_service = [
            e for e in obs.edge_deltas
            if e.from_id.startswith("service:") and e.type == "grants"
        ]
        assert len(grants_from_service) == 1

    def test_service_edge_points_to_access_state(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS, target=_TARGET, username="root", port="23"
        )
        grants_from_service = [
            e for e in obs.edge_deltas
            if e.from_id.startswith("service:") and e.type == "grants"
        ]
        access_ids = {n.id for n in obs.node_deltas if n.type == "access_state"}
        assert grants_from_service[0].to_id in access_ids

    def test_no_service_edge_without_port(self) -> None:
        """Existing callers that omit port still get no extra edge."""
        obs = self._PARSER.parse_text(
            self._SUCCESS, target=_TARGET, username="root"
        )
        service_edges = [e for e in obs.edge_deltas if e.from_id.startswith("service:")]
        assert len(service_edges) == 0

    def test_no_service_edge_on_failure(self) -> None:
        """Service edge only emitted on successful login."""
        obs = self._PARSER.parse_text(
            self._FAILURE, target=_TARGET, username="root", port="23"
        )
        service_edges = [e for e in obs.edge_deltas if e.from_id.startswith("service:")]
        assert len(service_edges) == 0

    def test_credential_to_access_state_edge_still_emitted(self) -> None:
        """The existing credential→access_state edge is still present."""
        obs = self._PARSER.parse_text(
            self._SUCCESS, target=_TARGET, username="root", port="23"
        )
        grants_edges = [e for e in obs.edge_deltas if e.type == "grants"]
        # Both credential→access_state and service→access_state
        assert len(grants_edges) == 2

    def test_non_default_proto_used_in_service_id(self) -> None:
        obs = self._PARSER.parse_text(
            self._SUCCESS, target=_TARGET, username="root", port="23", proto="udp"
        )
        service_edges = [e for e in obs.edge_deltas if e.from_id.startswith("service:")]
        assert service_edges[0].from_id == f"service:{_TARGET}:23/udp"
