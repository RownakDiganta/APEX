# test_credential_planner_multiprotocol.py
# Tests for CredentialPlanner's Phase 12B SSH/FTP support: deterministic ordering, per-protocol duplicate guard, and credential-required abandon paths.
"""Phase 12B tests for apex_host/planners/credential_planner.py.

Covers everything test_credential_phase_fix.py's original Telnet-only test
suite does not: SSH/FTP task selection, deterministic cross-protocol
ordering, per-protocol duplicate guards (a failed SSH attempt must never
block an unrelated FTP attempt), and the GlobalPlanner-level
auth_flow-vs-access_state distinction from Phase 12A, re-verified in the
context of SSH/FTP capabilities existing alongside a web auth_flow.
"""
from __future__ import annotations

from memfabric.ids import now
from memfabric.types import AbandonSignal, EvidenceBundle, Goal, Node, SubgraphView

from apex_host.planners.credential_planner import CredentialPlanner
from apex_host.planners.global_planner import GlobalPlanner
from apex_host.tools.registry import ToolRegistry
from apex_host.types import ApexPhase

_TARGET = "10.10.10.60"
_ANCHOR = f"host:{_TARGET}"


def _subgraph(*nodes: Node) -> SubgraphView:
    return SubgraphView(anchor=_ANCHOR, nodes=list(nodes), edges=[], depth=2)


def _service_node(port: str, service: str) -> Node:
    return Node(
        id=f"service:{_TARGET}:{port}/tcp", type="service",
        props={"port": port, "proto": "tcp", "service": service, "state": "open"},
        confidence=0.9, source="nmap", first_seen=now(), last_seen=now(),
    )


def _credential_node(username: str, protocol: str) -> Node:
    return Node(
        id=f"credential:{_TARGET}:{username}:{protocol}", type="credential",
        props={"username": username, "target": _TARGET, "secret_hint": "[redacted]", "protocol": protocol},
        confidence=0.9, source=protocol, first_seen=now(), last_seen=now(),
    )


def _goal() -> Goal:
    return Goal(id="goal-1", description=f"validate access to {_TARGET}", phase="credential", anchor_node=_ANCHOR)


def _evidence() -> EvidenceBundle:
    return EvidenceBundle(query="", entries=[], subgraph=None, tiers_queried=[])


def _planner(usernames: list[str] | None = None, passwords: list[str] | None = None) -> CredentialPlanner:
    registry = ToolRegistry(allowed_tools=["nmap", "nc", "curl"])
    return CredentialPlanner(_TARGET, registry, username_candidates=usernames, password_candidates=passwords)


# ---------------------------------------------------------------------------
# 1 / 2 / 3. Each protocol produces its dedicated task
# ---------------------------------------------------------------------------

class TestPerProtocolTaskSelection:
    async def test_ssh_only_produces_ssh_access_task(self) -> None:
        planner = _planner(usernames=["root"], passwords=["hunter2"])
        subgraph = _subgraph(_service_node("22", "ssh"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list) and len(result) == 1
        assert result[0].params["tool"] == "ssh_access"
        assert result[0].params["port"] == "22"

    async def test_ftp_only_produces_ftp_access_task(self) -> None:
        planner = _planner(usernames=["anonymous"], passwords=["guest@"])
        subgraph = _subgraph(_service_node("21", "ftp"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list) and len(result) == 1
        assert result[0].params["tool"] == "ftp_access"
        assert result[0].params["port"] == "21"

    async def test_telnet_only_still_produces_telnet_access_task(self) -> None:
        planner = _planner(usernames=["root"], passwords=[""])
        subgraph = _subgraph(_service_node("23", "telnet"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list) and len(result) == 1
        assert result[0].params["tool"] == "telnet_access"
        assert result[0].params["port"] == "23"


# ---------------------------------------------------------------------------
# 4. Deterministic ordering when multiple protocols exist
# ---------------------------------------------------------------------------

class TestDeterministicOrdering:
    async def test_telnet_wins_over_ssh_and_ftp(self) -> None:
        planner = _planner(usernames=["root"], passwords=["x"])
        subgraph = _subgraph(
            _service_node("21", "ftp"), _service_node("22", "ssh"), _service_node("23", "telnet"),
        )
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "telnet_access"

    async def test_ssh_wins_over_ftp_when_no_telnet(self) -> None:
        planner = _planner(usernames=["root"], passwords=["x"])
        subgraph = _subgraph(_service_node("21", "ftp"), _service_node("22", "ssh"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "ssh_access"

    async def test_ordering_is_stable_across_repeated_calls(self) -> None:
        """No randomness: the same subgraph always yields the same protocol choice."""
        planner = _planner(usernames=["root"], passwords=["x"])
        subgraph = _subgraph(_service_node("21", "ftp"), _service_node("22", "ssh"))
        results = [
            (await planner.plan(_goal(), subgraph, _evidence()))[0].params["tool"]  # type: ignore[index]
            for _ in range(5)
        ]
        assert results == ["ssh_access"] * 5

    async def test_lowest_port_wins_within_same_protocol(self) -> None:
        """Two SSH services on different ports -> the lower port is chosen."""
        planner = _planner(usernames=["root"], passwords=["x"])
        svc_high = Node(
            id=f"service:{_TARGET}:2222/tcp", type="service",
            props={"port": "2222", "proto": "tcp", "service": "ssh", "state": "open"},
            confidence=0.9, source="nmap", first_seen=now(), last_seen=now(),
        )
        subgraph = _subgraph(_service_node("22", "ssh"), svc_high)
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert result[0].params["port"] == "22"


# ---------------------------------------------------------------------------
# 5. Unrelated failed protocol does not block another protocol
# ---------------------------------------------------------------------------

class TestCrossProtocolIsolation:
    async def test_failed_ssh_does_not_block_ftp(self) -> None:
        planner = _planner(usernames=["root"], passwords=["x"])
        subgraph = _subgraph(
            _service_node("21", "ftp"), _service_node("22", "ssh"),
            _credential_node("root", "ssh"),  # SSH already attempted (failed or succeeded)
        )
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "ftp_access"

    async def test_failed_ftp_does_not_block_ssh(self) -> None:
        planner = _planner(usernames=["root"], passwords=["x"])
        subgraph = _subgraph(
            _service_node("22", "ssh"),
            _credential_node("root", "ftp"),  # unrelated protocol's own attempt
        )
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "ssh_access"

    async def test_telnet_attempt_does_not_block_ssh(self) -> None:
        planner = _planner(usernames=["root"], passwords=["x"])
        subgraph = _subgraph(
            _service_node("22", "ssh"),
            _credential_node("root", "telnet_access"),  # real pipeline's telnet protocol value
        )
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, list)
        assert result[0].params["tool"] == "ssh_access"


# ---------------------------------------------------------------------------
# 6. Duplicate same-protocol attempt is blocked
# ---------------------------------------------------------------------------

class TestSameProtocolDuplicateBlocked:
    async def test_ssh_already_attempted_abandons(self) -> None:
        planner = _planner(usernames=["root"], passwords=["x"])
        subgraph = _subgraph(_service_node("22", "ssh"), _credential_node("root", "ssh"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)
        assert "root" in result.reason
        assert "already" in result.reason.lower() or "recorded" in result.reason.lower()

    async def test_ftp_already_attempted_abandons(self) -> None:
        planner = _planner(usernames=["anonymous"], passwords=["x"])
        subgraph = _subgraph(_service_node("21", "ftp"), _credential_node("anonymous", "ftp"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)

    async def test_all_protocols_attempted_abandons(self) -> None:
        planner = _planner(usernames=["root"], passwords=["x"])
        subgraph = _subgraph(
            _service_node("22", "ssh"), _service_node("21", "ftp"),
            _credential_node("root", "ssh"), _credential_node("root", "ftp"),
        )
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)
        assert "every" in result.reason.lower() or "already" in result.reason.lower()


# ---------------------------------------------------------------------------
# 7. No credentials produces AbandonSignal
# ---------------------------------------------------------------------------

class TestNoCredentials:
    async def test_ssh_cap_no_credentials_abandons(self) -> None:
        planner = _planner()
        subgraph = _subgraph(_service_node("22", "ssh"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)
        assert "--username" in result.reason or "credentials" in result.reason.lower()

    async def test_ftp_cap_no_credentials_abandons(self) -> None:
        planner = _planner()
        subgraph = _subgraph(_service_node("21", "ftp"))
        result = await planner.plan(_goal(), subgraph, _evidence())
        assert isinstance(result, AbandonSignal)
        assert "credentials" in result.reason.lower()


# ---------------------------------------------------------------------------
# 8 / 9. GlobalPlanner: auth_flow alone stays in credential; only access_state advances
# ---------------------------------------------------------------------------

class TestGlobalPlannerGateWithMultiProtocolCapabilities:
    def _gp(self) -> GlobalPlanner:
        return GlobalPlanner(max_turns=20)

    def test_auth_flow_with_ssh_capability_stays_credential(self) -> None:
        """A web login page (auth_flow) discovered alongside an open SSH
        port must not skip credential validation for either protocol."""
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "endpoint", "auth_flow"}, turn_count=0,
        )
        assert phase == ApexPhase.credential

    def test_access_state_from_ssh_advances_to_priv_esc(self) -> None:
        phase = self._gp().decide_phase(
            node_types_seen={"host", "service", "access_state"}, turn_count=0, has_web_capability=False,
        )
        assert phase == ApexPhase.priv_esc
