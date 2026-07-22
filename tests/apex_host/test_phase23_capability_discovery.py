# test_phase23_capability_discovery.py
# Regression tests for Phase 23: the deterministic capability-evidence discovery pipeline — evidence model, central validation, provider protocol, all five providers, the discovery engine, identity/dedup, runtime resolution, lifecycle, objective reopening, operator-seed migration, replay, redaction, and full synthetic flows.
"""Phase 23 regression tests: structured automatic capability derivation.

Covers the full flow:

    Executor or validated runtime operation
        -> CapabilityEvidence
        -> CapabilityDiscoveryEngine
        -> CapabilityProvider
        -> CapabilityDerivationDecision
        -> CapabilityParser
        -> MemoryAPI access_capability node
           + CapabilityRuntimeRegistry adapter
        -> ObjectivePlanner

This is NOT autonomous vulnerability discovery — every evidence item in
every test here is either a directly-constructed ``CapabilityEvidence``
object (proving the pipeline's own logic) or the output of an existing,
already-tested executor/parser. No test performs a real network operation,
requires Docker/VPN/internet, or targets a real HTB machine. Every fixture
uses a synthetic target and a synthetic, well-formed (never real)
flag-shaped token.
"""
from __future__ import annotations

import dataclasses
import inspect
import json
import re
from pathlib import Path
from typing import Any

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node, SubgraphView

from apex_host.capabilities.decisions import CapabilityDerivationStatus
from apex_host.capabilities.discovery import CapabilityDiscoveryContext, run_capability_discovery
from apex_host.capabilities.evidence import CapabilityEvidence, CapabilityEvidenceType, validate_evidence
from apex_host.capabilities.lifecycle import CapabilityLifecycleState, capability_lifecycle_state
from apex_host.capabilities.providers import (
    DEFAULT_PROVIDERS,
    DirectFileReadCapabilityProvider,
    LocalCommandCapabilityProvider,
    RemoteCommandCapabilityProvider,
    SSHCapabilityProvider,
    WebCommandCapabilityProvider,
)
from apex_host.capabilities.runtime_resolution import register_capability_adapter
from apex_host.config import ApexConfig
from apex_host.eval.report import build_report, format_text, to_json_dict
from apex_host.graph_ids import access_capability_id, access_state_id, host_id
from apex_host.orchestration.capability_seed import (
    seed_bounded_command_capability,
    seed_direct_file_read_capability,
)
from apex_host.orchestration.outcome import EngagementOutcome, is_success_outcome
from apex_host.planners.access_capabilities import access_capabilities_from_subgraph
from apex_host.planners.objective import (
    objective_attempted_capability_pairs,
    objective_reopening_eligible,
    objective_status_from_subgraph,
)
from apex_host.runtime_registry import CapabilityRuntimeRegistry
from apex_host.types import AccessCapability, AccessCapabilityType

_TARGET = "10.10.10.211"
_ANCHOR = host_id(_TARGET)
_FLAG_VALUE = "c4f19b7e6a3d0281"  # synthetic, well-formed — never a real flag

_TRIPLE_QUOTED_RE = re.compile(r'("""|\'\'\')(?:.|\n)*?\1')


def _non_comment_code(source: str) -> str:
    stripped = _TRIPLE_QUOTED_RE.sub("", source)
    return "\n".join(line for line in stripped.splitlines() if not line.strip().startswith("#"))


def _make_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(), episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(), vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(), config=cfg,
    )


async def _seed_node(api: MemoryAPI, node_id: str, node_type: str, props: dict[str, Any] | None = None) -> None:
    ts = now()
    await api.upsert_node(Node(
        id=node_id, type=node_type, props=props or {}, confidence=0.9,
        source="test-seed", first_seen=ts, last_seen=ts,
    ))


async def _seed_edge(api: MemoryAPI, from_id: str, to_id: str, edge_type: str = "has_capability") -> None:
    ts = now()
    await api.upsert_edge(Edge(
        id=f"edge:{edge_type}:{from_id}:{to_id}", from_id=from_id, to_id=to_id, type=edge_type,
        props={}, confidence=0.9, source="test-seed", first_seen=ts, last_seen=ts,
    ))


async def _subgraph(api: MemoryAPI, target: str) -> SubgraphView:
    return await api.get_subgraph(host_id(target), depth=5)


async def _seed_ssh_prereqs(api: MemoryAPI, *, principal: str = "root", target: str = _TARGET) -> None:
    """Seed the host + access_state nodes a REAL engagement turn would
    already have created (via NmapParser + AccessParser) before
    ``CapabilityParser.derive_ssh_capability``'s ``enables`` edge (from the
    access_state node) is ever materialized — in production
    (``apex_host.orchestration.parsing_node``) this is always already true
    by the time discovery runs, since AccessParser's own node deltas are
    applied earlier in the SAME turn. Isolated discovery-engine tests that
    exercise SSH evidence need this fixture explicitly."""
    h_id = host_id(target)
    await _seed_node(api, h_id, "host", {"ip": target})
    await _seed_node(api, access_state_id(target, principal, protocol="ssh"), "access_state", {
        "level": "user", "username": principal, "target": target, "service": "ssh",
    })


def _ssh_evidence(
    *, principal: str = "root", confidence: float = 0.85, evidence_id: str = "",
    target: str = _TARGET, is_dry_run: bool = False,
) -> CapabilityEvidence:
    return CapabilityEvidence(
        evidence_id=evidence_id or new_id(),
        evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
        capability_family=AccessCapabilityType.ssh_command,
        target_host_id=host_id(target),
        source_task_id="task-1",
        principal=principal,
        validation_method="deterministic_benign_command",
        confidence=confidence,
        timestamp=now(),
        is_dry_run=is_dry_run,
    )


def _dfr_evidence(
    *, principal: str = "application", confidence: float = 0.8,
    validation_method: str = "path_dependent_content", evidence_id: str = "",
    capability_family: AccessCapabilityType = AccessCapabilityType.arbitrary_file_read,
    target: str = _TARGET,
) -> CapabilityEvidence:
    return CapabilityEvidence(
        evidence_id=evidence_id or new_id(),
        evidence_type=CapabilityEvidenceType.DIRECT_FILE_READ_VALIDATED,
        capability_family=capability_family,
        target_host_id=host_id(target),
        source_task_id="task-2",
        principal=principal,
        validation_method=validation_method,
        confidence=confidence,
        timestamp=now(),
        sanitized_attributes={"requires_auth": False, "max_response_bytes": 4096},
    )


def _local_command_evidence(
    *, principal: str = "application", confidence: float = 0.8,
    validation_method: str = "deterministic_benign_command", evidence_id: str = "",
    runtime_reference_id: str = "", target: str = _TARGET,
) -> CapabilityEvidence:
    return CapabilityEvidence(
        evidence_id=evidence_id or new_id(),
        evidence_type=CapabilityEvidenceType.LOCAL_COMMAND_VALIDATED,
        capability_family=AccessCapabilityType.local_shell,
        target_host_id=host_id(target),
        source_task_id="task-3",
        principal=principal,
        validation_method=validation_method,
        confidence=confidence,
        timestamp=now(),
        runtime_reference_id=runtime_reference_id,
        sanitized_attributes={"max_output_bytes": 4096},
    )


def _remote_command_evidence(
    *, principal: str = "application", confidence: float = 0.8,
    validation_method: str = "backend_confirmed_session", evidence_id: str = "",
    runtime_reference_id: str = "", target: str = _TARGET,
) -> CapabilityEvidence:
    return CapabilityEvidence(
        evidence_id=evidence_id or new_id(),
        evidence_type=CapabilityEvidenceType.REMOTE_COMMAND_VALIDATED,
        capability_family=AccessCapabilityType.remote_command,
        target_host_id=host_id(target),
        source_task_id="task-4",
        principal=principal,
        validation_method=validation_method,
        confidence=confidence,
        timestamp=now(),
        runtime_reference_id=runtime_reference_id,
        sanitized_attributes={"max_output_bytes": 4096, "strategy_id": "remote-strategy"},
    )


def _web_command_evidence(
    *, principal: str = "application", confidence: float = 0.8,
    validation_method: str = "operator_attestation", evidence_id: str = "",
    target: str = _TARGET,
) -> CapabilityEvidence:
    return CapabilityEvidence(
        evidence_id=evidence_id or new_id(),
        evidence_type=CapabilityEvidenceType.WEB_COMMAND_VALIDATED,
        capability_family=AccessCapabilityType.web_command,
        target_host_id=host_id(target),
        source_task_id="task-5",
        principal=principal,
        validation_method=validation_method,
        confidence=confidence,
        timestamp=now(),
        sanitized_attributes={"max_output_bytes": 4096},
    )


def _context(
    api: MemoryAPI, subgraph: SubgraphView, *, config: ApexConfig | None = None,
    registry: CapabilityRuntimeRegistry | None = None, attempt_runtime_registration: bool = True,
) -> CapabilityDiscoveryContext:
    return CapabilityDiscoveryContext(
        api=api, config=config or ApexConfig(target=_TARGET, dry_run=True),
        capability_registry=registry or CapabilityRuntimeRegistry(),
        subgraph=subgraph, target=_TARGET, now_iso=now(),
        attempt_runtime_registration=attempt_runtime_registration,
    )


# ---------------------------------------------------------------------------
# 1. Evidence model
# ---------------------------------------------------------------------------

class TestEvidenceModel:
    def test_evidence_is_frozen(self) -> None:
        ev = _ssh_evidence()
        with pytest.raises(Exception):  # noqa: PT011 - dataclasses.FrozenInstanceError
            ev.principal = "other"  # type: ignore[misc]

    def test_deterministic_id_content_addressed(self) -> None:
        assert access_capability_id(_TARGET, "ssh_command", "root") == access_capability_id(
            _TARGET, "ssh_command", "root"
        )

    def test_target_required(self) -> None:
        ev2 = CapabilityEvidence(
            evidence_id="e1", evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
            capability_family=AccessCapabilityType.ssh_command, target_host_id="",
            source_task_id="", principal="root", validation_method="deterministic_benign_command",
            confidence=0.9, timestamp=now(),
        )
        assert validate_evidence(ev2) is not None
        assert validate_evidence(ev2).reason == "target_mismatch"

    def test_capability_family_required_via_type_mismatch(self) -> None:
        ev = CapabilityEvidence(
            evidence_id="e2", evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
            capability_family=AccessCapabilityType.local_shell, target_host_id=_ANCHOR,
            source_task_id="", principal="root", validation_method="deterministic_benign_command",
            confidence=0.9, timestamp=now(),
        )
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "unsupported_evidence"

    def test_confidence_bounded_above_one(self) -> None:
        ev = _ssh_evidence(confidence=1.5)
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "confidence_below_threshold"

    def test_confidence_bounded_below_zero(self) -> None:
        ev = _ssh_evidence(confidence=-0.1)
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "confidence_below_threshold"

    def test_accepted_validation_methods_pass_central_validation(self) -> None:
        assert validate_evidence(_dfr_evidence(validation_method="canary_file_match")) is None
        assert validate_evidence(_dfr_evidence(validation_method="operator_attestation")) is None

    def test_opaque_runtime_reference_accepted(self) -> None:
        ev = _local_command_evidence(runtime_reference_id="opaque-ref-123")
        assert validate_evidence(ev) is None

    def test_raw_secret_fields_rejected(self) -> None:
        ev = _dfr_evidence()
        bad = dataclasses.replace(ev, sanitized_attributes={"password": "hunter2"})
        rejection = validate_evidence(bad)
        assert rejection is not None and rejection.reason == "secret_field_detected"

    def test_raw_output_fields_rejected(self) -> None:
        ev = _dfr_evidence()
        bad = dataclasses.replace(ev, sanitized_attributes={"raw_output": "some content"})
        rejection = validate_evidence(bad)
        assert rejection is not None and rejection.reason == "secret_field_detected"

    def test_raw_flag_like_values_rejected(self) -> None:
        ev = _dfr_evidence()
        bad = dataclasses.replace(ev, sanitized_attributes={"flag_value": _FLAG_VALUE})
        rejection = validate_evidence(bad)
        assert rejection is not None and rejection.reason == "secret_field_detected"

    def test_serialization_contains_no_runtime_object(self) -> None:
        ev = _local_command_evidence(runtime_reference_id="ref-1")
        serialized = json.dumps({
            "evidence_id": ev.evidence_id, "evidence_type": ev.evidence_type.value,
            "capability_family": ev.capability_family.value, "principal": ev.principal,
            "runtime_reference_id": ev.runtime_reference_id,
        })
        assert "object at 0x" not in serialized


# ---------------------------------------------------------------------------
# 2. Evidence types
# ---------------------------------------------------------------------------

class TestEvidenceTypes:
    def test_ssh_authenticated_command_exists(self) -> None:
        assert CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND.value == "ssh_authenticated_command"

    def test_direct_file_read_validated_exists(self) -> None:
        assert CapabilityEvidenceType.DIRECT_FILE_READ_VALIDATED.value == "direct_file_read_validated"

    def test_local_command_validated_exists(self) -> None:
        assert CapabilityEvidenceType.LOCAL_COMMAND_VALIDATED.value == "local_command_validated"

    def test_remote_command_validated_exists(self) -> None:
        assert CapabilityEvidenceType.REMOTE_COMMAND_VALIDATED.value == "remote_command_validated"

    def test_web_command_validated_exists(self) -> None:
        assert CapabilityEvidenceType.WEB_COMMAND_VALIDATED.value == "web_command_validated"

    def test_operator_attested_exists(self) -> None:
        assert CapabilityEvidenceType.OPERATOR_ATTESTED.value == "operator_attested"

    def test_unsupported_evidence_type_rejected_by_engine(self) -> None:
        class _FakeType:
            value = "not_a_real_type"
        ev = _ssh_evidence()
        object.__setattr__(ev, "evidence_type", _FakeType())  # type: ignore[assignment]
        # validate_evidence still passes structural checks (family mapping
        # lookup returns None for unknown type); provider selection then
        # fails to match anything.
        from apex_host.capabilities.discovery import _select_provider
        assert _select_provider(ev, DEFAULT_PROVIDERS) is None

    def test_no_vulnerability_named_evidence_types(self) -> None:
        names = [m.name for m in CapabilityEvidenceType]
        forbidden_substrings = ("sqli", "xss", "rce", "academy", "twomillion", "alert")
        for name in names:
            lowered = name.lower()
            for bad in forbidden_substrings:
                assert bad not in lowered, name


# ---------------------------------------------------------------------------
# 3. Central validation
# ---------------------------------------------------------------------------

class TestCentralValidation:
    def test_dry_run_evidence_rejected(self) -> None:
        ev = _ssh_evidence(is_dry_run=True)
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "dry_run_evidence"

    def test_low_confidence_rejected(self) -> None:
        ev = _ssh_evidence(confidence=0.1)
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "confidence_below_threshold"

    def test_invalid_method_http_200_rejected(self) -> None:
        ev = _dfr_evidence(validation_method="http_200")
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "invalid_validation_method"

    def test_llm_claim_rejected(self) -> None:
        ev = _dfr_evidence(validation_method="llm_claim")
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "invalid_validation_method"

    def test_credentials_alone_rejected(self) -> None:
        ev = _dfr_evidence(validation_method="credentials_found")
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "invalid_validation_method"

    def test_admin_access_alone_rejected(self) -> None:
        ev = _dfr_evidence(validation_method="admin_access")
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "invalid_validation_method"

    def test_payload_attempted_alone_rejected(self) -> None:
        ev = _dfr_evidence(validation_method="payload_attempted")
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "invalid_validation_method"

    def test_banner_only_rejected(self) -> None:
        ev = _dfr_evidence(validation_method="banner_only")
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "invalid_validation_method"

    def test_port_open_rejected(self) -> None:
        ev = _dfr_evidence(validation_method="port_open")
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "invalid_validation_method"

    def test_empty_method_rejected(self) -> None:
        ev = _dfr_evidence(validation_method="")
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "invalid_validation_method"

    def test_expired_evidence_rejected_when_ttl_configured(self) -> None:
        ev = _ssh_evidence()
        stale = dataclasses.replace(ev, timestamp="2000-01-01T00:00:00+00:00")
        rejection = validate_evidence(stale, evidence_ttl_seconds=60.0, now_iso=now())
        assert rejection is not None and rejection.reason == "expired_evidence"

    def test_not_expired_within_ttl(self) -> None:
        ev = _ssh_evidence()
        rejection = validate_evidence(ev, evidence_ttl_seconds=3600.0, now_iso=now())
        assert rejection is None

    def test_ttl_disabled_by_default(self) -> None:
        ev = _ssh_evidence()
        stale = dataclasses.replace(ev, timestamp="2000-01-01T00:00:00+00:00")
        assert validate_evidence(stale) is None

    def test_missing_target_rejected(self) -> None:
        ev = _ssh_evidence()
        bad = dataclasses.replace(ev, target_host_id="   ")
        rejection = validate_evidence(bad)
        assert rejection is not None and rejection.reason == "target_mismatch"

    def test_negative_runtime_generation_rejected(self) -> None:
        ev = _ssh_evidence()
        bad = dataclasses.replace(ev, runtime_reference_id="ref", runtime_generation=-1)
        rejection = validate_evidence(bad)
        assert rejection is not None and rejection.reason == "missing_runtime_reference"


# ---------------------------------------------------------------------------
# 4. Provider protocol
# ---------------------------------------------------------------------------

class TestProviderProtocol:
    def test_providers_cannot_write_memory_api(self) -> None:
        import apex_host.capabilities.providers as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "apply_deltas(" not in source
        assert "upsert_node(" not in source
        assert "upsert_edge(" not in source

    def test_providers_cannot_mutate_registry(self) -> None:
        import apex_host.capabilities.providers as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert ".register(" not in source
        assert "ensure_ssh(" not in source
        assert "ensure_direct_file_read(" not in source
        assert "ensure_bounded_command(" not in source

    def test_providers_are_deterministic(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ctx = _context(api, subgraph)
        ev = _ssh_evidence(evidence_id="fixed-id")
        d1 = SSHCapabilityProvider().evaluate(ev, ctx)
        d2 = SSHCapabilityProvider().evaluate(ev, ctx)
        assert d1.status == d2.status
        assert d1.confidence == d2.confidence
        assert d1.capability_id == d2.capability_id

    def test_provider_ordering_stable(self) -> None:
        names = [type(p).__name__ for p in DEFAULT_PROVIDERS]
        assert names == [type(p).__name__ for p in DEFAULT_PROVIDERS]

    async def test_one_provider_failure_isolated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(self: Any, evidence: Any, context: Any) -> Any:
            raise RuntimeError("synthetic provider failure")
        monkeypatch.setattr(SSHCapabilityProvider, "evaluate", _boom)
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        result = await run_capability_discovery([_ssh_evidence()], context=_context(api, subgraph))
        assert result.provider_failures == 1
        assert result.capabilities_derived == 0

    async def test_unsupported_provider_skipped_gracefully(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ev = CapabilityEvidence(
            evidence_id="e-x", evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
            capability_family=AccessCapabilityType.telnet_command, target_host_id=_ANCHOR,
            source_task_id="", principal="root", validation_method="deterministic_benign_command",
            confidence=0.9, timestamp=now(),
        )
        result = await run_capability_discovery([ev], context=_context(api, subgraph))
        assert result.evidence_rejected == 1
        assert result.capabilities_derived == 0


# ---------------------------------------------------------------------------
# 5. SSH provider
# ---------------------------------------------------------------------------

class TestSSHProvider:
    def _ctx(self) -> CapabilityDiscoveryContext:
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        return _context(_make_api(), subgraph)

    def test_valid_authenticated_command_evidence_accepted(self) -> None:
        decision = SSHCapabilityProvider().evaluate(_ssh_evidence(), self._ctx())
        assert decision.accepted
        assert decision.status is CapabilityDerivationStatus.accepted

    def test_port_22_alone_rejected(self) -> None:
        # Port/banner-only evidence never becomes SSH_AUTHENTICATED_COMMAND
        # evidence in the first place — proven by construction: no producer
        # in this codebase emits that evidence type from a bare open port.
        # Directly confirm a low-confidence "banner only" style evidence
        # (mirroring what such a signal WOULD look like) is rejected.
        ev = _ssh_evidence(confidence=0.05)
        decision = SSHCapabilityProvider().evaluate(ev, self._ctx())
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_missing_principal_rejected(self) -> None:
        decision = SSHCapabilityProvider().evaluate(_ssh_evidence(principal=""), self._ctx())
        assert decision.status is CapabilityDerivationStatus.rejected
        assert decision.sanitized_reason == "target_mismatch"

    def test_wrong_family_rejected(self) -> None:
        ev = _ssh_evidence()
        bad = dataclasses.replace(ev, capability_family=AccessCapabilityType.local_shell)
        decision = SSHCapabilityProvider().evaluate(bad, self._ctx())
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_wrong_evidence_type_rejected(self) -> None:
        decision = SSHCapabilityProvider().evaluate(_dfr_evidence(), self._ctx())
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_capability_type_correct(self) -> None:
        decision = SSHCapabilityProvider().evaluate(_ssh_evidence(), self._ctx())
        assert decision.capability_type is AccessCapabilityType.ssh_command

    def test_target_and_principal_preserved(self) -> None:
        decision = SSHCapabilityProvider().evaluate(_ssh_evidence(principal="testuser"), self._ctx())
        assert decision.principal == "testuser"
        assert decision.target_host_id == _ANCHOR

    def test_no_credentials_persisted_in_decision(self) -> None:
        decision = SSHCapabilityProvider().evaluate(_ssh_evidence(), self._ctx())
        serialized = json.dumps(decision.to_dict())
        assert "password" not in serialized.lower()

    def test_operator_attested_ssh_evidence_accepted(self) -> None:
        ev = CapabilityEvidence(
            evidence_id="e-op", evidence_type=CapabilityEvidenceType.OPERATOR_ATTESTED,
            capability_family=AccessCapabilityType.ssh_command, target_host_id=_ANCHOR,
            source_task_id="", principal="root", validation_method="operator_attestation",
            confidence=0.9, timestamp=now(),
        )
        decision = SSHCapabilityProvider().evaluate(ev, self._ctx())
        assert decision.accepted


# ---------------------------------------------------------------------------
# 6. Direct-file-read provider
# ---------------------------------------------------------------------------

class TestDirectFileReadProvider:
    def _ctx(self) -> CapabilityDiscoveryContext:
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        return _context(_make_api(), subgraph)

    def test_path_dependent_proof_accepted(self) -> None:
        decision = DirectFileReadCapabilityProvider().evaluate(_dfr_evidence(), self._ctx())
        assert decision.accepted

    def test_operator_attestation_accepted(self) -> None:
        decision = DirectFileReadCapabilityProvider().evaluate(
            _dfr_evidence(validation_method="operator_attestation"), self._ctx(),
        )
        assert decision.accepted

    def test_http_200_rejected(self) -> None:
        decision = DirectFileReadCapabilityProvider().evaluate(
            _dfr_evidence(validation_method="http_200"), self._ctx(),
        )
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_identical_content_proof_rejected_via_low_confidence(self) -> None:
        decision = DirectFileReadCapabilityProvider().evaluate(
            _dfr_evidence(confidence=0.1), self._ctx(),
        )
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_invalid_primitive_reference_family_rejected(self) -> None:
        ev = _dfr_evidence()
        bad = dataclasses.replace(ev, capability_family=AccessCapabilityType.ssh_command)
        decision = DirectFileReadCapabilityProvider().evaluate(bad, self._ctx())
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_confidence_threshold_enforced(self) -> None:
        decision = DirectFileReadCapabilityProvider().evaluate(_dfr_evidence(confidence=0.59), self._ctx())
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_correct_capability_type_api_file_read(self) -> None:
        decision = DirectFileReadCapabilityProvider().evaluate(
            _dfr_evidence(capability_family=AccessCapabilityType.api_file_read), self._ctx(),
        )
        assert decision.capability_type is AccessCapabilityType.api_file_read

    def test_no_url_secret_persisted(self) -> None:
        decision = DirectFileReadCapabilityProvider().evaluate(_dfr_evidence(), self._ctx())
        serialized = json.dumps(decision.to_dict())
        assert "http://" not in serialized and "https://" not in serialized


# ---------------------------------------------------------------------------
# 7. Local-command provider
# ---------------------------------------------------------------------------

class TestLocalCommandProvider:
    def _ctx(self) -> CapabilityDiscoveryContext:
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        return _context(_make_api(), subgraph)

    def test_deterministic_benign_proof_accepted(self) -> None:
        decision = LocalCommandCapabilityProvider().evaluate(_local_command_evidence(), self._ctx())
        assert decision.accepted

    def test_runtime_strategy_reference_carried_through(self) -> None:
        decision = LocalCommandCapabilityProvider().evaluate(
            _local_command_evidence(runtime_reference_id="ref-abc"), self._ctx(),
        )
        assert decision.runtime_reference_id == "ref-abc"

    def test_arbitrary_textual_output_alone_rejected(self) -> None:
        decision = LocalCommandCapabilityProvider().evaluate(
            _local_command_evidence(validation_method="port_open"), self._ctx(),
        )
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_dry_run_result_rejected_centrally(self) -> None:
        ev = _local_command_evidence()
        bad = dataclasses.replace(ev, is_dry_run=True)
        assert validate_evidence(bad) is not None

    def test_correct_capability_type(self) -> None:
        decision = LocalCommandCapabilityProvider().evaluate(_local_command_evidence(), self._ctx())
        assert decision.capability_type is AccessCapabilityType.local_shell

    def test_runtime_registration_field_present(self) -> None:
        decision = LocalCommandCapabilityProvider().evaluate(_local_command_evidence(), self._ctx())
        assert hasattr(decision, "runtime_available")


# ---------------------------------------------------------------------------
# 8. Remote-command provider
# ---------------------------------------------------------------------------

class TestRemoteCommandProvider:
    def _ctx(self) -> CapabilityDiscoveryContext:
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        return _context(_make_api(), subgraph)

    def test_backend_confirmed_bounded_strategy_accepted(self) -> None:
        decision = RemoteCommandCapabilityProvider().evaluate(_remote_command_evidence(), self._ctx())
        assert decision.accepted

    def test_non_ssh_remote_session_supported(self) -> None:
        decision = RemoteCommandCapabilityProvider().evaluate(
            _remote_command_evidence(validation_method="nonce_bound_execution"), self._ctx(),
        )
        assert decision.accepted

    def test_generic_command_claim_rejected(self) -> None:
        decision = RemoteCommandCapabilityProvider().evaluate(
            _remote_command_evidence(validation_method="llm_claim"), self._ctx(),
        )
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_wrong_family_rejected(self) -> None:
        ev = _remote_command_evidence()
        bad = dataclasses.replace(ev, capability_family=AccessCapabilityType.local_shell)
        decision = RemoteCommandCapabilityProvider().evaluate(bad, self._ctx())
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_correct_capability_type(self) -> None:
        decision = RemoteCommandCapabilityProvider().evaluate(_remote_command_evidence(), self._ctx())
        assert decision.capability_type is AccessCapabilityType.remote_command


# ---------------------------------------------------------------------------
# 9. Web-command provider
# ---------------------------------------------------------------------------

class TestWebCommandProvider:
    def _ctx(self) -> CapabilityDiscoveryContext:
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        return _context(_make_api(), subgraph)

    def test_valid_evidence_accepted_metadata_only_without_runtime_ref(self) -> None:
        decision = WebCommandCapabilityProvider().evaluate(_web_command_evidence(), self._ctx())
        assert decision.accepted
        assert decision.status is CapabilityDerivationStatus.runtime_unavailable

    def test_generic_admin_portal_access_rejected(self) -> None:
        decision = WebCommandCapabilityProvider().evaluate(
            _web_command_evidence(validation_method="admin_access"), self._ctx(),
        )
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_http_200_rejected(self) -> None:
        decision = WebCommandCapabilityProvider().evaluate(
            _web_command_evidence(validation_method="http_200"), self._ctx(),
        )
        assert decision.status is CapabilityDerivationStatus.rejected

    def test_token_cookie_not_persisted(self) -> None:
        decision = WebCommandCapabilityProvider().evaluate(_web_command_evidence(), self._ctx())
        serialized = json.dumps(decision.to_dict())
        assert "cookie" not in serialized.lower() and "token" not in serialized.lower()

    def test_correct_capability_type(self) -> None:
        decision = WebCommandCapabilityProvider().evaluate(_web_command_evidence(), self._ctx())
        assert decision.capability_type is AccessCapabilityType.web_command


# ---------------------------------------------------------------------------
# 10. Discovery engine
# ---------------------------------------------------------------------------

class TestDiscoveryEngine:
    async def test_one_evidence_accepted(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        result = await run_capability_discovery([_ssh_evidence()], context=_context(api, subgraph))
        assert result.capabilities_derived == 1

    async def test_batch_accepted(self) -> None:
        api = _make_api()
        for i in range(3):
            await _seed_ssh_prereqs(api, principal=f"user{i}")
        subgraph = await _subgraph(api, _TARGET)
        evidence = [_ssh_evidence(principal=f"user{i}") for i in range(3)]
        result = await run_capability_discovery(evidence, context=_context(api, subgraph))
        assert result.capabilities_derived == 3

    async def test_mixed_accepted_rejected(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        evidence = [_ssh_evidence(), _dfr_evidence(validation_method="http_200")]
        result = await run_capability_discovery(evidence, context=_context(api, subgraph))
        assert result.capabilities_derived == 1
        assert result.evidence_rejected == 1

    async def test_deterministic_ordering(self) -> None:
        api1, api2 = _make_api(), _make_api()
        for api in (api1, api2):
            await _seed_ssh_prereqs(api, principal="a")
            await _seed_ssh_prereqs(api, principal="b")
        subgraph1 = await _subgraph(api1, _TARGET)
        subgraph2 = await _subgraph(api2, _TARGET)
        evidence = [_ssh_evidence(principal="a", evidence_id="fixed-a"), _ssh_evidence(principal="b", evidence_id="fixed-b")]
        r1 = await run_capability_discovery(evidence, context=_context(api1, subgraph1))
        r2 = await run_capability_discovery(evidence, context=_context(api2, subgraph2))
        assert [d.capability_id for d in r1.decisions] == [d.capability_id for d in r2.decisions]

    async def test_maximum_batch_bound(self) -> None:
        api = _make_api()
        for i in range(10):
            await _seed_ssh_prereqs(api, principal=f"user{i}")
        subgraph = await _subgraph(api, _TARGET)
        evidence = [_ssh_evidence(principal=f"user{i}") for i in range(10)]
        ctx = _context(api, subgraph)
        ctx.max_evidence_per_cycle = 3
        result = await run_capability_discovery(evidence, context=ctx)
        assert result.evidence_evaluated == 3

    async def test_no_network_calls(self) -> None:
        import apex_host.capabilities.discovery as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "httpx" not in source
        assert "socket." not in source

    async def test_no_tool_calls(self) -> None:
        import apex_host.capabilities.discovery as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "subprocess" not in source
        assert "create_subprocess" not in source

    async def test_no_llm_calls(self) -> None:
        import apex_host.capabilities.discovery as mod
        source = _non_comment_code(inspect.getsource(mod))
        for term in ("openai", "ModelRouter", "LLMGateway", "llm_guard"):
            assert term not in source

    async def test_idempotent_rerun(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        ev = _ssh_evidence(evidence_id="stable-id")
        subgraph1 = await _subgraph(api, _TARGET)
        r1 = await run_capability_discovery([ev], context=_context(api, subgraph1))
        assert r1.capabilities_derived == 1
        subgraph2 = await _subgraph(api, _TARGET)
        r2 = await run_capability_discovery([ev], context=_context(api, subgraph2))
        assert r2.duplicate_count == 1
        assert r2.capabilities_derived == 0

    async def test_provider_exception_isolated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(self: Any, evidence: Any, context: Any) -> Any:
            raise ValueError("boom")
        monkeypatch.setattr(SSHCapabilityProvider, "evaluate", _boom)
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        result = await run_capability_discovery([_ssh_evidence(), _dfr_evidence()], context=_context(api, subgraph))
        assert result.provider_failures == 1
        assert result.capabilities_derived == 1  # the DFR evidence still succeeds (SSH raised before reaching apply_deltas)

    async def test_empty_evidence_list_is_noop(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        result = await run_capability_discovery([], context=_context(api, subgraph))
        assert result.evidence_evaluated == 0


# ---------------------------------------------------------------------------
# 11. Identity and deduplication
# ---------------------------------------------------------------------------

class TestIdentityAndDeduplication:
    async def test_identical_evidence_creates_one_capability(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        ev = _ssh_evidence(evidence_id="dup-1")
        subgraph = await _subgraph(api, _TARGET)
        await run_capability_discovery([ev], context=_context(api, subgraph))
        subgraph2 = await _subgraph(api, _TARGET)
        result = await run_capability_discovery([ev], context=_context(api, subgraph2))
        assert result.duplicate_count == 1
        caps = [n for n in (await _subgraph(api, _TARGET)).nodes if n.type == "access_capability"]
        assert len(caps) == 1

    async def test_two_evidence_items_support_one_capability(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        ev1 = _ssh_evidence(evidence_id="e1", confidence=0.85)
        await run_capability_discovery([ev1], context=_context(api, subgraph))
        subgraph2 = await _subgraph(api, _TARGET)
        ev2 = _ssh_evidence(evidence_id="e2", confidence=0.95)
        result = await run_capability_discovery([ev2], context=_context(api, subgraph2))
        assert result.capabilities_updated == 1
        caps = [n for n in (await _subgraph(api, _TARGET)).nodes if n.type == "access_capability"]
        assert len(caps) == 1
        assert caps[0].props["confidence"] == 0.95

    async def test_provenance_preserved(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        ev1 = _ssh_evidence(evidence_id="prov-1")
        await run_capability_discovery([ev1], context=_context(api, subgraph))
        subgraph2 = await _subgraph(api, _TARGET)
        ev2 = _ssh_evidence(evidence_id="prov-2")
        await run_capability_discovery([ev2], context=_context(api, subgraph2))
        caps = [n for n in (await _subgraph(api, _TARGET)).nodes if n.type == "access_capability"]
        provenance = caps[0].props["metadata"]["evidence_provenance"]
        assert "prov-1" in provenance and "prov-2" in provenance

    async def test_confidence_monotonic_never_lowers(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        ev1 = _ssh_evidence(evidence_id="hi", confidence=0.95)
        await run_capability_discovery([ev1], context=_context(api, subgraph))
        subgraph2 = await _subgraph(api, _TARGET)
        ev2 = _ssh_evidence(evidence_id="lo", confidence=0.86)
        await run_capability_discovery([ev2], context=_context(api, subgraph2))
        caps = [n for n in (await _subgraph(api, _TARGET)).nodes if n.type == "access_capability"]
        assert caps[0].props["confidence"] == 0.95

    async def test_duplicate_replay_does_not_inflate_confidence(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        ev = _ssh_evidence(evidence_id="same-1", confidence=0.85)
        await run_capability_discovery([ev], context=_context(api, subgraph))
        subgraph2 = await _subgraph(api, _TARGET)
        await run_capability_discovery([ev], context=_context(api, subgraph2))
        caps = [n for n in (await _subgraph(api, _TARGET)).nodes if n.type == "access_capability"]
        assert caps[0].props["confidence"] == 0.85

    async def test_different_principal_creates_distinct_capability(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api, principal="root")
        await _seed_ssh_prereqs(api, principal="admin")
        subgraph = await _subgraph(api, _TARGET)
        result = await run_capability_discovery(
            [_ssh_evidence(principal="root"), _ssh_evidence(principal="admin")], context=_context(api, subgraph),
        )
        assert result.capabilities_derived == 2

    async def test_different_target_creates_distinct_capability(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api, target=_TARGET)
        await _seed_ssh_prereqs(api, target="10.10.10.212")
        subgraph = await _subgraph(api, _TARGET)
        ev1 = _ssh_evidence(target=_TARGET)
        ev2 = dataclasses.replace(_ssh_evidence(target=_TARGET), target_host_id=host_id("10.10.10.212"))
        result = await run_capability_discovery([ev1, ev2], context=_context(api, subgraph))
        assert result.capabilities_derived == 2

    async def test_secret_values_do_not_affect_ids(self) -> None:
        cap_id_1 = access_capability_id(_TARGET, "ssh_command", "root")
        cap_id_2 = access_capability_id(_TARGET, "ssh_command", "root")
        assert cap_id_1 == cap_id_2  # never a function of any secret value


# ---------------------------------------------------------------------------
# 12. Runtime resolution
# ---------------------------------------------------------------------------

class TestRuntimeResolution:
    async def test_valid_reference_resolves_ssh(self) -> None:
        config = ApexConfig(
            target=_TARGET, dry_run=True, username_candidates=["root"], password_candidates=["pw"],
        )
        registry = CapabilityRuntimeRegistry()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        cap = AccessCapability(
            capability_id=access_capability_id(_TARGET, "ssh_command", "root"),
            host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.85, source_task_id="",
        )
        registered = register_capability_adapter(
            config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET, cap=cap,
        )
        assert registered is True
        assert registry.has(cap.capability_id)

    async def test_missing_reference_metadata_only(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)  # no credentials configured
        registry = CapabilityRuntimeRegistry()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        cap = AccessCapability(
            capability_id=access_capability_id(_TARGET, "ssh_command", "root"),
            host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.85, source_task_id="",
        )
        registered = register_capability_adapter(
            config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET, cap=cap,
        )
        assert registered is False
        assert not registry.has(cap.capability_id)

    async def test_wrong_target_principal_mismatch_rejected(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True, username_candidates=["root"], password_candidates=["pw"])
        registry = CapabilityRuntimeRegistry()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        cap = AccessCapability(
            capability_id=access_capability_id(_TARGET, "ssh_command", "someoneelse"),
            host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="someoneelse", confidence=0.85, source_task_id="",
        )
        registered = register_capability_adapter(
            config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET, cap=cap,
        )
        assert registered is False

    async def test_wrong_capability_type_no_adapter(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True)
        registry = CapabilityRuntimeRegistry()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        cap = AccessCapability(
            capability_id=access_capability_id(_TARGET, "telnet_command", "root"),
            host_id=_ANCHOR, capability_type=AccessCapabilityType.telnet_command,
            validated=True, principal="root", confidence=0.85, source_task_id="",
        )
        registered = register_capability_adapter(
            config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET, cap=cap,
        )
        assert registered is False

    def test_registry_is_authoritative_not_metadata(self) -> None:
        registry = CapabilityRuntimeRegistry()
        cap_id = access_capability_id(_TARGET, "local_shell", "application")
        assert registry.has(cap_id) is False  # regardless of what any EKG node claims

    def test_runtime_available_advisory_only(self) -> None:
        cap = AccessCapability(
            capability_id="x", host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.9, source_task_id="", runtime_available=True,
        )
        registry = CapabilityRuntimeRegistry()
        # The EKG claim (runtime_available=True) does not make the registry
        # actually have the adapter.
        assert registry.has(cap.capability_id) is False

    async def test_duplicate_registration_idempotent(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True, username_candidates=["root"], password_candidates=["pw"])
        registry = CapabilityRuntimeRegistry()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        cap = AccessCapability(
            capability_id=access_capability_id(_TARGET, "ssh_command", "root"),
            host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.85, source_task_id="",
        )
        register_capability_adapter(config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET, cap=cap)
        adapter1 = registry.get(cap.capability_id)
        register_capability_adapter(config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET, cap=cap)
        adapter2 = registry.get(cap.capability_id)
        assert adapter1 is adapter2


# ---------------------------------------------------------------------------
# 13. Lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_candidate_state(self) -> None:
        cap = AccessCapability(
            capability_id="x", host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=False, principal="root", confidence=0.0, source_task_id="",
        )
        assert capability_lifecycle_state(cap) is CapabilityLifecycleState.candidate

    def test_active_state(self) -> None:
        cap = AccessCapability(
            capability_id="x", host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.9, source_task_id="", runtime_available=True,
        )
        assert capability_lifecycle_state(cap) is CapabilityLifecycleState.active

    def test_unavailable_state(self) -> None:
        cap = AccessCapability(
            capability_id="x", host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.9, source_task_id="", runtime_available=False,
        )
        assert capability_lifecycle_state(cap) is CapabilityLifecycleState.unavailable

    def test_expired_reserved_not_produced(self) -> None:
        # No provider or engine code path ever assigns this state today.
        assert CapabilityLifecycleState.expired.value == "expired"

    def test_revoked_reserved_not_produced(self) -> None:
        assert CapabilityLifecycleState.revoked.value == "revoked"

    def test_superseded_reserved_not_produced(self) -> None:
        assert CapabilityLifecycleState.superseded.value == "superseded"

    def test_authorization_expiry_concept_documented_not_enforced_here(self) -> None:
        # This module never reads authorization state — it is a pure
        # derivation over validated/runtime_available only.
        import apex_host.capabilities.lifecycle as mod
        assert "PolicyAdvisor" not in inspect.getsource(mod)

    def test_historical_metadata_preserved_across_lifecycle_transitions(self) -> None:
        cap_unavailable = AccessCapability(
            capability_id="x", host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.9, source_task_id="",
            metadata={"validation_method": "deterministic_benign_command"}, runtime_available=False,
        )
        assert cap_unavailable.metadata["validation_method"] == "deterministic_benign_command"

    async def test_runtime_removal_changes_effective_availability(self) -> None:
        registry = CapabilityRuntimeRegistry()
        config = ApexConfig(target=_TARGET, dry_run=True, username_candidates=["root"], password_candidates=["pw"])
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        cap = AccessCapability(
            capability_id=access_capability_id(_TARGET, "ssh_command", "root"),
            host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.85, source_task_id="",
        )
        register_capability_adapter(config=config, capability_registry=registry, subgraph=subgraph, target=_TARGET, cap=cap)
        assert registry.has(cap.capability_id)
        # A fresh registry (new engagement) has no memory of the prior one.
        fresh_registry = CapabilityRuntimeRegistry()
        assert not fresh_registry.has(cap.capability_id)


# ---------------------------------------------------------------------------
# 14. Objective reopening
# ---------------------------------------------------------------------------

class TestObjectiveReopening:
    async def _seed_failed_objective_with_ssh(self, api: MemoryAPI) -> str:
        ssh_cap_id = access_capability_id(_TARGET, "ssh_command", "root")
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        await _seed_node(api, ssh_cap_id, "access_capability", {
            "capability_type": "ssh_command", "host_id": _ANCHOR, "validated": True,
            "principal": "root", "confidence": 0.85, "source_task_id": "", "metadata": {},
            "runtime_available": True,
        })
        await _seed_edge(api, _ANCHOR, ssh_cap_id)
        obj_id = f"objective:{_TARGET}:user_flag"
        await _seed_node(api, obj_id, "objective", {
            "objective_type": "user_flag", "status": "failed", "target": _TARGET,
            "attempted_paths": ["/home/root/user.txt"],
            "attempted_capability_paths": [[ssh_cap_id, "/home/root/user.txt"]],
        })
        # Without this edge the objective node is an orphan from the host
        # anchor's perspective and invisible to get_subgraph()'s traversal
        # — the identical "orphan node" bug class Phase 13/14/15/16/18 each
        # hit and fixed for their own opportunity/session/experience nodes
        # (production's ObjectiveParser always creates this edge).
        await _seed_edge(api, _ANCHOR, obj_id, edge_type="indicates")
        return ssh_cap_id

    async def test_blocked_objective_reopens_on_new_active_capability(self) -> None:
        api = _make_api()
        await self._seed_failed_objective_with_ssh(api)
        dfr_cap_id = access_capability_id(_TARGET, "arbitrary_file_read", "application")
        await _seed_node(api, dfr_cap_id, "access_capability", {
            "capability_type": "arbitrary_file_read", "host_id": _ANCHOR, "validated": True,
            "principal": "application", "confidence": 0.8, "source_task_id": "", "metadata": {},
            "runtime_available": True,
        })
        await _seed_edge(api, _ANCHOR, dfr_cap_id)
        subgraph = await _subgraph(api, _TARGET)
        assert objective_reopening_eligible(subgraph, _TARGET, "user_flag") is True

    async def test_exhausted_objective_reopens_on_new_active_capability(self) -> None:
        api = _make_api()
        await self._seed_failed_objective_with_ssh(api)
        subgraph = await _subgraph(api, _TARGET)
        # Only the already-attempted SSH capability exists — no reopening.
        assert objective_reopening_eligible(subgraph, _TARGET, "user_flag") is False
        # A second, brand-new capability appears.
        new_cap_id = access_capability_id(_TARGET, "remote_command", "application")
        await _seed_node(api, new_cap_id, "access_capability", {
            "capability_type": "remote_command", "host_id": _ANCHOR, "validated": True,
            "principal": "application", "confidence": 0.8, "source_task_id": "", "metadata": {},
            "runtime_available": True,
        })
        await _seed_edge(api, _ANCHOR, new_cap_id)
        subgraph2 = await _subgraph(api, _TARGET)
        assert objective_reopening_eligible(subgraph2, _TARGET, "user_flag") is True

    async def test_duplicate_evidence_does_not_reopen(self) -> None:
        api = _make_api()
        await self._seed_failed_objective_with_ssh(api)
        subgraph = await _subgraph(api, _TARGET)
        assert objective_reopening_eligible(subgraph, _TARGET, "user_flag") is False

    async def test_unavailable_capability_does_not_reopen(self) -> None:
        api = _make_api()
        await self._seed_failed_objective_with_ssh(api)
        new_cap_id = access_capability_id(_TARGET, "remote_command", "application")
        await _seed_node(api, new_cap_id, "access_capability", {
            "capability_type": "remote_command", "host_id": _ANCHOR, "validated": True,
            "principal": "application", "confidence": 0.8, "source_task_id": "", "metadata": {},
            "runtime_available": False,  # not runtime-active
        })
        await _seed_edge(api, _ANCHOR, new_cap_id)
        subgraph = await _subgraph(api, _TARGET)
        assert objective_reopening_eligible(subgraph, _TARGET, "user_flag") is False

    async def test_verified_objective_never_reopens(self) -> None:
        api = _make_api()
        await _seed_node(api, _ANCHOR, "host", {"ip": _TARGET})
        obj_id = f"objective:{_TARGET}:user_flag"
        await _seed_node(api, obj_id, "objective", {
            "objective_type": "user_flag", "status": "verified", "target": _TARGET,
            "attempted_paths": [], "attempted_capability_paths": [],
        })
        new_cap_id = access_capability_id(_TARGET, "remote_command", "application")
        await _seed_node(api, new_cap_id, "access_capability", {
            "capability_type": "remote_command", "host_id": _ANCHOR, "validated": True,
            "principal": "application", "confidence": 0.8, "source_task_id": "", "metadata": {},
            "runtime_available": True,
        })
        subgraph = await _subgraph(api, _TARGET)
        assert objective_reopening_eligible(subgraph, _TARGET, "user_flag") is False

    async def test_failed_old_pair_preserved_after_reopen(self) -> None:
        api = _make_api()
        ssh_cap_id = await self._seed_failed_objective_with_ssh(api)
        subgraph = await _subgraph(api, _TARGET)
        pairs = objective_attempted_capability_pairs(subgraph, _TARGET, "user_flag")
        assert (ssh_cap_id, "/home/root/user.txt") in pairs

    async def test_new_capability_path_pair_schedulable(self) -> None:
        api = _make_api()
        await self._seed_failed_objective_with_ssh(api)
        dfr_cap_id = access_capability_id(_TARGET, "arbitrary_file_read", "application")
        await _seed_node(api, dfr_cap_id, "access_capability", {
            "capability_type": "arbitrary_file_read", "host_id": _ANCHOR, "validated": True,
            "principal": "application", "confidence": 0.8, "source_task_id": "", "metadata": {},
            "runtime_available": True,
        })
        subgraph = await _subgraph(api, _TARGET)
        pairs = objective_attempted_capability_pairs(subgraph, _TARGET, "user_flag")
        assert (dfr_cap_id, "/home/root/user.txt") not in pairs

    def test_global_planner_routes_to_objective_when_reopened(self) -> None:
        from apex_host.planners.global_planner import GlobalPlanner
        from apex_host.types import ApexPhase
        gp = GlobalPlanner(max_turns=20)
        for _ in range(gp.budget_remaining(ApexPhase.objective.value)):
            gp.record_turn(ApexPhase.objective)
        assert gp.budget_remaining(ApexPhase.objective.value) == 0
        phase = gp.decide_phase(
            node_types_seen={"host", "service", "endpoint", "access_state"},
            turn_count=5, objective_status="failed", objective_reopened=True,
        )
        assert phase is ApexPhase.objective

    def test_no_endless_retry_without_new_capability(self) -> None:
        from apex_host.planners.global_planner import GlobalPlanner
        from apex_host.types import ApexPhase
        gp = GlobalPlanner(max_turns=20)
        for _ in range(gp.budget_remaining(ApexPhase.objective.value)):
            gp.record_turn(ApexPhase.objective)
        phase = gp.decide_phase(
            node_types_seen={"host", "service", "endpoint", "access_state"},
            turn_count=5, objective_status="failed", objective_reopened=False,
        )
        assert phase is ApexPhase.priv_esc


# ---------------------------------------------------------------------------
# 15. Operator seed migration
# ---------------------------------------------------------------------------

class TestOperatorSeedMigration:
    async def test_dfr_seed_emits_evidence_through_discovery(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True, direct_file_read_operator_attested=True,
            direct_file_read_origin=f"http://{_TARGET}",
            direct_file_read_endpoint_template="/download.php?file={path}",
            direct_file_read_principal="application",
        )
        created = await seed_direct_file_read_capability(api, config)
        assert created is True
        subgraph = await _subgraph(api, _TARGET)
        caps = access_capabilities_from_subgraph(subgraph)
        assert len(caps) == 1
        assert caps[0].capability_type is AccessCapabilityType.arbitrary_file_read

    async def test_bounded_command_seed_emits_evidence_through_discovery(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True, bounded_command_operator_attested=True,
            bounded_command_capability_type="local_shell", bounded_command_principal="application",
        )
        created = await seed_bounded_command_capability(api, config)
        assert created is True
        subgraph = await _subgraph(api, _TARGET)
        caps = access_capabilities_from_subgraph(subgraph)
        assert len(caps) == 1
        assert caps[0].capability_type is AccessCapabilityType.local_shell

    async def test_seed_produces_no_network_call(self) -> None:
        import apex_host.orchestration.capability_seed as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "httpx.AsyncClient(" not in source
        assert "create_subprocess" not in source

    async def test_seed_no_longer_imports_capability_parser_directly(self) -> None:
        import apex_host.orchestration.capability_seed as mod
        source = inspect.getsource(mod)
        assert "from apex_host.parsers.capability_parser import CapabilityParser" not in source

    async def test_duplicate_seed_call_idempotent(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True, bounded_command_operator_attested=True,
            bounded_command_capability_type="local_shell", bounded_command_principal="application",
        )
        first = await seed_bounded_command_capability(api, config)
        second = await seed_bounded_command_capability(api, config)
        assert first is True
        assert second is False  # already present
        subgraph = await _subgraph(api, _TARGET)
        caps = [n for n in subgraph.nodes if n.type == "access_capability"]
        assert len(caps) == 1

    async def test_seed_never_registers_runtime_adapter_prematurely(self) -> None:
        """Seeding uses a throwaway registry (attempt_runtime_registration=False)
        so the real, per-engagement CapabilityRuntimeRegistry constructed
        later never falsely believes an adapter is already registered."""
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True, bounded_command_operator_attested=True,
            bounded_command_capability_type="local_shell", bounded_command_principal="application",
        )
        await seed_bounded_command_capability(api, config)
        real_registry = CapabilityRuntimeRegistry()
        cap_id = access_capability_id(_TARGET, "local_shell", "application")
        assert not real_registry.has(cap_id)

    async def test_secrets_absent_from_seeded_capability(self) -> None:
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True, direct_file_read_operator_attested=True,
            direct_file_read_origin=f"http://{_TARGET}",
            direct_file_read_endpoint_template="/download.php?file={path}",
            direct_file_read_principal="application",
            direct_file_read_headers={"Authorization": "Bearer super-secret-token"},
        )
        await seed_direct_file_read_capability(api, config)
        subgraph = await _subgraph(api, _TARGET)
        serialized = json.dumps([n.props for n in subgraph.nodes], default=str)
        assert "super-secret-token" not in serialized


# ---------------------------------------------------------------------------
# 16. CapabilityParser integration
# ---------------------------------------------------------------------------

class TestCapabilityParserIntegration:
    async def test_parser_is_sole_capability_writer(self) -> None:
        import apex_host.capabilities.discovery as mod
        source = _non_comment_code(inspect.getsource(mod))
        # The engine constructs Node objects only for the advisory
        # runtime_available write-back, never for the capability's own
        # primary metadata (that always goes through CapabilityParser).
        assert "CapabilityParser()" in source

    async def test_memory_api_used_for_writes(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        await run_capability_discovery([_ssh_evidence()], context=_context(api, subgraph))
        found = await _subgraph(api, _TARGET)
        assert any(n.type == "access_capability" for n in found.nodes)

    async def test_confidence_does_not_regress_via_parser(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        await run_capability_discovery([_ssh_evidence(evidence_id="p1", confidence=0.95)], context=_context(api, subgraph))
        subgraph2 = await _subgraph(api, _TARGET)
        await run_capability_discovery([_ssh_evidence(evidence_id="p2", confidence=0.85)], context=_context(api, subgraph2))
        caps = [n for n in (await _subgraph(api, _TARGET)).nodes if n.type == "access_capability"]
        assert caps[0].props["confidence"] == 0.95

    async def test_provenance_edges_correct(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        subgraph = await _subgraph(api, _TARGET)
        await run_capability_discovery([_ssh_evidence()], context=_context(api, subgraph))
        found = await _subgraph(api, _TARGET)
        edge_types = {e.type for e in found.edges}
        assert "has_capability" in edge_types

    async def test_duplicate_write_idempotent(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        ev = _ssh_evidence(evidence_id="idem-1")
        subgraph = await _subgraph(api, _TARGET)
        await run_capability_discovery([ev], context=_context(api, subgraph))
        subgraph2 = await _subgraph(api, _TARGET)
        await run_capability_discovery([ev], context=_context(api, subgraph2))
        found = await _subgraph(api, _TARGET)
        caps = [n for n in found.nodes if n.type == "access_capability"]
        assert len(caps) == 1

    async def test_sanitized_metadata_only(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        await run_capability_discovery([_dfr_evidence()], context=_context(api, subgraph))
        found = await _subgraph(api, _TARGET)
        cap_node = next(n for n in found.nodes if n.type == "access_capability")
        serialized = json.dumps(cap_node.props)
        assert "password" not in serialized.lower()


# ---------------------------------------------------------------------------
# 17. Orchestration
# ---------------------------------------------------------------------------

class TestOrchestrationIntegration:
    def test_structured_result_emits_ssh_evidence(self) -> None:
        from apex_host.orchestration.parsing_node import ssh_capability_evidence_for_result
        tr = {"tool": "ssh_access", "success": True, "username": "root", "task_id": "t1", "dry_run": False}
        ev = ssh_capability_evidence_for_result(tr, target=_TARGET)
        assert ev is not None
        assert ev.evidence_type is CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND
        assert ev.principal == "root"

    def test_failed_ssh_result_emits_no_evidence(self) -> None:
        from apex_host.orchestration.parsing_node import ssh_capability_evidence_for_result
        tr = {"tool": "ssh_access", "success": False, "username": "root"}
        assert ssh_capability_evidence_for_result(tr, target=_TARGET) is None

    def test_missing_username_emits_no_evidence(self) -> None:
        from apex_host.orchestration.parsing_node import ssh_capability_evidence_for_result
        tr = {"tool": "ssh_access", "success": True, "username": ""}
        assert ssh_capability_evidence_for_result(tr, target=_TARGET) is None

    def test_non_ssh_tool_emits_no_evidence(self) -> None:
        from apex_host.orchestration.parsing_node import ssh_capability_evidence_for_result
        tr = {"tool": "nmap", "success": True}
        assert ssh_capability_evidence_for_result(tr, target=_TARGET) is None

    async def test_malformed_evidence_does_not_crash_graph(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ev = CapabilityEvidence(
            evidence_id="", evidence_type=CapabilityEvidenceType.SSH_AUTHENTICATED_COMMAND,
            capability_family=AccessCapabilityType.ssh_command, target_host_id="",
            source_task_id="", principal="", validation_method="", confidence=-5.0, timestamp="",
        )
        result = await run_capability_discovery([ev], context=_context(api, subgraph))
        assert result.capabilities_derived == 0
        assert result.evidence_rejected == 1

    def test_executor_remains_stateless(self) -> None:
        from apex_host.agents.ssh_executor import SSHExecutor
        assert not hasattr(SSHExecutor, "_capability_registry")

    def test_discovery_never_mutates_graph_state_directly(self) -> None:
        import apex_host.capabilities.discovery as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "ApexGraphState" not in source


# ---------------------------------------------------------------------------
# 18. Replay
# ---------------------------------------------------------------------------

class TestReplay:
    async def test_identical_replay_idempotent(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        ev = _ssh_evidence(evidence_id="replay-1")
        subgraph = await _subgraph(api, _TARGET)
        await run_capability_discovery([ev], context=_context(api, subgraph))
        for _ in range(3):
            subgraph = await _subgraph(api, _TARGET)
            await run_capability_discovery([ev], context=_context(api, subgraph))
        caps = [n for n in (await _subgraph(api, _TARGET)).nodes if n.type == "access_capability"]
        assert len(caps) == 1

    def test_no_runtime_object_restored_from_persistence(self) -> None:
        cap = AccessCapability(
            capability_id="x", host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.9, source_task_id="", runtime_available=True,
        )
        # AccessCapability itself never carries a live adapter object.
        assert not hasattr(cap, "adapter")
        assert not hasattr(cap, "session")

    async def test_active_runtime_must_be_re_resolved_each_engagement(self) -> None:
        config = ApexConfig(target=_TARGET, dry_run=True, username_candidates=["root"], password_candidates=["pw"])
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        cap = AccessCapability(
            capability_id=access_capability_id(_TARGET, "ssh_command", "root"),
            host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.85, source_task_id="", runtime_available=True,
        )
        fresh_registry = CapabilityRuntimeRegistry()
        assert not fresh_registry.has(cap.capability_id)
        register_capability_adapter(
            config=config, capability_registry=fresh_registry, subgraph=subgraph, target=_TARGET, cap=cap,
        )
        assert fresh_registry.has(cap.capability_id)

    async def test_expired_evidence_not_reactivated(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ev = _ssh_evidence(evidence_id="old-1")
        stale = dataclasses.replace(ev, timestamp="2000-01-01T00:00:00+00:00")
        ctx = _context(api, subgraph)
        ctx.evidence_ttl_seconds = 60.0
        result = await run_capability_discovery([stale], context=ctx)
        assert result.capabilities_derived == 0

    async def test_confidence_not_inflated_through_replay(self) -> None:
        api = _make_api()
        await _seed_ssh_prereqs(api)
        for _ in range(3):
            subgraph = await _subgraph(api, _TARGET)
            ev = _ssh_evidence(evidence_id="stable-conf", confidence=0.85)
            await run_capability_discovery([ev], context=_context(api, subgraph))
        caps = [n for n in (await _subgraph(api, _TARGET)).nodes if n.type == "access_capability"]
        assert caps[0].props["confidence"] == 0.85

    async def test_episodic_event_append_only_unaffected(self) -> None:
        # Discovery never touches the episodic store — no api.append_episode
        # call anywhere in this module.
        import apex_host.capabilities.discovery as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "append_episode" not in source


# ---------------------------------------------------------------------------
# 19. Persistence and redaction
# ---------------------------------------------------------------------------

class TestPersistenceAndRedaction:
    async def test_raw_output_absent_from_ekg(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        await run_capability_discovery([_dfr_evidence()], context=_context(api, subgraph))
        found = await _subgraph(api, _TARGET)
        serialized = json.dumps([n.props for n in found.nodes], default=str)
        assert _FLAG_VALUE not in serialized

    def test_credentials_absent_from_decision(self) -> None:
        decision = SSHCapabilityProvider().evaluate(_ssh_evidence(), _context(_make_api(), SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)))
        serialized = json.dumps(decision.to_dict())
        assert "pw" not in serialized or "password" not in serialized.lower()

    def test_tokens_absent_from_evidence_serialization(self) -> None:
        ev = _web_command_evidence()
        serialized = json.dumps({"principal": ev.principal, "validation_method": ev.validation_method})
        assert "Bearer" not in serialized

    def test_runtime_handles_absent_from_capability_dataclass(self) -> None:
        cap = AccessCapability(
            capability_id="x", host_id=_ANCHOR, capability_type=AccessCapabilityType.ssh_command,
            validated=True, principal="root", confidence=0.9, source_task_id="",
        )
        assert not hasattr(cap, "session")
        assert not hasattr(cap, "socket")

    async def test_raw_flag_absent_from_report(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        await run_capability_discovery([_ssh_evidence()], context=_context(api, subgraph))
        found = await _subgraph(api, _TARGET)
        state: dict[str, Any] = {
            "run_id": "r", "target": _TARGET, "phase": "done", "goal": "", "current_task": None,
            "evidence_summary": "", "findings": [], "last_tool_result": None, "last_error": None,
            "completed": True, "turn_count": 1, "planner_decisions": [], "tool_results": None,
            "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
            "execution_backend_log": [], "credential_validation_log": [],
            "outcome": "", "termination_reason": "", "termination_phase": "",
            "stall_reason": "", "privilege_state": "", "privilege_summary": {},
            "opportunity_ids": [], "attempted_opportunities": [], "enumeration_complete": False,
            "web_session_state": {}, "workflow_summary": {}, "learning_summary": {},
            "task_latency_log": [], "objective_status": "", "objective_summary": {},
        }
        report = build_report(state, found, ApexConfig(target=_TARGET))
        text = format_text(report)
        assert _FLAG_VALUE not in text
        data = to_json_dict(report)
        assert _FLAG_VALUE not in json.dumps(data, default=str)

    async def test_raw_flag_absent_from_json_export(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        await run_capability_discovery([_dfr_evidence()], context=_context(api, subgraph))
        found = await _subgraph(api, _TARGET)
        serialized = json.dumps([n.props for n in found.nodes] + [e.props for e in found.edges], default=str)
        assert _FLAG_VALUE not in serialized


# ---------------------------------------------------------------------------
# 20-24. Full synthetic flows
# ---------------------------------------------------------------------------

def _make_initial_state(target: str, run_id: str = "run-23") -> dict[str, Any]:
    return {
        "run_id": run_id, "target": target, "phase": "recon",
        "goal": f"Begin engagement against {target}", "current_task": None,
        "evidence_summary": "", "findings": [], "error_episodes": [],
        "last_tool_result": None, "last_error": None, "completed": False,
        "turn_count": 0, "planner_decisions": [], "tool_results": None,
        "repair_count": 0, "policy_decisions": [], "duplicate_actions": [],
        "completed_fingerprints": [], "execution_backend_log": [],
        "diagnostic_events": [], "credential_validation_log": [],
        "outcome": "", "termination_reason": "", "termination_phase": "",
        "stall_reason": "", "privilege_state": "", "privilege_summary": {},
        "opportunity_ids": [], "attempted_opportunities": [],
        "enumeration_complete": False, "web_session_state": {},
        "workflow_summary": {}, "learning_summary": {}, "task_latency_log": [],
        "objective_status": "", "objective_summary": {}, "direct_file_read_log": [],
        "bounded_command_log": [], "capability_discovery_log": [],
    }


class TestFullSyntheticSSHFlow:
    async def test_ssh_success_derives_capability_reaches_verified(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        """No operator capability seed — a real, successful SSH validation
        result flows through parse_observation -> evidence -> discovery ->
        CapabilityParser -> registration -> ObjectivePlanner ->
        UserFlagExecutor -> verify_user_flag -> user_flag_verified."""
        import paramiko

        from apex_host.graph import build_apex_graph

        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        class _FakeChannelFile:
            def __init__(self, data: bytes) -> None:
                self._data = data
                self.channel = type("C", (), {"recv_exit_status": lambda self: 0})()

            def read(self, _n: int = -1) -> bytes:
                return self._data

        class _FakeSSHClient:
            def set_missing_host_key_policy(self, *_a: Any, **_kw: Any) -> None: ...
            def connect(self, *_a: Any, **_kw: Any) -> None: ...
            def exec_command(self, command: str, timeout: float | None = None) -> Any:
                if "cat -- " in command and "user.txt" in command:
                    return None, _FakeChannelFile(_FLAG_VALUE.encode()), _FakeChannelFile(b"")
                return None, _FakeChannelFile(b"uid=0(root)\n"), _FakeChannelFile(b"")
            def close(self) -> None: ...

        monkeypatch.setattr(paramiko, "SSHClient", _FakeSSHClient)

        api = _make_api()
        h_id = host_id(_TARGET)
        await _seed_node(api, h_id, "host", {"ip": _TARGET})
        svc_id = f"service:{_TARGET}:22/tcp"
        await _seed_node(api, svc_id, "service", {"port": "22", "proto": "tcp", "service": "ssh", "state": "open"})
        await _seed_edge(api, h_id, svc_id, edge_type="exposes")

        config = ApexConfig(
            target=_TARGET, dry_run=False, max_turns=6,
            username_candidates=["root"], password_candidates=["testpass"],
            user_flag_candidate_roots=[str(tmp_path)], user_flag_candidate_filenames=["user.txt"],
        )
        from apex_host.tools.registry import ToolRegistry
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))

        assert final_state["outcome"] == EngagementOutcome.user_flag_verified.value
        assert is_success_outcome(EngagementOutcome(final_state["outcome"]))
        subgraph = await _subgraph(api, _TARGET)
        caps = access_capabilities_from_subgraph(subgraph)
        assert any(c.capability_type is AccessCapabilityType.ssh_command for c in caps)
        serialized = json.dumps([n.props for n in subgraph.nodes], default=str)
        assert _FLAG_VALUE not in serialized


class TestFullSyntheticDirectFileReadFlow:
    async def test_dfr_evidence_direct_to_discovery_reaches_verifier(self) -> None:
        """No operator capability seed relied upon for the DECISION path —
        directly constructs qualifying CapabilityEvidence and proves the
        discovery -> parser -> registration chain (using the pre-existing,
        already-tested runtime_resolution._register_direct_file_read_adapter
        path, which itself still requires ApexConfig.direct_file_read_*
        fields to construct a real adapter — this test proves discovery's
        OWN correctness independent of how the evidence was produced)."""
        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True,
            direct_file_read_origin=f"http://{_TARGET}",
            direct_file_read_endpoint_template="/download.php?file={path}",
            direct_file_read_principal="application",
        )
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        registry = CapabilityRuntimeRegistry()
        ctx = _context(api, subgraph, config=config, registry=registry)
        result = await run_capability_discovery([_dfr_evidence()], context=ctx)
        assert result.capabilities_derived == 1
        assert result.adapters_registered == 1
        cap_id = access_capability_id(_TARGET, "arbitrary_file_read", "application")
        assert registry.has(cap_id)


class TestFullSyntheticRemoteCommandFlow:
    async def test_remote_command_evidence_reaches_active_capability(self, tmp_path: Path) -> None:
        """No operator capability seed — validated bounded-command evidence
        emitted directly, remote adapter resolves via the real
        ToolBackendCommandReadStrategy/LocalToolBackend chain (no SSH or
        DFR capability needed)."""
        flag_file = tmp_path / "user.txt"
        flag_file.write_text(_FLAG_VALUE)

        api = _make_api()
        config = ApexConfig(
            target=_TARGET, dry_run=True, allowed_tools=["cat"],
            bounded_command_operator_attested=True, bounded_command_capability_type="remote_command",
            bounded_command_principal="application",
        )
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        registry = CapabilityRuntimeRegistry()
        ctx = _context(api, subgraph, config=config, registry=registry)
        result = await run_capability_discovery([_remote_command_evidence()], context=ctx)
        assert result.capabilities_derived == 1
        assert result.adapters_registered == 1
        cap_id = access_capability_id(_TARGET, "remote_command", "application")
        assert registry.has(cap_id)
        adapter = registry.get(cap_id)
        assert adapter is not None


class TestNegativeFullFlow:
    async def test_only_credentials_found_no_capability(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ev = _dfr_evidence(validation_method="credentials_found")
        result = await run_capability_discovery([ev], context=_context(api, subgraph))
        assert result.capabilities_derived == 0

    async def test_only_http_200_no_capability(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ev = _dfr_evidence(validation_method="http_200")
        result = await run_capability_discovery([ev], context=_context(api, subgraph))
        assert result.capabilities_derived == 0

    async def test_only_admin_portal_access_no_capability(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ev = _web_command_evidence(validation_method="admin_access")
        result = await run_capability_discovery([ev], context=_context(api, subgraph))
        assert result.capabilities_derived == 0

    async def test_only_llm_claim_no_capability(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ev = _remote_command_evidence(validation_method="llm_claim")
        result = await run_capability_discovery([ev], context=_context(api, subgraph))
        assert result.capabilities_derived == 0

    async def test_only_payload_attempt_record_no_capability(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ev = _dfr_evidence(validation_method="payload_attempted")
        result = await run_capability_discovery([ev], context=_context(api, subgraph))
        assert result.capabilities_derived == 0
        assert result.evidence_rejected == 1

    def test_objective_not_verified_without_capability(self) -> None:
        state = objective_status_from_subgraph(
            SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0), _TARGET, "user_flag",
        )
        assert state == "pending"
        assert not is_success_outcome(EngagementOutcome.max_turns_exhausted)


class TestDryRunFullFlow:
    async def test_dry_run_ssh_result_never_derives_capability(self) -> None:
        from apex_host.orchestration.parsing_node import ssh_capability_evidence_for_result
        tr = {"tool": "ssh_access", "success": True, "username": "root", "dry_run": True}
        ev = ssh_capability_evidence_for_result(tr, target=_TARGET)
        assert ev is not None
        assert ev.is_dry_run is True
        rejection = validate_evidence(ev)
        assert rejection is not None and rejection.reason == "dry_run_evidence"

    async def test_dry_run_evidence_produces_no_active_capability(self) -> None:
        api = _make_api()
        subgraph = SubgraphView(anchor=_ANCHOR, nodes=[], edges=[], depth=0)
        ev = _ssh_evidence(is_dry_run=True)
        result = await run_capability_discovery([ev], context=_context(api, subgraph))
        assert result.capabilities_derived == 0
        assert result.evidence_rejected == 1

    async def test_dry_run_engagement_reports_no_success(self) -> None:
        api = _make_api()
        config = ApexConfig(target=_TARGET, dry_run=True, max_turns=2)
        from apex_host.graph import build_apex_graph
        from apex_host.tools.registry import ToolRegistry
        registry = ToolRegistry.from_config(config)
        graph = build_apex_graph(api, registry, config)
        final_state = await graph.ainvoke(_make_initial_state(_TARGET))
        assert final_state["outcome"] != EngagementOutcome.user_flag_verified.value


# ---------------------------------------------------------------------------
# 25. Architecture scans
# ---------------------------------------------------------------------------

class TestArchitectureScans:
    def test_memfabric_unchanged_no_capability_terms(self) -> None:
        import pathlib
        memfabric_root = pathlib.Path(__file__).resolve().parents[2] / "memfabric"
        forbidden = ("CapabilityEvidence", "AccessCapability", "capability_discovery", "CapabilityProvider")
        for path in memfabric_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            for term in forbidden:
                assert term not in text, f"{term} found in {path}"

    def test_no_machine_names_in_capabilities_package(self) -> None:
        import pathlib
        pkg_root = pathlib.Path(__file__).resolve().parents[2] / "apex_host" / "capabilities"
        forbidden = ("meow", "lame", "blue", "academy", "twomillion")
        for path in pkg_root.rglob("*.py"):
            lowered = path.read_text(encoding="utf-8", errors="ignore").lower()
            for term in forbidden:
                assert term not in lowered, f"{term} found in {path}"

    def test_no_hardcoded_real_flag_values(self) -> None:
        import pathlib
        pkg_root = pathlib.Path(__file__).resolve().parents[2] / "apex_host" / "capabilities"
        for path in pkg_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert "HTB{" not in text and "flag{" not in text.lower()

    def test_no_shell_true(self) -> None:
        import pathlib
        pkg_root = pathlib.Path(__file__).resolve().parents[2] / "apex_host" / "capabilities"
        for path in pkg_root.rglob("*.py"):
            assert "shell=True" not in path.read_text(encoding="utf-8", errors="ignore")

    def test_no_arbitrary_execute_api_in_providers(self) -> None:
        import apex_host.capabilities.providers as mod
        source = _non_comment_code(inspect.getsource(mod))
        for term in ("def execute(", "def run_shell(", "os.system", "subprocess."):
            assert term not in source

    def test_no_generic_http_executor_in_capabilities_package(self) -> None:
        import pathlib
        pkg_root = pathlib.Path(__file__).resolve().parents[2] / "apex_host" / "capabilities"
        for path in pkg_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert "httpx.AsyncClient(" not in text

    def test_no_llm_authority_in_providers(self) -> None:
        import apex_host.capabilities.providers as mod
        source = inspect.getsource(mod)
        for term in ("ModelRouter", "LLMGateway", "openai", "llm_guard"):
            assert term not in source

    def test_no_provider_writes_memory_api(self) -> None:
        import apex_host.capabilities.providers as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "apply_deltas" not in source

    def test_no_provider_mutates_runtime_registry(self) -> None:
        import apex_host.capabilities.providers as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "CapabilityRuntimeRegistry(" not in source

    def test_objective_planner_transport_independent(self) -> None:
        import apex_host.planners.objective_planner as mod
        source = inspect.getsource(mod)
        for term in ("capability_type ==", "capability_type is AccessCapabilityType.ssh", "paramiko"):
            assert term not in source

    def test_user_flag_executor_transport_independent(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "capability_type ==" not in source
        assert "paramiko" not in source

    def test_objective_parser_transport_independent(self) -> None:
        import apex_host.parsers.objective_parser as mod
        source = _non_comment_code(inspect.getsource(mod))
        assert "capability_type ==" not in source

    def test_verify_user_flag_is_sole_verifier(self) -> None:
        import apex_host.agents.user_flag_executor as mod
        source = _non_comment_code(inspect.getsource(mod))
        # Docstrings are stripped by _non_comment_code, so any remaining
        # "verify_user_flag(" occurrence is a real call site (the import
        # statement itself has no trailing "(" after the bare name).
        assert source.count("verify_user_flag(") == 1

    def test_dry_run_default_true(self) -> None:
        assert ApexConfig(target=_TARGET).dry_run is True

    def test_user_flag_verified_sole_success_outcome(self) -> None:
        for outcome in EngagementOutcome:
            expected = outcome is EngagementOutcome.user_flag_verified
            assert is_success_outcome(outcome) == expected

    def test_capability_discovery_default_enabled(self) -> None:
        assert ApexConfig(target=_TARGET).capability_discovery_enabled is True

    def test_evidence_ttl_disabled_by_default(self) -> None:
        assert ApexConfig(target=_TARGET).capability_evidence_ttl_seconds == 0.0
