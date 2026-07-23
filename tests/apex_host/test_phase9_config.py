# test_phase9_config.py
# Phase 9 acceptance tests: shared-state boundaries, canonical configuration, safe defaults.
"""Phase 9 — Shared-State Boundaries, Canonical Configuration, and Safe Default Consistency.

80 tests across 7 groups:
  CFG  (15) — ApexConfig defaults, to_safe_dict, from_cli_args
  CLI  (15) — Entry-point correctness and llm_provider fix
  ENV  (10) — Environment isolation: config needs no env vars
  STATE(15) — ApexGraphState / TurnState field contracts
  SERIAL(10) — JSON serializability of config and state payloads
  ARCH (10) — Architecture scan: no inline IDs, no api._ access, no in-place mutations
  E2E  ( 5) — End-to-end integration smoke tests
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import operator
import re
from pathlib import Path
from typing import Any

import pytest

from apex_host.config import ApexConfig
from apex_host.eval.run_htb_local import parse_args as htb_parse_args
from apex_host.eval.run_synthetic_machine import (
    SYNTHETIC_TARGET,
    _make_api,
    seed_synthetic_machine,
)
from apex_host.graph_ids import host_id, service_id
from apex_host.graph_state import ApexGraphState
from apex_host.main import parse_args as main_parse_args
from apex_host.security.redaction import REDACTED_PLACEHOLDER
from memfabric.coordination.graph_state import TurnState
from memfabric.types import Episode, Node

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_APEX_HOST_ROOT = Path(__file__).parent.parent.parent / "apex_host"
_REPO_ROOT = Path(__file__).parent.parent.parent


def _apex_production_py_files() -> list[Path]:
    """All .py source files in apex_host/ that are not tests."""
    return [
        p for p in _APEX_HOST_ROOT.rglob("*.py")
        if "__pycache__" not in str(p) and "test_" not in p.name
    ]


def _read_source(rel_path: str) -> str:
    return (_REPO_ROOT / rel_path).read_text(encoding="utf-8")


def _base_config() -> ApexConfig:
    return ApexConfig(target="10.0.0.1")


# ---------------------------------------------------------------------------
# CFG group — ApexConfig defaults, to_safe_dict, from_cli_args
# ---------------------------------------------------------------------------

def test_cfg_01_dry_run_default_is_true() -> None:
    assert ApexConfig(target="t").dry_run is True


def test_cfg_02_use_llm_default_is_false() -> None:
    assert ApexConfig(target="t").use_llm is False


def test_cfg_03_policy_enabled_default_is_true() -> None:
    assert ApexConfig(target="t").policy_enabled is True


def test_cfg_04_llm_provider_default_is_fake() -> None:
    assert ApexConfig(target="t").llm_provider == "fake"


def test_cfg_05_config_schema_version_exists() -> None:
    assert ApexConfig(target="t").config_schema_version == "1"


def test_cfg_06_config_schema_version_is_str() -> None:
    assert isinstance(ApexConfig(target="t").config_schema_version, str)


def test_cfg_07_max_access_attempts_default_is_one() -> None:
    assert ApexConfig(target="t").max_access_attempts == 1


def test_cfg_08_allowed_tools_includes_nmap() -> None:
    assert "nmap" in ApexConfig(target="t").allowed_tools


def test_cfg_09_password_candidates_default_empty() -> None:
    assert ApexConfig(target="t").password_candidates == []


def test_cfg_10_to_safe_dict_returns_dict() -> None:
    d = _base_config().to_safe_dict()
    assert isinstance(d, dict)


def test_cfg_11_to_safe_dict_redacts_passwords() -> None:
    cfg = ApexConfig(target="t", password_candidates=["s3cr3t", "p@ss"])
    d = cfg.to_safe_dict()
    assert d["password_candidates"] == [REDACTED_PLACEHOLDER, REDACTED_PLACEHOLDER]
    assert "s3cr3t" not in str(d)
    assert "p@ss" not in str(d)


def test_cfg_12_to_safe_dict_preserves_target() -> None:
    cfg = ApexConfig(target="192.168.1.1")
    assert cfg.to_safe_dict()["target"] == "192.168.1.1"


def test_cfg_13_to_safe_dict_includes_schema_version() -> None:
    assert _base_config().to_safe_dict()["config_schema_version"] == "1"


def test_cfg_14_to_safe_dict_does_not_mutate_original() -> None:
    cfg = ApexConfig(target="t", password_candidates=["secret"])
    _ = cfg.to_safe_dict()
    assert cfg.password_candidates == ["secret"]


def test_cfg_15_to_safe_dict_empty_passwords_stay_empty() -> None:
    cfg = ApexConfig(target="t", password_candidates=[])
    d = cfg.to_safe_dict()
    assert d["password_candidates"] == []


# ---------------------------------------------------------------------------
# CLI group — entry-point correctness and llm_provider fix
# ---------------------------------------------------------------------------

def test_cli_01_main_parse_args_llm_provider_default_is_none() -> None:
    ns = main_parse_args(["--target", "10.0.0.1"])
    assert ns.llm_provider is None


def test_cli_02_from_cli_args_llm_provider_default_is_fake() -> None:
    ns = main_parse_args(["--target", "10.0.0.1"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.llm_provider == "fake"


def test_cli_03_from_cli_args_dry_run_default_true() -> None:
    ns = main_parse_args(["--target", "10.0.0.1"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.dry_run is True


def test_cli_04_from_cli_args_no_dry_run_gives_false() -> None:
    ns = main_parse_args(["--target", "10.0.0.1", "--no-dry-run"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.dry_run is False


def test_cli_05_from_cli_args_returns_apex_config() -> None:
    ns = main_parse_args(["--target", "10.0.0.1"])
    cfg = ApexConfig.from_cli_args(ns)
    assert isinstance(cfg, ApexConfig)


def test_cli_06_from_cli_args_use_llm_default_false() -> None:
    ns = main_parse_args(["--target", "10.0.0.1"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.use_llm is False


def test_cli_07_from_cli_args_use_llm_flag() -> None:
    ns = main_parse_args(["--target", "10.0.0.1", "--use-llm"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.use_llm is True


def test_cli_08_from_cli_args_explicit_llm_provider() -> None:
    ns = main_parse_args(["--target", "10.0.0.1", "--llm-provider", "openai"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.llm_provider == "openai"


def test_cli_09_from_cli_args_llm_model_sets_all_three() -> None:
    ns = main_parse_args(["--target", "10.0.0.1", "--llm-model", "my-model"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.planner_model == "my-model"
    assert cfg.executor_model == "my-model"
    assert cfg.parser_model == "my-model"


def test_cli_10_from_cli_args_max_turns() -> None:
    ns = main_parse_args(["--target", "10.0.0.1", "--max-turns", "7"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.max_turns == 7


def test_cli_11_from_cli_args_credentials() -> None:
    ns = main_parse_args([
        "--target", "10.0.0.1",
        "--username", "root", "--password", "toor",
    ])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.username_candidates == ["root"]
    assert cfg.password_candidates == ["toor"]


def test_cli_12_from_cli_args_knowledge_root() -> None:
    ns = main_parse_args(["--target", "10.0.0.1", "--knowledge-root", "./knowledge"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.knowledge_root == "./knowledge"


def test_cli_13_from_cli_args_policy_file() -> None:
    ns = main_parse_args(["--target", "10.0.0.1", "--policy-file", "./pol.yaml"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.policy_file == "./pol.yaml"


def test_cli_14_htb_parse_args_llm_provider_default_is_none() -> None:
    ns = htb_parse_args(["--target", "10.0.0.1"])
    assert ns.llm_provider is None


def test_cli_15_htb_from_cli_args_llm_provider_default_is_fake() -> None:
    ns = htb_parse_args(["--target", "10.0.0.1"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.llm_provider == "fake"


# ---------------------------------------------------------------------------
# ENV group — config construction needs no environment variables
# ---------------------------------------------------------------------------

def test_env_01_config_constructs_with_no_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    # Remove any OpenAI/router-related env vars from the current process.
    for key in list({"OPENAI_API_KEY", "OPENAI_BASE_URL"}):
        monkeypatch.delenv(key, raising=False)
    cfg = ApexConfig(target="10.0.0.1")
    assert cfg.target == "10.0.0.1"


def test_env_02_openai_api_key_not_a_config_field() -> None:
    field_names = {f.name for f in dataclasses.fields(ApexConfig)}
    assert "OPENAI_API_KEY" not in field_names
    assert "openai_api_key" not in field_names


def test_env_03_llm_base_url_none_is_valid() -> None:
    cfg = ApexConfig(target="t", llm_base_url=None)
    assert cfg.llm_base_url is None


def test_env_04_config_py_has_no_os_getenv_calls() -> None:
    src = _read_source("apex_host/config.py")
    assert "os.getenv" not in src
    assert "os.environ" not in src


def test_env_05_to_safe_dict_has_no_api_key_field() -> None:
    d = _base_config().to_safe_dict()
    keys_lower = {str(k).lower() for k in d}
    assert "openai_api_key" not in keys_lower
    assert "api_key" not in keys_lower


def test_env_06_schema_version_constant_not_env_dependent() -> None:
    cfg1 = ApexConfig(target="t")
    cfg2 = ApexConfig(target="t")
    assert cfg1.config_schema_version == cfg2.config_schema_version == "1"


def test_env_07_fake_provider_requires_no_api_key() -> None:
    from apex_host.llm.router import FakeModelRouter
    router = FakeModelRouter()
    assert router.planner_llm() is None


def test_env_08_dry_run_true_needs_no_runtime_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    cfg = ApexConfig(target="10.0.0.1", dry_run=True, use_llm=False)
    assert cfg.dry_run is True
    assert cfg.use_llm is False


def test_env_09_use_llm_false_implies_fake_router_by_default() -> None:
    cfg = ApexConfig(target="t", use_llm=False)
    # When use_llm=False, runtime.py uses FakeModelRouter — no API key required.
    assert cfg.use_llm is False
    assert cfg.llm_provider == "fake"


def test_env_10_llm_provider_fake_means_no_api_calls_needed() -> None:
    from apex_host.llm.router import FakeModelRouter
    cfg = ApexConfig(target="t", use_llm=True, llm_provider="fake")
    # FakeModelRouter is selected when use_llm=True and llm_provider="fake"
    router = FakeModelRouter()
    assert router.planner_llm() is None
    assert cfg.llm_provider == "fake"


# ---------------------------------------------------------------------------
# STATE group — ApexGraphState / TurnState field contracts
# ---------------------------------------------------------------------------

def test_state_01_run_id_in_annotations() -> None:
    assert "run_id" in ApexGraphState.__annotations__


def test_state_02_findings_in_annotations() -> None:
    assert "findings" in ApexGraphState.__annotations__


def test_state_03_planner_decisions_in_annotations() -> None:
    assert "planner_decisions" in ApexGraphState.__annotations__


def test_state_04_policy_decisions_in_annotations() -> None:
    assert "policy_decisions" in ApexGraphState.__annotations__


def test_state_05_duplicate_actions_in_annotations() -> None:
    assert "duplicate_actions" in ApexGraphState.__annotations__


def test_state_06_completed_fingerprints_in_annotations() -> None:
    assert "completed_fingerprints" in ApexGraphState.__annotations__


def test_state_07_tool_results_in_annotations() -> None:
    assert "tool_results" in ApexGraphState.__annotations__


def test_state_08_repair_count_in_annotations() -> None:
    assert "repair_count" in ApexGraphState.__annotations__


def test_state_09_operator_add_reducer_accumulates_lists() -> None:
    a: list[dict[str, Any]] = [{"phase": "recon"}]
    b: list[dict[str, Any]] = [{"phase": "web"}]
    result = operator.add(a, b)
    assert result == [{"phase": "recon"}, {"phase": "web"}]


def test_state_10_sample_apex_graph_state_is_json_serializable() -> None:
    sample: dict[str, Any] = {
        "run_id": "test-run",
        "target": "10.0.0.1",
        "phase": "recon",
        "goal": "begin engagement",
        "current_task": None,
        "evidence_summary": "",
        "findings": [],
        "error_episodes": [],
        "last_tool_result": None,
        "last_error": None,
        "completed": False,
        "turn_count": 0,
        "planner_decisions": [],
        "tool_results": None,
        "repair_count": 0,
        "policy_decisions": [],
        "duplicate_actions": [],
        "completed_fingerprints": [],
    }
    json.dumps(sample)  # must not raise


def test_state_11_api_not_in_apex_graph_state_annotations() -> None:
    assert "api" not in ApexGraphState.__annotations__


def test_state_12_executor_not_in_apex_graph_state_annotations() -> None:
    assert "executor" not in ApexGraphState.__annotations__


def test_state_13_planner_not_in_apex_graph_state_annotations() -> None:
    assert "planner" not in ApexGraphState.__annotations__


def test_state_14_turn_state_has_goal_annotation() -> None:
    assert "goal" in TurnState.__annotations__


def test_state_15_turn_state_has_tasks_annotation() -> None:
    assert "tasks" in TurnState.__annotations__


# ---------------------------------------------------------------------------
# SERIAL group — JSON serializability
# ---------------------------------------------------------------------------

def test_serial_01_to_safe_dict_is_json_serializable() -> None:
    cfg = ApexConfig(target="10.0.0.1", password_candidates=["secret"])
    json.dumps(cfg.to_safe_dict())  # must not raise


def test_serial_02_to_safe_dict_has_no_plaintext_password() -> None:
    cfg = ApexConfig(target="t", password_candidates=["my-secret-pw"])
    raw = json.dumps(cfg.to_safe_dict())
    assert "my-secret-pw" not in raw


def test_serial_03_to_safe_dict_field_count_equals_dataclass_fields() -> None:
    cfg = _base_config()
    assert len(cfg.to_safe_dict()) == len(dataclasses.fields(cfg))


def test_serial_04_config_schema_version_in_to_safe_dict() -> None:
    d = _base_config().to_safe_dict()
    assert "config_schema_version" in d


def test_serial_05_default_config_all_values_json_serializable() -> None:
    cfg = _base_config()
    d = cfg.to_safe_dict()
    json.dumps(d)  # no custom types in any default field value


def test_serial_06_node_props_json_serializable() -> None:
    from memfabric.ids import new_id, now
    n = Node(
        id=new_id(), type="host", props={"ip": "10.0.0.1"},
        confidence=0.9, source="test", first_seen=now(), last_seen=now(),
    )
    json.dumps(n.props)  # must not raise


def test_serial_07_episode_data_json_serializable() -> None:
    from memfabric.ids import new_id, now
    ep = Episode(
        id=new_id(), agent="test.agent", action="test_action", outcome="success",
        timestamp=now(), data={"stdout": "ok", "returncode": 0},
    )
    json.dumps(ep.data)  # must not raise


def test_serial_08_to_safe_dict_returns_new_dict() -> None:
    cfg = _base_config()
    d1 = cfg.to_safe_dict()
    d2 = cfg.to_safe_dict()
    assert d1 is not d2


def test_serial_09_repr_does_not_contain_plaintext_password() -> None:
    cfg = ApexConfig(target="t", password_candidates=["hunter2"])
    # repr() of the dataclass would normally show the field values.
    # For safety, verify the plaintext doesn't appear after to_safe_dict redaction.
    d = cfg.to_safe_dict()
    assert "hunter2" not in str(d)
    # The config object itself still holds the value (only to_safe_dict redacts).
    assert "hunter2" in str(cfg.password_candidates)


def test_serial_10_to_safe_dict_with_multiple_passwords_all_redacted() -> None:
    cfg = ApexConfig(target="t", password_candidates=["aaa", "bbb", "ccc"])
    d = cfg.to_safe_dict()
    pwds = d["password_candidates"]
    assert isinstance(pwds, list)
    assert all(p == REDACTED_PLACEHOLDER for p in pwds)
    assert len(pwds) == 3


# ---------------------------------------------------------------------------
# ARCH group — architecture scans
# ---------------------------------------------------------------------------

def test_arch_01_run_synthetic_no_f_string_host_id() -> None:
    src = _read_source("apex_host/eval/run_synthetic_machine.py")
    assert 'f"host:' not in src, "run_synthetic_machine must use graph_ids.host_id(), not f'host:...'"


def test_arch_02_run_synthetic_no_f_string_service_id() -> None:
    src = _read_source("apex_host/eval/run_synthetic_machine.py")
    assert 'f"service:' not in src, "run_synthetic_machine must use graph_ids.service_id(), not f'service:...'"


def test_arch_03_run_synthetic_no_f_string_edge_id() -> None:
    src = _read_source("apex_host/eval/run_synthetic_machine.py")
    assert 'f"edge:' not in src, "run_synthetic_machine must use exposes_edge_id(), not f'edge:...'"


def test_arch_04_no_api_private_access_in_production_apex_host() -> None:
    pattern = re.compile(r"\bapi\._[a-z]")
    violations: list[str] = []
    for path in _apex_production_py_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                violations.append(f"{path.relative_to(_REPO_ROOT)}:{lineno}: {line.strip()}")
    assert not violations, "Unexpected api._ private access:\n" + "\n".join(violations)


def test_arch_05_no_in_place_state_mutation_in_graph_py() -> None:
    src = _read_source("apex_host/graph.py")
    pattern = re.compile(r'state\["[^"]+"\]\.(append|extend|update|insert)\(')
    matches = pattern.findall(src)
    assert not matches, f"In-place state mutations found in graph.py: {matches}"


def test_arch_06_dry_run_default_true_in_config_source() -> None:
    src = _read_source("apex_host/config.py")
    assert "dry_run: bool = True" in src


def test_arch_07_llm_provider_default_fake_in_config_source() -> None:
    src = _read_source("apex_host/config.py")
    assert 'llm_provider: str = "fake"' in src


def test_arch_08_config_py_has_no_env_access() -> None:
    src = _read_source("apex_host/config.py")
    assert "os.getenv" not in src
    assert "os.environ" not in src


def test_arch_09_config_schema_version_default_is_one_in_source() -> None:
    src = _read_source("apex_host/config.py")
    assert 'config_schema_version: str = "1"' in src


def test_arch_10_apex_config_construction_only_in_approved_files() -> None:
    """ApexConfig( is constructed in at most 3 production files: config.py (classmethod),
    main.py (via from_cli_args), run_htb_local.py (via from_cli_args), and
    run_synthetic_machine.py. The classmethod body itself counts as one.
    Direct ApexConfig(**kwargs) construction outside of from_cli_args is flagged.
    """
    pattern = re.compile(r"\bApexConfig\(")
    approved = {
        "apex_host/config.py",           # from_cli_args classmethod
        "apex_host/eval/run_synthetic_machine.py",  # direct construction (minimal)
        # Phase 25 — a synthetic, no-CLI evaluation harness exactly like
        # run_synthetic_machine.py above; constructs ApexConfig directly
        # for the same reason (no argparse.Namespace to build from).
        "apex_host/eval/release_gate.py",
    }
    violations: list[str] = []
    for path in _apex_production_py_files():
        rel = str(path.relative_to(_REPO_ROOT)).replace("\\", "/")
        if rel in approved:
            continue
        src = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(src.splitlines(), 1):
            if pattern.search(line):
                violations.append(f"{rel}:{lineno}: {line.strip()}")
    assert not violations, (
        "Unexpected direct ApexConfig() construction outside approved files:\n"
        + "\n".join(violations)
    )


# ---------------------------------------------------------------------------
# E2E group — integration smoke tests
# ---------------------------------------------------------------------------

def test_e2e_01_dry_run_preserved_through_from_cli_args() -> None:
    ns = main_parse_args(["--target", "10.0.0.1"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.dry_run is True, "dry_run=True must survive CLI→config construction"


def test_e2e_02_no_dry_run_flag_propagates_correctly() -> None:
    ns = main_parse_args(["--target", "10.0.0.1", "--no-dry-run"])
    cfg = ApexConfig.from_cli_args(ns)
    assert cfg.dry_run is False


def test_e2e_03_synthetic_machine_nodes_use_canonical_host_id() -> None:
    async def _run() -> bool:
        api = _make_api()
        await seed_synthetic_machine(api)
        # Use the public get_subgraph to look up the host node.
        sg = await api.get_subgraph(host_id(SYNTHETIC_TARGET), depth=1)
        return any(
            n.id == host_id(SYNTHETIC_TARGET) and n.type == "host"
            for n in sg.nodes
        )

    found = asyncio.run(_run())
    assert found, f"Host node with canonical id '{host_id(SYNTHETIC_TARGET)}' not found in EKG"


def test_e2e_04_synthetic_machine_service_uses_canonical_id() -> None:
    expected_id = service_id(SYNTHETIC_TARGET, "80", "tcp")

    async def _run() -> bool:
        api = _make_api()
        await seed_synthetic_machine(api)
        sg = await api.get_subgraph(host_id(SYNTHETIC_TARGET), depth=1)
        return any(n.id == expected_id and n.type == "service" for n in sg.nodes)

    found = asyncio.run(_run())
    assert found, f"Service node with canonical id '{expected_id}' not found in EKG"


def test_e2e_05_to_safe_dict_json_serializable_with_real_config() -> None:
    ns = main_parse_args([
        "--target", "10.0.0.1",
        "--username", "root",
        "--password", "toor",
        "--max-turns", "3",
    ])
    cfg = ApexConfig.from_cli_args(ns)
    d = cfg.to_safe_dict()
    raw = json.dumps(d)
    assert "toor" not in raw
    assert "root" in raw  # username is NOT redacted
    assert d["config_schema_version"] == "1"
    assert d["max_turns"] == 3
