# test_policy_advisor.py
# Tests for PolicyAdvisor, policy rules, load_policy, and ScopePolicy.
"""Tests for the apex_host.policy package.

Acceptance criteria tested here:
  - nmap against config.target → approved
  - nmap against a different IP → blocked (target_in_scope)
  - ffuf with -w flag → blocked (no_password_list)
  - rm → blocked (no_destructive_command)
  - Missing policy file → conservative default still blocks off-scope targets
  - nc against target → approved
  - curl against target → approved
  - Tool in require_policy_approval_for → needs_human_review
  - policy_enabled=False → approved (bypasses all checks)
  - Sensitive path in args → blocked (no_sensitive_data)
  - allow_password_lists=True → wordlist flag approved
  - allow_sensitive_data_access=True → sensitive path approved
  - Infrastructure check: IP in args outside scope → blocked
  - load_policy when YAML exists → policy_loaded=True
  - load_policy when YAML missing → policy_loaded=False (conservative default)
  - ScopePolicy fields are correct types
  - PolicyDecision properties (is_approved, is_blocked, needs_review)
  - PolicyStatus enum values
"""
from __future__ import annotations

import pathlib
import tempfile
from typing import Any
from unittest.mock import patch


from apex_host.config import ApexConfig
from apex_host.policy import (
    PolicyAdvisor,
    PolicyDecision,
    PolicyRule,
    PolicyStatus,
    ScopePolicy,
    load_policy,
)
from apex_host.policy.policy_loader import _ALWAYS_BLOCKED_TOOLS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**kwargs: Any) -> ApexConfig:
    """Return an ApexConfig with safe defaults; override via kwargs."""
    defaults: dict[str, Any] = {
        "target": "10.10.10.14",
        "dry_run": True,
    }
    defaults.update(kwargs)
    return ApexConfig(**defaults)


def _make_task(tool: str, target: str = "", args: list[str] | None = None) -> Any:
    """Build a minimal duck-typed TaskSpec with a params dict."""
    class _FakeTask:
        params: dict[str, Any]
    t = _FakeTask()
    t.params = {"tool": tool, "target": target, "args": args or [], "parser": "command"}
    return t


def _make_policy(
    config: ApexConfig,
    *,
    allow_password_lists: bool = False,
    allow_sensitive_data_access: bool = False,
    require_review_for: list[str] | None = None,
    policy_loaded: bool = False,
) -> ScopePolicy:
    """Build a ScopePolicy directly (bypasses loader) for unit tests."""
    return ScopePolicy(
        allowed_targets=frozenset({config.target}),
        blocked_tools=_ALWAYS_BLOCKED_TOOLS,
        allow_password_lists=allow_password_lists,
        allow_sensitive_data_access=allow_sensitive_data_access,
        require_review_for=require_review_for or [],
        policy_loaded=policy_loaded,
        policy_source="test",
    )


def _make_advisor(config: ApexConfig, **policy_kwargs: Any) -> PolicyAdvisor:
    policy = _make_policy(config, **policy_kwargs)
    return PolicyAdvisor(policy, config)


def _fake_evidence() -> Any:
    """Minimal stub for EvidenceBundle — not used by current rules."""
    class _Stub:
        entries: list[Any] = []
        subgraph: Any = None
    return _Stub()


# ---------------------------------------------------------------------------
# PolicyStatus and PolicyDecision
# ---------------------------------------------------------------------------

class TestPolicyModels:
    def test_status_values(self) -> None:
        assert PolicyStatus.approved == "approved"
        assert PolicyStatus.blocked == "blocked"
        assert PolicyStatus.needs_human_review == "needs_human_review"

    def test_decision_is_approved(self) -> None:
        d = PolicyDecision(status=PolicyStatus.approved, rule_name="r", reason="ok")
        assert d.is_approved
        assert not d.is_blocked
        assert not d.needs_review

    def test_decision_is_blocked(self) -> None:
        d = PolicyDecision(status=PolicyStatus.blocked, rule_name="r", reason="no")
        assert d.is_blocked
        assert not d.is_approved
        assert not d.needs_review

    def test_decision_needs_review(self) -> None:
        d = PolicyDecision(
            status=PolicyStatus.needs_human_review, rule_name="r", reason="review"
        )
        assert d.needs_review
        assert not d.is_approved
        assert not d.is_blocked

    def test_decision_default_fields(self) -> None:
        d = PolicyDecision(status=PolicyStatus.approved, rule_name="r", reason="ok")
        assert d.task_tool == ""
        assert d.task_target == ""

    def test_policy_rule_enabled_default(self) -> None:
        rule = PolicyRule(name="no_rm", description="block rm")
        assert rule.enabled is True

    def test_scope_policy_fields(self) -> None:
        cfg = _make_config()
        p = _make_policy(cfg)
        assert isinstance(p.allowed_targets, frozenset)
        assert isinstance(p.blocked_tools, frozenset)
        assert isinstance(p.allow_password_lists, bool)
        assert isinstance(p.allow_sensitive_data_access, bool)
        assert isinstance(p.require_review_for, list)
        assert isinstance(p.policy_loaded, bool)
        assert isinstance(p.policy_source, str)


# ---------------------------------------------------------------------------
# nmap against own target → approved
# ---------------------------------------------------------------------------

class TestApprovedPaths:
    def test_nmap_against_target_approved(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("nmap", target="10.10.10.14", args=["-sV", "-T4", "10.10.10.14"])
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        assert decision.is_approved, f"Expected approved; got {decision}"

    def test_nc_against_target_approved(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("nc", target="10.10.10.14", args=["-nv", "10.10.10.14", "23"])
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        assert decision.is_approved

    def test_curl_against_target_approved(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("curl", target="10.10.10.14", args=["-s", "-I", "http://10.10.10.14"])
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.is_approved

    def test_approved_rule_name_for_safe_recon(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("nmap", target="10.10.10.14", args=["-sV", "10.10.10.14"])
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        assert decision.rule_name == "safe_recon_allowed"

    def test_python3_against_target_approved(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("python3", target="10.10.10.14", args=["script.py", "10.10.10.14"])
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        assert decision.is_approved


# ---------------------------------------------------------------------------
# Off-scope target → blocked
# ---------------------------------------------------------------------------

class TestTargetInScope:
    def test_nmap_against_different_ip_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("nmap", target="192.168.1.1", args=["-sV", "192.168.1.1"])
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        assert decision.is_blocked
        assert decision.rule_name == "target_in_scope"

    def test_target_not_in_scope_message(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("curl", target="8.8.8.8")
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.is_blocked
        assert "8.8.8.8" in decision.reason

    def test_no_target_field_passes_scope_check(self) -> None:
        """A task with no target field is not blocked by target_in_scope."""
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("python3", target="")
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        # No target field: passes scope rule; passes all others; default allow.
        assert decision.is_approved


# ---------------------------------------------------------------------------
# No attacking infrastructure (IP in args)
# ---------------------------------------------------------------------------

class TestNoAttackingInfrastructure:
    def test_ip_in_args_outside_scope_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        # no explicit target field, but arg contains an out-of-scope IP
        task = _make_task("nmap", target="", args=["-sV", "10.0.0.1"])
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        assert decision.is_blocked
        assert decision.rule_name == "no_attacking_infrastructure"

    def test_ip_in_scope_in_args_is_allowed(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("nmap", target="10.10.10.14", args=["-sV", "10.10.10.14"])
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        assert decision.is_approved


# ---------------------------------------------------------------------------
# Destructive commands → blocked
# ---------------------------------------------------------------------------

class TestNoDestructiveCommand:
    def test_rm_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("rm", target="10.10.10.14", args=["-rf", "/tmp/x"])
        decision = advisor.review_task(task, "execute", _fake_evidence(), cfg)
        assert decision.is_blocked
        assert decision.rule_name == "no_destructive_command"

    def test_mkfs_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("mkfs", args=["/dev/sda"])
        decision = advisor.review_task(task, "execute", _fake_evidence(), cfg)
        assert decision.is_blocked

    def test_dd_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("dd", args=["if=/dev/zero", "of=/dev/sda"])
        decision = advisor.review_task(task, "execute", _fake_evidence(), cfg)
        assert decision.is_blocked

    def test_hydra_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("hydra", target="10.10.10.14", args=["-l", "root"])
        decision = advisor.review_task(task, "credential", _fake_evidence(), cfg)
        assert decision.is_blocked

    def test_msfconsole_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("msfconsole", target="10.10.10.14")
        decision = advisor.review_task(task, "priv_esc", _fake_evidence(), cfg)
        assert decision.is_blocked


# ---------------------------------------------------------------------------
# Password list / wordlist → blocked unless permitted
# ---------------------------------------------------------------------------

class TestNoPasswordList:
    def test_ffuf_with_w_flag_blocked_by_default(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task(
            "ffuf",
            target="10.10.10.14",
            args=["-u", "http://10.10.10.14/FUZZ", "-w", "wordlist.txt"],
        )
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.is_blocked
        assert decision.rule_name == "no_password_list"

    def test_ffuf_with_wordlist_longform_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task(
            "ffuf",
            target="10.10.10.14",
            args=["-u", "http://10.10.10.14/FUZZ", "--wordlist", "list.txt"],
        )
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.is_blocked
        assert "-w" in decision.reason or "--wordlist" in decision.reason

    def test_allow_password_lists_true_permits_wordlist(self) -> None:
        cfg = _make_config(target="10.10.10.14", allow_password_lists=True)
        advisor = _make_advisor(cfg, allow_password_lists=True)
        task = _make_task(
            "ffuf",
            target="10.10.10.14",
            args=["-u", "http://10.10.10.14/FUZZ", "-w", "wordlist.txt"],
        )
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.is_approved

    def test_no_wordlist_flag_passes(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task(
            "ffuf",
            target="10.10.10.14",
            args=["-u", "http://10.10.10.14/FUZZ", "-mc", "200"],
        )
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        # ffuf is not a safe-recon tool → falls through to default_allow
        assert decision.is_approved


# ---------------------------------------------------------------------------
# Sensitive data paths → blocked unless permitted
# ---------------------------------------------------------------------------

class TestNoSensitiveData:
    def test_etc_shadow_blocked_by_default(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("curl", target="10.10.10.14", args=["http://10.10.10.14/etc/shadow"])
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.is_blocked
        assert decision.rule_name == "no_sensitive_data"

    def test_ssh_private_key_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task(
            "curl", target="10.10.10.14", args=["http://10.10.10.14/.ssh/id_rsa"]
        )
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.is_blocked

    def test_aws_credentials_blocked(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task(
            "curl",
            target="10.10.10.14",
            args=["http://10.10.10.14/.aws/credentials"],
        )
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.is_blocked

    def test_allow_sensitive_data_access_true_permits(self) -> None:
        cfg = _make_config(target="10.10.10.14", allow_sensitive_data_access=True)
        advisor = _make_advisor(cfg, allow_sensitive_data_access=True)
        task = _make_task(
            "curl", target="10.10.10.14", args=["http://10.10.10.14/etc/shadow"]
        )
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.is_approved


# ---------------------------------------------------------------------------
# require_policy_approval_for → needs_human_review
# ---------------------------------------------------------------------------

class TestRequireReview:
    def test_tool_in_require_list_returns_needs_review(self) -> None:
        cfg = _make_config(
            target="10.10.10.14",
            require_policy_approval_for=["gobuster"],
        )
        advisor = _make_advisor(cfg, require_review_for=["gobuster"])
        task = _make_task("gobuster", target="10.10.10.14", args=["dir", "-u", "http://10.10.10.14"])
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert decision.needs_review
        assert decision.rule_name == "require_review"

    def test_tool_not_in_require_list_passes(self) -> None:
        cfg = _make_config(
            target="10.10.10.14",
            require_policy_approval_for=["gobuster"],
        )
        advisor = _make_advisor(cfg, require_review_for=["gobuster"])
        task = _make_task("curl", target="10.10.10.14")
        decision = advisor.review_task(task, "web", _fake_evidence(), cfg)
        assert not decision.needs_review

    def test_empty_require_list_no_review_triggered(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        task = _make_task("nmap", target="10.10.10.14")
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        assert not decision.needs_review


# ---------------------------------------------------------------------------
# policy_enabled=False bypasses all checks
# ---------------------------------------------------------------------------

class TestPolicyDisabled:
    def test_policy_disabled_approves_everything(self) -> None:
        cfg = _make_config(target="10.10.10.14", policy_enabled=False)
        advisor = _make_advisor(cfg)
        # Would normally be blocked (different target + destructive tool)
        task = _make_task("rm", target="8.8.8.8", args=["-rf", "/"])
        decision = advisor.review_task(task, "execute", _fake_evidence(), cfg)
        assert decision.is_approved
        assert decision.rule_name == "policy_disabled"

    def test_policy_disabled_rule_name(self) -> None:
        cfg = _make_config(target="10.10.10.14", policy_enabled=False)
        advisor = _make_advisor(cfg)
        task = _make_task("hydra", target="10.10.10.14")
        decision = advisor.review_task(task, "credential", _fake_evidence(), cfg)
        assert decision.rule_name == "policy_disabled"


# ---------------------------------------------------------------------------
# load_policy — YAML present vs missing
# ---------------------------------------------------------------------------

class TestLoadPolicy:
    def test_load_policy_with_existing_yaml_sets_loaded_true(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("rules:\n  - name: test_rule\n    description: test\n")
            yaml_path = f.name
        cfg = _make_config(target="10.10.10.14", policy_file=yaml_path)
        policy = load_policy(cfg)
        assert policy.policy_loaded is True
        assert policy.policy_source == yaml_path

    def test_load_policy_missing_file_sets_loaded_false(self) -> None:
        cfg = _make_config(
            target="10.10.10.14",
            policy_file="/nonexistent/path/policy.yaml",
        )
        policy = load_policy(cfg)
        assert policy.policy_loaded is False
        assert policy.policy_source == "conservative_default"

    def test_load_policy_no_file_conservative_default(self) -> None:
        # Ensure no YAML file interferes by using a non-existent path and no
        # knowledge_root, and patching away the default fallback.
        cfg = _make_config(target="10.10.10.14")
        with patch(
            "apex_host.policy.policy_loader._DEFAULT_POLICY_YAML",
            pathlib.Path("/no/such/file.yaml"),
        ):
            policy = load_policy(cfg)
        assert policy.policy_loaded is False

    def test_load_policy_allowed_target_is_config_target(self) -> None:
        cfg = _make_config(target="10.10.10.99", policy_file="/no/file.yaml")
        policy = load_policy(cfg)
        assert "10.10.10.99" in policy.allowed_targets

    def test_load_policy_blocked_tools_contains_rm(self) -> None:
        cfg = _make_config(target="10.10.10.14", policy_file="/no/file.yaml")
        policy = load_policy(cfg)
        assert "rm" in policy.blocked_tools

    def test_load_policy_respects_allow_password_lists_false(self) -> None:
        cfg = _make_config(target="10.10.10.14", allow_password_lists=False)
        policy = load_policy(cfg)
        assert policy.allow_password_lists is False

    def test_load_policy_respects_allow_password_lists_true(self) -> None:
        cfg = _make_config(target="10.10.10.14", allow_password_lists=True)
        policy = load_policy(cfg)
        assert policy.allow_password_lists is True

    def test_load_policy_conservative_blocks_off_scope_even_without_yaml(self) -> None:
        """Even with policy_loaded=False, the advisor still blocks off-scope targets."""
        cfg = _make_config(target="10.10.10.14", policy_file="/no/file.yaml")
        policy = load_policy(cfg)
        advisor = PolicyAdvisor(policy, cfg)
        task = _make_task("nmap", target="192.168.1.100")
        decision = advisor.review_task(task, "recon", _fake_evidence(), cfg)
        assert decision.is_blocked

    def test_load_policy_via_knowledge_root(self, tmp_path: pathlib.Path) -> None:
        policy_dir = tmp_path / "policy_db" / "compiled"
        policy_dir.mkdir(parents=True)
        (policy_dir / "hackthebox_lab.yaml").write_text(
            "rules:\n  - name: htb_only\n    description: htb\n", encoding="utf-8"
        )
        cfg = _make_config(
            target="10.10.10.14",
            knowledge_root=str(tmp_path),
        )
        policy = load_policy(cfg)
        assert policy.policy_loaded is True
        assert "hackthebox_lab.yaml" in policy.policy_source

    def test_load_policy_malformed_yaml_returns_conservative_default(
        self, tmp_path: pathlib.Path
    ) -> None:
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_bytes(b"\x00\xff\xfe")  # binary garbage
        cfg = _make_config(target="10.10.10.14", policy_file=str(bad_yaml))
        policy = load_policy(cfg)
        assert policy.policy_loaded is False


# ---------------------------------------------------------------------------
# PolicyAdvisor.policy property
# ---------------------------------------------------------------------------

class TestAdvisorProperty:
    def test_policy_property_returns_scope_policy(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        p = advisor.policy
        assert isinstance(p, ScopePolicy)
        assert "10.10.10.14" in p.allowed_targets

    def test_advisor_is_stateless_between_calls(self) -> None:
        cfg = _make_config(target="10.10.10.14")
        advisor = _make_advisor(cfg)
        t1 = _make_task("nmap", target="10.10.10.14")
        t2 = _make_task("rm", target="10.10.10.14")
        d1 = advisor.review_task(t1, "recon", _fake_evidence(), cfg)
        d2 = advisor.review_task(t2, "recon", _fake_evidence(), cfg)
        assert d1.is_approved
        assert d2.is_blocked
        # First decision unchanged after second call
        assert d1.is_approved


# ---------------------------------------------------------------------------
# ApexConfig new policy fields
# ---------------------------------------------------------------------------

class TestApexConfigPolicyFields:
    def test_policy_enabled_default_true(self) -> None:
        cfg = ApexConfig(target="10.10.10.14")
        assert cfg.policy_enabled is True

    def test_policy_file_default_none(self) -> None:
        cfg = ApexConfig(target="10.10.10.14")
        assert cfg.policy_file is None

    def test_allow_sensitive_data_access_default_false(self) -> None:
        cfg = ApexConfig(target="10.10.10.14")
        assert cfg.allow_sensitive_data_access is False

    def test_allow_password_lists_default_false(self) -> None:
        cfg = ApexConfig(target="10.10.10.14")
        assert cfg.allow_password_lists is False

    def test_require_policy_approval_for_default_empty(self) -> None:
        cfg = ApexConfig(target="10.10.10.14")
        assert cfg.require_policy_approval_for == []

    def test_require_policy_approval_for_independent_instances(self) -> None:
        c1 = ApexConfig(target="10.10.10.14")
        c2 = ApexConfig(target="10.10.10.15")
        c1.require_policy_approval_for.append("gobuster")
        assert c2.require_policy_approval_for == []
