# test_eval_preflight.py
# Tests for apex_host/eval/preflight.py (Infra Phase 9) — the structured PreflightCheck/PreflightResult models and every individual check function. Distinct from test_preflight.py, which covers the older, unrelated apex_host/tools/preflight.py tool-availability checker.
"""Infra Phase 9 tests for the reusable preflight module.

Covers: the PreflightCheck/PreflightResult models (pass/fail/warning
semantics, human/JSON output, secret-free serialization); configuration
checks per mode; report-directory writability (creation, unwritable
detection, no-overwrite, no recursive chown); compiled-knowledge
validation (valid/missing/malformed, raw-corpus-absence tolerance);
policy validation (valid/missing/malformed, optional-vs-required); Kali
health (valid/unavailable/malformed/wrong-service, required-tool
absence, no token sent); remote smoke (real success, non-zero failure,
timeout failure, backend-mismatch failure, client closure, no target
contacted); and the live-confirmation safeguard.
"""
from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Callable

import httpx
import pytest

from apex_host.config import ApexConfig
from apex_host.eval.preflight import (
    PreflightCheck,
    PreflightResult,
    check_compiled_knowledge,
    check_configuration,
    check_llm_readiness,
    check_live_confirmation,
    check_policy,
    check_remote_backend_selected,
    check_remote_smoke,
    check_report_directory,
    check_tool_service_health,
    run_local_checks,
    run_smoke_checks,
)
from apex_host.types import ToolCommand, ToolResult


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


class TestPreflightCheck:
    def test_required_pass(self) -> None:
        c = PreflightCheck(name="x", passed=True, detail="ok")
        assert c.required is True
        assert c.to_dict() == {"name": "x", "passed": True, "detail": "ok", "required": True}

    def test_required_failure(self) -> None:
        c = PreflightCheck(name="x", passed=False, detail="broken")
        assert c.to_dict()["passed"] is False

    def test_optional_warning(self) -> None:
        c = PreflightCheck(name="x", passed=False, detail="skipped", required=False)
        assert c.required is False
        assert c.to_dict()["required"] is False


class TestPreflightResult:
    def test_all_required_pass_is_overall_pass(self) -> None:
        r = PreflightResult([PreflightCheck("a", True, "ok"), PreflightCheck("b", True, "ok")])
        assert r.passed is True
        assert r.failed_required == []

    def test_one_required_failure_fails_overall(self) -> None:
        r = PreflightResult([PreflightCheck("a", True, "ok"), PreflightCheck("b", False, "bad")])
        assert r.passed is False
        assert [c.name for c in r.failed_required] == ["b"]

    def test_optional_failure_is_warning_not_blocker(self) -> None:
        r = PreflightResult([PreflightCheck("a", False, "meh", required=False)])
        assert r.passed is True
        assert [c.name for c in r.warnings] == ["a"]
        assert r.failed_required == []

    def test_required_count_excludes_optional(self) -> None:
        r = PreflightResult([
            PreflightCheck("a", True, "ok"),
            PreflightCheck("b", True, "ok", required=False),
        ])
        assert r.required_count == 1

    def test_human_output_shows_pass_fail_tags(self) -> None:
        r = PreflightResult([PreflightCheck("a", True, "ok"), PreflightCheck("b", False, "bad")])
        text = r.format_text()
        assert "[PASS] a" in text
        assert "[FAIL] b" in text
        assert "bad" in text

    def test_human_output_shows_warn_tag_for_optional_failure(self) -> None:
        r = PreflightResult([PreflightCheck("a", False, "meh", required=False)])
        text = r.format_text()
        assert "[WARN] a" in text

    def test_human_output_summary_line_on_pass(self) -> None:
        r = PreflightResult([PreflightCheck("a", True, "ok")])
        assert "Preflight passed: 1 required check(s)" in r.format_text()

    def test_human_output_summary_line_on_fail(self) -> None:
        r = PreflightResult([PreflightCheck("a", False, "bad")])
        assert "Preflight FAILED" in r.format_text()
        assert "(a)" in r.format_text()

    def test_json_output_is_valid_json(self) -> None:
        r = PreflightResult([PreflightCheck("a", True, "ok")])
        data = json.loads(json.dumps(r.to_dict()))
        assert data["passed"] is True
        assert data["checks"][0]["name"] == "a"

    def test_secret_free_serialization(self) -> None:
        r = PreflightResult([PreflightCheck("configuration", True, "valid")])
        assert "tool_service_token" not in r.to_dict()


# ---------------------------------------------------------------------------
# Configuration checks
# ---------------------------------------------------------------------------


class TestCheckConfiguration:
    def test_valid_config_passes(self) -> None:
        result = check_configuration(ApexConfig(target="10.0.0.1"))
        assert result.passed is True

    def test_invalid_combination_fails(self) -> None:
        config = ApexConfig(target="10.0.0.1", tool_backend="remote", dry_run=False)
        result = check_configuration(config)
        assert result.passed is False
        assert "tool_service_url" in result.detail or "bearer token" in result.detail


class TestCheckRemoteBackendSelected:
    def test_remote_passes(self) -> None:
        result = check_remote_backend_selected(ApexConfig(target="x", tool_backend="remote"))
        assert result.passed is True

    def test_local_fails(self) -> None:
        result = check_remote_backend_selected(ApexConfig(target="x", tool_backend="local"))
        assert result.passed is False
        assert "remote" in result.detail


class TestCheckLiveConfirmation:
    def test_confirmed_and_not_dry_run_passes(self) -> None:
        result = check_live_confirmation(confirmed=True, dry_run=False)
        assert result.passed is True

    def test_dry_run_still_true_fails(self) -> None:
        result = check_live_confirmation(confirmed=True, dry_run=True)
        assert result.passed is False
        assert "--no-dry-run" in result.detail

    def test_not_confirmed_fails(self) -> None:
        result = check_live_confirmation(confirmed=False, dry_run=False)
        assert result.passed is False
        assert "confirm-live" in result.detail

    def test_neither_fails_on_dry_run_first(self) -> None:
        result = check_live_confirmation(confirmed=False, dry_run=True)
        assert result.passed is False


class TestLLMReadiness:
    def test_disabled_never_requires_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = ApexConfig(target="x", use_llm=False)
        assert check_llm_readiness(config).passed is True

    def test_fake_provider_never_requires_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = ApexConfig(target="x", use_llm=True, llm_provider="fake")
        assert check_llm_readiness(config).passed is True

    def test_real_provider_without_key_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = ApexConfig(target="x", use_llm=True, llm_provider="openai")
        result = check_llm_readiness(config)
        assert result.passed is False
        assert "OPENAI_API_KEY" in result.detail

    def test_real_provider_with_key_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-abc")
        config = ApexConfig(target="x", use_llm=True, llm_provider="openai")
        assert check_llm_readiness(config).passed is True


# ---------------------------------------------------------------------------
# Report directory
# ---------------------------------------------------------------------------


class TestCheckReportDirectory:
    def test_creates_missing_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "new_reports_dir"
        assert not target.exists()
        result = check_report_directory(default_dir=str(target))
        assert result.passed is True
        assert target.is_dir()

    def test_existing_writable_directory_passes(self, tmp_path: Path) -> None:
        result = check_report_directory(default_dir=str(tmp_path))
        assert result.passed is True

    def test_detects_unwritable_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "readonly"
        target.mkdir()
        target.chmod(stat.S_IREAD | stat.S_IEXEC)
        try:
            result = check_report_directory(default_dir=str(target))
            assert result.passed is False
            assert "not writable" in result.detail or "cannot create" in result.detail
        finally:
            target.chmod(stat.S_IRWXU)  # restore so tmp_path cleanup can remove it

    def test_validates_report_path_parent(self, tmp_path: Path) -> None:
        report_path = tmp_path / "sub" / "run.json"
        result = check_report_directory(default_dir=str(tmp_path), report_path=str(report_path))
        assert result.passed is True
        assert (tmp_path / "sub").is_dir()

    def test_validates_graph_path_parent(self, tmp_path: Path) -> None:
        graph_path = tmp_path / "graphs" / "ekg.json"
        result = check_report_directory(default_dir=str(tmp_path), graph_path=str(graph_path))
        assert result.passed is True
        assert (tmp_path / "graphs").is_dir()

    def test_preserves_existing_files(self, tmp_path: Path) -> None:
        existing = tmp_path / "existing_report.json"
        existing.write_text('{"real": "report"}')
        check_report_directory(default_dir=str(tmp_path))
        assert existing.read_text() == '{"real": "report"}'

    def test_does_not_recursively_change_permissions(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        file_in_sub = sub / "file.txt"
        file_in_sub.write_text("data")
        before = file_in_sub.stat().st_mode
        check_report_directory(default_dir=str(tmp_path))
        after = file_in_sub.stat().st_mode
        assert before == after

    def test_marker_file_removed_after_check(self, tmp_path: Path) -> None:
        check_report_directory(default_dir=str(tmp_path))
        markers = list(tmp_path.glob(".apex_preflight_write_test_*"))
        assert markers == []


# ---------------------------------------------------------------------------
# Compiled knowledge
# ---------------------------------------------------------------------------


def _write_valid_family(root: Path, family: str, filename: str, n: int) -> None:
    d = root / family / "compiled"
    d.mkdir(parents=True, exist_ok=True)
    with (d / filename).open("w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(json.dumps({"source_family": family, "source_type": "x", "id": i}) + "\n")


def _write_all_valid(root: Path) -> None:
    _write_valid_family(root, "policy_db", "policy_records.jsonl", 1)
    (root / "policy_db" / "compiled" / "hackthebox_lab.yaml").write_text("rules: []\n")
    _write_valid_family(root, "methodology_db", "methodology_chunks.jsonl", 1)
    _write_valid_family(root, "intel_db", "attack_techniques.jsonl", 100)
    _write_valid_family(root, "intel_db", "cwe_weaknesses.jsonl", 100)
    _write_valid_family(root, "intel_db", "capec_patterns.jsonl", 50)
    _write_valid_family(root, "intel_db", "cve_slim.jsonl", 1000)
    _write_valid_family(root, "payload_db", "payload_records.jsonl", 100)
    _write_valid_family(root, "payload_db", "wordlist_manifest.jsonl", 10)


class TestCheckCompiledKnowledge:
    def test_not_configured_is_a_soft_pass(self) -> None:
        result = check_compiled_knowledge(None)
        assert result.passed is True
        assert result.required is False

    def test_valid_compiled_knowledge_passes(self, tmp_path: Path) -> None:
        _write_all_valid(tmp_path)
        result = check_compiled_knowledge(str(tmp_path))
        assert result.passed is True
        assert result.required is True

    def test_missing_file_fails(self, tmp_path: Path) -> None:
        _write_all_valid(tmp_path)
        (tmp_path / "intel_db" / "compiled" / "cve_slim.jsonl").unlink()
        result = check_compiled_knowledge(str(tmp_path))
        assert result.passed is False
        assert "cve_slim.jsonl" in result.detail

    def test_malformed_json_fails(self, tmp_path: Path) -> None:
        _write_all_valid(tmp_path)
        (tmp_path / "policy_db" / "compiled" / "policy_records.jsonl").write_text("{not valid json\n")
        result = check_compiled_knowledge(str(tmp_path))
        assert result.passed is False

    def test_raw_corpus_absence_does_not_fail(self, tmp_path: Path) -> None:
        _write_all_valid(tmp_path)
        (tmp_path / "intel_db" / "cve").mkdir(parents=True, exist_ok=True)  # raw dir, no compiled data inside
        result = check_compiled_knowledge(str(tmp_path))
        assert result.passed is True

    def test_verifier_record_count_represented_in_detail(self, tmp_path: Path) -> None:
        _write_all_valid(tmp_path)
        result = check_compiled_knowledge(str(tmp_path))
        assert "records" in result.detail


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class TestCheckPolicy:
    def test_valid_policy_passes(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("allowed_targets: [10.0.0.1]\n")
        config = ApexConfig(target="10.0.0.1", policy_file=str(policy_file))
        result = check_policy(config, required=False)
        assert result.passed is True
        assert result.required is True  # a configured, resolved path is always required once found

    def test_missing_configured_policy_fails(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist.yaml"
        config = ApexConfig(target="10.0.0.1", policy_file=str(missing))
        result = check_policy(config, required=False)
        assert result.passed is False
        assert "not found" in result.detail

    def test_malformed_policy_fails(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "bad.yaml"
        policy_file.write_text("key: [unterminated\n")
        config = ApexConfig(target="10.0.0.1", policy_file=str(policy_file))
        result = check_policy(config, required=False)
        assert result.passed is False

    def test_no_policy_configured_optional_mode_passes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)  # no conventional knowledge/policy_db path here
        config = ApexConfig(target="10.0.0.1")
        result = check_policy(config, required=False)
        assert result.passed is True
        assert result.required is False

    def test_no_policy_configured_required_mode_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        config = ApexConfig(target="10.0.0.1")
        result = check_policy(config, required=True)
        assert result.passed is False
        assert result.required is True

    def test_empty_mapping_policy_fails(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "empty.yaml"
        policy_file.write_text("")
        config = ApexConfig(target="10.0.0.1", policy_file=str(policy_file))
        result = check_policy(config, required=False)
        assert result.passed is False


# ---------------------------------------------------------------------------
# Tool-service health (mock transports — never a real socket)
# ---------------------------------------------------------------------------


def _health_client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestCheckToolServiceHealth:
    @pytest.mark.asyncio
    async def test_valid_response_passes(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert "Authorization" not in request.headers, "must never send the bearer token to /health"
            return httpx.Response(200, json={"status": "ok", "service": "apex-tool-service", "tools": {"curl": True}})

        result = await check_tool_service_health("http://kali:8080", client=_health_client(handler))
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_service_unavailable_fails(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        result = await check_tool_service_health("http://kali:8080", client=_health_client(handler))
        assert result.passed is False
        assert "failed" in result.detail

    @pytest.mark.asyncio
    async def test_malformed_response_fails(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not json")

        result = await check_tool_service_health("http://kali:8080", client=_health_client(handler))
        assert result.passed is False
        assert "non-JSON" in result.detail

    @pytest.mark.asyncio
    async def test_wrong_service_name_fails(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": "ok", "service": "some-other-service", "tools": {}})

        result = await check_tool_service_health("http://kali:8080", client=_health_client(handler))
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_wrong_status_fails(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": "degraded", "service": "apex-tool-service", "tools": {}})

        result = await check_tool_service_health("http://kali:8080", client=_health_client(handler))
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_required_tool_unavailable_fails(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": "ok", "service": "apex-tool-service", "tools": {"curl": False}})

        result = await check_tool_service_health("http://kali:8080", client=_health_client(handler))
        assert result.passed is False
        assert "curl" in result.detail

    @pytest.mark.asyncio
    async def test_http_error_status_fails(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        result = await check_tool_service_health("http://kali:8080", client=_health_client(handler))
        assert result.passed is False
        assert "503" in result.detail

    @pytest.mark.asyncio
    async def test_no_url_configured_fails(self) -> None:
        result = await check_tool_service_health(None)
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_malformed_url_fails(self) -> None:
        result = await check_tool_service_health("not-a-url")
        assert result.passed is False


# ---------------------------------------------------------------------------
# Remote smoke — fake backend seam, plus one real local execution
# ---------------------------------------------------------------------------


class _FakeBackend:
    """Minimal ToolBackend stand-in with a pre-baked result."""

    name = "fake"

    def __init__(self, result: ToolResult) -> None:
        self._result = result
        self.closed = False

    async def execute(
        self, tool: str, arguments: list[str], *,
        timeout_seconds: float | None = None, stdin: str | None = None,
    ) -> ToolResult:
        return self._result

    async def aclose(self) -> None:
        self.closed = True


def _fake_result(**overrides: object) -> ToolResult:
    defaults: dict[str, object] = dict(
        command=ToolCommand(tool="curl", args=["--version"]),
        stdout="curl 8.0.0\n", stderr="", returncode=0, duration_seconds=0.01,
        dry_run=False, error=None, timed_out=False, backend="kali-service",
    )
    defaults.update(overrides)
    return ToolResult(**defaults)  # type: ignore[arg-type]


class TestCheckRemoteSmoke:
    @pytest.mark.asyncio
    async def test_real_local_execution_succeeds(self) -> None:
        """Uses the REAL LocalToolBackend with a real, safe, no-network
        `curl --version` — proves the full check_remote_smoke path end to
        end without any mock, and without contacting any target."""
        config = ApexConfig(target="x", dry_run=False, tool_backend="local", allowed_tools=["curl"])
        result = await check_remote_smoke(config)
        assert result.passed is True
        assert "local" in result.detail

    @pytest.mark.asyncio
    async def test_dry_run_backend_mismatch_fails(self) -> None:
        config = ApexConfig(target="x", dry_run=True)
        result = await check_remote_smoke(config)
        assert result.passed is False
        assert "dry-run" in result.detail

    @pytest.mark.asyncio
    async def test_non_zero_returncode_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.eval.preflight as preflight_mod

        fake = _FakeBackend(_fake_result(returncode=1, error="boom"))
        monkeypatch.setattr(preflight_mod, "select_runtime_backend", lambda config: fake)
        result = await check_remote_smoke(ApexConfig(target="x", dry_run=False, tool_backend="remote"))
        assert result.passed is False
        assert "exited 1" in result.detail
        assert fake.closed is True

    @pytest.mark.asyncio
    async def test_timeout_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.eval.preflight as preflight_mod

        fake = _FakeBackend(_fake_result(timed_out=True, returncode=-1))
        monkeypatch.setattr(preflight_mod, "select_runtime_backend", lambda config: fake)
        result = await check_remote_smoke(ApexConfig(target="x", dry_run=False, tool_backend="remote"))
        assert result.passed is False
        assert "timed out" in result.detail

    @pytest.mark.asyncio
    async def test_missing_token_fails_cleanly_no_traceback(self) -> None:
        """RemoteToolBackend.__init__ raises ValueError fast when no token
        is configured — this must become a clean PreflightCheck failure,
        never an unhandled exception, and never send a request."""
        config = ApexConfig(
            target="x", dry_run=False, tool_backend="remote",
            tool_service_url="http://kali:8080", tool_service_token="",
        )
        result = await check_remote_smoke(config)
        assert result.passed is False
        assert "token" in result.detail.lower()

    @pytest.mark.asyncio
    async def test_client_closed_on_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.eval.preflight as preflight_mod

        fake = _FakeBackend(_fake_result())
        monkeypatch.setattr(preflight_mod, "select_runtime_backend", lambda config: fake)
        await check_remote_smoke(ApexConfig(target="x", dry_run=False, tool_backend="remote"))
        assert fake.closed is True

    @pytest.mark.asyncio
    async def test_no_output_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import apex_host.eval.preflight as preflight_mod

        fake = _FakeBackend(_fake_result(stdout="", stderr=""))
        monkeypatch.setattr(preflight_mod, "select_runtime_backend", lambda config: fake)
        result = await check_remote_smoke(ApexConfig(target="x", dry_run=False, tool_backend="remote"))
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_no_target_contacted(self) -> None:
        """The hardcoded smoke command is curl --version — structurally
        incapable of contacting any target, real or otherwise."""
        config = ApexConfig(target="10.10.10.99", dry_run=False, tool_backend="local", allowed_tools=["curl"])
        result = await check_remote_smoke(config)
        assert "10.10.10.99" not in result.detail
        assert result.passed is True


# ---------------------------------------------------------------------------
# Mode-level aggregate runners
# ---------------------------------------------------------------------------


class TestRunLocalChecks:
    def test_check_mode_does_not_require_target(self, tmp_path: Path) -> None:
        from apex_host.config_env import CONFIG_CHECK_TARGET_PLACEHOLDER

        config = ApexConfig(target=CONFIG_CHECK_TARGET_PLACEHOLDER)
        checks = run_local_checks(config, default_report_dir=str(tmp_path))
        names = [c.name for c in checks]
        assert "configuration" in names
        assert all(c.name != "Kali health" for c in checks)  # local checks never touch the network

    def test_policy_required_flag_propagates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        config = ApexConfig(target="x")
        checks = run_local_checks(config, default_report_dir=str(tmp_path), policy_required=True)
        policy_check = next(c for c in checks if c.name == "policy")
        assert policy_check.passed is False


class TestRunSmokeChecks:
    @pytest.mark.asyncio
    async def test_smoke_includes_local_and_remote_checks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": "ok", "service": "apex-tool-service", "tools": {"curl": True}})

        import apex_host.eval.preflight as preflight_mod

        health_client = _health_client(handler)

        async def _patched_health(url: str | None, **kwargs: object) -> PreflightCheck:
            return await check_tool_service_health(url, client=health_client)

        monkeypatch.setattr(preflight_mod, "check_tool_service_health", _patched_health)
        fake = _FakeBackend(_fake_result())
        monkeypatch.setattr(preflight_mod, "select_runtime_backend", lambda config: fake)

        config = ApexConfig(
            target="x", dry_run=False, tool_backend="remote",
            tool_service_url="http://kali:8080", tool_service_token="t",
        )
        result = await run_smoke_checks(config, default_report_dir=str(tmp_path))
        names = [c.name for c in result.checks]
        assert "configuration" in names
        assert "Kali health" in names
        assert "remote tool smoke" in names
