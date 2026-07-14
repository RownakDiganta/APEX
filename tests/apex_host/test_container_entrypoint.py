# test_container_entrypoint.py
# Tests for apex_host/container_entrypoint.py (Infra Phase 9) — mode dispatch, preflight gating, live-confirmation refusal, exit codes, redaction, no-shell exec, and signal propagation.
"""Infra Phase 9 tests for the container entrypoint.

Every ``dry-run``/``run`` dispatch test mocks
``apex_host.container_entrypoint._run_engagement_and_report`` — the actual
engagement pipeline (``run_engagement``, ``build_report``, ...) is already
covered by ``tests/apex_host/test_htb_local_runner.py`` and friends; these
tests verify *entrypoint dispatch logic* (does preflight gate correctly,
is the live-confirmation refusal enforced, are exit codes/JSON/redaction
correct) without ever running a real engagement.
"""
from __future__ import annotations

import io
import json
import os
import signal
import asyncio
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

import apex_host.container_entrypoint as entry
from apex_host.eval.preflight import PreflightCheck, PreflightResult


async def _run(argv: list[str]) -> tuple[int, str, str]:
    """Invoke the entrypoint's async dispatch (bypassing sys.exit) and
    capture stdout/stderr, mirroring the existing test_check_config.py
    pattern."""
    args = entry._build_parser().parse_args(argv)
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        if args.mode == "exec":
            code = entry._handle_exec(args)
        else:
            handler = entry._MODE_HANDLERS[args.mode]
            code = await handler(args)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# check mode
# ---------------------------------------------------------------------------


class TestCheckMode:
    @pytest.mark.asyncio
    async def test_passes_with_writable_report_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("APEX_TARGET", raising=False)
        code, out, _ = await _run(["check", "--report-dir", str(tmp_path)])
        assert code == 0
        assert "Preflight passed" in out

    @pytest.mark.asyncio
    async def test_no_target_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("APEX_TARGET", raising=False)
        code, out, _ = await _run(["check"])
        assert "config-check" in out

    @pytest.mark.asyncio
    async def test_json_output_is_valid(self, tmp_path: Path) -> None:
        code, out, _ = await _run(["check", "--report-dir", str(tmp_path), "--json"])
        assert code == 0
        # The redacted config summary is printed as plain text before the
        # JSON blob — extract the JSON object specifically.
        json_start = out.index("{")
        data = json.loads(out[json_start:])
        assert data["passed"] is True
        assert "checks" in data

    @pytest.mark.asyncio
    async def test_fails_on_unwritable_report_dir(self, tmp_path: Path) -> None:
        import stat

        target = tmp_path / "readonly"
        target.mkdir()
        target.chmod(stat.S_IREAD | stat.S_IEXEC)
        try:
            code, out, _ = await _run(["check", "--report-dir", str(target)])
            assert code == 1
            assert "[FAIL]" in out
        finally:
            target.chmod(stat.S_IRWXU)

    @pytest.mark.asyncio
    async def test_malformed_env_value_exits_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APEX_MAX_TURNS", "notanumber")
        code, _, err = await _run(["check"])
        assert code == 2
        assert "APEX_MAX_TURNS" in err


# ---------------------------------------------------------------------------
# smoke mode
# ---------------------------------------------------------------------------


class TestSmokeMode:
    @pytest.mark.asyncio
    async def test_dispatches_to_run_smoke_checks(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        called: dict[str, object] = {}

        async def _fake_run_smoke_checks(config: object, **kwargs: object) -> PreflightResult:
            called["config"] = config
            return PreflightResult([PreflightCheck("configuration", True, "valid")])

        monkeypatch.setattr(entry, "run_smoke_checks", _fake_run_smoke_checks)
        code, out, _ = await _run(["smoke", "--report-dir", str(tmp_path)])
        assert code == 0
        assert called
        assert "Preflight passed" in out

    @pytest.mark.asyncio
    async def test_failure_propagates_exit_code(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _fake_fail(config: object, **kwargs: object) -> PreflightResult:
            return PreflightResult([PreflightCheck("Kali health", False, "unreachable")])

        monkeypatch.setattr(entry, "run_smoke_checks", _fake_fail)
        code, out, _ = await _run(["smoke", "--report-dir", str(tmp_path)])
        assert code == 1
        assert "[FAIL] Kali health" in out

    @pytest.mark.asyncio
    async def test_no_target_required(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        async def _fake(config: object, **kwargs: object) -> PreflightResult:
            return PreflightResult([PreflightCheck("configuration", True, "valid")])

        monkeypatch.setattr(entry, "run_smoke_checks", _fake)
        monkeypatch.delenv("APEX_TARGET", raising=False)
        code, out, _ = await _run(["smoke", "--report-dir", str(tmp_path)])
        assert code == 0
        assert "config-check" in out


# ---------------------------------------------------------------------------
# dry-run mode
# ---------------------------------------------------------------------------


class TestDryRunMode:
    @pytest.mark.asyncio
    async def test_requires_target(self) -> None:
        code, _, err = await _run(["dry-run"])
        assert code == 2
        assert "target" in err

    @pytest.mark.asyncio
    async def test_forces_dry_run_true(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        async def _fake_engagement(config: object, args: object) -> int:
            seen["dry_run"] = config.dry_run  # type: ignore[attr-defined]
            return 0

        monkeypatch.setattr(entry, "_run_engagement_and_report", _fake_engagement)
        monkeypatch.setenv("APEX_DRY_RUN", "false")  # must have NO effect on dry-run mode
        code, _, _ = await _run(["dry-run", "--target", "10.0.0.1", "--report-dir", str(tmp_path)])
        assert code == 0
        assert seen["dry_run"] is True

    @pytest.mark.asyncio
    async def test_preflight_failure_blocks_dispatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _boom(config: object, args: object) -> int:
            raise AssertionError("engagement must not be dispatched when preflight fails")

        monkeypatch.setattr(entry, "_run_engagement_and_report", _boom)
        import stat

        target = tmp_path / "readonly"
        target.mkdir()
        target.chmod(stat.S_IREAD | stat.S_IEXEC)
        try:
            code, out, _ = await _run(["dry-run", "--target", "10.0.0.1", "--report-dir", str(target)])
            assert code == 1
        finally:
            target.chmod(stat.S_IRWXU)

    @pytest.mark.asyncio
    async def test_preflight_success_dispatches_engagement(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        called = {"n": 0}

        async def _fake_engagement(config: object, args: object) -> int:
            called["n"] += 1
            return 0

        monkeypatch.setattr(entry, "_run_engagement_and_report", _fake_engagement)
        code, _, _ = await _run(["dry-run", "--target", "10.0.0.1", "--report-dir", str(tmp_path)])
        assert code == 0
        assert called["n"] == 1

    @pytest.mark.asyncio
    async def test_never_contacts_kali(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _fake_health(*a: object, **kw: object) -> PreflightCheck:
            raise AssertionError("dry-run must never check Kali health")

        async def _fake_engagement(config: object, args: object) -> int:
            return 0

        monkeypatch.setattr(entry, "_run_engagement_and_report", _fake_engagement)
        import apex_host.eval.preflight as preflight_mod

        monkeypatch.setattr(preflight_mod, "check_tool_service_health", _fake_health)
        code, _, _ = await _run(["dry-run", "--target", "10.0.0.1", "--report-dir", str(tmp_path)])
        assert code == 0


# ---------------------------------------------------------------------------
# run mode — refusal paths only, never a real dispatch
# ---------------------------------------------------------------------------


class TestRunModeRefusal:
    @pytest.mark.asyncio
    async def test_requires_target(self) -> None:
        code, _, err = await _run(["run", "--no-dry-run", "--confirm-live"])
        assert code == 2

    @pytest.mark.asyncio
    async def test_refuses_without_confirm_live(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _boom(config: object, args: object) -> int:
            raise AssertionError("must never dispatch without --confirm-live")

        monkeypatch.setattr(entry, "_run_engagement_and_report", _boom)
        code, out, _ = await _run(["run", "--target", "10.0.0.1", "--no-dry-run", "--report-dir", str(tmp_path)])
        assert code == 1
        assert "confirm-live" in out.lower()

    @pytest.mark.asyncio
    async def test_refuses_without_no_dry_run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _boom(config: object, args: object) -> int:
            raise AssertionError("must never dispatch while dry_run is True")

        monkeypatch.setattr(entry, "_run_engagement_and_report", _boom)
        code, out, _ = await _run(["run", "--target", "10.0.0.1", "--confirm-live", "--report-dir", str(tmp_path)])
        assert code == 1
        assert "dry_run" in out.lower() or "--no-dry-run" in out

    @pytest.mark.asyncio
    async def test_env_confirm_cannot_substitute_for_cli_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """There is deliberately no environment-variable equivalent for
        --confirm-live anywhere in this module — setting an arbitrary env
        var of that shape must have zero effect."""
        async def _boom(config: object, args: object) -> int:
            raise AssertionError("must never dispatch from an env var alone")

        monkeypatch.setattr(entry, "_run_engagement_and_report", _boom)
        monkeypatch.setenv("APEX_LIVE_CONFIRM", "I_UNDERSTAND_THIS_RUNS_COMMANDS")
        code, _, _ = await _run(["run", "--target", "10.0.0.1", "--no-dry-run", "--report-dir", str(tmp_path)])
        assert code == 1

    @pytest.mark.asyncio
    async def test_confirmed_and_no_dry_run_but_failing_preflight_blocks_dispatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _boom(config: object, args: object) -> int:
            raise AssertionError("must never dispatch when required preflight fails")

        monkeypatch.setattr(entry, "_run_engagement_and_report", _boom)
        monkeypatch.chdir(tmp_path)  # no conventional policy path -> policy required and missing
        code, out, _ = await _run(
            ["run", "--target", "10.0.0.1", "--no-dry-run", "--confirm-live", "--report-dir", str(tmp_path)],
        )
        assert code == 1
        assert "policy" in out.lower()

    @pytest.mark.asyncio
    async def test_fully_confirmed_and_passing_preflight_dispatches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        called = {"n": 0}

        async def _fake_engagement(config: object, args: object) -> int:
            called["n"] += 1
            return 0

        monkeypatch.setattr(entry, "_run_engagement_and_report", _fake_engagement)
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("rules: []\n")
        code, _, _ = await _run([
            "run", "--target", "10.0.0.1", "--no-dry-run", "--confirm-live",
            "--report-dir", str(tmp_path), "--policy-file", str(policy_file),
        ])
        assert code == 0
        assert called["n"] == 1


# ---------------------------------------------------------------------------
# Invalid mode
# ---------------------------------------------------------------------------


def test_invalid_mode_rejected_by_argparse() -> None:
    with pytest.raises(SystemExit):
        entry._build_parser().parse_args(["bogus-mode"])


def test_missing_mode_rejected() -> None:
    with pytest.raises(SystemExit):
        entry._build_parser().parse_args([])


# ---------------------------------------------------------------------------
# Token redaction
# ---------------------------------------------------------------------------


class TestRedaction:
    @pytest.mark.asyncio
    async def test_token_never_in_check_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "ultra-secret-entrypoint-token")
        code, out, err = await _run(["check", "--report-dir", str(tmp_path)])
        assert "ultra-secret-entrypoint-token" not in out
        assert "ultra-secret-entrypoint-token" not in err
        assert "present" in out

    @pytest.mark.asyncio
    async def test_token_never_in_smoke_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "ultra-secret-smoke-token")

        async def _fake(config: object, **kwargs: object) -> PreflightResult:
            return PreflightResult([PreflightCheck("configuration", True, "valid")])

        monkeypatch.setattr(entry, "run_smoke_checks", _fake)
        code, out, err = await _run(["smoke", "--report-dir", str(tmp_path)])
        assert "ultra-secret-smoke-token" not in out
        assert "ultra-secret-smoke-token" not in err


# ---------------------------------------------------------------------------
# exec mode — no shell, argv-list os.execvp
# ---------------------------------------------------------------------------


class TestExecMode:
    def test_calls_execvp_with_argv_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def _fake_execvp(file: str, args: list[str]) -> None:
            captured["file"] = file
            captured["args"] = args

        monkeypatch.setattr(os, "execvp", _fake_execvp)
        args = entry._build_parser().parse_args(["exec", "--", "python", "-m", "apex_host.main", "--help"])
        entry._handle_exec(args)
        assert captured["file"] == "python"
        assert captured["args"] == ["python", "-m", "apex_host.main", "--help"]

    def test_no_command_is_a_clear_usage_error(self) -> None:
        args = entry._build_parser().parse_args(["exec"])
        out = io.StringIO()
        with redirect_stderr(out):
            code = entry._handle_exec(args)
        assert code == 2
        assert "requires a command" in out.getvalue()

    def test_no_shell_string_interpretation_in_source(self) -> None:
        """Static guard: this module must never call subprocess with
        shell=True or os.system — os.execvp (argv-list, no shell) is the
        only process-launch mechanism exec mode uses."""
        import pathlib

        src = pathlib.Path(entry.__file__).read_text(encoding="utf-8")
        assert "shell=True" not in src
        assert "os.system(" not in src
        assert "os.execvp(" in src


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------


class TestSignalHandling:
    @pytest.mark.asyncio
    async def test_sigterm_cancels_running_coroutine_cleanly(self) -> None:
        async def _never_finishes() -> int:
            await asyncio.sleep(3600)
            return 0

        async def _send_sigterm_soon() -> None:
            await asyncio.sleep(0.05)
            os.kill(os.getpid(), signal.SIGTERM)

        result_task = asyncio.ensure_future(entry._run_with_signal_handling(_never_finishes()))
        asyncio.ensure_future(_send_sigterm_soon())
        code = await asyncio.wait_for(result_task, timeout=5.0)
        assert code == 143

    @pytest.mark.asyncio
    async def test_normal_completion_without_signal(self) -> None:
        async def _quick() -> int:
            return 0

        code = await entry._run_with_signal_handling(_quick())
        assert code == 0
