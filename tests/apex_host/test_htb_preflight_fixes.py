# test_htb_preflight_fixes.py
# Focused regression tests for the authorized-HTB preflight fixes: the deterministic report-directory resolver (Issue 4) and the live-preflight interlock gating of real remote execution (Issue 3).
"""Regression tests for two defects surfaced during a real authorized HTB
preflight:

- **Issue 4** — ``run_htb_local``'s preflight validated the current working
  directory ``"."`` (``/app`` in the container, not writable by the non-root
  user) when no ``--export-json``/``--export-graph`` was supplied, instead of
  the real report-output location. The fix is a deterministic resolver
  (``apex_host.eval.preflight.resolve_report_dir`` /
  ``default_report_directory``) that never returns ``"."``.

- **Issue 3** — a ``--preflight-only`` run with ``--tool-backend remote`` but
  without ``--no-dry-run`` falsely failed the remote smoke ("backend resolved
  to dry-run"); and a live (``--no-dry-run``) preflight performed a real
  remote execution without the ``--confirm-live`` interlock. The fix routes a
  live preflight through the centralized interlock and skips the meaningless
  smoke in dry-run.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apex_host.eval import preflight
from apex_host.eval.preflight import (
    PreflightCheck,
    PreflightResult,
    check_report_directory,
    default_report_directory,
    resolve_report_dir,
)
from apex_host.eval.run_htb_local import _async_main, parse_args

_TARGET = "10.129.0.5"


# ---------------------------------------------------------------------------
# Issue 4 — deterministic report-directory resolver
# ---------------------------------------------------------------------------


class TestResolveReportDir:
    def test_export_json_parent_is_used(self) -> None:
        assert resolve_report_dir(report_path="/app/run_reports/run.json") == "/app/run_reports"

    def test_export_graph_parent_is_used(self) -> None:
        assert resolve_report_dir(graph_path="/app/run_reports/ekg.json") == "/app/run_reports"

    def test_export_json_wins_over_graph(self) -> None:
        got = resolve_report_dir(
            report_path="/data/reports/run.json", graph_path="/other/graphs/ekg.json"
        )
        assert got == "/data/reports"

    def test_neither_export_uses_documented_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight, "_running_in_container", lambda: False)
        assert resolve_report_dir() == "run_reports"

    def test_never_returns_dot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for in_container in (True, False):
            monkeypatch.setattr(preflight, "_running_in_container", lambda v=in_container: v)
            assert resolve_report_dir() != "."
            assert resolve_report_dir(report_path="bare.json") != "."

    def test_bare_filename_does_not_resolve_to_dot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A filename with no directory component has an empty parent — it must
        # fall through to the documented default, never ".".
        monkeypatch.setattr(preflight, "_running_in_container", lambda: False)
        assert resolve_report_dir(report_path="run.json") == "run_reports"

    def test_container_default_is_app_run_reports(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight, "_running_in_container", lambda: True)
        assert default_report_directory() == "/app/run_reports"
        assert resolve_report_dir() == "/app/run_reports"

    def test_local_default_is_run_reports(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight, "_running_in_container", lambda: False)
        assert default_report_directory() == "run_reports"


# ---------------------------------------------------------------------------
# Issue 4 — report-directory check validates the real destination(s)
# ---------------------------------------------------------------------------


class TestCheckReportDirectoryDestinations:
    def test_writable_export_parent_passes(self, tmp_path: Path) -> None:
        report = tmp_path / "reports" / "run.json"
        result = check_report_directory(default_dir=str(tmp_path), report_path=str(report))
        assert result.passed is True
        assert (tmp_path / "reports").is_dir()

    def test_two_distinct_export_parents_both_checked(self, tmp_path: Path) -> None:
        report = tmp_path / "a" / "run.json"
        graph = tmp_path / "b" / "ekg.json"
        result = check_report_directory(
            default_dir=str(tmp_path), report_path=str(report), graph_path=str(graph)
        )
        assert result.passed is True
        assert (tmp_path / "a").is_dir() and (tmp_path / "b").is_dir()
        assert str(tmp_path / "a") in result.detail
        assert str(tmp_path / "b") in result.detail

    def test_missing_but_creatable_directory_is_created(self, tmp_path: Path) -> None:
        target = tmp_path / "deep" / "nested" / "reports"
        assert not target.exists()
        result = check_report_directory(default_dir=str(target))
        assert result.passed is True
        assert target.is_dir()

    def test_unwritable_directory_fails_clearly(self, tmp_path: Path) -> None:
        import stat

        target = tmp_path / "ro"
        target.mkdir()
        target.chmod(stat.S_IREAD | stat.S_IEXEC)
        try:
            result = check_report_directory(default_dir=str(target))
            assert result.passed is False
            assert str(target) in result.detail
            assert "not writable" in result.detail or "cannot create" in result.detail
        finally:
            target.chmod(stat.S_IRWXU)

    def test_path_with_spaces_is_handled(self, tmp_path: Path) -> None:
        spaced = tmp_path / "New Apex" / "run_reports"
        result = check_report_directory(default_dir=str(spaced))
        assert result.passed is True
        assert spaced.is_dir()

    def test_existing_report_file_never_overwritten(self, tmp_path: Path) -> None:
        existing = tmp_path / "run.json"
        existing.write_text('{"kept": true}', encoding="utf-8")
        check_report_directory(default_dir=str(tmp_path), report_path=str(existing))
        assert existing.read_text(encoding="utf-8") == '{"kept": true}'

    def test_marker_file_always_removed(self, tmp_path: Path) -> None:
        check_report_directory(default_dir=str(tmp_path))
        assert list(tmp_path.glob(".apex_preflight_write_test_*")) == []

    def test_resolver_pure_makes_no_writes(self, tmp_path: Path) -> None:
        # resolve_report_dir is pure — it must not touch the filesystem.
        before = set(tmp_path.iterdir())
        resolve_report_dir(report_path=str(tmp_path / "x.json"))
        resolve_report_dir()
        assert set(tmp_path.iterdir()) == before


# ---------------------------------------------------------------------------
# Issue 4 — passing report-directory check names the exact directory
# ---------------------------------------------------------------------------


class TestReportDirectoryOutput:
    def test_pass_output_shows_checked_directory(self, tmp_path: Path) -> None:
        check = check_report_directory(default_dir=str(tmp_path))
        assert check.passed is True
        assert check.show_detail_on_pass is True
        text = PreflightResult([check]).format_text()
        assert str(tmp_path) in text
        assert "is writable" in text

    def test_other_passing_checks_do_not_show_detail(self) -> None:
        check = PreflightCheck(name="configuration", passed=True, detail="valid")
        text = PreflightResult([check]).format_text()
        assert "[PASS] configuration" in text
        assert "valid" not in text  # default show_detail_on_pass=False

    def test_show_detail_on_pass_not_serialized(self, tmp_path: Path) -> None:
        # The display hint is intentionally absent from to_dict() to keep the
        # JSON schema stable.
        check = check_report_directory(default_dir=str(tmp_path))
        assert "show_detail_on_pass" not in check.to_dict()


# ---------------------------------------------------------------------------
# Issue 3 — dry-run and live preflight behavior
# ---------------------------------------------------------------------------


class TestPreflightOnlyBackendGating:
    @pytest.mark.asyncio
    async def test_dry_run_remote_backend_does_not_false_fail_smoke(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A dry-run --preflight-only with a remote backend must NOT attempt the
        # remote smoke (which would spuriously report "resolved to dry-run").
        report = tmp_path / "run.json"
        args = parse_args([
            "--target", _TARGET, "--preflight-only", "--dry-run",
            "--tool-backend", "remote", "--tool-service-url", "http://127.0.0.1:9/",
            "--export-json", str(report),
        ])
        code = await _async_main(args)
        out = capsys.readouterr().out
        assert code == 0
        assert "remote tool smoke" not in out
        assert "resolved to dry-run" not in out
        assert "report directory" in out

    @pytest.mark.asyncio
    async def test_live_preflight_without_confirm_live_is_blocked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A live (--no-dry-run) --preflight-only performs a real remote
        # execution and therefore must go through the interlock — missing
        # --confirm-live blocks it before any smoke command runs.
        report = tmp_path / "run.json"
        args = parse_args([
            "--target", _TARGET, "--preflight-only", "--no-dry-run",
            "--tool-backend", "remote", "--tool-service-url", "http://127.0.0.1:9/",
            "--export-json", str(report),
        ])
        code = await _async_main(args)
        out = capsys.readouterr().out
        assert code == 1
        assert "live_confirmed" in out
        assert "Live interlock: BLOCKED" in out

    @pytest.mark.asyncio
    async def test_dry_run_preflight_does_not_write_to_dot(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # With no export path, the resolved default directory (under tmp_path
        # here) is what gets validated — never the process working directory.
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(preflight, "_running_in_container", lambda: False)
        args = parse_args(["--target", _TARGET, "--preflight-only", "--dry-run"])
        code = await _async_main(args)
        assert code == 0
        # Default local dir was created under the (isolated) cwd, not the repo.
        assert (tmp_path / "run_reports").is_dir()


    @pytest.mark.asyncio
    async def test_live_preflight_with_confirm_live_reaches_remote_smoke(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # With --no-dry-run + --confirm-live + an in-scope target, the live
        # preflight is permitted to proceed through the interlock to the real
        # remote smoke command (spied here so no real service is needed).
        from apex_host.eval import preflight as preflight_mod

        called: dict[str, bool] = {"smoke": False, "health": False}

        async def _fake_health(url, **kwargs):  # type: ignore[no-untyped-def]
            called["health"] = True
            return preflight_mod.PreflightCheck(name="Kali health", passed=True, detail="ok")

        async def _fake_smoke(config, **kwargs):  # type: ignore[no-untyped-def]
            called["smoke"] = True
            return preflight_mod.PreflightCheck(name="remote tool smoke", passed=True, detail="ok")

        monkeypatch.setattr(preflight_mod, "check_tool_service_health", _fake_health)
        monkeypatch.setattr(preflight_mod, "check_remote_smoke", _fake_smoke)

        report = tmp_path / "run.json"
        args = parse_args([
            "--target", _TARGET, "--preflight-only", "--no-dry-run", "--confirm-live",
            "--tool-backend", "remote", "--tool-service-url", "http://127.0.0.1:9/",
            "--policy-file", str(tmp_path / "missing.yaml"),  # keeps policy check deterministic
            "--export-json", str(report),
        ])
        await _async_main(args)
        # The real remote execution path was reached only because --confirm-live
        # (and an in-scope target) satisfied the interlock — it is never
        # bypassed for a live preflight.
        assert called["smoke"] is True


class TestEngagementLiveInterlockUnaffectedByDryRun:
    @pytest.mark.asyncio
    async def test_no_dry_run_without_confirm_live_engagement_blocked(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        args = parse_args(["--target", _TARGET, "--no-dry-run", "--max-turns", "1"])
        code = await _async_main(args)
        out = capsys.readouterr().out
        assert code != 0
        assert "live_confirmed" in out
