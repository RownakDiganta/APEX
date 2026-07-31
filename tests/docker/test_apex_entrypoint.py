# test_apex_entrypoint.py
# Unit + optional-Docker-integration tests for docker/apex/entrypoint.py — the root-init privilege-drop wrapper that prepares the root-owned apex-knowledge-cache named volume for the non-root apex user. Dynamically imported (standalone script, not an installed package).
"""Tests for the APEX container privilege-drop entrypoint.

The unit tests exercise the entrypoint's pure/near-pure logic on the host
(no root, no Docker required) by monkeypatching the privileged syscalls
(``os.chown``/``os.setuid``/``os.setgid``/``os.setgroups``/``os.execv``) and
``os.geteuid`` — this gives full coverage of the root-init branch, the
idempotent ownership repair, the writability check + diagnostic, and argv
forwarding without ever needing elevated privilege.

An optional Docker integration test (skipped unless ``docker`` is available
AND the ``apex`` image has been built) mounts a fresh, deliberately
root-owned named volume and proves the fix end-to-end: the runtime user can
create ``/app/knowledge_cache/.init.lock``, runs as the non-root apex UID,
and the same operation FAILS when the privilege-drop entrypoint is bypassed.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import types
import uuid

import pytest

_APEX_DOCKER_DIR = pathlib.Path(__file__).parent.parent.parent / "docker" / "apex"
_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent


def _load_entrypoint() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("apex_entrypoint", _APEX_DOCKER_DIR / "entrypoint.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


entrypoint = _load_entrypoint()


# ---------------------------------------------------------------------------
# Static / source-level invariants
# ---------------------------------------------------------------------------

class TestSourceInvariants:
    def test_no_chmod_777(self) -> None:
        src = (_APEX_DOCKER_DIR / "entrypoint.py").read_text(encoding="utf-8")
        assert "chmod 777" not in src and "0777" not in src
        # The only permitted 0o777 usage is the permission-bit MASK in the
        # diagnostic (`info.st_mode & 0o777`) — never a chmod target.
        for ln in src.splitlines():
            if "0o777" in ln:
                assert "& 0o777" in ln, f"0o777 may only be used as a permission mask: {ln!r}"
        # chmod only ever applies the restrictive, non-world-writable constant.
        assert entrypoint._CACHE_DIR_MODE == 0o770

    def test_restrictive_mode_constant(self) -> None:
        assert entrypoint._CACHE_DIR_MODE == 0o770

    def test_prepares_only_knowledge_cache_not_run_reports(self) -> None:
        # run_reports is a bind mount that is already writable; chowning it
        # would rewrite host-side ownership, so it is deliberately excluded.
        assert entrypoint._PREPARE_DIRS == ("/app/knowledge_cache",)

    def test_targets_non_root_apex_user(self) -> None:
        assert entrypoint._RUNTIME_USER == "apex"

    def test_execs_the_real_container_entrypoint(self) -> None:
        src = (_APEX_DOCKER_DIR / "entrypoint.py").read_text(encoding="utf-8")
        assert "apex_host.container_entrypoint" in src
        assert "os.execv" in src  # process replacement, not subprocess


# ---------------------------------------------------------------------------
# prepare_dir — idempotency, conditional chown, content preservation
# ---------------------------------------------------------------------------

class TestPrepareDir:
    def test_creates_missing_directory(self, tmp_path: pathlib.Path) -> None:
        target = tmp_path / "knowledge_cache"
        assert not target.exists()
        my_uid, my_gid = os.getuid(), os.getgid()
        entrypoint.prepare_dir(str(target), my_uid, my_gid)
        assert target.is_dir()

    def test_no_chown_when_ownership_already_correct(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "cache"
        target.mkdir()
        my_uid, my_gid = os.getuid(), os.getgid()
        calls: list[tuple[str, int, int]] = []
        monkeypatch.setattr(entrypoint.os, "chown", lambda p, u, g, **k: calls.append((p, u, g)))
        entrypoint.prepare_dir(str(target), my_uid, my_gid)
        assert calls == [], "warm path (correct ownership) must not chown at all"

    def test_chown_recursive_only_when_ownership_wrong(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "cache"
        target.mkdir()
        (target / "family_intel_db.json").write_text('{"kept": true}', encoding="utf-8")
        calls: list[tuple[str, int, int]] = []
        monkeypatch.setattr(entrypoint.os, "chown", lambda p, u, g, **k: calls.append((p, u, g)))
        # Force the "ownership wrong" branch by targeting a UID we don't have.
        wrong_uid = os.getuid() + 12345
        entrypoint.prepare_dir(str(target), wrong_uid, os.getgid())
        assert calls, "a root-owned/mismatched volume must trigger an ownership repair"
        assert any(str(target) == c[0] for c in calls), "the volume root itself must be chowned"

    def test_existing_files_preserved(self, tmp_path: pathlib.Path) -> None:
        target = tmp_path / "cache"
        target.mkdir()
        payload = target / "family_policy_db.json"
        payload.write_text('{"real": "cache"}', encoding="utf-8")
        entrypoint.prepare_dir(str(target), os.getuid(), os.getgid())
        assert payload.read_text(encoding="utf-8") == '{"real": "cache"}'

    def test_idempotent(self, tmp_path: pathlib.Path) -> None:
        target = tmp_path / "cache"
        entrypoint.prepare_dir(str(target), os.getuid(), os.getgid())
        first_mode = stat.S_IMODE(target.stat().st_mode)
        entrypoint.prepare_dir(str(target), os.getuid(), os.getgid())
        assert stat.S_IMODE(target.stat().st_mode) == first_mode
        assert first_mode == 0o770

    def test_applies_restrictive_non_world_writable_mode(self, tmp_path: pathlib.Path) -> None:
        target = tmp_path / "cache"
        entrypoint.prepare_dir(str(target), os.getuid(), os.getgid())
        mode = stat.S_IMODE(target.stat().st_mode)
        assert mode == 0o770
        assert not (mode & stat.S_IWOTH), "cache dir must never be world-writable"


# ---------------------------------------------------------------------------
# verify_writable + report_unwritable
# ---------------------------------------------------------------------------

class TestWritabilityCheck:
    def test_verify_writable_true_on_writable_dir(self, tmp_path: pathlib.Path) -> None:
        assert entrypoint.verify_writable(str(tmp_path)) is True
        # The probe file is always cleaned up.
        assert list(tmp_path.glob(".apex_write_test.*")) == []

    def test_verify_writable_false_on_readonly_dir(self, tmp_path: pathlib.Path) -> None:
        ro = tmp_path / "ro"
        ro.mkdir()
        ro.chmod(stat.S_IREAD | stat.S_IEXEC)
        try:
            assert entrypoint.verify_writable(str(ro)) is False
        finally:
            ro.chmod(stat.S_IRWXU)

    def test_report_unwritable_exits_nonzero_with_diagnostic(
        self, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            entrypoint.report_unwritable(str(tmp_path), 1000, 1000)
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert str(tmp_path) in err
        assert "uid=1000 gid=1000" in err
        assert "ownership:" in err and "mode:" in err

    def test_report_unwritable_exposes_no_secrets(
        self, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-super-secret-value-123456")
        monkeypatch.setenv("APEX_TOOL_SERVICE_TOKEN", "tok-super-secret-abcdef")
        with pytest.raises(SystemExit):
            entrypoint.report_unwritable(str(tmp_path), 1000, 1000)
        err = capsys.readouterr().err
        assert "sk-super-secret-value-123456" not in err
        assert "tok-super-secret-abcdef" not in err


# ---------------------------------------------------------------------------
# main — root-init branch, non-root branch, argv forwarding
# ---------------------------------------------------------------------------

class TestMain:
    def _patch_common(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
        captured: dict[str, object] = {"execv": None, "dropped": False, "prepared": []}
        monkeypatch.setattr(entrypoint, "resolve_runtime_identity", lambda *a, **k: (1000, 1000))
        monkeypatch.setattr(
            entrypoint, "prepare_dir",
            lambda d, u, g: captured["prepared"].append((d, u, g)),  # type: ignore[union-attr]
        )
        monkeypatch.setattr(
            entrypoint, "drop_privileges",
            lambda u, g: captured.__setitem__("dropped", (u, g)),
        )
        monkeypatch.setattr(entrypoint, "verify_writable", lambda d: True)
        monkeypatch.setattr(
            entrypoint.os, "execv",
            lambda path, args: captured.__setitem__("execv", (path, list(args))),
        )
        return captured

    def test_root_start_prepares_then_drops_then_execs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = self._patch_common(monkeypatch)
        monkeypatch.setattr(entrypoint.os, "geteuid", lambda: 0)
        entrypoint.main(["check", "--knowledge-root", "/app/knowledge"])
        assert captured["prepared"] == [("/app/knowledge_cache", 1000, 1000)]
        assert captured["dropped"] == (1000, 1000), "must drop to the non-root apex UID/GID"
        path, args = captured["execv"]  # type: ignore[misc]
        assert path == sys.executable
        assert args == [sys.executable, "-m", "apex_host.container_entrypoint",
                        "check", "--knowledge-root", "/app/knowledge"]

    def test_non_root_start_skips_prepare_and_drop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = self._patch_common(monkeypatch)
        monkeypatch.setattr(entrypoint.os, "geteuid", lambda: 1000)  # already non-root
        entrypoint.main(["check"])
        assert captured["prepared"] == [], "non-root start cannot chown; must not attempt prepare"
        assert captured["dropped"] is False, "non-root start must not attempt a privilege drop"
        assert captured["execv"] is not None, "must still exec the real entrypoint"

    def test_forwards_exec_dash_dash_arguments_unchanged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = self._patch_common(monkeypatch)
        monkeypatch.setattr(entrypoint.os, "geteuid", lambda: 0)
        forwarded = ["exec", "--", "python", "-m", "apex_host.eval.run_htb_local",
                    "--target", "10.129.0.5", "--no-dry-run", "--confirm-live"]
        entrypoint.main(list(forwarded))
        _path, args = captured["execv"]  # type: ignore[misc]
        assert args == [sys.executable, "-m", "apex_host.container_entrypoint", *forwarded]

    def test_unwritable_after_prepare_fails_loudly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = self._patch_common(monkeypatch)
        monkeypatch.setattr(entrypoint.os, "geteuid", lambda: 0)
        monkeypatch.setattr(entrypoint, "verify_writable", lambda d: False)  # still unwritable
        with pytest.raises(SystemExit) as exc:
            entrypoint.main(["check"])
        assert exc.value.code == 1
        assert captured["execv"] is None, "must never exec the app when the cache is unwritable"


# ---------------------------------------------------------------------------
# Optional end-to-end Docker regression (skipped unless docker + image exist)
# ---------------------------------------------------------------------------

def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _apex_image_tag() -> str | None:
    """Return an available locally-built apex image tag, or None."""
    if not _docker_available():
        return None
    for tag in ("apex:volperm-test", "newapex-apex:latest", "apex:latest", "apex:phase5"):
        result = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return tag
    return None


_IMAGE_TAG = _apex_image_tag()
_docker_skip = pytest.mark.skipif(
    _IMAGE_TAG is None,
    reason="docker unavailable or no locally-built apex image (build with docker/apex/Dockerfile first)",
)


@_docker_skip
class TestDockerVolumePermissionEndToEnd:
    def _run(self, args: list[str], volume: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "docker", "run", "--rm",
                "-e", "APEX_KNOWLEDGE_CACHE_PATH=/app/knowledge_cache",
                "-v", f"{volume}:/app/knowledge_cache",
                *args,
            ],
            capture_output=True, text=True, timeout=120,
        )

    def _fresh_volume(self) -> str:
        name = f"apex-volperm-test-{uuid.uuid4().hex[:8]}"
        subprocess.run(["docker", "volume", "create", name], capture_output=True, text=True, check=True)
        # Reproduce a legacy, root-owned volume that ALREADY CONTAINS cache
        # data. It must be non-empty: Docker only re-applies the image
        # directory's (apex) ownership to an EMPTY named volume on first mount,
        # so a non-empty volume stays root-owned exactly like the volume from
        # the failed live run — the precondition the runtime fix must repair.
        subprocess.run(
            ["docker", "run", "--rm", "-u", "0:0", "-v", f"{name}:/vol", "busybox",
             "sh", "-c", "echo legacy > /vol/family_intel_db.json && chown -R 0:0 /vol && chmod 700 /vol"],
            capture_output=True, text=True, check=True,
        )
        return name

    def _rm_volume(self, name: str) -> None:
        subprocess.run(["docker", "volume", "rm", "-f", name], capture_output=True, text=True)

    def test_runtime_user_can_create_init_lock_on_root_owned_volume(self) -> None:
        assert _IMAGE_TAG is not None
        vol = self._fresh_volume()
        try:
            # Through the privilege-drop entrypoint (exec mode): create .init.lock
            # exactly like apex_host/knowledge/init_lock.py does, and print the id.
            res = self._run(
                [_IMAGE_TAG, "exec", "--", "python", "-c",
                 "import os;fd=os.open('/app/knowledge_cache/.init.lock',os.O_CREAT|os.O_EXCL|os.O_WRONLY);"
                 "os.close(fd);"
                 "kept=open('/app/knowledge_cache/family_intel_db.json').read().strip();"
                 "print('LOCK_OK',os.getuid(),'KEPT='+kept)"],
                vol,
            )
            assert "LOCK_OK" in res.stdout, f"stdout={res.stdout!r} stderr={res.stderr!r}"
            # Runs as the non-root apex UID (1000), not root.
            assert "LOCK_OK 1000" in res.stdout, f"expected non-root uid 1000: {res.stdout!r}"
            # The pre-existing (legacy, root-owned) cache file was preserved,
            # not deleted, by the ownership repair.
            assert "KEPT=legacy" in res.stdout, f"legacy cache content not preserved: {res.stdout!r}"
        finally:
            self._rm_volume(vol)

    def test_bypassing_entrypoint_as_apex_would_fail_on_root_owned_volume(self) -> None:
        """Demonstrates the ORIGINAL failure: bypassing the privilege-drop
        entrypoint and running as the non-root user against a root-owned
        volume reproduces the exact PermissionError the fix resolves."""
        assert _IMAGE_TAG is not None
        vol = self._fresh_volume()
        try:
            res = self._run(
                ["-u", "1000:1000", "--entrypoint", "python", _IMAGE_TAG,
                 "-c", "import os;os.open('/app/knowledge_cache/.init.lock',os.O_CREAT|os.O_EXCL|os.O_WRONLY)"],
                vol,
            )
            assert res.returncode != 0
            assert "Permission denied" in res.stderr, f"stderr={res.stderr!r}"
        finally:
            self._rm_volume(vol)
