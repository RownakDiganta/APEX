# test_policy_file_cli.py
# Tests for --policy-file CLI flag in run_htb_local.py and main.py.
"""Acceptance tests for --policy-file CLI wiring.

Covers:
1. parse_args accepts --policy-file.
2. The value reaches ApexConfig.policy_file.
3. Explicit policy-file takes precedence over knowledge-root discovery.
4. Omitting --policy-file preserves current automatic discovery behaviour.
5. A nonexistent explicit path uses the conservative fallback and emits a warning.
"""
from __future__ import annotations

import logging
import pathlib

import pytest


# ---------------------------------------------------------------------------
# run_htb_local.py
# ---------------------------------------------------------------------------

class TestRunHtbLocalPolicyFile:
    def _parse(self, argv: list[str]):  # type: ignore[no-untyped-def]
        from apex_host.eval.run_htb_local import parse_args
        return parse_args(argv)

    def test_policy_file_accepted(self) -> None:
        args = self._parse(["--target", "10.0.0.1", "--policy-file", "/tmp/policy.yaml"])
        assert args.policy_file == "/tmp/policy.yaml"

    def test_policy_file_default_is_none(self) -> None:
        args = self._parse(["--target", "10.0.0.1"])
        assert args.policy_file is None

    def test_policy_file_reaches_apex_config(self) -> None:
        from apex_host.config import ApexConfig
        args = self._parse(["--target", "10.0.0.1", "--policy-file", "/fake/path.yaml"])
        config = ApexConfig(
            target=args.target,
            policy_file=args.policy_file,
        )
        assert config.policy_file == "/fake/path.yaml"

    def test_omitting_policy_file_preserves_discovery(self) -> None:
        from apex_host.config import ApexConfig
        args = self._parse(["--target", "10.0.0.1"])
        config = ApexConfig(target=args.target)
        # policy_file is None → loader uses knowledge_root / conventional path fallback
        assert config.policy_file is None

    def test_policy_file_with_knowledge_root(self) -> None:
        args = self._parse([
            "--target", "10.0.0.1",
            "--knowledge-root", "/some/root",
            "--policy-file", "/explicit/policy.yaml",
        ])
        assert args.policy_file == "/explicit/policy.yaml"
        assert args.knowledge_root == "/some/root"


class TestRunHtbLocalPolicyFilePrecedence:
    """Verify the loader honours the explicit > discovery > fallback precedence."""

    def test_explicit_path_takes_precedence_over_knowledge_root(
        self, tmp_path: pathlib.Path,
    ) -> None:
        from apex_host.config import ApexConfig
        from apex_host.policy.policy_loader import _resolve_policy_path

        # Create a well-formed YAML at the explicit path.
        explicit = tmp_path / "my_policy.yaml"
        explicit.write_text("scope: explicit\n", encoding="utf-8")

        # Also create the conventional knowledge-root path so the loader *could*
        # discover it — but shouldn't, because explicit wins.
        kr_yaml = tmp_path / "policy_db" / "compiled" / "hackthebox_lab.yaml"
        kr_yaml.parent.mkdir(parents=True)
        kr_yaml.write_text("scope: discovered\n", encoding="utf-8")

        config = ApexConfig(
            target="10.0.0.1",
            policy_file=str(explicit),
            knowledge_root=str(tmp_path),
        )
        resolved = _resolve_policy_path(config)
        assert resolved == explicit, (
            f"Expected explicit path {explicit} but got {resolved}"
        )

    def test_knowledge_root_used_when_no_explicit(
        self, tmp_path: pathlib.Path,
    ) -> None:
        from apex_host.config import ApexConfig
        from apex_host.policy.policy_loader import _resolve_policy_path

        kr_yaml = tmp_path / "policy_db" / "compiled" / "hackthebox_lab.yaml"
        kr_yaml.parent.mkdir(parents=True)
        kr_yaml.write_text("scope: discovered\n", encoding="utf-8")

        config = ApexConfig(
            target="10.0.0.1",
            policy_file=None,
            knowledge_root=str(tmp_path),
        )
        resolved = _resolve_policy_path(config)
        assert resolved == kr_yaml

    def test_nonexistent_explicit_path_uses_conservative_fallback_with_warning(
        self, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        from apex_host.config import ApexConfig
        from apex_host.policy.policy_loader import load_policy

        missing = str(tmp_path / "does_not_exist.yaml")
        config = ApexConfig(target="10.0.0.1", policy_file=missing)

        with caplog.at_level(logging.DEBUG, logger="apex_host.policy.policy_loader"):
            policy = load_policy(config)

        # Conservative default: policy not considered "loaded".
        assert policy.policy_loaded is False
        # The loader should have logged something about the missing path.
        assert any("not found" in msg or "policy_file" in msg or missing in msg
                   for msg in caplog.messages), (
            f"Expected a warning/debug message about the missing path, got: {caplog.messages}"
        )

    def test_valid_explicit_path_marks_policy_loaded(
        self, tmp_path: pathlib.Path,
    ) -> None:
        from apex_host.config import ApexConfig
        from apex_host.policy.policy_loader import load_policy

        yaml_path = tmp_path / "policy.yaml"
        yaml_path.write_text("scope: test\n", encoding="utf-8")

        config = ApexConfig(target="10.0.0.1", policy_file=str(yaml_path))
        policy = load_policy(config)

        assert policy.policy_loaded is True
        assert policy.policy_source == str(yaml_path)


# ---------------------------------------------------------------------------
# main.py
# ---------------------------------------------------------------------------

class TestMainPyPolicyFile:
    def _parse(self, argv: list[str]):  # type: ignore[no-untyped-def]
        from apex_host.main import parse_args
        return parse_args(argv)

    def test_main_accepts_policy_file(self) -> None:
        args = self._parse(["--target", "10.0.0.1", "--policy-file", "/path/to/policy.yaml"])
        assert args.policy_file == "/path/to/policy.yaml"

    def test_main_policy_file_default_none(self) -> None:
        args = self._parse(["--target", "10.0.0.1"])
        assert args.policy_file is None
