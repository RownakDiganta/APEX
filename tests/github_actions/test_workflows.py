# test_workflows.py
# Static, content-based verification of the first-party GitHub Actions workflows (Infra Phase 11) — parses ci.yml/docker-publish.yml via PyYAML and asserts on structure/content. Does not require GitHub-hosted execution; the actual run/publish behavior can only be proven by pushing and inspecting the Actions tab (see docs/github-actions.md).
"""Static checks for `.github/workflows/ci.yml` and `.github/workflows/docker-publish.yml`.

Mirrors the pattern already established for `compose.yaml`/`compose.htb.yaml`
(`tests/docker/test_compose.py`, `tests/docker/test_compose_htb.py`): parse
the real file via PyYAML (already a project dependency — no new
dependency added) and assert on parsed structure for anything
structural, falling back to raw-text substring/regex checks only for
things YAML structure doesn't capture well (e.g. "this literal string
never appears anywhere in the file").

**The `on:` key gotcha.** YAML 1.1 (which PyYAML's default `SafeLoader`
implements) resolves the *unquoted* scalar `on` to the boolean `True`,
not the string `"on"` — so `yaml.safe_load(...)["on"]` raises `KeyError`
even though the file plainly has an `on:` block. `_triggers()` below
handles this by trying both `"on"` and `True` as the top-level key.

Tests are written against parsed structure and normalized text wherever
possible, deliberately avoiding exact step-name or whitespace matching so
a cosmetic rewording of a step's `name:` never breaks these tests.
"""
from __future__ import annotations

import pathlib
import re

import yaml

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_WORKFLOWS_DIR = _REPO_ROOT / ".github" / "workflows"
_CI_PATH = _WORKFLOWS_DIR / "ci.yml"
_PUBLISH_PATH = _WORKFLOWS_DIR / "docker-publish.yml"

_EXPECTED_IMAGES = {
    "apex": "docker/apex/Dockerfile",
    "apex-kali": "docker/kali/Dockerfile",
    "apex-vpn": "docker/vpn/Dockerfile",
}


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------

def _load(path: pathlib.Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, dict)
    return data


def _text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _triggers(data: dict) -> dict:
    """Return the `on:` block, handling PyYAML's YAML-1.1 `on` -> `True`
    key-resolution gotcha (see module docstring)."""
    if "on" in data:
        value = data["on"]
    elif True in data:
        value = data[True]
    else:
        raise AssertionError("workflow has no 'on:' trigger block at all")
    if isinstance(value, str):
        # A bare `on: push` (no further keys) parses as a string, not a dict.
        return {value: None}
    if isinstance(value, list):
        return {k: None for k in value}
    assert isinstance(value, dict)
    return value


def _all_run_commands(data: dict) -> str:
    """Concatenate every `run:` step's shell script across every job in
    the workflow, for substring/regex searching. Deliberately whitespace-
    insensitive (callers use substring/regex matching, not exact
    comparison)."""
    chunks: list[str] = []
    jobs = data.get("jobs", {})
    for job in jobs.values():
        for step in job.get("steps", []):
            run = step.get("run")
            if isinstance(run, str):
                chunks.append(run)
    return "\n".join(chunks)


def _all_steps(data: dict) -> list[dict]:
    steps: list[dict] = []
    for job in data.get("jobs", {}).values():
        steps.extend(job.get("steps", []))
    return steps


def _steps_using(data: dict, action_prefix: str) -> list[dict]:
    return [s for s in _all_steps(data) if isinstance(s.get("uses"), str) and s["uses"].startswith(action_prefix)]


def _matrix_include(data: dict, job_name: str) -> list[dict]:
    job = data["jobs"][job_name]
    return job["strategy"]["matrix"]["include"]


def _non_comment_text(path_text: str) -> str:
    """*path_text* with full-line `#` comments removed — used for negative
    ("X never appears") checks so this file's own explanatory comments
    (which legitimately name the things being forbidden, e.g. "never uses
    pull_request_target") never produce a false positive."""
    lines = [ln for ln in path_text.splitlines() if not ln.strip().startswith("#")]
    return "\n".join(lines)


_ci = _load(_CI_PATH)
_publish = _load(_PUBLISH_PATH)
_ci_text = _text(_CI_PATH)
_publish_text = _text(_PUBLISH_PATH)


# ---------------------------------------------------------------------------
# Workflow existence
# ---------------------------------------------------------------------------

class TestWorkflowExistence:
    def test_ci_workflow_exists(self) -> None:
        assert _CI_PATH.is_file()

    def test_publish_workflow_exists(self) -> None:
        assert _PUBLISH_PATH.is_file()

    def test_file_header_convention(self) -> None:
        for path in (_CI_PATH, _PUBLISH_PATH):
            lines = path.read_text(encoding="utf-8").splitlines()
            assert lines[0].startswith("# "), f"{path.name} missing file-header first line"
            assert lines[1].startswith("# "), f"{path.name} missing file-header second line"

    def test_only_two_workflow_files_at_project_root(self) -> None:
        """The project's own workflow directory contains exactly the two
        intended files — no stray/experimental third workflow."""
        found = sorted(p.name for p in _WORKFLOWS_DIR.glob("*.yml"))
        assert found == ["ci.yml", "docker-publish.yml"]

    def test_vendored_workflow_files_are_not_project_workflows(self) -> None:
        """Vendored third-party corpora under Knowledge/ (GTFOBins,
        SecLists, LOLBAS, PayloadsAllTheThings) ship their own
        `.github/workflows/` directories — these must never be confused
        with, counted as, or discovered as this project's own workflows.
        The project's workflow directory is exactly `.github/workflows/`
        at the repository root; nothing under `Knowledge/` is inside it."""
        vendored_github_dirs = list((_REPO_ROOT / "Knowledge").glob("**/.github"))
        assert len(vendored_github_dirs) > 0, (
            "expected to find at least one vendored .github directory under "
            "Knowledge/ (sanity check that this test is exercising something real)"
        )
        for vendored_dir in vendored_github_dirs:
            assert _WORKFLOWS_DIR not in vendored_dir.parents
            assert vendored_dir != _WORKFLOWS_DIR.parent


# ---------------------------------------------------------------------------
# Triggers
# ---------------------------------------------------------------------------

class TestTriggers:
    def test_ci_runs_on_pull_request(self) -> None:
        assert "pull_request" in _triggers(_ci)

    def test_ci_runs_on_push_to_default_branch(self) -> None:
        push = _triggers(_ci)["push"]
        assert push is not None and "main" in push.get("branches", [])

    def test_ci_supports_manual_dispatch(self) -> None:
        assert "workflow_dispatch" in _triggers(_ci)

    def test_publish_runs_on_push_to_default_branch(self) -> None:
        push = _triggers(_publish)["push"]
        assert push is not None and "main" in push.get("branches", [])

    def test_publish_runs_on_version_tags(self) -> None:
        push = _triggers(_publish)["push"]
        assert push is not None and "v*" in push.get("tags", [])

    def test_publish_supports_manual_dispatch(self) -> None:
        assert "workflow_dispatch" in _triggers(_publish)

    def test_no_pull_request_target_anywhere(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "pull_request_target" not in _non_comment_text(text)

    def test_ci_does_not_trigger_on_tags(self) -> None:
        """CI validates PRs and default-branch pushes — publishing on tags
        is docker-publish.yml's job, not ci.yml's."""
        push = _triggers(_ci).get("push")
        if push:
            assert "tags" not in push


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

class TestPermissions:
    def test_ci_workflow_level_permissions_are_contents_read_only(self) -> None:
        assert _ci["permissions"] == {"contents": "read"}

    def test_publish_workflow_level_permissions(self) -> None:
        perms = _publish["permissions"]
        assert perms.get("contents") == "read"
        assert perms.get("packages") == "write"

    def test_no_write_all_anywhere(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "write-all" not in text

    def test_no_packages_write_anywhere_in_ci(self) -> None:
        non_comment = _non_comment_text(_ci_text)
        assert "packages: write" not in non_comment
        assert "packages:write" not in non_comment.replace(" ", "")  # defensive, catches reformatted YAML

    def test_no_job_in_ci_grants_extra_permissions(self) -> None:
        for job in _ci["jobs"].values():
            assert "permissions" not in job, "ci.yml jobs must rely solely on the workflow-level contents:read"

    def test_publish_validate_job_is_narrowed_to_contents_read(self) -> None:
        validate_job = _publish["jobs"]["validate"]
        assert validate_job.get("permissions") == {"contents": "read"}


# ---------------------------------------------------------------------------
# Python validation
# ---------------------------------------------------------------------------

class TestPythonValidation:
    def test_python_311_used_in_both_workflows(self) -> None:
        for data in (_ci, _publish):
            setup_python_steps = _steps_using(data, "actions/setup-python@")
            assert setup_python_steps, "expected an actions/setup-python step"
            versions = {s.get("with", {}).get("python-version") for s in setup_python_steps}
            assert versions == {"3.11"}

    def test_official_uv_action_used(self) -> None:
        for data in (_ci, _publish):
            assert _steps_using(data, "astral-sh/setup-uv@"), "expected an astral-sh/setup-uv step"

    def test_uv_lock_check_present(self) -> None:
        for text in (_all_run_commands(_ci), _all_run_commands(_publish)):
            assert "uv lock --check" in text

    def test_frozen_sync_all_groups_present(self) -> None:
        for text in (_all_run_commands(_ci), _all_run_commands(_publish)):
            assert "uv sync --frozen --all-groups" in text

    def test_pytest_present(self) -> None:
        for text in (_all_run_commands(_ci), _all_run_commands(_publish)):
            assert re.search(r"uv run pytest\b", text)

    def test_ruff_present(self) -> None:
        for text in (_all_run_commands(_ci), _all_run_commands(_publish)):
            assert "uv run ruff check" in text

    def test_mypy_present(self) -> None:
        for text in (_all_run_commands(_ci), _all_run_commands(_publish)):
            assert re.search(r"uv run mypy\b", text)

    def test_mypy_is_never_invoked_with_a_bare_dot_path(self) -> None:
        """CLAUDE.md/README.md both document that `uv run mypy .` walks
        the vendored Knowledge/ corpus and fails on an unrelated,
        pre-existing module-name collision — the correct, scoped
        invocation is bare `uv run mypy` (uses [tool.mypy].files)."""
        for text in (_all_run_commands(_ci), _all_run_commands(_publish)):
            assert "uv run mypy ." not in text

    def test_no_requirements_txt_referenced(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "requirements.txt" not in text

    def test_no_pip_install_used_for_dependency_management(self) -> None:
        for text in (_all_run_commands(_ci), _all_run_commands(_publish)):
            assert "pip install" not in text

    def test_uv_not_installed_via_curl_pipe_sh(self) -> None:
        for text in (_all_run_commands(_ci), _all_run_commands(_publish)):
            assert "curl" not in text or "astral.sh" not in text

    def test_uv_cache_enabled(self) -> None:
        for data in (_ci, _publish):
            for step in _steps_using(data, "astral-sh/setup-uv@"):
                assert step.get("with", {}).get("enable-cache") is True


# ---------------------------------------------------------------------------
# Compose validation
# ---------------------------------------------------------------------------

class TestComposeValidation:
    def test_default_compose_config_rendered_in_ci(self) -> None:
        assert "docker compose config" in _all_run_commands(_ci)

    def test_default_compose_config_rendered_in_publish(self) -> None:
        assert "docker compose config" in _all_run_commands(_publish)

    def test_htb_override_config_rendered_in_ci(self) -> None:
        text = _all_run_commands(_ci)
        assert "compose.htb.yaml" in text
        assert "--profile htb" in text
        assert "config" in text

    def test_htb_override_config_rendered_in_publish(self) -> None:
        text = _all_run_commands(_publish)
        assert "compose.htb.yaml" in text
        assert "--profile htb" in text

    def test_no_vpn_startup_command_anywhere(self) -> None:
        """`docker compose ... up` (which would actually start containers,
        including the vpn service) must never appear — only `config`
        (pure rendering) is used anywhere in either workflow."""
        for text in (_ci_text, _publish_text):
            assert not re.search(r"docker compose[^\n]*\bup\b", text)
            assert "--profile htb up" not in text

    def test_no_dev_net_tun_referenced(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "/dev/net/tun" not in text or "test ! -e /dev/net/tun" in text

    def test_htb_ovpn_path_is_a_placeholder_never_a_real_secrets_path(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "ci-placeholder.ovpn" in text
            # No committed real profile filename (htb.ovpn without the
            # "ci-placeholder" qualifier would suggest a real operator path).
            assert "secrets/htb.ovpn" not in text

    def test_no_target_ip_literal_anywhere(self) -> None:
        ipv4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        allowed = {"0.0.0.0", "127.0.0.1"}
        for text in (_ci_text, _publish_text):
            for line in text.splitlines():
                if line.strip().startswith("#"):
                    continue
                for match in ipv4.finditer(line):
                    assert match.group(0) in allowed, f"unexpected IPv4 literal: {line!r}"

    def test_no_apex_target_env_var_set(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "APEX_TARGET" not in text

    def test_no_live_mode_flags(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "--confirm-live" not in text
            assert "--no-dry-run" not in text
            assert "run_htb_local" not in text

    def test_compose_output_redirected_not_printed(self) -> None:
        """Rendered Compose config is redirected to a file, never piped
        straight to the job log — defense in depth even though only
        disposable placeholder values are used."""
        text = _all_run_commands(_ci)
        for line in text.splitlines():
            if "docker compose" in line and "config" in line:
                continue  # multi-line run blocks continue onto the next line with the redirect
        assert "> /tmp/compose-default.rendered.yml" in text
        assert "> /tmp/compose-htb.rendered.yml" in text


# ---------------------------------------------------------------------------
# Image matrix
# ---------------------------------------------------------------------------

class TestImageMatrix:
    def test_ci_matrix_has_exactly_three_images(self) -> None:
        include = _matrix_include(_ci, "build-images")
        assert len(include) == 3

    def test_publish_matrix_has_exactly_three_images(self) -> None:
        include = _matrix_include(_publish, "build-and-push")
        assert len(include) == 3

    def test_ci_matrix_images_and_dockerfiles(self) -> None:
        include = _matrix_include(_ci, "build-images")
        found = {entry["image"]: entry["dockerfile"] for entry in include}
        assert found == _EXPECTED_IMAGES

    def test_publish_matrix_images_and_dockerfiles(self) -> None:
        include = _matrix_include(_publish, "build-and-push")
        found = {entry["image"]: entry["dockerfile"] for entry in include}
        assert found == _EXPECTED_IMAGES

    def test_build_context_is_repository_root_in_ci(self) -> None:
        job = _ci["jobs"]["build-images"]
        build_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@"))
        assert build_step["with"]["context"] == "."

    def test_build_context_is_repository_root_in_publish(self) -> None:
        job = _publish["jobs"]["build-and-push"]
        build_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@"))
        assert build_step["with"]["context"] == "."


# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------

class TestPublishing:
    def test_ghcr_is_used(self) -> None:
        assert "ghcr.io" in _publish_text

    def test_github_token_is_used_never_a_pat(self) -> None:
        login_steps = _steps_using(_publish, "docker/login-action@")
        assert login_steps
        for step in login_steps:
            assert step["with"]["password"] == "${{ secrets.GITHUB_TOKEN }}"

    def test_login_action_only_in_publish_workflow(self) -> None:
        assert _steps_using(_publish, "docker/login-action@")
        assert not _steps_using(_ci, "docker/login-action@")
        assert "docker/login-action" not in _ci_text

    def test_metadata_action_used_in_publish(self) -> None:
        assert _steps_using(_publish, "docker/metadata-action@")

    def test_buildx_used_in_both_workflows(self) -> None:
        assert _steps_using(_ci, "docker/setup-buildx-action@")
        assert _steps_using(_publish, "docker/setup-buildx-action@")

    def test_ci_build_steps_never_push(self) -> None:
        job = _ci["jobs"]["build-images"]
        build_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@"))
        assert build_step["with"]["push"] is False

    def test_publish_build_steps_push_true(self) -> None:
        job = _publish["jobs"]["build-and-push"]
        build_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@"))
        assert build_step["with"]["push"] is True

    def test_publishing_depends_on_validate_job(self) -> None:
        job = _publish["jobs"]["build-and-push"]
        needs = job["needs"]
        if isinstance(needs, str):
            needs = [needs]
        assert "validate" in needs

    def test_latest_tag_limited_to_default_branch(self) -> None:
        job = _publish["jobs"]["build-and-push"]
        meta_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/metadata-action@"))
        tags_config = meta_step["with"]["tags"]
        for line in tags_config.splitlines():
            if "value=latest" in line:
                assert "is_default_branch" in line

    def test_sha_tags_configured(self) -> None:
        job = _publish["jobs"]["build-and-push"]
        meta_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/metadata-action@"))
        assert "type=sha" in meta_step["with"]["tags"]

    def test_version_tags_configured(self) -> None:
        job = _publish["jobs"]["build-and-push"]
        meta_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/metadata-action@"))
        assert "type=semver" in meta_step["with"]["tags"]

    def test_oci_labels_applied(self) -> None:
        job = _publish["jobs"]["build-and-push"]
        meta_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/metadata-action@"))
        labels = meta_step["with"]["labels"]
        assert "org.opencontainers.image.title" in labels
        assert "org.opencontainers.image.description" in labels

    def test_provenance_and_sbom_enabled_only_when_pushing(self) -> None:
        publish_build = next(
            s for s in _publish["jobs"]["build-and-push"]["steps"]
            if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@")
        )
        assert publish_build["with"].get("provenance") is True
        assert publish_build["with"].get("sbom") is True

        ci_build = next(
            s for s in _ci["jobs"]["build-images"]["steps"]
            if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@")
        )
        assert "provenance" not in ci_build["with"]
        assert "sbom" not in ci_build["with"]

    def test_owner_is_derived_not_hardcoded(self) -> None:
        """The GHCR image owner comes from github.repository_owner
        (lowercased), never a hardcoded personal username."""
        assert "github.repository_owner" in _publish_text
        # No obviously-hardcoded personal-looking owner segment in the
        # image reference itself.
        assert "ghcr.io/rownakdiganta/" not in _publish_text.lower().replace(
            "${{ steps.owner.outputs.owner }}", "",
        )

    def test_owner_lowercasing_uses_safe_bash_parameter_expansion(self) -> None:
        """No unsafe shell evaluation (eval, backticks) for the
        lowercasing step."""
        assert "eval " not in _publish_text
        assert "eval(" not in _publish_text
        text = _all_run_commands(_publish)
        assert "${OWNER,,}" in text


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

class TestCache:
    def test_gha_cache_enabled_in_ci(self) -> None:
        job = _ci["jobs"]["build-images"]
        build_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@"))
        assert build_step["with"]["cache-from"].startswith("type=gha")
        assert build_step["with"]["cache-to"].startswith("type=gha")

    def test_gha_cache_enabled_in_publish(self) -> None:
        job = _publish["jobs"]["build-and-push"]
        build_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@"))
        assert build_step["with"]["cache-from"].startswith("type=gha")
        assert build_step["with"]["cache-to"].startswith("type=gha")

    def test_cache_scope_is_parameterized_by_matrix_image(self) -> None:
        for data, job_name in ((_ci, "build-images"), (_publish, "build-and-push")):
            job = data["jobs"][job_name]
            build_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@"))
            assert "matrix.image" in build_step["with"]["cache-from"]
            assert "matrix.image" in build_step["with"]["cache-to"]

    def test_cache_to_uses_mode_max(self) -> None:
        for data, job_name in ((_ci, "build-images"), (_publish, "build-and-push")):
            job = data["jobs"][job_name]
            build_step = next(s for s in job["steps"] if isinstance(s.get("uses"), str) and s["uses"].startswith("docker/build-push-action@"))
            assert "mode=max" in build_step["with"]["cache-to"]


# ---------------------------------------------------------------------------
# Secret safety
# ---------------------------------------------------------------------------

class TestSecretSafety:
    def test_no_openai_style_api_key(self) -> None:
        for text in (_ci_text, _publish_text):
            assert re.search(r"sk-[A-Za-z0-9]{10,}", text) is None

    def test_no_realistic_tool_service_token_value(self) -> None:
        """Only the documented disposable placeholder values ever appear
        — never a realistic-looking secret."""
        for text in (_ci_text, _publish_text):
            assert "APEX_TOOL_SERVICE_TOKEN: ci-disposable-token" in text or "ci-disposable-token" in text
            # A base64/hex-shaped 32+ char literal assigned directly to
            # the token variable would indicate a real secret leaked in.
            assert not re.search(r"APEX_TOOL_SERVICE_TOKEN:\s*[A-Za-z0-9+/]{20,}", text)

    def test_no_env_file_upload(self) -> None:
        for text in (_ci_text, _publish_text):
            assert ".env" not in text or "APEX_TOOL_SERVICE_TOKEN" in text  # only ever referenced as an env: block, not a path
            assert "upload-artifact" not in text

    def test_no_ovpn_content_or_real_profile_path(self) -> None:
        for text in (_ci_text, _publish_text):
            for line in text.splitlines():
                if ".ovpn" in line and not line.strip().startswith("#"):
                    assert "ci-placeholder.ovpn" in line

    def test_no_generic_credential_patterns(self) -> None:
        for text in (_ci_text, _publish_text):
            assert re.search(r"password\s*[:=]\s*['\"][^'\"$]", text, re.IGNORECASE) is None
            assert "BEGIN PRIVATE KEY" not in text
            assert "BEGIN RSA PRIVATE KEY" not in text

    def test_no_htb_target_ip(self) -> None:
        # 10.129.0.0/16 is the documented, generic HTB-lab CIDR (never a
        # literal target IP) — assert no more-specific 10.129.x.x host
        # address appears anywhere.
        for text in (_ci_text, _publish_text):
            assert not re.search(r"\b10\.129\.\d{1,3}\.\d{1,3}\b", text)

    def test_no_live_apex_execution(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "apex_host.main" not in text
            assert "apex_host.container_entrypoint run" not in text
            assert "--confirm-live" not in text

    def test_no_privileged_true(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "privileged: true" not in text
            assert "privileged:true" not in text.replace(" ", "")

    def test_no_docker_socket_mount(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "docker.sock" not in text

    def test_no_host_networking(self) -> None:
        for text in (_ci_text, _publish_text):
            assert "network_mode: host" not in text
            assert "--network host" not in text

    def test_secrets_context_only_used_for_github_token(self) -> None:
        """The only `secrets.*` context reference anywhere in either
        workflow is the built-in GITHUB_TOKEN — no custom/manual PAT
        secret is referenced."""
        for text in (_ci_text, _publish_text):
            secret_refs = re.findall(r"secrets\.(\w+)", text)
            assert set(secret_refs) <= {"GITHUB_TOKEN"}
