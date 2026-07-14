# test_apex_dockerfile.py
# Static, content-based verification of docker/apex/Dockerfile and .dockerignore (Infra Phase 5) — does not require a Docker daemon.
"""Static checks for the APEX application container build context.

These tests read `docker/apex/Dockerfile` and `.dockerignore` as plain text
and assert on their *content* (substrings/regexes/line ordering), not their
exact formatting — a comment rewording or line-wrap should never break
these tests. They intentionally do not require Docker to be installed or
running; the actual build + runtime smoke tests are performed manually
(and recorded in `docs/apex-container.md` / the Phase 5 report) since a
`docker build` in a test suite would be slow, environment-dependent, and
outside what "focused static tests" means here.
"""
from __future__ import annotations

import pathlib
import re

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_DOCKERFILE_PATH = _REPO_ROOT / "docker" / "apex" / "Dockerfile"
_DOCKERIGNORE_PATH = _REPO_ROOT / ".dockerignore"

_KALI_TOOLS = ("nmap", "telnet", "netcat", "hydra", "gobuster", "ffuf")


def _dockerfile_text() -> str:
    return _DOCKERFILE_PATH.read_text(encoding="utf-8")


def _dockerfile_lines() -> list[str]:
    return _dockerfile_text().splitlines()


def _non_comment_lines() -> list[str]:
    return [ln for ln in _dockerfile_lines() if ln.strip() and not ln.strip().startswith("#")]


def _dockerignore_lines() -> list[str]:
    text = _DOCKERIGNORE_PATH.read_text(encoding="utf-8")
    return [
        ln.strip() for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]


# ---------------------------------------------------------------------------
# Existence
# ---------------------------------------------------------------------------

def test_dockerfile_exists() -> None:
    assert _DOCKERFILE_PATH.is_file()


def test_dockerignore_exists() -> None:
    assert _DOCKERIGNORE_PATH.is_file()


# ---------------------------------------------------------------------------
# Base image: pinned, not `latest`
# ---------------------------------------------------------------------------

def _from_lines() -> list[str]:
    return [ln for ln in _non_comment_lines() if re.match(r"^FROM\s", ln)]


def test_at_least_two_from_stages_multi_stage_build() -> None:
    froms = _from_lines()
    assert len(froms) >= 2, f"expected a multi-stage build, found {len(froms)} FROM line(s)"


def test_every_from_line_names_a_stage() -> None:
    for ln in _from_lines():
        assert re.search(r"\bAS\s+\w+", ln, re.IGNORECASE), f"FROM line missing stage name: {ln!r}"


def test_no_latest_tag_anywhere() -> None:
    for ln in _from_lines():
        assert ":latest" not in ln, f"FROM line uses a floating 'latest' tag: {ln!r}"


def test_python_base_image_pinned_by_digest() -> None:
    python_froms = [ln for ln in _from_lines() if re.search(r"\bpython:", ln)]
    assert python_froms, "expected at least one `FROM python:...` stage"
    for ln in python_froms:
        assert "@sha256:" in ln, f"Python base image not pinned by digest: {ln!r}"
        assert re.search(r"python:3\.11", ln), f"expected a Python 3.11 base image: {ln!r}"


def test_uv_tool_image_pinned_by_digest() -> None:
    uv_froms = [ln for ln in _from_lines() if "astral-sh/uv" in ln]
    assert uv_froms, "expected the official astral-sh/uv image as a build stage"
    for ln in uv_froms:
        assert "@sha256:" in ln, f"uv image not pinned by digest: {ln!r}"


# ---------------------------------------------------------------------------
# Locked, frozen dependency installation
# ---------------------------------------------------------------------------

def test_uv_sync_uses_frozen_flag() -> None:
    text = _dockerfile_text()
    assert re.search(r"uv sync[^\n]*--frozen", text), (
        "expected `uv sync --frozen` so the build fails on a stale/inconsistent lock file"
    )


def test_uv_sync_excludes_dev_dependencies() -> None:
    text = _dockerfile_text()
    assert re.search(r"uv sync[^\n]*--no-dev", text), "expected `uv sync ... --no-dev`"


def test_no_unlocked_pip_requirements_install() -> None:
    for ln in _non_comment_lines():
        assert not re.search(r"pip install\s+-r\s+requirements", ln), (
            f"unlocked `pip install -r requirements*.txt` found: {ln!r}"
        )


def test_lock_file_not_regenerated_in_image() -> None:
    text = _dockerfile_text()
    assert "uv lock" not in text or "uv lock --check" in text or "uv.lock" in text
    # No RUN line may call `uv lock` to (re)generate the lock file inside the image.
    for ln in _non_comment_lines():
        assert not re.match(r"^RUN\s+uv lock\b", ln), f"lock file must not be regenerated in-image: {ln!r}"


def test_uv_lock_copied_before_first_party_source() -> None:
    """Dependency metadata must be COPYed (and installed) before application
    source, so editing source code doesn't invalidate the expensive
    dependency-resolution Docker layer."""
    lines = _dockerfile_lines()
    lock_copy_idx = next(
        (i for i, ln in enumerate(lines) if re.match(r"^COPY\s+.*uv\.lock", ln)), None,
    )
    source_copy_idx = next(
        (i for i, ln in enumerate(lines) if re.match(r"^COPY\s+apex_host\b", ln)), None,
    )
    assert lock_copy_idx is not None, "expected a `COPY ... uv.lock ...` line"
    assert source_copy_idx is not None, "expected a `COPY apex_host ...` line"
    assert lock_copy_idx < source_copy_idx, (
        "uv.lock must be copied (and dependencies installed) before apex_host source, "
        "for Docker layer caching"
    )


# ---------------------------------------------------------------------------
# Non-root execution
# ---------------------------------------------------------------------------

def test_user_directive_present_and_not_root() -> None:
    user_lines = [ln for ln in _non_comment_lines() if re.match(r"^USER\s", ln)]
    assert user_lines, "expected a USER directive"
    last_user = user_lines[-1].split(maxsplit=1)[1].strip()
    assert last_user not in ("root", "0"), f"final USER must not be root: {last_user!r}"


def test_no_sudo_or_password_setup() -> None:
    for ln in _non_comment_lines():
        assert "sudo" not in ln.lower(), f"unexpected sudo reference in a non-comment line: {ln!r}"
        assert "passwd" not in ln.lower(), f"unexpected password-setup reference: {ln!r}"


# ---------------------------------------------------------------------------
# No Docker socket, no container orchestration
# ---------------------------------------------------------------------------

def test_no_docker_socket_reference() -> None:
    text = _dockerfile_text()
    assert "/var/run/docker.sock" not in text
    assert "docker.sock" not in text


def test_no_docker_cli_invocation() -> None:
    for ln in _non_comment_lines():
        assert not re.search(r"\bdocker (exec|run|compose)\b", ln), (
            f"Dockerfile must not invoke Docker itself: {ln!r}"
        )


# ---------------------------------------------------------------------------
# No Kali / offensive tooling installed in the APEX image
# ---------------------------------------------------------------------------

def test_no_kali_tools_in_apt_install_lines() -> None:
    apt_install_lines = [
        ln for ln in _non_comment_lines()
        if "apt-get install" in ln or "apt install" in ln
    ]
    assert apt_install_lines, "expected at least one apt-get install line (libgomp1/ca-certificates)"
    combined = " ".join(apt_install_lines).lower()
    for tool in _KALI_TOOLS:
        assert re.search(rf"\b{re.escape(tool)}\b", combined) is None, (
            f"Kali/offensive tool {tool!r} must not be installed in the APEX image"
        )


def test_no_kali_tool_name_anywhere_as_a_package() -> None:
    """Broader sweep: none of the Kali tool names may appear as a apt/pip
    package target anywhere in the file (not just recognized apt-get lines)."""
    for tool in _KALI_TOOLS:
        # Allow the tool name inside a comment/prose sentence (explaining
        # what is *excluded*) but never as an install target token.
        for ln in _non_comment_lines():
            assert tool not in ln.lower(), f"unexpected reference to {tool!r} in a non-comment line: {ln!r}"


def test_does_not_start_the_tool_service() -> None:
    text = _dockerfile_text()
    assert "apex_tool_service.app" not in text or "CMD" not in text.split("apex_tool_service.app")[-1][:50]
    for ln in _non_comment_lines():
        if re.match(r"^(CMD|ENTRYPOINT)\b", ln):
            assert "apex_tool_service" not in ln, f"the APEX image must not start the tool service: {ln!r}"


# ---------------------------------------------------------------------------
# Safe default command
# ---------------------------------------------------------------------------

def test_cmd_present_and_safe() -> None:
    """Infra Phase 9: the default CMD is now the container ENTRYPOINT's
    'check' subcommand (apex_host.container_entrypoint) — local-only
    configuration/knowledge/policy validation, no target, no network call.
    ('--help' was Phase 5's own safe default before the entrypoint existed;
    'check' is a stricter, more thorough safe default — see
    docs/container-entrypoint.md.)"""
    cmd_lines = [ln for ln in _non_comment_lines() if re.match(r"^CMD\b", ln)]
    assert cmd_lines, "expected a default CMD"
    cmd = cmd_lines[-1]
    assert "--no-dry-run" not in cmd, f"default CMD must not disable dry-run: {cmd!r}"
    assert "--target" not in cmd, f"default CMD must not hardcode a target: {cmd!r}"
    assert "--confirm-live" not in cmd, f"default CMD must never confirm live mode: {cmd!r}"
    assert re.search(r'"check"', cmd), f"expected the safe default CMD to use 'check' mode: {cmd!r}"


def test_entrypoint_present_and_uses_container_entrypoint_module() -> None:
    entrypoint_lines = [ln for ln in _non_comment_lines() if re.match(r"^ENTRYPOINT\b", ln)]
    assert entrypoint_lines, "expected an ENTRYPOINT directive (Infra Phase 9)"
    entrypoint = entrypoint_lines[-1]
    assert "apex_host.container_entrypoint" in entrypoint
    assert entrypoint.strip().startswith("ENTRYPOINT ["), "must be exec-form JSON array, not shell form"


def test_entrypoint_and_cmd_use_no_shell_json_array_form() -> None:
    for ln in _non_comment_lines():
        if re.match(r"^(ENTRYPOINT|CMD)\b", ln):
            assert ln.strip().endswith("]"), f"must be exec-form (JSON array): {ln!r}"
            assert " && " not in ln and " || " not in ln and ";" not in ln, f"no shell operators allowed: {ln!r}"


def test_no_hardcoded_target_ip_anywhere() -> None:
    """No dotted-quad IPv4 literal appears anywhere in non-comment Dockerfile
    lines (a hardcoded Meow/HTB target would look like this)."""
    ipv4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    for ln in _non_comment_lines():
        assert ipv4.search(ln) is None, f"unexpected IPv4 literal in Dockerfile: {ln!r}"


def test_no_hardcoded_secret_values() -> None:
    text = _dockerfile_text()
    # No ENV/ARG line may assign a real-looking secret value to the known
    # secret-shaped variables — they must be absent from ENV/ARG entirely
    # (accepted at `docker run` time only), never defaulted here.
    forbidden_assigned = re.compile(
        r"^(ENV|ARG)\s+(OPENAI_API_KEY|APEX_TOOL_SERVICE_TOKEN)\s*=", re.MULTILINE,
    )
    assert forbidden_assigned.search(text) is None, (
        "OPENAI_API_KEY/APEX_TOOL_SERVICE_TOKEN must never be assigned a value in the Dockerfile"
    )
    # No sk-... (OpenAI-shaped) token literal anywhere.
    assert re.search(r"sk-[A-Za-z0-9]{10,}", text) is None


# ---------------------------------------------------------------------------
# No .env copied
# ---------------------------------------------------------------------------

def test_no_env_file_copied() -> None:
    for ln in _non_comment_lines():
        if re.match(r"^COPY\b", ln):
            assert not re.search(r"\.env\b", ln), f"a COPY line references .env: {ln!r}"


# ---------------------------------------------------------------------------
# Health check decision
# ---------------------------------------------------------------------------

def test_healthcheck_if_present_is_not_trivial_theater() -> None:
    healthcheck_lines = [ln for ln in _non_comment_lines() if ln.startswith("HEALTHCHECK")]
    for ln in healthcheck_lines:
        assert "python --version" not in ln and "python -c \"pass\"" not in ln, (
            f"a HEALTHCHECK must represent real readiness, not interpreter existence: {ln!r}"
        )


# ---------------------------------------------------------------------------
# .dockerignore content
# ---------------------------------------------------------------------------

def test_dockerignore_excludes_git() -> None:
    lines = _dockerignore_lines()
    assert any(ln in (".git", ".git/", ".git/**") for ln in lines)


def test_dockerignore_excludes_venv() -> None:
    lines = _dockerignore_lines()
    assert any(".venv" in ln for ln in lines)


def test_dockerignore_excludes_env_files() -> None:
    lines = _dockerignore_lines()
    assert any(ln in (".env", ".env/") for ln in lines)
    assert any(".env." in ln for ln in lines)


def test_dockerignore_excludes_ovpn_files() -> None:
    lines = _dockerignore_lines()
    assert any("ovpn" in ln.lower() for ln in lines)


def test_dockerignore_excludes_tests() -> None:
    lines = _dockerignore_lines()
    assert "tests" in lines or "tests/" in lines


def test_dockerignore_excludes_caches() -> None:
    lines = _dockerignore_lines()
    text = "\n".join(lines)
    for cache_dir in (".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__"):
        assert cache_dir in text, f"expected {cache_dir!r} excluded from the build context"


def test_dockerignore_excludes_run_reports() -> None:
    lines = _dockerignore_lines()
    assert any("run_reports" in ln for ln in lines)


def test_dockerignore_excludes_raw_knowledge_corpora() -> None:
    lines = _dockerignore_lines()
    text = "\n".join(lines)
    for raw_dir in ("SecLists", "PayloadsAllTheThings", "GTFOBins", "LOLBAS"):
        assert raw_dir in text, f"expected raw corpus {raw_dir!r} excluded from the build context"
    # Raw intel_db source directories (not the compiled/ distillations).
    for raw_intel in ("intel_db/cve", "intel_db/cwe", "intel_db/capec", "intel_db/attack"):
        assert raw_intel in text, f"expected raw dataset {raw_intel!r} excluded"


def test_dockerignore_does_not_exclude_required_runtime_files() -> None:
    """The negative-space check: none of the exclusion patterns may match
    the exact files/directories the Dockerfile needs to COPY."""
    lines = _dockerignore_lines()
    forbidden_bare_excludes = {
        "pyproject.toml", "uv.lock", "memfabric", "apex_host", "apex_tool_service",
        "memfabric/", "apex_host/", "apex_tool_service/", "Knowledge", "Knowledge/",
    }
    for ln in lines:
        assert ln not in forbidden_bare_excludes, (
            f".dockerignore must not blanket-exclude a required runtime path: {ln!r}"
        )


def test_dockerignore_does_not_exclude_compiled_knowledge() -> None:
    lines = _dockerignore_lines()
    for ln in lines:
        assert "compiled" not in ln.lower() or ln.lower().startswith("#"), (
            f".dockerignore must not exclude compiled/ knowledge artifacts: {ln!r}"
        )


# ---------------------------------------------------------------------------
# Dockerfile COPY list matches what .dockerignore permits through
# (cross-check between the two files)
# ---------------------------------------------------------------------------

def test_dockerfile_copies_only_compiled_knowledge_subdirectories() -> None:
    """Every Knowledge-related COPY line in the Dockerfile must reference a
    `.../compiled` path — never a raw source directory."""
    for ln in _non_comment_lines():
        if re.match(r"^COPY\b", ln) and "Knowledge" in ln:
            assert "compiled" in ln, f"Knowledge COPY line must target a compiled/ subdirectory: {ln!r}"
