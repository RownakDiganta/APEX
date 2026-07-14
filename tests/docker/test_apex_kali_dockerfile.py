# test_apex_kali_dockerfile.py
# Static, content-based verification of docker/kali/Dockerfile (Infra Phase 6) — does not require a Docker daemon.
"""Static checks for the Kali Linux tool-service container build.

Mirrors the pattern in `tests/docker/test_apex_dockerfile.py` (Infra
Phase 5): reads `docker/kali/Dockerfile` as plain text and asserts on
content (substrings/regexes/line ordering), never exact formatting, so a
comment rewording or line-wrap never breaks these tests. These tests do
not require Docker to be installed or running — the actual build +
runtime validation (image build, container start, tool execution, the
real `RemoteToolBackend` contract smoke test) is performed manually and
recorded in `docs/kali-container.md`.
"""
from __future__ import annotations

import pathlib
import re

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_DOCKERFILE_PATH = _REPO_ROOT / "docker" / "kali" / "Dockerfile"
_DOCKERIGNORE_PATH = _REPO_ROOT / ".dockerignore"
_ALLOWLIST_PATH = _REPO_ROOT / "apex_tool_service" / "allowlist.py"

# Tools explicitly forbidden by this phase's task brief: metapackages,
# exploit frameworks, brute-force/password-cracking tools, and fuzzers not
# present in apex_tool_service's own allowlist.
_FORBIDDEN_PACKAGES = (
    "kali-linux-default",
    "kali-linux-large",
    "kali-linux-everything",
    "metasploit-framework",
    "sqlmap",
    "hydra",
    "medusa",
    "patator",
    "gobuster",
    "ffuf",
    "nikto",
    "whatweb",
    "masscan",
    "john",
    "hashcat",
    "telnetd",
    "openssh-server",
)

# apex_tool_service/allowlist.py::ALLOWED_TOOLS keys this image must satisfy.
_ALLOWLISTED_TOOLS = ("nmap", "curl", "nc", "netcat", "ping", "telnet")


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


def _non_comment_joined() -> str:
    """All non-comment lines joined into one string, so a RUN instruction
    split across multiple `\\`-continued lines can still be matched by a
    single substring/regex check."""
    return " ".join(_non_comment_lines())


def _logical_run_blocks() -> list[str]:
    """Group non-comment lines into logical Dockerfile instructions: a line
    starting a new instruction (RUN/COPY/ENV/...) begins a block, and any
    following lines that are pure continuations (the previous line in the
    block ended with a trailing `\\`) are appended to it."""
    blocks: list[str] = []
    current: list[str] = []
    for ln in _non_comment_lines():
        if current and current[-1].rstrip().endswith("\\"):
            current.append(ln)
        else:
            if current:
                blocks.append(" ".join(current))
            current = [ln]
    if current:
        blocks.append(" ".join(current))
    return blocks


# ---------------------------------------------------------------------------
# Existence
# ---------------------------------------------------------------------------

def test_dockerfile_exists() -> None:
    assert _DOCKERFILE_PATH.is_file()


def test_file_header_convention() -> None:
    lines = _dockerfile_lines()
    assert lines[0] == "# Dockerfile"
    assert lines[1].startswith("# ")


# ---------------------------------------------------------------------------
# Base image: official Kali, pinned by digest, not `latest`
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


def test_kali_base_image_is_official_and_pinned_by_digest() -> None:
    kali_froms = [ln for ln in _from_lines() if "kalilinux/kali-rolling" in ln]
    assert kali_froms, "expected `FROM kalilinux/kali-rolling@sha256:...` (the official Kali image)"
    for ln in kali_froms:
        assert "@sha256:" in ln, f"Kali base image not pinned by digest: {ln!r}"


def test_no_unofficial_kali_image_reference() -> None:
    text = _dockerfile_text().lower()
    # Guard against a community-maintained substitute image being swapped in.
    assert "kalilinux/kali-rolling" in text
    for bad in ("kasmweb/kali", "linuxserver/kali", "diglol/kali", "lscr.io/linuxserver/kali"):
        assert bad not in text, f"unofficial Kali image reference found: {bad!r}"


def test_kali_base_used_for_both_stages() -> None:
    """Both builder and runtime stages must be the same official, pinned Kali
    base — no python:slim/debian:slim substitution for either stage."""
    kali_froms = [ln for ln in _from_lines() if "kalilinux/kali-rolling" in ln]
    assert len(kali_froms) == 2, f"expected exactly 2 Kali-based stages, found {len(kali_froms)}: {kali_froms}"


def test_uv_tool_image_pinned_by_digest() -> None:
    uv_froms = [ln for ln in _from_lines() if "astral-sh/uv" in ln]
    assert uv_froms, "expected the official astral-sh/uv image as a build stage"
    for ln in uv_froms:
        assert "@sha256:" in ln, f"uv image not pinned by digest: {ln!r}"


# ---------------------------------------------------------------------------
# Locked, frozen dependency installation; no dev deps
# ---------------------------------------------------------------------------

def test_uv_sync_uses_frozen_flag() -> None:
    text = _dockerfile_text()
    assert re.search(r"uv sync[^\n]*--frozen", text), (
        "expected `uv sync --frozen` so the build fails on a stale/inconsistent lock file"
    )


def test_uv_sync_excludes_dev_dependencies() -> None:
    blocks = [b for b in _logical_run_blocks() if "uv sync" in b]
    assert blocks, "expected at least one `uv sync` invocation"
    for b in blocks:
        assert "--no-dev" in b, f"every `uv sync` call must exclude dev dependencies: {b!r}"


def test_no_unlocked_pip_requirements_install() -> None:
    for ln in _non_comment_lines():
        assert not re.search(r"pip install\s+-r\s+requirements", ln), (
            f"unlocked `pip install -r requirements*.txt` found: {ln!r}"
        )
        assert not re.match(r"^RUN\s+pip\b", ln), f"no direct pip install expected: {ln!r}"


def test_lock_file_not_regenerated_in_image() -> None:
    for ln in _non_comment_lines():
        assert not re.match(r"^RUN\s+uv lock\b", ln), f"lock file must not be regenerated in-image: {ln!r}"


def test_uv_lock_copied_before_first_party_source() -> None:
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
        "uv.lock must be copied (and dependencies installed) before apex_host source"
    )


def test_no_uv_in_runtime_stage_env_path() -> None:
    """The final runtime stage should not need `uv` itself at container run
    time — only the pre-built venv and its interpreter are copied forward."""
    text = _dockerfile_text()
    runtime_stage = text.split("AS runtime", 1)[-1]
    assert "COPY --from=uv" not in runtime_stage, "uv binary must not be copied into the runtime stage"
    assert not re.search(r"^RUN\s+uv\s", runtime_stage, re.MULTILINE), (
        "no `uv` invocation expected in the runtime stage"
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


def test_no_capabilities_added_in_dockerfile() -> None:
    joined = _non_comment_joined()
    assert "--cap-add" not in joined, "capability grants belong to a future Compose phase, not this Dockerfile"
    assert "setcap" not in joined, "no additional file capabilities should be granted in this phase"


# ---------------------------------------------------------------------------
# No Docker socket, no container orchestration, no general remote shell
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


def test_no_ssh_server_installed() -> None:
    for ln in _non_comment_lines():
        assert "openssh-server" not in ln, f"unexpected SSH server install: {ln!r}"


def test_no_telnet_daemon_installed() -> None:
    apt_blocks = " ".join(b for b in _logical_run_blocks() if "apt-get install" in b)
    assert not re.search(r"\btelnetd\b", apt_blocks), "telnetd (server) must not be installed, only the telnet client"
    assert re.search(r"\btelnet\b", apt_blocks), "expected the telnet client to be installed"


# ---------------------------------------------------------------------------
# Tool manifest: no forbidden packages; allowlist tools installed
# ---------------------------------------------------------------------------

def test_no_forbidden_packages_in_apt_install_lines() -> None:
    apt_blocks = [b for b in _logical_run_blocks() if "apt-get install" in b or "apt install" in b]
    assert apt_blocks, "expected at least one apt-get install block"
    combined = " ".join(apt_blocks).lower()
    for pkg in _FORBIDDEN_PACKAGES:
        assert re.search(rf"\b{re.escape(pkg)}\b", combined) is None, (
            f"forbidden package {pkg!r} must not be installed in the Kali tool-service image"
        )


def test_no_forbidden_package_name_anywhere_as_a_token() -> None:
    """Broader sweep: none of the forbidden package names may appear as an
    install target anywhere in the file (not just recognized apt-get lines)."""
    for pkg in _FORBIDDEN_PACKAGES:
        for ln in _non_comment_lines():
            assert pkg not in ln.lower(), f"unexpected reference to {pkg!r} in a non-comment line: {ln!r}"


def test_allowlisted_tools_have_corresponding_apt_packages() -> None:
    """Every apex_tool_service allowlist entry must map to an installed apt
    package in the runtime stage (nmap/curl/telnet map 1:1 by name;
    ping -> iputils-ping; nc/netcat -> netcat-openbsd, evidence recorded in
    docs/kali-container.md)."""
    text = _dockerfile_text()
    runtime_stage = text.split("AS runtime", 1)[-1]
    assert re.search(r"\bnmap\b", runtime_stage)
    assert re.search(r"\bcurl\b", runtime_stage)
    assert re.search(r"\btelnet\b", runtime_stage)
    assert "iputils-ping" in runtime_stage, "expected iputils-ping (provides the `ping` binary)"
    assert "netcat-openbsd" in runtime_stage, "expected netcat-openbsd (provides both `nc` and `netcat`)"


def test_allowlist_module_has_no_extra_tools_beyond_manifest() -> None:
    """Cross-check: apex_tool_service's own ALLOWED_TOOLS keys are exactly
    the set this Dockerfile documents installing (via iputils-ping /
    netcat-openbsd / nmap / curl / telnet)."""
    allowlist_text = _ALLOWLIST_PATH.read_text(encoding="utf-8")
    match = re.search(r"ALLOWED_TOOLS[^{]*\{([^}]*)\}", allowlist_text, re.DOTALL)
    assert match, "could not locate ALLOWED_TOOLS dict in allowlist.py"
    keys = set(re.findall(r'"([a-zA-Z0-9_]+)"\s*:', match.group(1)))
    assert keys == set(_ALLOWLISTED_TOOLS), (
        f"apex_tool_service allowlist {keys} no longer matches the tool manifest "
        f"this test (and docs/kali-container.md) assumes: {set(_ALLOWLISTED_TOOLS)}"
    )


def test_no_iproute2_installed_no_allowlist_mapping() -> None:
    """iproute2 was in this phase's 'minimum evaluation set' but maps to no
    apex_tool_service allowlist entry and no code-usage evidence — evaluated
    and deliberately excluded (see docs/kali-container.md)."""
    apt_install_lines = " ".join(ln for ln in _non_comment_lines() if "apt-get install" in ln)
    assert "iproute2" not in apt_install_lines


# ---------------------------------------------------------------------------
# Python provisioning: managed interpreter, no reliance on Kali's own apt
# python3 package for the copied venv
# ---------------------------------------------------------------------------

def test_uv_python_install_pins_exact_version() -> None:
    text = _dockerfile_text()
    assert re.search(r"uv python install 3\.11\.14", text), (
        "expected a pinned `uv python install 3.11.14` (matching docker/apex/Dockerfile's pin)"
    )


def test_managed_python_copied_into_runtime_stage() -> None:
    text = _dockerfile_text()
    assert re.search(r"COPY --from=builder\s+/opt/uv-python\s+/opt/uv-python", text), (
        "expected the managed CPython directory copied byte-for-byte into the runtime stage"
    )


# ---------------------------------------------------------------------------
# Startup command: only the tool service, nothing else
# ---------------------------------------------------------------------------

def test_cmd_starts_only_the_tool_service() -> None:
    cmd_lines = [ln for ln in _non_comment_lines() if re.match(r"^CMD\b", ln)]
    assert cmd_lines, "expected a default CMD"
    cmd = cmd_lines[-1]
    if "apex_tool_service" in cmd:
        return
    # Indirect form: CMD invokes a copied entrypoint script that itself
    # delegates to apex_tool_service.__main__.main() (see
    # docker/kali/entrypoint.py) — verify that script actually does so.
    entrypoint_copy = next(
        (ln for ln in _non_comment_lines() if re.match(r"^COPY\b.*entrypoint\.py", ln)), None,
    )
    assert entrypoint_copy is not None, (
        f"CMD does not reference apex_tool_service directly and no entrypoint.py is COPYed: {cmd!r}"
    )
    entrypoint_path = _REPO_ROOT / "docker" / "kali" / "entrypoint.py"
    assert entrypoint_path.is_file(), f"entrypoint.py referenced but missing: {entrypoint_path}"
    entrypoint_text = entrypoint_path.read_text(encoding="utf-8")
    assert "apex_tool_service" in entrypoint_text, (
        "entrypoint.py must delegate to apex_tool_service"
    )
    assert re.search(r"\.main\s*\(", entrypoint_text) or "main(" in entrypoint_text


def test_cmd_does_not_launch_a_shell() -> None:
    cmd_lines = [ln for ln in _non_comment_lines() if re.match(r"^(CMD|ENTRYPOINT)\b", ln)]
    for ln in cmd_lines:
        for shell in ("bash", "/bin/sh", '"sh"', "zsh"):
            assert shell not in ln, f"CMD/ENTRYPOINT must not launch a shell: {ln!r}"


def test_no_offensive_tool_autostarted() -> None:
    cmd_lines = [ln for ln in _non_comment_lines() if re.match(r"^(CMD|ENTRYPOINT)\b", ln)]
    for ln in cmd_lines:
        for tool in ("nmap", "hydra", "msfconsole"):
            assert tool not in ln, f"CMD/ENTRYPOINT must not autostart {tool!r}: {ln!r}"


# ---------------------------------------------------------------------------
# Port, host binding, health check
# ---------------------------------------------------------------------------

def test_expose_8080() -> None:
    text = _dockerfile_text()
    assert re.search(r"^EXPOSE\s+8080\s*$", text, re.MULTILINE), "expected `EXPOSE 8080`"


def test_binds_0_0_0_0_via_env() -> None:
    text = _dockerfile_text()
    assert re.search(r"APEX_TOOL_SERVICE_HOST\s*=\s*0\.0\.0\.0", text), (
        "expected APEX_TOOL_SERVICE_HOST=0.0.0.0 so the service is reachable from outside the container "
        "(the service's own default is 127.0.0.1-only)"
    )


def test_healthcheck_present_and_targets_health_endpoint() -> None:
    text = _dockerfile_text()
    healthcheck_lines = [ln for ln in _non_comment_lines() if ln.startswith("HEALTHCHECK")]
    assert healthcheck_lines, "expected a HEALTHCHECK directive"
    hc_block = text[text.index("HEALTHCHECK"):]
    assert "/health" in hc_block.split("CMD", 2)[-1][:200] or "/health" in text
    assert re.search(r"curl", " ".join(healthcheck_lines) + text[text.index("HEALTHCHECK"):text.index("HEALTHCHECK") + 300])


def test_healthcheck_does_not_require_bearer_token() -> None:
    text = _dockerfile_text()
    hc_start = text.index("HEALTHCHECK")
    hc_segment = text[hc_start:hc_start + 400]
    assert "Authorization" not in hc_segment, f"health check must not require auth: {hc_segment!r}"
    assert "Bearer" not in hc_segment


def test_healthcheck_has_interval_timeout_retries() -> None:
    healthcheck_lines = [ln for ln in _non_comment_lines() if ln.startswith("HEALTHCHECK")]
    assert healthcheck_lines
    hc = healthcheck_lines[0]
    assert "--interval=" in hc
    assert "--timeout=" in hc
    assert "--retries=" in hc


def test_healthcheck_if_present_is_not_trivial_theater() -> None:
    healthcheck_lines = [ln for ln in _non_comment_lines() if ln.startswith("HEALTHCHECK")]
    for ln in healthcheck_lines:
        assert "python --version" not in ln and 'python -c "pass"' not in ln, (
            f"a HEALTHCHECK must represent real readiness, not interpreter existence: {ln!r}"
        )


# ---------------------------------------------------------------------------
# No hardcoded secrets / tokens
# ---------------------------------------------------------------------------

def test_no_hardcoded_bearer_token() -> None:
    text = _dockerfile_text()
    forbidden_assigned = re.compile(r"^(ENV|ARG)\s+APEX_TOOL_SERVICE_TOKEN\s*=", re.MULTILINE)
    assert forbidden_assigned.search(text) is None, (
        "APEX_TOOL_SERVICE_TOKEN must never be assigned a value in the Dockerfile"
    )


def test_no_hardcoded_secret_values() -> None:
    text = _dockerfile_text()
    assert re.search(r"sk-[A-Za-z0-9]{10,}", text) is None
    assert "phase6-test-token" not in text, "no realistic-looking test token literal in the Dockerfile"


def test_no_hardcoded_target_ip_anywhere() -> None:
    ipv4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    for ln in _non_comment_lines():
        for m in ipv4.finditer(ln):
            assert m.group(0) in ("127.0.0.1", "0.0.0.0"), (
                f"unexpected non-loopback/non-bind-all IPv4 literal in Dockerfile: {ln!r}"
            )


# ---------------------------------------------------------------------------
# Filesystem: no secrets/knowledge/reports copied
# ---------------------------------------------------------------------------

def test_no_env_file_copied() -> None:
    for ln in _non_comment_lines():
        if re.match(r"^COPY\b", ln):
            assert not re.search(r"\.env\b", ln), f"a COPY line references .env: {ln!r}"


def test_no_ovpn_file_copied() -> None:
    text = _dockerfile_text()
    assert ".ovpn" not in text


def test_no_knowledge_directory_copied() -> None:
    for ln in _non_comment_lines():
        if re.match(r"^COPY\b", ln):
            assert "Knowledge" not in ln and "knowledge" not in ln, (
                f"the Kali tool-service image must carry no knowledge corpora: {ln!r}"
            )


def test_no_run_reports_directory_created() -> None:
    text = _dockerfile_text()
    assert "run_reports" not in text


def test_no_secrets_directory_copied() -> None:
    for ln in _non_comment_lines():
        if re.match(r"^COPY\b", ln):
            assert "secrets" not in ln.lower(), f"unexpected secrets reference in COPY: {ln!r}"


# ---------------------------------------------------------------------------
# APT hygiene: cache cleanup, noninteractive, no-install-recommends
# ---------------------------------------------------------------------------

def test_apt_lists_cleaned_up() -> None:
    apt_blocks = [b for b in _logical_run_blocks() if "apt-get install" in b]
    assert apt_blocks, "expected at least one apt-get install RUN block"
    for block in apt_blocks:
        assert "rm -rf /var/lib/apt/lists" in block, f"apt-get install block missing cache cleanup: {block!r}"


def test_apt_noninteractive() -> None:
    text = _dockerfile_text()
    assert "DEBIAN_FRONTEND=noninteractive" in text


def test_apt_no_install_recommends() -> None:
    apt_install_lines = [ln for ln in _non_comment_lines() if "apt-get install" in ln]
    for ln in apt_install_lines:
        assert "--no-install-recommends" in ln, f"expected --no-install-recommends: {ln!r}"


def test_apt_update_and_install_combined_in_one_layer() -> None:
    text = _dockerfile_text()
    run_blocks = re.findall(r"RUN\s+apt-get update[\s\\]*&&[\s\\]*apt-get install", text)
    assert run_blocks, "expected `apt-get update && apt-get install` combined in a single RUN"


# ---------------------------------------------------------------------------
# No dev tools (pytest/ruff/mypy) in the final image
# ---------------------------------------------------------------------------

def test_no_dev_tool_installation() -> None:
    joined = _non_comment_joined().lower()
    for tool in ("pytest", "ruff", "mypy"):
        assert tool not in joined, f"dev tool {tool!r} must not appear in a non-comment Dockerfile line"


# ---------------------------------------------------------------------------
# .dockerignore still permits this build (shared file with docker/apex)
# ---------------------------------------------------------------------------

def test_dockerignore_does_not_exclude_docker_directory() -> None:
    lines = _dockerignore_lines()
    for ln in lines:
        assert ln not in ("docker", "docker/", "docker/**"), (
            f".dockerignore must not blanket-exclude docker/, breaking docker/kali/Dockerfile: {ln!r}"
        )


def test_dockerignore_does_not_exclude_required_kali_build_inputs() -> None:
    lines = _dockerignore_lines()
    forbidden_bare_excludes = {
        "pyproject.toml", "uv.lock", "memfabric", "apex_host", "apex_tool_service",
        "memfabric/", "apex_host/", "apex_tool_service/",
    }
    for ln in lines:
        assert ln not in forbidden_bare_excludes, (
            f".dockerignore must not blanket-exclude a required Kali-build input: {ln!r}"
        )
