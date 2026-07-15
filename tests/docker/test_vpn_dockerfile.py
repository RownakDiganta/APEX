# test_vpn_dockerfile.py
# Static, content-based verification of docker/vpn/Dockerfile and its support scripts (Infra Phase 10) — does not require a Docker daemon.
"""Static checks for the VPN container build.

Mirrors the pattern in `tests/docker/test_apex_kali_dockerfile.py` (Infra
Phase 6): reads `docker/vpn/Dockerfile` and its Python support scripts as
plain text and asserts on content, never exact formatting. These tests do
not require Docker to be installed or running — the actual build +
runtime validation (image build, missing-profile/missing-tun fail-fast,
`docker history` inspection) is performed manually and recorded in
`docs/htb-vpn-container.md`.
"""
from __future__ import annotations

import pathlib
import re

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_VPN_DIR = _REPO_ROOT / "docker" / "vpn"
_DOCKERFILE_PATH = _VPN_DIR / "Dockerfile"
_ENTRYPOINT_PATH = _VPN_DIR / "entrypoint.py"
_READINESS_SERVER_PATH = _VPN_DIR / "readiness_server.py"
_ROUTE_CHECK_PATH = _VPN_DIR / "route_check.py"
_TUNNEL_STATUS_PATH = _VPN_DIR / "tunnel_status.py"


def _dockerfile_text() -> str:
    return _DOCKERFILE_PATH.read_text(encoding="utf-8")


def _dockerfile_lines() -> list[str]:
    return _dockerfile_text().splitlines()


def _non_comment_lines() -> list[str]:
    return [ln for ln in _dockerfile_lines() if ln.strip() and not ln.strip().startswith("#")]


def _non_comment_text() -> str:
    return "\n".join(_non_comment_lines())


# ---------------------------------------------------------------------------
# Existence
# ---------------------------------------------------------------------------

def test_dockerfile_exists() -> None:
    assert _DOCKERFILE_PATH.is_file()


def test_all_support_scripts_exist() -> None:
    for path in (_ENTRYPOINT_PATH, _READINESS_SERVER_PATH, _ROUTE_CHECK_PATH, _TUNNEL_STATUS_PATH):
        assert path.is_file(), f"missing required VPN support script: {path}"


def test_file_header_convention() -> None:
    for path in (_DOCKERFILE_PATH, _ENTRYPOINT_PATH, _READINESS_SERVER_PATH, _ROUTE_CHECK_PATH, _TUNNEL_STATUS_PATH):
        lines = path.read_text(encoding="utf-8").splitlines()
        assert lines[0].startswith("# "), f"{path.name} missing file-header first line"
        assert lines[1].startswith("# "), f"{path.name} missing file-header second line"


# ---------------------------------------------------------------------------
# Base image and packages
# ---------------------------------------------------------------------------

def test_uses_official_pinned_python_base_image() -> None:
    text = _dockerfile_text()
    assert "FROM python:3.11.14-slim-bookworm@sha256:" in text, (
        "expected the same digest-pinned Python base image used by docker/apex/Dockerfile"
    )


def test_installs_openvpn_and_iproute2() -> None:
    text = _non_comment_text()
    assert "openvpn" in text
    assert "iproute2" in text


def test_no_dev_tools_or_offensive_packages() -> None:
    text = _non_comment_text().lower()
    forbidden = (
        "sqlmap", "metasploit", "hydra", "medusa", "nmap", "gobuster", "ffuf",
        "netcat", "telnet", "ssh-server", "openssh-server",
    )
    for pkg in forbidden:
        assert pkg not in text, f"unexpected package/tool reference in docker/vpn/Dockerfile: {pkg!r}"


def test_apt_cache_cleaned() -> None:
    text = _dockerfile_text()
    assert "rm -rf /var/lib/apt/lists/*" in text


# ---------------------------------------------------------------------------
# No profile, no credentials, no APEX source baked in
# ---------------------------------------------------------------------------

def test_no_ovpn_file_copied_into_image() -> None:
    text = _dockerfile_text()
    for line in _non_comment_lines():
        assert not line.strip().upper().startswith("COPY") or ".ovpn" not in line, (
            f"unexpected COPY of a .ovpn-shaped path: {line!r}"
        )
    assert "COPY" not in "\n".join(ln for ln in _non_comment_lines() if ".ovpn" in ln)
    assert ".ovpn" not in _non_comment_text() or "mkdir -p /vpn" in text


def test_no_hardcoded_credentials() -> None:
    text = _dockerfile_text()
    assert re.search(r"password\s*=", text, re.IGNORECASE) is None
    assert "APEX_TOOL_SERVICE_TOKEN" not in text
    # sha256 digest pins (hex, a subset of the base64 alphabet) are expected
    # and legitimate (FROM ...@sha256:...) — exclude lines naming them.
    candidate_lines = [ln for ln in _non_comment_lines() if "sha256:" not in ln]
    assert re.search(r"[A-Za-z0-9+/]{32,}={0,2}", "\n".join(candidate_lines)) is None, (
        "no base64-shaped literal (possible embedded secret) in docker/vpn/Dockerfile"
    )


def test_no_apex_source_or_knowledge_copied() -> None:
    text = _non_comment_text()
    for forbidden in ("apex_host", "memfabric", "apex_tool_service", "Knowledge/", "pyproject.toml", "uv.lock"):
        assert forbidden not in text, f"docker/vpn/Dockerfile must not reference {forbidden!r}"


def test_only_first_party_scripts_copied() -> None:
    """Every COPY instruction in this Dockerfile must reference a file
    under docker/vpn/ — no third-party VPN wrapper image content, no
    vendored script from elsewhere in the repository."""
    for line in _non_comment_lines():
        if line.strip().upper().startswith("COPY"):
            assert "docker/vpn/" in line or "mkdir" in line, f"unexpected COPY source: {line!r}"


def test_no_ssh_server_started() -> None:
    text = _non_comment_text().lower()
    assert "sshd" not in text
    assert "openssh-server" not in text


# ---------------------------------------------------------------------------
# Entrypoint and CMD
# ---------------------------------------------------------------------------

def test_exec_form_entrypoint_no_shell() -> None:
    entrypoint_lines = [ln for ln in _dockerfile_lines() if ln.strip().startswith("ENTRYPOINT")]
    assert len(entrypoint_lines) == 1
    line = entrypoint_lines[0]
    assert line.strip().startswith("ENTRYPOINT ["), "must use exec-form JSON array"
    assert "&&" not in line and "||" not in line and ";" not in line
    assert "python3" in line and "entrypoint.py" in line
    # No separate, top-level CMD instruction — the only "CMD" token
    # permitted anywhere is HEALTHCHECK's own required `CMD <command>`
    # sub-directive (a continuation line, preceded by a backslash-ended
    # HEALTHCHECK line, never a standalone instruction).
    lines = _dockerfile_lines()
    for i, ln in enumerate(lines):
        if not ln.strip().startswith("CMD "):
            continue
        previous = lines[i - 1] if i > 0 else ""
        assert previous.rstrip().endswith("\\") and "HEALTHCHECK" in previous, (
            f"unexpected standalone CMD instruction at line {i + 1}: {ln!r}"
        )


def test_healthcheck_targets_readiness_endpoint_not_bare_process_check() -> None:
    text = _dockerfile_text()
    assert "HEALTHCHECK" in text
    healthcheck_block = text[text.index("HEALTHCHECK"):]
    assert "8090" in healthcheck_block
    assert "/health" in healthcheck_block


def test_exposes_only_readiness_port() -> None:
    lines = [ln for ln in _dockerfile_lines() if ln.strip().startswith("EXPOSE")]
    assert lines == ["EXPOSE 8090"]


# ---------------------------------------------------------------------------
# Documented root exception (no NET_ADMIN/tun assertions belong here — those
# are runtime capabilities granted by compose.yaml, verified in
# tests/docker/test_compose.py; this file only verifies the Dockerfile
# documents *why* root is used).
# ---------------------------------------------------------------------------

def test_root_usage_is_documented() -> None:
    text = _dockerfile_text()
    assert "root" in text.lower()
    assert "NET_ADMIN" in text
    assert "USER " not in _non_comment_text().replace("USER apextool", "").replace("USER apex", ""), (
        "docker/vpn/Dockerfile must not declare a USER directive dropping to a "
        "non-root account it cannot actually operate as (documented exception)"
    )


def test_env_documents_route_cidr_default() -> None:
    text = _dockerfile_text()
    assert "APEX_HTB_ROUTE_CIDR=10.129.0.0/16" in text


# ---------------------------------------------------------------------------
# Support scripts: no shell execution, argv-list subprocess only
# ---------------------------------------------------------------------------

def test_entrypoint_uses_argv_list_subprocess_only() -> None:
    text = _ENTRYPOINT_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in text
    assert "os.system(" not in text
    assert "subprocess.Popen(argv" in text


def test_entrypoint_verifies_profile_and_tun_before_starting_openvpn() -> None:
    text = _ENTRYPOINT_PATH.read_text(encoding="utf-8")
    assert "_verify_profile" in text
    assert "_verify_tun_device" in text
    assert "/vpn/htb.ovpn" in text
    assert "/dev/net/tun" in text


def test_entrypoint_never_writes_to_profile_path() -> None:
    text = _ENTRYPOINT_PATH.read_text(encoding="utf-8")
    assert "open(_PROFILE_PATH" not in text
    assert '"w"' not in text and "'w'" not in text


def test_entrypoint_forwards_signals() -> None:
    text = _ENTRYPOINT_PATH.read_text(encoding="utf-8")
    assert "SIGTERM" in text
    assert "SIGINT" in text
    assert "send_signal" in text


def test_entrypoint_uses_auth_nocache() -> None:
    text = _ENTRYPOINT_PATH.read_text(encoding="utf-8")
    assert "--auth-nocache" in text


def test_entrypoint_does_not_inject_route_directives() -> None:
    """The entrypoint must never construct --route/--redirect-gateway
    flags itself — only whatever the operator's own .ovpn profile
    specifies takes effect. Checked against the actual argv list
    constructed in _run_openvpn(), not the whole file (whose own
    docstring legitimately discusses these flag names in prose)."""
    text = _ENTRYPOINT_PATH.read_text(encoding="utf-8")
    argv_block = text[text.index("argv = ["):text.index("logger.info(\"starting openvpn")]
    assert "--route" not in argv_block
    assert "--redirect-gateway" not in argv_block


def test_readiness_server_is_stdlib_only() -> None:
    """No FastAPI/uvicorn/httpx/apex_host import — this file must remain
    dependency-free so it can run inside the minimal VPN image."""
    text = _READINESS_SERVER_PATH.read_text(encoding="utf-8")
    for forbidden in ("import fastapi", "import uvicorn", "import httpx", "import apex_host", "from apex_host"):
        assert forbidden not in text


def _extract_call_blocks(text: str, call_prefix: str) -> list[str]:
    """Return the full ``call_prefix(...)`` substring for every call site,
    matching parens by depth so nested parens/braces in the arguments
    don't truncate the block early."""
    blocks: list[str] = []
    start = 0
    while True:
        idx = text.find(call_prefix, start)
        if idx == -1:
            break
        depth = 0
        end = idx + len(call_prefix) - 1  # index of the opening '('
        for pos in range(end, len(text)):
            if text[pos] == "(":
                depth += 1
            elif text[pos] == ")":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        blocks.append(text[idx:end + 1])
        start = end + 1
    return blocks


def test_readiness_server_never_exposes_sensitive_fields() -> None:
    """The JSON payload dicts constructed in _handle_health/_handle_route_check
    must never include a whole-environment dump or profile-content field —
    checked against the actual `_json_response(...)` call sites, not the
    whole file (whose own docstring legitimately discusses "never the
    profile's content" in prose)."""
    text = _READINESS_SERVER_PATH.read_text(encoding="utf-8")
    payload_blocks = _extract_call_blocks(text, "_json_response(")
    assert payload_blocks, "expected at least one _json_response(...) call site"
    for block in payload_blocks:
        assert "os.environ" not in block
        assert "certificate" not in block
        assert "profile" not in block


def test_route_check_validates_target_before_subprocess() -> None:
    text = _ROUTE_CHECK_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in text
    assert "validate_target_ip" in text
    # Within run_route_get's own function body (not the whole file, whose
    # docstring/other functions also mention these names), the validation
    # call must textually precede the subprocess.run call.
    body_start = text.index("def run_route_get(")
    body = text[body_start:]
    assert body.index("validate_target_ip(target)") < body.index("subprocess.run(")


def test_route_check_only_runs_ip_route_get() -> None:
    text = _ROUTE_CHECK_PATH.read_text(encoding="utf-8")
    assert '"ip", "route", "get"' in text
    assert "ip route add" not in text
    assert "ip route del" not in text


def test_tunnel_status_uses_readonly_ip_commands_only() -> None:
    text = _TUNNEL_STATUS_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in text
    assert '"link", "show"' in text
    assert '"route", "show"' in text
    assert "route add" not in text
    assert "route del" not in text
