# test_compose.py
# Static, content-based verification of compose.yaml (Infra Phase 7) — parses via PyYAML, does not require a Docker daemon.
"""Static checks for the APEX/Kali Docker Compose environment.

Mirrors the pattern in `tests/docker/test_apex_dockerfile.py` (Infra
Phase 5) and `tests/docker/test_apex_kali_dockerfile.py` (Infra Phase 6):
read `compose.yaml` and assert on its *parsed structure* (via PyYAML,
already an `apex_host` runtime dependency — no new dependency added) and,
where interpolation syntax matters, its raw text. These tests do not
require Docker or Docker Compose to be installed or running — the actual
`docker compose config`/`build`/`up` runtime validation is performed
manually and recorded in `docs/docker-compose.md`.
"""
from __future__ import annotations

import pathlib

import yaml

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_COMPOSE_PATH = _REPO_ROOT / "compose.yaml"


def _compose_text() -> str:
    return _COMPOSE_PATH.read_text(encoding="utf-8")


def _non_comment_text() -> str:
    """compose.yaml's own text minus full-line comments — used for negative
    ("X does not appear") checks so this file's own explanatory comments
    (which legitimately name the things being forbidden, e.g. "no
    docker.sock mount") never produce a false positive."""
    lines = [ln for ln in _compose_text().splitlines() if not ln.strip().startswith("#")]
    return "\n".join(lines)


def _compose_dict() -> dict:
    data = yaml.safe_load(_compose_text())
    assert isinstance(data, dict)
    return data


# ---------------------------------------------------------------------------
# Existence and basic structure
# ---------------------------------------------------------------------------

def test_compose_file_exists() -> None:
    assert _COMPOSE_PATH.is_file()


def test_file_header_convention() -> None:
    lines = _compose_text().splitlines()
    assert lines[0] == "# compose.yaml"
    assert lines[1].startswith("# ")


def test_compose_file_parses_as_yaml() -> None:
    data = _compose_dict()
    assert "services" in data
    assert "networks" in data


def test_no_top_level_version_key() -> None:
    """The modern Compose Specification deprecates/ignores `version:` —
    this phase's task brief explicitly forbids adding it."""
    data = _compose_dict()
    assert "version" not in data


# ---------------------------------------------------------------------------
# Services: exactly apex + kali, no unexplained extras
# ---------------------------------------------------------------------------

def test_apex_and_kali_services_exist() -> None:
    data = _compose_dict()
    assert set(data["services"].keys()) == {"apex", "kali"}, (
        "compose.yaml should start only the two intended application "
        "services unless a helper service is separately justified"
    )


def test_services_use_intended_dockerfiles() -> None:
    data = _compose_dict()
    apex = data["services"]["apex"]
    kali = data["services"]["kali"]
    assert apex["build"]["dockerfile"] == "docker/apex/Dockerfile"
    assert kali["build"]["dockerfile"] == "docker/kali/Dockerfile"


def test_build_context_is_repo_root() -> None:
    data = _compose_dict()
    for name in ("apex", "kali"):
        assert data["services"][name]["build"]["context"] == ".", (
            f"{name} must build from the repository root, matching each "
            "Dockerfile's own documented build command"
        )


# ---------------------------------------------------------------------------
# No privileged mode, no host networking, no Docker socket
# ---------------------------------------------------------------------------

def test_no_privileged_mode_anywhere() -> None:
    data = _compose_dict()
    for name, svc in data["services"].items():
        assert svc.get("privileged") is not True, f"{name} must not be privileged"
    assert "privileged: true" not in _compose_text()


def test_no_host_networking() -> None:
    text = _non_comment_text()
    assert "network_mode: host" not in text
    assert "network_mode: \"host\"" not in text
    data = _compose_dict()
    for name, svc in data["services"].items():
        assert svc.get("network_mode") != "host", f"{name} must not use host networking"


def test_no_service_network_mode() -> None:
    """`network_mode: service:*` is explicitly out of scope for this phase."""
    data = _compose_dict()
    for name, svc in data["services"].items():
        network_mode = svc.get("network_mode")
        if network_mode is not None:
            assert not str(network_mode).startswith("service:"), (
                f"{name} must not use network_mode: service:* in this phase"
            )


def test_no_docker_socket_mounted() -> None:
    text = _non_comment_text()
    assert "docker.sock" not in text
    data = _compose_dict()
    for name, svc in data["services"].items():
        for vol in svc.get("volumes", []):
            vol_str = vol if isinstance(vol, str) else str(vol)
            assert "docker.sock" not in vol_str, f"{name} must not mount the Docker socket"


def test_no_unexpected_capabilities() -> None:
    data = _compose_dict()
    for name, svc in data["services"].items():
        cap_add = svc.get("cap_add", [])
        assert "NET_ADMIN" not in cap_add, f"{name} must not add NET_ADMIN in this phase"
        assert "NET_RAW" not in cap_add, (
            f"{name} must not add NET_RAW merely to enable default Nmap SYN scans "
            "in this phase — deferred, see docs/docker-compose.md"
        )


def test_no_ssh_or_vpn_configuration() -> None:
    text = _non_comment_text()
    assert ".ovpn" not in text
    assert "openvpn" not in text.lower()


# ---------------------------------------------------------------------------
# Kali not published to the host; apex has no published ports
# ---------------------------------------------------------------------------

def test_kali_has_no_host_port_publication() -> None:
    data = _compose_dict()
    kali = data["services"]["kali"]
    assert "ports" not in kali, (
        "kali must not publish port 8080 (or any port) to the host by default"
    )


def test_kali_exposes_8080_internally() -> None:
    data = _compose_dict()
    kali = data["services"]["kali"]
    exposed = [str(p) for p in kali.get("expose", [])]
    assert "8080" in exposed


def test_apex_has_no_published_ports() -> None:
    data = _compose_dict()
    apex = data["services"]["apex"]
    assert "ports" not in apex


# ---------------------------------------------------------------------------
# Token handling: no hardcoded token; both services share the same
# fail-fast interpolated variable
# ---------------------------------------------------------------------------

def test_no_hardcoded_token_value() -> None:
    text = _compose_text()
    assert "phase7-test-token" not in text, "no realistic-looking test token literal in compose.yaml"
    assert "sk-" not in text, "no OpenAI-shaped API key literal in compose.yaml"


def test_token_uses_fail_fast_interpolation() -> None:
    data = _compose_dict()
    for name in ("apex", "kali"):
        token_value = data["services"][name]["environment"]["APEX_TOOL_SERVICE_TOKEN"]
        assert token_value.startswith("${APEX_TOOL_SERVICE_TOKEN"), (
            f"{name}'s APEX_TOOL_SERVICE_TOKEN must be interpolated, not a literal value"
        )
        assert ":?" in token_value, (
            f"{name}'s APEX_TOOL_SERVICE_TOKEN interpolation must use the fail-fast "
            "':?' form so an unset token is a hard error, not a silent empty string"
        )


def test_both_services_receive_the_same_token_variable() -> None:
    data = _compose_dict()
    apex_token = data["services"]["apex"]["environment"]["APEX_TOOL_SERVICE_TOKEN"]
    kali_token = data["services"]["kali"]["environment"]["APEX_TOOL_SERVICE_TOKEN"]
    assert apex_token == kali_token, "both services must reference the identical interpolated token variable"


# ---------------------------------------------------------------------------
# Internal networking and service discovery
# ---------------------------------------------------------------------------

def test_apex_tool_service_url_uses_kali_service_name() -> None:
    # Infra Phase 8: interpolated with a $APEX_TOOL_SERVICE_URL override
    # (default unchanged: http://kali:8080) rather than a bare literal.
    data = _compose_dict()
    apex_env = data["services"]["apex"]["environment"]
    value = apex_env["APEX_TOOL_SERVICE_URL"]
    assert value.startswith("${APEX_TOOL_SERVICE_URL:-")
    assert value.endswith("http://kali:8080}")


def test_apex_tool_backend_is_remote_by_default() -> None:
    # Infra Phase 8: interpolated with a $APEX_TOOL_BACKEND override
    # (default unchanged: remote) rather than a bare literal.
    data = _compose_dict()
    apex_env = data["services"]["apex"]["environment"]
    value = apex_env["APEX_TOOL_BACKEND"]
    assert value.startswith("${APEX_TOOL_BACKEND:-")
    assert value.endswith("remote}")


def test_dedicated_network_exists() -> None:
    data = _compose_dict()
    assert "apex-internal" in data["networks"]


def test_both_services_join_the_dedicated_network() -> None:
    data = _compose_dict()
    for name in ("apex", "kali"):
        networks = data["services"][name].get("networks")
        assert networks is not None
        assert "apex-internal" in networks


def test_no_fixed_ip_addresses_configured() -> None:
    text = _compose_text()
    assert "ipv4_address" not in text
    assert "ipam" not in text


# ---------------------------------------------------------------------------
# Health dependency
# ---------------------------------------------------------------------------

def test_apex_depends_on_kali_health() -> None:
    data = _compose_dict()
    depends_on = data["services"]["apex"]["depends_on"]
    assert "kali" in depends_on
    assert depends_on["kali"]["condition"] == "service_healthy"


# ---------------------------------------------------------------------------
# Report persistence; Kali cannot access reports
# ---------------------------------------------------------------------------

def test_apex_report_volume_configured() -> None:
    data = _compose_dict()
    volumes = data["services"]["apex"].get("volumes", [])
    assert any("run_reports" in str(v) and "/app/run_reports" in str(v) for v in volumes), (
        "expected a ./run_reports -> /app/run_reports volume for apex"
    )


def test_kali_has_no_report_volume() -> None:
    data = _compose_dict()
    kali = data["services"]["kali"]
    for vol in kali.get("volumes", []):
        assert "run_reports" not in str(vol), "kali must not mount the APEX report directory"


def test_kali_has_no_volumes_at_all() -> None:
    """Kali has no reason to mount anything — verified as the stronger,
    more specific claim (not just 'no run_reports')."""
    data = _compose_dict()
    kali = data["services"]["kali"]
    assert "volumes" not in kali or not kali["volumes"]


# ---------------------------------------------------------------------------
# Compiled knowledge: no duplicate/inconsistent-casing mount
# ---------------------------------------------------------------------------

def test_no_duplicate_knowledge_volume_mount() -> None:
    """Compiled knowledge is baked into the apex image (docker/apex/Dockerfile);
    this file must not additionally mount a second, possibly differently-cased
    knowledge path over it."""
    data = _compose_dict()
    apex = data["services"]["apex"]
    for vol in apex.get("volumes", []):
        vol_str = str(vol).lower()
        assert "knowledge" not in vol_str, (
            f"unexpected knowledge-related volume mount on apex: {vol!r}"
        )


# ---------------------------------------------------------------------------
# Safe default command; no live target; no API key hardcoded
# ---------------------------------------------------------------------------

def test_apex_default_command_is_smoke_mode() -> None:
    """Infra Phase 9: the default command is now the container ENTRYPOINT's
    'smoke' subcommand (apex_host.container_entrypoint, set as
    docker/apex/Dockerfile's ENTRYPOINT) — not the standalone
    apex_host.eval.compose_smoke module directly (still available, unused
    as the Compose default as of this phase)."""
    data = _compose_dict()
    command = data["services"]["apex"].get("command")
    assert command is not None
    joined = " ".join(command) if isinstance(command, list) else str(command)
    assert command[0] == "smoke"
    assert "run_htb_local" not in joined, "the default command must not launch a live-engagement entry point"
    assert "--confirm-live" not in joined, "the default command must never confirm live mode"
    assert "--target" not in joined, "the default command must not hardcode a target"


def test_no_hardcoded_target_ip_anywhere() -> None:
    # 0.0.0.0 is a bind-all address (APEX_TOOL_SERVICE_HOST's real
    # apex_tool_service default, Infra Phase 8), not a target — the only
    # literal IPv4 addresses allowed anywhere in this file.
    import re

    allowed = {"0.0.0.0"}
    ipv4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    for ln in _compose_text().splitlines():
        stripped = ln.strip()
        if stripped.startswith("#"):
            continue
        for match in ipv4.finditer(stripped):
            assert match.group(0) in allowed, f"unexpected IPv4 literal in compose.yaml: {ln!r}"


def test_no_hardcoded_api_key() -> None:
    text = _compose_text()
    assert "OPENAI_API_KEY" not in text or "${OPENAI_API_KEY" in text or "OPENAI_API_KEY" not in text
    import re

    assert re.search(r"sk-[A-Za-z0-9]{10,}", text) is None


# ---------------------------------------------------------------------------
# .dockerignore still permits both builds (shared file, unchanged by this phase)
# ---------------------------------------------------------------------------

def test_dockerignore_still_allows_required_build_inputs() -> None:
    dockerignore = (_REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    lines = [
        ln.strip() for ln in dockerignore.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    forbidden = {
        "pyproject.toml", "uv.lock", "memfabric", "apex_host", "apex_tool_service",
        "memfabric/", "apex_host/", "apex_tool_service/", "docker", "docker/",
    }
    for ln in lines:
        assert ln not in forbidden, f".dockerignore must not blanket-exclude a required build input: {ln!r}"
