# test_compose_htb.py
# Static, content-based verification of compose.htb.yaml (Infra Phase 10) — the Compose override file that activates HTB VPN mode. Does not require a Docker daemon; the actual merged-config validation (`docker compose -f compose.yaml -f compose.htb.yaml --profile htb config`) is performed manually and recorded in docs/htb-vpn-container.md.
"""Static checks for the HTB Compose override file.

This file is meaningless parsed alone (it's an override, always merged on
top of ``compose.yaml``) — these tests check its own structure in
isolation (kali's namespace-sharing redefinition, apex's environment
overrides, vpn's fail-fast volume override), not the merged result. The
merged result itself is verified by real `docker compose config` runs
(manual, recorded in docs/htb-vpn-container.md) since PyYAML alone cannot
reproduce Compose's own merge semantics (list replacement, environment-map
merging, `!reset` handling).
"""
from __future__ import annotations

import pathlib

import yaml

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_HTB_COMPOSE_PATH = _REPO_ROOT / "compose.htb.yaml"
_BASE_COMPOSE_PATH = _REPO_ROOT / "compose.yaml"


class _ResetTagLoader(yaml.SafeLoader):
    """A SafeLoader that understands the Compose Specification's `!reset`
    tag (used to explicitly clear a value inherited from a merged-in base
    file) — PyYAML's plain `safe_load` has no built-in constructor for it
    and raises a ConstructorError otherwise. `!reset X` is parsed here as
    `None`, matching Compose's own "reset to empty" semantics closely
    enough for structural assertions (we only need to confirm the key is
    present and was intentionally reset, not reproduce Compose's exact
    merge algorithm)."""


def _reset_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> None:
    return None


_ResetTagLoader.add_constructor("!reset", _reset_constructor)


def _htb_text() -> str:
    return _HTB_COMPOSE_PATH.read_text(encoding="utf-8")


def _htb_dict() -> dict:
    data = yaml.load(_htb_text(), Loader=_ResetTagLoader)
    assert isinstance(data, dict)
    return data


def _base_dict() -> dict:
    return yaml.safe_load(_BASE_COMPOSE_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Existence and basic structure
# ---------------------------------------------------------------------------

def test_compose_htb_file_exists() -> None:
    assert _HTB_COMPOSE_PATH.is_file()


def test_file_header_convention() -> None:
    lines = _htb_text().splitlines()
    assert lines[0] == "# compose.htb.yaml"
    assert lines[1].startswith("# ")


def test_compose_htb_parses_as_yaml() -> None:
    data = _htb_dict()
    assert "services" in data


def test_no_top_level_version_key() -> None:
    data = _htb_dict()
    assert "version" not in data


def test_only_redefines_kali_apex_never_vpn() -> None:
    """This override file must never redefine `vpn` itself — vpn's own
    service definition lives entirely in compose.yaml (base file); this
    file only adds a `volumes:` override for it (tested separately below)
    is intentionally the one exception, verified precisely rather than
    forbidding the key outright."""
    data = _htb_dict()
    assert set(data["services"].keys()) == {"kali", "apex", "vpn"}
    # vpn's override here must be scoped to `volumes:` only — no build/
    # network/capability redefinition (those stay owned by compose.yaml).
    vpn_override = data["services"]["vpn"]
    assert set(vpn_override.keys()) == {"volumes"}


# ---------------------------------------------------------------------------
# kali: network namespace sharing
# ---------------------------------------------------------------------------

def test_kali_network_mode_is_service_vpn() -> None:
    data = _htb_dict()
    kali = data["services"]["kali"]
    assert kali.get("network_mode") == "service:vpn"


def test_kali_networks_and_expose_are_reset() -> None:
    """`networks:` and `expose:` from the base file's `kali` service must
    be explicitly cleared here — network_mode and networks are mutually
    exclusive per the Compose Specification (verified live this phase —
    without this, `docker compose config` fails validation)."""
    data = _htb_dict()
    kali = data["services"]["kali"]
    assert kali.get("networks") is None
    assert kali.get("expose") is None


def test_kali_depends_on_vpn_health() -> None:
    data = _htb_dict()
    kali = data["services"]["kali"]
    assert kali["depends_on"]["vpn"]["condition"] == "service_healthy"


def test_kali_gets_no_added_capabilities_in_htb_mode() -> None:
    """Sharing vpn's network namespace must not grant kali any
    capability — network_mode: service:X shares only the network
    namespace, never capabilities/filesystem/user namespace."""
    data = _htb_dict()
    kali = data["services"]["kali"]
    assert "cap_add" not in kali
    assert kali.get("privileged") is not True
    assert "user" not in kali, "kali must not override its image's own non-root USER"


def test_kali_does_not_redefine_build_or_image() -> None:
    """This override must not change WHAT kali runs — only how it's
    networked. No `build:`/`image:` key here means Compose inherits the
    base file's docker/kali/Dockerfile build unchanged."""
    data = _htb_dict()
    kali = data["services"]["kali"]
    assert "build" not in kali
    assert "image" not in kali


# ---------------------------------------------------------------------------
# apex: service discovery through the shared vpn namespace
# ---------------------------------------------------------------------------

def test_apex_tool_service_url_points_at_vpn_not_kali() -> None:
    data = _htb_dict()
    apex_env = data["services"]["apex"]["environment"]
    assert apex_env["APEX_TOOL_SERVICE_URL"] == "http://vpn:8080"


def test_apex_vpn_service_url_configured() -> None:
    data = _htb_dict()
    apex_env = data["services"]["apex"]["environment"]
    assert apex_env["APEX_VPN_SERVICE_URL"] == "http://vpn:8090"


def test_apex_htb_route_cidr_interpolated_with_real_default() -> None:
    data = _htb_dict()
    apex_env = data["services"]["apex"]["environment"]
    value = apex_env["APEX_HTB_ROUTE_CIDR"]
    assert value.startswith("${APEX_HTB_ROUTE_CIDR:-")
    assert value.endswith("10.129.0.0/16}")


def test_apex_depends_on_vpn_health() -> None:
    data = _htb_dict()
    apex = data["services"]["apex"]
    assert apex["depends_on"]["vpn"]["condition"] == "service_healthy"


def test_apex_does_not_redefine_command_or_confirm_live() -> None:
    """HTB mode must not introduce a live-engagement default — no
    `command:` override here means the base file's ["smoke",
    "--knowledge-root", "/app/knowledge"] still applies, and no
    non-comment line may configure --confirm-live/run_htb_local/--target
    (this test's own docstring and the file's explanatory comments
    legitimately discuss these names in prose)."""
    data = _htb_dict()
    apex = data["services"]["apex"]
    assert "command" not in apex
    non_comment_lines = [ln for ln in _htb_text().splitlines() if not ln.strip().startswith("#")]
    non_comment_text = "\n".join(non_comment_lines)
    assert "--confirm-live" not in non_comment_text
    assert "run_htb_local" not in non_comment_text
    assert "--target" not in non_comment_text


def test_apex_gets_no_added_capabilities_or_ports() -> None:
    data = _htb_dict()
    apex = data["services"]["apex"]
    assert "cap_add" not in apex
    assert "ports" not in apex
    assert apex.get("privileged") is not True


# ---------------------------------------------------------------------------
# vpn: only the fail-fast volume override
# ---------------------------------------------------------------------------

def test_vpn_volumes_override_uses_fail_fast_interpolation() -> None:
    data = _htb_dict()
    vpn = data["services"]["vpn"]
    volumes = vpn["volumes"]
    assert len(volumes) == 1
    assert volumes[0].startswith("${APEX_HTB_OVPN_PATH")
    assert ":?" in volumes[0], "must use the fail-fast ':?' interpolation form, not a soft default"
    assert volumes[0].endswith(":/vpn/htb.ovpn:ro")


def test_no_privileged_mode_anywhere_in_htb_file() -> None:
    data = _htb_dict()
    for name, svc in data["services"].items():
        assert svc.get("privileged") is not True, f"{name} must not be privileged"
    assert "privileged: true" not in _htb_text()


def test_no_docker_socket_mounted() -> None:
    text = _htb_text()
    assert "docker.sock" not in text


def test_no_host_networking() -> None:
    text = _htb_text()
    assert "network_mode: host" not in text
    assert 'network_mode: "host"' not in text


def test_no_hardcoded_secrets_or_target_ip() -> None:
    import re

    text = _htb_text()
    assert "sk-" not in text
    ipv4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    allowed = {"10.129.0.0"}  # the HTB route CIDR default's network address only
    for ln in text.splitlines():
        stripped = ln.strip()
        if stripped.startswith("#"):
            continue
        for match in ipv4.finditer(stripped):
            assert match.group(0) in allowed, f"unexpected IPv4 literal: {ln!r}"


# ---------------------------------------------------------------------------
# Consistency with the base file
# ---------------------------------------------------------------------------

def test_base_file_still_declares_vpn_service_this_file_extends() -> None:
    base = _base_dict()
    assert "vpn" in base["services"], (
        "compose.htb.yaml's vpn.volumes override assumes compose.yaml "
        "already declares the vpn service — base file drifted"
    )
