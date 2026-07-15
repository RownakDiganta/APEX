# test_compose_mock_vpn.py
# Static, content-based verification of compose.mock-vpn.yaml (Infra Phase 10) — the TEST-ONLY override that substitutes a harmless HTTP server for the real OpenVPN container. Does not require a Docker daemon; the actual live namespace-sharing validation is performed manually and recorded in docs/htb-vpn-container.md.
"""Static checks for the mock VPN namespace integration test fixture.

This file must never be mistaken for production configuration — every
test here reinforces that `compose.mock-vpn.yaml` grants NO capability,
mounts NO device, requires NO real profile, and is clearly labeled as a
mock everywhere it appears.
"""
from __future__ import annotations

import pathlib

import yaml

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_MOCK_VPN_PATH = _REPO_ROOT / "compose.mock-vpn.yaml"


class _ResetTagLoader(yaml.SafeLoader):
    pass


def _reset_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> None:
    return None


_ResetTagLoader.add_constructor("!reset", _reset_constructor)


def _mock_text() -> str:
    return _MOCK_VPN_PATH.read_text(encoding="utf-8")


def _mock_dict() -> dict:
    data = yaml.load(_mock_text(), Loader=_ResetTagLoader)
    assert isinstance(data, dict)
    return data


def test_file_exists() -> None:
    assert _MOCK_VPN_PATH.is_file()


def test_file_header_convention() -> None:
    lines = _mock_text().splitlines()
    assert lines[0] == "# compose.mock-vpn.yaml"
    assert lines[1].startswith("# ")


def test_clearly_labeled_as_mock_not_real_vpn() -> None:
    text = _mock_text()
    normalized = " ".join(text.split())  # collapse newlines/whitespace so a
    # banner-wrapped phrase (e.g. "does NOT\n# * prove...") still matches.
    assert "MOCK" in text
    assert "NOT prove HTB connectivity" in normalized
    assert "does NOT start OpenVPN" in normalized


def test_only_redefines_vpn_service() -> None:
    data = _mock_dict()
    assert set(data["services"].keys()) == {"vpn"}


def test_replaces_build_with_plain_pinned_image() -> None:
    data = _mock_dict()
    vpn = data["services"]["vpn"]
    assert vpn.get("build") is None
    assert isinstance(vpn.get("image"), str)
    assert vpn["image"].startswith("python:3.11.14-slim-bookworm@sha256:")


def test_runs_only_http_server_no_openvpn() -> None:
    """No non-comment line may reference the openvpn binary — the file's
    own explanatory comments legitimately name it (to explain what is
    being replaced), so only non-comment lines are checked."""
    data = _mock_dict()
    command = data["services"]["vpn"]["command"]
    assert command == ["python3", "-m", "http.server", "8090"]
    non_comment_lines = [ln for ln in _mock_text().splitlines() if not ln.strip().startswith("#")]
    assert "openvpn" not in "\n".join(non_comment_lines).lower()


def test_no_capabilities_no_devices_no_profile_mount() -> None:
    """The whole point of the mock: prove namespace sharing without any
    of the real service's elevated privileges. Checked against the parsed
    structure (not raw text, since the file's own comments legitimately
    name NET_ADMIN/tun to explain what was cleared)."""
    data = _mock_dict()
    vpn = data["services"]["vpn"]
    assert vpn.get("cap_add") is None
    assert vpn.get("devices") is None
    assert vpn.get("volumes") is None


def test_healthcheck_present_and_capability_free() -> None:
    data = _mock_dict()
    vpn = data["services"]["vpn"]
    assert "healthcheck" in vpn
    test_cmd = vpn["healthcheck"]["test"]
    assert test_cmd[0] == "CMD"
    assert "urllib" in " ".join(test_cmd)


def test_no_ovpn_reference() -> None:
    text = _mock_text()
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        assert ".ovpn" not in line
