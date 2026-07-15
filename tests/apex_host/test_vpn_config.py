# test_vpn_config.py
# Tests for Infra Phase 10's HTB VPN configuration layer — apex_host/config.py's new fields, apex_host/config_env.py's CIDR/URL/timeout parsing and env merge, and to_safe_dict() basename redaction.
"""Infra Phase 10 configuration tests.

Covers: `ApexConfig`'s four new VPN fields (defaults, `to_safe_dict()`
basename-only redaction of `htb_ovpn_path`), `config_env.py`'s
`validate_cidr()` (strict CIDR parsing), and the generic env-merge
picking up `APEX_VPN_SERVICE_URL`/`APEX_VPN_HEALTH_TIMEOUT_SECONDS`/
`APEX_HTB_ROUTE_CIDR`/`APEX_HTB_OVPN_PATH` without ever requiring them —
the default, non-htb configuration path is completely unaffected.
"""
from __future__ import annotations

import argparse

import pytest

from apex_host.config import ApexConfig
from apex_host.config_env import (
    ENV_HTB_OVPN_PATH,
    ENV_HTB_ROUTE_CIDR,
    ENV_VPN_HEALTH_TIMEOUT_SECONDS,
    ENV_VPN_SERVICE_URL,
    EnvConfigError,
    merge_env_into_args,
    validate_cidr,
)


# ---------------------------------------------------------------------------
# ApexConfig field defaults
# ---------------------------------------------------------------------------

class TestApexConfigVpnFields:
    def test_defaults_are_safe(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.vpn_service_url is None
        assert config.vpn_health_timeout_seconds == 10.0
        assert config.htb_route_cidr == "10.129.0.0/16"
        assert config.htb_ovpn_path is None

    def test_fields_are_settable(self) -> None:
        config = ApexConfig(
            target="10.0.0.1",
            vpn_service_url="http://vpn:8090",
            vpn_health_timeout_seconds=5.0,
            htb_route_cidr="172.16.0.0/12",
            htb_ovpn_path="/home/user/secrets/htb.ovpn",
        )
        assert config.vpn_service_url == "http://vpn:8090"
        assert config.vpn_health_timeout_seconds == 5.0
        assert config.htb_route_cidr == "172.16.0.0/12"
        assert config.htb_ovpn_path == "/home/user/secrets/htb.ovpn"


class TestToSafeDictRedaction:
    def test_htb_ovpn_path_none_stays_none(self) -> None:
        config = ApexConfig(target="10.0.0.1")
        assert config.to_safe_dict()["htb_ovpn_path"] is None

    def test_htb_ovpn_path_shows_only_basename(self) -> None:
        config = ApexConfig(target="10.0.0.1", htb_ovpn_path="/home/alice/secrets/htb.ovpn")
        safe = config.to_safe_dict()
        assert safe["htb_ovpn_path"] == "htb.ovpn"
        assert "alice" not in str(safe["htb_ovpn_path"])
        assert "/home" not in str(safe["htb_ovpn_path"])

    def test_full_host_path_never_appears_anywhere_in_safe_dict(self) -> None:
        config = ApexConfig(target="10.0.0.1", htb_ovpn_path="/Users/mdrownakdiganta/secrets/htb.ovpn")
        safe = config.to_safe_dict()
        assert "mdrownakdiganta" not in str(safe.values())

    def test_other_vpn_fields_not_redacted(self) -> None:
        """vpn_service_url/htb_route_cidr/vpn_health_timeout_seconds are
        non-sensitive operational configuration — returned verbatim."""
        config = ApexConfig(
            target="10.0.0.1", vpn_service_url="http://vpn:8090", htb_route_cidr="10.129.0.0/16",
        )
        safe = config.to_safe_dict()
        assert safe["vpn_service_url"] == "http://vpn:8090"
        assert safe["htb_route_cidr"] == "10.129.0.0/16"


# ---------------------------------------------------------------------------
# from_cli_args wiring
# ---------------------------------------------------------------------------

class TestFromCliArgsVpnFields:
    def _make_args(self, **overrides: object) -> argparse.Namespace:
        base = {
            "target": "10.0.0.1", "vpn_service_url": None, "htb_route_cidr": None,
            "htb_ovpn_path": None, "vpn_health_timeout": None,
        }
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_defaults_when_absent(self) -> None:
        config = ApexConfig.from_cli_args(self._make_args())
        assert config.vpn_service_url is None
        assert config.htb_route_cidr == "10.129.0.0/16"
        assert config.htb_ovpn_path is None
        assert config.vpn_health_timeout_seconds == 10.0

    def test_explicit_values_propagate(self) -> None:
        config = ApexConfig.from_cli_args(self._make_args(
            vpn_service_url="http://vpn:8090", htb_route_cidr="172.16.0.0/12",
            htb_ovpn_path="./secrets/htb.ovpn", vpn_health_timeout=3.0,
        ))
        assert config.vpn_service_url == "http://vpn:8090"
        assert config.htb_route_cidr == "172.16.0.0/12"
        assert config.htb_ovpn_path == "./secrets/htb.ovpn"
        assert config.vpn_health_timeout_seconds == 3.0

    def test_missing_attrs_do_not_raise(self) -> None:
        """A namespace without any VPN attribute at all (e.g. main.py's,
        which does not declare these flags) must still construct cleanly
        with the safe defaults."""
        args = argparse.Namespace(target="10.0.0.1")
        config = ApexConfig.from_cli_args(args)
        assert config.vpn_service_url is None
        assert config.htb_route_cidr == "10.129.0.0/16"


# ---------------------------------------------------------------------------
# config_env.py — validate_cidr
# ---------------------------------------------------------------------------

class TestValidateCidr:
    def test_valid_cidr(self) -> None:
        assert validate_cidr(ENV_HTB_ROUTE_CIDR, "10.129.0.0/16") == "10.129.0.0/16"

    def test_normalizes_host_bits(self) -> None:
        # ipaddress with strict=False masks host bits rather than rejecting.
        assert validate_cidr(ENV_HTB_ROUTE_CIDR, "10.129.5.5/16") == "10.129.0.0/16"

    def test_malformed_raises_env_config_error(self) -> None:
        with pytest.raises(EnvConfigError) as exc_info:
            validate_cidr(ENV_HTB_ROUTE_CIDR, "not-a-cidr")
        assert ENV_HTB_ROUTE_CIDR in str(exc_info.value)

    def test_out_of_range_prefix_raises(self) -> None:
        with pytest.raises(EnvConfigError):
            validate_cidr(ENV_HTB_ROUTE_CIDR, "10.129.0.0/99")

    def test_error_message_never_echoes_a_secret(self) -> None:
        # CIDR values are never secrets, but the message-shape convention
        # (name the variable, quote the value) should hold regardless.
        with pytest.raises(EnvConfigError) as exc_info:
            validate_cidr(ENV_HTB_ROUTE_CIDR, "garbage")
        assert "garbage" in str(exc_info.value)  # value IS shown — it's not a secret


# ---------------------------------------------------------------------------
# config_env.py — generic env merge picks up the four new variables
# ---------------------------------------------------------------------------

class TestMergeEnvIntoArgsVpnFields:
    def _make_args(self) -> argparse.Namespace:
        return argparse.Namespace(
            target="10.0.0.1", dry_run=True,
            vpn_service_url=None, htb_route_cidr=None, htb_ovpn_path=None, vpn_health_timeout=None,
        )

    def test_unset_env_leaves_fields_none(self) -> None:
        merged = merge_env_into_args(self._make_args(), env={})
        assert merged.vpn_service_url is None
        assert merged.htb_route_cidr is None
        assert merged.htb_ovpn_path is None
        assert merged.vpn_health_timeout is None

    def test_env_fills_all_four(self) -> None:
        env = {
            ENV_VPN_SERVICE_URL: "http://vpn:8090",
            ENV_HTB_ROUTE_CIDR: "10.129.0.0/16",
            ENV_HTB_OVPN_PATH: "./secrets/htb.ovpn",
            ENV_VPN_HEALTH_TIMEOUT_SECONDS: "5",
        }
        merged = merge_env_into_args(self._make_args(), env=env)
        assert merged.vpn_service_url == "http://vpn:8090"
        assert merged.htb_route_cidr == "10.129.0.0/16"
        assert merged.htb_ovpn_path == "./secrets/htb.ovpn"
        assert merged.vpn_health_timeout == 5.0

    def test_explicit_cli_value_wins_over_env(self) -> None:
        args = self._make_args()
        args.htb_route_cidr = "172.16.0.0/12"
        merged = merge_env_into_args(args, env={ENV_HTB_ROUTE_CIDR: "10.129.0.0/16"})
        assert merged.htb_route_cidr == "172.16.0.0/12"

    def test_malformed_env_cidr_raises(self) -> None:
        with pytest.raises(EnvConfigError):
            merge_env_into_args(self._make_args(), env={ENV_HTB_ROUTE_CIDR: "not-a-cidr"})

    def test_malformed_env_url_raises(self) -> None:
        with pytest.raises(EnvConfigError):
            merge_env_into_args(self._make_args(), env={ENV_VPN_SERVICE_URL: "not-a-url"})

    def test_malformed_env_timeout_raises(self) -> None:
        with pytest.raises(EnvConfigError):
            merge_env_into_args(self._make_args(), env={ENV_VPN_HEALTH_TIMEOUT_SECONDS: "not-a-number"})

    def test_negative_timeout_raises(self) -> None:
        with pytest.raises(EnvConfigError):
            merge_env_into_args(self._make_args(), env={ENV_VPN_HEALTH_TIMEOUT_SECONDS: "-1"})

    def test_namespace_without_vpn_attrs_is_skipped_silently(self) -> None:
        """A namespace that doesn't declare these attributes at all
        (e.g. apex_host.main's, which has no VPN flags) must not raise —
        the hasattr() guard skips them silently, per the established
        pattern for export_json/export_graph."""
        args = argparse.Namespace(target="10.0.0.1", dry_run=True)
        merged = merge_env_into_args(args, env={ENV_HTB_ROUTE_CIDR: "10.129.0.0/16"})
        assert not hasattr(merged, "htb_route_cidr")

    def test_blank_env_value_counts_as_absent(self) -> None:
        merged = merge_env_into_args(self._make_args(), env={ENV_HTB_OVPN_PATH: "   "})
        assert merged.htb_ovpn_path is None
