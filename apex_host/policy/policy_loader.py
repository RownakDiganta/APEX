# policy_loader.py
# Loads ScopePolicy from hackthebox_lab.yaml or returns a conservative default if the file is missing.
"""Policy loader for the APEX host application.

``load_policy(config)`` is the single public entry point.  It tries to find
a compiled policy YAML file in the following order:

1. ``config.policy_file`` (explicit operator override)
2. ``<knowledge_root>/policy_db/compiled/hackthebox_lab.yaml``
   (when ``config.knowledge_root`` is set)
3. ``knowledge/policy_db/compiled/hackthebox_lab.yaml``
   (relative to the current working directory — works for local development)

When no file is found the function returns the **conservative default**:
  - Only ``config.target`` is allowed as a scan target.
  - Destructive commands are blocked unconditionally.
  - Password-list fuzzing is blocked (unless ``config.allow_password_lists``).
  - Sensitive data access is blocked (unless ``config.allow_sensitive_data_access``).
  - No extra tools require human review beyond the default set.

The conservative default is the *safe* fallback — not the permissive one.
A missing file means more restrictions, not fewer.
"""
from __future__ import annotations

import logging
import pathlib
from typing import TYPE_CHECKING

from apex_host.policy.models import ScopePolicy

if TYPE_CHECKING:
    from apex_host.config import ApexConfig

logger = logging.getLogger(__name__)

# Tools always blocked by policy, independent of ApexConfig.allowed_tools.
# This list is intentionally broader than safety.py's _DESTRUCTIVE_COMMANDS:
# it also covers network-attack utilities that should never run autonomously.
_ALWAYS_BLOCKED_TOOLS: frozenset[str] = frozenset({
    # Destructive system commands
    "rm", "mkfs", "dd", "shutdown", "reboot", "halt", "poweroff",
    "fdisk", "format", "mkswap",
    # Brute-force / autonomous credential-attack tools (no autonomous use)
    "hydra", "medusa", "patator", "hashcat", "john",
    # Exploit frameworks that must never run autonomously
    "msfconsole", "msfvenom",
})

# Default path relative to CWD for local development.
_DEFAULT_POLICY_YAML = pathlib.Path("knowledge/policy_db/compiled/hackthebox_lab.yaml")


def load_policy(config: "ApexConfig") -> ScopePolicy:
    """Build a ScopePolicy from config and an optional YAML file.

    The returned policy is always conservative.  Finding the YAML only means
    the policy is *documented* — it does not relax any restrictions.  All
    restrictions come from ``config`` fields that the operator must explicitly
    set to loosen.

    Parameters
    ----------
    config:
        Live ``ApexConfig``.  Reads ``policy_enabled``, ``policy_file``,
        ``knowledge_root``, ``allow_password_lists``,
        ``allow_sensitive_data_access``, and
        ``require_policy_approval_for``.

    Returns
    -------
    ScopePolicy
        Fully populated scope policy.  ``policy_loaded`` is True when a
        YAML file was found; False when the conservative default is in effect.
    """
    policy_path = _resolve_policy_path(config)
    policy_loaded = False
    policy_source = "conservative_default"

    if policy_path is not None:
        try:
            import yaml  # pyyaml; present in the venv

            raw = policy_path.read_text(encoding="utf-8")
            yaml.safe_load(raw)  # validate well-formed; we don't use the data
            policy_loaded = True
            policy_source = str(policy_path)
            logger.info("policy_loader: loaded policy from %s", policy_path)
        except FileNotFoundError:
            logger.debug("policy_loader: policy file not found at %s", policy_path)
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
            logger.warning(
                "policy_loader: could not read policy file %s: %s — "
                "using conservative default",
                policy_path, exc,
            )

    return ScopePolicy(
        allowed_targets=frozenset({config.target}),
        blocked_tools=_ALWAYS_BLOCKED_TOOLS,
        allow_password_lists=config.allow_password_lists,
        allow_sensitive_data_access=config.allow_sensitive_data_access,
        require_review_for=list(config.require_policy_approval_for),
        policy_loaded=policy_loaded,
        policy_source=policy_source,
    )


def _resolve_policy_path(config: "ApexConfig") -> pathlib.Path | None:
    """Return the best candidate path for the policy YAML, or None."""
    # Priority 1: explicit operator-supplied path
    if config.policy_file:
        return pathlib.Path(config.policy_file)

    # Priority 2: derived from knowledge_root
    if config.knowledge_root:
        candidate = pathlib.Path(config.knowledge_root) / "policy_db" / "compiled" / "hackthebox_lab.yaml"
        return candidate

    # Priority 3: conventional local-development path
    if _DEFAULT_POLICY_YAML.exists():
        return _DEFAULT_POLICY_YAML

    return None
