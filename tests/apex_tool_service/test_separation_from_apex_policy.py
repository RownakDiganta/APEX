# test_separation_from_apex_policy.py
# Proves and documents the trust-boundary split: apex_tool_service is a mechanical execution boundary, not the APEX policy/legal authorization decision.
"""apex_tool_service does not decide whether a target is authorized.

That decision belongs entirely to ``apex_host.policy.PolicyAdvisor`` and
runs *before* any request would ever be sent to this service (see
``docs/tool-execution-architecture.md`` §5 "Policy-to-execution invariant").
This service only enforces mechanical execution safety: is the tool
allowlisted, are the arguments well-formed, is the caller authenticated,
are limits respected. Both checks are required in the final system —
defense in depth, not either/or.

These tests prove the separation structurally: apex_tool_service does not
import apex_host or memfabric anywhere, so it cannot accidentally
duplicate, bypass, or depend on APEX's policy decision — it has no way to
even see it.
"""
from __future__ import annotations

import pathlib
import re

_PACKAGE_ROOT = pathlib.Path(__file__).parent.parent.parent / "apex_tool_service"


def _source_files() -> list[pathlib.Path]:
    return [p for p in sorted(_PACKAGE_ROOT.rglob("*.py")) if "__pycache__" not in p.parts]


def test_apex_tool_service_never_imports_apex_host() -> None:
    violations = []
    for path in _source_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r"\bimport\s+apex_host\b", stripped) or re.search(
                r"\bfrom\s+apex_host\b", stripped
            ):
                violations.append(f"{path.name}:{lineno}: {stripped}")
    assert violations == [], (
        "apex_tool_service must never import apex_host — it is an "
        "independently deployable, mechanical execution boundary, not part "
        "of the APEX policy decision:\n" + "\n".join(violations)
    )


def test_apex_tool_service_never_imports_memfabric() -> None:
    violations = []
    for path in _source_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r"\bimport\s+memfabric\b", stripped) or re.search(
                r"\bfrom\s+memfabric\b", stripped
            ):
                violations.append(f"{path.name}:{lineno}: {stripped}")
    assert violations == [], violations


def test_apex_tool_service_does_not_reference_policy_advisor() -> None:
    """The service must not reimplement or reference APEX's policy decision type."""
    violations = []
    for path in _source_files():
        text = path.read_text(encoding="utf-8")
        if "PolicyAdvisor" in text or "PolicyDecision" in text:
            violations.append(path.name)
    assert violations == [], (
        f"apex_tool_service must not reference APEX's PolicyAdvisor/PolicyDecision "
        f"types — that decision is made entirely upstream, before a request ever "
        f"reaches this service: {violations}"
    )


def test_apex_tool_service_does_not_make_authorization_decisions_about_targets() -> None:
    """The allowlist/validation layer only inspects tool name and argument shape
    — never a "target"/"scope" field, which would duplicate APEX policy logic."""
    from apex_tool_service.models import ExecuteRequest

    fields = set(ExecuteRequest.model_fields.keys())
    assert "target" not in fields
    assert "scope" not in fields
    assert "authorized" not in fields
