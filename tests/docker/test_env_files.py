# test_env_files.py
# Static tests for .env.example content and .gitignore/.dockerignore rules (Infra Phase 8) — does not require a Docker daemon.
"""Static checks for the environment-file workflow.

Covers: `.env.example` exists, documents every variable
`apex_host/config_env.py` and `apex_tool_service/settings.py` genuinely
support, contains no non-empty secret and no target, has no duplicate
variable names, and its commented-out default values match the real
implemented defaults. Also covers Git/Docker ignore-rule behavior: `.env`
is ignored, `.env.example` is not, `.env.local`/`secrets/`/`*.ovpn` are
ignored, and Docker's build context excludes real `.env` files while
retaining `.env.example`.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_ENV_EXAMPLE_PATH = _REPO_ROOT / ".env.example"
_GITIGNORE_PATH = _REPO_ROOT / ".gitignore"
_DOCKERIGNORE_PATH = _REPO_ROOT / ".dockerignore"


def _env_example_text() -> str:
    return _ENV_EXAMPLE_PATH.read_text(encoding="utf-8")


def _env_example_lines() -> list[str]:
    """Every `KEY=value` assignment line (commented-out examples included,
    since those are still meaningful documentation, but tracked separately
    from active/uncommented lines)."""
    return _env_example_text().splitlines()


def _active_assignments() -> dict[str, str]:
    """Only uncommented `KEY=value` lines — the variables actually "on" in
    a fresh `cp .env.example .env`."""
    result: dict[str, str] = {}
    for ln in _env_example_lines():
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        result[key.strip()] = value.strip()
    return result


_ASSIGNMENT_RE = re.compile(r"^(?:# )?([A-Z][A-Z0-9_]*)=(.*)$")


def _all_assignments_including_commented() -> list[tuple[str, str]]:
    """Every real `KEY=value` pair, whether commented out (`# KEY=value`,
    a single-space comment marker — this file's own documented-default
    convention) or active. Deliberately does NOT match a shell command
    embedded inside a multi-line usage example (e.g. `#   KEY=$(...)`,
    indented well past the single-space comment marker) — those describe
    how to invoke a command, not a variable this file documents."""
    result: list[tuple[str, str]] = []
    for ln in _env_example_lines():
        m = _ASSIGNMENT_RE.match(ln)
        if m:
            result.append((m.group(1), m.group(2).strip()))
    return result


# ---------------------------------------------------------------------------
# .env.example — existence and structure
# ---------------------------------------------------------------------------


def test_env_example_exists() -> None:
    assert _ENV_EXAMPLE_PATH.is_file()


def test_file_header_convention() -> None:
    lines = _env_example_lines()
    assert lines[0] == "# .env.example"
    assert lines[1].startswith("# ")


def test_env_example_committed_not_ignored() -> None:
    result = subprocess.run(
        ["git", "check-ignore", "-q", ".env.example"], cwd=_REPO_ROOT,
    )
    assert result.returncode == 1, ".env.example must NOT be gitignored"




# ---------------------------------------------------------------------------
# Required documented variables
# ---------------------------------------------------------------------------

_REQUIRED_VARIABLES = {
    "APEX_DRY_RUN", "APEX_TARGET", "APEX_TOOL_BACKEND", "APEX_TOOL_SERVICE_URL",
    "APEX_TOOL_SERVICE_TOKEN", "APEX_USE_LLM", "APEX_LLM_PROVIDER", "APEX_LLM_MODEL",
    # Phase 5 — native OpenAI/Anthropic/OpenRouter providers: one credential
    # variable per provider (never a shared/fallback credential), plus
    # provider-specific (never generic/ambiguous) base URL overrides.
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY",
    "APEX_LLM_OPENAI_BASE_URL", "APEX_LLM_ANTHROPIC_BASE_URL", "APEX_LLM_OPENROUTER_BASE_URL",
}


def test_all_required_variables_documented() -> None:
    all_names = {name for name, _ in _all_assignments_including_commented()}
    missing = _REQUIRED_VARIABLES - all_names
    assert not missing, f"missing required documented variables: {missing}"


def test_tool_service_server_variables_documented() -> None:
    all_names = {name for name, _ in _all_assignments_including_commented()}
    for name in (
        "APEX_TOOL_SERVICE_HOST", "APEX_TOOL_SERVICE_PORT",
        "APEX_TOOL_SERVICE_DEFAULT_TIMEOUT_SECONDS", "APEX_TOOL_SERVICE_MAX_TIMEOUT_SECONDS",
        "APEX_TOOL_SERVICE_MAX_ARGUMENTS", "APEX_TOOL_SERVICE_MAX_ARGUMENT_LENGTH",
        "APEX_TOOL_SERVICE_MAX_STDIN_BYTES", "APEX_TOOL_SERVICE_MAX_STDOUT_BYTES",
        "APEX_TOOL_SERVICE_MAX_STDERR_BYTES",
    ):
        assert name in all_names, f"missing tool-service variable: {name}"


def test_variable_names_are_unique() -> None:
    """Every KEY should appear (commented or not) at most once — a
    duplicate would be confusing and a likely copy-paste mistake."""
    names = [name for name, _ in _all_assignments_including_commented()]
    duplicates = {n for n in names if names.count(n) > 1}
    assert not duplicates, f"duplicate variable names in .env.example: {duplicates}"


# ---------------------------------------------------------------------------
# No secrets, no target
# ---------------------------------------------------------------------------


def test_tool_service_token_is_blank() -> None:
    active = _active_assignments()
    assert "APEX_TOOL_SERVICE_TOKEN" in active
    assert active["APEX_TOOL_SERVICE_TOKEN"] == ""


def test_openai_api_key_is_blank() -> None:
    active = _active_assignments()
    assert "OPENAI_API_KEY" in active
    assert active["OPENAI_API_KEY"] == ""


def test_anthropic_api_key_is_blank() -> None:
    active = _active_assignments()
    assert "ANTHROPIC_API_KEY" in active
    assert active["ANTHROPIC_API_KEY"] == ""


def test_openrouter_api_key_is_blank() -> None:
    active = _active_assignments()
    assert "OPENROUTER_API_KEY" in active
    assert active["OPENROUTER_API_KEY"] == ""


def test_no_target_provided() -> None:
    active = _active_assignments()
    assert "APEX_TARGET" in active
    assert active["APEX_TARGET"] == "", "no default target may ever be provided"


def test_no_hardcoded_target_ip_anywhere() -> None:
    """No non-loopback/non-bind-all IPv4 literal anywhere — comment or not.
    10.129.0.0 (Infra Phase 10) is the network address of
    APEX_HTB_ROUTE_CIDR's real default — a generic HTB-lab private range
    documented by name, not any specific engagement target."""
    ipv4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    allowed = {"0.0.0.0", "10.129.0.0"}
    for ln in _env_example_lines():
        for match in ipv4.finditer(ln):
            assert match.group(0) in allowed, f"unexpected IPv4 literal: {ln!r}"


def test_no_openai_style_api_key_pattern() -> None:
    text = _env_example_text()
    assert re.search(r"sk-[A-Za-z0-9]{10,}", text) is None


def test_no_realistic_looking_token_value() -> None:
    text = _env_example_text().lower()
    for bad in ("phase7-test-token", "phase8-test-token", "phase8-baseline-token", "dev-only-token"):
        assert bad not in text


def test_every_non_blank_value_is_a_safe_default_or_placeholder() -> None:
    """Every *active* (uncommented) assignment must be either blank or a
    documented safe default — never something secret-shaped."""
    active = _active_assignments()
    for key, value in active.items():
        if not value:
            continue
        assert not re.search(r"sk-[A-Za-z0-9]{10,}", value)
        assert "token" not in value.lower() or key.endswith("_TOKEN") is False


# ---------------------------------------------------------------------------
# Comments explain required fields
# ---------------------------------------------------------------------------


def _preceding_comment_block(assignment_line: str) -> str:
    """The contiguous run of `#`-prefixed comment lines immediately above
    the first line matching *assignment_line* exactly (e.g.
    ``"APEX_TOOL_SERVICE_TOKEN="``), joined into one string."""
    lines = _env_example_lines()
    idx = lines.index(assignment_line)
    block: list[str] = []
    i = idx - 1
    while i >= 0 and lines[i].strip().startswith("#"):
        block.insert(0, lines[i])
        i -= 1
    return "\n".join(block)


def test_required_token_has_explanatory_comment() -> None:
    block = _preceding_comment_block("APEX_TOOL_SERVICE_TOKEN=")
    assert "REQUIRED" in block


def test_target_has_explanatory_comment() -> None:
    block = _preceding_comment_block("APEX_TARGET=")
    assert "no default target" in block.lower()


# ---------------------------------------------------------------------------
# Values match implemented defaults (apex_tool_service/settings.py)
# ---------------------------------------------------------------------------


def test_documented_defaults_match_service_settings() -> None:
    all_pairs = dict(_all_assignments_including_commented())
    expected = {
        "APEX_TOOL_SERVICE_PORT": "8080",
        "APEX_TOOL_SERVICE_DEFAULT_TIMEOUT_SECONDS": "30",
        "APEX_TOOL_SERVICE_MAX_TIMEOUT_SECONDS": "120",
        "APEX_TOOL_SERVICE_MAX_ARGUMENTS": "32",
        "APEX_TOOL_SERVICE_MAX_STDIN_BYTES": "65536",
        "APEX_TOOL_SERVICE_MAX_STDOUT_BYTES": "1048576",
        "APEX_TOOL_SERVICE_MAX_STDERR_BYTES": "1048576",
    }
    for key, expected_value in expected.items():
        assert all_pairs.get(key) == expected_value, (
            f"{key} documented as {all_pairs.get(key)!r}, but the real "
            f"ServiceSettings default is {expected_value!r}"
        )


def test_apex_dry_run_default_matches_safety_invariant() -> None:
    active = _active_assignments()
    assert active["APEX_DRY_RUN"] == "true"


def test_apex_use_llm_default_is_false() -> None:
    active = _active_assignments()
    assert active["APEX_USE_LLM"] == "false"


def test_apex_llm_provider_default_is_fake() -> None:
    active = _active_assignments()
    assert active["APEX_LLM_PROVIDER"] == "fake", (
        "must not default to an external provider — the safe default is 'fake'"
    )


def test_apex_tool_backend_default_is_remote_for_compose() -> None:
    active = _active_assignments()
    assert active["APEX_TOOL_BACKEND"] == "remote"


def test_apex_tool_service_url_matches_compose_service_name() -> None:
    active = _active_assignments()
    assert active["APEX_TOOL_SERVICE_URL"] == "http://kali:8080"


# ---------------------------------------------------------------------------
# Phase 5 — native OpenAI/Anthropic/OpenRouter provider configuration
# ---------------------------------------------------------------------------


def test_provider_specific_base_url_vars_documented_but_commented_out() -> None:
    """The three provider-specific base URL overrides are documented (so an
    operator can find and uncomment them) but inactive by default — leaving
    all three unset means every provider uses its own official SDK
    default endpoint."""
    active = _active_assignments()
    all_names = {name for name, _ in _all_assignments_including_commented()}
    for name in (
        "APEX_LLM_OPENAI_BASE_URL", "APEX_LLM_ANTHROPIC_BASE_URL", "APEX_LLM_OPENROUTER_BASE_URL",
    ):
        assert name in all_names, f"missing documented variable: {name}"
        assert name not in active, f"{name} must not be active by default"


def test_no_stale_openai_base_url_variable() -> None:
    """The old, single ambiguous OPENAI_BASE_URL variable (which used to
    double as "point OpenAI at OpenRouter") no longer exists anywhere in
    the template — replaced by the three provider-specific variables
    above, each scoped to exactly one provider."""
    all_names = {name for name, _ in _all_assignments_including_commented()}
    assert "OPENAI_BASE_URL" not in all_names


def test_no_stale_router_style_model_example_in_active_llm_model_value() -> None:
    """APEX_LLM_MODEL's active (uncommented) value must be blank — never a
    leftover router-style example value such as "openai/gpt-5.5" baked in
    as an active default."""
    active = _active_assignments()
    assert active.get("APEX_LLM_MODEL", "") == ""


def test_llm_section_mentions_no_provider_neutral_default() -> None:
    text = _env_example_text()
    assert "no provider-neutral default" in text.lower()


def test_llm_section_documents_all_three_provider_names() -> None:
    text = _env_example_text()
    for provider in ("openai", "anthropic", "openrouter"):
        assert f"provider={provider}" in text.lower() or f"apex_llm_provider={provider}" in text.lower()


# ---------------------------------------------------------------------------
# VPN section (Infra Phase 10) — used only by the "htb" Compose profile.
# ---------------------------------------------------------------------------


def test_htb_ovpn_path_is_active_but_blank() -> None:
    """APEX_HTB_OVPN_PATH is uncommented (active) so a fresh `cp .env.example
    .env` shows the variable's shape, but its value is always blank — no
    default target machine, no operator-specific host path, ever shipped
    in a committed template."""
    active = _active_assignments()
    assert "APEX_HTB_OVPN_PATH" in active
    assert active["APEX_HTB_OVPN_PATH"] == ""


def test_htb_route_cidr_default_matches_real_default() -> None:
    """APEX_HTB_ROUTE_CIDR is active with the same real default
    apex_host.config.ApexConfig.htb_route_cidr and
    docker/vpn/Dockerfile's own ENV both use — a non-target-specific,
    generic HTB-lab private range, not a credential."""
    active = _active_assignments()
    assert active.get("APEX_HTB_ROUTE_CIDR") == "10.129.0.0/16"


def test_vpn_service_url_and_timeout_remain_commented_defaults() -> None:
    """APEX_VPN_SERVICE_URL/APEX_VPN_HEALTH_TIMEOUT_SECONDS stay commented
    out — they are meaningful only inside the htb Compose profile, which
    sets APEX_VPN_SERVICE_URL itself (compose.htb.yaml); nothing in the
    default, non-htb workflow needs them active."""
    active = _active_assignments()
    assert "APEX_VPN_SERVICE_URL" not in active
    assert "APEX_VPN_HEALTH_TIMEOUT_SECONDS" not in active


def test_no_ovpn_file_content_or_real_path_in_env_example() -> None:
    """.env.example documents the *shape* of VPN configuration but must
    never contain real profile content, a real host path, or a target.
    Any "secrets/htb.ovpn"-style example path appears only inside a
    comment line (illustrative documentation), never as an active
    assignment's value."""
    for ln in _env_example_lines():
        if "secrets/" in ln or ".ovpn" in ln:
            stripped = ln.strip()
            assert stripped == "" or stripped.startswith("#"), (
                f"non-comment line references a concrete VPN path: {ln!r}"
            )
    active = _active_assignments()
    # APEX_HTB_OVPN_PATH must never carry a real, non-blank path in the
    # committed template (covered above too — restated here explicitly
    # against this section's own historical "must stay inactive" intent).
    assert active.get("APEX_HTB_OVPN_PATH", "") == ""


def test_compose_yaml_references_vpn_variables_only_in_the_vpn_service() -> None:
    """Infra Phase 10: compose.yaml legitimately references
    APEX_HTB_OVPN_PATH/APEX_HTB_ROUTE_CIDR now (the `vpn` service's own
    profile-gated configuration) — the base file's `apex`/`kali` service
    definitions must not reference either, since VPN configuration only
    ever flows to apex/kali through the separate compose.htb.yaml override."""
    compose_text = (_REPO_ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert "APEX_HTB_OVPN_PATH" in compose_text
    assert "APEX_HTB_ROUTE_CIDR" in compose_text

    import yaml

    data = yaml.safe_load(compose_text)
    for name in ("apex", "kali"):
        env = data["services"][name].get("environment", {})
        assert not any("VPN" in k or "HTB" in k for k in env), (
            f"{name} in the base compose.yaml must not reference VPN/HTB "
            "variables — that only happens in compose.htb.yaml"
        )


# ---------------------------------------------------------------------------
# Git ignore rules
# ---------------------------------------------------------------------------


def _git_check_ignore(path: str) -> bool:
    """True if *path* would be ignored by git (relative to repo root)."""
    result = subprocess.run(
        ["git", "check-ignore", "-q", path], cwd=_REPO_ROOT,
    )
    return result.returncode == 0


class TestGitIgnoreRules:
    def test_env_is_ignored(self) -> None:
        assert _git_check_ignore(".env")

    def test_env_local_is_ignored(self) -> None:
        assert _git_check_ignore(".env.local")

    def test_env_example_is_not_ignored(self) -> None:
        assert not _git_check_ignore(".env.example")

    def test_secrets_directory_is_ignored(self) -> None:
        assert _git_check_ignore("secrets/anything.txt")

    def test_ovpn_files_are_ignored(self) -> None:
        assert _git_check_ignore("client.ovpn")
        assert _git_check_ignore("vpn/client.ovpn")

    def test_no_broad_env_star_glob_in_gitignore(self) -> None:
        """The task brief's explicit requirement: never a bare `.env*`
        pattern that would silently also match .env.example."""
        lines = [
            ln.strip() for ln in _GITIGNORE_PATH.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert ".env*" not in lines


# ---------------------------------------------------------------------------
# Docker ignore rules
# ---------------------------------------------------------------------------


class TestDockerIgnoreRules:
    def test_dockerignore_excludes_env(self) -> None:
        lines = _dockerignore_lines()
        assert ".env" in lines

    def test_dockerignore_excludes_env_local(self) -> None:
        lines = _dockerignore_lines()
        assert ".env.local" in lines

    def test_dockerignore_negates_env_example(self) -> None:
        """`.env.*` is a glob that would otherwise also match
        `.env.example` — the explicit `!.env.example` negation must be
        present, and must appear after the `.env.*` pattern it negates."""
        text = _DOCKERIGNORE_PATH.read_text(encoding="utf-8")
        assert "!.env.example" in text
        assert text.index(".env.*") < text.index("!.env.example")

    def test_dockerignore_excludes_ovpn_and_secrets(self) -> None:
        lines = _dockerignore_lines()
        assert "*.ovpn" in lines
        assert "secrets/" in lines

    def test_neither_dockerfile_copies_env(self) -> None:
        for dockerfile in ("docker/apex/Dockerfile", "docker/kali/Dockerfile"):
            text = (_REPO_ROOT / dockerfile).read_text(encoding="utf-8")
            for ln in text.splitlines():
                stripped = ln.strip()
                if stripped.startswith("#"):
                    continue
                if re.match(r"^COPY\b", stripped):
                    assert ".env" not in stripped, f"{dockerfile}: COPY references .env: {stripped!r}"


def _dockerignore_lines() -> list[str]:
    return [
        ln.strip() for ln in _DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#") and not ln.strip().startswith("!")
    ]
