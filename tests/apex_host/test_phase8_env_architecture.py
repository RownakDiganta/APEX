# test_phase8_env_architecture.py
# Architecture invariants for Infra Phase 8's environment-configuration workflow — environment reads stay centralized, ApexConfig.to_safe_dict() redacts every secret field.
"""Repository-wide architecture scan verifying that Infra Phase 8 did not
scatter new ``os.environ``/``os.getenv`` reads across the codebase, that
``apex_host/config.py`` itself still never reads the environment (the
pre-existing invariant this phase's design was required to preserve), and
that ``ApexConfig.to_safe_dict()`` redacts every field capable of holding a
secret.
"""
from __future__ import annotations

import pathlib
import re

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_APEX_HOST_ROOT = _REPO_ROOT / "apex_host"
_ENV_PATTERN = re.compile(r"\bos\.environ\b|\bos\.getenv\b")

# The complete, closed set of apex_host/ files permitted to read the
# process environment directly, each with a specific, documented reason:
_APPROVED_ENV_READERS = {
    # The Infra Phase 8 centralized loader itself — its entire purpose.
    "apex_host/config_env.py",
    # Pre-existing (Infra Phase 4): APEX_TOOL_SERVICE_TOKEN fallback.
    "apex_host/tools/remote_backend.py",
    # Phase 5 (native OpenAI/Anthropic/OpenRouter providers): the shared
    # base-URL-override precedence resolver reads each provider's own
    # SDK-recognized env var (OPENAI_BASE_URL / ANTHROPIC_BASE_URL /
    # OPENROUTER_BASE_URL) as the last fallback before that provider's
    # official default — never a credential.
    "apex_host/llm/router.py",
    # Phase 5: apex_host.llm.providers.base.read_credential() is the ONE
    # place any of the three provider credential env vars
    # (OPENAI_API_KEY / ANTHROPIC_API_KEY / OPENROUTER_API_KEY) is actually
    # read — called by each native provider adapter's own __init__/
    # generate()/check_readiness(), never by a planner or the gateway.
    "apex_host/llm/providers/base.py",
    # Entry points: build the {file, **os.environ} mapping for --env-file,
    # per apex_host/config_env.py::load_env_file's own documented contract.
    "apex_host/main.py",
    "apex_host/eval/run_htb_local.py",
    # Infra Phase 8: reads token/OPENAI_API_KEY *presence* only, for
    # validation and the redacted summary — never prints the value.
    "apex_host/eval/check_config.py",
    # Infra Phase 7: reads APEX_TOOL_BACKEND / APEX_TOOL_SERVICE_URL as its
    # own CLI-flag defaults (a narrow, purpose-built connectivity smoke
    # module, not apex_host/config.py).
    "apex_host/eval/compose_smoke.py",
    # Infra Phase 9: the container entrypoint builds the {file, **os.environ}
    # mapping for --env-file (same load_env_file contract as main.py/
    # run_htb_local.py above) and reads token/OPENAI_API_KEY *presence* only
    # for its redacted configuration summary — never prints either value.
    "apex_host/container_entrypoint.py",
    # Infra Phase 9: apex_host/eval/preflight.py::check_llm_readiness reads
    # OPENAI_API_KEY *presence* only (never its value) to validate LLM
    # credential readiness before a live run — same discipline as
    # check_config.py above.
    "apex_host/eval/preflight.py",
}


def _py_files(root: pathlib.Path) -> list[pathlib.Path]:
    return [
        p for p in sorted(root.rglob("*.py"))
        if "__pycache__" not in p.parts
    ]


def test_config_py_still_has_zero_env_access() -> None:
    """The pre-existing, Phase-9-era invariant this phase's design was
    explicitly required to preserve (task brief: "Inspect that decision
    carefully... revise the design with the least invasive approach")."""
    src = (_APEX_HOST_ROOT / "config.py").read_text(encoding="utf-8")
    assert "os.getenv" not in src
    assert "os.environ" not in src


def test_env_reads_are_confined_to_the_approved_file_set() -> None:
    violations: list[str] = []
    for path in _py_files(_APEX_HOST_ROOT):
        rel = str(path.relative_to(_REPO_ROOT)).replace("\\", "/")
        src = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(src.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _ENV_PATTERN.search(line) and rel not in _APPROVED_ENV_READERS:
                violations.append(f"{rel}:{lineno}: {stripped}")
    assert not violations, (
        "Unexpected os.environ/os.getenv access outside the approved file "
        "set — either this is a new, undocumented scattering of environment "
        "reads (fix: route it through apex_host/config_env.py instead), or "
        "the file is a legitimate new reader that should be added to "
        "_APPROVED_ENV_READERS in this test with a documented reason:\n"
        + "\n".join(violations)
    )


def test_approved_readers_all_still_exist_and_read_env() -> None:
    """The inverse check: every entry in the allowlist must still be a real
    file that actually reads the environment — an allowlist entry for code
    that was since removed or refactored would silently stop testing
    anything."""
    for rel in _APPROVED_ENV_READERS:
        path = _REPO_ROOT / rel
        assert path.is_file(), f"approved env reader no longer exists: {rel}"
        src = path.read_text(encoding="utf-8")
        assert _ENV_PATTERN.search(src), (
            f"{rel} is in the approved env-reader allowlist but no longer "
            "reads os.environ/os.getenv — remove it from the allowlist"
        )


def test_no_new_dotenv_auto_load_anywhere() -> None:
    """python-dotenv's ``load_dotenv()`` (which mutates real os.environ as
    a side effect and can implicitly discover a `.env` file via directory
    walking) must never be called anywhere in apex_host — only the
    explicit, injection-safe ``dotenv_values()`` (via
    apex_host.config_env.load_env_file) is permitted."""
    for path in _py_files(_APEX_HOST_ROOT):
        src = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(src.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            assert "load_dotenv(" not in line, (
                f"{path.relative_to(_REPO_ROOT)}:{lineno}: implicit "
                f"load_dotenv() call found — use "
                "apex_host.config_env.load_env_file() instead: "
                f"{line.strip()!r}"
            )


class TestSafeSerializationRedaction:
    def test_tool_service_token_redacted(self) -> None:
        from apex_host.config import ApexConfig

        config = ApexConfig(target="10.0.0.1", tool_service_token="super-secret-token")
        safe = config.to_safe_dict()
        assert safe["tool_service_token"] != "super-secret-token"
        assert "super-secret-token" not in str(safe)

    def test_password_candidates_redacted(self) -> None:
        from apex_host.config import ApexConfig

        config = ApexConfig(target="10.0.0.1", password_candidates=["hunter2"])
        safe = config.to_safe_dict()
        assert safe["password_candidates"] != ["hunter2"]
        assert "hunter2" not in str(safe)

    def test_empty_secrets_not_falsely_marked_present(self) -> None:
        from apex_host.config import ApexConfig

        config = ApexConfig(target="10.0.0.1")
        safe = config.to_safe_dict()
        assert safe["tool_service_token"] == ""
        assert safe["password_candidates"] == []

    def test_no_new_plaintext_secret_field_added(self) -> None:
        """Guards against a future field being added to ApexConfig that
        holds a secret *value* (a token or password string/list) without
        to_safe_dict() redacting it. Boolean policy flags whose name
        happens to contain "password" (e.g. allow_password_lists — a
        wordlist-permission toggle, not a secret) are correctly excluded:
        only str/list[str]-typed fields can hold an actual secret value."""
        from dataclasses import fields

        from apex_host.config import ApexConfig

        safe_dict_src = pathlib.Path(
            _APEX_HOST_ROOT / "config.py"
        ).read_text(encoding="utf-8")
        safe_dict_body = safe_dict_src.split("def to_safe_dict")[1].split("def ")[0]
        for f in fields(ApexConfig):
            if f.type not in ("str", "list[str]"):
                continue
            if "token" in f.name.lower() or "password" in f.name.lower():
                assert f.name in safe_dict_body, (
                    f"ApexConfig.{f.name} looks secret-shaped but is not "
                    "referenced inside to_safe_dict() — it may leak in plaintext"
                )
