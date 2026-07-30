# test_htb_workflow_docs.py
# Documentation/CLI consistency regression tests: guard the authorized-HTB workflow docs against the exact drift observed during a real preflight (stale --report-dir, vpn_route_check missing --vpn-service-url, router-style model name paired with --llm-provider openai).
"""Scan every Markdown doc's fenced code blocks and assert the copy-pasteable
authorized-HTB commands cannot regress to the forms that failed during a real
preflight:

- **Issue 5** — no ``run_htb_local`` example uses ``--report-dir`` (a flag that
  exists only on ``apex_host.container_entrypoint``, never on
  ``run_htb_local``).
- **Issue 1** — every ``vpn_route_check`` invocation includes the required
  ``--vpn-service-url`` argument.
- **Issue 2** — no example pairs ``--llm-provider openai`` with a router-style
  ``--llm-model openai/...`` (which the native OpenAI provider rejects).

Only fenced code blocks in ``*.md`` files are scanned — prose that merely
*mentions* a flag or module name is intentionally ignored, and multi-line
backslash-continued commands are scanned as a single block.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_LLM_MODEL_OPENAI_PREFIX_RE = re.compile(r"--llm-model\s+openai/")


def _markdown_files() -> list[Path]:
    files = sorted(_REPO_ROOT.glob("*.md"))
    files += sorted((_REPO_ROOT / "docs").glob("*.md"))
    # Never scan the vendored third-party knowledge corpora.
    return [f for f in files if "Knowledge" not in f.parts and "knowledge" not in f.parts]


def _code_blocks(text: str) -> list[str]:
    return [m.group(1) for m in _BLOCK_RE.finditer(text)]


@pytest.mark.parametrize("doc", _markdown_files(), ids=lambda p: str(p.relative_to(_REPO_ROOT)))
def test_run_htb_local_examples_never_use_report_dir(doc: Path) -> None:
    for block in _code_blocks(doc.read_text(encoding="utf-8")):
        if "run_htb_local" in block:
            assert "--report-dir" not in block, (
                f"{doc}: a run_htb_local example uses --report-dir, which that CLI does "
                "not support (use --export-json/--export-graph)."
            )


@pytest.mark.parametrize("doc", _markdown_files(), ids=lambda p: str(p.relative_to(_REPO_ROOT)))
def test_vpn_route_check_examples_include_service_url(doc: Path) -> None:
    for block in _code_blocks(doc.read_text(encoding="utf-8")):
        if "vpn_route_check" in block and "python" in block:
            assert "--vpn-service-url" in block, (
                f"{doc}: a vpn_route_check example omits the required --vpn-service-url."
            )


@pytest.mark.parametrize("doc", _markdown_files(), ids=lambda p: str(p.relative_to(_REPO_ROOT)))
def test_openai_provider_never_paired_with_router_style_model(doc: Path) -> None:
    for block in _code_blocks(doc.read_text(encoding="utf-8")):
        if "--llm-provider openai" in block:
            assert not _LLM_MODEL_OPENAI_PREFIX_RE.search(block), (
                f"{doc}: --llm-provider openai is paired with a router-style "
                "--llm-model openai/... — native OpenAI model names have no vendor/ prefix "
                "(use --llm-provider openrouter for router-style ids)."
            )


def test_at_least_one_markdown_file_scanned() -> None:
    # Guard against the glob silently matching nothing (which would make the
    # parametrized tests vacuously pass).
    assert len(_markdown_files()) > 3
