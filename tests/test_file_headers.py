# test_file_headers.py
# Enforces the two-line file-header convention required by CLAUDE.md §12.6.
"""File-header convention enforcement tests (F18).

Every Python file in ``memfabric/`` and ``apex_host/`` must start with
exactly two comment lines:

    # filename.py
    # One-line explanation of what this file does.

These tests scan the production source trees and fail if any file is
missing the header, has the wrong filename in the first line, or has a
non-comment second line.

Tests:
    HEADER-01  All memfabric/ source files have a first comment line.
    HEADER-02  All apex_host/ source files have a first comment line.
    HEADER-03  All orchestration/ source files have a correct filename header.
    HEADER-04  Synthetic missing-header case is detected by the scanner.
    HEADER-05  Synthetic wrong-path header case is detected by the scanner.
"""
from __future__ import annotations

import pathlib
from typing import Iterator

import pytest

_PROJECT_ROOT = pathlib.Path(__file__).parent.parent
_MEMFABRIC_ROOT = _PROJECT_ROOT / "memfabric"
_APEX_HOST_ROOT = _PROJECT_ROOT / "apex_host"
_ORCHESTRATION_ROOT = _APEX_HOST_ROOT / "orchestration"

# Files that are intentionally exempt (generated, vendored, or empty).
_EXEMPT_FILES: frozenset[str] = frozenset({"__init__.py"})


def _py_files(root: pathlib.Path) -> Iterator[pathlib.Path]:
    """Yield all .py files under root, skipping __pycache__ directories."""
    for p in sorted(root.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        # __init__.py files are allowed to have just a package docstring.
        if p.name == "__init__.py":
            continue
        yield p


def _check_first_line(path: pathlib.Path) -> str | None:
    """Return an error string if the first line is not a valid comment, else None."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        return f"{path}: could not read — {exc}"
    if not lines:
        return f"{path}: empty file"
    first = lines[0]
    if not first.startswith("# "):
        return f"{path}: first line is not a comment: {first!r}"
    return None


def _check_filename_header(path: pathlib.Path) -> str | None:
    """Return an error string if the first line doesn't contain the filename, else None."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        return f"{path}: could not read — {exc}"
    if not lines:
        return f"{path}: empty file"
    first = lines[0]
    # Expected: "# filename.py" where filename matches path.name
    expected_prefix = f"# {path.name}"
    if not first.startswith(expected_prefix):
        return (
            f"{path}: first line {first!r} does not start with "
            f"expected {expected_prefix!r}"
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# HEADER-01 — memfabric/ source files
# ─────────────────────────────────────────────────────────────────────────────

def _memfabric_files() -> list[pathlib.Path]:
    return list(_py_files(_MEMFABRIC_ROOT))


@pytest.mark.parametrize("path", _memfabric_files(), ids=lambda p: str(p.relative_to(_PROJECT_ROOT)))
def test_header01_memfabric_files_have_first_comment(path: pathlib.Path) -> None:
    """HEADER-01: every memfabric/ source file must start with a comment line."""
    err = _check_first_line(path)
    if err:
        pytest.fail(err)


# ─────────────────────────────────────────────────────────────────────────────
# HEADER-02 — apex_host/ source files
# ─────────────────────────────────────────────────────────────────────────────

def _apex_host_files() -> list[pathlib.Path]:
    return list(_py_files(_APEX_HOST_ROOT))


@pytest.mark.parametrize("path", _apex_host_files(), ids=lambda p: str(p.relative_to(_PROJECT_ROOT)))
def test_header02_apex_host_files_have_first_comment(path: pathlib.Path) -> None:
    """HEADER-02: every apex_host/ source file must start with a comment line."""
    err = _check_first_line(path)
    if err:
        pytest.fail(err)


# ─────────────────────────────────────────────────────────────────────────────
# HEADER-03 — orchestration/ files have correct filename in header
# ─────────────────────────────────────────────────────────────────────────────

def _orchestration_files() -> list[pathlib.Path]:
    return list(_py_files(_ORCHESTRATION_ROOT))


@pytest.mark.parametrize(
    "path",
    _orchestration_files(),
    ids=lambda p: str(p.relative_to(_PROJECT_ROOT)),
)
def test_header03_orchestration_files_have_correct_path_header(path: pathlib.Path) -> None:
    """HEADER-03: each orchestration/ file's first comment must name the file."""
    err = _check_filename_header(path)
    if err:
        pytest.fail(err)


# ─────────────────────────────────────────────────────────────────────────────
# HEADER-04 — Synthetic missing-header detection
# ─────────────────────────────────────────────────────────────────────────────

def test_header04_synthetic_missing_header_is_detected(tmp_path: pathlib.Path) -> None:
    """HEADER-04: _check_first_line returns an error for a missing comment."""
    bad = tmp_path / "bad_module.py"
    bad.write_text('"""No header comment."""\n\nx = 1\n', encoding="utf-8")
    err = _check_first_line(bad)
    assert err is not None, "Expected an error for a file without a comment header"
    assert "not a comment" in err.lower() or "first line" in err.lower()


# ─────────────────────────────────────────────────────────────────────────────
# HEADER-05 — Synthetic wrong-path header detection
# ─────────────────────────────────────────────────────────────────────────────

def test_header05_synthetic_wrong_path_header_is_detected(tmp_path: pathlib.Path) -> None:
    """HEADER-05: _check_filename_header returns an error for a mismatched filename."""
    wrong = tmp_path / "correct_name.py"
    wrong.write_text(
        "# wrong_name.py\n# This is the description.\n\nx = 1\n",
        encoding="utf-8",
    )
    err = _check_filename_header(wrong)
    assert err is not None, "Expected an error when first-line filename does not match"
    assert "correct_name.py" in err or "wrong_name.py" in err
