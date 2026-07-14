# compile_knowledge.py
# CLI entrypoint: compiles all knowledge database sources into compact JSONL records.
"""Compile all knowledge database sources into compact JSONL records.

Usage
-----
    python -m apex_host.knowledge.compiler.compile_knowledge \\
        --knowledge-root ./knowledge

Strict mode (verifies all 9 required outputs exist after compilation):
    python -m apex_host.knowledge.compiler.compile_knowledge \\
        --knowledge-root ./knowledge --strict --verbose

Inspection only (no writes):
    python -m apex_host.knowledge.compiler.compile_knowledge \\
        --knowledge-root ./knowledge --inspect

Selective family:
    python -m apex_host.knowledge.compiler.compile_knowledge \\
        --policy-db ./knowledge/policy_db

Each family's compiled output lands in <family_dir>/compiled/.
Missing source directories are skipped gracefully with a logged warning.

Exit codes
----------
0 — compilation succeeded; all expected outputs present (in strict mode).
1 — no source directories found, a compiler raised, or strict-mode verification
    detected missing or empty output files.
"""
from __future__ import annotations

import argparse
import logging
import pathlib
import sys

logger = logging.getLogger(__name__)

# Required output files for each family — the single source of truth used by
# --strict verification and the layout detector.
REQUIRED_OUTPUTS: dict[str, list[str]] = {
    "policy_db": [
        "policy_records.jsonl",
        "hackthebox_lab.yaml",
    ],
    "methodology_db": [
        "methodology_chunks.jsonl",
    ],
    "intel_db": [
        "attack_techniques.jsonl",
        "cwe_weaknesses.jsonl",
        "capec_patterns.jsonl",
        "cve_slim.jsonl",
    ],
    "payload_db": [
        "payload_records.jsonl",
        "wordlist_manifest.jsonl",
    ],
}


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(levelname)-8s %(name)s: %(message)s",
        level=level,
        stream=sys.stderr,
    )


def _resolve_paths(
    args: argparse.Namespace,
) -> dict[str, pathlib.Path | None]:
    """Resolve per-family source paths from --knowledge-root or explicit flags."""
    root = pathlib.Path(args.knowledge_root) if args.knowledge_root else None

    def _resolve(explicit: str | None, subdir: str) -> pathlib.Path | None:
        if explicit:
            return pathlib.Path(explicit)
        if root:
            candidate = root / subdir
            return candidate if candidate.is_dir() else None
        return None

    return {
        "policy":      _resolve(args.policy_db,      "policy_db"),
        "methodology": _resolve(args.methodology_db, "methodology_db"),
        "intel":       _resolve(args.intel_db,       "intel_db"),
        "payload":     _resolve(args.payload_db,     "payload_db"),
    }


def _run_inspect(args: argparse.Namespace) -> int:
    """Print an inspection report for the knowledge root.  No writes to disk."""
    _setup_logging(args.verbose)
    root_arg = args.knowledge_root or "."
    from apex_host.knowledge.compiler.layout import detect_layout, format_inspect_report
    layout = detect_layout(root_arg)
    print(format_inspect_report(layout))
    if not layout.root_exists or not layout.any_family_found():
        return 1
    return 0 if layout.all_outputs_present() else 1


def _verify_outputs(
    family_name: str,
    compiled_dir: pathlib.Path,
    strict: bool,
) -> list[str]:
    """Return a list of problem descriptions for a family's compiled outputs.

    Checks that each expected output file exists and is non-empty.
    """
    problems: list[str] = []
    for filename in REQUIRED_OUTPUTS.get(family_name, []):
        out = compiled_dir / filename
        if not out.exists():
            problems.append(f"MISSING  {out}")
        elif out.stat().st_size == 0:
            problems.append(f"EMPTY    {out}")
    return problems


def _run(args: argparse.Namespace) -> int:
    """Execute compilation for all resolved source families.

    Returns an exit code: 0 on success, 1 if at least one family had an error,
    no source directories were found, or --strict verification failed.
    """
    _setup_logging(args.verbose)

    if getattr(args, "inspect", False):
        return _run_inspect(args)

    strict = getattr(args, "strict", False)
    paths = _resolve_paths(args)
    any_found = False
    exit_code = 0
    all_problems: list[str] = []

    # --- policy_db ---
    if (p := paths["policy"]):
        any_found = True
        try:
            from apex_host.knowledge.compiler.policy_compiler import compile_policy
            src = p / "sources" if (p / "sources").is_dir() else p
            count = compile_policy(sources_path=src, output_dir=p / "compiled")
            print(f"[policy_db]          {count:>6d} records  → {p / 'compiled'}")
            if strict:
                problems = _verify_outputs("policy_db", p / "compiled", strict)
                all_problems.extend(problems)
        except Exception as exc:  # pragma: no cover
            logger.error("policy_db compilation failed: %s", exc)
            exit_code = 1

    # --- methodology_db ---
    if (p := paths["methodology"]):
        any_found = True
        try:
            from apex_host.knowledge.compiler.methodology_compiler import compile_methodology
            count = compile_methodology(sources_path=p, output_dir=p / "compiled")
            print(f"[methodology_db]     {count:>6d} records  → {p / 'compiled'}")
            if strict:
                problems = _verify_outputs("methodology_db", p / "compiled", strict)
                all_problems.extend(problems)
        except Exception as exc:  # pragma: no cover
            logger.error("methodology_db compilation failed: %s", exc)
            exit_code = 1

    # --- intel_db ---
    if (p := paths["intel"]):
        any_found = True
        try:
            from apex_host.knowledge.compiler.intel_compiler import compile_intel
            count = compile_intel(intel_db_path=p, output_dir=p / "compiled")
            print(f"[intel_db]           {count:>6d} records  → {p / 'compiled'}")
            if strict:
                problems = _verify_outputs("intel_db", p / "compiled", strict)
                all_problems.extend(problems)
        except Exception as exc:  # pragma: no cover
            logger.error("intel_db compilation failed: %s", exc)
            exit_code = 1

    # --- payload_db ---
    if (p := paths["payload"]):
        any_found = True
        try:
            from apex_host.knowledge.compiler.payload_compiler import compile_payload
            p_count, m_count = compile_payload(payload_db_path=p, output_dir=p / "compiled")
            print(
                f"[payload_db]    {p_count:>6d} payload + {m_count:>5d} manifests"
                f"  → {p / 'compiled'}"
            )
            if strict:
                problems = _verify_outputs("payload_db", p / "compiled", strict)
                all_problems.extend(problems)
        except Exception as exc:  # pragma: no cover
            logger.error("payload_db compilation failed: %s", exc)
            exit_code = 1

    if not any_found:
        print(
            "No source directories found. "
            "Pass --knowledge-root ./knowledge or explicit family flags.",
            file=sys.stderr,
        )
        return 1

    if all_problems:
        print(
            f"\nSTRICT: {len(all_problems)} output problem(s) detected:",
            file=sys.stderr,
        )
        for problem in all_problems:
            print(f"  {problem}", file=sys.stderr)
        exit_code = 1
    elif strict and any_found:
        total = sum(len(v) for v in REQUIRED_OUTPUTS.values())
        print(f"\nSTRICT: all {total} required outputs verified present and non-empty.")

    return exit_code


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m apex_host.knowledge.compiler.compile_knowledge",
        description=(
            "Compile raw knowledge database sources into compact JSONL records. "
            "Compiled outputs are written to <family_dir>/compiled/. "
            "Does NOT fetch anything from the internet."
        ),
    )
    parser.add_argument(
        "--knowledge-root",
        metavar="DIR",
        help=(
            "Root of the knowledge directory (e.g. ./knowledge). "
            "Sub-directories (intel_db, methodology_db, payload_db, policy_db) "
            "are discovered automatically."
        ),
    )
    parser.add_argument("--policy-db", metavar="DIR", help="Explicit path to policy_db/ directory.")
    parser.add_argument("--methodology-db", metavar="DIR", help="Explicit path to methodology_db/ directory.")
    parser.add_argument("--intel-db", metavar="DIR", help="Explicit path to intel_db/ directory.")
    parser.add_argument("--payload-db", metavar="DIR", help="Explicit path to payload_db/ directory.")
    parser.add_argument(
        "--inspect",
        action="store_true",
        help=(
            "Print a layout report showing which DB folders exist, source file "
            "counts, expected outputs, and which outputs are missing. No writes."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "After compilation, verify every expected output file exists and is "
            "non-empty. Exit 1 if any check fails."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging (shows per-file progress).",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help=(
            "Skip the post-compilation verification step.  By default the "
            "verifier runs automatically after compilation to confirm all 9 "
            "required outputs exist, are non-empty, and contain valid records."
        ),
    )
    return parser


def _run_verify(args: argparse.Namespace) -> int:
    """Run verify_compiled after a successful compilation.

    Only fires when ``--knowledge-root`` was supplied, all four family
    directories exist under that root (complete knowledge root, not a partial
    fixture), and ``--no-verify`` was NOT passed.  Returns the verification
    exit code (0 = all OK, 1 = failures).
    """
    root_arg = getattr(args, "knowledge_root", None)
    if not root_arg:
        return 0
    root = pathlib.Path(root_arg)
    # Only run the full 9-file verifier when all four family dirs are present.
    # A partial compilation (e.g. only policy_db in a test fixture) should not
    # trigger the full-suite verifier — that would always fail.
    _ALL_FAMILIES = ("policy_db", "methodology_db", "intel_db", "payload_db")
    if not all((root / f).is_dir() for f in _ALL_FAMILIES):
        return 0
    print("\n--- Post-compilation verification ---")
    from apex_host.knowledge.compiler.verify_compiled import (
        verify_compiled, _format_result,
    )
    result = verify_compiled(root)
    print(_format_result(result))
    return 0 if result.passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    exit_code = _run(args)
    # Auto-verify unless --no-verify or --inspect (inspect makes no writes)
    if exit_code == 0 and not getattr(args, "no_verify", False) \
            and not getattr(args, "inspect", False):
        verify_code = _run_verify(args)
        if verify_code != 0:
            exit_code = verify_code
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
