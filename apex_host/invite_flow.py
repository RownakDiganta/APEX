# invite_flow.py
# Generic, opt-in invite/registration flow helpers (§28.35): pure decode chain,
# endpoint matching, and auto-approve pattern matching. No machine-specific paths.
"""Generic invite/registration flow primitives (§28.35).

Pure, dependency-light helpers used by the opt-in auto-invite-flow feature. All
values (endpoint patterns, decode steps, field names) are OPERATOR-configured —
this module hardcodes no path, no decode order, and no machine name. No JS is
executed; decoding is pure Python (§28.24 unchanged). The feature is default-off
and only reachable when the operator sets ``--auto-invite-flow`` (§11.2 amended
exception, §28.30 amended operator-configured auto-approval).
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from memfabric.types import Node, SubgraphView, TaskSpec

#: Decode steps the operator may compose, in order, via ``--invite-decode-steps``.
_SUPPORTED_DECODE_STEPS: frozenset[str] = frozenset({"base64", "rot13", "hex", "url"})


class DecodeError(ValueError):
    """A decode step failed or an unknown step name was supplied."""


def supported_decode_steps() -> frozenset[str]:
    return _SUPPORTED_DECODE_STEPS


def decode_response(raw: str, steps: list[str]) -> str:
    """Apply an operator-configured sequence of pure-Python decode steps.

    Supported: ``base64``, ``rot13``, ``hex``, ``url``. Raises ``DecodeError`` on
    an unknown step name or a step that cannot decode its input — the caller
    aborts the flow rather than sending a garbage value. NEVER executes code.
    """
    result = raw.strip()
    for step in steps:
        name = step.strip().lower()
        if not name:
            continue
        try:
            if name == "base64":
                result = base64.b64decode(result).decode("utf-8", errors="replace")
            elif name == "rot13":
                result = codecs.decode(result, "rot_13")
            elif name == "hex":
                result = bytes.fromhex(result.strip()).decode("utf-8", errors="replace")
            elif name == "url":
                result = urllib.parse.unquote(result)
            else:
                raise DecodeError(f"unknown decode step: {name!r}")
        except (binascii.Error, ValueError) as exc:
            if isinstance(exc, DecodeError):
                raise
            raise DecodeError(f"decode step {name!r} failed: {type(exc).__name__}") from exc
    return result


def _compile(patterns: list[str]) -> list[re.Pattern[str]]:
    """Compile operator regex patterns; a malformed pattern falls back to a
    literal (escaped) match rather than raising."""
    out: list[re.Pattern[str]] = []
    for p in patterns:
        p = p.strip()
        if not p:
            continue
        try:
            out.append(re.compile(p))
        except re.error:
            out.append(re.compile(re.escape(p)))
    return out


def find_matching_endpoints(
    subgraph: "SubgraphView", patterns: list[str],
) -> list["Node"]:
    """Discovered ``endpoint`` nodes whose URL or path matches any pattern.

    Order-preserving over the subgraph's node order; deduped by node id. Empty
    when no patterns are configured or nothing matches (never raises)."""
    compiled = _compile(patterns)
    if not compiled:
        return []
    out: list[Node] = []
    seen: set[str] = set()
    for node in subgraph.nodes:
        if node.type != "endpoint" or node.id in seen:
            continue
        url = str(node.props.get("url", ""))
        path = str(node.props.get("path", ""))
        if any(rx.search(url) or (path and rx.search(path)) for rx in compiled):
            seen.add(node.id)
            out.append(node)
    return out


def build_invite_flow_task(
    subgraph: "SubgraphView", config: object, *,
    target: str, host_ip: str, goal_id: str, anchor: str | None,
) -> "TaskSpec | None":
    """Emit ONE ``invite_flow`` orchestrator TaskSpec when the opt-in flow is
    enabled and all three endpoint types (generate/verify/register) have been
    discovered — else None (§28.35).

    Idempotent: returns None once a credential node from ``auto_registration``
    already exists (the flow succeeded), so it is emitted at most once."""
    if not getattr(config, "auto_invite_flow", False):
        return None
    for n in subgraph.nodes:
        if n.type == "credential" and str(n.props.get("source", "")) == "auto_registration":
            return None
    gen = find_matching_endpoints(subgraph, list(getattr(config, "invite_generate_patterns", [])))
    ver = find_matching_endpoints(subgraph, list(getattr(config, "invite_verify_patterns", [])))
    reg = find_matching_endpoints(subgraph, list(getattr(config, "invite_register_patterns", [])))
    if not (gen and ver and reg):
        return None
    from memfabric.ids import new_id
    from memfabric.types import TaskSpec

    return TaskSpec(
        id=new_id(), goal_id=goal_id, executor_domain="web",
        params={
            "tool": "invite_flow", "args": [], "target": target, "parser": "invite_flow",
            "generate_url": str(gen[0].props.get("url", "")),
            "verify_url": str(ver[0].props.get("url", "")),
            "register_url": str(reg[0].props.get("url", "")),
            "host_ip": host_ip,
            "decode_steps": list(getattr(config, "invite_decode_steps", [])),
            "verify_response_field": str(getattr(config, "invite_verify_response_field", "code")),
            "register_username_field": str(getattr(config, "invite_register_username_field", "username")),
            "register_password_field": str(getattr(config, "invite_register_password_field", "password")),
        },
        subgraph_anchor=anchor, phase="web",
    )


def action_matches_auto_approve(method: str, url: str, patterns: list[str]) -> bool:
    """True if a send-side action (``METHOD url``) matches an operator
    ``--auto-approve-send-patterns`` entry.

    Matching is against ``"<METHOD> <url>"`` and ``"<METHOD> <path>"`` so a
    pattern like ``"POST /api/v1/invite/verify"`` matches regardless of scheme/
    host. Empty patterns → never auto-approve (fail-closed). A malformed regex
    falls back to a literal match. This ONLY says whether the operator opted to
    auto-approve THIS action; it never relaxes ``safety.py`` or policy scope."""
    compiled = _compile(patterns)
    if not compiled:
        return False
    m = (method or "GET").upper()
    try:
        path = urllib.parse.urlsplit(url).path or url
    except ValueError:
        path = url
    candidates = (f"{m} {url}", f"{m} {path}")
    return any(rx.search(c) for rx in compiled for c in candidates)
