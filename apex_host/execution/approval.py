# approval.py
# Fail-closed human-approval gate at the dispatch chokepoint: classifies each
# action read-side vs send-side; send-side actions require explicit per-action
# human approval before reaching the executor. A safety control, not capability.
"""Supervised approval gate (§28.30).

A mechanical, fail-closed control that sits at the dispatch chokepoint. It
classifies every proposed action by its SHAPE (HTTP method / body / headers /
command) as READ-SIDE or SEND-SIDE:

- READ-SIDE (GET/HEAD, bounded file/credential reads, recon/nmap, the existing
  discovery/curl ``--resolve`` GETs) runs autonomously, exactly as today.
- SEND-SIDE (any non-GET/HEAD method, any request body, any custom Authorization
  header/auth flag, or any tool that is not a recognized bounded read) is BLOCKED
  and requires an explicit, per-action human approval token before it may reach
  the executor.

This module adds NO request-building/offensive capability — it only GATES
actions. Classification defaults to SEND-SIDE when ambiguous. When no approval
provider is available, or the environment is non-interactive/dry-run, or ANY
error occurs in the gate, the decision is DENY (never default-allow). The
downstream ``safety.py`` and ``PolicyAdvisor`` guards are unchanged and still run
BEHIND the gate — approval lets an action REACH those guards, it never bypasses
them.
"""
from __future__ import annotations

import enum
import json
import logging
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from apex_host.security.redaction import REDACTED_PLACEHOLDER, redact_secret_patterns
from memfabric.ids import new_id, now

if TYPE_CHECKING:
    from memfabric.types import TaskSpec

logger = logging.getLogger(__name__)


class ActionClass(str, enum.Enum):
    """Read-side (autonomous) vs send-side (approval-required) classification."""

    READ_SIDE = "read_side"
    SEND_SIDE = "send_side"


# Structured bounded-read executors (routed to executors; they never construct an
# attack request — they read a bounded response). All read-side.
_BOUNDED_READ_EXECUTORS: frozenset[str] = frozenset({
    "browser", "telnet_access", "ssh_access", "ftp_access",
    "priv_esc_analyze", "priv_esc_enum", "user_flag_verify",
})
# Recon/discovery command tools (GET-based / read-only inspection). Read-side.
_RECON_READ_TOOLS: frozenset[str] = frozenset({
    "nmap", "nc", "netcat", "ping", "telnet", "searchsploit", "ffuf", "gobuster",
})
# curl flags that carry a REQUEST BODY → send-side.
_CURL_BODY_FLAGS: frozenset[str] = frozenset({
    "-d", "--data", "--data-ascii", "--data-binary", "--data-raw",
    "--data-urlencode", "-F", "--form", "-T", "--upload-file", "--json",
})
# curl AUTH flags (custom/forged credentials) → send-side.
_CURL_AUTH_FLAGS: frozenset[str] = frozenset({
    "-u", "--user", "--oauth2-bearer", "--aws-sigv4", "--negotiate",
    "--ntlm", "--digest", "--anyauth",
})
_READ_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})


def _curl_method(args: list[str]) -> str:
    """The HTTP method a curl argv would use — curl defaults to GET."""
    for i, a in enumerate(args):
        if a in ("-X", "--request"):
            return (args[i + 1] if i + 1 < len(args) else "").upper()
        if a.startswith("-X") and len(a) > 2:  # -XPOST form
            return a[2:].upper()
    return "GET"


def classify_action(task: "TaskSpec") -> tuple[ActionClass, str]:
    """Classify *task* READ_SIDE vs SEND_SIDE on its SHAPE. Deterministic;
    defaults to SEND_SIDE when ambiguous. Returns ``(class, reason)``."""
    tool = str(task.params.get("tool", ""))
    args = [str(a) for a in task.params.get("args", [])]
    if tool in _BOUNDED_READ_EXECUTORS:
        return ActionClass.READ_SIDE, f"bounded-read executor {tool!r}"
    if tool in _RECON_READ_TOOLS:
        return ActionClass.READ_SIDE, f"recon/discovery tool {tool!r}"
    if tool == "curl":
        method = _curl_method(args)
        if method not in _READ_METHODS:
            return ActionClass.SEND_SIDE, f"HTTP method {method}"
        for i, a in enumerate(args):
            base = a.split("=", 1)[0]
            if a in _CURL_BODY_FLAGS or base in _CURL_BODY_FLAGS:
                return ActionClass.SEND_SIDE, f"request body ({base})"
            if a in _CURL_AUTH_FLAGS or base in _CURL_AUTH_FLAGS:
                return ActionClass.SEND_SIDE, f"auth flag ({base})"
            if a in ("-H", "--header"):
                val = (args[i + 1] if i + 1 < len(args) else "").lower().lstrip()
                if val.startswith(("authorization:", "proxy-authorization:")):
                    return ActionClass.SEND_SIDE, "custom Authorization header"
        return ActionClass.READ_SIDE, "curl GET/HEAD, no body, no auth"
    # Unknown / unrecognized tool → fail-closed send-side.
    return ActionClass.SEND_SIDE, f"unrecognized tool {tool!r} — default send-side"


def _render_curl(args: list[str]) -> tuple[str, str, list[str], str]:
    """Extract (method, url, headers, body) from a curl argv for DISPLAY only —
    it reads the args that already exist; it never builds a request."""
    method = _curl_method(args)
    url = ""
    headers: list[str] = []
    body = ""
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-H", "--header") and i + 1 < len(args):
            headers.append(args[i + 1])
            i += 2
            continue
        if a in _CURL_BODY_FLAGS and i + 1 < len(args):
            body = args[i + 1]
            i += 2
            continue
        if a.startswith(("http://", "https://")):
            url = a
        i += 1
    return method, url, headers, body


def bind_approval_token(fingerprint: str) -> str:
    """The per-action approval token — bound to the action's fingerprint so an
    approval can never be a blanket approve-all (§28.30)."""
    return f"approved:{fingerprint}"


@dataclass(slots=True)
class ApprovalRequest:
    """A send-side action rendered in full for an operator decision."""

    action_id: str
    fingerprint: str
    tool: str
    method: str
    url: str
    headers: list[str]
    body: str
    args: list[str]
    target: str
    phase: str
    intent: str
    graph_context: str
    reason: str  # why it was classified send-side

    def render(self) -> str:
        lines = [
            "=== SEND-SIDE ACTION — APPROVAL REQUIRED (§28.30) ===",
            f"why gated : {self.reason}",
            f"tool      : {self.tool}",
            f"method    : {self.method}",
            f"url       : {self.url or self.target}",
        ]
        for h in self.headers:
            lines.append(f"header    : {redact_secret_patterns(h)}")
        if self.body:
            lines.append(f"body      : {redact_secret_patterns(self.body)}")
        lines.append(f"intent    : {self.intent}")
        lines.append(f"context   : {self.graph_context}")
        return "\n".join(lines)


@dataclass(slots=True)
class ApprovalDecision:
    """The operator's decision for ONE send-side action."""

    approved: bool
    reason: str
    timestamp: str
    token: str = ""  # bound to the action fingerprint when approved


@runtime_checkable
class ApprovalProvider(Protocol):
    """The swappable operator interface. A terminal y/N prompt today; a richer
    UI later. Must NEVER auto-approve in a non-interactive context."""

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision: ...


class AutoDenyApprovalProvider:
    """The fail-closed default: denies every send-side action. Used when no
    operator interface is wired (a send-side action still cannot execute)."""

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(False, "no approval provider (fail-closed auto-deny)", now())


class TerminalApprovalProvider:
    """Renders the action and blocks for a terminal ``y/N`` decision. DENIES
    (fail-closed) in dry-run or any non-interactive context (no TTY)."""

    def __init__(
        self,
        *,
        dry_run: bool = True,
        stream: Any | None = None,
        input_fn: Any | None = None,
        interactive: bool | None = None,
    ) -> None:
        self._dry_run = dry_run
        self._out = stream if stream is not None else sys.stderr
        self._input = input_fn if input_fn is not None else input
        self._interactive = interactive

    def _is_interactive(self) -> bool:
        if self._interactive is not None:
            return self._interactive
        try:
            return sys.stdin.isatty()
        except (ValueError, OSError):
            return False

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        ts = now()
        if self._dry_run or not self._is_interactive():
            return ApprovalDecision(
                False, "non-interactive/dry-run — fail-closed deny", ts)
        try:
            self._out.write("\n" + request.render() + "\n")
            self._out.flush()
            ans = self._input("Approve THIS send-side action? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt, OSError):
            return ApprovalDecision(False, "no operator input — deny", ts)
        if ans == "y":
            return ApprovalDecision(
                True, "operator approved", ts, token=bind_approval_token(request.fingerprint))
        return ApprovalDecision(False, "operator denied", ts)


class AutoApproveProvider:
    """§28.30 amended — operator-configured auto-approval for the opt-in
    auto-invite-flow (§28.35).

    Auto-approves ONLY: (1) the ``invite_flow`` orchestrator task itself (the
    operator explicitly enabled ``--auto-invite-flow``), and (2) any send-side
    action whose ``METHOD url`` matches an operator ``--auto-approve-send-patterns``
    entry. EVERYTHING ELSE delegates to the wrapped fail-closed provider, so a
    send-side action the operator did NOT list still requires normal approval /
    is denied. This never relaxes ``safety.py`` or ``PolicyAdvisor`` scope — those
    run behind the gate regardless. Auto-approval is a deliberate operator
    override, recorded with ``auto_approved=True`` in the audit log."""

    def __init__(self, patterns: list[str], fallback: ApprovalProvider) -> None:
        self._patterns = [p for p in (patterns or []) if p.strip()]
        self._fallback = fallback

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        from apex_host.invite_flow import action_matches_auto_approve

        matched = request.tool == "invite_flow"
        if not matched and self._patterns:
            matched = action_matches_auto_approve(
                request.method, request.url or request.target, self._patterns)
        if matched:
            return ApprovalDecision(
                True, "auto_approved: operator-configured (§28.35)", now(),
                token=bind_approval_token(request.fingerprint))
        return self._fallback.request_approval(request)


class ApprovalGate:
    """Classifies each action and, for send-side actions, obtains an explicit
    per-action approval before it may proceed. Fail-closed on ANY error. Appends
    an immutable audit record (durable log file + the returned record for the
    episodic event store)."""

    def __init__(
        self,
        provider: ApprovalProvider | None = None,
        *,
        audit_log_path: str | None = None,
        passwords: list[str] | None = None,
    ) -> None:
        self._provider: ApprovalProvider = provider or AutoDenyApprovalProvider()
        self._audit_log_path = audit_log_path
        self._passwords = [p for p in (passwords or []) if len(p) >= 4]

    def classify(self, task: "TaskSpec") -> tuple[ActionClass, str]:
        try:
            return classify_action(task)
        except Exception as exc:  # fail-closed on any classifier error
            logger.warning("approval classifier error → send-side: %s", exc)
            return ActionClass.SEND_SIDE, f"classifier error ({type(exc).__name__}) → send-side"

    def review(
        self,
        task: "TaskSpec",
        *,
        fingerprint: str,
        phase: str,
        intent: str = "",
        graph_context: str = "",
    ) -> tuple[ActionClass, ApprovalDecision | None, dict[str, Any] | None]:
        """Returns ``(action_class, decision, audit_record)``. ``decision`` and
        ``audit_record`` are ``None`` for read-side actions (no gate needed)."""
        action_class, reason = self.classify(task)
        if action_class is ActionClass.READ_SIDE:
            return action_class, None, None

        request = self._build_request(task, fingerprint, phase, intent, graph_context, reason)
        try:
            decision = self._provider.request_approval(request)
        except Exception as exc:  # fail-closed on any provider error
            logger.warning("approval provider error → deny: %s", exc)
            decision = ApprovalDecision(False, f"provider error ({type(exc).__name__}) → deny", now())
        # An approval MUST carry the token bound to THIS action's fingerprint —
        # a blanket/foreign token is rejected (never approve-all).
        if decision.approved and decision.token != bind_approval_token(fingerprint):
            decision = ApprovalDecision(
                False, "approval token not bound to this action → deny", now())
        record = self._audit(request, decision)
        return action_class, decision, record

    def _build_request(
        self, task: "TaskSpec", fingerprint: str, phase: str,
        intent: str, graph_context: str, reason: str,
    ) -> ApprovalRequest:
        tool = str(task.params.get("tool", ""))
        args = [str(a) for a in task.params.get("args", [])]
        target = str(task.params.get("target", ""))
        method: str = "N/A"
        url: str = ""
        headers: list[str] = []
        body: str = ""
        if tool == "curl":
            method, url, headers, body = _render_curl(args)
        stated = intent or str(task.params.get("intent", "") or task.params.get("rationale", "")
                               or getattr(task, "goal_id", ""))
        return ApprovalRequest(
            action_id=new_id(), fingerprint=fingerprint, tool=tool, method=method,
            url=url, headers=headers, body=body, args=args, target=target, phase=phase,
            intent=stated, graph_context=graph_context, reason=reason,
        )

    def _redact(self, text: str) -> str:
        out = redact_secret_patterns(text or "")
        for pw in self._passwords:
            out = out.replace(pw, REDACTED_PLACEHOLDER)
        return out

    def _audit(self, request: ApprovalRequest, decision: ApprovalDecision) -> dict[str, Any]:
        record: dict[str, Any] = {
            "kind": "approval_gate_decision",
            "action_id": request.action_id,
            "fingerprint": request.fingerprint,
            "classification": ActionClass.SEND_SIDE.value,
            "class_reason": request.reason,
            "tool": request.tool,
            "method": request.method,
            "url": request.url or request.target,
            "target": request.target,
            "phase": request.phase,
            "headers": [self._redact(h) for h in request.headers],
            "body": self._redact(request.body),
            "intent": (request.intent or "")[:500],
            "graph_context": (request.graph_context or "")[:500],
            "approved": decision.approved,
            # §28.35 — operator-configured auto-approval is recorded distinctly.
            "auto_approved": decision.reason.startswith("auto_approved"),
            "decision_reason": decision.reason,
            "timestamp": decision.timestamp,
        }
        if self._audit_log_path:
            try:
                with open(self._audit_log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, sort_keys=True) + "\n")
            except OSError as exc:  # a failed durable write must not crash the run
                logger.warning("approval audit-log write failed: %s", exc)
        return record


def build_default_gate(config: Any) -> ApprovalGate:
    """Construct the production gate from an ``ApexConfig``: a fail-closed
    terminal provider (deny in dry-run/non-interactive) + the configured durable
    audit log. Send-side actions in the current pipeline (e.g. a GraphQL
    introspection POST) are therefore denied unless an operator approves them at
    a real terminal."""
    provider: ApprovalProvider = TerminalApprovalProvider(
        dry_run=bool(getattr(config, "dry_run", True)))
    # §28.30 amended / §28.35 — only when the operator explicitly opted in.
    if getattr(config, "auto_invite_flow", False):
        provider = AutoApproveProvider(
            list(getattr(config, "auto_approve_send_patterns", []) or []), provider)
    return ApprovalGate(
        provider,
        audit_log_path=getattr(config, "approval_audit_log_path", None),
        passwords=list(getattr(config, "password_candidates", []) or []),
    )
