# rules.py
# Deterministic, stateless rule functions for scope and policy enforcement.
"""Deterministic policy rule functions.

Each public rule function has the signature:

    check_*(task, policy, config) -> PolicyDecision | None

Return ``None`` to indicate the rule passes (no violation).  Return a
``PolicyDecision`` to indicate a binding outcome (``blocked`` or
``needs_human_review``).  Returning ``approved`` from a rule is reserved for
the explicit safe-recon / bounded-credential-validation acknowledgement
rules only.

Rules are pure functions with no side-effects.  They never call tools, never
read from MemoryAPI, and never touch the filesystem.

**Rule evaluation order (enforced in advisor.py):**

1. ``check_no_destructive_command``   — hard block, runs first
2. ``check_target_in_scope``          — block off-scope targets
3. ``check_no_attacking_infrastructure`` — block tasks targeting non-target IPs
4. ``check_no_password_list``         — block wordlist/credential bruteforce
5. ``check_no_sensitive_data``        — block sensitive file reads
6. ``check_require_review``           — flag tasks needing human review
7. ``check_safe_recon_allowed``       — explicit approval for nmap/nc/curl on target
8. ``check_bounded_credential_validation`` — explicit approval (or a defense-
   in-depth block) for telnet_access/ssh_access/ftp_access tasks (Phase 12B)
9. ``check_bounded_priv_esc_enumeration`` — explicit approval for
   searchsploit/priv_esc_analyze planning tasks (Phase 13)
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from apex_host.planners.priv_esc_opportunities import ENUM_COMMANDS as _ENUM_COMMANDS
from apex_host.policy.models import PolicyDecision, PolicyStatus
from apex_host.verification.user_flag import is_bounded_candidate_path

if TYPE_CHECKING:
    from collections.abc import Callable

    from apex_host.config import ApexConfig
    from apex_host.policy.models import ScopePolicy
    from memfabric.types import TaskSpec

    # Precise type for every rule function in this module.
    _RuleFn = Callable[[TaskSpec, ScopePolicy, ApexConfig], PolicyDecision | None]

# ---------------------------------------------------------------------------
# Internal constants — NOT exported.  Host apps that need to add patterns
# should use config.require_policy_approval_for or subclass the advisor.
# ---------------------------------------------------------------------------

# IPv4 address pattern — used to detect when a tool arg contains an IP.
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Args that indicate wordlist / password-list usage.
_PASSWORD_LIST_FLAGS: frozenset[str] = frozenset({
    "-w", "--wordlist",
    "-P", "--passwords", "--passfile",
    "-C", "--combo-file",
    "--user-combo",
})

# Path fragments indicating sensitive system data.
_SENSITIVE_PATHS: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/passwd",
    "/.ssh/",
    "/id_rsa",
    "/id_ed25519",
    "/id_ecdsa",
    "/.aws/credentials",
    "/.aws/config",
    "/secrets/",
    "/private_key",
    "/.gnupg/",
    "/.netrc",
)

# Tools considered safe for passive recon against the assigned target.
_SAFE_RECON_TOOLS: frozenset[str] = frozenset({
    "nmap", "nc", "netcat", "curl", "python3",
})

# Phase 12B — bounded, one-attempt credential-validation task tools. Each is
# routed by TaskDispatcher to its own dedicated executor (TelnetExecutor /
# SSHExecutor / FTPExecutor) — never through the generic run_command_fn path.
_CREDENTIAL_VALIDATION_TOOLS: frozenset[str] = frozenset({
    "telnet_access", "ssh_access", "ftp_access",
})

# The only harmless commands/operations a credential-validation task may
# request. Mirrors the allowlists inside SSHExecutor/FTPExecutor themselves
# (apex_host/agents/ssh_executor.py::_ALLOWED_VALIDATION_COMMANDS,
# ftp_executor.py::_ALLOWED_VALIDATION_OPERATIONS) — this is a second,
# independent check at the policy boundary, not a replacement for the
# executor's own allowlist.
_CREDENTIAL_VALIDATION_COMMANDS: frozenset[str] = frozenset({"id", "whoami", "PWD", "NOOP"})

# Phase 13 — privilege-escalation planning tasks. ``priv_esc_analyze`` is a
# zero-network, zero-subprocess task that only echoes an already-computed
# analytical signal (see apex_host/agents/priv_esc_analysis_executor.py);
# ``searchsploit`` is an existing, unchanged local exploit-db lookup with no
# target interaction at all. ``priv_esc_enum`` (Phase 13B) is a bounded,
# read-only enumeration command over an already-validated SSH session (see
# apex_host/agents/priv_esc_enum_executor.py) — checked further below
# against a fixed command_key allowlist. None of the three ever executes an
# exploit.
_PRIV_ESC_PLANNING_TOOLS: frozenset[str] = frozenset({
    "priv_esc_analyze", "searchsploit", "priv_esc_enum",
})

# Phase 13B — the only enumeration command_keys a priv_esc_enum task may
# request. Mirrors the credential-validation pattern above: this is a
# second, independent check at the policy boundary on top of
# PrivEscEnumExecutor's own identical allowlist (both are sourced from the
# same table in apex_host/planners/priv_esc_opportunities.py::ENUM_COMMANDS).
_PRIV_ESC_ENUM_COMMAND_KEYS: frozenset[str] = frozenset(_ENUM_COMMANDS)

# Phase 18 — bounded user-flag-objective verification tasks. Routed by
# TaskDispatcher to UserFlagExecutor exactly like the other specialised
# executors above — never through the generic run_command_fn path.
_USER_FLAG_VERIFICATION_TOOLS: frozenset[str] = frozenset({"user_flag_verify"})


# ---------------------------------------------------------------------------
# Public rule functions
# ---------------------------------------------------------------------------

def check_no_destructive_command(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Block any tool that appears in the policy's blocked-tools set."""
    tool = str(task.params.get("tool", "")).strip().lower()
    if tool in policy.blocked_tools:
        return PolicyDecision(
            status=PolicyStatus.blocked,
            rule_name="no_destructive_command",
            reason=f"tool {tool!r} is in the policy blocked-tools list",
            task_tool=tool,
            task_target=str(task.params.get("target", "")),
        )
    return None


def check_target_in_scope(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Block tasks whose explicit target field is not in the allowed targets."""
    raw_target = str(task.params.get("target", "")).strip()
    if not raw_target:
        return None  # no explicit target field; checked by infrastructure rule

    if raw_target not in policy.allowed_targets:
        return PolicyDecision(
            status=PolicyStatus.blocked,
            rule_name="target_in_scope",
            reason=(
                f"target {raw_target!r} is not in the allowed scope "
                f"{sorted(policy.allowed_targets)}"
            ),
            task_tool=str(task.params.get("tool", "")),
            task_target=raw_target,
        )
    return None


def check_no_attacking_infrastructure(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Block tasks whose args contain an IP address outside the allowed scope.

    This catches cases where the IP appears in args rather than (or in addition
    to) the explicit target field.  Addresses belonging to ``policy.allowed_targets``
    are permitted.  Non-IP strings are ignored.
    """
    args: list[str] = list(task.params.get("args", []))
    tool = str(task.params.get("tool", ""))

    for token in args:
        for match in _IPV4_RE.finditer(token):
            ip = match.group(1)
            if ip not in policy.allowed_targets:
                return PolicyDecision(
                    status=PolicyStatus.blocked,
                    rule_name="no_attacking_infrastructure",
                    reason=(
                        f"arg {token!r} contains IP {ip!r} which is outside "
                        f"the allowed scope {sorted(policy.allowed_targets)}"
                    ),
                    task_tool=tool,
                    task_target=ip,
                )
    return None


def check_no_password_list(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Block wordlist/password-list use when the policy does not allow it."""
    if policy.allow_password_lists:
        return None

    args: list[str] = list(task.params.get("args", []))
    tool = str(task.params.get("tool", ""))

    for token in args:
        if token in _PASSWORD_LIST_FLAGS:
            return PolicyDecision(
                status=PolicyStatus.blocked,
                rule_name="no_password_list",
                reason=(
                    f"arg {token!r} indicates password/wordlist use; "
                    "set config.allow_password_lists=True to permit this"
                ),
                task_tool=tool,
                task_target=str(task.params.get("target", "")),
            )
    return None


def check_no_sensitive_data(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Block access to known sensitive system file paths when not permitted."""
    if policy.allow_sensitive_data_access:
        return None

    args: list[str] = list(task.params.get("args", []))
    tool = str(task.params.get("tool", ""))

    for token in args:
        token_lower = token.lower()
        for sensitive in _SENSITIVE_PATHS:
            if sensitive.lower() in token_lower:
                return PolicyDecision(
                    status=PolicyStatus.blocked,
                    rule_name="no_sensitive_data",
                    reason=(
                        f"arg {token!r} references a sensitive path "
                        f"({sensitive!r}); set config.allow_sensitive_data_access=True "
                        "to permit this (requires explicit operator approval)"
                    ),
                    task_tool=tool,
                    task_target=str(task.params.get("target", "")),
                )
    return None


def check_require_review(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Flag tasks whose tool is in the require-human-review list."""
    tool = str(task.params.get("tool", "")).strip()
    if tool in policy.require_review_for:
        return PolicyDecision(
            status=PolicyStatus.needs_human_review,
            rule_name="require_review",
            reason=(
                f"tool {tool!r} is in config.require_policy_approval_for; "
                "a human operator must approve this task before execution"
            ),
            task_tool=tool,
            task_target=str(task.params.get("target", "")),
        )
    return None


def check_safe_recon_allowed(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Explicit approval for safe passive recon tools against the assigned target.

    This rule runs last.  It returns an ``approved`` decision only when the
    tool is in the safe-recon set AND the target is in scope.  For all other
    tasks, it returns None and the advisor falls through to the default
    ``approved`` outcome.

    The explicit approval is useful for callers who want to know *why* a task
    was approved (rule_name = "safe_recon_allowed"), not just that it wasn't
    blocked.
    """
    tool = str(task.params.get("tool", "")).strip().lower()
    raw_target = str(task.params.get("target", "")).strip()

    if tool in _SAFE_RECON_TOOLS and raw_target in policy.allowed_targets:
        return PolicyDecision(
            status=PolicyStatus.approved,
            rule_name="safe_recon_allowed",
            reason=f"tool {tool!r} is a safe recon tool against assigned target {raw_target!r}",
            task_tool=tool,
            task_target=raw_target,
        )
    return None


def check_bounded_credential_validation(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Explicit approval for bounded, one-attempt credential-validation tasks
    (Phase 12B: telnet_access / ssh_access / ftp_access).

    This rule runs after every blocking rule (destructive-command, scope,
    attacking-infrastructure, password-list, sensitive-data) and after
    ``check_require_review`` — those already enforce "limited to the
    configured authorized target" and "no wordlist/brute-force flags" for
    these tools exactly as they do for any other tool, since credential
    tasks carry the same ``target``/``args`` params. This rule adds one more,
    credential-validation-specific check on top: the requested validation
    ``command``/``operation`` (if the task specifies one) must be in the
    fixed harmless allowlist — never an arbitrary string. This is defense in
    depth on top of SSHExecutor's/FTPExecutor's own identical allowlists;
    a task that somehow requested something else is blocked here before it
    ever reaches an executor.

    Returns ``approved`` (not merely ``None``) for a passing credential task
    so the policy audit log records *why* it was approved — the same
    transparency ``check_safe_recon_allowed`` provides for recon tools.
    This rule never approves brute-force/spraying behavior: it does not
    change the fact that CredentialPlanner itself only ever emits exactly
    one task per protocol per turn (see
    ``apex_host/planners/credential_planner.py``) — this rule cannot make an
    unsafe planner safe, it only classifies tasks the planner already
    produced safely.
    """
    tool = str(task.params.get("tool", "")).strip().lower()
    if tool not in _CREDENTIAL_VALIDATION_TOOLS:
        return None

    raw_target = str(task.params.get("target", "")).strip()
    requested_command = str(
        task.params.get("command") or task.params.get("operation") or ""
    ).strip()

    if requested_command and requested_command not in _CREDENTIAL_VALIDATION_COMMANDS:
        return PolicyDecision(
            status=PolicyStatus.blocked,
            rule_name="bounded_credential_validation",
            reason=(
                f"credential-validation tool {tool!r} requested command/operation "
                f"{requested_command!r} which is outside the fixed harmless allowlist "
                f"{sorted(_CREDENTIAL_VALIDATION_COMMANDS)}"
            ),
            task_tool=tool,
            task_target=raw_target,
        )

    return PolicyDecision(
        status=PolicyStatus.approved,
        rule_name="bounded_credential_validation",
        reason=(
            f"tool {tool!r} is a bounded, one-attempt credential-validation task "
            f"against assigned target {raw_target!r}"
        ),
        task_tool=tool,
        task_target=raw_target,
    )


def check_bounded_priv_esc_enumeration(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Explicit approval for privilege-escalation *planning* tasks (Phase 13).

    Covers ``searchsploit`` (an existing, unchanged local exploit-db lookup
    — no target interaction at all), ``priv_esc_analyze`` (a zero-network,
    zero-subprocess task that only echoes an already-computed analytical
    signal — see ``apex_host/agents/priv_esc_analysis_executor.py``), and
    (Phase 13B) ``priv_esc_enum`` (a bounded, read-only enumeration command
    over an already-validated SSH session — see
    ``apex_host/agents/priv_esc_enum_executor.py``). None of the three ever
    executes an exploit or contacts the target beyond what earlier phases
    already established; this rule exists for audit-trail clarity (mirrors
    ``check_safe_recon_allowed``/``check_bounded_credential_validation``),
    not because any of them is otherwise unsafe — all three would also pass
    through the default-allow fallthrough with no rule at all.

    For ``priv_esc_enum`` specifically, the requested ``command_key`` (read
    from either the ``command_key`` param or the task's first ``args``
    token, mirroring how the planner encodes it) must be in the fixed
    read-only allowlist ``_PRIV_ESC_ENUM_COMMAND_KEYS`` — defense in depth
    on top of ``PrivEscEnumExecutor``'s own identical allowlist; a task that
    somehow requested an unrecognised key is blocked here before it ever
    reaches an executor or opens a connection.

    Returns ``None`` (no opinion) for any other tool so a mistaken future
    reuse of this rule for a real exploitation tool has no effect — approval
    is scoped exactly to the three known-safe tool names above.
    """
    tool = str(task.params.get("tool", "")).strip().lower()
    if tool not in _PRIV_ESC_PLANNING_TOOLS:
        return None

    raw_target = str(task.params.get("target", "")).strip()
    if raw_target not in policy.allowed_targets:
        return None  # fall through; check_target_in_scope already blocked this

    if tool == "priv_esc_enum":
        args = [str(a) for a in task.params.get("args", [])]
        command_key = str(task.params.get("command_key") or (args[0] if args else "")).strip()
        if command_key not in _PRIV_ESC_ENUM_COMMAND_KEYS:
            return PolicyDecision(
                status=PolicyStatus.blocked,
                rule_name="bounded_priv_esc_enumeration",
                reason=(
                    f"priv_esc_enum requested command_key {command_key!r} which is "
                    f"outside the fixed read-only allowlist {sorted(_PRIV_ESC_ENUM_COMMAND_KEYS)}"
                ),
                task_tool=tool,
                task_target=raw_target,
            )

    return PolicyDecision(
        status=PolicyStatus.approved,
        rule_name="bounded_priv_esc_enumeration",
        reason=(
            f"tool {tool!r} is a non-executing privilege-escalation planning "
            f"task against assigned target {raw_target!r}"
        ),
        task_tool=tool,
        task_target=raw_target,
    )


def check_bounded_user_flag_verification(
    task: "TaskSpec",
    policy: "ScopePolicy",
    config: "ApexConfig",
) -> PolicyDecision | None:
    """Explicit approval (or a defense-in-depth block) for bounded
    user-flag-objective verification tasks (Phase 18: ``user_flag_verify``).

    Mirrors ``check_bounded_priv_esc_enumeration`` exactly: this rule adds
    one verification-specific check on top of every already-applicable
    blocking rule above (scope, attacking-infrastructure, password-list,
    sensitive-data all already apply unmodified, since these tasks carry
    the same ``target``/``args`` params any other task does). The requested
    ``candidate_path`` must pass
    ``apex_host.verification.user_flag.is_bounded_candidate_path`` — the
    SAME function ``UserFlagExecutor`` itself checks before ever opening a
    connection (defense in depth, not a replacement for that check). This
    rule cannot make an unsafe planner safe: it only classifies tasks
    ``ObjectivePlanner`` already produced under its own one-bounded-
    candidate-per-turn invariant (see
    ``apex_host/planners/objective_planner.py``).

    Phase 20 — no changes were needed to support the direct-file-read
    capability. This rule was already fully transport-independent: it
    inspects only ``task.params["target"]``/``["candidate_path"]``, both of
    which are present in a ``user_flag_verify`` task regardless of whether
    ``ObjectivePlanner`` selected an SSH or a direct-file-read capability
    (neither ``capability_id``/``capability_type``/``principal`` nor any
    HTTP-specific field ever needs to reach this rule — the request SHAPE
    itself, unlike the candidate path, is never task-controlled at all; see
    ``apex_host/runtime_registry.py::DirectFileReadPrimitive``). A blocked
    task never reaches ``UserFlagExecutor``, and therefore never reaches the
    adapter, regardless of which transport it would have used.
    """
    tool = str(task.params.get("tool", "")).strip().lower()
    if tool not in _USER_FLAG_VERIFICATION_TOOLS:
        return None

    raw_target = str(task.params.get("target", "")).strip()
    if raw_target not in policy.allowed_targets:
        return None  # fall through; check_target_in_scope already blocked this

    candidate_path = str(task.params.get("candidate_path", "")).strip()
    allowed_filenames = frozenset(getattr(config, "user_flag_candidate_filenames", None) or [])

    if not is_bounded_candidate_path(candidate_path, allowed_filenames=allowed_filenames):
        return PolicyDecision(
            status=PolicyStatus.blocked,
            rule_name="bounded_user_flag_verification",
            reason=(
                f"user_flag_verify requested candidate_path {candidate_path!r} "
                "which fails bounded-path validation"
            ),
            task_tool=tool,
            task_target=raw_target,
        )

    return PolicyDecision(
        status=PolicyStatus.approved,
        rule_name="bounded_user_flag_verification",
        reason=(
            f"tool {tool!r} is a bounded, read-only user-flag verification task "
            f"against assigned target {raw_target!r}"
        ),
        task_tool=tool,
        task_target=raw_target,
    )


# ---------------------------------------------------------------------------
# Ordered rule registry used by PolicyAdvisor
# ---------------------------------------------------------------------------

# Evaluate in this order.  The first non-None result is the policy decision.
# Blocking rules come first so they cannot be bypassed by later rules.
ALL_RULES: tuple[_RuleFn, ...] = (
    check_no_destructive_command,
    check_target_in_scope,
    check_no_attacking_infrastructure,
    check_no_password_list,
    check_no_sensitive_data,
    check_require_review,
    check_safe_recon_allowed,
    check_bounded_credential_validation,
    check_bounded_priv_esc_enumeration,
    check_bounded_user_flag_verification,
)
