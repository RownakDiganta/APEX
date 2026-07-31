# nmap_command.py
# The single authoritative Nmap command normalizer: selects an unprivileged TCP-connect (-sT) scan when the execution backend lacks raw sockets, enforces exactly one scan mode, drops LLM-injected dangerous flags/extra targets, never silently converts UDP to TCP, plans a deterministic one-time raw-socket repair, and produces the order-independent canonical fingerprint token list for semantic duplicate suppression.
"""Nmap command construction/normalization for the execution chokepoint.

Every nmap invocation — whether its args came from the deterministic
``ReconPlanner``, from an LLM planner, or from a repair — passes through
``normalize_nmap_command`` before it is executed (wired in
``apex_host.execution.dispatcher._run_command``). This is the ONE place a
scan mode is chosen, so the demonstrated live failure

    Couldn't open a raw socket. Error: (1) Operation not permitted

cannot recur: on a backend without raw-socket privilege (the restricted Kali
tool service runs non-root with zero added Linux capabilities —
``docs/kali-container.md`` §5/§14), the normalizer forces an unprivileged
``-sT`` TCP-connect scan and never emits ``-sS`` (nor relies on nmap's
privileged SYN default).

Design guarantees
-----------------
- **Backend capability is a three-state input** (``RAW_SOCKET`` /
  ``UNPRIVILEGED`` / ``UNKNOWN``). ``UNKNOWN`` defaults **safely** to the
  unprivileged ``-sT`` behavior. Only an explicit ``RAW_SOCKET`` capability
  permits the existing privileged strategy.
- **Exactly one scan mode** is emitted. On an unprivileged/unknown backend
  that is always a single ``-sT``.
- **The LLM cannot inject arbitrary nmap arguments.** Only a small, fixed
  allowlist of safe flags survives (``-sV``, ``-Pn``, ``-n``, ``--open``,
  ``-v``/``-vv``, ``-6``, ``-T0``..``-T5``, and the bounded value flags
  ``-p <ports>`` / ``--top-ports <n>``). Scripts (``--script``), output
  files (``-oN``/``-oX``/``-oG``/``-oA``/``-oS``), input lists (``-iL``/
  ``-iR``), and any extra positional target are dropped. Shell operators are
  already blocked upstream by ``apex_host.tools.safety``. The single
  positional is always exactly the authorized target.
- **UDP is never silently converted to TCP.** A ``-sU`` request on a
  non-raw-socket backend returns ``unsupported=True`` with a clear reason
  rather than a rewritten TCP scan.

This module is pure (no I/O, no config, no subprocess) and fully unit-tested.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Three-state backend capability (requirement: distinguish raw-capable /
# unprivileged / unknown). UNKNOWN is treated identically to UNPRIVILEGED for
# scan selection — the safe default — but is reported distinctly.
RAW_SOCKET = "raw_socket"
UNPRIVILEGED = "unprivileged"
UNKNOWN = "unknown"
_CAPABILITIES = frozenset({RAW_SOCKET, UNPRIVILEGED, UNKNOWN})

# Reported transport of the normalized command.
TRANSPORT_TCP_CONNECT = "tcp_connect"
TRANSPORT_TCP_SYN = "tcp_syn"
TRANSPORT_UDP = "udp"
TRANSPORT_PING = "ping"

_TCP_CONNECT_FLAG = "-sT"
_TCP_SYN_FLAG = "-sS"
_UDP_FLAG = "-sU"
_PING_FLAG = "-sn"

# Every nmap scan-mode selector token, mapped to a coarse intent. Anything
# not listed here is not a scan-mode token.
_SCAN_MODE_INTENT: dict[str, str] = {
    "-sT": "tcp_connect",
    "-sS": "tcp_syn",
    "-sU": "udp",
    "-sn": "ping",
    # Other raw-socket TCP/IP scan types — collapsed to the generic "tcp"
    # intent so the LLM can never pick an arbitrary exotic raw scan; they are
    # replaced by -sT (unprivileged) or the privileged default (raw-capable).
    "-sA": "tcp", "-sW": "tcp", "-sM": "tcp", "-sN": "tcp", "-sF": "tcp",
    "-sX": "tcp", "-sY": "tcp", "-sZ": "tcp", "-sO": "tcp", "-sI": "tcp",
    "-sL": "tcp",
}

# Safe boolean flags preserved verbatim.
_SAFE_BOOL_FLAGS: frozenset[str] = frozenset({
    "-sV", "-Pn", "-n", "--open", "-v", "-vv", "-6",
})
# Safe value flags: kept only with a validated value token.
_PORTS_VALUE_RE = re.compile(r"^[TU]?:?[0-9][0-9,\-]*$")
_TOP_PORTS_VALUE_RE = re.compile(r"^[0-9]{1,5}$")
_TIMING_RE = re.compile(r"^-T[0-5]$")


@dataclass(frozen=True, slots=True)
class NmapNormalization:
    """Result of normalizing an nmap command.

    ``args`` is the sanitized command (empty when ``unsupported``).
    ``transport`` is the selected scan transport (see the ``TRANSPORT_*``
    constants). ``changed`` is whether normalization altered the input.
    ``dropped`` lists the tokens removed (flag names only — never a secret;
    values of dropped value-flags are not retained)."""

    args: list[str]
    transport: str
    capability: str
    unsupported: bool = False
    reason: str = ""
    changed: bool = False
    dropped: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class NmapRepairPlan:
    """A deterministic, bounded repair decision for a raw-socket failure.

    ``terminal=True`` means no repair is possible (the command already used
    ``-sT``, or it was a UDP scan that cannot be converted) — the task must
    fail terminally rather than loop. Otherwise ``repaired_args`` is the
    equivalent unprivileged ``-sT`` command to run exactly once."""

    terminal: bool
    repaired_args: list[str] | None
    transport: str
    reason: str


def _classify_scan_intent(args: list[str]) -> str | None:
    """Return the coarse scan intent requested by *args* (``tcp_connect`` /
    ``tcp_syn`` / ``udp`` / ``ping`` / ``tcp``), or ``None`` if no scan-mode
    flag is present. The last scan-mode flag wins (matches nmap)."""
    intent: str | None = None
    for token in args:
        mapped = _SCAN_MODE_INTENT.get(token)
        if mapped is not None:
            intent = mapped
    return intent


def is_tcp_connect_command(args: list[str]) -> bool:
    """True iff *args* already requests an unprivileged TCP-connect scan
    (``-sT`` present and no raw-socket scan mode)."""
    return _classify_scan_intent(args) == "tcp_connect"


def _keep_safe_flags(args: list[str], target: str) -> tuple[list[str], list[str]]:
    """Return (kept_flags, dropped) — the allowlisted flags (with validated
    values) preserved from *args*, minus scan-mode flags and the target
    positional (both re-added by the caller)."""
    kept: list[str] = []
    dropped: list[str] = []
    i = 0
    n = len(args)
    while i < n:
        token = args[i]
        if token in _SCAN_MODE_INTENT:
            i += 1  # scan mode decided separately; never carried through verbatim
            continue
        if token in _SAFE_BOOL_FLAGS or _TIMING_RE.match(token):
            kept.append(token)
            i += 1
            continue
        if token == "-p":
            if i + 1 < n and _PORTS_VALUE_RE.match(args[i + 1]):
                kept.extend([token, args[i + 1]])
                i += 2
            else:
                dropped.append(token)
                i += 1
            continue
        if token == "--top-ports":
            if i + 1 < n and _TOP_PORTS_VALUE_RE.match(args[i + 1]):
                kept.extend([token, args[i + 1]])
                i += 2
            else:
                dropped.append(token)
                i += 1
            continue
        if token == target:
            i += 1  # the authorized target is re-appended once at the end
            continue
        # Unknown flag, injected script/output flag, or an extra positional
        # target — dropped. Value flags like --script=... / -oN <file> lose
        # their value here too (we never carry an unrecognized value forward).
        dropped.append(token)
        i += 1
    return kept, dropped


def normalize_nmap_command(
    args: list[str], target: str, *, capability: str,
) -> NmapNormalization:
    """Normalize an nmap command for *capability*.

    See the module docstring for the full rule set. Never raises.
    """
    original = [str(a) for a in args]
    cap = capability if capability in _CAPABILITIES else UNKNOWN
    privileged_allowed = cap == RAW_SOCKET

    intent = _classify_scan_intent(original)
    kept, dropped = _keep_safe_flags(original, target)

    # UDP must never be silently converted to TCP.
    if intent == "udp":
        if privileged_allowed:
            normalized = [_UDP_FLAG, *kept, target]
            return NmapNormalization(
                args=normalized, transport=TRANSPORT_UDP, capability=cap,
                changed=normalized != original, dropped=dropped,
            )
        return NmapNormalization(
            args=[], transport=TRANSPORT_UDP, capability=cap, unsupported=True,
            reason=(
                "UDP scan (-sU) requires raw-socket privilege the backend lacks; "
                "not converting to a TCP scan"
            ),
            changed=True, dropped=dropped,
        )

    if intent == "ping":
        normalized = [_PING_FLAG, *kept, target]
        return NmapNormalization(
            args=normalized, transport=TRANSPORT_PING, capability=cap,
            changed=normalized != original, dropped=dropped,
        )

    # TCP / service scan intent (tcp_connect, tcp_syn, generic tcp, or none).
    if privileged_allowed and intent == "tcp_syn":
        scan_flag, transport = [_TCP_SYN_FLAG], TRANSPORT_TCP_SYN
    elif privileged_allowed and intent is None:
        # Raw-capable, no explicit scan → nmap's privileged SYN default
        # (the existing strategy). No scan flag emitted.
        scan_flag, transport = [], TRANSPORT_TCP_SYN
    else:
        # Everything else — unprivileged/unknown (any intent), an explicit
        # -sT, or a generic raw TCP scan on a raw-capable backend — becomes a
        # single unprivileged TCP-connect scan. The LLM can never select an
        # arbitrary exotic raw scan type: only -sS (SYN) and the SYN default
        # survive on a raw-capable backend; everything else is -sT.
        scan_flag, transport = [_TCP_CONNECT_FLAG], TRANSPORT_TCP_CONNECT

    normalized = [*scan_flag, *kept, target]
    return NmapNormalization(
        args=normalized, transport=transport, capability=cap,
        changed=normalized != original, dropped=dropped,
    )


#: Canonical representative flag for each coarse scan intent — used ONLY for
#: fingerprint identity, never for execution. ``tcp`` (a generic raw TCP scan)
#: shares ``-sT``'s representative because both collapse to an unprivileged
#: ``-sT`` at execution on a non-raw-socket backend.
_INTENT_FINGERPRINT_TOKEN: dict[str, str] = {
    "tcp_connect": "-sT",
    "tcp_syn": "-sS",
    "udp": "-sU",
    "ping": "-sn",
    "tcp": "-sT",
}


def canonical_fingerprint_args(args: list[str], target: str) -> list[str]:
    """Return an ORDER-INDEPENDENT canonical token list for fingerprinting an
    nmap command (a semantic action identity, never an executable command).

    Two nmap invocations that differ ONLY in the order of independent flags —
    ``["-sV", "-T4"]`` vs ``["-T4", "-sV"]`` — are the SAME action and must
    share one fingerprint. This canonicalizer makes flag order irrelevant by
    sorting (and de-duplicating) the independent boolean/timing flags, while
    keeping flag/value pairs (``-p <ports>`` / ``--top-ports <n>``) BOUND and
    sorting them by ``(flag, value)`` so a semantically-OPPOSITE command
    (``-p 80`` vs ``-p 443``) never collides — the exact distinctness guarantee
    the previous order-preserving fingerprint protected, now achieved WITHOUT
    treating harmless flag reordering as a distinct action.

    The scan-mode intent is preserved as a single canonical representative
    token, so an explicit ``-sT`` connect scan and a no-scan default remain
    DISTINCT actions. Unknown/injected flags (``--script``, ``-oN``, an extra
    positional) and the target positional are dropped — they are ALSO dropped
    at execution by :func:`normalize_nmap_command`, so two commands differing
    only in a dropped token execute identically and correctly share one
    identity. Pure; never raises.
    """
    original = [str(a).strip() for a in args]
    intent = _classify_scan_intent(original)
    intent_token = _INTENT_FINGERPRINT_TOKEN.get(intent or "", "")

    kept, _dropped = _keep_safe_flags(original, target)
    bools: list[str] = []
    pairs: list[tuple[str, str]] = []
    i = 0
    n = len(kept)
    while i < n:
        tok = kept[i]
        if tok in ("-p", "--top-ports") and i + 1 < n:
            pairs.append((tok, kept[i + 1]))
            i += 2
        else:
            bools.append(tok)
            i += 1

    tokens: list[str] = []
    if intent_token:
        tokens.append(intent_token)
    tokens.extend(sorted(set(bools)))
    for flag, value in sorted(pairs):
        tokens.append(flag)
        tokens.append(value)
    return tokens


def plan_raw_socket_repair(args: list[str], target: str) -> NmapRepairPlan:
    """Deterministic, bounded repair for a classified
    ``raw_socket_permission_denied`` nmap failure.

    - If the failed command already used ``-sT`` (TCP connect), the failure
      is **terminal** — a connect scan does not need raw sockets, so retrying
      the same transport would loop.
    - If it was a UDP scan, it is **terminal** — UDP cannot be converted to
      TCP without changing the operator's intent.
    - Otherwise, return the equivalent unprivileged ``-sT`` command to run
      exactly once.
    """
    original = [str(a) for a in args]
    intent = _classify_scan_intent(original)

    if intent == "tcp_connect":
        return NmapRepairPlan(
            terminal=True, repaired_args=None, transport=TRANSPORT_TCP_CONNECT,
            reason="command already used -sT (TCP connect); raw-socket failure is terminal",
        )
    if intent == "udp":
        return NmapRepairPlan(
            terminal=True, repaired_args=None, transport=TRANSPORT_UDP,
            reason="UDP scan cannot be repaired to a TCP scan without changing intent",
        )

    rewritten = normalize_nmap_command(original, target, capability=UNPRIVILEGED)
    return NmapRepairPlan(
        terminal=False, repaired_args=rewritten.args, transport=rewritten.transport,
        reason="rewrote to an unprivileged -sT TCP-connect scan",
    )
