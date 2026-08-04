# nmap_command.py
# The single authoritative Nmap command normalizer: on a backend without raw-socket privilege it forces an unprivileged TCP-connect scan (-sT) AND injects --unprivileged and -Pn (so nmap running as uid 0 without CAP_NET_RAW never attempts raw-socket host discovery/OS probing and hard-fails with EPERM), enforces exactly one scan mode, drops LLM-injected dangerous flags/extra targets, truthfully refuses raw-only features (-sU/-O/--traceroute) rather than silently downgrading them, plans a deterministic one-time raw-socket repair, and produces the order-independent canonical fingerprint token list for semantic duplicate suppression.
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
  that is always a single ``-sT``, and the command additionally gets
  ``--unprivileged`` and ``-Pn`` injected. ``-sT`` alone is NOT sufficient:
  nmap running as ``uid 0`` in the restricted Kali tool-service container
  (no ``CAP_NET_RAW``) still assumes raw-socket privilege for its default
  host-discovery ping probes and fails with ``Couldn't open a raw socket.
  Error: (1) Operation not permitted`` even on a connect scan. ``-Pn`` skips
  host discovery entirely and ``--unprivileged`` tells nmap to take the pure
  connect-socket code path despite being root.
- **Raw-socket-only features are truthfully refused, never silently
  downgraded.** On a non-raw-socket backend a UDP scan (``-sU``), OS detection
  (``-O``), and ``--traceroute`` each return ``unsupported=True`` with a clear
  reason rather than a rewritten TCP scan that would misrepresent what ran.
  TCP-family raw scan types (``-sS``/``-sA``/``-sW``/``-sM``/…) are instead
  converted to ``-sT`` — they have a faithful unprivileged equivalent.
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
#: The two flags injected on an unprivileged/unknown backend so nmap running
#: as uid 0 without CAP_NET_RAW does not attempt raw-socket operations. Both
#: are the actual resolution for the demonstrated EPERM failure.
_UNPRIVILEGED_FLAG = "--unprivileged"
_PN_FLAG = "-Pn"
#: Raw-socket-only feature flags that have NO faithful unprivileged equivalent.
#: On a non-raw-socket backend these are refused (unsupported_capability),
#: never silently dropped so a plain TCP scan is presented as if it ran them.
_RAW_ONLY_FEATURE_FLAGS: tuple[str, ...] = ("-O", "--traceroute")

#: The fixed, small set of the most common service ports — the escalation
#: target when a broad ``--top-ports`` discovery scan times out with 0 open
#: ports. A ``-p <this> -sV`` scan is a handful of ports, so it completes fast
#: over VPN latency (the known-good ~14s scan) where the top-1000 does not.
#: A fixed, well-known port list, NOT a machine-specific value (§13.8).
_COMMON_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
)


def common_ports() -> str:
    """The fixed, well-known common-port list (§13.8 — never machine-specific).

    The single source of truth for both the incomplete-scan escalation
    (:func:`plan_incomplete_scan_escalation`) and the recon planner's targeted
    ``-p <common> -sV`` pass, so the two always agree on which ports the fast
    complete scan covers.
    """
    return _COMMON_PORTS

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

# Safe boolean flags preserved verbatim. ``--unprivileged`` is included so it
# (a) survives normalization when injected and (b) is reflected in the canonical
# fingerprint — a command carrying ``--unprivileged`` is a materially DIFFERENT
# action from one without it, which is what makes the deterministic raw-socket
# repair a distinct, non-dedup-suppressed action (§27.2).
_SAFE_BOOL_FLAGS: frozenset[str] = frozenset({
    "-sV", "-Pn", "-n", "--open", "-v", "-vv", "-6", "--unprivileged",
})
# Safe value flags: kept only with a validated value token.
_PORTS_VALUE_RE = re.compile(r"^[TU]?:?[0-9][0-9,\-]*$")
_TOP_PORTS_VALUE_RE = re.compile(r"^[0-9]{1,5}$")
_TIMING_RE = re.compile(r"^-T[0-5]$")
# Bounding value flags for the two-pass recon scans (§25.6). --max-retries
# takes a small integer; --host-timeout takes a bare number or an nmap
# duration (`90s`, `2m`, `500ms`, `1h`). Both are safe (bounded, no shell
# metacharacters) and are preserved so the fast first-pass discovery scan
# actually stays bounded end-to-end.
_MAX_RETRIES_VALUE_RE = re.compile(r"^[0-9]{1,2}$")
_HOST_TIMEOUT_VALUE_RE = re.compile(r"^[0-9]+(ms|s|m|h)?$")
#: Value flags handled as (flag, validated-value) pairs. Maps each flag to the
#: regex its value must match; a flag whose value is missing or malformed is
#: dropped (flag name only recorded in `dropped`).
_VALUE_FLAG_PATTERNS: dict[str, re.Pattern[str]] = {
    "-p": _PORTS_VALUE_RE,
    "--top-ports": _TOP_PORTS_VALUE_RE,
    "--max-retries": _MAX_RETRIES_VALUE_RE,
    "--host-timeout": _HOST_TIMEOUT_VALUE_RE,
}


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
        value_pattern = _VALUE_FLAG_PATTERNS.get(token)
        if value_pattern is not None:
            if i + 1 < n and value_pattern.match(args[i + 1]):
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

    # Raw-socket-only features (OS detection, traceroute) have no faithful
    # unprivileged equivalent — refuse them truthfully rather than silently
    # dropping them and running a plain TCP scan that lacks them. TCP-family
    # raw *scan types* are handled below (converted to -sT), not here.
    if not privileged_allowed:
        raw_feature = next((f for f in _RAW_ONLY_FEATURE_FLAGS if f in original), None)
        if raw_feature is not None:
            return NmapNormalization(
                args=[], transport=TRANSPORT_TCP_CONNECT, capability=cap,
                unsupported=True,
                reason=(
                    f"{raw_feature} requires raw-socket privilege the backend "
                    "lacks; not silently downgrading to a plain TCP scan"
                ),
                changed=True, dropped=dropped,
            )

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
        normalized = [_TCP_SYN_FLAG, *kept, target]
        return NmapNormalization(
            args=normalized, transport=TRANSPORT_TCP_SYN, capability=cap,
            changed=normalized != original, dropped=dropped,
        )
    if privileged_allowed and intent is None:
        # Raw-capable, no explicit scan → nmap's privileged SYN default
        # (the existing strategy). No scan flag emitted.
        normalized = [*kept, target]
        return NmapNormalization(
            args=normalized, transport=TRANSPORT_TCP_SYN, capability=cap,
            changed=normalized != original, dropped=dropped,
        )
    if privileged_allowed:
        # Raw-capable with an explicit -sT or a generic raw TCP scan
        # (-sA/-sW/-sM/…) → a single -sT. No --unprivileged/-Pn injection:
        # the operator has raw privilege and chose (or gets collapsed to) a
        # connect scan; we do not rewrite their host-discovery behavior.
        normalized = [_TCP_CONNECT_FLAG, *kept, target]
        return NmapNormalization(
            args=normalized, transport=TRANSPORT_TCP_CONNECT, capability=cap,
            changed=normalized != original, dropped=dropped,
        )

    # Unprivileged / unknown backend (any intent, or an explicit raw scan
    # type): force a single -sT AND inject --unprivileged and -Pn. -sT alone
    # is insufficient — nmap running as uid 0 without CAP_NET_RAW still
    # attempts raw-socket host-discovery ping probes and fails with EPERM.
    # --unprivileged forces the pure connect-socket path; -Pn skips discovery.
    # Both are de-duplicated against any the planner/LLM already supplied so a
    # doubled -Pn / --unprivileged is never emitted.
    kept_wo = [k for k in kept if k not in (_UNPRIVILEGED_FLAG, _PN_FLAG)]
    normalized = [_TCP_CONNECT_FLAG, _UNPRIVILEGED_FLAG, _PN_FLAG, *kept_wo, target]
    return NmapNormalization(
        args=normalized, transport=TRANSPORT_TCP_CONNECT, capability=cap,
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
        if tok in _VALUE_FLAG_PATTERNS and i + 1 < n:
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

    The flags that actually resolve the EPERM are ``--unprivileged`` and
    ``-Pn`` (alongside ``-sT``) — a bare ``-sT`` is NOT enough, because nmap
    as uid 0 still attempts raw-socket host discovery. So:

    - If it was a UDP scan, it is **terminal** — UDP cannot be converted to
      TCP without changing the operator's intent.
    - If the failed command **already had all three of** ``--unprivileged``,
      ``-Pn``, and ``-sT`` and still failed, the failure is **terminal** —
      the unprivileged flags are already present, so retrying would loop.
    - Otherwise, return the equivalent unprivileged command with
      ``--unprivileged -Pn -sT`` added (via
      :func:`normalize_nmap_command`). Because ``--unprivileged`` is a
      fingerprinted flag (see :func:`canonical_fingerprint_args`), the
      rewritten command is a DISTINCT action from the failed one and is not
      dedup-suppressed.

    *args* should be the command that actually executed (the normalized args
    recorded on the tool result) so the terminal decision reflects what nmap
    was really given — not the pre-normalization planner args.
    """
    original = [str(a) for a in args]
    intent = _classify_scan_intent(original)

    if intent == "udp":
        return NmapRepairPlan(
            terminal=True, repaired_args=None, transport=TRANSPORT_UDP,
            reason="UDP scan cannot be repaired to a TCP scan without changing intent",
        )

    already_unprivileged = (
        intent == "tcp_connect"
        and _UNPRIVILEGED_FLAG in original
        and _PN_FLAG in original
    )
    if already_unprivileged:
        return NmapRepairPlan(
            terminal=True, repaired_args=None, transport=TRANSPORT_TCP_CONNECT,
            reason=(
                "command already used --unprivileged -Pn -sT; raw-socket "
                "failure is terminal"
            ),
        )

    rewritten = normalize_nmap_command(original, target, capability=UNPRIVILEGED)
    return NmapRepairPlan(
        terminal=False, repaired_args=rewritten.args, transport=rewritten.transport,
        reason="rewrote to an unprivileged -sT scan with --unprivileged -Pn",
    )


def _host_timeout_of(args: list[str]) -> str:
    """Return the ``--host-timeout`` value present in *args*, else ``""``."""
    for i, tok in enumerate(args):
        if tok == "--host-timeout" and i + 1 < len(args):
            return str(args[i + 1])
    return ""


def plan_incomplete_scan_escalation(args: list[str], target: str) -> NmapRepairPlan:
    """Deterministic, bounded escalation for a classified
    ``nmap_incomplete_host_timeout`` scan (exited 0, timed out, 0 open ports).

    A broad ``--top-ports`` discovery scan that times out over VPN latency is
    escalated to a SMALLER, targeted ``-p <common-ports> -sV`` scan — the
    known-good fast scan that completes in ~14s where the top-1000 does not.
    This is a DISTINCT action from the discovery scan (it carries ``-p`` and
    ``-sV`` and drops ``--top-ports``), so it is not dedup-suppressed against
    the timed-out scan.

    - If the failed scan was **already** the targeted ``-p … -sV`` escalation
      and STILL timed out with nothing, there is no smaller bounded scan to try
      — it is **terminal** (surfaced as an honest outcome, never a bare
      duplicate stall, and never a fabricated port/service).
    - Otherwise, return the targeted escalation, preserving the connect-scan
      intent, the ``--host-timeout`` budget, and going through
      :func:`normalize_nmap_command` so the unprivileged flags are injected and
      the id stays canonical.

    *args* should be the command that ACTUALLY executed (the normalized args on
    the tool result).
    """
    original = [str(a) for a in args]
    kept, _dropped = _keep_safe_flags(original, target)
    already_targeted = "-p" in kept and "-sV" in kept
    if already_targeted:
        return NmapRepairPlan(
            terminal=True, repaired_args=None, transport=TRANSPORT_TCP_CONNECT,
            reason=(
                "targeted -p <common-ports> -sV scan also timed out with no open "
                "ports; no smaller bounded scan to escalate to"
            ),
        )

    host_timeout = _host_timeout_of(original)
    escalated = [
        _TCP_CONNECT_FLAG, "-Pn", "-T4",
        "-p", _COMMON_PORTS, "-sV", "--max-retries", "2",
    ]
    if host_timeout:
        escalated += ["--host-timeout", host_timeout]
    escalated.append(target)
    rewritten = normalize_nmap_command(escalated, target, capability=UNPRIVILEGED)
    return NmapRepairPlan(
        terminal=False, repaired_args=rewritten.args, transport=rewritten.transport,
        reason="escalated a timed-out top-ports discovery scan to a targeted -p <common> -sV scan",
    )
