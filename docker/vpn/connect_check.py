# connect_check.py
# Safe, single-attempt, bounded-timeout TCP connect diagnostic for the VPN container — classifies the outcome (connected/refused/timeout/unreachable/error) from the raw socket errno, distinguishing "no route to host" from a silent timeout from a refused connection.
"""TCP connect diagnostic.

Answers "what actually happens when I try to open a TCP connection to
<target>:<port>?" with a single, bounded-timeout attempt — never a scan,
never a retry loop, never a port range. This complements
``route_check.py`` (which only asks "would the kernel route traffic
there?" without ever sending a packet): this module actually attempts the
connection, so it can distinguish cases `ip route get` cannot —
specifically, a route that resolves correctly in the routing table but
still fails at connection time (e.g. an ICMP Destination/Host Unreachable
received back from somewhere in the network path, which manifests as a
*delayed* ``EHOSTUNREACH``/``ENETUNREACH``, not an instant local failure).

Outcome classification (the ``outcome`` field), each backed by the raw
socket ``errno`` where one exists:

| ``outcome`` | Meaning | Typical cause |
|---|---|---|
| ``connected`` | TCP handshake completed | Port open and reachable |
| ``refused`` | ``ECONNREFUSED`` | Port closed, but the host itself responded (RST) |
| ``unreachable`` | ``EHOSTUNREACH``/``ENETUNREACH`` | An ICMP unreachable was received, or the local routing/interface state cannot reach the destination — this is the outcome a route that looks valid in `ip route get` can still produce, since `ip route get` is a local lookup only and does not itself send a packet or wait for a network response |
| ``timeout`` | No response at all within the bound | SYN was sent but nothing came back (RST, SYN-ACK, or ICMP) before the timeout — this is what nmap classifies as **filtered** for the equivalent `-sT` scan; a stateful firewall silently dropping the packet is the most common cause |
| ``invalid_target`` / ``invalid_port`` | Input validation failed | Never attempted a connection |
| ``error`` | Some other `OSError` | See ``detail`` |

Deliberately dependency-free (stdlib only) — copied into the minimal VPN
image standalone, never imports ``apex_host``, consistent with every
other file in this directory.
"""
from __future__ import annotations

import errno as errno_module
import socket
import time
from dataclasses import dataclass

from route_check import InvalidTargetError, validate_target_ip

_DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
_MIN_PORT = 1
_MAX_PORT = 65535

# Maps a raw connect() errno to this module's outcome vocabulary. Any
# errno not listed here still produces a result (outcome="error") — this
# module never raises for an ordinary connection failure.
_ERRNO_OUTCOMES: dict[int, str] = {
    errno_module.ECONNREFUSED: "refused",
    errno_module.EHOSTUNREACH: "unreachable",
    errno_module.ENETUNREACH: "unreachable",
    errno_module.ETIMEDOUT: "timeout",
}


class InvalidPortError(ValueError):
    """Raised when a caller-supplied port is not a valid TCP port number."""


def validate_port(raw: str | int) -> int:
    """Validate *raw* as an integer TCP port in [1, 65535]. Returns the
    normalized ``int`` on success. Raises ``InvalidPortError`` (a
    ``ValueError`` subclass) for anything else."""
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise InvalidPortError(f"{raw!r} is not a valid integer port") from exc
    if not (_MIN_PORT <= port <= _MAX_PORT):
        raise InvalidPortError(f"port {port} is out of range ({_MIN_PORT}-{_MAX_PORT})")
    return port


@dataclass(frozen=True, slots=True)
class ConnectCheckResult:
    """Structured result of a single, bounded TCP connect attempt."""

    target: str
    port: int
    ok: bool
    outcome: str
    errno: int | None
    errno_name: str | None
    elapsed_seconds: float
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "port": self.port,
            "ok": self.ok,
            "outcome": self.outcome,
            "errno": self.errno,
            "errno_name": self.errno_name,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "detail": self.detail,
        }


def _classify_errno(err_num: int | None) -> str:
    if err_num is None:
        return "error"
    return _ERRNO_OUTCOMES.get(err_num, "error")


def run_connect_check(
    target: str, port: str | int, *, timeout_seconds: float = _DEFAULT_CONNECT_TIMEOUT_SECONDS,
) -> ConnectCheckResult:
    """Attempt exactly one TCP connection to *target*:*port*, bounded by
    *timeout_seconds*. Never raises for an ordinary connection failure —
    every outcome (including invalid input) is represented in the
    returned ``ConnectCheckResult``, matching the "ordinary failure is
    data" discipline used throughout this project's other tool-execution
    boundaries (``route_check.py``, ``apex_host.tools.backend``).

    Never retries and never attempts more than one destination — a
    caller wanting to probe multiple ports must call this once per port
    itself; this function has no looping/scanning behavior of its own.
    """
    try:
        normalized_target = validate_target_ip(target)
    except InvalidTargetError as exc:
        return ConnectCheckResult(
            target=str(target), port=0, ok=False, outcome="invalid_target",
            errno=None, errno_name=None, elapsed_seconds=0.0, detail=str(exc),
        )
    try:
        normalized_port = validate_port(port)
    except InvalidPortError as exc:
        return ConnectCheckResult(
            target=normalized_target, port=0, ok=False, outcome="invalid_port",
            errno=None, errno_name=None, elapsed_seconds=0.0, detail=str(exc),
        )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_seconds)
    start = time.monotonic()
    try:
        sock.connect((normalized_target, normalized_port))
        elapsed = time.monotonic() - start
        return ConnectCheckResult(
            target=normalized_target, port=normalized_port, ok=True, outcome="connected",
            errno=None, errno_name=None, elapsed_seconds=elapsed,
            detail=f"TCP connect to {normalized_target}:{normalized_port} succeeded",
        )
    except socket.timeout:
        elapsed = time.monotonic() - start
        return ConnectCheckResult(
            target=normalized_target, port=normalized_port, ok=False, outcome="timeout",
            errno=None, errno_name=None, elapsed_seconds=elapsed,
            detail=(
                f"no response within {timeout_seconds}s — a SYN was sent but nothing came "
                "back (this is what a port scanner reports as 'filtered')"
            ),
        )
    except OSError as exc:
        elapsed = time.monotonic() - start
        err_num = exc.errno
        outcome = _classify_errno(err_num)
        errno_name = errno_module.errorcode.get(err_num, None) if err_num is not None else None
        return ConnectCheckResult(
            target=normalized_target, port=normalized_port, ok=False, outcome=outcome,
            errno=err_num, errno_name=errno_name, elapsed_seconds=elapsed, detail=str(exc),
        )
    finally:
        sock.close()
