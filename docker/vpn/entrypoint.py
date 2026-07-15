# entrypoint.py
# VPN container entrypoint: validates the mounted profile and /dev/net/tun, starts the readiness HTTP server in a background thread, then runs OpenVPN in the foreground with signal propagation. Exec-form, no shell, no shell string evaluation.
"""VPN container entrypoint.

Startup sequence:

    1. Verify /vpn/htb.ovpn exists and is readable    -> fail fast, non-zero, if not
    2. Verify /dev/net/tun exists                      -> fail fast, non-zero, if not
    3. Start the readiness HTTP server (background thread, docker/vpn/readiness_server.py)
    4. Start OpenVPN in the foreground (argv-list subprocess, never a shell)
    5. Forward SIGTERM/SIGINT to the OpenVPN child; propagate its exit code

This script never reads the mounted profile's content beyond what
``openvpn`` itself needs to start (it is opened only by OpenVPN, not by
this script) and never writes to it — the read-only bind mount
(``:ro`` in ``compose.yaml``) enforces this at the kernel level regardless,
but this script does not even attempt a write.

Does not print embedded credentials beyond what OpenVPN itself
unavoidably logs to its own stdout (e.g. TLS negotiation details, "AUTH:
Received control message"). This script adds no additional logging of
profile content, and never echoes environment variables.

Does not override valid HTB profile routing directives — no ``--route``,
``--redirect-gateway``, or similar flag is added by this script. Whatever
routes the ``.ovpn`` profile itself specifies are what takes effect;
``APEX_HTB_ROUTE_CIDR`` is used only for the *readiness check* (verifying
a matching route appears after OpenVPN starts), never to inject a route
directive into the OpenVPN invocation itself.

No shell string evaluation anywhere in this file — every subprocess call
uses an explicit argument list.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from types import FrameType

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout,
)
logger = logging.getLogger("vpn_entrypoint")

_PROFILE_PATH = Path("/vpn/htb.ovpn")
_TUN_DEVICE_PATH = Path("/dev/net/tun")
_READINESS_PORT_ENV = "APEX_VPN_READINESS_PORT"
_DEFAULT_READINESS_PORT = 8090

_child_process: "subprocess.Popen[bytes] | None" = None


def _verify_profile() -> None:
    if not _PROFILE_PATH.exists():
        logger.error("VPN profile not found at %s — mount a valid .ovpn file read-only at this path", _PROFILE_PATH)
        raise SystemExit(1)
    if not os.access(_PROFILE_PATH, os.R_OK):
        logger.error("VPN profile at %s exists but is not readable", _PROFILE_PATH)
        raise SystemExit(1)


def _verify_tun_device() -> None:
    if not _TUN_DEVICE_PATH.exists():
        logger.error(
            "%s not found — the container must be started with "
            "'--device /dev/net/tun:/dev/net/tun' (or the equivalent 'devices:' "
            "entry in compose.yaml)",
            _TUN_DEVICE_PATH,
        )
        raise SystemExit(1)


def _start_readiness_server() -> None:
    """Start the readiness HTTP server (docker/vpn/readiness_server.py) in
    a daemon background thread. A daemon thread ensures the process can
    still exit cleanly on SIGTERM without needing separate shutdown logic
    for the HTTP server."""
    import readiness_server

    port = int(os.environ.get(_READINESS_PORT_ENV, _DEFAULT_READINESS_PORT))
    thread = threading.Thread(
        target=readiness_server.run_server, kwargs={"port": port}, daemon=True, name="readiness-server",
    )
    thread.start()
    logger.info("readiness server thread started on port %d", port)


def _forward_signal(signum: int, _frame: FrameType | None) -> None:
    if _child_process is not None and _child_process.poll() is None:
        logger.info("forwarding signal %d to openvpn (pid=%d)", signum, _child_process.pid)
        _child_process.send_signal(signum)


def _run_openvpn() -> int:
    """Start OpenVPN in the foreground as an argv-list subprocess (never a
    shell) and wait for it to exit, forwarding SIGTERM/SIGINT to the child
    in the meantime. Returns the child's exit code."""
    global _child_process

    argv = [
        "openvpn",
        "--config", str(_PROFILE_PATH),
        # Hardening: never cache the decrypted auth secret in memory longer
        # than necessary for the initial connection.
        "--auth-nocache",
    ]
    # No --daemon flag: OpenVPN stays in the foreground and logs to its
    # controlling process's stderr by default — this container's only
    # observability surface (docker logs) — with no separate --log/
    # --log-append file redirection needed.
    logger.info("starting openvpn (config=%s)", _PROFILE_PATH)
    _child_process = subprocess.Popen(argv, shell=False)  # noqa: S603 - argv list, no shell, fixed binary

    signal.signal(signal.SIGTERM, _forward_signal)
    signal.signal(signal.SIGINT, _forward_signal)

    returncode = _child_process.wait()
    logger.info("openvpn exited with code %d", returncode)
    return returncode


def main() -> int:
    _verify_profile()
    _verify_tun_device()
    _start_readiness_server()
    return _run_openvpn()


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    raise SystemExit(main())
