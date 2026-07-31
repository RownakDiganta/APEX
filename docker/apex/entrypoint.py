# entrypoint.py
# Root-init entrypoint for the APEX container: as root, prepare the mounted knowledge-cache named volume for the non-root apex user, then permanently drop privileges and exec the real Python entrypoint (apex_host.container_entrypoint). Never runs the engagement as root; never widens permissions to world-writable.
"""APEX container privilege-drop entrypoint (Docker only).

Root cause this file fixes
--------------------------
The ``apex`` service mounts a Docker *named* volume
(``apex-knowledge-cache``) at ``/app/knowledge_cache`` (see ``compose.yaml``).
A brand-new named volume mounted onto a path Docker has to create is created
**root-owned**. The APEX application runs as the non-root ``apex`` user
(UID/GID 1000), so its very first durable-cache operation —
``apex_host/knowledge/init_lock.py`` creating ``/app/knowledge_cache/.init.lock``
via ``os.open(..., O_CREAT|O_EXCL)`` — fails with ``PermissionError: [Errno 13]
Permission denied``, blocking every live engagement.

Design (the standard, minimal "root-init then drop" pattern)
------------------------------------------------------------
This script is the image ``ENTRYPOINT``. Because it must ``chown`` a
possibly-root-owned mounted volume, the image does NOT set a final ``USER``
directive — the container starts as root, this script performs the *minimum*
privileged preparation, and then **permanently** drops to the non-root
``apex`` user (via ``os.setgroups``/``os.setgid``/``os.setuid``) before
``os.execv``-ing the real Python entrypoint. The engagement, LLM calls,
report generation, and tool orchestration therefore all run as the non-root
user — exactly as before — with only the directory-preparation step ever
holding elevated privilege.

Using ``os.execv`` (process replacement) means the real entrypoint inherits
PID 1, so container signals reach it directly and its exit code is the
container's exit code — no wrapper process, no signal-forwarding logic, no
swallowed exit code.

This uses only the Python standard library already present in the image (no
``gosu``/``su-exec`` package to add) and is intentionally domain-agnostic
container plumbing — it imports nothing from ``apex_host``/``memfabric`` and
performs no APEX configuration parsing (that remains
``apex_host.container_entrypoint``'s job, unchanged).
"""
from __future__ import annotations

import os
import pwd
import stat
import sys

#: Directory mode for prepared cache directories: owner + group ``rwx``, no
#: access for "other" — a restrictive, never world-writable mode. The
#: knowledge cache holds only initialization bookkeeping, and the ``apex``
#: user is the only account that ever needs it.
_CACHE_DIR_MODE = 0o770

#: The one mounted named-volume target Docker creates root-owned for a fresh
#: volume. ``/app/run_reports`` is a bind mount that is already writable by the
#: runtime user (created + chowned at image build time) and is intentionally
#: NOT touched here — chowning a bind mount would rewrite host-side ownership.
_PREPARE_DIRS = ("/app/knowledge_cache",)

#: The non-root runtime account created in docker/apex/Dockerfile. The UID/GID
#: are resolved from this name at runtime, never hard-coded here.
_RUNTIME_USER = "apex"


def resolve_runtime_identity(user: str = _RUNTIME_USER) -> tuple[int, int]:
    """Return ``(uid, gid)`` for *user* from the image's own passwd database."""
    entry = pwd.getpwnam(user)
    return entry.pw_uid, entry.pw_gid


def chown_recursive(path: str, uid: int, gid: int) -> None:
    """Repair ownership of *path* and everything under it to *uid*/*gid*.

    Only ever called when the directory root's ownership is already wrong (a
    fresh or legacy root-owned volume) — the one demonstrated compatibility
    case that justifies a recursive pass. The cache is small bookkeeping, so
    this is bounded; the normal warm path never reaches it.
    """
    os.chown(path, uid, gid, follow_symlinks=False)
    for root, dirs, files in os.walk(path):
        for name in (*dirs, *files):
            try:
                os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)
            except OSError:
                # Best-effort per entry; the post-drop write test below is the
                # authoritative check that the runtime user can actually write.
                pass


def prepare_dir(path: str, uid: int, gid: int) -> None:
    """Ensure *path* exists and is owned/writable by the runtime user.

    Idempotent: ownership is repaired only when it is actually wrong, never an
    unconditional (potentially expensive) recursive ``chown`` on every start.
    Never deletes or truncates any existing cache content.
    """
    os.makedirs(path, exist_ok=True)
    info = os.stat(path)
    if info.st_uid != uid or info.st_gid != gid:
        chown_recursive(path, uid, gid)
    os.chmod(path, _CACHE_DIR_MODE)


def drop_privileges(uid: int, gid: int) -> None:
    """Permanently drop from root to *uid*/*gid*.

    Order matters: supplementary groups first, then the primary GID, then the
    UID last (once the UID is dropped, the other two calls would fail).
    """
    os.setgroups([gid])
    os.setgid(gid)
    os.setuid(uid)


def verify_writable(path: str) -> bool:
    """Return whether the *current* (post-drop) process can create a file in
    *path*. Uses ``O_EXCL`` and removes the probe immediately — never touches
    or overwrites a real cache file."""
    probe = os.path.join(path, f".apex_write_test.{os.getpid()}")
    try:
        fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        os.unlink(probe)
    except OSError:
        return False
    return True


def report_unwritable(path: str, uid: int, gid: int) -> None:
    """Print a clear, secret-free diagnostic identifying the path, runtime
    UID/GID, current directory ownership, and mode, then exit non-zero. Never
    prints environment variables or any secret."""
    try:
        info = os.stat(path)
        ownership = f"{info.st_uid}:{info.st_gid}"
        mode = f"{stat.filemode(info.st_mode)} ({oct(info.st_mode & 0o777)})"
    except OSError as exc:
        ownership = f"<stat failed: {exc.__class__.__name__}>"
        mode = "<unknown>"
    lines = [
        "FATAL: the APEX knowledge cache is not writable by the non-root runtime user.",
        f"  path:      {path}",
        f"  runtime:   uid={uid} gid={gid} ({_RUNTIME_USER})",
        f"  ownership: {ownership}",
        f"  mode:      {mode}",
        "  Fix: recreate the cache volume (e.g. 'docker compose ... down -v', or",
        "       'docker volume rm <project>_apex-knowledge-cache' while the stack is stopped)",
        "       and retry. See README.md 'Diagnosing knowledge-cache ownership issues'.",
    ]
    print("\n".join(lines), file=sys.stderr)
    sys.exit(1)


def main(argv: list[str]) -> None:
    uid, gid = resolve_runtime_identity()
    started_as_root = os.geteuid() == 0

    if started_as_root:
        for directory in _PREPARE_DIRS:
            prepare_dir(directory, uid, gid)
        drop_privileges(uid, gid)
    # else: the container was started as an explicit non-root user (e.g. a
    # `--user` override). Ownership cannot be repaired from here; proceed and
    # let the write test below surface any real problem loudly rather than
    # silently.

    for directory in _PREPARE_DIRS:
        if not verify_writable(directory):
            report_unwritable(directory, uid, gid)

    # Process replacement: the real entrypoint becomes PID 1, inherits signals
    # directly, and its exit code is the container's exit code. All argv after
    # this script (CMD or `docker run`/`compose run` arguments) are forwarded
    # verbatim — including the `exec -- ...` form.
    os.execv(sys.executable, [sys.executable, "-m", "apex_host.container_entrypoint", *argv])


if __name__ == "__main__":
    main(sys.argv[1:])
