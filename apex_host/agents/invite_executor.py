# invite_executor.py
# Opt-in auto-invite-flow orchestrator (§28.35): GET challenge -> decode -> POST
# verify -> POST register, per-send auto-approve + safety gated; runtime-only creds.
"""Generic auto-invite/registration flow executor (§28.35).

Runs a bounded, operator-configured onboarding flow as ONE orchestrator task:
GET a challenge, decode it (pure Python — no JS execution), POST it to a verify
endpoint, POST the resulting code to a register endpoint, and capture the
returned credentials. Every SEND-side sub-request (POST) is individually checked
against the operator's ``--auto-approve-send-patterns`` (fail-closed if not
listed) and still passes through ``safety.py`` inside ``run_command``. Every
request only ever connects to the AUTHORIZED target IP (a ``--resolve`` pin,
§28.8), so nothing off-scope is contacted. Captured credentials are stored ONLY
in the process-local ``CapabilityRuntimeRegistry`` (never the EKG/episodic/
checkpoint, amended P8-I03); the plaintext password never appears in the returned
result. Default OFF — nothing here runs unless ``config.auto_invite_flow`` and,
under ``dry_run`` (the default), it performs no network I/O at all.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from apex_host.invite_flow import DecodeError, action_matches_auto_approve, decode_response
from apex_host.types import ToolCommand

if TYPE_CHECKING:
    from apex_host.config import ApexConfig
    from apex_host.runtime_registry import CapabilityRuntimeRegistry
    from apex_host.types import ToolResult
    from memfabric.types import EvidenceBundle, TaskSpec

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class InviteFlowResult:
    """Secret-free outcome of an invite flow — the password is NEVER a field."""

    success: bool
    username: str = ""
    invite_code_obtained: bool = False
    credentials_stored: bool = False
    dry_run: bool = False
    error: str | None = None
    steps: list[str] = field(default_factory=list)


class InviteFlowExecutor:
    """Stateless per-call orchestrator for the opt-in invite flow (§28.35)."""

    def __init__(
        self,
        config: "ApexConfig",
        run_command_fn: Any,
        capability_registry: "CapabilityRuntimeRegistry",
    ) -> None:
        self._config = config
        self._run = run_command_fn
        self._registry = capability_registry

    async def run(self, task: "TaskSpec", evidence: "EvidenceBundle") -> InviteFlowResult:
        p = task.params
        steps: list[str] = []

        # Dry-run (the default): no network, no credentials, nothing "succeeds".
        if bool(getattr(self._config, "dry_run", True)):
            return InviteFlowResult(
                False, dry_run=True, steps=["dry_run: invite flow not executed"])

        host_ip = str(p.get("host_ip") or self._config.target)
        gen_url = str(p.get("generate_url") or "")
        ver_url = str(p.get("verify_url") or "")
        reg_url = str(p.get("register_url") or "")
        decode_steps = list(p.get("decode_steps") or [])
        verify_field = str(p.get("verify_response_field") or "code")
        invite_field = str(p.get("register_invite_field") or "invite_code")
        user_field = str(p.get("register_username_field") or "username")
        pass_field = str(p.get("register_password_field") or "password")
        patterns = list(getattr(self._config, "auto_approve_send_patterns", []) or [])

        # 1. GET challenge (read-side).
        r = await self._curl("GET", gen_url, host_ip)
        if not self._ok(r):
            return InviteFlowResult(False, steps=steps + ["generate: request failed"],
                                    error="generate GET failed")
        steps.append("generate: fetched challenge")

        # 2. Decode (pure Python — never executes the JS/response).
        try:
            decoded = decode_response(r.stdout, decode_steps)  # type: ignore[union-attr]
        except DecodeError as exc:
            return InviteFlowResult(False, steps=steps + ["decode: failed"],
                                    error=f"decode failed: {exc}")
        steps.append(f"decode: applied {len(decode_steps)} step(s)")

        # 3. POST verify (send-side) — fail-closed unless operator auto-approved it.
        if not action_matches_auto_approve("POST", ver_url, patterns):
            return InviteFlowResult(
                False, steps=steps + ["verify: not auto-approved"],
                error="verify POST not in --auto-approve-send-patterns (fail-closed)")
        r = await self._curl("POST", ver_url, host_ip, body=f"{verify_field}={decoded}")
        if not self._ok(r):
            return InviteFlowResult(False, steps=steps + ["verify: request failed"],
                                    error="verify POST failed")
        invite_code = self._json_field(r.stdout, verify_field)  # type: ignore[union-attr]
        if not invite_code:
            return InviteFlowResult(
                False, steps=steps + ["verify: no invite code in response"],
                error="invite code not found in verify response")
        steps.append("verify: obtained invite code")

        # 4. POST register (send-side) — fail-closed unless operator auto-approved it.
        if not action_matches_auto_approve("POST", reg_url, patterns):
            return InviteFlowResult(
                False, steps=steps + ["register: not auto-approved"],
                error="register POST not in --auto-approve-send-patterns (fail-closed)")
        r = await self._curl("POST", reg_url, host_ip, body=f"{invite_field}={invite_code}")
        if not self._ok(r):
            return InviteFlowResult(False, steps=steps + ["register: request failed"],
                                    error="register POST failed")
        username = self._json_field(r.stdout, user_field)  # type: ignore[union-attr]
        password = self._json_field(r.stdout, pass_field)  # type: ignore[union-attr]
        if not username or not password:
            return InviteFlowResult(
                False, steps=steps + ["register: credentials not in response"],
                error="credentials not found in register response")

        # 5. Store plaintext ONLY in the runtime registry (never the EKG/episode).
        self._registry.set_manual_credentials(username, password)
        steps.append("register: credentials stored in runtime registry (redacted in EKG)")
        return InviteFlowResult(
            True, username=username, invite_code_obtained=True,
            credentials_stored=True, steps=steps)

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _ok(r: "ToolResult | None") -> bool:
        return r is not None and r.returncode == 0 and not r.error

    async def _curl(
        self, method: str, url: str, host_ip: str, *, body: str | None = None,
    ) -> "ToolResult | None":
        """Build + run one bounded curl, pinned to the AUTHORIZED IP (§28.8).

        safety.py runs inside run_command; a rejected command (metachar/
        destructive) returns None (the flow aborts fail-safe)."""
        try:
            sp = urlsplit(url)
        except ValueError:
            return None
        host = sp.hostname
        if not host:
            return None
        port = sp.port or (443 if sp.scheme == "https" else 80)
        args = ["-s"]
        # Only ever connect to the authorized IP: a vhost URL is --resolve-pinned
        # to host_ip; a bare-IP URL is fetched directly (host must equal host_ip).
        if host != host_ip:
            args += ["-L", "--resolve", f"{host}:{port}:{host_ip}"]
        if method != "GET":
            args += ["-X", method]
        if body is not None:
            args += ["-d", body]
        args.append(url)
        cmd = ToolCommand(
            tool="curl", args=args,
            timeout_seconds=int(getattr(self._config, "max_command_seconds", 30)))
        try:
            return await self._run(cmd, self._config)  # type: ignore[no-any-return]
        except (ValueError, OSError) as exc:  # safety rejection / transport error
            logger.warning("invite flow curl rejected/failed: %s", type(exc).__name__)
            return None

    @staticmethod
    def _json_field(text: str, field_name: str) -> str:
        try:
            data = json.loads(text.strip())
        except (json.JSONDecodeError, ValueError):
            return ""
        if isinstance(data, dict):
            v = data.get(field_name)
            return str(v) if v not in (None, "") else ""
        return ""
