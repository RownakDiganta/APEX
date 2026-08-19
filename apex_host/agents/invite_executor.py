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
import secrets
import string
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

#: §28.35 — common field names for the invite code in a verify response, tried
#: (after the operator-supplied field) so the operator need not guess the exact
#: name. The code alone permits an any-string fallback (a code is opaque); a
#: credential NEVER does (a wrong string as a password would be misleading).
_CODE_FIELDS: tuple[str, ...] = ("code", "invite_code", "token", "invite", "data", "result")
_USERNAME_FIELDS: tuple[str, ...] = ("username", "user", "login", "name")
_PASSWORD_FIELDS: tuple[str, ...] = ("password", "pass", "secret", "pwd")
#: Strings that are status/flags, never an invite code — excluded from the
#: any-string fallback.
_NON_CODE_STRINGS: frozenset[str] = frozenset(
    {"success", "true", "false", "ok", "error", "failed", "none", "1", "0"})


@dataclass(slots=True)
class InviteFlowResult:
    """Secret-free outcome of an invite flow — the password is NEVER a field."""

    success: bool
    username: str = ""
    invite_code_obtained: bool = False
    credentials_stored: bool = False
    credentials_auto_generated: bool = False
    register_urls_tried: list[str] = field(default_factory=list)
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
        r = await self._curl("POST", ver_url, host_ip,
                             body=f"{verify_field}={decoded}", capture_status=True)
        if not self._ok(r):
            return InviteFlowResult(False, steps=steps + ["verify: request failed"],
                                    error="verify POST failed")
        # Capture the HTTP status so a wrong endpoint/method (e.g. a 405 Method
        # Not Allowed, or a 404) is surfaced clearly instead of an opaque
        # "code not found" — the configured verify endpoint may not match the
        # target's actual invite flow (which APEX cannot hardcode).
        v_body, v_status = self._split_status(r.stdout)  # type: ignore[union-attr]
        status_note = f" (verify returned HTTP {v_status})" if v_status else ""
        if v_status and v_status[:1] in ("4", "5"):
            return InviteFlowResult(
                False, steps=steps + [f"verify: HTTP {v_status}"],
                error=(f"verify POST to {ver_url} returned HTTP {v_status} — the "
                       "configured --invite-verify-patterns endpoint/method may not "
                       "match the target's actual invite flow"))
        verify_json = self._parse_json(v_body)
        if verify_json is None:
            return InviteFlowResult(
                False, steps=steps + ["verify: non-JSON response"],
                error=f"verify response was not a JSON object{status_note}")
        invite_code = self._extract_field(
            verify_json, verify_field, _CODE_FIELDS, allow_any_string=True)
        if not invite_code:
            tried = ", ".join(dict.fromkeys((verify_field, *_CODE_FIELDS)))
            return InviteFlowResult(
                False, steps=steps + ["verify: no invite code in response"],
                error=("invite code not found in verify response (tried fields: "
                       f"{tried}; also searched nested objects up to depth 3)"
                       f"{status_note}"))
        steps.append("verify: obtained invite code")

        # 4. POST register — try each operator-listed candidate endpoint in order,
        # each individually fail-closed against --auto-approve-send-patterns and
        # safety.py, stopping at the FIRST accepted (2xx/3xx) response. This lets
        # the operator supply a few candidate register endpoints without knowing
        # which one the target uses; APEX only ever POSTs to endpoints the
        # operator explicitly listed AND auto-approved (never autonomous spraying).
        reg_urls = [u for u in (p.get("register_urls") or [reg_url]) if u]
        content_type = str(p.get("register_content_type") or "application/x-www-form-urlencoded")
        reg_tried: list[str] = []
        last_reason = ""
        result: tuple[str, str, bool] | None = None
        for candidate in reg_urls:
            if not action_matches_auto_approve("POST", candidate, patterns):
                last_reason = f"{candidate}: not in --auto-approve-send-patterns"
                continue
            reg_tried.append(candidate)
            attempt = await self._attempt_register(
                candidate, host_ip, invite_code, content_type,
                user_field, pass_field, invite_field)
            if attempt is not None:
                result = attempt
                steps.append(f"register: accepted by {candidate}")
                break
            last_reason = f"{candidate}: not accepted"
        if result is None:
            return InviteFlowResult(
                False, register_urls_tried=reg_tried,
                steps=steps + ["register: no endpoint accepted the registration"],
                error=("registration was not accepted by any configured endpoint "
                       f"({last_reason or 'none auto-approved'})"))
        username, password, auto_generated = result

        # 5. Store plaintext ONLY in the runtime registry (never the EKG/episode).
        self._registry.set_manual_credentials(username, password)
        steps.append("register: credentials stored in runtime registry (redacted in EKG)")
        return InviteFlowResult(
            True, username=username, invite_code_obtained=True,
            credentials_stored=True, credentials_auto_generated=auto_generated,
            register_urls_tried=reg_tried, steps=steps)

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _generate_credentials() -> tuple[str, str]:
        """Generate RANDOM, THROWAWAY credentials for the TARGET APPLICATION
        registration (§28.35). These are for the simulated app on the target
        only — never a real/HTB-platform credential, never reused. Uses
        ``secrets`` (CSPRNG), not ``random``.

        Username: ``apex_`` + 8 lowercase alphanumerics. Password: 16 chars from
        letters/digits/a small symbol set."""
        u_alpha = string.ascii_lowercase + string.digits
        username = "apex_" + "".join(secrets.choice(u_alpha) for _ in range(8))
        p_alpha = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(secrets.choice(p_alpha) for _ in range(16))
        return username, password

    @staticmethod
    def _split_status(stdout: str) -> tuple[str, str]:
        """Split a curl body+``\\n%{http_code}`` capture into (body, status)."""
        if "\n" in stdout:
            body, _, status = stdout.rpartition("\n")
            status = status.strip()
            if status.isdigit():
                return body, status
        return stdout, ""

    @staticmethod
    def _is_error_response(body: str) -> bool:
        low = body.lower()
        return any(k in low for k in (
            "error", "failed", "invalid", "already exists", "already taken",
            "is taken", "bad request", "unauthorized", "forbidden"))

    @classmethod
    def _register_succeeded(cls, status: str, body: str) -> bool:
        """A registration is successful on a 2xx/3xx HTTP status; when no status
        was captured, fall back to a conservative body keyword check."""
        if status:
            return status[:1] in ("2", "3")
        return not cls._is_error_response(body)

    async def _attempt_register(
        self, url: str, host_ip: str, invite_code: str, content_type: str,
        user_field: str, pass_field: str, invite_field: str,
    ) -> tuple[str, str, bool] | None:
        """One registration POST to *url*. Returns (username, password,
        auto_generated) on a 2xx/3xx (or server-returned credentials), else None.

        Sends RANDOM THROWAWAY target-app credentials (never a real/HTB
        credential, §28.35) in the chosen content type; prefers server-returned
        credentials when the server generates them instead."""
        gen_user, gen_pass = self._generate_credentials()
        if content_type == "application/json":
            body = json.dumps({user_field: gen_user, pass_field: gen_pass,
                               invite_field: invite_code})
            headers: list[str] | None = ["Content-Type: application/json"]
        else:
            body = f"{user_field}={gen_user}&{pass_field}={gen_pass}&{invite_field}={invite_code}"
            headers = None
        r = await self._curl("POST", url, host_ip, body=body,
                             capture_status=True, headers=headers)
        if not self._ok(r):
            return None
        resp_body, status = self._split_status(r.stdout)  # type: ignore[union-attr]
        reg_json = self._parse_json(resp_body)
        resp_user = self._extract_field(reg_json, user_field, _USERNAME_FIELDS) if reg_json else ""
        resp_pass = self._extract_field(reg_json, pass_field, _PASSWORD_FIELDS) if reg_json else ""
        if resp_user and resp_pass:
            return resp_user, resp_pass, False  # server returned credentials
        if self._register_succeeded(status, resp_body):
            return gen_user, gen_pass, True  # our throwaway credentials
        return None

    @staticmethod
    def _ok(r: "ToolResult | None") -> bool:
        return r is not None and r.returncode == 0 and not r.error

    async def _curl(
        self, method: str, url: str, host_ip: str, *, body: str | None = None,
        capture_status: bool = False, headers: list[str] | None = None,
    ) -> "ToolResult | None":
        """Build + run one bounded curl, pinned to the AUTHORIZED IP (§28.8).

        safety.py runs inside run_command; a rejected command (metachar/
        destructive) returns None (the flow aborts fail-safe). When
        *capture_status* is set, the HTTP status code is appended to stdout as a
        final line (``-w '\\n%{http_code}'``) so the caller can determine success
        by status rather than by parsing the body."""
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
        if capture_status:
            args += ["-w", "\\n%{http_code}"]
        for h in headers or []:
            args += ["-H", h]
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
    def _parse_json(text: str) -> dict[str, object] | None:
        """Parse a JSON object response, or None when the body is not a JSON
        object (e.g. an HTML page or a JSON array)."""
        try:
            data = json.loads(text.strip())
        except (json.JSONDecodeError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _search_named(data: object, names: tuple[str, ...], depth: int) -> str:
        """Recursively find the first STRING value under any of *names* (§28.35).

        Checks the named fields at THIS level first (a shallower match wins),
        then recurses into nested dicts and lists-of-objects up to *depth* — so a
        code nested under e.g. ``{"data": {"code": "..."}}`` is found. Bounded by
        *depth* and stdlib-only; never raises."""
        if isinstance(data, dict):
            for name in names:
                v = data.get(name)
                if isinstance(v, str) and v.strip():
                    return v.strip()
            if depth > 0:
                for v in data.values():
                    if isinstance(v, (dict, list)):
                        found = InviteFlowExecutor._search_named(v, names, depth - 1)
                        if found:
                            return found
        elif isinstance(data, list) and depth > 0:
            for item in data:
                if isinstance(item, (dict, list)):
                    found = InviteFlowExecutor._search_named(item, names, depth - 1)
                    if found:
                        return found
        return ""

    @staticmethod
    def _extract_field(
        data: dict[str, object], preferred: str, candidates: tuple[str, ...],
        *, allow_any_string: bool = False, max_depth: int = 3,
    ) -> str:
        """Return the first non-empty STRING value for *preferred* then each of
        *candidates*, searched at the top level AND in nested objects up to
        *max_depth* (§28.35 — so the operator need not guess the exact field name
        OR its nesting). When *allow_any_string* and none matched, fall back to
        the first TOP-LEVEL non-status string value (used ONLY for the opaque
        invite code, never for a credential, and never nested — a nested random
        string would be too loose a guess)."""
        names = tuple(n for n in (preferred, *candidates) if n)
        found = InviteFlowExecutor._search_named(data, names, max_depth)
        if found:
            return found
        if allow_any_string and isinstance(data, dict):
            for v in data.values():
                if isinstance(v, str) and len(v.strip()) > 5 \
                        and v.strip().lower() not in _NON_CODE_STRINGS:
                    return v.strip()
        return ""
