# gateway.py
# Centralized LLM invocation gateway — the single approved surface for calling any model in APEX.
"""Single approved LLM invocation surface for APEX.

``LLMGateway`` is the **exclusive** point through which any model adapter is
called in APEX.  No planner, executor, parser, or graph node may call a
provider adapter directly; they must either inject and use an ``LLMGateway``
or go through ``PlanningEngine`` (which creates an internal gateway).

Every invocation follows the same pipeline:

1. **Router check** — return early when no router / no model is configured.
2. **Budget reservation** — atomic ``BudgetReservation`` via ``asyncio.Lock``.
3. **Prompt sanitization** — remove secret material before provider I/O.
4. **Pre-call guard** — reject prompts with out-of-scope targets or residual
   secrets; release reservation if blocked (provider never invoked).
5. **Provider invocation** — the only place in APEX that calls
   ``chat_llm.invoke(messages)``; run in a thread pool to preserve the event
   loop; guarded by a configurable timeout.
6. **Extract usage** — capture actual token counts from response metadata.
7. **Post-call guard** — reject responses that contain persistence, brute-force,
   or exfiltration patterns; call ``reservation.fail()`` on block.
8. **Commit reservation** — ``reservation.commit(actual_tokens)`` on success.
9. **Emit audit record** — sanitized metadata stored in ``audit_log``.
10. **Return ``LLMCallResult``** — callers check ``.status`` before using
    ``.raw_text``.

``invoke()`` never raises.  ``asyncio.CancelledError`` is an exception to this
rule: it always propagates so the event loop can cancel normally; the
reservation is released before re-raising.

Allowed exceptions to the "all calls through gateway" rule
-----------------------------------------------------------
- The provider adapter classes in ``apex_host/llm/router.py`` may construct
  LangChain model objects — they are the router, not a planner.
- Tests may use ``_StubLLM`` / ``_StubRouter`` in place of real providers;
  the gateway receives them transparently.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, cast

from apex_host.planning.engine import _LLMChatModel

if TYPE_CHECKING:
    from apex_host.llm.router import ModelRouter
    from apex_host.planning.budget import LLMBudgetTracker, BudgetReservation
    from apex_host.policy.llm_guard import LLMPolicyGuard

logger = logging.getLogger(__name__)

# Default invocation timeout in seconds.  Override at construction time.
_DEFAULT_TIMEOUT_SECONDS: float = 120.0


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class LLMCallPurpose(Enum):
    """The purpose of a gateway LLM call (for audit and budget accounting)."""

    planning = "planning"
    repair = "repair"


class LLMCallStatus(Enum):
    """Outcome of a gateway invocation."""

    success = "success"
    fallback_no_router = "fallback_no_router"
    fallback_no_model = "fallback_no_model"
    budget_exhausted = "budget_exhausted"
    prompt_blocked = "prompt_blocked"
    output_blocked = "output_blocked"
    provider_error = "provider_error"
    timeout = "timeout"
    cancelled = "cancelled"

    @property
    def is_success(self) -> bool:
        return self == LLMCallStatus.success

    @property
    def is_fallback(self) -> bool:
        return self in (
            LLMCallStatus.fallback_no_router,
            LLMCallStatus.fallback_no_model,
            LLMCallStatus.budget_exhausted,
        )

    @property
    def is_blocked(self) -> bool:
        return self in (LLMCallStatus.prompt_blocked, LLMCallStatus.output_blocked)

    @property
    def is_error(self) -> bool:
        return self in (
            LLMCallStatus.provider_error,
            LLMCallStatus.timeout,
            LLMCallStatus.cancelled,
        )


@dataclass(slots=True)
class LLMCallContext:
    """Context for a single gateway invocation."""

    purpose: LLMCallPurpose
    phase: str
    messages: list[dict[str, str]]
    allowed_tools: list[str] = field(default_factory=list)
    # Optional timeout override for this specific call.
    timeout_seconds: float | None = None


@dataclass(slots=True)
class LLMCallResult:
    """Result of a gateway invocation.

    ``raw_text`` is only meaningful when ``status == LLMCallStatus.success``.
    For all other statuses ``raw_text`` is ``""``; callers MUST check
    ``status`` before using ``raw_text``.
    """

    status: LLMCallStatus
    raw_text: str = ""
    blocked_reason: str = ""
    redaction_count: int = 0
    error: str = ""
    actual_input_tokens: int = 0
    actual_output_tokens: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "raw_text_len": len(self.raw_text),
            "blocked_reason": self.blocked_reason,
            "redaction_count": self.redaction_count,
            "error": self.error,
            "actual_input_tokens": self.actual_input_tokens,
            "actual_output_tokens": self.actual_output_tokens,
        }


@dataclass
class _AuditRecord:
    """Sanitized per-call audit metadata (no raw prompt or response text)."""

    decision_id: str
    purpose: str
    phase: str
    status: str
    redaction_count: int
    blocked_reason: str
    error: str
    actual_input_tokens: int
    actual_output_tokens: int
    elapsed_seconds: float


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


class LLMGateway:
    """Single approved LLM invocation surface for APEX.

    Parameters
    ----------
    model_router:
        ``ModelRouter`` instance.  ``None`` or a ``FakeModelRouter`` (which
        returns ``None`` for all roles) returns a fallback result immediately.
    budget:
        Shared ``LLMBudgetTracker``.  ``None`` disables budget enforcement.
    guard:
        ``LLMPolicyGuard`` for pre/post content checks.  ``None`` disables
        content checking.  When ``use_llm=True`` in production, the guard
        MUST be provided (see ``build_apex_graph``).
    timeout_seconds:
        Default timeout for provider invocations.
    """

    def __init__(
        self,
        model_router: "ModelRouter | None",
        budget: "LLMBudgetTracker | None" = None,
        guard: "LLMPolicyGuard | None" = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._router = model_router
        self._budget = budget
        self._guard = guard
        self._timeout = timeout_seconds
        self._audit_log: list[_AuditRecord] = []

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        """Sanitized audit records for all invocations (no raw content)."""
        return [
            {
                "decision_id": r.decision_id,
                "purpose": r.purpose,
                "phase": r.phase,
                "status": r.status,
                "redaction_count": r.redaction_count,
                "blocked_reason": r.blocked_reason,
                "error": r.error,
                "actual_input_tokens": r.actual_input_tokens,
                "actual_output_tokens": r.actual_output_tokens,
                "elapsed_seconds": round(r.elapsed_seconds, 3),
            }
            for r in self._audit_log
        ]

    async def invoke(self, ctx: LLMCallContext) -> LLMCallResult:
        """Invoke the LLM through all safety layers.

        Returns an ``LLMCallResult``.  Never raises (except
        ``asyncio.CancelledError`` which always propagates).
        Callers MUST check ``result.status`` before using ``result.raw_text``.
        """
        from memfabric.ids import new_id as _new_id

        decision_id = _new_id()
        t0 = time.monotonic()

        # 1. Router / model availability checks (no budget reserved yet)
        if self._router is None:
            result = LLMCallResult(status=LLMCallStatus.fallback_no_router)
            self._record_audit(decision_id, ctx, result, time.monotonic() - t0)
            return result

        llm = self._router.planner_llm()
        if llm is None:
            result = LLMCallResult(status=LLMCallStatus.fallback_no_model)
            self._record_audit(decision_id, ctx, result, time.monotonic() - t0)
            return result

        # 2. Atomic budget reservation
        reservation: "BudgetReservation | None" = None
        if self._budget is not None:
            ok, reason, reservation = await self._budget.reserve(
                purpose=ctx.purpose.value,
                phase=ctx.phase,
            )
            if not ok:
                result = LLMCallResult(
                    status=LLMCallStatus.budget_exhausted,
                    blocked_reason=reason,
                )
                self._record_audit(decision_id, ctx, result, time.monotonic() - t0)
                return result

        messages = list(ctx.messages)
        redaction_count = 0

        # 3. Prompt sanitization + 4. Pre-call guard
        if self._guard is not None:
            messages, redaction_count = self._guard.sanitize_messages(messages)
            if redaction_count > 0:
                logger.debug(
                    "llm_gateway: %d secret(s) redacted from %s prompt (phase=%s)",
                    redaction_count, ctx.purpose.value, ctx.phase,
                )
            prompt_blocked, prompt_reason = self._guard.check_prompt(messages)
            if prompt_blocked:
                logger.warning(
                    "llm_gateway: prompt blocked (purpose=%s phase=%s): %s",
                    ctx.purpose.value, ctx.phase, prompt_reason,
                )
                # Pre-call block: release reservation (provider never invoked).
                if reservation is not None:
                    await reservation.release()
                result = LLMCallResult(
                    status=LLMCallStatus.prompt_blocked,
                    blocked_reason=prompt_reason,
                    redaction_count=redaction_count,
                )
                self._record_audit(decision_id, ctx, result, time.monotonic() - t0)
                return result

        # 5. Provider invocation (in thread pool, with timeout)
        timeout = ctx.timeout_seconds if ctx.timeout_seconds is not None else self._timeout
        chat_llm = cast(_LLMChatModel, llm)
        raw: str = ""
        actual_in: int = 0
        actual_out: int = 0
        try:
            raw_response = await asyncio.wait_for(
                asyncio.to_thread(chat_llm.invoke, messages),
                timeout=timeout,
            )
            raw = str(getattr(raw_response, "content", raw_response))
            # 6. Extract usage metadata when available
            usage = getattr(raw_response, "usage_metadata", None) or getattr(
                raw_response, "response_metadata", {}
            )
            if isinstance(usage, dict):
                actual_in = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0)
                actual_out = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0)

        except asyncio.TimeoutError:
            err_str = f"provider timeout after {timeout}s"
            logger.warning("llm_gateway: %s (purpose=%s phase=%s)", err_str, ctx.purpose.value, ctx.phase)
            if reservation is not None:
                await reservation.fail()
            result = LLMCallResult(
                status=LLMCallStatus.timeout,
                error=err_str,
                redaction_count=redaction_count,
            )
            self._record_audit(decision_id, ctx, result, time.monotonic() - t0)
            return result

        except asyncio.CancelledError:
            # CancelledError propagates; release reservation before re-raising.
            logger.debug("llm_gateway: cancelled (purpose=%s phase=%s)", ctx.purpose.value, ctx.phase)
            if reservation is not None:
                await reservation.release()
            raise

        except Exception as exc:
            err_str = str(exc)
            logger.warning(
                "llm_gateway: provider error (purpose=%s phase=%s): %s",
                ctx.purpose.value, ctx.phase, exc,
            )
            if reservation is not None:
                await reservation.fail()
            status = (
                LLMCallStatus.timeout
                if "timeout" in err_str.lower()
                else LLMCallStatus.provider_error
            )
            result = LLMCallResult(
                status=status,
                error=err_str,
                redaction_count=redaction_count,
            )
            self._record_audit(decision_id, ctx, result, time.monotonic() - t0)
            return result

        # 7. Post-call guard
        if self._guard is not None:
            out_blocked, out_reason = self._guard.check_output(raw)
            if out_blocked:
                logger.warning(
                    "llm_gateway: output blocked (purpose=%s phase=%s): %s",
                    ctx.purpose.value, ctx.phase, out_reason,
                )
                if reservation is not None:
                    await reservation.fail()
                result = LLMCallResult(
                    status=LLMCallStatus.output_blocked,
                    blocked_reason=out_reason,
                    redaction_count=redaction_count,
                    actual_input_tokens=actual_in,
                    actual_output_tokens=actual_out,
                )
                self._record_audit(decision_id, ctx, result, time.monotonic() - t0)
                return result

        # 8. Commit reservation
        if reservation is not None:
            await reservation.commit(
                actual_input_tokens=actual_in,
                actual_output_tokens=actual_out,
            )

        result = LLMCallResult(
            status=LLMCallStatus.success,
            raw_text=raw,
            redaction_count=redaction_count,
            actual_input_tokens=actual_in,
            actual_output_tokens=actual_out,
        )
        self._record_audit(decision_id, ctx, result, time.monotonic() - t0)
        return result

    def _record_audit(
        self,
        decision_id: str,
        ctx: LLMCallContext,
        result: LLMCallResult,
        elapsed: float,
    ) -> None:
        """Append a sanitized audit record (no raw content)."""
        self._audit_log.append(_AuditRecord(
            decision_id=decision_id,
            purpose=ctx.purpose.value,
            phase=ctx.phase,
            status=result.status.value,
            redaction_count=result.redaction_count,
            blocked_reason=result.blocked_reason,
            error=result.error,
            actual_input_tokens=result.actual_input_tokens,
            actual_output_tokens=result.actual_output_tokens,
            elapsed_seconds=elapsed,
        ))
