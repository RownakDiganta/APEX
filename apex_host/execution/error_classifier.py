# error_classifier.py
# Fine-grained, apex_host-level diagnostic error classification layered on top of (never replacing) memfabric.types.Outcome.
"""Fine-grained execution diagnostic classification (Phase 3, post-live-test
debugging track).

``memfabric.types.Outcome`` is a deliberately small, domain-agnostic
4-value enum (``success`` / ``script_error`` / ``fixable`` / ``fundamental``)
that drives skill-lifecycle and repair-eligibility decisions inside the
generic substrate — it must never be extended with apex_host-specific
categories (memfabric Invariant: the substrate stays domain-agnostic).
This module does NOT touch ``Outcome``. It answers a narrower,
apex_host-only, report-facing question: "for a human operator reading a
report, which of a small, fixed set of categories best explains why this
specific execution did not succeed?" — never consumed by memfabric, never
used to drive a retry/repair control-flow decision (those remain the
exclusive responsibility of ``apex_host.execution.dispositions
.classify_retry`` and ``apex_host.orchestration.completion.outcome_for``,
both unchanged by this module).

Boundary definitions
---------------------
- ``SUCCESS``: no error, returncode 0 (or absent).
- ``POLICY_BLOCK``: ``PolicyAdvisor`` denied the task before any I/O
  (``tr["policy_blocked"]``).
- ``PROVIDER_ERROR``: an LLM/provider-layer failure (``tr["llm_error_category"]``
  set — see ``apex_host.llm.errors.LLMErrorCategory``). Distinct from every
  other category here because it originates in the planning layer, never
  in tool execution.
- ``CAPABILITY_MISSING``: a structured capability/adapter never connected
  (``tr["connected"] is False`` — the Phase 18B/20/21 access-capability
  convention). The requested action could not even be attempted because
  the underlying mechanism (SSH session, bounded-read strategy, ...) was
  unavailable.
- ``TIMEOUT``: the executor's own timeout fired (``tr["timed_out"]``), or
  the error text says so.
- ``BACKEND_ERROR``: a transport/environment-level failure BELOW the
  tool's own application logic — DNS/connection failure, tool binary not
  found in PATH, or any other raised transport exception
  (``tr["error"]`` is set to a real exception message, not merely a
  nonzero return code).
- ``FUNDAMENTAL``: a nonzero return code that reflects an environment/
  privilege constraint the SAME command can never overcome by retrying
  or reformatting arguments alone in the general case (e.g. a raw-socket
  permission failure) — mirrors ``memfabric.types.Outcome.fundamental``'s
  own intent, just more specifically named here.
- ``FIXABLE``: reserved for a future finer-grained "known, mechanically
  correctable" bucket (e.g. a bad flag whose correction is deterministic,
  not merely LLM-repair-eligible) — not currently produced by this
  classifier; included in the vocabulary for forward compatibility and
  because ``memfabric.types.Outcome.fixable`` already exists as a sibling
  concept.
- ``SCRIPT_ERROR``: the residual bucket — a nonzero return code that does
  not match any more specific category above. This is intentionally the
  LAST classification tried, never the first, per "do not force unrelated
  failures into the original three categories if the current architecture
  already supports more precise categories."

Was the original Nmap raw-socket failure correctly classified as
``script_error``? At the ``Outcome`` level (the level that drives whether
``RepairEngine`` is invoked) — **yes**: a corrected command (Phase 1's
``-sT`` fix) genuinely resolves it, which is exactly what
``Outcome.script_error``'s "repair eligible" semantics are for. At the
REPORT level — before this module, "script_error" was the only label
available, generic enough to also mean "syntax typo", "wrong flag value",
or any of a dozen unrelated causes. ``classify_execution_diagnostic()``
now yields the more specific ``FUNDAMENTAL`` for the exact raw-socket
marker (an environment/privilege constraint, not a simple arg fix) while
leaving the underlying ``Outcome``/repair-eligibility path untouched.
"""
from __future__ import annotations

from typing import Any

SUCCESS = "success"
SCRIPT_ERROR = "script_error"
FIXABLE = "fixable"
FUNDAMENTAL = "fundamental"
PROVIDER_ERROR = "provider_error"
POLICY_BLOCK = "policy_block"
BACKEND_ERROR = "backend_error"
TIMEOUT = "timeout"
CAPABILITY_MISSING = "capability_missing"

#: The complete, fixed diagnostic-category vocabulary — never an open string.
DIAGNOSTIC_CATEGORIES: tuple[str, ...] = (
    SUCCESS, SCRIPT_ERROR, FIXABLE, FUNDAMENTAL, PROVIDER_ERROR,
    POLICY_BLOCK, BACKEND_ERROR, TIMEOUT, CAPABILITY_MISSING,
)

#: Message substrings (checked case-insensitively) indicating a
#: transport/environment failure below the tool's own application logic —
#: command not found, or the network/host was unreachable.
_BACKEND_ERROR_MARKERS: tuple[str, ...] = (
    "not found in path", "no such file", "command not found",
    "connection refused", "network unreachable", "network is unreachable",
    "name or service not known", "nodename nor servname",
    "failed to establish a new connection", "no route to host",
)

#: Message substrings indicating the executor's own timeout fired, for
#: callers that only set ``tr["error"]`` rather than ``tr["timed_out"]``.
_TIMEOUT_MARKERS: tuple[str, ...] = ("timed out", "timeout")

#: A tool-specific fine-grained classifier (currently only
#: ``apex_host.parsers.nmap_parser.classify_nmap_error``, Phase 1) may
#: already have populated ``tr["error_category"]`` with a more precise
#: label than a generic returncode check could produce. This maps those
#: known tool-specific labels onto the unified diagnostic vocabulary.
_TOOL_ERROR_CATEGORY_MAP: dict[str, str] = {
    "raw_socket_permission_denied": FUNDAMENTAL,
    "nmap_execution_failed": SCRIPT_ERROR,
}


def classify_execution_diagnostic(tr: dict[str, Any]) -> str:
    """Classify one dispatcher tool-result dict into a single diagnostic
    category from :data:`DIAGNOSTIC_CATEGORIES`. Never raises. Order of
    checks (first match wins) is deliberate — see module docstring for
    the boundary each category represents.
    """
    if tr.get("policy_blocked"):
        return POLICY_BLOCK
    if tr.get("llm_error_category"):
        return PROVIDER_ERROR
    if tr.get("connected") is False:
        return CAPABILITY_MISSING
    if tr.get("timed_out"):
        return TIMEOUT

    error = tr.get("error")
    returncode = tr.get("returncode")
    tool_category = str(tr.get("error_category") or "")

    if not error and returncode in (0, None):
        return SUCCESS

    err_lower = str(error or "").lower()
    if any(marker in err_lower for marker in _TIMEOUT_MARKERS):
        return TIMEOUT
    if any(marker in err_lower for marker in _BACKEND_ERROR_MARKERS):
        return BACKEND_ERROR

    if tool_category in _TOOL_ERROR_CATEGORY_MAP:
        return _TOOL_ERROR_CATEGORY_MAP[tool_category]

    if error:
        # A transport-level exception occurred (raised below the tool's
        # own application logic) but did not match a known marker above.
        return BACKEND_ERROR

    if returncode not in (0, None):
        return SCRIPT_ERROR

    return FUNDAMENTAL
