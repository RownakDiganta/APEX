# phase_gates.py
# Pure evidence gates for the authoritative phase-transition decision (GlobalPlanner): whether an actionable credential hypothesis exists (never merely a credential-validation capability), and whether web discovery has produced meaningful evidence — each with a typed reason for reporting.
"""Evidence prerequisites for entering/remaining in a phase.

The single authoritative phase-transition path is
``apex_host.planners.global_planner.GlobalPlanner.decide_phase``. This module
supplies the two evidence gates that path consults, as pure functions over a
``SubgraphView`` (blackboard model — no I/O, no config mutation, no secrets):

- :func:`credential_hypothesis` — is credential validation *actionable*? The
  mere presence of a credential-validation **capability** (a service that
  *could* be logged into) does **not** make it actionable. A bounded
  credential *hypothesis* must exist, from one of four evidence sources:
  operator-supplied username/password, discovered credential evidence, a
  policy-permitted default-credential hypothesis, or a structured
  authentication-bypass opportunity supported by evidence. When none exists
  the reason is the typed constant :data:`MISSING_CREDENTIAL_HYPOTHESIS`.

- :func:`web_evidence_status` — has web discovery produced *meaningful*
  evidence (a successfully fetched page, a form/technology/opportunity, or a
  structured result), as opposed to merely having *attempted* web tasks? A
  policy-blocked or execution-failed request produces no such evidence and
  never counts. A bare ``endpoint`` node from a discovered-but-unfetched link
  is not meaningful evidence either.

Neither function decides a phase; ``GlobalPlanner`` combines their booleans
with the per-phase budgets. This keeps "which node types signal progress"
in one auditable place.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from memfabric.types import SubgraphView

# ---------------------------------------------------------------------------
# Credential-hypothesis sources / typed reasons
# ---------------------------------------------------------------------------

CREDENTIAL_SOURCE_OPERATOR = "operator_supplied"
CREDENTIAL_SOURCE_DISCOVERED = "discovered_evidence"
CREDENTIAL_SOURCE_POLICY_DEFAULT = "policy_default"
CREDENTIAL_SOURCE_AUTH_BYPASS = "auth_bypass_opportunity"
CREDENTIAL_SOURCE_NONE = "none"

#: Typed reason emitted when the credential phase is unavailable — a
#: credential-validation capability may be present, but no bounded credential
#: hypothesis exists to act on.
MISSING_CREDENTIAL_HYPOTHESIS = "missing_credential_hypothesis"

# A ``credential`` node marked as *discovered* (found in a config file, banner,
# leak, ...) rather than produced as an attempt record by ``AccessParser``.
# Normal attempt-record credential nodes never carry these markers, so this
# never false-fires on a prior failed login.
_DISCOVERED_CREDENTIAL_SOURCES = frozenset({"discovered", "found", "leaked", "leak"})

# ``web_opportunity`` categories that represent a structured *bypass*
# (evidence that access may be obtainable without a password) — distinct from
# an ``authentication_portal`` (a login form, which is an auth *surface* that
# still REQUIRES credentials and must not, by itself, satisfy the hypothesis).
_AUTH_BYPASS_CATEGORIES = frozenset({"auth_bypass", "authentication_bypass", "default_credentials"})


@dataclass(frozen=True, slots=True)
class CredentialHypothesis:
    """Whether credential validation is actionable, and why.

    ``source`` is one of the ``CREDENTIAL_SOURCE_*`` constants; ``reason`` is a
    short, secret-free explanation (never a username or password value)."""

    available: bool
    source: str
    reason: str


def _has_discovered_credentials(subgraph: "SubgraphView") -> bool:
    for n in subgraph.nodes:
        if n.type != "credential":
            continue
        if n.props.get("discovered") is True:
            return True
        if str(n.props.get("source", "")).strip().lower() in _DISCOVERED_CREDENTIAL_SOURCES:
            return True
    return False


def _has_auth_bypass_opportunity(subgraph: "SubgraphView") -> bool:
    for n in subgraph.nodes:
        if n.type == "web_opportunity" and str(n.props.get("category", "")).strip().lower() in _AUTH_BYPASS_CATEGORIES:
            return True
    return False


def credential_hypothesis(
    subgraph: "SubgraphView",
    *,
    has_operator_credentials: bool,
    allow_default_credentials: bool = False,
) -> CredentialHypothesis:
    """Return whether at least one bounded credential hypothesis exists.

    Checked in a fixed order (operator > discovered > policy-default >
    auth-bypass) so ``source`` is deterministic. The presence of a
    credential-validation *capability* is deliberately NOT consulted here — a
    capability is a surface, not an actionable input.
    """
    if has_operator_credentials:
        return CredentialHypothesis(
            True, CREDENTIAL_SOURCE_OPERATOR,
            "operator-supplied username/password configured",
        )
    if _has_discovered_credentials(subgraph):
        return CredentialHypothesis(
            True, CREDENTIAL_SOURCE_DISCOVERED,
            "credential evidence discovered in the EKG",
        )
    if allow_default_credentials:
        return CredentialHypothesis(
            True, CREDENTIAL_SOURCE_POLICY_DEFAULT,
            "policy-permitted default-credential hypothesis enabled",
        )
    if _has_auth_bypass_opportunity(subgraph):
        return CredentialHypothesis(
            True, CREDENTIAL_SOURCE_AUTH_BYPASS,
            "structured authentication-bypass opportunity present",
        )
    return CredentialHypothesis(False, CREDENTIAL_SOURCE_NONE, MISSING_CREDENTIAL_HYPOTHESIS)


# ---------------------------------------------------------------------------
# Web-evidence gate
# ---------------------------------------------------------------------------

WEB_EVIDENCE_NONE = "no_web_content_evidence"
WEB_EVIDENCE_CONTENT = "page_content_fetched"
WEB_EVIDENCE_STRUCTURED = "structured_web_evidence"
WEB_EVIDENCE_NO_CAPABILITY = "no_web_capability"
# §28.13 — discovered (enumerated) endpoints remain unfetched: a productive
# fetch action is still available, so the web phase is NOT complete yet.
WEB_EVIDENCE_PENDING_ENDPOINTS = "unfetched_discovered_endpoints"


@dataclass(frozen=True, slots=True)
class WebEvidence:
    """Whether web discovery has produced meaningful evidence, and why."""

    complete: bool
    reason: str


def _endpoint_url_host(url: str) -> str:
    """Lowercased host of an endpoint URL (``http://host/path`` → ``host``)."""
    return (urlsplit(url).hostname or "").strip().lower()


def _has_web_content(subgraph: "SubgraphView") -> bool:
    """True when the EKG holds meaningful web evidence — content from the REAL
    app, not a redirect stub.

    Counts: a ``form`` or ``web_opportunity`` (only produced by parsing a real
    body/browser fetch); a fetched, non-redirect ``endpoint`` (browsed, marked
    ``fetched``, or carrying a real HTTP status that is NOT a 3xx redirect); and
    (only when no vhost is known) a ``tech`` node accompanying an ``endpoint``.

    Does NOT count:
    - A BARE ``tech`` node (no endpoint present) — nmap ``-sV`` produces
      ``service``+``tech`` with no endpoint; counting it would skip the web
      phase on any versioned HTTP service (§26.3/§28.6 regression guard).
    - A **redirect-stub** endpoint — one whose only observation is a 3xx status
      (e.g. the bare IP returning ``301 → Location: http://<vhost>/``). The real
      content lives behind the vhost; the stub must NOT satisfy the web phase.
    - A ``vhost`` node on its own (§28.8 corrected) — discovering the vhost is
      *progress that requires a follow-up fetch*, NOT completion. When a vhost
      is known, ONLY a fetch of the vhost itself (an endpoint whose URL host is
      that vhost) — or a ``form``/``web_opportunity`` from it — completes the
      web phase; bare-IP endpoints are treated as redirect stubs. This is what
      forces the Host-aware ``--resolve`` fetch as the required next web action
      instead of letting the IP stub end the phase."""
    nodes = list(subgraph.nodes)
    vhost_names = {
        str(n.props.get("hostname", "")).strip().lower()
        for n in nodes
        if n.type == "vhost" and str(n.props.get("hostname", "")).strip()
    }

    # A form / web_opportunity is real content — it can only come from a
    # successful body/browser fetch of the app, never from a redirect stub.
    if any(n.type in ("form", "web_opportunity") for n in nodes):
        return True

    for n in nodes:
        if n.type != "endpoint":
            continue
        status = str(n.props.get("status", "")).strip()
        if status.startswith("3"):
            continue  # a redirect stub is not meaningful content on its own
        fetched = (
            n.props.get("browsed") is True
            or n.props.get("fetched") is True
            or status.isdigit()
        )
        if not fetched:
            continue
        # When a vhost is known, the bare-IP endpoints are redirect stubs — only
        # a fetch of the vhost itself is the real app's content.
        if vhost_names and _endpoint_url_host(str(n.props.get("url", ""))) not in vhost_names:
            continue
        return True

    # tech+endpoint fingerprinting counts only when no vhost redirect is in play
    # (with a vhost, the stub's Server-header tech must not end the phase before
    # the real app behind the vhost is fetched).
    if not vhost_names:
        has_endpoint = any(n.type == "endpoint" for n in nodes)
        if has_endpoint and any(n.type == "tech" for n in nodes):
            return True
    return False


def web_evidence_status(
    subgraph: "SubgraphView", *, has_web_capability: bool = True,
) -> WebEvidence:
    """Return whether web discovery is *complete enough* to leave the web
    phase. ``has_web_capability=False`` (no HTTP/HTTPS surface) is trivially
    complete — there is nothing to fetch. A terminal, budget-exhausted
    inability to make further web progress is handled by ``GlobalPlanner``
    (not here), since it depends on the turn budget, not the EKG."""
    from apex_host.planners.web_opportunities import pending_js_assets, pending_page_fetches

    if not has_web_capability:
        return WebEvidence(True, WEB_EVIDENCE_NO_CAPABILITY)
    # §28.13, §28.24 — while there is a discovered-but-unfetched PAGE (enumeration
    # hit, relative-link page, or JS-referenced /api path) or an unanalyzed JS
    # asset, the web phase is NOT complete: fetching/parsing it is a productive
    # next action, so the loop must not end (never mark complete with a
    # high-signal discovery outstanding — e.g. /invite's JS still unanalyzed).
    # GlobalPlanner's web-budget exhaustion still force-advances if the budget
    # runs out, so this can never loop forever.
    if pending_page_fetches(subgraph) or pending_js_assets(subgraph):
        return WebEvidence(False, WEB_EVIDENCE_PENDING_ENDPOINTS)
    if _has_web_content(subgraph):
        return WebEvidence(True, WEB_EVIDENCE_CONTENT)
    return WebEvidence(False, WEB_EVIDENCE_NONE)
