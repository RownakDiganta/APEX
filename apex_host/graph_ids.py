# graph_ids.py
# Centralized canonical EKG node/edge ID builders and URL normalization for apex_host.
"""Centralized EKG identity functions for apex_host.

This is the **sole** location where EKG node and edge IDs are constructed.
No parser, executor, or planner may build IDs with inline f-strings — they
must call the functions here.  This prevents ID-format drift across parsers
and makes the ID scheme explicit and testable.

Schema versioning
-----------------
``EKG_SCHEMA_VERSION`` is incremented whenever an ID-construction function
changes in a way that would produce different IDs for the same semantic
entity.  Exporters embed this field so downstream consumers can detect
compatibility breaks.

URL normalization
-----------------
``_normalize_endpoint_url(url)`` and its public callers (``endpoint_id``,
``auth_flow_id``, ``form_id``, ``token_id``) normalise URLs before
embedding them in node IDs so that ``http://host/`` and ``http://host``
produce the same ID.  Rules:

1. Lowercase scheme and host.
2. Strip default ports (`:80` after ``http://``, ``:443`` after ``https://``).
3. Collapse ``//`` path runs (after the authority) to a single ``/``.
4. Strip a trailing ``/`` from the path **unless** the path is the root
   (scheme + host + ``/`` with no further segments).

Tech node scoping
-----------------
``tech_id(host_addr, tech_name)`` produces **host-scoped** tech nodes so
that two different hosts running OpenSSH get separate EKG nodes.  This
reflects the reality that the installation (and its version/config) is
host-specific.
"""
from __future__ import annotations

import re
import urllib.parse

EKG_SCHEMA_VERSION: str = "1"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_MULTI_SLASH_RE = re.compile(r"(?<=[^:/])//+")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def _slug(name: str) -> str:
    """Lowercase alphanumeric slug, spaces/dots/dashes collapsed to '-'."""
    return _NON_ALNUM_RE.sub("-", name.strip().lower()).strip("-")


def _normalize_endpoint_url(url: str) -> str:
    """Return a canonical form of *url* for use in EKG node IDs.

    Rules applied in order:
    1. Lowercase scheme and netloc (host + port).
    2. Strip default port (':80' for http, ':443' for https).
    3. Collapse multiple consecutive slashes in the path (but not in the
       authority — ``http://`` is never touched).
    4. Strip a trailing slash from the path unless the path is exactly ``/``
       (i.e., the root path — ``http://host/`` keeps its slash).

    Examples::

        http://HOST/        → http://host/
        http://host:80/     → http://host/
        https://host:443/   → https://host/
        http://host:8080/   → http://host:8080/    (non-default port kept)
        http://host/a//b    → http://host/a/b
        http://host/path/   → http://host/path     (trailing slash stripped)
        http://host/        → http://host/          (root path kept)
    """
    if not url:
        return url
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return url

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    # Normalise path: collapse double slashes, strip trailing slash unless root
    path = parsed.path
    path = _MULTI_SLASH_RE.sub("/", path)
    if path not in ("", "/") and path.endswith("/"):
        path = path.rstrip("/")

    # Reassemble — preserve query and fragment so relative URL identity
    # comparisons still work if callers pass full URLs with query strings.
    normalized = urllib.parse.urlunparse(
        (scheme, netloc, path, parsed.params, parsed.query, parsed.fragment)
    )
    return normalized


# ---------------------------------------------------------------------------
# Node ID builders
# ---------------------------------------------------------------------------

def host_id(ip: str) -> str:
    """Canonical ID for a host node.

    >>> host_id("10.10.10.14")
    'host:10.10.10.14'
    """
    return f"host:{ip}"


def service_id(ip: str, port: str | int, proto: str = "tcp") -> str:
    """Canonical ID for a service node.

    >>> service_id("10.10.10.14", 23, "tcp")
    'service:10.10.10.14:23/tcp'
    """
    return f"service:{ip}:{port}/{proto}"


def tech_slug(name: str) -> str:
    """Slug form of a technology name for use in ``tech_id``.

    >>> tech_slug("OpenSSH 8.2")
    'openssh-8-2'
    """
    return _slug(name)


def tech_id(host_addr: str, tech_name: str) -> str:
    """Canonical ID for a technology node, scoped to the host.

    Two hosts running the same software get separate tech nodes because the
    installation (version, configuration) is host-specific.

    >>> tech_id("10.10.10.14", "OpenSSH")
    'tech:10.10.10.14:openssh'
    """
    return f"tech:{host_addr}:{tech_slug(tech_name)}"


def credential_id(target: str, username: str, protocol: str = "") -> str:
    """Canonical ID for a credential node.

    ``protocol`` is optional and defaults to ``""`` so existing Telnet call
    sites (``apex_host/parsers/access_parser.py::AccessParser.parse_text``)
    are byte-for-byte unchanged — this preserves Phase 12A/pre-Phase-12B EKG
    IDs and every test that hardcodes them. Phase 12B's SSH/FTP validation
    path (``AccessParser.parse_structured``) passes an explicit ``protocol``
    (``"ssh"`` / ``"ftp"``) so a credential node for one protocol never
    collides with, or is mistaken for, a node from a different protocol —
    a failed SSH attempt must never look like an unrelated FTP attempt.

    >>> credential_id("10.10.10.14", "root")
    'credential:10.10.10.14:root'
    >>> credential_id("10.10.10.14", "root", protocol="ssh")
    'credential:10.10.10.14:root:ssh'
    """
    suffix = f":{protocol}" if protocol else ""
    return f"credential:{target}:{username}{suffix}"


def access_state_id(target: str, username: str, protocol: str = "") -> str:
    """Canonical ID for an access_state node.

    See ``credential_id`` for why ``protocol`` is optional and defaults to
    ``""`` (Telnet backward compatibility).

    >>> access_state_id("10.10.10.14", "root")
    'access_state:10.10.10.14:root'
    >>> access_state_id("10.10.10.14", "root", protocol="ssh")
    'access_state:10.10.10.14:root:ssh'
    """
    suffix = f":{protocol}" if protocol else ""
    return f"access_state:{target}:{username}{suffix}"


def endpoint_id(url: str) -> str:
    """Canonical ID for an endpoint node, with URL normalization.

    >>> endpoint_id("http://host/")
    'endpoint:http://host/'
    >>> endpoint_id("http://host:80/path/")
    'endpoint:http://host/path'
    """
    return f"endpoint:{_normalize_endpoint_url(url)}"


def auth_flow_id(url: str) -> str:
    """Canonical ID for an auth_flow node.

    >>> auth_flow_id("http://host:80/login")
    'auth_flow:http://host/login'
    """
    return f"auth_flow:{_normalize_endpoint_url(url)}"


def auth_flow_form_id(url: str, form_index: int) -> str:
    """Canonical ID for an auth_flow node derived from a specific form.

    Used by BrowserParser when a form contains a password field.

    >>> auth_flow_form_id("http://host:80/login", 0)
    'auth_flow:http://host/login:0'
    """
    return f"auth_flow:{_normalize_endpoint_url(url)}:{form_index}"


def auth_flow_hint_id(url: str, hint: str) -> str:
    """Canonical ID for an auth_flow node derived from an auth hint.

    Used by BrowserParser when auth_hints are reported in the observation.

    >>> auth_flow_hint_id("http://host/", "Login")
    'auth_flow:http://host/:hint:Login'
    """
    return f"auth_flow:{_normalize_endpoint_url(url)}:hint:{hint}"


def normalize_url(url: str) -> str:
    """Public alias for ``_normalize_endpoint_url`` for callers that need it directly."""
    return _normalize_endpoint_url(url)


def form_id(url: str, form_index: int = 0) -> str:
    """Canonical ID for a form node observed at *url*.

    >>> form_id("http://host/login", 0)
    'form:http://host/login:0'
    """
    return f"form:{_normalize_endpoint_url(url)}:{form_index}"


def token_id(url: str, token_name: str) -> str:
    """Canonical ID for a CSRF/nonce/hidden-input token node.

    >>> token_id("http://host/", "csrf")
    'token:http://host/:csrf'
    """
    return f"token:{_normalize_endpoint_url(url)}:{token_name}"


def priv_esc_opportunity_id(target: str, category: str, discriminator: str) -> str:
    """Canonical ID for a privilege-escalation opportunity node (Phase 13).

    ``discriminator`` distinguishes multiple opportunities in the same
    category for the same target (e.g. a service+version slug for
    ``vulnerable_service``, or a username for ``sudo``/``docker`` group
    hints) — slugged the same way ``tech_id`` slugs technology names, so the
    ID is stable and dedup-safe across turns/reruns.

    >>> priv_esc_opportunity_id("10.10.10.14", "vulnerable_service", "vsftpd 2.3.4")
    'priv_esc_opportunity:10.10.10.14:vulnerable_service:vsftpd-2-3-4'
    >>> priv_esc_opportunity_id("10.10.10.14", "sudo", "sudo-group-root")
    'priv_esc_opportunity:10.10.10.14:sudo:sudo-group-root'
    """
    return f"priv_esc_opportunity:{target}:{category}:{_slug(discriminator)}"


def web_opportunity_id(target: str, category: str, discriminator: str) -> str:
    """Canonical ID for a web-exploitation-planning opportunity node (Phase 14).

    Mirrors ``priv_esc_opportunity_id`` exactly — ``discriminator``
    distinguishes multiple opportunities in the same category for the same
    target (e.g. a URL path slug for ``admin_panel``, a form-URL slug for
    ``authentication_portal``), so the ID is stable and dedup-safe across
    turns/reruns.

    >>> web_opportunity_id("10.10.10.80", "admin_panel", "http://10.10.10.80/admin")
    'web_opportunity:10.10.10.80:admin_panel:http-10-10-10-80-admin'
    """
    return f"web_opportunity:{target}:{category}:{_slug(discriminator)}"


def priv_esc_evidence_id(target: str, command_key: str, port: str = "") -> str:
    """Canonical ID for a privilege-enumeration evidence node (Phase 13B).

    ``command_key`` is the fixed enumeration-command allowlist key (e.g.
    ``"sudo_l"``, ``"suid"``) — never the raw command string — so the ID is
    stable regardless of how the command is phrased internally.

    >>> priv_esc_evidence_id("10.10.10.14", "sudo_l")
    'priv_esc_evidence:10.10.10.14:sudo-l'
    >>> priv_esc_evidence_id("10.10.10.14", "sudo_l", port="2222")
    'priv_esc_evidence:10.10.10.14:sudo-l:2222'
    """
    suffix = f":{port}" if port else ""
    return f"priv_esc_evidence:{target}:{_slug(command_key)}{suffix}"


def priv_esc_recommendation_id(opportunity_id: str) -> str:
    """Canonical ID for a recommendation node derived from *opportunity_id*.

    One recommendation per opportunity (1:1) — see
    ``apex_host/parsers/priv_esc_parser.py``.

    >>> priv_esc_recommendation_id("priv_esc_opportunity:10.10.10.14:sudo:sudo-group-root")
    'priv_esc_recommendation:priv_esc_opportunity:10.10.10.14:sudo:sudo-group-root'
    """
    return f"priv_esc_recommendation:{opportunity_id}"


# ---------------------------------------------------------------------------
# Edge ID builders
# ---------------------------------------------------------------------------

def exposes_edge_id(from_node_id: str, to_node_id: str) -> str:
    """Canonical ID for an 'exposes' edge.

    >>> exposes_edge_id("host:10.0.0.1", "service:10.0.0.1:22/tcp")
    'exposes:host:10.0.0.1:service:10.0.0.1:22/tcp'
    """
    return f"exposes:{from_node_id}:{to_node_id}"


def runs_edge_id(service_node_id: str, tech_node_id: str) -> str:
    """Canonical ID for a 'runs' edge (service → tech).

    >>> runs_edge_id("service:10.0.0.1:22/tcp", "tech:10.0.0.1:openssh")
    'runs:service:10.0.0.1:22/tcp:tech:10.0.0.1:openssh'
    """
    return f"runs:{service_node_id}:{tech_node_id}"


def grants_edge_id(from_node_id: str, to_node_id: str) -> str:
    """Canonical ID for a 'grants' edge (credential → access_state).

    >>> grants_edge_id("credential:10.0.0.1:root", "access_state:10.0.0.1:root")
    'grants:credential:10.0.0.1:root:access_state:10.0.0.1:root'
    """
    return f"grants:{from_node_id}:{to_node_id}"


def tested_edge_id(service_node_id: str, credential_node_id: str) -> str:
    """Canonical ID for a 'tested' edge (service → credential).

    >>> tested_edge_id("service:10.0.0.1:23/tcp", "credential:10.0.0.1:root")
    'tested:service:10.0.0.1:23/tcp:credential:10.0.0.1:root'
    """
    return f"tested:{service_node_id}:{credential_node_id}"


def contains_edge_id(from_node_id: str, to_node_id: str) -> str:
    """Canonical ID for a 'contains' edge (endpoint → form/token).

    >>> contains_edge_id("endpoint:http://host/", "form:http://host/:0")
    'contains:endpoint:http://host/:form:http://host/:0'
    """
    return f"contains:{from_node_id}:{to_node_id}"


def requires_edge_id(from_node_id: str, to_node_id: str) -> str:
    """Canonical ID for a 'requires' edge (endpoint → auth_flow).

    >>> requires_edge_id("endpoint:http://host/login", "auth_flow:http://host/login")
    'requires:endpoint:http://host/login:auth_flow:http://host/login'
    """
    return f"requires:{from_node_id}:{to_node_id}"


def indicates_edge_id(from_node_id: str, to_node_id: str) -> str:
    """Canonical ID for an 'indicates' edge (access_state/service → priv_esc_opportunity).

    >>> indicates_edge_id("access_state:10.0.0.1:root", "priv_esc_opportunity:10.0.0.1:sudo:sudo-group-root")
    'indicates:access_state:10.0.0.1:root:priv_esc_opportunity:10.0.0.1:sudo:sudo-group-root'
    """
    return f"indicates:{from_node_id}:{to_node_id}"


def collects_edge_id(from_node_id: str, to_node_id: str) -> str:
    """Canonical ID for a 'collects' edge (host → priv_esc_evidence, Phase 13B).

    >>> collects_edge_id("host:10.0.0.1", "priv_esc_evidence:10.0.0.1:sudo_l")
    'collects:host:10.0.0.1:priv_esc_evidence:10.0.0.1:sudo_l'
    """
    return f"collects:{from_node_id}:{to_node_id}"


def produces_edge_id(from_node_id: str, to_node_id: str) -> str:
    """Canonical ID for a 'produces' edge (priv_esc_evidence → priv_esc_opportunity, Phase 13B).

    >>> produces_edge_id("priv_esc_evidence:10.0.0.1:sudo_l", "priv_esc_opportunity:10.0.0.1:sudo:sudo-group-root")
    'produces:priv_esc_evidence:10.0.0.1:sudo_l:priv_esc_opportunity:10.0.0.1:sudo:sudo-group-root'
    """
    return f"produces:{from_node_id}:{to_node_id}"


def recommends_edge_id(from_node_id: str, to_node_id: str) -> str:
    """Canonical ID for a 'recommends' edge (priv_esc_opportunity → priv_esc_recommendation, Phase 13B;
    also reused unchanged for workflow → workflow_recommendation, Phase 15 —
    see ``workflow_recommendation_id``).

    >>> recommends_edge_id("priv_esc_opportunity:10.0.0.1:sudo:x", "priv_esc_recommendation:priv_esc_opportunity:10.0.0.1:sudo:x")
    'recommends:priv_esc_opportunity:10.0.0.1:sudo:x:priv_esc_recommendation:priv_esc_opportunity:10.0.0.1:sudo:x'
    """
    return f"recommends:{from_node_id}:{to_node_id}"


# ---------------------------------------------------------------------------
# Phase 15 — multi-step exploitation orchestration node IDs
#
# No new edge-ID builders were needed for Phase 15: ``indicates_edge_id``
# (host/step → workflow/session/opportunity), ``contains_edge_id``
# (workflow → workflow_step), and ``recommends_edge_id`` (workflow →
# workflow_recommendation, above) were already generic enough to reuse —
# mirrors the same "don't fragment the graph" discipline Phase 14 applied
# to node types. See docs/workflow-orchestration.md.
# ---------------------------------------------------------------------------

def workflow_id(target: str, workflow_key: str) -> str:
    """Canonical ID for a workflow node (Phase 15).

    Content-addressed on ``target``+``workflow_key`` only (never on step
    state) — re-deriving the same workflow always upserts the same node.

    >>> workflow_id("10.10.10.14", "credential_to_privesc")
    'workflow:10.10.10.14:credential_to_privesc'
    """
    return f"workflow:{target}:{workflow_key}"


def workflow_step_id(workflow_node_id: str, step_name: str) -> str:
    """Canonical ID for a workflow_step node, scoped to its parent workflow.

    >>> workflow_step_id("workflow:10.10.10.14:credential_to_privesc", "validate_credentials")
    'workflow_step:workflow:10.10.10.14:credential_to_privesc:validate_credentials'
    """
    return f"workflow_step:{workflow_node_id}:{step_name}"


def session_id(target: str, kind: str, discriminator: str = "") -> str:
    """Canonical ID for a session node (a planning object only — never a
    live, executable session APEX holds open).

    >>> session_id("10.10.10.14", "ssh")
    'session:10.10.10.14:ssh'
    >>> session_id("10.10.10.14", "ssh", "root")
    'session:10.10.10.14:ssh:root'
    """
    suffix = f":{_slug(discriminator)}" if discriminator else ""
    return f"session:{target}:{kind}{suffix}"


def workflow_recommendation_id(workflow_node_id: str) -> str:
    """Canonical ID for a workflow_recommendation node — one per workflow (1:1).

    >>> workflow_recommendation_id("workflow:10.10.10.14:credential_to_privesc")
    'workflow_recommendation:workflow:10.10.10.14:credential_to_privesc'
    """
    return f"workflow_recommendation:{workflow_node_id}"


# ---------------------------------------------------------------------------
# Phase 16 — adaptive learning, reflection & experience replay node IDs
#
# No new edge-ID builders were needed for Phase 16 either: ``indicates_edge_id``
# (host → experience, experience → workflow) and ``recommends_edge_id``
# (experience → experience_recommendation) were already generic enough to
# reuse — the same "don't fragment the graph" discipline Phase 14/15 applied.
# See docs/experience-replay.md.
# ---------------------------------------------------------------------------

def experience_id(target: str, category: str, discriminator: str) -> str:
    """Canonical ID for an experience node (Phase 16).

    Content-addressed on ``target``+``category``+``discriminator`` only
    (never on occurrence_count/confidence) — re-deriving the same
    experience across engagements always upserts the same node, with
    ``occurrence_count`` incremented rather than a new node created. This
    is the entire mechanism behind "experience replay": a stable ID, not a
    remembered Python object.

    >>> experience_id("10.10.10.14", "repeated_planner_mistake", "nmap:recon")
    'experience:10.10.10.14:repeated_planner_mistake:nmap-recon'
    """
    return f"experience:{target}:{category}:{_slug(discriminator)}"


def experience_recommendation_id(experience_node_id: str) -> str:
    """Canonical ID for an experience_recommendation node — one per experience (1:1).

    >>> experience_recommendation_id("experience:10.10.10.14:successful_workflow:credential_to_privesc")
    'experience_recommendation:experience:10.10.10.14:successful_workflow:credential_to_privesc'
    """
    return f"experience_recommendation:{experience_node_id}"
