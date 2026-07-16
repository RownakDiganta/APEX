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
