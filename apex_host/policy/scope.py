# scope.py
# Domain-neutral target normalization and policy scope matching: authorizes a URL/host target by its normalized host (and optionally its permitted port) — never by prefix or substring.
"""Target normalization and scope matching for the policy layer.

This is the single, authoritative helper the policy rules use to decide
whether a task's ``target`` field is inside the engagement scope. It exists
because a scope is expressed as a set of authorized *hosts* (normally one —
``config.target``), while a task's target may legitimately be a full HTTP(S)
URL for the same host (e.g. ``http://10.129.75.42/robots.txt`` for the
authorized host ``10.129.75.42``). A raw string ``in allowed_targets``
comparison wrongly rejects those equivalent URLs.

Normalization rules
-------------------
- A bare IPv4/IPv6 address or hostname is a **host-only** target (no scheme,
  no port). IPs are canonicalized (``ipaddress.ip_address(...).compressed``);
  hostnames are lowercased with a single trailing FQDN dot stripped.
- An ``http``/``https`` URL is parsed with :func:`urllib.parse.urlsplit`. Its
  hostname (userinfo and port stripped by the parser) is canonicalized the
  same way; the port is the URL's explicit port, or the scheme default
  (80/443); the path/query are retained for reporting but never affect host
  authorization.
- Bracketed IPv6 URLs (``http://[::1]:8080/``) are supported — ``urlsplit``
  yields the un-bracketed host.

Rejected (``normalize_target`` returns ``None`` → the caller treats the
target as out of scope):
- unsupported schemes (``ftp://``, ``file://``, ...);
- credential-bearing URLs (any userinfo / ``user@host`` / ``user:pass@host``);
- URLs with no host (``http:///path``);
- malformed URLs (unbalanced brackets, invalid port);
- bare targets that carry a path/query/userinfo (a bare-host field must be a
  host, not a URL fragment).

Scope matching is by **normalized host equality only** — never a prefix or
substring test — so authorizing ``10.129.75.42`` never authorizes
``10.129.75.43``, ``10.129.75.42.evil.example``, or ``evil.example`` (with the
IP merely in its path/query). When ``allowed_ports`` is supplied, a URL whose
port is not permitted is out of scope even if its host is authorized.

This module is domain-neutral (no cybersecurity specifics) and lives in
``apex_host`` — ``memfabric`` is unchanged.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

_HTTP_SCHEMES: frozenset[str] = frozenset({"http", "https"})
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    """A parsed, canonicalized target.

    ``host`` is the canonical comparison key (compressed IP, or lowercased
    hostname). ``scheme`` is ``""`` for a bare host/IP, else ``http``/
    ``https``. ``port`` is the explicit or scheme-default port for a URL, or
    ``None`` for a bare host. ``path``/``query`` are retained for reporting
    only and never affect authorization.
    """

    raw: str
    host: str
    scheme: str
    port: int | None
    path: str
    query: str


@dataclass(frozen=True, slots=True)
class ScopeMatch:
    """Result of a scope check. ``allowed`` is the decision; ``reason`` is a
    human-readable explanation; ``normalized`` is the parsed target (``None``
    when the target could not be normalized)."""

    allowed: bool
    reason: str
    normalized: NormalizedTarget | None


def _canonical_host(host: str | None) -> str | None:
    """Return a canonical comparison key for *host*, or ``None`` if empty.

    IP literals are compressed to their canonical form; hostnames are
    lowercased with a single trailing FQDN-root dot removed. Never raises.
    """
    if not host:
        return None
    candidate = host.strip()
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        normalized = candidate.rstrip(".").lower()
        return normalized or None


def normalize_target(raw: str | None) -> NormalizedTarget | None:
    """Parse *raw* into a :class:`NormalizedTarget`, or ``None`` if it is
    empty, malformed, credential-bearing, host-less, or uses an unsupported
    scheme (see the module docstring for the full rule set)."""
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None

    if "://" in value:
        try:
            parts = urlsplit(value)
        except ValueError:
            return None
        scheme = parts.scheme.lower()
        if scheme not in _HTTP_SCHEMES:
            return None
        # Reject any credential-bearing URL. Check the netloc for '@' directly
        # (defense in depth) in addition to the parsed username/password —
        # a URL must never smuggle authorization via userinfo.
        if "@" in parts.netloc:
            return None
        try:
            if parts.username is not None or parts.password is not None:
                return None
            hostname = parts.hostname
            port = parts.port
        except ValueError:
            return None
        canon = _canonical_host(hostname)
        if canon is None:
            return None
        if port is None:
            port = _DEFAULT_PORTS[scheme]
        if port < 0 or port > 65535:
            return None
        return NormalizedTarget(
            raw=value, host=canon, scheme=scheme, port=port,
            path=parts.path, query=parts.query,
        )

    # Bare host / IP (no scheme). A bare-host field must be exactly a host —
    # a path/query/userinfo means the caller sent a URL fragment in the wrong
    # form, which is rejected rather than silently accepted. (An IPv6 literal
    # legitimately contains ':' and is handled by _canonical_host below.)
    if "@" in value or "/" in value or "?" in value:
        return None
    canon = _canonical_host(value)
    if canon is None:
        return None
    return NormalizedTarget(raw=value, host=canon, scheme="", port=None, path="", query="")


def canonical_allowed_hosts(allowed_targets: Iterable[str]) -> frozenset[str]:
    """Normalize each authorized target to its canonical host key. Targets
    that cannot be normalized are dropped (they can never match anything)."""
    hosts: set[str] = set()
    for target in allowed_targets:
        normalized = normalize_target(target)
        if normalized is not None:
            hosts.add(normalized.host)
    return frozenset(hosts)


def resolve_pin_authorizes(
    target_host: str,
    args: Iterable[object],
    allowed_targets: Iterable[str],
    *,
    allowed_ports: Iterable[int] | None = None,
) -> bool:
    """True iff a ``curl --resolve <host>:<port>:<addr>`` entry in *args* pins
    *target_host* to an **authorized** IP (a host in *allowed_targets*).

    This is what makes a name-based virtual-host fetch in scope: the request's
    real network destination is the pinned address, not a DNS lookup of the
    (possibly off-scope-looking) vhost name. Authorization therefore follows
    the pinned address, which must be an already-authorized host, and — when
    the policy restricts ports — the pinned port must be permitted. A pin to a
    non-authorized address (or a malformed entry) authorizes nothing.
    """
    canon_target = _canonical_host(target_host)
    if canon_target is None:
        return False
    allowed_hosts = canonical_allowed_hosts(allowed_targets)
    permitted_ports = frozenset(allowed_ports) if allowed_ports is not None else None
    tokens = [str(a) for a in args]
    for i, tok in enumerate(tokens):
        if tok != "--resolve" or i + 1 >= len(tokens):
            continue
        # curl --resolve format: <host>:<port>:<address>
        bits = tokens[i + 1].split(":", 2)
        if len(bits) != 3:
            continue
        pin_host, pin_port, pin_addr = bits
        if _canonical_host(pin_host) != canon_target:
            continue
        if not pin_port.isdigit():
            continue
        if permitted_ports is not None and int(pin_port) not in permitted_ports:
            continue
        # The pinned address (IPv6 may be bracketed) must be an authorized host.
        addr = _canonical_host(pin_addr.strip().strip("[]"))
        if addr is not None and addr in allowed_hosts:
            return True
    return False


def target_in_scope(
    raw_target: str,
    allowed_targets: Iterable[str],
    *,
    allowed_ports: Iterable[int] | None = None,
) -> ScopeMatch:
    """Return whether *raw_target* is inside the scope defined by
    *allowed_targets* (a set of authorized host identifiers).

    Authorization is by normalized host equality only (never prefix/substring)
    and, when *allowed_ports* is given, by permitted port. A target that
    cannot be normalized (malformed, credential-bearing, unsupported scheme,
    host-less) is out of scope.
    """
    normalized = normalize_target(raw_target)
    if normalized is None:
        return ScopeMatch(
            allowed=False,
            reason=(
                f"target {raw_target!r} is malformed, credential-bearing, "
                "host-less, or uses an unsupported scheme"
            ),
            normalized=None,
        )

    allowed_hosts = canonical_allowed_hosts(allowed_targets)
    if normalized.host not in allowed_hosts:
        return ScopeMatch(
            allowed=False,
            reason=(
                f"target host {normalized.host!r} (from {raw_target!r}) is not in "
                f"the allowed scope {sorted(allowed_hosts)}"
            ),
            normalized=normalized,
        )

    if allowed_ports is not None and normalized.port is not None:
        permitted = frozenset(allowed_ports)
        if normalized.port not in permitted:
            return ScopeMatch(
                allowed=False,
                reason=(
                    f"target port {normalized.port} (from {raw_target!r}) is not in "
                    f"the permitted ports {sorted(permitted)}"
                ),
                normalized=normalized,
            )

    return ScopeMatch(allowed=True, reason="target in scope", normalized=normalized)
