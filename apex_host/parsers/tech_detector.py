# tech_detector.py
# Deterministic, no-fingerprinting-tool technology detection from HTTP headers, HTML markers, and URL patterns.
"""Deterministic web technology detection (Phase 14).

Every function here is pure — no I/O, no network, no fingerprinting tool
(no WhatWeb/Wappalyzer/nmap `-sV` scripts). Detection is entirely
regex/substring matching over data APEX has already collected (HTTP
response headers, an HTML body excerpt, and the request URL). This module
answers "what does this response look like it is running", never "let me
go probe further to confirm" — it makes no additional request of its own.

Confidence tiers (deliberately conservative, never claiming certainty from
a weak signal):
    header match  -> 0.85  (a `Server`/`X-Powered-By` header is a direct claim)
    html marker    -> 0.6   (a path/string fragment is suggestive, not proof)
    url pattern    -> 0.4   (weakest signal — a `.php` extension or `/wp-admin`
                             path is common but not definitive)

``detect_technologies()`` merges all three channels and deduplicates by
name, keeping the highest-confidence finding for each.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_HEADER_CONFIDENCE = 0.85
_HTML_CONFIDENCE = 0.6
_URL_CONFIDENCE = 0.4


@dataclass(slots=True, frozen=True)
class TechFinding:
    """One detected technology — a plain, evidence-carrying record.

    ``version`` is ``""`` when no version string was recoverable from the
    matched signal (most HTML/URL markers never carry one; only a handful
    of headers do).
    """
    name: str
    version: str
    confidence: float
    source: str  # "header" | "html" | "url"
    excerpt: str = ""


# ---------------------------------------------------------------------------
# Header-based detection
# ---------------------------------------------------------------------------

_SERVER_PRODUCT_RE = re.compile(r"^(?P<product>[A-Za-z][^\s/(]*)(?:/(?P<version>[\d.]+))?")

# Server header product name -> canonical technology name (case-insensitive
# match on the leading product token).
_SERVER_PRODUCT_MAP: dict[str, str] = {
    "apache": "Apache",
    "nginx": "nginx",
    "microsoft-iis": "IIS",
    "werkzeug": "Flask",
}


def detect_from_headers(headers: dict[str, str]) -> list[TechFinding]:
    """Detect technologies from HTTP response headers only.

    Recognises: Apache / nginx / IIS / Werkzeug(Flask) via ``Server``;
    PHP / ASP.NET / Express via ``X-Powered-By``; ASP.NET via
    ``X-AspNet-Version``; PHP / ASP.NET / Django / Express via
    session-cookie name patterns in ``Set-Cookie``.
    """
    findings: list[TechFinding] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    server = lower_headers.get("server", "")
    if server:
        m = _SERVER_PRODUCT_RE.match(server.strip())
        if m:
            product = m.group("product")
            version = m.group("version") or ""
            canonical = _SERVER_PRODUCT_MAP.get(product.lower())
            if canonical:
                findings.append(TechFinding(
                    name=canonical, version=version, confidence=_HEADER_CONFIDENCE,
                    source="header", excerpt=server[:200],
                ))

    powered_by = lower_headers.get("x-powered-by", "")
    if powered_by:
        pb_lower = powered_by.lower()
        if "php" in pb_lower:
            vm = re.search(r"php/([\d.]+)", pb_lower)
            findings.append(TechFinding(
                name="PHP", version=vm.group(1) if vm else "", confidence=_HEADER_CONFIDENCE,
                source="header", excerpt=powered_by[:200],
            ))
        if "asp.net" in pb_lower:
            findings.append(TechFinding(
                name="ASP.NET", version="", confidence=_HEADER_CONFIDENCE,
                source="header", excerpt=powered_by[:200],
            ))
        if "express" in pb_lower:
            findings.append(TechFinding(
                name="Express", version="", confidence=_HEADER_CONFIDENCE,
                source="header", excerpt=powered_by[:200],
            ))

    if "x-aspnet-version" in lower_headers:
        findings.append(TechFinding(
            name="ASP.NET", version=lower_headers["x-aspnet-version"].strip(),
            confidence=_HEADER_CONFIDENCE, source="header",
            excerpt=lower_headers["x-aspnet-version"][:200],
        ))

    # Set-Cookie is scanned for a matched cookie-NAME pattern only — the
    # excerpt stored on the resulting TechFinding is a fixed, redacted
    # description, never the raw header (which carries the actual
    # session/CSRF value; storing it verbatim would leak credential-shaped
    # material into the EKG, exactly what apex_host.security.redaction
    # exists to prevent elsewhere in this project).
    set_cookie = lower_headers.get("set-cookie", "")
    if set_cookie:
        sc_lower = set_cookie.lower()
        if "phpsessid" in sc_lower:
            findings.append(TechFinding(name="PHP", version="", confidence=_HEADER_CONFIDENCE, source="header", excerpt="Set-Cookie name pattern: PHPSESSID"))
        if "asp.net_sessionid" in sc_lower:
            findings.append(TechFinding(name="ASP.NET", version="", confidence=_HEADER_CONFIDENCE, source="header", excerpt="Set-Cookie name pattern: ASP.NET_SessionId"))
        if "csrftoken" in sc_lower or ("sessionid" in sc_lower and "phpsessid" not in sc_lower):
            findings.append(TechFinding(name="Django", version="", confidence=_HEADER_CONFIDENCE, source="header", excerpt="Set-Cookie name pattern: csrftoken/sessionid"))
        if "connect.sid" in sc_lower:
            findings.append(TechFinding(name="Express", version="", confidence=_HEADER_CONFIDENCE, source="header", excerpt="Set-Cookie name pattern: connect.sid"))

    if "x-generator" in lower_headers and "drupal" in lower_headers["x-generator"].lower():
        findings.append(TechFinding(name="Drupal", version="", confidence=_HEADER_CONFIDENCE, source="header", excerpt=lower_headers["x-generator"][:200]))

    return findings


# ---------------------------------------------------------------------------
# HTML-marker-based detection
# ---------------------------------------------------------------------------

_HTML_MARKERS: tuple[tuple[str, str], ...] = (
    # (technology name, marker substring to search for, case-insensitive)
    ("WordPress", "wp-content"),
    ("WordPress", "wp-includes"),
    ("Joomla", "/components/com_"),
    ("Joomla", "joomla"),
    ("Drupal", "sites/default/files"),
    ("Drupal", "drupal.settings"),
    ("Django", "csrfmiddlewaretoken"),
)

_GENERATOR_META_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)


def detect_from_html(html: str) -> list[TechFinding]:
    """Detect technologies from HTML body markers and a generator meta tag."""
    if not html:
        return []
    findings: list[TechFinding] = []
    lower_html = html.lower()
    seen: set[str] = set()

    for name, marker in _HTML_MARKERS:
        if name in seen:
            continue
        if marker.lower() in lower_html:
            idx = lower_html.find(marker.lower())
            excerpt = html[max(0, idx - 20):idx + 40].strip()
            findings.append(TechFinding(name=name, version="", confidence=_HTML_CONFIDENCE, source="html", excerpt=excerpt[:200]))
            seen.add(name)

    gm = _GENERATOR_META_RE.search(html)
    if gm:
        content = gm.group(1).strip()
        content_lower = content.lower()
        for name in ("wordpress", "joomla", "drupal"):
            canonical = name.capitalize() if name != "wordpress" else "WordPress"
            if name in content_lower and canonical not in seen:
                findings.append(TechFinding(name=canonical, version="", confidence=_HTML_CONFIDENCE, source="html", excerpt=content[:200]))
                seen.add(canonical)

    return findings


# ---------------------------------------------------------------------------
# URL-pattern-based detection (weakest signal)
# ---------------------------------------------------------------------------

_URL_PATTERNS: tuple[tuple[str, str], ...] = (
    ("PHP", r"\.php(\?|$)"),
    ("ASP.NET", r"\.aspx?(\?|$)"),
    ("WordPress", r"/wp-admin|/wp-login\.php|/wp-json"),
    ("Joomla", r"/administrator(/|$)"),
    ("Drupal", r"/user/login|/node/\d+"),
)


def detect_from_url(url: str) -> list[TechFinding]:
    """Detect technologies from URL path/extension patterns only."""
    if not url:
        return []
    findings: list[TechFinding] = []
    seen: set[str] = set()
    for name, pattern in _URL_PATTERNS:
        if name in seen:
            continue
        if re.search(pattern, url, re.IGNORECASE):
            findings.append(TechFinding(name=name, version="", confidence=_URL_CONFIDENCE, source="url", excerpt=url[:200]))
            seen.add(name)
    return findings


# ---------------------------------------------------------------------------
# Merge + dedup
# ---------------------------------------------------------------------------

def detect_technologies(*, headers: dict[str, str] | None = None, html: str = "", url: str = "") -> list[TechFinding]:
    """Merge header/HTML/URL detection channels, keeping the
    highest-confidence finding per technology name.

    Deterministic ordering: header channel first, then HTML, then URL — a
    later, lower-confidence channel never overwrites an earlier, stronger
    finding for the same name.
    """
    all_findings = [
        *detect_from_headers(headers or {}),
        *detect_from_html(html),
        *detect_from_url(url),
    ]
    best: dict[str, TechFinding] = {}
    for f in all_findings:
        existing = best.get(f.name)
        if existing is None or f.confidence > existing.confidence:
            best[f.name] = f
    # Deterministic output ordering — alphabetical by name, never
    # insertion-order-dependent.
    return [best[name] for name in sorted(best)]
