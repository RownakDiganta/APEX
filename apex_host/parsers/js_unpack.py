# js_unpack.py
# Generic, execution-free unpacker for Dean Edwards p,a,c,k,e,d packed JavaScript (§28.33).
"""Reveal the literal strings hidden by the ``eval(function(p,a,c,k,e,d){…})``
JavaScript packer, WITHOUT executing the JavaScript (§28.33).

This is a GENERIC, domain-agnostic transform — it reimplements the packer's own
base-N word-substitution algorithm as pure string manipulation. It never calls
``eval``/``exec``, never runs a JS engine, and contains NO machine-specific
mapping: the revealed strings come entirely from the packed input's OWN keyword
array, exactly as the packer itself would substitute them at runtime. Unpacking
a packer block is the same class of operation as base64-decoding — it turns an
encoded literal back into the literal it encodes, so the existing static
``JSParser`` extractors can read the API-endpoint paths inside.

Bounded and fail-safe: malformed input never raises; anything unparseable is
skipped and the caller keeps whatever it already had.
"""
from __future__ import annotations

import re

#: The packer's own digit alphabet: ``c.toString(36)`` yields ``0-9a-z`` for
#: values 0-35, and the packer maps 36-61 to ``String.fromCharCode(c+29)`` =
#: ``A-Z``. So index ``d`` -> this character.
_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

#: Cheap detector — the packer's signature function header. The 6th parameter is
#: ``d`` in the common form and ``r`` in an older variant; both are accepted.
_MARKER_RE = re.compile(
    r"function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)"
)

#: Dominant invocation form: ``'PAYLOAD',BASE,COUNT,'KW1|KW2|…'.split('|'),…``.
#: Named backrefs match the payload/keyword closing quote to their opener, so an
#: unescaped inner quote of the OTHER kind never ends the string early.
_SPLIT_FORM_RE = re.compile(
    r"(?P<pq>['\"])(?P<p>(?:\\.|(?!(?P=pq)).)*)(?P=pq)"
    r"\s*,\s*(?P<a>\d{1,3})\s*,\s*(?P<c>\d{1,7})\s*,\s*"
    r"(?P<kq>['\"])(?P<k>(?:\\.|(?!(?P=kq)).)*)(?P=kq)"
    r"\s*\.\s*split\s*\(\s*(?P<dq>['\"])(?P<delim>[^'\"]{0,2})(?P=dq)\s*\)",
    re.DOTALL,
)

#: Array-literal keyword form: ``'PAYLOAD',BASE,COUNT,['KW1','KW2',…]``.
_ARRAY_FORM_RE = re.compile(
    r"(?P<pq>['\"])(?P<p>(?:\\.|(?!(?P=pq)).)*)(?P=pq)"
    r"\s*,\s*(?P<a>\d{1,3})\s*,\s*(?P<c>\d{1,7})\s*,\s*\[(?P<k>[^\]]*)\]",
    re.DOTALL,
)

#: Safety bounds — a JS bundle can be large; never do unbounded work.
_MAX_BLOCKS = 8
_MAX_COUNT = 100_000
_MAX_INPUT = 2_000_000

_ARRAY_ELEM_RE = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""")


def _unescape(s: str) -> str:
    """Undo the handful of backslash escapes that appear in a packed literal.

    Deliberately minimal (not a full JS string decoder): the packed payload and
    keyword strings only ever contain escaped quotes, escaped backslashes, and
    (occasionally) escaped forward slashes.
    """
    return (
        s.replace("\\\\", "\x00")
        .replace("\\/", "/")
        .replace("\\'", "'")
        .replace('\\"', '"')
        .replace("\x00", "\\")
    )


def _encode(n: int, base: int) -> str:
    """The packer's token for keyword index ``n`` in the given radix."""
    if n == 0:
        return "0"
    out: list[str] = []
    while n > 0:
        out.append(_ALPHABET[n % base])
        n //= base
    return "".join(reversed(out))


def _unpack_one(payload: str, base: int, count: int, keywords: list[str]) -> str:
    """Apply the packer's whole-word token -> keyword substitution to *payload*.

    Iterates highest index first (the packer's ``while(c--)`` order) and only
    substitutes a non-empty keyword, mirroring its ``if(k[c])`` guard.
    """
    limit = min(count, len(keywords))
    for i in range(limit - 1, -1, -1):
        kw = keywords[i]
        if not kw:
            continue
        token = _encode(i, base)

        # A function replacement avoids re interpreting backslashes/group refs in
        # kw. ``\b<token>\b`` — token is alphanumeric, so word boundaries
        # reproduce the packer's own ``new RegExp('\\b'+e(c)+'\\b','g')``.
        def _repl(_m: re.Match[str], _kw: str = kw) -> str:
            return _kw

        payload = re.sub(r"\b" + re.escape(token) + r"\b", _repl, payload)
    return payload


def _parse_array(body: str) -> list[str]:
    return [_unescape(m.group(2)) for m in _ARRAY_ELEM_RE.finditer(body)]


def is_packed(text: str) -> bool:
    """True if *text* contains a Dean Edwards packer block."""
    return bool(text) and len(text) <= _MAX_INPUT and _MARKER_RE.search(text) is not None


def unpack_payloads(text: str) -> list[str]:
    """Return the unpacked payload string of each packer block in *text*.

    Empty list when *text* is not packed or nothing could be safely decoded.
    Never raises — a malformed block is skipped, not fatal.
    """
    if not is_packed(text):
        return []
    results: list[str] = []
    for rx, is_split in ((_SPLIT_FORM_RE, True), (_ARRAY_FORM_RE, False)):
        for m in rx.finditer(text):
            if len(results) >= _MAX_BLOCKS:
                break
            try:
                base = int(m.group("a"))
                count = int(m.group("c"))
                if base < 2 or base > 62 or count <= 0 or count > _MAX_COUNT:
                    continue
                payload = _unescape(m.group("p"))
                if is_split:
                    delim = m.group("delim") or "|"
                    keywords = _unescape(m.group("k")).split(delim)
                else:
                    keywords = _parse_array(m.group("k"))
                if not keywords:
                    continue
                results.append(_unpack_one(payload, base, count, keywords))
            except (ValueError, re.error):
                continue
    return results
