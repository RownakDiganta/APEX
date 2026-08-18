# test_js_deobfuscation.py
# Generic (execution-free) Dean Edwards packer unpacking in the JS parser (§28.33).
from __future__ import annotations

from apex_host.parsers.js_parser import JSParser
from apex_host.parsers.js_unpack import is_packed, unpack_payloads

# The real packer function body (its content is irrelevant to the unpacker, which
# reads only the invocation arguments; included for realism). Plain string — NOT
# an f-string — so its many braces need no escaping.
_BODY = (
    "function(p,a,c,k,e,d){e=function(c){return c.toString(a)};"
    "if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}"
    "k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};"
    "while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}"
)


def _packed_split(payload: str, base: int, count: int, keywords: list[str]) -> str:
    """A valid ``'KW1|KW2|…'.split('|')`` packer invocation. `payload` is wrapped
    in single quotes, so use double quotes for any literal inside it."""
    kw = "|".join(keywords)
    return f"eval({_BODY}('{payload}',{base},{count},'{kw}'.split('|'),0,{{}}))"


def _packed_array(payload: str, base: int, count: int, keywords: list[str]) -> str:
    arr = ",".join(f"'{k}'" for k in keywords)
    return f"eval({_BODY}('{payload}',{base},{count},[{arr}],0,{{}}))"


# base 36 tokens: encode(i) is the plain base-36 digit for i<36, so index 7 -> '7'.
# payload `7:"/1/2/3/4/5/6"` with the keyword array below unpacks to
# `url:"/api/v1/invite/how/to/generate"`.
_KEYWORDS = ["console", "api", "v1", "invite", "how", "to", "generate", "url"]
_PAYLOAD = '7:"/1/2/3/4/5/6"'
_EXPECTED_URL = "/api/v1/invite/how/to/generate"


class TestUnpacker:
    def test_detects_packed_js(self) -> None:
        assert is_packed(_packed_split(_PAYLOAD, 36, 8, _KEYWORDS)) is True

    def test_normal_js_not_detected(self) -> None:
        assert is_packed('function t(){return "/api/test";}') is False
        assert is_packed("") is False

    def test_unpacks_to_the_hidden_url_split_form(self) -> None:
        out = unpack_payloads(_packed_split(_PAYLOAD, 36, 8, _KEYWORDS))
        assert len(out) == 1
        assert _EXPECTED_URL in out[0]
        assert 'url:"' in out[0]

    def test_unpacks_array_keyword_form(self) -> None:
        out = unpack_payloads(_packed_array(_PAYLOAD, 36, 8, _KEYWORDS))
        assert out and _EXPECTED_URL in out[0]

    def test_non_default_base_24(self) -> None:
        # base 24: index 23 -> 'n' (10->'a' … 23->'n'). payload token 'n' resolves
        # to keyword[23]. Build a keyword array where index 23 is the URL.
        kws = [""] * 24
        kws[1] = "url"
        kws[23] = "/api/v1/x"
        out = unpack_payloads(_packed_split('1:"n"', 24, 24, kws))
        assert out and "/api/v1/x" in out[0]

    def test_malformed_never_raises(self) -> None:
        # Marker present but the invocation is garbage — returns [], no exception.
        assert unpack_payloads("eval(function(p,a,c,k,e,d){})(garbage") == []

    def test_empty_keyword_left_as_token(self) -> None:
        # An empty keyword is skipped (packer's ``if(k[c])`` guard): token stays.
        out = unpack_payloads(_packed_split('1 2', 36, 3, ["", "api", ""]))
        assert out == ["api 2"]


class TestParseJsDeobfuscation:
    def _urls(self, obs) -> list[str]:
        return [n.props.get("url") for n in obs.node_deltas if n.type == "endpoint"]

    def test_parse_js_extracts_deobfuscated_endpoint(self) -> None:
        packed = _packed_split(_PAYLOAD, 36, 8, _KEYWORDS)
        obs = JSParser().parse_js(
            packed, target="http://2million.htb/js/inviteapi.min.js", host_ip="10.129.48.197"
        )
        urls = self._urls(obs)
        assert any(_EXPECTED_URL in str(u) for u in urls), urls
        # the extracted API endpoint is reachable via a host--exposes--> edge
        api_id = next(n.id for n in obs.node_deltas
                      if n.type == "endpoint" and _EXPECTED_URL in str(n.props.get("url")))
        exposes = {(e.from_id, e.to_id) for e in obs.edge_deltas if e.type == "exposes"}
        assert ("host:10.129.48.197", api_id) in exposes
        # the JS node is flagged as deobfuscated
        js_node = next(n for n in obs.node_deltas if n.props.get("js_asset"))
        assert js_node.props.get("js_deobfuscated") is True

    def test_parse_js_normal_js_still_extracts_and_not_flagged(self) -> None:
        normal = 'function t(){$.ajax({url:"/api/v1/status"})}'
        obs = JSParser().parse_js(
            normal, target="http://2million.htb/js/app.js", host_ip="10.129.48.197"
        )
        assert any("/api/v1/status" in str(u) for u in self._urls(obs))
        js_node = next(n for n in obs.node_deltas if n.props.get("js_asset"))
        assert "js_deobfuscated" not in js_node.props

    def test_html_served_as_js_is_not_unpacked(self) -> None:
        # §28.27 — an HTML body (starts with '<') that happens to contain a packer
        # marker is never unpacked and yields no API endpoints.
        html = "<html><body><script>eval(function(p,a,c,k,e,d){})('x',36,1,''.split('|'))</script></body></html>"
        obs = JSParser().parse_js(
            html, target="http://2million.htb/js/broken.js", host_ip="10.129.48.197"
        )
        api = [n for n in obs.node_deltas if n.type == "endpoint" and not n.props.get("js_asset")]
        assert api == []
        js_node = next(n for n in obs.node_deltas if n.props.get("js_asset"))
        assert "js_deobfuscated" not in js_node.props
