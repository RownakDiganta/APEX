# test_web_depth_reachability.py
# Regression: discovered links/JS assets stay reachable to the depth-bounded planner (§28.32).
from __future__ import annotations

import pytest

from apex_host.parsers.command_parser import CommandParser
from apex_host.planners.phase_gates import web_evidence_status
from apex_host.planners.web_opportunities import (
    pending_js_assets,
    pending_page_fetches,
)
from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Edge, Node, RawObservation

_IP = "10.129.48.197"
_H = f"host:{_IP}"
_HP = "endpoint:http://2million.htb/"
_INV = "endpoint:http://2million.htb/invite"
_JS = "endpoint:http://2million.htb/js/inviteapi.min.js"
_REG = "endpoint:http://2million.htb/register"

# /invite's HTML: a script asset + a link, both same-origin (vhost 2million.htb).
_INVITE_HTML = (
    "<html><head><title>Invite</title>"
    '<script src="/js/inviteapi.min.js"></script></head>'
    '<body><a href="/register">register</a></body></html>'
)


def _node(nid: str, ntype: str, props: dict, src: str = "seed") -> Node:
    return Node(id=nid, type=ntype, props=props, confidence=0.6, source=src,
                first_seen="t", last_seen="t")


def _edge(frm: str, to: str, etype: str) -> Edge:
    return Edge(id=f"{etype}:{frm}:{to}", from_id=frm, to_id=to, type=etype,
                props={}, confidence=0.6, source="seed", first_seen="t", last_seen="t")


def _fresh_api() -> MemoryAPI:
    cfg = Config()
    return MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )


async def _seed_chain(api: MemoryAPI) -> None:
    """host -> homepage(d1) -> /invite(d2, via contains) then parse /invite's body."""
    await api.apply_deltas(
        nodes=[
            _node(_H, "host", {"ip": _IP}, "nmap"),
            _node(f"vhost:{_IP}:2million.htb", "vhost",
                  {"hostname": "2million.htb", "ip": _IP}, "curl"),
            _node(_HP, "endpoint", {"url": "http://2million.htb/", "path": "/", "fetched": True}),
            _node(_INV, "endpoint", {"url": "http://2million.htb/invite", "path": "/invite"}),
        ],
        edges=[
            _edge(_H, f"vhost:{_IP}:2million.htb", "exposes"),
            _edge(_H, _HP, "exposes"),
            _edge(_HP, _INV, "contains"),  # /invite is at depth 2 from host
        ],
    )
    obs = CommandParser().parse_curl_body(
        RawObservation(raw=_INVITE_HTML,
                       metadata={"target": "http://2million.htb/invite",
                                 "host_ip": _IP, "source": "curl_body"})
    )
    await api.apply_deltas(nodes=obs.node_deltas, edges=obs.edge_deltas)


@pytest.mark.asyncio
async def test_parse_curl_body_attaches_host_exposes_to_children() -> None:
    """The JS asset and the discovered link each get a host--exposes--> edge."""
    obs = CommandParser().parse_curl_body(
        RawObservation(raw=_INVITE_HTML,
                       metadata={"target": "http://2million.htb/invite",
                                 "host_ip": _IP, "source": "curl_body"})
    )
    exposes = {(e.from_id, e.to_id) for e in obs.edge_deltas if e.type == "exposes"}
    assert (_H, _JS) in exposes, "JS asset must be exposed by the authorized host"
    assert (_H, _REG) in exposes, "discovered link must be exposed by the authorized host"
    # provenance contains edges are still present
    contains = {(e.from_id, e.to_id) for e in obs.edge_deltas if e.type == "contains"}
    assert (_INV, _JS) in contains
    assert (_INV, _REG) in contains


@pytest.mark.asyncio
async def test_js_asset_reachable_in_planner_depth_subgraph() -> None:
    """A JS asset discovered on a depth-2 page is reachable at depth 2 (§28.32).

    Without the host--exposes--> edge the JS asset sits at depth 3 (host ->
    homepage -> /invite -> js) — invisible to the depth-2 planner subgraph while
    the depth-3 phase gate still sees it, which duplicate-stalled the web phase.
    """
    api = _fresh_api()
    await _seed_chain(api)

    sg2 = await api.get_subgraph(_H, depth=2)
    ids = {n.id for n in sg2.nodes}
    assert _JS in ids, "JS asset must be reachable in the depth-2 planner subgraph"
    assert _REG in ids, "discovered link must be reachable in the depth-2 planner subgraph"

    js_urls = [n.props.get("url") for n in pending_js_assets(sg2)]
    assert "http://2million.htb/js/inviteapi.min.js" in js_urls


@pytest.mark.asyncio
async def test_gate_and_planner_agree_at_same_depth() -> None:
    """The gate must not report a pending endpoint the planner (same depth) can't see."""
    api = _fresh_api()
    await _seed_chain(api)

    sg2 = await api.get_subgraph(_H, depth=2)
    # Gate says incomplete because the JS asset is unfetched — and crucially the
    # planner CAN see it now, so it can act (not a phantom pending).
    ev = web_evidence_status(sg2)
    assert ev.complete is False
    assert ev.reason == "unfetched_discovered_endpoints"
    # planner sees a fetchable pending item (JS asset or page), i.e. non-empty
    assert pending_js_assets(sg2) or pending_page_fetches(sg2)
