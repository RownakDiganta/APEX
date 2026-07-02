# test_payload_repo_loader.py
# Tests for PayloadRepoLoader and seed_loader verifying chunk proposal, required metadata, markdown heading splits, missing-path handling, the staging isolation invariant, and retrieval text after promotion.
from __future__ import annotations

import pathlib

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import PassthroughReranker, StubEmbedder, TextGraphMatcher
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Tier

from apex_host.knowledge.payload_repo_loader import PayloadRepoLoader
from apex_host.knowledge.seed_loader import seed_payload_repo


def make_api(*, with_retriever: bool = False) -> tuple[MemoryAPI, Config]:
    cfg = Config()
    lexical = BM25LexicalIndex()
    vector = FaissVectorIndex(dim=cfg.vector_dim)
    kv = InMemoryKVStore()
    graph = NetworkXGraphStore()
    api = MemoryAPI(
        graph=graph,
        episodic=JSONLEpisodicStore(path=None),
        lexical=lexical,
        vector=vector,
        kv=kv,
        config=cfg,
    )
    if with_retriever:
        retriever = HybridRetriever(
            lexical=lexical,
            vector=vector,
            embedder=StubEmbedder(),
            reranker=PassthroughReranker(),
            graph=graph,
            graph_matcher=TextGraphMatcher(),
            kv=kv,
            config=cfg,
        )
        api.set_retriever(retriever)
    return api, cfg


def _write_repo(root: pathlib.Path) -> None:
    (root / "sqli").mkdir()
    (root / "sqli" / "basics.md").write_text(
        "# SQL Injection\n\n"
        "## Authentication bypass\n"
        "Generic payload family note for auth bypass technique placeholder.\n\n"
        "## Union based\n"
        "Generic note about union-based extraction technique placeholder.\n"
    )
    (root / "xss").mkdir()
    (root / "xss" / "notes.txt").write_text(
        "Generic reflected XSS technique placeholder text for testing chunking."
    )


async def test_loader_proposes_knowledge_chunks(tmp_path: pathlib.Path) -> None:
    _write_repo(tmp_path)
    api, _ = make_api()
    loader = PayloadRepoLoader(str(tmp_path), api)

    count = await loader.load()

    assert count > 0
    staged = await api.get_staged_knowledge()
    assert len(staged) == count


async def test_loader_attaches_required_metadata(tmp_path: pathlib.Path) -> None:
    _write_repo(tmp_path)
    api, _ = make_api()
    loader = PayloadRepoLoader(str(tmp_path), api)
    await loader.load()

    staged = await api.get_staged_knowledge()
    assert staged
    for entry in staged:
        assert entry.metadata["tier"] == "semantic"
        assert entry.metadata["source"] == "payload_repo"
        assert entry.metadata["payload_family"] in {"sqli", "xss"}
        assert entry.metadata["file_ext"] in {".md", ".txt"}


async def test_loader_markdown_chunks_by_heading(tmp_path: pathlib.Path) -> None:
    _write_repo(tmp_path)
    api, _ = make_api()
    loader = PayloadRepoLoader(str(tmp_path), api)
    await loader.load()

    staged = await api.get_staged_knowledge()
    md_chunks = [e for e in staged if e.metadata["file_ext"] == ".md"]
    # Two '## ' headings in basics.md -> at least 2 chunks
    assert len(md_chunks) >= 2


async def test_loader_missing_repo_path_returns_zero(tmp_path: pathlib.Path) -> None:
    api, _ = make_api()
    loader = PayloadRepoLoader(str(tmp_path / "does-not-exist"), api)
    count = await loader.load()
    assert count == 0


async def test_staged_knowledge_not_retrievable_until_promoted(tmp_path: pathlib.Path) -> None:
    _write_repo(tmp_path)
    api, _ = make_api()
    loader = PayloadRepoLoader(str(tmp_path), api)
    await loader.load()

    from memfabric.types import ALL_TIERS

    bundle = await api.query(text="injection technique", tiers=ALL_TIERS)
    staged_hits = [e for e in bundle.entries if e.tier == "staged"]
    assert staged_hits == []


async def test_seed_payload_repo_promotes_entries(tmp_path: pathlib.Path) -> None:
    _write_repo(tmp_path)
    api, cfg = make_api()

    count = await seed_payload_repo(str(tmp_path), api, cfg)

    assert count > 0
    staged = await api.get_staged_knowledge()
    assert all(entry.promoted for entry in staged)


async def test_chunk_index_present_in_metadata(tmp_path: pathlib.Path) -> None:
    _write_repo(tmp_path)
    api, _ = make_api()
    loader = PayloadRepoLoader(str(tmp_path), api)
    await loader.load()

    staged = await api.get_staged_knowledge()
    for entry in staged:
        assert "chunk_index" in entry.metadata
        assert isinstance(entry.metadata["chunk_index"], int)


async def test_query_returns_non_empty_text_after_promotion(tmp_path: pathlib.Path) -> None:
    """After seed_payload_repo, api.query() entries must have non-empty text."""
    _write_repo(tmp_path)
    api, cfg = make_api(with_retriever=True)

    count = await seed_payload_repo(str(tmp_path), api, cfg)
    assert count > 0

    bundle = await api.query(
        text="injection technique placeholder",
        tiers=[Tier.semantic],
        k=5,
    )
    assert bundle.entries, "expected at least one result after seeding"
    assert all(e.text for e in bundle.entries), "ScoredEntry.text must not be empty after promotion"


async def test_query_text_matches_chunk_content(tmp_path: pathlib.Path) -> None:
    """Text returned in ScoredEntry must contain words from the original chunk."""
    _write_repo(tmp_path)
    api, cfg = make_api(with_retriever=True)
    await seed_payload_repo(str(tmp_path), api, cfg)

    bundle = await api.query(
        text="union based extraction technique placeholder",
        tiers=[Tier.semantic],
        k=5,
    )
    assert bundle.entries
    combined = " ".join(e.text for e in bundle.entries).lower()
    assert "placeholder" in combined
