from __future__ import annotations

import pathlib

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex

from apex_host.knowledge.payload_repo_loader import PayloadRepoLoader
from apex_host.knowledge.seed_loader import seed_payload_repo


def make_api() -> tuple[MemoryAPI, Config]:
    cfg = Config()
    api = MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )
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
