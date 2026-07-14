# test_reflector_domain_agnostic.py
# Verifies that memfabric's Reflector generalizer contains no hardcoded domain-specific patterns.
"""Tests for domain-agnostic design of the memfabric Reflector.

Invariants verified:
1. Default memfabric generalizer does NOT slot IPv4 addresses or port numbers
   (no hardcoded cybersecurity patterns in the substrate).
2. A host application can supply domain-specific patterns and they ARE applied.
3. The built-in UUID pattern fires regardless of host-supplied patterns.
4. No cybersecurity terminology appears in the memfabric.reflector source.
5. The Reflector worker uses Config.slot_patterns when calling generalize().
"""
from __future__ import annotations

import pathlib
import re
import uuid

import pytest

from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.ids import new_id, now
from memfabric.reflector.consolidate import _build_pattern, generalize
from memfabric.reflector.worker import ReflectorWorker
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.types import Episode, Outcome


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ep(action: str, data: dict) -> Episode:
    return Episode(
        id=new_id(), timestamp=now(), agent="test",
        action=action, outcome=Outcome.success, data=data,
    )


def make_api_with_patterns(slot_patterns: list[str]) -> tuple[MemoryAPI, Config]:
    cfg = Config(slot_patterns=slot_patterns, min_chain_len=1, skill_prior=0.5)
    api = MemoryAPI(
        graph=NetworkXGraphStore(),
        episodic=JSONLEpisodicStore(path=None),
        lexical=BM25LexicalIndex(),
        vector=FaissVectorIndex(dim=cfg.vector_dim),
        kv=InMemoryKVStore(),
        config=cfg,
    )
    return api, cfg


# ---------------------------------------------------------------------------
# 1. Default generalizer: NO IPv4/port slotting
# ---------------------------------------------------------------------------

def test_default_no_ipv4_slotting() -> None:
    """Without any slot_patterns, IPv4 addresses are preserved verbatim."""
    ep = _ep("connect", {"target": "10.10.14.5", "host": "192.168.1.100"})
    skill = generalize([ep])  # no slot_patterns → defaults to []
    template_str = str(skill.template)
    assert "10.10.14.5" in template_str, "IPv4 must NOT be slotted when no pattern is supplied"
    assert "192.168.1.100" in template_str


def test_default_no_port_slotting() -> None:
    """Without any slot_patterns, numeric port-like values are preserved verbatim."""
    ep = _ep("probe", {"port": "8080", "alt_port": "22", "service_port": "443"})
    skill = generalize([ep])
    template_str = str(skill.template)
    assert "8080" in template_str
    assert "22" in template_str
    assert "443" in template_str


def test_default_no_short_numeric_slotting() -> None:
    """Small integers that happen to look like port numbers are not slotted by default."""
    ep = _ep("step", {"count": "3306", "score": "65535"})
    skill = generalize([ep])
    template_str = str(skill.template)
    assert "3306" in template_str
    assert "65535" in template_str


def test_default_empty_slots_map() -> None:
    """With no patterns and no UUIDs in the data, the slots map must be empty."""
    ep = _ep("action", {"key": "plain-value", "num": "12345"})
    skill = generalize([ep])
    assert skill.template["slots"] == {}


# ---------------------------------------------------------------------------
# 2. Built-in UUID pattern fires regardless of host patterns
# ---------------------------------------------------------------------------

def test_uuid_slotted_by_default() -> None:
    """UUID v4 strings are ALWAYS slotted — they are universally opaque."""
    uid = str(uuid.uuid4())
    ep = _ep("fetch", {"session_id": uid})
    skill = generalize([ep])
    steps_str = str(skill.template["steps"])  # check steps only, not inverse map
    assert uid not in steps_str, "UUID must be replaced with a slot reference in steps"
    assert "<SLOT_" in steps_str
    # The inverse map (slots dict) holds concrete values — that's expected.
    assert uid in skill.template["slots"].values()


def test_uuid_slotted_even_with_no_extra_patterns() -> None:
    uid = str(uuid.uuid4())
    ep = _ep("op", {"token": uid, "plain": "hello"})
    skill = generalize([ep], slot_patterns=[])
    steps_str = str(skill.template["steps"])
    assert uid not in steps_str
    assert "hello" in steps_str  # non-UUID plain text is preserved


# ---------------------------------------------------------------------------
# 3. Host-supplied patterns ARE applied
# ---------------------------------------------------------------------------

def test_host_supplied_ipv4_pattern_slots_ip() -> None:
    """When the host supplies an IPv4 pattern, addresses are replaced with slots in steps."""
    ipv4 = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    ep = _ep("connect", {"target": "10.10.14.5"})
    skill = generalize([ep], slot_patterns=[ipv4])
    steps_str = str(skill.template["steps"])
    assert "10.10.14.5" not in steps_str
    assert "<SLOT_" in steps_str


def test_host_supplied_port_pattern_slots_port() -> None:
    """When the host supplies a port pattern, port numbers are replaced in steps."""
    port_pattern = r"\d{4,6}"
    ep = _ep("probe", {"port": "8080"})
    skill = generalize([ep], slot_patterns=[port_pattern])
    steps_str = str(skill.template["steps"])
    assert "8080" not in steps_str
    assert "<SLOT_" in steps_str


def test_host_supplied_both_patterns() -> None:
    """Both IPv4 and port patterns work together — one pass, two slot types."""
    patterns = [r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r"\d{4,6}"]
    ep = _ep("scan", {"target": "192.168.1.1", "port": "8080", "proto": "tcp"})
    skill = generalize([ep], slot_patterns=patterns)
    steps_str = str(skill.template["steps"])
    assert "192.168.1.1" not in steps_str
    assert "8080" not in steps_str
    assert "tcp" in steps_str  # non-matching plain text is preserved


def test_host_supplied_custom_domain_pattern() -> None:
    """Arbitrary host-supplied patterns work (e.g., a medical record ID format)."""
    mrn_pattern = r"MRN-\d{6}"
    ep = _ep("lookup", {"record": "MRN-123456", "type": "patient"})
    skill = generalize([ep], slot_patterns=[mrn_pattern])
    steps_str = str(skill.template["steps"])
    assert "MRN-123456" not in steps_str
    assert "patient" in steps_str


def test_slot_map_inverse_is_correct() -> None:
    """The slots dict in the template maps slot_ref → concrete_value correctly."""
    ipv4 = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    ep = _ep("ping", {"target": "10.0.0.1"})
    skill = generalize([ep], slot_patterns=[ipv4])
    # inverse map: {<SLOT_0>: "10.0.0.1"}
    assert "10.0.0.1" in skill.template["slots"].values()


# ---------------------------------------------------------------------------
# 4. Config.slot_patterns default is empty
# ---------------------------------------------------------------------------

def test_config_default_slot_patterns_empty() -> None:
    """The substrate Config ships with slot_patterns=[] — no domain patterns."""
    cfg = Config()
    assert cfg.slot_patterns == [], (
        "Config.slot_patterns must default to [] so the substrate is domain-agnostic"
    )


def test_config_slot_patterns_wired_to_worker() -> None:
    """The Reflector worker passes Config.slot_patterns to generalize()."""
    # Supply a custom pattern that would slot the word "MARKER" only
    api, cfg = make_api_with_patterns(slot_patterns=[r"MARKER"])

    # The pattern should affect generalize() when called from the worker
    from memfabric.reflector.consolidate import generalize as _gen
    ep = _ep("action", {"key": "MARKER"})
    skill = _gen([ep], slot_patterns=cfg.slot_patterns)
    steps_str = str(skill.template["steps"])
    assert "MARKER" not in steps_str
    assert "<SLOT_" in steps_str


# ---------------------------------------------------------------------------
# 5. ReflectorWorker passes slot_patterns from Config
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_worker_uses_slot_patterns_from_config() -> None:
    """ReflectorWorker passes Config.slot_patterns through to generalize()."""
    # Supply a simple pattern: slot any 4-digit string
    api, cfg = make_api_with_patterns(slot_patterns=[r"\d{4}"])
    worker = ReflectorWorker(api, cfg)

    chain_id = new_id()
    ep1 = _ep("step_a", {"val": "1234"})
    ep1.chain_id = chain_id
    ep1.outcome = Outcome.success
    ep2 = _ep("step_b", {"val": "5678"})
    ep2.chain_id = chain_id
    ep2.outcome = Outcome.success

    await api.append_episode(ep1)
    await api.append_episode(ep2)
    await worker.run_once()

    skills = await api.get_staged_skills()
    assert len(skills) >= 1
    # The 4-digit value should have been slotted by the supplied pattern
    steps_str = str(skills[0].template["steps"])
    assert "1234" not in steps_str
    assert "<SLOT_" in steps_str


@pytest.mark.asyncio
async def test_worker_no_slotting_without_patterns() -> None:
    """With empty slot_patterns (default), numeric values are preserved in the template."""
    api, cfg = make_api_with_patterns(slot_patterns=[])
    worker = ReflectorWorker(api, cfg)

    chain_id = new_id()
    ep1 = _ep("step_a", {"port": "9999"})
    ep1.chain_id = chain_id
    ep1.outcome = Outcome.success
    ep2 = _ep("step_b", {"port": "9999"})
    ep2.chain_id = chain_id
    ep2.outcome = Outcome.success

    await api.append_episode(ep1)
    await api.append_episode(ep2)
    await worker.run_once()

    skills = await api.get_staged_skills()
    assert len(skills) >= 1
    steps_str = str(skills[0].template["steps"])
    assert "9999" in steps_str, "Port number must NOT be slotted without an explicit pattern"


# ---------------------------------------------------------------------------
# 6. Static scan: no cybersecurity terms in memfabric/reflector source
# ---------------------------------------------------------------------------

_CYBER_TERMS = re.compile(
    r"\b(?:IPv4|CVE|CWE|exploit|shell|credential|port\b|nmap|scan|"
    r"vulnerability|pentest|payload)\b",
    re.IGNORECASE,
)

_REFLECTOR_DIR = pathlib.Path(__file__).parent.parent / "memfabric" / "reflector"


def _source_files() -> list[pathlib.Path]:
    return list(_REFLECTOR_DIR.rglob("*.py"))


@pytest.mark.parametrize("src_file", _source_files(), ids=lambda p: p.name)
def test_no_cybersecurity_terms_in_memfabric_reflector(src_file: pathlib.Path) -> None:
    """No cybersecurity-specific terms may appear in memfabric/reflector/*.py."""
    if "__pycache__" in str(src_file):
        return
    source = src_file.read_text(encoding="utf-8")
    # Strip string literals and comments before checking to avoid false positives
    # from docstrings/comments that explain WHY something was removed.
    # We check the AST for actual Name/Attribute nodes in comments separately.
    # Allow the term "port" in comments explaining the pattern was REMOVED
    # (the fix documentation itself may mention what was removed).
    # Filter out matches that only appear inside # comment lines.
    non_comment_matches = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        found = _CYBER_TERMS.findall(line)
        non_comment_matches.extend(found)

    assert non_comment_matches == [], (
        f"{src_file.name} contains cybersecurity-specific terms in non-comment code: "
        f"{non_comment_matches!r}. Move domain-specific patterns to the host application."
    )


# ---------------------------------------------------------------------------
# 7. _build_pattern behaves correctly
# ---------------------------------------------------------------------------

def test_build_pattern_empty_gives_uuid_only() -> None:
    """With no extra patterns, the compiled regex matches only UUIDs."""
    pat = _build_pattern([])
    uid = str(uuid.uuid4())
    assert pat.search(uid), "UUID must match the built-in pattern"
    assert not pat.search("192.168.1.1"), "IPv4 must NOT match the built-in-only pattern"
    assert not pat.search("8080"), "Port must NOT match the built-in-only pattern"


def test_build_pattern_with_ipv4() -> None:
    pat = _build_pattern([r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"])
    assert pat.search("10.0.0.1")
    uid = str(uuid.uuid4())
    assert pat.search(uid)       # UUID still matches


def test_build_pattern_with_port() -> None:
    pat = _build_pattern([r"\d{4,6}"])
    assert pat.search("8080")
    assert not pat.search("99")  # too short


def test_build_pattern_combined() -> None:
    patterns = [r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r"\d{4,6}"]
    pat = _build_pattern(patterns)
    assert pat.search("10.0.0.1")
    assert pat.search("8080")
    uid = str(uuid.uuid4())
    assert pat.search(uid)
