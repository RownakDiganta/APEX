# init_state.py
# Persisted knowledge-initialization state: per-family manifest + completion status, read/written atomically, with explicit schema versioning and corruption detection.
"""Durable, atomically-persisted knowledge-initialization state.

This is the small, cheap-to-read/write bookkeeping file that makes cold vs.
warm vs. incremental startup decidable WITHOUT re-staging anything: for
each compiled-knowledge family, it records the ``FamilyManifest`` that was
in effect the last time this family finished a successful staging +
Reflector-promotion cycle, plus a completion status and summary counts.

Two files, deliberately kept separate (see
``apex_host.knowledge.init_cache`` module docstring for the full design):

- ``init_state.json`` (this module) — small, structured, human-readable
  bookkeeping. Read/written on every startup.
- ``lexical_snapshot.jsonl`` (``init_cache.py``) — the actual promoted
  document content, potentially large. Read only on a cache-hit warm start;
  written only after a successful (re-)promotion.

Completion semantics (non-negotiable, per this feature's own design brief):
a ``FamilyInitRecord.status`` is only ever set to ``"complete"`` by
``init_cache.py`` AFTER ``promote_staged_knowledge_until_stable`` has
actually returned with a terminal, no-further-action stop_reason
(``"exhausted"`` or ``"no_progress"`` — both mean "nothing more can happen
without new input", see ``apex_host.knowledge.seed_loader
.PromotionSummary.stop_reason``). A run interrupted mid-promotion
(``"max_passes"``/``"timeout"``/``"max_records"``, or a crash before this
module's ``write_init_state`` is even called) leaves the family's status at
``"in_progress"`` (or absent from the file entirely, for a fresh family) —
never falsely ``"complete"``. Because ``write_init_state`` uses
``apex_host.async_utils.write_json_atomic`` (temp file + fsync + rename —
Phase 7's established pattern), a crash DURING the write itself leaves the
previous, still-valid file in place; there is no code path that can produce
a truncated or partially-written state file.

Schema versioning: ``KnowledgeInitState.state_schema_version`` is checked on
load. A version mismatch (or any parse/shape failure) is treated as
corruption — see ``read_init_state``'s ``StateReadResult.status``.
"""
from __future__ import annotations

import json
import logging
import pathlib
from dataclasses import dataclass, field
from typing import Any, Literal

from apex_host.async_utils import read_text_async, write_json_atomic
from apex_host.knowledge.manifest import FamilyManifest

logger = logging.getLogger(__name__)

STATE_SCHEMA_VERSION = "1"
"""Bumped when this module's own JSON shape changes in a way that would
make an older persisted file unparseable or misleading under the new code
(new required field, renamed field, changed semantics of an existing one).
A mismatch is always treated as corruption (never partially trusted)."""

_STATE_FILENAME = "init_state.json"

FamilyStatus = Literal["complete", "in_progress"]

ReadStatus = Literal["ok", "missing", "corrupt", "incompatible_schema"]


@dataclass(slots=True)
class FamilyInitRecord:
    """One family's persisted initialization bookkeeping."""

    manifest: FamilyManifest
    status: FamilyStatus
    records_staged: int = 0
    records_promoted: int = 0
    records_blocked: int = 0
    updated_at: str = ""
    # Phase 4 item 8 (removed-record policy): ids the family manifest no
    # longer contains but whose promoted documents are still retained in
    # the lexical snapshot (never silently dropped — see init_cache.py
    # "Removed-record policy"). Bounded set of ids only; never the full
    # record content.
    deprecated_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "status": self.status,
            "records_staged": self.records_staged,
            "records_promoted": self.records_promoted,
            "records_blocked": self.records_blocked,
            "updated_at": self.updated_at,
            "deprecated_ids": list(self.deprecated_ids),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FamilyInitRecord":
        return cls(
            manifest=FamilyManifest.from_dict(dict(d.get("manifest") or {})),
            status=d.get("status", "in_progress"),
            records_staged=int(d.get("records_staged", 0)),
            records_promoted=int(d.get("records_promoted", 0)),
            records_blocked=int(d.get("records_blocked", 0)),
            updated_at=str(d.get("updated_at", "")),
            deprecated_ids=list(d.get("deprecated_ids") or []),
        )


@dataclass(slots=True)
class KnowledgeInitState:
    """The full persisted state: one ``FamilyInitRecord`` per known family."""

    state_schema_version: str = STATE_SCHEMA_VERSION
    families: dict[str, FamilyInitRecord] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_schema_version": self.state_schema_version,
            "families": {name: rec.to_dict() for name, rec in self.families.items()},
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "KnowledgeInitState":
        families_raw = d.get("families") or {}
        if not isinstance(families_raw, dict):
            raise ValueError("families must be a dict")
        return cls(
            state_schema_version=str(d.get("state_schema_version", "")),
            families={
                name: FamilyInitRecord.from_dict(dict(rec))
                for name, rec in families_raw.items()
                if isinstance(rec, dict)
            },
        )


@dataclass(slots=True)
class StateReadResult:
    """Outcome of attempting to load a persisted ``KnowledgeInitState``.

    ``status``:
    - ``"ok"``      — loaded successfully, schema version matches.
    - ``"missing"`` — no state file exists at this path (first run / fresh
      volume). Not an error — the expected cold-start case.
    - ``"corrupt"`` — the file exists but is not valid JSON, or its shape
      does not match the expected structure.
    - ``"incompatible_schema"`` — valid JSON, valid shape, but
      ``state_schema_version`` does not match ``STATE_SCHEMA_VERSION``.

    In every non-``"ok"`` case, ``state`` is a FRESH, empty
    ``KnowledgeInitState`` — callers can always safely treat the result as
    "start from cold" without a separate null check, while ``reason`` gives
    the operator-facing explanation for the report's ``reuse_rejected_reason``.
    """

    status: ReadStatus
    state: KnowledgeInitState
    reason: str = ""


def state_path(cache_dir: str | pathlib.Path) -> pathlib.Path:
    return pathlib.Path(cache_dir) / _STATE_FILENAME


async def read_init_state(cache_dir: str | pathlib.Path) -> StateReadResult:
    """Load the persisted state, classifying why reuse might be rejected.

    Never raises — every failure mode (missing file, malformed JSON, wrong
    shape, incompatible schema version) is captured in the returned
    ``StateReadResult`` so ``init_cache.py`` can always proceed with a safe
    rebuild.
    """
    path = state_path(cache_dir)
    if not path.exists():
        return StateReadResult(
            status="missing", state=KnowledgeInitState(), reason="no persisted state file"
        )

    try:
        raw = await read_text_async(path)
    except OSError as exc:
        return StateReadResult(
            status="corrupt", state=KnowledgeInitState(), reason=f"cannot read state file: {exc}"
        )

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("init_state: malformed JSON at %s: %s", path, exc)
        return StateReadResult(
            status="corrupt", state=KnowledgeInitState(), reason=f"malformed JSON: {exc}"
        )

    if not isinstance(parsed, dict):
        return StateReadResult(
            status="corrupt", state=KnowledgeInitState(), reason="top-level JSON is not an object"
        )

    try:
        loaded = KnowledgeInitState.from_dict(parsed)
    except (ValueError, TypeError, KeyError) as exc:
        logger.warning("init_state: unexpected shape at %s: %s", path, exc)
        return StateReadResult(
            status="corrupt", state=KnowledgeInitState(), reason=f"unexpected shape: {exc}"
        )

    if loaded.state_schema_version != STATE_SCHEMA_VERSION:
        return StateReadResult(
            status="incompatible_schema",
            state=KnowledgeInitState(),
            reason=(
                f"state_schema_version mismatch: file has "
                f"{loaded.state_schema_version!r}, code expects {STATE_SCHEMA_VERSION!r}"
            ),
        )

    return StateReadResult(status="ok", state=loaded)


async def write_init_state(cache_dir: str | pathlib.Path, state: KnowledgeInitState) -> None:
    """Atomically persist *state* — temp file + fsync + rename (Phase 7 pattern).

    A crash during this call leaves the PREVIOUS file (or no file) intact;
    a reader can never observe a partially-written state file.
    """
    await write_json_atomic(state_path(cache_dir), state.to_dict())
