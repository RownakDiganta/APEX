# Knowledge Initialization (Phase 4)

This document is the full design record for Phase 4 of the post-live-test
debugging track ("Phase 4 of exactly four debugging phases"). Phases 1-3
fixed LLM readiness/container-compatible Nmap execution, duplicate-action
suppression/phase-transition evidence gating, and report diagnostics/
finding deduplication/phase semantics, respectively. This phase fixes a
startup-performance defect: almost the entire wall-clock time of an
engagement was spent re-staging and re-Reflector-promoting compiled
knowledge that had not changed since the previous run.

## 1. Live-test evidence and root causes

**Evidence:** 63,783 records staged; 63,764 promoted; 19 remained; 639
promotion passes; `stop_reason=no_progress`; `elapsed_seconds≈1,757.752`;
total engagement runtime ≈1,785 seconds — i.e. the actual engagement (after
seeding) lasted only a few seconds.

**Two independent root causes, both fixed:**

1. **The promotion loop itself was accidentally O(records × passes).**
   `ReflectorWorker._apply_promotion_gate()` called
   `MemoryAPI.get_staged_knowledge()`/`get_staged_skills()` — which
   **deep-copied every staged entry, including already-promoted ones** —
   on every single pass. `apex_host.knowledge.seed_loader
   .promote_staged_knowledge_until_stable()`'s own before/after progress
   check did the same, twice more per pass. For a 63,783-record corpus
   promoted 100-at-a-time (`reflector_max_promotions_per_run` default),
   that is ~639 passes × up to 63,783 deep copies — tens of millions of
   `copy.deepcopy()` calls on dataclasses with nested dicts. This is what
   actually consumed the ~1,758 seconds — not the (cheap) promotion-gate
   predicate itself.
2. **No cross-run persistence.** Every disposable APEX container starts
   with empty, purely in-memory reference stores
   (`BM25LexicalIndex`, `MemoryAPI`'s staging dicts). Even after fixing (1),
   every container restart re-did the (now fast) staging+promotion work
   from scratch, because nothing survived the restart.

## 2. Promotion-loop performance fix

**`memfabric/api.py`** — `MemoryAPI` gained:
- `get_staged_knowledge(*, promoted: bool | None = None)` /
  `get_staged_skills(*, promoted=None, quarantined=None)` — optional
  filters. `promoted=False` (the exact filter every hot-path caller uses)
  is served from a new, incrementally-maintained index
  (`_unpromoted_knowledge_ids` / `_unpromoted_active_skill_ids`) rather
  than scanning the whole staging dict. `None` (the default) reproduces
  the exact prior unfiltered behavior — fully backward compatible.
- `count_staged_knowledge(...)` / `count_staged_skills(...)` — same
  filters, no copying at all (just a `len()` on the index set for the
  `False`/`(False, False)` fast path).
- `select_unpromoted_knowledge_ids(predicate, *, limit=None)` /
  `select_unpromoted_active_skill_ids(...)` — the actual fix for the
  quadratic behavior. Evaluates a caller-supplied predicate directly
  against **live** staged objects (never copied — no object ever leaves
  this method) and returns only matching ids, stopping as soon as `limit`
  matches are found. `MemoryAPI` never imports promotion policy itself
  (`memfabric.reflector.gates`'s pure functions remain the sole owner of
  that) — the predicate is injected by the caller.

**`ReflectorWorker._apply_promotion_gate()`** now calls
`select_unpromoted_knowledge_ids(lambda e: should_promote_knowledge(e,
...), limit=cap)` instead of fetching the entire remaining-unpromoted set
and breaking early — this is what turns "deep-copy the entire remaining
pool every pass, use only `cap` of them" into "find exactly `cap` matches,
copy nothing."

**`memfabric/reflector/gates.py`** gained two pure diagnostic functions
(no state mutation, no I/O): `classify_unpromoted_knowledge(entry, *,
min_confidence)` and `classify_unpromoted_skill(skill, *,
min_evidence_count, min_confidence)`. A `KnowledgeEntry`'s confidence is
fixed at proposal time — nothing in this codebase ever changes it
afterward — so `"below_min_confidence"` is a **permanent** classification
for a knowledge entry (re-running the promotion pass can never change the
outcome); a `Skill`'s classification (`"below_min_evidence"`,
`"below_min_confidence"`) is not necessarily permanent, since evidence
accumulates via `merge_skill_candidate`.

**`apex_host/knowledge/seed_loader.py`** — `promote_staged_knowledge_until_stable`
now uses the cheap `count_staged_*()` methods for its before/after
progress check (was: deep-copy-based list comprehensions), and, once the
loop stops, runs **one** bounded classification pass
(`classify_remaining_staged()`) over only the remaining un-promoted
entries, producing `PromotionSummary.blocked_reason_counts` — a bounded
`{reason: count}` dict, **never a per-record ID list**.

### Measured effect

A synthetic benchmark reproducing the exact reported shape (63,783 staged
records across 4 families, 19 permanently below-confidence interspersed
throughout — not just a tail) went from an estimated ~1,758s (extrapolated
from the pre-fix algorithmic complexity) to **0.22 seconds** for the
promotion loop alone, with the identical outcome: 63,764 promoted, 20 (19
in one specific run, 20 in another — depends on exact interspersion)
remaining, 639 passes, `stop_reason=no_progress`,
`blocked_reason_counts={"below_min_confidence": 19}`. See §7 for the full
cold/warm/incremental benchmark including file I/O and manifest
computation.

## 3. Persistent knowledge-initialization cache

### Why this does not violate any Memory Fabric invariant

- **No second write path.** The only way a document ever enters
  `BM25LexicalIndex._docs` is through `BM25LexicalIndex.add()` — called
  either by `MemoryAPI.promote_knowledge()` (the normal, Reflector-gated
  path) or by the new `BM25LexicalIndex.import_documents()` (the reuse
  path), which is itself implemented as a loop of plain `add()` calls.
- **The Reflector remains the sole promoter.** A cache "reuse" hit imports
  documents that were themselves only ever written by a real
  `MemoryAPI.promote_knowledge()` call in some **prior** run. Reloading a
  store's own prior, legitimate output at process start is the same
  pattern the reference `JSONLEpisodicStore` already uses (it replays its
  own file into memory at construction) — not a new promotion mechanism.
- **Not "rebuilding from files behind MemoryAPI's back."** The cache
  orchestrator never reads the raw compiled knowledge JSONL files to
  reconstruct promoted state. It reads its own prior serialization of what
  the lexical index already legitimately produced (a `family_<name>.json`
  payload file, written by this feature, in this feature's own format).
  The raw compiled files are read only to compute a **comparison-only**
  manifest — a cheap, read-only operation with no `MemoryAPI` interaction.
- **Staging/Reflector-promotion is untouched for changed or new content.**
  Any record that is new or content-changed goes through the exact same
  `propose_knowledge()` → `ReflectorWorker.run_once()` path as before this
  feature existed.

### Manifest identity — deterministic, content-hash based, never mtime

`apex_host/knowledge/manifest.py::compute_family_record_set()` reads a
family's compiled JSONL files and computes, per record, a SHA-256
`content_hash` over `(text, confidence, tags, metadata, title,
source_type)` — deliberately **not** the record's `id` (compiled-record
IDs are content-addressed on `source_path` + `chunk_index`, not on the
text itself, so an edited source file can produce the *same* ID with
*different* content — see `apex_host/knowledge/compiler/common.py
::stable_record_id`). The family-level `dataset_id` is a SHA-256 over
every sorted `"id:content_hash"` pair — deterministic regardless of file
order or JSONL line order, and completely independent of file modification
time. Two runs of the compiler over byte-identical source files always
produce the identical manifest, even with a fresh `mtime` from a clean
checkout or container rebuild.

A `FamilyManifest` carries: `family`, `schema_version`
(`apex_host.knowledge.compiler.schemas.COMPILER_SCHEMA_VERSION`),
`source_artifacts` (filenames present), `record_count`, `dataset_id`
(the identity), and `compiled_at` (diagnostic only — the maximum
`updated_at` seen — **never** consulted for the reuse decision).

### Two-file persisted format

- **`init_state.json`** (small, always read/written every run) — one
  `FamilyInitRecord` per family: its `manifest`, `status`
  (`"complete"`/`"in_progress"`), summary counts, and `deprecated_ids`.
  Schema-versioned (`STATE_SCHEMA_VERSION`); a version mismatch or any
  parse/shape failure is treated as corruption.
- **`family_<name>.json`** (one per family, potentially large — read only
  on a reuse hit or an incremental diff) — the manifest, per-record
  content-hash digests (for diffing without re-reading compiled files a
  second time), and the promoted document content
  (`{id, text, metadata}` triples) for `BM25LexicalIndex.import_documents()`.

Both are written atomically via the existing Phase 7
`apex_host.async_utils.write_json_atomic` helper (temp file + `fsync` +
rename) — a crash mid-write leaves the previous file (or no file) intact.

### Cold / warm / incremental / rebuild decision logic

For each of the four known families, on every startup
(`apex_host.knowledge.init_cache.initialize_compiled_knowledge`):

1. Compute the current `FamilyManifest` (cheap — a read-only JSON parse +
   hash pass over the compiled files).
2. Look up the persisted `FamilyInitRecord` for this family.
3. **Reuse** — persisted record exists, `status=="complete"`, and its
   manifest's identity matches the current one exactly: import the
   family's persisted documents directly into the fresh
   `BM25LexicalIndex` (`import_documents()`). Zero `propose_knowledge()`
   calls, zero Reflector passes for this family.
4. **Incremental** — a prior payload exists but the manifest differs:
   re-import the prior payload's documents (restores every unchanged
   record instantly), then diff current vs. prior per-record digests to
   find `added_or_changed` ids, and stage **only those** via
   `load_compiled_family(..., only_ids=added_or_changed)`. A same-id,
   content-edited record is correctly detected (its digest changes even
   though its id does not) and re-staged.
5. **Removed records** — an id present in the prior payload but absent
   from the current manifest is **never deleted** (memfabric has no
   "delete promoted knowledge" primitive — index promotion is
   append/upsert-only by design). It is recorded in
   `FamilyInitRecord.deprecated_ids` (a bounded id list, never content)
   and its already-imported document is left in place, still retrievable.
   The explicit, documented way to actually drop it is a full rebuild for
   that family (§5).
6. **Cold** — no prior payload at all (first run, or after a reset):
   stage everything via the unmodified `load_compiled_family()` path.
7. One shared `promote_staged_knowledge_until_stable()` pass covers every
   family that staged anything this run — the Reflector remains the sole
   promotion path regardless of how many families changed.
8. A family's `init_state.json` record is marked `status="complete"`
   **only if** the promotion pass reached a genuinely terminal state
   (`stop_reason` in `{"exhausted", "no_progress"}` — both mean "nothing
   more can happen without new input"). A budget-interrupted run
   (`"max_passes"`/`"timeout"`/`"max_records"`) leaves `status="in_progress"`.
   **Critically, the family's payload file is also only (re-)written when
   the run was terminal** — an interrupted run's digests would otherwise
   record "staged but never promoted" records as if their content had
   already been fully handled, causing a future resumed run to silently
   skip re-staging them forever (found and fixed during this phase's own
   testing — see the `TestInterruptedInitialization` test class).

`KnowledgeInitReport.initialization_mode` — one of `cold` / `resumed` /
`incremental` / `reused` / `rebuild` — precedence: `rebuild` (state
corruption detected) > `resumed` (a prior run left a family
`in_progress`) > `incremental` (at least one family did a genuine
record-level partial update against its own prior payload) > `reused`
(every configured family matched, nothing processed) > `cold`.

### Corruption detection and recovery

`apex_host/knowledge/init_state.py::read_init_state()` never raises.
Every failure mode — missing file (`"missing"`, the expected cold-start
case), malformed JSON, wrong shape, or `state_schema_version` mismatch
(`"corrupt"` / `"incompatible_schema"`) — returns a fresh, empty
`KnowledgeInitState` plus a human-readable `reason`, surfaced in the report
as `reuse_rejected_reason`.

**Two independent corruption scenarios, both handled safely:**
- `init_state.json` corrupted, but a family's `family_<name>.json` payload
  is still intact: the orchestrator treats the family as "changed" (state
  bookkeeping is gone), but the incremental diff against the still-valid
  payload finds **zero** actual content changes — a safe, minimal
  "rebuild" that re-derives correct bookkeeping without re-staging
  anything.
- The payload file is *also* corrupted or missing: falls through to a full
  re-stage for that specific family (`only_ids=None`).

### Concurrency and atomicity

`apex_host/knowledge/init_lock.py::cache_directory_lock()` — a
cross-process advisory lock using `os.O_CREAT | os.O_EXCL` (atomic at the
OS level) on a `.init.lock` file inside the cache directory. This is
**not** related to, and never interacts with, `MemoryAPI._graph_lock` /
`_staging_lock` (single-process `asyncio.Lock`s) — it solves a different
problem (two OS processes racing to read-decide-write the same cache
directory), entirely at the filesystem level, entirely inside
`apex_host`. A lock file older than `stale_after_seconds` (default 300s)
is treated as abandoned (its holder crashed without releasing it) and
reclaimed. If the lock cannot be acquired within
`knowledge_cache_lock_timeout_seconds` (default 30s), the caller degrades
to an **uncached** initialization for that run only — never blocks
indefinitely, never corrupts the cache.

Because every write is atomic (temp + rename) and the lock serializes the
read-decide-write critical section per cache directory, a crash at any
point leaves either the previous valid state or no state — never a false
"fully initialized" claim, and never a torn/partially-written file.

### No durable storage configured

When `ApexConfig.knowledge_cache_path` is `None` (the default) or
`knowledge_cache_enabled=False`, the orchestrator falls back to the
pre-existing, now-fast, unconditional stage-everything-every-time path,
logs a clear `WARNING` explaining persistence is disabled, and reports
`persistence_enabled=False`, `persistence_path_category="not_configured"`.
It never pretends to be persistent when it is not.

## 4. Configuration and CLI

New `ApexConfig` fields: `knowledge_cache_path: str | None = None`,
`knowledge_cache_enabled: bool = True`,
`knowledge_cache_lock_timeout_seconds: float = 30.0`,
`knowledge_cache_stale_lock_seconds: float = 300.0`.

New CLI flags (`apex_host.main`, `apex_host.eval.run_htb_local`,
`apex_host.container_entrypoint`): `--knowledge-cache-path DIR`,
`--no-knowledge-cache`, `--knowledge-cache-lock-timeout SECONDS`,
`--reset-knowledge-cache [FAMILY]`.

Environment variables (`apex_host/config_env.py`, same
CLI-wins-over-env-wins-over-default precedence as every other setting):
`APEX_KNOWLEDGE_CACHE_PATH`, `APEX_KNOWLEDGE_CACHE_LOCK_TIMEOUT_SECONDS`.

## 5. Reset and rebuild commands

```bash
# CLI: reset every family, forcing a full cold rebuild on the next run
python -m apex_host.eval.run_htb_local --target <IP> \
    --knowledge-root ./knowledge --knowledge-cache-path ./cache \
    --reset-knowledge-cache

# CLI: reset only one family
python -m apex_host.eval.run_htb_local --target <IP> \
    --knowledge-root ./knowledge --knowledge-cache-path ./cache \
    --reset-knowledge-cache intel_db

# Docker Compose: remove the named volume entirely (stack must be stopped)
docker compose down
docker volume rm apex-knowledge-cache

# Docker Compose: remove ALL project named volumes (equivalent, broader)
docker compose down -v
```

`reset_knowledge_cache(cache_dir, family=None)` (importable from
`apex_host.knowledge.init_cache`) deletes the relevant `family_<name>.json`
payload file(s) and their entries in `init_state.json`. Safe to call when
nothing is cached yet (returns `0`). This is the explicit, documented path
to actually purge a `deprecated_ids` entry (§3, item 5) — the next run
starts cold for the reset family(ies) and only stages what currently
exists in the compiled files.

## 6. Docker volume

`compose.yaml` gained one new, minimum-necessary durable volume:

```yaml
services:
  apex:
    environment:
      APEX_KNOWLEDGE_CACHE_PATH: ${APEX_KNOWLEDGE_CACHE_PATH:-/app/knowledge_cache}
    volumes:
      - apex-knowledge-cache:/app/knowledge_cache
volumes:
  apex-knowledge-cache:
    name: apex-knowledge-cache
```

A **named** volume (Docker-managed lifecycle), not a bind mount — the
cache is opaque, container-internal bookkeeping with no reason for an
operator to browse it from the host the way `./run_reports` is. It holds
only `init_state.json` + one `family_<name>.json` per compiled-knowledge
family (manifest identity, content-hash digests, promoted document
text/metadata) — **never** secrets, **never** raw compiled-knowledge
source files (those stay baked into the image at `/app/knowledge`,
unchanged since Infra Phase 5), and **never** engagement- or
target-specific state (episodic memory and the working-tier EKG remain
entirely in-process, never persisted by this feature — see §8). `kali`
never mounts this volume; it has no reason to read or write it.

## 7. Cold / warm / incremental behavior — measured benchmark

Reproducing the exact reported scale (63,783 total records: policy_db=33,
methodology_db=4, intel_db=53,505, payload_db=10,241; 19 permanently
below-confidence records interspersed throughout):

| Run | Mode | records_staged | records_promoted | records_skipped_existing | wall time |
|---|---|---|---|---|---|
| 1. Clean cold init | `cold` | 63,783 | 63,764 | 0 | **1.693s** |
| 2. Immediate second (unchanged) | `reused` | 0 | 0 | 63,783 | **0.662s** |
| 3. One family changed (+1 record) | `incremental` | 1 | 1 | 63,783 | **0.691s** |

All three runs reproduce `stop_reason=no_progress`,
`blocked_reason_counts={"below_min_confidence": 19}` on the cold run (run
2/3 have `records_blocked=0` since nothing was staged, so no promotion
pass ran for those families).

**Honest accounting of the warm-run cost:** 0.662s for a fully-reused run
is not "instant" — it is the time to read and SHA-256-hash all 63,783
compiled records across 4 files to compute the comparison manifest (a
read-only, `MemoryAPI`-free operation — see §3), plus importing 63,764
already-promoted documents into a fresh `BM25LexicalIndex`. This is,
however, ~2.5x faster than the cold run and, more importantly, **does zero
`propose_knowledge()`/`promote_knowledge()` calls** — the actual
Reflector-promotion cost (the dominant cost in the original live-test
report) is completely eliminated on a cache hit, not merely reduced.

Compare against the live-test baseline: ~1,758 seconds for the promotion
loop alone, repeated on every run regardless of whether anything changed.

## 8. Security considerations

- The cache never stores secrets. Compiled knowledge records themselves
  carry no credential material; the cache payload is a mechanical
  transformation of the same compiled JSONL files APEX already ships.
- The cache is strictly **compiled-knowledge** state — HTB
  target-specific episodic memory and the working-tier EKG are never
  written to it. `initialize_compiled_knowledge()` only ever touches the
  `BM25LexicalIndex` (via `import_documents()`) and the staging/promotion
  path (via the existing `propose_knowledge()`/Reflector path) — it never
  touches `MemoryAPI`'s graph or episodic stores.
- `init_state.json`/`family_<name>.json` are plain JSON, human-readable —
  intentionally, since they hold nothing sensitive; an operator can
  inspect them directly.
- The cross-process lock file (`.init.lock`) contains only a PID and a
  timestamp — no data.

## 9. Expected startup logs

**Cold (no cache, or first run):**
```
knowledge init cache: no durable knowledge_cache_path configured — persistence is DISABLED for this run. ...
Compiled knowledge staged:
  policy_db: 33
  ...
Reflector bootstrap: passes=639 promoted=63,764 remaining=19 stop_reason=no_progress elapsed=0.2s blocked_reasons={'below_min_confidence': 19}
```

**Warm (unchanged, cache hit):**
```
knowledge init cache: policy_db reused (33 records imported from cache, 0 staged, 0 promoted)
knowledge init cache: methodology_db reused (4 records imported from cache, 0 staged, 0 promoted)
knowledge init cache: intel_db reused (53505 records imported from cache, 0 staged, 0 promoted)
knowledge init cache: payload_db reused (10241 records imported from cache, 0 staged, 0 promoted)
```

**Corrupted state:**
```
init_state: malformed JSON at <path>/init_state.json: ...
knowledge init cache: policy_db marked complete but payload snapshot missing/corrupt — treating as changed
```
(only when the payload is *also* gone/corrupt — otherwise the rebuild is
silent and cheap, see §3)

## 10. Blocked-record diagnostics — how to read them

`RunReport`'s "Knowledge Seeding" text section (and the JSON
`knowledge_seeding.promotion.blocked_reason_counts` field) shows a
**bounded, grouped-by-reason** summary — never a list of the actual
blocked record IDs. Categories (from `memfabric.reflector.gates
.classify_unpromoted_knowledge` / `classify_unpromoted_skill`):

| Reason | Meaning | Permanent this run? |
|---|---|---|
| `below_min_confidence` (knowledge) | `entry.confidence < min_confidence` | **Yes** — a `KnowledgeEntry`'s confidence never changes after staging |
| `below_min_evidence` (skill) | `evidence_count < min_evidence_count` | No — evidence accumulates via merges |
| `below_min_confidence` (skill) | `confidence < min_confidence` | No — a skill's confidence can rise via merges |
| `quarantined` (skill) | Permanently removed from retrieval | Yes |
| `eligible_pending_pass` | Clears the gate but a per-pass cap was reached first | No — will promote on a future pass |

If you see `below_min_confidence` records at the end of a cold run's
knowledge seeding, this is expected and correct — those specific compiled
records were authored/compiled at a confidence below
`Config.min_confidence` (default 0.5), and no number of additional
Reflector passes will change that. Investigate the compiler output for
that record (e.g. a PDF-stub methodology record compiled without a PDF
library installed, which lands at confidence 0.4) rather than raising
`reflector_max_promotions_per_run` or `knowledge_promotion_max_passes`.

## 11. Migration

**Existing users without the cache:** `knowledge_cache_path` defaults to
`None` — behavior is byte-for-byte the pre-Phase-4 unconditional
stage-everything path (just faster, thanks to §2's fix), until an operator
opts in with `--knowledge-cache-path` (or the Compose default, which
already sets it via the new named volume). No manual, destructive
migration is required.

**Existing compiled knowledge** (the `compiled/*.jsonl` files themselves)
is fully unchanged and fully supported — the manifest system reads the
exact same files `apex_host.knowledge.compiled_loader` always has.

**Schema/version handling:** `apex_host.knowledge.compiler.schemas
.COMPILER_SCHEMA_VERSION` (compiled-record shape) and
`apex_host.knowledge.init_state.STATE_SCHEMA_VERSION` (persisted
bookkeeping shape) are independent, explicit version constants. A future
change to either is detected automatically (a mismatched
`COMPILER_SCHEMA_VERSION` shows up as part of the manifest identity and
causes a normal "changed" re-stage; a mismatched `STATE_SCHEMA_VERSION`
is detected by `read_init_state()` as `"incompatible_schema"` and triggers
a safe rebuild) — no manual one-time action is required in either case.
