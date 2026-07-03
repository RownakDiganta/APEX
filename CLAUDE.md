# CLAUDE.md — Unified Memory Fabric & Coordination Substrate

This file instructs Claude Code on what to build, how to structure it, and what the
invariants are. Read it fully before writing any code.

> **Reference architecture:** `APEX-Nexus-Unified-Architecture-Detailed.md` (project
> root) is the detailed engineering spec that this file distils. Read both before
> making structural changes. CLAUDE.md governs implementation decisions;
> the architecture doc provides the full design rationale, data schemas, scaling
> model, and evaluation plan.

---

## 0. What this project is (and is not)

You are building a **domain-agnostic, typed memory substrate for long-horizon
multi-agent systems**, plus the **blackboard coordination layer** that sits on top
of it. This is the reusable infrastructure core of the "APEX-Nexus" design: a
unified four-tier memory fabric behind a single typed API, a hybrid retrieval
engine, and a stateless-executor orchestration loop with an async consolidation
worker.

The substrate is defined over **generic node/edge/episode/skill types**. It knows
nothing about any specific task domain. Domain logic (what the executors actually
*do*, what a "skill" encodes, what gets parsed out of tool output) is supplied by
the host application through narrow interfaces this substrate defines. Do **not**
bake any domain-specific behavior, tool-driving code, or task content into the
substrate. If you find yourself writing anything that drives an external tool,
controls a browser, or encodes a task-specific procedure, stop — that belongs in
the host application, behind the `Executor` / `Parser` protocols, not here.

Build only what Section 3 lists. Section 9 ("Out of scope") is binding.

---

## 1. Design invariants (do not violate these)

These come straight from the architecture and are the reason the system works.
Treat them as hard constraints, not suggestions.

1. **The Memory API is the only way to touch state.** No component reads or
   mutates a store directly. Everything goes through `MemoryAPI`. If a component
   needs state it doesn't have, it *retrieves* it — it never accumulates a
   transcript.

2. **Episodic memory is append-only and immutable.** An episode, once appended, is
   never edited or deleted. It is an audit log you can replay to reconstruct any
   run. Treat it like an event store.

3. **Working memory (the graph) is upsert with last-writer-wins _per field_, plus
   provenance.** When two writers set the same node field, the later write wins for
   *that field only* — never clobber the whole node. Every node and edge carries
   `confidence`, `source`, `first_seen`, `last_seen`.

   **LWW ordering rule (non-negotiable):** "Later write" is determined by a
   monotonic `logical_version` counter maintained inside `MemoryAPI`
   (`_write_clock`), incremented at the moment each `upsert_node` / `upsert_edge`
   call is received. `logical_version` is the **primary** ordering key.
   Wall-clock timestamps (`last_seen`, `first_seen`) on the `Node`/`Edge` objects
   are **observational metadata only** — they are NOT the ordering authority.
   A caller that supplies a back-dated or future-dated `last_seen` cannot cause
   its write to win or lose based on the wall-clock value alone. Timestamps are
   used only as a tie-breaker when two calls share the same `logical_version`
   (which should not occur in normal sequential execution).

   Per-field provenance records: `value`, `source`, `timestamp`, `confidence`,
   **and `logical_version`**. Conflict detection is **epistemic** (do two
   high-confidence sources disagree on the value?) and fires regardless of
   `logical_version` ordering — a logically-later write that contradicts a
   high-confidence existing value still creates a `Conflict` rather than
   silently overwriting.

4. **Semantic and procedural writes are _proposals_, not commits.** A `propose_*`
   call stages an entry. It does **not** become retrievable until the Reflector
   promotes it through a quality gate. One bad turn must not be able to poison the
   knowledge base. This staging boundary is non-negotiable.

5. **Context is retrieved and scoped, never accumulated.** Every planner/executor
   invocation gets a freshly retrieved, bounded `EvidenceBundle` (a scoped subgraph
   + ranked evidence). Context size is a function of the live working-set, not of
   turn count. This is the entire point of the design — protect it.

6. **Executors are stateless.** All durable state lives in the fabric. An executor
   crash loses nothing; a run is resumable from the episodic log + graph snapshot.
   Do not let an executor hold state between tasks.

7. **No agent-to-agent calls.** Coordination is exclusively through the fabric
   (blackboard model). Components communicate by writing to and reading from
   memory, never by calling each other.

8. **Provenance and confidence travel with every claim.** Anything retrievable can
   be traced to who wrote it, when, and how confident they were. Conflicting
   high-confidence claims surface as a `Conflict` the orchestrator must resolve
   before depending on the value.

---

## 2. Tech stack & conventions

- **Language:** Python 3.11+. Use `from __future__ import annotations`.
- **Typing:** full type hints everywhere. Run `mypy --strict` clean. Public
  surfaces use `Protocol` for pluggable boundaries (executors, parsers, embedders,
  rerankers, stores) so the substrate stays domain-agnostic and testable.
- **Data shapes:** `@dataclass(slots=True)` for records; `pydantic` v2 only at the
  external API boundary if you add a service layer (not required for the core).
- **Async:** the control loop and Memory API are `async`. Stores expose async
  methods. CPU-bound work (BM25 scoring, embedding) goes through
  `asyncio.to_thread` or a process pool — never block the loop.
- **Errors:** no bare `except`. Catch specific exceptions. The loop must degrade
  gracefully: a failed executor produces a `fundamental`/`script_error` outcome
  episode, it does not crash the engagement.
- **Logging:** stdlib `logging`, module-level loggers, structured where it helps.
  No `print` in library code.
- **IDs:** ULID or UUID4 (pick one, wrap in a `new_id()` helper). IDs are opaque
  strings.
- **Time:** UTC ISO-8601 via a single `now()` helper. Never call `datetime.now()`
  scattered around.
- **Dependencies:** keep them few and boring. `rank_bm25`, `numpy`, a vector index
  (`faiss-cpu`), `networkx` for the in-memory graph reference implementation,
  `langgraph>=0.2` for the coordination state machine, `pytest`/`pytest-asyncio`
  for tests. Everything pluggable behind a Protocol so these can be swapped.
- **No global mutable singletons** for stores. Inject dependencies through
  constructors. (One small exception: a module-level `logging` logger.)

### Reuse from the predecessor codebase
A prior project ("APEX") already has clean, domain-neutral implementations of two
things you should adapt rather than reinvent:
- **A BM25-over-a-markdown-corpus index** (lazy build, `## `-section chunking,
  2-char-minimum tokenizer that preserves short acronyms, zero-score filtering).
  Reuse this pattern as the **lexical channel** of the retriever and as a static
  semantic-seed loader. Keep it behind the `LexicalIndex` Protocol.
- **A BM25 retriever with a dedup guard, top-k cap, and graceful empty-index
  degradation.** Reuse the structure for the same behaviors here.
These are the only two pieces to port. Port the *shape and the lessons*
(graceful degradation, lazy indexing, dedup), not any task content.

### Logical vs physical tier storage (read before writing tier-related code)

The "four-tier memory fabric" label refers to **logical tiers distinguished by
metadata at retrieval time**.  The physical backend mapping is:

| Tier | Dedicated physical store | Also indexed in |
|---|---|---|
| `working` | `GraphStore` (EKG nodes + edges) | Shared `LexicalIndex` — `tier=working` metadata |
| `episodic` | `EpisodicStore` (append-only JSONL) | Shared `LexicalIndex` — `tier=episodic` metadata |
| `semantic` | **None — logical tier only** | Shared `LexicalIndex` + `VectorIndex` — `tier=semantic` metadata |
| `procedural` | **None — logical tier only** | Shared `LexicalIndex` + `VectorIndex` — `tier=procedural` metadata |

`semantic` and `procedural` are **metadata-distinguished entries in the same
shared BM25 and vector indexes** that serve all tiers.  When
`MemoryAPI.promote_knowledge()` or `promote_skill()` is called, the entry is
added to the same `LexicalIndex`/`VectorIndex` instance as working and episodic
content — the only difference is `"tier": "semantic"` or `"tier": "procedural"`
in the metadata dict.  `MemoryAPI.query(tiers=[...])` enforces tier boundaries
by post-filtering on that metadata field inside `HybridRetriever.search()`.

**Do not claim physical tier isolation** in code comments, docstrings, or tests
unless you have explicitly configured separate backend instances.  The staging
gate and Reflector promotion are quality/provenance boundaries, not storage
boundaries.

Physical backend separation (a dedicated `LexicalIndex` or `VectorIndex`
instance per tier) is possible by injecting different store implementations
through the Protocol seams in `stores/protocols.py`.  It is **not the default**
and the substrate does not require it.

### No domain-specific regex in memfabric (non-negotiable)

`memfabric` is domain-agnostic.  **No domain-specific identifier patterns may
appear in any `memfabric/` source file**, including the Reflector.

The only built-in slot-extraction pattern in `memfabric/reflector/consolidate.py`
is UUID v4 — universally opaque in any domain.  All other patterns (IPv4,
port numbers, CVE IDs, hostnames, medical record IDs, financial tickers, etc.)
are supplied by the host application via `Config.slot_patterns`.

**Rules:**

1. **`Config.slot_patterns` defaults to `[]`** (empty list).  With the default,
   only UUIDs are replaced with slot references during skill generalization.
   The substrate ships neutral and produces useful skills for any domain.

2. **Host apps own domain-specific patterns.**  The cybersecurity host supplies
   IPv4 and port patterns through `ApexConfig.slot_patterns`, which are copied
   into a `memfabric.Config` at runtime.  A medical host would supply MRN
   patterns; a financial host would supply ticker/ISIN patterns — all through
   the same `Config.slot_patterns` field.

3. **`generalize()` accepts `slot_patterns` as a parameter.**  The Reflector
   worker passes `config.slot_patterns` through to every `generalize()` call.
   Direct callers may supply patterns inline.

4. **The static scan in `tests/test_reflector_domain_agnostic.py` is
   authoritative.**  The parametrized test `test_no_cybersecurity_terms_in_memfabric_reflector`
   scans every `memfabric/reflector/*.py` file for cybersecurity terminology in
   non-comment lines and fails the build if any is found.  When adding new
   reflector code, ensure it passes this scan.

5. **CVE/CWE patterns remain in `apex_host/knowledge/cve_patterns.py`.**  That
   file feeds the `HybridRetriever`'s regex channel, which is a separate
   extension point from the slot-extraction mechanism.

### LWW ordering policy (read before writing graph-write code)

`MemoryAPI` maintains a monotonic `_write_clock: int` counter.  Every call to
`upsert_node` or `upsert_edge` increments the counter and assigns its current
value as the `logical_version` for that write.  The ordering rules are:

1. **`logical_version` is the primary ordering key.**  The write with the
   higher `logical_version` wins, always — regardless of the `last_seen` /
   `first_seen` timestamps on the `Node` or `Edge` objects.
2. **Wall-clock timestamps are observational metadata only.**  They are stored
   in per-field provenance for auditability but must never be the sole reason
   one write beats another.  A caller supplying a back-dated `last_seen` does
   not cause its write to lose (or win) based on the timestamp alone.
3. **Timestamp is a tie-breaker only.**  Used only when two writes share the
   same `logical_version`, which should not occur in normal sequential execution.
4. **Conflict detection is epistemic, not temporal.**  When both the existing
   value and the incoming value have `confidence >= conflict_confidence_floor`
   and the values differ, a `Conflict` is created regardless of the
   `logical_version` ordering.  A logically-later write does not automatically
   win over a high-confidence existing claim — the contradiction is escalated.
5. **`logical_version` is recorded in per-field provenance.**  Every field
   provenance dict includes `{value, source, timestamp, confidence,
   logical_version}`.  `Conflict.claim_a` and `Conflict.claim_b` both carry
   `logical_version` so the orchestrator can see causal ordering.

**Do not implement LWW using only wall-clock comparison.** If you find code
that compares `last_seen` strings without consulting `logical_version` first,
it violates this invariant and must be fixed.

### Working-tier retrieval freshness (non-negotiable)

Every `upsert_node` and `upsert_edge` call must **synchronously** refresh
the retrieval indexes so that the immediately following `query()` call sees
the written data — no lag, no cache TTL wait, no Reflector promotion required
for working-tier state.

Three surfaces that must be kept fresh on every graph write:

1. **Lexical (BM25) index** — `_refresh_working_indexes()` calls
   `lexical.add(id, text, meta)` which updates in-place (no stale duplicate
   doc per id).  This is always active.
2. **Retrieval cache** — `_refresh_working_indexes()` calls
   `kv.delete_prefix("retrieval:")` which deletes all cached query results.
   Without this, a second call with the same query text returns stale data
   from the KVStore even after the index is updated.  This is always active.
3. **Vector (dense) index** — when an `Embedder` is injected into `MemoryAPI`
   at construction time (`embedder=` keyword arg), `_refresh_working_indexes()`
   also calls `embedder.embed([text])` and `vector.add(id, vec, meta)`.  If no
   embedder is provided (the default), the vector index is not updated on writes
   and the dense channel will return no working-tier results when it fires.

**Invariant:** a fresh `query()` immediately after a graph write must see that
write.  If you add any new code path that writes to the `GraphStore` directly
without going through `MemoryAPI`, or if you add a caching layer without
corresponding invalidation, you break this invariant.

### Conflict lifecycle (non-negotiable)

Every `Conflict` record goes through a defined lifecycle managed by
`memfabric/coordination/conflict.py`.  The lifecycle prevents conflicts from
accumulating forever while preserving full provenance.

**Statuses** (`ConflictStatus` enum, `memfabric/types.py`):

| Status | Meaning | Blocks dependents? |
|---|---|---|
| `open` | Detected, awaiting resolution | **Yes** |
| `resolved` | Winner chosen by policy or orchestrator | No |
| `superseded` | A later write made both claims moot | No |
| `quarantined` | Reflector marked the field as untrusted | No |

**Default resolution policy** (applied by `resolve_by_policy` in `conflict.py`):
1. Higher `confidence` claim wins.
2. Tie → higher `logical_version` claim wins.
3. Still tied → conflict **remains `open`** (returns `False`); human intervention required.

**Invariants:**
- Only `open` conflicts block dependents (`dependents_blocked()` predicate).
- `resolved`, `superseded`, and `quarantined` conflicts do **not** block.
- Every status transition appends an entry to `Conflict.history` (append-only
  provenance log).  Conflict records are never deleted.
- `claim_a` and `claim_b` dicts are never mutated after creation; they are the
  exact provenance state at the moment of detection.
- The `resolved: bool` field is kept for backward compatibility; it is `True`
  whenever `status` is anything other than `open`.

**`MemoryAPI` conflict surface:**
- `get_conflicts(node_id=, status=)` — filter by node and/or lifecycle status.
- `resolve_conflict(id, resolution=None)` — apply policy (if no string given) or
  record an explicit orchestrator override.
- `auto_resolve_conflict(id)` — apply policy only, returns `False` on tie.
- `supersede_conflict(id, reason=)` — mark superseded.
- `quarantine_conflict(id, reason=)` — mark quarantined.
- `dependents_blocked_by(node_id, field_name)` — True if any open conflict
  contests that field.

**Unresolved conflicts must block dependents** — any planning or query path that
reads a contested field must call `dependents_blocked_by()` first and skip or
escalate if it returns `True`.

### Graph merge must be transactional (non-negotiable)

`MemoryAPI.apply_deltas(nodes=..., edges=..., episodes=..., knowledge=..., skills=...)`
is the atomic batch-write surface.  **All writes in a batch succeed together or
none are visible** — no partial state is exposed to future `query()` calls.

Rules:
1. **Write order within a batch:** nodes → edges → episodes → knowledge proposals
   → skill proposals.  A failure at any step triggers full rollback of everything
   committed earlier in the same batch.
2. **Rollback for new entries:** newly-created nodes/edges are deleted via
   `delete_node` / `delete_edge`; their lexical/vector index entries are removed.
3. **Rollback for updated entries:** the pre-batch snapshot captured before
   writes began is restored via `put_node` / `put_edge`; indexes are re-synced
   to the restored state.
4. **Episode rollback:** `JSONLEpisodicStore._pop_episodes` is a private rollback
   method (NOT on the `EpisodicStore` Protocol — it does not violate the
   immutability invariant for normal code paths).  `apply_deltas` calls it via
   `getattr`; stores without it log a warning and leave those episodes in place.
5. **Proposal rollback:** staged knowledge/skill dicts are cleaned up in reverse
   write order.
6. **Cache bust after rollback:** `kv.delete_prefix("retrieval:")` is called
   after rollback so stale cache entries from the failed batch are not returned.
7. **`apex_host/graph.py` must use `apply_deltas`:** `parse_observation` calls
   `apply_deltas(nodes=..., edges=..., knowledge=...)` and `write_memory` calls
   `apply_deltas(episodes=[episode])`.  Individual `upsert_node` / `upsert_edge`
   / `propose_knowledge` / `append_episode` calls are no longer acceptable in
   these graph nodes.

**Invariant:** after any exception during an `apply_deltas` call, the fabric
state must be byte-for-byte identical to its state immediately before the call.
A test that queries for rolled-back entries must find nothing.

---

## 3. What to build — module map

Build in this order. Each module is independently testable; write its tests before
moving on.

```
memfabric/
├── __init__.py
├── ids.py                    # new_id(), now()
├── types.py                  # Node, Edge, Episode, KnowledgeEntry, Skill,
│                             # EvidenceBundle, Outcome enum, Conflict
├── stores/
│   ├── __init__.py
│   ├── protocols.py          # GraphStore, EpisodicStore, VectorIndex,
│   │                         # LexicalIndex, KVStore  (all Protocols)
│   ├── graph_networkx.py     # in-memory EKG reference impl (networkx)
│   ├── episodic_jsonl.py     # append-only JSONL event store reference impl
│   ├── lexical_bm25.py       # BM25 channel (adapt predecessor pattern)
│   └── vector_hnsw.py        # dense channel reference impl (hnswlib)
├── api.py                    # MemoryAPI — THE ONLY state surface (Section 4)
├── retrieval/
│   ├── __init__.py
│   ├── protocols.py          # Embedder, Reranker, GraphMatcher Protocols
│   ├── fusion.py             # reciprocal-rank fusion
│   ├── gate.py               # low-confidence gate logic
│   └── engine.py             # HybridRetriever (Section 5)
├── coordination/
│   ├── __init__.py
│   ├── protocols.py          # Executor, Parser, Planner Protocols
│   ├── budget.py             # per-phase token/turn budget accounting
│   ├── scheduler.py          # concurrency-capped task dispatch
│   ├── conflict.py           # EKG conflict detection + resolution policy
│   ├── graph_state.py        # TurnState TypedDict + reducers (LangGraph)
│   ├── graph_loop.py         # compiled LangGraph StateGraph (Section 6.5)
│   └── loop.py               # Orchestrator — delegates to graph_loop
├── reflector/
│   ├── __init__.py
│   ├── consolidate.py        # episodic→skill generalization + merge (Section 7)
│   ├── gates.py              # promotion / decay / quarantine policy
│   └── worker.py             # async Reflector driven off the episodic stream
└── config.py                 # typed config dataclass; thresholds live here

tests/
└── ... (mirror the package; see Section 8)
```

---

## 4. The Memory API (`api.py`)

This is the heart. Get it right; everything else depends on it.

```python
class MemoryAPI:
    def __init__(self, graph, episodic, retriever, kv, *, config): ...

    # ---- read ----
    async def query(self, *, text: str | None = None,
                    subgraph_anchor: str | None = None,
                    tiers: Sequence[Tier] = ALL_TIERS,
                    k: int = 8,
                    filters: Mapping[str, object] | None = None
                    ) -> EvidenceBundle: ...

    async def get_subgraph(self, anchor_node: str, depth: int,
                           edge_types: Sequence[str] | None = None
                           ) -> SubgraphView: ...

    # ---- write: working memory (upsert, last-writer-wins PER FIELD) ----
    async def upsert_node(self, node: Node) -> str: ...
    async def upsert_edge(self, edge: Edge) -> str: ...

    # ---- write: episodic (append-only, immutable) ----
    async def append_episode(self, trace: Episode) -> str: ...

    # ---- write: staged knowledge/skills (proposals; Reflector gates) ----
    async def propose_knowledge(self, entry: KnowledgeEntry) -> str: ...
    async def propose_skill(self, skill: Skill) -> str: ...

    # ---- derived state ----
    async def open_tasks(self) -> list[OpenTask]: ...
        # NOT a stored list. Derived live from the graph: open Weakness-like
        # nodes (generic: nodes of a configurable "actionable" type) that have no
        # terminal outcome edge. The task tree is a VIEW, never a stored tree.
```

Implementation rules:
- `upsert_node` merges field-by-field into any existing node with that id. For each
  incoming field, keep the value with the newer `last_seen`; record `source` per
  field in a `_provenance` sub-map. Never replace the whole props dict.
- `upsert_edge` same discipline.
- On an upsert that contradicts an existing high-confidence field (both ≥
  `config.conflict_confidence_floor`, different values), do **not** silently
  overwrite — create a `Conflict` record via the conflict module and leave both
  claims visible. (See Section 6.4.)
- `append_episode` validates the episode is well-formed, assigns id + timestamp,
  appends, and returns. It must be safe to call concurrently.
- `propose_*` writes to a **staging** area that `query` does **not** read from
  unless `tiers` explicitly includes a `STAGED` debug tier. Promotion is the
  Reflector's job only.
- `query` orchestrates the retriever (Section 5) across the requested tiers and
  returns a single fused, scoped `EvidenceBundle`. It attaches the anchor subgraph
  when `subgraph_anchor` is given.

---

## 5. Hybrid retrieval (`retrieval/`)

Generalize one retriever to serve all tiers. Channels:

- **BM25** (`LexicalIndex`) — exact identifiers, version strings. **Always runs.**
- **CVE/CWE-style regex / identifier lookup** — a cheap exact-match channel over a
  configurable set of identifier patterns. **Always runs.** (The patterns are
  config, not hardcoded domain knowledge — default to an empty pattern set so the
  substrate ships neutral; the host app supplies patterns.)
- **Dense vectors** (`VectorIndex` + `Embedder`) — semantic similarity. **Runs only
  when the BM25 top score < `config.low_confidence_tau`** (the low-confidence gate).
- **Graph traversal** (`GraphMatcher`) — match a query's structural pattern against
  the EKG subgraph. **Runs only when the gate opens** (same condition as dense).

Pipeline: gather candidates from active channels → **reciprocal-rank fusion**
(`fusion.py`, standard RRF with `k≈60`, weights per channel from config) →
**cross-encoder rerank the top-n only** (`Reranker` Protocol; default impl is a
no-op pass-through so the core ships without a heavy model) → return top-k as an
`EvidenceBundle`. **Cache** by `(query_hash, subgraph_hash)` in the `KVStore`.

Keep every channel behind a Protocol. The substrate ships with: real BM25, real
hnswlib vectors, a no-op reranker, an identity embedder stub (raises if used
without being configured), and a simple subgraph-pattern `GraphMatcher`. The host
app swaps in real embedders/rerankers.

`gate.py` is tiny and pure: given the BM25 score distribution and `tau`, decide
whether the expensive channels fire. Unit-test it in isolation.

---

## 6. Coordination layer (`coordination/`)

### 6.1 Protocols (`protocols.py`)
```python
class Executor(Protocol):
    domain: str
    async def run(self, task: TaskSpec, evidence: EvidenceBundle
                  ) -> ExecutorResult: ...   # returns EKG deltas + an Episode

class Parser(Protocol):
    def parse(self, raw: RawObservation) -> ParsedObservation: ...  # → EKG deltas

class Planner(Protocol):
    async def plan(self, goal: Goal, subgraph: SubgraphView,
                   evidence: EvidenceBundle) -> list[TaskSpec] | AbandonSignal: ...
```
The substrate **defines** these and ships **test fakes** only (a deterministic
`EchoExecutor`, a `StaticPlanner`). Real executors/planners live in the host app.
This is the seam that keeps the core domain-agnostic — honor it.

### 6.2 Scheduler (`scheduler.py`)
Concurrency-capped dispatch: `cap = min(os.cpu_count()-2, config.max_concurrency)`,
excess tasks queue. Sub-planner goals with disjoint subgraph anchors may run in
parallel. Return results as they complete; the loop merges them.

### 6.3 Budget (`budget.py`)
Per-phase token/turn ceilings enforced by the orchestrator. A phase that hits its
ceiling stops being allocated new tasks. Pure accounting, fully unit-testable.

### 6.4 Conflict (`conflict.py`)
Detect contradictory high-confidence field writes; create a `Conflict` record;
provide a resolution policy (default: higher confidence wins, ties broken by
recency, unresolved conflicts block dependents). The orchestrator consults this
before depending on a contested value.

### 6.5 Control loop (`graph_state.py` + `graph_loop.py` + `loop.py`)

The coordination loop is a **compiled LangGraph StateGraph**.  The graph has
exactly four nodes, executed in order:

```
START → read_context → plan ─┬─ (abandoned) → END
                               └─ dispatch → merge → END
```

**`graph_state.py`** — `TurnState` TypedDict:
- Holds only generic substrate types: `Goal`, `SubgraphView`, `EvidenceBundle`,
  `TaskSpec` (with `operator.add` reducer), `ExecutorResult` (same reducer),
  `abandoned: bool`, `abandon_reason: str`, and `retry_counts` (dict reducer).
- `MemoryAPI`, `Scheduler`, `Executor` map, `Planner`, and `Config` are
  **never stored in TurnState** — they are injected via closures in
  `build_graph()`.  This upholds Invariant 7 (blackboard, no agent-to-agent
  object passing) and Invariant 1 (MemoryAPI is the sole state surface).

**`graph_loop.py`** — `build_graph(api, scheduler, executors, planner, config, *, checkpointer)`:
- `read_context`: fetches scoped `SubgraphView` + `EvidenceBundle` from `MemoryAPI`.
- `plan`: calls `planner.plan()`; sets `abandoned=True` on `AbandonSignal` or
  appends `TaskSpec`s via the list reducer.
- Conditional edge: `abandoned → END`, else `dispatch`.
- `dispatch`: runs tasks through the concurrency-capped `Scheduler`; retry
  logic (bounded by `config.max_retries`) lives inside the executor closure.
  Appends `ExecutorResult`s via the list reducer.
- `merge`: writes all deltas back through `MemoryAPI` (upserts, episodic
  append, proposals).
- Compiled with a `MemorySaver` checkpointer (pre-registered with the
  substrate's types to silence LangGraph 1.x msgpack warnings).

**`loop.py`** — `Orchestrator.run_turn(goal, planner, budget=None)`:
- Public signature is **unchanged**.
- Creates one `MemorySaver` at `__init__` (shared across turns for auditability).
- Each turn: calls `build_graph(...)` with the current planner captured in a
  closure, assigns a unique `thread_id`, runs `graph.ainvoke(initial_state)`.
- Exposes `orchestrator.last_thread_id` and `orchestrator.last_graph` so callers
  can read back the checkpoint via `await orch.last_graph.aget_state(config)`.

Failure routing by `Outcome` (inside the dispatch node closure):
- `script_error` / `fixable` → retry (bounded by `config.max_retries`).
- `fundamental` → returned immediately without retry.

LangGraph is **confined** to the generic coordination loop.  No domain logic,
no offensive tools, no browser automation, no agent-to-agent calls.  Graph nodes
call the generic Protocols only.

---

## 7. Reflector (`reflector/`)

Async, batched, off the episodic stream. Never in the hot path.

`consolidate.py`:
```
for each completed sub-chain in the episodic stream:
    if outcome == success and chain.length >= config.min_chain_len:
        candidate = generalize(chain)        # concrete params → typed slots
        match = nearest_skill(candidate)     # vector sim + precondition overlap
        if match and sim > config.skill_merge_theta:
            merge(match, candidate); match.wins += 1; bump_confidence(match)
        else:
            stage_new_skill(candidate, confidence=config.skill_prior)
    if outcome == fundamental:
        stage_or_strengthen_negative_skill(chain)
```
`generalize()` turns a concrete action chain into a templated skill with typed
slots — **the templating mechanism is generic** (replace concrete values with slot
references by type). It does not encode any domain procedure itself; it operates on
whatever action structure the host app's episodes contain.

`gates.py` (the safety rail — build it carefully):
- **Promotion gate:** a staged skill/knowledge entry becomes retrievable only after
  it clears `config.min_evidence_count` and `config.min_confidence`.
- **Decay:** confidence of skills unused for > `config.decay_unused_runs` decays.
- **Quarantine:** a skill whose live win-rate drops below `config.winrate_floor` is
  pulled out of retrieval (not deleted — quarantined, with its record intact).

`worker.py` drives this on a schedule or off a stream cursor; it reads episodic +
procedural, writes promotions/decay/quarantine through the Memory API's staging
promotion path. It is the **only** thing allowed to promote a proposal.

---

## 8. Testing requirements

Write tests as you go; do not batch them at the end.

- **Per-field LWW upsert:** two writers, overlapping fields → correct field-level
  merge, provenance recorded, no whole-node clobber.
- **Episodic immutability:** append, then attempt mutation → rejected; replay
  reconstructs state.
- **Staging isolation:** a `propose_*` entry is NOT returned by `query` until the
  Reflector promotes it. This is a security-relevant invariant — test it explicitly.
- **Retrieval gate:** BM25 strong → dense/graph never fire; BM25 weak → they fire.
  Assert with a spy on the expensive channels.
- **RRF fusion:** known input rankings → known fused order.
- **Cache hit:** identical `(query_hash, subgraph_hash)` → second call skips
  channel execution.
- **Open-task view:** is derived, not stored — mutating the graph changes the view
  with no separate write.
- **Scheduler cap:** never exceeds the concurrency cap; excess queues; disjoint
  anchors parallelize.
- **Budget ceiling:** a phase at its ceiling gets no new allocations.
- **Conflict:** contradictory high-confidence writes → `Conflict` created, dependents
  blocked until resolved.
- **Reflector gates:** below-threshold staged skill never promoted; unused skill
  decays; losing skill quarantined and removed from retrieval.
- **Resumability:** kill mid-run (drop in-memory state), rebuild from episodic +
  graph snapshot → engagement continues correctly.

**LangGraph-specific tests** (`tests/test_graph_loop.py`):
- **Turn round-trip parity:** graph-backed `Orchestrator` produces the same
  outcomes as the old hand-rolled loop.
- **Conditional abandon edge:** `AbandonSignal` → `plan` node sets
  `abandoned=True` → router sends to `END`; `results` is empty.
- **Outcome routing / retries:** `script_error` retried up to `max_retries`;
  `fundamental` not retried; `fixable` clue injected into params on retry.
- **Checkpoint round-trip:** after `run_turn`, the turn's state is readable via
  `await orch.last_graph.aget_state({"configurable": {"thread_id": tid}})`.
- **State stays generic:** `TurnState` fields must not contain `MemoryAPI`,
  `Scheduler`, `Executor`, `Planner`, or `Config` types — verified by type
  introspection.
- **Budget integration:** pre-exhausted budget skips graph entirely; budget
  consumed on dispatch; NOT consumed on abandon.

Use `pytest-asyncio`. Use the test fakes (`EchoExecutor`, `StaticPlanner`) — do not
write real executors to test the loop.

---

## 9. Out of scope — DO NOT build these here

These are intentionally excluded. They are either host-application concerns or
outside what this substrate should contain. If the architecture doc mentions them,
that is context, not an instruction to implement them in this repo.

- **Any concrete Executor that drives an external tool, shell, scanner, or network
  service.** The substrate ships only the `Executor` Protocol and deterministic
  test fakes. Real executors are the host app's responsibility and must not appear
  here.
- **Any browser-driving / page-automation / auth-flow component.** Only the generic
  `Executor` seam exists here; no automation, no DOM/token/session handling.
- **Domain-specific parsers.** Ship the `Parser` Protocol and a trivial pass-through
  fake. Real parsers that interpret specific tool output live in the host app.
- **Pre-loaded skill/knowledge content or domain precondition templates.** The
  procedural and semantic tiers ship **empty**. Seeds are loaded by the host app at
  runtime through `propose_*` + Reflector promotion. Do not ship a populated KB.
- **Real embedder / reranker model weights.** Ship Protocols + a no-op reranker +
  an embedder stub that raises if used unconfigured. Wiring a real model is host-app
  config.
- **CVE/CWE/identifier pattern sets.** The regex channel ships with an **empty**
  default pattern set; patterns are config supplied by the host app.
- **Service/network/API exposure, auth, multi-tenant, or deployment infra.** This is
  a library. No server, no endpoints, unless explicitly asked for later.

---

## 10. Definition of done (for the skeleton)

- All modules in Section 3 exist with the signatures above, `mypy --strict` clean.
- Every Section 8 test passes against the reference store impls (194 total).
- A `examples/smoke_run.py` wires: networkx graph + JSONL episodic + BM25 + faiss
  + the test-fake `EchoExecutor`/`StaticPlanner` + LangGraph orchestrator, runs
  ~5 loop turns, and shows: retrieval scoping, per-field upsert + provenance, an
  appended episode stream, the derived open-task view changing, a LangGraph
  checkpoint written and read back, and the Reflector promoting one skill through
  the gate — **all on synthetic, domain-neutral data**.
- `README.md` documents the Memory API surface, the eight invariants (Section 1),
  and the host-app extension seams (the Protocols), making explicit that executors,
  parsers, embedders, and seed content are supplied by the host application.

---

## 11. APEX Host Application Layer

`memfabric` remains the substrate. `apex_host` is the cybersecurity application
built on top of it, occupying exactly the extension seams Section 9 reserved
(`Executor`, `Parser`, `Planner`, identifier-pattern config, seed knowledge).
**Do not add cyber-specific code to `memfabric`. Do not delete or rewrite
`memfabric`.** Everything in this section lives under `apex_host/`.

### 11.1 Module map

```
apex_host/
├── __init__.py
├── main.py              # CLI: python -m apex_host.main --target T --payload-repo P --dry-run
├── config.py             # ApexConfig (target, payload_repo_path, allowed_tools, dry_run=True, ...)
├── types.py               # ApexPhase, ApexFinding, ToolCommand, ToolResult,
│                          # BrowserObservation, ApexRunConfig
├── graph_state.py         # ApexGraphState TypedDict — serializable-only fields
├── graph.py                # APEX multi-agent LangGraph (Section 11.3)
├── runtime.py               # Wires MemoryAPI + stores + retriever + APEX graph
├── llm/
│   ├── router.py            # ModelRouter (LangChain) + FakeModelRouter test fake
│   └── prompts.py
├── planners/                # rule-based today; LLM seam for later
│   ├── global_planner.py
│   ├── recon_planner.py
│   ├── web_planner.py
│   ├── priv_esc_planner.py
│   └── credential_planner.py
├── agents/                  # implement memfabric.coordination.protocols.Executor
│   ├── recon_executor.py
│   ├── browser_executor.py
│   ├── execute_executor.py
│   └── repair_executor.py
├── parsers/                 # produce memfabric Node/Edge deltas
│   ├── nmap_parser.py
│   ├── ffuf_parser.py
│   ├── gobuster_parser.py
│   ├── browser_parser.py
│   └── command_parser.py
├── tools/
│   ├── safety.py             # allowlist + dangerous-operator/destructive-command blocking
│   ├── runner.py              # asyncio.create_subprocess_exec, never shell=True
│   └── registry.py
├── knowledge/
│   ├── payload_repo_loader.py # RAG seed source — ingests an external payload repo
│   ├── cve_patterns.py         # CVE-\d{4}-\d+, CWE-\d+, identifier regex (config, not content)
│   └── seed_loader.py
└── eval/
    ├── metrics.py
    └── run_synthetic_machine.py

tests/apex_host/
├── test_graph.py
├── test_payload_repo_loader.py
├── test_recon_parser.py
├── test_browser_parser.py
├── test_tool_safety.py
└── test_synthetic_run.py
```

### 11.2 Safety invariants (non-negotiable)

These are stricter than, and additive to, the memfabric invariants:

- **No raw subprocess calls outside `apex_host/tools/runner.py`.** Every
  command execution path goes through `runner.py`, which goes through
  `safety.py` first.
- **`asyncio.create_subprocess_exec`, never `shell=True`.** Arguments are
  passed as a list; no shell string interpolation.
- **`tools/safety.py` gates every command**: tool name must be in
  `ApexConfig.allowed_tools` (allowlist); destructive commands (`rm`, `mkfs`,
  `dd`, `shutdown`, `reboot`, ...) are blocked unconditionally, independent of
  the allowlist; shell metacharacters (`;`, `&&`, `||`, `|`, `>`, `>>`, `<`,
  `` ` ``, `$(`) found in any token raise `ValueError`.
- **`ApexConfig.dry_run` defaults to `True`.** With `dry_run=True`,
  `runner.py` returns a `ToolResult` describing what would have run and
  performs no execution. Real execution requires the host to explicitly set
  `dry_run=False`.
- **No real autonomous exploitation.** Planners are deterministic, rule-based,
  and do not make autonomous high-risk exploit decisions. `ExecuteExecutor`
  performs bounded command execution only — no destructive commands, ever
  (enforced by `safety.py`, not by planner discipline alone).
- **`BrowserExecutor` only drives Playwright when `dry_run=False`.** In
  dry-run mode it returns a synthetic `BrowserObservation`. It holds no
  browser state across tasks — each `run()` call is stateless, consistent
  with memfabric Invariant 6.
- **No payload content lives in source files.** `knowledge/payload_repo_loader.py`
  reads from an external, host-supplied `payload_repo_path` at runtime and
  stages chunks via `MemoryAPI.propose_knowledge()`. The repository content
  itself is never copied into `apex_host` source.
- **All memory writes go through `MemoryAPI`.** No `apex_host` component
  touches a memfabric store directly (memfabric Invariant 1 applies here too).
- **No machine-specific profile files.** Do not create files named after
  individual HTB machines or targets (e.g. `meow.py`, `lame.py`, `blue.py`,
  or any `<machine-name>.py`). Target details (IP, credentials, payload repo)
  are always supplied through CLI flags at runtime. Machine-specific solver
  logic, expected credential paths, default usernames, and expected service
  configurations must never be committed to the repository. Every authorized
  HTB Easy/Medium machine reachable over the VPN is a valid target and is
  treated identically by the architecture.

### 11.3 The APEX LangGraph (`graph.py`)

This is a **separate** LangGraph StateGraph from memfabric's
`coordination/graph_loop.py`. The distinction matters:

- **memfabric's `graph_loop.py`** is the generic *one-turn* substrate loop
  (`read_context → plan → dispatch → merge`), domain-agnostic, confined to
  the `Executor`/`Planner` Protocols and their test fakes.
- **`apex_host/graph.py`** is the APEX-specific *multi-turn, multi-phase*
  cyber engagement workflow. It is built from real (but safety-gated)
  `apex_host` planners and executors.

```
START → load_context → global_plan → route_phase
      → [recon_agent | web_agent | browser_agent | execute_agent | priv_esc_agent]
      → parse_observation → write_memory → reflect_or_continue
      → END  (or loop back to load_context)
```

- `load_context`: queries `MemoryAPI` for current evidence; populates
  `evidence_summary` in state.
- `global_plan`: rule-based `GlobalPlanner` reads `open_tasks()` / findings /
  turn budget and decides the next `ApexPhase` and goal.
- `route_phase`: conditional edge selecting the agent for the current phase.
- Agent nodes: run a tool via `tools/runner.py` (safety-checked, dry-run
  aware), producing a `last_tool_result`.
- `parse_observation`: the phase-appropriate `parsers/*` module turns the
  tool result into `Node`/`Edge` deltas and writes them through `MemoryAPI`;
  simplified findings are appended to state.
- `write_memory`: appends the turn's `Episode` via `MemoryAPI.append_episode`.
- `reflect_or_continue`: ends when `phase == done` or `turn_count >=
  config.max_turns`; otherwise loops back to `load_context`.

`ApexGraphState` (in `graph_state.py`) holds **only serializable substrate
data** — `run_id`, `target`, `phase`, `goal`, `current_task`,
`evidence_summary`, `findings`, `last_tool_result`, `last_error`,
`completed`, `turn_count`. It must **never** contain `MemoryAPI`, tool
runner instances, executors, planners, or LLM client objects — those are
injected via closures in `build_apex_graph()`, exactly as memfabric's
`build_graph()` does for `TurnState`.

### 11.4 RAG seeding from the payload repository

`knowledge/payload_repo_loader.py` is the RAG seed source for payload
knowledge. It recursively reads `.md`/`.txt`/`.py`/`.rb`/`.sh`/`.json`/
`.yaml`/`.yml` files under `ApexConfig.payload_repo_path`, chunks markdown
files by `## ` heading (reusing the lazy-chunking lesson from Section 2's
predecessor pattern) and other files by size, and calls
`MemoryAPI.propose_knowledge()` per chunk with metadata
(`source_path`, `payload_family`, `file_ext`, `tier="semantic"`,
`source="payload_repo"`). Staged entries are not retrievable until the
Reflector promotes them (memfabric Invariant 4) — `apex_host` does not
bypass the staging gate.

### 11.5 Definition of done for `apex_host`

- Existing memfabric tests still pass unmodified.
- New `tests/apex_host/` tests pass.
- `python -m apex_host.main --target 127.0.0.1 --payload-repo ./payloads
  --dry-run` runs end-to-end with **no real command execution**.
- No cybersecurity-specific code added to `memfabric`.
- No raw `subprocess`/`asyncio.create_subprocess_*` calls anywhere in
  `apex_host` outside `apex_host/tools/runner.py`.
- All memory writes go through `MemoryAPI`.

---

## 12. Working Prototype Roadmap

### 12.1 Goal

Turn the current `apex_host` skeleton into a working prototype that can run
safely against **authorized HackTheBox Easy/Medium machines** from a local
macOS workstation over the HTB VPN. This is a local-first, single-operator
prototype — not a production tool, not a Kali replacement, not a cloud
service.

### 12.2 Meow is the first smoke test only

"Meow" (HTB Starting Point machine) is used as the **first end-to-end
smoke test** for the dry-run → real-execution pipeline. It is not
hardcoded anywhere in the codebase. The architecture is fully
target-agnostic: any HTB Easy/Medium machine reachable over the VPN can be
the engagement target. The only thing that changes between targets is the
`--target` IP/hostname passed on the CLI and the phase progression driven
by whatever the live tool output produces.

### 12.3 Authorization requirement (non-negotiable)

Every real-execution run (`--no-dry-run`) **must** target an authorized
lab machine:

- Hack The Box (HTB) machines accessed through the official HTB VPN.
- Other explicitly authorized lab environments (TryHackMe, PWNX, personal
  lab VMs, etc.).

**Never** run `--no-dry-run` against any host you do not own or have
explicit written permission to test. `dry_run=True` is the default and
remains so. Removing the default requires a deliberate flag on every
invocation.

### 12.4 No Kali integration yet

All tools (`nmap`, `ffuf`, `gobuster`, `curl`, `searchsploit`) run from the
local macOS environment. Homebrew or direct binary installs suffice for the
prototype phase. Kali integration (via SSH, Docker, or a shared toolchain
container) is a future milestone and does not affect the current
architecture — the `ToolRegistry` / `runner.py` boundary is the abstraction
point where that wiring would plug in.

### 12.5 Prototype milestones

| Milestone | What it proves |
|---|---|
| M1 — dry-run end-to-end | CLI runs without errors; all safety gates hold |
| M2 — first real recon | `nmap` output parsed into EKG host/service nodes |
| M3 — phase progression | GlobalPlanner advances through recon → web → credential |
| M4 — Meow smoke test | Full engagement against Meow over HTB VPN, findings logged |
| M5 — second target | Prototype generalizes: different IP, different phase path |

### 12.6 File-header convention (enforced)

Every Python file in this repo must start with:

```python
# filename.py
# One-line explanation of what this file does.
```

This must be the literal first two lines — before docstrings, before
`from __future__ import annotations`, before imports. If you create a new
file, add this header. The CI header scan (`find ... | while read f; do head
-1 "$f" | grep -v "^#" && echo "MISSING: $f"; done`) enforces this.

### 12.7 Local Mac Tool Profile

The default `ApexConfig.allowed_tools` is tuned for a vanilla macOS workstation:

| Tool | Source | Status |
|---|---|---|
| `nmap` | Homebrew (`brew install nmap`) | Default |
| `curl` | macOS built-in | Default |
| `python3` | macOS built-in | Default |
| `nc` | macOS built-in (`/usr/bin/nc`) | Default |
| `netcat` | Alternate binary name | Optional |
| `ffuf` | Homebrew (`brew install ffuf`) | Optional |
| `gobuster` | Homebrew / manual build | Optional |
| `searchsploit` | `exploitdb` Homebrew tap | Optional |

**Optional tools** are registered in `ToolRegistry._KNOWN_TOOLS` but **not** in
the default `allowed_tools`. Add them explicitly:

```python
config = ApexConfig(target="10.10.10.x", allowed_tools=["nmap", "curl", "python3", "nc", "ffuf"])
```

**Missing tools degrade gracefully.** `runner.py` calls `shutil.which()` before
any live execution. If the binary is not in `PATH`, it returns a
`ToolResult(error="tool '...' not found in PATH")` and the engagement continues
— it does not crash. Dry-run mode is unaffected (no PATH check needed; the
dry-run result is synthetic).

**Preflight check.** Before a real-execution run, verify your tool stack:

```bash
python -m apex_host.main --target 10.10.10.x --preflight
```

This calls `check_local_tools(config)` from `apex_host/tools/preflight.py`,
prints a per-tool OK/MISSING table, and exits with code 1 if any tool is
missing, 0 if all are available.

### 12.8 Parser Expansion for Common HTB Services

`apex_host/parsers/` produces EKG node/edge deltas from tool output. All
parsers are **stateless** — they receive raw text and return a
`ParsedObservation` with no stored state. All writes go through `MemoryAPI`
(memfabric Invariant 1). Unknown non-empty output is **never silently dropped**:
it becomes a staged `KnowledgeEntry` at confidence 0.25–0.3.

#### Node and edge type conventions

| Node type | Meaning | Key props |
|---|---|---|
| `host` | A reachable IP/hostname | `ip`, `target` |
| `service` | An open port / protocol binding | `port`, `proto`, `service`, `version` |
| `tech` | An identified product or library | `name`, `version` |
| `endpoint` | An HTTP path/URL | `url`, `status`, `server` |
| `auth_flow` | A login mechanism or credential boundary | `url`, `hint` |
| `credential` | A captured credential or token | `username`, `secret_hint` |
| `access_state` | Current privilege level reached | `level`, `evidence` |

| Edge type | Meaning |
|---|---|
| `exposes` | host → service, host → endpoint |
| `runs` | service → tech, endpoint → tech |
| `requires` | endpoint → auth_flow |
| `contains` | endpoint → form, endpoint → token |

#### Parser routing (in `apex_host/graph.py` `parse_observation`)

| Tool name / `parser` field | Parser class | What it produces |
|---|---|---|
| `nmap` | `NmapParser` | host, service, tech nodes; exposes + runs edges |
| `curl` (HTTP/ output) | `CommandParser` | endpoint + tech nodes; exposes + runs edges |
| `nc` / `netcat` | `BannerParser` | service + tech nodes; runs edges |
| `ffuf` | `FfufParser` | endpoint nodes; exposes edges |
| `gobuster` | `GobusterParser` | endpoint nodes; exposes edges |
| anything else | `CommandParser` fallback | staged `KnowledgeEntry` (confidence 0.3) |

#### Tech extraction rules

- **nmap**: version string → first non-digit token(s) = product name (max 3
  words), first digit-starting token = version. Empty version → no tech node.
- **curl -I**: `Server:` header → `product[/version]` pattern. No `Server:`
  header → endpoint node only, no tech node.
- **nc/netcat**: SSH banner `SSH-proto-software` → OpenSSH/etc. FTP `220`
  banner → vsftpd or ProFTPD if detectable. Telnet `login:` prompt → telnet
  service node. Unrecognised → `KnowledgeEntry`.

### 12.9 Generic Recon Prototype

`ReconPlanner` drives the recon phase in two deterministic stages, reading only
the `SubgraphView` passed in — no direct `MemoryAPI` calls (blackboard model,
Invariant 7).

#### Flow: target → host → service → tech / banner observations

```
turn 1 (no services known)
  ReconPlanner  →  nmap -sV -T4 <target>
  NmapParser    →  host node + service nodes + tech nodes (from version banner)
  MemoryAPI     ←  upsert_node / upsert_edge  (via parse_observation in graph.py)

turn 2+ (services exist in subgraph)
  ReconPlanner  →  nc -nv <target> <port>  (up to 3 safe banner probes)
  BannerParser  →  service node + tech node (SSH/FTP/Telnet/…)
  MemoryAPI     ←  upsert_node / upsert_edge
```

#### Safe banner probe set

`ReconPlanner` only emits `nc` banner probes for services in the
`_BANNER_PROBE_SERVICES` set (ssh, ftp, telnet, smtp, mysql, redis,
postgresql) or whose port is in `_BANNER_PROBE_PORTS` (21, 22, 23, 25,
3306, 5432, 6379). UDP services, closed/filtered ports, and services
outside these sets are skipped. At most `_MAX_BANNER_TASKS = 3` nc tasks
are emitted per turn.

#### Args convention

All args emitted by planners are **complete** — the target (and port for nc)
are already included in `params["args"]`. Graph.py's `_run_one_task` passes
args directly to `ToolCommand` without appending target. This is consistent
across all tools (nmap: `["-sV", "-T4", target]`; nc: `["-nv", target, port]`;
curl: `["-s", "-I", url]`).

#### Dry-run vs live

- `dry_run=True` (default): runner returns synthetic stdout; parsers receive it
  but produce no real nodes (nmap dry-run output is not valid nmap format);
  no real network traffic is generated. Use for routing / safety verification.
- `dry_run=False` (`--no-dry-run`): `nmap -sV -T4 <target>` is executed against
  an **authorized** HTB/VPN target. All safety gates in `tools/safety.py`
  still apply. `nc` banner probes are similarly gated.

#### Recon success criteria (non-negotiable)

A recon turn is only considered **meaningful** when the resulting EKG contains
at least one `service` node in addition to the `host` node.  A host node alone
(IP discovered, no open ports recorded) is **not** sufficient to advance the
phase — the GlobalPlanner must not advance from `recon` to `web` or `credential`
unless at least one `service` node with a valid `port` prop exists in the subgraph.

This rule prevents the engagement from skipping to exploitation phases based on
a bare ping or a failed nmap run.  It is enforced by `GlobalPlanner.decide_phase`
reading `capabilities_from_subgraph()` — the phase advances only when one or
more capabilities (which require service nodes) are present.

**`NmapParser` acceptance criteria** — the parser MUST produce:

| Output | Condition |
|---|---|
| One `host` node | Always, when the IP is present in the output |
| One `service` node per open port | `port`, `proto`, and `service` props required |
| One `exposes` edge per service | `host:<ip>` → `service:<ip>:<port>` |
| One `tech` node per version string | Only when the nmap version field is non-empty |
| One `runs` edge per tech node | `service:<ip>:<port>` → `tech:<name>` |

If nmap output contains no open ports (all filtered or closed), the parser
produces only the `host` node.  That is valid output but insufficient for phase
advancement (see above).

**No machine-specific solver logic** — `NmapParser`, `ReconPlanner`, and
`GlobalPlanner` must not contain hardcoded expected services, expected ports, or
expected credential paths for any specific target.  Every routing decision is
driven exclusively by the live EKG state after parsing.

### 12.10 Payload RAG Prototype

#### Source of truth

Payload knowledge lives **only** in an external directory supplied via
`--payload-repo <path>` at startup (e.g., `./payloads`). No payload text
is embedded in source files. `apex_host/knowledge/payload_repo_loader.py`
reads that directory at runtime and stages chunks via
`MemoryAPI.propose_knowledge()`.

#### Chunking

Markdown files are split on `## ` headings (section-level chunks). All
other file types (`.txt`, `.py`, `.rb`, `.sh`, `.json`, `.yaml`, `.yml`)
are size-chunked at 1 500 characters. Each chunk carries metadata:

| Field | Value |
|---|---|
| `source_path` | Absolute path to the source file |
| `payload_family` | Parent directory name (e.g., `sqli`, `xss`) |
| `file_ext` | Extension (e.g., `.md`) |
| `tier` | `"semantic"` |
| `source` | `"payload_repo"` |
| `chunk_index` | 0-based position within the file's chunk list |

#### Promotion path

`seed_payload_repo(path, api, config)` in `knowledge/seed_loader.py`:

1. Calls `PayloadRepoLoader.load()` — proposes all chunks to the staging
   area (NOT yet retrievable, per memfabric Invariant 4).
2. Runs one `ReflectorWorker.run_once()` pass — the real Reflector
   promotion path, not a shortcut. Promotes every staged knowledge entry
   whose `confidence >= config.min_confidence` (default 0.5; the loader
   sets confidence to 0.7, so all entries clear the gate).

After this call, promoted chunks are in the BM25 lexical index and are
returned by `MemoryAPI.query()` with their text populated in
`ScoredEntry.text`.

#### Retrieval text fix

Prior to Phase 4, `ScoredEntry.text` was always `""` after RRF fusion
because the BM25 search interface returned `(id, score, metadata)` tuples
without the raw text. The fix:

- `memfabric/api.py`: all `lexical.add()` calls now include `"_text"` in
  the metadata dict, set to the same text string passed as the second arg.
- `memfabric/retrieval/engine.py`: `ScoredEntry` is built with
  `text=str(meta.get("_text", ""))` so the text travels through RRF back
  to callers.

#### Tests

`tests/apex_host/test_payload_repo_loader.py` verifies:
- Chunks are proposed and staged correctly.
- All required metadata fields are present (`tier`, `source`,
  `payload_family`, `file_ext`, `chunk_index`).
- Markdown files split into ≥ 2 chunks when `## ` headings are present.
- Missing repo path returns 0 (graceful degradation).
- Staged entries are NOT returned by `api.query()` until promoted
  (staging isolation invariant).
- `seed_payload_repo` promotes all entries via the Reflector path.
- `api.query()` returns non-empty `ScoredEntry.text` after promotion.
- Retrieved text contains words from the original chunk content.

### 12.11 Generic Service Capability Model

`apex_host/planners/capabilities.py` is the single place where observed EKG
nodes are translated into named, safe planner actions.  No individual planner
may contain service-name strings or port-number sets — those live exclusively
in this module.

#### Why this prevents Meow-specific hardcoding

Without a capability layer every planner hardcodes its own idea of what
constitutes SSH, HTTP, or a banner-probeable port.  Two planners that both
care about SSH would each carry their own `{"ssh", "22"}` constants, and
adding a new planner for a different HTB machine would require hunting through
all of them.  `capabilities_from_subgraph()` centralises that knowledge: any
target whose EKG has an SSH service node will produce
`access_validate_ssh` regardless of which machine it came from.

#### API

```python
from apex_host.planners.capabilities import Capability, capabilities_from_subgraph

caps: list[Capability] = capabilities_from_subgraph(subgraph)
```

`Capability` fields: `name`, `target`, `port`, `service`, `confidence`,
`source_node_id`.

#### Capability names

| Name | Trigger | Planner consumer |
|---|---|---|
| `web_probe` | HTTP/HTTPS service or endpoint node | `WebPlanner`, `ReconPlanner` |
| `browser_observe` | HTTP/HTTPS service or endpoint node | browser agent |
| `access_validate_telnet` | Telnet service/port 23 | `ReconPlanner` banner probe |
| `access_validate_ssh` | SSH service/port 22 | `ReconPlanner` banner probe |
| `access_validate_ftp` | FTP service/port 21 | `ReconPlanner` banner probe |
| `service_probe` | Open TCP on a probeworthy port, no specific match | `ReconPlanner` banner probe |
| `exploit_research` | Service node with non-empty version string | `PrivEscPlanner` |

`service_probe` is only emitted for ports in `_PROBEWORTHY_PORTS` (21, 22,
23, 25, 3306, 5432, 6379).  Arbitrary high ports produce no capability and
are silently skipped — this prevents nc-probing every open port.

`exploit_research` coexists with protocol-specific capabilities (a versioned
SSH service produces both `access_validate_ssh` **and** `exploit_research`).

#### Planner update rule

If a planner needs to classify services or ports, it calls
`capabilities_from_subgraph(subgraph)` and filters by `Capability.name`.
It must **not** inspect `node.props["service"]` or hardcode port strings.

#### Tests

`tests/apex_host/test_capabilities.py` verifies:
- Telnet service/port 23 → `access_validate_telnet`.
- SSH service/port 22 → `access_validate_ssh`.
- FTP service/port 21 → `access_validate_ftp`.
- HTTP/HTTPS service → `web_probe` + `browser_observe`.
- Versioned service → `exploit_research` (coexists with protocol cap).
- Port 6379 (no service name) → `service_probe`.
- SMB port 445 → no capability.
- UDP service → no capability.
- Closed/filtered service → no capability.
- Endpoint node → `web_probe` + `browser_observe`.
- All `Capability` fields (`target`, `port`, `service`, `confidence`,
  `source_node_id`) carry the correct values.

---

### 12.12 Generic Bounded Access Validation

Provides a one-attempt, explicit-credential login validation workflow for
authorized HTB Easy/Medium machines. No brute force. No credential stuffing.
No autonomous credential guessing. Telnet is implemented first; SSH/FTP are
capability placeholders for future iterations.

#### Safety invariants (non-negotiable)

- **No brute force, no credential stuffing.** `CredentialPlanner` emits
  exactly ONE task per turn, using the first configured credential pair.
  There is no loop over `username_candidates × password_candidates`.
- **No autonomous credential guessing.** Credentials must be supplied
  explicitly by the operator via `--username` / `--password` CLI flags.
  If neither is supplied and a telnet capability is found, the planner
  returns `AbandonSignal` with a helpful message.
- **Dry-run enforced in `TelnetExecutor`.** With `config.dry_run=True`
  (the default), `TelnetExecutor.run()` returns a synthetic result
  immediately — `asyncio.open_connection` is never called.
- **`TelnetExecutor` uses `asyncio.open_connection`, never subprocess.**
  This upholds the "no raw subprocess outside runner.py" invariant while
  still being safe — TCP is not a subprocess.
- **Secret material never stored in EKG.** `AccessParser` always sets
  `secret_hint="[redacted]"` on the `credential` node. The plaintext
  password never appears in graph state, episodic log, or proposals.

#### Flow

```
CredentialPlanner.plan()
  ├── capabilities_from_subgraph() finds access_validate_telnet
  │     ├── credentials configured? → emit ONE TaskSpec(tool="telnet_access", parser="access")
  │     └── no credentials         → AbandonSignal (operator must supply --username/--password)
  └── no telnet capability → fallback curl HEAD probe or AbandonSignal
```

`execute_agent` in `graph.py` routes `tool="telnet_access"` tasks to
`TelnetExecutor.run()` (asyncio TCP), then builds a `tool_result` dict
compatible with the existing `parse_observation` / `write_memory` nodes.

`parse_observation` routes `parser="access"` to `AccessParser.parse_text()`:
- Always emits a `credential` node (`username` + `secret_hint="[redacted]"`).
- On success (shell prompt detected, no failure indicator): also emits an
  `access_state` node and a `grants` edge `credential → access_state`.
- On failure (`login incorrect` / `authentication failed` / etc.): only the
  `credential` node is emitted — no `access_state`.

#### New config fields (`ApexConfig`)

| Field | Type | Default | Purpose |
|---|---|---|---|
| `username_candidates` | `list[str]` | `[]` | Usernames from `--username` |
| `password_candidates` | `list[str]` | `[]` | Passwords from `--password` |
| `max_access_attempts` | `int` | `1` | Upper bound on attempts (never > 1 in this iteration) |

#### New CLI flags (`main.py`)

```bash
python -m apex_host.main \
  --target 10.10.10.14 \
  --username root \
  --password "" \
  --dry-run
```

Both `--username` and `--password` are `append`-action flags (can be
repeated). Only the first pair is used. `dry_run=True` is the default.

#### New files

| File | Purpose |
|---|---|
| `apex_host/agents/telnet_executor.py` | Stateless bounded telnet login executor |
| `apex_host/parsers/access_parser.py` | Session-text → EKG credential/access_state deltas |
| `tests/apex_host/test_access_validation.py` | 20+ tests for all four acceptance criteria |

#### Tests (`tests/apex_host/test_access_validation.py`)

- `CredentialPlanner` abandons without credentials when telnet cap present.
- `CredentialPlanner` emits exactly one task with explicit credentials.
- Multiple credential pairs → still exactly one task (first pair only).
- `AccessParser` creates credential + access_state + grants on shell prompt.
- `AccessParser` creates credential node only on login-incorrect output.
- `AccessParser` returns empty on blank input.
- `TelnetExecutor` dry-run returns synthetic success, `dry_run=True` in data.
- `TelnetExecutor` dry-run monkeypatch verifies `asyncio.open_connection`
  is never called.

---

### 12.14 Browser Executor Prototype

`apex_host/agents/browser_executor.py` drives Playwright in live mode and
returns a synthetic `BrowserObservation` in dry-run mode (the safe default).
Each `run()` call creates a fresh browser instance and tears it down before
returning — no browser state, no session, no page handle is held on `self`
across calls (memfabric Invariant 6: executors are stateless).

#### What the executor collects (live mode)

| Data | How | EKG result |
|---|---|---|
| Page title | `page.title()` | stored in `episode.data` |
| Forms with input field names | JS eval — `document.forms` | `form` node per form |
| Password-field auth hint | JS eval — `input[type="password"]` | `auth_flow` node |
| Hidden-input / meta token names (`csrf`, `token`, `nonce`) | JS eval | `token` node per name |
| Same-origin anchor links (≤ 50) | JS eval — `a[href]` | stored in obs for future probing |

Playwright is **only imported** (lazy) and **only executed** when
`config.dry_run is False`.  In dry-run mode a synthetic observation is
returned immediately — no import, no subprocess, no network.

#### Observation data flow

The executor stores collected data in `episode.data["obs"]` as a plain
JSON-serialisable dict.  `browser_agent` in `apex_host/graph.py` passes
this through to `tool_result["obs"]`.  `parse_observation` reconstructs a
`BrowserObservation` from that dict and calls `BrowserParser.parse_observation`
to produce EKG node/edge deltas — consistent with every other
executor/parser pair: all writes go through `MemoryAPI` in `parse_observation`,
never inside the executor itself (memfabric Invariant 1).

#### BrowserParser node types

| Input | Output nodes | Output edges |
|---|---|---|
| Any URL observed | `endpoint` | — |
| A form element | `form` | `endpoint → form` (`contains`) |
| A form with a password field | `auth_flow` | `endpoint → auth_flow` (`requires`) |
| `auth_hints` list entries | `auth_flow` | `endpoint → auth_flow` (`requires`) |
| Token names (csrf, nonce, …) | `token` | `endpoint → token` (`contains`) |

#### How this feeds planning

`BrowserParser` produces `auth_flow` nodes.  `GlobalPlanner.decide_phase`
advances from `web` to `credential` as soon as `"auth_flow" in node_types_seen`.
So a successful browser observation of a login page causes the very next turn
to enter the credential phase and attempt bounded access validation — the
browser and credential phases are automatically chained through the EKG.

#### Web-phase routing

```
web phase, turn N (no prior web finding) → web_agent → ffuf / curl → endpoint discovery
web phase, turn N+1 (prior web finding)  → browser_agent → BrowserExecutor → form/token/auth_flow discovery
```

`WebPlanner` uses `capabilities_from_subgraph(subgraph)` to derive the
correct base URL from the highest-confidence `web_probe` capability in the
EKG.  If nmap found port 8080 the ffuf/curl tasks probe `http://target:8080`,
not the hardcoded port 80.  Falls back to `http://target` before recon runs.

#### Tests

`tests/apex_host/test_browser_executor.py` verifies:
- Dry-run returns `Outcome.success`; `dry_run=True` flag present in episode data.
- `episode.data["obs"]` dict contains url, title, forms, tokens, links.
- Synthetic forms include a password field (triggers `auth_flow` node).
- Synthetic tokens include a csrf-pattern name (triggers `token` node).
- Two consecutive dry-run calls are independent (stateless executor).
- `BrowserParser` creates `endpoint`, `auth_flow`, `token` nodes from the
  synthetic obs produced by `BrowserExecutor` in dry-run mode.
- `WebPlanner` derives correct http/https URL from port-80/443/8080 capability.
- Highest-confidence capability wins when multiple web services are present.
- Web phase routes to `browser_agent` after a prior web finding.

---

### 12.13 Local HTB Runner

`apex_host/eval/run_htb_local.py` is the **general-purpose local runner**
for authorized HTB Easy/Medium machines from a macOS workstation. It wraps
`runtime.py` and prints a phase-by-phase summary, findings table, EKG
node/edge breakdown, and episode count after each engagement.

All target details are supplied through CLI flags. No machine-specific
profiles, expected credential paths, default usernames, or target-specific
phase progressions are stored in the codebase (see §11.2 safety invariants).

#### New files

| File | Purpose |
|---|---|
| `apex_host/eval/run_htb_local.py` | General local HTB runner with rich output |
| `apex_host/eval/export_graph.py` | Serialises EKG nodes + edges to JSON |

#### Usage

Generic dry-run (safe, no real commands):
```bash
python -m apex_host.eval.run_htb_local \
  --target <HTB_TARGET_IP> \
  --payload-repo ./payloads \
  --dry-run
```

Generic live authorized run (HTB VPN required):
```bash
python -m apex_host.eval.run_htb_local \
  --target <HTB_TARGET_IP> \
  --payload-repo ./payloads \
  --no-dry-run \
  --username <USER> \
  --password <PASS>
```

Export EKG to JSON after the run:
```bash
python -m apex_host.eval.run_htb_local \
  --target <HTB_TARGET_IP> --dry-run \
  --export-graph ./ekg_snapshot.json
```

#### Report output

After each run the runner prints:
- **Phase Summary** — finding count per phase
- **Findings** — id, type, confidence, source per finding
- **EKG Summary** — node and edge counts by type (from a depth-10 subgraph
  traversal rooted at `host:<target>`)
- **Episodes** — turns completed and last error

#### Tests

`tests/apex_host/test_htb_local_runner.py` verifies:
- `export_ekg` returns the correct structure for known EKG state.
- `NmapParser` produces host + telnet service nodes from synthetic nmap text.
- `AccessParser` produces credential + access_state nodes from a synthetic
  success session string.
- **Synthetic E2E**: combining both parsers populates all four required node
  types (host, service, credential, access_state) in one MemoryAPI.
- The `grants` edge is present between credential and access_state.
- `credential.secret_hint` is always `"[redacted]"`.
- `format_report` contains the expected sections.
- `run_engagement` completes without error in dry-run mode.
- `ApexConfig.dry_run` defaults to `True` (live mode cannot be triggered
  accidentally).

---

## 13. Development commands

### Run the test suite

```bash
.venv/bin/python -m pytest tests/ -q
```

### Dry-run engagement (default — safe, no real commands)

```bash
python -m apex_host.main \
  --target <HTB-machine-IP> \
  --payload-repo ./payloads \
  --dry-run
```

No network traffic is generated. Tool invocations are simulated and logged.
Use this to verify routing logic, phase progression, and EKG writes without
touching a live target.

### Real engagement (authorized HTB/VPN targets only)

```bash
python -m apex_host.main \
  --target <HTB-machine-IP> \
  --payload-repo ./payloads \
  --no-dry-run
```

**Only run this against an authorized HTB machine over the official HTB
OpenVPN connection (or another explicitly authorized lab environment).** All
commands are still safety-gated by `apex_host/tools/safety.py` — the
allowlist and destructive-command block apply even in real-execution mode.

---

### 12.15 Safe Web Probing

`WebPlanner` produces bounded, non-exploitative HTTP probes for the web
phase. No fuzzing wordlists are assumed; directory discovery is strictly
opt-in.

#### Design rules (non-negotiable)

- **No autonomous exploitation.** Web probing is discovery and fingerprinting
  only. No SQLi payloads, XSS injections, or directory traversal attempts.
- **No high-risk fuzzing by default.** `ffuf` and `gobuster` are never
  emitted unless `ApexConfig.web_wordlist_path` is explicitly set. The
  default is `None`, which guarantees no wordlist-based fuzzing runs.
- **Safe by default.** `curl -s -I <url>` (HEAD) and `curl -s <url>` (body)
  are always safe; they generate a single HTTP request each. They remain the
  only probes when no wordlist is configured.

#### Probe emission order

| # | Task | Condition | Parser |
|---|------|-----------|--------|
| 1 | `curl -s -I <url>` | curl in `allowed_tools` | `command` (existing `CommandParser.parse`) |
| 2 | `curl -s <url>` | curl in `allowed_tools` | `curl_body` (`CommandParser.parse_curl_body`) |
| 3 | `ffuf -u <url>/FUZZ -w <wordlist> -mc 200,301,302,403 -maxtime 60` | curl in `allowed_tools` **AND** `web_wordlist_path` set | `ffuf` |
| 4 | `gobuster dir -u <url> -w <wordlist> -q --no-progress` | gobuster in `allowed_tools` **AND** `web_wordlist_path` set | `gobuster` |

#### `CommandParser.parse_curl_body` — HTML body parsing

`parse_curl_body(raw)` extracts page structure from an HTML body response:

- Detects HTML by presence of `<html`, `<!doctype`, or `<title` (case-insensitive).
- Extracts the `<title>` content → stored as `props["title"]` on the base
  `endpoint` node. Surrounding whitespace is collapsed.
- Extracts relative `href` values (paths starting with `/`; external
  `http://`/`https://` URLs are excluded) → up to **20** additional
  `endpoint` nodes with `props["url"]` (full URL) and `props["path"]` (path only).
- Creates `contains` edges from the base endpoint to each link endpoint.
- Creates one `exposes` edge from `host:<ip>` to the base endpoint.
- Non-HTML content → fallback `KnowledgeEntry` at confidence 0.3.
- Empty content → returns empty `ParsedObservation`.

The 20-link cap keeps the EKG bounded on pages with large nav menus.

#### New config fields

| Field | Type | Default | Purpose |
|---|---|---|---|
| `web_wordlist_path` | `str \| None` | `None` | Path to wordlist for ffuf/gobuster; `None` disables both |
| `max_web_paths` | `int` | `50` | Passed as `-maxtime` hint to ffuf |

#### New CLI flags

```bash
python -m apex_host.main --target 10.10.10.80 \
  --web-wordlist /path/to/wordlist.txt \
  --max-web-paths 50 \
  --dry-run
```

Both flags are also available on `apex_host/eval/run_htb_local.py`.

#### Tests (`tests/apex_host/test_web_planner.py`)

- `WebPlanner` without wordlist → only curl HEAD + body, no ffuf/gobuster.
- `WebPlanner` with wordlist → ffuf and gobuster included.
- HEAD task is first, body task is second.
- HEAD task uses parser `"command"`; body task uses parser `"curl_body"`.
- Both curl tasks target the same base URL.
- ffuf args include `-mc` (status filter) and `-maxtime` flags.
- wordlist path appears verbatim in ffuf and gobuster args.
- `AbandonSignal` returned when no allowed tools are available.
- `CommandParser.parse_curl_body` extracts title, whitespace-collapses it.
- `parse_curl_body` creates `exposes` edge from `host:<ip>`.
- `parse_curl_body` extracts relative links as endpoint nodes with `contains` edges.
- `parse_curl_body` excludes external URLs.
- `parse_curl_body` caps link endpoint nodes at 20.
- `parse_curl_body` falls back to `KnowledgeEntry` for non-HTML content.
- `parse_curl_body` returns empty observation for blank input.
- `parse_curl_body` preserves explicit port in the base URL (e.g., `:8080`).

---

## 13. Future Modification Rules for Claude Code

When a future session of Claude Code continues work on this codebase, the
following rules apply. They reinforce the design invariants in Section 1,
the safety invariants in Section 11.2, and the conventions established
throughout Sections 2–12. Treat them as binding constraints, not
suggestions.

### 13.1 Read CLAUDE.md before writing any code

Read this file **in full** before writing, editing, or deleting any file.
Changes that violate the rules in Section 1, Section 11.2, or this section
will need to be reverted. If CLAUDE.md and the architecture doc conflict,
CLAUDE.md governs implementation; the architecture doc provides rationale.

### 13.2 Preserve file-header convention

Every Python file must start with exactly two comment lines before any
`from __future__ import annotations`, docstring, or import:

```python
# filename.py
# One-line explanation of what this file does.
```

When creating a new file, add this header first. When editing an existing
file, never remove or shift its header lines.

### 13.3 Never put host-specific code in `memfabric`

`memfabric/` is domain-agnostic. It must not contain:
- Cybersecurity terminology (CVE, exploit, shell, credential, …)
- References to `apex_host` modules, types, or classes
- Any concrete `Executor`, `Planner`, or `Parser` that drives real tooling

If you need to add a behavior that belongs in the host application, place
it under `apex_host/` and wire it through the Protocol seams Section 9
defines. If you find yourself adding an import of `apex_host` inside
`memfabric`, stop — you are in the wrong module.

### 13.4 Add tests for every behavior change

Each new module or modified behavior needs a matching test in `tests/`.
Tests live in `tests/` (for `memfabric`) or `tests/apex_host/` (for the
host application). The file structure mirrors the package; the naming
convention is `test_<module>.py`.

- Write the test **before** or **alongside** the implementation, not after.
- Tests must run under `pytest` with no network access and no real tool
  execution (`dry_run=True` for all `ApexConfig` instances in tests).
- If you touch an existing module, run the existing tests before and after
  your change to confirm no regression. Run with:
  ```bash
  .venv/bin/python -m pytest tests/ -q
  ```

### 13.5 The dry-run default must never change

`ApexConfig.dry_run` defaults to `True`. This is a safety invariant, not
a convenience setting. Never change this default, never add code that
implicitly sets `dry_run=False`, and never bypass it in tests. Real
execution (`dry_run=False`) must always require an explicit CLI flag
(`--no-dry-run`) on every invocation. If you are writing a test, pass
`dry_run=True` explicitly so the intent is visible in the test.

### 13.6 No raw subprocess outside `apex_host/tools/runner.py`

Every command execution path goes through `apex_host/tools/runner.py`,
which calls `safety.py` first. Do not use `subprocess`, `os.system`,
`asyncio.create_subprocess_exec`, or `asyncio.create_subprocess_shell`
anywhere else in the codebase. If you need to run a new tool, add it to
`ToolRegistry._KNOWN_TOOLS` and emit a `TaskSpec` from a planner; the
graph's `execute_agent` node will route it through `runner.py`.

### 13.7 All memory writes go through `MemoryAPI`

No `apex_host` component, parser, or executor may write to a `memfabric`
store directly. Every state change goes through `MemoryAPI.upsert_node`,
`upsert_edge`, `append_episode`, `propose_knowledge`, or `propose_skill`.
This is Invariant 1 from Section 1 — do not violate it even in test
helpers. Test helpers that need pre-seeded EKG state must call the
`MemoryAPI` methods, not the store directly.

### 13.8 Meow is a smoke test, not hardcoded behavior

"Meow" (HTB Starting Point machine) is used as the first end-to-end
smoke test only. No machine-specific code, expected credentials, default
usernames, service-specific flows, or expected port sets may be committed
to the repository. All target details (IP, phase path, credential pairs)
are supplied through CLI flags at runtime. The architecture must remain
fully target-agnostic: any authorized HTB Easy/Medium machine produces the
same code path.

### 13.9 No machine-specific profile files

Do not create files named after individual machines or targets (e.g.
`meow.py`, `lame.py`, `blue.py`, `<machine-name>.py`). If you feel the
urge to create such a file, ask yourself: "can this behavior be expressed
as generic config or CLI flags?" The answer is always yes.

### 13.10 Staging gate is non-negotiable

A `propose_knowledge` or `propose_skill` call stages an entry. The entry
is **not** retrievable until the Reflector promotes it. Never call
internal staging-store methods directly to bypass this gate, and never
promote entries from outside `reflector/worker.py` except through the
test-only `ReflectorWorker.run_once()` path (which itself uses the
standard promotion logic). Bypassing the gate is a security-relevant
violation — see the test in Section 8 ("Staging isolation").

### 13.11 How to extend the system safely

**Add a new tool**: Register in `ToolRegistry._KNOWN_TOOLS`. Emit
`TaskSpec` from a planner. Route in `graph.py`'s `execute_agent`. Add
parser. Add tests.

**Add a new phase**: Add a value to `ApexPhase`. Update `GlobalPlanner`'s
decision logic. Add the corresponding agent/planner. Wire the conditional
edge in `graph.py`. Add tests.

**Change a retrieval threshold**: Edit `memfabric/config.py` (the
`Config` dataclass). Never hard-code a threshold in a component; it must
be config-driven so tests can override it.

**Add new EKG node/edge types**: Document them in CLAUDE.md Section 12.8
(the node/edge type convention table). Add parsers that produce them. Add
tests that verify the correct node type and props are created.

---

## 14. LLM Planning Layer (`apex_host/planning/`)

The planning layer provides an optional LLM backend for all `apex_host`
planners.  It is **additive** — existing rule-based planners continue to work
unchanged and are registered as the fallback inside `PlanningEngine`.

### 14.1 Module map

```
apex_host/planning/
├── __init__.py          # public exports
├── models.py            # Pydantic v2: PlannerOutput, PlannedTask
├── prompt_builder.py    # PromptBuilder — builds system+user messages
├── validator.py         # Validator — safety gate on raw LLM text
└── engine.py            # PlanningEngine — the sole ModelRouter caller
```

### 14.2 Invariants (non-negotiable)

1. **`PlanningEngine` is the only component permitted to call
   `ModelRouter.planner_llm()`.**  No planner, executor, parser, or graph
   node may call the router directly.

2. **Planners never construct prompts manually.**  Any component that needs
   to send a planning prompt to an LLM must go through `PlanningEngine`,
   which delegates to `PromptBuilder`.

3. **Executors never call LLMs.**  Executors are stateless tool runners;
   all reasoning lives in the planning layer.

4. **`MemoryAPI` remains the only state source.**  `PlanningEngine` reads
   context through the `EvidenceBundle` and `SubgraphView` passed in — it
   never queries `MemoryAPI` directly.

5. **Fallback is mandatory.**  Every `PlanningEngine` instance must be
   constructed with a `fallback_planner`.  Any LLM failure, network error,
   or validator rejection triggers the fallback — the engagement never
   stalls due to LLM unavailability.

6. **`FakeModelRouter` returns `None`.**  When `planner_llm()` returns
   `None`, `PlanningEngine` immediately delegates to the fallback without
   attempting any LLM call.  This is what makes dry-run and tests safe by
   default.

### 14.3 Flow

```
PlanningEngine.plan(goal, phase, subgraph, evidence)
  │
  ├── router.planner_llm() → None?
  │     └── yes → fallback_planner.plan() → TaskSpec list
  │
  ├── PromptBuilder.build_messages(goal, phase, evidence, ekg_summary, allowed_tools)
  │     └── [system_msg, user_msg]
  │
  ├── llm.invoke(messages) → raw string
  │     └── exception → fallback_planner.plan()
  │
  ├── Validator.validate(raw, allowed_tools)
  │     ├── JSON parse failure → None → fallback
  │     ├── schema mismatch   → None → fallback
  │     ├── unsupported tool  → None → fallback
  │     ├── destructive tool  → None → fallback
  │     ├── shell metachar    → None → fallback
  │     └── unknown domain    → None → fallback
  │
  ├── stop_reason set? → AbandonSignal(reason)
  │
  ├── no selected_tasks? → fallback_planner.plan()
  │
  └── _to_task_spec() × N → list[TaskSpec]
```

### 14.4 `PlannerOutput` schema (Pydantic v2)

```python
class PlannedTask(BaseModel):
    tool: str               # must be in allowed_tools
    args: list[str]         # no shell metacharacters
    parser: str             # nmap | banner | command | curl_body | ffuf | gobuster | access
    executor_domain: str    # recon | web | credential | priv_esc | execute | browser
    target: str             # IP or URL; engine fills in default if blank
    rationale: str          # one-line explanation (stored for auditability)

class PlannerOutput(BaseModel):
    reasoning: str          # chain-of-thought (not forwarded to executors)
    confidence: float       # 0..1 (< 0.35 → advisory warning, not a hard reject)
    selected_tasks: list[PlannedTask]
    rejected_tasks: list[dict]  # considered but not selected (for Reflector)
    stop_reason: str | None     # set → AbandonSignal; None → execute tasks
    next_phase: str | None      # phase hint for GlobalPlanner (informational)
```

### 14.5 Validator rejection rules

The `Validator` returns `None` (triggering fallback) on any of these:

| Condition | Why rejected |
|---|---|
| `json.JSONDecodeError` | Malformed JSON |
| `pydantic.ValidationError` | Missing required field or type mismatch |
| `task.tool` not in `allowed_tools` | Unsupported / not allowlisted |
| `task.tool` in destructive blocklist | `rm`, `mkfs`, `dd`, `shutdown`, … |
| Shell metachar in any `task.args` token | `;`, `&&`, `\|\|`, `\|`, `>`, `>>`, `<`, `$(`, `` ` `` |
| `task.executor_domain` not in known set | Unknown action type |

JSON wrapped in a ` ```json … ``` ` code fence is automatically stripped
before parsing — a common LLM output format.

### 14.6 `PromptBuilder` contract

`PromptBuilder.build_messages(goal, phase, evidence, ekg_summary, allowed_tools)`
returns `[{"role": "system", "content": …}, {"role": "user", "content": …}]`.

The system message contains:
- Critical safety rules (no destructive commands, no shell operators)
- The `PlannerOutput` JSON schema

The user message contains:
- Current phase and goal description
- Allowed tools list
- EKG summary (from `summarize_subgraph()`)
- Retrieved semantic knowledge (up to 5 entries)
- Retrieved procedural skills (up to 3 entries)
- Recent episodic lessons (up to 4 entries)

### 14.7 Wiring into `apex_host`

To use `PlanningEngine` with an existing planner as fallback:

```python
from apex_host.planning import PlanningEngine
from apex_host.llm.router import OpenAIModelRouter

engine = PlanningEngine(
    model_router=OpenAIModelRouter(config),
    fallback_planner=ReconPlanner(target, registry),
    allowed_tools=config.allowed_tools,
    target=config.target,
)

# In graph.py — call engine.plan() instead of planner.plan() directly:
result = await engine.plan(goal, phase, subgraph, evidence)
```

In tests and dry-run mode, `FakeModelRouter` returns `None` for all roles,
so `PlanningEngine` always falls back to the deterministic planner — no LLM
calls, no network, no API key required.

### 14.8 Extension rules for Claude Code

- **Adding a new planner**: register the deterministic planner as
  `fallback_planner` inside `PlanningEngine`.  Wire `PlanningEngine` into
  `graph.py` rather than the raw planner.
- **Changing the prompt format**: edit `PromptBuilder` only — never add
  prompt-building logic to a planner or executor.
- **Changing validation rules**: edit `Validator` only.  If a new tool
  should be blocked unconditionally, add it to `_DESTRUCTIVE_COMMANDS` in
  `validator.py`.
- **Tests**: every new planning behavior needs a test in
  `tests/apex_host/test_planning_engine.py`.  Use `_StubLLM` /
  `_StubRouter` patterns already established there; do not call real LLMs
  in tests.
---

## 15. Planner Responsibilities

### 15.1 Separation of responsibilities

| Component | Responsible for | Must NOT do |
|---|---|---|
| `GlobalPlanner` | Phase selection, budget allocation, goal text | Emit TaskSpecs, call LLM directly |
| Domain planners (Recon, Web, Credential, PrivEsc) | TaskSpec production within their phase | Phase routing, LLM calls, memory writes |
| `PlanningEngine` | LLM call, prompt building, validation, TaskSpec conversion, fallback | Hold state, write memory, call executors |
| Executors | Tool execution (safety-gated) | Plan tasks, write memory |
| Parsers | Tool output → EKG node/edge deltas | Execute tools, plan tasks |
| `MemoryAPI` | All reads and writes to the fabric | None (it is the sole state surface) |

### 15.2 Domain planner structure (`_<Name>Deterministic` + thin wrapper)

Every domain planner follows this two-class pattern:

```python
class _ReconDeterministic:
    """Pure rule-based fallback — no LLM dependency."""
    async def plan(self, goal, subgraph, evidence) -> list[TaskSpec] | AbandonSignal: ...

class ReconPlanner:
    """Thin wrapper — routes through PlanningEngine when model_router provided."""
    def __init__(self, target, registry, *, model_router=None, allowed_tools=None,
                 confidence_threshold=0.4, max_retries=1) -> None:
        self._core = _ReconDeterministic(target, registry)
        if model_router is not None:
            self._engine = PlanningEngine(model_router, self._core, ...)
    
    async def plan(self, goal, subgraph, evidence) -> list[TaskSpec] | AbandonSignal:
        if self._engine is not None:
            return await self._engine.plan(goal, <PHASE>, subgraph, evidence)
        return await self._core.plan(goal, subgraph, evidence)
```

**Rules:**
- The `_<Name>Deterministic` class must be self-contained (no LLM imports,
  no PlanningEngine imports, no model_router references).
- `model_router=None` is the default — callers that do not supply a router
  get the fully-deterministic behaviour with no code path changes.
- The `_engine` attribute is `None` when no router is provided; existence
  of `_engine` is the sole routing predicate in `plan()`.

### 15.3 Fallback policy

When `PlanningEngine` falls back to the deterministic planner it does so on:

| Trigger | Retry before fallback? |
|---|---|
| `ModelRouter.planner_llm()` returns `None` | No — immediate fallback |
| LLM invocation raises an exception | Yes — up to `max_retries` times |
| `Validator.validate()` returns `None` | Yes — up to `max_retries` times |
| LLM output confidence < `confidence_threshold` | No — epistemic signal, not transient |
| LLM output has no `selected_tasks` | Yes — up to `max_retries` times |

The deterministic planner ALWAYS produces a valid result (or `AbandonSignal`).
The LLM path is strictly opt-in: `FakeModelRouter` (the default) returns
`None`, ensuring no LLM calls in tests or dry-run mode.

### 15.4 GlobalPlanner budget allocation

`GlobalPlanner` tracks per-phase turn budgets to prevent the engagement from
getting stuck in a single phase indefinitely:

```python
gp = GlobalPlanner(max_turns=20, phase_budgets={"recon": 6, "web": 5})
gp.record_turn(ApexPhase.recon)   # call once per turn, AFTER decide_phase
remaining = gp.budget_remaining(ApexPhase.recon)
```

`graph.py` calls `record_turn(phase)` inside `global_plan` after `decide_phase`
returns a non-`done` phase.  When a phase's budget is exhausted, `decide_phase`
force-advances to the next phase (as if the phase's completion EKG-node had
already been observed).  This prevents indefinite recon or web loops when
real tool output fails to produce the expected node types.

`decide_phase` now accepts an optional `current_phase` kwarg (the phase value
currently stored in `ApexGraphState`).  Passing it enables the budget
force-advance logic; omitting it preserves backward-compatible behaviour.

### 15.5 Wiring model_router into graph.py

```python
from apex_host.llm.router import OpenAIModelRouter
from apex_host.graph import build_apex_graph

graph = build_apex_graph(
    api, registry, config,
    model_router=OpenAIModelRouter(config),   # optional; omit for deterministic
)
```

When `model_router` is `None` (the default), `build_apex_graph` constructs
each planner without a router, preserving fully-deterministic behavior.
When a router is provided, each domain planner wraps its deterministic core
in a `PlanningEngine` with `config.planning_confidence_threshold` and
`config.max_planning_retries`.

### 15.6 Tests

New tests for planner + engine wiring live in
`tests/apex_host/test_planners_with_engine.py`.  Key patterns:

- Use `_StubRouter(_StubLLM(json_str))` to inject a deterministic LLM stub.
- Use `_FakeModelRouter()` to exercise the deterministic-only path.
- Use `_RaisingLLM()` to test retry + fallback behavior.
- Use `_RotatingLLM(bad_count, good_json)` to test retry-until-success.
- `_FallbackCounter` wraps a real deterministic planner and counts calls.
- All tests use `dry_run=True` (the default) — no real LLM calls ever.

---

## 16. Complete LLM Planning Loop

This section documents the operational planning architecture added in Phase 5
(complete APEX-Nexus loop).  All components are in production and covered
by `tests/apex_host/test_repair_engine.py` (26 tests).

### 16.1 EvidenceBundle Summarization

`PromptBuilder.build_messages()` now accepts two optional keyword arguments:

- `findings: list[dict[str, Any]] | None` — accumulated findings from
  `ApexGraphState.findings` (last 10 entries, confidence-annotated).  The
  LLM sees a compact summary of what has been discovered so far without
  receiving the full EKG graph.
- `candidate_tasks: list[str] | None` — human-readable descriptions of the
  tasks the deterministic fallback planner would emit.  Helps the LLM
  understand what the rule-based fallback would do and why it might choose
  differently.

The full graph is never sent to the LLM.  Context is always a bounded
summary: EKG node-type counts, findings list (capped at 10), and retrieved
evidence entries (5 semantic, 3 procedural, 4 episodic).

### 16.2 Dynamic Replanning

After every `write_memory` pass, `reflect_or_continue` queries the live
EKG (depth-2 subgraph) and calls `global_planner.decide_phase()` (read-only,
no budget charge) to derive the freshest phase.  This updates `state["phase"]`
before the state checkpoint is written so that debuggers and the JSON export
always show the most current phase, not the one selected at the start of the
turn.

`global_plan` continues to own phase selection at the start of each turn
(with budget charging via `record_turn()`).  `reflect_or_continue` peeks
only — it does not double-charge the budget.

### 16.3 Planner Reflection (Repair Agent)

`apex_host/planning/repair.py` implements `RepairEngine`:

- Called by `repair_agent` when a task fails with `script_error` or
  `fixable` outcome and `repair_count < config.max_repair_attempts`.
- Returns `None` immediately when `config.dry_run=True` (the default) — no
  repair in dry-run mode; the failure was synthetic.
- Returns `None` when `ModelRouter.planner_llm()` returns `None`
  (`FakeModelRouter` path).
- Builds a focused repair prompt via `_build_repair_messages()` — a separate
  prompt from the main planner prompt, describing only the failure context.
- Validates the LLM output through the same `Validator` used by
  `PlanningEngine` (same safety gate: destructive tools blocked, shell
  metacharacters blocked).
- On success: executes the repaired task via `run_command()`, parses +
  writes through `MemoryAPI`, appends a repair `Episode` with
  `agent=f"apex.{phase}.repair"`.
- `fundamental` outcomes are never repaired — `route_after_write` routes
  directly to `reflect_or_continue`.

**Graph topology after Phase 5:**
```
agent → parse_observation → write_memory
      → route_after_write → repair_agent (script_error/fixable, budget OK)
                          → reflect_or_continue (fundamental, or budget exhausted)
repair_agent → reflect_or_continue
```

`config.max_repair_attempts` defaults to 1.  `repair_count` is reset to 0
by `reflect_or_continue` at the end of every turn.

### 16.4 Planner Decision Logging

Every planner invocation produces a `PlanDecision` record stored in
`ApexGraphState.planner_decisions` (append-only, `operator.add` reducer).

`PlanDecision` fields: `planner_model` ("llm" | "deterministic"),
`confidence`, `selected_task_count`, `rejected_task_count`,
`reasoning_summary`, `fallback_used`, `timestamp`, `phase`.

**How it flows:**

1. `PlanningEngine.plan()` records the decision via `_record_llm()` or
   `_record_fallback()` at every exit point.
2. Each planner wrapper (`ReconPlanner`, etc.) exposes `last_decision:
   PlanDecision | None` which reads from `_engine.last_decision` when an
   engine is configured, or from a locally-set `_last_decision` in the
   deterministic path.
3. `_run_tasks()` / `execute_agent` in `graph.py` reads `planner.last_decision`
   after `plan()` returns and includes it in `planner_decisions: [decision.to_dict()]`.
4. `RunReport.planner_decisions` and `to_json_dict()` export the full list.
5. `format_text()` prints a condensed summary (total / LLM-backed /
   deterministic counts + last 5 per-turn details).

### 16.5 Concurrent Task Execution

`_run_tasks()` in `graph.py` now runs **all tasks** produced by a planner
concurrently using `asyncio.gather` with a `Semaphore` cap of
`min(config.max_concurrency, len(tasks))`.

All tool results are stored in `state["tool_results"]: list[dict]`.
`parse_observation` and `write_memory` iterate over `tool_results` (or fall
back to `[last_tool_result]` for backward compatibility).  One Episode is
created per tool result.

`execute_agent` (credential phase) always runs one task (CredentialPlanner
emits exactly one task per turn per §12.12 safety invariants).

### 16.6 Reflector Integration

`ApexRuntime.run()` now triggers one `ReflectorWorker.run_once()` pass
after the engagement graph completes.  This promotes staged knowledge/skill
entries above the quality gate, applies confidence decay to unused skills,
and quarantines skills whose win-rate fell below `config.winrate_floor`.

The Reflector is the **only** component allowed to promote proposals
(CLAUDE.md §13.10).  The `run_once()` call in `ApexRuntime.run()` is
wrapped in a `try/except` so a Reflector failure does not crash the
engagement — it is logged as a warning and the final state is returned
regardless.

### 16.7 New State Fields

| Field | Type | Reducer | Purpose |
|---|---|---|---|
| `planner_decisions` | `list[dict]` | `operator.add` | Audit log, one dict per planner call |
| `tool_results` | `list[dict] \| None` | overwrite | All tool results from current turn |
| `repair_count` | `int` | overwrite | Repairs consumed this turn; reset to 0 by reflect_or_continue |

### 16.8 New Config Fields

| Field | Default | Purpose |
|---|---|---|
| `max_repair_attempts` | `1` | Max repair calls per turn; 0 disables repair |

### 16.9 Authorization requirement (inherited from §12.3)

All real-execution runs (`--no-dry-run`) **must** target authorized lab
machines.  `RepairEngine` and concurrent task execution are both no-ops in
dry-run mode.  The safety invariants from §11.2 and §12.3 apply to all new
components without exception.

---

## 17. LLM Runtime Wiring

This section documents the LLM wiring layer added in Phase 6.  It connects
the existing `OpenAIModelRouter` and `PlanningEngine` to the actual CLI and
runtime so operators can enable LLM planning with a single flag.

### 17.1 Design invariants (additive to §1 and §16)

1. **Default is always deterministic.**  `ApexConfig.use_llm` defaults to
   `False`.  Without `--use-llm`, `FakeModelRouter` is used and no API calls
   are made — no key, no network, no cost.

2. **Router construction is owned by `ApexRuntime.run()`.**  No planner,
   executor, parser, graph node, or test helper constructs a `ModelRouter`
   directly.  The single construction point is `runtime.py`, so swapping
   the provider is always a one-file change.

3. **LLM objects are never stored in `ApexGraphState`.**  The router is a
   local variable in `run()`; it is closed over by `build_apex_graph()` and
   never serialised into state (memfabric Invariant 1, CLAUDE.md §16.3).

4. **`use_llm=True` + `llm_provider="fake"` still uses `FakeModelRouter`.**
   Setting `llm_provider="fake"` (the default) is a safety backstop —
   even if `--use-llm` is mistakenly passed without an explicit provider,
   no real API calls occur.

5. **`llm_base_url` takes precedence over `OPENAI_BASE_URL` env var.**
   Operators supplying `--llm-base-url` get consistent routing regardless
   of what `OPENAI_BASE_URL` is set to in the environment.

### 17.2 New `ApexConfig` fields

| Field | Type | Default | Purpose |
|---|---|---|---|
| `use_llm` | `bool` | `False` | Enable real LLM via `OpenAIModelRouter` |
| `llm_provider` | `str` | `"fake"` | Provider ID; `"fake"` → `FakeModelRouter`, `"openai"` → `OpenAIModelRouter` |
| `llm_base_url` | `str \| None` | `None` | Overrides `OPENAI_BASE_URL` env var (e.g. `https://openrouter.ai/api/v1`) |
| `planner_model` | `str` | `"openai/gpt-5.5"` | Updated from `gpt-4o-mini` |
| `executor_model` | `str` | `"openai/gpt-5.5"` | Updated from `gpt-4o-mini` |
| `parser_model` | `str` | `"openai/gpt-5.5"` | Updated from `gpt-4o-mini` |

### 17.3 New CLI flags (both `main.py` and `run_htb_local.py`)

| Flag | Default | Effect |
|---|---|---|
| `--use-llm` | `False` | Enable LLM planning |
| `--llm-provider PROVIDER` | `"openai"` | Provider for real LLM (only "openai" is supported today) |
| `--llm-model MODEL` | `None` | Sets `planner_model`, `executor_model`, `parser_model` simultaneously |
| `--llm-base-url URL` | `None` | Override API base URL (e.g. OpenRouter) |

### 17.4 Runtime routing logic (`apex_host/runtime.py`)

```python
if config.use_llm and config.llm_provider != "fake":
    model_router = OpenAIModelRouter(config)   # reads OPENAI_API_KEY from env
else:
    model_router = FakeModelRouter()           # safe default: no API calls

graph = build_apex_graph(api, registry, config, model_router=model_router)
```

`OpenAIModelRouter` reads `config.llm_base_url` first, then falls back to
`os.environ.get("OPENAI_BASE_URL")`.  API keys are never stored in config —
they are read from `OPENAI_API_KEY` at the moment `_build()` is called.

### 17.5 Exact CLI command for OpenRouter

```bash
export OPENAI_API_KEY=sk-or-...   # OpenRouter API key

python -m apex_host.eval.run_htb_local \
  --target <HTB_TARGET_IP> \
  --payload-repo ./payloads \
  --dry-run \
  --use-llm \
  --llm-provider openai \
  --llm-model openai/gpt-5.5 \
  --llm-base-url https://openrouter.ai/api/v1
```

Add `--no-dry-run` only for authorized HTB VPN targets.

### 17.6 Tests (`tests/apex_host/test_llm_wiring.py`)

37 tests covering:
- `ApexConfig` new fields have correct defaults
- Model names updated to `"openai/gpt-5.5"`
- `FakeModelRouter` returns `None` for all roles
- `OpenAIModelRouter._base_url` prefers `config.llm_base_url` over env var
- `main.py` and `run_htb_local.py` parse all four new flags correctly
- `--llm-model` sets planner/executor/parser models simultaneously
- `ApexRuntime.run()` uses `FakeModelRouter` when `use_llm=False`
- `ApexRuntime.run()` constructs `OpenAIModelRouter` when `use_llm=True` and `llm_provider != "fake"`
- `llm_provider="fake"` keeps `FakeModelRouter` even with `use_llm=True`
- `PlanningEngine` falls back to deterministic when LLM returns invalid output
- Dry-run engagement completes with `FakeModelRouter` (baseline)

### 17.7 Extension rules for Claude Code

- **Adding a new provider**: add a new `*ModelRouter` class in `router.py`,
  add its provider string to the `if/elif` chain in `ApexRuntime.run()`,
  and add a `--llm-provider` option to the CLI help text.
- **Changing the default model**: update `planner_model`, `executor_model`,
  and `parser_model` in `ApexConfig` — never hardcode a model name outside
  that class.
- **Tests**: any new routing behavior needs tests in
  `tests/apex_host/test_llm_wiring.py`.  Never construct `OpenAIModelRouter`
  in a test without patching it — use `FakeModelRouter` or a `_StubRouter`
  to avoid API key requirements.
