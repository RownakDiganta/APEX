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

### Environment setup (uv)

`uv` is the authoritative dependency and environment manager (see §22 for the
full migration record). One-time setup from a clean checkout:

```bash
uv sync --all-groups
```

All commands below assume this has been run. Every command is either
prefixed with `uv run` (recommended — no activation step needed) or assumes
an activated `uv`-managed `.venv` (`source .venv/bin/activate`). Do not use
`pip install`, a manually created `venv`, or any Python interpreter outside
the `uv`-managed `.venv` for this project.

### Run the test suite

```bash
uv run pytest tests/ -q
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

### Full-stack dry-run with compiled knowledge and explicit policy file

```bash
python -m apex_host.eval.run_htb_local \
  --target <HTB-machine-IP> \
  --payload-repo ./payloads \
  --knowledge-root ./knowledge \
  --policy-file ./knowledge/policy_db/compiled/hackthebox_lab.yaml \
  --dry-run \
  --export-json ./run_report.json
```

This is the recommended development workflow command.  It:
- Seeds all four compiled knowledge families from `./knowledge/` (63,000+ records
  promoted across ~639 Reflector passes in ~5 s).
- Loads the explicit policy YAML so `policy_source` is visible in the report.
- Exports a full structured JSON report to `./run_report.json` for offline inspection.
- Generates no real network traffic (dry-run mode).

The JSON report includes `policy_gate.policy_source`,
`knowledge_seeding.promotion` (passes, promoted, remaining, stop_reason),
and per-family counts.  Verify with:

```bash
python -c "import json; r=json.load(open('run_report.json')); \
  print('policy_source:', r['policy_gate']['policy_source']); \
  print('promoted:', r['knowledge_seeding']['promotion']['records_promoted'])"
```

### Localhost duplicate-action + logging verification (safe, no real commands)

Use this to verify that:
- duplicate deterministic fallback tasks are skipped (not repeated),
- normal `-v` does **not** print per-record promotion IDs,
- reports show `duplicate_actions` metadata.

```bash
python -m apex_host.eval.run_htb_local \
  --target 127.0.0.1 \
  --knowledge-root ./knowledge \
  --policy-file ./knowledge/policy_db/compiled/hackthebox_lab.yaml \
  --dry-run \
  --use-llm \
  --llm-provider openai \
  --llm-model gpt-5 \
  --max-turns 3 \
  --max-llm-calls 3 \
  --max-llm-calls-per-phase 1 \
  --export-json ./run_reports/duplicate_control_dry.json \
  --export-graph ./run_reports/duplicate_control_dry_ekg.json \
  -v
```

Expected output:
- At most one identical nmap action executes; subsequent identical fallback tasks
  are skipped and recorded as `skip_task` in `duplicate_actions`.
- No per-record promotion IDs appear under normal `-v`; use `--trace-records`
  to enable those.
- `run_reports/duplicate_control_dry.json` contains a `"duplicate_actions"` section
  with `total_skipped ≥ 0`.
- All safety gates remain active (`policy_decisions` present in JSON).

Verify the JSON report:
```bash
python -c "
import json
r = json.load(open('./run_reports/duplicate_control_dry.json'))
print('duplicate_actions:', r.get('duplicate_actions'))
print('policy_blocked:', r['policy_gate']['policy_blocked_count'])
"
```

Add `--trace-records` to also see per-record Reflector promotion logs.

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
  uv run pytest tests/ -q
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

---

## 18. External Knowledge Base Layout

The project keeps an external knowledge directory (`knowledge/` at the repo
root) that contains raw downloaded files from public sources.  **APEX never
loads huge raw files directly at runtime.**  Instead, compiler scripts
(one per family) read the raw sources and write compact JSONL files to a
`compiled/` subdirectory.  At runtime APEX ingests those compiled files via
`MemoryAPI.propose_knowledge()` + Reflector promotion — exactly the same
path as the payload repo loader.

> **Directory name:** the real on-disk directory is `knowledge/` (all
> lowercase, no typo).  Earlier notes that said `Knowlwdge/` were incorrect.
> Use `--knowledge-root ./knowledge` on the CLI.
>
> **Correction (Infra Phase 5, 2026-07-14):** the statement above is only
> true on a case-**insensitive** filesystem (macOS/APFS, where `Knowledge`
> and `knowledge` resolve to the same inode). `git ls-files` shows every
> tracked path under this directory actually uses `Knowledge/` (capital
> K) — confirmed during Infra Phase 5's container build investigation. On
> a case-**sensitive** filesystem (Linux — what any CI runner, Docker
> build, or non-macOS contributor's checkout uses), only `Knowledge/`
> exists; `--knowledge-root ./knowledge` would silently find nothing
> there. This paragraph is left in place per this file's append-only
> correction convention (§21 R12) rather than rewritten — see
> `docs/apex-container.md` §9 for the full investigation and how
> `docker/apex/Dockerfile` handles the mismatch (copies from the real
> `Knowledge/` source path, to a deliberately lowercase `/app/knowledge/`
> destination inside the image).

### 18.1 Directory layout

```
knowledge/
├── intel_db/                 ← CVE, CWE, CAPEC, MITRE ATT&CK raw data
│   ├── attack/enterprise-attack.json
│   ├── capec/capec.xml
│   ├── cve/nvdcve-2.0-<year>.json  (2002–2026 + modified + recent, 26 files)
│   └── cwe/cwe.xml
│
├── methodology_db/           ← Methodology PDFs (files sit directly at root)
│   ├── NIST_SP800_115.pdf
│   ├── OWASP_Code_Review_Guide_v2.pdf
│   ├── owasp_web_security_testing_guide_v4.pdf
│   └── ptes_technical_guidelines.pdf
│
├── payload_db/               ← 4 living-off-the-land / wordlist sub-projects
│   ├── GTFOBins/             ← 477 Linux binary abuse entries
│   │   └── _gtfobins/       ← *** EXTENSIONLESS YAML files, one per binary ***
│   ├── LOLBAS/               ← 242 Windows binary abuse entries
│   │   └── yml/{OSBinaries,OSLibraries,OSScripts,...}/*.yml
│   ├── PayloadsAllTheThings/ ← 67+ web attack payload categories (.md files)
│   └── SecLists/             ← 6055 wordlist files (manifest-only in RAG)
│       ├── Discovery/
│       ├── Passwords/        ← restricted_use="explicit_operator_approval_required"
│       ├── Fuzzing/
│       └── …
│
└── policy_db/                ← HTB authorisation boundary documents
    ├── readme.md
    └── sources/htb/          ← 17 HTB legal documents + legal_index.md
```

### 18.2 Subdirectory conventions (per family)

Each knowledge family directory may grow the following subdirectories over
time.  `sources/` contains the raw downloaded originals; `compiled/` is
written by compiler scripts (all four compilers are now implemented);
`indexes/` is optional.

```
<family>/
├── sources/     ← raw downloaded originals — never modified by code
├── compiled/    ← JSONL files produced by compiler scripts (runtime source)
└── indexes/     ← optional prebuilt BM25 / vector index snapshots
```

**Never point `PayloadRepoLoader` or any runtime loader directly at
`sources/`.** The raw NVD CVE JSON alone is several gigabytes.  Compiler
scripts extract, normalise, and chunk the raw data once; APEX ingests the
compact JSONL output.  **Compiler scripts never fetch from the internet;
they read only from the local `sources/` directory tree.**

### 18.3 Compiled record schema

All compiled JSONL files use the `CompiledKnowledgeRecord` dataclass defined
in `apex_host/knowledge/compiler/schemas.py`.  Required fields:

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Stable content-addressed ID (first 32 hex chars of SHA-256) |
| `source_family` | `SourceFamily` | `intel_db`, `methodology_db`, `payload_db`, `policy_db` |
| `source_type` | `SourceType` | `cve`, `cwe`, `capec`, `attack`, `methodology`, `payload`, `wordlist_manifest`, `htb_rule`, `legal_doc` |
| `source_path` | `str` | Path to the original source file |
| `title` | `str` | Short label (file name, section heading, CVE ID, …) |
| `text` | `str` | Normalised textual content indexed by BM25 + vector |
| `tags` | `list[str]` | Free-form filter labels |
| `confidence` | `float` | Prior confidence (0–1) |
| `updated_at` | `str` | ISO-8601 UTC compile timestamp |
| `metadata` | `dict` | Arbitrary pass-through fields |

### 18.4 Knowledge Compiler Layer

`apex_host/knowledge/compiler/` is the compiler package.  All four source
families have compiler modules.  The CLI entrypoint drives all of them:

```
python -m apex_host.knowledge.compiler.compile_knowledge \
    --knowledge-root ./Knowlwdge
```

#### Module map

| Module | Purpose |
|---|---|
| `schemas.py` | `CompiledKnowledgeRecord`, `SourceFamily`, `SourceType` |
| `common.py` | `iter_files`, `read_text_safely`, `write_jsonl`, `stable_record_id`, `normalize_whitespace` |
| `policy_compiler.py` | `compile_policy(sources_path, output_dir) → int` |
| `methodology_compiler.py` | `compile_methodology(sources_path, output_dir) → int` |
| `intel_compiler.py` | `compile_intel(intel_db_path, output_dir) → int` |
| `payload_compiler.py` | `compile_payload(payload_db_path, output_dir) → tuple[int, int]` |
| `compile_knowledge.py` | CLI entrypoint (`__main__`) for all four compilers |

#### Output files (per family)

| Family | Output file(s) |
|---|---|
| `policy_db` | `compiled/policy_records.jsonl`, `compiled/hackthebox_lab.yaml` |
| `methodology_db` | `compiled/methodology_chunks.jsonl` |
| `intel_db` | `compiled/attack_techniques.jsonl`, `compiled/cwe_weaknesses.jsonl`, `compiled/capec_patterns.jsonl`, `compiled/cve_slim.jsonl` |
| `payload_db` | `compiled/payload_records.jsonl`, `compiled/wordlist_manifest.jsonl` |

#### Key design rules

- **Compiled JSONL is the sole runtime source.**  Nothing reads raw sources at
  runtime.  If a compiled file does not exist, that family is skipped with a
  warning — no fall-back to raw.
- **SecLists wordlists are manifest-only.**  `payload_compiler` never ingests
  individual wordlist lines into RAG.  Each file gets one manifest record
  (`source_type="wordlist_manifest"`) describing its path, category, approx
  line count, and recommended use.  `Passwords/` and credential directories
  carry `metadata.restricted_use="explicit_operator_approval_required"`.
- **No internet access.**  Compiler scripts read only from the local
  `sources/` directory tree.  They never issue HTTP requests or shell out
  to download tools.
- **PDF stubs.**  When no PDF library is installed, `.pdf` files produce a
  metadata-only stub record at `confidence=0.4` rather than crashing.
- **CVE cap.**  `intel_compiler` caps CVE records at `_CVE_RECORDS_PER_FILE =
  2000` per NVD file to keep compiled output bounded (NVD files can exceed
  25,000 entries each).
- **Idempotent IDs.**  `stable_record_id(family, type, path, chunk_index,
  extra)` produces a stable 32-char hex ID via SHA-256; re-running the
  compiler on unchanged sources produces the same IDs.
- **All compiler modules follow §12.6** (two-line file header) and write
  only to `compiled/`.  They never modify `sources/`.

### 18.5 ApexConfig knowledge fields

`ApexConfig` exposes five optional path fields so the runtime knows where to
find compiled knowledge at startup:

| Field | Default | CLI flag (future) |
|---|---|---|
| `knowledge_root` | `None` | `--knowledge-root` |
| `policy_db_path` | `None` | `--policy-db-path` |
| `methodology_db_path` | `None` | `--methodology-db-path` |
| `intel_db_path` | `None` | `--intel-db-path` |
| `payload_db_path` | `None` | `--payload-db-path` |

When `knowledge_root` is set, the convention is
`<knowledge_root>/<family>/compiled/`.  Per-family overrides take
precedence.  `None` means the family is not loaded at startup — this is
the safe default.  The existing `payload_repo_path` field and
`PayloadRepoLoader` are unchanged; `payload_db_path` will eventually
supersede `payload_repo_path` when a payload compiler script is added.

### 18.6 Rules for Claude Code

- **Never load raw source files at runtime.** Point runtime loaders at
  `compiled/*.jsonl` only.  If a compiled file does not exist for a family,
  skip that family and log a warning — do not fall back to raw sources.
- **Compiler scripts belong under `apex_host/knowledge/`**, not in
  `memfabric/`.  They may use the `compiler/` package freely.
- **No domain content in source files.**  Compiler scripts read external
  directories; they never embed raw payload text, CVE descriptions, or
  legal excerpts in Python source.
- **Tests for new compiler scripts** go in
  `tests/apex_host/test_<family>_compiler.py`.  Tests must use `tmp_path`
  fixtures and synthetic data — never load real files from `knowledge/`.
- **`stable_record_id` must be used** for all compiled record IDs so that
  re-running a compiler on unchanged sources is idempotent (same IDs,
  no duplicate proposals in the staging area).

### 18.7 External Knowledge Layout Reality Check

This section documents the **real on-disk layout** verified by
`apex_host/knowledge/compiler/layout.py` and the `--inspect` flag.  Use it
as the single source of truth before writing path-dependent compiler code.

#### Verified path assumptions

| Family | Real source path | Notes |
|---|---|---|
| `policy_db` | `knowledge/policy_db/sources/htb/` | `sources/` subdir exists; `compiled/` does not auto-create |
| `methodology_db` | `knowledge/methodology_db/` (root) | **No** `sources/` subdir; PDFs sit at root |
| `intel_db` | `knowledge/intel_db/{attack,capec,cve,cwe}/` | 4 named subdirs; 26 NVD CVE JSON files |
| `payload_db` | `knowledge/payload_db/` (root) | 4 sub-projects directly under root; **no** `sources/` |

#### GTFOBins format (non-obvious)

GTFOBins entries are **extensionless YAML files** inside `_gtfobins/` (not
`.yml`).  The tool name is the filename (e.g. `_gtfobins/curl`).  The YAML
root key is `functions:` mapping category names to a list of `{code, contexts}`
dicts.  The compiler handles these via `_compile_gtfobins()` and
`_is_gtfobins_entry()` — do not route them through `_compile_yaml()` which
expects `.yml` / `.yaml` extensions and `Name`/`Commands` keys.

#### Layout detector

`apex_host/knowledge/compiler/layout.py` provides:
- `detect_layout(root) → KnowledgeLayout` — structured report (no writes).
- `format_inspect_report(layout) → str` — human-readable text.

The `--inspect` CLI flag invokes these:
```bash
python -m apex_host.knowledge.compiler.compile_knowledge \
    --knowledge-root ./knowledge --inspect
```

Exit codes: **0** all compiled outputs present; **1** any output missing or
root absent.  The flag never writes to disk.

#### Expected compiled outputs after running all compilers

| Family | File | Status |
|---|---|---|
| `policy_db` | `policy_db/compiled/policy_records.jsonl` | missing until compiled |
| `policy_db` | `policy_db/compiled/hackthebox_lab.yaml` | missing until compiled |
| `methodology_db` | `methodology_db/compiled/methodology_chunks.jsonl` | missing until compiled |
| `intel_db` | `intel_db/compiled/attack_techniques.jsonl` | missing until compiled |
| `intel_db` | `intel_db/compiled/cwe_weaknesses.jsonl` | missing until compiled |
| `intel_db` | `intel_db/compiled/capec_patterns.jsonl` | missing until compiled |
| `intel_db` | `intel_db/compiled/cve_slim.jsonl` | missing until compiled |
| `payload_db` | `payload_db/compiled/payload_records.jsonl` | missing until compiled |
| `payload_db` | `payload_db/compiled/wordlist_manifest.jsonl` | missing until compiled |

To compile everything:
```bash
python -m apex_host.knowledge.compiler.compile_knowledge \
    --knowledge-root ./knowledge
```

---

### 18.8 Required Compiled Knowledge Outputs

The table below lists every file that must exist under `knowledge/` after the
compilers run.  This is the authoritative list — it matches the
`REQUIRED_OUTPUTS` dict in `compile_knowledge.py` and the `--strict` flag
checks exactly these nine files.

| # | Family | File | Description | Min records |
|---|---|---|---|---|
| 1 | `policy_db` | `policy_db/compiled/policy_records.jsonl` | HTB rule + legal doc records | 1 |
| 2 | `policy_db` | `policy_db/compiled/hackthebox_lab.yaml` | HTB rule summary YAML (human-readable) | — |
| 3 | `methodology_db` | `methodology_db/compiled/methodology_chunks.jsonl` | PDF/Markdown methodology chunks | 1 |
| 4 | `intel_db` | `intel_db/compiled/attack_techniques.jsonl` | MITRE ATT&CK enterprise attack patterns | 100 |
| 5 | `intel_db` | `intel_db/compiled/cwe_weaknesses.jsonl` | CWE weakness descriptions | 100 |
| 6 | `intel_db` | `intel_db/compiled/capec_patterns.jsonl` | CAPEC attack patterns | 50 |
| 7 | `intel_db` | `intel_db/compiled/cve_slim.jsonl` | NVD CVE slim records (capped 2000/file) | 1000 |
| 8 | `payload_db` | `payload_db/compiled/payload_records.jsonl` | GTFOBins/LOLBAS/PAT semantic records | 100 |
| 9 | `payload_db` | `payload_db/compiled/wordlist_manifest.jsonl` | SecLists wordlist manifests (no line content) | 10 |

#### Compile and verify all 9 outputs

```bash
# Compile (idempotent — safe to re-run):
python -m apex_host.knowledge.compiler.compile_knowledge \
    --knowledge-root ./knowledge

# Compile + verify (exits 1 if any file is missing or empty):
python -m apex_host.knowledge.compiler.compile_knowledge \
    --knowledge-root ./knowledge --strict

# Inspect without writing (shows per-file size and OK/MISSING status):
python -m apex_host.knowledge.compiler.compile_knowledge \
    --knowledge-root ./knowledge --inspect
```

#### Record counts from real knowledge/ (as of last full compile)

| Family | File | Records |
|---|---|---|
| `policy_db` | `policy_records.jsonl` | 21 |
| `methodology_db` | `methodology_chunks.jsonl` | 4 (PDF stubs) |
| `intel_db` | `attack_techniques.jsonl` | 697 |
| `intel_db` | `cwe_weaknesses.jsonl` | 969 |
| `intel_db` | `capec_patterns.jsonl` | 571 |
| `intel_db` | `cve_slim.jsonl` | 51,268 |
| `payload_db` | `payload_records.jsonl` | 4,171 |
| `payload_db` | `wordlist_manifest.jsonl` | 6,070 |

#### Rules for Claude Code

- **`REQUIRED_OUTPUTS` in `compile_knowledge.py` is the single source of truth.**
  `--strict` mode, `layout.py` output expectations, and
  `tests/apex_host/test_compilers_output.py` all reference the same 9 files.
  If a compiler is added or renamed, update `REQUIRED_OUTPUTS` first, then
  the `_*_OUTPUTS` lists in `layout.py`, then the tests.
- **All 9 must be present before RAG ingestion runs.**  `ApexRuntime` (future)
  will call `seed_knowledge_db()` which reads compiled JSONL via
  `MemoryAPI.propose_knowledge()` + Reflector promotion.  A missing file is a
  no-op for that family (compiler gracefully returns 0), but the knowledge gap
  will affect retrieval quality.
- **Never add a 10th output without updating `REQUIRED_OUTPUTS` and the table
  above.**  The `--strict` flag will silently not check it otherwise.

---

### 18.9 Compiled Knowledge Runtime Seeding

This section documents how compiled JSONL knowledge is loaded into `MemoryAPI` at
engagement startup.  All four knowledge families (`policy_db`, `methodology_db`,
`intel_db`, `payload_db`) use the same path: `propose_knowledge()` → Reflector
promotion → retrievable via `api.query(filters=...)`.

#### Design rules (non-negotiable)

- **Only reads `compiled/` JSONL — never raw sources at runtime.**  The raw NVD CVE
  JSON alone is several gigabytes.  `compiled_loader.py` reads only the compact
  output files listed in `_FAMILY_JSONL`.
- **All writes go through `MemoryAPI.propose_knowledge()`** (memfabric Invariant 1).
  `compiled_loader.py` never touches a store directly.
- **Staging gate is preserved** (memfabric Invariant 4, CLAUDE.md §13.10).  Staged
  entries are NOT retrievable until `ReflectorWorker.run_once()` promotes them.
  `seed_compiled_knowledge()` calls `run_once()` after all families are staged.
- **`source_family` survives promotion.**  `promote_knowledge()` in `memfabric/api.py`
  merges `entry.metadata` into the lexical and vector index metadata so that
  `source_family` (and other provenance fields) are present on `ScoredEntry.metadata`
  after retrieval.  `HybridRetriever.search()` applies the `filters` dict as a
  post-filter after reranking.

#### Module map

| Module | Purpose |
|---|---|
| `apex_host/knowledge/compiled_loader.py` | `load_compiled_family(compiled_dir, family, api) → int` — stage one family |
| `apex_host/knowledge/query_filters.py` | Pre-built filter dicts + post-filter helpers for source_family / source_type |
| `apex_host/knowledge/seed_loader.py` | `seed_compiled_knowledge(api, config, mf_config) → dict[str, int]` — all families |
| `apex_host/runtime.py` | `ApexRuntime.seed_all()` — backward-compatible wrapper that calls both seeders |

#### Seeding flow

```
ApexRuntime.seed_all()
  ├── seed_payload_repo(payload_repo_path, api, mf_config)    # raw payload repo (unchanged)
  └── seed_compiled_knowledge(api, apex_config, mf_config)
        ├── for each family: load_compiled_family(compiled_dir, family, api)
        │     └── propose_knowledge() per record  → staging area (NOT yet retrievable)
        └── ReflectorWorker.run_once()             → promotes entries above quality gate
```

#### Path resolution

| Priority | Source |
|---|---|
| 1 (highest) | Explicit per-family field: `ApexConfig.policy_db_path`, `intel_db_path`, etc. |
| 2 | `ApexConfig.knowledge_root / <family> / compiled` |
| 3 | Missing / no config → family skipped with count 0 (no crash) |

#### Filter dicts (from `query_filters.py`)

```python
from apex_host.knowledge.query_filters import (
    POLICY_FILTER, PAYLOAD_FILTER, INTEL_FILTER, METHODOLOGY_FILTER,
    WORDLIST_MANIFEST_FILTER,
    source_family_filter, source_type_filter, combined_filter,
    filter_by_source_family, filter_by_source_type, filter_by_metadata,
)

# At query time (post-filter enforced in HybridRetriever):
bundle = await api.query(text="SQL injection", k=10, filters=INTEL_FILTER)

# Or filter an existing result list:
intel_hits = filter_by_source_family(bundle.entries, "intel_db")
```

#### CLI flags (both `main.py` and `run_htb_local.py`)

```bash
python -m apex_host.main \
  --target <IP> \
  --payload-repo ./payloads \
  --knowledge-root ./knowledge \
  --dry-run
```

When `--knowledge-root` is omitted, only the raw payload repo is seeded (backward
compatible with all existing tests and scripts).

#### Metadata fields preserved after promotion

Every `ScoredEntry` from a compiled knowledge query carries:

| Field | Value |
|---|---|
| `source_family` | `"policy_db"`, `"intel_db"`, `"payload_db"`, `"methodology_db"` |
| `source_type` | `"htb_rule"`, `"legal_doc"`, `"attack"`, `"cve"`, `"cwe"`, `"capec"`, `"payload"`, `"wordlist_manifest"`, `"methodology"` |
| `source_path` | Absolute path to the original source file |
| `title` | Short label (e.g. CVE ID, file name, technique name) |
| `tags` | Free-form filter labels from the compiler |
| `tier` | `"semantic"` (all compiled knowledge is in the semantic tier) |
| `restricted_use` | `"general"` or `"explicit_operator_approval_required"` (for Passwords/ entries) |

#### Tests (`tests/apex_host/test_compiled_loader.py`)

32 tests covering:
- Staging isolation: records not retrievable before `ReflectorWorker.run_once()`
- `policy_db` filter returns only policy records (no cross-family leakage)
- `payload_db` filter returns only payload records
- `intel_db` filter returns only intel records
- `methodology_db` filter returns only methodology records
- `seed_compiled_knowledge()` returns correct per-family counts
- Graceful degradation: missing family produces count 0, no crash
- No knowledge root configured → all counts 0
- `ScoredEntry.text` is non-empty after promotion (retrieval text fix)
- `query_filters.py` helper functions and pre-built constants
- CLI `--knowledge-root` flag parsed correctly in `main.py` and `run_htb_local.py`
- Per-family path override takes priority over `knowledge_root`
- Malformed JSONL lines skipped; valid lines still staged
- Empty-text records skipped
- `_record_to_knowledge_entry` preserves all metadata fields and respects confidence override

#### Rules for Claude Code

- **Never bypass the staging gate.**  Do not call internal staging-store methods
  directly to make compiled entries immediately retrievable.  Only `ReflectorWorker`
  may promote (§13.10).
- **`promote_knowledge()` must merge `entry.metadata`.**  The fix in `memfabric/api.py`
  (`{**entry.metadata, "tier": ..., "source": ..., "_text": ...}`) must be preserved.
  Reverting it breaks the filter system silently.
- **`HybridRetriever.search()` must apply `filters` as a post-filter.**  The fix in
  `memfabric/retrieval/engine.py` (post-filter after reranking) must be preserved.
  Without it, `api.query(filters=...)` returns unfiltered results.
- **`seed_all()` is the public seeding surface.**  The old `seed()` method is kept
  for backward compatibility but callers should prefer `seed_all()`.
- **Tests for new compiled-knowledge behavior** go in
  `tests/apex_host/test_compiled_loader.py`.  Use `tmp_path` fixtures and synthetic
  JSONL data — never load real files from `knowledge/`.

---

### 18.10 Initial Knowledge Promotion Strategy

**Why the default `reflector_max_promotions_per_run=100` cap exists:** During
normal post-engagement Reflector passes the cap prevents log floods and keeps
each `run_once()` call bounded.  It is a per-pass limit, not a lifetime limit.

**Why startup seeding needs multiple passes:** `seed_compiled_knowledge_full()`
stages all compiled records in one shot (e.g. 63,783 at startup), then calls
`promote_staged_knowledge_until_stable()` which loops `run_once()` until every
promotable record is indexed.  At cap=100, 63,783 records need ~638 passes,
taking roughly 5 seconds in-memory.

#### `promote_staged_knowledge_until_stable()` — bounded loop contract

The loop terminates on the **first** condition that triggers:

| Stop reason | When it fires |
|---|---|
| `exhausted` | All un-promoted staged entries are now promoted |
| `no_progress` | A pass promoted zero entries (all remaining are below `min_confidence`) |
| `max_passes` | `ApexConfig.knowledge_promotion_max_passes` reached (default 1000) |
| `max_records` | `ApexConfig.knowledge_promotion_max_records` cap reached (default `None`) |
| `timeout` | `ApexConfig.knowledge_promotion_timeout_seconds` elapsed (default `None`) |
| `single_pass` | Mode is `"single_pass"` — legacy behaviour; exactly one pass |
| `disabled` | Mode is `"disabled"` — staging only, no promotion |

**Progress tracking uses un-promoted entry counts.**  `get_staged_knowledge()`
returns all staging-dict entries including already-promoted ones (which stay for
auditability).  The loop counts only those where `entry.promoted is False` so
it correctly detects `no_progress` and `exhausted`.

#### `PromotionSummary` dataclass

Returned by `seed_compiled_knowledge_full()` and included in `seed_all()` under
the `"_promotion"` key:

| Field | Type | Description |
|---|---|---|
| `records_staged_initial` | `int` | Un-promoted entries counted at loop start |
| `records_promoted` | `int` | Total promoted across all passes |
| `records_remaining` | `int` | Un-promoted entries when loop ended |
| `passes_run` | `int` | `run_once()` calls made |
| `stop_reason` | `str` | See table above |
| `elapsed_seconds` | `float` | Wall-clock time |

#### Controlling the promotion strategy via `ApexConfig`

| Field | Default | Purpose |
|---|---|---|
| `knowledge_promotion_mode` | `"until_stable"` | `"until_stable"`, `"single_pass"`, or `"disabled"` |
| `knowledge_promotion_max_passes` | `1000` | Hard cap — prevents infinite loops |
| `knowledge_promotion_max_records` | `None` | Optional promoted-records cap |
| `knowledge_promotion_timeout_seconds` | `None` | Optional wall-clock timeout |

#### Rules for Claude Code

- **Never modify `reflector_max_promotions_per_run` to fix startup promotion.**
  The correct fix is the multi-pass loop in `seed_loader.py`.  The per-run cap
  stays low intentionally to keep normal post-engagement Reflector passes bounded.
- **Progress must be tracked by un-promoted count, not raw staging-dict size.**
  `get_staged_knowledge()` includes promoted entries; always filter by
  `not entry.promoted` before counting to detect real progress.
- **`mode="disabled"` is for test fixtures only** — just like
  `policy_enabled=False`.  Do not set it in production configurations.
- **Tests** go in `tests/apex_host/test_promotion_loop.py`.  Use synthetic
  JSONL fixtures; never load real `knowledge/` files.

---

## 19. PolicyAdvisor and Scope Enforcement

`apex_host/policy/` is the deterministic scope and policy enforcement layer.
It is **not legal advice** and must never be called "LegalAdvisor".  It
enforces engagement scope constraints using configurable, LLM-free rules.

### 19.1 Design invariants (non-negotiable)

1. **No LLM calls.** `PolicyAdvisor` is purely synchronous and deterministic.
   It never calls `ModelRouter`, never does I/O in `review_task()`, and
   never touches `MemoryAPI`.

2. **Conservative by default.** A missing or unreadable policy YAML file
   makes the advisor **more** restrictive, not less.  The conservative
   default allows only `config.target` and blocks all destructive and
   brute-force tools regardless of whether a YAML was found.

3. **Blocking rules run first.** The rule evaluation order in `ALL_RULES`
   (in `rules.py`) is fixed.  Destructive-command and target-scope rules
   run before any permissive rules so they cannot be bypassed.

4. **All restrictions come from `ApexConfig`.** The policy YAML file (when
   present) is only used to confirm that an operator-supplied policy exists
   (`policy_loaded=True`).  The YAML content itself is not parsed for rules —
   restrictions are set exclusively through `ApexConfig` fields.  This means
   YAML presence never automatically relaxes anything.

5. **`policy_enabled=False` is for test fixtures only.** Do not set it in
   production configurations.  Every real engagement must run with policy
   checking enabled.

6. **Secret material is never evaluated.** Rules inspect tool names and
   `args` tokens only.  They never read from the EKG, execute tools, or
   call network services.

### 19.2 Module map

```
apex_host/policy/
├── __init__.py          # public exports: PolicyAdvisor, models, load_policy
├── models.py            # PolicyStatus, PolicyDecision, PolicyRule, ScopePolicy
├── policy_loader.py     # load_policy(config) → ScopePolicy
├── rules.py             # deterministic rule functions + ALL_RULES registry
└── advisor.py           # PolicyAdvisor.review_task()
```

### 19.3 Public API

```python
from apex_host.policy import PolicyAdvisor, PolicyDecision, PolicyStatus, load_policy

policy = load_policy(config)                   # loads YAML or conservative default
advisor = PolicyAdvisor(policy, config)

decision = advisor.review_task(task, phase, evidence, config)
# decision.status: "approved" | "blocked" | "needs_human_review"
# decision.rule_name: the name of the rule that fired (or "default_allow")
# decision.reason: human-readable explanation
```

`review_task` is synchronous and always returns a `PolicyDecision` — it never
raises.  Rule exceptions are caught internally, logged, and skipped.

### 19.4 Rule registry and evaluation order

Rules are evaluated in the fixed order defined in `rules.ALL_RULES`.
The first rule that returns a non-None `PolicyDecision` wins.

| # | Rule function | When it fires |
|---|---|---|
| 1 | `check_no_destructive_command` | `task.params["tool"]` in `policy.blocked_tools` |
| 2 | `check_target_in_scope` | `task.params["target"]` not in `policy.allowed_targets` |
| 3 | `check_no_attacking_infrastructure` | An arg token contains an IP outside the allowed scope |
| 4 | `check_no_password_list` | An arg token is a wordlist flag (`-w`, `--wordlist`, …) |
| 5 | `check_no_sensitive_data` | An arg token contains a known sensitive path fragment |
| 6 | `check_require_review` | Tool is in `policy.require_review_for` |
| 7 | `check_safe_recon_allowed` | Safe recon tool against assigned target → explicit `approved` |
| — | Default allow | All rules returned None → `approved` |

### 19.5 New `ApexConfig` fields

| Field | Type | Default | Purpose |
|---|---|---|---|
| `policy_enabled` | `bool` | `True` | Enable scope enforcement; `False` is for test fixtures only |
| `policy_file` | `str \| None` | `None` | Explicit path to policy YAML; overrides knowledge_root lookup |
| `allow_sensitive_data_access` | `bool` | `False` | Permit access to sensitive system paths (requires explicit operator approval) |
| `allow_password_lists` | `bool` | `False` | Permit wordlist/password-list flags (e.g. `ffuf -w`) |
| `require_policy_approval_for` | `list[str]` | `[]` | Tool names that always require human review |

### 19.6 Policy YAML lookup order

`load_policy` resolves the policy YAML in priority order:

1. `config.policy_file` (explicit operator override — set via `--policy-file` CLI flag)
2. `<config.knowledge_root>/policy_db/compiled/hackthebox_lab.yaml`
3. `knowledge/policy_db/compiled/hackthebox_lab.yaml` (local development)

If none exists: `policy_loaded=False`, `policy_source="conservative_default"`.
**The same restrictions apply regardless of `policy_loaded`.**

#### `--policy-file` CLI flag

Both `main.py` and `eval/run_htb_local.py` expose:

```bash
--policy-file PATH
```

This sets `ApexConfig.policy_file` to the supplied path.  The field already
existed in `ApexConfig`; the flag exposes it on the CLI so operators can supply
an explicit policy file without relying on the `--knowledge-root` discovery path.

**Precedence (non-negotiable):**
1. `--policy-file PATH` (wins always, when present)
2. `--knowledge-root DIR` discovery (`<DIR>/policy_db/compiled/hackthebox_lab.yaml`)
3. Local dev convention (`knowledge/policy_db/compiled/hackthebox_lab.yaml`)
4. Conservative built-in default (no file needed; same rules always apply)

**If the explicit path does not exist:** `load_policy` falls back to the
conservative default and emits a warning log at `DEBUG` level — it does **not**
crash.  `policy_loaded=False` and `policy_source="conservative_default"`.

**Tests** go in `tests/apex_host/test_policy_file_cli.py`.

### 19.7 Blocked tools (always blocked, independent of allowed_tools)

`_ALWAYS_BLOCKED_TOOLS` in `policy_loader.py` covers:

- Destructive system commands: `rm`, `mkfs`, `dd`, `shutdown`, `reboot`,
  `halt`, `poweroff`, `fdisk`, `format`, `mkswap`
- Autonomous brute-force tools: `hydra`, `medusa`, `patator`, `hashcat`, `john`
- Exploit frameworks: `msfconsole`, `msfvenom`

These are blocked by `check_no_destructive_command` (rule 1) before any other
rule runs.  Adding one to `ApexConfig.allowed_tools` does **not** unblock it.

### 19.8 Execution-Time Policy Gate (implemented)

`PolicyAdvisor` is wired into every agent node in `apex_host/graph.py` as a
**mandatory pre-execution gate**.  The gate runs **before** any tool command,
subprocess, or network connection is initiated — including `TelnetExecutor`,
`BrowserExecutor`, and `RepairEngine` repaired tasks.

#### How the gate is injected

`build_apex_graph()` accepts an optional `advisor: PolicyAdvisor | None = None`
parameter.  When `None` (the production default), the advisor is constructed
from `load_policy(config)` inside the function and captured in a closure shared
by all agent nodes.  Tests inject a `_FakeAdvisor` through this parameter —
no monkeypatching of internals is required.

```python
graph = build_apex_graph(api, registry, config, advisor=_FakeAdvisor(always_blocked=True))
```

#### Gate placement in each agent node

| Node | Gate fires before |
|---|---|
| `recon_agent` / `web_agent` / `priv_esc_agent` | `run_command()` in `_run_tasks()._run_one_cmd()` |
| `execute_agent` (credential) | `TelnetExecutor.run()` or `run_command()` |
| `browser_agent` | `BrowserExecutor.run()` |
| `repair_agent` | `run_command()` for the repaired task |

All gate checks are performed synchronously inside the async node functions —
no I/O, no LLM calls.

#### Blocked task result structure

When `advisor.review_task()` returns a non-approved decision, the agent node
returns a synthetic tool result dict immediately (without touching runner.py):

```python
{
    "task_id": task.id,
    "tool": tool,
    "args": [...],
    "target": target,
    "parser": parser_name,
    "stdout": "",
    "stderr": "",
    "returncode": 1,
    "dry_run": config.dry_run,
    "error": f"policy_blocked: {reason}",
    "phase": state["phase"],
    "policy_blocked": True,
    "policy_rule": rule_name,
}
```

`returncode=1` with `error="policy_blocked: ..."` causes `_outcome_for()` to
return `Outcome.fundamental`, so `route_after_write` sends the turn to
`reflect_or_continue` — **blocked tasks are never retried by `repair_agent`**.

#### `policy_decisions` state field

Every task reviewed by `PolicyAdvisor` (approved or blocked) appends one dict
to `state["policy_decisions"]` via the `operator.add` reducer:

```python
{
    "tool": tool,
    "target": target,
    "phase": state["phase"],
    "status": "approved" | "blocked" | "needs_human_review",
    "rule_name": rule_name,
    "reason": reason,
}
```

`RunReport` derives `policy_approved_count`, `policy_blocked_count`,
`policy_needs_review_count`, and `last_blocked_reasons` from this list.
`to_json_dict()` exports `"policy_gate"` (summary dict) and
`"policy_decisions"` (raw list).

#### Gate for `needs_human_review`

Both `blocked` AND `needs_human_review` decisions prevent execution:
`if not pd.is_approved` is the gate condition.  The result is the same
blocked tool result dict — the turn continues without executing the task.

### 19.9 Tests

`tests/apex_host/test_policy_advisor.py` (53 tests) verifies all rule-level
acceptance criteria:

- `nmap` against `config.target` → `approved` (rule: `safe_recon_allowed`)
- `nmap` against a different IP → `blocked` (rule: `target_in_scope`)
- `ffuf -w wordlist.txt` → `blocked` (rule: `no_password_list`)
- `rm` → `blocked` (rule: `no_destructive_command`)
- Missing policy YAML → conservative default still blocks off-scope targets
- `nc` and `curl` against target → `approved`
- Tool in `require_policy_approval_for` → `needs_human_review`
- `policy_enabled=False` → `approved` (rule: `policy_disabled`)
- `/etc/shadow` in args → `blocked` (rule: `no_sensitive_data`)
- `allow_password_lists=True` → wordlist flag approved
- `allow_sensitive_data_access=True` → sensitive path approved
- IP in args outside scope → `blocked` (rule: `no_attacking_infrastructure`)
- Malformed YAML file → `policy_loaded=False`, conservative default applied
- All `ApexConfig` policy fields have correct defaults

`tests/apex_host/test_policy_gate.py` (18 tests) verifies the execution-time
gate wired into `graph.py`:

- Approved task → `run_command` is called; no blocked policy_decisions entry
- Blocked task → `run_command` is NOT called; blocked entry in `policy_decisions`;
  `last_tool_result.policy_blocked == True`; `error` contains `"policy_blocked"`
- Blocked credential task (`telnet_access`) → `TelnetExecutor.run` is NOT called;
  blocked entry in `policy_decisions` with `tool="telnet_access"`
- Blocked browser task → `BrowserExecutor.run` is NOT called; blocked entry
  in `policy_decisions` with `tool="browser"`
- `build_report` derives correct `policy_approved_count` / `policy_blocked_count` /
  `policy_needs_review_count` / `last_blocked_reasons` from `state["policy_decisions"]`
- `format_text` renders a "Policy Gate" section
- `to_json_dict` includes `"policy_gate"` summary and `"policy_decisions"` raw list
- `ApexGraphState` has `policy_decisions` field typed as `Annotated[list[dict], operator.add]`

### 19.10 Rules for Claude Code

- **Never call it LegalAdvisor.** It is a scope and policy enforcement tool.
- **Never add LLM calls to `PolicyAdvisor` or any `rules.py` function.**
  Determinism is a safety property here, not a limitation.
- **New rules go in `rules.py`, not in `advisor.py` or planners.**  Add the
  function to `ALL_RULES` in the correct position (blocking rules before
  permissive ones).
- **Tests for new rules** go in `tests/apex_host/test_policy_advisor.py`.
  Use the `_make_task` / `_make_advisor` helper pattern established there.
- **Gate wiring tests** go in `tests/apex_host/test_policy_gate.py`.  Use
  `_FakeAdvisor` and the `advisor=` parameter on `build_apex_graph()`.
- **Blocked tasks are never retried.** `returncode=1` + `error="policy_blocked:…"`
  routes to `reflect_or_continue`, not `repair_agent`.  Do not add retry logic
  for blocked tasks.
- **`policy_decisions` must appear in every agent return dict.**  When adding a
  new agent node or tool path, include `"policy_decisions": [pd_entry]` in the
  return value so the `operator.add` reducer accumulates the decision.  Missing
  this key means the gate fires but leaves no audit trail.
- **`policy_enabled=False` is for test fixtures only.**  Never set it in
  an `ApexConfig` that is used for a real engagement.
- **The YAML content is not trusted input.** `load_policy` reads the YAML
  only to verify the file is well-formed (`yaml.safe_load`, not `yaml.load`).
  It never evaluates YAML keys as policy rules.

---

### 19.11 LLM Policy Checkpoints

`apex_host/policy/llm_guard.py` provides `LLMPolicyGuard` — a synchronous,
stateless content filter that wraps every LLM call in `PlanningEngine` and
`RepairEngine`.  No I/O, no network access, no MemoryAPI calls.

#### Three-layer pipeline (in order)

```
PromptBuilder.build_messages()
  → LLMPolicyGuard.sanitize_messages()   # strip secrets from prompt
  → LLMPolicyGuard.check_prompt()        # pre-flight scope/secret check
  → LLM call (only if not blocked)
  → LLMPolicyGuard.check_output()        # post-LLM safety check
  → Validator                            # existing schema/tool gate
  → TaskSpec list
```

On any block (`check_prompt` or `check_output` returns `(True, reason)`),
the engine **immediately** falls back to the deterministic planner — no
exception, no stall.  The `RepairEngine` returns `None` on block (skipping
repair for this turn).

#### `sanitize_messages(messages) → (sanitized, count)`

Replaces in all message content (case-sensitive):
- Every configured password from `ApexConfig.password_candidates` (minimum
  4 characters to avoid false positives) → `[REDACTED_PASSWORD]`
- Every configured username from `ApexConfig.username_candidates` (same
  minimum length) → `[REDACTED_USERNAME]`
- `sk-<20+ chars>` (OpenAI-style key) → `[REDACTED_API_KEY]`
- `AKIA<16 chars>` (AWS access key) → `[REDACTED_AWS_KEY]`
- `Bearer <20+ chars>` → `Bearer [REDACTED_TOKEN]`
- `ghp_<36 chars>` (GitHub PAT) → `[REDACTED_GITHUB_TOKEN]`
- `-----BEGIN ... PRIVATE KEY-----` → `[REDACTED_PRIVATE_KEY]`

Returns the sanitized message list and the total substitution count.  The
original list is never mutated.

#### `check_prompt(messages) → (blocked, reason)`

Blocks when any message content contains:
- A configured password that survived `sanitize_messages` (defense-in-depth).
- A `-----BEGIN ... PRIVATE KEY-----` header not caught by pattern redaction.
- An IPv4 address in a `GOAL:` or `TARGET:` line that is not `config.target`.

Non-GOAL/TARGET lines (evidence content, EKG summaries) are **not** scanned
for IPs — this prevents false positives from knowledge-base content that
legitimately references other IP addresses.

#### `check_output(raw_text) → (blocked, reason)`

Blocks when the raw LLM output contains any of:

| Category | Trigger examples |
|---|---|
| Persistence/backdoor | `crontab -e`, `authorized_keys`, `.bashrc`, `systemctl enable`, `nc -e` |
| Brute force | `hydra`, `medusa`, `patator`, `hashcat`, `john … --wordlist` |
| Data exfiltration | `/etc/shadow`, `base64 … </etc/` |
| Out-of-scope target | Non-target IP in a `"target":` or `"args":` JSON field |

The check runs on the **raw JSON string** before any parsing, so it catches
dangerous content in reasoning, args, and rationale fields alike.

#### `PlanDecision` audit fields

Three new fields (with safe defaults) record guard activity per planner
invocation:

| Field | Type | Meaning |
|---|---|---|
| `policy_checkpoint_status` | `str` | `""` = guard not configured; `"clean"` = guard ran, nothing flagged; `"redacted"` = secrets were redacted; `"blocked"` = guard blocked the call |
| `redaction_count` | `int` | Number of substitutions made by `sanitize_messages` |
| `policy_block_reason` | `str` | Human-readable block reason, or `""` if not blocked |

These appear in `PlanDecision.to_dict()` and therefore in `RunReport.planner_decisions`.

#### Wiring

`LLMPolicyGuard` is injected into `PlanningEngine` and `RepairEngine` via
a `guard: LLMPolicyGuard | None = None` constructor parameter — consistent
with how `PolicyAdvisor` is injected into `build_apex_graph()`.

**`PlanningEngine`** wiring (in `apex_host/planning/engine.py`):

```python
engine = PlanningEngine(
    model_router=router,
    fallback_planner=deterministic_planner,
    allowed_tools=config.allowed_tools,
    target=config.target,
    guard=LLMPolicyGuard(config),   # add this
)
```

**`RepairEngine`** wiring (in `apex_host/planning/repair.py`):

```python
engine = RepairEngine(
    model_router=model_router,
    allowed_tools=config.allowed_tools,
    target=config.target,
    dry_run=config.dry_run,
    guard=LLMPolicyGuard(config),   # add this
)
```

When `guard=None` (the default), the engine behaves exactly as before —
no guard checks, no overhead.  `FakeModelRouter` (the default) returns
`None` for `planner_llm()`, so the engine falls back to deterministic
before the guard is ever reached.

#### Rules for Claude Code

- **`PlanningEngine` remains the only planner LLM caller.**  `LLMPolicyGuard`
  sits inside `PlanningEngine.plan()` — it is not called by planners, parsers,
  or executors directly.
- **`RepairEngine` must use the same guard.**  Any future repair-like engine
  must apply the same pre/post checks.
- **Do not store chain-of-thought.**  `policy_block_reason` records why the
  guard blocked, not LLM reasoning content.
- **No real LLM calls in tests.**  Use `_StubRouter(_StubLLM(json_str))` or
  `_FakeModelRouter()`.  Never construct `OpenAIModelRouter` in a test.
- **New block categories go in `llm_guard.py`.**  Add to the appropriate
  pattern list (`_PERSISTENCE_PATTERNS`, `_BRUTE_FORCE_PATTERNS`,
  `_EXFILTRATION_PATTERNS`).  Add a test in `test_llm_guard.py`.
- **Tests** go in `tests/apex_host/test_llm_guard.py`.  Use the established
  `_StubLLM` / `_CapturingLLM` / `_StubRouter` / `_StubFallback` pattern.
- **`sanitize_messages` never mutates the input list.**  It returns a new list.
- **`guard=None` is the safe default.**  Do not add `guard=LLMPolicyGuard(config)`
  to any `PlanningEngine` construction without explicitly deciding to enable it.
  The default is deterministic behavior with no guard overhead.

---

## 20. Knowledge + Policy Definition of Done

A session of Claude Code that modifies, extends, or verifies knowledge or
policy components **must** clear every item in this checklist before
reporting success.  "Compiles" and "tests pass" are necessary but not
sufficient — real compiled files must exist and verification must pass.

### 20.1 Knowledge compilation

1. **Real `./knowledge` compiles without error:**
   ```bash
   python -m apex_host.knowledge.compiler.compile_knowledge \
       --knowledge-root ./knowledge --strict --verbose
   ```
   Exit code must be **0**.  Any `STRICT:` failure line in stderr = not done.

2. **All 9 required compiled outputs exist and are valid:**
   ```bash
   python -m apex_host.knowledge.compiler.verify_compiled \
       --knowledge-root ./knowledge
   ```
   Exit code must be **0**.  Any `[FAIL]` line = not done.

3. **Compiled knowledge seeds through MemoryAPI:**
   `seed_compiled_knowledge(api, config, mf_config)` must stage all families
   and `ReflectorWorker.run_once()` must promote them so that
   `api.query(filters=INTEL_FILTER)` returns non-empty `ScoredEntry` objects
   with `ScoredEntry.text != ""`.

### 20.2 Policy gates

4. **`PolicyAdvisor` gates risky execution:**
   `advisor.review_task(task, phase, evidence, config)` must return
   `blocked` for off-scope targets, destructive tools, and brute-force tools,
   and `approved` for safe recon tools against `config.target`.

5. **`LLMPolicyGuard` checkpoints are active:**
   When wired into `PlanningEngine` or `RepairEngine`, `sanitize_messages`
   must redact configured passwords before the LLM call, and `check_output`
   must return `(True, reason)` for any output containing persistence patterns
   (e.g. `crontab -e`), brute-force tools (e.g. `hydra`), or exfiltration
   patterns (e.g. `/etc/shadow`).

### 20.3 Codebase invariants

6. **No host-specific code added to `memfabric`:**
   `grep -r "CVE\|exploit\|shell\|credential\|hydra\|nmap\|telnet" memfabric/`
   must find no matches in non-test source files.

7. **All tests pass:**
   ```bash
   uv run pytest tests/ -q
   ```
   Exit code **0**.  No failures, no errors.

8. **`verify_compiled` always runs after `compile_knowledge` (unless `--no-verify`):**
   Modifying the compiler must not break the auto-verify flow.  The
   `--no-verify` flag is for CI pipelines that run verification separately —
   never skip it in interactive development.

### 20.4 Quick verification commands (in order)

```bash
# 1. Compile
python -m apex_host.knowledge.compiler.compile_knowledge \
    --knowledge-root ./knowledge --strict --verbose

# 2. Verify
python -m apex_host.knowledge.compiler.verify_compiled \
    --knowledge-root ./knowledge

# 3. Test
uv run pytest tests/ -q
```

Or via Make:

```bash
make compile-knowledge
make verify-knowledge
make test
```

All three must exit **0** before a session is considered complete.

---

## 21. Reviewer Remediation Roadmap

This section records the known defects and the order in which they will be
fixed. It is generated from the full per-finding audit in
`docs/reviewer_findings_audit.md` (Phase 0 baseline, 2026-07-13).

**Baseline:** 1311 tests passing, `mypy --strict` clean (101 source files).  
**Post-Phase 1 (initial):** 1386 tests passing, `mypy --strict` clean, 135 pre-existing ruff errors.  
**Post-Phase 1 (re-open corrections, 2026-07-13):** 1426 tests passing, `mypy --strict` clean, 135 ruff errors (exit code 1). 40 new tests in `tests/test_graph_phase1_extended.py` covering: deep copy isolation at all nesting depths (I01–I09), query snapshot Option C contract (J01–J04), pre-batch snapshot completeness (K01–K02), episode transaction capability (L01–L05), rollback-failure handling (M01–M05), repository-wide architecture scan (N01–N05), and `_graph_lock` holders table (O01–O10).  
**Post-Phase 10 (2026-07-14):** 2618 tests passing, `mypy --strict` clean (125 source files), 130 ruff errors (at Phase 8 ceiling, exit code 1).  
**Post-Phase 11 (2026-07-14):** 2668 tests passing, `mypy --strict` clean (125 source files), 130 ruff errors (at Phase 10 ceiling, exit code 1). All 21 findings independently re-verified; F16 and F21 confirmed fixed; F15 confirmed NOT A DEFECT.

Do **not** implement fixes from later phases before earlier phases are
complete — later phases depend on substrate-level invariants restored in
Phase 1 and 2.

**12-Phase Remediation Sequence:**

| Phase | Area | Status |
|---|---|---|
| Phase 1 | Graph transaction, isolation, rollback (`memfabric`) | ✓ COMPLETE |
| Phase 2 | Conflict enforcement and winner persistence | OPEN |
| Phase 3 | Skill lifecycle, decay, quarantine | OPEN |
| Phase 4 | Hybrid retrieval and cache correctness | OPEN |
| Phase 5 | Centralized LLM gateway and repair budgets | OPEN |
| Phase 6 | Unified execution, policy, deduplication, errors | OPEN |
| Phase 7 | Async responsiveness and cancellation | ✓ COMPLETE |
| Phase 8 | Secret redaction and graph representation | ✓ COMPLETE |
| Phase 9 | State boundaries and configuration consistency | ✓ COMPLETE |
| Phase 10 | Orchestration refactor | ✓ COMPLETE |
| Phase 11 | Independent final verification | ✓ COMPLETE |

---

### Strict Reviewer Remediation Program — 12 Binding Rules

The following rules govern ALL future remediation sessions. Treat them as
hard constraints, equivalent in authority to the design invariants in §1.

**R01 — Phase 0 (audit) must be complete before any fix is written.**
No fix may be written while audit findings are still being gathered. The audit
is complete when `docs/reviewer_findings_audit.md`, `docs/remediation_traceability_matrix.md`,
and `docs/remediation_validation_baseline.md` all exist and are current.

**R02 — Every finding must be independently reproduced before marked CONFIRMED.**
A finding is CONFIRMED only when the reviewer has observed the failure scenario
described in `docs/reviewer_findings_audit.md` — either through a failing test,
a code trace, or a repo-wide search that corroborates the claim. PLAUSIBLE is
used when the failure path is theoretically valid but not yet observed in practice.

**R03 — Write the failing test first (red), then fix (green).**
The missing test for a finding must be written and confirmed to fail before the
fix is applied. A fix whose test was written after the code is not trusted.

**R04 — No phase may combine findings from different severity tiers without justification.**
Phase groupings in §21 are by dependency and severity, not by convenience.
Mixing a Medium finding from Phase 2 into Phase 4 to ship it faster is prohibited.

**R05 — Every phase ends with a full `pytest -q` run.**
All previously-passing tests must still pass. The test count must be ≥ the
prior phase's count. Zero failures is a hard requirement, not a target.

**R06 — `mypy --strict` must be clean after every phase.**
No type errors may be introduced. If a fix requires a type annotation change,
that change is in scope for the phase. If it requires a new Protocol, add it.

**R07 — The ruff error count must not increase.**
The baseline ruff count (135 at Phase 1) is a ceiling. Fixing a ruff error is
welcome. Adding a new one (even a fixable one) is not acceptable.

**R08 — No architectural changes during remediation phases.**
Do not add new top-level modules, change Protocol signatures, or restructure
package boundaries during Phases 2–5. The remediation program fixes
implementation defects; it does not redesign the architecture.

**R09 — `docs/remediation_traceability_matrix.md` must be updated at phase end.**
The Phase Completion Checklist table in the matrix must be updated with the
actual test count, mypy result, and ruff count for the completed phase.

**R10 — Substantive fixes during audit (Phase 0) are prohibited.**
Phase 0 is read-only. If a defect is found during Phase 0 that is tempting to
fix immediately (e.g., a one-line change), it must be logged as a finding and
fixed in the appropriate numbered phase. The audit must remain unpolluted by
interleaved fixes.

**R11 — Never mark a phase complete without running the full validation suite.**
The three commands in `docs/remediation_validation_baseline.md` (pytest, mypy,
ruff) must all produce outputs that satisfy the acceptance criteria. "It should
pass" is not sufficient.

**R12 — Findings are never deleted; they are only status-updated.**
`docs/reviewer_findings_audit.md` is append-only for findings. A fixed finding
is marked `FIXED (date)` with a fix description. A finding found to be invalid
is marked `NOT REPRODUCED` with the evidence. Rows are never deleted.

---

### Phase 1 — Substrate Correctness (`memfabric`) ✓ COMPLETE

**Initial completion:** 2026-07-13  
**Re-open corrections completed:** 2026-07-13  
**Final test count after all Phase 1 corrections:** 1426 passed  
**mypy after Phase 1:** Success — no issues found in 101 source files  
**Ruff after Phase 1:** 135 errors (baseline unchanged, exit code 1)

Fixes to `memfabric/` only. No `apex_host` changes.

**Phase 1 re-open — 12 issues resolved:**

| Issue | Description | Resolution |
|---|---|---|
| I1 | Shallow defensive copies (one-level-deep) | Fixed: `copy.deepcopy` for `props` and `_provenance` (T13 updated) |
| I2 | Query snapshot consistency undocumented | Fixed: Option C documented in `query()` docstring; tests J01–J04 |
| I3 | Pre-batch snapshot completeness unproven | Fixed: tests K01–K02 verify Phase 1 snapshot before Phase 2 writes |
| I4 | Episode transaction not all-or-nothing | Fixed: capability pre-check raises `TransactionCapabilityError` before any writes |
| I5 | Rollback failures swallowed silently | Fixed: per-step try/except; `TransactionIntegrityError` if rollback fails |
| I6 | Architecture scan limited to `memfabric/` | Fixed: tests N01–N05 scan both `memfabric/` and `apex_host/` |
| I7 | `_graph_lock` users table unverified | Fixed: tests O01–O10 prove each method's locking behaviour |
| I8 | Ruff reported as "passes" (incorrect) | Fixed: "Ruff baseline unchanged at 135 errors (exit code 1)" |
| I9 | Test functions listed as ranges not names | Fixed: all tests named explicitly in this section |
| I10 | Incorrect finding status for F01 | Fixed: F01 specific k-omission FIXED; broader retrieval cache OPEN (Phase 4) |
| I11 | Phase ordering was 5-phase (incorrect) | Fixed: replaced with 12-phase sequence above |
| I12 | "No architectural changes" (inaccurate wording) | Fixed: MemoryAPI internal transaction architecture changed; top-level boundaries unchanged |

| Finding | Description | File(s) | Status |
|---|---|---|---|
| F01 | Add `k` to `_cache_key` payload to prevent stale truncated retrieval results | `memfabric/retrieval/engine.py` | FIXED |
| F02 | Snapshot `_write_clock` before `apply_deltas` batch; restore on rollback | `memfabric/api.py` | FIXED |
| F19 | (Same fix as F02 — different symptom, same root) | `memfabric/api.py` | FIXED |

**Additional substrate hardening delivered in Phase 1:**

1. **`_graph_lock` (new)** — `asyncio.Lock` added to `MemoryAPI.__init__`. Every
   `upsert_node`, `upsert_edge`, and `apply_deltas` acquires this lock for the
   full read-modify-write cycle, eliminating the TOCTOU race where a concurrent
   writer could interleave between a graph read and its paired write. Two callers
   updating disjoint fields on the same node now both survive.

2. **`_upsert_node_locked` / `_upsert_edge_locked`** — internal helpers that
   contain the merge / LWW logic and require the caller to hold `_graph_lock`.
   Public `upsert_node` / `upsert_edge` acquire the lock and delegate. `apply_deltas`
   acquires the lock once for the entire batch and calls the locked helpers.

3. **Defensive copies in `NetworkXGraphStore`** — `get_node`, `get_edge`,
   `get_subgraph`, `all_nodes`, `all_edges` now return copies of stored objects
   (`_copy_node`, `_copy_edge` helpers). Callers can no longer corrupt stored state
   by mutating the returned `props` dict.

**Transaction invariants guaranteed after Phase 1:**
- `_graph_lock` is the single exclusive boundary for all graph mutations.
- Lock nesting order (always outer→inner): `_graph_lock` → `_staging_lock` →
  `GraphStore._lock`. Never acquired in reverse order.
- Do not hold `_graph_lock` while executing tools, calling LLMs, running browser
  automation, embedding large batches, reranking, or doing unrelated filesystem I/O.
- This is a single-process guarantee (Python asyncio, cooperative multitasking).
  Multi-process deployments must replace `asyncio.Lock` with a distributed
  advisory lock (e.g. Redis SETNX) backed by the same durable graph store.

**Acceptance criteria (all passed):**

*Initial Phase 1 tests (`tests/test_graph_atomicity.py` — 17 tests):*
- `test_t07_write_clock_restored_after_rollback` — covers F02/F19
- `test_t15_cache_key_includes_k`, `test_t16_different_k_causes_cache_miss` — covers F01
- `test_t01` through `test_t14`, `test_t17` — concurrent write, defensive copy, batch atomicity
- All 1311 pre-existing tests still pass (1328 total)

*Phase 1 Comprehensive (`tests/test_graph_transaction_complete.py` et al. — 58 new tests):*
- Reader isolation (Design A), public deletion API, complete rollback coverage
- Test count after Phase 1 Comprehensive: **1386 passed**

*Phase 1 Re-open corrections (`tests/test_graph_phase1_extended.py` — 40 new tests):*
- `test_i01`–`test_i09` — deep copy isolation at all nesting depths, all 5 public read paths
- `test_j01`–`test_j04` — query snapshot Option C contract; subgraph under `_graph_lock`
- `test_k01`–`test_k02` — pre-batch snapshot complete before first write; rollback restores
- `test_l01`–`test_l05` — episode capability pre-check; `TransactionCapabilityError` attributes
- `test_m01`–`test_m05` — rollback-failure injection; `TransactionIntegrityError` attributes
- `test_n01`–`test_n05` — architecture scan: `apex_host/` + `memfabric/` + synthetic violations
- `test_o01`–`test_o10` — exact `_graph_lock` acquisition for every public method
- **Final test count: 1426 passed**

### Phase 1 — Comprehensive Transaction Model (16 binding rules)

The following rules govern all future work on `memfabric/api.py` and any code that
touches graph state.  They are derived from the Phase 1 comprehensive implementation
and are as binding as the invariants in §1.

**T01 — `_graph_lock` is the SOLE transaction boundary for all graph mutations.**  
Every call that reads and then writes graph state must hold `_graph_lock` for the
entire read-modify-write cycle.  This includes `upsert_node`, `upsert_edge`, and
`apply_deltas`.  No graph mutation may occur without this lock.

**T02 — `_graph_lock` is NOT reentrant.**  
`asyncio.Lock` is not reentrant.  Any method that already holds `_graph_lock` must call
`self._graph.*` methods directly (store methods) rather than public `MemoryAPI` methods
to avoid deadlock.  Document "requires `_graph_lock` to be held" on every internal
locked helper.

**T03 — Reader paths acquire `_graph_lock`.**  
`get_subgraph()`, `open_tasks()`, and the subgraph-attachment path inside `query()`
each acquire `_graph_lock` for the duration of their graph reads.  This prevents any
reader from observing a partial batch state between `await` points.

**T04 — Lock nesting order is fixed and inviolable.**  
Outer to inner: `_graph_lock` → `_staging_lock` → `GraphStore._lock`.  Never acquire
in a different order.  `_staging_lock` is never acquired while waiting for `_graph_lock`.

**T05 — `_write_clock` is always restored after rollback.**  
`_rollback_locked` restores `self._write_clock = pre_clock` as its FIRST action before
restoring any nodes or edges.  No other code may decrement or reset `_write_clock`
except during rollback.  This prevents version-sequence gaps from accumulating.

**T06 — Rollback removes newly-created entries from all indexes.**  
For each entry created in a failed batch: `_delete_node_locked` / `_delete_edge_locked`
removes the entry from the graph, lexical index, and optional vector index.  A final
`kv.delete_prefix("retrieval:")` is called at the end of rollback to bust the cache.

**T07 — Rollback restores updated entries in all indexes.**  
For each entry updated in a failed batch: `put_node` / `put_edge` restores the pre-batch
snapshot, and `lexical.add` (with old text and metadata) restores the old lexical entry.

**T08 — `_delete_node_locked` and `_delete_edge_locked` are the canonical deletion helpers.**  
All deletion code paths (rollback, public `delete_node`, public `delete_edge`) must use
these locked helpers.  No code path may call `self._graph.delete_node()` directly except
inside one of these helpers.

**T09 — Public `delete_node` and `delete_edge` acquire `_graph_lock`.**  
These are the only public deletion methods on `MemoryAPI`.  Callers that need to delete
must go through these methods, not through store methods directly.

**T10 — Episode rollback uses `_pop_episodes` via `getattr`.**  
`apply_deltas` rolls back episodes by calling `getattr(self._episodic, "_pop_episodes")`.
Stores without this method log a warning — they do not crash.  The Protocol does not
expose `_pop_episodes`; it is an implementation detail of in-memory stores only.

**T11 — Proposal rollback removes only the batch's own proposals.**  
`_rollback_locked` removes only IDs that were staged during the failed batch.
Pre-existing proposals (staged before the batch) must survive unchanged.

**T12 — The retrieval cache is always busted at the end of rollback.**  
`kv.delete_prefix("retrieval:")` is called after all per-entry index operations complete,
whether the batch succeeded or failed.  This is the canonical cache-bust point.

**T13 — Defensive copies are fully isolated deep copies (`copy.deepcopy`).**  
`_copy_node` / `_copy_edge` use `copy.deepcopy` for both `props` and `_provenance`.
This guarantees isolation at every nesting depth — callers cannot corrupt stored state
by mutating nested dicts, nested lists, or nested provenance values in returned objects.
The earlier "one-level-deep" description was incorrect and has been corrected.  Tests
I01–I09 in `tests/test_graph_phase1_extended.py` verify isolation for all nesting depths
and all five public read paths.

**T14 — `apply_deltas` snapshot is taken before ANY write, not lazily.**  
All `pre_nodes` and `pre_edges` lookups happen in the Phase 1 snapshot loop before
the Phase 2 write loop begins.  No snapshot may be taken after a write has started.

**T15 — Reader isolation guarantee scope is single-process asyncio.**  
The lock is `asyncio.Lock`, which is a single-process guarantee.  Multi-process
deployments require a distributed advisory lock (e.g. Redis SETNX) backed by the
same durable store.  Do not claim cross-process isolation without explicit wiring.

**T16 — Architecture scan test `test_g01_no_production_graph_mutation_bypasses_memory_api`
is the authoritative bypass detector.**  
If you add new graph-mutation code, run this test.  It fails if any file outside
`api.py` and `graph_networkx.py` calls `put_node`, `put_edge`, `delete_node`, or
`delete_edge` on a graph store.  Passing this test is a necessary (but not sufficient)
condition for Invariant 1 compliance.

---

### Phase 2 — Conflict Enforcement and Winner Persistence

Enforce documented conflict lifecycle invariants in `memfabric/`. Requires Phase 1 complete.

| Finding | Description | File(s) |
|---|---|---|
| F20 | Wire `dependents_blocked_by()` check into `read_context` (substrate) and `load_context` (apex) before subgraph is passed to planners | `memfabric/coordination/graph_loop.py`, `apex_host/graph.py` |

**Acceptance criteria:** `test_conflict_blocks_planner_when_field_contested` passes; no regressions.

---

### Phase 3 — Skill Lifecycle, Decay, Quarantine

Enforce documented but unenforced Reflector invariants. Requires Phase 2 complete.

| Finding | Description | File(s) |
|---|---|---|
| F21 | Replace direct `best_match.wins += 1 / confidence = ...` mutations in Reflector with `await api.update_skill_result(id, won=True)` | `memfabric/reflector/worker.py:133-138` |

**Acceptance criteria:** `test_reflector_skill_update_goes_through_api` passes; no regressions.

---

### Phase 4 — Hybrid Retrieval and Cache Correctness

Fixes to `memfabric/retrieval/`. Requires Phase 1 complete. Can run parallel to Phase 3.

| Finding | Description | File(s) |
|---|---|---|
| F01-broader | Broader retrieval cache correctness beyond `k` — query hash coverage | `memfabric/retrieval/engine.py` |
| F05 | Replace count-only `_context_hash` with content-sensitive hash (node/edge ID sets) | `apex_host/planning/engine.py:145-154` |

**Acceptance criteria:** Cache correctness tests pass; no regressions.

---

### Phase 5 — Centralized LLM Gateway and Repair Budgets

Fixes to the LLM planning layer. Requires Phase 4 complete.

| Finding | Description | File(s) |
|---|---|---|
| F03 | Add `budget_tracker` param to `RepairEngine`; gate LLM calls through `can_call()` | `apex_host/planning/repair.py` |
| F04 | Pass `budget_tracker=budget_tracker` to `RepairEngine` in `build_apex_graph` | `apex_host/graph.py:318-323` |
| F08 | Pass `current_phase=state.get("phase")` to `decide_phase` in `reflect_or_continue` peek | `apex_host/graph.py:1108-1112` |
| F14 | Wire `LLMPolicyGuard(config)` into `PlanningEngine` and `RepairEngine` when `use_llm=True` | `apex_host/graph.py` |

**Acceptance criteria:** Missing tests from F03, F04, F08, F14 pass; no regressions.

---

### Phase 6 — Unified Execution, Policy, Deduplication, Error Handling

Fixes to `apex_host/graph.py` and parsers. Requires Phase 5 complete.

| Finding | Description | File(s) |
|---|---|---|
| F06 | `route_after_write`: check all `tool_results` for failures, not only `last_tool_result` | `apex_host/graph.py:942-957` |
| F07 | Browser episode outcome: derive from own `tool_result["error"]`, not `state["last_error"]` | `apex_host/graph.py:905-908` |
| F09 | Add `return_exceptions=True` to `asyncio.gather` in `_run_tasks`; handle exception entries | `apex_host/graph.py:537` |
| F10 | Derive `NmapParser` edge IDs deterministically (host+port+proto+tech slug) | `apex_host/parsers/nmap_parser.py` |
| F11 | Derive `AccessParser` `grants` edge ID deterministically (credential ID + access_state ID) | `apex_host/parsers/access_parser.py` |
| F12 | Refactor `CredentialPlanner` to call `capabilities_from_subgraph` once per `plan()` | `apex_host/planners/credential_planner.py` |
| F13 | Mark duplicate-skip episodes with a distinct outcome/flag so Reflector ignores them | `apex_host/graph.py:488-503` + `write_memory` |
| F15 | Add test; verify `GlobalPlanner.record_turn` doesn't double-charge on phase transitions | `apex_host/graph.py:344-358` + test |
| F16 | Add accumulation test for `duplicate_actions` across turns | `tests/apex_host/test_duplicate_actions.py` |

**Acceptance criteria:** Missing tests from F06–F16 pass; no regressions.

---

### Phase 7 — Async Responsiveness and Cancellation ✓ COMPLETE

**Completion date:** 2026-07-14  
**Tests after Phase 7:** 2218 passed  
**mypy after Phase 7:** Success — 109 source files  
**Ruff after Phase 7:** 130 errors (below 133 baseline)

Implemented fixes A01–A09 and created `tests/apex_host/test_phase7_async.py` (131 tests).

#### Async reliability invariants (binding — added 2026-07-14)

**P7-I01** — CPU-bound BM25 work runs in a thread pool via `asyncio.to_thread`,
never blocking the event loop.  `BM25LexicalIndex.search()` and `_rebuild_async()`
both use this pattern.

**P7-I02** — Holding `asyncio.Lock` while `await asyncio.to_thread(...)` runs is
**correct**.  The lock maintains mutual exclusion but the event loop is free to
schedule other coroutines that do not need the same lock.

**P7-I03** — Subprocess timeout sends SIGTERM first, waits
`config.subprocess_sigterm_grace_seconds` (default 5 s), then SIGKILL.  Never
immediate SIGKILL on timeout.

**P7-I04** — `asyncio.CancelledError` in any subprocess path triggers child
cleanup (SIGTERM → wait) before re-raising.  No zombie/orphan processes.

**P7-I05** — `playwright.chromium.launch()` is wrapped in `asyncio.wait_for`
with `config.browser_launch_timeout_seconds` (default 30 s).  No indefinite hang.

**P7-I06** — Report and EKG export writes are atomic: temp-file write in same
directory + `os.fsync` + POSIX rename.  A crash mid-write cannot leave a
truncated file at the destination path.

**P7-I07** — File reads during knowledge seeding (`compiled_loader.py`) use
`asyncio.to_thread(path.read_text, ...)` to avoid blocking the event loop.

**P7-I08** — `IO_SEMAPHORE` and `CPU_SEMAPHORE` in `apex_host/async_utils.py`
bound concurrent thread-pool submissions.  Limits: `max(4, cpu_count * 2)` for
I/O, `max(2, cpu_count)` for CPU.

**P7-I09** — `ApexRuntime.aclose()` is idempotent (safe to call multiple times).
It cancels all background asyncio tasks and awaits `asyncio.gather(...,
return_exceptions=True)` to suppress individual cancellation exceptions.

**P7-I10** — All five Phase 7 timeout config fields have safe, non-zero defaults:
`subprocess_sigterm_grace_seconds=5.0`, `browser_launch_timeout_seconds=30.0`,
`telnet_read_timeout_seconds=10.0`, `retrieval_channel_timeout_seconds=5.0`,
`parser_timeout_seconds=10.0`.

#### New files

| File | Purpose |
|---|---|
| `apex_host/async_utils.py` | `run_io`, `run_cpu`, `write_atomic_async`, `write_json_atomic`, semaphore constants |
| `tests/apex_host/test_phase7_async.py` | 131 tests across 19 groups (G01–G19) |
| `docs/phase7_end_report.md` | Full Phase 7 end report |

#### Modified files

| File | Change |
|---|---|
| `memfabric/stores/lexical_bm25.py` | A01 (scoring) + A02 (rebuild) via `asyncio.to_thread` |
| `memfabric/stores/episodic_jsonl.py` | A03: file append via `asyncio.to_thread` |
| `apex_host/knowledge/compiled_loader.py` | A04: file read via `asyncio.to_thread` |
| `apex_host/eval/report.py` | A05: atomic temp-file write |
| `apex_host/eval/export_graph.py` | A06: atomic temp-file write |
| `apex_host/tools/runner.py` | A07 (SIGTERM grace) + A08 (CancelledError cleanup) |
| `apex_host/agents/browser_executor.py` | A09: `asyncio.wait_for` on launch |
| `apex_host/config.py` | 5 new timeout fields |
| `apex_host/runtime.py` | `aclose()` shutdown method |

---

### Phase 8 — Secret Redaction and Graph Representation ✓ COMPLETE

**Completion date:** 2026-07-14  
**Tests after Phase 8:** 2298 passed  
**mypy after Phase 8:** Success — 112 source files  
**Ruff after Phase 8:** 130 errors (at Phase 7 ceiling)

#### Binding invariants (P8 series)

**P8-I01 — `apex_host.security.redaction` is the sole source of redaction logic.**  
No `apex_host` source file (other than `redaction.py` itself) may contain the
string literals `"[redacted]"` or `"[session_redacted]"` as code constants.
Import `REDACTED_PLACEHOLDER` / `SESSION_REDACTED_PLACEHOLDER` from that module.

**P8-I02 — Live session transcripts are never stored.**  
`TelnetExecutor` (and any future network session executor) writes
`SESSION_REDACTED_PLACEHOLDER` to `episode.data["stdout"]` — never the raw
session bytes.  Metadata fields (`stdout_length`, `shell_found`) may be stored
alongside for debugging without leaking credential material.

**P8-I03 — `secret_hint` is always `REDACTED_PLACEHOLDER`.**  
Every `credential` node written to the EKG must have
`props["secret_hint"] = REDACTED_PLACEHOLDER`.  The plaintext credential must
never appear in graph state, episodic log, or any proposal.

**P8-I04 — `apex_host.graph_ids` is the sole source of EKG ID construction.**  
All parsers and graph-writing components call the builder functions in
`graph_ids.py`.  Inline f-strings like `f"host:{ip}"` in parsers are a
violation caught by the ARCH test suite in `test_phase8_redaction.py`.

**P8-I05 — `put_edge` must validate both endpoint nodes exist.**  
`NetworkXGraphStore.put_edge()` raises `ValueError` with a message containing
`"from_id"` or `"to_id"` when the referenced node does not exist.
`MemoryAPI.upsert_edge()` propagates this exception.  Dangling edges are
prevented at the store boundary.

**P8-I06 — `export_ekg` always includes schema_version.**  
Every call to `export_ekg()` includes `"schema_version": EKG_SCHEMA_VERSION`
as the first key in the returned dict so consumers can detect incompatible
schema changes.

#### New files

| File | Purpose |
|---|---|
| `apex_host/security/__init__.py` | Package; re-exports `redact_dict`, `redact_session_text`, `redact_value` |
| `apex_host/security/redaction.py` | Central recursive redaction; `REDACTED_PLACEHOLDER`, `SESSION_REDACTED_PLACEHOLDER` |
| `apex_host/graph_ids.py` | Canonical EKG ID builders + `normalize_url()` + `EKG_SCHEMA_VERSION = "1"` |
| `tests/apex_host/test_phase8_redaction.py` | 80 acceptance tests (REDACT, CANARY, BOUND, GRAPH_ID, URL, PAR, DANGLE, SCHEMA, ARCH, INT) |

#### Modified files

`apex_host/agents/telnet_executor.py`, `apex_host/parsers/access_parser.py`,
all six parser files (nmap, banner, browser, command, ffuf, gobuster),
`memfabric/stores/graph_networkx.py` (parallel-edge + dangling-edge fixes),
`apex_host/graph.py` (canonical anchor node), `apex_host/eval/export_graph.py`
(schema_version key).

---

### Phase 9 — Shared-State Boundaries, Canonical Configuration, and Safe Default Consistency ✓ COMPLETE

**Completion date:** 2026-07-14  
**Tests added (Phase 9):** 80 (`tests/apex_host/test_phase9_config.py`)  
**Total tests after Phase 9:** 2378 passed  
**mypy after Phase 9:** Success — 112 source files  
**Ruff after Phase 9:** 130 errors (at Phase 8 ceiling, exit code 1)

#### Binding invariants (P9 series)

**P9-I01 — `ApexConfig.from_cli_args()` is the canonical CLI→config factory.**  
Both `main.py` and `eval/run_htb_local.py` call `ApexConfig.from_cli_args(args)` to
construct `ApexConfig`.  No other production file (except `config.py` itself and
`eval/run_synthetic_machine.py`) may call `ApexConfig(...)` directly.  Adding a new
CLI flag means adding its mapping in `from_cli_args()` only — not in two separate files.

**P9-I02 — `llm_provider` defaults to `"fake"` end-to-end.**  
`ApexConfig.llm_provider = "fake"` is the field default.  Both CLI entry points register
`--llm-provider` with `default=None` so that when the flag is absent, `from_cli_args()`
propagates `None` → field default `"fake"`.  Setting `"openai"` requires an explicit
`--llm-provider openai` flag on every invocation.

**P9-I03 — `to_safe_dict()` is the approved serialisation path.**  
`to_safe_dict()` returns all `ApexConfig` fields as a JSON-serialisable dict with
`password_candidates` replaced by `[REDACTED_PLACEHOLDER]` entries.  It uses
`REDACTED_PLACEHOLDER` (imported from `apex_host.security.redaction`) — never a
hardcoded `"[redacted]"` string literal (which would violate P8-I01).

**P9-I04 — `run_synthetic_machine.py` uses only canonical graph_ids builders.**  
The five inline EKG ID f-strings have been replaced with calls to `_host_id`,
`_service_id`, `_endpoint_id`, `_auth_flow_id`, and `_exposes_edge_id` from
`apex_host.graph_ids`.  ARCH tests 01–03 verify no f-strings remain.

#### New files

| File | Purpose |
|---|---|
| `tests/apex_host/test_phase9_config.py` | 80 acceptance tests across 7 groups (CFG, CLI, ENV, STATE, SERIAL, ARCH, E2E) |

#### Modified files

| File | Change |
|---|---|
| `apex_host/config.py` | Added `config_schema_version: str = "1"` field; `to_safe_dict()` method; `from_cli_args()` classmethod; `fields as _dc_fields` and `REDACTED_PLACEHOLDER as _REDACTED` imports |
| `apex_host/main.py` | Changed `--llm-provider default="openai"` → `default=None`; replaced 20-line `config_kwargs` block with `config = ApexConfig.from_cli_args(args)` |
| `apex_host/eval/run_htb_local.py` | Same two changes as `main.py` |
| `apex_host/eval/run_synthetic_machine.py` | Replaced inline EKG ID f-strings with canonical `graph_ids` builders |

#### Defects fixed

| # | Description |
|---|---|
| D1 | `--llm-provider` CLI default was `"openai"` — overrode ApexConfig's safe `"fake"` default even when user did not pass the flag |
| D2 | Both `main.py` and `run_htb_local.py` had separate 20-line `config_kwargs` blocks with no divergence detection |
| D3 | `run_synthetic_machine.py` built EKG IDs with inline f-strings — P8-I04 violation |
| D4 | No `config_schema_version` field |
| D5 | No `to_safe_dict()` method — no safe serialisation path that redacts credentials |
| D6 | No `from_cli_args()` factory — duplicated mapping logic across two entry points |

---

### Phase 10 — Orchestration Refactor ✓ COMPLETE

**Completion date:** 2026-07-14  
**Tests after Phase 10:** 2618 passed  
**mypy after Phase 10:** Success — 125 source files  
**Ruff after Phase 10:** 130 errors (at Phase 8 ceiling, exit code 1)

Decomposed monolithic `apex_host/graph.py` (1056 lines, `build_apex_graph` ~830 lines)
into a 13-module `apex_host/orchestration/` package.  Fixed F17 and F18.
Verified all prior-phase fixes (F04/F06/F07/F08/F09/F13/F14) are correctly placed
in the decomposed architecture.

| Finding | Description | File(s) | Status |
|---|---|---|---|
| F17 | Update README test count | `README.md` | FIXED (2026-07-14) |
| F18 | Add `tests/test_file_headers.py` — two-line file-header convention | `tests/test_file_headers.py` | FIXED (2026-07-14) |

#### Binding invariants (P10 series)

**P10-I01 — `build_apex_graph()` public signature is unchanged.**
All parameters preserved. Thin wrapper `apex_host/graph.py` re-exports from
`apex_host/orchestration/builder.py`.

**P10-I02 — Node factory pattern: `make_<name>_node(deps)` returns async node function.**
No graph node defined inline in `build_apex_graph`. Each factory receives
`OrchestrationDeps` and returns an independently testable async function.

**P10-I03 — `OrchestrationDeps` is a frozen dataclass — immutable after construction.**
All node closures share one `OrchestrationDeps`. Mutation would create race conditions.

**P10-I04 — `OrchestrationDeps` never appears in `ApexGraphState`.**
Infrastructure objects captured by node closures only (memfabric Invariant 1).

**P10-I05 — Node names in the compiled graph are stable.**
`load_context`, `global_plan`, `recon_agent`, `web_agent`, `browser_agent`,
`execute_agent`, `priv_esc_agent`, `parse_observation`, `write_memory`,
`repair_agent`, `reflect_or_continue` must never be renamed (checkpoint replay).

**P10-I06 — `routing.py` is the sole location for routing function definitions.**
All conditional edge logic lives in `orchestration/routing.py`.

**P10-I07 — `completion.py` functions are pure (no I/O, no state, no async).**
`outcome_for`, `is_repairable`, `should_complete` are synchronous pure functions.

**P10-I08 — `run_command` is imported inside `build_apex_graph()`, not at module level.**
Tests that monkeypatch `run_command` must target `apex_host.tools.runner.run_command`
and apply the patch BEFORE calling `build_apex_graph()`.

**P10-I09 — No `check_conflict_dependencies` call in orchestration/ modules.**
The conflict gate is owned by `TaskDispatcher.dispatch()` in `execution/dispatcher.py`.

**P10-I10 — All orchestration files follow the §12.6 two-line file-header convention.**
Enforced by `tests/test_file_headers.py` (F18).

**P10-I11 — `build_planners()` in `dependencies.py` is the single planner factory.**
All domain planners are created in `build_planners`; no planner is constructed
elsewhere in the orchestration package.

#### New files

| File | Purpose |
|---|---|
| `apex_host/orchestration/__init__.py` | Package re-exports |
| `apex_host/orchestration/builder.py` | `build_apex_graph()` entry point |
| `apex_host/orchestration/completion.py` | Pure completion/outcome functions |
| `apex_host/orchestration/models.py` | Record builder helpers |
| `apex_host/orchestration/dependencies.py` | `OrchestrationDeps`; `build_planners` |
| `apex_host/orchestration/routing.py` | Routing functions and `PHASE_NODE` |
| `apex_host/orchestration/context_node.py` | `load_context` node |
| `apex_host/orchestration/global_plan_node.py` | `global_plan` node |
| `apex_host/orchestration/dispatch_node.py` | All agent dispatch nodes |
| `apex_host/orchestration/parsing_node.py` | `parse_observation` node |
| `apex_host/orchestration/memory_node.py` | `write_memory` node |
| `apex_host/orchestration/repair_node.py` | `repair_agent` node |
| `apex_host/orchestration/continuation_node.py` | `reflect_or_continue` node |
| `tests/apex_host/test_phase10_orchestration.py` | 120 acceptance tests |
| `tests/test_file_headers.py` | 5 F18 enforcement tests |

#### Acceptance criteria (all met)

- ✓ `README.md` count matches `pytest --collect-only -q | tail -1` (2618)
- ✓ `test_file_headers.py` passes (5/5)
- ✓ 2618 tests pass (120 new in Phase 10 + all prior)
- ✓ mypy --strict: Success (125 source files)
- ✓ ruff: 130 errors (at ceiling)
- ✓ No dry_run default changed
- ✓ No memfabric changes

---

### Phase 11 — Independent Final Verification ✓ COMPLETE

**Completion date:** 2026-07-14  
**Tests after Phase 11:** 2668 passed  
**mypy after Phase 11:** Success — 125 source files  
**Ruff after Phase 11:** 130 errors (at Phase 10 ceiling, exit code 1)

50 new tests in `tests/test_final_verification.py` across 10 groups (GRAPH,
CONFLICT, SKILL, RETRIEVAL, LLM, EXEC, ASYNC, SECRET, CONFIG, INTEG — 5 tests
each). All 21 original findings (F01–F21) and async findings (A01–A09) independently
re-verified without trusting prior phase labels.

**Final finding statuses:**
- F01–F14, F17–F21, A01–A09: FIXED (independently verified)
- F15: NOT A DEFECT (`record_turn` is called exactly once per non-done phase;
  `reflect_or_continue` only peeks — no budget double-charge)
- F16: FIXED (Phase 7 — 7 accumulation tests in `test_phase7_async.py::TestDuplicateActionsAccumulation`)
- F21: FIXED (Phase 3 — `worker.py` uses `api.merge_skill_candidate()`, no direct mutation)

**Known limitations (acknowledged, not blocking):**
- 130 pre-existing ruff errors (predominantly F401 unused imports, auto-fixable)
- 53 pre-existing PytestWarnings in `test_retrieval_phase4.py`
- `asyncio.Lock` is single-process only; multi-process deployments need a distributed lock
- `write_json_atomic` requires sequential calls per path — not safe for concurrent writes to same path

Validation outputs recorded in `docs/final_validation_report.md`.
All findings documented in `docs/reviewer_remediation_report.md`.

---

### How to update this roadmap

When a phase's fixes are committed, update the table row to include the
commit hash and mark the finding as `[FIXED]`. Do not delete rows — keep
the audit trail visible. Increment the test count in the baseline line at
the top of this section to reflect the new passing count.

---

## 22. Infrastructure Migration Roadmap

This is a separate migration track from the Reviewer Remediation Program in
§21 — it governs **packaging, environment management, and the tool-execution
runtime architecture**, not application-level correctness. Its own phase
numbering ("Infra Phase 1", "Infra Phase 2", …) is independent of the
Reviewer Remediation "Phase 1"–"Phase 11" in §21; do not conflate the two.
(Earlier revisions of this section were titled "Packaging & Environment" —
broadened here to cover Infra Phase 2, which is architecture, not packaging.)

### Infra Phase 1 — `uv` dependency and environment management ✓ COMPLETE

**Completion date:** 2026-07-14 (dependency/environment migration); corrected
and genuinely completed 2026-07-14 (Ruff remediation pass — see below).

> **Correction note:** an earlier version of this record marked Infra Phase 1
> complete while `uv run ruff check .` still reported 134 pre-existing errors.
> That was wrong — a `pyproject.toml`/`uv.lock` migration that ships with a
> failing lint command is not "complete." This entry has been corrected in
> place (not appended as a new phase, since the Ruff failures were pre-existing
> repository state exposed by this same migration's own validation step, not
> a separate follow-on concern) once `uv run ruff check .` genuinely passed.

**Scope:** make `uv` the sole, authoritative dependency and Python
environment manager for the repository, **and** ensure the resulting
`uv run ruff check .` command actually exits successfully for all first-party
code. No Docker, Docker Compose, Kali integration, GitHub Actions/CI, HTB VPN
validation, or Meow debugging was in scope for this phase, and none of it was
touched.

**Authoritative sources (binding going forward):**

- **`pyproject.toml`** is the authoritative dependency declaration.
  Runtime dependencies live in `[project].dependencies`; development
  dependencies live in `[dependency-groups].dev` (PEP 735 / uv dependency
  groups — not `[project.optional-dependencies]`).
- **`uv.lock`** is the required, committed lock file. It must stay in sync
  with `pyproject.toml` (`uv lock --check` must pass) and must be
  regenerated (`uv lock`) and committed whenever a dependency or version
  constraint changes.
- **`.python-version`** pins the interpreter to `3.11` so `uv sync` /
  `uv run` always provision Python 3.11.14 rather than whatever `python3`
  resolves to on a given machine. This matters: on a clean host, `uv`
  otherwise defaults to the newest available interpreter (3.14 was observed
  during this migration), and mypy's `python_version = "3.11"` setting then
  rejects PEP 695 syntax present in newer numpy's bundled `.pyi` stubs —
  a real, reproducible failure mode this pin exists specifically to prevent.
- **No legacy dependency files existed** (`requirements*.txt`, `setup.py`,
  `setup.cfg`, `Pipfile`, `poetry.lock`, `tox.ini` were all absent before
  this migration) — nothing to remove or reconcile.

**Standard development commands (see README.md "Development environment
(uv)" for the full contributor-facing version):**

```bash
uv sync --all-groups          # clean environment setup
uv run pytest -q              # test suite
uv run ruff check .           # lint
uv run mypy                   # type check — bare, uses [tool.mypy] files scope
uv run python -m apex_host.eval.run_htb_local --help   # CLI
uv lock                       # regenerate uv.lock after a dependency change
uv lock --check                # verify uv.lock is up to date, no changes
```

**`mypy` invocation is intentionally scoped, not `mypy .`.** The repository
has long documented `mypy --strict` (relying on `[tool.mypy] files =
["memfabric", "apex_host"]`) as its type-check target — this predates the
`uv` migration and is preserved unchanged. Literally running `mypy .` (or
`uv run mypy .`) overrides that `files` config with the CLI argument and
walks the entire repository tree, including the vendored, gitignored
`Knowledge/` reference corpus (GTFOBins, LOLBAS, PayloadsAllTheThings,
SecLists), which contains a file with an intentionally broken relative
import (`Knowledge/payload_db/GTFOBins/linter/__main__.py`) that is not part
of this project's source. This was reproduced identically against both the
pre-migration `.venv` and the post-migration `uv`-managed one — it is
pre-existing repository structure, not something introduced by this
migration. `uv run mypy` (no path argument) is therefore the correct,
scope-preserving invocation and is what CI or contributors should run.

**Dependency corrections made during migration (not scope creep — these are
gaps between declared and actual dependencies, found by diffing real
imports against `pyproject.toml`):**

| Change | Reason |
|---|---|
| Added `PyYAML>=6.0` to `[project].dependencies` | `apex_host/knowledge/compiler/payload_compiler.py` and `policy_compiler.py` both `import yaml` directly at module level — this was previously an undeclared transitive dependency that happened to be pulled in by something else. It is now a direct, correctly-declared runtime dependency. |
| Added `ruff>=0.6` to `[dependency-groups].dev` | Ruff is documented and used extensively throughout this file and the remediation roadmap (§21, R07) but was never declared as a project dependency; it was only present in the old `.venv` because someone installed it manually. |
| Migrated `[project.optional-dependencies].dev` → `[dependency-groups].dev` | Matches the `uv`-preferred PEP 735 dependency-group mechanism referenced in this section; functionally equivalent set of packages (pytest, pytest-asyncio, mypy, ruff, types-networkx, types-PyYAML). |

No existing version constraint was tightened, loosened, or upgraded to a
newer major version as part of this migration. `uv lock` resolved slightly
newer patch/minor versions than were previously installed for several
transitive dependencies (e.g. `langgraph`, `langchain-core`); this is
`uv lock` doing what any fresh resolution against the existing `>=` bounds
does, not a deliberate upgrade decision.

**Ruff remediation (correction pass — brings `uv run ruff check .` to a
genuine, unconditional pass):**

The `uv`/`pyproject.toml` migration surfaced 134 pre-existing Ruff findings
across first-party `apex_host/`, `memfabric/`, `tests/`, and `examples/`
code (`ruff` had never been declared as a project dependency before this
migration, so it had never been run through a reproducible, lockfile-pinned
environment). All 134 were fixed — none suppressed, none ignored, no rule
family disabled, no vendored-path exclusion added (see the "Repository
boundary" note below — no vendored file ever appeared in the failure list,
so no exclusion was needed or added).

| Code | Count | Nature | Resolution |
|---|---|---|---|
| `F401` (unused import) | 107 | Dead imports accumulated across test files and a handful of `apex_host` modules; none were `__all__`-re-exported or side-effect imports (verified by grep before fixing) | `ruff check . --select F401 --fix` (safe, auto-fixable) |
| `F841` (unused local variable) | 17 | Mix of genuinely dead setup code (e.g. a `verbose` variable in `apex_host/knowledge/compiler/compile_knowledge.py` that duplicated logic already handled via `args.verbose` two lines above), vestigial test scaffolding from earlier test-refactors (unused `graph`/`initial`/`disp` objects, unused mock-instrumentation variables), and `result = await x()` assignments whose return value was never asserted on (only a mock's `call_count` was checked) | Manually reviewed and fixed individually — each case traced to confirm no side-effect-bearing expression was silently dropped and no assertion was weakened; see git diff for the 17 individual edits |
| `F541` (f-string, no placeholders) | 4 | Plain string content mistakenly marked with an `f` prefix | `ruff check . --select F541 --fix` (safe, auto-fixable — removes the `f` prefix only) |
| `E741` (ambiguous variable name `l`) | 2 | Generator-expression loop variable named `l` in `methodology_compiler.py` and `payload_compiler.py` | Manually renamed `l` → `line` in both files (no name collisions in scope) |
| `F811` (redefinition of unused name) | 2 | `tests/apex_host/test_knowledge_schemas.py` imported `SourceFamily`/`SourceType` at module level but never used them there — the only use was a local re-import inside `test_compiler_package_imports_cleanly` (deliberately verifying the package's public re-export surface, already marked `# noqa: F401`) | Removed the dead, never-used module-level imports of `SourceFamily`/`SourceType` (auto-fixed as part of the `F401` pass above — same root cause, F811 disappeared once the shadowed module-level import was gone); the intentional local re-import and its `noqa` were left untouched |
| `E401` (multiple imports, one line) | 1 | `import io, contextlib` in a test | `ruff check . --select E401 --fix` (safe, auto-fixable — splits into two `import` statements) |
| `F821` (undefined name) | 1 | `tests/test_graph_atomicity.py:553` annotated a variable as `_DictKVStore`, a name that does not exist anywhere in the codebase — a real typo/bug (should be `InMemoryKVStore`, which is imported and is the actual concrete type of `api._kv` in that test). Went undetected by `mypy` because `tests/` is outside `[tool.mypy] files` scope. | Manually corrected `_DictKVStore` → `InMemoryKVStore` |

**Repository-boundary analysis — no exclusions needed or added.** Every one
of the 134 findings above was in `apex_host/`, `tests/`, or `examples/` —
first-party code. The vendored, gitignored corpus at `Knowledge/` (containing
`GTFOBins`, `LOLBAS`, `PayloadsAllTheThings`, `SecLists`, plus downloaded
`intel_db`/`methodology_db`/`policy_db` raw sources) produced **zero**
findings, because Ruff's default `respect-gitignore = true` already keeps it
out of scope — confirmed empirically by running `uv run ruff check Knowledge
--no-cache`, which reports `No Python files found under the given path(s)`.
No `[tool.ruff]` `exclude`/`extend-exclude` entries were added, because none
were needed: adding one would have been an unjustified, undocumented
exclusion of the exact kind this correction pass was told to avoid. The only
`[tool.ruff]` addition is `target-version = "py311"` (explicit, matches
`[project].requires-python`; ruff already inferred the same value implicitly,
so this changes no enforcement behavior). Default lint rule selection
(`E4`, `E7`, `E9`, `F`) is untouched — no rule family was disabled.
First-party knowledge-management code (`apex_host/knowledge/compiler/*.py`,
`apex_host/knowledge/seed_loader.py` — note: distinct from the root-level
vendored `Knowledge/` data directory) remains fully linted; several of the
fixes above (the `E741` renames, the `compile_knowledge.py` dead-variable
removal) are in that exact package.

**Validation performed (final, clean-rebuilt `.venv`, Python 3.11.14):**

| Check | Pre-migration baseline | Before this correction pass | After this correction pass |
|---|---|---|---|
| `pytest` | 2668 passed | 2668 passed | **2668 passed** (unchanged — all fixes behavior-preserving) |
| `ruff check .` | 134 errors (pre-existing; §21 baseline of "130" is stale by 4 — drift unrelated to either migration pass) | 134 errors | **0 errors — `All checks passed!`** |
| `mypy` (scoped) | Success — 125 source files | Success — 125 source files | **Success — 125 source files** (unchanged) |
| CLI `--help` | n/a | exit 0 | **exit 0** (both `apex_host.main` and `apex_host.eval.run_htb_local`) |

**Deferred to later infra phases (explicitly out of scope for this phase,
per this task's own instructions — do not start these without a new,
explicit go-ahead):**

- Docker / Dockerfile
- Docker Compose
- Kali Linux toolchain integration
- GitHub Actions / CI publishing (no `.github/workflows` exists for this
  project today — only vendored copies inside gitignored `Knowledge/`
  third-party corpora, which are not this project's CI and were left
  untouched)
- HTB VPN live-run validation
- Meow (or any other machine) exploitation/debugging

**Known pre-existing issues, still present, intentionally not touched by
this correction pass** (out of scope — not Ruff, not dependency/environment
management):

- §21's remediation-program Ruff-error-ceiling reference ("130 errors") in
  the historical, append-only Phase-11 report is stale (actual was 134 before
  this pass, 0 after). That historical record is preserved as-is per §21 R12
  (findings/records are status-updated, never rewritten) — it describes what
  was true when Phase 11 of the *Reviewer Remediation Program* completed, a
  separate track from this infrastructure migration. No new "Infra Phase 2"
  correction was opened for it; if §21 is revisited in its own remediation
  track, that reference should be updated there.
- `docs/*.md` phase-audit reports (e.g. `docs/final_validation_report.md`)
  still reference `.venv/bin/python` invocations. These are dated,
  append-only historical records of what was actually run at the time
  (§21 R12 — findings/records are never rewritten) and were deliberately
  left untouched; they are not living developer instructions.

---

### Infra Phase 2 — Tool-execution backend architecture and contracts ✓ COMPLETE

**Completion date:** 2026-07-14

**Full design rationale, current-state analysis, and phase-by-phase plan:**
[`docs/tool-execution-architecture.md`](docs/tool-execution-architecture.md).
This CLAUDE.md entry is a summary and progress record; the doc is
authoritative for architecture detail.

**Scope:** define a replaceable `ToolBackend` abstraction (dry-run / local /
remote-contract-only) that formalizes a seam that already existed implicitly
in `TaskDispatcher`, without changing default runtime behavior and without
implementing the actual Kali HTTP service. **Not in scope and NOT done:**
Dockerfiles, Docker Compose, a Kali container image, VPN container/tunnel
work, GitHub Actions/CI, or any live Meow-specific fix. Those all remain
entirely unimplemented after this phase — see
`docs/tool-execution-architecture.md` §16–§17 for what each still requires.

**Architecture decisions (see the linked doc for full detail):**

- **`ToolBackend`** (`apex_host/tools/backend.py`) — a `typing.Protocol`
  with `async def execute(tool, arguments, *, timeout_seconds=None,
  stdin=None) -> ToolExecutionResult`. `ToolExecutionResult` is a type
  alias for the existing `apex_host.types.ToolResult` — no duplicate
  result model was created.
- **`DryRunToolBackend`** — standalone, never spawns a process or opens a
  network connection (proven by monkeypatch-based tests), still enforces
  `apex_host/tools/safety.py::check_command` first.
- **`LocalToolBackend`** — thin wrapper delegating entirely to the
  existing, Phase-7-hardened `apex_host.tools.runner.run_command`; no
  subprocess logic duplicated. Still honors `ApexConfig.dry_run`
  internally as defense in depth — explicitly documented as intentional,
  not a bug (see the doc's §7 "important nuance" note).
- **`RemoteToolBackend`** — contract only. Constructing it is safe;
  `execute()` unconditionally raises `NotImplementedError`. No HTTP
  client, no FastAPI/Flask, no network I/O anywhere in this phase.
- **`ToolResult`** (`apex_host/types.py`) gained two additive fields:
  `timed_out: bool = False` and `backend: str = ""`. `ToolCommand` gained
  one additive field: `stdin: str | None = None`. All five existing
  `ToolResult(...)` construction sites in `runner.py` were updated to
  populate the two new fields; no other field's value changed.
- **`ApexConfig`** (`apex_host/config.py`) gained four additive fields:
  `tool_backend: str = "local"` (the default preserves current behavior —
  `"local"` is what `build_apex_graph()` has always used),
  `tool_service_url: str | None = None`, `tool_service_token: str = ""`
  (no secret default; redacted by `to_safe_dict()` when non-empty),
  `tool_service_timeout_seconds: float = 120.0`. No environment-variable
  reading was added anywhere — `config.py`'s own
  `test_arch_08_config_py_has_no_env_access` architecture test forbids it,
  and no other module reads these vars either. `.env.example` and CLI flag
  wiring remain explicitly deferred (per this phase's own instructions).
- **`build_apex_graph()`** (`apex_host/orchestration/builder.py`) gained
  one additive, keyword-only parameter: `tool_backend: ToolBackend | None
  = None`. When `None` (the default — every existing call site), behavior
  is byte-for-byte unchanged: `run_command_fn=run_command`, exactly as
  before this phase. When a `ToolBackend` is supplied, `TaskDispatcher`
  receives `apex_host.tools.backend.to_run_command_fn(tool_backend)`
  instead — `TaskDispatcher` itself was not modified.
- **Policy invariant unchanged and re-proven through the new seam:**
  `TaskDispatcher.dispatch()`'s policy gate (step 1) still runs before any
  backend is ever called, for both fresh tasks and `RepairEngine`-repaired
  tasks (same `dispatch()` call site). Proven by
  `test_policy_blocked_task_never_reaches_backend_adapter` (a spy-wrapped
  backend records zero calls for a policy-blocked task).

**Deliberately NOT done in this phase (see doc §17 and §19 for the full
list and rationale):**

- `config.tool_backend` is not consumed by `build_apex_graph()`'s *default*
  construction — only the explicit `tool_backend=` keyword argument is
  honored. Auto-wiring the config value into the default path is deferred
  to Phase 3, validated together with a real `RemoteToolBackend`.
- `ToolCommand.stdin` is defined but not piped into `runner.py`'s
  subprocess call; `LocalToolBackend.execute(..., stdin=...)` raises
  `NotImplementedError` rather than silently dropping it.
- `ToolResult.timed_out` / `.backend` are not yet threaded through
  `TaskDispatcher._run_command()`'s dict-building code into
  `RunReport`/EKG episodes.
- `apex_host/agents/recon_executor.py` / `execute_executor.py` (a second,
  orphaned local-execution path used only by their own tests, never by the
  live graph) were left as-is — flagged as a consolidation opportunity,
  not touched (removing them was judged out of this phase's narrow scope).
- `RemoteToolBackend`'s HTTP transport, the restricted Kali tool service
  itself, its server-side allowlist/timeout/audit/health enforcement (doc
  §11), Dockerfiles, Docker Compose, VPN container work, CI, and any
  Meow-specific live-run change — **all remain entirely unimplemented.**

**New files:**

| File | Purpose |
|---|---|
| `apex_host/tools/backend.py` | `ToolBackend` protocol, `DryRunToolBackend`, `LocalToolBackend`, `RemoteToolBackend`, `select_tool_backend()`, `to_run_command_fn()` |
| `docs/tool-execution-architecture.md` | Full architecture document (19 required sections) |
| `tests/apex_host/test_tool_backend.py` | 30 focused tests: protocol conformance, dry-run isolation, local-backend parity with `run_command`, remote-backend contract-only behavior, backend selection |

**Modified files:**

| File | Change |
|---|---|
| `apex_host/types.py` | `ToolResult.timed_out`, `ToolResult.backend`, `ToolCommand.stdin` — all additive |
| `apex_host/tools/runner.py` | Five `ToolResult(...)` sites now populate `backend`/`timed_out`; no other behavior change |
| `apex_host/config.py` | Four additive `ApexConfig` fields; `to_safe_dict()` redacts `tool_service_token` when set |
| `apex_host/orchestration/builder.py` | `build_apex_graph(..., tool_backend=None)` opt-in seam |
| `tests/apex_host/test_phase6_dispatcher.py` | 5 new tests in `TestToolBackendSeam`: policy-block-never-reaches-backend, approved-task-reaches-backend-once, default-path end-to-end smoke test, explicit-backend end-to-end smoke test, dispatcher-level backend-adapter parity |

**Validation (all against a clean-rebuilt `.venv`, Python 3.11.14):**

| Check | Result |
|---|---|
| `uv lock --check` | Pass |
| `uv sync --all-groups` | Pass |
| `uv run pytest -q` | **2704 passed** (2668 baseline + 30 new backend tests + 5 new dispatcher-seam tests + 1 net from collection ordering), 53 warnings — no regressions |
| `uv run pytest tests/apex_host/test_tool_backend.py tests/apex_host/test_phase6_dispatcher.py -q` | 161 passed (30 + 131) |
| `uv run ruff check .` | `All checks passed!` |
| `uv run mypy` | Success — 126 source files (was 125; `+1` for `apex_host/tools/backend.py`) |
| `uv run python -m apex_host.eval.run_htb_local --help` | exit 0 |
| `git diff --check` | exit 0 |

**Phase-by-phase implementation map** (full version in the linked doc §17;
**renumbered by Infra Phase 3** — see that phase's record below): Infra
Phase 3 builds the restricted Kali tool service (`apex_tool_service/`);
Phase 4 implements `RemoteToolBackend`'s transport and wires
`config.tool_backend` into the default path; Phase 5 adds the APEX
application Dockerfile; Phase 6 adds the Kali tool-service Dockerfile;
Phase 7 wires `ToolCommand.stdin`; Phase 8 adds `.env.example` + CLI
flags; Phase 9+ covers VPN validation, CI publishing, and Meow-specific
live-run work.
>
> **Correction (Infra Phase 6, 2026-07-15):** this projection originally
> said "Phase 6 adds Compose" — that did not happen. Infra Phase 6 built
> the Kali tool-service container image (`docker/kali/Dockerfile`) instead;
> Docker Compose remains unstarted (deferred again, see that phase's
> record below). Numbering beyond Phase 6 in this paragraph is historical
> projection, not a commitment — treat only the completed-phase records
> below as authoritative.

---

### Infra Phase 3 — Restricted Kali-compatible tool-execution service ✓ COMPLETE

**Completion date:** 2026-07-14

**Full design, trust boundary, API contract, and deferred work:**
[`docs/kali-tool-service.md`](docs/kali-tool-service.md). This entry is a
summary and progress record; that doc is authoritative.

> **Renumbering note:** `docs/tool-execution-architecture.md` (written in
> Infra Phase 2) originally proposed "Phase 3 = client transport, Phase 4 =
> server." This phase built the *server* first (the client needs a
> finalized contract to implement against), so Phase 3 and Phase 4 are
> swapped from that original proposal. Both documents have been updated to
> reflect this — see `docs/tool-execution-architecture.md` §10 and §17.

**Scope:** build `apex_tool_service/`, a small, independently deployable
HTTP service — the future Kali-container-side execution boundary — that
accepts structured tool-execution requests, authenticates them, validates
them mechanically, executes only an explicit allowlist of binaries with
`shell=False` and no command-string concatenation, and returns a
structured result. **Not in scope and NOT done:** `RemoteToolBackend`'s
HTTP client in `apex_host` (still `NotImplementedError` — Phase 4), any
Kali or APEX Dockerfile, Docker Compose, `.env.example`, VPN networking,
CI publishing, or any Meow-specific change. All remain entirely
unimplemented after this phase.

**Package location:** `apex_tool_service/` (repo root, parallel to
`apex_host/` and `memfabric/`; registered in `[tool.hatch.build.targets.wheel]`
and `[tool.mypy] files` in `pyproject.toml`). Deliberately does not import
`apex_host` or `memfabric` anywhere — proven by
`tests/apex_tool_service/test_separation_from_apex_policy.py`. Run with
`uv run python -m apex_tool_service` (primary) or
`uv run uvicorn apex_tool_service.app:app` (alternative).

**Authentication decision:** `POST /v1/execute` requires
`Authorization: Bearer <token>`, compared with `hmac.compare_digest`
(timing-safe). No default token exists anywhere in source. Missing
server-side token configuration (`ServiceSettings.token is None`) makes
`/v1/execute` fail closed with `503` for **every** request regardless of
client credentials — distinct from `401` (bad/missing client credential).
`GET /health` is intentionally unauthenticated (documented rationale:
exposes only a fixed service name, status, and `{tool: bool}` availability
map — no secrets, no paths, no env vars). The token is never logged
(success or failure path) and never appears in any response body.

**Allowlist decision:** `apex_tool_service/allowlist.py::ALLOWED_TOOLS` =
`nmap`, `curl`, `nc`, `netcat`, `ping`, `telnet` — each mapped to an exact
binary name, never shell-resolved. `nmap`/`curl`/`nc`/`netcat` have direct
APEX usage evidence (`apex_host/tools/registry.py`); `ping`/`telnet` were
included per this phase's own task brief despite thin/no direct APEX
evidence (documented explicitly in `docs/kali-tool-service.md` §6).
Deliberately excluded despite evidence: `ffuf`/`gobuster` (wordlist
fuzzers, already policy-gated opt-in on the APEX side), `searchsploit`
(different risk shape — local DB search, not network execution),
`python3` (explicitly forbidden by this phase's task brief as a
general-purpose interpreter, overriding local usage evidence). A second,
independent `NEVER_ALLOWED` constant (shells, other interpreters, `env`,
`sudo`/`su`, container control planes, destructive commands) is checked in
addition to `ALLOWED_TOOLS` membership, so a careless future edit to the
allowlist cannot silently reintroduce a shell.

**Validation decision:** request structure via Pydantic v2
(`model_config = ConfigDict(extra="forbid")` — a raw `"command"` field is
rejected by schema alone). Mechanical checks in `apex_tool_service/validation.py`:
argument count/length/total-byte-size limits, shell-metacharacter rejection
(`;`, `&&`, `\|\|`, `\|`, `>>`, `>`, `<`, `` $( ``, `` ` ``, duplicated —
not imported — from `apex_host/tools/safety.py`'s list), control-character
rejection (newline, carriage return, null byte), stdin byte-size limit,
and timeout-bounds validation (an out-of-bounds explicit `timeout_seconds`
is rejected, never silently clamped). All limits are `ServiceSettings`
fields, not scattered magic numbers.

**Execution:** `apex_tool_service/executor.py` — the sole
`asyncio.create_subprocess_exec` call site in the package (enforced by a
static scan test), always `shell=False`, always argv-list. SIGTERM → 5s
grace → SIGKILL on timeout (mirrors `apex_host/tools/runner.py`'s Phase 7
hardening, reimplemented independently — no import). Output is
byte-truncated before UTF-8 decoding (`errors="replace"`) so truncation
never raises. Ordinary failures (non-zero exit, timeout, missing binary,
launch `OSError`) are represented in the response, never raised as
exceptions to the HTTP layer.

**New files:**

| File | Purpose |
|---|---|
| `apex_tool_service/__init__.py` | Package marker + module docstring (trust-boundary summary) |
| `apex_tool_service/__main__.py` | `python -m apex_tool_service` CLI entrypoint (uvicorn runner) |
| `apex_tool_service/app.py` | FastAPI app factory; `/health`, `/v1/execute`; auth-before-body-parsing ordering |
| `apex_tool_service/settings.py` | `ServiceSettings` — sole env-var-reading module in the package |
| `apex_tool_service/allowlist.py` | `ALLOWED_TOOLS`, `NEVER_ALLOWED`, `tool_availability()` |
| `apex_tool_service/validation.py` | `RequestValidationError` + all mechanical checks |
| `apex_tool_service/auth.py` | Bearer-token check, timing-safe, fail-closed |
| `apex_tool_service/executor.py` | The sole subprocess call site |
| `apex_tool_service/audit.py` | Structured audit logging, bounded argument previews |
| `apex_tool_service/models.py` | `ExecuteRequest`/`ExecuteResponse`/`HealthResponse` (Pydantic v2) |
| `docs/kali-tool-service.md` | Full architecture document (18 required sections) |
| `tests/apex_tool_service/*.py` (8 files) | 124 focused tests — health, auth, validation, execution, security invariants, settings, audit, policy separation |

**Modified files:** `pyproject.toml` (added `fastapi`, `uvicorn` runtime
deps; `httpx` dev dep for ASGI testing; registered `apex_tool_service` in
hatch packages and mypy files), `uv.lock` (regenerated — 5 new packages:
fastapi, starlette, uvicorn, click, annotated-doc — no `fastapi[all]`, no
Kali toolset installed as a Python dependency),
`docs/tool-execution-architecture.md` (§10 marked finalized-elsewhere, §17
phase table renumbered).

**Validation (all against a clean-rebuilt `.venv`, Python 3.11.14):**

| Check | Result |
|---|---|
| `uv lock --check` | Pass |
| `uv sync --all-groups` | Pass — 5 new packages, no Kali tools installed |
| `uv run pytest tests/apex_tool_service -q` | **124 passed** |
| `uv run pytest tests/apex_tool_service/test_security_invariants.py -q` | **13 passed** |
| `uv run pytest -q` (full) | **2828 passed** (2704 baseline + 124 new), 53 warnings — no regressions |
| `uv run ruff check .` | `All checks passed!` |
| `uv run mypy` | Success — 136 source files (was 126; `+10` for `apex_tool_service`) |
| `uv run python -m apex_tool_service --help` | exit 0 |
| `uv run python -m apex_host.eval.run_htb_local --help` | exit 0 |
| Real HTTP smoke test (`python -m apex_tool_service` as a subprocess, real TCP socket, `curl` against `127.0.0.1:18080`) | `/health` 200 with accurate tool map; unauthenticated `/v1/execute` 401; authenticated `/v1/execute` 200 with real `curl --version` output |
| `git diff --check` | exit 0 |

**Deferred at the time this Phase 3 record was written; RemoteToolBackend/
config-wiring/report-threading items were completed in Infra Phase 4 (see
that record below — this paragraph is left as the historical Phase 3
snapshot per this document's append-only convention for phase records):**
`RemoteToolBackend` HTTP client transport in `apex_host`; wiring
`config.tool_backend` into `build_apex_graph()`'s default construction;
threading `timed_out`/`backend` into `RunReport`; Kali Dockerfile; APEX
Dockerfile; Docker Compose; `.env.example`; VPN networking; CI publishing;
any Meow-specific change. **Still entirely unstarted after Infra Phase 4:**
Kali Dockerfile; APEX Dockerfile; Docker Compose; `.env.example`; VPN
networking; CI publishing; any Meow-specific change.

---

### Infra Phase 4 — `RemoteToolBackend` HTTP transport and runtime wiring ✓ COMPLETE

**Completion date:** 2026-07-14

**Full client implementation, error mapping, configuration, lifecycle, and
routing detail:** [`docs/remote-tool-backend.md`](docs/remote-tool-backend.md)
(new document, per this phase's own instruction). This entry is a summary
and progress record.

**Scope:** implement the real HTTP transport for `RemoteToolBackend`
(previously a Phase 2 contract-only stub) and wire centralized backend
selection into the actual engagement runtime, so normal construction paths
(`apex_host.runtime.ApexRuntime.run()`, `apex_host.eval.run_htb_local`)
select the correct backend from `ApexConfig` automatically, with no manual
`tool_backend=` injection required for ordinary use. **Not in scope and NOT
done:** Dockerfiles, Docker Compose, VPN containers, GitHub Actions,
`.env.example`, or any Meow-specific exploitation change — none of these
were started.

**Key decisions:**

- **`RemoteToolBackend`** moved to its own module,
  `apex_host/tools/remote_backend.py` (re-exported from
  `apex_host/tools/backend.py` for backward compatibility with existing
  imports) — justified by size (a real `httpx` client with 9+ distinct
  failure-mode mappings is substantially larger than the other two
  backends). Constructed from `ApexConfig` (never bare kwargs); the bearer
  token resolves as `config.tool_service_token or
  os.environ.get("APEX_TOOL_SERVICE_TOKEN") or ""`, mirroring
  `apex_host/llm/router.py::OpenAIModelRouter`'s existing
  `OPENAI_API_KEY`/`OPENAI_BASE_URL` precedent exactly.
- **`select_runtime_backend(config)`** (`apex_host/tools/backend.py`) —
  the new, centralized, safety-aware selector. Binding invariant:
  `config.dry_run=True` always yields `DryRunToolBackend`, regardless of
  `config.tool_backend`. Enforced twice — once at selection time (this
  function), once again inside `RemoteToolBackend.execute()` itself
  (defense in depth, in case the class is ever constructed and injected
  directly, bypassing this selector).
- **`build_apex_graph()`'s default** (`tool_backend=None`, no explicit
  injection) now calls `select_runtime_backend(config)` instead of the
  literal `apex_host.tools.runner.run_command` function. For the unchanged
  default configuration (`dry_run=True`, or `dry_run=False` with
  `tool_backend="local"`) the resulting behavior is unchanged — both route
  to the same underlying `run_command` call, just through
  `LocalToolBackend`'s thin wrapper instead of directly.
- **`apex_host.runtime.ApexRuntime.run()`** constructs the backend
  explicitly (rather than relying on `build_apex_graph`'s internal
  default) specifically so it can close it in a `finally` block after the
  graph completes — the fully lifecycle-managed production entry point.
  `build_apex_graph()`'s own internal default fallback has a documented
  lifecycle limitation for direct callers who don't go through
  `ApexRuntime` (see its docstring and `docs/remote-tool-backend.md` §2.2).
- **`select_tool_backend()`** now normalizes `tool_backend` values
  (case/whitespace) at the point of interpretation, without mutating
  `config.tool_backend` itself.
- **CLI:** `--tool-backend`, `--tool-service-url`, `--tool-service-timeout`
  added to both `apex_host/main.py` and `apex_host/eval/run_htb_local.py`,
  wired through `ApexConfig.from_cli_args()`. **Deliberately no
  `--tool-service-token` flag** — CLI arguments are visible in shell
  history and `ps`; the token must come from the `APEX_TOOL_SERVICE_TOKEN`
  environment variable.
- **Report/EKG threading:** `TaskDispatcher._run_command()`'s result dict
  now includes `timed_out`/`backend` (already present on `ToolResult`
  since Phase 2, never consumed until now). A new accumulated
  `ApexGraphState.execution_backend_log` field (populated in
  `orchestration/memory_node.py::write_memory`, excluding Telnet/Browser
  results which carry no `"backend"` key) feeds two new, additive
  `RunReport` fields: `backend_usage: dict[str, int]` and
  `timed_out_count: int`, surfaced in both `format_text()` and
  `to_json_dict()`.
- **Routing preserved exactly:** `TelnetExecutor` and `BrowserExecutor`
  remain wired into `TaskDispatcher` through their own dedicated
  constructor parameters, completely independent of `run_command_fn` /
  `tool_backend`. Setting `tool_backend="remote"` has zero effect on
  Telnet or Browser task routing — proven by
  `tests/apex_host/test_runtime_backend_wiring.py::test_telnet_and_browser_bypass_even_with_remote_backend_configured`.
  No Telnet login behavior was reimplemented through the generic backend;
  no Meow-specific change was made.

**New files:**

| File | Purpose |
|---|---|
| `apex_host/tools/remote_backend.py` | Real `RemoteToolBackend` HTTP client implementation |
| `docs/remote-tool-backend.md` | Full Infra Phase 4 client documentation |
| `tests/apex_host/test_remote_backend.py` | 57 tests: request construction, response mapping, HTTP/transport failures, configuration, lifecycle, 3 contract-integration tests against the real `apex_tool_service` app |
| `tests/apex_host/test_runtime_backend_wiring.py` | 14 tests: default/explicit backend selection, policy-blocked-zero-requests, approved-exactly-one-request, Telnet/Browser routing preservation, CLI flag wiring |

**Modified files:** `apex_host/tools/backend.py` (re-exports
`RemoteToolBackend`, adds `_normalize_backend_name`/`select_runtime_backend`,
removes the old stub class), `apex_host/orchestration/builder.py` (default
`tool_backend=None` path), `apex_host/runtime.py` (explicit backend
construction + `finally`-block `aclose()`), `apex_host/config.py` (CLI
wiring in `from_cli_args`; refined field docstrings), `apex_host/main.py`
+ `apex_host/eval/run_htb_local.py` (3 new CLI flags each),
`apex_host/execution/dispatcher.py` (`timed_out`/`backend` in the result
dict), `apex_host/graph_state.py` (new `execution_backend_log` field),
`apex_host/orchestration/memory_node.py` (populates the new field),
`apex_host/eval/report.py` (`backend_usage`/`timed_out_count` fields +
text/JSON surfacing), `apex_host/eval/run_synthetic_machine.py` (new state
field in its literal), `pyproject.toml` (`httpx` moved from dev to
runtime dependency — production code in `remote_backend.py` now imports
it directly), `tests/apex_host/test_tool_backend.py` (stale stub-era
`RemoteToolBackend` tests updated for the real constructor signature),
`tests/apex_host/test_phase6_dispatcher.py` (`_FakeToolResult` gained
`timed_out`/`backend` fields), `tests/apex_host/test_policy_gate.py` (one
test's `dry_run` flipped — see rationale in that test's updated docstring),
`tests/apex_host/test_report.py` (8 new tests),
`docs/tool-execution-architecture.md` + `docs/kali-tool-service.md`
(cross-references updated to point at the now-real implementation).

**Validation (all against a clean-rebuilt `.venv`, Python 3.11.14):**

| Check | Result |
|---|---|
| `uv lock --check` | Pass |
| `uv sync --all-groups` | Pass |
| `uv run pytest tests/apex_host/test_remote_backend.py -q` | **57 passed** |
| `uv run pytest tests/apex_host/test_runtime_backend_wiring.py -q` | **14 passed** |
| `uv run pytest tests/apex_host/test_report.py -q` | **77 passed** (8 new) |
| `uv run pytest -q` (full) | **2911 passed**, 53 warnings — no regressions |
| `uv run ruff check .` | `All checks passed!` |
| `uv run mypy` | Success — 137 source files |
| `uv run python -m apex_host.eval.run_htb_local --help` | exit 0 |
| `uv run python -m apex_tool_service --help` | exit 0 |
| `git diff --check` | exit 0 |

**Deferred at the time this Phase 4 record was written; the APEX
Dockerfile was completed in Infra Phase 5 (see that record below — left
here unrewritten per the append-only convention):** Kali Dockerfile; APEX
Dockerfile; Docker Compose; VPN networking; CI publishing; `.env.example`;
any Meow-specific diagnosis, deterministic Meow test, or authorized live
Meow validation. **Still entirely unstarted after Infra Phase 5:** Kali
Dockerfile; Docker Compose; VPN networking; CI publishing; `.env.example`;
any Meow-specific work.

---

### Infra Phase 5 — APEX application container image ✓ COMPLETE

**Completion date:** 2026-07-14

**Full design, security properties, and current limitations:**
[`docs/apex-container.md`](docs/apex-container.md) (new document, per this
phase's own instruction). This entry is a summary and progress record.

**Scope:** build a reproducible, non-root, `uv.lock`-locked container image
for the APEX *application* (`apex_host` + `memfabric`) that can run the
established CLIs without a local Python/uv setup. **Not in scope and NOT
done:** the Kali tool-service image, Docker Compose, VPN containers,
`.env.example`, GitHub Actions, container-orchestration/entrypoint
scripting beyond the plain `CMD`, or any Meow-specific change — none of
these were started.

**Files:** [`docker/apex/Dockerfile`](docker/apex/Dockerfile) (new,
multi-stage), [`.dockerignore`](.dockerignore) (new, repository root),
`tests/docker/test_apex_dockerfile.py` (new, 35 static tests — no Docker
daemon required to run them).

**Base image:** `python:3.11.14-slim-bookworm`, pinned by digest
(`sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d`
— the manifest-list digest, verified via `docker buildx imagetools inspect`
so it resolves correctly per-platform). `3.11.14` matches the exact patch
version every prior Infra Phase has developed/tested against
(`.python-version` pins `3.11`). Debian slim over Alpine specifically to
avoid musl-libc/scientific-Python-wheel incompatibility risk
(`numpy`/`faiss-cpu`). The `uv` binary itself comes from
`ghcr.io/astral-sh/uv:0.11.28`, also digest-pinned
(`sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa`).

**Multi-stage build:** `uv` (binary source) → `builder` (`uv sync --frozen
--no-dev --no-install-project` for deps, then `--no-editable` after
copying first-party source, for optimal Docker layer caching) →
`runtime` (copies only the finished `/app/.venv`; no build toolchain, no
`uv`, no `pyproject.toml`/`uv.lock`, no raw source tree — the
`--no-editable` install means none of that is needed at runtime).

**Non-root user:** `apex`, UID/GID 1000 (explicit, not `--system` — avoids
a spurious `useradd` warning), no password, no login shell, no `sudo`.
Verified: `docker run --rm apex:phase5 id` → `uid=1000(apex) gid=1000(apex)`.

**Knowledge strategy (investigated, not assumed):** `Knowledge/` (the real,
git-tracked, capital-K directory — see the correction note added to §18
above) is 4.3 GB total; `Knowledge/*/compiled/` is ~49 MB. Only the four
`compiled/` subdirectories are copied into the image (source path
`Knowledge/...`, destination `/app/knowledge/...` — deliberately lowercase
to match every documented `--knowledge-root` CLI example). Raw corpora
(SecLists 1.9 GB, NVD CVE raw feed 2.3 GB, GTFOBins/LOLBAS/
PayloadsAllTheThings, raw PDFs) never reach the Docker build context at
all — excluded in `.dockerignore`.

**`apex_tool_service` is present in the image but never started.** It is
a package of the same Hatchling distribution as `apex_host`/`memfabric`
(`[tool.hatch.build.targets.wheel] packages = [...]`), so `uv sync` cannot
build the project wheel without it — but no `CMD`/`ENTRYPOINT` in
`docker/apex/Dockerfile` references `apex_tool_service`, statically
enforced by a dedicated test.

**Browser/Playwright:** the Python `playwright` package is installed
(runtime dependency); no browser binary (`playwright install chromium`)
was installed — `BrowserExecutor` only imports Playwright when
`dry_run=False`, and installing a real browser bundle was judged a
separate future decision (documented, not made, in
`docs/apex-container.md` §12).

**No HEALTHCHECK added** — APEX is a one-shot CLI, not a long-running
server; a check that only confirmed "Python starts" would be theater, not
real readiness (documented decision, `docs/apex-container.md` §"Health
check decision").

**Validation (all against a clean-rebuilt `.venv`, Python 3.11.14, and a
freshly built `apex:phase5` image):**

| Check | Result |
|---|---|
| `uv lock --check` | Pass |
| `uv sync --all-groups` | Pass |
| `uv run pytest -q` (full) | **2946 passed** (2911 baseline + 35 new static Dockerfile tests), no regressions |
| `uv run ruff check .` | `All checks passed!` |
| `uv run mypy` | Success — 137 source files |
| `uv run python -m apex_host.eval.run_htb_local --help` | exit 0 |
| `docker build -f docker/apex/Dockerfile -t apex:phase5 .` | Success — 688 MB, ~132 s cold / ~10 s cached |
| `docker run --rm apex:phase5 python -m apex_host.main --help` | exit 0 |
| `docker run --rm apex:phase5 python -m apex_host.eval.run_htb_local --help` | exit 0 |
| `docker run --rm apex:phase5 python -c "import apex_host, memfabric"` | `imports-ok` |
| `docker run --rm apex:phase5 id` | `uid=1000(apex) gid=1000(apex)` — non-root |
| Writable `/app/run_reports` | Verified as non-root user |
| `pytest`/`ruff`/`mypy` inside the image | All `None` (absent) |
| `nmap`/`telnet`/`nc`/`hydra`/`gobuster`/`ffuf` inside the image | All absent from `PATH` |
| `docker run --rm apex:phase5 python -m apex_host.knowledge.compiler.verify_compiled --knowledge-root /app/knowledge` | All 9 required outputs verified OK (63,783 records) |
| `docker history --no-trunc` secret scan | Clean |
| `git diff --check` | exit 0 |

**Deferred to Infra Phase 6+ (as of Infra Phase 5):** Kali tool-service
Docker image; Docker Compose; `.env.example`; container entrypoint/
preflight orchestration; VPN networking; CI image publishing; Meow
diagnosis; deterministic Meow tests; authorized live Meow validation.
**None of these were started in Infra Phase 5.**

### Infra Phase 6 — Kali Linux tool-service container image ✓ COMPLETE

**Date:** 2026-07-15
**Files:** `docker/kali/Dockerfile`, `docker/kali/entrypoint.py`,
`tests/docker/test_apex_kali_dockerfile.py` (53 static tests),
`docs/kali-container.md` (full design/evidence record)

Built and validated, against a real Docker daemon, the running counterpart
to `apex_tool_service` (Infra Phase 3): a Kali Linux container that starts
only the restricted HTTP tool-execution service, with a small,
evidence-justified set of pre-installed binaries.

**Base image:** official `kalilinux/kali-rolling`, pinned by digest
(`sha256:8a1ea7281085ffef4963e82766c70869d7db910df88dcbb1f03d2899420b9577`),
used for both the multi-stage `builder` and `runtime` stages. No
community/unofficial Kali image; no `:latest` tag. APT package versions are
explicitly NOT pinned (documented limitation — Kali rolling has no dated
snapshot repository).

**Installed tools** (map 1:1 to `apex_tool_service/allowlist.py::ALLOWED_TOOLS`,
verified live via a running container's own `GET /health`): `nmap`, `curl`,
`iputils-ping` (→ `ping`), `netcat-openbsd` (→ **both** `nc` and `netcat`,
verified via `update-alternatives` symlinks — one package satisfies both
allowlist entries), `telnet` (client only — `telnetd` deliberately not
installed), `ca-certificates`. Explicitly excluded, with evidence recorded
in `docs/kali-container.md` §3: `kali-linux-{default,large,everything}`,
`metasploit-framework`, `sqlmap`, `hydra`, `medusa`, `patator`, `gobuster`,
`ffuf`, `nikto`, `whatweb`, `masscan`, `john`, `hashcat`, `telnetd`,
`openssh-server`, any Docker client, `sudo`, `iproute2`.

**Python provisioning:** a **uv-managed** (`python-build-standalone`)
CPython 3.11.14 — deliberately not Kali's own rolling `python3` package,
because `apex_tool_service` is unavoidably bundled with `apex_host`/
`memfabric` in one Hatchling distribution (see "Packaging limitation"
below), so `uv sync` installs the full heavy dependency graph
(numpy/faiss-cpu/playwright/langgraph); Kali's bleeding-edge `python3`
risked missing prebuilt wheels for those packages, which would have forced
a from-source build requiring a full compiler toolchain. The managed
interpreter (`/opt/uv-python`) and the prepared venv (`/app/.venv`) are
copied byte-for-byte into the runtime stage at matching absolute paths.
`uv` itself is not present in the runtime image.

**Non-root execution:** dedicated `apextool` user, UID/GID 1000, no login
shell (`nologin`), no `sudo`, no password. Verified live:
`docker run --rm apex-kali:phase6 id` → `uid=1000(apextool)
gid=1000(apextool)`.

**Linux capability finding (empirical, load-bearing for future Meow work):**
`ping` and `nmap -sT` work unprivileged under Docker's default capability
set with **zero** capability grant (no `--cap-add`, no `setcap` anywhere in
this Dockerfile — capability decisions are deliberately deferred to a
future Compose phase). `nmap`'s **default/SYN-scan mode does NOT work
unprivileged** — verified live: a bare-flags nmap request (the exact
request shape used in every prior phase's documented API examples) fails
with `returncode=1`, `stderr: "Couldn't open a raw socket... QUITTING!"`
— nmap 7.99 does not auto-fallback to a connect scan. Any future caller of
this container (a `ReconPlanner`-driven task, a manual API call) **must
pass `-sT` explicitly**, or a future Compose phase must grant
`--cap-add=NET_RAW --cap-add=NET_ADMIN` (untested, deferred). Full
investigation: `docs/kali-container.md` §5/§14.

**Port/health/auth:** `EXPOSE 8080`; `APEX_TOOL_SERVICE_HOST=0.0.0.0`
(overriding the library's own `127.0.0.1`-only default, since a container's
purpose is external reachability); `HEALTHCHECK` targets the unauthenticated
`GET /health` via `curl`, no tool invoked, no token required. No
`APEX_TOOL_SERVICE_TOKEN` is ever set in the image (verified: unset →
`/v1/execute` fails closed with 503; execution requires an operator-supplied
`-e APEX_TOOL_SERVICE_TOKEN=...` at `docker run` time).

**Observability addition (`docker/kali/entrypoint.py`):** discovered that
`apex_tool_service`'s own `INFO`-level audit lines (`execution_accepted`/
`execution_complete`) were silently dropped under Python's default logging
configuration when run as a container's sole process — only uvicorn's own
access-log lines and `WARNING`-level events reached `docker logs`. Added a
narrowly-scoped entrypoint script (explicitly an allowed `docker/kali/`
support-file type) that calls `logging.basicConfig(level=logging.INFO)`
before delegating to the unmodified `apex_tool_service.__main__.main()` —
a pure observability change; no allowlist/validation/auth/execution logic
in `apex_tool_service` itself was touched. Verified live, before and after.

**Packaging limitation (documented, not fixed — per task brief
"consider-but-do-not-perform"):** because `apex_tool_service` shares one
Hatchling distribution with `apex_host`/`memfabric`, the copied `/app/.venv`
layer is 313 MB (the majority of the image's 813 MB total), almost
entirely unused-at-runtime scientific/LLM dependencies. This image never
starts, imports, or exposes anything from `apex_host`/`memfabric` — the
weight is a build-size/attack-surface cost, not a functional or security
leak. A future package split was considered and explicitly not performed.

**Real end-to-end validation performed (all 9 parts of this phase's
runtime-validation checklist, recorded with full command transcripts in
`docs/kali-container.md` §13):** no-token fail-closed startup; test-token
authenticated execution; safe tool executions including the nmap privilege
demonstration; unknown/dangerous-tool and shell-metacharacter rejection;
non-root `id` check; installed/excluded-tool inspection; dev-tool absence;
filesystem secret/data absence; and — the phase's completion gate — a
**real** `apex_host.tools.remote_backend.RemoteToolBackend` client
constructed with `dry_run=False` executing `curl --version` against the
**real running Dockerized container**, returning
`ToolResult(backend="kali-service", returncode=0, error=None, ...)`,
proving the full chain real client → real container → real binary →
`ToolResult`. All temporary containers were stopped and removed after
validation.

**Minor pre-existing discrepancy surfaced (not fixed, out of this phase's
scope):** `docs/kali-tool-service.md` §5 states `RemoteToolBackend` should
normalize the server's `backend` field to `"remote"`; the real Infra Phase 4
implementation (`apex_host/tools/remote_backend.py::_map_response`) instead
passes the server's own value through verbatim, so a successful response's
`ToolResult.backend` is `"kali-service"`, not `"remote"`. Recorded for
visibility; `apex_host/tools/remote_backend.py` is outside this phase's
authorized file list (`docker/kali/` only).

**Deferred to Infra Phase 7+ (as of Infra Phase 6):** Docker Compose wiring
this image and the Infra Phase 5 APEX application image together; VPN
container/networking; `.env.example`; Linux capability grants for
default/SYN-scan nmap support; CI image publishing; Meow-specific
diagnosis/tests/live validation. **None of these were started in this
phase.**

### Infra Phase 7 — Docker Compose integration (APEX ↔ Kali) ✓ COMPLETE

**Date:** 2026-07-15
**Files:** `compose.yaml`, `apex_host/eval/compose_smoke.py`,
`tests/docker/test_compose.py` (33 static tests),
`docs/docker-compose.md` (full design/evidence record)

Wired the Infra Phase 5 APEX application image and the Infra Phase 6 Kali
tool-service image into a runnable two-service Docker Compose environment,
validated against a real `docker compose` daemon (v2.34.0-desktop.1),
including a real `RemoteToolBackend` call from the `apex` container to the
`kali` container over Compose's internal network. Neither
`docker/apex/Dockerfile` nor `docker/kali/Dockerfile` was modified.

**Topology:** `compose.yaml` at the repo root, modern Compose Specification
(no top-level `version:` key), two services (`apex`, `kali`) joined to one
dedicated network (`apex-internal`). `kali` has no `ports:` mapping — only
`expose: ["8080"]` — so it is never published to the host; verified live
via `docker compose port kali 8080` (returns `:0`, unbound) and a direct
`curl http://127.0.0.1:8080/health` from the host (connection refused,
curl exit code 7). `apex` reaches `kali` at `http://kali:8080` via
Compose's built-in service-name DNS — verified live
(`socket.gethostbyname("kali")` → the container's real `apex-internal`
address). `apex.depends_on.kali.condition: service_healthy` relies on
`kali`'s own image-baked `HEALTHCHECK` (Infra Phase 6, not duplicated in
`compose.yaml`) — verified live: `apex`'s command does not start until
`kali`'s health check has already passed.

**Token handling:** both services require `APEX_TOOL_SERVICE_TOKEN` via
Compose's fail-fast `${APEX_TOOL_SERVICE_TOKEN:?...}` interpolation — no
reusable default token is baked in anywhere. Verified live: `docker
compose config` with the variable unset fails immediately (exit code 1,
clear error message); with it set, both services receive the identical
interpolated value. No `.env.example` was created (explicitly deferred,
per this phase's own task brief).

**Safe default behavior:** `apex`'s default Compose `command:` is
`apex_host.eval.compose_smoke` (new module, `apex_host/eval/`) with no
flags — which defaults to `--dry-run`, exactly like every other APEX
entry point (CLAUDE.md §13.5 — never violated). `docker compose up
--abort-on-container-exit` therefore starts `kali`, waits for it to become
healthy, runs a bounded connectivity check that never contacts `kali` for
real (`backend_used="dry-run"`), and exits `0` — verified live end to end,
including a log scan confirming no secret ever appears in either
container's output. `--abort-on-container-exit` was chosen (and is used
consistently throughout `docs/docker-compose.md`) because `apex`'s command
finishes in under a second while `kali` is a long-running server with no
natural exit.

**Real remote execution (completion criterion):** `docker compose run
--rm apex python -m apex_host.eval.compose_smoke --no-dry-run` performs a
real `RemoteToolBackend` → `kali` → `curl --version` round trip through
Compose's internal network. Verified live:
`ToolResult(backend="kali-service", returncode=0, dry_run=False,
elapsed_seconds=0.128)`.

**Dry-run isolation (completion criterion):** with `kali` running and a
deliberately invalid/unreachable `APEX_TOOL_SERVICE_URL` substituted,
`--dry-run` still completes in `elapsed_seconds=0.000` — proving
`RemoteToolBackend`'s own internal dry-run short-circuit fires before any
socket is opened, even inside the real container network with a real
(healthy) `kali` service available.

**Report persistence:** `./run_reports:/app/run_reports` bind mount
(plain bind, not a named volume, so an operator can inspect JSON output
directly from the host). macOS Docker Desktop bind-mount / non-root UID
behavior was evaluated empirically (not assumed): a file written by the
container's UID 1000 `apex` user was immediately readable on the host,
owned by the invoking host user, with no permission errors — verified via
a real `compose_smoke.json` artifact written, inspected, and then removed
(pre-existing, legitimate reports under `run_reports/` were left
untouched). `kali` has no `volumes:` entry at all — it cannot read or
write any APEX report.

**Compiled knowledge:** available exactly once — baked into the `apex`
image (unchanged from Infra Phase 5); `compose.yaml` does not additionally
mount `./Knowledge`/`./knowledge`, avoiding a duplicate, differently-cased
copy.

**Security properties verified live via `docker inspect` on the running
containers** (not just the static Compose file): `Privileged=false`,
`CapAdd=[]` (in particular, **no `NET_ADMIN`, no `NET_RAW`** — this
phase's task brief explicitly forbade adding `NET_RAW` merely to enable
default/SYN-scan Nmap; the Infra Phase 6 finding that only `nmap -sT` and
`ping` work unprivileged therefore still holds unchanged inside this
Compose environment), `NetworkMode=apex-internal` (not `host`), no
`docker.sock` reference anywhere, `kali`'s `Mounts` is `[]`, both
containers run as their pre-existing non-root users
(`uid=1000(apex)`/`uid=1000(apextool)`), and a grep of both images'
`docker history --no-trunc` output plus every container log line produced
during validation for the disposable test token used this phase
(`phase7-test-token`) found zero matches.

**Real end-to-end validation performed (all items from this phase's
runtime-validation checklist, recorded with full command transcripts in
`docs/docker-compose.md`):** missing-token failure; rendered
`docker compose config`; `docker compose build --no-cache` (one transient
PyPI network timeout on the first attempt, resolved by a plain retry);
default safe startup with `--abort-on-container-exit`; `docker compose ps`
health/state; internal DNS resolution; real remote execution; dry-run
isolation with an invalid URL; report persistence with the macOS
UID/bind-mount finding; no-host-port-mapping proof (two independent
methods); non-root identity for both services; full security inspection;
and `docker compose down --remove-orphans` cleanup with test-artifact
removal. All temporary containers and the `apex-internal` network were
removed after validation.

**Deferred to Infra Phase 8+ (as of Infra Phase 7):** `.env.example` for
either `apex_host` or `apex_tool_service`; HTB VPN container/tunnel
routing (nothing in `apex-internal` can reach an HTB target); Linux
capability grants (`NET_RAW`/`NET_ADMIN`) for unprivileged default/SYN-scan
nmap support; wiring a full multi-turn engagement
(`apex_host.eval.run_htb_local`) into Compose; GitHub Actions/CI image
publishing; Meow-specific diagnosis, deterministic Meow tests, or
authorized live Meow validation. **None of these were started in this
phase.**

### Infra Phase 8 — Environment configuration workflow ✓ COMPLETE

**Date:** 2026-07-15
**Files:** `.env.example`, `apex_host/config_env.py`,
`apex_host/eval/check_config.py`, `compose.yaml` (updated), `.gitignore` /
`.dockerignore` (updated), `apex_host/main.py` /
`apex_host/eval/run_htb_local.py` (updated CLI defaults + merge wiring),
`docs/environment-configuration.md` (152 new focused tests across five
files — see below)

Built the `.env.example` workflow, centralized `APEX_*` environment-variable
loading in a single new module, and documented every supported
configuration value. `apex_host/config.py` itself still never reads the
environment — the pre-existing architecture invariant
(`test_arch_08_config_py_has_no_env_access`) was preserved unchanged, per
this phase's own instruction to "revise the design with the least invasive
approach" rather than relax that test.

**Centralized loader:** `apex_host/config_env.py` — the sole place
(outside two narrow, documented, pre-existing exceptions:
`RemoteToolBackend.__init__`'s `APEX_TOOL_SERVICE_TOKEN` fallback and
`OpenAIModelRouter`'s `OPENAI_API_KEY`/`OPENAI_BASE_URL` reads, both
unchanged) `apex_host` reads `APEX_*` environment variables. Strict
boolean/int/float parsing (never Python truthy-string heuristics), backend/
log-level/URL validation, and a generic `merge_env_into_args()` that fills
`None`-valued CLI attributes from a validated environment value — never
overwriting an explicit CLI flag. Every function accepts an injected
`Mapping[str, str]`, defaulting to `os.environ` only when none is given, so
tests never patch global process state.

**Precedence (binding, tested):** explicit CLI argument > environment
value > built-in safe default. Implemented by changing the relevant CLI
flags' `argparse` declarations from concrete defaults (e.g. `default=True`,
`default=20`) to `default=None`, then merging once at the top of each
entry point's `main()` before `ApexConfig.from_cli_args()` is called.

**Two fields have dedicated, stricter rules layered on the generic merge:**

- **`dry_run` — asymmetric safety rule.** `APEX_DRY_RUN` can only ever
  *reinforce* the safe default (`true`, or absent, → `True`); `APEX_DRY_RUN
  =false` with no explicit `--no-dry-run` CLI flag raises a clear
  `EnvConfigError` rather than silently enabling real execution — CLAUDE.md
  §13.5's "explicit CLI flag required for real execution" invariant now
  extends to environment variables too, and this phase's own philosophy
  rule 10 ("no automatic live engagement may start from loading .env") is
  enforced structurally, not just by convention.
- **`target` — "at least one of two, blank counts as absent."** Explicit
  `--target` always wins; `APEX_TARGET` is the fallback; a blank
  `APEX_TARGET` counts as unset; `apex_host.main`/`run_htb_local` require
  at least one (clear error otherwise); `apex_host.eval.check_config`
  substitutes a synthetic placeholder (`"config-check"`) instead of
  requiring one, since it validates configuration shape only.

**`apex_host/eval/check_config.py`** — new safe validation command
(`python -m apex_host.eval.check_config`). No target required; no network
call by default (`--check-connectivity` is the sole, explicit opt-in, and
even then only issues `GET /health`, never `POST /v1/execute`); prints a
fully redacted summary (`ApexConfig.to_safe_dict()` plus
`tool_service_token`/`OPENAI_API_KEY` shown as `present`/`absent` only,
never the value); exits `0`/`1`/`2` for valid/invalid/malformed-invocation.
Validates: remote backend requires URL and token (only when not in
dry-run); malformed URL; negative timeout; `max_turns < 1`; LLM enabled
with a real provider requires `OPENAI_API_KEY` (never required when
disabled or `llm_provider=fake`).

**`.env.example`** — one committed, secret-free template covering APEX
execution, target/runtime-file paths, tool backend, LLM configuration
(defaults to `fake`/`false`, never an external provider), and tool-service
server configuration. Every tool-service default documented is the real,
verified `apex_tool_service/settings.py::ServiceSettings` value (30s/120s/
32/512/65536/1048576/1048576) — not the illustrative numbers this phase's
own task brief happened to suggest, per its own "do not invent values"
instruction. `APEX_TARGET=` and both secret fields
(`APEX_TOOL_SERVICE_TOKEN=`, `OPENAI_API_KEY=`) are blank. A commented-out,
inert note documents that HTB VPN integration (`APEX_HTB_OVPN_PATH`-style)
does not exist yet — no such variable is read anywhere, and `compose.yaml`
references nothing VPN-related.

**`.gitignore`/`.dockerignore`:** both now cover `.env`, `.env.local`,
`.env.*.local`, `secrets/`, `*.ovpn` using exact-name patterns (never a
broad `.env*` glob that would catch `.env.example`). `.dockerignore`'s
`.env.*` entry (a genuine glob, unlike Git's exact-name `.env`) is followed
by an explicit `!.env.example` negation, restoring it to the build context
— verified live: `git check-ignore -q .env` exits 0 (ignored),
`git check-ignore -q .env.example` exits 1 (not ignored).

**`compose.yaml`:** the required-token fail-fast interpolation
(`${APEX_TOOL_SERVICE_TOKEN:?...}`) is unchanged; every other variable
(`APEX_TOOL_BACKEND`, `APEX_TOOL_SERVICE_URL`, and all nine
`apex_tool_service` server-configuration variables on the `kali` service)
now uses `${VAR:-default}` interpolation with the default matching the
real, verified implementation default — overridable via `.env` with zero
behavior change for anyone who does not edit it. Verified live:
`docker compose config` renders correctly with real defaults; a real
`docker compose up --build --abort-on-container-exit` run (using a fresh,
temporary `.env` copied from `.env.example`, never overwriting any
pre-existing user `.env`) completed the same safe dry-run smoke check as
Infra Phase 7, unaffected by this phase's changes.

**`python-dotenv` — retained, and given genuine, tested use.** Was
declared as a dependency since Infra Phase 1 but never imported anywhere.
This phase adds `apex_host.config_env.load_env_file()` — the **only**
place `apex_host` reads a dotenv-format file, and only when a caller
explicitly passes `--env-file PATH` (new flag on all three CLI entry
points: `apex_host.main`, `apex_host.eval.run_htb_local`,
`apex_host.eval.check_config`). Uses `dotenv_values()` (never
`load_dotenv()`), so the real process environment is never mutated as a
side effect — the returned mapping flows only through each function's
explicit `env=` parameter. Never loaded automatically or implicitly from
the working directory; Docker Compose's own, entirely separate, built-in
`.env` reading is unaffected and unchanged.

**Tests (152 new, across 5 files):**
`tests/apex_host/test_config_env.py` (89 — strict parsing, target/dry_run
resolution rules, generic merge, dotenv loading), `tests/apex_host/
test_check_config.py` (20 — safe defaults, redaction, every validation
rule), `tests/docker/test_env_files.py` (34 — `.env.example` content,
required-variable coverage, no secrets/target, real-default matching, Git/
Docker ignore-rule behavior), `tests/apex_host/test_phase8_env_architecture.py`
(8 — environment reads confined to an approved, closed file set;
`config.py` still has zero env access; every secret-shaped `ApexConfig`
field is redacted by `to_safe_dict()`; no `load_dotenv()` anywhere), plus 3
existing `tests/docker/test_compose.py` tests updated for the new
`${VAR:-default}` interpolation syntax (2 tests in
`tests/apex_host/test_llm_wiring.py` were also updated: `--use-llm`'s raw
CLI default changed from `False` to `None`, an intentional, documented
change required for the env-merge design — the *resolved* `ApexConfig`
value is unchanged and still asserted).

**Real end-to-end validation performed (recorded with full command
transcripts in `docs/environment-configuration.md` and this response):**
safe/default config check; valid remote config check with a disposable
token; missing-token failure; invalid-backend failure; malformed-number
failure; token-leak search (grep across stdout/stderr and both images'
`docker history --no-trunc`); `cp .env.example .env` → verified ignored by
Git, read automatically by Compose, safe default Compose mode working with
only the token filled in, no target contacted, `.env` absent from both
built images; full strict-validation suite (lock, sync, full pytest count,
ruff, mypy, both CLI `--help` commands, diff check, git status).

**Deferred to Infra Phase 9+ (as of Infra Phase 8):** final container
entrypoint/preflight orchestration beyond what already exists; HTB VPN
container/tunnel routing; GitHub Actions/CI image publishing; wiring a full
multi-turn engagement (`apex_host.eval.run_htb_local`) into Compose;
Meow-specific diagnosis, deterministic Meow tests, or authorized live Meow
validation. **None of these were started in this phase.**

---

### Infra Phase 9 — Container entrypoint and automated preflight orchestration ✓ COMPLETE

**Date:** 2026-07-15
**Files:** `apex_host/eval/preflight.py` (new), `apex_host/container_entrypoint.py`
(new), `apex_host/eval/check_config.py` (renamed `_validate_combinations` →
public `validate_combinations`), `docker/apex/Dockerfile` (updated),
`compose.yaml` (updated), `docs/container-entrypoint.md` (new),
`tests/apex_host/test_eval_preflight.py` (new, 65 tests),
`tests/apex_host/test_container_entrypoint.py` (new, 28 tests),
`tests/apex_host/test_phase8_env_architecture.py` (allowlist updated),
`tests/docker/test_apex_dockerfile.py` / `tests/docker/test_compose.py`
(updated for the new entrypoint/command contract)

Built the final safe container entrypoint and automated preflight
orchestration described in this phase's own task brief.
`apex_host/container_entrypoint.py` is now `docker/apex/Dockerfile`'s
`ENTRYPOINT` — every mode runs a structured preflight pass (configuration →
report directory → compiled knowledge → policy → [smoke/run only] Kali
health → [smoke/run only] one harmless remote-tool command) before
dispatching to any operational command. `docker compose up --build`
remains safe, deterministic, and target-free — it now performs a genuinely
real (not synthetic) connectivity verification by default, closing the gap
Infra Phase 7/8's `compose_smoke` module left open.

**`apex_host/eval/preflight.py`** — reusable, independently-testable
preflight checks, never embedded directly in the entrypoint. Two frozen
dataclasses: `PreflightCheck` (`name`, `passed`, `detail`,
`required: bool = True`) and `PreflightResult` (aggregate; `.passed`,
`.failed_required`, `.warnings`, `.required_count`, `.to_dict()`,
`.format_text()`). Eight check functions, none of which import or start
the engagement graph: `check_configuration` (reuses `check_config.py`'s
newly-public `validate_combinations` — one implementation, two callers),
`check_remote_backend_selected` (smoke mode's own explicit "tool_backend
must be remote" requirement), `check_report_directory` (writability proven
via a uniquely-named, immediately-removed marker file — never overwrites a
real report, never recursively changes permissions), `check_compiled_knowledge`
(delegates entirely to the existing `verify_compiled()` — never
duplicates the nine-file spec; a soft pass when no root is configured, a
hard failure when a configured root is missing/corrupt),
`check_policy` (reuses `policy_loader._resolve_policy_path`'s exact
three-tier resolution so it validates precisely what `load_policy()` would
actually load; required only for `run` mode, a soft informational pass
elsewhere), `check_tool_service_health` (bounded, unauthenticated
`GET /health`; `client:` param injectable for `httpx.MockTransport`-based
tests), `check_remote_smoke` (executes one real, harmless, hardcoded
`curl --version` through the real `select_runtime_backend(config)`),
`check_llm_readiness` (trivial pass when `use_llm=False`), and
`check_live_confirmation` (`run` mode's own safeguard — see below).

**`apex_host/container_entrypoint.py`** — the container `ENTRYPOINT`. Five
modes: `check` (local-only, no target, no network — the Dockerfile's safe
default), `smoke` (adds Kali health + one harmless remote command; forces
`dry_run=False` unconditionally since its command is hardcoded and
non-configurable — the same safety profile already accepted for Infra
Phase 7/8's `compose_smoke --no-dry-run`), `dry-run` (requires a target;
forces `dry_run=True` unconditionally — no CLI flag on this subcommand can
override it; dispatches to the existing, unmodified
`apex_host.eval.run_htb_local.run_engagement()` pipeline on preflight
success), `run` (the live-run path: requires `--target`, `--no-dry-run`
resolved through the normal, unmodified `resolve_dry_run` precedence, and
an explicit `--confirm-live` CLI flag with **no environment-variable
substitute anywhere** — this phase's own task brief preferred an explicit
CLI flag over `APEX_LIVE_CONFIRM` because environment values can go stale;
also runs the full preflight with `policy_required=True`, unlike every
other mode), and `exec` (bypasses the entire workflow via argv-list
`os.execvp` — process replacement, never a shell, so no signal-forwarding
logic is needed once it succeeds). `_run_with_signal_handling()` wraps
every async mode's dispatch in an `asyncio.Task` with a `SIGTERM` handler
that cancels it cleanly (exit code `143`) rather than leaving the
interpreter's default disposition to kill it mid-await.

**`run` mode never dispatches to the engagement pipeline when refused** —
proven by dedicated tests that inject an `AssertionError`-raising fake in
place of `_run_engagement_and_report` for every refusal path (missing
`--confirm-live`; missing `--no-dry-run`; a stale `$APEX_LIVE_CONFIRM`-style
env var, which has zero effect by design; a failing required preflight
check such as a missing policy file).

**Bug found and fixed during this phase:** `check_remote_smoke`'s first
implementation did not catch the `ValueError` that
`select_runtime_backend()`/`RemoteToolBackend.__init__` raises fail-fast
(an established Infra Phase 4 behavior) for a missing bearer token —
direct manual testing surfaced an unhandled traceback instead of a clean,
structured failure. Fixed by wrapping the call in `try/except ValueError`
and returning an ordinary failed `PreflightCheck` — no request is ever
sent when the backend cannot be constructed. This satisfies the "missing
service token: smoke fails before execution, never sends a request"
runtime-validation requirement.

**`docker/apex/Dockerfile`:** `ENTRYPOINT ["python", "-m",
"apex_host.container_entrypoint"]` / `CMD ["check", "--knowledge-root",
"/app/knowledge"]` — both exec-form JSON arrays, no shell, so signals are
delivered directly to the Python interpreter and `CMD`'s arguments are
appended to `ENTRYPOINT`'s argv rather than shell-reinterpreted. The prior
bare `--help` invocation now has a documented equivalent via `exec` mode
(`docker run --rm apex-image exec -- python -m apex_host.main --help`) or
`--entrypoint python`.

**`compose.yaml`:** the `apex` service's default `command:` changed from
`["python", "-m", "apex_host.eval.compose_smoke"]` to `["smoke",
"--knowledge-root", "/app/knowledge"]`. Unlike Phase 7/8's dry-run-by-default
smoke module, this performs a *real* connectivity check by design (§ above)
— `docker compose up --build --abort-on-container-exit` now exercises the
genuine Kali health + harmless-command path on every run, not a synthetic
placeholder. Compose's default `restart: "no"` policy already produces the
desired "`kali` stays running after `apex` exits cleanly" behavior with no
added configuration — both `--abort-on-container-exit` (auto-stopping,
recommended for a single verification pass) and a bare `docker compose up
--build` (leaves `kali` running for a follow-up `docker compose run apex
dry-run ...`) remain valid, documented workflows.

**`.env.example` — unchanged.** No new variable was required; the
live-confirmation safeguard is deliberately CLI-only with no environment
equivalent (see `run` mode above); no default target, no VPN variable, and
no way to enable live mode by default was added.

**Tests (93 new, across 2 new files + 2 updated):**
`tests/apex_host/test_eval_preflight.py` (65 — every check function's
pass/fail/warning paths, using `tmp_path`/`stat` for platform-safe
report-directory permission tests, synthetic fixtures matching the real
9-file compiled-knowledge spec, `httpx.MockTransport` for health checks,
and a fake backend plus one real `LocalToolBackend` execution for the
remote-smoke check), `tests/apex_host/test_container_entrypoint.py` (28 —
every mode, `--json` output, exit-code propagation, token redaction
(a real distinctive token value asserted absent from all captured
output), `exec` mode's `os.execvp` argv-list call (mocked — never actually
replaces the test process) and its "no shell" static source-text guard,
and `SIGTERM` cancellation of a running coroutine via a genuine
`os.kill(os.getpid(), signal.SIGTERM)` in an async test). Every `dry-run`/
`run` dispatch test mocks `_run_engagement_and_report` — no real engagement
work occurs in any test. `tests/apex_host/test_phase8_env_architecture.py`'s
`_APPROVED_ENV_READERS` allowlist was extended for the two new files (both
read only token/API-key *presence*, matching the pre-existing redaction
discipline; the architecture test caught this correctly on first run and
was fixed, not weakened). `tests/docker/test_apex_dockerfile.py` and
`tests/docker/test_compose.py` were updated for the new `ENTRYPOINT`/`CMD`
and `smoke`-mode default command contracts.

**Real end-to-end validation performed:** host-side `check` mode (pass and
report-directory-failure paths); host-side `smoke` mode against a running
`apex_tool_service` (real health check, real `curl --version`); missing
compiled knowledge (clear, actionable, non-zero failure); missing/malformed
policy file (both failure shapes); missing service token (fails before any
request is sent — see the bug fix above); Kali unavailable (bounded
timeout, never hangs); a real `docker compose up --build` two-container
startup with a disposable test token (Kali healthy, `smoke` preflight
visible in `docker compose logs apex`, harmless smoke succeeds, no target
contacted, no secret printed, `apex` exits `0`, `kali` remains healthy
afterward); container `check` mode via direct `docker run`; container
`smoke` mode via `docker compose run`; a full `dry-run` engagement against
a placeholder target with report export, confirmed to never contact Kali;
`run` mode's refusal paths (missing `--confirm-live` alone; missing
`--no-dry-run` alone even with `--confirm-live` present) — live execution
against a real target was never attempted, since no HTB VPN routing exists
yet; `SIGTERM` signal propagation; full strict-validation suite (lock
check, sync, 3283 tests passing, ruff clean, mypy clean across 142 source
files, both CLI `--help` commands, diff check, git status); cleanup of all
temporary containers/networks/env files/smoke artifacts. Full detail:
[`docs/container-entrypoint.md`](docs/container-entrypoint.md).

**Deferred to Infra Phase 10+ (as of Infra Phase 9):** HTB VPN
container/tunnel routing (`run` mode's live path remains unexercised
against a real target); GitHub Actions/CI image publishing; Meow-specific
diagnosis, deterministic Meow tests, or authorized live Meow validation.
**None of these were started in this phase.** No git branch was created;
no commit or push was made as part of this phase's work.

---

### Infra Phase 10 — HTB VPN networking architecture ✓ CODE COMPLETE — LIVE VALIDATION REQUIRED

**Date:** 2026-07-15
**Files:** `docker/vpn/` (new — `Dockerfile`, `entrypoint.py`,
`readiness_server.py`, `tunnel_status.py`, `route_check.py`),
`compose.yaml` (updated — new `vpn` service, profile-gated),
`compose.htb.yaml` (new — Compose override activating HTB mode),
`compose.mock-vpn.yaml` (new — test-only override substituting a harmless
HTTP server for the real OpenVPN build), `apex_host/config.py` /
`apex_host/config_env.py` (updated — four new VPN fields/env vars),
`apex_host/eval/preflight.py` (updated — VPN readiness checks),
`apex_host/eval/vpn_route_check.py` (new — manual route-lookup CLI),
`apex_host/container_entrypoint.py` (updated — VPN CLI flags),
`.env.example` (updated — VPN section populated), `docs/htb-vpn-container.md`
(new), `docs/htb-vpn-manual-validation.md` (new), plus correction notes in
`docs/docker-compose.md` and `docs/container-entrypoint.md`. 177 new
tests across 8 new test files plus updates to `tests/docker/test_compose.py`
and `tests/docker/test_env_files.py`.

Implemented the Docker-side HTB VPN networking architecture this phase's
own task brief required, and validated everything locally reproducible
without a real HTB profile — a dedicated VPN container, an `htb` Compose
profile, network-namespace sharing between `kali` and `vpn`, VPN-specific
preflight checks, a no-packet route-lookup utility, and a mock namespace
integration test proving the topology works against a real Docker daemon.
**No real, authorized HTB `.ovpn` profile was available in this
development environment** — live OpenVPN initialization, real tunnel/route
establishment, and real target reachability were never tested. This phase
is **code-complete, not live-validated** — see
`docs/htb-vpn-manual-validation.md` for the exact remaining steps an
operator with a real profile must perform.

**Topology and the coherent design chosen** (of the three options this
phase's task brief posed for APEX-to-Kali service discovery once `kali`
shares `vpn`'s network namespace): **Option 1** — the VPN service itself
joins `apex-internal`, and `apex` reaches the shared namespace through
`vpn`'s own Compose DNS name and exposed ports (`http://vpn:8080` for
Kali's real tool API, `http://vpn:8090` for the VPN container's own
readiness API). Option 2 (aliasing `vpn` as `kali`) was rejected — `kali`
has no Compose DNS identity of its own once it uses `network_mode:
service:vpn`, so inventing an alias would not remove a real constraint.
Option 3 (binding Kali's HTTP service to `0.0.0.0:8080` inside the shared
namespace) was already true unconditionally since Infra Phase 6 — a
supporting fact, not a separate design choice.

**Why a separate `compose.htb.yaml` override file, not one shared
`compose.yaml`:** Compose has no mechanism for a single named service to
have two different `network_mode`/`networks` configurations depending on
which `--profile` flag is active — profiles only gate whether a whole
service starts, not which of two configs it uses. `compose.htb.yaml` is
the standard Compose "override file" idiom: merged via `-f compose.yaml
-f compose.htb.yaml`, it redefines only `kali` (network mode) and `apex`
(service-discovery environment variables), never `vpn` itself, and never
touches the base file. Discovered and fixed during this phase: `network_mode`
and `networks` are mutually exclusive per the Compose Specification —
`compose.htb.yaml` uses the Compose Spec's `!reset` tag to explicitly
clear `kali`'s inherited `networks:`/`expose:` from the base file, since
without it `docker compose config` fails validation.

**Discovered and fixed during this phase:** Compose validates/interpolates
every service declared in a file up front, **regardless of whether that
service's profile is active** — `profiles:` only gates whether a service
*starts*. An initial version of `vpn`'s `volumes:` entry in the base
`compose.yaml` used the fail-fast `${APEX_HTB_OVPN_PATH:?...}` form,
which broke the default (non-`htb`-profile) `docker compose config`/`up`
workflow entirely — a bare `docker compose up` failed before ever
reaching the profile gate. Fixed by using a **soft** default
(`${APEX_HTB_OVPN_PATH:-/dev/null}`) in the base file (harmless — `vpn`
never actually starts by default anyway) and moving the **real** fail-fast
requirement into `compose.htb.yaml`'s own `vpn.volumes:` override
(Compose's list-merge semantics: a list declared in an override file
replaces the base file's list entirely) — only evaluated when
`compose.htb.yaml` is explicitly merged in. Verified live: default
`docker compose config` renders identically to Infra Phase 9 (no `vpn`
service in the output at all — Compose excludes non-active-profile
services from `config`, not merely from `up`); HTB-mode `docker compose
-f compose.yaml -f compose.htb.yaml --profile htb config` with no
`APEX_HTB_OVPN_PATH` set fails clearly and immediately.

**`docker/vpn/` — the VPN image and its four first-party scripts, all
stdlib-only** (no FastAPI/uvicorn/httpx/`apex_host` import — deliberately,
to avoid the same "one Hatchling distribution pulls in the whole
scientific-Python dependency tree" packaging problem `docs/kali-container.md`
already documented for the Kali image):

- `entrypoint.py` — verifies `/vpn/htb.ovpn` exists and is readable and
  `/dev/net/tun` exists (both fail-fast, non-zero, before anything else
  starts); starts the readiness HTTP server in a daemon background
  thread; runs OpenVPN in the foreground as an argv-list subprocess
  (`--auth-nocache`, never `--route`/`--redirect-gateway` — whatever the
  profile itself specifies is what takes effect); forwards
  `SIGTERM`/`SIGINT` to the OpenVPN child and propagates its exit code.
  Never opens the profile for writing.
- `readiness_server.py` — a minimal `http.server`-based HTTP server:
  `GET /health` (`{"status", "service", "tunnel", "route_cidr"}` only —
  never the profile, certificate, full route table, or an environment
  dump) and `GET /route-check?target=<ip>` (delegates to `route_check.py`).
  Unauthenticated by design, matching `apex_tool_service`'s own
  `GET /health` precedent (Infra Phase 3) — it reveals nothing sensitive.
- `tunnel_status.py` — `check_tunnel_status(route_cidr)` runs `ip -o link
  show`/`ip route show` (read-only inspection, never `add`/`del`) and
  determines readiness from BOTH a tunnel-shaped (`tun*`/`tap*`/`ppp*`)
  UP interface AND a matching route — process existence alone is
  insufficient, per this phase's own explicit requirement. `validate_cidr()`
  strictly validates the configured CIDR via `ipaddress.ip_network`.
- `route_check.py` — `run_route_get(target)` validates the target as a
  syntactically well-formed IP address (`ipaddress.ip_address`, rejecting
  hostnames/CIDR-notation/shell-metacharacter strings) **before** ever
  constructing the `["ip", "route", "get", target]` argv list — never a
  shell, never any other `ip` subcommand, bounded timeout, sends no
  packet (a kernel routing-table lookup only).

**Root, by necessity — the one documented exception to this project's
universal non-root convention.** OpenVPN must create a tun/tap device and
modify this container's own routing table, which requires `CAP_NET_ADMIN`
*and*, in practice, root inside the container's own user namespace —
`NET_ADMIN` alone does not grant a non-root user permission to open
`/dev/net/tun` or reconfigure routes. `apex` and `kali` remain non-root in
every mode, including HTB mode — verified live via `docker inspect`
(`kali`'s `User=apextool`, `CapAdd=[]` unchanged while sharing `vpn`'s
namespace).

**Configuration (Infra Phase 10 additions to the existing `config_env.py`/
`ApexConfig` layer, not a new parallel system):** `apex_host/config.py`
gained four fields — `vpn_service_url: str | None = None`,
`vpn_health_timeout_seconds: float = 10.0`, `htb_route_cidr: str =
"10.129.0.0/16"`, `htb_ovpn_path: str | None = None` — wired into
`from_cli_args()` and `to_safe_dict()`. `htb_ovpn_path`'s redaction is
**basename-only** (not full `"[redacted]"`) — per this phase's own
instruction: "the VPN profile path is sensitive operational configuration
but not necessarily a credential... show only that it is configured or
its basename." `apex_host/config_env.py` gained
`ENV_VPN_SERVICE_URL`/`ENV_VPN_HEALTH_TIMEOUT_SECONDS`/`ENV_HTB_ROUTE_CIDR`/
`ENV_HTB_OVPN_PATH` and a new `validate_cidr()` strict parser (independently
re-implemented, not imported, from `docker/vpn/tunnel_status.py`'s own
`validate_cidr` — `apex_host` and `docker/vpn/` are deliberately
non-overlapping dependency trees). All four flow through the existing
generic env-merge (`merge_env_into_args`), so CLI > environment > safe
default precedence is inherited automatically, not reimplemented.

**Preflight (Infra Phase 10 additions to the Infra Phase 9
`apex_host/eval/preflight.py` module):** `check_htb_profile_configured(path,
required=)` — host-side only, checks file existence/readability via
`Path.exists()`/`os.access()`, **never opens the file for content** (a
canary-style test, `test_never_reads_file_content`, confirms fake
credential material placed in a test fixture never appears in the check's
own detail message); soft pass when unconfigured (mirrors `check_policy`'s
established pattern), hard failure when configured-but-missing/unreadable
regardless of `required`. `check_vpn_readiness(url, expected_route_cidr,
timeout, client=)` — one HTTP round trip to the VPN readiness server's
`GET /health`, producing two `PreflightCheck`s ("VPN service reachable",
"VPN tunnel/route ready") from the single response; returns `[]` (zero
network calls) when `vpn_service_url` is unset — proven by
`test_default_config_produces_no_checks` and
`test_run_smoke_checks_default_config_has_no_vpn_checks`, the load-bearing
tests establishing that every non-HTB invocation is byte-for-byte
unaffected. **Deliberately never calls `/route-check`** — that endpoint is
reserved for the manual utility only
(`test_never_calls_route_check_endpoint`). Both new checks are wired into
`run_local_checks`/`run_vpn_checks`, which `run_smoke_checks` and
`_handle_run` (in `container_entrypoint.py`) both call — `check` and
`dry-run` modes only ever run the local (filesystem-only) HTB-profile
check; `smoke` and `run` also run the network-touching VPN readiness
checks.

**`apex_host/eval/vpn_route_check.py`** — the manual, operator-invoked
route-lookup CLI (`python -m apex_host.eval.vpn_route_check
--vpn-service-url http://vpn:8090 --target <ip>`). Client-side IP
validation (`ipaddress.ip_address`) happens before any HTTP request is
constructed. **Never wired into any automatic preflight path or engagement
mode** — this is deliberate and tested
(`test_vpn_preflight.py::test_never_calls_route_check_endpoint`); it exists
solely for the manual validation workflow documented in
`docs/htb-vpn-manual-validation.md`.

**Mock VPN namespace integration — real Docker, no real HTB profile,
clearly labeled throughout as a mock:** `compose.mock-vpn.yaml`
substitutes a plain, official, digest-pinned `python -m http.server` for
the real `docker/vpn/Dockerfile` build (no OpenVPN, no `NET_ADMIN`, no
`/dev/net/tun`, no real profile). Run via `docker compose -f compose.yaml
-f compose.htb.yaml -f compose.mock-vpn.yaml --profile htb up --build`.
**Verified live, this phase:** the real, unmodified `kali` image was
reachable at `http://vpn:8080` while sharing the mock `vpn` service's
network namespace — a real `GET /health` and a real `curl --version`
executed successfully through it (`[PASS] Kali health`, `[PASS] remote
tool smoke` in `apex`'s own preflight output). `docker inspect
newapex-kali-1` showed `NetworkMode=container:<vpn-container-id>`,
`CapAdd=[]`, `User=apextool` — namespace sharing granted zero extra
privilege, confirming the design. `[FAIL] VPN service reachable` (HTTP 404
from the mock, which has no real `/health` JSON contract) is the expected,
correct outcome — it proves the VPN readiness check is not a false
positive against a non-VPN service. Neither `kali`'s port 8080 nor the
mock `vpn`'s port 8090 was published to the host (verified via `docker
compose port` and a direct host `curl` failing with connection refused).
**This mock proves only the network-namespace-sharing mechanism — it does
NOT start OpenVPN, does NOT create a real tunnel, and does NOT prove HTB
connectivity in any way.** Every file and doc section describing it says
so explicitly.

**Real (non-mock) runtime validation performed, all without a real HTB
profile:** VPN image built (`docker build -f docker/vpn/Dockerfile`, 234
MB, ~7s from cache); `docker image inspect`/`docker history --no-trunc`
confirmed no `.ovpn` file, no credential, no `apex_host`/`memfabric`
source anywhere in the image, root user (documented), exec-form
`ENTRYPOINT`, `EXPOSE 8090` only; missing-profile fail-fast (`docker run
--rm --entrypoint sh apex-vpn... -c "..."` with no mount → clear error,
exit 1); missing-`/dev/net/tun` fail-fast (profile mounted via `/dev/null`
substitute, no `--device` flag → clear error, exit 1); a harmless,
deliberately-invalid `.ovpn` file (garbage text, no real config directives)
mounted into the **real** `docker/vpn/Dockerfile` build via
`compose.htb.yaml` → OpenVPN itself rejected it in under a second
("Options error: Unrecognized option..."), the entrypoint propagated exit
code 1, no hang, no leaked profile structure beyond OpenVPN's own
diagnostic naming of the invalid first token; default (non-`htb`-profile)
`docker compose up --build --abort-on-container-exit` re-verified
end-to-end after all `vpn` service additions — 7 required checks pass
(now including one new, always-soft-pass `[PASS] HTB profile configured`
line), `apex` exits `0`, byte-for-byte consistent with Infra Phase 9's own
verified output. All temporary containers/networks/images were removed
after each scenario via `docker compose down --remove-orphans` plus
targeted `docker rmi` — **no `docker network prune`/`docker system
prune`** was used anywhere in this phase.

**Tests (177 new):** `tests/docker/test_vpn_dockerfile.py` (28 — base
image, packages, no-profile/no-credentials/no-APEX-source static checks,
exec-form entrypoint, healthcheck, root-usage documentation, support
scripts' argv-list/no-shell discipline), `tests/docker/test_compose_htb.py`
(22 — override-file structure, `!reset` handling via a custom PyYAML
loader, kali network-mode/depends_on, apex environment overrides, vpn's
fail-fast volume override), `tests/docker/test_vpn_scripts.py` (58 —
dynamically imported via `importlib.util.spec_from_file_location` since
`docker/vpn/` is not an installed package; CIDR/IP validation, route/
interface parsing, subprocess mocking for `run_route_get`/
`check_tunnel_status`, and a **real, local-only HTTP round trip** against
the actual `readiness_server.ReadinessHandler` on an ephemeral loopback
port), `tests/apex_host/test_vpn_config.py` (23), `tests/apex_host/
test_vpn_preflight.py` (23 — including the load-bearing "default config
produces zero network calls" tests), `tests/apex_host/test_vpn_route_check.py`
(13), `tests/docker/test_compose_mock_vpn.py` (9 — mock file structure,
capability-free, clearly labeled). Plus updates to the existing
`tests/docker/test_compose.py` (new `vpn`-service tests; the three tests
that previously asserted "no VPN configuration in this phase" —
`test_no_service_network_mode`, `test_no_unexpected_capabilities`,
`test_no_ssh_or_vpn_configuration` — were rewritten to assert the new,
intentional, scoped invariants: no `network_mode: service:*` in the
**base** file specifically, `NET_ADMIN` allowed **only** on `vpn`, no
literal host `.ovpn` path anywhere) and `tests/docker/test_env_files.py`
(same treatment for `.env.example`'s VPN section).

**Total test count after Infra Phase 10:** 3469 passed (up from 3283 at
Infra Phase 9), `ruff check .` clean, `mypy` clean across 143 source files.

**Deferred / explicitly not performed in this phase:** live OpenVPN
initialization against a real HTB server; real tunnel/route establishment;
real HTB target reachability validation; GitHub Actions/CI publishing;
Meow-specific diagnosis, deterministic Meow exploitation logic, or any
machine-specific code (CLAUDE.md §13.8/§13.9's standing prohibition,
unchanged and re-verified — no target IP, expected credential, or
machine-specific routing decision was added anywhere in this phase). No
git branch was created; no commit or push was made as part of this
phase's work.

---

### Infra Phase 11 — GitHub Actions CI and GHCR image publishing ✓ CODE COMPLETE — GITHUB RUN VALIDATION REQUIRED

**Date:** 2026-07-16
**Files:** `.github/workflows/ci.yml` (new), `.github/workflows/docker-publish.yml`
(new), `tests/github_actions/__init__.py` (new),
`tests/github_actions/test_workflows.py` (new, 78 tests), `docs/github-actions.md`
(new), `README.md` (updated — new GitHub Actions/GHCR paragraph in the
APEX Host Layer section)

Added the two first-party GitHub Actions workflows this phase's own task
brief required — CI validation (`ci.yml`) and GHCR image publishing
(`docker-publish.yml`) — plus 78 static tests proving their structure and
content, and full documentation. Per this phase's own explicit
instruction, this record treats Infra Phases 1-10 (including Phase 10's
HTB VPN integration and its Cap-machine infrastructure validation) as
already complete context for sequencing purposes; this session did not
itself re-verify Phase 10's live-validation status and made no change to
that phase's own CLAUDE.md record (§ above, left exactly as originally
written per the append-only convention) — only Phase 11's own work is
reported here.

**No root `.github/workflows` directory existed before this phase** —
confirmed by direct filesystem search. Four *vendored* `.github/workflows`
directories exist under `Knowledge/payload_db/{GTFOBins,LOLBAS,
PayloadsAllTheThings,SecLists}/` (each third-party corpus ships its own,
unrelated upstream CI) — these were identified, left completely untouched,
and are statically proven distinct from this project's own workflow
directory by `tests/github_actions/test_workflows.py::TestWorkflowExistence::test_vendored_workflow_files_are_not_project_workflows`.

**Default branch verified, not assumed:** `git symbolic-ref
refs/remotes/origin/HEAD` → `refs/remotes/origin/main` — `main` is the
real default branch, confirmed before writing any trigger config (the
task brief explicitly warned "do not guess"). Git remote:
`git@github.com:RownakDiganta/APEX.git` — neither the remote nor the
default branch was modified.

**Action pins are real, verified commit SHAs, not fabricated.** Every
`uses:` line in both workflow files pins to a full 40-character commit
SHA resolved via a live query against the real GitHub API
(`https://api.github.com/repos/<owner>/<repo>/git/refs/tags/<tag>`) for
each action's current stable release tag at the time this phase was
written, with the corresponding version documented in an inline comment:
`actions/checkout` (v7.0.0), `actions/setup-python` (v6.3.0),
`astral-sh/setup-uv` (v8.3.2 — whose own release notes reference the
exact `0.11.28` uv version this project already pins elsewhere),
`docker/setup-buildx-action` (v4.2.0), `docker/login-action` (v4.4.0),
`docker/metadata-action` (v6.2.0), `docker/build-push-action` (v7.3.0).
No SHA in either file was guessed or invented — an unverifiable/fabricated
SHA would either fail immediately (safe) or, far worse, silently resolve
to an unintended commit (a real supply-chain risk); querying the real API
was the only acceptable way to satisfy the task brief's explicit
preference for full-SHA pinning.

**`ci.yml`** — three jobs: `validate` (checkout → Python 3.11 → uv 0.11.28
→ `uv lock --check` → `uv sync --frozen --all-groups` → `uv run pytest -q`
→ `uv run ruff check .` → `uv run mypy`), `compose-validate` (renders both
`docker compose config` and the HTB-profile override render, both
redirected to a temp file rather than printed, then explicitly asserts
`/dev/net/tun` and the placeholder `.ovpn` path do not exist afterward —
positive proof, not just omission, that nothing VPN-related started),
and `build-images` (matrix over the three Dockerfiles, `push: false`,
GHA cache scoped per image, `needs: [validate, compose-validate]`).
Workflow-level `permissions: contents: read` only — no job overrides it
upward, and `docker/login-action` does not appear anywhere in this file.
Triggers: `pull_request`, `push: branches: [main]`, `workflow_dispatch`.
Concurrency group keyed by PR number or ref, `cancel-in-progress: true`.

**`docker-publish.yml`** — two jobs: `validate` (a full, independent copy
of the same Python + Compose validation — does not assume `ci.yml` already
ran for this commit, since a `workflow_dispatch` or tag push may have no
associated `ci.yml` run at all; narrowed to `permissions: contents: read`
at the job level even though the workflow grants `packages: write`
overall) and `build-and-push` (`needs: [validate]` — publishing is
structurally impossible without validation passing first, not merely
relying on branch protection). `build-and-push` computes a lowercased
GHCR owner via bash's `${OWNER,,}` parameter expansion (no `eval`, no
unsafe interpolation — routed through `env:` per GitHub's own
script-injection-avoidance guidance) since the real repository owner
login (`RownakDiganta`) is mixed-case and GHCR requires lowercase image
names; logs in via `docker/login-action` using `secrets.GITHUB_TOKEN`
only (no manually created PAT anywhere); uses `docker/metadata-action`
for tags (`latest` gated on `{{is_default_branch}}` — never reassigned by
a tag push, deliberately, since a maintainer may tag a historical release
after `main` has moved on; unconditional `type=sha`; `type=semver`
patterns for `{{version}}`, `v{{version}}`, `{{major}}.{{minor}}`,
`{{major}}`) and OCI labels (`org.opencontainers.image.title`/
`.description` explicitly overridden per matrix entry; `.source`/
`.revision`/`.created`/`.version` populated automatically by the action
from real repository/workflow metadata — no invented version anywhere);
builds with `provenance: true`/`sbom: true` (pushed-image-only — `ci.yml`
never enables either, since there is nothing to attach an attestation to
when `push: false`). Triggers: `push: branches: [main]` + `tags: ["v*"]`,
`workflow_dispatch` — never `pull_request`/`pull_request_target`.
Concurrency group keyed by `github.ref`, `cancel-in-progress: false` (a
publish must run to completion, never be interrupted mid-manifest-upload
by an unrelated run) — a deliberately separate group namespace from
`ci.yml`'s own.

**GHCR image names:** `ghcr.io/<repository_owner, lowercased>/apex`,
`.../apex-kali`, `.../apex-vpn` — owner derived from
`github.repository_owner` at run time, never hardcoded.

**Reproducibility caveat documented, not glossed over:** neither
`provenance`/`sbom` attestation claims the Kali image's `apt-get install`
step is fully reproducible beyond the pinned base digest and committed
Dockerfile instructions — Kali rolling has no dated package-snapshot
repository, so exact package versions can still differ between builds on
different days (pre-existing, already-documented limitation, restated
accurately in `docs/github-actions.md` §19 rather than overclaimed).

**Tests (78 new, `tests/github_actions/test_workflows.py`):** existence
(including the vendored-vs-project workflow distinction), triggers
(including the `on:`-parses-as-`True` PyYAML/YAML-1.1 gotcha, handled via
a dedicated `_triggers()` helper that tries both `"on"` and `True` as the
top-level key), permissions (workflow- and job-level, including the
`docker-publish.yml` `validate` job's own narrowing), Python validation
(3.11, official `setup-uv`, all five required commands, and an explicit
regression guard against the documented `mypy .` footgun), Compose
validation (both renders, no `up` command anywhere, no `/dev/net/tun`
outside the one intentional non-existence assertion, no target IP, no
live-mode flag), image matrix (exactly three entries in both files,
correct Dockerfile per image, correct build context), publishing (GHCR,
`GITHUB_TOKEN`-only secret usage, `docker/login-action` confined to the
publish workflow, metadata-action, buildx, PR `push: false`, the
`needs: [validate]` dependency, `latest` gated correctly, SHA/semver tags
present), cache (GHA cache enabled, scope uniquely parameterized by
`matrix.image` in both files), and secret safety (no API-key-shaped
literal, no realistic token value, no `.env`/`.ovpn` upload or content,
no generic credential pattern, no HTB target IP, no live APEX execution
flag, no `privileged: true`, no Docker-socket mount, and — the most
load-bearing single test — a whole-file scan proving the only
`secrets.*` context reference anywhere in either workflow is
`GITHUB_TOKEN`). Two tests initially false-positived on this file's own
explanatory prose (`pull_request_target`/`packages: write` mentioned in
comments describing what is forbidden) — fixed with a `_non_comment_text()`
helper that strips full-line `#` comments before the negative-assertion
scan, the same pattern already established in `tests/docker/test_compose.py`.

**Total test count after Infra Phase 11:** 3573 passed (up from 3495 at
the end of the prior session's Phase 10 debugging turn — 78 new workflow
tests), `ruff check .` clean, `mypy` clean across 143 source files
(workflow YAML files are not part of the mypy-scoped file set and were
never expected to be).

**Local validation performed (all commands the workflows themselves
run, reproduced directly):** `uv lock --check`, `uv sync --all-groups`,
full `uv run pytest -q`, `uv run ruff check .`, `uv run mypy`, default
`docker compose config` with a disposable token, the HTB-profile
`docker compose -f compose.yaml -f compose.htb.yaml --profile htb config`
render with the placeholder `.ovpn` path (never a real one), and a fresh
`docker build` of all three images (`docker/apex/Dockerfile`,
`docker/kali/Dockerfile`, `docker/vpn/Dockerfile`) tagged
`*:phase11-ci`. `actionlint` was checked for (`command -v actionlint`)
and was not installed — per this phase's own instruction, no unverified
binary was installed to obtain it; GitHub-hosted execution remains the
final workflow-syntax validation step, explicitly stated as such rather
than assumed passed.

**Deferred / explicitly not performed in this phase (structurally
impossible without violating "do not commit or push"):** no branch was
created, nothing was committed or pushed, so the workflows have **not**
run on GitHub — no CI run, no publish run, no GHCR package of any kind
exists yet, and package visibility has not been checked. `docs/github-actions.md`
§27 lists the exact remaining steps. No APEX exploitation behavior was
debugged, no Cap/Meow workflow was modified, no target-specific
exploitation logic was added, and no live HTB engagement was run —
entirely out of scope for this phase and untouched.

---

## 23. Application Repair Roadmap — Phase 12

Separate from the Infrastructure Migration Roadmap (§22) and the Reviewer
Remediation Program (§21): this track fixes defects in the APEX
*application logic* surfaced by the HTB Exploitation Workflow Diagnostic
Report — why APEX, with working infrastructure, still could not reliably
progress through an HTB engagement. "Phase 12" numbering is independent of
both §21's and §22's phase counters.

### Phase 12A — State Machine Correctness (R1) ✓ COMPLETE

Fixed the three confirmed state-machine bugs from the diagnostic report,
without adding any new exploitation capability:

- **Bug A (credential-phase budget oscillation):** `GlobalPlanner.decide_phase()`
  keyed budget-exhaustion forcing off the single-call `current_phase`
  argument, which only matched the exhausted phase on one call — the next
  turn's `current_phase` was already the peeked-forward phase, so forcing
  silently stopped applying and the engagement oscillated back into the
  just-exhausted phase forever. Fixed by checking every budget-tracked
  phase's own persistent `_spent` counter on every call, independent of
  `current_phase`.
- **Bug B (`auth_flow` treated as `access_state`):** `_select_phase()` let a
  bare `auth_flow` node (a login page merely *discovered*) skip the
  credential phase the same way a validated `access_state` did. Fixed —
  only `access_state` gates the credential→priv_esc transition now.
- **Bug E (silent `END` on an unroutable phase):** `route_after_global_plan`
  used `PHASE_NODE.get(phase, END)` — any phase not in the 4-entry
  dispatch map (e.g. the still-unreachable `ApexPhase.exploit`/`lateral`)
  disappeared into `END` with no diagnostic trail. Fixed with a new
  `unknown_phase_agent` node (`apex_host/orchestration/diagnostics_node.py`)
  that appends a diagnostic `Episode`, records a new
  `ApexGraphState.diagnostic_events` entry, sets `last_error`, and
  terminates cleanly.

**Files changed:** `apex_host/planners/global_planner.py`,
`apex_host/orchestration/routing.py`,
`apex_host/orchestration/diagnostics_node.py` (new),
`apex_host/orchestration/builder.py`, `apex_host/graph_state.py`,
`apex_host/runtime.py`, `apex_host/eval/run_synthetic_machine.py`, plus
test fixes for behavior that had encoded the bugs themselves (three
pre-existing tests asserted the pre-fix, buggy expectations and were
corrected, not weakened) and a new `tests/apex_host/test_phase12a_state_machine.py`
(12 tests). **Validation:** full suite passed (3590 tests at the time),
`ruff`/`mypy` clean, CLI smoke and diff checks clean. No exploitation,
SSH/FTP, privilege escalation, or infrastructure changes were made in this
phase — see Phase 12B below for SSH/FTP.

### Phase 12B — Bounded SSH/FTP Credential Validation ✓ COMPLETE

**Full design document:** [`docs/credential-validation.md`](docs/credential-validation.md)
(21 required sections). This entry is a summary and progress record; that
document is authoritative.

**Scope:** Phase 12A fixed the state machine; it did not fix the fact that
the credential phase could only ever validate Telnet, which almost no real
HTB service exposes. Phase 12B adds `SSHExecutor`
(`apex_host/agents/ssh_executor.py`, Paramiko) and `FTPExecutor`
(`apex_host/agents/ftp_executor.py`, stdlib `ftplib`) so APEX can produce
its existing `access_state` success signal on realistic services, without
crossing into exploitation.

**Binding invariants (all verified by dedicated tests):**

1. **One bounded attempt per protocol, ever, per target/username.**
   `CredentialPlanner` emits at most one task per turn, using only
   `username_candidates[0]`/`password_candidates[0]` — never a loop over
   candidates, never every protocol in one turn. A `_protocol_already_attempted()`
   guard (scoped to `protocol + target + username`, via each credential
   node's `protocol` prop) prevents re-attempting a protocol that already
   has a recorded credential node.
2. **No brute force, no credential spraying, no cracking tools.** No
   Hydra/Medusa/Ncrack/Metasploit anywhere in the new code (statically
   verified). No wordlist, no `itertools.product` over candidate pairs.
3. **Fixed harmless validation actions only.** SSH: `id`/`whoami`
   (`_ALLOWED_VALIDATION_COMMANDS`). FTP: `PWD`/`NOOP`
   (`_ALLOWED_VALIDATION_OPERATIONS`). Both allowlists are enforced twice —
   once inside the executor, once at the policy boundary
   (`apex_host/policy/rules.py::check_bounded_credential_validation`) —
   before any executor is ever reached.
4. **No file transfer, no port forwarding, no persistent session.** Neither
   executor calls `open_sftp()`/`request_port_forward()`/`invoke_shell()`
   (SSH) or `RETR`/`STOR`/`DELE`/`MKD`/`RMD`/`RNFR`/`RNTO`/`NLST` (FTP) —
   statically verified absent from both modules. Every session is closed
   in a `finally` block on every code path.
5. **Deterministic protocol ordering, never random.**
   `_PROTOCOL_ORDER = ("telnet", "ssh", "ftp")` in
   `apex_host/planners/credential_planner.py` — fixed and documented.
   Telnet first purely for backward compatibility. Within one protocol,
   lowest port number wins.
6. **Cross-protocol isolation.** `apex_host/graph_ids.py::credential_id`/
   `access_state_id` gained an optional `protocol` parameter (default
   `""`, preserving Telnet's exact pre-Phase-12B ID format). SSH/FTP pass
   an explicit `protocol="ssh"`/`"ftp"`, so a failed SSH attempt's nodes
   can never collide with, or block, an unrelated FTP attempt.
7. **`access_state` only on true, complete success.** `AccessParser.parse_structured()`
   (new method; `parse_text` for Telnet is byte-for-byte unchanged) takes
   an explicit `success`/`authenticated` bool from the executor (SSH/FTP
   classify definitively via typed exceptions/response codes — no text
   heuristic). An open port or banner alone never creates `access_state`;
   authenticating but then having the harmless command itself fail never
   creates `access_state` either — only a fully successful, executed
   validation does.
8. **No secret ever reaches result models, reports, episodes, EKG nodes,
   logs, exceptions, `repr()`, or serialized state.** Enforced by
   `CredentialValidationResult` having no password field at all,
   `secret_hint="[redacted]"` on every credential node, and
   `error_detail` strings built from fixed messages or `type(exc).__name__`
   — never `str(exc)` — except FTP's `error_perm` handler, which routes
   the server's own response text through
   `apex_host.security.redaction.redact_session_text()` (P8-S06's sole
   redaction function) before use, in case a server response happens to
   echo back the submitted password.

**Defect found and fixed during this phase (not previously known):**
`apex_host/orchestration/models.py::task_info()` echoed `TaskSpec.params`
verbatim into the public, checkpoint-persisted `ApexGraphState["current_task"]`
field — including the raw plaintext password for telnet/ssh/ftp tasks. This
predates Phase 12B (present since Telnet/Phase 12A) but was surfaced by
this phase's own "never in serialized state" test requirement. Fixed by
masking any `"password"` key by name before the dict enters state. Verified
safe against `RepairEngine` — its own LLM output schema
(`apex_host/planning/repair.py::PlannedTask`) never carries a
`username`/`password` field, so no working repair functionality depended
on the raw value being present in `current_task`.

**Dependency added:** `paramiko>=3.4` (runtime — `ssh_executor.py` imports
it directly) plus `types-paramiko` (dev, for `mypy --strict`). No FTP
dependency was needed — the standard library's `ftplib` was sufficient. No
brute-force/cracking library was added. `uv.lock` regenerated
(`paramiko`, `bcrypt`, `cffi`, `cryptography`, `pynacl`, `invoke`, plus the
`types-paramiko` stub — 8 new packages).

**Files changed (new):** `apex_host/agents/ssh_executor.py`,
`apex_host/agents/ftp_executor.py`, `docs/credential-validation.md`,
`tests/apex_host/test_ssh_executor.py` (29 tests),
`tests/apex_host/test_ftp_executor.py` (27 tests),
`tests/apex_host/test_credential_planner_multiprotocol.py` (17 tests),
`tests/apex_host/test_dispatcher_credential_protocols.py` (15 tests),
`tests/apex_host/test_access_parser_structured.py` (14 tests),
`tests/apex_host/test_credential_validation_security.py` (19 tests) —
121 new tests total.

**Files changed (modified):** `apex_host/graph_ids.py` (optional
`protocol` param, Telnet-compatible default), `apex_host/types.py`
(`CredentialErrorCategory`, `CredentialValidationResult`),
`apex_host/parsers/access_parser.py` (`parse_structured()`, `parse_text`
untouched), `apex_host/planners/credential_planner.py` (multi-protocol
`_CredentialDeterministic.plan()`, deterministic ordering, per-protocol
duplicate guard), `apex_host/planners/capabilities.py` (docstring only —
capability derivation itself was already correct, now documented as
consumed rather than a placeholder), `apex_host/execution/dispatcher.py`
(`ssh_executor`/`ftp_executor` constructor params, `_run_ssh`/`_run_ftp`,
shared `_credential_result_to_tr` disposition mapping),
`apex_host/orchestration/builder.py` (executor construction + wiring),
`apex_host/orchestration/parsing_node.py` (routes `ssh_access`/
`ftp_access` to `parse_structured`), `apex_host/orchestration/memory_node.py`
(new `credential_validation_log` accumulation), `apex_host/orchestration/models.py`
(password-redaction fix above), `apex_host/graph_state.py` (new
`credential_validation_log` additive field), `apex_host/policy/rules.py`
(`check_bounded_credential_validation` rule), `apex_host/config.py` (six
new timeout fields: `ssh_connect_timeout_seconds`, `ssh_auth_timeout_seconds`,
`ssh_command_timeout_seconds`, `ftp_connect_timeout_seconds`,
`ftp_login_timeout_seconds`, `ftp_command_timeout_seconds` — no new
credential fields; `--username`/`--password` are reused unchanged across
all three protocols), `apex_host/eval/report.py` (three new additive
`RunReport` fields + text/JSON surfacing), `apex_host/runtime.py` +
`apex_host/eval/run_synthetic_machine.py` (new state-field initialization),
`README.md`, `pyproject.toml`/`uv.lock`.

**Explicitly not changed:** `apex_host/agents/telnet_executor.py` (byte-for-byte
unchanged — the phase's own hard requirement), Docker, Compose, VPN,
GitHub Actions, GHCR, `apex_tool_service` — SSH/FTP validation runs
entirely inside the APEX process via Python libraries, never through the
Kali Tool API or `RemoteToolBackend`, so no infrastructure change was
needed or made.

**Validation (clean-rebuilt `.venv`, Python 3.11.14):**

| Check | Result |
|---|---|
| `uv lock --check` | Pass |
| `uv sync --all-groups` | Pass — 8 new packages |
| `uv run pytest -q` (full) | **3713 passed** (3590 baseline + 121 new + 2 net from Phase 12A test renames), 53 pre-existing warnings — no regressions |
| Focused: SSH executor | 29 passed |
| Focused: FTP executor | 27 passed |
| Focused: CredentialPlanner (multi-protocol) | 17 passed |
| Focused: Dispatcher (SSH/FTP routing) | 15 passed |
| Focused: AccessParser/memory + full-graph | 14 passed |
| Focused: Security invariants | 19 passed |
| `uv run ruff check .` | All checks passed |
| `uv run mypy` | Success — 146 source files |
| `python -m apex_host.eval.run_htb_local --help` | exit 0 |
| `python -m apex_tool_service --help` | exit 0 |
| `git diff --check` | exit 0 |

**Remaining known limitations (documented, not defects):** Telnet/SSH/FTP
only — no RDP/WinRM/SMB/database credential validation. One credential
pair per protocol per engagement — no rotation. Password authentication
only for SSH — no key-based auth (no key-reference model existed in the
repository's authorized configuration surface to extend). The duplicate
guard is scoped to `protocol + target + username`, not port-sensitive — a
documented, deliberate consistency choice with Telnet's own original,
tested scoping. No privilege escalation, payload execution, flag capture,
or persistent shell access was added — `access_state` remains the
engagement's terminal success signal, exactly as it was before this phase.
