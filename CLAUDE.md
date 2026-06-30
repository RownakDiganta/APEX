# CLAUDE.md — Unified Memory Fabric & Coordination Substrate

This file instructs Claude Code on what to build, how to structure it, and what the
invariants are. Read it fully before writing any code.

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