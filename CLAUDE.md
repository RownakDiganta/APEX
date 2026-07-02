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