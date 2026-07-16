# memfabric + apex_host — Unified Memory Fabric, Coordination Substrate & APEX Host Application

`memfabric` is a domain-agnostic, typed memory substrate for long-horizon
multi-agent systems, plus the blackboard coordination layer that sits on top
of it. `apex_host` is the cybersecurity host application built on top of it —
see [APEX Host Layer](#apex-host-layer) below.

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Host Application                         │
│   Executor  ·  Planner  ·  Parser  ·  Embedder  ·  Reranker   │
└────────────────────────┬────────────────────────────────────────┘
                         │  (Protocol seams — host supplies these)
┌────────────────────────▼────────────────────────────────────────┐
│                      MemoryAPI  (api.py)                        │
│  The only way to touch state.  All components go through here.  │
├────────────────────────────────────────────────────────────────-┤
│  Four-tier fabric                                               │
│  ┌───────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐  │
│  │  Working  │  │ Episodic │  │ Semantic  │  │ Procedural │  │
│  │  (EKG)   │  │  (JSONL) │  │ (promoted │  │ (promoted  │  │
│  │ networkx │  │ log      │  │  knowledge│  │  skills)   │  │
│  └───────────┘  └──────────┘  └───────────┘  └────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  Hybrid Retriever                                               │
│  BM25 → gate → [dense + graph] → RRF fusion → rerank → cache  │
├─────────────────────────────────────────────────────────────────┤
│  Coordination (LangGraph StateGraph)                            │
│  read_context → plan → [abandon?] → dispatch → merge → END     │
│  Orchestrator (loop.py) delegates each turn to the graph        │
├─────────────────────────────────────────────────────────────────┤
│  Reflector (async, off hot path)                                │
│  episodes → chains → generalise → promote / decay / quarantine │
└─────────────────────────────────────────────────────────────────┘
```

---

## Eight design invariants

These are hard constraints, not suggestions.

1. **The Memory API is the only way to touch state.** No component reads or
   mutates a store directly.

2. **Episodic memory is append-only and immutable.** An episode, once
   appended, is never edited or deleted.

3. **Working memory uses upsert with last-writer-wins per field, plus
   provenance.** Every node field carries `confidence`, `source`,
   `first_seen`, `last_seen`. Provenance is recorded per field in
   `_provenance`.

4. **Semantic and procedural writes are proposals, not commits.** A
   `propose_*` call stages an entry. It does **not** become retrievable
   until the Reflector promotes it through the quality gate.

5. **Context is retrieved and scoped, never accumulated.** Every invocation
   gets a freshly retrieved, bounded `EvidenceBundle`.

6. **Executors are stateless.** All durable state lives in the fabric.

7. **No agent-to-agent calls.** Coordination is exclusively through the
   fabric (blackboard model).

8. **Provenance and confidence travel with every claim.** Conflicting
   high-confidence claims surface as a `Conflict` the orchestrator must
   resolve.

---

## Development environment (uv)

[`uv`](https://docs.astral.sh/uv/) is the required dependency and
Python-environment manager for this repository. `pyproject.toml` is the
authoritative dependency declaration; `uv.lock` is the committed, reproducible
lock file. Do not use `pip install`, `venv`, or `poetry` directly — all
environment setup goes through `uv`.

**Supported Python version:** 3.11 (`requires-python = ">=3.11"` in
`pyproject.toml`, pinned to `3.11` via `.python-version` so `uv` always
selects a 3.11 interpreter rather than whatever `python3` happens to resolve
to on `PATH`). `mypy` is likewise configured for `python_version = "3.11"`.

### Installing uv

```bash
# macOS (Homebrew)
brew install uv

# Or via the official installer (macOS/Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

See the [uv installation docs](https://docs.astral.sh/uv/getting-started/installation/)
for Windows and other options.

### Clean environment setup

```bash
git clone <repo-url>
cd apex   # or wherever the repo lives
uv sync --all-groups
```

`uv sync --all-groups` reads `uv.lock`, downloads Python 3.11.14 automatically
if it isn't already installed, creates `.venv/`, and installs the runtime
dependencies plus every group under `[dependency-groups]` (currently just
`dev`: pytest, pytest-asyncio, mypy, ruff, and type stubs). The package itself
(`memfabric`, which also ships `apex_host`) is installed editable, so local
source edits are picked up immediately with no reinstall step.

To install only runtime dependencies (no dev tooling):

```bash
uv sync --no-dev
```

### Running commands

Prefix any command with `uv run` to execute it inside the managed
environment — no manual `source .venv/bin/activate` required (though that
still works if you prefer it):

```bash
# Tests
uv run pytest -q

# Ruff (lint)
uv run ruff check .

# mypy (type check — scoped to memfabric + apex_host via [tool.mypy] files)
uv run mypy

# Main APEX CLI
uv run python -m apex_host.eval.run_htb_local --help
uv run python -m apex_host.main --help
```

> **Note on `mypy` scope:** run `uv run mypy` (no path argument) rather than
> `uv run mypy .`. The bare form uses the `files = ["memfabric", "apex_host"]`
> scope already declared in `[tool.mypy]` in `pyproject.toml` — the project's
> long-standing, documented type-check target. Passing `.` explicitly
> overrides that config and makes mypy walk the entire repository tree,
> including the vendored, gitignored `Knowledge/` reference corpus (GTFOBins,
> LOLBAS, PayloadsAllTheThings, SecLists), which is not part of this
> project's source and is not type-checkable (`mypy .` fails immediately with
> `Knowledge/payload_db/GTFOBins/linter/__main__.py:1: error: No parent
> module`). This is pre-existing repository content, not a defect introduced
> by dependency migration.

### Refreshing the lock file

After intentionally adding, removing, or changing the version constraint of a
dependency in `pyproject.toml`:

```bash
uv lock            # recompute uv.lock
uv sync --all-groups   # apply it to .venv/
```

To verify the committed lock file is still up to date with `pyproject.toml`
(e.g. in a pre-commit check or CI step) without modifying anything:

```bash
uv lock --check
```

Commit the updated `uv.lock` alongside the `pyproject.toml` change.

---

## Memory API surface

```python
class MemoryAPI:
    # --- read ---
    async def query(self, *, text, subgraph_anchor, tiers, k, filters) -> EvidenceBundle
    async def get_subgraph(self, anchor_node, depth, edge_types) -> SubgraphView

    # --- working memory (EKG): per-field LWW upsert ---
    async def upsert_node(self, node: Node) -> str
    async def upsert_edge(self, edge: Edge) -> str

    # --- episodic: append-only ---
    async def append_episode(self, episode: Episode) -> str

    # --- staged proposals (Reflector gates these) ---
    async def propose_knowledge(self, entry: KnowledgeEntry) -> str
    async def propose_skill(self, skill: Skill) -> str

    # --- derived state (live view, never stored) ---
    async def open_tasks(self) -> list[OpenTask]
```

---

## Host-app extension seams (Protocols)

The substrate is domain-agnostic.  Real implementations are supplied by the
host application through these Protocol boundaries:

| Protocol | Purpose | Substrate ships |
|---|---|---|
| `Executor` | Stateless work unit; returns EKG deltas + Episode | `EchoExecutor` test fake |
| `Planner` | Decomposes a Goal into TaskSpecs | `StaticPlanner` test fake |
| `Parser` | Turns raw tool output into EKG deltas | `PassthroughParser` fake |
| `Embedder` | Text → dense vector | `StubEmbedder` (raises if used) |
| `Reranker` | Cross-encoder rerank | `PassthroughReranker` (no-op) |
| `GraphMatcher` | Structural EKG pattern match | `TextGraphMatcher` (token overlap) |
| `GraphStore` | EKG persistence | `NetworkXGraphStore` (in-memory) |
| `EpisodicStore` | Append-only event log | `JSONLEpisodicStore` (file/memory) |
| `LexicalIndex` | BM25 full-text index | `BM25LexicalIndex` |
| `VectorIndex` | Dense ANN index | `FaissVectorIndex` |
| `KVStore` | Retrieval cache | `InMemoryKVStore` |

The coordination loop is a **LangGraph StateGraph** (`graph_loop.py`).
`TurnState` holds only generic substrate types; `MemoryAPI`, `Scheduler`,
`Executor`, and `Planner` are injected as closures — never stored in state.
Each turn writes a checkpoint to a `MemorySaver` keyed by `thread_id`; use
`await orch.last_graph.aget_state({"configurable": {"thread_id": tid}})` to
inspect the post-turn state.

**Executors, parsers, embedders, rerankers, and seed knowledge/skill content
are always supplied by the host application.  The substrate ships none.**

---

## Quick start

```python
import asyncio
from memfabric.api import MemoryAPI
from memfabric.config import Config
from memfabric.stores.graph_networkx import NetworkXGraphStore
from memfabric.stores.episodic_jsonl import JSONLEpisodicStore
from memfabric.stores.lexical_bm25 import BM25LexicalIndex
from memfabric.stores.vector_faiss import FaissVectorIndex
from memfabric.stores.kv_memory import InMemoryKVStore
from memfabric.retrieval.engine import HybridRetriever
from memfabric.retrieval.protocols import StubEmbedder, PassthroughReranker, TextGraphMatcher

async def main():
    cfg = Config()
    lexical = BM25LexicalIndex()
    vector  = FaissVectorIndex(dim=cfg.vector_dim)
    kv      = InMemoryKVStore()
    graph   = NetworkXGraphStore()

    api = MemoryAPI(
        graph=graph, episodic=JSONLEpisodicStore(),
        lexical=lexical, vector=vector, kv=kv, config=cfg,
    )

    retriever = HybridRetriever(
        lexical=lexical, vector=vector,
        embedder=StubEmbedder(),      # swap for a real embedder
        reranker=PassthroughReranker(),
        graph=graph, graph_matcher=TextGraphMatcher(),
        kv=kv, config=cfg,
    )
    api.set_retriever(retriever)

    # Plug in host-app executors/planners and run the orchestrator loop

asyncio.run(main())
```

See `examples/smoke_run.py` for a complete end-to-end demonstration.

---

## Running tests

```bash
uv run pytest -v
```

2668 tests total (as of 2026-07-14 Phase 11 final verification): the `tests/` directory
covers all Section 8 memfabric invariants (including LangGraph-specific tests in
`tests/test_graph_loop.py`) plus:
- 17 concurrency/atomicity/defensive-copy tests in `tests/test_graph_atomicity.py`
- 51 transaction-correctness tests in `tests/test_graph_transaction_complete.py`
  (reader isolation, commit/index/cache coherence, rollback integrity, proposal
  staging isolation, public deletion API, defensive copies, architecture scan,
  episode contract)
- 40 Phase 1 re-open correction tests in `tests/test_graph_phase1_extended.py`
  (deep copy isolation at all nesting depths, query snapshot Option C contract,
  pre-batch snapshot completeness, episode capability pre-check, rollback-failure
  injection, repository-wide architecture scan, `_graph_lock` holders table)
- 7 deterministic stress tests in `tests/test_graph_stress.py`
  (100+ concurrent writers, mixed readers/writers, LWW correctness, write-clock
  monotonicity, open-tasks consistency under concurrent writes)
- 117 Phase 4 retrieval and cache correctness tests in `tests/test_retrieval_phase4.py`
  (gate Option A+, complete SHA-256 cache-key schema, cache invalidation events,
  deep-copy immutability, k validation, RRF determinism, diagnostics, identifier
  channel, channel soft/hard failures, index_generation advancement)
- 96 Phase 5 Reopen tests in `tests/apex_host/test_phase5_reopen.py`
  (`BudgetReservation` lifecycle, concurrent atomic reservation, gateway
  exclusivity architecture scans, `RepairRequest` structure, fail-closed guard,
  sanitize/check_prompt/check_output content-safety checkpoints, `LLMCallStatus`
  properties)
- 126 Phase 6 dispatcher tests in `tests/apex_host/test_phase6_dispatcher.py`
  (`ExecutionDisposition` properties, `classify_retry`, `ErrorCategory`,
  `TaskRegistry` atomicity and snapshot/restore, `TaskDispatcher` policy/conflict/
  duplicate gates, executor routing, SHA-256 fingerprint, F06–F13 regression guards)
- 131 Phase 7 async responsiveness tests in `tests/apex_host/test_phase7_async.py`
  (event-loop heartbeat, BM25 thread offload, JSONL concurrent append, SIGTERM
  grace period, browser launch timeout, atomic file write, config timeout fields,
  `aclose()` idempotency, compiled loader async, bounded concurrency, cancellation
  propagation, F15/F16 regression guards, lock duration, `async_utils` helpers)
- 80 Phase 8 secret-redaction and graph-representation tests in
  `tests/apex_host/test_phase8_redaction.py`
  (REDACT — central module constants and recursive redact_value/dict/session_text;
  CANARY — canary password never survives into EKG node props, episodic log, or
  episode.data; BOUND — secret_hint always REDACTED_PLACEHOLDER, live stdout
  always SESSION_REDACTED_PLACEHOLDER with stdout_length metadata; GRAPH_ID —
  all canonical builder functions host_id/service_id/tech_id/credential_id/etc.;
  URL — normalize_url strips default ports, lowercases, deduplicates equivalent
  URLs; PAR — parallel edges between same node pair both visible via
  get_edges_for_node; DANGLE — put_edge rejects missing from_id or to_id;
  SCHEMA — EKG_SCHEMA_VERSION="1" in every export_ekg output; ARCH — AST scan
  confirms no hard-coded "[redacted]" strings in source, no inline ID f-strings
  in parsers; INT — full nmap→EKG + access→EKG pipeline with canonical IDs)
- 80 Phase 9 shared-state boundaries and canonical configuration tests in
  `tests/apex_host/test_phase9_config.py`
  (CFG — ApexConfig field defaults, to_safe_dict password redaction, schema version,
  mutation isolation; CLI — parse_args defaults, from_cli_args round-trip, llm_provider
  safe default end-to-end; ENV — no env vars required, no API key fields, OS isolation;
  STATE — ApexGraphState/TurnState field names, operator.add semantics, serialisability,
  no infra objects in state; SERIAL — JSON serializability, password redaction,
  field count alignment; ARCH — no inline ID f-strings, no api._ private access,
  no in-place state mutations, source-level defaults; E2E — dry_run preserved through
  CLI, canonical IDs in seeded EKG, to_safe_dict on real config)

- 120 Phase 10 orchestration decomposition tests in
  `tests/apex_host/test_phase10_orchestration.py`
  (CHAR — characterization of each node's observable behaviour; BUILD — graph
  construction, wiring, node topology; ROUTE — pure routing-function correctness;
  COMP — outcome_for/is_repairable/should_complete pure functions; MODEL —
  make_pd_entry/task_info helpers; DEPS — OrchestrationDeps and build_planners;
  ARCH — module boundaries, file structure, no-state-in-deps; PAR — new graph
  matches original behaviour; E2E — full dry-run engagement; FIX — F06/F07/F08/
  F09/F13 regression fixes)

- 50 Phase 11 final verification tests in `tests/test_final_verification.py`
  (GRAPH — transaction atomicity, LWW, episodic immutability, provenance, rollback;
  CONFLICT — open conflict blocks, resolution lifecycle, field detection, budget;
  SKILL — staging promotion, decay, quarantine, merge via API;
  RETRIEVAL — gate open/close, cache key coverage, mutation invalidation, tier bounds;
  LLM — gateway architecture, budget atomicity, guard block, redaction;
  EXEC — task registry dedup, policy gate wiring, repair exclusions, parser failure;
  ASYNC — event loop heartbeat, async write, task cancellation, executor timeout;
  SECRET — sanitization, canary redaction, parallel edges, canonical IDs, schema version;
  CONFIG — safe defaults, from_cli_args parity, store bypass scan, file header scan;
  INTEG — dry-run engagement, staging gate, all CONFIRMED findings verified fixed)

while `tests/apex_host/` covers the full host application layer — parsers,
planners, executors, knowledge seeding, policy enforcement, LLM wiring, and
the complete engagement graph.

> **Note for contributors:** the count grows as new findings are remediated.
> Run `uv run pytest --collect-only -q | tail -1` for the current count.

---

## Atomic Graph Updates and Transaction Visibility

All graph writes in `MemoryAPI` are serialised through `_graph_lock`
(`asyncio.Lock`), eliminating the TOCTOU race where concurrent async
coroutines could interleave between a `get_node`/`get_edge` read and the
paired `put_node`/`put_edge` write. The lock is also acquired by all reader
paths (`query()`, `get_subgraph()`, `open_tasks()`) so that no reader ever
observes a partially-written batch (Design A — reader isolation).

### Transaction model

`apply_deltas(nodes=..., edges=..., episodes=..., knowledge=..., skills=...)` is
the atomic batch-write surface. All writes in a batch succeed together or none
are visible: nodes first, then edges, then episodes, then knowledge and skill
proposals. A failure at any step triggers a full rollback of everything committed
in that batch, and the cache is busted so stale results cannot be returned.

The lock nesting order is inviolable (must never be reversed):
`_graph_lock` → `_staging_lock` → `GraphStore._lock`

Internal helpers (`_upsert_node_locked`, `_upsert_edge_locked`,
`_delete_node_locked`, `_delete_edge_locked`, `_rollback_locked`) require the
caller to hold `_graph_lock`. They call `self._graph.*` directly — never the
public `MemoryAPI` methods — to avoid deadlock (asyncio.Lock is not reentrant).

### Per-field LWW with `logical_version`

`_write_clock` is a monotonic counter incremented at the start of every
`upsert_node` / `upsert_edge` call. `logical_version` is the primary ordering
key for last-writer-wins field merges — wall-clock timestamps are observational
metadata only. Two concurrent writers updating disjoint fields on the same node
both survive: the second writer reads the first writer's committed state and
merges field-by-field on top of it.

### Reader isolation guarantee

Three reader paths previously lacked `_graph_lock` and could observe partial
batch state (Phase 1 Comprehensive fix):

- `query()` — subgraph attachment now under `_graph_lock`
- `get_subgraph()` — acquires `_graph_lock` for the full graph traversal
- `open_tasks()` — acquires `_graph_lock` for the node + edge enumeration

In the single-process asyncio runtime, a reader coroutine that starts after a
writer releases the lock always sees the complete committed batch state. A reader
that starts while the writer holds the lock blocks at `async with _graph_lock:`
until the writer finishes — partial state is never observable.

### Rollback behavior

A failed `apply_deltas` batch:
1. Restores `_write_clock` to its pre-batch value (first action — preserves
   `logical_version` ordering across retries).
2. Removes any newly-created nodes and edges from the graph store, lexical
   index, and vector index (via `_delete_node_locked` / `_delete_edge_locked`).
3. Restores the pre-batch snapshot for any node or edge that was updated (not
   newly created) by the failed batch.
4. Rolls back episode appends via `_pop_episodes` (called through `getattr`
   on the `JSONLEpisodicStore` — the standard `EpisodicStore` Protocol
   does not expose this method to prevent accidental misuse).
5. Removes staged knowledge and skill proposals added in the failed batch.
6. Busts the retrieval cache (`kv.delete_prefix("retrieval:")`) so stale
   cached results from the failed batch are not served.

Earlier committed writes on the same nodes are preserved — rollback is
limited to the failed batch.

### Deletion API

`MemoryAPI.delete_node(node_id)` and `MemoryAPI.delete_edge(edge_id)` are the
public deletion surface. Each acquires `_graph_lock`, calls the corresponding
locked helper (which removes the entry from the graph store, lexical index, and
vector index), then busts the retrieval cache. Callers must not call store
methods directly.

### Defensive copies

`NetworkXGraphStore.get_node`, `get_edge`, `get_subgraph`, `all_nodes`,
`all_edges` return copies of stored objects via `_copy_node` / `_copy_edge`
helpers. Callers can freely mutate the returned `props` dict without corrupting
stored state.

### Episode contract

`JSONLEpisodicStore.append` is append-only and never mutates existing records.
`_pop_episodes` is a private rollback method not exposed on the `EpisodicStore`
Protocol. It is called only by `_rollback_locked` via `getattr` — not by any
other code path.

### Architecture bypass scan

`tests/test_graph_transaction_complete.py::test_g01` performs an AST-level scan
of every production `memfabric/` source file and fails if any file outside
`api.py` and `graph_networkx.py` calls store mutation methods (`put_node`,
`put_edge`, `delete_node`, `delete_edge`, `append`) directly. This is the
authoritative check that Invariant 1 (MemoryAPI is the sole state surface) holds
across the entire substrate.

### Single-process scope

`_graph_lock` is an `asyncio.Lock` (cooperative multitasking, same event loop
only). The reader isolation guarantee above applies within a single process.
Multi-process deployments must replace `_graph_lock` with a distributed advisory
lock (e.g. Redis `SETNX`) backed by the same durable graph store.

---

## Sensitive Data Handling

All credential material is kept out of the EKG and episodic log by three
graduated mechanisms:

| Layer | What | Where |
|---|---|---|
| `REDACTED_PLACEHOLDER = "[redacted]"` | `credential.secret_hint` on every EKG node | `apex_host.security.redaction` |
| `SESSION_REDACTED_PLACEHOLDER = "[session_redacted]"` | Live telnet session raw stdout in episodic log | `apex_host.security.redaction` |
| `redact_session_text(text, passwords)` | Arbitrary session text before storage in `access_state.evidence` | `apex_host.security.redaction` |

**Rule:** `apex_host.security.redaction` is the sole source of these constants
and functions.  No other `apex_host` source file may contain the string literals
`"[redacted]"` or `"[session_redacted]"` as code constants.  Import them by name.

`TelnetExecutor` stores `stdout_length` and `shell_found` metadata alongside
`SESSION_REDACTED_PLACEHOLDER` so debugging information survives without leaking
credential content.

---

## Graph Identity and Relationships

### Canonical ID builders (`apex_host/graph_ids.py`)

Every EKG node and edge ID is constructed by a function in `apex_host/graph_ids.py`.
No inline f-strings are permitted in parsers.

| Function | Returns | Example |
|---|---|---|
| `host_id(ip)` | `"host:{ip}"` | `"host:10.0.0.1"` |
| `service_id(host, port, proto)` | `"service:{host}:{port}/{proto}"` | `"service:10.0.0.1:22/tcp"` |
| `tech_id(host, name)` | `"tech:{host}:{slug}"` | `"tech:10.0.0.1:openssh"` |
| `credential_id(host, user, protocol="")` | `"credential:{host}:{user}[:{protocol}]"` | `"credential:10.0.0.1:root"` (Telnet, unchanged) / `"credential:10.0.0.1:root:ssh"` |
| `access_state_id(host, user, protocol="")` | `"access_state:{host}:{user}[:{protocol}]"` | `"access_state:10.0.0.1:root:ssh"` |
| `endpoint_id(url)` | `"endpoint:{normalized_url}"` | `"endpoint:http://host/login"` |
| `auth_flow_id(url)` | `"auth_flow:{normalized_url}"` | `"auth_flow:http://host/login"` |

Tech nodes are host-scoped (`tech:{host}:{slug}`) so the same software found on
two different hosts produces distinct EKG nodes.

### URL normalization (`normalize_url`)

`normalize_url(url)` produces canonical URLs for deduplication:
- Lowercases scheme and host
- Strips default ports (`:80` from `http://`, `:443` from `https://`)
- Collapses double slashes in paths
- Strips trailing `/` from non-root paths

Two equivalent URLs (`http://host:80/path/` and `http://host/path`) produce
the same `endpoint_id` and therefore the same EKG node.

### Parallel edges and dangling-edge prevention

`NetworkXGraphStore.get_edges_for_node()` reads from the internal `_edges` dict
(not NetworkX iterators), so ALL edges between any node pair are visible —
including multiple edge types between the same source and target.

`NetworkXGraphStore.put_edge()` validates that both `from_id` and `to_id` exist
as nodes before writing the edge, raising `ValueError` with a diagnostic message
if either is missing.  This prevents dangling edges from entering the graph.

### EKG schema versioning

`export_ekg()` always includes `"schema_version": "1"` as the first key in the
returned dict.  The version constant is `apex_host.graph_ids.EKG_SCHEMA_VERSION`.

---

## Reliability Remediation Status

> **Important:** The architecture documentation (CLAUDE.md, this README, and
> the architecture doc) describes the *intended* invariants of the system.  Only
> invariants that are covered by a passing test in `tests/` should be treated as
> implementation-verified guarantees.  The remaining invariants are design goals
> being enforced progressively through the remediation program below.

A Phase 0 audit (2026-07-13) identified **21 findings** across 5 repair phases.
Phase 1 is complete; Phases 2–5 are open.  All findings are documented in
[`docs/reviewer_findings_audit.md`](docs/reviewer_findings_audit.md).
The full traceability matrix is in [`docs/remediation_traceability_matrix.md`](docs/remediation_traceability_matrix.md).
The validation baseline is in [`docs/remediation_validation_baseline.md`](docs/remediation_validation_baseline.md).
The remediation roadmap and 12 binding rules are in `CLAUDE.md` Section 21.

**Fixed (Phase 1 + Phase 1 Comprehensive):**

| Area | Finding(s) | Status |
|---|---|---|
| `memfabric` cache | F01 — `_cache_key` excluded `k`; different-sized requests shared cache entry | **FIXED** |
| `memfabric` rollback | F02, F19 — `apply_deltas` rollback did not restore `_write_clock` | **FIXED** |
| Reader isolation | (new) — `query()`, `get_subgraph()`, `open_tasks()` could observe partial batch state | **FIXED** |
| Deletion API | (new) — no public `delete_node`/`delete_edge` on `MemoryAPI` surface | **FIXED** |
| Rollback completeness | (new) — rollback used direct store calls, bypassing locked helpers | **FIXED** |
| TOCTOU race | (new) — concurrent field-merge could lose writes without `_graph_lock` | **FIXED** |
| Defensive copies | (new) — `NetworkXGraphStore` returned live internal objects | **FIXED** |

**Open findings by area:**

| Area | Finding(s) | Severity | Repair Phase |
|---|---|---|---|
| LLM budget | F03, F04 — `RepairEngine` bypasses `LLMBudgetTracker`; tracker not injected | Medium | 2 |
| LLM planning | F05 — `_context_hash` too coarse; false "repeated context" skips valid LLM calls | Low | 2 |
| LLM guard | F14 — `LLMPolicyGuard` not wired into `build_apex_graph` by default | Low | 2 |
| Graph routing | F06 — `route_after_write` only checks first task result in multi-task turns | Medium | 3 |
| Graph routing | F07 — browser episode outcome reads stale `state["last_error"]` | Medium | 3 |
| Graph routing | F08 — `reflect_or_continue` peek omits `current_phase` from `decide_phase` | Low | 2 |
| Graph safety | F09 — `asyncio.gather` in `_run_tasks` lacks `return_exceptions=True` | Medium | 3 |
| Parser idempotency | F10, F11 — `NmapParser` and `AccessParser` edge IDs not deterministic | Low | 3 |
| Episodic log | F13 — duplicate-skip tasks written as `Outcome.success` episodes | Low | 3 |
| Planner efficiency | F12 — `CredentialPlanner` calls `capabilities_from_subgraph` twice per `plan()` | Low | 4 |
| Documentation | F17 — README test count stale (corrected to 1311 at Phase 0; 1328 at Phase 1; 1386 at Phase 1 Comprehensive; 1426 at Phase 1 re-open) | Info | 10 |
| Tooling | F18 — no test enforces the file-header convention (CLAUDE.md §12.6) | Info | 4 |
| Conflict invariant | F20 — `dependents_blocked_by()` is implemented but never called in planner/query paths | Medium | 5 |
| Reflector invariant | F21 — Reflector directly mutates staged Skill objects, bypassing `MemoryAPI` | Low | 5 |

None of the open findings affect the safety invariants (`dry_run=True` default,
no subprocess outside `runner.py`, `policy_enabled=True` by default). The
`MemoryAPI`-as-sole-state-surface invariant has one known exception (F21) in
the Reflector skill-merge path; it does not affect correctness in the cooperative
asyncio runtime but is a documented invariant violation that must be fixed in
Phase 5.

---

## APEX Host Layer

`memfabric` remains the generic substrate — it knows nothing about
cybersecurity. `apex_host/` is the APEX-specific cybersecurity application
built entirely on top of it, occupying exactly the extension seams
`memfabric` reserves for host applications (`Executor`, `Parser`, `Planner`,
identifier-pattern config, seed knowledge). No cyber-specific code lives in
`memfabric`; full detail is in `CLAUDE.md` Section 11.

```
apex_host/
├── main.py / runtime.py / graph.py / graph_state.py / config.py / types.py
├── llm/         # ModelRouter (LangChain) — pluggable, defaults to a fake
├── planners/    # rule-based today; implement memfabric's Planner Protocol
├── agents/      # implement memfabric's Executor Protocol
├── parsers/     # turn tool output into memfabric Node/Edge deltas
├── tools/       # safety.py (allowlist + destructive-command block) +
│                # runner.py (the ONLY place a subprocess may be spawned)
├── knowledge/   # payload-repo RAG seed loader (stages via propose_knowledge)
└── eval/        # synthetic-machine evaluation harness (no real network)
```

**Multi-agent orchestration uses a second, separate LangGraph** —
`apex_host/graph.py` — distinct from `memfabric`'s generic one-turn
`graph_loop.py`. It's a multi-turn, multi-phase engagement workflow:

```
START → load_context → global_plan → route_phase
      → [recon_agent | web_agent | browser_agent | execute_agent | priv_esc_agent]
      → parse_observation → write_memory → reflect_or_continue
      → END  (or loop back to load_context)
```

`ApexGraphState` holds only JSON-serializable primitives — never `MemoryAPI`,
tool runner instances, executors, planners, or LLM clients, which are
injected via closures in `build_apex_graph()` exactly as `memfabric` does for
`TurnState`.

**RAG seeding**: `apex_host/knowledge/payload_repo_loader.py` is the seed
source for payload knowledge. It reads an external, host-supplied payload
repository at runtime and stages chunks via `MemoryAPI.propose_knowledge()` —
nothing is promoted until the Reflector clears the staging gate (`memfabric`
Invariant 4 is never bypassed).

**Bounded credential validation (Phase 12B):** APEX can prove — never
guess — that an operator-supplied credential pair works, over Telnet, SSH,
or FTP. Each protocol gets exactly one bounded login attempt per
engagement (no brute force, no credential spraying); a successful
validation is the engagement's terminal success signal (`access_state` in
the EKG). SSH uses [Paramiko](https://www.paramiko.org/) with agent
forwarding and local key discovery disabled; FTP uses the standard
library's `ftplib` in passive mode. Both run only a single fixed harmless
command afterward (`id`/`whoami` for SSH, `PWD`/`NOOP` for FTP) and close
the connection immediately — no file transfer, no persistent session, no
privilege escalation. Full design, safety model, and test strategy:
[`docs/credential-validation.md`](docs/credential-validation.md).

**Safety**: `ApexConfig.dry_run` defaults to `True`. Every command execution
path goes through `apex_host/tools/runner.py`, which checks
`apex_host/tools/safety.py` first (allowlist + unconditional destructive-
command block + shell-metacharacter block) and uses
`asyncio.create_subprocess_exec` only — never `shell=True`. No raw
subprocess calls exist anywhere else in `apex_host`. `BrowserExecutor` only
drives Playwright when `dry_run=False`; in dry-run it returns a synthetic
observation and holds no browser state across calls.

```bash
python -m apex_host.main --target 127.0.0.1 --payload-repo ./payloads --dry-run
```

runs the full engagement end-to-end with **zero real command execution**.

**Tool execution architecture (Infra Phase 2):** `apex_host/tools/backend.py`
defines a `ToolBackend` protocol — `DryRunToolBackend`, `LocalToolBackend`
(wraps the `runner.py` pathway above unchanged), and `RemoteToolBackend`
(a real HTTP client as of Infra Phase 4 — see below). Full design and
trust boundaries live in
[`docs/tool-execution-architecture.md`](docs/tool-execution-architecture.md).

**Kali tool service (Infra Phase 3):** `apex_tool_service/` is a small,
independently deployable, independently tested HTTP service — the future
Kali-container-side execution boundary. Run it locally with
`uv run python -m apex_tool_service`; full API contract, authentication,
allowlist, and validation rules are documented in
[`docs/kali-tool-service.md`](docs/kali-tool-service.md).

**Remote backend wiring (Infra Phase 4):** `RemoteToolBackend`
(`apex_host/tools/remote_backend.py`) now has a real, tested async HTTP
client that speaks `apex_tool_service`'s contract, and backend selection is
centralized: `apex_host.tools.backend.select_runtime_backend(config)` picks
`DryRunToolBackend` / `LocalToolBackend` / `RemoteToolBackend` from
`ApexConfig`, with the binding invariant that `dry_run=True` always
overrides `tool_backend` — dry-run engagements never contact the tool
service. Both `ApexRuntime.run()` and `build_apex_graph()`'s default
construction use this selector automatically; no manual backend injection
is needed for ordinary use. New CLI flags: `--tool-backend
{dry-run,local,remote}`, `--tool-service-url URL`,
`--tool-service-timeout SECS` (on both `apex_host.main` and
`apex_host.eval.run_htb_local`). The bearer token has **no CLI flag** —
set it via `export APEX_TOOL_SERVICE_TOKEN=...` instead (CLI args leak
into shell history and `ps`). **Updated in Infra Phase 6:**
`RemoteToolBackend` has now been verified against a real Dockerized
`apex_tool_service` instance (see the Kali container section below) — what
remains missing is Docker Compose wiring the APEX and Kali containers
together on a shared network, and VPN routing to reach an authorized HTB
target. Full detail: [`docs/remote-tool-backend.md`](docs/remote-tool-backend.md).

**APEX application container (Infra Phase 5):** `docker/apex/Dockerfile`
builds a reproducible, non-root, `uv.lock`-locked image containing
`apex_host` + `memfabric` and only runtime dependencies (no pytest/ruff/
mypy, no Kali tools, no raw knowledge corpora — only the ~49 MB compiled
subset). Build and smoke-test **just this image**:

```bash
docker build -f docker/apex/Dockerfile -t apex:latest .

docker run --rm apex:latest                       # ENTRYPOINT's safe default: 'check' mode
docker run --rm apex:latest exec -- python -m apex_host.main --help
docker run --rm apex:latest id                     # confirms non-root (uid=1000)
```

**Container entrypoint (Infra Phase 9):** the image's `ENTRYPOINT` is
`apex_host.container_entrypoint`, not a bare CLI module — starting the
container with no arguments runs a real, local, network-free `check` pass
(configuration/report-directory/knowledge/policy validation) and exits `0`
or `1` accordingly; it never begins a live engagement merely because the
container starts. Modes: `check` (local-only, the default), `smoke`
(adds a real Kali health check + one harmless `curl --version` through the
real backend), `dry-run` (a full dry-run engagement, `dry_run` forced
`True`), `run` (live — requires both `--no-dry-run` and an explicit
`--confirm-live` CLI flag; there is no environment-variable substitute for
the latter), and `exec` (bypasses the workflow entirely via argv-list
`os.execvp`, e.g. the prior phase's bare `--help` equivalent above). Full
mode reference, preflight check categories, and troubleshooting:
[`docs/container-entrypoint.md`](docs/container-entrypoint.md).

**Kali tool-service container (Infra Phase 6):** `docker/kali/Dockerfile`
builds the real, running counterpart to `apex_tool_service` — an official,
digest-pinned `kalilinux/kali-rolling` image with only the six
allowlist-mapped binaries installed (`nmap`, `curl`, `iputils-ping` →
`ping`, `netcat-openbsd` → `nc`/`netcat`, `telnet` client only), running
the restricted HTTP service as a non-root user. Build and smoke-test it:

```bash
docker build -f docker/kali/Dockerfile -t apex-kali:phase6 .

docker run -d --name apex-kali -p 8080:8080 \
  -e APEX_TOOL_SERVICE_TOKEN=your-local-dev-token \
  apex-kali:phase6

curl -s http://127.0.0.1:8080/health   # no token needed

curl -s -X POST http://127.0.0.1:8080/v1/execute \
  -H "Authorization: Bearer your-local-dev-token" \
  -d '{"tool": "curl", "arguments": ["--version"]}'

docker rm -f apex-kali   # stop and remove
```

No live HTB/VPN target is contacted by any of the commands above — every
one of them talks only to the container's own loopback interface. A real
`apex_host.tools.remote_backend.RemoteToolBackend` client was verified
against a real running instance of this image during Infra Phase 6
(`ToolResult(backend="kali-service", returncode=0, ...)` for a real
`curl --version` execution), closing the "still missing" gap noted above
for Infra Phase 4 — `RemoteToolBackend` has now been exercised against a
real Dockerized service, not just in-process. One notable,
empirically-verified finding: `nmap`'s default/SYN-scan mode does **not**
work unprivileged inside this container (`-sT` is required) — see
[`docs/kali-container.md`](docs/kali-container.md) §5 for the full
capability investigation. Full detail on every installed/excluded tool,
the build design, and all nine parts of this phase's runtime validation:
[`docs/kali-container.md`](docs/kali-container.md).

**Docker Compose integration (Infra Phase 7):** `compose.yaml` wires the
APEX application and Kali tool-service images together on a dedicated,
non-host-published internal network (`apex-internal`) — `apex` reaches
`kali` at `http://kali:8080` by Compose's built-in service-name DNS, and
`kali`'s port 8080 is never published to the host.

**Environment configuration workflow (Infra Phase 8):** `.env.example`
documents every supported variable (tool backend, tool-service limits, LLM
provider, log level, report paths — full reference:
[`docs/environment-configuration.md`](docs/environment-configuration.md)).
The development flow is:

```bash
cp .env.example .env
# Edit .env: generate and set the one required value, APEX_TOOL_SERVICE_TOKEN
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Then start the canonical, safe, target-free setup-verification command
(builds both images, waits for `kali` to report healthy, then runs the
`apex` container's own `ENTRYPOINT` in `smoke` mode):

```bash
docker compose up --build --abort-on-container-exit
```

(`APEX_TOOL_SERVICE_TOKEN=...` may also be set inline on the command line
instead of editing `.env`, exactly as in earlier phases — both work
identically; Compose reads `.env` automatically.)

Clearly, up front:

- **The token must be generated by you** — the value above is a disposable,
  local, non-reusable credential. Never commit `.env` (it is gitignored) and
  never reuse a token you find in documentation or an example.
- **Default Compose behavior validates the whole setup, but never engages a
  target.** `apex`'s default command (Infra Phase 9: `smoke` mode, via the
  container's `ENTRYPOINT`) validates local configuration, the mounted
  report directory, the image's baked-in compiled knowledge, and policy
  configuration, then performs a *real* (not synthetic) Kali `GET /health`
  check and one hardcoded, harmless `curl --version` execution through the
  real `RemoteToolBackend`. It never contacts an HTB target and never
  begins an engagement.
- **`APEX_DRY_RUN=true` is the safe default** for `dry-run`/`run` modes —
  set in `.env.example`, matching `ApexConfig.dry_run`'s own hardcoded
  default. An environment variable can never flip this to `false` by
  itself; real execution always requires the explicit `--no-dry-run` CLI
  flag (CLAUDE.md §13.5), and `run` mode additionally requires an explicit
  `--confirm-live` CLI flag with no environment-variable substitute.
- **No target is contacted** by the default Compose workflow above.
- **HTB VPN integration (Infra Phase 10) is code-complete but not
  live-validated** — a dedicated `vpn` container, an `htb` Compose
  profile, and a network-namespace-sharing design exist and were verified
  with a real Docker environment (missing-profile fail-fast, bounded
  invalid-profile failure, and a mock-VPN namespace test proving Kali is
  reachable through the shared namespace) — but no real HTB profile was
  available during development, so live OpenVPN initialization and real
  target reachability were never tested. See
  [`docs/htb-vpn-container.md`](docs/htb-vpn-container.md) and
  [`docs/htb-vpn-manual-validation.md`](docs/htb-vpn-manual-validation.md)
  for the architecture and the exact remaining steps an operator with a
  real profile must run.
- **Live Meow (or any other machine) execution is not ready** through this
  workflow — that remains a later phase, and requires completing the live
  VPN validation above first.

To run a full dry-run engagement against a placeholder target through
Compose (writes a report to the mounted `./run_reports/`, never contacts
Kali):

```bash
docker compose run --rm apex dry-run --target 10.0.0.1 --export-json /app/run_reports/run.json
```

To validate configuration without starting anything (works on the host or
inside the container, contacts no target, and by default makes no network
call at all):

```bash
uv run python -m apex_host.eval.check_config
# or, equivalently, the container entrypoint's own local-only mode:
docker compose run --rm apex check
```

Full design, every verified runtime-validation command, and the
non-root/capability/security properties:
[`docs/docker-compose.md`](docs/docker-compose.md),
[`docs/environment-configuration.md`](docs/environment-configuration.md), and
[`docs/container-entrypoint.md`](docs/container-entrypoint.md) (the
`check`/`smoke`/`dry-run`/`run`/`exec` mode reference).

**HTB VPN container (Infra Phase 10):** `docker/vpn/Dockerfile` builds a
small, first-party, auditable OpenVPN container that owns the HTB tunnel
and network namespace. A dedicated `htb` Compose profile
(`compose.htb.yaml`, an override merged on top of `compose.yaml`) makes
`kali` share the VPN container's network namespace
(`network_mode: service:vpn`) so its outbound tool traffic uses the
tunnel, while `apex` reaches both Kali's tool API and the VPN container's
own first-party readiness API (`GET /health`, `GET /route-check` — no
FastAPI/uvicorn dependency, stdlib `http.server` only) at
`http://vpn:8080`/`http://vpn:8090`. Only the `vpn` service ever receives
`NET_ADMIN`/`/dev/net/tun`; `apex` and `kali` remain unprivileged and
non-root in every mode, including HTB mode (verified live via `docker
inspect`). The default Compose workflow is completely unaffected — `vpn`
is gated behind `profiles: ["htb"]` and never starts on a bare `docker
compose up`:

```bash
# Default (unaffected by VPN additions):
docker compose up --build --abort-on-container-exit

# HTB mode (requires a real .ovpn profile — see the manual validation doc):
APEX_TOOL_SERVICE_TOKEN=<disposable> APEX_HTB_OVPN_PATH=./secrets/htb.ovpn \
  docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  up --build --abort-on-container-exit
```

A route-check utility (`apex_host/eval/vpn_route_check.py`) answers
"would traffic to this target use the VPN route?" via a no-packet `ip
route get` lookup — manual/operator-invoked only, never called by any
automatic preflight path. **No real HTB profile was available during
development** — the VPN image, missing/invalid-profile fail-fast
behavior, and the network-namespace-sharing mechanism were all verified
against a real Docker environment (including a mock-VPN integration test
proving Kali is reachable through the shared namespace), but live OpenVPN
initialization and real target reachability were never tested. Full
architecture: [`docs/htb-vpn-container.md`](docs/htb-vpn-container.md).
Exact remaining steps for an operator with a real profile:
[`docs/htb-vpn-manual-validation.md`](docs/htb-vpn-manual-validation.md).

**GitHub Actions CI and GHCR publishing (Infra Phase 11):**
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) validates every
pull request and push to the default branch — lock-file check, frozen
dependency install, the full test suite, Ruff, mypy, both Compose
configurations rendered (default and HTB — never starting a real VPN),
and all three images built (never pushed).
[`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml)
re-validates from scratch and then builds and publishes all three images
to GHCR:

```text
ghcr.io/<repository-owner>/apex
ghcr.io/<repository-owner>/apex-kali
ghcr.io/<repository-owner>/apex-vpn
```

— but **only** on pushes to the default branch, `v*` version tags, or
manual dispatch; **never** from a pull request, and never using
`pull_request_target`. Pull-request builds always run with `push: false`
and no GHCR authentication step at all — a fork PR cannot reach the
publishing token or push an image under any circumstance. Default-branch
pushes publish `latest` + a SHA tag; version tags publish the full
semantic-version tag family (`v1.2.3`, `1.2.3`, `1.2`, `1`) + a SHA tag.
Publishing authenticates with GitHub's own built-in `GITHUB_TOKEN` (no
manually created PAT) and always depends on a fresh validation pass
(`needs: [validate]`) — a broken build is never published. **CI never
connects to HTB, never starts the VPN tunnel, and never runs a live APEX
engagement** — every command either workflow runs was reproduced and
verified locally as part of this phase (see
[`docs/github-actions.md`](docs/github-actions.md) for the complete
design, every job/permission/trigger, and the exact GitHub-side steps
still required to prove a real run).

---

## APEX Host Quickstart

### 1. Install dependencies

This project uses [`uv`](https://docs.astral.sh/uv/) as the sole dependency and
environment manager. See [Development environment (uv)](#development-environment-uv)
below for the full setup reference; the short version:

```bash
uv sync --all-groups
```

This creates `.venv/` (Python 3.11, pinned by `.python-version`) and installs
both the runtime dependencies and the `dev` dependency group (pytest, mypy,
ruff, type stubs) from `uv.lock`. Prefix all commands below with `uv run`
(e.g. `uv run python -m apex_host.main ...`), or activate the environment
first with `source .venv/bin/activate` if you prefer not to type `uv run`
every time.

Install local tools (macOS with Homebrew):

```bash
brew install nmap ffuf
```

`curl`, `python3`, and `nc` ship with macOS and need no extra install.

### 2. Preflight check

Verify that your allowed tools are in `PATH` before running a live engagement:

```bash
python -m apex_host.main --target <HTB_IP> --preflight
```

This prints a per-tool OK / MISSING table and exits with code 1 if anything
is absent.  Dry-run mode is unaffected by missing tools (no PATH check needed).

### 3. Dry-run engagement (safe default — no real commands)

```bash
python -m apex_host.eval.run_htb_local \
    --target <HTB_IP> \
    --payload-repo ./payloads \
    --dry-run
```

No network traffic is generated.  Tool invocations are simulated, EKG writes
happen, the Reflector runs, and the full report is printed.  Use this to
verify routing logic and phase progression before going live.

Export the run report to JSON for inspection:

```bash
python -m apex_host.eval.run_htb_local \
    --target <HTB_IP> --payload-repo ./payloads --dry-run \
    --export-json ./run_reports/dry_run.json
```

### 4. Live authorized HTB run

> **Authorization required.** Only run with `--no-dry-run` against an
> authorized machine — HTB machines accessed over the official HTB OpenVPN
> connection, or another explicitly authorized lab environment.

```bash
# Connect to HTB VPN first:
#   sudo openvpn --config ~/htb.ovpn

python -m apex_host.eval.run_htb_local \
    --target <HTB_IP> \
    --payload-repo ./payloads \
    --no-dry-run \
    --username root \
    --password "" \
    --export-json ./run_reports/live_run.json
```

All commands are still gated by `apex_host/tools/safety.py` (allowlist +
unconditional destructive-command block) even in live mode.

Export the EKG as JSON after the run:

```bash
python -m apex_host.eval.run_htb_local \
    --target <HTB_IP> --no-dry-run \
    --export-graph ./ekg_snapshot.json
```

### 5. Troubleshooting missing tools

| Symptom | Cause | Fix |
|---|---|---|
| `tool 'nmap' not found in PATH` | nmap not installed | `brew install nmap` |
| `tool 'ffuf' not found in PATH` | ffuf not installed | `brew install ffuf` |
| `AbandonSignal: no web-capable tools` | curl not in `allowed_tools` | `curl` is in the default list; confirm `ApexConfig.allowed_tools` |
| `AbandonSignal: no credentials configured` | a telnet/SSH/FTP capability was found but no `--username` | Pass `--username <user> --password <pass>` |
| Dry-run report shows no EKG nodes | Parser received synthetic output | Expected — dry-run nmap output is not valid nmap XML; use `--no-dry-run` for real parsing |

### 6. Run the test suite

```bash
uv run pytest tests/ -q
```

All tests run in dry-run mode with no network access.

---

## Planning architecture

### Overview

`apex_host/planning/` is the optional LLM planning backend.  It sits between
the rule-based planners and the LLM, implementing a prompt → validate → TaskSpec
pipeline.  The rule-based planners remain fully functional and are registered as
the fallback inside `PlanningEngine` — the LLM is an enhancement, not a dependency.

```
MemoryAPI
  ↓ (EvidenceBundle + SubgraphView)
PlanningEngine.plan(goal, phase, subgraph, evidence)
  │
  ├── ModelRouter.planner_llm() → None?  ──yes──▶ fallback_planner.plan()
  │
  ├── PromptBuilder.build_messages(...)
  │
  ├── llm.invoke(messages)  ──error──▶ fallback_planner.plan()
  │
  ├── Validator.validate(raw, allowed_tools)  ──None──▶ fallback_planner.plan()
  │
  ├── stop_reason?  ──yes──▶ AbandonSignal
  │
  └── _to_task_spec() × N ──▶ list[TaskSpec]
                                  ↓
                              Executor → Parser → MemoryAPI
```

### Modules

| Module | Purpose |
|---|---|
| `planning/models.py` | Pydantic v2 `PlannerOutput` and `PlannedTask` schemas |
| `planning/prompt_builder.py` | `PromptBuilder` — the only place that constructs LLM prompts |
| `planning/validator.py` | `Validator` — safety gate; rejects malformed/unsafe LLM output |
| `planning/engine.py` | `PlanningEngine` — the only caller of `ModelRouter.planner_llm()` |

### `PlannerOutput` structure

```json
{
  "reasoning": "chain-of-thought text (not forwarded to executors)",
  "confidence": 0.85,
  "selected_tasks": [
    {
      "tool": "nmap",
      "args": ["-sV", "-T4", "10.10.10.99"],
      "parser": "nmap",
      "executor_domain": "recon",
      "target": "10.10.10.99",
      "rationale": "Discover open ports and service versions"
    }
  ],
  "rejected_tasks": [],
  "stop_reason": null,
  "next_phase": null
}
```

### Provider configuration

#### No LLM (dry-run / tests)

The default `FakeModelRouter` returns `None` for every role.  `PlanningEngine`
immediately delegates to the fallback planner — no API key, no network, no
latency.

```python
from apex_host.llm.router import FakeModelRouter
from apex_host.planning import PlanningEngine

engine = PlanningEngine(
    model_router=FakeModelRouter(),
    fallback_planner=recon_planner,
    allowed_tools=config.allowed_tools,
    target=config.target,
)
```

#### OpenAI / OpenRouter

```bash
export OPENAI_API_KEY=sk-...
# Optional: point to OpenRouter or any OpenAI-compatible endpoint
export OPENAI_BASE_URL=https://openrouter.ai/api/v1
```

```python
from apex_host.llm.router import OpenAIModelRouter

engine = PlanningEngine(
    model_router=OpenAIModelRouter(config),
    fallback_planner=recon_planner,
    allowed_tools=config.allowed_tools,
    target=config.target,
)
```

`OpenAIModelRouter` reads `OPENAI_API_KEY` and `OPENAI_BASE_URL` from the
environment — API keys are never hardcoded.

### Safety invariants

- `PlanningEngine` is the **only** component that calls `ModelRouter.planner_llm()`.
- Planners **never** construct prompt strings.
- Executors **never** call LLMs.
- `MemoryAPI` is still the **only** state source — `PlanningEngine` does not
  write to any store.
- Any LLM failure triggers the deterministic fallback; the engagement continues.

### Validator rejection rules

| Condition | Result |
|---|---|
| Malformed JSON | Fallback |
| Schema mismatch | Fallback |
| Tool not in `allowed_tools` | Fallback |
| Destructive command (`rm`, `mkfs`, `dd`, …) | Fallback |
| Shell metacharacter in args | Fallback |
| Unknown `executor_domain` | Fallback |

### Running the tests

```bash
uv run pytest tests/apex_host/test_planning_engine.py -v
```

### Type checking

```bash
uv run mypy apex_host/planning/ --strict
```

Expected: `Success: no issues found in 8 source files`

---

## Planner workflow

### How planners interact with MemoryAPI

```
MemoryAPI
  │
  ├── get_subgraph() → SubgraphView
  └── query()        → EvidenceBundle
          │
          ▼
     DomainPlanner.plan(goal, subgraph, evidence)
          │
          ├── model_router=None?  ──yes──▶ _NameDeterministic.plan()  ──▶ list[TaskSpec]
          │
          └── model_router set?  ──yes──▶ PlanningEngine.plan()
                                               │
                                               ├── confidence < threshold?  ──▶ fallback
                                               ├── LLM error?               ──▶ retry → fallback
                                               ├── validator rejection?      ──▶ retry → fallback
                                               └── stop_reason?             ──▶ AbandonSignal
                                                         │
                                                         ▼
                                                   list[TaskSpec]
                                                         │
                                                         ▼
                                                graph.py → Executor → Parser → MemoryAPI
```

### Planner structure

Each domain planner follows the `_<Name>Deterministic` + thin wrapper pattern:

```python
# Without LLM (default — fully deterministic)
planner = ReconPlanner(target, registry)

# With LLM (optional — falls back to deterministic on any failure)
planner = ReconPlanner(
    target, registry,
    model_router=OpenAIModelRouter(config),
    allowed_tools=config.allowed_tools,
    confidence_threshold=0.4,   # from config.planning_confidence_threshold
    max_retries=1,              # from config.max_planning_retries
)
```

### Wiring via `build_apex_graph`

```python
from apex_host.graph import build_apex_graph
from apex_host.llm.router import OpenAIModelRouter

# Deterministic-only (default, safe)
graph = build_apex_graph(api, registry, config)

# LLM-backed planning (opt-in)
graph = build_apex_graph(
    api, registry, config,
    model_router=OpenAIModelRouter(config),
)
```

`config.planning_confidence_threshold` (default `0.4`) and
`config.max_planning_retries` (default `1`) control when the engine
falls back to the deterministic planner.

### GlobalPlanner budget tracking

```python
gp = GlobalPlanner(max_turns=20, phase_budgets={"recon": 6, "web": 5})

# Inside the graph loop:
phase = gp.decide_phase(
    node_types_seen=node_types_seen,
    turn_count=state["turn_count"],
    current_phase=state.get("phase"),  # enables budget force-advance
)
gp.record_turn(phase)  # call after decide_phase
```

When a phase exhausts its budget (`budget_remaining == 0`), `decide_phase`
injects the phase's completion EKG-node type into the decision — forcing
advancement to the next phase even if real tool output hasn't produced that
node type yet.

### Running planner + engine tests

```bash
uv run pytest tests/apex_host/test_planners_with_engine.py -v
```

### Test count

| Test file | Tests |
|---|---|
| `tests/apex_host/test_planning_engine.py` | 47 |
| `tests/apex_host/test_planners_with_engine.py` | 58 |

---

## Phase 5 — Complete LLM Planning Loop

This phase makes the planning loop **fully operational** for authorized
HackTheBox Easy/Medium machines.

### What was added

| Feature | Where |
|---|---|
| `PlanDecision` audit log | `apex_host/planning/models.py` |
| `PlanningEngine.last_decision` | `apex_host/planning/engine.py` |
| `PromptBuilder` findings + candidate_tasks | `apex_host/planning/prompt_builder.py` |
| `RepairEngine` (script_error/fixable repair) | `apex_host/planning/repair.py` |
| `last_decision` on all planner wrappers | `apex_host/planners/*.py` |
| `planner_decisions`, `tool_results`, `repair_count` in state | `apex_host/graph_state.py` |
| Concurrent task execution (`asyncio.gather` + semaphore) | `apex_host/graph.py` |
| `repair_agent` node + `route_after_write` routing | `apex_host/graph.py` |
| Dynamic replanning in `reflect_or_continue` | `apex_host/graph.py` |
| Reflector triggered after engagement | `apex_host/runtime.py` |
| Planner decisions in run report + JSON export | `apex_host/eval/report.py` |
| `config.max_repair_attempts` | `apex_host/config.py` |

### Updated graph topology

```
START → load_context → global_plan ──────────────────────── END (done)
                             │
                      route_phase
                             │
       ┌─────────────────────┴──────────────────────────┐
   recon_agent  web_agent  browser_agent  execute_agent  priv_esc_agent
       └─────────────────────┬──────────────────────────┘
                      parse_observation
                             │
                       write_memory
                             │
                      route_after_write
                       │             │
                  repair_agent    reflect_or_continue ── END
                       │             │
                  reflect_or_continue
                             │
                       load_context (next turn)
```

### Running tests

```bash
# All tests (851 total)
uv run pytest tests/ -q

# LLM wiring tests only
uv run pytest tests/apex_host/test_llm_wiring.py -v

# Repair engine + complete loop tests
uv run pytest tests/apex_host/test_repair_engine.py -v
```

### Enabling the LLM planning layer

The system defaults to fully deterministic mode (no LLM calls, no API key
required). Enable LLM planning via CLI:

```bash
export OPENAI_API_KEY=sk-...

# Via OpenRouter (recommended — access many models with one key)
python -m apex_host.eval.run_htb_local \
  --target <HTB_TARGET_IP> \
  --payload-repo ./payloads \
  --dry-run \
  --use-llm \
  --llm-provider openai \
  --llm-model openai/gpt-5.5 \
  --llm-base-url https://openrouter.ai/api/v1

# Via direct OpenAI API
python -m apex_host.eval.run_htb_local \
  --target <HTB_TARGET_IP> \
  --payload-repo ./payloads \
  --dry-run \
  --use-llm \
  --llm-model openai/gpt-5.5
```

Or in Python:

```python
from apex_host.config import ApexConfig
from apex_host.runtime import build_runtime

config = ApexConfig(
    target="<IP>",
    use_llm=True,
    llm_provider="openai",
    llm_base_url="https://openrouter.ai/api/v1",  # optional; overrides OPENAI_BASE_URL
    planner_model="openai/gpt-5.5",
)
runtime = build_runtime(config)   # wires OpenAIModelRouter automatically
```

When `use_llm=False` (the default) or `llm_provider="fake"`, `FakeModelRouter`
is used — all planners run deterministically with zero API calls or network
traffic. `RepairEngine` is also a no-op in this mode.

### Running an authorized HTB machine (dry-run first, always)

```bash
# Step 1: dry-run verification (safe, no real commands)
python -m apex_host.eval.run_htb_local \
  --target <HTB_TARGET_IP> \
  --payload-repo ./payloads \
  --dry-run

# Step 2: real run (authorized HTB VPN target only)
python -m apex_host.eval.run_htb_local \
  --target <HTB_TARGET_IP> \
  --payload-repo ./payloads \
  --no-dry-run \
  --username root \
  --password ""

# Step 3: real run WITH LLM planning (HTB VPN + OPENAI_API_KEY required)
python -m apex_host.eval.run_htb_local \
  --target <HTB_TARGET_IP> \
  --payload-repo ./payloads \
  --no-dry-run \
  --use-llm \
  --llm-provider openai \
  --llm-model openai/gpt-5.5 \
  --llm-base-url https://openrouter.ai/api/v1 \
  --username root \
  --password ""
```

**Never** run `--no-dry-run` against a host you do not own or have explicit
written authorization to test.

---

## Knowledge Compilation

External threat-intelligence and payload knowledge lives in `knowledge/` and
must be compiled into compact JSONL before APEX can ingest it via the RAG
pipeline.  Three commands cover the full workflow.

### 1. Compile all knowledge families

```bash
python -m apex_host.knowledge.compiler.compile_knowledge \
    --knowledge-root ./knowledge \
    --strict --verbose
```

Reads `knowledge/{intel_db,methodology_db,payload_db,policy_db}/` and writes
nine JSONL / YAML files under each family's `compiled/` directory.  `--strict`
exits 1 if any required output is missing or empty.  A post-compilation
verification pass runs automatically unless `--no-verify` is passed.

Make shortcut:

```bash
make compile-knowledge
```

### 2. Verify compiled outputs

Confirm all nine required outputs exist, are non-empty, contain valid JSON per
line, and include `source_family` + `source_type` in every record:

```bash
python -m apex_host.knowledge.compiler.verify_compiled \
    --knowledge-root ./knowledge
```

Make shortcut:

```bash
make verify-knowledge
```

Exit 0 = all checks passed; exit 1 = one or more files failed.

### 3. Run the full test suite

```bash
uv run pytest tests/ -q
```

Make shortcut:

```bash
make test
```

All tests run with `dry_run=True` (the default) — no real network traffic,
no real command execution, no API keys required.

### Required compiled outputs (nine files)

| # | Family | File | Min records |
|---|---|---|---|
| 1 | `policy_db` | `compiled/policy_records.jsonl` | 1 |
| 2 | `policy_db` | `compiled/hackthebox_lab.yaml` | — |
| 3 | `methodology_db` | `compiled/methodology_chunks.jsonl` | 1 |
| 4 | `intel_db` | `compiled/attack_techniques.jsonl` | 100 |
| 5 | `intel_db` | `compiled/cwe_weaknesses.jsonl` | 100 |
| 6 | `intel_db` | `compiled/capec_patterns.jsonl` | 50 |
| 7 | `intel_db` | `compiled/cve_slim.jsonl` | 1 000 |
| 8 | `payload_db` | `compiled/payload_records.jsonl` | 100 |
| 9 | `payload_db` | `compiled/wordlist_manifest.jsonl` | 10 |

If any file is missing, run `make compile-knowledge` first.
