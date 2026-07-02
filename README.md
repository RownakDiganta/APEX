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
python -m pytest tests/ -v
```

234 tests total: 194 in `tests/` covering all Section 8 invariants (including
LangGraph-specific tests in `tests/test_graph_loop.py`), plus 40 in
`tests/apex_host/` for the host application layer below.

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

---

## APEX Host Quickstart

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

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
| `AbandonSignal: no credentials configured` | telnet cap found but no `--username` | Pass `--username <user> --password <pass>` |
| Dry-run report shows no EKG nodes | Parser received synthetic output | Expected — dry-run nmap output is not valid nmap XML; use `--no-dry-run` for real parsing |

### 6. Run the test suite

```bash
.venv/bin/python -m pytest tests/ -q
```

All tests run in dry-run mode with no network access.
