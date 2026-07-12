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
.venv/bin/python -m pytest tests/apex_host/test_planning_engine.py -v
```

### Type checking

```bash
.venv/bin/python -m mypy apex_host/planning/ --strict
```

Expected: `Success: no issues found in 5 source files`

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
.venv/bin/python -m pytest tests/apex_host/test_planners_with_engine.py -v
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
.venv/bin/python -m pytest tests/ -q

# LLM wiring tests only
.venv/bin/python -m pytest tests/apex_host/test_llm_wiring.py -v

# Repair engine + complete loop tests
.venv/bin/python -m pytest tests/apex_host/test_repair_engine.py -v
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
.venv/bin/python -m pytest tests/ -q
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
