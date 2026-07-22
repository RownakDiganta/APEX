# APEX‑Nexus (Detailed): A Unified‑Memory, Scalable Agentic Architecture

> Detailed engineering expansion of the APEX‑Nexus proposal. Subsumes all three
> slide proposals (Browser Agent, Hybrid RAG, Hierarchical Planning) and unifies
> them around a single typed **memory fabric** that every agent reads and writes.
> This document keeps the design thesis from the overview and adds component
> specs, data schemas, the control loop, retrieval scoring, the consolidation
> algorithm, scaling math, and a phased rollout + evaluation plan.

---

## 0. TL;DR for the reviewer

- **One substrate, four tiers.** Working (graph world‑model) · Episodic (traces) ·
  Semantic (KB/CVE) · Procedural (skills). Replaces 2 disconnected RAGs + an
  ephemeral Task Tree.
- **Memory is the center, agents are clients.** Blackboard coordination — no
  agent‑to‑agent calls — which is what makes it scale and resume.
- **Context is retrieved, not accumulated.** The 30–40‑turn degradation is solved
  at the root: an agent's context is a scoped subgraph + retrieved evidence, not
  a transcript.
- **Self‑improvement flywheel.** An async Reflector turns episodes into reusable
  skills, so learning compounds within a run and across HTB machines.

---

## 1. Design thesis — why "combine all three" is not enough

The three deck proposals each fix one organ:

| Proposal | Fixes | But ignores |
|----------|-------|-------------|
| Browser Agent | Web blindness | Its discoveries never enrich the knowledge base |
| Hybrid Sparse–Dense RAG | Retrieval misses | Only serves *PayloadsRAG*, not failures/state |
| Hierarchical Planners | Context explosion | Each planner still needs a context *source* |

They share a hidden coupling: **all three are really memory reads and writes.**
A browser observation, a retrieved technique, and a planner's context slice are
the same operation against the same substrate — but in current APEX that
substrate is *fragmented* into PayloadsRAG + Error Path RAG + an ephemeral Task
Tree + per‑agent scratch state. Nothing feeds back into anything else.

**The unifying move:** promote memory to the center of the system and make
planning, retrieval, browsing, and execution all *clients* of one typed memory
fabric. That single change creates the feedback loops none of the three have on
their own — and self‑improvement falls out for free.

---

## 2. Architecture overview

```
                        ┌─────────────────────────────────────────────┐
                        │          UNIFIED MEMORY FABRIC (UMF)        │
                        │                                             │
   write ◀──────────────│  Working   Episodic   Semantic   Procedural │──────────▶ read
   (structured          │  (EKG)     (traces)   (KB/CVE)   (skills)   │  (retrieved,
    observations)       │     ▲          ▲          ▲          ▲      │   scoped context)
                        │     └──────────┴────┬─────┴──────────┘      │
                        │            Hybrid Retrieval +               │
                        │       Graph Traversal + CVE/CWE Regex       │
                        └─────────────────────────────────────────────┘
                              ▲           ▲            ▲          ▲
            ┌─────────────────┘           │            │          └──────────────┐
            │                             │            │                         │
   ┌────────────────┐          ┌──────────────────┐    │  async       ┌────────────────────┐
   │ GLOBAL         │  goals   │  DOMAIN          │    │ consolidate  │  REFLECTOR /       │
   │ ORCHESTRATOR   │─────────▶│  SUB‑PLANNERS    │    │◀─────────────│  CURATOR (offline) │
   │ • kill‑chain   │◀─────────│ Recon│Web│PrivEsc│    │              │ • episodic→skills  │
   │ • phase budget │ findings │  Lateral│Cred    │    │              │ • dedup, confidence│
   │ • merge graph  │          └──────────────────┘    │              │ • decay stale paths│
   └────────────────┘                   │              │              └────────────────────┘
                                        ▼ (tasks)      │
                          ┌────────────────────────────────────────────┐
                          │  STATELESS EXECUTOR POOL (scales out)      │
                          │  Recon    Execute    Browser   (+ future)  │
                          │  Agent     Agent      Agent                │
                          │            │          (Playwright/Chromium)│
                          └────────────────────────────────────────────┘
                                         │
                                    Kali Linux + Target
                                         │
                          structured results ▶ written back to UMF
```

Two layers only: a **Unified Memory Fabric** and an **agentic layer** that all
reads/writes through it. No agent talks to another agent directly — they
coordinate through memory (blackboard model). That is what makes it scale.

### 2.1 Component contract at a glance

| Component | Reads | Writes | Model tier |
|-----------|-------|--------|------------|
| Global Orchestrator | EKG summary view, phase budgets | phase plan, task allocations, merged findings | strong (planning) |
| Domain Sub‑Planner | scoped subgraph + retrieved evidence | candidate tasks, hypotheses, abandon‑signals | strong (planning) |
| Recon Executor | task spec | EKG nodes (hosts/services/endpoints) + episodic trace | cheap/fast |
| Execute Executor | task spec + evidence bundle | EKG edges (vuln/access) + episodic trace | mid |
| Browser Executor | task spec + page goal | EKG nodes (DOM/token/auth) + episodic trace | mid + fast (action selection) |
| Reflector/Curator | episodic + procedural | procedural skills, semantic entries, confidence/decay | strong (offline batch) |

---

## 3. The Unified Memory Fabric (UMF)

One substrate, four cognitively‑grounded tiers, one retrieval interface. Physically:
a graph store (EKG) + a vector index + a sparse/BM25 index + an object store for
raw artifacts, fronted by a single typed **Memory API**.

### 3.1 The Memory API (the only way agents touch state)

```
read:   query(text?, subgraph_anchor?, tiers=[...], k, filters) -> EvidenceBundle
        get_subgraph(anchor_node, depth, edge_types) -> EKG fragment
write:  upsert_node(node), upsert_edge(edge)          # working memory
        append_episode(trace)                         # episodic, immutable
        propose_knowledge(entry)                      # staged → Reflector gates
state:  open_tasks() -> derived from EKG (weaknesses w/o terminal outcome)
```

Two write disciplines matter: **episodic is append‑only and immutable** (an
audit log you can replay), while **working memory (EKG) is upsert** with
last‑writer‑wins per field plus provenance. Semantic/procedural writes are
*proposals* — they do not become retrievable until the Reflector promotes them
(prevents one bad turn from poisoning the KB).

### 3.2 Working memory — the Engagement Knowledge Graph (EKG)
The current Task Tree is replaced by a **typed graph world‑model** of the target:

```
Host ──hosts──▶ Service ──exposes──▶ Endpoint ──vuln──▶ Weakness(CVE/CWE)
  │                │                     │                   │
  │                └──runs──▶ Tech       └──requires──▶ AuthFlow(JS/CSRF/JWT)
  │                                                          │
  └──owns──▶ Credential ──grants──▶ AccessState(user/root, foothold)
                                          │
                                          └──enables──▶ next Host (lateral)
```

Node and edge schema (minimum viable):

```jsonc
Node  { id, type, props{}, confidence: 0..1, source: agent_id, first_seen, last_seen }
Edge  { id, type, from, to, props{}, confidence: 0..1, source }
// types: Host, Service, Tech, Endpoint, AuthFlow, Weakness, Credential, AccessState
```

Planners read a **subgraph**, never a transcript. The Task Tree becomes a *view*
derived from the graph (open `Weakness` nodes with no terminal `AccessState` →
open tasks). **This is the real fix for context explosion:** an agent's context
is bounded by the relevant subgraph size, not by turn count. A 60‑turn engagement
and a 6‑turn one present the same‑sized context if the live attack surface is the
same.

### 3.3 Episodic memory — action traces
Every `(state, action, observation, outcome)` tuple, for **successes and
failures alike**. This subsumes the Error Path RAG but adds the half it was
missing — what *worked*.

```jsonc
Episode {
  id, run_id, turn, agent_id,
  state_anchor: node_id,         // where in the EKG this happened
  action: { tool, args, intent },
  observation: { stdout_ref, parsed{}, ekg_delta[] },
  outcome: "success" | "script_error" | "fixable" | "fundamental",
  lesson?: string,               // free text, only on failures/successes worth keeping
  cost: { tokens, wall_ms }
}
```

The Script/Fixable/Fundamental taxonomy from slide 3 is preserved as the
`outcome` tag — it drives the **repair / retry‑with‑clue / abandon** branch — but
it is no longer a separate store.

### 3.4 Semantic memory — knowledge base
PayloadsRAG + CVE/CWE + MITRE ATT&CK technique mapping, unified. Static seed
knowledge plus anything the Reflector promotes from episodes. Each entry carries
an ATT&CK technique id so retrieval and planning share one ontology.

### 3.5 Procedural memory — distilled skills
The self‑improving core. The Reflector compresses recurring successful episodic
chains into reusable **playbooks**, made retrievable *by graph shape*:

```jsonc
Skill {
  id, name: "Joomla CodeMirror → browser‑driven RCE",
  preconditions: [ {node:"Tech", props:{name:"Joomla", ver:">=4"}},
                   {node:"AuthFlow", props:{type:"JS"}} ],   // matched against EKG
  steps: [ ...ordered action templates... ],
  attack_id: "T1190",
  evidence: { wins, losses, machines[] },     // provenance
  confidence: 0..1
}
```

Because preconditions are EKG patterns, a skill is retrieved when the *shape* of
the current target matches — not when keywords happen to align.

### 3.6 One retrieval interface for all four tiers
The slide‑7 Hybrid Sparse–Dense + CVE/CWE‑regex retriever is **generalized to
serve every tier**, not just payloads:

```
query (+ EKG subgraph as context)
   ├─▶ BM25            (exact identifiers, version strings)      weight wb
   ├─▶ Dense vectors   (semantic exploit families)               weight wd
   ├─▶ Graph traversal (precondition match against EKG)   ◀──new  weight wg
   └─▶ CVE/CWE regex   (identifier lookup)                        weight wr
            │
   Reciprocal‑rank fusion  →  cross‑encoder re‑rank (top‑n only)
            │
     scoped EvidenceBundle  ──▶ requesting agent
```

Scoring detail (keeps it cheap):
- Always run BM25 + regex (cheap, exact).
- Run **dense + graph only when BM25 top‑score < τ** (low‑confidence gate) — most
  exact‑identifier hits never pay for the expensive channels.
- Fuse with reciprocal‑rank fusion (RRF), then cross‑encode just the top‑n for
  final ordering. Cache by `(query_hash, subgraph_hash)`.

Adding **graph traversal** as a fourth channel is the upgrade over slide 7: it
retrieves by *attack‑surface shape* ("an upload endpoint behind JS auth on PHP"),
which keyword/vector search alone cannot express.

---

## 4. Scalable agentic layer

| Role | Count | State | Responsibility |
|------|-------|-------|----------------|
| **Global Orchestrator** | 1 | reads EKG | Kill‑chain phase allocation, per‑phase budget, merges sub‑planner findings into EKG |
| **Domain Sub‑Planners** | N (Recon, Web, PrivEsc, Lateral, Cred) | scoped subgraph | Plan within one domain over a small, domain‑specific context |
| **Executor Pool** | M (horizontal) | **stateless** | Recon / Execute / **Browser** agents; run tools, return *structured* observations |
| **Reflector / Curator** | 1, async | offline | Consolidate episodic→procedural, dedup, assign confidence, decay stale paths |

Key properties:

- **Stateless executors** → scale horizontally and run in parallel; a crash
  loses nothing because state lives in the UMF (engagements become *resumable*).
- **Browser Agent is a first‑class executor**, not a side‑car. Its DOM state,
  CSRF tokens, JWTs, and auth flows are written back as **EKG nodes**, so a
  dynamic discovery immediately feeds retrieval *and* planning. (Slide 5's
  browser agent had no path back into memory — here it does.)
- **Context is retrieved, not accumulated.** Each planner/executor invocation
  gets a freshly retrieved, scoped bundle. This kills the 30–40‑turn degradation
  more fundamentally than hierarchy alone.
- **Model routing / tiered compute:** strong model for the Orchestrator and
  Sub‑Planners; cheap/fast models for parsing, recon triage, and browser action
  selection. Cost scales with reasoning need, not turn count.

### 4.1 The control loop (one turn)

```
1. Orchestrator reads EKG summary → picks the highest‑value open phase
   given remaining budget; allocates a goal to a Sub‑Planner.
2. Sub‑Planner pulls its scoped subgraph + an EvidenceBundle (incl. matching
   Skills) → emits 1..k concrete tasks (or an abandon‑signal).
3. Scheduler dispatches tasks to the Executor Pool (parallel, capped by
   concurrency + per‑phase token budget). Browser tasks → Browser Agent.
4. Each executor runs its tool, parses output to EKG deltas, appends an
   Episode. Failures carry the Script/Fixable/Fundamental tag.
5. Orchestrator merges deltas into the EKG; conflicts resolved by
   confidence + recency. Open‑task view recomputes.
6. Loop. Reflector runs asynchronously off the episodic stream — never blocks
   the loop.
```

### 4.2 Failure handling (slide‑3 taxonomy, wired into the loop)

```
outcome == script_error  → Repair Executor re‑emits a fixed script (same task)
outcome == fixable        → retry with the retrieved "clue" (bounded retries)
outcome == fundamental    → mark Weakness node dead; Sub‑Planner abandons branch;
                            Reflector records an anti‑pattern (negative skill)
```

Negative skills are first‑class: "this shape looks exploitable but isn't, because
X" is retrievable and stops the planner re‑opening dead ends across runs.

### 4.3 Concurrency, budget, and conflict control

- **Concurrency cap** on the executor pool (e.g. min(cores‑2, 16)); excess tasks
  queue. Sub‑Planners run in parallel because their subgraphs are disjoint by
  domain.
- **Per‑phase token budget** enforced by the Orchestrator — a hard ceiling that
  prevents one domain from starving the engagement.
- **EKG conflict resolution:** upsert is last‑writer‑wins *per field* with
  provenance; contradictory high‑confidence claims raise a `Conflict` node the
  Orchestrator must resolve before depending on it.

---

## 5. The self‑improvement flywheel (what none of the three have)

```
Execute ─▶ Episodic trace ─▶ Reflector consolidates ─▶ Procedural skill / Semantic entry
   ▲                                                              │
   └───────────  retrieved next turn (& next run, & next machine) ┘
```

### 5.1 Reflector consolidation algorithm (async, batched)

```
for each completed sub‑chain in the episodic stream:
  if chain.outcome == success and chain.length >= 2:
     candidate = generalize(chain)               # params → typed slots
     match = nearest_skill(candidate)            # vector + precondition overlap
     if match and sim > θ:  merge(match, candidate); match.wins++; bump confidence
     else:                  stage new Skill (confidence = prior)
  if chain.outcome == fundamental:
     stage/strengthen a negative skill (anti‑pattern)

periodically:
  decay confidence of skills unused for > N runs
  quarantine skills whose live win‑rate drops below floor
  promote staged semantic entries that cleared the evidence gate
```

Quality gates are the safety rail: nothing enters retrievable procedural memory
without a minimum evidence count and confidence, and anything that starts losing
in the field decays or is quarantined. This is what stops the flywheel from
poisoning itself.

Because memory is unified and writable by every agent, learning compounds:
browser discoveries enrich the KB, failures and successes both become
retrievable, and skills transfer across HTB machines. Cross‑run learning stops
being a single‑purpose Error‑Path feature and becomes a system‑wide property.

---

## 6. How it beats each slide proposal

| Dimension | Slide proposal | APEX‑Nexus |
|-----------|----------------|------------|
| Web interaction | Browser Agent (isolated) | Browser Agent **whose observations write to the EKG** → feed retrieval + planning |
| Retrieval | Hybrid Sparse–Dense (payloads only) | Same fusion **+ graph‑traversal channel**, serving **all four** memory tiers, low‑confidence‑gated for cost |
| Planning | Hierarchical planners | Hierarchical planners **over a shared graph world‑model**, with retrieved (not accumulated) context |
| Memory | 2 disconnected RAGs + ephemeral tree | **One typed fabric**: working/episodic/semantic/procedural + a single Memory API |
| Learning | Error‑Path RAG (failures only) | **Reflector flywheel**: successes + failures + anti‑patterns → reusable skills, cross‑run, with quality gates |
| Scale / cost | not addressed | Stateless executor pool, resumable engagements, model routing, per‑phase budgets |

---

## 7. Scaling & cost model

- **Context per planner call** is `O(live subgraph + k·evidence)`, independent of
  turn count → flat token cost on long‑horizon machines instead of the current
  super‑linear growth. This is the single biggest cost win.
- **Throughput** scales with executor pool size; the bottleneck moves from "one
  Coordinator's context" to "target‑side tool latency," which is the right place
  for it to be.
- **Retrieval cost** is bounded by the low‑confidence gate (dense/graph only fire
  when BM25 is weak) + cross‑encoding only the top‑n + caching.
- **Compute routing** keeps strong‑model spend on the ~2 planning roles; the
  M executors and parsers run on cheap/fast models.

---

## 8. Phased rollout (each phase independently shippable & measurable)

1. **UMF core + Memory API + EKG** behind current APEX (Task Tree becomes a
   derived view). No behavior change yet — pure substrate swap. *Measure:* parity
   on the 30/42 baseline.
2. **Unified hybrid retrieval** (slide‑7 + graph channel) over the new fabric.
   *Measure:* retrieval accuracy lift (target the slide‑7 ~+10–15%).
3. **Browser Executor** writing observations into the EKG. *Measure:* recover the
   JS/CSRF/SPA machines APEX currently can't reach.
4. **Hierarchical planners** over the EKG with retrieved context. *Measure:*
   long‑horizon (30–40+ turn) machine success + token/turn flattening.
5. **Reflector flywheel** on. *Measure:* cross‑run transfer — success on machine
   *k+1* given lessons from *1..k*.

---

## 9. Evaluation plan

> **Success definition (implementation note, added post-Phase-18 —
> `CLAUDE.md` §23 "Phase 18"):** the general `AccessState(user/root,
> foothold)` model above is preserved unchanged — a foothold or validated
> credential remains a real, tracked graph state. For the *selected HTB
> benchmark* implementation, however, "solving a machine" (and therefore
> the headline success-rate metric below) is mapped specifically to
> **verified retrieval of the machine's user flag** — an `AccessState`
> alone, without a cryptographically confirmed flag read, does not count
> as a solved machine. See `docs/user-flag-objective.md` for the objective
> model, verification mechanism, and EKG representation this maps onto.
>
> **Access-capability abstraction note (added post-Phase-18B —
> `CLAUDE.md` §23 "Phase 18B"):** the access mechanism underlying the
> above is transport-independent, not SSH-specific. A validated login
> produces a generic `AccessCapability` record (capability TYPE, principal,
> confidence — never a password or live session, which live only in a
> runtime-only, non-EKG registry), and the objective-verification flow
> selects among validated capabilities rather than searching for a
> specific protocol. The abstraction exists so a future adapter (Telnet, a
> local shell, a file-read API) requires adding only that adapter, never
> re-deriving the objective/verification model itself. See
> `docs/user-flag-objective.md` §16 for the full design.
>
> **Direct file read capability note (added post-Phase-20 — `CLAUDE.md`
> §23 "Phase 20"):** the abstraction note above predicted exactly this — a
> second capability adapter, `DirectFileReadCapabilityAdapter`, letting the
> objective be satisfied through a generic, bounded, policy-gated direct
> file-read primitive (arbitrary file read, LFI, path traversal, an
> authenticated download endpoint, or an XSS-assisted read) instead of SSH.
> It is not a general-purpose HTTP client: the adapter's only method takes
> a bounded candidate path and substitutes it into one fixed,
> operator-attested request shape — host, port, scheme, endpoint, method,
> headers, and redirect policy are all configuration, never
> task-controlled. `ObjectivePlanner`, `UserFlagExecutor`,
> `ObjectiveParser`, and the report generator required zero changes to
> support the new adapter, confirming the abstraction's own design promise.
> See `docs/user-flag-objective.md` §17 for the full design.

- **Same benchmark as the paper:** the 42 HTB machines; headline metric is the
  71.4% (30/42) success rate — under this implementation, "success" per
  machine means a verified user-flag retrieval, not merely a foothold.
- **Falsifiable claim:** unified memory + graph‑scoped context lifts the **12/42
  machines APEX currently fails** (long‑horizon + JS‑gated), not just the easy
  wins.
- **Ablations** (isolates each contribution): (a) UMF vs split stores; (b) graph
  retrieval channel on/off; (c) browser→EKG writeback on/off; (d) retrieved vs
  accumulated context; (e) Reflector on/off measured by cross‑run transfer.
- **Cost curves:** tokens/turn vs turn number — expect flat (Nexus) vs rising
  (current). Wall‑clock vs executor‑pool size.
- **Memory‑safety:** track procedural‑memory precision (fraction of retrieved
  skills that actually fire correctly) to confirm the gates prevent poisoning.

---

## 10. Risks / honest caveats

- **Graph extraction is the hard part** — turning raw tool output into reliable
  EKG nodes needs a robust parser/normalizer; garbage‑in degrades planning.
  Mitigation: confidence + provenance on every node, `Conflict` nodes for
  contradictions.
- **Reflector quality gates** — bad consolidation could poison procedural
  memory; needs evidence thresholds, decay, quarantine, and negative skills.
- **Retrieval latency** — four channels + cross‑encoder rerank add cost; mitigate
  with the low‑confidence gate, top‑n cross‑encoding, and caching.
- **Coordination correctness** — blackboard + parallel executors introduce
  write‑conflict and staleness risks; the per‑field provenance + confidence
  resolution and append‑only episodic log are the defense.
- **Eval honesty** — improvements must be shown per‑machine and ablated, not as a
  single aggregate number; the easy wins must not mask whether the hard machines
  actually moved.
```
