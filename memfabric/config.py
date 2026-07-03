# config.py
# Typed Config dataclass holding all tunable thresholds for conflict detection, retrieval gating, Reflector gates, scheduler limits, and vector index dimensions.
"""Typed configuration dataclass.  All tunable thresholds live here;
nothing is hardcoded in module logic."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Config:
    # --- conflict / upsert ---
    conflict_confidence_floor: float = 0.8
    """Both old and new field confidence must be >= this to trigger a Conflict."""

    # --- retrieval gate ---
    low_confidence_tau: float = 0.3
    """BM25 max-score below this → open the expensive channels."""

    retrieval_cache_ttl: float = 300.0
    """Seconds to cache retrieval results in the KVStore."""

    retrieval_top_k_multiplier: int = 5
    """Multiplier over k when fetching candidates before tier-filtering."""

    rrf_k: int = 60
    """Constant k in reciprocal-rank fusion formula."""

    channel_weight_lexical: float = 1.0
    channel_weight_dense: float = 1.0
    channel_weight_graph: float = 0.5
    channel_weight_regex: float = 0.5

    # --- staging / reflector ---
    min_evidence_count: int = 2
    """Episodes needed before a staged skill is eligible for promotion."""

    min_confidence: float = 0.5
    """Minimum confidence for promotion."""

    skill_merge_theta: float = 0.85
    """Vector similarity above which a new candidate merges into an existing skill."""

    skill_prior: float = 0.5
    """Starting confidence for newly staged skills."""

    min_chain_len: int = 2
    """Minimum episode-chain length to trigger skill generalisation."""

    decay_unused_runs: int = 10
    """Skill unused for this many Reflector passes has its confidence decayed."""

    decay_factor: float = 0.9
    """Multiplicative confidence decay per unused pass."""

    winrate_floor: float = 0.3
    """Skill win-rate below this → quarantine."""

    # --- orchestrator / scheduler ---
    max_concurrency: int = 4
    """Maximum parallel executor slots."""

    max_retries: int = 2
    """Bounded retries for script_error / fixable outcomes."""

    # --- open-task view ---
    actionable_node_types: list[str] = field(
        default_factory=lambda: ["weakness", "task", "goal", "finding"]
    )
    """Node types treated as 'open tasks' when they have no terminal outcome edge."""

    terminal_edge_types: list[str] = field(
        default_factory=lambda: ["resolved", "abandoned", "completed"]
    )
    """Edge types that close an actionable node."""

    # --- slot extraction patterns ---
    slot_patterns: list[str] = field(default_factory=list)
    """Additional regex patterns (as raw strings) used by the Reflector to
    identify concrete values that should be replaced with slot references when
    generalising episode chains into Skill templates.

    Default: empty — only UUID v4 strings are slotted by the built-in pattern.

    Host applications supply domain-specific patterns here.  For example,
    a cybersecurity host would add IPv4 and port patterns::

        Config(slot_patterns=[
            r"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",   # IPv4
            r"\\d{4,6}",                                       # port/numeric ID
        ])

    The substrate itself must contain no domain-specific patterns.
    """

    # --- reflector throttling ---
    reflector_max_promotions_per_run: int = 100
    """Maximum combined knowledge+skill promotions per run_once() call.

    Prevents log floods when seeding large corpora (e.g. a payload repo with
    hundreds of chunks).  Entries not promoted in one run are processed in the
    next call because they remain staged with ``promoted=False``.
    """

    reflector_log_every_n: int = 25
    """Emit a per-item DEBUG log every N promotions during a run_once() pass.

    Individual promotion logs are always at DEBUG; only the end-of-pass
    summary (promoted=N skipped=M remaining=K) is at INFO.
    """

    # --- vector index ---
    vector_dim: int = 384
    """Embedding dimensionality for the dense vector index."""
