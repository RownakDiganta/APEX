"""Per-phase token/turn budget accounting.

Pure accounting — no I/O, fully synchronous, trivially unit-testable.
The orchestrator consults the budget before allocating a new task to a phase.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PhasebudgetError(Exception):
    """Raised when trying to consume from an exhausted budget."""
    phase: str
    resource: str


@dataclass
class PhaseBudget:
    """Budget tracking for a single named phase."""
    phase: str
    max_turns: int
    max_tokens: int
    turns_used: int = 0
    tokens_used: int = 0

    def turns_remaining(self) -> int:
        return max(0, self.max_turns - self.turns_used)

    def tokens_remaining(self) -> int:
        return max(0, self.max_tokens - self.tokens_used)

    def can_allocate(self, turns: int = 1, tokens: int = 0) -> bool:
        return (
            self.turns_used + turns <= self.max_turns
            and self.tokens_used + tokens <= self.max_tokens
        )

    def consume(self, turns: int = 1, tokens: int = 0) -> None:
        if not self.can_allocate(turns, tokens):
            resource = "turns" if self.turns_used + turns > self.max_turns else "tokens"
            raise PhasebudgetError(phase=self.phase, resource=resource)
        self.turns_used += turns
        self.tokens_used += tokens

    def is_exhausted(self) -> bool:
        return self.turns_used >= self.max_turns or self.tokens_used >= self.max_tokens


@dataclass
class BudgetLedger:
    """Collection of phase budgets for one engagement run."""
    _phases: dict[str, PhaseBudget] = field(default_factory=dict)

    def add_phase(self, budget: PhaseBudget) -> None:
        self._phases[budget.phase] = budget

    def get(self, phase: str) -> PhaseBudget | None:
        return self._phases.get(phase)

    def can_allocate(self, phase: str, turns: int = 1, tokens: int = 0) -> bool:
        b = self._phases.get(phase)
        if b is None:
            return False
        return b.can_allocate(turns, tokens)

    def consume(self, phase: str, turns: int = 1, tokens: int = 0) -> None:
        b = self._phases[phase]
        b.consume(turns, tokens)

    def open_phases(self) -> list[PhaseBudget]:
        """Phases that still have budget remaining."""
        return [b for b in self._phases.values() if not b.is_exhausted()]

    def all_exhausted(self) -> bool:
        return all(b.is_exhausted() for b in self._phases.values())
