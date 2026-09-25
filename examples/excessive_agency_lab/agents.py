"""
Multi-agent orchestration for the lab.

Instead of one operator working a single tactic ladder, a COORDINATOR routes each
objective to specialist sub-agents — each of which owns one technique family — and
re-routes to a different specialist when the current one is exhausted. It also uses
the analyst's refusal signal to steer toward the specialist whose technique the
target's behaviour hints at.

This is an orchestrator/worker multi-agent pattern. Each specialist implements the
same `propose(objective, history) -> Proposal | None` interface as the plain
operators, and the orchestrator is itself just an operator (a meta-operator), so
the engine drives it unchanged.
"""

from __future__ import annotations

from typing import Any

from operators import Analyst, Proposal
from tactics import TACTICS_BY_RANK

History = list[dict[str, Any]]


class Specialist:
    """A sub-agent that owns one technique family (a subset of tactic categories)."""

    def __init__(self, name: str, categories: set[str]) -> None:
        self.name = name
        self._categories = categories
        # Its own tactics, in escalation order.
        self._tactics = [t for t in TACTICS_BY_RANK if t.category in categories]
        self._i = 0

    def reset(self) -> None:
        self._i = 0

    def exhausted(self) -> bool:
        return self._i >= len(self._tactics)

    def owns(self, category: str | None) -> bool:
        return category in self._categories

    def propose(self, objective: Any) -> Proposal | None:
        if self.exhausted():
            return None
        tactic = self._tactics[self._i]
        self._i += 1
        # Tag the tactic with the specialist so the trace/report shows the routing.
        return Proposal(tactic.render(objective), f"{self.name}:{tactic.name}",
                        tactic.category, tactic.rationale)


def default_specialists() -> list[Specialist]:
    return [
        Specialist("social-engineer", {"plain", "social", "authority_spoof"}),
        Specialist("injector", {"injection_override", "indirect_retrieval"}),
        Specialist("protocol", {"schema_confusion"}),
    ]


class OrchestratorOperator:
    """Coordinator agent: routes objectives to specialist sub-agents, re-routing on
    exhaustion and steering by the analyst's hint."""

    name = "orchestrator"

    def __init__(self, specialists: list[Specialist] | None = None) -> None:
        self._specialists = specialists or default_specialists()
        self._analyst = Analyst()
        self._active = 0
        self.routing_log: list[str] = []

    def reset(self) -> None:
        for s in self._specialists:
            s.reset()
        self._active = 0
        self.routing_log = []

    def _route(self, history: History) -> int | None:
        """Choose which specialist handles the next step."""
        # 1) The analyst reads the last refusal; if it points at a technique, route
        #    to the specialist that owns it (unless that specialist is spent).
        hint = self._analyst.recommend(history[-1]["response"]) if history else None
        if hint:
            for idx, s in enumerate(self._specialists):
                if s.owns(hint) and not s.exhausted():
                    return idx
        # 2) Otherwise stay on the current specialist while it still has tactics.
        if not self._specialists[self._active].exhausted():
            return self._active
        # 3) Else advance to the next specialist that still has moves.
        for idx, s in enumerate(self._specialists):
            if not s.exhausted():
                return idx
        return None

    def propose(self, objective: Any, history: History) -> Proposal | None:
        # Bounded loop (never recurses): route, delegate, or give up when all spent.
        for _ in range(len(self._specialists) + 1):
            idx = self._route(history)
            if idx is None:
                return None
            self._active = idx
            proposal = self._specialists[idx].propose(objective)
            if proposal is not None:
                self.routing_log.append(self._specialists[idx].name)
                return proposal
        return None
