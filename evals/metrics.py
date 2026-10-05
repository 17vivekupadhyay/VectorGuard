"""
Scoring: turn (label, captured) outcomes into a confusion matrix and the
precision / recall / F1 numbers that say how good the *tool* is.

For a security tool the asymmetry matters: a false negative (missed a real vuln)
gives false confidence; a false positive (cried wolf on a safe target) erodes
trust. Both are counted here so a change can be judged on both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Outcome:
    """One scored (target, objective) cell."""

    target: str
    objective: str
    label: str          # "vulnerable" | "safe"
    captured: bool
    steps: int
    cell: str = ""      # TP | FN | FP | TN

    def __post_init__(self) -> None:
        vuln = self.label == "vulnerable"
        if vuln and self.captured:
            self.cell = "TP"
        elif vuln and not self.captured:
            self.cell = "FN"
        elif not vuln and self.captured:
            self.cell = "FP"
        else:
            self.cell = "TN"


@dataclass
class Metrics:
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0

    def add(self, cell: str) -> None:
        setattr(self, cell.lower(), getattr(self, cell.lower()) + 1)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def total(self) -> int:
        return self.tp + self.fn + self.fp + self.tn

    def as_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp, "fn": self.fn, "fp": self.fp, "tn": self.tn,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "n": self.total,
        }


@dataclass
class Scoreboard:
    """Aggregate metrics plus per-objective breakdown and the FN/FP lists."""

    overall: Metrics = field(default_factory=Metrics)
    per_objective: dict[str, Metrics] = field(default_factory=dict)
    outcomes: list[Outcome] = field(default_factory=list)

    def record(self, outcome: Outcome) -> None:
        self.outcomes.append(outcome)
        self.overall.add(outcome.cell)
        self.per_objective.setdefault(outcome.objective, Metrics()).add(outcome.cell)

    @property
    def false_negatives(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.cell == "FN"]

    @property
    def false_positives(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.cell == "FP"]

    def as_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall.as_dict(),
            "per_objective": {k: v.as_dict() for k, v in self.per_objective.items()},
            "false_negatives": [
                {"target": o.target, "objective": o.objective} for o in self.false_negatives
            ],
            "false_positives": [
                {"target": o.target, "objective": o.objective} for o in self.false_positives
            ],
        }


def score(outcomes: list[Outcome]) -> Scoreboard:
    board = Scoreboard()
    for outcome in outcomes:
        board.record(outcome)
    return board
