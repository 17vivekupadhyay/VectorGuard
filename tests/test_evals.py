"""Tests for the golden-set eval harness: metrics math + the headline property."""

from __future__ import annotations

from evals.golden.manifest import GOLDEN_SET, OBJECTIVES
from evals.metrics import Outcome, score
from evals.run_eval import run_mode


# ------------------------------------------------------------------- metrics math
def test_outcome_cell_classification():
    assert Outcome("t", "o", "vulnerable", True, 1).cell == "TP"
    assert Outcome("t", "o", "vulnerable", False, 1).cell == "FN"
    assert Outcome("t", "o", "safe", True, 1).cell == "FP"
    assert Outcome("t", "o", "safe", False, 1).cell == "TN"


def test_precision_recall_f1():
    outcomes = [
        Outcome("a", "o", "vulnerable", True, 1),   # TP
        Outcome("b", "o", "vulnerable", True, 1),   # TP
        Outcome("c", "o", "vulnerable", False, 1),  # FN
        Outcome("d", "o", "safe", True, 1),         # FP
        Outcome("e", "o", "safe", False, 1),        # TN
    ]
    board = score(outcomes)
    m = board.overall
    assert (m.tp, m.fn, m.fp, m.tn) == (2, 1, 1, 1)
    assert round(m.precision, 3) == round(2 / 3, 3)
    assert round(m.recall, 3) == round(2 / 3, 3)
    assert round(m.f1, 3) == round(2 / 3, 3)
    assert len(board.false_negatives) == 1
    assert len(board.false_positives) == 1


def test_empty_denominators_are_safe():
    # No vulnerable targets -> recall defined as 1.0; no positives -> precision 1.0.
    board = score([Outcome("a", "o", "safe", False, 1)])
    assert board.overall.recall == 1.0
    assert board.overall.precision == 1.0


# ------------------------------------------------------------- golden-set property
def test_golden_set_is_balanced():
    # Must contain both vulnerable and safe cells or precision/recall are meaningless.
    labels = [lbl for gt in GOLDEN_SET for lbl in gt.labels.values()]
    assert "vulnerable" in labels and "safe" in labels
    # Every target labels every objective.
    for gt in GOLDEN_SET:
        assert set(gt.labels) == set(OBJECTIVES)


def test_adaptive_beats_baseline_recall_at_full_precision():
    baseline = run_mode("baseline")
    adaptive = run_mode("adaptive")

    # Deterministic oracle against fakes that only emit flags when truly
    # vulnerable: neither mode should ever false-alarm.
    assert baseline.overall.fp == 0
    assert adaptive.overall.fp == 0
    assert baseline.overall.precision == 1.0
    assert adaptive.overall.precision == 1.0

    # Adaptation is the whole point: it must catch strictly more real vulns.
    assert adaptive.overall.recall > baseline.overall.recall
    assert adaptive.overall.tp > baseline.overall.tp

    # The misses the baseline makes are exactly the encoding-only targets.
    missed = {(o.target, o.objective) for o in baseline.false_negatives}
    assert ("kf_injection", "prompt_injection_obey") in missed
    assert ("kf_leak", "system_prompt_leak") in missed
    # And adaptive closes them.
    assert adaptive.overall.fn == 0


def test_eval_is_reproducible():
    # Same inputs, same number — the property the whole eval depends on.
    first = run_mode("adaptive").overall.as_dict()
    second = run_mode("adaptive").overall.as_dict()
    assert first == second
