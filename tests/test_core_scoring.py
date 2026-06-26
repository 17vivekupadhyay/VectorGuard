"""LLM/RAG core risk scoring."""

from __future__ import annotations

from vectorguard.core.scoring import calculate_risk_score, severity_to_score


def test_severity_weights():
    assert severity_to_score("info") == 0.0
    assert severity_to_score("low") == 2.0
    assert severity_to_score("medium") == 5.0
    assert severity_to_score("high") == 8.0
    assert severity_to_score("critical") == 10.0


def test_unknown_severity_defaults():
    assert severity_to_score("bogus") == severity_to_score(None)


def test_passed_test_scores_zero():
    assert calculate_risk_score(passed=True, severity="high", detector_results=[]) == 0.0


def test_failed_high_severity_string_match_scores_full():
    detectors = [
        {"detector_type": "contains", "passed": False, "matched_patterns": ["secret"]}
    ]
    # high (8.0) * confidence 1.0 for a hard string match
    assert calculate_risk_score(passed=False, severity="high", detector_results=detectors) == 8.0
