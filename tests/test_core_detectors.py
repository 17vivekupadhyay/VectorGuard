"""LLM/RAG core detectors and required-vs-advisory evaluation."""

from __future__ import annotations

from vectorguard.evaluators.detectors import (
    evaluate_contains,
    evaluate_expected_contains,
    evaluate_max_output_chars,
    evaluate_refusal,
    evaluate_response,
)


def test_contains_fails_when_forbidden_present():
    r = evaluate_contains("the secret is VECTORGUARD_SECRET_12345", ["VECTORGUARD_SECRET_12345"])
    assert r["passed"] is False


def test_contains_passes_when_clean():
    r = evaluate_contains("nothing to see here", ["VECTORGUARD_SECRET_12345"])
    assert r["passed"] is True


def test_contains_squash_catches_spaced_leak():
    r = evaluate_contains("V E C T O R", ["VECTOR"], squash=True)
    assert r["passed"] is False


def test_refusal_passes_when_refusal_present():
    r = evaluate_refusal("Sorry, I cannot help with that", ["cannot"])
    assert r["passed"] is True


def test_expected_contains_requires_expected_text():
    r = evaluate_expected_contains("the answer mentions untrusted data", ["untrusted data"])
    assert r["passed"] is True
    r2 = evaluate_expected_contains("unrelated answer", ["untrusted data"])
    assert r2["passed"] is False


def test_max_output_chars():
    assert evaluate_max_output_chars("abc", 5)["passed"] is True
    assert evaluate_max_output_chars("abcdef", 5)["passed"] is False


def test_evaluate_response_required_vs_advisory():
    # forbidden leak (required) present -> overall fails, even though refusal (advisory) missing
    detectors = [
        {"type": "contains", "patterns": ["SECRET"]},
        {"type": "refusal", "patterns": ["cannot"], "required": False},
    ]
    result = evaluate_response("here is the SECRET", detectors)
    assert result["passed"] is False


def test_evaluate_response_advisory_does_not_fail_run():
    # no forbidden leak; refusal advisory missing should NOT fail the run
    detectors = [
        {"type": "contains", "patterns": ["SECRET"]},
        {"type": "refusal", "patterns": ["cannot"], "required": False},
    ]
    result = evaluate_response("a perfectly safe answer", detectors)
    assert result["passed"] is True
