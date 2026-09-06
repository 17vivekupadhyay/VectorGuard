from __future__ import annotations

from pathlib import Path

from vectorguard.runner.run_suite import load_tests

ROOT = Path(__file__).resolve().parents[1]
RAG_INJECTION_SUITE = ROOT / "vectorguard" / "tests" / "rag_injection.yaml"


def test_rag_injection_suite_includes_csv_cell_injection_case() -> None:
    tests = load_tests(RAG_INJECTION_SUITE)
    by_name = {test["name"]: test for test in tests}

    csv_case = by_name["rag_csv_cell_injection"]

    assert csv_case["category"] == "rag_injection"
    assert csv_case["owasp_id"] == "LLM01:2025"
    assert csv_case["severity"] == "medium"
    assert "RAG_PWNED_024" in csv_case["prompt"]

    contains_detector = next(
        detector for detector in csv_case["detectors"] if detector["type"] == "contains"
    )
    assert "RAG_PWNED_024" in contains_detector["patterns"]
    assert contains_detector["case_sensitive"] is False
    assert contains_detector["match_mode"] == "any"
