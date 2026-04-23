from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from vectorguard.evaluators.detectors import evaluate_response


def load_tests(test_file: str | Path) -> list[dict[str, Any]]:
    path = Path(test_file)

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data.get("tests", [])


def infer_owasp_id(category: str) -> str:
    mapping = {
        "prompt_injection": "LLM01:2025",
        "authority_spoofing": "LLM01:2025",
        "sensitive_data_disclosure": "LLM02:2025",
        "indirect_leakage": "LLM02:2025",
        "prompt_leakage": "LLM07:2025",
    }
    return mapping.get(category, "unmapped")


def build_detectors(test: dict[str, Any]) -> list[dict[str, Any]]:
    if "detectors" in test:
        return test["detectors"]

    if "detector" in test:
        return [test["detector"]]

    return [
        {
            "type": "contains",
            "patterns": test.get("forbidden_patterns", []),
            "case_sensitive": False,
            "match_mode": "any",
            "normalize": True,
            "squash": True,
        }
    ]


def run_suite(target: Any, test_file: str | Path) -> list[dict[str, Any]]:
    tests = load_tests(test_file)
    results: list[dict[str, Any]] = []

    for test in tests:
        response = target.send_prompt(test["prompt"])

        detectors = build_detectors(test)
        evaluation = evaluate_response(
            response_text=response.text,
            detectors=detectors,
        )

        detector_results = evaluation.get("detector_results", [])

        detector_types: list[str] = []
        matched_patterns: list[str] = []
        evidence: dict[str, str] = {}

        for detector_result in detector_results:
            detector_type = detector_result.get("detector_type")
            if detector_type:
                detector_types.append(detector_type)

            matched_patterns.extend(detector_result.get("matched_patterns", []))
            evidence.update(detector_result.get("evidence", {}))

        results.append(
            {
                "name": test["name"],
                "category": test["category"],
                "owasp_id": test.get(
                    "owasp_id",
                    infer_owasp_id(test.get("category", "unknown")),
                ),
                "severity": test.get("severity", "unknown"),
                "prompt": test["prompt"],
                "response_text": response.text,
                "status_code": response.status_code,
                "latency_ms": round(response.latency_ms, 2),
                "passed": evaluation["passed"],
                "reason": evaluation["reason"],
                "detector_type": ", ".join(detector_types) if detector_types else "unknown",
                "matched_patterns": matched_patterns,
                "evidence": evidence,
            }
        )

    return results