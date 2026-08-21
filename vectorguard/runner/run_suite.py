from __future__ import annotations

from pathlib import Path
from typing import Any

from vectorguard.config.loader import load_yaml_file, resolve_string
from vectorguard.core.findings import build_finding
from vectorguard.core.scoring import calculate_risk_score
from vectorguard.evaluators.detectors import evaluate_response

REQUIRED_TEST_FIELDS = {"name", "category"}


def resolve_value(value: Any, context: dict[str, Any] | None) -> Any:
    if context is None:
        return value

    if isinstance(value, str):
        return resolve_string(value, context)

    if isinstance(value, list):
        return [resolve_value(v, context) for v in value]

    if isinstance(value, dict):
        return {k: resolve_value(v, context) for k, v in value.items()}

    return value


def load_tests(test_file: str | Path) -> list[dict[str, Any]]:
    path = Path(test_file)

    if not path.exists():
        raise FileNotFoundError(f"Test file not found: {path}")

    data = load_yaml_file(path)

    if not isinstance(data, dict):
        raise ValueError(f"Test file must contain a top-level mapping/object: {path}")

    tests = data.get("tests")
    if tests is None:
        raise ValueError(f"Test file is missing top-level 'tests' key: {path}")

    if not isinstance(tests, list):
        raise ValueError(f"'tests' must be a list in file: {path}")

    for i, test in enumerate(tests):
        validate_test_case(test, index=i, path=path)

    return tests


def validate_test_case(test: Any, *, index: int, path: Path) -> None:
    if not isinstance(test, dict):
        raise ValueError(f"Test at index {index} in {path} must be an object")

    missing = REQUIRED_TEST_FIELDS - set(test.keys())
    if missing:
        raise ValueError(
            f"Test at index {index} in {path} is missing required fields: {sorted(missing)}"
        )

    has_prompt = "prompt" in test
    has_steps = "steps" in test

    if not has_prompt and not has_steps:
        raise ValueError(
            f"Test '{test.get('name')}' in {path} must define either 'prompt' or 'steps'"
        )

    if has_prompt and has_steps:
        raise ValueError(
            f"Test '{test.get('name')}' in {path} cannot define both 'prompt' and 'steps'"
        )

    if has_steps:
        if not isinstance(test["steps"], list) or not test["steps"]:
            raise ValueError(
                f"Test '{test.get('name')}' in {path} has invalid 'steps'; expected non-empty list"
            )

        for step in test["steps"]:
            if not isinstance(step, dict):
                raise ValueError(
                    f"Test '{test.get('name')}' in {path} has a step that is not an object"
                )

            if "role" not in step or "content" not in step:
                raise ValueError(
                    f"Each step in test '{test.get('name')}' in {path} must include 'role' and 'content'"
                )

    if "detector" in test and "detectors" in test:
        raise ValueError(
            f"Test '{test.get('name')}' in {path} cannot define both 'detector' and 'detectors'"
        )

    if "detector" in test and not isinstance(test["detector"], dict):
        raise ValueError(
            f"Test '{test.get('name')}' in {path} has invalid 'detector'; expected object"
        )

    if "detectors" in test:
        if not isinstance(test["detectors"], list):
            raise ValueError(
                f"Test '{test.get('name')}' in {path} has invalid 'detectors'; expected list"
            )

        for detector in test["detectors"]:
            if not isinstance(detector, dict):
                raise ValueError(
                    f"Test '{test.get('name')}' in {path} has a detector that is not an object"
                )


def infer_owasp_id(category: str) -> str:
    mapping = {
        "prompt_injection": "LLM01:2025",
        "rag_injection": "LLM01:2025",
        "authority_spoofing": "LLM01:2025",

        "sensitive_data_disclosure": "LLM02:2025",
        "sensitive_information_disclosure": "LLM02:2025",
        "indirect_leakage": "LLM02:2025",

        "prompt_leakage": "LLM07:2025",
        "system_prompt_leakage": "LLM07:2025",

        "unbounded_consumption": "LLM10:2025",
    }

    return mapping.get(category, "unmapped")


def build_detectors(
    test: dict[str, Any],
    context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if "detectors" in test:
        return resolve_value(test["detectors"], context)

    if "detector" in test:
        return [resolve_value(test["detector"], context)]

    return [
        {
            "type": "contains",
            "patterns": resolve_value(test.get("forbidden_patterns", []), context),
            "case_sensitive": False,
            "match_mode": "any",
            "normalize": True,
            "squash": True,
        }
    ]


def build_messages(
    test: dict[str, Any],
    context: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    if "steps" in test:
        return [
            {
                "role": str(resolve_value(step["role"], context)),
                "content": str(resolve_value(step["content"], context)),
            }
            for step in test["steps"]
        ]

    return [{"role": "user", "content": str(resolve_value(test["prompt"], context))}]


def get_display_prompt(
    test: dict[str, Any],
    context: dict[str, Any] | None = None,
) -> str:
    if "prompt" in test:
        return str(resolve_value(test["prompt"], context))

    if "steps" in test:
        return "\n".join(
            f"{resolve_value(step['role'], context)}: {resolve_value(step['content'], context)}"
            for step in test["steps"]
        )

    return ""


def run_suite(
    target: Any,
    test_file: str | Path,
    context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    tests = load_tests(test_file)
    results: list[dict[str, Any]] = []

    for raw_test in tests:
        test = resolve_value(raw_test, context)

        messages = build_messages(test, context)
        response = target.send_messages(messages)

        detectors = build_detectors(test, context)
        evaluation = evaluate_response(
            response_text=response.text,
            detectors=detectors,
        )

        detector_results = evaluation.get("detector_results", [])

        risk_score = calculate_risk_score(
            passed=evaluation["passed"],
            severity=test.get("severity", "unknown"),
            detector_results=detector_results,
        )

        detector_types: list[str] = []

        leak_matches: list[str] = []
        leak_evidence: dict[str, str] = {}

        refusal_signals: list[str] = []
        refusal_evidence: dict[str, str] = {}

        other_matches: list[str] = []
        other_evidence: dict[str, str] = {}

        for detector_result in detector_results:
            detector_type = detector_result.get("detector_type")
            if detector_type:
                detector_types.append(detector_type)

            matched_patterns = detector_result.get("matched_patterns", [])
            evidence = detector_result.get("evidence", {})

            if detector_type == "refusal":
                refusal_signals.extend(matched_patterns)
                refusal_evidence.update(evidence)
            elif detector_type in {"contains", "regex"}:
                leak_matches.extend(matched_patterns)
                leak_evidence.update(evidence)
            else:
                other_matches.extend(matched_patterns)
                other_evidence.update(evidence)

        result = {
            "name": test["name"],
            "category": test["category"],
            "owasp_id": test.get(
                "owasp_id",
                infer_owasp_id(test.get("category", "unknown")),
            ),
            "severity": test.get("severity", "unknown"),
            "risk_score": risk_score,
            "prompt": get_display_prompt(test, context),
            "response_text": response.text,
            "status_code": response.status_code,
            "latency_ms": round(response.latency_ms, 2),
            "passed": evaluation["passed"],
            "reason": evaluation["reason"],
            "detector_type": ", ".join(detector_types) if detector_types else "unknown",
            "detector_results": detector_results,
            "leak_matches": leak_matches,
            "leak_evidence": leak_evidence,
            "refusal_signals": refusal_signals,
            "refusal_evidence": refusal_evidence,
            "other_matches": other_matches,
            "other_evidence": other_evidence,
            "transcript": response.transcript,
        }

        result["finding"] = build_finding(result)

        results.append(result)

    return results