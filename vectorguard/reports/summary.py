from __future__ import annotations

from collections import Counter
from typing import Any


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for result in results if result.get("passed"))
    failed = total - passed

    by_category = Counter(result.get("category", "unknown") for result in results)
    by_severity = Counter(result.get("severity", "unknown") for result in results)

    failed_tests = [
        {
            "name": result.get("name"),
            "category": result.get("category"),
            "severity": result.get("severity"),
            "reason": result.get("reason"),
        }
        for result in results
        if not result.get("passed")
    ]

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round((passed / total) * 100, 2) if total else 0.0,
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "failed_tests": failed_tests,
    }