from __future__ import annotations

from collections import Counter
from typing import Any


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for result in results if result.get("passed"))
    failed = total - passed

    by_category = Counter(result.get("category", "unknown") for result in results)
    by_severity = Counter(result.get("severity", "unknown") for result in results)

    total_risk_score = round(
        sum(float(result.get("risk_score", 0.0)) for result in results),
        2,
    )

    max_risk_score = round(
        max((float(result.get("risk_score", 0.0)) for result in results), default=0.0),
        2,
    )

    failed_tests = [
        {
            "name": result.get("name"),
            "category": result.get("category"),
            "severity": result.get("severity"),
            "risk_score": result.get("risk_score", 0.0),
            "reason": result.get("reason"),
            "finding_title": (
                result.get("finding", {}).get("title")
                if result.get("finding")
                else None
            ),
        }
        for result in results
        if not result.get("passed")
    ]

    failed_tests.sort(
        key=lambda item: float(item.get("risk_score", 0.0)),
        reverse=True,
    )

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round((passed / total) * 100, 2) if total else 0.0,
        "total_risk_score": total_risk_score,
        "max_risk_score": max_risk_score,
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "failed_tests": failed_tests,
    }