"""
Findings assembly for the VectorGuard Web Agent.

Turns a web test plus its raw result and detector results into a higher-level
finding. A finding is created only when at least one detector is suspicious.

Reuses ``vectorguard.core.scoring.severity_to_score`` so web findings share the
same severity weighting as the LLM/RAG core.
"""

from __future__ import annotations

from typing import Any

from vectorguard.core.scoring import severity_to_score

from .models import WebTest

# Categorical detector confidence -> ordering and a numeric factor for scoring.
CONFIDENCE_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}
CONFIDENCE_FACTOR: dict[str, float] = {"low": 0.5, "medium": 0.75, "high": 1.0}


def highest_confidence(confidences: list[str]) -> str:
    """Return the highest confidence label, defaulting to 'low'."""
    if not confidences:
        return "low"
    return max(confidences, key=lambda c: CONFIDENCE_ORDER.get(c, 0))


def _flatten_matched(detectors: list[dict[str, Any]]) -> list[Any]:
    """Collect unique matched values across detectors, preserving order."""
    matched: list[Any] = []
    for detector in detectors:
        for item in detector.get("matched", []):
            if item not in matched:
                matched.append(item)
    return matched


def build_finding(
    *,
    test: WebTest,
    raw_result: dict[str, Any],
    detector_results: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Build a single finding for a test, or ``None`` if nothing is suspicious.
    """
    suspicious = [d for d in detector_results if d.get("suspicious")]
    if not suspicious:
        return None

    confidence = highest_confidence([d.get("confidence", "low") for d in suspicious])
    risk_score = round(
        severity_to_score(test.severity) * CONFIDENCE_FACTOR.get(confidence, 0.5),
        2,
    )

    response = raw_result.get("response", {})

    return {
        "id": test.id,
        "title": test.name,
        "category": test.category,
        "owasp": test.owasp,
        "severity": test.severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "endpoint": test.request.path,
        "method": test.request.method,
        "status_code": response.get("status_code"),
        "evidence": {
            "suspicious_detectors": suspicious,
            "matched": _flatten_matched(suspicious),
            "evidence_files": raw_result.get("evidence", {}),
        },
        "remediation": list(test.remediation),
    }


def build_findings_payload(
    *,
    test: WebTest,
    raw_result: dict[str, Any],
    detector_results: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build the ``findings.json`` payload for a single-test scan.

    Returns ``{"metadata": {...}, "findings": [...]}``. The findings list is
    empty when no detector is suspicious.
    """
    finding = build_finding(
        test=test,
        raw_result=raw_result,
        detector_results=detector_results,
    )

    payload: dict[str, Any] = {"findings": [finding] if finding else []}
    if metadata is not None:
        payload = {"metadata": metadata, "findings": payload["findings"]}

    return payload
