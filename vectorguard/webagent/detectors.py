"""
Detector engine for the VectorGuard Web Agent.

Detectors evaluate the raw result of a single safe request (Phase 6) and emit a
structured, deterministic signal. They never send requests and never decide a
final finding on their own (findings are assembled in Phase 8).

Each detector returns:

    {
        "detector": "<type>",
        "suspicious": true | false,
        "confidence": "low" | "medium" | "high",
        "matched": [...],
        "explanation": "...",
    }

Supported types:
    status_code, body_contains_any, body_not_contains_any,
    response_length_gt, response_length_delta_gt, error_keywords
"""

from __future__ import annotations

from typing import Any

from .models import DetectorSpec

# Default error/stack-trace markers used by error_keywords when a test does not
# supply its own keyword list. Kept conservative and read-only.
DEFAULT_ERROR_KEYWORDS: tuple[str, ...] = (
    "sql syntax",
    "syntax error",
    "sqlstate",
    "unclosed quotation",
    "you have an error in your sql",
    "ora-",
    "odbc",
    "psqlexception",
    "mysql_fetch",
    "supplied argument is not a valid",
    "warning: pg_",
    "traceback (most recent call last)",
    "internal server error",
)


class WebDetectorError(ValueError):
    """Raised for an unknown detector type or invalid detector configuration."""


def _result(
    detector: str,
    *,
    suspicious: bool,
    confidence: str,
    matched: list[Any],
    explanation: str,
) -> dict[str, Any]:
    return {
        "detector": detector,
        "suspicious": suspicious,
        "confidence": confidence,
        "matched": matched,
        "explanation": explanation,
    }


def _require(config: dict[str, Any], key: str, detector: str) -> Any:
    if key not in config:
        raise WebDetectorError(f"{detector} detector requires '{key}'.")
    return config[key]


def detect_status_code(config: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    suspicious_if = _require(config, "suspicious_if", "status_code")
    expected = suspicious_if if isinstance(suspicious_if, list) else [suspicious_if]

    status = ctx["status_code"]
    suspicious = status in expected

    return _result(
        "status_code",
        suspicious=suspicious,
        confidence="high" if suspicious else "low",
        matched=[status] if suspicious else [],
        explanation=(
            f"Response status {status} matched suspicious_if {expected}."
            if suspicious
            else f"Response status {status} did not match suspicious_if {expected}."
        ),
    )


def detect_body_contains_any(config: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    keywords = _require(config, "keywords", "body_contains_any")
    body_lower = ctx["body_text"].lower()

    matched = [kw for kw in keywords if str(kw).lower() in body_lower]
    suspicious = len(matched) > 0

    return _result(
        "body_contains_any",
        suspicious=suspicious,
        confidence="medium" if suspicious else "low",
        matched=matched,
        explanation=(
            f"Response body contained keyword(s): {matched}."
            if suspicious
            else "Response body contained none of the configured keywords."
        ),
    )


def detect_body_not_contains_any(config: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    keywords = _require(config, "keywords", "body_not_contains_any")
    body_lower = ctx["body_text"].lower()

    present = [kw for kw in keywords if str(kw).lower() in body_lower]
    suspicious = len(present) == 0

    return _result(
        "body_not_contains_any",
        suspicious=suspicious,
        confidence="low",
        matched=present,
        explanation=(
            f"Response body contained none of the expected keywords: {list(keywords)}."
            if suspicious
            else f"Response body contained expected keyword(s): {present}."
        ),
    )


def detect_response_length_gt(config: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    value = _require(config, "value", "response_length_gt")
    length = ctx["body_length"]
    suspicious = length > value

    return _result(
        "response_length_gt",
        suspicious=suspicious,
        confidence="low",
        matched=[length] if suspicious else [],
        explanation=(
            f"Response length {length} exceeded threshold {value}."
            if suspicious
            else f"Response length {length} did not exceed threshold {value}."
        ),
    )


def detect_response_length_delta_gt(config: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    value = _require(config, "value", "response_length_delta_gt")
    baseline = config.get("baseline")
    length = ctx["body_length"]

    if baseline is None:
        return _result(
            "response_length_delta_gt",
            suspicious=False,
            confidence="low",
            matched=[],
            explanation=(
                "No baseline length provided; cannot compute a length delta. "
                "Baselines are produced by the planner in a later phase."
            ),
        )

    delta = abs(length - baseline)
    suspicious = delta > value

    return _result(
        "response_length_delta_gt",
        suspicious=suspicious,
        confidence="medium" if suspicious else "low",
        matched=[delta] if suspicious else [],
        explanation=(
            f"Length delta {delta} (|{length} - {baseline}|) exceeded threshold {value}."
            if suspicious
            else f"Length delta {delta} (|{length} - {baseline}|) did not exceed threshold {value}."
        ),
    )


def detect_error_keywords(config: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    keywords = config.get("keywords") or list(DEFAULT_ERROR_KEYWORDS)
    body_lower = ctx["body_text"].lower()

    matched = [kw for kw in keywords if str(kw).lower() in body_lower]
    suspicious = len(matched) > 0

    return _result(
        "error_keywords",
        suspicious=suspicious,
        confidence="high" if suspicious else "low",
        matched=matched,
        explanation=(
            f"Response body contained error marker(s): {matched}."
            if suspicious
            else "Response body contained no known error markers."
        ),
    )


DETECTOR_REGISTRY = {
    "status_code": detect_status_code,
    "body_contains_any": detect_body_contains_any,
    "body_not_contains_any": detect_body_not_contains_any,
    "response_length_gt": detect_response_length_gt,
    "response_length_delta_gt": detect_response_length_delta_gt,
    "error_keywords": detect_error_keywords,
}


def validate_detector_specs(specs: list[DetectorSpec]) -> None:
    """
    Preflight check that every detector type is supported.

    Called before any HTTP request is sent so an unknown detector type fails
    fast without touching the target. Raises :class:`WebDetectorError`.
    """
    for spec in specs:
        if spec.type not in DETECTOR_REGISTRY:
            allowed = ", ".join(sorted(DETECTOR_REGISTRY))
            raise WebDetectorError(
                f"Unknown detector type {spec.type!r}. Supported types: {allowed}."
            )


def evaluate_detector(spec: DetectorSpec, ctx: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a single detector spec against the request context."""
    evaluator = DETECTOR_REGISTRY.get(spec.type)
    if evaluator is None:
        allowed = ", ".join(sorted(DETECTOR_REGISTRY))
        raise WebDetectorError(
            f"Unknown detector type {spec.type!r}. Supported types: {allowed}."
        )
    return evaluator(spec.config, ctx)


def evaluate_detectors(
    specs: list[DetectorSpec],
    *,
    body_text: str,
    status_code: int,
    body_length: int | None = None,
) -> list[dict[str, Any]]:
    """Evaluate all detector specs against one request's result."""
    ctx = {
        "body_text": body_text or "",
        "status_code": status_code,
        "body_length": body_length if body_length is not None else len(body_text or ""),
    }
    return [evaluate_detector(spec, ctx) for spec in specs]
