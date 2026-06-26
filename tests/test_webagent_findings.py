"""Findings assembly + evidence redaction."""

from __future__ import annotations

from vectorguard.webagent.evidence import redact_headers
from vectorguard.webagent.findings import build_finding, highest_confidence
from vectorguard.webagent.loader import validate_web_test

TEST = validate_web_test(
    {
        "id": "forced_browsing_admin",
        "name": "Forced browsing admin panel",
        "category": "access_control",
        "owasp": "A01-Broken-Access-Control",
        "severity": "high",
        "request": {"method": "GET", "path": "/admin"},
        "detectors": [{"type": "status_code", "suspicious_if": 200}],
        "remediation": ["Enforce server-side authorization."],
    }
)

RAW = {"request": {"url": "http://localhost/admin"}, "response": {"status_code": 200}, "evidence": {}}


def test_no_finding_when_nothing_suspicious():
    detectors = [{"detector": "status_code", "suspicious": False, "confidence": "low", "matched": []}]
    assert build_finding(test=TEST, raw_result=RAW, detector_results=detectors) is None


def test_finding_built_when_suspicious():
    detectors = [
        {"detector": "status_code", "suspicious": True, "confidence": "high", "matched": [200]},
        {"detector": "body_contains_any", "suspicious": True, "confidence": "medium", "matched": ["Admin"]},
    ]
    finding = build_finding(test=TEST, raw_result=RAW, detector_results=detectors)
    assert finding is not None
    assert finding["id"] == "forced_browsing_admin"
    assert finding["severity"] == "high"
    # highest confidence among suspicious detectors wins
    assert finding["confidence"] == "high"
    # high severity (8.0) * high confidence factor (1.0)
    assert finding["risk_score"] == 8.0


def test_highest_confidence_ordering():
    assert highest_confidence(["low", "medium", "high"]) == "high"
    assert highest_confidence(["low", "medium"]) == "medium"
    assert highest_confidence([]) == "low"


def test_redact_headers_scrubs_secrets():
    redacted = redact_headers(
        {
            "Authorization": "Bearer abc",
            "Cookie": "session=xyz",
            "Set-Cookie": "session=xyz",
            "X-API-Key": "k",
            "Content-Type": "text/html",
        }
    )
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["Cookie"] == "[REDACTED]"
    assert redacted["Set-Cookie"] == "[REDACTED]"
    assert redacted["X-API-Key"] == "[REDACTED]"
    # non-sensitive header preserved
    assert redacted["Content-Type"] == "text/html"
