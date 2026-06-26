"""Web Agent detector engine."""

from __future__ import annotations

import pytest

from vectorguard.webagent.detectors import (
    WebDetectorError,
    evaluate_detectors,
    validate_detector_specs,
)
from vectorguard.webagent.models import DetectorSpec


def _run(spec, *, body_text="", status_code=200, body_length=None):
    return evaluate_detectors(
        [spec], body_text=body_text, status_code=status_code, body_length=body_length
    )[0]


def test_status_code_suspicious_on_match():
    r = _run(DetectorSpec("status_code", {"suspicious_if": 200}), status_code=200)
    assert r["suspicious"] is True
    assert r["confidence"] == "high"


def test_status_code_not_suspicious_on_miss():
    r = _run(DetectorSpec("status_code", {"suspicious_if": 500}), status_code=200)
    assert r["suspicious"] is False


def test_status_code_accepts_list():
    r = _run(DetectorSpec("status_code", {"suspicious_if": [500, 502]}), status_code=502)
    assert r["suspicious"] is True


def test_body_contains_any():
    spec = DetectorSpec("body_contains_any", {"keywords": ["Admin", "delete user"]})
    r = _run(spec, body_text="<h1>Admin</h1><p>delete user</p>")
    assert r["suspicious"] is True
    assert set(r["matched"]) == {"Admin", "delete user"}
    assert r["confidence"] == "medium"


def test_body_not_contains_any_flags_absence():
    spec = DetectorSpec("body_not_contains_any", {"keywords": ["csrf", "token"]})
    r = _run(spec, body_text="<form>no protection here</form>")
    assert r["suspicious"] is True


def test_error_keywords_detects_sql_error():
    spec = DetectorSpec("error_keywords", {"keywords": ["SQL syntax"]})
    r = _run(spec, body_text="You have an error in your SQL syntax")
    assert r["suspicious"] is True
    assert r["confidence"] == "high"


def test_response_length_gt():
    spec = DetectorSpec("response_length_gt", {"value": 10})
    assert _run(spec, body_length=50)["suspicious"] is True
    assert _run(spec, body_length=5)["suspicious"] is False


def test_response_length_delta_gt_without_baseline_is_not_suspicious():
    spec = DetectorSpec("response_length_delta_gt", {"value": 100})
    assert _run(spec, body_length=500)["suspicious"] is False


def test_unknown_detector_type_preflight_raises():
    with pytest.raises(WebDetectorError):
        validate_detector_specs([DetectorSpec("magic_eightball", {})])


def test_detector_output_shape():
    r = _run(DetectorSpec("status_code", {"suspicious_if": 200}), status_code=200)
    assert set(r.keys()) == {
        "detector",
        "suspicious",
        "confidence",
        "matched",
        "explanation",
    }
