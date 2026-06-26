"""Web test YAML schema validation."""

from __future__ import annotations

import copy

import pytest

from vectorguard.webagent.loader import WebTestValidationError, validate_web_test

VALID = {
    "id": "forced_browsing_admin",
    "name": "Forced browsing admin panel",
    "category": "access_control",
    "owasp": "A01-Broken-Access-Control",
    "severity": "high",
    "safe": True,
    "requires_state_changing": False,
    "request": {"method": "GET", "path": "/admin", "headers": {}, "params": {}},
    "detectors": [{"type": "status_code", "suspicious_if": 200}],
    "remediation": ["Enforce server-side authorization."],
}


def test_valid_web_test_parses():
    test = validate_web_test(copy.deepcopy(VALID))
    assert test.id == "forced_browsing_admin"
    assert test.request.method == "GET"
    assert test.request.path == "/admin"
    assert test.detectors[0].type == "status_code"


def test_missing_required_field_rejected():
    data = copy.deepcopy(VALID)
    del data["owasp"]
    with pytest.raises(WebTestValidationError):
        validate_web_test(data)


def test_invalid_severity_rejected():
    data = copy.deepcopy(VALID)
    data["severity"] = "extreme"
    with pytest.raises(WebTestValidationError):
        validate_web_test(data)


def test_path_must_start_with_slash():
    data = copy.deepcopy(VALID)
    data["request"]["path"] = "admin"
    with pytest.raises(WebTestValidationError):
        validate_web_test(data)


def test_detectors_must_be_non_empty():
    data = copy.deepcopy(VALID)
    data["detectors"] = []
    with pytest.raises(WebTestValidationError):
        validate_web_test(data)


def test_detector_requires_type():
    data = copy.deepcopy(VALID)
    data["detectors"] = [{"suspicious_if": 200}]
    with pytest.raises(WebTestValidationError):
        validate_web_test(data)


def test_non_bool_safe_rejected():
    data = copy.deepcopy(VALID)
    data["safe"] = "yes"
    with pytest.raises(WebTestValidationError):
        validate_web_test(data)
