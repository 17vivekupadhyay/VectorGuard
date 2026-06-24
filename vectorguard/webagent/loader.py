"""
Web test YAML loader and validation for the VectorGuard Web Agent.

Reuses ``vectorguard.config.loader.load_yaml_file`` (duplicate-key rejection and
top-level-mapping enforcement) and adds typed validation of the web test schema.

No HTTP requests are made here. This module only parses and validates files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vectorguard.config.loader import load_yaml_file

from .models import SEVERITY_LEVELS, DetectorSpec, RequestSpec, WebTest


class WebTestValidationError(ValueError):
    """Raised when a web test file is missing fields or has invalid values."""


def _require_str(data: dict[str, Any], key: str, *, where: str) -> str:
    if key not in data:
        raise WebTestValidationError(f"{where}: missing required field '{key}'.")

    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise WebTestValidationError(
            f"{where}: field '{key}' must be a non-empty string."
        )

    return value


def _optional_bool(data: dict[str, Any], key: str, default: bool, *, where: str) -> bool:
    if key not in data:
        return default

    value = data[key]
    if not isinstance(value, bool):
        raise WebTestValidationError(f"{where}: field '{key}' must be a boolean.")

    return value


def _validate_request(request: Any, *, where: str) -> RequestSpec:
    if not isinstance(request, dict):
        raise WebTestValidationError(f"{where}: 'request' must be a mapping/object.")

    method = _require_str(request, "method", where=f"{where}.request")
    path = _require_str(request, "path", where=f"{where}.request")

    if not path.startswith("/"):
        raise WebTestValidationError(
            f"{where}.request: 'path' must start with '/' (got {path!r})."
        )

    headers = request.get("headers", {})
    if not isinstance(headers, dict):
        raise WebTestValidationError(
            f"{where}.request: 'headers' must be a mapping/object if present."
        )

    params = request.get("params", {})
    if not isinstance(params, dict):
        raise WebTestValidationError(
            f"{where}.request: 'params' must be a mapping/object if present."
        )

    return RequestSpec(
        method=method,
        path=path,
        headers=headers,
        params=params,
    )


def _validate_detectors(detectors: Any, *, where: str) -> list[DetectorSpec]:
    if not isinstance(detectors, list) or not detectors:
        raise WebTestValidationError(
            f"{where}: 'detectors' must be a non-empty list."
        )

    specs: list[DetectorSpec] = []
    for index, detector in enumerate(detectors):
        location = f"{where}.detectors[{index}]"
        if not isinstance(detector, dict):
            raise WebTestValidationError(f"{location}: each detector must be a mapping/object.")

        detector_type = _require_str(detector, "type", where=location)
        config = {key: value for key, value in detector.items() if key != "type"}
        specs.append(DetectorSpec(type=detector_type, config=config))

    return specs


def _validate_remediation(remediation: Any, *, where: str) -> list[str]:
    if remediation is None:
        return []

    if not isinstance(remediation, list):
        raise WebTestValidationError(
            f"{where}: 'remediation' must be a list of strings if present."
        )

    for index, item in enumerate(remediation):
        if not isinstance(item, str):
            raise WebTestValidationError(
                f"{where}.remediation[{index}]: each item must be a string."
            )

    return list(remediation)


def validate_web_test(data: dict[str, Any], *, where: str = "web test") -> WebTest:
    """Validate a parsed web test mapping and return a typed :class:`WebTest`."""
    if not isinstance(data, dict):
        raise WebTestValidationError(f"{where}: top-level content must be a mapping/object.")

    test_id = _require_str(data, "id", where=where)
    location = f"{where} '{test_id}'"

    name = _require_str(data, "name", where=location)
    category = _require_str(data, "category", where=location)
    owasp = _require_str(data, "owasp", where=location)
    severity = _require_str(data, "severity", where=location)

    if severity not in SEVERITY_LEVELS:
        allowed = ", ".join(sorted(SEVERITY_LEVELS))
        raise WebTestValidationError(
            f"{location}: 'severity' must be one of [{allowed}] (got {severity!r})."
        )

    safe = _optional_bool(data, "safe", True, where=location)
    requires_state_changing = _optional_bool(
        data, "requires_state_changing", False, where=location
    )

    if "request" not in data:
        raise WebTestValidationError(f"{location}: missing required field 'request'.")
    request = _validate_request(data["request"], where=location)

    if "detectors" not in data:
        raise WebTestValidationError(f"{location}: missing required field 'detectors'.")
    detectors = _validate_detectors(data["detectors"], where=location)

    remediation = _validate_remediation(data.get("remediation"), where=location)

    return WebTest(
        id=test_id,
        name=name,
        category=category,
        owasp=owasp,
        severity=severity,
        request=request,
        detectors=detectors,
        safe=safe,
        requires_state_changing=requires_state_changing,
        remediation=remediation,
    )


def load_web_test(path: str | Path) -> WebTest:
    """
    Load and validate a single web test YAML file.

    Raises ``FileNotFoundError`` if the file is missing and
    :class:`WebTestValidationError` for schema problems, both with the file path
    in the message.
    """
    file_path = Path(path)

    # load_yaml_file rejects duplicate keys and non-mapping top-level content.
    data = load_yaml_file(file_path)

    return validate_web_test(data, where=f"web test {file_path}")
