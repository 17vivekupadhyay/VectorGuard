"""
Evidence capture for the VectorGuard Web Agent.

Handles redaction of sensitive headers and writes request/response evidence to
disk under the scan output directory. Sensitive values (auth, cookies, API keys)
are never written to evidence or reports.

This module performs no network I/O.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

REDACTED = "[REDACTED]"

# Header names (compared case-insensitively) whose values must be redacted in
# any saved request/response metadata.
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
    }
)


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    """Return a copy of headers with sensitive values replaced by ``[REDACTED]``."""
    if not headers:
        return {}

    redacted: dict[str, str] = {}
    for key, value in dict(headers).items():
        if str(key).lower() in SENSITIVE_HEADERS:
            redacted[str(key)] = REDACTED
        else:
            redacted[str(key)] = str(value)
    return redacted


def save_evidence(
    out_dir: str | Path,
    raw_result: dict[str, Any],
    body_text: str,
) -> dict[str, str]:
    """
    Write per-test evidence files and return their paths.

    Creates ``<out_dir>/evidence/`` with:
      - ``<test_id>_request.json``  (request metadata, headers already redacted)
      - ``<test_id>_response.txt``  (raw response body text)
    """
    evidence_dir = Path(out_dir) / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    test_id = str(raw_result.get("test_id", "unknown_test"))

    request_path = evidence_dir / f"{test_id}_request.json"
    response_path = evidence_dir / f"{test_id}_response.txt"

    request_payload = {
        "request": raw_result.get("request", {}),
        "response_meta": raw_result.get("response", {}),
    }

    request_path.write_text(json.dumps(request_payload, indent=2), encoding="utf-8")
    response_path.write_text(body_text or "", encoding="utf-8")

    return {
        "request_file": str(request_path),
        "response_file": str(response_path),
    }


def save_raw_results(
    out_dir: str | Path,
    results: list[dict[str, Any]],
) -> str:
    """Write the combined ``raw_results.json`` and return its path."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    raw_results_path = out_path / "raw_results.json"
    raw_results_path.write_text(
        json.dumps({"results": results}, indent=2),
        encoding="utf-8",
    )

    return str(raw_results_path)


def save_detector_results(
    out_dir: str | Path,
    results: list[dict[str, Any]],
) -> str:
    """Write ``detector_results.json`` and return its path."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    detector_results_path = out_path / "detector_results.json"
    detector_results_path.write_text(
        json.dumps({"results": results}, indent=2),
        encoding="utf-8",
    )

    return str(detector_results_path)
