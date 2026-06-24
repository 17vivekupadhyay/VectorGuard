"""
Safe HTTP runner for the VectorGuard Web Agent.

Phase 6 supports GET only. Every request re-validates the final URL host against
the scope allowlist before it is sent, uses a bounded timeout, and does not
follow redirects (so an out-of-scope redirect target is never fetched).

Detectors are not applied here (Phase 7). This runner sends one safe GET request
and returns structured raw evidence with sensitive headers redacted.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

import httpx

from .evidence import redact_headers
from .models import WebTest
from .scope import validate_scope

DEFAULT_TIMEOUT_SECONDS = 10.0


class RunnerError(RuntimeError):
    """Raised when a test cannot be executed by the safe runner."""


def build_url(target: str, path: str) -> str:
    """Join a target base URL and a request path that starts with '/'."""
    return target.rstrip("/") + path


def run_get_test(
    *,
    test: WebTest,
    target: str,
    scope: list[str],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any], str]:
    """
    Execute a single GET web test and return ``(raw_result, body_text)``.

    Raises :class:`RunnerError` if the test method is not GET, and
    ``ScopeError`` if the resolved URL host is out of scope. Network failures
    propagate as ``httpx.HTTPError``.
    """
    method = test.request.method.upper()
    if method != "GET":
        raise RunnerError(
            f"Phase 6 runner supports GET only; test '{test.id}' uses {method}."
        )

    url = build_url(target, test.request.path)

    # Re-validate scope against the resolved URL before sending anything.
    validate_scope(url, scope)

    start = time.perf_counter()
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        response = client.get(
            url,
            headers=test.request.headers or None,
            params=test.request.params or None,
        )
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    body_text = response.text
    body_sha256 = hashlib.sha256(response.content).hexdigest()

    raw_result: dict[str, Any] = {
        "test_id": test.id,
        "name": test.name,
        "category": test.category,
        "owasp": test.owasp,
        "severity": test.severity,
        "request": {
            "method": method,
            "url": url,
            "path": test.request.path,
            "params": test.request.params,
            "headers": redact_headers(test.request.headers),
        },
        "response": {
            "status_code": response.status_code,
            "headers": redact_headers(response.headers),
            "body_length": len(body_text),
            "elapsed_ms": elapsed_ms,
            "body_sha256": body_sha256,
        },
    }

    return raw_result, body_text
