"""Scope allowlist enforcement (the Web Agent's first safety gate)."""

from __future__ import annotations

import pytest

from vectorguard.webagent.scope import (
    ScopeError,
    extract_host,
    is_in_scope,
    validate_scope,
)


def test_extract_host_strips_scheme_and_port():
    assert extract_host("http://localhost:5000/admin") == "localhost"
    assert extract_host("http://127.0.0.1:8080") == "127.0.0.1"
    assert extract_host("localhost:5000") == "localhost"


def test_localhost_allowed_when_scoped():
    assert validate_scope("http://localhost:5000", ["localhost"]) == "localhost"


def test_127_0_0_1_allowed_when_scoped():
    assert validate_scope("http://127.0.0.1:8080", ["127.0.0.1"]) == "127.0.0.1"


def test_loopback_aliases_are_not_interchangeable():
    # 127.0.0.1 is NOT auto-allowed just because localhost is scoped.
    assert is_in_scope("http://127.0.0.1:5000", ["localhost"]) is False


def test_out_of_scope_host_blocked():
    with pytest.raises(ScopeError):
        validate_scope("http://evil.example.com", ["localhost"])


def test_empty_scope_blocked():
    with pytest.raises(ScopeError):
        validate_scope("http://localhost:5000", [])


def test_unparseable_target_blocked():
    with pytest.raises(ScopeError):
        validate_scope("", ["localhost"])
