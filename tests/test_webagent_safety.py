"""HTTP method safety policy (the Web Agent's second safety gate)."""

from __future__ import annotations

import pytest

from vectorguard.webagent.safety import (
    MethodSafetyError,
    is_method_allowed,
    validate_method,
)


@pytest.mark.parametrize("method", ["GET", "get", "HEAD", "OPTIONS"])
def test_safe_methods_allowed(method):
    assert validate_method(method) == method.upper()


def test_post_blocked_by_default():
    with pytest.raises(MethodSafetyError):
        validate_method("POST")


def test_post_allowed_with_flag():
    assert validate_method("POST", allow_state_changing=True) == "POST"


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH"])
def test_destructive_methods_always_blocked(method):
    with pytest.raises(MethodSafetyError):
        validate_method(method)


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH"])
def test_destructive_blocked_even_with_flag(method):
    # The flag only unlocks POST; destructive methods stay blocked.
    with pytest.raises(MethodSafetyError):
        validate_method(method, allow_state_changing=True)


def test_unknown_method_blocked():
    with pytest.raises(MethodSafetyError):
        validate_method("FROBNICATE")


def test_is_method_allowed_boolean():
    assert is_method_allowed("GET") is True
    assert is_method_allowed("POST") is False
    assert is_method_allowed("POST", allow_state_changing=True) is True
    assert is_method_allowed("DELETE", allow_state_changing=True) is False
