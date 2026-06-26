"""Deterministic planner rules + scope enforcement."""

from __future__ import annotations

import pytest

from vectorguard.webagent.planner import build_plan
from vectorguard.webagent.scope import ScopeError

CONFIG = {
    "target": "http://localhost:5000",
    "scope": ["localhost"],
    "description": "demo",
    "known_endpoints": ["/login", "/admin", "/filter?category=Gifts", "/my-account", "/my-account/change-email"],
    "cookies": ["session"],
}


def _ids(entries):
    return {e["template_id"] for e in entries}


def test_plan_selects_executable_get_templates():
    plan = build_plan(CONFIG)
    selected = _ids(plan["selected_tests"])
    assert "access_control_forced_browsing_admin" in selected  # /admin
    assert "injection_sqli_basic_error_probe" in selected       # query param
    assert "jwt_cookie_shape_check" in selected                 # /my-account / cookie


def test_plan_gates_state_changing_templates():
    plan = build_plan(CONFIG)
    gated = _ids(plan["gated_tests"])
    assert "auth_username_enumeration" in gated      # /login (POST)
    assert "csrf_missing_token_check" in gated        # change-email (POST)


def test_gated_entries_are_not_executable_now():
    plan = build_plan(CONFIG)
    for entry in plan["gated_tests"]:
        assert entry["executable_now"] is False


def test_plan_blocks_out_of_scope_target():
    bad = dict(CONFIG, target="http://evil.example.com")
    with pytest.raises(ScopeError):
        build_plan(bad)


def test_plan_requires_target_and_scope():
    from vectorguard.webagent.planner import PlannerError

    with pytest.raises(PlannerError):
        build_plan({"scope": ["localhost"]})
    with pytest.raises(PlannerError):
        build_plan({"target": "http://localhost:5000"})
