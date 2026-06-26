"""Strict validation of LLM planner output (the LLM fence)."""

from __future__ import annotations

import pytest

from vectorguard.webagent.agent.llm_planner import build_template_catalog
from vectorguard.webagent.agent.schemas import (
    LLMPlanValidationError,
    validate_llm_plan,
)

CATALOG = build_template_catalog()
KNOWN = ["/admin", "/filter?category=Gifts", "/my-account"]


def test_valid_plan_accepted():
    data = {
        "selected_tests": [
            {"template_id": "access_control_forced_browsing_admin", "endpoint": "/admin"}
        ],
        "gated_tests": [{"template_id": "csrf_missing_token_check"}],
        "skipped_tests": [],
    }
    out = validate_llm_plan(data, known_endpoints=KNOWN, templates=CATALOG)
    assert out["selected_tests"][0]["template_id"] == "access_control_forced_browsing_admin"
    assert out["gated_tests"][0]["template_id"] == "csrf_missing_token_check"


def test_invented_template_rejected():
    data = {"selected_tests": [{"template_id": "totally_made_up"}], "gated_tests": [], "skipped_tests": []}
    with pytest.raises(LLMPlanValidationError):
        validate_llm_plan(data, known_endpoints=KNOWN, templates=CATALOG)


def test_state_changing_template_in_selected_rejected():
    # csrf is POST/gated; it must not appear in selected_tests
    data = {"selected_tests": [{"template_id": "csrf_missing_token_check"}], "gated_tests": [], "skipped_tests": []}
    with pytest.raises(LLMPlanValidationError):
        validate_llm_plan(data, known_endpoints=KNOWN, templates=CATALOG)


def test_invented_endpoint_rejected():
    data = {
        "selected_tests": [
            {"template_id": "access_control_forced_browsing_admin", "endpoint": "/secret-invented"}
        ],
        "gated_tests": [],
        "skipped_tests": [],
    }
    with pytest.raises(LLMPlanValidationError):
        validate_llm_plan(data, known_endpoints=KNOWN, templates=CATALOG)


def test_missing_list_key_rejected():
    with pytest.raises(LLMPlanValidationError):
        validate_llm_plan({"selected_tests": []}, known_endpoints=KNOWN, templates=CATALOG)
