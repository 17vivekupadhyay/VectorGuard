"""
Deterministic planner for the VectorGuard Web Agent.

Given a target config (target, scope, known endpoints, cookies), the planner
maps known web surfaces to PortSwigger-core templates and writes ``plan.json``.

The planner only *selects* tests. It never sends HTTP requests and never invents
endpoints. An optional LLM planner is a later phase; this deterministic planner
remains the default.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vectorguard.config.loader import load_yaml_file

from .loader import load_web_test
from .scope import ScopeError, validate_scope

# Where the PortSwigger-core templates live.
PORTSWIGGER_DIR = Path("vectorguard/web_tests/portswigger_core")

# Stable template id -> filename ordering used for plan output.
TEMPLATE_FILES: dict[str, str] = {
    "access_control_forced_browsing_admin": "access_control_forced_browsing_admin.yaml",
    "injection_sqli_basic_error_probe": "injection_sqli_basic_error_probe.yaml",
    "auth_username_enumeration": "auth_username_enumeration.yaml",
    "csrf_missing_token_check": "csrf_missing_token_check.yaml",
    "jwt_cookie_shape_check": "jwt_cookie_shape_check.yaml",
}

# Endpoint substrings that suggest a state-changing/account action (CSRF rule).
ACCOUNT_ACTION_HINTS = ("change-email", "change-password", "update", "account")


class PlannerError(ValueError):
    """Raised when a target config is missing required fields."""


def load_target_config(path: str | Path) -> dict[str, Any]:
    """Load a target config YAML (reuses the shared loader)."""
    return load_yaml_file(path)


def _select_templates(
    known_endpoints: list[str],
    cookies: list[str],
) -> dict[str, str]:
    """Apply the deterministic rules; return template_id -> reason."""
    reasons: dict[str, str] = {}

    def select(template_id: str, reason: str) -> None:
        reasons.setdefault(template_id, reason)

    for endpoint in known_endpoints:
        if "/admin" in endpoint:
            select(
                "access_control_forced_browsing_admin",
                f"Known endpoint {endpoint} suggests an admin-only route worth a "
                f"safe GET access-control check.",
            )
        if "?" in endpoint:
            select(
                "injection_sqli_basic_error_probe",
                f"Known endpoint {endpoint} exposes a query parameter to probe "
                f"with a safe error-based SQL injection check.",
            )
        if "login" in endpoint:
            select(
                "auth_username_enumeration",
                f"Known endpoint {endpoint} is a login route; username-enumeration "
                f"review is planned (gated, manual).",
            )
        if any(hint in endpoint for hint in ACCOUNT_ACTION_HINTS):
            select(
                "csrf_missing_token_check",
                f"Known endpoint {endpoint} is a state-changing/account action; "
                f"CSRF token check is planned (gated, manual).",
            )
        if "my-account" in endpoint:
            select(
                "jwt_cookie_shape_check",
                f"Known endpoint {endpoint} is an authenticated account page; "
                f"JWT/session shape review (informational).",
            )

    if cookies and "jwt_cookie_shape_check" not in reasons:
        select(
            "jwt_cookie_shape_check",
            f"Session cookies present ({', '.join(cookies)}); JWT/session shape "
            f"review (informational).",
        )

    return reasons


def build_plan(
    config: dict[str, Any],
    *,
    templates_dir: Path = PORTSWIGGER_DIR,
) -> dict[str, Any]:
    """Validate the config and build the plan payload."""
    target = config.get("target")
    if not target:
        raise PlannerError("Target config is missing required field 'target'.")

    scope = config.get("scope") or []
    if not scope:
        raise PlannerError("Target config is missing required field 'scope'.")

    # Enforce that the target host is in its own declared scope.
    validate_scope(str(target), list(scope))

    description = config.get("description", "")
    known_endpoints = [str(e) for e in (config.get("known_endpoints") or [])]
    cookies = [str(c) for c in (config.get("cookies") or [])]

    reasons = _select_templates(known_endpoints, cookies)

    selected_tests: list[dict[str, Any]] = []
    gated_tests: list[dict[str, Any]] = []
    skipped_tests: list[dict[str, Any]] = []

    for template_id, filename in TEMPLATE_FILES.items():
        template_path = templates_dir / filename
        test = load_web_test(template_path)
        executable_now = (
            test.request.method.upper() == "GET" and not test.requires_state_changing
        )

        if template_id in reasons:
            entry = {
                "template_id": template_id,
                "template_path": str(template_path),
                "owasp": test.owasp,
                "reason": reasons[template_id],
                "executable_now": executable_now,
            }
            if executable_now:
                selected_tests.append(entry)
            else:
                gated_tests.append(entry)
        else:
            skipped_tests.append(
                {
                    "template_id": template_id,
                    "reason": "No known endpoint or signal matched this template's rules.",
                }
            )

    return {
        "target": str(target),
        "scope": list(scope),
        "description": description,
        "selected_tests": selected_tests,
        "gated_tests": gated_tests,
        "skipped_tests": skipped_tests,
    }


def save_plan(out_dir: str | Path, plan: dict[str, Any]) -> str:
    """Write ``plan.json`` and return its path."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    plan_path = out_path / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    return str(plan_path)
