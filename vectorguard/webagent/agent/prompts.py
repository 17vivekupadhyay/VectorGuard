"""
Prompt construction for the optional LLM planner.

The prompt is built only from structured surface data (target, scope, known
endpoints, cookies, allowed templates) - never raw HTML or response bodies. It
instructs the model to return strict JSON and to choose only among the provided
template IDs.
"""

from __future__ import annotations

import json
from typing import Any

SAFETY_RULES = [
    "Only choose template_id values from the provided allowed templates.",
    "Only reference endpoints from the provided known_endpoints list.",
    "Do not invent endpoints, evidence, or new tests.",
    "Executable (GET, non-state-changing) templates go in selected_tests.",
    "State-changing or POST templates must go in gated_tests, never selected_tests.",
    "Output strict JSON only. No prose, no markdown, no comments.",
]


def build_planner_prompt(
    *,
    target: str,
    scope: list[str],
    description: str,
    known_endpoints: list[str],
    cookies: list[str],
    template_catalog: dict[str, dict[str, Any]],
) -> str:
    """Build the structured planning prompt string."""
    allowed = {
        template_id: {
            "owasp": meta["owasp"],
            "method": meta["method"],
            "executable_now": meta["executable_now"],
        }
        for template_id, meta in template_catalog.items()
    }

    surface = {
        "target": target,
        "scope": scope,
        "description": description,
        "known_endpoints": known_endpoints,
        "cookies": cookies,
        "allowed_templates": allowed,
    }

    schema_hint = {
        "selected_tests": [
            {
                "template_id": "<one of allowed_templates>",
                "owasp": "<owasp id>",
                "reason": "<short reason>",
                "endpoint": "<one of known_endpoints>",
                "requires_state_changing": False,
            }
        ],
        "gated_tests": [
            {"template_id": "<one of allowed_templates>", "reason": "<short reason>"}
        ],
        "skipped_tests": [
            {"template_id": "<one of allowed_templates>", "reason": "<short reason>"}
        ],
    }

    rules = "\n".join(f"- {rule}" for rule in SAFETY_RULES)

    return (
        "You are a defensive AppSec planning assistant for VectorGuard Web Agent.\n"
        "Map the known web surface to safe, PortSwigger-inspired test templates.\n\n"
        "Rules:\n"
        f"{rules}\n\n"
        "Surface (structured data only):\n"
        f"{json.dumps(surface, indent=2)}\n\n"
        "Respond with strict JSON matching this shape:\n"
        f"{json.dumps(schema_hint, indent=2)}\n"
    )
