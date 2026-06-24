"""
Strict validation of LLM planner output for the VectorGuard Web Agent.

The LLM is only allowed to choose among known template IDs and reference known
endpoints. Any deviation raises :class:`LLMPlanValidationError`, which the CLI
treats as a signal to fall back to the deterministic planner.

Expected LLM JSON shape:

    {
      "selected_tests": [
        {"template_id": "...", "owasp": "...", "reason": "...",
         "requires_state_changing": false, "endpoint": "/admin"}
      ],
      "skipped_tests": [{"template_id": "...", "reason": "..."}]
    }

``gated_tests`` is also accepted. Selected tests must be executable now
(GET, not state-changing); state-changing templates must be gated.
"""

from __future__ import annotations

from typing import Any

REQUIRED_LIST_KEYS = ("selected_tests", "gated_tests", "skipped_tests")


class LLMPlanValidationError(ValueError):
    """Raised when LLM planner output violates the allowed schema/rules."""


def _validate_test_entry(
    entry: Any,
    *,
    known_endpoints: list[str],
    templates: dict[str, dict[str, Any]],
    expect_executable: bool,
) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise LLMPlanValidationError("each test entry must be a JSON object.")

    template_id = entry.get("template_id")
    if not isinstance(template_id, str) or template_id not in templates:
        raise LLMPlanValidationError(f"unknown template_id: {template_id!r}.")

    meta = templates[template_id]
    actual_executable = bool(meta["executable_now"])

    # Selected must be executable; gated must be non-executable.
    if actual_executable != expect_executable:
        bucket = "selected_tests" if expect_executable else "gated_tests"
        raise LLMPlanValidationError(
            f"template {template_id!r} cannot be placed in {bucket} "
            f"(executable_now={actual_executable})."
        )

    # The LLM may not invent endpoints.
    endpoint = entry.get("endpoint")
    if endpoint is not None and endpoint not in known_endpoints:
        raise LLMPlanValidationError(
            f"endpoint {endpoint!r} is not in known_endpoints."
        )

    # If the LLM declared executable_now / requires_state_changing, they must
    # match the real template metadata.
    declared_exec = entry.get("executable_now")
    if declared_exec is not None and bool(declared_exec) != actual_executable:
        raise LLMPlanValidationError(
            f"executable_now mismatch for template {template_id!r}."
        )

    declared_state = entry.get("requires_state_changing")
    if declared_state is not None and bool(declared_state) != bool(
        meta["requires_state_changing"]
    ):
        raise LLMPlanValidationError(
            f"requires_state_changing mismatch for template {template_id!r}."
        )

    return {
        "template_id": template_id,
        "template_path": meta["template_path"],
        "owasp": meta["owasp"],
        "reason": entry.get("reason") or "Selected by LLM planner.",
        "executable_now": actual_executable,
    }


def validate_llm_plan(
    data: Any,
    *,
    known_endpoints: list[str],
    templates: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Validate raw LLM output and return normalized plan lists."""
    if not isinstance(data, dict):
        raise LLMPlanValidationError("LLM output must be a JSON object.")

    for key in REQUIRED_LIST_KEYS:
        if key not in data or not isinstance(data[key], list):
            raise LLMPlanValidationError(f"missing or invalid '{key}' list.")

    selected = [
        _validate_test_entry(
            entry,
            known_endpoints=known_endpoints,
            templates=templates,
            expect_executable=True,
        )
        for entry in data["selected_tests"]
    ]

    gated = [
        _validate_test_entry(
            entry,
            known_endpoints=known_endpoints,
            templates=templates,
            expect_executable=False,
        )
        for entry in data["gated_tests"]
    ]

    skipped: list[dict[str, Any]] = []
    for entry in data["skipped_tests"]:
        if not isinstance(entry, dict):
            raise LLMPlanValidationError("each skipped entry must be a JSON object.")
        template_id = entry.get("template_id")
        if not isinstance(template_id, str) or template_id not in templates:
            raise LLMPlanValidationError(
                f"unknown template_id in skipped_tests: {template_id!r}."
            )
        skipped.append(
            {
                "template_id": template_id,
                "reason": entry.get("reason") or "Skipped by LLM planner.",
            }
        )

    return {
        "selected_tests": selected,
        "gated_tests": gated,
        "skipped_tests": skipped,
    }
