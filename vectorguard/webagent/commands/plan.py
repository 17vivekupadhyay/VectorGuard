"""VectorGuard Web Agent 'plan' command.

Maps a target config's endpoints to templates (no HTTP requests).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ..agent import (
    FALLBACK_MESSAGE,
    LLMPlanValidationError,
    LLMUnavailableError,
    get_llm_client,
    plan_with_llm,
)
from ..planner import PlannerError, build_plan, load_target_config, save_plan
from ..scope import ScopeError

# Printed by commands that never send HTTP requests.
NO_HTTP_NOTICE = "[web-agent] no HTTP requests are sent by this command."


def _run_planner(config: dict, planner_mode: str) -> tuple[dict, str]:
    """
    Build a plan with the chosen planner.

    The deterministic planner is the default. The LLM planner falls back to the
    deterministic planner when no client is configured or its output is invalid.
    Returns ``(plan, planner_used)``.
    """
    if planner_mode != "llm":
        return build_plan(config), "deterministic"

    try:
        plan = plan_with_llm(config, client=get_llm_client())
        return plan, "llm"
    except LLMUnavailableError:
        print(FALLBACK_MESSAGE)
    except LLMPlanValidationError as error:
        print(f"LLM plan invalid ({error}); falling back to deterministic planner.")

    return build_plan(config), "deterministic (fallback)"


def cmd_plan(args: argparse.Namespace) -> int:
    """Plan which tests would run for a target (no requests)."""
    print(NO_HTTP_NOTICE)
    print("Command: plan")

    if not args.config:
        print("Error: plan requires --config <target_config.yaml>.")
        return 2

    try:
        config = load_target_config(args.config)
    except FileNotFoundError as error:
        print(f"Error: {error}")
        return 2
    except ValueError as error:
        print(f"Error: could not parse config - {error}")
        return 2

    try:
        plan, planner_used = _run_planner(config, args.planner)
    except (PlannerError, ScopeError) as error:
        print(f"Error: {error}")
        return 2

    out_path = Path(args.out)
    plan_path = save_plan(out_path, plan)

    print(f"  Planner:     {planner_used}")
    print(f"  Target:      {plan['target']}")
    print(f"  Scope:       {', '.join(plan['scope'])}")
    print(f"  Description: {plan['description']}")

    print(f"\nSelected (executable now, GET): {len(plan['selected_tests'])}")
    for entry in plan["selected_tests"]:
        print(f"  - {entry['template_id']} ({entry['owasp']})")

    print(f"\nGated (state-changing/POST, not run in safe mode): {len(plan['gated_tests'])}")
    for entry in plan["gated_tests"]:
        print(f"  - {entry['template_id']} ({entry['owasp']})")

    print(f"\nSkipped (no matching signal): {len(plan['skipped_tests'])}")
    for entry in plan["skipped_tests"]:
        print(f"  - {entry['template_id']}")

    print(f"\nPlan saved:\n  {plan_path}")
    return 0
