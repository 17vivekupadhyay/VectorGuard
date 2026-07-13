"""VectorGuard Web Agent 'generate-tests' command.

Builds a plan and writes concrete YAML test files (no HTTP requests).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ..generator import generate_tests
from ..planner import PlannerError, load_target_config
from ..scope import ScopeError

# Printed by commands that never send HTTP requests.
NO_HTTP_NOTICE = "[web-agent] no HTTP requests are sent by this command."


def cmd_generate_tests(args: argparse.Namespace) -> int:
    """Build the plan and write concrete YAML test files (no requests)."""
    print(NO_HTTP_NOTICE)
    print("Command: generate-tests")

    if not args.config:
        print("Error: generate-tests requires --config <target_config.yaml>.")
        return 2

    try:
        config = load_target_config(args.config)
        plan, written = generate_tests(
            config,
            config_path=args.config,
            out_dir=args.out,
        )
    except FileNotFoundError as error:
        print(f"Error: {error}")
        return 2
    except (PlannerError, ScopeError) as error:
        print(f"Error: {error}")
        return 2
    except ValueError as error:
        print(f"Error: could not parse config - {error}")
        return 2

    print(f"  Target: {plan['target']}")
    print(f"  Output: {args.out}")

    print(f"\nExecutable GET tests generated: {len(written['executable'])}")
    for path in written["executable"]:
        print(f"  {path}")

    print(f"\nGated (state-changing) tests generated: {len(written['gated'])}")
    for path in written["gated"]:
        print(f"  {path}")

    print(f"\nPlan saved:\n  {Path(args.out) / 'plan.json'}")
    return 0
