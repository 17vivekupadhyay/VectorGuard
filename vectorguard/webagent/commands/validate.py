"""VectorGuard Web Agent 'validate' command.

Validates a web test YAML file (dry-run, no HTTP requests).
"""

from __future__ import annotations

import argparse

from .shared import (
    print_web_test_summary,
    load_web_test_or_report,
)

# Printed by commands that never send HTTP requests.
NO_HTTP_NOTICE = "[web-agent] no HTTP requests are sent by this command."


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate a web test YAML file (dry-run)."""
    print(NO_HTTP_NOTICE)
    print("Command: validate")

    if not args.tests:
        print("Error: A test file is required. Pass --tests <file.yaml>.")
        return 2

    test = load_web_test_or_report(args.tests)
    if test is None:
        return 2

    print(f"  Tests: {args.tests}")
    print_web_test_summary(test)
    print("Valid web test.")
    return 0
