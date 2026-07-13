"""VectorGuard Web Agent 'check' command.

Verifies scope and HTTP method safety for a target (no HTTP requests).
"""

from __future__ import annotations

import argparse

from ..safety import MethodSafetyError, validate_method
from ..scope import ScopeError, validate_scope

# Printed by commands that never send HTTP requests.
NO_HTTP_NOTICE = "[web-agent] no HTTP requests are sent by this command."


def cmd_check(args: argparse.Namespace) -> int:
    """Verify scope and HTTP method safety for a target (no requests)."""
    print(NO_HTTP_NOTICE)
    print("Command: check")

    if not args.target:
        print("Error: A target is required. Pass --target <url>.")
        return 2

    try:
        host = validate_scope(args.target, args.scope or [])
    except ScopeError as error:
        print(f"  Scope:  BLOCKED - {error}")
        return 2

    print(f"  Scope:  OK - {host} is in scope.")

    try:
        method = validate_method(
            args.method,
            allow_state_changing=args.allow_state_changing,
        )
    except MethodSafetyError as error:
        print(f"  Method: BLOCKED - {error}")
        return 2

    print(f"  Method: OK - {method} is permitted.")
    return 0
