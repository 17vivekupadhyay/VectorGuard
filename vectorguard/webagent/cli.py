"""
VectorGuard Web Agent CLI.

A defensive, authorized OWASP-style web application security testing layer.

Phase 3 status: skeleton / dry-run only. Commands parse arguments, validate
target/scope, create the output directory, and print a summary. **No HTTP
requests are sent.** Later phases add the safe HTTP runner, detectors, findings,
reports, and the planner.

Subcommands:
    plan      Plan which tests would run for a target (dry-run).
    validate  Validate a web test YAML file (dry-run).
    scan      Run a scan (Phase 3: dry-run summary only, zero requests).
    report    Render a report from a previous scan (dry-run).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .config import build_scan_options
from .models import ScanOptions
from .safety import MethodSafetyError, validate_method
from .scope import ScopeError, validate_scope

DRY_RUN_NOTICE = (
    "[dry-run] Web Agent skeleton (Phase 3): no HTTP requests are sent yet."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vectorguard.webagent.cli",
        description=(
            "VectorGuard Web Agent - a defensive, authorized OWASP-style web "
            "application security testing layer. Skeleton (Phase 3): dry-run only."
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # plan
    plan_parser = subparsers.add_parser(
        "plan",
        help="Plan which tests would run for a target (dry-run).",
    )
    plan_parser.add_argument("--target", help="Target base URL, e.g. http://localhost:5000")
    plan_parser.add_argument(
        "--scope",
        action="append",
        help="Allowed host (repeatable). Required before any real scan.",
    )
    plan_parser.add_argument(
        "--out",
        default="reports/web_plan",
        help="Output directory for the plan.",
    )
    plan_parser.set_defaults(func=cmd_plan)

    # validate
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate a web test YAML file (dry-run).",
    )
    validate_parser.add_argument(
        "--tests",
        help="Path to a web test YAML file or directory.",
    )
    validate_parser.set_defaults(func=cmd_validate)

    # scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a scan (Phase 3: dry-run summary only, zero requests).",
    )
    scan_parser.add_argument(
        "--target",
        help="Target base URL, e.g. http://localhost:5000",
    )
    scan_parser.add_argument(
        "--scope",
        action="append",
        help="Allowed host (repeatable). Required for every scan.",
    )
    scan_parser.add_argument(
        "--tests",
        help="Path to a web test YAML file or directory.",
    )
    scan_parser.add_argument(
        "--out",
        default="reports/web_scan",
        help="Output directory for evidence and reports.",
    )
    scan_parser.add_argument(
        "--allow-state-changing",
        action="store_true",
        help="Allow gated state-changing POST tests (off by default).",
    )
    scan_parser.set_defaults(func=cmd_scan)

    # check
    check_parser = subparsers.add_parser(
        "check",
        help="Verify scope and HTTP method safety for a target (no requests).",
    )
    check_parser.add_argument(
        "--target",
        help="Target base URL, e.g. http://localhost:5000",
    )
    check_parser.add_argument(
        "--scope",
        action="append",
        help="Allowed host (repeatable). Required.",
    )
    check_parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method to evaluate against the safety policy (default: GET).",
    )
    check_parser.add_argument(
        "--allow-state-changing",
        action="store_true",
        help="Permit state-changing POST (PUT/PATCH/DELETE stay blocked).",
    )
    check_parser.set_defaults(func=cmd_check)

    # report
    report_parser = subparsers.add_parser(
        "report",
        help="Render a report from a previous scan (dry-run).",
    )
    report_parser.add_argument(
        "--out",
        default="reports/web_scan",
        help="Scan output directory to render a report from.",
    )
    report_parser.set_defaults(func=cmd_report)

    return parser


def cmd_plan(args: argparse.Namespace) -> int:
    print(DRY_RUN_NOTICE)
    print("Command: plan")
    print(f"  Target: {args.target or '(none)'}")
    print(f"  Scope:  {args.scope or '(none)'}")
    print(f"  Out:    {args.out}")
    print("Planner is not implemented yet (Phase 10). Nothing was executed.")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    print(DRY_RUN_NOTICE)
    print("Command: validate")
    print(f"  Tests: {args.tests or '(none)'}")
    print("Web test validation is not implemented yet (Phase 5). Nothing was executed.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    print(DRY_RUN_NOTICE)

    try:
        options = build_scan_options(
            target=args.target,
            scope=args.scope,
            out_dir=args.out,
            tests=args.tests,
            allow_state_changing=args.allow_state_changing,
        )
    except ValueError as error:
        print(f"Error: {error}")
        return 2

    # Authoritative scope enforcement: block out-of-scope targets before any
    # output directory is created. No request is made in Phase 4.
    try:
        host = validate_scope(options.target, options.scope)
    except ScopeError as error:
        print(f"Error: {error}")
        return 2

    out_path = Path(options.out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    print_scan_summary(options, out_path, host)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    print(DRY_RUN_NOTICE)
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


def cmd_report(args: argparse.Namespace) -> int:
    print(DRY_RUN_NOTICE)
    print("Command: report")
    print(f"  Out: {args.out}")
    print("Report rendering is not implemented yet (Phase 8). Nothing was executed.")
    return 0


def print_scan_summary(options: ScanOptions, out_path: Path, host: str) -> None:
    safety_mode = "safe" if options.safe_mode else "unsafe"

    print("Command: scan")
    print("VectorGuard Web Agent - dry-run scan summary")
    print(f"  Target:        {options.target}")
    print(f"  Target host:   {host or '(could not parse)'}")
    print(f"  Scope:         {', '.join(options.scope)}")
    print(f"  In scope:      True (enforced)")
    print(f"  Tests:         {options.tests or '(none provided)'}")
    print(f"  Output dir:    {out_path}")
    print(f"  Safety mode:   {safety_mode}")
    print(f"  State-changing allowed: {options.allow_state_changing}")
    print(f"  Blocked methods (default): DELETE, PUT, PATCH")
    print(f"  Created output directory: {out_path.resolve()}")
    print("No HTTP requests were sent. The runner is added in Phase 6.")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
