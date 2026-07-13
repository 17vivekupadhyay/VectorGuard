"""
VectorGuard Web Agent CLI.

A defensive, authorized OWASP-style web application security testing layer.

Subcommands:
    plan          Plan which tests would run for a target (no requests).
    generate-tests Build and write concrete test files (no requests).
    agent         Run the bounded observe-decide-act agent loop over a target.
    validate      Validate a web test YAML file (no requests).
    scan          Validate, then send one safe GET and save evidence.
    check         Verify scope and method safety for a target (no requests).
    report        Render a report from a previous scan (no requests).
"""

from __future__ import annotations

import argparse

from .agent.agent_loop import DEFAULT_MAX_DISCOVERED, DEFAULT_MAX_STEPS
from .commands import (
    cmd_agent,
    cmd_check,
    cmd_generate_tests,
    cmd_plan,
    cmd_report,
    cmd_scan,
    cmd_validate,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="python -m vectorguard.webagent.cli",
        description=(
            "VectorGuard Web Agent - a defensive, authorized OWASP-style web "
            "application security testing layer."
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # plan
    plan_parser = subparsers.add_parser(
        "plan",
        help="Map a target config's endpoints to templates (no requests).",
    )
    plan_parser.add_argument(
        "--config",
        help="Path to a target config YAML (target, scope, known_endpoints, cookies).",
    )
    plan_parser.add_argument(
        "--planner",
        choices=["deterministic", "llm"],
        default="deterministic",
        help="Planner mode. Default: deterministic (LLM falls back to it).",
    )
    plan_parser.add_argument(
        "--out",
        default="reports/web_plan",
        help="Output directory for plan.json.",
    )
    plan_parser.set_defaults(func=cmd_plan)

    # generate-tests
    generate_parser = subparsers.add_parser(
        "generate-tests",
        help="Build the plan and write concrete YAML test files (no requests).",
    )
    generate_parser.add_argument(
        "--config",
        help="Path to a target config YAML (target, scope, known_endpoints, cookies).",
    )
    generate_parser.add_argument(
        "--out",
        default="reports/web_generated_tests",
        help="Output directory for plan.json and generated_tests/.",
    )
    generate_parser.set_defaults(func=cmd_generate_tests)

    # agent
    agent_parser = subparsers.add_parser(
        "agent",
        help="Run the bounded observe-decide-act agent loop over a target config.",
    )
    agent_parser.add_argument(
        "--config",
        help="Path to a target config YAML (target, scope, known_endpoints, cookies).",
    )
    agent_parser.add_argument(
        "--planner",
        choices=["deterministic", "llm"],
        default="deterministic",
        help="Decision strategy. Default: deterministic (LLM falls back to it).",
    )
    agent_parser.add_argument(
        "--max-steps",
        type=int,
        default=DEFAULT_MAX_STEPS,
        help=f"Maximum agent iterations (default: {DEFAULT_MAX_STEPS}).",
    )
    agent_parser.add_argument(
        "--discover",
        action="store_true",
        help="Enable bounded same-origin endpoint discovery (off by default).",
    )
    agent_parser.add_argument(
        "--max-discovered",
        type=int,
        default=DEFAULT_MAX_DISCOVERED,
        help=f"Cap on discovered endpoints (default: {DEFAULT_MAX_DISCOVERED}).",
    )
    agent_parser.add_argument(
        "--out",
        default="reports/web_agent_run",
        help="Output directory for evidence, findings, report, and agent_run.json.",
    )
    agent_parser.add_argument(
        "--ai-summary",
        action="store_true",
        help="Also write agent_summary.md (falls back to a placeholder without an LLM).",
    )
    agent_parser.set_defaults(func=cmd_agent)

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
        help="Validate, then send one safe GET request and save evidence.",
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
    scan_parser.add_argument(
        "--ai-summary",
        action="store_true",
        help="Also write agent_summary.md (falls back to a placeholder without an LLM).",
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
    report_parser.add_argument(
        "--ai-summary",
        action="store_true",
        help="Also write agent_summary.md (falls back to a placeholder without an LLM).",
    )
    report_parser.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the appropriate command."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
