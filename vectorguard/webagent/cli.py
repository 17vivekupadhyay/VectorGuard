"""
VectorGuard Web Agent CLI.

A defensive, authorized OWASP-style web application security testing layer.

Status: scope/method safety and YAML validation are enforced; ``scan`` sends a
single safe GET request and saves evidence (Phase 6). Detectors, findings, and
reports are added in later phases.

Subcommands:
    plan      Plan which tests would run for a target (not implemented yet).
    validate  Load and validate a web test YAML file (no requests).
    scan      Validate, then send one safe GET and save evidence.
    check     Verify scope and method safety for a target (no requests).
    report    Render a report from a previous scan (not implemented yet).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import httpx

from .config import build_scan_options
from .detectors import WebDetectorError, evaluate_detectors, validate_detector_specs
from .evidence import save_detector_results, save_evidence, save_raw_results
from .loader import WebTestValidationError, load_web_test
from .models import ScanOptions, WebTest
from .runner import RunnerError, run_get_test
from .safety import MethodSafetyError, validate_method
from .scope import ScopeError, validate_scope

# Printed by commands that never send HTTP requests (plan, validate, report, check).
NO_HTTP_NOTICE = "[web-agent] no HTTP requests are sent by this command."


def build_parser() -> argparse.ArgumentParser:
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
    print(NO_HTTP_NOTICE)
    print("Command: plan")
    print(f"  Target: {args.target or '(none)'}")
    print(f"  Scope:  {args.scope or '(none)'}")
    print(f"  Out:    {args.out}")
    print("Planner is not implemented yet (Phase 10). Nothing was executed.")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
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


def load_web_test_or_report(tests_path: str) -> WebTest | None:
    """Load and validate a web test, printing a helpful error on failure."""
    try:
        return load_web_test(tests_path)
    except FileNotFoundError as error:
        print(f"Error: {error}")
    except WebTestValidationError as error:
        print(f"Error: invalid web test - {error}")
    except ValueError as error:
        # Raised by the shared YAML loader (e.g. duplicate keys, non-mapping).
        print(f"Error: could not parse YAML - {error}")
    return None


def print_web_test_summary(test: WebTest) -> None:
    print(f"  id:       {test.id}")
    print(f"  name:     {test.name}")
    print(f"  category: {test.category}")
    print(f"  owasp:    {test.owasp}")
    print(f"  severity: {test.severity}")
    print(f"  safe:     {test.safe}")
    print(f"  requires_state_changing: {test.requires_state_changing}")
    print(f"  request:  {test.request.method} {test.request.path}")
    print(f"  detectors: {', '.join(d.type for d in test.detectors)}")


def cmd_scan(args: argparse.Namespace) -> int:
    print("Command: scan")

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

    # A test file is required to send a request in Phase 6.
    if not options.tests:
        print("Error: scan requires --tests <file.yaml>.")
        return 2

    # Authoritative scope enforcement: block out-of-scope targets before any
    # request is sent or output directory is created.
    try:
        host = validate_scope(options.target, options.scope)
    except ScopeError as error:
        print(f"Error: {error}")
        return 2

    # Validate the test file (Phase 5).
    test = load_web_test_or_report(options.tests)
    if test is None:
        return 2

    # Enforce the method safety policy (Phase 4) before sending anything.
    try:
        validate_method(
            test.request.method,
            allow_state_changing=options.allow_state_changing,
        )
    except MethodSafetyError as error:
        print(f"Error: {error}")
        return 2

    # Preflight: reject unknown detector types before any request is sent.
    try:
        validate_detector_specs(test.detectors)
    except WebDetectorError as error:
        print(f"Error: {error}")
        return 2

    out_path = Path(options.out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    print_scan_summary(options, out_path, host)
    print_web_test_summary(test)

    # Send the safe GET request (Phase 6). The runner re-validates scope against
    # the resolved URL and does not follow redirects.
    try:
        raw_result, body_text = run_get_test(
            test=test,
            target=options.target,
            scope=options.scope,
        )
    except RunnerError as error:
        print(f"Error: {error}")
        return 2
    except ScopeError as error:
        print(f"Error: {error}")
        return 2
    except httpx.HTTPError as error:
        print(f"Error: request failed - {error}")
        return 1

    evidence_files = save_evidence(out_path, raw_result, body_text)
    raw_result["evidence"] = evidence_files
    raw_results_path = save_raw_results(out_path, [raw_result])

    response_meta = raw_result["response"]
    print("\nRequest sent (safe GET):")
    print(f"  URL:           {raw_result['request']['url']}")
    print(f"  Status:        {response_meta['status_code']}")
    print(f"  Body length:   {response_meta['body_length']}")
    print(f"  Elapsed (ms):  {response_meta['elapsed_ms']}")
    print(f"  Body sha256:   {response_meta['body_sha256']}")
    print("\nEvidence saved:")
    print(f"  {evidence_files['request_file']}")
    print(f"  {evidence_files['response_file']}")
    print(f"  {raw_results_path}")

    # Evaluate detectors against the raw result (Phase 7). No findings yet.
    try:
        detector_results = evaluate_detectors(
            test.detectors,
            body_text=body_text,
            status_code=response_meta["status_code"],
            body_length=response_meta["body_length"],
        )
    except WebDetectorError as error:
        print(f"\nError: {error}")
        return 2

    detector_payload = {
        "test_id": test.id,
        "detector_results": detector_results,
    }
    detector_results_path = save_detector_results(out_path, [detector_payload])

    print("\nDetector results:")
    for result in detector_results:
        flag = "SUSPICIOUS" if result["suspicious"] else "ok"
        print(
            f"  [{flag}] {result['detector']} "
            f"(confidence={result['confidence']}) - {result['explanation']}"
        )
    print(f"\nDetector results saved:\n  {detector_results_path}")
    print("\nFindings and reports are produced in Phase 8.")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
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


def cmd_report(args: argparse.Namespace) -> int:
    print(NO_HTTP_NOTICE)
    print("Command: report")
    print(f"  Out: {args.out}")
    print("Report rendering is not implemented yet (Phase 8). Nothing was executed.")
    return 0


def print_scan_summary(options: ScanOptions, out_path: Path, host: str) -> None:
    safety_mode = "safe" if options.safe_mode else "unsafe"

    print("VectorGuard Web Agent - scan")
    print(f"  Target:        {options.target}")
    print(f"  Target host:   {host or '(could not parse)'}")
    print(f"  Scope:         {', '.join(options.scope)}")
    print(f"  In scope:      True (enforced)")
    print(f"  Tests:         {options.tests or '(none provided)'}")
    print(f"  Output dir:    {out_path}")
    print(f"  Safety mode:   {safety_mode}")
    print(f"  State-changing allowed: {options.allow_state_changing}")
    print(f"  Blocked methods (default): DELETE, PUT, PATCH")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
