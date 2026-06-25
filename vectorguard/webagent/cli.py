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
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx

from .config import build_scan_options
from .detectors import WebDetectorError, evaluate_detectors, validate_detector_specs
from .evidence import save_detector_results, save_evidence, save_raw_results
from .agent import (
    FALLBACK_MESSAGE,
    LLMPlanValidationError,
    LLMUnavailableError,
    get_llm_client,
    plan_with_llm,
)
from .agent.agent_loop import (
    DEFAULT_MAX_DISCOVERED,
    DEFAULT_MAX_STEPS,
    run_agent,
)
from .agent.report_agent import (
    AISummaryUnavailableError,
    FALLBACK_SUMMARY_MESSAGE,
    generate_ai_summary,
    load_scan_artifacts,
    placeholder_summary_markdown,
    save_agent_summary,
)
from .findings import build_findings_payload
from .generator import generate_tests
from .loader import WebTestValidationError, load_web_test
from .models import ScanOptions, WebTest
from .planner import PlannerError, build_plan, load_target_config, save_plan
from .report import build_report_markdown, save_report
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


def _maybe_write_ai_summary(out_path: Path) -> None:
    """
    Write agent_summary.md when --ai-summary is requested.

    Never fails the caller: on a missing scan or an unavailable LLM client it
    prints a helpful message and writes a placeholder summary instead.
    """
    try:
        artifacts = load_scan_artifacts(out_path)
    except FileNotFoundError as error:
        print(f"AI summary skipped: {error}")
        return

    try:
        text = generate_ai_summary(artifacts, client=get_llm_client())
        summary_path = save_agent_summary(out_path, text)
        print(f"\nAI summary written:\n  {summary_path}")
    except AISummaryUnavailableError:
        print(f"\n{FALLBACK_SUMMARY_MESSAGE}")
        summary_path = save_agent_summary(out_path, placeholder_summary_markdown(artifacts))
        print(f"Wrote placeholder summary:\n  {summary_path}")


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


def cmd_generate_tests(args: argparse.Namespace) -> int:
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


def cmd_agent(args: argparse.Namespace) -> int:
    print("Command: agent")

    if not args.config:
        print("Error: agent requires --config <target_config.yaml>.")
        return 2

    try:
        config = load_target_config(args.config)
    except FileNotFoundError as error:
        print(f"Error: {error}")
        return 2
    except ValueError as error:
        print(f"Error: could not parse config - {error}")
        return 2

    client = get_llm_client() if args.planner == "llm" else None
    if args.planner == "llm" and client is None:
        print(FALLBACK_MESSAGE)

    out_path = Path(args.out)
    out_path.mkdir(parents=True, exist_ok=True)

    try:
        result = run_agent(
            config,
            out_dir=out_path,
            client=client,
            max_steps=args.max_steps,
            discover=args.discover,
            max_discovered=args.max_discovered,
        )
    except ScopeError as error:
        print(f"Error: {error}")
        return 2
    except WebDetectorError as error:
        print(f"Error: {error}")
        return 2

    trace = result["trace"]
    raw_results = result["raw_results"]
    detector_payloads = result["detector_payloads"]
    findings = result["findings"]

    raw_results_path = save_raw_results(out_path, raw_results)
    detector_results_path = save_detector_results(out_path, detector_payloads)

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]
    metadata = {
        "run_id": run_id,
        "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "target": trace["target"],
        "scope": trace["scope"],
        "safety_mode": "safe",
        "allow_state_changing": False,
        "tests_file": f"agent loop ({trace['strategy']})",
        "out_dir": str(out_path),
    }

    findings_path = out_path / "findings.json"
    findings_path.write_text(
        json.dumps({"metadata": metadata, "findings": findings}, indent=2),
        encoding="utf-8",
    )

    report_text = build_report_markdown(
        metadata=metadata,
        findings=findings,
        raw_results=raw_results,
        detector_results=detector_payloads,
    )
    report_path = save_report(out_path, report_text)

    agent_run_path = out_path / "agent_run.json"
    agent_run_path.write_text(json.dumps(trace, indent=2), encoding="utf-8")

    print(f"  Strategy:    {trace['strategy']}")
    print(f"  Target:      {trace['target']}")
    print(f"  Steps taken: {trace['steps_taken']} (cap {trace['max_steps']})")
    print(f"  Stopped:     {trace['stopped_reason']}")
    if trace.get("discovery_enabled"):
        discovered = trace.get("discovered_endpoints", [])
        print(f"  Discovered:  {len(discovered)} endpoint(s): {discovered}")

    print("\nDecision trace:")
    for entry in trace["steps"]:
        decision = entry["decision"]
        if decision["action"] == "stop":
            print(f"  step {entry['step']}: STOP ({decision['reason']})")
            continue
        if "error" in entry:
            print(f"  step {entry['step']}: {decision['template_id']} -> error: {entry['error']}")
            continue
        result_meta = entry["result"]
        flag = "FINDING" if entry["finding_id"] else "clean"
        disc = " (discovered)" if entry["action"].get("discovered") else ""
        print(
            f"  step {entry['step']}: [{decision['source']}] {decision['template_id']}"
            f"{disc} ({entry['action']['path']}) "
            f"-> {result_meta['status_code']} [{flag}] "
            f"suspicious={result_meta['suspicious_detectors']}"
        )

    print(f"\nFindings: {len(findings)}")
    for finding in findings:
        print(
            f"  - {finding['id']} ({finding['severity']}, "
            f"confidence={finding['confidence']}, risk={finding['risk_score']})"
        )

    print("\nSaved:")
    print(f"  {raw_results_path}")
    print(f"  {detector_results_path}")
    print(f"  {findings_path}")
    print(f"  {report_path}")
    print(f"  {agent_run_path}")

    if args.ai_summary:
        _maybe_write_ai_summary(out_path)

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

    # Build findings and a deterministic Markdown report (Phase 8).
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]
    metadata = {
        "run_id": run_id,
        "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "target": options.target,
        "scope": options.scope,
        "safety_mode": "safe" if options.safe_mode else "unsafe",
        "allow_state_changing": options.allow_state_changing,
        "tests_file": options.tests,
        "out_dir": str(out_path),
    }

    findings_payload = build_findings_payload(
        test=test,
        raw_result=raw_result,
        detector_results=detector_results,
        metadata=metadata,
    )
    findings_path = out_path / "findings.json"
    findings_path.write_text(json.dumps(findings_payload, indent=2), encoding="utf-8")

    report_text = build_report_markdown(
        metadata=metadata,
        findings=findings_payload["findings"],
        raw_results=[raw_result],
        detector_results=[detector_payload],
    )
    report_path = save_report(out_path, report_text)

    findings = findings_payload["findings"]
    print(f"\nFindings: {len(findings)}")
    for finding in findings:
        print(
            f"  - {finding['id']} ({finding['severity']}, "
            f"confidence={finding['confidence']}, risk={finding['risk_score']})"
        )
    print("\nReports saved:")
    print(f"  {findings_path}")
    print(f"  {report_path}")

    if args.ai_summary:
        _maybe_write_ai_summary(out_path)

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

    out_path = Path(args.out)

    def _load(name: str) -> dict | None:
        path = out_path / name
        if not path.exists():
            print(f"Error: {path} not found. Run a scan first.")
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    findings_payload = _load("findings.json")
    raw_results_payload = _load("raw_results.json")
    detector_results_payload = _load("detector_results.json")
    if (
        findings_payload is None
        or raw_results_payload is None
        or detector_results_payload is None
    ):
        return 2

    report_text = build_report_markdown(
        metadata=findings_payload.get("metadata", {}),
        findings=findings_payload.get("findings", []),
        raw_results=raw_results_payload.get("results", []),
        detector_results=detector_results_payload.get("results", []),
    )
    report_path = save_report(out_path, report_text)

    print(f"  Regenerated: {report_path}")

    if args.ai_summary:
        _maybe_write_ai_summary(out_path)

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
