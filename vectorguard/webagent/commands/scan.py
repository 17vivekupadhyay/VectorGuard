"""VectorGuard Web Agent 'scan' command.

Validates, then sends one safe GET request and saves evidence.
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx

from ..config import build_scan_options
from ..detectors import WebDetectorError, evaluate_detectors, validate_detector_specs
from ..evidence import save_detector_results, save_evidence, save_raw_results
from ..findings import build_findings_payload
from ..models import ScanOptions
from ..report import build_report_markdown, save_report
from ..runner import RunnerError, run_get_test
from ..safety import MethodSafetyError, validate_method
from ..scope import ScopeError, validate_scope
from .shared import (
    maybe_write_ai_summary,
    print_scan_summary,
    print_web_test_summary,
    load_web_test_or_report,
)


def cmd_scan(args: argparse.Namespace) -> int:
    """Validate, then send one safe GET request and save evidence."""
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
        maybe_write_ai_summary(out_path)

    return 0
