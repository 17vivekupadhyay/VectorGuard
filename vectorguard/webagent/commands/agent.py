"""VectorGuard Web Agent 'agent' command.

Run the bounded observe-decide-act agent loop over a target config.
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from ..agent import (
    FALLBACK_MESSAGE,
    get_llm_client,
)
from ..agent.agent_loop import (
    DEFAULT_MAX_DISCOVERED,
    DEFAULT_MAX_STEPS,
    run_agent,
)
from ..agent.report_agent import (
    AISummaryUnavailableError,
    FALLBACK_SUMMARY_MESSAGE,
    generate_ai_summary,
    load_scan_artifacts,
    placeholder_summary_markdown,
    save_agent_summary,
)
from ..detectors import WebDetectorError
from ..evidence import save_detector_results, save_raw_results
from ..planner import load_target_config
from ..report import build_report_markdown, save_report
from ..scope import ScopeError

# Shared helper for AI summary writing.
from .shared import maybe_write_ai_summary


def cmd_agent(args: argparse.Namespace) -> int:
    """Run the bounded observe-decide-act agent loop over a target config."""
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
        maybe_write_ai_summary(out_path)

    return 0
