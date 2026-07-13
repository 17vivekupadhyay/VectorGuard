"""VectorGuard Web Agent 'report' command.

Renders a report from a previous scan (dry-run, no HTTP requests).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..report import build_report_markdown, save_report
from .shared import maybe_write_ai_summary

# Printed by commands that never send HTTP requests.
NO_HTTP_NOTICE = "[web-agent] no HTTP requests are sent by this command."


def cmd_report(args: argparse.Namespace) -> int:
    """Render a report from a previous scan (dry-run)."""
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
        maybe_write_ai_summary(out_path)

    return 0
