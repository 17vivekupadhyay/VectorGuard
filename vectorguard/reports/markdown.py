from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _format_result(result: dict[str, Any]) -> str:
    status = "🟢 PASSED" if result.get("passed") else "🔴 FAILED"

    lines = [
        f"### {result.get('name', 'unknown_test')}",
        f"- Status: {status}",
        f"- Category: {result.get('category', 'unknown')}",
        f"- OWASP ID: {result.get('owasp_id', 'unmapped')}",
        f"- Severity: {result.get('severity', 'unknown')}",
        f"- Detector: {result.get('detector_type', 'unknown')}",
        f"- Latency (ms): {result.get('latency_ms', 'unknown')}",
        f"- Reason: {result.get('reason', 'No reason provided.')}",
        "",
        "**Prompt**",
        "```",
        str(result.get("prompt", "")),
        "```",
        "",
        "**Response**",
        "```",
        str(result.get("response_text", "")),
        "```",
    ]

    matched_patterns = result.get("matched_patterns", [])
    if matched_patterns:
        lines.extend(
            [
                "",
                f"- Matched Patterns: {matched_patterns}",
            ]
        )

    evidence = result.get("evidence", {})
    if evidence:
        lines.extend(["", "**Evidence**"])
        for pattern, snippet in evidence.items():
            lines.extend(
                [
                    f"- Pattern: `{pattern}`",
                    "```",
                    str(snippet),
                    "```",
                ]
            )

    return "\n".join(lines)


def build_markdown_report(
    results: list[dict[str, Any]],
    summary: dict[str, Any],
    suite_name: str = "VectorGuard Run",
) -> str:
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# {suite_name}",
        "",
        f"_Generated: {timestamp}_",
        "",
        "## Summary",
        f"- Total tests: {summary.get('total', 0)}",
        f"- 🟢 Passed: {summary.get('passed', 0)}",
        f"- 🔴 Failed: {summary.get('failed', 0)}",
        f"- Pass rate: {summary.get('pass_rate', 0.0)}%",
        "",
        "## By Category",
    ]

    by_category = summary.get("by_category", {})
    if by_category:
        for category, count in by_category.items():
            lines.append(f"- {category}: {count}")
    else:
        lines.append("- None")

    lines.extend(["", "## By Severity"])
    by_severity = summary.get("by_severity", {})
    if by_severity:
        for severity, count in by_severity.items():
            lines.append(f"- {severity}: {count}")
    else:
        lines.append("- None")

    failed_tests = summary.get("failed_tests", [])
    lines.extend(["", "## Failed Tests"])
    if failed_tests:
        for test in failed_tests:
            lines.append(
                f"- 🔴 {test.get('name')} ({test.get('category')}, {test.get('severity')}): {test.get('reason')}"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## Detailed Results", ""])

    for result in results:
        lines.append(_format_result(result))
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def save_markdown_report(
    results: list[dict[str, Any]],
    summary: dict[str, Any],
    output_dir: str = "vectorguard/storage",
    suite_name: str = "VectorGuard Run",
) -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_path = Path(output_dir) / f"run_{timestamp}.md"

    report_text = build_markdown_report(
        results=results,
        summary=summary,
        suite_name=suite_name,
    )

    with output_path.open("w", encoding="utf-8") as f:
        f.write(report_text)

    return str(output_path)