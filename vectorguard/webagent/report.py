"""
Deterministic Markdown report for the VectorGuard Web Agent.

Builds ``report.md`` from the scan metadata, findings, raw results, and detector
results. No LLM is used; an optional AI summary is a later phase.

The builder takes plain structures (the same shapes saved to ``findings.json``,
``raw_results.json``, and ``detector_results.json``) so the ``report`` command
can regenerate a report from a previous scan directory.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DISCLAIMER = (
    "VectorGuard Web Agent is a defensive, authorized OWASP-style testing aid. "
    "Findings are signals for human review, not proof of complete security. "
    "Run it only against local labs, owned applications, or explicitly "
    "authorized targets."
)


def build_retest_command(metadata: dict[str, Any]) -> str:
    """Reconstruct the scan command that reproduces this run."""
    target = metadata.get("target", "<target>")
    scope = metadata.get("scope", []) or ["<host>"]
    tests = metadata.get("tests_file", "<tests.yaml>")
    out_dir = metadata.get("out_dir", "<out>")

    scope_args = " ".join(f"--scope {host}" for host in scope)
    return (
        "python3 -m vectorguard.webagent.cli scan "
        f"--target {target} {scope_args} "
        f"--tests {tests} --out {out_dir}"
    )


def _detector_summary(detector_results: list[dict[str, Any]]) -> tuple[int, int]:
    """Return (total_detectors, suspicious_detectors) across all tests."""
    total = 0
    suspicious = 0
    for entry in detector_results:
        for detector in entry.get("detector_results", []):
            total += 1
            if detector.get("suspicious"):
                suspicious += 1
    return total, suspicious


def build_report_markdown(
    *,
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    raw_results: list[dict[str, Any]],
    detector_results: list[dict[str, Any]],
) -> str:
    timestamp = metadata.get("generated") or datetime.now(UTC).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    total_detectors, suspicious_detectors = _detector_summary(detector_results)
    by_severity = Counter(f.get("severity", "unknown") for f in findings)

    lines: list[str] = [
        "# VectorGuard Web Agent Report",
        "",
        f"_Generated: {timestamp}_",
        "",
        "## Scan Metadata",
        f"- Run ID: {metadata.get('run_id', 'unknown')}",
        f"- Tests file: {metadata.get('tests_file', 'unknown')}",
        f"- Output directory: {metadata.get('out_dir', 'unknown')}",
        "",
        "## Target",
        f"- {metadata.get('target', 'unknown')}",
        "",
        "## Scope",
    ]

    scope = metadata.get("scope", [])
    if scope:
        lines.extend(f"- {host}" for host in scope)
    else:
        lines.append("- (none)")

    lines.extend(
        [
            "",
            "## Safety Mode",
            f"- Safety mode: {metadata.get('safety_mode', 'safe')}",
            f"- State-changing allowed: {metadata.get('allow_state_changing', False)}",
            "- Blocked methods (default): DELETE, PUT, PATCH",
            "",
            "## Test Run",
        ]
    )

    for raw in raw_results:
        request = raw.get("request", {})
        response = raw.get("response", {})
        lines.append(
            f"- {raw.get('test_id', 'unknown')}: "
            f"{request.get('method', '?')} {request.get('path', '?')} "
            f"-> status {response.get('status_code', '?')}, "
            f"length {response.get('body_length', '?')}"
        )
    lines.append(
        f"- Detectors evaluated: {total_detectors} "
        f"({suspicious_detectors} suspicious)"
    )

    lines.extend(["", "## Findings Summary"])
    if findings:
        lines.append(f"- Total findings: {len(findings)}")
        for severity, count in by_severity.most_common():
            lines.append(f"- {severity}: {count}")
    else:
        lines.append("- No findings. No detector flagged this scan as suspicious.")

    lines.extend(["", "## Detailed Findings"])
    if findings:
        for finding in findings:
            lines.extend(_format_finding(finding))
    else:
        lines.append("- None")

    lines.extend(["", "## Evidence Files"])
    evidence_listed = False
    for raw in raw_results:
        evidence = raw.get("evidence", {})
        for label, path in evidence.items():
            lines.append(f"- {raw.get('test_id', 'unknown')} {label}: {path}")
            evidence_listed = True
    if not evidence_listed:
        lines.append("- None")

    lines.extend(["", "## Remediation"])
    remediation_listed = False
    for finding in findings:
        remediation = finding.get("remediation", [])
        if remediation:
            lines.append(f"- {finding.get('id', 'finding')}:")
            lines.extend(f"  - {item}" for item in remediation)
            remediation_listed = True
    if not remediation_listed:
        lines.append("- No remediation needed for this scan (no findings).")

    lines.extend(
        [
            "",
            "## Retest Command",
            "```bash",
            build_retest_command(metadata),
            "```",
            "",
            "## Limitations / Defensive-Use Note",
            f"- {DISCLAIMER}",
            "",
        ]
    )

    return "\n".join(lines).strip() + "\n"


def _format_finding(finding: dict[str, Any]) -> list[str]:
    evidence = finding.get("evidence", {})
    suspicious = evidence.get("suspicious_detectors", [])

    lines = [
        f"### {finding.get('title', finding.get('id', 'finding'))}",
        f"- ID: {finding.get('id', 'unknown')}",
        f"- Category: {finding.get('category', 'unknown')}",
        f"- OWASP: {finding.get('owasp', 'unmapped')}",
        f"- Severity: {finding.get('severity', 'unknown')}",
        f"- Confidence: {finding.get('confidence', 'unknown')}",
        f"- Risk score: {finding.get('risk_score', 'n/a')}",
        f"- Endpoint: {finding.get('method', '?')} {finding.get('endpoint', '?')}",
        f"- Status code: {finding.get('status_code', '?')}",
        f"- Matched evidence: {evidence.get('matched', [])}",
        "",
        "**Suspicious detectors**",
    ]

    for detector in suspicious:
        lines.append(
            f"- {detector.get('detector', '?')} "
            f"(confidence={detector.get('confidence', '?')}): "
            f"{detector.get('explanation', '')}"
        )

    return lines


def save_report(out_dir: str | Path, report_text: str) -> str:
    """Write ``report.md`` and return its path."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    report_path = out_path / "report.md"
    report_path.write_text(report_text, encoding="utf-8")

    return str(report_path)
