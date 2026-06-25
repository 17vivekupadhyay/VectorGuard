"""
Optional AI report summary for the VectorGuard Web Agent.

Turns existing scan evidence into a polished, analyst-style ``agent_summary.md``.
The deterministic ``report.md`` remains the default and is always produced first.

Hard rules:
- The summary may only discuss data already present in findings.json,
  detector_results.json, raw_results.json, and plan.json (when available).
- It must not invent endpoints, vulnerabilities, or evidence.
- It must preserve detector confidence levels.
- With zero findings it must state that no suspicious findings were detected.

No LLM client is wired in this phase, so generation falls back to a clear
placeholder. The project works without any API keys. The client is the same
mockable ``complete(prompt) -> str`` protocol used by the planner.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .llm_planner import LLMClient, LLMUnavailableError, get_llm_client

FALLBACK_SUMMARY_MESSAGE = (
    "AI summary unavailable; deterministic report.md was still generated."
)

SUMMARY_SECTIONS = [
    "Executive summary",
    "OWASP mapping",
    "Findings explained in plain English",
    "Technical evidence",
    "Risk and impact",
    "Remediation",
    "Retest plan",
    "Limitations",
]


class AISummaryUnavailableError(RuntimeError):
    """Raised when no LLM client is configured for the report summary."""


def load_scan_artifacts(out_dir: str | Path) -> dict[str, Any]:
    """
    Load the JSON evidence the summary is allowed to use.

    ``findings.json`` is required (run a scan first). The detector results, raw
    results, and plan are included when present.
    """
    out_path = Path(out_dir)

    findings_path = out_path / "findings.json"
    if not findings_path.exists():
        raise FileNotFoundError(f"{findings_path} not found. Run a scan first.")

    artifacts: dict[str, Any] = {
        "findings": json.loads(findings_path.read_text(encoding="utf-8")),
    }

    for filename, key in (
        ("detector_results.json", "detector_results"),
        ("raw_results.json", "raw_results"),
        ("plan.json", "plan"),
    ):
        path = out_path / filename
        if path.exists():
            artifacts[key] = json.loads(path.read_text(encoding="utf-8"))

    return artifacts


def build_summary_prompt(artifacts: dict[str, Any]) -> str:
    """Build the analyst-summary prompt from existing JSON evidence only."""
    sections = "\n".join(f"- {section}" for section in SUMMARY_SECTIONS)

    return (
        "You are a defensive AppSec analyst writing a report summary for "
        "VectorGuard Web Agent.\n"
        "Use ONLY the JSON evidence provided below. Do not invent endpoints, "
        "vulnerabilities, or evidence. Preserve the confidence levels exactly. "
        "If there are zero findings, clearly state that no suspicious findings "
        "were detected.\n\n"
        "Write Markdown with exactly these sections:\n"
        f"{sections}\n\n"
        "Evidence (JSON):\n"
        f"{json.dumps(artifacts, indent=2)}\n"
    )


def generate_ai_summary(
    artifacts: dict[str, Any],
    *,
    client: LLMClient | None,
) -> str:
    """
    Generate the AI summary Markdown.

    Raises :class:`AISummaryUnavailableError` when no client is configured.
    """
    if client is None:
        raise AISummaryUnavailableError(FALLBACK_SUMMARY_MESSAGE)

    prompt = build_summary_prompt(artifacts)
    try:
        return client.complete(prompt)
    except LLMUnavailableError as error:
        # A configured client that fails mid-call still falls back cleanly.
        raise AISummaryUnavailableError(str(error))


def _findings(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    return artifacts.get("findings", {}).get("findings", [])


def placeholder_summary_markdown(artifacts: dict[str, Any]) -> str:
    """
    Deterministic placeholder used when no LLM client is available.

    It states that the AI summary was skipped, reflects the real finding count
    (including the zero-findings case), and points to the deterministic report.
    """
    findings = _findings(artifacts)

    lines = [
        "# VectorGuard Web Agent - AI Summary (skipped)",
        "",
        "_AI summary was skipped because no LLM client is configured._",
        "_The deterministic report.md is the authoritative output._",
        "",
        "## Status",
    ]

    if findings:
        lines.append(f"- {len(findings)} finding(s) were detected. See report.md for details.")
        for finding in findings:
            lines.append(
                f"  - {finding.get('id', 'finding')} "
                f"({finding.get('severity', 'unknown')}, "
                f"confidence={finding.get('confidence', 'unknown')})"
            )
    else:
        lines.append("- No suspicious findings were detected in this scan.")

    lines.extend(
        [
            "",
            "## How to enable the AI summary",
            "- Configure an LLM client for the web agent, then re-run with --ai-summary.",
            "",
        ]
    )

    return "\n".join(lines).strip() + "\n"


def save_agent_summary(out_dir: str | Path, text: str) -> str:
    """Write ``agent_summary.md`` and return its path."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    summary_path = out_path / "agent_summary.md"
    summary_path.write_text(text, encoding="utf-8")

    return str(summary_path)


def write_ai_summary(out_dir: str | Path, *, client: LLMClient | None = None) -> str:
    """
    Produce ``agent_summary.md`` for a scan directory.

    Uses the configured client (defaults to ``get_llm_client()``); on
    unavailability, writes a clear placeholder instead of failing. Returns the
    written path. The caller is responsible for any console messaging.
    """
    artifacts = load_scan_artifacts(out_dir)
    if client is None:
        client = get_llm_client()

    try:
        text = generate_ai_summary(artifacts, client=client)
    except AISummaryUnavailableError:
        text = placeholder_summary_markdown(artifacts)

    return save_agent_summary(out_dir, text)
