"""JSON + Markdown reports for a black-box run."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .campaign import BlackBoxResult

_CONF_ORDER = {"deterministic": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


def render_markdown(run: BlackBoxResult) -> str:
    lines = [
        f"# VectorGuard Black-Box Report — {run.url}",
        "",
        f"- Generated: {datetime.now(UTC).isoformat()}",
        f"- Adapter: {run.adapter}",
        f"- Objectives: {', '.join(run.objectives)}",
        f"- Findings captured: **{len(run.captured)}/{len(run.findings)}**",
        "",
        "> Black-box findings are signals for review, not verified verdicts. "
        "Confidence reflects how provable each signal is from outside the target.",
        "",
        "## Summary",
        "",
        "| Objective | OWASP | Result | Confidence | Method |",
        "|-----------|-------|--------|------------|--------|",
    ]
    for f in sorted(run.findings, key=lambda x: _CONF_ORDER.get(x.confidence, 9)):
        status = "🔴 signal" if f.captured else "🟢 none"
        lines.append(f"| {f.objective} | {f.owasp} | {status} | {f.confidence} | {f.method} |")
    lines.append("")

    for f in run.findings:
        if not f.captured:
            continue
        lines += [
            f"## {f.objective} ({f.owasp}) — {f.confidence} confidence",
            "",
            f"- **Evidence:** {f.evidence}",
            f"- **Probe:** `{f.payload[:200]}`",
        ]
        if f.proof:
            lines.append(f"- **Proof:** `{f.to_dict()['proof']}`")
        if f.response_excerpt:
            lines.append(f"- **Response excerpt:** {f.to_dict()['response_excerpt']}")
        lines.append("")

    lines += [
        "## Remediation",
        "",
        "- Treat all user/retrieved input as untrusted; separate it from instructions.",
        "- Never place secrets in model-visible prompts or context; filter outputs (DLP).",
        "- Enforce output size / rate / cost limits and timeouts.",
        "- Keep system prompts free of sensitive operational detail; add leak filters.",
        "",
    ]
    return "\n".join(lines)


def save_report(run: BlackBoxResult, out_dir: str) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path, md_path = out / "blackbox.json", out / "report.md"
    json_path.write_text(json.dumps(run.to_dict(), indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(run), encoding="utf-8")
    return json_path, md_path
