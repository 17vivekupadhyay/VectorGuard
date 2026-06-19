"""Render campaign results to JSON + Markdown exploit reports."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from engine import CampaignResult


def render_markdown(result: CampaignResult) -> str:
    lines: list[str] = []
    lines.append(f"# Agentic Red-Team Report — target `{result.target_profile}`")
    lines.append("")
    lines.append(f"> {result.target_description}")
    lines.append("")
    lines.append(f"- Generated: {datetime.now(UTC).isoformat()}")
    lines.append(f"- Operator: `{result.operator}`")
    lines.append(f"- Victim user: `{result.victim}`")
    lines.append(f"- Budget: {result.max_steps} steps/objective")
    lines.append(f"- Objectives captured: **{result.captured_count}/{len(result.results)}**")
    lines.append("- OWASP: LLM06:2025 Excessive Agency")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Objective | Result | Winning tactic | Steps |")
    lines.append("|-----------|--------|----------------|-------|")
    for r in result.results:
        status = "🔴 EXPLOITED" if r.captured else "🟢 resisted"
        tac = r.winning_tactic or "—"
        lines.append(f"| `{r.tool}` | {status} | {tac} | {r.steps} |")
    lines.append("")

    for r in result.results:
        lines.append(f"## Objective: `{r.tool}` on `{r.victim}`")
        lines.append("")
        if r.captured:
            lines.append(f"**EXPLOITED** in {r.steps} step(s) via `{r.winning_tactic}` "
                         f"({r.winning_category}).")
            lines.append("")
            lines.append(f"- Proof (inert): `{r.proof}`")
        else:
            lines.append("**Resisted** — no tactic caused the forbidden tool to fire.")
        lines.append("")
        lines.append("<details><summary>Transcript</summary>")
        lines.append("")
        for s in r.trace:
            mark = "CAPTURED" if s.captured else "denied"
            lines.append(f"- step {s.step} [{s.category}] {mark}")
            lines.append(f"  - payload: {s.payload.splitlines()[0]}")
            lines.append(f"  - response: {s.response.splitlines()[0]}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("## Remediation")
    lines.append("")
    lines.append("- Enforce authorization **server-side**, bound to a verified session.")
    lines.append("- Never derive tool permissions from message text, retrieved content, "
                 "or structured-looking syntax.")
    lines.append("- Require explicit human confirmation for destructive tools.")
    lines.append("- Treat all model-visible input (including retrieved documents) as untrusted.")
    lines.append("")
    return "\n".join(lines)


def save_report(result: CampaignResult, out_dir: str) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "campaign.json"
    md_path = out / "report.md"
    json_path.write_text(json.dumps(_json_safe(result), indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(result), encoding="utf-8")
    return json_path, md_path


def _json_safe(result: CampaignResult) -> dict:
    d = asdict(result)
    d["captured_count"] = result.captured_count
    d["total_objectives"] = len(result.results)
    return d
