"""
Campaign: run every objective and produce the EXPLOIT report.

This is the deliverable a startup forwards: per-objective status (CAPTURED with
proof + full reproduction transcript, or ATTEMPTED but not captured), OWASP
mapping, severity, and an aggregate summary.

Reuses the core scoring/summary math: each captured objective is a *failed
defense*, so an episode maps onto the existing result shape with
``passed = not captured`` and feeds ``build_summary`` unchanged.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from vectorguard.reports.summary import build_summary

from .episode import DEFAULT_MAX_STEPS, run_episode

if TYPE_CHECKING:
    from vectorguard.targets.base import BaseTarget

    from .analyst import Analyst
    from .judge import Judge
    from .objectives import Objective
    from .operator import Operator


def _episode_to_result(episode: dict[str, Any]) -> dict[str, Any]:
    """Adapt an episode onto the core result shape (captured => not passed)."""
    captured = bool(episode["captured"])
    finding = None
    if captured:
        finding = {
            "title": episode["title"],
            "owasp_id": episode["owasp_id"],
            "severity": episode["severity"],
            "evidence": episode["evidence"],
            "proof": episode["proof"],
            "capture_method": episode["capture_method"],
        }
    return {
        "name": episode["objective_id"],
        "category": episode["objective_id"],
        "owasp_id": episode["owasp_id"],
        "severity": episode["severity"],
        "passed": not captured,
        "risk_score": episode["risk_score"],
        "reason": episode["evidence"] or episode["stopped_reason"],
        "finding": finding,
    }


def run_campaign(
    target: BaseTarget,
    objectives: list[Objective],
    operator: Operator,
    *,
    judge: Judge | None = None,
    analyst: Analyst | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    out_dir: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run all objectives, build the report, and (optionally) write it to disk."""
    episodes: list[dict[str, Any]] = []
    for objective in objectives:
        episode = run_episode(
            target,
            objective,
            operator,
            judge=judge,
            analyst=analyst,
            max_steps=max_steps,
        )
        episodes.append(episode)

    results = [_episode_to_result(ep) for ep in episodes]
    summary = build_summary(results)

    # Report the strategy that actually drove the attack, not just what was
    # configured: a configured-but-unreachable LLM degrades to deterministic
    # per step, and the deliverable should say so honestly.
    used_llm = any(
        step.get("source") == "llm" for ep in episodes for step in ep["steps"]
    )
    effective_strategy = "llm" if used_llm else "deterministic"

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    report: dict[str, Any] = {
        "run_id": run_id,
        "metadata": metadata or {},
        "strategy": effective_strategy,
        "configured_strategy": operator.strategy,
        "summary": summary,
        "captured_count": sum(1 for ep in episodes if ep["captured"]),
        "objectives": episodes,
    }

    if out_dir is not None:
        report["report_paths"] = _write_reports(report, out_dir)

    return report


# ----------------------------------------------------------------- report files


def _write_reports(report: dict[str, Any], out_dir: str | Path) -> dict[str, str]:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)

    json_path = directory / "report.json"
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    md_path = directory / "report.md"
    md_path.write_text(_render_markdown(report), encoding="utf-8")

    return {"json": str(json_path), "markdown": str(md_path)}


def _render_transcript(transcript: list[dict[str, str]]) -> str:
    lines: list[str] = []
    for turn in transcript:
        role = turn.get("role", "?").upper()
        content = (turn.get("content") or "").strip()
        lines.append(f"**{role}:**\n\n```\n{content}\n```")
    return "\n\n".join(lines)


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    meta = report.get("metadata", {})
    captured = report["captured_count"]
    total = len(report["objectives"])

    out: list[str] = []
    out.append("# VectorGuard Red-Team Exploit Report\n")
    out.append(f"- Run: `{report['run_id']}`")
    out.append(f"- Target: `{meta.get('target', 'unknown')}`")
    out.append(f"- Attacker strategy: **{report['strategy']}**")
    out.append(f"- Objectives captured: **{captured} / {total}**")
    out.append(f"- Total risk score: **{summary.get('total_risk_score', 0.0)}**")
    out.append("")

    out.append("## Coverage\n")
    out.append("| Objective | OWASP | Severity | Status | Method | Steps |")
    out.append("|---|---|---|---|---|---|")
    for ep in report["objectives"]:
        status = "🚩 CAPTURED" if ep["captured"] else "attempted"
        out.append(
            f"| {ep['objective_id']} | {ep['owasp_id']} | {ep['severity']} "
            f"| {status} | {ep['capture_method'] if ep['captured'] else '-'} "
            f"| {ep['steps_taken']} |"
        )
    out.append("")

    captured_eps = [ep for ep in report["objectives"] if ep["captured"]]
    if captured_eps:
        out.append("## Confirmed exploits\n")
        for ep in captured_eps:
            out.append(f"### 🚩 {ep['title']} ({ep['owasp_id']})\n")
            out.append(f"- Severity: **{ep['severity']}** | risk score: {ep['risk_score']}")
            out.append(f"- Capture method: `{ep['capture_method']}`")
            out.append(f"- Evidence: {ep['evidence']}")
            out.append(f"- Proof held: `{ep['proof']}`")
            out.append(f"- Captured in {ep['steps_taken']} step(s) via tactic escalation.\n")
            out.append("**Reproduction transcript:**\n")
            out.append(_render_transcript(ep["transcript"]))
            out.append("")

    attempted_eps = [ep for ep in report["objectives"] if not ep["captured"]]
    if attempted_eps:
        out.append("## Attempted (not captured)\n")
        for ep in attempted_eps:
            out.append(
                f"- **{ep['objective_id']}** ({ep['owasp_id']}): "
                f"{ep['stopped_reason']} after {ep['steps_taken']} step(s)."
            )
        out.append("")

    return "\n".join(out)
