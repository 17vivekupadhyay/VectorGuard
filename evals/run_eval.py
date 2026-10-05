"""
Golden-set eval runner.

Runs VectorGuard's attacker+oracle against every (target, objective) pair in the
golden set, compares the verdict to the ground-truth label, and reports
precision / recall / F1 — for the defense-aware ``adaptive`` attacker, the fixed
``baseline`` ladder, or both side by side.

Fully deterministic and key-free: the deterministic operator + analyst run
against in-process fake targets, so the number is reproducible on every machine
and in CI.

    python -m evals.run_eval                 # both modes, comparison
    python -m evals.run_eval --mode adaptive  # one mode
    python -m evals.run_eval --out evals/results
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vectorguard.redteam.episode import DEFAULT_MAX_STEPS, run_episode
from vectorguard.redteam.objectives import ObjectiveConfig, build_objectives
from vectorguard.redteam.operator import Operator

from .golden.manifest import GOLDEN_SET, OBJECTIVES
from .metrics import Outcome, Scoreboard, score

MODES = ("baseline", "adaptive")


def run_mode(mode: str, *, max_steps: int = DEFAULT_MAX_STEPS) -> Scoreboard:
    """Score the whole golden set under one attacker mode."""
    use_defense_model = mode == "adaptive"
    cfg = ObjectiveConfig()
    outcomes: list[Outcome] = []

    for gt in GOLDEN_SET:
        for obj_id in OBJECTIVES:
            objective = build_objectives(selected=[obj_id], config=cfg)[0]
            # Fresh target + fresh operator per cell: no state leaks between runs.
            operator = Operator(client=None, seeds=[], max_steps=max_steps)
            result = run_episode(
                gt.factory(),
                objective,
                operator,
                max_steps=max_steps,
                use_defense_model=use_defense_model,
            )
            outcomes.append(
                Outcome(
                    target=gt.name,
                    objective=obj_id,
                    label=gt.labels[obj_id],
                    captured=bool(result["captured"]),
                    steps=int(result["steps_taken"]),
                )
            )
    return score(outcomes)


def _fmt_pct(x: float) -> str:
    return f"{x:.0%}"


def render_markdown(boards: dict[str, Scoreboard]) -> str:
    out: list[str] = ["# VectorGuard Golden-Set Eval\n"]
    out.append(
        f"Targets: **{len(GOLDEN_SET)}** · objectives: **{len(OBJECTIVES)}** · "
        f"cells scored per mode: **{len(GOLDEN_SET) * len(OBJECTIVES)}**\n"
    )

    # Headline comparison when both modes ran.
    if "baseline" in boards and "adaptive" in boards:
        b, a = boards["baseline"].overall, boards["adaptive"].overall
        out.append("## Headline: defense-aware adaptation vs fixed ladder\n")
        out.append("| Mode | Precision | Recall | F1 | TP | FN | FP | TN |")
        out.append("|---|---|---|---|---|---|---|---|")
        for name, m in (("baseline (fixed ladder)", b), ("adaptive (defense-aware)", a)):
            out.append(
                f"| {name} | {_fmt_pct(m.precision)} | {_fmt_pct(m.recall)} | "
                f"{m.f1:.2f} | {m.tp} | {m.fn} | {m.fp} | {m.tn} |"
            )
        out.append("")
        out.append(
            f"> **Recall {_fmt_pct(b.recall)} → {_fmt_pct(a.recall)}** at precision "
            f"{_fmt_pct(a.precision)}: defense-aware reasoning catches "
            f"{a.tp - b.tp} vulnerabilit{'y' if a.tp - b.tp == 1 else 'ies'} the fixed "
            f"ladder misses (the encoding-only targets).\n"
        )

    for mode, board in boards.items():
        out.append(f"## Mode: {mode}\n")
        o = board.overall
        out.append(
            f"Overall — precision **{_fmt_pct(o.precision)}**, recall "
            f"**{_fmt_pct(o.recall)}**, F1 **{o.f1:.2f}** "
            f"(TP {o.tp} · FN {o.fn} · FP {o.fp} · TN {o.tn})\n"
        )
        out.append("| Objective | Precision | Recall | F1 | TP | FN | FP | TN |")
        out.append("|---|---|---|---|---|---|---|---|")
        for obj_id, m in board.per_objective.items():
            out.append(
                f"| {obj_id} | {_fmt_pct(m.precision)} | {_fmt_pct(m.recall)} | "
                f"{m.f1:.2f} | {m.tp} | {m.fn} | {m.fp} | {m.tn} |"
            )
        out.append("")
        if board.false_negatives:
            out.append("**Missed (false negatives) — a real vuln the tool did not catch:**")
            for o_ in board.false_negatives:
                out.append(f"- `{o_.target}` / {o_.objective}")
            out.append("")
        if board.false_positives:
            out.append("**False alarms (false positives) — flagged a safe target:**")
            for o_ in board.false_positives:
                out.append(f"- `{o_.target}` / {o_.objective}")
            out.append("")
        if not board.false_negatives and not board.false_positives:
            out.append("_No false negatives or false positives in this mode._\n")

    return "\n".join(out)


def _print_console(boards: dict[str, Scoreboard]) -> None:
    print("\nVectorGuard Golden-Set Eval")
    for mode, board in boards.items():
        o = board.overall
        print(
            f"  {mode:>9}: precision {_fmt_pct(o.precision)} · recall "
            f"{_fmt_pct(o.recall)} · F1 {o.f1:.2f} "
            f"(TP {o.tp} FN {o.fn} FP {o.fp} TN {o.tn})"
        )
    if "baseline" in boards and "adaptive" in boards:
        b, a = boards["baseline"].overall, boards["adaptive"].overall
        print(
            f"  → adaptation lifts recall {_fmt_pct(b.recall)} → {_fmt_pct(a.recall)} "
            f"at precision {_fmt_pct(a.precision)}"
        )
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.run_eval", description=__doc__)
    parser.add_argument("--mode", choices=(*MODES, "both"), default="both")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    parser.add_argument("--out", default="evals/results")
    args = parser.parse_args(argv)

    modes = MODES if args.mode == "both" else (args.mode,)
    boards = {mode: run_mode(mode, max_steps=args.max_steps) for mode in modes}

    report: dict[str, Any] = {
        "targets": len(GOLDEN_SET),
        "objectives": list(OBJECTIVES),
        "max_steps": args.max_steps,
        "modes": {mode: board.as_dict() for mode, board in boards.items()},
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "eval.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out_dir / "eval.md").write_text(render_markdown(boards), encoding="utf-8")

    _print_console(boards)
    print(f"  reports: {out_dir / 'eval.md'}  ·  {out_dir / 'eval.json'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
