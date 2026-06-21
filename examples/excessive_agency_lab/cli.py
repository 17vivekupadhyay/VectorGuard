"""
CLI for the agentic red-team lab framework (sandbox only).

    python3 cli.py --target naive-auth --objectives all --out reports/agent_rt
    python3 cli.py --target all --victim bob

⚠️  Runs only against the in-process sandbox targets in this folder. It cannot be
   pointed at a URL or a real system, the tools are inert mocks, and it requires
   the --i-own-this-sandbox attestation flag.
"""

from __future__ import annotations

import argparse

from engine import CampaignResult, run_campaign
from llm_client import LLMClient
from objectives import ALL_OBJECTIVE_IDS, build_objectives
from operators import DeterministicOperator, LLMOperator
from report import save_report
from targets import TARGET_PROFILES, build_target

BOLD, DIM, RED, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[90m", "\033[91m", "\033[92m", "\033[93m", "\033[0m"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python3 cli.py",
        description="VectorGuard agentic red-team lab — sandbox excessive-agency testing.",
    )
    p.add_argument(
        "--target",
        default="naive-auth",
        help=f"Sandbox target profile, or 'all'. Choices: {', '.join(TARGET_PROFILES)}.",
    )
    p.add_argument(
        "--objectives",
        default="all",
        help=f"Comma-separated objective ids, or 'all'. Choices: {', '.join(ALL_OBJECTIVE_IDS)}.",
    )
    p.add_argument("--victim", default="bob", help="Victim username to target.")
    p.add_argument("--max-steps", type=int, default=8, help="Budget per objective.")
    p.add_argument(
        "--operator",
        choices=["deterministic", "llm"],
        default="deterministic",
        help="Attacker brain. 'llm' uses an LLM (configure via LLM_BASE_URL / "
             "LLM_MODEL / LLM_API_KEY) and falls back to deterministic if absent.",
    )
    p.add_argument("--out", default=None, help="If set, write JSON + Markdown reports here.")
    p.add_argument(
        "--i-own-this-sandbox",
        action="store_true",
        help="Required attestation: these are owned, disposable sandbox targets.",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress the streaming trace.")
    return p


def _build_operator(kind: str):
    """Build the requested operator; degrade LLM -> deterministic if unconfigured."""
    if kind != "llm":
        return DeterministicOperator()
    client = LLMClient.from_env()
    if client is None:
        print(f"{YELLOW}[operator] LLM not configured (set LLM_BASE_URL + LLM_MODEL). "
              f"Falling back to deterministic.{RESET}")
        return DeterministicOperator()
    print(f"{DIM}[operator] LLM operator: {client.describe()} "
          f"(deterministic fallback armed){RESET}")
    return LLMOperator(client, fallback=DeterministicOperator())


def _targets(name: str) -> list[str]:
    if name == "all":
        return list(TARGET_PROFILES)
    if name not in TARGET_PROFILES:
        raise SystemExit(f"unknown target profile: {name!r} (choices: {', '.join(TARGET_PROFILES)})")
    return [name]


def _print_campaign_summary(result: CampaignResult) -> None:
    n, total = result.captured_count, len(result.results)
    head = f"{RED}{BOLD}{n}/{total} objectives EXPLOITED{RESET}" if n else \
        f"{GREEN}{BOLD}all {total} objectives resisted{RESET}"
    print(f"\n{BOLD}── {result.target_profile} ──{RESET}  {head}")
    for r in result.results:
        if r.captured:
            print(f"  {RED}EXPLOITED{RESET} {r.tool:<20} via {r.winning_tactic} "
                  f"(step {r.steps})")
        else:
            print(f"  {GREEN}resisted {RESET} {r.tool:<20} ({r.steps} tactics tried)")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.i_own_this_sandbox:
        print(f"{RED}Refusing to run.{RESET} Pass --i-own-this-sandbox to attest these "
              f"are owned, disposable sandbox targets.")
        return 2

    selected = None if args.objectives == "all" else args.objectives.split(",")
    objectives = build_objectives(selected, args.victim)

    print(f"{BOLD}VectorGuard :: agentic red-team lab (LLM06:2025){RESET}")
    print(f"{DIM}sandbox targets · inert mock tools · no network · no real effect{RESET}")

    operator = _build_operator(args.operator)

    exploited_any = False
    for profile in _targets(args.target):
        target = build_target(profile)
        result = run_campaign(
            target, objectives, operator,
            authorized_lab=True, max_steps=args.max_steps, verbose=not args.quiet,
        )
        _print_campaign_summary(result)
        exploited_any = exploited_any or result.captured_count > 0
        if args.out:
            out_dir = args.out if args.target != "all" else f"{args.out}/{profile}"
            jp, mp = save_report(result, out_dir)
            print(f"  {DIM}reports: {jp} · {mp}{RESET}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
